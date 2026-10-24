// Model roles (SDK-API "v0.1.63 additions", BRIDGE §15.4, MANIFEST §7.1): `modelRole(role)` resolves the binding the workspace
// bridge holds for a role the manifest declares with `usedBy` "app" (`GET /tb/v1/model-roles/<role>` with TB-Assert, the path
// and auth of a key fetch). Bindings are cached until `keysRev` changes (one revision for keys and bindings). Values carry a
// key: they are never logged, never returned in an op result.

import {
  activeModelRoles,
  DATA_POLICIES,
  declaredModelRoles,
  MODEL_ROLES_PATH,
  type ModelRole,
  type ModelRoleRequirement,
  type ResolvedModelRole,
  settingsFromEnv,
} from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import type { BridgeClient } from "./bridge-client.ts";
import { errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import type { SecretRegistry } from "./log.ts";
import type { Attention } from "./status.ts";

export interface ModelRolesInternals {
  modelRole(role: ModelRole): Promise<ResolvedModelRole | null>;
  /** slice shows a pause: drop cached bindings and what readiness knew */
  dropCache(): void;
  /** resolve every required role in force, so readiness knows (a failure counts as unresolved) */
  refresh(): Promise<void>;
  /** required roles in force that do not resolve (readiness `needs_keys`) */
  missing(): ModelRole[];
  /** `model_role_missing` while `missing()` is not empty */
  attention(): Attention | null;
}

interface Entry {
  rev: number;
  value: Promise<ResolvedModelRole | null>;
}

export function createModelRoles(opts: {
  manifest: Manifest;
  env: Record<string, string | undefined>;
  secrets: SecretRegistry;
  log: Logger;
  bridge: () => BridgeClient | null;
  /** the keysRev the SDK knows (status long-poll); a binding is cached for one value of it */
  rev: () => number;
  /** what readiness knows about the roles changed: push a status */
  changed?: () => void;
}): ModelRolesInternals {
  const { manifest } = opts;
  const declared = new Map<string, ModelRoleRequirement>(declaredModelRoles(manifest).filter((r) => r.usedBy.includes("app")).map((r) => [r.role, r]));
  const cache = new Map<ModelRole, Entry>();
  /** required roles in force → did the last resolve find a binding (absent = not asked yet = not set) */
  const resolved = new Map<ModelRole, boolean>();
  let signature = "";

  const inForce = (): ModelRoleRequirement[] => activeModelRoles(manifest, settingsFromEnv(manifest, opts.env), "app");
  const missing = (): ModelRole[] => inForce().filter((r) => r.required && resolved.get(r.role) !== true).map((r) => r.role);
  const settle = (): void => {
    const now = missing().join(",");
    if (now === signature) return;
    signature = now;
    opts.changed?.();
  };

  const fetchRole = async (role: ModelRole): Promise<ResolvedModelRole | null> => {
    const client = opts.bridge();
    if (!client) return null;
    const r = await client.request("GET", MODEL_ROLES_PATH.replace("{role}", encodeURIComponent(role)));
    // 404: role_not_set, or no route at all (a bridge without cap `model_roles`: 404 without a refuse code, RM-17): fail closed, null,
    // never a guess and never a fall back to keys. 403 role_policy_too_low: nothing of the binding is sent
    if (r.status === 404) return null;
    if (r.status === 403 && errorFrom(r, "model_role_unavailable").code === "role_policy_too_low") return null;
    if (r.status !== 200) throw errorFrom(r, "model_role_unavailable");
    const b = r.body as Partial<Record<keyof ResolvedModelRole, unknown>> | null;
    const text = (v: unknown): string | null => (typeof v === "string" ? v : null);
    const provider = text(b?.provider);
    const model = text(b?.model);
    if (provider === null || model === null || b?.role !== role || !(DATA_POLICIES as readonly unknown[]).includes(b.dataPolicy)) {
      throw new TbError("model_role_unavailable", "bridge model role answer malformed", 502);
    }
    const key = text(b.key);
    if (key) opts.secrets.add(key);
    return {
      role,
      provider,
      model,
      baseUrl: text(b.baseUrl),
      key,
      dataPolicy: b.dataPolicy as ResolvedModelRole["dataPolicy"],
      dims: typeof b.dims === "number" ? b.dims : null,
    };
  };

  const resolve = (role: ModelRole): Promise<ResolvedModelRole | null> => {
    const rev = opts.rev();
    // a key or base URL of an earlier revision is dropped at once, not only replaced when its role is asked for again
    for (const [r, e] of cache) if (e.rev !== rev) cache.delete(r);
    const hit = cache.get(role);
    if (hit) return hit.value;
    const value = fetchRole(role).then(
      (v) => {
        if (declared.get(role)?.required) {
          resolved.set(role, v !== null);
          settle();
        }
        return v;
      },
      (e: unknown) => {
        if (cache.get(role)?.value === value) cache.delete(role); // an error is not cached: the next call asks again
        throw e;
      },
    );
    cache.set(role, { rev, value });
    return value;
  };

  return {
    async modelRole(role) {
      const r = declared.get(role);
      if (!r) throw new TbError("role_undeclared", `model role not declared in settings.modelRoles with usedBy "app": ${String(role)}`, 500);
      // `when` false: the role is not in force for this deployment (the bridge holds no requirement for it)
      if (!inForce().some((x) => x.role === role)) return null;
      const v = await resolve(role);
      return v ? { ...v } : null;
    },
    dropCache() {
      cache.clear();
      resolved.clear();
      settle();
    },
    async refresh() {
      for (const r of inForce()) {
        if (!r.required) continue;
        try {
          await resolve(r.role);
        } catch (e) {
          resolved.set(r.role, false);
          opts.log.debug("model role prefetch failed", { role: r.role, code: e instanceof TbError ? e.code : "error" });
        }
      }
      settle();
    },
    missing,
    attention() {
      const roles = missing();
      if (roles.length === 0) return null;
      return { code: "model_role_missing", reason: `Model role not set: ${roles.join(", ")}. Set it on the Keys and models page.` };
    },
  };
}
