// tb-exec and model roles (BRIDGE §15.4, MANIFEST §7.1): a service whose manifest `settings.modelRoles[]` lists it with `env`
// gets each resolved binding as env vars (`provider`, `model`, `baseUrl`, `key`, `dims`; dims as a string). An unset optional
// role sets nothing. Values never reach a log; the key joins the secret registry.
import { createHash } from "node:crypto";
import { activeModelRoles, declaredModelRoles, MODEL_ROLE_ENV_FIELDS, type ModelRole, type ModelRoleEnv, settingsFromEnv } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";
import type { SecretRegistry } from "../server/log.ts";
import type { ServiceBridge } from "./bridge.ts";
import { retryable } from "./identity.ts";
import { sleep } from "./util.ts";

/** Settings this service's env carries: only these can be judged here (a `when` on another setting is the bridge's call). */
export function carriedSettings(manifest: Manifest, env: Record<string, string | undefined>): Set<string> {
  return new Set((manifest.runtime.env ?? []).filter((e) => "setting" in e && typeof e.setting === "string" && env[e.name] !== undefined).map((e) => e.setting as string));
}

export interface ExecRole {
  role: ModelRole;
  env: ModelRoleEnv;
  required: boolean;
  /** required AND certainly in force: the upstream waits for it (as for a required key) */
  blocking: boolean;
}

/**
 * The roles tb-exec resolves for `serviceId`: listed with `env`, `when` true for the settings this service's env carries.
 * A `when` on a setting the env does not carry is not judged: the role is asked for (the bridge answers `role_not_declared`
 * when it is not in force), but it never blocks the upstream.
 */
export function rolesInForce(manifest: Manifest, serviceId: string, env: Record<string, string | undefined>): ExecRole[] {
  const carried = carriedSettings(manifest, env);
  const certain = new Set(activeModelRoles(manifest, settingsFromEnv(manifest, env), serviceId).map((r) => r.role));
  const out: ExecRole[] = [];
  for (const r of declaredModelRoles(manifest)) {
    if (!r.usedBy.includes(serviceId) || !r.env) continue;
    const judged = !r.when || Object.keys(r.when).every((k) => carried.has(k));
    if (judged && !certain.has(r.role)) continue;
    out.push({ role: r.role, env: r.env, required: r.required, blocking: r.required && judged });
  }
  return out;
}

export interface FetchedRoles {
  /** env name → value (memory only) */
  values: Map<string, string>;
  /** `<envName>\0<sha256 of the value>\0` per delivered value, in order (the caller folds them into its fingerprint) */
  parts: string[];
  /** roles that did not resolve (unset, below policy, refused) */
  missing: ModelRole[];
  /** the missing roles the upstream must wait for */
  blocking: ModelRole[];
  rev: number;
}

export async function fetchRoles(roles: readonly ExecRole[], bridge: ServiceBridge, secrets: SecretRegistry, log: Logger, signal: AbortSignal): Promise<FetchedRoles> {
  const out: FetchedRoles = { values: new Map(), parts: [], missing: [], blocking: [], rev: 0 };
  for (const r of roles) {
    let delay = 1000;
    for (;;) {
      try {
        const b = await bridge.fetchModelRole(r.role, signal);
        if (!b) {
          out.missing.push(r.role);
          if (r.blocking) out.blocking.push(r.role);
        } else {
          out.rev = Math.max(out.rev, b.keysRev);
          if (b.key) secrets.add(b.key);
          const value: Record<(typeof MODEL_ROLE_ENV_FIELDS)[number], string | null> = { provider: b.provider, model: b.model, baseUrl: b.baseUrl, key: b.key, dims: b.dims === null ? null : String(b.dims) };
          for (const field of MODEL_ROLE_ENV_FIELDS) {
            const name = r.env[field];
            const v = value[field];
            if (name === undefined || v === null) continue;
            out.values.set(name, v);
            out.parts.push(`${name}\0${createHash("sha256").update(v, "utf8").digest("hex")}\0`);
          }
        }
        break;
      } catch (e) {
        if (signal.aborted) throw e;
        if (!retryable(e)) {
          log.warn("model role not delivered", { role: r.role, code: e instanceof TbError ? e.code : "model_role_fetch_failed" });
          out.missing.push(r.role);
          if (r.blocking) out.blocking.push(r.role);
          break;
        }
        await sleep(delay, signal);
        delay = Math.min(delay * 2, 30_000);
      }
    }
  }
  return out;
}
