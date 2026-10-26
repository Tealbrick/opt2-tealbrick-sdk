// Keys (SDK-API §8, CORE §10, C2): app-own value (tb_keys, sealed under TB_KEK) wins over the workspace default
// fetched from the bridge (`GET /tb/v1/keys/<name>` with TB-Assert). Defaults are cached in memory until `keysRev`
// changes or the slice shows a pause. Values are never logged, returned to persons, or compared in clear.
// v0.1.63: the model-role bindings ride on the same revision (`modelRole`, ./model-roles.ts); `keysRev` is one number for both.

import { conditionHolds, settingsFromEnv } from "@opt2-tealbrick/manifest";
import { BRIDGE_INTERNAL_PATHS, type KeyFetchResponse } from "@opt2-tealbrick/spec/bridge";
import type { Condition, KeyRequirement, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, KeyApi, KeyStatus, Logger, PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import type { BridgeClient } from "./bridge-client.ts";
import { errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import type { SecretRegistry } from "./log.ts";
import { createModelRoles, type ModelRolesInternals } from "./model-roles.ts";
import type { Sealer } from "./secrets.ts";
import type { RawDb, Row } from "./store.ts";

const KEY_PURPOSE = "app-key";
const MAX_KEY_BYTES = 16 * 1024;

/**
 * `when` on a key: ONE evaluation (manifest package `conditionHolds` over `settingsFromEnv`): settings reach the app
 * only as env (`runtime.env[].setting`, C16 S6); a setting no env entry carries takes its manifest default.
 */
export function keyConditionHolds(when: Condition | undefined, manifest: Manifest, env: Record<string, string | undefined>): boolean {
  return conditionHolds(when, settingsFromEnv(manifest, env));
}

export interface KeysInternals extends KeyApi {
  /** v0.1.63: required model roles in force that do not resolve (readiness `needs_keys`) */
  rolesMissing: ModelRolesInternals["missing"];
  /** v0.1.63: `model_role_missing` attention while `rolesMissing()` is not empty */
  rolesAttention: ModelRolesInternals["attention"];
  set(principal: PersonPrincipal, name: string, value: string): Promise<void>;
  remove(principal: PersonPrincipal, name: string): Promise<void>;
  /** status long-poll returned a new keysRev */
  onKeysRev(rev: number): Promise<void>;
  /** slice shows a pause: drop cached default values */
  dropCache(): void;
  /** prefetch workspace defaults so health/readiness know presence */
  refresh(): Promise<void>;
  needsKeys(): boolean;
  keysRev(): number;
}

export function createKeys(opts: {
  db: RawDb;
  manifest: Manifest;
  env: Record<string, string | undefined>;
  sealer: Sealer;
  secrets: SecretRegistry;
  audit: AuditLog;
  log: Logger;
  bridge: () => BridgeClient | null;
  emit: (names: string[]) => Promise<void>;
  /** v0.1.63: what readiness knows about the model roles changed: push a status */
  rolesChanged?: () => void;
  /** the verified slice shows the workspace or this instance paused (C349): `getKey` and `modelRole` throw `paused` */
  paused?: () => boolean;
}): KeysInternals {
  const { db, manifest, sealer, secrets } = opts;
  const declared = new Map<string, KeyRequirement>((manifest.settings?.keys ?? []).filter((k) => k.usedBy.includes("app")).map((k) => [k.name, k]));
  const cache = new Map<string, string | null>();
  const listeners = new Set<(names: string[]) => void>();
  let rev = 0;
  const roles = createModelRoles({ manifest, env: opts.env, secrets, log: opts.log, bridge: opts.bridge, rev: () => rev, changed: opts.rolesChanged, paused: opts.paused });

  const req = (name: string): KeyRequirement => {
    const k = declared.get(name);
    if (!k) throw new TbError("key_undeclared", `key not declared in settings.keys with usedBy "app": ${name}`, 500);
    return k;
  };
  const appOwn = (name: string): string | null => {
    const row = db.prepare("SELECT sealed FROM tb_keys WHERE name = ?").get(name) as Row | undefined;
    if (!row) return null;
    try {
      return sealer.unsealText(KEY_PURPOSE, name, String(row.sealed));
    } catch {
      // §7.3: a restore into a deployment with another KEK drops app-own keys (status needs_keys)
      return null;
    }
  };
  const fetchDefault = async (name: string): Promise<string | null> => {
    if (cache.has(name)) return cache.get(name) ?? null;
    const client = opts.bridge();
    if (!client) return null;
    const r = await client.request("GET", BRIDGE_INTERNAL_PATHS.keys.replace("{name}", encodeURIComponent(name)));
    if (r.status === 404) {
      cache.set(name, null);
      return null;
    }
    if (r.status !== 200) throw errorFrom(r, "key_unavailable");
    const body = r.body as KeyFetchResponse;
    if (typeof body?.value !== "string") throw new TbError("key_unavailable", "bridge key answer malformed", 502);
    secrets.add(body.value);
    cache.set(name, body.value);
    return body.value;
  };
  const notify = async (names: string[]) => {
    for (const cb of listeners) {
      try {
        cb(names);
      } catch (e) {
        opts.log.warn("onKeysChanged listener failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    }
    await opts.emit(names);
  };
  const present = (k: KeyRequirement): { present: boolean; source: KeyStatus["source"] } => {
    if (db.prepare("SELECT 1 FROM tb_keys WHERE name = ?").get(k.name)) return { present: true, source: "app_own" };
    if (k.source === "account_default" && typeof cache.get(k.name) === "string") return { present: true, source: "account_default" };
    return { present: false, source: null };
  };

  return {
    modelFetch: async () => null, // until sdk#53 ships modelFetch: fail closed (no endpoint, no key read)
    async getKey(name) {
      if (opts.paused?.()) throw new TbError("paused", "this workspace or instance is paused", 403);
      const k = req(name);
      const own = appOwn(name);
      if (own !== null) {
        secrets.add(own);
        return own;
      }
      return k.source === "account_default" ? fetchDefault(name) : null;
    },
    modelRole: (role) => roles.modelRole(role),
    rolesMissing: roles.missing,
    rolesAttention: roles.attention,
    onKeysChanged(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
    async status() {
      return [...declared.values()].map((k) => ({ name: k.name, required: k.required && keyConditionHolds(k.when, manifest, opts.env), ...present(k) }));
    },
    async set(principal, name, value) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can set keys", 403);
      req(name);
      if (typeof value !== "string" || value.length === 0 || Buffer.byteLength(value) > MAX_KEY_BYTES) throw new TbError("key_invalid", "key value must be 1..16384 bytes", 400);
      db.prepare("INSERT INTO tb_keys (name, sealed, updated_at) VALUES (?, ?, ?) ON CONFLICT (name) DO UPDATE SET sealed = excluded.sealed, updated_at = excluded.updated_at").run(
        name,
        sealer.sealText(KEY_PURPOSE, name, value),
        Date.now(),
      );
      secrets.add(value);
      await opts.audit.record({ actor: principal.id, action: "key.set", target: name, detail: { name } });
      await notify([name]);
    },
    async remove(principal, name) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can delete keys", 403);
      req(name);
      db.prepare("DELETE FROM tb_keys WHERE name = ?").run(name);
      await opts.audit.record({ actor: principal.id, action: "key.delete", target: name, detail: { name } });
      await notify([name]);
    },
    async onKeysRev(next) {
      if (next === rev) return;
      rev = next;
      cache.clear();
      await this.refresh();
      // the callbacks below may call modelRole(): the role cache is keyed by `rev`, so they already read fresh bindings
      await notify([...declared.values()].filter((k) => k.source === "account_default").map((k) => k.name));
    },
    dropCache() {
      cache.clear();
      roles.dropCache();
    },
    async refresh() {
      for (const k of declared.values()) {
        if (k.source !== "account_default") continue;
        try {
          await fetchDefault(k.name);
        } catch (e) {
          opts.log.debug("key prefetch failed", { name: k.name, code: e instanceof TbError ? e.code : "error" });
        }
      }
      await roles.refresh();
    },
    needsKeys() {
      return [...declared.values()].some((k) => k.required && keyConditionHolds(k.when, manifest, opts.env) && !present(k).present);
    },
    keysRev: () => rev,
  };
}
