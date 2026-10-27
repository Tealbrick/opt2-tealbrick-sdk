// tb-exec configuration: the TB_* env of a companion service (SDK-API §13) + its entry in the app manifest.
import { readFileSync } from "node:fs";
import { isAbsolute, normalize } from "node:path";
import { manifestDigest, validateManifest } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest, Service } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { readEnv, type SdkConfig } from "../server/env.ts";
import { TbError } from "../server/errors.ts";

export const SDK_VERSION: string = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;

/**
 * Proxy variables of a role-bound service's env: a proxy would resolve the name itself and skip the endpoint check (BRIDGE §15.3).
 * EVERY name ending in `_proxy` (any case: HTTP_PROXY, GRPC_PROXY, PIP_PROXY, SOCKS_PROXY, GLOBAL_AGENT_HTTP_PROXY, NODE_USE_ENV_PROXY,
 * npm_config_proxy, npm_config_https_proxy ...), `proxy`, and `npm_config_*proxy`.
 */
export const PROXY_ENV = /_proxy$|^proxy$|^npm_config_.*proxy$/i;

export interface ExecConfig {
  env: SdkConfig;
  instanceId: InstanceId;
  service: Service;
  bridgeUrl: string;
  manifest: Manifest;
  manifestDigest: `sha256:${string}`;
}

/** Reads env + manifest; throws TbError `env_invalid` / `manifest_invalid` / `service_unknown`. */
export function loadExecConfig(env: Record<string, string | undefined>, manifestPath: string): ExecConfig {
  const cfg = readEnv(env);
  const svc = env.TB_SERVICE;
  if (!svc) throw new TbError("env_invalid", "TB_SERVICE is required", 500);
  if (!cfg.instanceId) throw new TbError("env_invalid", "TB_INSTANCE_ID is required", 500);
  if (!cfg.bridgeUrl) throw new TbError("env_invalid", "TB_BRIDGE_URL is required", 500);
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    throw new TbError("manifest_invalid", `cannot read the app manifest at ${manifestPath}`, 500);
  }
  const v = validateManifest(raw);
  if (!v.ok) throw new TbError("manifest_invalid", "the app manifest does not validate", 500, { errors: v.errors.slice(0, 20) });
  const service = v.manifest.runtime.services?.find((s) => s.id === svc);
  if (!service) throw new TbError("service_unknown", `manifest declares no service ${svc}`, 500);
  return { env: cfg, instanceId: cfg.instanceId, service, bridgeUrl: cfg.bridgeUrl, manifest: v.manifest, manifestDigest: manifestDigest(v.manifest) };
}

/** Child env: the container env minus every TB_* name (KEK, enrolment code stay with tb-exec), plus the keys. `stripProxy` (a role-bound service): minus HTTP(S)_PROXY, ALL_PROXY, NO_PROXY in any case. */
export function childEnv(base: Record<string, string | undefined>, keys: ReadonlyMap<string, string>, opts: { stripProxy?: boolean } = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(base)) if (v !== undefined && !k.startsWith("TB_")) out[k] = v;
  for (const [k, v] of keys) out[k] = v;
  // after the key and role env went in: a role env name can no more bring a proxy back (M-MR-4 refuses such names too)
  if (opts.stripProxy) for (const k of Object.keys(out)) if (PROXY_ENV.test(k)) delete out[k];
  return out;
}

/**
 * C373a: tb-exec's own service env (NOT `TB_*`: the manifest `envName` pattern refuses that prefix, so apps set these
 * through `runtime.services[].env` like any other value). tb-exec reads them from its container env; the child sees them too.
 */
export const EXEC_ENV = {
  /** decimal bytes; the cap of one streamed restore body (default {@link RESTORE_DEFAULT_MAX_BYTES}, hard bound {@link RESTORE_HARD_MAX_BYTES}) */
  restoreMaxBytes: "TBEXEC_RESTORE_MAX_BYTES",
  /** a path RELATIVE to TB_DATA_DIR (no `..`); the stats route reports its size, never its name */
  mainDataFile: "TBEXEC_MAIN_DATA_FILE",
} as const;

export const RESTORE_DEFAULT_MAX_BYTES = 512 * 1024 * 1024;
/** the hard upper bound in code: a larger env value clamps to this */
export const RESTORE_HARD_MAX_BYTES = 16 * 1024 * 1024 * 1024;

/** `TBEXEC_RESTORE_MAX_BYTES` → bytes: unset / empty / not a positive decimal integer → 512 MiB; above 16 GiB → 16 GiB. */
export function restoreMaxBytesFrom(env: Record<string, string | undefined>, log?: Logger): number {
  const raw = env[EXEC_ENV.restoreMaxBytes]?.trim();
  if (!raw) return RESTORE_DEFAULT_MAX_BYTES;
  const n = /^[0-9]{1,30}$/.test(raw) ? Number(raw) : Number.NaN;
  if (!(n > 0)) {
    log?.warn("restore cap env invalid; default used", { env: EXEC_ENV.restoreMaxBytes, bytes: RESTORE_DEFAULT_MAX_BYTES });
    return RESTORE_DEFAULT_MAX_BYTES;
  }
  if (n > RESTORE_HARD_MAX_BYTES) {
    log?.warn("restore cap env above the hard bound; clamped", { env: EXEC_ENV.restoreMaxBytes, bytes: RESTORE_HARD_MAX_BYTES });
    return RESTORE_HARD_MAX_BYTES;
  }
  return n;
}

/** `TBEXEC_MAIN_DATA_FILE` → the normalised relative path, or null (unset, absolute, or leaving the data dir). */
export function mainDataFileFrom(env: Record<string, string | undefined>, log?: Logger): string | null {
  const raw = env[EXEC_ENV.mainDataFile]?.trim();
  if (!raw) return null;
  const rel = normalize(raw);
  if (isAbsolute(rel) || rel === "." || rel.split(/[\\/]/).includes("..")) {
    log?.warn("main data file env invalid; ignored", { env: EXEC_ENV.mainDataFile });
    return null;
  }
  return rel;
}
