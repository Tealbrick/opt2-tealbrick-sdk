// tb-exec configuration: the TB_* env of a companion service (SDK-API §13) + its entry in the app manifest.
import { readFileSync } from "node:fs";
import { manifestDigest, validateManifest } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest, Service } from "@opt2-tealbrick/spec/manifest";
import { readEnv, type SdkConfig } from "../server/env.ts";
import { TbError } from "../server/errors.ts";

export const SDK_VERSION: string = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;

/** Proxy variables of a role-bound service's env: a proxy would resolve the name itself and skip the endpoint check (BRIDGE §15.3). */
export const PROXY_ENV = /^(http_proxy|https_proxy|all_proxy|no_proxy)$/i;

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
  for (const [k, v] of Object.entries(base)) if (v !== undefined && !k.startsWith("TB_") && !(opts.stripProxy && PROXY_ENV.test(k))) out[k] = v;
  for (const [k, v] of keys) out[k] = v;
  return out;
}
