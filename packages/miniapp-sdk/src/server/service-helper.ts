// `callServiceHelper(serviceId, path, body)` (SDK-API §11, C6, Coordinator C33): JSON POST to the app-owned helper that
// `tb-exec` runs inside a companion service, authenticated with an instance assertion (TB-Assert: htm, htu, bd).
import { type Ed25519KeyPair, signInstanceAssertion } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import { netCause } from "./net-cause.ts";

/** tb-exec control port (SDK-API §11), private network only. */
export const TB_EXEC_CONTROL_PORT = 7077 as const;

const HELPER_TIMEOUT_MS = 30_000;

export interface ServiceHelperContext {
  manifest: Manifest;
  env: Record<string, string | undefined>;
  instanceId: InstanceId;
  instanceKey: Ed25519KeyPair;
  bridgeId: () => BridgeId | null;
}

/**
 * Host of a companion service. SPEC-GAP: no env name carries a service's private address; the SDK reads the
 * runtime.env entry whose value templates `{{services.<id>.url}}` (or `.host`) and uses its host with `helper.port`.
 */
export function serviceHost(manifest: Manifest, env: Record<string, string | undefined>, serviceId: string): string | null {
  const entry = manifest.runtime.env?.find((e) => "value" in e && typeof e.value === "string" && new RegExp(`\\{\\{services\\.${serviceId}\\.(url|host)\\}\\}`).test(e.value));
  const raw = entry ? env[entry.name] : undefined;
  if (!raw) return null;
  try {
    return new URL(raw.includes("://") ? raw : `http://${raw}`).hostname || null;
  } catch {
    return null;
  }
}

export function createServiceHelperCaller(ctx: ServiceHelperContext): <O = Json>(serviceId: string, path: string, body: Json) => Promise<O> {
  return async <O = Json>(serviceId: string, path: string, body: Json): Promise<O> => {
    const svc = ctx.manifest.runtime.services?.find((s) => s.id === serviceId);
    if (!svc?.helper?.paths.includes(path)) throw new TbError("helper_path_undeclared", `helper path not declared: ${serviceId} ${path}`, 500);
    const host = serviceHost(ctx.manifest, ctx.env, serviceId);
    if (!host) throw new TbError("helper_unavailable", `no private address for service ${serviceId} (runtime.env {{services.${serviceId}.url}})`, 503);
    const bridge = ctx.bridgeId();
    if (!bridge) throw new TbError("no_bridge", "service helpers need a claimed instance", 503);
    const bytes = new TextEncoder().encode(JSON.stringify(body));
    const assertion = await signInstanceAssertion({ key: ctx.instanceKey, ins: ctx.instanceId, bridge, method: "POST", pathAndQuery: path, body: bytes, now: Math.floor(Date.now() / 1000) });
    let res: Response;
    try {
      res = await fetch(`http://${host.includes(":") ? `[${host}]` : host}:${svc.helper.port}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", accept: "application/json", [BRIDGE_HEADERS.assertion]: assertion },
        body: bytes,
        redirect: "error",
        signal: AbortSignal.timeout(HELPER_TIMEOUT_MS),
      });
    } catch (e) {
      // C390: the reason (refused, timeout, DNS, …) as a label, so a log tells the failures apart
      const cause = netCause(e);
      throw new TbError("helper_unavailable", `service helper ${serviceId} not reachable (${cause})`, 503, { cause });
    }
    const text = await res.text();
    let parsed: unknown = null;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      throw new TbError("helper_failed", `service helper ${serviceId} answered non-JSON`, 502);
    }
    if (!res.ok) throw errorFrom({ status: res.status, body: parsed }, "helper_failed");
    return parsed as O;
  };
}
