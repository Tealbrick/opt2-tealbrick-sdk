// The SDK's only client of the bridge internal API (BRIDGE §3.2, §8.3, §9.4, §10): every request after the claim
// carries an instance assertion in `TB-Assert` (htm, htu, bd).
import { type Ed25519KeyPair, signInstanceAssertion } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, BRIDGE_INTERNAL_PATHS, type ClaimRequest, type ClaimResponse, type ProofClaimCap } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import { TbError } from "./errors.ts";

export interface BridgeResponse {
  status: number;
  body: unknown;
  /** the raw `Retry-After` header, when the bridge sent one */
  retryAfter?: string;
}

const REQUEST_TIMEOUT_MS = 35_000;

/**
 * v0.1.36 (C268 B/C268c, spec 0.1.52): the optional call-proof claims this SDK's hook verifier accepts. The APP INSTANCE sends it in
 * its claim and in EVERY status push (also failed mode); the bridge adds `bd` to a hook proof only for an app that lists it. A service
 * (exec) never sends it. The route (bridge-routes.ts handleHook) hashes the raw body whenever a proof carries `bd`.
 */
export const SDK_PROOF_CLAIMS: readonly ProofClaimCap[] = ["bd"];

async function readBody(res: Response): Promise<unknown> {
  const text = await res.text();
  if (text === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

/** Error envelope → TbError (code passes through unchanged, CORE §8). */
export function errorFrom(r: BridgeResponse, fallback: string): TbError {
  const e = (r.body as { error?: { code?: unknown; message?: unknown } } | null)?.error;
  return new TbError(typeof e?.code === "string" ? e.code : fallback, typeof e?.message === "string" ? e.message : `bridge answered ${r.status}`, r.status >= 400 ? r.status : 502);
}

export class BridgeClient {
  readonly #base: string;
  readonly #ins: InstanceId;
  readonly #key: Ed25519KeyPair;
  readonly #bridge: () => BridgeId | null;

  constructor(opts: { baseUrl: string; instanceId: InstanceId; key: Ed25519KeyPair; bridgeId: () => BridgeId | null }) {
    this.#base = opts.baseUrl;
    this.#ins = opts.instanceId;
    this.#key = opts.key;
    this.#bridge = opts.bridgeId;
  }

  /** `POST /tb/v1/claim` — the K6 code authenticates (no assertion yet). */
  async claim(req: ClaimRequest, signal?: AbortSignal): Promise<BridgeResponse> {
    return this.#send("POST", BRIDGE_INTERNAL_PATHS.claim, req, {}, signal, false);
  }

  /** Assertion-signed request to the bridge internal listener. */
  async request(method: "GET" | "POST", pathAndQuery: string, body?: unknown, headers: Record<string, string> = {}, signal?: AbortSignal): Promise<BridgeResponse> {
    return this.#send(method, pathAndQuery, body, headers, signal, true);
  }

  async #send(method: "GET" | "POST", pathAndQuery: string, body: unknown, headers: Record<string, string>, signal: AbortSignal | undefined, assert: boolean): Promise<BridgeResponse> {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const h: Record<string, string> = { ...headers, accept: "application/json" };
    if (bytes) h["content-type"] = "application/json";
    if (assert) {
      const bridge = this.#bridge();
      if (!bridge) throw new TbError("needs_claim", "the instance has not claimed its bridge yet", 503);
      h[BRIDGE_HEADERS.assertion] = await signInstanceAssertion({
        key: this.#key,
        ins: this.#ins,
        bridge,
        method,
        pathAndQuery,
        body: bytes,
        now: Math.floor(Date.now() / 1000),
      });
    }
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS + (pathAndQuery.includes("wait=") ? 60_000 : 0));
    let res: Response;
    try {
      res = await fetch(this.#base + pathAndQuery, {
        method,
        headers: h,
        body: bytes,
        redirect: "error",
        signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
      });
    } catch (e) {
      if (signal?.aborted) throw e;
      throw new TbError("bridge_unavailable", "bridge not reachable", 503);
    }
    const retryAfter = res.headers.get("retry-after");
    return { status: res.status, body: await readBody(res), ...(retryAfter === null ? {} : { retryAfter }) };
  }
}

export type { ClaimResponse };
