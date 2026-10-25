// tb-exec's client of the bridge internal API (BRIDGE §9.4, §10): claim as a service, key fetch, status long-poll.
// Every request after the claim carries a service instance assertion (`TB-Assert`, `svc` = TB_SERVICE, htm/htu/bd).
import { DATA_POLICIES, type Ed25519KeyPair, MODEL_ROLES_PATH, type ModelRole, type ModelRoleFetchResponse, signInstanceAssertion } from "@opt2-tealbrick/manifest";
import { type AppStatus, type AppStatusResponse, BRIDGE_HEADERS, BRIDGE_INTERNAL_PATHS, type ClaimRequest, type ClaimResponse, type KeyFetchResponse } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import { TbError } from "../server/errors.ts";

const REQUEST_TIMEOUT_MS = 35_000;
export const STATUS_WAIT_S = 60;

export interface Reply {
  status: number;
  body: unknown;
}

/** Error envelope → TbError with the envelope's code (CORE §8); network failures → `bridge_unreachable`. */
export function replyError(r: Reply, fallback: string): TbError {
  const e = (r.body as { error?: { code?: unknown; message?: unknown } } | null)?.error;
  return new TbError(typeof e?.code === "string" ? e.code : fallback, typeof e?.message === "string" ? e.message : `bridge answered ${r.status}`, r.status);
}

export class ServiceBridge {
  readonly #base: string;
  readonly #ins: InstanceId;
  readonly #svc: string;
  readonly #key: Ed25519KeyPair;
  #bridge: BridgeId | null = null;

  constructor(opts: { baseUrl: string; instanceId: InstanceId; service: string; key: Ed25519KeyPair }) {
    this.#base = opts.baseUrl;
    this.#ins = opts.instanceId;
    this.#svc = opts.service;
    this.#key = opts.key;
  }

  setBridge(id: BridgeId): void {
    this.#bridge = id;
  }

  async claim(req: ClaimRequest, signal?: AbortSignal): Promise<ClaimResponse> {
    const r = await this.#send("POST", BRIDGE_INTERNAL_PATHS.claim, req, signal, false);
    if (r.status !== 200) throw replyError(r, "claim_failed");
    return r.body as ClaimResponse;
  }

  /** `GET /tb/v1/keys/<name>`; 404 `key_not_set` → null; other refusals throw. */
  async fetchKey(name: string, signal?: AbortSignal): Promise<KeyFetchResponse | null> {
    const r = await this.#send("GET", BRIDGE_INTERNAL_PATHS.keys.replace("{name}", encodeURIComponent(name)), undefined, signal, true);
    if (r.status === 200) {
      const b = r.body as KeyFetchResponse;
      if (typeof b?.value !== "string" || typeof b.keysRev !== "number") throw new TbError("bridge_invalid", "key fetch answer is malformed", 502);
      return b;
    }
    if (r.status === 404) return null;
    throw replyError(r, "key_fetch_failed");
  }

  /** `GET /tb/v1/model-roles/<role>` (BRIDGE §15.4); 404 (`role_not_set`) and 403 `role_policy_too_low` → null; other refusals throw. */
  async fetchModelRole(role: ModelRole, signal?: AbortSignal): Promise<ModelRoleFetchResponse | null> {
    const r = await this.#send("GET", MODEL_ROLES_PATH.replace("{role}", encodeURIComponent(role)), undefined, signal, true);
    if (r.status === 200) {
      const b = r.body as Partial<Record<keyof ModelRoleFetchResponse, unknown>> | null;
      if (b?.role !== role || typeof b.provider !== "string" || typeof b.model !== "string" || typeof b.keysRev !== "number" || !(DATA_POLICIES as readonly unknown[]).includes(b.dataPolicy)) {
        throw new TbError("bridge_invalid", "model role answer is malformed", 502);
      }
      return {
        role,
        provider: b.provider,
        model: b.model,
        baseUrl: typeof b.baseUrl === "string" ? b.baseUrl : null,
        key: typeof b.key === "string" ? b.key : null,
        dataPolicy: b.dataPolicy as ModelRoleFetchResponse["dataPolicy"],
        dims: typeof b.dims === "number" ? b.dims : null,
        keysRev: b.keysRev,
      };
    }
    if (r.status === 404) return null;
    if (r.status === 403 && replyError(r, "model_role_fetch_failed").code === "role_policy_too_low") return null;
    throw replyError(r, "model_role_fetch_failed");
  }

  /** `POST /tb/v1/status?wait=60`: 200 → new slice/keysRev, 204 → nothing changed. */
  async status(body: AppStatus, signal?: AbortSignal): Promise<AppStatusResponse | null> {
    const r = await this.#send("POST", `${BRIDGE_INTERNAL_PATHS.status}?wait=${STATUS_WAIT_S}`, body, signal, true, STATUS_WAIT_S * 1000);
    if (r.status === 204) return null;
    if (r.status === 200 && typeof (r.body as AppStatusResponse | null)?.keysRev === "number") return r.body as AppStatusResponse;
    throw replyError(r, "status_failed");
  }

  async #send(method: "GET" | "POST", pathAndQuery: string, body: unknown, signal: AbortSignal | undefined, assert: boolean, extraMs = 0): Promise<Reply> {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const h: Record<string, string> = { accept: "application/json" };
    if (bytes) h["content-type"] = "application/json";
    if (assert) {
      if (!this.#bridge) throw new TbError("needs_claim", "the service has not claimed yet", 503);
      h[BRIDGE_HEADERS.assertion] = await signInstanceAssertion({
        key: this.#key,
        ins: this.#ins,
        svc: this.#svc,
        bridge: this.#bridge,
        method,
        pathAndQuery,
        body: bytes,
        now: Math.floor(Date.now() / 1000),
      });
    }
    const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS + extraMs);
    let res: Response;
    try {
      res = await fetch(this.#base + pathAndQuery, { method, headers: h, body: bytes, redirect: "error", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
    } catch (e) {
      if (signal?.aborted) throw e;
      throw new TbError("bridge_unreachable", "the bridge cannot be reached", 503);
    }
    const text = await res.text();
    let parsed: unknown = null;
    if (text !== "") {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = null;
      }
    }
    return { status: res.status, body: parsed };
  }
}
