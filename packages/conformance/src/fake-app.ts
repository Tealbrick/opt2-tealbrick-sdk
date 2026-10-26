// Fake app for the bridge target (CONFORMANCE §3): an app instance generated from a manifest, built on node:http and
// @opt2-tealbrick/manifest only. As the SDK would, it re-verifies every grant and call proof (CORE §8: op proofs bind
// op / input / context / grant jti, hook proofs bind hook / phase, bridge-op proofs bind bop / body) and records every
// request with its verdict. It also acts as the instance towards the bridge internal surface (claim, status, key
// fetch, companion call) with its own Ed25519 key (K8). Behaviour per op / hook / bridge op is set by the checks.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  bridgeOpBinding,
  digest,
  type Ed25519KeyPair,
  generateKeyPair,
  manifestDigest,
  memoryReplayGuard,
  signInstanceAssertion,
  verifyBridgeOpProof,
  verifyCallProof,
  verifyGrant,
  verifyHookProof,
} from "@opt2-tealbrick/manifest";
import { type AppStatus, BRIDGE_HEADERS, type CallEnvelope, type ClaimRequest, type JsonObject } from "@opt2-tealbrick/spec/bridge";
import { BRIDGE_OP_PATH, type BridgeId, type BridgeOp, type InstanceId, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { HookPhase, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, KeySet, TrustContext } from "@opt2-tealbrick/spec/sdk";
import { closeServer, type HttpAnswer, header, listen, readRaw, request, sendError, sendJson } from "./http.ts";
import { newId, nowS, peek } from "./tokens.ts";

/** What the fake app needs from the run: current trust material and a global event order. */
export interface FakeAppWorld {
  ws: WorkspaceId;
  bridge: BridgeId;
  /** keys trusted for grants / slices (Portal keys, or the standalone bridge issuer after handover) */
  issuers(): KeySet;
  /** keys trusted for call proofs (the enrolled bridge key) */
  bridgeKeys(): KeySet;
  revokedJtis(): ReadonlySet<string>;
  /** strictly increasing event counter shared by every fake (hook order assertions) */
  seq(): number;
  /** bridge internal listener origin */
  bridgeInternalUrl(): string;
}

export type ReceivedKind = "op" | "hook" | "bridge_op" | "ui" | "public" | "manifest" | "health" | "person_op" | "other";

export interface Received {
  seq: number;
  at: number;
  kind: ReceivedKind;
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  /** op / hook id / bop */
  name: string;
  /** proof variant seen in TB-Call: `op` (gjti), `hook`, `bop`, or null when absent / unreadable */
  variant: "op" | "hook" | "bop" | null;
  /** re-verification result (ops: proof + grant; hooks: hook proof; bridge ops: bridge-op proof) */
  verified: boolean;
  reason: string;
  /** verified claims (grant for ops) */
  grant?: Record<string, unknown>;
  proof?: Record<string, unknown>;
  /** conformance 0.1.31 (BRIDGE §16): the exact body bytes of a relayed person op (`kind: "person_op"`) */
  raw?: Buffer;
}

export interface OpInfo {
  op: string;
  input: Json;
  context: JsonObject;
  idempotencyKey?: string;
  /** call id from the verified proof */
  call: string;
  grantSub: string;
  /** verified grant claims (v0.1.19 C111a: the app applies the forwarded grant's caps / wf) */
  grant: Record<string, unknown>;
  /** verified op proof claims (`hv` = a before hook's hold verdict, v0.1.13 G1) */
  proof: Record<string, unknown>;
}
export type OpAnswerSpec = { status: number; body: unknown };
export type OpHandler = (info: OpInfo) => Promise<OpAnswerSpec> | OpAnswerSpec;
/**
 * conformance 0.1.31 (BRIDGE §16): answer to a relayed person op (`POST /tb/v1/person-op`). The fake does not verify K14 (the
 * bridge rows check what the bridge forwards); `holdMs` = answer only after that long (a forward that times out).
 */
export type PersonOpHandler = (rec: Received) => Promise<OpAnswerSpec & { holdMs?: number }> | (OpAnswerSpec & { holdMs?: number });
/** `null` = never answer (timeout test); otherwise status + JSON body */
export type HookHandler = (hookId: string, phase: HookPhase, body: Record<string, unknown>) => Promise<OpAnswerSpec | null> | OpAnswerSpec | null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function variantOf(token: string | undefined): Received["variant"] {
  const c = token ? peek(token) : null;
  if (!c) return null;
  if ("gjti" in c) return "op";
  if ("hook" in c) return "hook";
  if ("bop" in c) return "bop";
  return null;
}

export class FakeApp {
  url = "";
  readonly ins: InstanceId;
  readonly manifest: Manifest;
  readonly digest: string;
  readonly received: Received[] = [];
  key!: Ed25519KeyPair;
  /** per-op behaviour; default answers 200 ok with an echo carrying `marker` */
  onOp: OpHandler | null = null;
  /** per-hook behaviour; default: before allows, context adds nothing, after passes */
  onHook: HookHandler | null = null;
  /** conformance 0.1.31: relayed person ops; default answers 200 ok with an empty output */
  onPersonOp: PersonOpHandler | null = null;
  /** bridge-op answers */
  catalog: (body: Record<string, unknown>) => unknown = () => [];
  resolve: (body: Record<string, unknown>) => unknown = () => ({});
  scopeSummary: () => unknown = () => [];
  marker = "";
  readonly #world: FakeAppWorld;
  readonly #replay = memoryReplayGuard();
  readonly #server = createServer((req, res) => void this.#handle(req, res));

  private constructor(manifest: Manifest, world: FakeAppWorld, ins: InstanceId) {
    this.manifest = manifest;
    this.ins = ins;
    this.digest = manifestDigest(manifest);
    this.#world = world;
  }

  static async create(manifest: Manifest, world: FakeAppWorld, ins: InstanceId = newId("ins") as InstanceId): Promise<FakeApp> {
    const a = new FakeApp(manifest, world, ins);
    a.key = await generateKeyPair();
    a.url = await listen(a.#server);
    return a;
  }

  get product(): string {
    return this.manifest.id;
  }

  trust(): TrustContext {
    const w = this.#world;
    return { now: nowS(), self: `tb:ins:${this.ins}`, ws: w.ws, bridge: w.bridge, issuers: w.issuers(), bridgeKeys: w.bridgeKeys(), revokedJtis: w.revokedJtis() };
  }

  of(kind: ReceivedKind, name?: string): Received[] {
    return this.received.filter((r) => r.kind === kind && (name === undefined || r.name === name));
  }

  close(): Promise<void> {
    return this.#server.listening ? closeServer(this.#server) : Promise.resolve();
  }

  /** v0.1.24 (C117, B27.hook_app_down): the app goes down — its listener closes, connections are refused. */
  async stop(): Promise<void> {
    if (this.#server.listening) await closeServer(this.#server);
  }

  /** Brings a stopped app up again on the same origin (`url` unchanged). */
  async start(): Promise<void> {
    if (this.#server.listening) return;
    await listen(this.#server, Number(new URL(this.url).port));
  }

  get up(): boolean {
    return this.#server.listening;
  }

  // ── server side (what the bridge calls) ──────────────────────────────────────
  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    const raw = await readRaw(req).catch(() => Buffer.alloc(0));
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
    const proof = header(req, BRIDGE_HEADERS.callProof);
    const rec: Received = {
      seq: this.#world.seq(),
      at: Date.now(),
      kind: "other",
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers,
      body: raw.toString("utf8"),
      name: "",
      variant: variantOf(proof),
      verified: false,
      reason: "",
    };
    this.received.push(rec);
    let body: unknown;
    try {
      body = raw.length ? JSON.parse(raw.toString("utf8")) : undefined;
    } catch {
      body = undefined;
    }
    try {
      if (req.method === "GET" && path === "/tb/v1/manifest") {
        rec.kind = "manifest";
        return sendJson(res, 200, this.manifest);
      }
      if (req.method === "GET" && path === "/tb/v1/health") {
        rec.kind = "health";
        return sendJson(res, 200, { status: "ok", manifestDigest: this.digest, version: this.manifest.version });
      }
      if (req.method === "POST" && path === "/tb/v1/person-op") return await this.#personOp(rec, raw, res);
      const op = /^\/tb\/v1\/ops\/([A-Za-z0-9_.-]+)$/.exec(path);
      if (req.method === "POST" && op) return await this.#op(rec, op[1] as string, proof, header(req, "authorization"), body, res);
      const hook = /^\/tb\/v1\/hooks\/([a-z0-9_]+)$/.exec(path);
      if (req.method === "POST" && hook) return await this.#hook(rec, hook[1] as string, proof, body, res);
      const bop = /^\/tb\/v1\/bridge\/([a-z-]+)$/.exec(path);
      if (req.method === "POST" && bop) return this.#bridgeOp(rec, bop[1] as string, proof, body, res);
      if (path.startsWith(`/a/${this.product}/`) || path === `/a/${this.product}`) {
        rec.kind = "ui";
        rec.name = path.slice(`/a/${this.product}`.length) || "/";
        return sendJson(res, 200, { ui: true, path: rec.name });
      }
      if (path.startsWith(`/p/${this.product}/`)) {
        rec.kind = "public";
        rec.name = path;
        return sendJson(res, 200, { public: true });
      }
      sendError(res, 404, "not_found", "no such route");
    } catch (e) {
      rec.reason = e instanceof Error ? e.message : String(e);
      sendError(res, 500, "internal", "fake app error");
    }
  }

  async #op(rec: Received, opId: string, proof: string | undefined, authorization: string | undefined, body: unknown, res: ServerResponse): Promise<void> {
    rec.kind = "op";
    rec.name = opId;
    const grant = /^Bearer (\S+)$/.exec(authorization ?? "")?.[1];
    if (!grant) {
      rec.reason = "no grant";
      return sendError(res, 403, "grant_invalid", "grant required");
    }
    const trust = this.trust();
    const g = verifyGrant(grant, trust);
    if (!g.ok) {
      rec.reason = `grant: ${g.code} ${g.reason}`;
      return sendError(res, 403, g.code, "grant refused");
    }
    rec.grant = g.claims as unknown as Record<string, unknown>;
    if (!isObj(body) || !isObj(body.context) || !("input" in body)) {
      rec.reason = "body shape";
      return sendError(res, 400, "input_invalid", "body must be {input, context}");
    }
    const input = body.input as Json;
    const context = body.context as JsonObject;
    const p = verifyCallProof(
      proof ?? "",
      trust,
      { op: opId, inputDigest: digest(input), contextDigest: digest(context as Json), grantJti: g.claims.jti, grantSub: g.claims.sub },
      this.#replay,
    );
    if (!p.ok) {
      rec.reason = `proof: ${p.code} ${p.reason}`;
      return sendError(res, 401, "call_proof_invalid", "call proof refused");
    }
    rec.proof = p.claims as unknown as Record<string, unknown>;
    rec.verified = true;
    const info: OpInfo = {
      op: opId,
      input,
      context,
      ...(typeof body.idempotencyKey === "string" ? { idempotencyKey: body.idempotencyKey } : {}),
      call: String(p.claims.call),
      grantSub: g.claims.sub,
      grant: g.claims as unknown as Record<string, unknown>,
      proof: p.claims as unknown as Record<string, unknown>,
    };
    const a = this.onOp ? await this.onOp(info) : { status: 200, body: { status: "ok", output: { op: opId, marker: this.marker } } };
    sendJson(res, a.status, a.body);
  }

  async #personOp(rec: Received, raw: Buffer, res: ServerResponse): Promise<void> {
    rec.kind = "person_op";
    rec.raw = Buffer.from(raw);
    rec.name = String(peek(rec.headers["tb-person-op"] ?? "")?.op ?? "");
    const a = this.onPersonOp ? await this.onPersonOp(rec) : { status: 200, body: { status: "ok", output: {} } };
    if (a.holdMs) {
      await sleep(a.holdMs);
      if (res.destroyed) return;
    }
    sendJson(res, a.status, a.body);
  }

  async #hook(rec: Received, hookId: string, proof: string | undefined, body: unknown, res: ServerResponse): Promise<void> {
    rec.kind = "hook";
    rec.name = hookId;
    const declared = (this.manifest.hooks ?? []).find((h) => h.id === hookId);
    if (!declared || !isObj(body) || body.phase !== declared.phase || !isObj(body.context)) {
      rec.reason = "undeclared hook or bad envelope";
      return sendError(res, 400, "input_invalid", "hook envelope");
    }
    const call = isObj(body.call) ? body.call : {};
    const p = verifyHookProof(
      proof ?? "",
      this.trust(),
      { hook: hookId, phase: declared.phase, contextDigest: digest(body.context as Json), ...("input" in call ? { inputDigest: digest(call.input as Json) } : {}) },
      this.#replay,
    );
    if (!p.ok) {
      rec.reason = `proof: ${p.code} ${p.reason}`;
      return sendError(res, 401, "call_proof_invalid", "hook proof refused");
    }
    rec.proof = p.claims as unknown as Record<string, unknown>;
    rec.verified = true;
    const a = this.onHook ? await this.onHook(hookId, declared.phase, body) : null;
    if (a === null && this.onHook) {
      await sleep(5000);
      if (!res.destroyed) sendJson(res, 200, declared.phase === "before" ? { allow: true } : declared.phase === "context" ? { add: {} } : {});
      return;
    }
    const dflt = declared.phase === "before" ? { allow: true } : declared.phase === "context" ? { add: {} } : {};
    sendJson(res, a?.status ?? 200, a?.body ?? dflt);
  }

  #bridgeOp(rec: Received, path: string, proof: string | undefined, body: unknown, res: ServerResponse): void {
    rec.kind = "bridge_op";
    const bop = (Object.entries(BRIDGE_OP_PATH).find(([, p]) => p === path)?.[0] ?? "") as BridgeOp | "";
    rec.name = bop || path;
    if (!bop || !isObj(body)) {
      rec.reason = "unknown bridge op or body";
      sendError(res, 404, "not_found", "no such bridge op");
      return;
    }
    // C91: THE binding rule (manifest bridgeOpBinding): catalog {bop, op}, resolve {bop, op, in}, mark {bop, in},
    // scope_summary {bop} — a proof binding more or fewer claims is refused, as the SDK refuses it
    const p = verifyBridgeOpProof(proof ?? "", this.trust(), bridgeOpBinding(bop, body as Json), this.#replay);
    if (!p.ok) {
      rec.reason = `proof: ${p.code} ${p.reason}`;
      sendError(res, 401, "call_proof_invalid", "bridge-op proof refused");
      return;
    }
    if (typeof body.op === "string" && !this.manifest.operations.some((o) => o.id === body.op)) {
      rec.reason = "op not declared";
      sendError(res, 400, "input_invalid", "op not declared");
      return;
    }
    rec.proof = p.claims as unknown as Record<string, unknown>;
    rec.verified = true;
    const out = bop === "catalog" ? this.catalog(body) : bop === "resolve" ? this.resolve(body) : bop === "scope_summary" ? this.scopeSummary() : { marked: true };
    sendJson(res, 200, out);
  }

  // ── instance side (what the app calls at the bridge internal listener) ──────
  async #assert(method: string, pathAndQuery: string, body?: Uint8Array): Promise<string> {
    return signInstanceAssertion({ key: this.key, ins: this.ins, bridge: this.#world.bridge, method, pathAndQuery, ...(body ? { body } : {}), now: nowS() });
  }

  claim(code: string, override: Partial<ClaimRequest> = {}, key: Ed25519KeyPair = this.key): Promise<HttpAnswer> {
    const body: ClaimRequest = { code, instancePublicKey: key.publicJwk, manifestDigest: this.digest as ClaimRequest["manifestDigest"], version: this.manifest.version, sdkVersion: `${this.manifest.sdkMajor}.0.0`, ...override };
    return request(`${this.#world.bridgeInternalUrl()}/tb/v1/claim`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  }

  async status(s: Partial<AppStatus> = {}, wait = 0): Promise<HttpAnswer> {
    const body: AppStatus = { readiness: "ready", version: this.manifest.version, sdkVersion: `${this.manifest.sdkMajor}.0.0`, scopesRev: 1, sliceRevision: 0, keysRev: 0, pendingHolds: 0, ...s };
    const path = `/tb/v1/status?wait=${wait}`;
    const raw = new TextEncoder().encode(JSON.stringify(body));
    return request(`${this.#world.bridgeInternalUrl()}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", [BRIDGE_HEADERS.assertion]: await this.#assert("POST", path, raw) },
      body: raw,
      timeoutMs: (wait + 15) * 1000,
    });
  }

  async fetchKey(name: string, assert = true): Promise<HttpAnswer> {
    const path = `/tb/v1/keys/${encodeURIComponent(name)}`;
    return request(`${this.#world.bridgeInternalUrl()}${path}`, { headers: assert ? { [BRIDGE_HEADERS.assertion]: await this.#assert("GET", path) } : {} });
  }

  /** conformance 0.1.28 (BRIDGE §14.1): `POST /tb/v1/events` with this instance's assertion (htm, htu, bd). */
  async postEvents(items: unknown[]): Promise<HttpAnswer> {
    const path = "/tb/v1/events";
    const raw = new TextEncoder().encode(JSON.stringify({ items }));
    return request(`${this.#world.bridgeInternalUrl()}${path}`, {
      method: "POST",
      headers: { "content-type": "application/json", [BRIDGE_HEADERS.assertion]: await this.#assert("POST", path, raw) },
      body: raw,
      timeoutMs: 40_000,
    });
  }

  async companion(env: CallEnvelope, grant: string | null): Promise<HttpAnswer> {
    const path = "/tb/v1/call";
    const raw = new TextEncoder().encode(JSON.stringify(env));
    return request(`${this.#world.bridgeInternalUrl()}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        [BRIDGE_HEADERS.assertion]: await this.#assert("POST", path, raw),
        ...(grant !== null ? { [BRIDGE_HEADERS.companionGrant]: grant } : {}),
      },
      body: raw,
      timeoutMs: 40_000,
    });
  }
}
