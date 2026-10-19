// Drives an app the way the bridge does (CORE §8, BRIDGE §8.1 step 10, §9.1): op calls with a grant + `TB-Call` op
// proof, hook calls with a hook proof, bridge ops with a bridge-op proof, and person launch (K11) + session + person
// ops. Every call can be tampered with in one named way so negative cases stay one line in the checks.
import { bridgeOpProofClaims, DEFAULT_HELD_FAMILIES, type Ed25519KeyPair, hookCallerRef, ulid, withStandardOps } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, BRIDGE_OP_PATH, type BridgeOp, type CallId, type FreeCaps, type HoldVerdictClaim, type InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { AgentMode, CrudAction, HoldFamily, HookPhase } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import type { FakeBridge } from "./fake-bridge.ts";
import { errorCode, type HttpAnswer, request } from "./http.ts";
import { newId, nowS, peek, rawSign } from "./tokens.ts";

/** One named deviation from a correct bridge call (negative cases). */
export type OpTamper =
  | "input"
  | "context"
  | "op"
  | "gjti"
  | "sub"
  | "no_proof"
  | "no_grant"
  | "proof_key"
  | "proof_aud"
  | "proof_aud_missing"
  | "proof_expired"
  | "grant_key"
  | "grant_aud"
  | "grant_aud_missing"
  | "grant_aud_array"
  | "grant_expired"
  | "grant_future"
  | "grant_ws"
  | "grant_cnf";

export interface CallOptions {
  /** calling agent (default: the first fake agent) */
  agent?: AgentId;
  /** companion caller instance instead of an agent */
  caller?: InstanceId;
  crud?: CrudAction[];
  mode?: AgentMode;
  /** grant `held` (default: an agent card's DEFAULT_HELD_FAMILIES; an app caller: the workspace apps policy, CORE I8) */
  held?: readonly (HoldFamily | (string & {}))[];
  caps?: FreeCaps;
  wf?: string[];
  context?: Record<string, Json>;
  idempotencyKey?: string;
  tamper?: OpTamper;
  /** replaces the minted grant / proof / Authorization value (typ confusion, person credentials) */
  grant?: string;
  proof?: string;
  authorization?: string;
  headers?: Record<string, string>;
  /** grant signing key override (key rotation cases) */
  grantKey?: Ed25519KeyPair;
  /** v0.1.13 (G1): the op proof carries this before-hook hold verdict (`hv`) */
  hv?: HoldVerdictClaim;
  /** spec 0.1.46 (GRANT-PRD): the companion grant (`caller` only) carries `prd` = this product, as Portal Core's grants do */
  prd?: string;
}

export interface SentRequest {
  path: string;
  headers: Record<string, string>;
  body: string;
}

export interface OpAnswer extends HttpAnswer {
  code: string | null;
  grant: string;
  proof: string;
  callId: string | null;
  sent: SentRequest;
}

/** One named deviation from a correct hook call (negative cases); `input` changes `call.input` after signing. */
export type HookTamper = "no_proof" | "proof_key" | "phase" | "context" | "input" | "op_proof";

export interface HookAnswer extends HttpAnswer {
  code: string | null;
  sent: SentRequest;
}

export interface PersonSession {
  cookie: string;
  csrf: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** SDK-API §5: browser pages (the launch form POST) may answer HTML that shows the same error codes. */
const PERSON_CODES = /\b(ticket_invalid|ticket_used|session_required|csrf_invalid)\b/;
function htmlPersonCode(a: HttpAnswer): string | null {
  if (!(a.headers.get("content-type") ?? "").includes("text/html")) return null;
  return PERSON_CODES.exec(a.text)?.[1] ?? null;
}

/** Changes one value of `input` while keeping its shape (a schema-valid tamper where possible). */
export function tamperValue(input: Json): Json {
  if (isObj(input)) {
    const out: Record<string, Json> = { ...(input as Record<string, Json>) };
    for (const [k, v] of Object.entries(out)) {
      if (typeof v === "string") return { ...out, [k]: `${v}-tampered` };
      if (typeof v === "number") return { ...out, [k]: v + 1 };
      if (typeof v === "boolean") return { ...out, [k]: !v };
    }
    return { ...out, tb_conformance_tamper: true };
  }
  return { tampered: input };
}

export class AppClient {
  readonly #b: FakeBridge;
  readonly url: string;
  readonly #ops: OperationView[];

  constructor(bridge: FakeBridge, url: string) {
    this.#b = bridge;
    this.url = url;
    this.#ops = withStandardOps(bridge.manifest);
  }

  get personBase(): string {
    return `/a/${this.#b.manifest.id}`;
  }

  opView(id: string): OperationView | undefined {
    return this.#ops.find((o) => o.id === id);
  }

  async #send(method: string, path: string, headers: Record<string, string>, body?: string): Promise<HttpAnswer> {
    this.#b.capture({ dir: "app-out", method, path, headers, body: body ?? "" });
    const a = await request(this.url + path, { method, headers, ...(body !== undefined ? { body } : {}) });
    const h: Record<string, string> = {};
    a.headers.forEach((v, k) => {
      h[k] = v;
    });
    this.#b.capture({ dir: "app-in", method, path, headers: h, body: a.text });
    return a;
  }

  get(path: string, headers: Record<string, string> = {}): Promise<HttpAnswer> {
    return this.#send("GET", path, headers);
  }
  post(path: string, body: string, headers: Record<string, string> = {}): Promise<HttpAnswer> {
    return this.#send("POST", path, { "content-type": "application/json", ...headers }, body);
  }

  // ── op calls ──────────────────────────────────────────────────────────────
  async callOp(op: string, input: Json, opts: CallOptions = {}): Promise<OpAnswer> {
    const b = this.#b;
    const m = b.mint;
    const view = this.opView(op);
    const agentId = opts.agent ?? b.ids.agents[0].id;
    const agent = b.ids.agents.find((a) => a.id === agentId);
    const sub = opts.caller ? (`tb:ins:${opts.caller}` as const) : (`tb:agt:${agentId}` as const);
    const mode = opts.mode ?? (opts.caller ? "bound" : (agent?.mode ?? "free"));
    const aud = `tb:ins:${b.ids.ins}` as const;
    const context: Record<string, Json> = opts.context ?? {};
    const t = opts.tamper;
    const now = nowS();
    const other = `tb:ins:${newId("ins")}` as `tb:ins:${InstanceId}`;
    const grantSpec = {
      sub,
      aud,
      crud: opts.crud ?? view?.crud ?? ["read"],
      mode,
      // v0.1.15 (C105 / C105a, L1): a new agent card holds DEFAULT_HELD_FAMILIES; a companion grant holds appsPolicy.held
      held: opts.held ?? (opts.caller ? [...b.appsPolicy.held] : [...DEFAULT_HELD_FAMILIES]),
      caps: opts.caps ?? {},
      wf: opts.wf ?? (mode === "bound" ? [op] : []),
      ...(opts.grantKey ? { key: opts.grantKey } : {}),
      ...(opts.caller && opts.prd !== undefined ? { prd: opts.prd } : {}),
    };
    let grant = opts.grant;
    if (grant === undefined) {
      if (t === "grant_aud_missing" || t === "grant_aud_array") {
        const g = peek(await m.grant(grantSpec)) as Record<string, unknown>;
        if (t === "grant_aud_missing") delete g.aud;
        else g.aud = [aud];
        grant = await rawSign({ alg: "EdDSA", typ: "tb-grant+jwt", kid: b.activePortalKey().kid }, g, b.activePortalKey());
      } else {
        grant = await m.grant({
          ...grantSpec,
          ...(t === "grant_key" ? { key: b.stranger } : {}),
          ...(t === "grant_aud" ? { aud: other } : {}),
          ...(t === "grant_expired" ? { iat: now - 43200 - 120, exp: now - 120 } : {}),
          ...(t === "grant_future" ? { iat: now + 600 } : {}),
          ...(t === "grant_ws" ? { ws: newId("ws") as `ws_${string}` } : {}),
          ...(t === "grant_cnf" ? { brg: newId("brg") as `brg_${string}` } : {}),
        });
      }
    }
    const gjti = String(peek(grant)?.jti ?? ulid());
    const sentInput = t === "input" ? tamperValue(input) : input;
    const sentContext = t === "context" ? { ...context, "tb-conformance.tampered": true } : context;
    let proof = opts.proof;
    if (proof === undefined && t !== "no_proof") {
      const otherOp = this.#ops.find((o) => o.id !== op && o.audience === "agent")?.id ?? "tb.hold_status";
      const p = {
        sub: t === "sub" ? `tb:agt:${b.ids.agents.find((a) => a.id !== agentId)?.id ?? newId("agt")}` : sub,
        aud: t === "proof_aud" ? other : aud,
        gjti: t === "gjti" ? ulid() : gjti,
        op: t === "op" ? otherOp : op,
        input,
        context,
        ...(t === "proof_key" ? { key: b.stranger } : {}),
        ...(t === "proof_expired" ? { iat: now - 200, exp: now - 140 } : {}),
        ...(opts.hv ? { hv: opts.hv } : {}),
      };
      proof = await m.callProof(p);
      if (t === "proof_aud_missing") {
        const c = peek(proof) as Record<string, unknown>;
        delete c.aud;
        proof = await rawSign({ alg: "EdDSA", typ: "tb-call+jwt", kid: b.bridgeKeys[0].kid }, c, b.bridgeKeys[0]);
      }
    }
    const headers: Record<string, string> = { "content-type": "application/json", ...(opts.headers ?? {}) };
    const authorization = opts.authorization ?? (t === "no_grant" ? undefined : `Bearer ${grant}`);
    if (authorization !== undefined) headers.authorization = authorization;
    if (proof !== undefined) headers[BRIDGE_HEADERS.callProof.toLowerCase()] = proof;
    const body = JSON.stringify({ input: sentInput, context: sentContext, ...(opts.idempotencyKey !== undefined ? { idempotencyKey: opts.idempotencyKey } : {}) });
    const path = `/tb/v1/ops/${encodeURIComponent(op)}`;
    const a = await this.#send("POST", path, headers, body);
    return { ...a, code: errorCode(a.body), grant, proof: proof ?? "", callId: proof ? String(peek(proof)?.call ?? "") : null, sent: { path, headers, body } };
  }

  /** Re-sends an earlier op or hook request byte for byte (proof replay, C6). */
  async resend<T extends HttpAnswer & { code: string | null; sent: SentRequest }>(prev: T): Promise<T> {
    const a = await this.#send("POST", prev.sent.path, prev.sent.headers, prev.sent.body);
    return { ...prev, ...a, code: errorCode(a.body) };
  }

  // ── hooks ─────────────────────────────────────────────────────────────────
  async callHook(
    hookId: string,
    phase: HookPhase,
    req: { call: Record<string, Json>; context?: Record<string, Json>; output?: Json },
    opts: { tamper?: HookTamper } = {},
  ): Promise<HookAnswer> {
    const b = this.#b;
    const context = req.context ?? {};
    // C268 A (spec 0.1.50, SDK >= 0.1.35): the proof `sub` is the CALLER ref of the request body and the proof `call` the id of the
    // request, exactly as the bridge signs them. A caller that is not an agent or an app instance falls back to agent A.
    const callerRef = hookCallerRef(req.call.caller);
    const sub = callerRef === "" ? `tb:agt:${b.ids.agents[0].id}` : callerRef;
    const callId = typeof req.call.id === "string" ? (req.call.id as CallId) : undefined;
    const aud = `tb:ins:${b.ids.ins}` as const;
    const t = opts.tamper;
    const call = t === "input" && req.call.input !== undefined ? { ...req.call, input: tamperValue(req.call.input) } : req.call;
    const body: Record<string, Json> = { phase, call, context: t === "context" ? { ...context, "tb-conformance.tampered": true } : context };
    if (phase === "after") body.output = req.output ?? {};
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (t !== "no_proof") {
      headers[BRIDGE_HEADERS.callProof.toLowerCase()] =
        t === "op_proof"
          ? await b.mint.callProof({ sub, aud, gjti: ulid(), op: hookId, input: req.call.input ?? null, context })
          : await b.mint.hookProof({
              sub,
              aud,
              hook: hookId,
              ...(callId !== undefined ? { call: callId } : {}),
              phase: t === "phase" ? (phase === "before" ? "after" : "before") : phase,
              context,
              ...(req.call.input !== undefined ? { input: req.call.input } : {}),
              ...(t === "proof_key" ? { key: b.stranger } : {}),
            });
    }
    const path = `/tb/v1/hooks/${encodeURIComponent(hookId)}`;
    const raw = JSON.stringify(body);
    const a = await this.#send("POST", path, headers, raw);
    return { ...a, code: errorCode(a.body), sent: { path, headers, body: raw } };
  }

  // ── bridge ops (C16 B5) ─────────────────────────────────────────────────────
  async callBridgeOp(
    bop: BridgeOp,
    body: Json,
    opts: { op?: string; tamper?: "no_proof" | "op_proof" | "hook_proof" | "bop_mismatch" | "body" | "proof_key" } = {},
  ): Promise<HttpAnswer & { code: string | null }> {
    const b = this.#b;
    const aud = `tb:ins:${b.ids.ins}` as const;
    const t = opts.tamper;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (t !== "no_proof") {
      let proof: string;
      if (t === "op_proof") proof = await b.mint.callProof({ sub: `tb:agt:${b.ids.agents[0].id}`, aud, gjti: ulid(), op: opts.op ?? bop, input: body, context: {} });
      else if (t === "hook_proof") proof = await b.mint.hookProof({ sub: `tb:agt:${b.ids.agents[0].id}`, aud, hook: bop, phase: "before", context: {} });
      else {
        // C91: THE binding rule (manifest bridgeOpProofClaims): catalog {op}, resolve {op, in}, mark {in},
        // scope_summary {}; `bop_mismatch` signs another bop with this bop's claims, `body` binds a tampered body
        const signedBop: BridgeOp = t === "bop_mismatch" ? (bop === "mark" ? "catalog" : "mark") : bop;
        const claims = bridgeOpProofClaims(bop, t === "body" ? tamperValue(body) : body);
        proof = await b.mint.bridgeOpProof({
          aud,
          bop: signedBop,
          ...(claims.op !== undefined ? { op: claims.op } : opts.op !== undefined && (bop === "catalog" || bop === "resolve") ? { op: opts.op } : {}),
          ...(claims.in !== undefined ? { in: claims.in } : {}),
          ...(t === "proof_key" ? { key: b.stranger } : {}),
        });
      }
      headers[BRIDGE_HEADERS.callProof.toLowerCase()] = proof;
    }
    const a = await this.#send("POST", `/tb/v1/bridge/${BRIDGE_OP_PATH[bop]}`, headers, JSON.stringify(body));
    return { ...a, code: errorCode(a.body) };
  }

  // ── person launch + session (SDK-API §5) ────────────────────────────────────
  async launch(opts: { path?: string; tamper?: "aud" | "expired" | "key" | "ws" | "grant_as_ticket"; ticket?: string } = {}): Promise<
    HttpAnswer & { code: string | null; ticket: string; cookie: string | null; location: string | null; setCookie: string }
  > {
    const b = this.#b;
    const t = opts.tamper;
    const now = nowS();
    let ticket = opts.ticket;
    if (ticket === undefined) {
      ticket =
        t === "grant_as_ticket"
          ? await b.mint.grant({ sub: `tb:agt:${b.ids.agents[0].id}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free" })
          : await b.mint.launchTicket({
              person: b.ids.person,
              aud: t === "aud" ? (`tb:ins:${newId("ins")}` as `tb:ins:${InstanceId}`) : `tb:ins:${b.ids.ins}`,
              ...(opts.path !== undefined ? { path: opts.path } : {}),
              ...(t === "expired" ? { iat: now - 200, exp: now - 140 } : {}),
              ...(t === "key" ? { key: b.stranger } : {}),
              ...(t === "ws" ? { ws: newId("ws") as `ws_${string}` } : {}),
            });
    }
    const a = await this.#send("POST", `${this.personBase}/tb/launch`, { "content-type": "application/x-www-form-urlencoded", origin: this.url }, new URLSearchParams({ ticket }).toString());
    const setCookie = a.headers.getSetCookie().join("\n");
    const m = /(?:^|\n)tb_session=([^;\n]+)/.exec(setCookie);
    return { ...a, code: errorCode(a.body) ?? htmlPersonCode(a), ticket, cookie: m ? m[1] : null, location: a.headers.get("location"), setCookie };
  }

  async session(cookie: string): Promise<HttpAnswer & { csrf: string | null; principal: Record<string, unknown> | null }> {
    const a = await this.#send("GET", `${this.personBase}/tb/v1/session`, { cookie: `tb_session=${cookie}` });
    const body = isObj(a.body) ? a.body : {};
    return { ...a, csrf: typeof body.csrf === "string" ? body.csrf : null, principal: isObj(body.principal) ? body.principal : null };
  }

  /** Launch + session in one step; null when either fails. */
  async signIn(): Promise<PersonSession | null> {
    const l = await this.launch();
    if (!l.cookie) return null;
    const s = await this.session(l.cookie);
    return s.status === 200 && s.csrf ? { cookie: l.cookie, csrf: s.csrf } : null;
  }

  async personOp(
    sess: PersonSession,
    op: string,
    input: Json,
    opts: { omitCsrf?: boolean; idempotencyKey?: string } = {},
  ): Promise<HttpAnswer & { code: string | null; output: unknown }> {
    // SPEC-GAP: SDK-API §3.2 does not fix the person-op body; `{ input, idempotencyKey? }` mirrors the agent body (CORE §8)
    // and is what the SDK implements.
    const headers: Record<string, string> = { "content-type": "application/json", cookie: `tb_session=${sess.cookie}`, origin: this.url };
    if (!opts.omitCsrf) headers["tb-csrf"] = sess.csrf;
    const body = JSON.stringify({ input, ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}) });
    const a = await this.#send("POST", `${this.personBase}/tb/v1/ops/${encodeURIComponent(op)}`, headers, body);
    const output = isObj(a.body) && a.body.status === "ok" ? a.body.output : undefined;
    return { ...a, code: errorCode(a.body), output };
  }

  logout(sess: PersonSession): Promise<HttpAnswer> {
    return this.#send("POST", `${this.personBase}/tb/v1/logout`, { "content-type": "application/json", cookie: `tb_session=${sess.cookie}`, "tb-csrf": sess.csrf, origin: this.url }, "{}");
  }
}
