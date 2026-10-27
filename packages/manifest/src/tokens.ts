// Kind verifiers (CREDENTIALS §3 V0 + per-kind checks, §10, §11) and the issuer-side signers Core, the bridge and
// the conformance fakes use, so no party hand-rolls claims or lifetimes.
import type { InstanceSlice, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import {
  type AgentSessionClaims,
  type BridgeOp,
  type BridgeRef,
  type CallProofBridgeOpClaims,
  type CallProofHookClaims,
  type CallProofOpClaims,
  type ConfigClaims,
  type GrantClaims,
  LEEWAY_S,
  LIFETIME_S,
  type PairingCodeClaims,
  type PersonTicketClaims,
  type PersonTicketKeysClaims,
  type PersonTicketLaunchClaims,
  type ReleaseIndexClaims,
  type Sha256Digest,
  TYP,
  type Ulid,
  type WorkspaceId,
} from "@opt2-tealbrick/spec/credentials";
import type { HookPhase } from "@opt2-tealbrick/spec/manifest";
import { KNOWN_HOLD_FAMILIES } from "@opt2-tealbrick/spec/manifest";
import type {
  Ed25519KeyPair,
  Json,
  KeySet,
  Refusal,
  TrustContext,
  VerifiedCallProof,
  VerifiedGrant,
  VerifiedTicket,
} from "@opt2-tealbrick/spec/sdk";
import { digest } from "./jcs.ts";
import { INVALID_TOKEN, type Issue, issueClaims, type ReplayGuard, signJws, type V0Failure, verifyV0 } from "./jws.ts";
import { WORKFLOW_GRANT_TTL_SEC, type WorkflowGrantClaims } from "./spec-p1.temp.ts";

export type { TrustContext, VerifiedCallProof, VerifiedGrant, VerifiedTicket };

/** Grant refusal codes (BRIDGE error list; the app SDK passes them through). */
export const GRANT_REFUSAL = { invalid: "grant_invalid", expired: "grant_expired", revoked: "grant_revoked" } as const;

const refusal = (code: string, reason: string): Refusal => ({ ok: false, code, reason });
const fromV0 = (f: V0Failure, code: string = INVALID_TOKEN): Refusal => refusal(code, `step ${f.step}: ${f.reason}`);
const kindFail = (reason: string, code: string = INVALID_TOKEN): Refusal => refusal(code, `step 9: ${reason}`);

/** Issuers of Portal-signed kinds present in a key set (Portal, or the standalone bridge named by a Portal-signed slice). */
function issuersIn(keys: KeySet, kinds: readonly ("portal" | "brg" | "ins")[]): string[] {
  const out = new Set<string>();
  for (const k of keys.keys) {
    const iss = k.issuer as string;
    if ((iss === "tb:portal" && kinds.includes("portal")) || (iss.startsWith("tb:brg:") && kinds.includes("brg")) || (iss.startsWith("tb:ins:") && kinds.includes("ins"))) out.add(iss);
  }
  return [...out];
}

function once(replay: ReplayGuard | undefined, c: { jti: string; exp: number }, now: number): boolean {
  return !replay || replay(c.jti, c.exp + LEEWAY_S, now);
}

// ── K10 grant ────────────────────────────────────────────────────────────────
/**
 * CREDENTIALS §11 order: V0 (`tb-grant+jwt`, `ctx.issuers`, `iss` ∈ {tb:portal, standalone issuer}, `aud` = ctx.self,
 * ≤ 43200 s) → `ws` → `cnf.brg` → `jti` ∉ revoked. Codes: `grant_expired` (time window), `grant_revoked`, else `grant_invalid`.
 */
export function verifyGrant(token: string, ctx: TrustContext): VerifiedGrant | Refusal {
  const r = verifyV0<GrantClaims>(token, ctx.issuers, {
    typ: TYP.grant,
    aud: ctx.self,
    iss: issuersIn(ctx.issuers, ["portal", "brg"]),
    now: ctx.now,
    maxLifetimeS: LIFETIME_S.grant,
  });
  if (!r.ok) return fromV0(r, r.expired ? GRANT_REFUSAL.expired : GRANT_REFUSAL.invalid);
  const c = r.claims;
  if (c.ws !== ctx.ws) return kindFail("ws", GRANT_REFUSAL.invalid);
  if (c.cnf.brg !== ctx.bridge) return kindFail("cnf.brg", GRANT_REFUSAL.invalid);
  if (ctx.revokedJtis.has(c.jti)) return kindFail("revoked jti", GRANT_REFUSAL.revoked);
  const [, kind, id] = c.sub.split(":");
  const caller = kind === "agt" ? ({ type: "agent", id } as const) : ({ type: "app", id } as const);
  // v0.1.17 (C108): unknown held families are ignored (tolerant reader); `money` stays held by authorize() regardless
  const held = c.held.filter((f) => (KNOWN_HOLD_FAMILIES as readonly string[]).includes(f));
  return { ok: true, token, claims: held.length === c.held.length ? c : { ...c, held }, caller: caller as VerifiedGrant["caller"] };
}

// ── K7 call proofs (op, hook, bridge op) ─────────────────────────────────────
function verifyProof<C extends object>(token: string, ctx: TrustContext) {
  const brg = `tb:brg:${ctx.bridge}`;
  return verifyV0<C>(token, ctx.bridgeKeys, { typ: TYP.callProof, aud: ctx.self, iss: [brg], now: ctx.now, maxLifetimeS: LIFETIME_S.proof });
}

/**
 * Op call proof (`TB-Call`, `gjti` variant): V0 with slice `bridge.keys`, `iss` = workspace bridge (= grant `cnf.brg`),
 * `aud` = ctx.self, ≤ 60 s; then `gjti`, `op`, `in`, `ctx` (and `sub` when `grantSub` is passed) bound; then replay.
 */
export function verifyCallProof(
  token: string,
  ctx: TrustContext,
  bind: { op: string; inputDigest: Sha256Digest; contextDigest: Sha256Digest; grantJti: Ulid; grantSub?: string },
  replay?: ReplayGuard,
): VerifiedCallProof | Refusal {
  const r = verifyProof<CallProofOpClaims>(token, ctx);
  if (!r.ok) return fromV0(r);
  const c = r.claims;
  if (!("gjti" in c)) return kindFail("not an op proof");
  if (c.gjti !== bind.grantJti) return kindFail("gjti");
  if (bind.grantSub !== undefined && c.sub !== bind.grantSub) return kindFail("sub");
  if (c.op !== bind.op) return kindFail("op");
  if (c.in !== bind.inputDigest || c.ctx !== bind.contextDigest) return kindFail("body digests");
  if (!once(replay, c, ctx.now)) return refusal(INVALID_TOKEN, "step 10: jti replay");
  return { ok: true, claims: c };
}

/**
 * Hook call proof (`hook` variant): `hook`, `phase`, `ctx`, `in` (present iff `bind.inputDigest`) bound; no grant.
 * v0.1.27 (C268 A): optional `sub` and `call`. When given they must equal the proof's `sub` (the CALLER ref of the hook request:
 * `callerRef(call.caller)`) and its `call` claim (the id of the hook request, `call.id`): a hook request whose body names another
 * caller or another call than the one the bridge signed for is refused `invalid_token`, so a captured proof cannot be replayed for a
 * body that claims a different caller. Absent = not compared (callers older than 0.1.27 pass neither). A value that is given but
 * empty or not a string never matches (fail closed).
 * v0.1.52 (C268 B, manifest 0.1.28): optional `bd` = sha256 of the exact hook request body bytes (the same digest format as every
 * other `bd`, `sha256:<64 hex>`, shape-checked by the claim set: a malformed `bd` never gets here). When the proof carries `bd`
 * it must equal `bind.bodyDigest` (the digest of the raw bytes the caller hashed BEFORE parsing); a proof with `bd` and no
 * `bind.bodyDigest` is refused (fail closed). A proof without `bd` is not compared (a later slice flag makes it required).
 */
export function verifyHookProof(
  token: string,
  ctx: TrustContext,
  bind: { hook: string; phase: HookPhase; contextDigest: Sha256Digest; inputDigest?: Sha256Digest; sub?: string; call?: string; bodyDigest?: Sha256Digest },
  replay?: ReplayGuard,
): VerifiedCallProof<CallProofHookClaims> | Refusal {
  const r = verifyProof<CallProofHookClaims>(token, ctx);
  if (!r.ok) return fromV0(r);
  const c = r.claims;
  if (!("hook" in c)) return kindFail("not a hook proof");
  if (c.hook !== bind.hook || c.phase !== bind.phase) return kindFail("hook/phase");
  if (c.ctx !== bind.contextDigest || c.in !== bind.inputDigest) return kindFail("body digests");
  if (bind.sub !== undefined && (typeof bind.sub !== "string" || bind.sub === "" || c.sub !== bind.sub)) return kindFail("sub");
  if (bind.call !== undefined && (typeof bind.call !== "string" || bind.call === "" || c.call !== bind.call)) return kindFail("call");
  if (c.bd !== undefined && c.bd !== bind.bodyDigest) return kindFail("bd");
  if (!once(replay, c, ctx.now)) return refusal(INVALID_TOKEN, "step 10: jti replay");
  return { ok: true, claims: c };
}

/**
 * v0.1.27 (C268 A): the proof `sub` ref of a hook request's caller (`call.caller`): an agent is `tb:agt:<id>`, an app instance
 * `tb:ins:<id>`. Anything else (a missing caller, another type, a non-string or empty id) gives `""`, which never matches a proof.
 */
export function hookCallerRef(caller: unknown): string {
  if (!caller || typeof caller !== "object" || Array.isArray(caller)) return "";
  const { type, id } = caller as { type?: unknown; id?: unknown };
  if (typeof id !== "string" || id === "") return "";
  return type === "agent" ? `tb:agt:${id}` : type === "app" ? `tb:ins:${id}` : "";
}

/**
 * THE bridge-op binding rule (SDK-API §3.2, C91): which claims a bridge-op proof carries for a body. The bridge signs
 * exactly these claims and the SDK (and conformance) verify exactly these — one function, so they cannot drift.
 * catalog → {bop, op} (the search query is NOT bound); resolve → {bop, op, in}; mark → {bop, in}; scope_summary → {bop}.
 * `in` = digest(body).
 */
export function bridgeOpBinding(bop: BridgeOp, body: Json): { bop: BridgeOp; op?: string; inputDigest?: Sha256Digest } {
  const op = body && typeof body === "object" && !Array.isArray(body) && typeof body.op === "string" ? body.op : undefined;
  switch (bop) {
    case "catalog":
      return { bop, ...(op !== undefined ? { op } : {}) };
    case "resolve":
      return { bop, ...(op !== undefined ? { op } : {}), inputDigest: digest(body) };
    case "mark":
      return { bop, inputDigest: digest(body) };
    default:
      return { bop };
  }
}

/** Claims the bridge puts into a bridge-op proof for `body` ({@link bridgeOpBinding} as claim names). */
export function bridgeOpProofClaims(bop: BridgeOp, body: Json): { bop: BridgeOp; op?: string; in?: Sha256Digest } {
  const b = bridgeOpBinding(bop, body);
  return { bop: b.bop, ...(b.op !== undefined ? { op: b.op } : {}), ...(b.inputDigest !== undefined ? { in: b.inputDigest } : {}) };
}

/** Bridge-op proof (`bop` variant, C16 B5): `iss = sub` = workspace bridge; `bop`, `op`, `in` bound (each present iff bound). */
export function verifyBridgeOpProof(
  token: string,
  ctx: TrustContext,
  bind: { bop: BridgeOp; op?: string; inputDigest?: Sha256Digest },
  replay?: ReplayGuard,
): VerifiedCallProof<CallProofBridgeOpClaims> | Refusal {
  const r = verifyProof<CallProofBridgeOpClaims>(token, ctx);
  if (!r.ok) return fromV0(r);
  const c = r.claims;
  if (!("bop" in c)) return kindFail("not a bridge-op proof");
  if (c.bop !== bind.bop || c.op !== bind.op) return kindFail("bop/op");
  if (c.in !== bind.inputDigest) return kindFail("body digest");
  if (!once(replay, c, ctx.now)) return refusal(INVALID_TOKEN, "step 10: jti replay");
  return { ok: true, claims: c };
}

// ── K11 person tickets ───────────────────────────────────────────────────────
/** App SDK: only `pur: "launch"`, `aud` = ctx.self, ≤ 60 s, `ws`. The one-time `jti` check is the SDK's (DB). */
export function verifyTicket(token: string, ctx: TrustContext): VerifiedTicket | Refusal {
  const r = verifyV0<PersonTicketClaims>(token, ctx.issuers, {
    typ: TYP.personTicket,
    aud: ctx.self,
    iss: issuersIn(ctx.issuers, ["portal", "brg", "ins"]),
    now: ctx.now,
    maxLifetimeS: LIFETIME_S.ticketLaunch,
  });
  if (!r.ok) return fromV0(r);
  if (r.claims.pur !== "launch") return kindFail("pur");
  if (r.claims.ws !== ctx.ws) return kindFail("ws");
  return { ok: true, claims: r.claims };
}

/** Bridge key page: only `pur: "keys"`, `aud` = the bridge, ≤ 120 s, `ws`. The one-time `jti` check is the bridge's (volume). */
export function verifyKeysTicket(
  token: string,
  ctx: { now: number; self: BridgeRef; ws: WorkspaceId; issuers: KeySet },
): { ok: true; claims: PersonTicketKeysClaims } | Refusal {
  const r = verifyV0<PersonTicketClaims>(token, ctx.issuers, {
    typ: TYP.personTicket,
    aud: ctx.self,
    iss: issuersIn(ctx.issuers, ["portal", "brg"]),
    now: ctx.now,
    maxLifetimeS: LIFETIME_S.ticketKeys,
  });
  if (!r.ok) return fromV0(r);
  if (r.claims.pur !== "keys") return kindFail("pur");
  if (r.claims.ws !== ctx.ws) return kindFail("ws");
  return { ok: true, claims: r.claims };
}

// ── K9 config / slice ────────────────────────────────────────────────────────
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isPause = (v: unknown) => isObj(v) && typeof v.workspace === "boolean" && Array.isArray(v.agents) && Array.isArray(v.instances);
const isRevoked = (v: unknown) => isObj(v) && Array.isArray(v.jtis) && v.jtis.every((j) => isObj(j) && typeof j.jti === "string" && Number.isSafeInteger(j.exp));

/**
 * Slice (`tb-slice+jws`): V0 (`ctx.issuers`, `iss` ∈ {tb:portal, standalone issuer}, `aud = sub` = ctx.self, ≤ 12 h —
 * older fails closed, C9) → `ws`, `ins`, `bridge.id` = ctx.bridge and the credential section's shape. The full body
 * schema (instance-slice.schema.json) and `rev` > installed rev are the caller's checks.
 */
export function verifySlice(token: string, ctx: Omit<TrustContext, "bridgeKeys" | "revokedJtis">): { ok: true; slice: InstanceSlice } | Refusal {
  const r = verifyV0<InstanceSlice>(token, ctx.issuers, {
    typ: TYP.slice,
    aud: ctx.self,
    iss: issuersIn(ctx.issuers, ["portal", "brg"]),
    now: ctx.now,
    maxLifetimeS: LIFETIME_S.configOrSlice,
  });
  if (!r.ok) return fromV0(r);
  const s = r.claims as unknown as Record<string, unknown>;
  if (s.ws !== ctx.ws) return kindFail("ws");
  if (`tb:ins:${String(s.ins)}` !== ctx.self || typeof s.product !== "string") return kindFail("ins/product");
  const b = s.bridge;
  if (!isObj(b) || b.id !== ctx.bridge || !Array.isArray(b.keys)) return kindFail("bridge");
  if (!Array.isArray(s.portalKeys) || !isPause(s.pause) || !isRevoked(s.revoked) || !Number.isSafeInteger(s.personNbf)) return kindFail("credential section");
  if (!Array.isArray(s.grants) || !s.grants.every((g) => typeof g === "string") || !Array.isArray(s.agents)) return kindFail("grants/agents");
  return { ok: true, slice: r.claims };
}

/**
 * Config (`tb-config+jws`): V0 (`iss = tb:portal`, `aud = sub` = ctx.self, ≤ 12 h) → credential section shape.
 * Returns the claims and the whole payload as `body` (schema validation, `ws` = enrolled workspace and `rev` order are
 * the bridge's checks, BRIDGE §5.2).
 */
export function verifyConfig(token: string, ctx: { now: number; self: BridgeRef; issuers: KeySet }): { ok: true; claims: ConfigClaims; body: unknown } | Refusal {
  const r = verifyV0<ConfigClaims & Record<string, unknown>>(token, ctx.issuers, {
    typ: TYP.config,
    aud: ctx.self,
    iss: ["tb:portal"],
    now: ctx.now,
    maxLifetimeS: LIFETIME_S.configOrSlice,
  });
  if (!r.ok) return fromV0(r);
  const b = r.claims;
  if (!Array.isArray(b.portalKeys) || !isPause(b.pause) || !isRevoked(b.revoked) || !Array.isArray(b.connections) || !Array.isArray(b.instanceKeys) || !Array.isArray(b.grants)) {
    return kindFail("credential section");
  }
  const claims: ConfigClaims = { iss: b.iss, sub: b.sub, aud: b.aud, iat: b.iat, exp: b.exp, jti: b.jti, ws: b.ws, v: b.v, rev: b.rev };
  return { ok: true, claims, body: b };
}

// ── K2b pairing code, K5 agent session (bridge-side V0; state checks stay in the bridge) ──
/** V0 for K2b (`iss = tb:portal`, `aud` = this bridge, ≤ 600 s) → `ws` → `jti` ∉ revoked → one-time `jti` (replay). */
export function verifyPairingCode(
  token: string,
  ctx: { now: number; self: BridgeRef; ws: WorkspaceId; issuers: KeySet; revokedJtis: ReadonlySet<Ulid>; replay?: ReplayGuard },
): { ok: true; claims: PairingCodeClaims } | Refusal {
  const r = verifyV0<PairingCodeClaims>(token, ctx.issuers, { typ: TYP.pairingCode, aud: ctx.self, iss: ["tb:portal"], now: ctx.now, maxLifetimeS: LIFETIME_S.pairingCode });
  if (!r.ok) return fromV0(r);
  if (r.claims.ws !== ctx.ws) return kindFail("ws");
  if (ctx.revokedJtis.has(r.claims.jti)) return kindFail("revoked jti");
  if (!once(ctx.replay, r.claims, ctx.now)) return refusal(INVALID_TOKEN, "step 10: jti replay");
  return { ok: true, claims: r.claims };
}

/** V0 for K5 access tokens (`keys` = the bridge's own key, `iss = aud` = this bridge, ≤ 900 s) → `ws`. */
export function verifyAgentSession(token: string, ctx: { now: number; self: BridgeRef; ws: WorkspaceId; keys: KeySet }): { ok: true; claims: AgentSessionClaims } | Refusal {
  const r = verifyV0<AgentSessionClaims>(token, ctx.keys, { typ: TYP.agentSession, aud: ctx.self, iss: [ctx.self], now: ctx.now, maxLifetimeS: LIFETIME_S.agentAccess });
  if (!r.ok) return fromV0(r);
  if (r.claims.ws !== ctx.ws) return kindFail("ws");
  return { ok: true, claims: r.claims };
}

// ── issuer-side signers (lifetimes enforced: exp defaults to iat + max, longer → RangeError) ──
/** K10. v0.1.33 (spec 0.1.82, C373 P1): a grant with `wfl` (a per-workflow companion grant) lives at most WORKFLOW_GRANT_TTL_SEC (the default `exp`). */
export async function signGrant(claims: Issue<GrantClaims> | Issue<WorkflowGrantClaims>, key: Ed25519KeyPair): Promise<string> {
  const max = Object.hasOwn(claims, "wfl") ? WORKFLOW_GRANT_TTL_SEC : LIFETIME_S.grant;
  return signJws(TYP.grant, issueClaims<GrantClaims>(claims, max), key);
}
export async function signCallProof(claims: Issue<CallProofOpClaims>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.callProof, issueClaims<CallProofOpClaims>(claims, LIFETIME_S.proof), key);
}
export async function signHookProof(claims: Issue<CallProofHookClaims>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.callProof, issueClaims<CallProofHookClaims>(claims, LIFETIME_S.proof), key);
}
export async function signBridgeOpProof(claims: Issue<CallProofBridgeOpClaims>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.callProof, issueClaims<CallProofBridgeOpClaims>(claims, LIFETIME_S.proof), key);
}
/** K11: `launch` ≤ 60 s, `keys` ≤ 120 s. */
export async function signTicket(claims: Issue<PersonTicketLaunchClaims> | Issue<PersonTicketKeysClaims>, key: Ed25519KeyPair): Promise<string> {
  const max = claims.pur === "launch" ? LIFETIME_S.ticketLaunch : LIFETIME_S.ticketKeys;
  return signJws(TYP.personTicket, issueClaims<PersonTicketClaims>(claims, max), key);
}
/** K9 config: the payload is the whole workspace config (claims + body). */
export async function signConfig(config: Issue<WorkspaceConfig>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.config, issueClaims<WorkspaceConfig>(config, LIFETIME_S.configOrSlice), key);
}
/** K9 slice: the payload is the whole instance slice (claims + body). */
export async function signSlice(slice: Issue<InstanceSlice>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.slice, issueClaims<InstanceSlice>(slice, LIFETIME_S.configOrSlice), key);
}
export async function signPairingCode(claims: Issue<PairingCodeClaims>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.pairingCode, issueClaims<PairingCodeClaims>(claims, LIFETIME_S.pairingCode), key);
}
export async function signAgentSession(claims: Issue<AgentSessionClaims>, key: Ed25519KeyPair): Promise<string> {
  return signJws(TYP.agentSession, issueClaims<AgentSessionClaims>(claims, LIFETIME_S.agentAccess), key);
}

// ── Release index (v0.1.1, C30): signed digest of the Platform release index body ──
export type ReleaseIndexBody = { schema: "opt2.release-index/v2"; releases: unknown[]; offers?: unknown[] } & Record<string, unknown>;

/** Signs `digest(body)`; Platform's release key. Lifetime ≤ 180 d. */
export async function signReleaseIndex(body: ReleaseIndexBody, input: { iat: number; exp?: number }, key: Ed25519KeyPair): Promise<string> {
  const exp = input.exp ?? input.iat + LIFETIME_S.releaseIndex;
  if (!Number.isInteger(input.iat) || !Number.isInteger(exp) || exp <= input.iat || exp - input.iat > LIFETIME_S.releaseIndex) {
    throw new RangeError(`lifetime must be 1..${LIFETIME_S.releaseIndex} s`);
  }
  const claims: ReleaseIndexClaims = {
    iss: "tb:releases",
    aud: "tb:portal",
    iat: input.iat,
    exp,
    schema: "opt2.release-index/v2",
    indexDigest: digest(body as Json),
    releases: Array.isArray(body.releases) ? body.releases.length : 0,
    offers: Array.isArray(body.offers) ? body.offers.length : 0,
  };
  return signJws(TYP.releaseIndex, claims, key);
}

/** Core: verifies the index JWS with the pinned release key set (`keySetFrom(jwks, "tb:releases")`) and that it signs this body. */
export function verifyReleaseIndex(token: string, body: ReleaseIndexBody, ctx: { now: number; keys: KeySet }): { ok: true; claims: ReleaseIndexClaims } | Refusal {
  const r = verifyV0<ReleaseIndexClaims>(token, ctx.keys, { typ: TYP.releaseIndex, aud: "tb:portal", iss: ["tb:releases"], now: ctx.now, maxLifetimeS: LIFETIME_S.releaseIndex });
  if (!r.ok) return { ok: false, code: INVALID_TOKEN, reason: `step ${r.step}: ${r.reason}` };
  if (r.claims.indexDigest !== digest(body as Json)) return { ok: false, code: INVALID_TOKEN, reason: "index digest mismatch" };
  const n = Array.isArray(body.releases) ? body.releases.length : -1;
  const m = Array.isArray(body.offers) ? body.offers.length : 0;
  if (r.claims.releases !== n || r.claims.offers !== m) return { ok: false, code: INVALID_TOKEN, reason: "index counts mismatch" };
  return { ok: true, claims: r.claims };
}
