// Compact JWS (Ed25519, `alg: EdDSA`) with the CREDENTIALS §3 "V0" check order, closed claim sets per `typ`,
// and generic request-bound assertions (CREDENTIALS §10). The ONE implementation (CORE §3).
import { verify as edVerify, webcrypto } from "node:crypto";
import {
  type AgentAssertionClaims,
  BRIDGE_OPS,
  type BridgeAssertionClaims,
  type BridgeId,
  type InstanceAssertionClaims,
  type InstanceId,
  LEEWAY_S,
  LIFETIME_S,
  MAX_JWS_BYTES,
  type OwnerAssertionClaims,
  type PairStateClaims,
  TYP,
  type Typ,
  type Ulid,
} from "@opt2-tealbrick/spec/credentials";
import { AGENT_MODES, CRUD_ACTIONS, HOOK_HOLD_FAMILIES, HOOK_PHASES } from "@opt2-tealbrick/spec/manifest";
import type { Ed25519KeyPair, JwsExpect, KeySet, Refusal } from "@opt2-tealbrick/spec/sdk";
import { sha256Bytes } from "./jcs.ts";
import { findKey, publicKeyObject } from "./keys.ts";
import { DATA_POLICIES, MODEL_ID_PATTERN, MODEL_ROLE_HINTS_MAX, MODEL_ROLES, PROVIDER_ID_PATTERN } from "./model-roles.ts";
import { ULID_RE, ulid } from "./random.ts";
import { WORKFLOW_GRANT_TTL_SEC, WORKFLOW_ID_PATTERN } from "./spec-p1.temp.ts";

export type { JwsExpect, Refusal };

/** Clock skew L (CREDENTIALS §3): accept iff `iat ≤ now + L` and `now < exp + L` and `0 < exp − iat ≤ max`. */
export const CLOCK_SKEW_S = LEEWAY_S;
/** Config / slice JWS carry their whole body (BRIDGE S2: ≤ 4 MB); every other kind is ≤ MAX_JWS_BYTES. */
export const MAX_DOCUMENT_JWS_BYTES = 4 * 1024 * 1024;
const DOCUMENT_TYPS: ReadonlySet<string> = new Set([TYP.config, TYP.slice]);
/** v0.1.11 (C62/C63): the key-set statement has its own signer/verifier (keyset.ts: no exp/sub/jti, root keys). */
export const KEYSET_TYP = "tb-keyset+jws";
/** Spec 0.1.58..0.1.64 added token types this package has no signer or verifier for (host agent: `tb-host-assert+jwt`, `tb-host-plan+jws`; person op: `tb-person-op+jwt`; other lanes), so they are unknown types here. */
const UNSUPPORTED_TYPS: readonly string[] = [TYP.hostAssertion, TYP.hostPlan, TYP.personOp];
type ClaimTyp = Exclude<Typ, typeof KEYSET_TYP | typeof TYP.hostAssertion | typeof TYP.hostPlan | typeof TYP.personOp>;
const ALL_TYPS: ReadonlySet<string> = new Set(Object.values(TYP as Record<string, string>).filter((t) => t !== KEYSET_TYP && !UNSUPPORTED_TYPS.includes(t)));

// ── claim checks (step 5: closed claim set + types) ──────────────────────────
type Check = (v: unknown) => boolean;
const ID_BODY = "[0-7][0-9A-HJKMNP-TV-Z]{25}";
const idRe = (p: string) => new RegExp(`^${p}_${ID_BODY}$`);
const refRe = (...kinds: string[]) => new RegExp(`^tb:(?:${kinds.map((k) => (k === "portal" ? "portal" : `${k}:${k}_${ID_BODY}`)).join("|")})$`);
const re = (r: RegExp): Check => (v) => typeof v === "string" && r.test(v);
const int: Check = (v) => Number.isSafeInteger(v) && (v as number) >= 0;
const str = (max: number): Check => (v) => typeof v === "string" && v.length > 0 && v.length <= max;
const oneOf = (vals: readonly string[]): Check => (v) => typeof v === "string" && vals.includes(v);
/** v0.1.13 (G1) op proof `hv {f, r, by}`: closed object, f ∈ HOOK_HOLD_FAMILIES, r 1..280, by = `<productId>/<hookId>` (manifest id patterns). */
const holdVerdictC: Check = (v) => {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const o = v as Record<string, unknown>;
  return (
    Object.keys(o).every((k) => k === "f" || k === "r" || k === "by") &&
    oneOf(HOOK_HOLD_FAMILIES)(o.f) &&
    str(280)(o.r) &&
    typeof o.by === "string" &&
    /^[a-z][a-z0-9-]{1,31}\/(?!tb_)[a-z][a-z0-9_]{1,39}$/.test(o.by)
  );
};
const setOf = (vals: readonly string[]): Check => (v) => Array.isArray(v) && v.every((x) => vals.includes(x)) && new Set(v).size === v.length;
/** v0.1.17 (C108, tolerant reader): a grant's `held` may name families this build does not know (a newer Core); they are
 *  shape-checked here and IGNORED by verifyGrant (an app cannot declare an unknown family, so ignoring is safe). */
const heldC: Check = (v) => Array.isArray(v) && v.length <= 32 && v.every((x) => typeof x === "string" && /^[a-z][a-z0-9_]{1,31}$/.test(x)) && new Set(v).size === v.length;
const strArr = (maxItems: number, maxLen: number): Check => (v) => Array.isArray(v) && v.length <= maxItems && v.every(str(maxLen));
/** v0.1.23 (spec 0.1.46, GRANT-PRD): a companion grant's `prd` = the product id of its calling instance (`^[a-z][a-z0-9-]{1,31}$`, CORE §1). */
const productC = re(/^[a-z][a-z0-9-]{1,31}$/);
/** v0.1.33 (spec 0.1.82, C373 P1): `wfl` on a per-workflow companion grant. */
const workflowIdC = re(new RegExp(WORKFLOW_ID_PATTERN));
const digestC = re(/^sha256:[0-9a-f]{64}$/);
const wsC = re(idRe("ws"));
const ulidC = re(ULID_RE);
const htmC = oneOf(["GET", "POST", "PUT", "PATCH", "DELETE"]);
const htuC: Check = (v) => typeof v === "string" && v.startsWith("/") && !v.startsWith("//") && v.length <= 2048;
const capC: Check = (v) => {
  const c = v as Record<string, unknown> | null;
  return !!c && typeof c === "object" && !Array.isArray(c) && Object.keys(c).length === 2 && int(c.max) && (c.per === "hour" || c.per === "day");
};
const capsC: Check = (v) => {
  const c = v as Record<string, unknown> | null;
  if (!c || typeof c !== "object" || Array.isArray(c)) return false;
  return Object.entries(c).every(([k, x]) => (k === "write" || k === "outward" || k === "destructive") && capC(x));
};
const cnfC: Check = (v) => {
  const c = v as Record<string, unknown> | null;
  return !!c && typeof c === "object" && !Array.isArray(c) && Object.keys(c).length === 1 && re(idRe("brg"))(c.brg);
};
const httpsUrlC: Check = (v) => {
  if (typeof v !== "string" || v.length > 2048) return false;
  try {
    return new URL(v).protocol === "https:";
  } catch {
    return false;
  }
};

/**
 * v0.1.31 (spec 0.1.63, K11 `roles`, BRIDGE §15.2): the keys ticket's display pre-fill: at most MODEL_ROLE_HINTS_MAX items, each a closed
 * object `{role ∈ MODEL_ROLES, provider? ^[a-z][a-z0-9-]{1,31}$, model? MODEL_ID_PATTERN, dataPolicy? ∈ DATA_POLICIES}`. Launch tickets stay without it.
 */
const PROVIDER_ID_RE = new RegExp(PROVIDER_ID_PATTERN);
const MODEL_ID_RE = new RegExp(MODEL_ID_PATTERN);
const roleHintsC: Check = (v) =>
  Array.isArray(v) &&
  v.length <= MODEL_ROLE_HINTS_MAX &&
  v.every((h) => {
    if (!h || typeof h !== "object" || Array.isArray(h)) return false;
    const o = h as Record<string, unknown>;
    return (
      Object.keys(o).every((k) => k === "role" || k === "provider" || k === "model" || k === "dataPolicy") &&
      oneOf(MODEL_ROLES)(o.role) &&
      (!has(o, "provider") || (typeof o.provider === "string" && PROVIDER_ID_RE.test(o.provider))) &&
      (!has(o, "model") || (typeof o.model === "string" && MODEL_ID_RE.test(o.model))) &&
      (!has(o, "dataPolicy") || oneOf(DATA_POLICIES)(o.dataPolicy))
    );
  });

interface ClaimSpec {
  iss: Check;
  sub: Check;
  aud: Check;
  required: Record<string, Check>;
  optional: Record<string, Check>;
  /** cross-field rule; returns the failure reason or null */
  cross?: (c: Record<string, unknown>) => string | null;
  /** config / slice: the payload also carries the document body (validated by its JSON Schema, not here) */
  open?: boolean;
  /** signed document digests (release index, C30): no `sub`, no `jti` */
  document?: boolean;
}

const sameIssSub = (c: Record<string, unknown>) => (c.iss === c.sub ? null : "iss != sub");
const BINDING = { htm: htmC, htu: htuC };
const P = re(refRe("portal"));
const AGT = re(refRe("agt"));
const INS = re(refRe("ins"));
const BRG = re(refRe("brg"));
const PER = re(refRe("per"));
const CALLER = re(refRe("agt", "ins"));
const has = (c: Record<string, unknown>, k: string) => Object.hasOwn(c, k);
const BASE = ["iss", "sub", "aud", "iat", "exp", "jti"];

const sha256C: Check = (v) => typeof v === "string" && /^sha256:[0-9a-f]{64}$/.test(v);
const countC: Check = (v) => int(v) && (v as number) >= 0;
const CLAIM_SPECS: Record<ClaimTyp, ClaimSpec> = {
  [TYP.releaseIndex]: {
    iss: (v) => v === "tb:releases",
    sub: (v) => v === undefined,
    aud: P,
    required: { schema: (v) => v === "opt2.release-index/v2", indexDigest: sha256C, releases: countC, offers: countC },
    optional: {},
    document: true,
  },
  [TYP.pairingCode]: { iss: P, sub: AGT, aud: BRG, required: { ws: wsC }, optional: { rid: str(128) } },
  [TYP.agentSession]: { iss: BRG, sub: AGT, aud: BRG, required: { ws: wsC, con: re(idRe("con")), gen: int }, optional: {}, cross: (c) => (c.iss === c.aud ? null : "iss != aud") },
  [TYP.config]: { iss: re(refRe("portal", "brg")), sub: BRG, aud: BRG, required: { ws: wsC, v: (v) => v === 1, rev: int }, optional: {}, open: true, cross: (c) => (c.sub === c.aud ? null : "sub != aud") },
  [TYP.slice]: { iss: re(refRe("portal", "brg")), sub: INS, aud: INS, required: { ws: wsC, v: (v) => v === 1, rev: int }, optional: {}, open: true, cross: (c) => (c.sub === c.aud ? null : "sub != aud") },
  [TYP.grant]: {
    iss: re(refRe("portal", "brg")),
    sub: CALLER,
    aud: INS,
    required: { ws: wsC, cnf: cnfC, crud: setOf(CRUD_ACTIONS), mode: oneOf(AGENT_MODES), held: heldC, caps: capsC, wf: strArr(1024, 128), polrev: int },
    // v0.1.23 (GRANT-PRD, spec 0.1.46): `prd` rides on companion grants; shape-checked here, read by the SDK only for an app caller
    // v0.1.33 (spec 0.1.82, C373 P1): `wfl` = the workflow id of the calling app on a per-workflow companion grant (WORKFLOW_ID_PATTERN)
    optional: { prd: productC, wfl: workflowIdC },
    // companion grants are always bound (CREDENTIALS §11, CORE I8); a grant with `wfl` (WorkflowGrantClaims) is a companion grant that
    // always carries `prd` and lives at most WORKFLOW_GRANT_TTL_SEC (exp − iat); anything else is refused as a whole (grant_invalid)
    cross: (c) => {
      const companion = String(c.sub).startsWith("tb:ins:");
      if (companion && c.mode !== "bound") return "companion grant not bound";
      if (!has(c, "wfl")) return null;
      if (!companion) return "wfl on a non-companion grant";
      if (!has(c, "prd")) return "wfl grant without prd";
      return (c.exp as number) - (c.iat as number) > WORKFLOW_GRANT_TTL_SEC ? "wfl grant lifetime" : null;
    },
  },
  [TYP.personTicket]: {
    iss: re(refRe("portal", "brg", "ins")),
    sub: PER,
    aud: re(refRe("ins", "brg")),
    required: { ws: wsC, pur: oneOf(["launch", "keys"]) },
    optional: { path: htuC, req: strArr(64, 128), roles: roleHintsC },
    cross: (c) => {
      if (c.pur === "launch") return INS(c.aud) && !has(c, "req") && !has(c, "roles") ? null : "launch ticket shape";
      return BRG(c.aud) && !has(c, "path") ? null : "keys ticket shape";
    },
  },
  [TYP.agentAssertion]: { iss: AGT, sub: AGT, aud: BRG, required: { con: re(idRe("con")) }, optional: {}, cross: sameIssSub },
  [TYP.bridgeAssertion]: { iss: BRG, sub: BRG, aud: P, required: { ...BINDING }, optional: { bd: digestC }, cross: sameIssSub },
  [TYP.pairState]: { iss: BRG, sub: BRG, aud: P, required: { rid: str(128), ret: httpsUrlC, rh: str(253), cn: str(256) }, optional: {}, cross: sameIssSub },
  [TYP.instanceAssertion]: { iss: INS, sub: INS, aud: BRG, required: { ...BINDING }, optional: { svc: str(64), bd: digestC }, cross: sameIssSub },
  [TYP.ownerAssertion]: { iss: PER, sub: PER, aud: BRG, required: { ...BINDING }, optional: { bd: digestC }, cross: sameIssSub },
  [TYP.callProof]: {
    iss: BRG,
    sub: re(refRe("agt", "ins", "brg")),
    aud: INS,
    required: { call: re(idRe("call")) },
    optional: { gjti: ulidC, op: str(128), in: digestC, ctx: digestC, hook: str(128), phase: oneOf(HOOK_PHASES), bop: oneOf(BRIDGE_OPS), hv: holdVerdictC, bd: digestC },
    // variants told apart by exactly one of gjti / hook / bop (CREDENTIALS §10); v0.1.52 (C268 B): `bd` (sha256 of the raw hook
    // request body) is allowed ONLY on the hook variant; on an op or bridge-op proof it stays an unknown claim ("... proof shape")
    cross: (c) => {
      const variants = ["gjti", "hook", "bop"].filter((k) => has(c, k));
      if (variants.length !== 1) return "call proof variant";
      const only = (req: string[], allowed: string[]) =>
        req.every((k) => has(c, k)) && Object.keys(c).every((k) => BASE.includes(k) || k === "call" || req.includes(k) || allowed.includes(k));
      if (variants[0] === "gjti") return CALLER(c.sub) && only(["gjti", "op", "in", "ctx"], ["hv"]) ? null : "op proof shape";
      if (variants[0] === "hook") return CALLER(c.sub) && only(["hook", "phase", "ctx"], ["in", "bd"]) ? null : "hook proof shape";
      return c.sub === c.iss && only(["bop"], ["op", "in"]) ? null : "bridge-op proof shape";
    },
  },
};
/** Step 5–6 shape check of a claim set for `typ`; returns the failure reason or null. */
function claimsProblem(typ: Typ, c: unknown): string | null {
  const spec = CLAIM_SPECS[typ as ClaimTyp];
  if (!spec) return "typ has no claim set";
  if (!c || typeof c !== "object" || Array.isArray(c)) return "claims not an object";
  const o = c as Record<string, unknown>;
  if (Array.isArray(o.aud)) return "aud is an array";
  if (!spec.iss(o.iss) || !spec.sub(o.sub) || !spec.aud(o.aud)) return "iss/sub/aud format";
  if (!int(o.iat) || !int(o.exp)) return "iat/exp";
  if (spec.document ? has(o, "jti") || has(o, "sub") : !ulidC(o.jti)) return "jti/sub";
  for (const [k, check] of Object.entries(spec.required)) if (!check(o[k])) return `claim ${k}`;
  for (const [k, check] of Object.entries(spec.optional)) if (has(o, k) && !check(o[k])) return `claim ${k}`;
  if (!spec.open) {
    for (const k of Object.keys(o)) if (!BASE.includes(k) && !has(spec.required, k) && !has(spec.optional, k)) return `unknown claim ${k}`;
  }
  return spec.cross ? spec.cross(o) : null;
}

/** Throws if `claims` is not a valid claim set for `typ` (used by every signer). */
export function assertClaims(typ: Typ, claims: object): void {
  const p = claimsProblem(typ, claims);
  if (p) throw new TypeError(`claims for ${typ}: ${p}`);
}

// ── V0 verification ──────────────────────────────────────────────────────────
const B64URL = /^[A-Za-z0-9_-]+$/;
const FORBIDDEN_HEADERS = ["jku", "jwk", "x5u", "x5c", "crit"];

/** Internal failure; `expired` lets the grant verifier report `grant_expired`. */
export interface V0Failure {
  ok: false;
  step: number;
  reason: string;
  expired?: boolean;
}
export interface V0Success<C> {
  ok: true;
  header: { typ: Typ; kid: string };
  claims: C;
}

function b64json(part: string): unknown {
  if (!B64URL.test(part)) return undefined;
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
}

const fail = (step: number, reason: string, expired?: boolean): V0Failure => ({ ok: false, step, reason, ...(expired ? { expired } : {}) });

/**
 * V0 steps 1–4 for any `typ` (shared with the key-set statement verifier): size ≤ `maxBytes`, three base64url parts,
 * header exactly `{alg: EdDSA, typ, kid}` (no jku/jwk/x5u/x5c/crit), `typ` equal, `kid` ∈ `keys`, Ed25519 signature;
 * then the decoded payload (unchecked: claim rules belong to the caller).
 */
export function verifySignedCompact(token: string, keys: KeySet, typ: string, maxBytes: number): { ok: true; kid: string; entry: KeySet["keys"][number]; payload: unknown } | V0Failure {
  // (1) size + 3 parts
  if (typeof token !== "string") return fail(1, "not a string");
  if (token.length > maxBytes) return fail(1, "too large");
  const parts = token.split(".");
  if (parts.length !== 3 || !B64URL.test(parts[2])) return fail(1, "not a compact JWS");
  // (2) header exact, alg, typ
  const header = b64json(parts[0]) as Record<string, unknown> | undefined;
  if (!header || typeof header !== "object" || Array.isArray(header)) return fail(2, "header");
  if (FORBIDDEN_HEADERS.some((h) => has(header, h))) return fail(2, "forbidden header");
  const hk = Object.keys(header);
  if (hk.length !== 3 || header.alg !== "EdDSA" || typeof header.kid !== "string" || typeof header.typ !== "string") return fail(2, "header members");
  if (header.typ !== typ) return fail(2, "typ");
  // (3) kid in the trusted set
  const entry = findKey(keys, header.kid);
  if (!entry) return fail(3, "unknown kid");
  // (4) signature
  const sig = Buffer.from(parts[2], "base64url");
  if (sig.length !== 64) return fail(4, "signature length");
  let good = false;
  try {
    good = edVerify(null, Buffer.from(`${parts[0]}.${parts[1]}`, "ascii"), publicKeyObject(entry.jwk), sig);
  } catch {
    good = false;
  }
  if (!good) return fail(4, "signature");
  return { ok: true, kid: header.kid, entry, payload: b64json(parts[1]) };
}

/** CREDENTIALS §3 V0 steps 1–8 (kind-specific step 9 and one-time step 10 belong to the callers). */
export function verifyV0<C extends object>(token: string, keys: KeySet, expect: JwsExpect): V0Success<C> | V0Failure {
  if (!ALL_TYPS.has(expect.typ)) return fail(2, "typ");
  const sv = verifySignedCompact(token, keys, expect.typ, DOCUMENT_TYPS.has(expect.typ) ? MAX_DOCUMENT_JWS_BYTES : MAX_JWS_BYTES);
  if (!sv.ok) return sv;
  const { entry } = sv;
  const header = { kid: sv.kid };
  // (5) closed claim set, types
  const claims = sv.payload as Record<string, unknown> | undefined;
  const problem = claimsProblem(expect.typ, claims);
  if (problem || !claims) return fail(5, problem ?? "claims");
  // (6) iss allowed for this typ and equal to the issuer the key is trusted for
  if (!expect.iss.includes(claims.iss as string) || entry.issuer !== claims.iss) return fail(6, "iss");
  // (7) aud = verifier's own reference (single string)
  if (typeof expect.aud !== "string" || claims.aud !== expect.aud) return fail(7, "aud");
  // (8) time window + max lifetime
  const iat = claims.iat as number;
  const exp = claims.exp as number;
  if (iat > expect.now + LEEWAY_S) return fail(8, "iat in the future");
  if (exp - iat <= 0 || exp - iat > expect.maxLifetimeS) return fail(8, "lifetime");
  if (expect.now >= exp + LEEWAY_S) return fail(8, "expired", true);
  return { ok: true, header: { typ: expect.typ, kid: header.kid }, claims: claims as C };
}

export const INVALID_TOKEN = "invalid_token";
const refuse = (f: V0Failure, code = INVALID_TOKEN): Refusal => ({ ok: false, code, reason: `step ${f.step}: ${f.reason}` });

/** V0 steps 1–8; every failure → `invalid_token` (the reason names the step for the verifier's log, never the token). */
export function verifyJws<C extends object>(token: string, keys: KeySet, expect: JwsExpect): { ok: true; header: { typ: Typ; kid: string }; claims: C } | Refusal {
  const r = verifyV0<C>(token, keys, expect);
  return r.ok ? r : refuse(r);
}

// ── signing ──────────────────────────────────────────────────────────────────
const enc = (v: unknown) => Buffer.from(JSON.stringify(v), "utf8").toString("base64url");

/** Compact JWS `{alg: EdDSA, typ, kid}`; the claim set is checked against the closed set for `typ` first. */
export async function signJws<C extends object>(typ: Typ, claims: C, key: Ed25519KeyPair): Promise<string> {
  if (!ALL_TYPS.has(typ)) throw new TypeError(`signJws: unknown typ ${typ}`);
  assertClaims(typ, claims);
  return signCompact(typ, claims, key, DOCUMENT_TYPS.has(typ) ? MAX_DOCUMENT_JWS_BYTES : MAX_JWS_BYTES);
}

/**
 * Compact JWS assembly for any `typ` (claims already checked by the caller): header `{alg: EdDSA, typ, kid}`, signature
 * from a key pair or an external signer, size ≤ `maxBytes`. Shared by signJws and the key-set statement signer.
 */
export async function signCompact(typ: string, claims: object, key: Ed25519KeyPair | ExternalSigner, maxBytes: number): Promise<string> {
  if (typeof key?.kid !== "string" || key.kid.length === 0) throw new TypeError("signCompact: key.kid");
  const input = `${enc({ alg: "EdDSA", typ, kid: key.kid })}.${enc(claims)}`;
  let sig: string;
  if ("privateKey" in key) {
    sig = Buffer.from(await webcrypto.subtle.sign({ name: "Ed25519" }, key.privateKey as webcrypto.CryptoKey, Buffer.from(input, "ascii"))).toString("base64url");
  } else {
    sig = await key.sign(input);
    if (typeof sig !== "string" || !B64URL.test(sig) || Buffer.from(sig, "base64url").length !== 64) throw new TypeError("signCompact: signature must be 64 bytes base64url");
  }
  const token = `${input}.${sig}`;
  if (token.length > maxBytes) throw new RangeError(`signCompact: ${typ} exceeds size limit`);
  return token;
}

/** v0.1.1 (C26): external signer — the private key stays outside the process (OS keychain / Secure Enclave). */
export interface ExternalSigner {
  kid: string;
  /** Ed25519 signature over the ASCII signing input, base64url (64 bytes). */
  sign(signingInput: string): string | Promise<string>;
}

/** Same JWS format and claim checks as `signJws`; the signature comes from `signer`. */
export async function signJwsWithSigner<C extends object>(typ: Typ, claims: C, signer: ExternalSigner): Promise<string> {
  if (!ALL_TYPS.has(typ)) throw new TypeError(`signJwsWithSigner: unknown typ ${typ}`);
  assertClaims(typ, claims);
  if (typeof signer?.kid !== "string" || signer.kid.length === 0) throw new TypeError("signJwsWithSigner: signer.kid");
  return signCompact(typ, claims, signer, DOCUMENT_TYPS.has(typ) ? MAX_DOCUMENT_JWS_BYTES : MAX_JWS_BYTES);
}

/** Claims as callers pass them to a signer: `iat` explicit (pure), `exp` defaults to `iat + max`, `jti` to a fresh ULID. */
export type Issue<C> = Omit<C, "iat" | "exp" | "jti"> & { iat: number; exp?: number; jti?: Ulid };

/** Fills `exp`/`jti`, enforcing `0 < exp − iat ≤ maxLifetimeS`. */
export function issueClaims<C>(claims: Issue<C>, maxLifetimeS: number): C {
  const exp = claims.exp ?? claims.iat + maxLifetimeS;
  if (!int(claims.iat) || !int(exp) || exp - claims.iat <= 0 || exp - claims.iat > maxLifetimeS) {
    throw new RangeError(`lifetime must be 1..${maxLifetimeS} s`);
  }
  return { ...claims, exp, jti: claims.jti ?? ulid() } as C;
}

// ── replay ───────────────────────────────────────────────────────────────────
/** One-time check: returns true and records `jti` until `until` (epoch s) if unseen, false if seen (replay). */
export type ReplayGuard = (jti: string, until: number, now: number) => boolean;

/** In-memory replay set (enough for proofs, CREDENTIALS §10); entries are pruned after `until`. */
export function memoryReplayGuard(): ReplayGuard {
  const seen = new Map<string, number>();
  let inserts = 0;
  return (jti, until, now) => {
    if (++inserts % 256 === 0) for (const [k, u] of seen) if (u < now) seen.delete(k);
    const u = seen.get(jti);
    if (u !== undefined && u >= now) return false;
    seen.set(jti, until);
    return true;
  };
}

// ── assertions (CREDENTIALS §10, §17) ────────────────────────────────────────
interface AssertionClaimsByTyp {
  "tb-agent-assert+jwt": AgentAssertionClaims;
  "tb-bridge-assert+jwt": BridgeAssertionClaims;
  "tb-pair-state+jwt": PairStateClaims;
  "tb-instance-assert+jwt": InstanceAssertionClaims;
  "tb-owner-assert+jwt": OwnerAssertionClaims;
}
export type AssertionTyp = keyof AssertionClaimsByTyp;
const BOUND_TYPS: ReadonlySet<string> = new Set([TYP.bridgeAssertion, TYP.instanceAssertion, TYP.ownerAssertion]);
const ASSERTION_TYPS: ReadonlySet<string> = new Set([TYP.agentAssertion, ...BOUND_TYPS, TYP.pairState]);
const assertionLifetime = (typ: AssertionTyp) => (typ === TYP.pairState ? LIFETIME_S.pairState : LIFETIME_S.proof);

export interface RequestBindingInput {
  method: string;
  /** path + query, as received */
  pathAndQuery: string;
  /** raw body; absent or empty = no body */
  body?: Uint8Array;
}

/**
 * Signs an agent / bridge / pair-state / instance / owner assertion. Request-bound typs (bridge, instance, owner)
 * require `request`; `htm`, `htu` and `bd` (sha256 of the raw body, only when a body exists) are derived from it.
 */
export async function signAssertion<T extends AssertionTyp>(
  typ: T,
  claims: Issue<Omit<AssertionClaimsByTyp[T], "htm" | "htu" | "bd">>,
  key: Ed25519KeyPair,
  request?: RequestBindingInput,
): Promise<string> {
  if (!ASSERTION_TYPS.has(typ)) throw new TypeError(`signAssertion: ${typ} is not an assertion typ`);
  const full: Record<string, unknown> = { ...issueClaims<Record<string, unknown>>(claims as Issue<Record<string, unknown>>, assertionLifetime(typ)) };
  if (BOUND_TYPS.has(typ)) {
    if (!request) throw new TypeError(`signAssertion: ${typ} needs the request binding`);
    full.htm = request.method.toUpperCase();
    full.htu = request.pathAndQuery;
    if (request.body && request.body.length > 0) full.bd = sha256Bytes(request.body);
  } else if (request) {
    throw new TypeError(`signAssertion: ${typ} carries no request binding`);
  }
  return signJws(typ, full, key);
}

/** Instance assertion for header `TB-Assert` (types/sdk.ts §A). */
export async function signInstanceAssertion(input: {
  key: Ed25519KeyPair;
  ins: InstanceId;
  svc?: string;
  bridge: BridgeId;
  method: string;
  pathAndQuery: string;
  body?: Uint8Array;
  now: number;
}): Promise<string> {
  const ref = `tb:ins:${input.ins}` as const;
  return signAssertion(
    TYP.instanceAssertion,
    { iss: ref, sub: ref, aud: `tb:brg:${input.bridge}`, iat: input.now, ...(input.svc !== undefined ? { svc: input.svc } : {}) },
    input.key,
    { method: input.method, pathAndQuery: input.pathAndQuery, body: input.body },
  );
}

export interface AssertionExpect {
  typ: AssertionTyp;
  /** verifier's own reference (`tb:brg:<self>` or `tb:portal`) */
  aud: string;
  /** epoch seconds */
  now: number;
  /** request-bound typs only: the received method, path + query and raw body */
  method?: string;
  pathAndQuery?: string;
  body?: Uint8Array;
  /** one-time `jti` set (CREDENTIALS §10: until `exp + L`); omit only when the caller records `jti` itself */
  replay?: ReplayGuard;
}

/**
 * Generic assertion verifier: V0 with `keys` = the signer's trusted keys (their issuer = the allowed `iss`), `iss = sub`,
 * lifetime ≤ 60 s (pair state ≤ 600 s); request-bound typs: `htm`/`htu` equal, `bd` present iff a body exists and equal
 * to its sha256; then the replay check. Kind checks against live state (connection active, `kid` = registered key, pause
 * rules) stay with the caller. Every failure → `invalid_token`.
 */
export function verifyAssertion<T extends AssertionTyp>(token: string, keys: KeySet, expect: AssertionExpect & { typ: T }): { ok: true; header: { typ: Typ; kid: string }; claims: AssertionClaimsByTyp[T] } | Refusal {
  if (!ASSERTION_TYPS.has(expect.typ)) return { ok: false, code: INVALID_TOKEN, reason: "not an assertion typ" };
  const issuers = [...new Set(keys.keys.map((k) => k.issuer as string))];
  const r = verifyV0<AssertionClaimsByTyp[T]>(token, keys, { typ: expect.typ, aud: expect.aud, iss: issuers, now: expect.now, maxLifetimeS: assertionLifetime(expect.typ) });
  if (!r.ok) return refuse(r);
  const c = r.claims as unknown as Record<string, unknown>;
  if (BOUND_TYPS.has(expect.typ)) {
    if (typeof expect.method !== "string" || typeof expect.pathAndQuery !== "string") return refuse({ ok: false, step: 9, reason: "binding not supplied" });
    if (c.htm !== expect.method.toUpperCase() || c.htu !== expect.pathAndQuery) return refuse({ ok: false, step: 9, reason: "htm/htu" });
    const hasBody = !!expect.body && expect.body.length > 0;
    if (hasBody ? c.bd !== sha256Bytes(expect.body as Uint8Array) : has(c, "bd")) return refuse({ ok: false, step: 9, reason: "bd" });
  }
  if (expect.replay && !expect.replay(c.jti as string, (c.exp as number) + LEEWAY_S, expect.now)) return refuse({ ok: false, step: 10, reason: "jti replay" });
  return r;
}
