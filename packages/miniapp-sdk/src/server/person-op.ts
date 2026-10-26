// Person op relayed from a native owner session (SDK-API §21, CREDENTIALS K14, spec 0.1.64, C326): the private-network route
// `POST /tb/v1/person-op`, the K14 verifier and the family rule `familyAllowedFor` (C332a(4)).
import type { IncomingMessage, ServerResponse } from "node:http";
import { sha256Bytes, ULID_RE, validateInput, verifySignedCompact } from "@opt2-tealbrick/manifest";
import {
  type InstanceRef,
  LIFETIME_S,
  MAX_JWS_BYTES,
  type PersonId,
  type PersonOpClaims,
  TYP,
  type WorkspaceId,
} from "@opt2-tealbrick/spec/credentials";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import type { Json, KeySet, PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { header, readRaw, requestId, sendError } from "./http.ts";
import { runPersonOp, toTbError } from "./ops.ts";
import type { Runtime } from "./runtime.ts";

/** SPEC-GAP: spec 0.1.64 names the header in SDK-API §21 / CREDENTIALS K14 only (no constant in BRIDGE_HEADERS). */
export const PERSON_OP_HEADER = "TB-Person-Op" as const;
/** Standard ops a relay may name (SDK-API §21: "or tb.holds_list / tb.holds_decide"); they still need an allow-list entry. */
const RELAY_STANDARD_OPS: readonly string[] = ["tb.holds_list", "tb.holds_decide"];

/** K14 relay clients (spec e62bbad: `tbm` only); checked inside V0, so any other `cli` is 401 `person_op_invalid`. */
const RELAY_CLIENTS: readonly string[] = PERSON_OP_RELAY.clients;
/** The ONLY leeway on K14 times (spec e62bbad: the general LEEWAY_S does not apply to K14). */
const K14_LEEWAY_S = PERSON_OP_RELAY.expLeewayS;
const K14_CLAIMS = new Set(["iss", "sub", "aud", "iat", "exp", "jti", "ws", "op", "bd", "idk", "cli", "pop"]);
const ID_BODY = ULID_RE.source.slice(1, -1);
const PER_REF = new RegExp(`^tb:per:per_${ID_BODY}$`);
const WS_ID = new RegExp(`^ws_${ID_BODY}$`);
const POP_ID = new RegExp(`^pop_${ID_BODY}$`);
const DIGEST = /^sha256:[0-9a-f]{64}$/;
/** PersonOpCallInput.idempotencyKey: 16..64 chars [A-Za-z0-9_-] (spec routes.ts) */
const IDK = /^[A-Za-z0-9_-]{16,64}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const int = (v: unknown): v is number => Number.isSafeInteger(v) && (v as number) >= 0;

/**
 * K14 V0 (CREDENTIALS §3 steps 1–8 + the K14 kind checks, SDK-API §21 first step): Portal keys ONLY (`iss = tb:portal`; a
 * standalone or bridge issuer is never accepted), `typ tb-person-op+jwt`, the closed K14 claim set, `aud` = own instance,
 * `ws` = own, `exp − iat ≤ LIFETIME_S.personOp`, `now ≤ exp + PERSON_OP_RELAY.expLeewayS` (NOT the general LEEWAY_S; the same
 * 2 s bound applies to an `iat` in the future), `cli` ∈ `PERSON_OP_RELAY.clients`. One-time `jti`, `personNbf` and `bd` are
 * the route's next steps.
 * SPEC-GAP / L1 note: steps 1–4 are the manifest's `verifySignedCompact`; the K14 claim set lives here until
 * `@opt2-tealbrick/manifest` (built on spec ≤ 0.1.57, no K14 claim set) ships a `verifyPersonOp`; then this moves there.
 */
export function verifyPersonOp(token: string, ctx: { now: number; self: InstanceRef; ws: WorkspaceId; issuers: KeySet }): { ok: true; claims: PersonOpClaims } | { ok: false; reason: string } {
  const portal: KeySet = { keys: ctx.issuers.keys.filter((k) => k.issuer === "tb:portal") };
  const sv = verifySignedCompact(token, portal, TYP.personOp, MAX_JWS_BYTES);
  if (!sv.ok) return { ok: false, reason: `step ${sv.step}: ${sv.reason}` };
  const c = sv.payload;
  if (!isObj(c)) return { ok: false, reason: "step 5: claims not an object" };
  for (const k of Object.keys(c)) if (!K14_CLAIMS.has(k)) return { ok: false, reason: `step 5: unknown claim ${k}` };
  if (typeof c.sub !== "string" || !PER_REF.test(c.sub)) return { ok: false, reason: "step 5: sub" };
  if (!int(c.iat) || !int(c.exp)) return { ok: false, reason: "step 5: iat/exp" };
  if (typeof c.jti !== "string" || !ULID_RE.test(c.jti)) return { ok: false, reason: "step 5: jti" };
  if (typeof c.ws !== "string" || !WS_ID.test(c.ws)) return { ok: false, reason: "step 5: claim ws" };
  if (typeof c.op !== "string" || c.op.length === 0 || c.op.length > 128) return { ok: false, reason: "step 5: claim op" };
  if (typeof c.bd !== "string" || !DIGEST.test(c.bd)) return { ok: false, reason: "step 5: claim bd" };
  if (typeof c.idk !== "string" || !IDK.test(c.idk)) return { ok: false, reason: "step 5: claim idk" };
  if (typeof c.cli !== "string" || c.cli.length === 0 || c.cli.length > 32) return { ok: false, reason: "step 5: claim cli" };
  if (typeof c.pop !== "string" || !POP_ID.test(c.pop)) return { ok: false, reason: "step 5: claim pop" };
  // (6) iss: Portal only, and the key is trusted for exactly that issuer
  if (c.iss !== "tb:portal" || sv.entry.issuer !== "tb:portal") return { ok: false, reason: "step 6: iss" };
  // (7) aud = own instance (single string)
  if (c.aud !== ctx.self) return { ok: false, reason: "step 7: aud" };
  // (9, kind) ws = own workspace
  if (c.ws !== ctx.ws) return { ok: false, reason: "step 9: ws" };
  // (8) lifetime + time window: only PERSON_OP_RELAY.expLeewayS (K14 must end within Core's coreWaitS)
  if (c.exp - c.iat <= 0 || c.exp - c.iat > LIFETIME_S.personOp) return { ok: false, reason: "step 8: lifetime" };
  if (c.iat > ctx.now + K14_LEEWAY_S) return { ok: false, reason: "step 8: iat in the future" };
  if (ctx.now > c.exp + K14_LEEWAY_S) return { ok: false, reason: "step 8: expired" };
  // (9, kind) cli ∈ PERSON_OP_RELAY.clients (SDK-API §21: part of the V0 checks, before the jti is consumed)
  if (!RELAY_CLIENTS.includes(c.cli)) return { ok: false, reason: "step 9: cli" };
  return { ok: true, claims: c as unknown as PersonOpClaims };
}

const invalid = (why: string) => new TbError("person_op_invalid", `relayed person op refused (${why})`, 401);
const notAllowed = () => new TbError("person_op_not_allowed", "this operation is not on the person-op relay list for this client", 403);

/**
 * `POST /tb/v1/person-op` (private network; only the workspace bridge sends it, BRIDGE §15). No cookie, no CSRF. Checks in
 * the SDK-API §21 order: K14 V0 (incl. `cli`) → `jti` unused, then CONSUMED (`tb_used_jti`, until `exp` + expLeewayS) before any body check →
 * `iat ≥` slice `personNbf` → `bd` over the RAW body bytes → allow-list (writes only for `writeClients`) → person op of the
 * own manifest → input schema → idempotency with key = `idk` → the same handler path as `/a/<product>/tb/v1/ops/:op`.
 * Standalone (bridge) and app-alone mode: 503 `person_op_unavailable` (there is no K14 issuer).
 */
export async function handleRelayedPersonOp(rt: Runtime, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const rid = requestId();
  try {
    const unavailable = () => new TbError("person_op_unavailable", "the person-op relay is not available in standalone or app-alone mode", 503);
    if (rt.cfg.standalone || rt.trust.slice?.standalone) throw unavailable();
    const now = Date.now();
    const tctx = rt.trust.context(now);
    if (!tctx) throw new TbError("person_op_unavailable", "no verified instance slice yet", 503);
    const v = verifyPersonOp(header(req, PERSON_OP_HEADER) ?? "", { now: tctx.now, self: tctx.self, ws: tctx.ws, issuers: tctx.issuers });
    if (!v.ok) {
      rt.log.warn("relayed person op refused", { reason: v.reason });
      throw invalid("token");
    }
    const c = v.claims;
    // one-time: consumed BEFORE any body check, so a refused body still spends the token (S-PO-4)
    const used = rt.db.prepare("INSERT OR IGNORE INTO tb_used_jti (jti, exp) VALUES (?, ?)").run(c.jti, c.exp + K14_LEEWAY_S);
    if (Number(used.changes) !== 1) throw invalid("already used");
    if (c.iat < (rt.trust.slice?.personNbf ?? 0)) throw invalid("signed out everywhere after it was minted");
    let raw: Buffer;
    try {
      raw = await readRaw(req, PERSON_OP_RELAY.maxInputBytes);
    } catch (e) {
      // Core never mints K14 for a body over maxInputBytes: a larger body cannot match `bd`
      if (e instanceof TbError && e.code === "payload_too_large") throw invalid("body digest");
      throw e;
    }
    if (sha256Bytes(raw) !== c.bd) throw invalid("body digest");
    const entry = PERSON_OP_RELAY.allow.find((a) => a.product === rt.product);
    const isRead = (entry?.read as readonly string[] | undefined)?.includes(c.op) ?? false;
    const isWrite = (entry?.write as readonly string[] | undefined)?.includes(c.op) ?? false;
    // a write op only for cli ∈ writeClients (cli ∈ clients was a V0 check)
    if (!isRead && !isWrite) throw notAllowed();
    if (isWrite && !(PERSON_OP_RELAY.writeClients as readonly string[]).includes(c.cli)) throw notAllowed();
    const op = rt.ops.get(c.op);
    if (op?.audience !== "person" || (op.standard && !RELAY_STANDARD_OPS.includes(op.id))) throw new TbError("op_not_found", `no person operation ${c.op}`, 404);
    let input: unknown;
    try {
      input = JSON.parse(raw.toString("utf8"));
    } catch {
      throw new TbError("validation_failed", "body is not JSON", 400);
    }
    if (!isObj(input)) throw new TbError("validation_failed", "body must be the op input object", 400);
    const vi = validateInput(op, input as Json);
    if (!vi.ok) throw new TbError("validation_failed", "input does not match the schema", 400, { errors: vi.errors });
    const principal: PersonPrincipal = {
      type: "person",
      id: c.sub.slice("tb:per:".length) as PersonId,
      ws: c.ws,
      instance: rt.instanceId,
      iss: c.iss,
      sessionExpiresAt: c.exp * 1000,
      via: c.cli,
    };
    await runPersonOp(rt, req, res, rid, op, principal, input as Json, op.standard ? null : c.idk);
  } catch (e) {
    sendError(res, rid, toTbError(e, rt));
  }
}
