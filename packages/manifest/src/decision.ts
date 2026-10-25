// Decision functions (CORE §7, C8, C10, I1, I4; SDK-API §2): bridge `gate()` and app `authorize()`. Pure, synchronous.
import type { CrudAction } from "@opt2-tealbrick/spec/manifest";
import type { AdmittedBy, AuthorizeInput, Decision, GateDecision, GateInput } from "@opt2-tealbrick/spec/sdk";
import { verifyGrant } from "./tokens.ts";
import { type HoldFamilyFields, holdFamilySet } from "./variants.ts";

export type { AdmittedBy, AuthorizeInput, Decision, GateDecision, GateInput };

/**
 * spec 0.1.74 (C354a), copied until the spec pin moves: `AuthorizeInput` whose effective `op` may carry `holdFamilies` (a
 * dynamic resolution's hold-family SET; the call is held when ANY member is held). Accepts every 0.1.57 `AuthorizeInput`.
 */
export type AuthorizeInputV074 = Omit<AuthorizeInput, "op"> & { op: AuthorizeInput["op"] & HoldFamilyFields };

/** The one standard agent op that needs only a valid grant (CORE §7, I4). */
export const HOLD_STATUS_OP = "tb.hold_status";
/** v0.1.13 (G4): like `tb.hold_status`, a valid grant suffices (an agent sees only its own holds; the SDK filters). */
export const HOLDS_PENDING_OP = "tb.holds_pending";
const ANY_GRANT_OPS: ReadonlySet<string> = new Set([HOLD_STATUS_OP, HOLDS_PENDING_OP]);
/** `reason` values; refusal reasons are the wire error codes (BRIDGE / SDK-API). Grant failures use the verifyGrant code. */
export const DECISION_REASON = {
  paused: "paused",
  crudExceedsGrant: "crud_exceeds_grant",
  audienceNotAgent: "audience_not_agent",
  scopeTypeUnknown: "scope_type_unknown",
  notInWorkflow: "not_in_workflow",
  scopeDenied: "scope_denied",
  heldMoney: "held_money",
  /** v0.1.13 (G1): a before hook's attested hold verdict */
  heldByHook: "held_by_hook",
  heldFamily: "held_family",
  capsExceeded: "caps_exceeded",
  pass: "pass",
  approved: "approved",
  run: "run",
} as const;

const subset = (a: readonly CrudAction[], b: readonly CrudAction[]) => a.every((x) => b.includes(x));

/**
 * v0.1.21 (C111a, Bridge request, L1): THE workflow rule — `op` is allowed by the grant's `wf` iff the grant is Bound or
 * its `wf` is non-empty, and `wf` lists the op; otherwise (Free with an empty `wf`) every op passes this step. gate()
 * step (4) and tools/list use this one function.
 */
export function opInGrantWorkflow(claims: { mode: string; wf: readonly string[] }, opId: string, listing?: string): boolean {
  // v0.1.21 (spec 0.1.43, LR-1 C234): a `listing: "workflow"` op passes ONLY when the grant's wf names it, in any mode
  if (listing === "workflow") return claims.wf.includes(opId);
  return !(claims.mode === "bound" || claims.wf.length > 0) || claims.wf.includes(opId);
}
const listingOf = (op: GateInput["op"]): string | undefined => (op.standard ? undefined : op.listing);

/**
 * v0.1.21 (L1): THE tools/list rule — the static part of gate() steps (3)–(4) for one op and one verified grant: the
 * standard ops that need only a valid grant are listed; otherwise the op is agent-audience, `op.crud ⊆ grant.crud`, its
 * `scopeType` is declared by the target manifest, and opInGrantWorkflow holds. Pause and validity are the caller's
 * (a paused or invalid grant lists nothing). A tool listed here passes gate() steps (3)–(4) when called.
 * v0.1.27 (C283 A1): the converse no longer holds for an op WITH a `scopeType`: gate() passes it above `grant.crud` (the SDK
 * decides with the app's own access), but this function still lists it only when `op.crud ⊆ grant.crud`. A scoped op above the
 * grant is listed through the app's `scope_summary` `admittedOps` (bridge), never from here: listing stays the narrower side.
 */
export function opVisibleToGrant(op: GateInput["op"], claims: { mode: string; wf: readonly string[]; crud: readonly CrudAction[] }, declaredScopeTypes: readonly string[]): boolean {
  if (op.standard && ANY_GRANT_OPS.has(op.id)) return true;
  if (!subset(op.crud, claims.crud) || op.audience !== "agent") return false;
  const scopeType = op.standard ? undefined : op.scopeType;
  if (scopeType !== undefined && !declaredScopeTypes.includes(scopeType)) return false;
  return opInGrantWorkflow(claims, op.id, listingOf(op));
}

/**
 * Bridge, every routed call: (1) paused (workspace, agent, connection, instance) → refuse; (2) `verifyGrant` → refuse
 * with its code; (3) `op.crud ⊆ grant.crud` — v0.1.27 (C283 A1): SKIPPED for an op WITH a `scopeType` (the app's own access
 * may be primary above the Portal grant; the SDK `authorize()` enforces it, and an SDK that does not know the rule still
 * refuses `op.crud ⊄ grant.crud`) — agent audience, `scopeType` declared by the target manifest; (4) Bound or non-empty `wf`:
 * `op.id ∈ grant.wf` — v0.1.19 (C111a): also for a Free grant whose `wf` is non-empty. `tb.hold_status` and
 * `tb.holds_pending` need only a valid grant (I4): they skip (3) and (4). An op WITHOUT a `scopeType` keeps the CRUD ceiling here.
 */
export function gate(input: GateInput): GateDecision {
  const p = input.paused;
  if (p.workspace || p.agent || p.connection || p.instance) return { decision: "refuse", reason: DECISION_REASON.paused };
  const g = verifyGrant(input.grant, input.trust);
  if (!g.ok) return { decision: "refuse", reason: g.code };
  const op = input.op;
  if (op.standard && ANY_GRANT_OPS.has(op.id)) return { decision: "pass", reason: DECISION_REASON.pass };
  const scopeType = op.standard ? undefined : op.scopeType;
  // v0.1.27 (C283 A1): only an op WITH a scope type skips the ceiling (its access is decided by the app); standard and unscoped ops keep it
  if (scopeType === undefined && !subset(op.crud, g.claims.crud)) return { decision: "refuse", reason: DECISION_REASON.crudExceedsGrant };
  if (op.audience !== "agent") return { decision: "refuse", reason: DECISION_REASON.audienceNotAgent };
  if (scopeType !== undefined && !input.declaredScopeTypes.includes(scopeType)) return { decision: "refuse", reason: DECISION_REASON.scopeTypeUnknown };
  // v0.1.19 (C111a): `wf`, when non-empty, limits ops in ANY mode (bound grants always carry a non-empty wf)
  if (!opInGrantWorkflow(g.claims, op.id, listingOf(op))) return { decision: "refuse", reason: DECISION_REASON.notInWorkflow };
  return { decision: "pass", reason: DECISION_REASON.pass };
}

/**
 * App SDK, before executing: (0) slice pause (workspace, instance, calling agent) → refuse `paused`; (1) `verifyGrant`
 * → refuse with its code; (2) an op WITHOUT a `scopeType`: `op.crud ⊆ grant.crud`; an op WITH one (no access → refuse):
 * `access.authority === "owner"` → `op.crud ⊆ access.crud` (v0.1.27, C283 A1: the owner-set row is primary, also above the
 * grant; a narrower owner row still narrows), else (bounded or absent) `op.crud ⊆ grant.crud ∩ access.crud`; failing → `scope_denied`.
 * A scoped op that passed (2) carries `admittedBy` (`app_owner_row` for an owner row, `portal_grant` otherwise) on every
 * later decision (hold, run), never on a refusal. (2b, v0.1.13 G1) a hook hold verdict (proof `hv`) → hold with its family,
 * `heldBy`; (3) effect `money` (always) or any member of the op's hold-family set (`holdFamilySet`: `holdFamilies` ∪
 * {`holdFamily`}, spec 0.1.74) `∈ grant.held` → hold, recording the FIRST held member as `holdFamily`; (4) Free caps:
 * `usage[effect] ≥ caps[effect].max` → hold `caps` (v0.1.19 C111a: in ANY mode, whenever `caps` has the effect); (5) run. An approved hold for this exact call (C8: once per call)
 * skips (2b), (3) and (4). `tb.hold_status` and `tb.holds_pending` skip (2) (I4). Pause, grant validity, holds, caps and `money` are
 * Portal-grant rules an owner row never overrides.
 */
export function authorize(input: AuthorizeInputV074): Decision {
  const p = input.paused;
  if (p.workspace || p.instance || p.agent) return { decision: "refuse", reason: DECISION_REASON.paused };
  const g = verifyGrant(input.grant, input.trust);
  if (!g.ok) return { decision: "refuse", reason: g.code };
  const { op } = input;
  const grant = g.claims;
  let admitted: { admittedBy: AdmittedBy } | Record<string, never> = {};
  if (!ANY_GRANT_OPS.has(op.id)) {
    if (op.scopeType === undefined) {
      if (!subset(op.crud, grant.crud)) return { decision: "refuse", reason: DECISION_REASON.scopeDenied };
    } else {
      const access = input.access;
      if (access === null) return { decision: "refuse", reason: DECISION_REASON.scopeDenied };
      // only the exact value "owner" is primary; absent, "bounded" or anything else keeps the Portal grant as the ceiling
      const owner = access.authority === "owner";
      if (!subset(op.crud, access.crud) || (!owner && !subset(op.crud, grant.crud))) return { decision: "refuse", reason: DECISION_REASON.scopeDenied };
      admitted = { admittedBy: owner ? "app_owner_row" : "portal_grant" };
    }
  }
  if (input.approval === "approved") return { decision: "run", reason: DECISION_REASON.approved, ...admitted };
  // v0.1.13 (G1): the bridge-attested before-hook verdict (proof `hv`) holds after the scope checks
  const hv = input.holdVerdict ?? null;
  if (hv) return { decision: "hold", reason: DECISION_REASON.heldByHook, holdFamily: hv.family, heldBy: hv.by, ...admitted };
  if (op.effect === "money") return { decision: "hold", reason: DECISION_REASON.heldMoney, holdFamily: "money", ...admitted };
  // spec 0.1.74 (C354a): held when ANY member of the set is held (an empty holdFamilies falls back to holdFamily)
  const heldFamily = [...holdFamilySet(op)].find((f) => grant.held.includes(f));
  if (heldFamily !== undefined) return { decision: "hold", reason: DECISION_REASON.heldFamily, holdFamily: heldFamily, ...admitted };
  if (op.effect === "write" || op.effect === "outward" || op.effect === "destructive") {
    const cap = grant.caps[op.effect];
    if (cap && (input.usage[op.effect] ?? 0) >= cap.max) return { decision: "hold", reason: DECISION_REASON.capsExceeded, holdFamily: "caps", ...admitted };
  }
  return { decision: "run", reason: DECISION_REASON.run, ...admitted };
}
