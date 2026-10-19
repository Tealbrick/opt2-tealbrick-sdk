// decision.ts: gate() step order (CORE §7, I4) and authorize() order (CORE §7, I1, C8, SDK-API §2).
import assert from "node:assert/strict";
import { test } from "node:test";
import type { GrantClaims } from "@opt2-tealbrick/spec/credentials";
import type { AuthorizeInput, GateInput, OperationView } from "@opt2-tealbrick/spec/sdk";
import { authorize, gate } from "../src/decision.ts";
import type { Issue } from "../src/jws.ts";
import { signGrant } from "../src/tokens.ts";
import { world } from "./fixtures.ts";

const op = (over: Partial<Extract<OperationView, { standard: false }>> = {}): OperationView => ({
  standard: false,
  id: "notes_search",
  title: "Search",
  description: "Search notes",
  crud: ["read"],
  effect: "read",
  scopeType: "area",
  idempotency: "none",
  receipt: true,
  audience: "agent",
  ...over,
});
const holdStatus: OperationView = { standard: true, id: "tb.hold_status", title: "Hold status", crud: ["read"], effect: "read", audience: "agent", idempotency: "none", receipt: false };

async function setup(grant: Partial<Issue<GrantClaims>> = {}) {
  const w = await world();
  const token = await signGrant(w.grantClaims(grant), w.portal);
  const bad = await signGrant(w.grantClaims(grant), w.stranger);
  const gateIn = (over: Partial<GateInput> = {}): GateInput => ({
    paused: { workspace: false, agent: false, connection: false, instance: false },
    grant: token,
    trust: w.trust,
    op: op(),
    declaredScopeTypes: ["area"],
    ...over,
  });
  const authIn = (over: Partial<AuthorizeInput> = {}): AuthorizeInput => ({
    paused: { workspace: false, instance: false, agent: false },
    grant: token,
    trust: w.trust,
    op: { id: "notes_search", crud: ["read"], effect: "read", scopeType: "area" },
    access: { level: "read", crud: ["read"] },
    usage: {},
    approval: "none",
    holdVerdict: null,
    ...over,
  });
  return { w, token, bad, gateIn, authIn };
}

test("gate: pass, and each step refuses in order", async () => {
  const { gateIn, bad } = await setup();
  assert.deepEqual(gate(gateIn()), { decision: "pass", reason: "pass" });
  // (1) paused wins over everything, including an invalid grant
  for (const k of ["workspace", "agent", "connection", "instance"] as const) {
    const paused = { workspace: false, agent: false, connection: false, instance: false, [k]: true };
    assert.deepEqual(gate(gateIn({ paused, grant: bad })), { decision: "refuse", reason: "paused" }, k);
  }
  // (2) grant invalid wins over CRUD
  assert.deepEqual(gate(gateIn({ grant: bad, op: op({ crud: ["delete"] }) })), { decision: "refuse", reason: "grant_invalid" });
  // (3) CRUD ceiling (v0.1.27, C283 A1: UNSCOPED ops only), audience, scope type
  assert.equal(gate(gateIn({ op: op({ crud: ["read", "delete"], scopeType: undefined }), declaredScopeTypes: [] })).reason, "crud_exceeds_grant");
  assert.equal(gate(gateIn({ op: op({ audience: "person" }) })).reason, "audience_not_agent");
  assert.equal(gate(gateIn({ op: op({ scopeType: "folder" }) })).reason, "scope_type_unknown");
  assert.equal(gate(gateIn({ op: op({ scopeType: undefined }), declaredScopeTypes: [] })).decision, "pass");
  // (3) before (4): CRUD failure reported even when not in wf
  assert.equal(gate(gateIn({ op: op({ crud: ["delete"], scopeType: undefined }), declaredScopeTypes: [] })).reason, "crud_exceeds_grant");
});

test("gate: Bound workflow (4)", async () => {
  const { gateIn } = await setup({ mode: "bound", wf: ["notes_search"] });
  assert.equal(gate(gateIn()).decision, "pass");
  assert.equal(gate(gateIn({ op: op({ id: "notes_list" }) })).reason, "not_in_workflow");
});

test("gate: tb.hold_status passes with any valid grant (I4), never with an invalid one", async () => {
  const { gateIn, bad } = await setup({ crud: ["create"], mode: "bound", wf: [] });
  assert.equal(gate(gateIn({ op: holdStatus })).decision, "pass");
  assert.equal(gate(gateIn({ op: holdStatus, grant: bad })).reason, "grant_invalid");
  assert.equal(gate(gateIn({ op: holdStatus, paused: { workspace: true, agent: false, connection: false, instance: false } })).reason, "paused");
});

test("gate: expired / revoked grants carry their codes", async () => {
  const { w, gateIn, token } = await setup();
  assert.equal(gate(gateIn({ trust: { ...w.trust, now: w.trust.now + 43200 + 30 } })).reason, "grant_expired");
  const jti = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).jti;
  assert.equal(gate(gateIn({ trust: { ...w.trust, revokedJtis: new Set([jti]) } })).reason, "grant_revoked");
});

test("authorize: run, pause (0), grant (1), scope (2)", async () => {
  const { authIn, bad } = await setup();
  assert.deepEqual(authorize(authIn()), { decision: "run", reason: "run", admittedBy: "portal_grant" });
  for (const k of ["workspace", "instance", "agent"] as const) {
    const paused = { workspace: false, instance: false, agent: false, [k]: true };
    assert.deepEqual(authorize(authIn({ paused, grant: bad })), { decision: "refuse", reason: "paused" }, k);
  }
  // paused also blocks an approved held action (pause matrix: release refused while paused)
  assert.equal(authorize(authIn({ paused: { workspace: true, instance: false, agent: false }, approval: "approved" })).reason, "paused");
  assert.deepEqual(authorize(authIn({ grant: bad })), { decision: "refuse", reason: "grant_invalid" });
  // op.crud ⊄ grant.crud
  assert.equal(authorize(authIn({ op: { id: "notes_delete", crud: ["delete"], effect: "destructive", scopeType: "area" }, access: { level: "all", crud: ["read", "delete"] } })).reason, "scope_denied");
  // op.crud ⊄ access.crud
  assert.equal(authorize(authIn({ op: { id: "notes_add", crud: ["create"], effect: "write", scopeType: "area" } })).reason, "scope_denied");
  // scopeType but no access row
  assert.equal(authorize(authIn({ access: null })).reason, "scope_denied");
  // no scopeType: access is not consulted
  assert.equal(authorize(authIn({ op: { id: "ping", crud: ["read"], effect: "read" }, access: null })).decision, "run");
  // grant failure before scope check
  assert.equal(authorize(authIn({ grant: bad, access: null })).reason, "grant_invalid");
});

test("authorize: holds (3) — money always, held family, approval once per call", async () => {
  const { authIn } = await setup({ crud: ["read", "create", "update"], held: ["first_contact"] });
  const write = { level: "rw", crud: ["read", "create", "update"] as ("read" | "create" | "update")[] };
  const money = { id: "pay", crud: ["create"] as "create"[], effect: "money" as const, scopeType: "area" };
  assert.deepEqual(authorize(authIn({ op: money, access: write })), { decision: "hold", reason: "held_money", holdFamily: "money", admittedBy: "portal_grant" });
  assert.deepEqual(authorize(authIn({ op: money, access: write, approval: "approved" })), { decision: "run", reason: "approved", admittedBy: "portal_grant" });
  const contact = { id: "send", crud: ["create"] as "create"[], effect: "outward" as const, holdFamily: "first_contact" as const, scopeType: "area" };
  assert.deepEqual(authorize(authIn({ op: contact, access: write })), { decision: "hold", reason: "held_family", holdFamily: "first_contact", admittedBy: "portal_grant" });
  assert.equal(authorize(authIn({ op: { ...contact, holdFamily: "live_call" }, access: write })).decision, "run");
  assert.equal(authorize(authIn({ op: contact, access: write, approval: "approved" })).decision, "run");
  // scope refusal precedes holds
  assert.equal(authorize(authIn({ op: money, access: { level: "r", crud: ["read"] } })).reason, "scope_denied");
});

test("authorize: Free caps (4) after holds; money has no cap", async () => {
  const { authIn } = await setup({ crud: ["read", "create"], held: ["first_contact"], caps: { write: { max: 5, per: "hour" }, outward: { max: 0, per: "day" } } });
  const access = { level: "rw", crud: ["read", "create"] as ("read" | "create")[] };
  const add = { id: "notes_add", crud: ["create"] as "create"[], effect: "write" as const, scopeType: "area" };
  assert.equal(authorize(authIn({ op: add, access, usage: { write: 4 } })).decision, "run");
  assert.deepEqual(authorize(authIn({ op: add, access, usage: { write: 5 } })), { decision: "hold", reason: "caps_exceeded", holdFamily: "caps", admittedBy: "portal_grant" });
  assert.equal(authorize(authIn({ op: add, access, usage: { write: 5 }, approval: "approved" })).decision, "run");
  // max 0 holds the first call; usage of another effect does not count
  const send = { id: "send", crud: ["create"] as "create"[], effect: "outward" as const, scopeType: "area" };
  assert.equal(authorize(authIn({ op: send, access, usage: { write: 100 } })).reason, "caps_exceeded");
  // destructive has no cap in this grant → run
  assert.equal(authorize(authIn({ op: { ...add, effect: "destructive" }, access, usage: { destructive: 999 } })).decision, "run");
  // held family wins over caps
  assert.equal(authorize(authIn({ op: { ...send, holdFamily: "first_contact" }, access, usage: { outward: 9 } })).holdFamily, "first_contact");
});

test("authorize: tb.hold_status skips the scope step (I4)", async () => {
  const { authIn, bad } = await setup({ crud: ["create"] });
  const hs = { id: "tb.hold_status", crud: ["read"] as "read"[], effect: "read" as const };
  assert.equal(authorize(authIn({ op: hs, access: null })).decision, "run");
  assert.equal(authorize(authIn({ op: hs, access: null, grant: bad })).reason, "grant_invalid");
});

test("authorize v0.1.13 (G1): a hook hold verdict holds after scope; approval runs once; scope refusal wins", async () => {
  const { authIn } = await setup({ crud: ["read", "create"] });
  const access = { level: "rw", crud: ["read", "create"] as ("read" | "create")[] };
  const add = { id: "notes_add", crud: ["create"] as "create"[], effect: "write" as const, scopeType: "area" };
  const hv = { family: "policy" as const, reason: "needs owner review", by: "rules/rules_gate" };
  assert.deepEqual(authorize(authIn({ op: add, access, holdVerdict: hv })), { decision: "hold", reason: "held_by_hook", holdFamily: "policy", heldBy: "rules/rules_gate", admittedBy: "portal_grant" });
  assert.equal(authorize(authIn({ op: add, access, holdVerdict: hv, approval: "approved" })).decision, "run");
  assert.equal(authorize(authIn({ op: add, access: { level: "r", crud: ["read"] }, holdVerdict: hv })).reason, "scope_denied");
  // a read op is held too when a hook says so
  assert.equal(authorize(authIn({ holdVerdict: { ...hv, family: "first_contact" } })).holdFamily, "first_contact");
});

test("gate + authorize v0.1.13 (G4): tb.holds_pending needs only a valid grant (I4)", async () => {
  const { authIn, gateIn, bad } = await setup({ crud: ["create"], mode: "bound", wf: ["notes_add"] });
  const hp = { id: "tb.holds_pending", crud: ["read"] as "read"[], effect: "read" as const };
  assert.equal(authorize(authIn({ op: hp, access: null })).decision, "run");
  const view = { standard: true as const, id: "tb.holds_pending" as const, title: "Pending approvals", crud: ["read"] as "read"[], effect: "read" as const, audience: "agent" as const, idempotency: "none" as const, receipt: false as const };
  assert.equal(gate(gateIn({ op: view })).decision, "pass");
  assert.equal(gate(gateIn({ op: view, grant: bad })).reason, "grant_invalid");
});

test("C111a (spec 0.1.19): a non-empty wf limits ops in ANY mode; caps apply in any mode", async () => {
  const free = await setup({ mode: "free", wf: ["notes_search"], crud: ["read", "create"], caps: { write: { max: 1, per: "hour" } } });
  const view = (id: string, crud: ("read" | "create")[], effect: "read" | "write") => ({ standard: false as const, id, title: id, description: id, crud, effect, audience: "agent" as const, idempotency: "none" as const, receipt: false, input: { type: "object" as const }, output: { type: "object" as const }, scopeType: "area" }) as unknown as OperationView;
  assert.equal(gate(free.gateIn({ op: view("notes_search", ["read"], "read") })).decision, "pass");
  assert.deepEqual(gate(free.gateIn({ op: view("notes_add", ["create"], "write") })), { decision: "refuse", reason: "not_in_workflow" });
  // Free with an empty wf keeps verb-level access
  const open = await setup({ mode: "free", wf: [], crud: ["read", "create"] });
  assert.equal(gate(open.gateIn({ op: view("notes_add", ["create"], "write") })).decision, "pass");
  // caps still apply to a Free op-limited grant (authorize)
  const add = { id: "notes_search", crud: ["create"] as "create"[], effect: "write" as const, scopeType: "area" };
  const access = { level: "rw", crud: ["read", "create"] as ("read" | "create")[] };
  assert.equal(authorize(free.authIn({ op: add, access, usage: { write: 0 } })).decision, "run");
  assert.deepEqual(authorize(free.authIn({ op: add, access, usage: { write: 1 } })), { decision: "hold", reason: "caps_exceeded", holdFamily: "caps", admittedBy: "portal_grant" });
});

test("opInGrantWorkflow / opVisibleToGrant (L1): tools/list shows exactly what gate() steps 3–4 pass", async () => {
  const { gate: g, opInGrantWorkflow, opVisibleToGrant } = await import("../src/decision.ts");
  assert.equal(opInGrantWorkflow({ mode: "free", wf: [] }, "x"), true);
  assert.equal(opInGrantWorkflow({ mode: "free", wf: ["a"] }, "x"), false);
  assert.equal(opInGrantWorkflow({ mode: "bound", wf: [] }, "x"), false);
  assert.equal(opInGrantWorkflow({ mode: "bound", wf: ["x"] }, "x"), true);
  const view = (id: string, crud: ("read" | "create")[], over: Record<string, unknown> = {}) =>
    ({ standard: false, id, title: id, description: id, crud, effect: crud.includes("create") ? "write" : "read", audience: "agent", idempotency: "none", receipt: false, input: { type: "object" }, output: { type: "object" }, scopeType: "area", ...over }) as unknown as OperationView;
  const hp = { standard: true as const, id: "tb.holds_pending" as const, title: "p", crud: ["read"] as "read"[], effect: "read" as const, audience: "agent" as const, idempotency: "none" as const, receipt: false as const };
  for (const grant of [
    { mode: "free" as const, wf: [] as string[], crud: ["read", "create"] as ("read" | "create")[] },
    { mode: "free" as const, wf: ["notes_search"], crud: ["read", "create"] as ("read" | "create")[] },
    { mode: "bound" as const, wf: ["notes_add"], crud: ["read"] as ("read" | "create")[] },
  ]) {
    const s = await setup(grant);
    for (const op of [view("notes_search", ["read"]), view("notes_add", ["create"]), view("notes_other", ["read"], { scopeType: "ghost" }), view("person_op", ["read"], { audience: "person" }), view("node_pump", ["read"], { listing: "workflow" }), view("notes_add", ["create"], { listing: "workflow" }), hp]) {
      const listed = opVisibleToGrant(op, grant, ["area"]);
      const passes = g(s.gateIn({ op })).decision === "pass";
      // v0.1.27 (C283 A1): listing is the NARROWER side. Everything listed passes gate(); the only op gate() passes without listing is
      // an agent op WITH a scopeType whose crud is above the grant (the app's own access decides; the bridge lists it via admittedOps)
      const op2 = op as { standard: boolean; crud: string[]; scopeType?: string; audience: string };
      const aboveGrant = !op2.standard && op2.scopeType === "area" && op2.audience === "agent" && !op2.crud.every((c) => (grant.crud as string[]).includes(c));
      if (listed) assert.equal(passes, true, `${grant.mode} wf[${grant.wf}] crud[${grant.crud}] ${op.id}: listed but gate refuses`);
      else if (!aboveGrant) assert.equal(passes, false, `${grant.mode} wf[${grant.wf}] crud[${grant.crud}] ${op.id}: gate passes an op that is not listed`);
    }
  }
});

test("v0.1.21 (LR-1, C234): a listing workflow op is visible and passes ONLY when the grant wf names it, in any mode", async () => {
  const { gate: g, opInGrantWorkflow, opVisibleToGrant } = await import("../src/decision.ts");
  // fires on bad: a Free card with an empty wf saw every op before; a workflow op must stay hidden from it
  assert.equal(opInGrantWorkflow({ mode: "free", wf: [] }, "node_pump", "workflow"), false);
  assert.equal(opInGrantWorkflow({ mode: "free", wf: ["other"] }, "node_pump", "workflow"), false);
  assert.equal(opInGrantWorkflow({ mode: "bound", wf: ["other"] }, "node_pump", "workflow"), false);
  // quiet on good: the machine card's wf names it
  assert.equal(opInGrantWorkflow({ mode: "free", wf: ["node_pump"] }, "node_pump", "workflow"), true);
  assert.equal(opInGrantWorkflow({ mode: "bound", wf: ["node_pump"] }, "node_pump", "workflow"), true);
  // default listing keeps the old rule
  assert.equal(opInGrantWorkflow({ mode: "free", wf: [] }, "x", "default"), true);
  const pump = { standard: false, id: "node_pump", title: "p", description: "p", crud: ["read"], effect: "read", audience: "agent", idempotency: "none", receipt: false, input: { type: "object" }, output: { type: "object" }, listing: "workflow" } as unknown as OperationView;
  for (const grant of [
    { mode: "free" as const, wf: [] as string[], crud: ["read"] as "read"[] },
    { mode: "free" as const, wf: ["node_pump"], crud: ["read"] as "read"[] },
  ]) {
    const s = await setup(grant);
    const listed = opVisibleToGrant(pump, grant, []);
    const d = g(s.gateIn({ op: pump }));
    assert.equal(listed, grant.wf.includes("node_pump"));
    assert.equal(d.decision === "pass", grant.wf.includes("node_pump"), JSON.stringify(d));
    if (!listed) assert.equal(d.reason, "not_in_workflow");
  }
});

// ── v0.1.27 (C283 A1, C277): the owner-set access row is primary for a scoped op ───────────────────────────────────────────
type Crud = "read" | "create" | "update" | "delete";
const ownerAccess = (crud: Crud[]) => ({ level: "owner_level", crud, authority: "owner" as const });
const boundedAccess = (crud: Crud[]) => ({ level: "bounded_level", crud, authority: "bounded" as const });
const delOp = { id: "notes_delete", crud: ["delete"] as Crud[], effect: "destructive" as const, scopeType: "area" };

test("gate (C283 A1): a scoped op above grant.crud passes to the SDK; an UNSCOPED op above it is still refused (fires on bad)", async () => {
  const { gateIn } = await setup({ crud: ["read"] });
  // fires on bad: before 0.1.27 this refused crud_exceeds_grant at the bridge, so an owner row above the grant could never reach the SDK
  assert.deepEqual(gate(gateIn({ op: op({ crud: ["read", "delete"] }) })), { decision: "pass", reason: "pass" });
  // quiet on good / the rule stays for everything else
  assert.equal(gate(gateIn({ op: op({ crud: ["read", "delete"], scopeType: undefined }), declaredScopeTypes: [] })).reason, "crud_exceeds_grant");
  assert.equal(gate(gateIn({ op: { standard: true, id: "tb.keys_status", title: "k", crud: ["read", "delete"], effect: "read", audience: "agent", idempotency: "none", receipt: false } as OperationView })).reason, "crud_exceeds_grant");
  // the other gate steps still apply to a scoped op above the grant
  assert.equal(gate(gateIn({ op: op({ crud: ["delete"], scopeType: "folder" }) })).reason, "scope_type_unknown");
  assert.equal(gate(gateIn({ op: op({ crud: ["delete"], audience: "person" }) })).reason, "audience_not_agent");
  assert.equal(gate(gateIn({ op: op({ crud: ["delete"], id: "notes_other" }), paused: { workspace: false, agent: true, connection: false, instance: false } })).reason, "paused");
  const bound = await setup({ crud: ["read"], mode: "bound", wf: ["notes_search"] });
  assert.equal(gate(bound.gateIn({ op: op({ id: "notes_delete", crud: ["delete"] }) })).reason, "not_in_workflow");
  assert.equal(gate(bound.gateIn({ op: op({ id: "notes_search", crud: ["read", "delete"] }) })).decision, "pass");
  const bad = await setup({ crud: ["read"] });
  assert.equal(gate(bad.gateIn({ op: op({ crud: ["delete"] }), grant: bad.bad })).reason, "grant_invalid");
});

test("authorize (C283 A1): an owner row admits above the grant; a bounded row is capped by the grant (fires on bad)", async () => {
  const { authIn } = await setup({ crud: ["read"], held: [] });
  // owner row wider than the grant: runs, and the receipt says which rule admitted it
  assert.deepEqual(authorize(authIn({ op: delOp, access: ownerAccess(["read", "delete"]) })), { decision: "run", reason: "run", admittedBy: "app_owner_row" });
  // fires on bad: the same row as `bounded` (or without authority) is refused scope_denied by the Portal ceiling
  assert.deepEqual(authorize(authIn({ op: delOp, access: boundedAccess(["read", "delete"]) })), { decision: "refuse", reason: "scope_denied" });
  assert.deepEqual(authorize(authIn({ op: delOp, access: { level: "x", crud: ["read", "delete"] } })), { decision: "refuse", reason: "scope_denied" });
  // only the exact value "owner" counts
  for (const authority of ["Owner", "primary", "", null, 1, true]) {
    assert.equal(authorize(authIn({ op: delOp, access: { level: "x", crud: ["read", "delete"], authority } as never })).reason, "scope_denied", String(authority));
  }
  // an owner row NARROWER than the grant still narrows (the row's crud is the effective crud)
  const wide = await setup({ crud: ["read", "create", "delete"], held: [] });
  assert.equal(authorize(wide.authIn({ op: delOp, access: ownerAccess(["read"]) })).reason, "scope_denied");
  assert.equal(authorize(wide.authIn({ op: delOp, access: ownerAccess(["read", "delete"]) })).decision, "run");
  // no row at all is a refusal whatever the grant says
  assert.equal(authorize(wide.authIn({ op: delOp, access: null })).reason, "scope_denied");
  // bounded row inside the grant: the Portal grant admits
  assert.deepEqual(authorize(wide.authIn({ op: delOp, access: boundedAccess(["read", "delete"]) })), { decision: "run", reason: "run", admittedBy: "portal_grant" });
});

test("authorize (C283 A1): an UNSCOPED op ignores the access row, also an owner row (fires on bad)", async () => {
  const { authIn } = await setup({ crud: ["read"], held: [] });
  const unscopedDelete = { id: "purge", crud: ["delete"] as Crud[], effect: "destructive" as const };
  assert.deepEqual(authorize(authIn({ op: unscopedDelete, access: ownerAccess(["read", "delete"]) })), { decision: "refuse", reason: "scope_denied" });
  assert.deepEqual(authorize(authIn({ op: unscopedDelete, access: null })), { decision: "refuse", reason: "scope_denied" });
  // within the grant it runs, with no admittedBy (no scope rule applied)
  assert.deepEqual(authorize(authIn({ op: { id: "ping", crud: ["read"], effect: "read" }, access: ownerAccess(["read"]) })), { decision: "run", reason: "run" });
});

test("authorize (C283 A1, S4): pause, revoked/invalid grant, expiry and wrong audience beat an owner row (fires on bad)", async () => {
  const { authIn, bad, w } = await setup({ crud: ["read"], held: [] });
  const access = ownerAccess(["read", "delete"]);
  for (const k of ["workspace", "instance", "agent"] as const) {
    assert.deepEqual(authorize(authIn({ op: delOp, access, paused: { workspace: false, instance: false, agent: false, [k]: true } })), { decision: "refuse", reason: "paused" }, k);
  }
  assert.equal(authorize(authIn({ op: delOp, access, grant: bad })).reason, "grant_invalid");
  // revoked grant (jti in the slice revoked list)
  const good = await signGrant(w.grantClaims({ crud: ["read"] }), w.portal);
  const jti = JSON.parse(Buffer.from(good.split(".")[1] ?? "", "base64url").toString("utf8")).jti as string;
  const revoked = authorize(authIn({ op: delOp, access, grant: good, trust: { ...w.trust, revokedJtis: new Set([jti]) as never } }));
  assert.equal(revoked.decision, "refuse");
  assert.notEqual(revoked.reason, "scope_denied");
  // expired grant
  const expired = authorize(authIn({ op: delOp, access, grant: good, trust: { ...w.trust, now: w.trust.now + 13 * 3600 } }));
  assert.equal(expired.decision, "refuse");
  assert.notEqual(expired.reason, "scope_denied");
});

test("authorize (C283 A1, S6): an owner row never skips a hold, a hook verdict, money or a cap; admittedBy rides along (fires on bad)", async () => {
  const { authIn } = await setup({ crud: ["read"], held: ["destructive"], caps: { destructive: { max: 1, per: "hour" } } });
  const access = ownerAccess(["read", "delete"]);
  const held = authorize(authIn({ op: { ...delOp, holdFamily: "destructive" }, access }));
  assert.deepEqual(held, { decision: "hold", reason: "held_family", holdFamily: "destructive", admittedBy: "app_owner_row" });
  assert.deepEqual(authorize(authIn({ op: delOp, access, usage: { destructive: 1 } })), { decision: "hold", reason: "caps_exceeded", holdFamily: "caps", admittedBy: "app_owner_row" });
  assert.equal(authorize(authIn({ op: { ...delOp, effect: "money" }, access })).holdFamily, "money");
  const hv = { family: "first_contact" as const, reason: "new person", by: "rules/guard" };
  assert.deepEqual(authorize(authIn({ op: delOp, access, holdVerdict: hv })), { decision: "hold", reason: "held_by_hook", holdFamily: "first_contact", heldBy: "rules/guard", admittedBy: "app_owner_row" });
  // approval runs it once, still admitted by the owner row; but a refusal at step 2 beats an approval
  assert.deepEqual(authorize(authIn({ op: delOp, access, approval: "approved" })), { decision: "run", reason: "approved", admittedBy: "app_owner_row" });
  assert.equal(authorize(authIn({ op: delOp, access: boundedAccess(["read", "delete"]), approval: "approved" })).reason, "scope_denied");
  // a refusal never carries admittedBy
  assert.equal("admittedBy" in authorize(authIn({ op: delOp, access: boundedAccess(["read", "delete"]) })), false);
});

test("authorize (C283 A1): tb.hold_status and tb.holds_pending carry no admittedBy and never read the access row", async () => {
  const { authIn } = await setup({ crud: ["create"] });
  const hs = { id: "tb.hold_status", crud: ["read"] as Crud[], effect: "read" as const };
  assert.deepEqual(authorize(authIn({ op: hs, access: null })), { decision: "run", reason: "run" });
});
