// C373 P1 (spec 0.1.82): per-workflow companion grants in the manifest package — M-CP-4 (schema + rules + target half),
// the `wfl` grant claim (closed claim set), the bridge feature row, the cap constant and the error-code list.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import type { Manifest, ManifestValidation } from "@opt2-tealbrick/spec/manifest";
import manifestSchema from "@opt2-tealbrick/spec/schemas/manifest.schema.json" with { type: "json" };
import { APP_WORKFLOW_GRANTS_CAP } from "../src/caller-context.ts";
import { manifestSchemaP1, WORKFLOW_GRANT_TTL_SEC, WORKFLOW_GRANTS_CAP, WORKFLOW_ID_PATTERN } from "../src/spec-p1.temp.ts";
import { signGrant, verifyGrant } from "../src/tokens.ts";
import { validateCompanions, validateCompanionWorkflows, validateManifest } from "../src/validate.ts";
import { requiredBridgeVersion } from "../src/version.ts";
import { WORKFLOW_GRANT_ERROR_CODES } from "../src/vocab.ts";
import { payloadOf, rawSign, world } from "./fixtures.ts";

const base = (): any => structuredClone(example);
const withPw = (pw: unknown, mut?: (m: any) => void) => {
  const m = base();
  m.companions[0].perWorkflow = pw;
  mut?.(m);
  return m;
};
const issues = (r: ManifestValidation) => (r.ok ? [] : r.errors);
function expectIssue(r: ManifestValidation, rule: string, code: string, path?: string): void {
  assert.equal(r.ok, false, `expected ${rule}/${code}, got ok`);
  const hit = issues(r).find((e) => e.rule === rule && e.code === code && (path === undefined || e.path === path));
  assert.ok(hit, `expected ${rule}/${code}${path ? ` at ${path}` : ""}; got ${JSON.stringify(issues(r))}`);
}
const code = (r: { ok: boolean; code?: string }) => (r.ok ? "ok" : r.code);

describe("M-CP-4 (manifest alone: schema + companionRules)", () => {
  test("a perWorkflow ceiling on a one-product entry validates; the digest covers it", () => {
    const plain = validateManifest(base());
    const r = validateManifest(withPw({ operations: ["event_get", "event_create"], crud: ["read", "create"] }));
    assert.equal(r.ok, true, JSON.stringify(issues(r)));
    assert.ok(plain.ok && r.ok && plain.digest !== r.digest, "perWorkflow changes the manifest digest");
  });
  test("an op may be in operations and in perWorkflow.operations (not narrowed for that op)", () => {
    assert.equal(validateManifest(withPw({ operations: ["event_get"], crud: ["read"] })).ok, true);
  });
  test("perWorkflow on the wildcard entry is refused (schema)", () => {
    const m = base();
    m.companions.push({ product: "*", operations: ["tb.holds_pending"], crud: ["read"], purpose: "x", perWorkflow: { operations: ["event_get"], crud: ["read"] } });
    expectIssue(validateManifest(m), "schema", "schema_invalid");
  });
  test("a standard op in perWorkflow is refused (tb.hold_status, tb.holds_pending, any tb.*)", () => {
    for (const op of ["tb.hold_status", "tb.holds_pending", "tb.receipts_list"]) {
      expectIssue(validateManifest(withPw({ operations: ["event_get", op], crud: ["read"] })), "schema", "schema_invalid");
    }
  });
  test("closed shape: unknown key, missing crud, empty ops, > 64 ops, duplicate ops, unknown crud are refused (schema)", () => {
    const bad: unknown[] = [
      { operations: ["event_get"], crud: ["read"], scopes: [] },
      { operations: ["event_get"] },
      { crud: ["read"] },
      { operations: [], crud: ["read"] },
      { operations: Array.from({ length: 65 }, (_, i) => `op_${i}`), crud: ["read"] },
      { operations: ["event_get", "event_get"], crud: ["read"] },
      { operations: ["event_get"], crud: ["read", "admin"] },
      "event_get",
    ];
    for (const pw of bad) expectIssue(validateManifest(withPw(pw)), "schema", "schema_invalid");
  });
  test("64 ops is the limit and validates", () => {
    assert.equal(validateManifest(withPw({ operations: Array.from({ length: 64 }, (_, i) => `op_${i}`), crud: ["read"] })).ok, true);
  });
  test("the TEMP schema is a copy: the imported spec schema object is not changed", () => {
    const s = manifestSchemaP1() as { $defs: { companion: { properties: Record<string, unknown> } } };
    assert.ok(s.$defs.companion.properties.perWorkflow);
    const pinned = manifestSchema as unknown as { $defs: { companion: { properties: Record<string, unknown> } } };
    assert.equal("perWorkflow" in pinned.$defs.companion.properties, false);
  });
});

describe("M-CP-4 target half (validateCompanionWorkflows)", () => {
  const op = (extra: object) => ({
    id: "event_get",
    title: "Get event",
    description: "Get one event.",
    input: { type: "object" },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
    ...extra,
  });
  const create = op({ id: "event_create", crud: ["create"], effect: "write", idempotency: "required" });
  const target = (ops: object[]): Manifest => ({ ...base(), id: "calendar", operations: ops });
  const good = () => withPw({ operations: ["event_get", "event_create"], crud: ["read", "create"] });

  test("matching target passes; validateCompanions (M-CP-2) ignores perWorkflow", () => {
    assert.equal(validateCompanionWorkflows(good(), [target([op({}), create])]).ok, true);
    assert.equal(validateCompanions(good(), [target([op({}), create])]).ok, true);
  });
  test("a perWorkflow op the target does not have → companion_op_invalid at /perWorkflow/operations", () => {
    expectIssue(validateCompanionWorkflows(good(), [target([op({})])]), "M-CP-4", "companion_op_invalid", "/companions/0/perWorkflow/operations");
  });
  test("a person-audience target op → companion_op_invalid", () => {
    expectIssue(validateCompanionWorkflows(good(), [target([op({}), { ...create, audience: "person" }])]), "M-CP-4", "companion_op_invalid", "/companions/0/perWorkflow/operations");
  });
  test("op.crud not within perWorkflow.crud → companion_op_invalid at /perWorkflow/crud", () => {
    const m = withPw({ operations: ["event_get", "event_create"], crud: ["read"] });
    expectIssue(validateCompanionWorkflows(m, [target([op({}), create])]), "M-CP-4", "companion_op_invalid", "/companions/0/perWorkflow/crud");
  });
  test("perWorkflow.crud wider than its ops need → companion_op_invalid", () => {
    const m = withPw({ operations: ["event_get"], crud: ["read", "delete"] });
    expectIssue(validateCompanionWorkflows(m, [target([op({})])]), "M-CP-4", "companion_op_invalid", "/companions/0/perWorkflow/crud");
  });
  test("the base entry's crud is not the ceiling of perWorkflow (separate sets): base read, perWorkflow create is valid", () => {
    const m = withPw({ operations: ["event_create"], crud: ["create"] });
    assert.equal(validateCompanionWorkflows(m, [target([op({}), create])]).ok, true);
    assert.equal(validateCompanions(m, [target([op({}), create])]).ok, true);
  });
  test("a listed dynamic op adds its crudCeiling to the union (C370a); a static op cannot widen", () => {
    const dyn = op({ id: "tools_call", dynamic: { mode: "call", crudCeiling: ["read", "update"] } });
    assert.equal(validateCompanionWorkflows(withPw({ operations: ["tools_call"], crud: ["read", "update"] }), [target([dyn])]).ok, true);
    expectIssue(validateCompanionWorkflows(withPw({ operations: ["tools_call"], crud: ["read", "delete"] }), [target([dyn])]), "M-CP-4", "companion_op_invalid");
  });
  test("targets not supplied and entries without perWorkflow are not checked", () => {
    assert.equal(validateCompanionWorkflows(good(), []).ok, true);
    assert.equal(validateCompanionWorkflows(base(), [target([])]).ok, true);
  });
});

describe("bridge feature row and vocabulary", () => {
  test("requiredBridgeVersion: perWorkflow declared → per_workflow_grants row; absent → no row", () => {
    const r = requiredBridgeVersion(withPw({ operations: ["event_get"], crud: ["read"] }));
    assert.ok(r.reasons.some((x) => x.includes("per-workflow companion grants")), JSON.stringify(r));
    assert.equal(r.bridge, "0.2.12");
    assert.equal(requiredBridgeVersion(base()).reasons.some((x) => x.includes("per-workflow")), false);
  });
  test("cap constant = the spec cap name; error codes are the six spec codes", () => {
    assert.equal(APP_WORKFLOW_GRANTS_CAP, "app_workflow_grants");
    assert.equal(APP_WORKFLOW_GRANTS_CAP, WORKFLOW_GRANTS_CAP);
    assert.deepEqual([...WORKFLOW_GRANT_ERROR_CODES].sort(), [
      "workflow_grant_missing",
      "workflow_grant_required",
      "workflow_grant_withdrawn",
      "workflow_grants_full",
      "workflow_grants_unsupported",
      "workflow_mismatch",
    ]);
  });
});

describe("wfl claim (CREDENTIALS v0.1.82, closed grant claim set)", () => {
  const companion = async () => {
    const w = await world();
    const claims = { ...w.grantClaims({ sub: `tb:ins:${w.other}`, mode: "bound", wf: ["event_get"], held: ["money"], caps: {} }), prd: "observer" };
    return { w, claims };
  };
  test("a companion grant with wfl + prd verifies; signGrant defaults exp to iat + WORKFLOW_GRANT_TTL_SEC; wfl is read back", async () => {
    const { w, claims } = await companion();
    const g = await signGrant({ ...claims, wfl: "weekly-digest" } as never, w.portal);
    const r = verifyGrant(g, w.trust);
    assert.ok(r.ok, JSON.stringify(r));
    assert.equal(r.ok && (r.claims as { wfl?: string }).wfl, "weekly-digest");
    assert.equal(r.ok && r.claims.exp - r.claims.iat, WORKFLOW_GRANT_TTL_SEC);
    assert.equal(WORKFLOW_GRANT_TTL_SEC, 900);
  });
  test("a malformed wfl is refused at signing and at verification (pattern ^[a-z][a-z0-9-]{2,39}$)", async () => {
    const { w, claims } = await companion();
    const header = { alg: "EdDSA", typ: TYP.grant, kid: w.portal.kid };
    const base0 = payloadOf(await signGrant({ ...claims, wfl: "ok-wf" } as never, w.portal));
    const re = new RegExp(WORKFLOW_ID_PATTERN);
    for (const bad of ["", "ab", "Weekly", "1abc", "a_b_c", "x".repeat(41), 7, null]) {
      assert.equal(typeof bad === "string" && re.test(bad), false);
      await assert.rejects(signGrant({ ...claims, wfl: bad } as never, w.portal), `sign wfl ${JSON.stringify(bad)}`);
      assert.equal(code(verifyGrant(await rawSign(header, { ...base0, wfl: bad }, w.portal), w.trust)), "grant_invalid", `verify wfl ${JSON.stringify(bad)}`);
    }
    for (const ok of ["abc", "a-1", `a${"b".repeat(39)}`]) assert.ok(verifyGrant(await rawSign(header, { ...base0, wfl: ok }, w.portal), w.trust).ok, ok);
  });
  test("wfl only on a companion grant, always with prd, and at most WORKFLOW_GRANT_TTL_SEC long (grant_invalid otherwise)", async () => {
    const { w, claims } = await companion();
    const header = { alg: "EdDSA", typ: TYP.grant, kid: w.portal.kid };
    const p = payloadOf(await signGrant({ ...claims, wfl: "ok-wf" } as never, w.portal)) as Record<string, unknown>;
    const agent = payloadOf(await signGrant(w.grantClaims({}), w.portal)) as Record<string, unknown>;
    const { prd: _drop, ...noPrd } = p;
    const cases: [string, Record<string, unknown>][] = [
      ["agent grant with wfl", { ...agent, wfl: "ok-wf", prd: "observer" }],
      ["no prd", noPrd],
      ["lifetime 901 s", { ...p, exp: (p.iat as number) + WORKFLOW_GRANT_TTL_SEC + 1 }],
      ["lifetime 12 h", { ...p, exp: (p.iat as number) + 43200 }],
      ["unknown claim next to wfl", { ...p, zzz: 1 }],
    ];
    for (const [name, payload] of cases) assert.equal(code(verifyGrant(await rawSign(header, payload, w.portal), w.trust)), "grant_invalid", name);
    assert.ok(verifyGrant(await rawSign(header, { ...p, exp: (p.iat as number) + WORKFLOW_GRANT_TTL_SEC }, w.portal), w.trust).ok, "exactly 900 s");
    await assert.rejects(signGrant({ ...claims, wfl: "ok-wf", exp: claims.iat + 43200 } as never, w.portal), "signing a long wfl grant throws");
  });
  test("a base companion grant (no wfl) is unchanged: 12 h, prd optional", async () => {
    const { w, claims } = await companion();
    const r = verifyGrant(await signGrant(claims as never, w.portal), w.trust);
    assert.ok(r.ok);
    assert.equal(r.ok && r.claims.exp - r.claims.iat, 43200);
  });
});
