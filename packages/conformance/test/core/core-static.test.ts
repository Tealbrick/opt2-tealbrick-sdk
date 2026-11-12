// Core target, static layer: the spec route table passes every check; each broken copy fails the right check.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ROUTES, type RouteOp } from "@opt2-tealbrick/spec/routes";
import { CORE_CHECKS, CORE_STATIC_CHECKS, fieldsOf, loadSpecTypes, parseDeclarations, runCoreStatic, stringUnion } from "../../src/index.ts";
import { exampleProductIds } from "../../src/targets.ts";

const types = loadSpecTypes();
const run = (routes: readonly RouteOp[], t = types, productIds = exampleProductIds()) => runCoreStatic({ routes, types: t, productIds });
const failing = (routes: readonly RouteOp[], t = types, productIds?: string[]) =>
  run(routes, t, productIds)
    .filter((c) => c.status === "fail")
    .map((c) => c.id);
const edit = (opId: string, patch: Partial<RouteOp>): RouteOp[] => ROUTES.map((r) => (r.opId === opId ? ({ ...r, ...patch } as RouteOp) : r));
const extraRow = (row: Partial<RouteOp>): RouteOp[] => [...ROUTES, { ...(ROUTES.find((r) => r.opId === "workspaces.list") as RouteOp), ...row } as RouteOp];

describe("core static checks", () => {
  it("the spec route table passes every static check, one result per catalogued id", () => {
    const results = run(ROUTES);
    assert.deepEqual(
      results.map((r) => r.id),
      CORE_STATIC_CHECKS.map((c) => c.id),
    );
    assert.deepEqual(
      results.filter((r) => r.status !== "pass").map((r) => `${r.id}: ${r.asserted}`),
      [],
    );
    const ids = CORE_CHECKS.map((c) => c.id);
    assert.equal(new Set(ids).size, ids.length, "catalogue ids unique");
  });

  it("type scan reads the spec declarations (fields, unions)", () => {
    assert.ok(fieldsOf(types, "DeviceLookupInput").some((f) => f.name === "userCode" && !f.optional));
    assert.ok(stringUnion(types, "SecretBearingSchema").includes("DeviceStart"));
    assert.deepEqual(fieldsOf(types, "NoSuchSchema"), []);
  });

  it("R1: duplicate op id / path, internal row on a gateway path, unknown auth class, mixed person + bridge", () => {
    assert.ok(failing([...ROUTES, ROUTES[0]]).includes("R1.table.unique_ops"));
    assert.ok(failing(extraRow({ opId: "x.dup_path" })).includes("R1.table.unique_paths"));
    assert.ok(failing(edit("workspaces.list", { exposure: "internal" })).includes("R1.table.internal_paths"));
    assert.ok(failing(edit("workspaces.list", { auth: ["anyone" as "public"] })).includes("R1.table.row_fields"));
    assert.ok(failing(edit("workspaces.list", { auth: ["browser", "bridge"] })).includes("R1.table.p1_disjoint"));
    assert.ok(failing(edit("workspaces.list", { auth: ["public"] })).includes("R1.table.explicit_public"));
    assert.ok(failing(edit("workspaces.get", { path: "/workspaces/{id}" })).includes("R1.table.bindings"));
  });

  it("R1 payment webhook (sdk#72): a table on Stripe (spec 0.1.75 rows), on Paddle only, or on both passes; none, a wrong class or a stray class fails", () => {
    const without = (...ids: string[]) => ROUTES.filter((r) => !ids.includes(r.opId));
    assert.deepEqual(failing(without("paddle.webhook")), []);
    assert.deepEqual(failing(without("stripe.webhook")), []);
    assert.deepEqual(failing(ROUTES), []);
    const none = run(without("paddle.webhook", "stripe.webhook")).find((c) => c.id === "R1.table.explicit_public");
    assert.equal(none?.status, "fail");
    assert.match(none?.asserted ?? "", /missing payment webhook row \(paddle\.webhook or stripe\.webhook\)/);
    assert.ok(failing(edit("paddle.webhook", { auth: ["stripe-webhook"] })).includes("R1.table.explicit_public"));
    assert.ok(failing(edit("paddle.webhook", { auth: ["public"] })).includes("R1.table.explicit_public"));
    assert.ok(failing(edit("clerk.webhook", { auth: ["paddle-webhook"] })).includes("R1.table.explicit_public"));
    assert.ok(failing(extraRow({ opId: "x.hook", method: "POST", path: "/x/webhook", auth: ["paddle-webhook"] })).includes("R1.table.explicit_public"));
  });

  it("R5 named exceptions of spec 0.1.67 / 0.1.82 cover exactly their rows", () => {
    assert.ok(!failing(ROUTES).includes("R5.forbidden_ops"));
    assert.ok(failing(extraRow({ opId: "grants.check", method: "POST", path: "/grants/check" })).includes("R5.forbidden_ops"));
    assert.ok(failing(extraRow({ opId: "x.staff", path: "/staff/list" })).includes("R5.forbidden_ops"));
  });

  it("R1 RT9: host auth on a non-host row, a host.* row without host, or a host.* row that also takes another class", () => {
    assert.ok(failing(edit("workspaces.list", { auth: ["host"] })).includes("R1.table.rt9"));
    assert.ok(failing(edit("host.plans", { auth: ["bridge"] })).includes("R1.table.rt9"));
    assert.ok(failing(edit("host.plans", { auth: ["host", "bridge"] })).includes("R1.table.rt9"));
    assert.ok(!failing(ROUTES).includes("R1.table.rt9"), "the spec's own table passes");
  });

  it("R2: owner-cli on a non-draft mutation, on a confirm row, on drafts.apply", () => {
    const mutation = ROUTES.find((r) => r.method !== "GET" && r.auth.join() === "browser" && !r.opId.startsWith("drafts.")) as RouteOp;
    assert.ok(failing(edit(mutation.opId, { auth: ["browser", "owner-cli"] })).includes("R2.owner_cli_rows"));
    assert.ok(failing(edit("workspaces.list", { confirm: true })).includes("R2.owner_cli_no_confirm"));
    assert.ok(failing(edit("drafts.apply", { auth: ["browser", "owner-cli"] })).includes("R2.apply_browser_only"));
    assert.ok(failing(edit("workspaces.list", { draftable: true })).includes("R2.draftable_rows"));
  });

  it("R4: an input field that can hold a key value; a code input on a logged row", () => {
    const evil = parseDeclarations("export interface EvilKeyInput { ws: string; name: string; value: string }");
    const merged = new Map([...types, ...evil]);
    assert.ok(failing(extraRow({ opId: "keys.set", method: "PUT", path: "/workspaces/{ws}/apps/{app}/key-value", input: "EvilKeyInput" as RouteOp["input"] }), merged).includes("R4.no_key_input"));
    assert.ok(failing(edit("device.lookup", { bodyLog: "meta" })).includes("R4.secret_inputs_unlogged"));
  });

  it("R5: forbidden op families, product-named routes, catch-all paths", () => {
    assert.ok(failing(extraRow({ opId: "tools.call", method: "POST", path: "/workspaces/{ws}/tools/call" })).includes("R5.forbidden_ops"));
    assert.ok(failing(extraRow({ opId: "x.jwks", path: "/.well-known/jwks.json" })).includes("R5.forbidden_ops"));
    assert.ok(failing(extraRow({ opId: "x.product", path: "/workspaces/{ws}/acme-notes" }), types, ["acme-notes"]).includes("R5.no_product_routes"));
    assert.ok(failing(extraRow({ opId: "x.v2", path: "/v2/workspaces" })).includes("R5.no_passthrough"));
  });

  it("R7 / R8 / cred.dev: device rows", () => {
    assert.ok(failing(edit("device.token", { idempotent: true })).includes("R7.device_rows"));
    assert.ok(failing(edit("device.approve", { auth: ["browser", "owner-cli"] })).includes("R8.user_code_required"));
    assert.ok(failing(extraRow({ opId: "device.pending", path: "/device/pending", output: "DeviceRequest" })).includes("cred.dev.no_unbound_list"));
    assert.ok(failing(extraRow({ opId: "x.uc", path: "/device/echo", output: "DeviceStart" })).includes("cred.dev.no_clear_user_code"));
  });

  it("R9: a ticket or code reachable with the owner CLI session; secret output on a logged row", () => {
    assert.ok(failing(edit("workspaces.list", { output: "TicketResult" })).includes("R9.owner_cli_outputs"));
    const secretRow = ROUTES.find((r) => r.output === "PairingCode") as RouteOp;
    assert.ok(failing(edit(secretRow.opId, { bodyLog: "meta" })).includes("R9.secret_outputs"));
    const leaky = parseDeclarations("export interface LeakyOut { ticket: string }");
    assert.ok(failing(extraRow({ opId: "x.leak", path: "/leak", auth: ["browser"], output: "LeakyOut" as RouteOp["output"] }), new Map([...types, ...leaky])).includes("R9.secret_list_complete"));
  });

  it("R10: a bodyLog: none row marked idempotent", () => {
    const row = ROUTES.find((r) => r.bodyLog === "none" && r.method !== "GET" && r.auth.some((a) => a === "browser")) as RouteOp;
    assert.ok(failing(edit(row.opId, { idempotent: true })).includes("R10.no_idempotent_secret_rows"));
  });
});
