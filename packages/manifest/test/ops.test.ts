import assert from "node:assert/strict";
import { describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { STANDARD_OPERATIONS } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import {
  agentOperations,
  DYNAMIC_CALL_INPUT_SCHEMA,
  DYNAMIC_SEARCH_INPUT_SCHEMA,
  derivedToolNames,
  dynamicToolNames,
  isStandardOpId,
  mcpToolName,
  STANDARD_OPERATION_VIEWS,
  standardOpInputSchema,
  toolNameFits,
  withStandardOps,
} from "../src/ops.ts";
import { validateAgainstSchema } from "../src/validate.ts";

const m = (): Manifest => structuredClone(example) as Manifest;

describe("withStandardOps", () => {
  test("manifest ops first (standard: false), then the 11 standard ops in STANDARD_OPERATIONS order", () => {
    const views = withStandardOps(m());
    assert.equal(views.length, example.operations.length + 11);
    assert.deepEqual(
      views.slice(0, example.operations.length).map((v) => [v.id, v.standard]),
      example.operations.map((o) => [o.id, false]),
    );
    assert.deepEqual(
      views.slice(example.operations.length).map((v) => v.id),
      [...STANDARD_OPERATIONS],
    );
  });
  test("audience / crud / effect per SDK-API §6", () => {
    const byId = new Map(STANDARD_OPERATION_VIEWS.map((v) => [v.id, v]));
    const expected: Record<string, [string, string[], string]> = {
      "tb.hold_status": ["agent", ["read"], "read"],
      "tb.holds_list": ["person", ["read"], "read"],
      "tb.holds_decide": ["person", ["update"], "write"],
      "tb.receipts_list": ["person", ["read"], "read"],
      "tb.agents_list": ["person", ["read"], "read"],
      "tb.scopes_set": ["person", ["update"], "write"],
      "tb.keys_status": ["person", ["read"], "read"],
      "tb.key_set": ["person", ["update"], "write"],
      "tb.key_delete": ["person", ["delete"], "write"],
      "tb.export": ["person", ["read"], "read"],
    };
    for (const [id, [audience, crud, effect]] of Object.entries(expected)) {
      const v = byId.get(id as never);
      assert.ok(v, id);
      assert.equal(v.audience, audience, id);
      assert.deepEqual(v.crud, crud, id);
      assert.equal(v.effect, effect, id);
      assert.equal(v.receipt, false, id);
      assert.equal(v.standard, true, id);
    }
  });
  test("results are copies: mutating one does not leak into the next call", () => {
    const first = withStandardOps(m());
    first[first.length - 1].crud.push("delete");
    const second = withStandardOps(m());
    assert.deepEqual(second[second.length - 1].crud, ["read"]);
    assert.throws(() => {
      (STANDARD_OPERATION_VIEWS as any[]).push({});
    });
  });
});

describe("agentOperations", () => {
  test("agent manifest ops + tb.hold_status + tb.holds_pending (v0.1.13), no person ops", () => {
    const ids = agentOperations(m()).map((o) => o.id);
    assert.deepEqual(ids, [
      ...example.operations.filter((o) => o.audience === "agent").map((o) => o.id),
      "tb.hold_status",
      "tb.holds_pending",
    ]);
    assert.ok(!ids.includes("notebook_rename"));
  });
});

describe("tool names", () => {
  test("mcpToolName: <product>__<op>, standard ids use tb_", () => {
    assert.equal(mcpToolName("notes", "note_get"), "notes__note_get");
    assert.equal(mcpToolName("notes", "tb.hold_status"), "notes__tb_hold_status");
  });
  test("dynamicToolNames: _search and _call", () => {
    assert.deepEqual(dynamicToolNames("connect-x", "tools"), { search: "connect-x__tools_search", call: "connect-x__tools_call" });
  });
  test("toolNameFits: ≤ 64 chars and charset", () => {
    assert.equal(toolNameFits("a".repeat(64)), true);
    assert.equal(toolNameFits("a".repeat(65)), false);
    assert.equal(toolNameFits("notes__Note"), false);
    assert.equal(toolNameFits("notes.x"), false);
  });
  test("derivedToolNames: person → none; search → three names; list → base only", () => {
    const ops = m().operations;
    assert.deepEqual(derivedToolNames("notes", ops[7]), []);
    assert.deepEqual(derivedToolNames("notes", ops[0]), ["notes__note_create"]);
    const dyn = { ...ops[1], id: "tools", dynamic: { mode: "search" as const, crudCeiling: ["read" as const], effectCeiling: "read" as const } };
    assert.deepEqual(derivedToolNames("notes", dyn), ["notes__tools", "notes__tools_search", "notes__tools_call"]);
    assert.deepEqual(derivedToolNames("notes", { ...dyn, dynamic: { ...dyn.dynamic, mode: "list" as const } }), ["notes__tools"]);
  });
});

describe("standard op ids and schemas", () => {
  test("isStandardOpId", () => {
    assert.equal(isStandardOpId("tb.export"), true);
    assert.equal(isStandardOpId("tb_export"), false);
    assert.equal(isStandardOpId("note_get"), false);
  });
  test("standardOpInputSchema shapes", () => {
    assert.equal(validateAgainstSchema(standardOpInputSchema("tb.holds_decide"), { holdId: "hld_1", decision: "approve" }).ok, true);
    assert.equal(validateAgainstSchema(standardOpInputSchema("tb.holds_decide"), { holdId: "hld_1", decision: "maybe" }).ok, false);
    assert.equal(validateAgainstSchema(standardOpInputSchema("tb.scopes_set"), { agent: "a", type: "t", id: "i", access: null }).ok, true);
    assert.equal(validateAgainstSchema(standardOpInputSchema("tb.export"), { x: 1 }).ok, false);
  });
  test("tb.scopes_set input (manifest 0.1.28, C283c): acceptOffer is {adds: crud actions} and nothing else", { timeout: 60_000 }, () => {
    const schema = standardOpInputSchema("tb.scopes_set");
    const base = { agent: "a", type: "t", id: "i", access: "write" };
    assert.equal(validateAgainstSchema(schema, { ...base, acceptOffer: { adds: ["delete"] } }).ok, true);
    assert.equal(validateAgainstSchema(schema, { ...base, acceptOffer: { adds: [] } }).ok, true);
    assert.equal(validateAgainstSchema(schema, { ...base, acceptOffer: { adds: ["read", "create", "update", "delete"] } }).ok, true);
    for (const bad of [{ adds: ["drop"] }, {}, { adds: "delete" }, { adds: ["delete"], extra: 1 }, { adds: [1] }, "delete", null, ["delete"], { adds: Array(9).fill("read") }] as Json[]) {
      assert.equal(validateAgainstSchema(schema, { ...base, acceptOffer: bad }).ok, false, JSON.stringify(bad));
    }
    assert.equal(validateAgainstSchema(schema, base).ok, true, "acceptOffer is optional");
    assert.equal(validateAgainstSchema(schema, { ...base, acceptsOffer: { adds: [] } }).ok, false, "an unknown key is still refused");
  });
  test("dynamic call and search input schemas", () => {
    assert.equal(validateAgainstSchema(DYNAMIC_CALL_INPUT_SCHEMA, { tool: "send_mail", arguments: {} }).ok, true);
    assert.equal(validateAgainstSchema(DYNAMIC_CALL_INPUT_SCHEMA, { tool: "Bad Name", arguments: {} }).ok, false);
    assert.equal(validateAgainstSchema(DYNAMIC_SEARCH_INPUT_SCHEMA, { query: "mail", limit: 5 }).ok, true);
    assert.equal(validateAgainstSchema(DYNAMIC_SEARCH_INPUT_SCHEMA, { limit: 5 }).ok, false);
  });
});
