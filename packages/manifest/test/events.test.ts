// v0.1.30 (spec 0.1.57, C274c/C274d): manifest `events` — M-EV-1..4, the bridge feature row and the shared helpers
// (eventDecl, eventScopeType, validateEventPayload, eventVisibleToGrant) the SDK and the bridge both call (L1).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import type { Manifest, ManifestValidation } from "@opt2-tealbrick/spec/manifest";
import {
  EVENT_DATA_MAX_BYTES,
  eventDecl,
  eventScopeType,
  eventVisibleCrud,
  eventVisibleToGrant,
  requiredBridgeVersion,
  validateEventPayload,
  validateManifest,
} from "../src/index.ts";

const ev = (over: Record<string, unknown> = {}) => ({
  name: "note.shared",
  title: "A note was shared with the agent",
  payloadSchema: { type: "object", additionalProperties: false, required: ["noteId"], properties: { noteId: { type: "string" } } },
  visibleWith: "note_get",
  audience: "target",
  ...over,
});
const withEvents = (events: unknown[], over: Record<string, unknown> = {}): any => ({ ...structuredClone(example), ...over, events });

function issue(r: ManifestValidation, rule: string, code: string): void {
  assert.equal(r.ok, false, `expected ${rule}/${code}, got ok`);
  if (r.ok) return;
  assert.ok(
    r.errors.some((e) => e.rule === rule && e.code === code),
    `expected ${rule}/${code}; got ${JSON.stringify(r.errors)}`,
  );
}

describe("M-EV rules (MANIFEST §16.1)", () => {
  test("a valid declaration (scoped and unscoped, target and granted) validates", () => {
    const m = withEvents([ev(), ev({ name: "note.created", audience: "granted", visibleWith: "note_search" })]);
    const r = validateManifest(m);
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });

  test("M-EV-1: duplicate, pattern, tb. names and a manifest tb → event_name_invalid", () => {
    issue(validateManifest(withEvents([ev(), ev()])), "M-EV-1", "event_name_invalid");
    issue(validateManifest(withEvents([ev({ name: "shared" })])), "M-EV-1", "event_name_invalid");
    issue(validateManifest(withEvents([ev({ name: "Note.Shared" })])), "M-EV-1", "event_name_invalid");
    issue(validateManifest(withEvents([ev({ name: "tb.hold.decided" })])), "M-EV-1", "event_name_invalid");
    issue(validateManifest(withEvents([ev({ name: `n.${"a".repeat(64)}` })])), "M-EV-1", "event_name_invalid");
    issue(validateManifest(withEvents([ev()], { id: "tb" })), "M-EV-1", "event_name_invalid");
    // a manifest tb WITHOUT events is not touched by M-EV-1
    const plain = validateManifest({ ...structuredClone(example), id: "tb" });
    assert.ok(plain.ok || !plain.errors.some((e) => e.rule === "M-EV-1"));
  });

  test("M-EV-2: object root, strict compile, ≤ 8 KiB, M-OP-8 limits → event_schema_invalid", () => {
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "array" } })])), "M-EV-2", "event_schema_invalid");
    // strict: an unknown keyword is refused (the operation-schema compile would accept it)
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: { a: { type: "string", colour: "red" } } } })])), "M-EV-2", "event_schema_invalid");
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: { a: { $ref: "https://x.example/s.json" } } } })])), "M-EV-2", "event_schema_invalid");
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", $id: "urn:x" } })])), "M-EV-2", "event_schema_invalid");
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: { a: { type: "string", contentEncoding: "base64" } } } })])), "M-EV-2", "event_schema_invalid");
    const big: Record<string, unknown> = {};
    for (let i = 0; i < 200; i++) big[`field_${i}`] = { type: "string", description: "x".repeat(30) };
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: big } })])), "M-EV-2", "event_schema_invalid");
    // a local $ref compiles
    const local = validateManifest(withEvents([ev({ payloadSchema: { type: "object", $defs: { id: { type: "string" } }, properties: { noteId: { $ref: "#/$defs/id" } } } })]));
    assert.equal(local.ok, true, JSON.stringify(!local.ok && local.errors));
  });

  test("M-EV-3: visibleWith = an agent op of the manifest, not dynamic → event_visible_with_invalid", () => {
    issue(validateManifest(withEvents([ev({ visibleWith: "no_such_op" })])), "M-EV-3", "event_visible_with_invalid");
    issue(validateManifest(withEvents([ev({ visibleWith: "notebook_rename" })])), "M-EV-3", "event_visible_with_invalid");
    issue(validateManifest(withEvents([ev({ visibleWith: "tb.hold_status" })])), "M-EV-3", "event_visible_with_invalid");
    const dyn = withEvents([ev({ visibleWith: "lookup" })]);
    dyn.operations.push({ id: "lookup", title: "Lookup", description: "Dynamic lookup.", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } });
    issue(validateManifest(dyn), "M-EV-3", "event_visible_with_invalid");
  });

  test("M-EV-4: no top-level summary in the payload schema → event_schema_invalid", () => {
    issue(validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: { summary: { type: "string" } } } })])), "M-EV-4", "event_schema_invalid");
    // a nested `summary` is not top-level
    const nested = validateManifest(withEvents([ev({ payloadSchema: { type: "object", properties: { note: { type: "object", properties: { summary: { type: "string" } } } } } })]));
    assert.equal(nested.ok, true, JSON.stringify(!nested.ok && nested.errors));
  });

  test("requiredBridgeVersion: events declared (also an empty list) → bridge 0.2.7", () => {
    const r = requiredBridgeVersion(withEvents([ev()]));
    assert.equal(r.bridge, "0.2.7");
    assert.ok(r.reasons.some((x) => x.includes("app events (C274)")));
    assert.equal(requiredBridgeVersion(withEvents([])).bridge, "0.2.7");
    assert.equal(requiredBridgeVersion(structuredClone(example) as any).bridge === "0.2.7", false);
  });
});

describe("event helpers (L1: SDK and bridge)", () => {
  const m = withEvents([ev(), ev({ name: "note.created", audience: "granted", visibleWith: "notebook_list" })]) as Manifest;
  // an unscoped agent op for the unscoped event
  (m.operations as unknown[]).push({ id: "notebook_list", title: "List notebooks", description: "List.", input: { type: "object" }, output: { type: "object" }, crud: ["read"], effect: "read", idempotency: "none", receipt: false, audience: "agent" });

  test("eventDecl: manifest declarations, PLATFORM_EVENTS for tb.*, null otherwise", () => {
    assert.equal(eventDecl(m, "note.shared")?.platform, false);
    assert.equal(eventDecl(m, "note.unknown"), null);
    const p = eventDecl(m, "tb.hold.decided");
    assert.equal(p?.platform, true);
    assert.equal(p?.visibleWith, "tb.hold_status");
    assert.equal(p?.audience, "target");
    assert.equal(eventDecl(m, "tb.other"), null);
    assert.equal(eventDecl(m, "tb.constructor"), null);
  });

  test("eventScopeType: the visibleWith op's scopeType, else null", () => {
    assert.equal(eventScopeType(m, eventDecl(m, "note.shared") as never), "notebook");
    assert.equal(eventScopeType(m, eventDecl(m, "note.created") as never), null);
    assert.equal(eventScopeType(m, eventDecl(m, "tb.hold.decided") as never), null);
    assert.deepEqual(eventVisibleCrud(m, { visibleWith: "note_get" }), ["read"]);
  });

  test("validateEventPayload: schema, object, ≤ 2 KiB JCS", () => {
    const d = eventDecl(m, "note.shared") as NonNullable<ReturnType<typeof eventDecl>>;
    assert.equal(validateEventPayload(d, { noteId: "n1" }).ok, true);
    const bad = validateEventPayload(d, { noteId: 1 });
    assert.equal(bad.ok, false);
    assert.equal(!bad.ok && bad.code, "event_payload_invalid");
    assert.equal((validateEventPayload(d, [1]) as { code?: string }).code, "event_payload_invalid");
    assert.equal((validateEventPayload(d, { noteId: "x".repeat(EVENT_DATA_MAX_BYTES) }) as { code?: string }).code, "event_too_large");
    const p = eventDecl(m, "tb.hold.decided") as NonNullable<ReturnType<typeof eventDecl>>;
    assert.equal(validateEventPayload(p, { holdId: "hld_01M53BAEQSGKVVY4PRM2VE6FBF", op: "note_create", decision: "expired" }).ok, true);
    assert.equal(validateEventPayload(p, { holdId: "hld_01M53BAEQSGKVVY4PRM2VE6FBF", op: "note_create", decision: "approve" }).ok, false);
  });

  test("eventVisibleToGrant: the tools/list rule; owner authority skips op.crud ⊆ grant.crud only", () => {
    const shared = { visibleWith: "note_get" };
    const write = { visibleWith: "note_update" };
    const g = (crud: string[], over: Record<string, unknown> = {}) => ({ mode: "free", wf: [] as string[], crud: crud as never, ...over });
    assert.equal(eventVisibleToGrant(m, shared, g(["read"])), true);
    assert.equal(eventVisibleToGrant(m, write, g(["read"])), false, "bounded: op.crud ⊄ grant.crud");
    assert.equal(eventVisibleToGrant(m, write, g(["read"]), "bounded"), false);
    assert.equal(eventVisibleToGrant(m, write, g(["read"]), "owner"), true, "owner row admits above the grant (C283 A1)");
    assert.equal(eventVisibleToGrant(m, write, g(["read"], { mode: "bound", wf: ["note_get"] }), "owner"), false, "the wf rule still applies");
    assert.equal(eventVisibleToGrant(m, { visibleWith: "notebook_rename" }, g(["create", "read", "update", "delete"]), "owner"), false, "person op");
    assert.equal(eventVisibleToGrant(m, { visibleWith: "missing" }, g(["read"])), false);
    assert.equal(eventVisibleToGrant(m, { visibleWith: "tb.hold_status" }, g([], { mode: "bound", wf: ["note_get"] })), true, "any valid grant (I4)");
  });
});
