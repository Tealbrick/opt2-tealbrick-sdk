// manifest 0.1.31 (spec 0.1.76, C330(1), M4b, C354): `listing: "lazy"` — M-OP-13. Capability gating, never a version: no
// requiredBridgeVersion row and no requires.bridge rule (Core and the bridge decide by the `lazy_tools` cap).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import { BRIDGE_FEATURES, requiredBridgeVersion, validateManifest } from "../src/index.ts";

type Op = { id: string; audience: string; dynamic?: unknown; listing?: string };
type M = { operations: Op[]; requires?: { bridge?: string } } & Record<string, unknown>;
const base = (): M => structuredClone(example) as unknown as M;
const withLazy = (): M => {
  const m = base();
  (m.operations.find((o) => o.audience === "agent" && o.dynamic === undefined) as Op).listing = "lazy";
  delete m.requires;
  return m;
};
const codes = (r: ReturnType<typeof validateManifest>) => (r.ok ? [] : r.errors.map((e) => `${e.rule}:${e.code}:${e.path}`));
/** does the pinned spec schema know `lazy`? (false until the pin moves to spec >= 0.1.76) */
const schemaKnowsLazy = !codes(validateManifest(withLazy())).some((c) => c.startsWith("schema:"));

describe("listing lazy (spec 0.1.76)", () => {
  test("C354: no version gate — requiredBridgeVersion ignores lazy ops and BRIDGE_FEATURES has no lazy row", () => {
    assert.deepEqual(requiredBridgeVersion(withLazy() as never), requiredBridgeVersion(base() as never));
    assert.ok(!BRIDGE_FEATURES.some((f) => /lazy/.test(f.feature)));
  });

  test("M-OP-13: a static lazy op without requires.bridge is valid; lazy on a dynamic op → listing_invalid", { skip: schemaKnowsLazy ? false : "the pinned spec schema (before 0.1.76) refuses listing lazy itself (schema_invalid)" }, () => {
    const ok = validateManifest(withLazy());
    assert.equal(ok.ok, true, JSON.stringify(codes(ok)));
    const m = withLazy();
    const engine = { id: "note_engine", title: "Engine", description: "Engine tools", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" } };
    m.operations.push(engine as Op);
    assert.equal(validateManifest(m).ok, true, `the dynamic op itself is valid: ${JSON.stringify(codes(validateManifest(m)))}`);
    (m.operations.at(-1) as Op).listing = "lazy";
    assert.ok(codes(validateManifest(m)).includes(`M-OP-13:listing_invalid:/operations/${m.operations.length - 1}/listing`), JSON.stringify(codes(validateManifest(m))));
  });

  test("today's pin: a lazy manifest is refused by the schema (so no bridge on this validator lists it as hot)", { skip: schemaKnowsLazy ? "the pinned schema accepts lazy" : false }, () => {
    assert.ok(codes(validateManifest(withLazy())).some((c) => c.startsWith("schema:schema_invalid")));
  });
});
