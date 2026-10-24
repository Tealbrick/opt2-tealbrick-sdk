// manifest 0.1.31 (spec 0.1.66, C330(1), M4b; QA-SPEC48-2/-3): `listing: "lazy"` — M-OP-13 and the requiredBridgeVersion row.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import { compareSemver, LAZY_LISTING_MIN_BRIDGE, requiredBridgeVersion, validateManifest } from "../src/index.ts";

type Op = { id: string; audience: string; dynamic?: unknown; listing?: string };
type M = { operations: Op[]; requires?: { bridge?: string } } & Record<string, unknown>;
const base = (): M => structuredClone(example) as unknown as M;
const staticAgentOp = (m: M) => m.operations.find((o) => o.audience === "agent" && o.dynamic === undefined) as Op;
const withLazy = (requires?: string): M => {
  const m = base();
  staticAgentOp(m).listing = "lazy";
  if (requires === undefined) delete m.requires;
  else m.requires = { ...(m.requires ?? {}), bridge: requires };
  return m;
};
const codes = (r: ReturnType<typeof validateManifest>) => (r.ok ? [] : r.errors.map((e) => `${e.rule}:${e.code}:${e.path}`));
/** does the pinned spec schema know `lazy`? (false until the pin moves to spec >= 0.1.66) */
const schemaKnowsLazy = !codes(validateManifest(withLazy(LAZY_LISTING_MIN_BRIDGE))).some((c) => c.startsWith("schema:"));

describe("listing lazy (spec 0.1.66)", () => {
  test("requiredBridgeVersion: any lazy op → at least LAZY_LISTING_MIN_BRIDGE, with the reason; none → no lazy row", () => {
    const r = requiredBridgeVersion(withLazy() as never);
    assert.ok(r.bridge !== null && compareSemver(r.bridge, LAZY_LISTING_MIN_BRIDGE) >= 0);
    assert.ok(r.reasons.some((x) => x.startsWith(`${LAZY_LISTING_MIN_BRIDGE}:`) && x.includes("lazy_tools")));
    assert.ok(!requiredBridgeVersion(base() as never).reasons.some((x) => x.includes("lazy_tools")));
  });

  test("M-OP-13: requires.bridge absent or below the minimum → listing_invalid; at the minimum → valid; lazy on a dynamic op → listing_invalid", { skip: schemaKnowsLazy ? false : "the pinned spec schema (before 0.1.66) refuses listing lazy itself (schema_invalid)" }, () => {
    for (const rb of [undefined, "0.2.7"]) {
      assert.ok(codes(validateManifest(withLazy(rb))).includes("M-OP-13:listing_invalid:/requires/bridge"), String(rb));
    }
    const ok = validateManifest(withLazy(LAZY_LISTING_MIN_BRIDGE));
    assert.equal(ok.ok, true, JSON.stringify(codes(ok)));
    const m = withLazy(LAZY_LISTING_MIN_BRIDGE);
    const engine = { id: "note_engine", title: "Engine", description: "Engine tools", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" } };
    m.operations.push(engine as Op);
    assert.equal(validateManifest(m).ok, true, `the dynamic op itself is valid: ${JSON.stringify(codes(validateManifest(m)))}`);
    (m.operations.at(-1) as Op).listing = "lazy";
    assert.ok(codes(validateManifest(m)).includes(`M-OP-13:listing_invalid:/operations/${m.operations.length - 1}/listing`), JSON.stringify(codes(validateManifest(m))));
  });

  test("today's pin: a lazy manifest is refused by the schema (so the bridge never lists it as hot)", { skip: schemaKnowsLazy ? "the pinned schema accepts lazy" : false }, () => {
    assert.ok(codes(validateManifest(withLazy(LAZY_LISTING_MIN_BRIDGE))).some((c) => c.startsWith("schema:schema_invalid")));
  });
});
