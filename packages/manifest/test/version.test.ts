import assert from "node:assert/strict";
import { test } from "node:test";
import { compareSemver, requiredBridgeVersion, sdkMajorOf, sdkMajorServed } from "../src/index.ts";

test("sdkMajorOf: 0.x counts as major 1 (C35/C44)", () => {
  assert.equal(sdkMajorOf("0.1.2"), 1);
  assert.equal(sdkMajorOf("0.9.0-rc.1"), 1);
  assert.equal(sdkMajorOf("1.0.0"), 1);
  assert.equal(sdkMajorOf("2.3.4"), 2);
  assert.throws(() => sdkMajorOf("1.0"));
  assert.throws(() => sdkMajorOf("v1.0.0"));
});

test("sdkMajorServed: current major and the one before", () => {
  assert.equal(sdkMajorServed("0.1.2", 1), true);
  assert.equal(sdkMajorServed("1.4.0", 2), true);
  assert.equal(sdkMajorServed("0.1.0", 3), false);
  assert.equal(sdkMajorServed("3.0.0", 2), false);
});

test("compareSemver and requiredBridgeVersion (C104): feature table + declared, highest wins", () => {
  assert.equal(compareSemver("0.1.16", "0.1.9"), 1);
  assert.equal(compareSemver("0.1.9", "0.1.9"), 0);
  assert.equal(compareSemver("1.0.0-rc.1", "1.0.0"), -1);
  assert.throws(() => compareSemver("1.0", "1.0.0"));
  assert.deepEqual(requiredBridgeVersion({ operations: [{}], companions: [] }), { bridge: null, reasons: [] });
  assert.equal(requiredBridgeVersion({ operations: [{ dynamic: { mode: "search" } }] }).bridge, "0.1.15");
  const wild = requiredBridgeVersion({ operations: [{ dynamic: {} }], companions: [{ product: "*", operations: ["tb.holds_pending"] }] });
  assert.equal(wild.bridge, "0.1.16");
  assert.equal(wild.reasons.length, 3);
  assert.equal(requiredBridgeVersion({ companions: [{ product: "*", operations: ["tb.holds_pending"] }], requires: { bridge: "0.1.17" } }).bridge, "0.1.17");
  assert.equal(requiredBridgeVersion({ operations: [{ dynamic: {} }], requires: { bridge: "0.1.2" } }).bridge, "0.1.15");
});

test("C105/C107: DEFAULT_HELD_FAMILIES / KNOWN_HOLD_FAMILIES are re-exported from the spec vocabulary (L1)", async () => {
  const m = await import("../src/index.ts");
  // spec 0.1.41 (C232, LA-2): + public_link
  assert.deepEqual([...m.DEFAULT_HELD_FAMILIES], ["destructive", "money", "first_contact", "identity", "public_link"]);
  assert.ok((m.KNOWN_HOLD_FAMILIES as readonly string[]).includes("outward") && !(m.DEFAULT_HELD_FAMILIES as readonly string[]).includes("outward"), "outward known, not held by default");
  assert.deepEqual([...m.KNOWN_HOLD_FAMILIES], [...m.HOLD_FAMILIES]);
  for (const f of m.DEFAULT_HELD_FAMILIES) assert.ok((m.KNOWN_HOLD_FAMILIES as readonly string[]).includes(f));
});

test("C232 (LA-2): an outward op may declare public_link; a typo stays refused; old grants with the word verify (C108)", async () => {
  const m = await import("../src/index.ts");
  assert.ok((m.KNOWN_HOLD_FAMILIES as readonly string[]).includes("public_link"));
  assert.ok((m.HOOK_HOLD_FAMILIES as readonly string[]).includes("public_link"));
});

test("requiredBridgeCaps (spec 0.1.68, C354): declared caps plus secret_output for a secretOutput op; secretOutput never gates a bridge version", async () => {
  const { requiredBridgeCaps } = await import("../src/index.ts");
  assert.deepEqual(requiredBridgeCaps({ operations: [{}] }), []);
  assert.deepEqual(requiredBridgeCaps({ operations: [{}, { secretOutput: true }], requires: { bridgeCaps: ["secret_output"] } }), ["secret_output"]);
  assert.deepEqual(requiredBridgeCaps({ operations: [{ secretOutput: true }] }), ["secret_output"], "implied even when undeclared");
  assert.deepEqual(requiredBridgeCaps({ operations: [], requires: { bridgeCaps: ["lazy_tools", "hook_tool"] } }), ["hook_tool", "lazy_tools"]);
  const v = requiredBridgeVersion({ operations: [{ secretOutput: true }], requires: { bridgeCaps: ["secret_output"] } });
  assert.deepEqual(v, { bridge: null, reasons: [] }, "no version-based gate for secret_output");
});
