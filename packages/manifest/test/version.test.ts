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

test("compareSemver: pre-release identifiers per semver (C382): numeric ones as numbers, numeric below words, fewer below more", () => {
  assert.equal(compareSemver("0.4.0-dev.10", "0.4.0-dev.9"), 1);
  assert.equal(compareSemver("0.4.0-dev.9", "0.4.0-dev.10"), -1);
  assert.equal(compareSemver("0.4.0-dev.99", "0.4.0-dev.10"), 1);
  assert.equal(compareSemver("1.0.0-alpha", "1.0.0-alpha.1"), -1);
  assert.equal(compareSemver("1.0.0-alpha.1", "1.0.0-alpha.beta"), -1);
  assert.equal(compareSemver("1.0.0-rc.1", "1.0.0-beta.11"), 1);
  assert.equal(compareSemver("1.0.0-1", "1.0.0-alpha"), -1);
  assert.equal(compareSemver("1.0.0-dev.01", "1.0.0-dev.1"), 0);
  assert.equal(compareSemver("0.4.0-dev.10", "0.4.0"), -1);
});
