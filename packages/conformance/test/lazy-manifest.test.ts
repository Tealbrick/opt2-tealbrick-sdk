// conformance 0.1.30 (spec 0.1.73, BRIDGE §7.5): the lazy-tools app of group `lazy` (B30.*) and the rows' wiring.
import assert from "node:assert/strict";
import { test } from "node:test";
import { validateManifest } from "@opt2-tealbrick/manifest";
import { exampleManifests, LAZY_FIND_WORD, LAZY_HOOK_ID, LAZY_OPS, lazyManifest } from "../src/bridge-world.ts";
import { BRIDGE_GROUP_ORDER, BRIDGE_GROUPS } from "../src/checks/bridge-ids.ts";
import { MORE_CALL_OP, MORE_SEARCH_OP } from "../src/checks/bridge-lazy.ts";

test("group lazy: seven B30 rows, run by the bridge target", () => {
  assert.ok(BRIDGE_GROUP_ORDER.includes("lazy"));
  assert.deepEqual(
    (BRIDGE_GROUPS.lazy ?? []).map((c) => c.id),
    ["B30.lazy_hidden", "B30.lazy_annotations", "B30.lazy_search", "B30.lazy_grant", "B30.lazy_call_same_route", "B30.lazy_unknown", "B30.lazy_hot_and_direct"],
  );
  assert.equal(MORE_SEARCH_OP, "tb_more_search");
  assert.equal(MORE_CALL_OP, "tb_more_call");
});

test("lazyManifest: null exactly while the suite's validator refuses listing lazy; else one listed op, four lazy ops and a hook on make", () => {
  const base = exampleManifests()[0];
  assert.ok(base);
  const m = lazyManifest(base);
  // the probe the derivation itself depends on: does the pinned validator know `lazy`?
  const probe = structuredClone(base) as typeof base;
  const op = probe.operations.find((o) => o.audience === "agent" && !o.dynamic);
  assert.ok(op);
  (op as { listing?: string }).listing = "lazy";
  const accepts = validateManifest(probe).ok;
  if (!accepts) {
    assert.equal(m, null, "a validator before spec 0.1.73 refuses the derived app: group lazy reports not_run with the cap");
    return;
  }
  assert.ok(m);
  const agent = m.operations.filter((o) => o.audience === "agent");
  assert.deepEqual(agent.map((o) => o.id).sort(), Object.values(LAZY_OPS).sort());
  const lazy = agent.filter((o) => (o as { listing?: string }).listing === "lazy").map((o) => o.id);
  assert.deepEqual(lazy.sort(), [LAZY_OPS.drop, LAZY_OPS.find, LAZY_OPS.make, LAZY_OPS.send].sort());
  assert.ok(agent.find((o) => o.id === LAZY_OPS.find)?.description.includes(LAZY_FIND_WORD));
  assert.deepEqual(m.hooks?.map((h) => h.id), [LAZY_HOOK_ID]);
  assert.equal(agent.find((o) => o.id === LAZY_OPS.hot)?.effect, "outward", "the listed op is wider than the lazy read (B30.lazy_annotations)");
  assert.equal(m.requires, undefined, "C354: no version minimum; the lazy_tools cap gates it");
  assert.equal(validateManifest(m).ok, true);
});
