// conformance 0.1.31 (spec 0.1.64, BRIDGE §16): the R-PO rows pass against the mini bridge's relay, are not_applicable for a bridge
// without the person_ops cap, and FAIL against variants that break one rule each. B9.portal_paths admits the relay paths only for a
// bridge that declares the cap.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { type Report, runBridgeTarget } from "../../src/index.ts";
import { type MiniFlags, type MiniState, startMiniBridge } from "./mini-bridge.ts";

const RPO = ["R-PO-1", "R-PO-2", "R-PO-3", "R-PO-4", "R-PO-5", "R-PO-6", "R-PO-7", "R-PO-8"];
const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
const asserted = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.asserted ?? "";
const run = (flags: MiniFlags, opts: { logs?: boolean } = {}) => {
  const state: MiniState = {};
  return runBridgeTarget({
    start: (env) => startMiniBridge(env, flags, state),
    ...(opts.logs === false ? {} : { logs: () => (state.logs ?? []).join("\n") }),
    groups: ["person_ops", "scan"],
    timeoutMs: 3000,
    bootTimeoutMs: 15_000,
    pauseLatencyMs: 4000,
  });
};

describe("bridge target: person-op relay (R-PO, spec 0.1.64)", () => {
  it("a bridge that declares person_ops and implements BRIDGE §16 passes R-PO-1..8; B9 admits the relay paths and stays clean", { timeout: 120_000 }, async () => {
    const r = await run({ personOps: true });
    for (const id of RPO) assert.equal(status(r, id), "pass", `${id}: ${asserted(r, id)}`);
    assert.equal(status(r, "B9.portal_paths"), "pass", asserted(r, "B9.portal_paths"));
    assert.equal(status(r, "B9.no_payload"), "pass", asserted(r, "B9.no_payload"));
    assert.match(asserted(r, "B9.portal_paths"), /person_ops cap declared/);
    assert.match(asserted(r, "R-PO-3"), /sha256 = bd; TB-Person-Op = K14/);
  });

  it("a bridge without the cap: every R-PO row is not_applicable (by capability) and B9.portal_paths passes", { timeout: 120_000 }, async () => {
    const r = await run({});
    for (const id of RPO) assert.equal(status(r, id), "not_applicable", `${id}: ${asserted(r, id)}`);
    assert.match(asserted(r, "R-PO-2"), /does not declare the person_ops capability.*never by version/);
    assert.equal(status(r, "B9.portal_paths"), "pass", asserted(r, "B9.portal_paths"));
  });

  it("R-PO-4 is not_run (never a pass) when the harness cannot capture the bridge's logs", { timeout: 120_000 }, async () => {
    const r = await run({ personOps: true }, { logs: false });
    assert.equal(status(r, "R-PO-4"), "not_run", asserted(r, "R-PO-4"));
    assert.match(asserted(r, "R-PO-4"), /cannot capture the bridge's logs/);
    for (const id of RPO.filter((x) => x !== "R-PO-4")) assert.equal(status(r, id), "pass", `${id}: ${asserted(r, id)}`);
  });

  it("fire-on-bad: each broken §16 rule fails its row; polling without the cap fails R-PO-1 and B9.portal_paths", { timeout: 300_000 }, async () => {
    const cases: [MiniFlags, string[]][] = [
      [{ personOps: true, personOpFaults: { rewritesBody: true } }, ["R-PO-3"]],
      [{ personOps: true, personOpFaults: { retries: true } }, ["R-PO-5"]],
      [{ personOps: true, personOpFaults: { logsBody: true } }, ["R-PO-4"]],
      [{ personOps: true, personOpFaults: { unknownInsNotDelivered: true } }, ["R-PO-2"]],
      [{ personOps: true, personOpFaults: { zeroForUnreachable: true } }, ["R-PO-6"]],
      [{ personOpsWithoutCap: true }, ["R-PO-1", "B9.portal_paths"]],
      // spec 0.1.70 (C354): a bridge that forwards whatever the app declares, or that reads malformed caps as a declaration
      [{ personOps: true, personOpFaults: { ignoresAppCaps: true } }, ["R-PO-7", "R-PO-8"]],
      [{ personOps: true, personOpFaults: { lenientAppCaps: true } }, ["R-PO-8"]],
    ];
    const reports = await Promise.all(cases.map(([flags]) => run(flags)));
    cases.forEach(([flags, ids], i) => {
      const r = reports[i] as Report;
      for (const id of ids) assert.equal(status(r, id), "fail", `${JSON.stringify(flags)} ${id}: ${status(r, id)} ${asserted(r, id)}`);
    });
    // a faulty variant fails ONLY its own row among R-PO (the others still pass)
    assert.equal(status(reports[0] as Report, "R-PO-5"), "pass", asserted(reports[0] as Report, "R-PO-5"));
    assert.equal(status(reports[1] as Report, "R-PO-3"), "pass", asserted(reports[1] as Report, "R-PO-3"));
    assert.equal(status(reports[7] as Report, "R-PO-7"), "pass", `lenient caps still refuse an app without caps: ${asserted(reports[7] as Report, "R-PO-7")}`);
  });
});
