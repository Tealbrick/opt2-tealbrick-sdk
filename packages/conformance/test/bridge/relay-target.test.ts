// Relay target sensitivity: a minimal correct stdio relay passes every relay check; variants that open a listener,
// filter tools/list, write the token to disk, present a person credential upstream, refuse calls locally, reconnect
// without Last-Event-ID, do not re-subscribe after a lost session or leak their own re-subscribe answer fail the
// matching check. Without a login the relay has no credential and the run fails.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { RELAY_CHECKS, type Report, runRelayTarget } from "../../src/index.ts";

const relay = fileURLToPath(new URL("./mini-relay.ts", import.meta.url));
const run = (broken = "", login = true) =>
  runRelayTarget({ cmd: `node ${relay} serve${broken ? ` --broken=${broken}` : ""}`, ...(login ? { loginCmd: `node ${relay} login` } : {}), timeoutMs: 4000 });
const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
const why = (r: Report, id: string) => `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`;

describe("relay target", () => {
  it("a correct relay passes every relay check", async () => {
    const r = await run();
    assert.deepEqual(new Set(r.checks.map((c) => c.id)), new Set(RELAY_CHECKS.map((c) => c.id)));
    for (const c of r.checks) assert.equal(c.status, "pass", why(r, c.id));
    assert.equal(r.ok, true);
  });
  const broken: [string, string, string][] = [
    ["opens a listener", "listen", "B10.stdio_only"],
    ["filters tools/list", "filter", "B10.forwards_verbatim"],
    ["writes its token to disk", "disk", "B10.no_state_on_disk"],
    ["presents a person credential upstream", "person", "cred.p1.relay_rejects_person"],
    ["refuses unlisted tools locally", "local", "B10.no_local_checks"],
    ["answers tealbrick/events/stream locally", "local-stream", "B10.events_forwarded"],
    ["changes the event frame it forwards", "mangle-event", "B10.events_forwarded"],
    ["reconnects without Last-Event-ID", "no-last-event-id", "B10.events_last_event_id"],
    ["does not stream again after a lost session", "no-resubscribe", "B10.events_resubscribe"],
    ["writes its own re-subscribe answer to stdout", "leak-resub", "B10.events_resubscribe"],
    ["re-sends the client's initialize and writes that answer to stdout", "leak-reinit", "B10.events_resubscribe"],
    ["re-subscribes without the new session id", "resub-nosession", "B10.events_resubscribe"],
    ["re-subscribes but opens no new GET stream", "no-new-get", "B10.events_resubscribe"],
  ];
  for (const [name, flag, id] of broken) {
    it(`fails a relay that ${name}`, async () => {
      const r = await run(flag);
      assert.equal(status(r, id), "fail", why(r, id));
      assert.equal(r.ok, false);
    });
  }
  it("an upstream without tealbrick/events/* → the B10.events_* rows are not_run (gated by what the upstream offers, never by relay version)", async () => {
    const r = await runRelayTarget({ cmd: `node ${relay} serve`, loginCmd: `node ${relay} login`, timeoutMs: 4000, upstreamEvents: false });
    for (const id of ["B10.events_forwarded", "B10.events_last_event_id", "B10.events_resubscribe"]) assert.equal(status(r, id), "not_run", why(r, id));
    for (const c of r.checks.filter((c) => !c.id.startsWith("B10.events_"))) assert.equal(c.status, "pass", why(r, c.id));
  });
  it("without a login the relay has no credential: key_connection not_run, run fails", async () => {
    const r = await run("", false);
    assert.equal(status(r, "B10.key_connection"), "not_run");
    assert.equal(r.ok, false);
  });

  // test hygiene: a run must leave no relay process behind, whatever the variant (the listener variant keeps its event loop alive)
  it("leaves no relay process running after a run, also for the variant that opens a listener", async () => {
    const count = () => {
      const r = spawnSync("pgrep", ["-f", `${relay} serve --broken=listen`], { encoding: "utf8" });
      return r.error ? null : r.stdout.split("\n").filter(Boolean).length;
    };
    const before = count();
    await run("listen");
    const after = count();
    if (before === null || after === null) return; // no pgrep on this machine
    assert.equal(after, before, "a mini-relay serve --broken=listen process was left behind");
  });
});
