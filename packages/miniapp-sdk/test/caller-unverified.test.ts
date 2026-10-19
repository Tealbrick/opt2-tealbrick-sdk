// v0.1.35 (C261 = C243, spec 0.1.49): with the verified slice flag `appCallers: "verified"`, an APP caller without a verified
// product (no grant `prd`, no slice `companionCallers` entry) is refused 403 `caller_unverified`, retryable, nothing runs, audited.
// Without the flag the earlier lenient rule holds (the call runs with `product` absent). Each test says what fails without its guard.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { keySetFrom, signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Json, OpContext, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { decideHold, defineApp, startApp } from "../src/server/index.ts";
import type { ClaimedJob } from "../src/server/jobs.ts";
import { CALLER_UNVERIFIED_MESSAGE, callerUnverified, fireScheduledOp } from "../src/server/ops.ts";
import type { Runtime } from "../src/server/runtime.ts";
import { applySdkMigrations, openDb } from "../src/server/store.ts";
import { TrustState } from "../src/server/trust.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dataDir: string;
  ran: { note_delete: number };
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const ran = { note_delete: 0 };
  // a boot that fails must not leave the bridge or the app listening: an open handle would keep the test process alive for ever
  let running: RunningApp | undefined;
  try {
    running = await startApp(
      defineApp({
        manifest: fixtureManifest(port),
        migrations: migrationsDir(t.dir),
        handlers: {
          note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
          note_get: async (_input, ctx: OpContext) => ({ type: ctx.caller.type, product: ctx.caller.product ?? null }) as Json,
          note_delete: async () => {
            ran.note_delete += 1;
            return { deleted: true };
          },
          notebook_rename: async () => ({}),
        },
      }),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    await until(async () => running?.status() === "ok");
  } catch (e) {
    await running?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  return {
    w,
    bridge,
    running,
    base: `http://127.0.0.1:${port}`,
    dataDir: t.dir,
    ran,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function appGrant(b: Booted, ins: InstanceId, wf: string[], prd?: string): Promise<string> {
  return signGrant(
    { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read", "delete"], mode: "bound", held: [], caps: {}, wf, polrev: 1, ...(prd !== undefined ? { prd } : {}) } as never,
    b.w.portal,
  );
}

async function call(b: Booted, op: string, input: Json, grantToken: string, key = `k_${ulid()}`) {
  const proof = await callProof(b.w, grantToken, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${grantToken}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: key }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** pushes a slice and waits until the app serves it (the status long poll carries the revision) */
async function push(b: Booted, over: Parameters<typeof slice>[2]): Promise<void> {
  const before = b.bridge.statuses.length;
  b.bridge.push(await slice(b.w, PRODUCT, over));
  await until(async () => b.bridge.statuses.length > before && (b.bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === b.w.rev);
}

function receiptRows(b: Booted, op: string): { status: string; caller_id: string; caller_product: string | null; meta: string }[] {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    return db.prepare("SELECT status, caller_id, caller_product, meta FROM tb_receipts WHERE op = ? ORDER BY created_at, id").all(op) as never;
  } finally {
    db.close();
  }
}

describe("C261 caller_unverified", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  test("with appCallers: verified an app caller with no product is refused 403 caller_unverified, retryable, nothing runs, and a refused receipt records it", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    await push(b, { appCallers: "verified", companionCallers: [{ product: "other", ins: `ins_${ulid()}` as InstanceId, name: "Someone else" }] });
    const ran0 = b.ran.note_delete;
    const r = await call(b, "note_delete", { id: "x" }, await appGrant(b, ins, ["note_delete"]));
    assert.equal(r.status, 403, JSON.stringify(r.body));
    assert.equal(r.body.error.code, "caller_unverified", "fires on bad: without the guard the call runs with product absent (the lenient rule)");
    assert.equal(r.body.error.message, CALLER_UNVERIFIED_MESSAGE);
    assert.match(r.body.error.message, /update the bridge, or retry after the workspace config refreshes/);
    assert.equal(r.body.error.details?.retryable, true);
    assert.equal(b.ran.note_delete, ran0, "nothing ran");
    const rows = receiptRows(b, "note_delete").filter((x) => x.caller_id === ins);
    assert.equal(rows.length, 1, "the refusal is audited as ONE refused receipt");
    assert.equal(rows[0]?.status, "refused");
    assert.deepEqual(JSON.parse(rows[0]?.meta ?? "null"), { reason: "caller_unverified" });
    assert.equal(rows[0]?.caller_product, null);
  });

  test("every route of an app caller is covered: a standard op (tb.hold_status) and a read op are refused too, and no scope defaults are created for it", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    await push(b, { appCallers: "verified" });
    const g = await appGrant(b, ins, ["note_get"]);
    const hs = await call(b, "tb.hold_status", { holdId: "hld_00000000000000000000000000" }, g);
    assert.equal(hs.body.error?.code, "caller_unverified");
    const get = await call(b, "note_get", { id: "x" }, g);
    assert.equal(get.status, 403);
    assert.equal(get.body.error.code, "caller_unverified");
    assert.deepEqual(await b.running.scopes.list(ins as never), [], "refused before first sight: no own instance, no default rows");
  });

  test("quiet on good: a caller listed in companionCallers, and a caller whose grant carries prd, run (product from the slice / from the grant)", async () => {
    const listed = `ins_${ulid()}` as InstanceId;
    const withPrd = `ins_${ulid()}` as InstanceId;
    await push(b, { appCallers: "verified", companionCallers: [{ product: "evolution", ins: listed, name: "Evolution" }] });
    const a = await call(b, "note_get", { id: "x" }, await appGrant(b, listed, ["note_get"]));
    assert.equal(a.status, 200, JSON.stringify(a.body));
    assert.deepEqual(a.body.output, { type: "app", product: "evolution" });
    const p = await call(b, "note_get", { id: "x" }, await appGrant(b, withPrd, ["note_get"], "kanban"));
    assert.equal(p.status, 200, JSON.stringify(p.body));
    assert.deepEqual(p.body.output, { type: "app", product: "kanban" });
  });

  test("retryable: the same caller runs once the slice lists it, and is refused again when the slice drops it", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    const g = await appGrant(b, ins, ["note_get"]);
    await push(b, { appCallers: "verified" });
    assert.equal((await call(b, "note_get", { id: "x" }, g)).body.error?.code, "caller_unverified");
    await push(b, { appCallers: "verified", companionCallers: [{ product: "evolution", ins, name: "Evolution" }] });
    assert.equal((await call(b, "note_get", { id: "x" }, g)).status, 200);
    await push(b, { appCallers: "verified" });
    assert.equal((await call(b, "note_get", { id: "x" }, g)).body.error?.code, "caller_unverified");
  });

  test("a resumed held app call: the owner approved it, then the caller lost its verified product: the retry is refused caller_unverified, the approval stays unused and runs once the caller is verified again", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    const entry = { product: "evolution", ins, name: "Evolution" };
    const held = await signGrant(
      { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read", "delete"], mode: "bound", held: ["destructive"], caps: {}, wf: ["note_delete"], polrev: 1 } as never,
      b.w.portal,
    );
    await push(b, { appCallers: "verified", companionCallers: [entry] });
    const key = `k_${ulid()}`;
    const first = await call(b, "note_delete", { id: "held-1" }, held, key);
    assert.equal(first.status, 202, JSON.stringify(first.body));
    const principal = { type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as unknown as PersonPrincipal;
    await decideHold(principal, { holdId: first.body.holdId, decision: "approve" });
    const ran0 = b.ran.note_delete;
    await push(b, { appCallers: "verified" });
    const retry = await call(b, "note_delete", { id: "held-1" }, held, key);
    assert.equal(retry.status, 403, "fires on bad: the approved retry must not run for a caller the instance can no longer verify");
    assert.equal(retry.body.error.code, "caller_unverified");
    assert.equal(b.ran.note_delete, ran0);
    assert.equal((await b.running.receipts.get(first.body.holdId))?.status, "approved", "the approval is not consumed by a refusal");
    await push(b, { appCallers: "verified", companionCallers: [entry] });
    const again = await call(b, "note_delete", { id: "held-1" }, held, key);
    assert.equal(again.status, 200, JSON.stringify(again.body));
    assert.equal(b.ran.note_delete, ran0 + 1, "exactly once");
  });

  test("without the flag nothing changes: the unverified app caller runs with product absent (also for any value other than \"verified\")", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    const g = await appGrant(b, ins, ["note_get"]);
    for (const over of [{}, { appCallers: "lenient" }, { appCallers: true }, { appCallers: "Verified" }]) {
      await push(b, over);
      const r = await call(b, "note_get", { id: "x" }, g);
      assert.equal(r.status, 200, `${JSON.stringify(over)}: ${JSON.stringify(r.body)}`);
      assert.deepEqual(r.body.output, { type: "app", product: null });
    }
  });

  test("agent callers are not affected by the flag", async () => {
    await push(b, { appCallers: "verified" });
    const r = await call(b, "note_get", { id: "x" }, await grant(b.w, b.w.agents.a));
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output, { type: "agent", product: null });
  });

  test("unit: callerUnverified is true only for an app caller without product under the exact flag", () => {
    const rt = (flag: unknown) => ({ trust: { appCallersVerified: () => flag === "verified" } }) as never;
    assert.equal(callerUnverified(rt("verified"), { type: "app" }), true);
    assert.equal(callerUnverified(rt("verified"), { type: "app", product: "x" }), false);
    assert.equal(callerUnverified(rt("verified"), { type: "agent" }), false);
    assert.equal(callerUnverified(rt("verified"), { type: "person" }), false);
    assert.equal(callerUnverified(rt(undefined), { type: "app" }), false);
    assert.equal(callerUnverified(rt("lenient"), { type: "app" }), false);
  });
});

// v0.1.36 gap G2 (sdk#34 review): fireScheduledOp refuses `caller_unverified` itself. Through a whole app the line cannot be reached
// from outside: a fire first needs the caller in the slice `companionCallers` (else `grant_revoked`), and a listed caller always has a
// product (the entry's own). So the guard is tested where it lives: fireScheduledOp with a real grant, a real TrustState and a runtime
// stub that stops the run (a sentinel) at the first thing the fire does AFTER the guard. The only way to see the product missing at
// that point is a trust state that lists the caller but answers no product, which is what the guard defends against.
describe("C261 caller_unverified: a scheduled fire (v0.1.36 gap G2)", { timeout: 60_000 }, () => {
  const PAST_GUARD = new Error("past the caller_unverified guard");
  const BRG = "brg_00000000000000000000000000";

  async function fire(opts: { verified: boolean; product: string | undefined; prd?: string }) {
    const w = await world();
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db);
      const ins = `ins_${ulid()}` as InstanceId;
      class T extends TrustState {
        // a trust context that accepts the Portal-signed grant below (what a slice would give), without a slice
        override context(nowMs: number) {
          return { now: Math.floor(nowMs / 1000), self: this.self, ws: w.ws, bridge: BRG as never, issuers: keySetFrom({ keys: [w.portal.publicJwk] }, "tb:portal"), bridgeKeys: { keys: [] }, revokedJtis: new Set<string>() };
        }
        override appCallersVerified(): boolean {
          return opts.verified;
        }
        // the caller IS listed (the grant_revoked check passes) ...
        override companionCallers() {
          return [{ product: "listed", ins, name: "Evolution", provider: null }];
        }
        // ... but the trust state answers no product for it (what the guard defends against)
        override companionProduct(): string | undefined {
          return opts.product;
        }
      }
      const trust = new T(db, w.ins, { bootstrap: null, alone: { ws: w.ws, ownKey: w.portal.publicJwk } });
      const token = await signGrant(
        { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${w.ins}`, iat: nowS(), ws: w.ws, cnf: { brg: BRG }, crud: ["read", "delete"], mode: "bound", held: [], caps: {}, wf: ["note_delete"], polrev: 1, ...(opts.prd ? { prd: opts.prd } : {}) } as never,
        w.portal,
      );
      const op = { id: "note_delete", title: "Delete note", standard: false, crud: ["delete"], effect: "destructive", audience: "agent", receipt: true };
      const receipts: { status: string; meta: { reason?: string; scheduled?: string }; caller: { id: string; type: string } }[] = [];
      let ran = 0;
      let pastGuard = 0;
      const rt = {
        cfg: { standalone: true },
        trust,
        ops: new Map([["note_delete", op]]),
        def: { handlers: { note_delete: async () => { ran += 1; return {}; } } },
        sealer: { unsealText: () => token },
        log: { warn: () => {} },
        statusChanged: () => {},
        receipts: {
          insert: (r: never) => receipts.push(r),
          // the first thing the fire touches after the guard, the workflow check and the scope step
          findApproved: () => {
            pastGuard += 1;
            throw PAST_GUARD;
          },
        },
      } as unknown as Runtime;
      const job = { id: "job_1", op: "note_delete", input: { id: "x" }, key: "k_scheduled_1", caller: { type: "app", id: ins, name: "Evolution" }, callerMode: "bound", grantSealed: "sealed", holdId: null } as unknown as ClaimedJob;
      const outcome = await fireScheduledOp(rt, job, new AbortController().signal).then((o) => ({ o }), (e: unknown) => ({ e }));
      db.close();
      return { outcome, receipts, ran, pastGuard, ins };
    } finally {
      t.cleanup();
    }
  }

  test("fires on bad: with appCallers: verified and no product for the app caller, the fire is refused caller_unverified, the handler never runs, one refused receipt", { timeout: 60_000 }, async () => {
    const r = await fire({ verified: true, product: undefined });
    assert.equal("e" in r.outcome ? String(r.outcome.e) : "", "", "the fire returned an outcome (the guard stopped it before anything else ran)");
    assert.deepEqual("o" in r.outcome ? r.outcome.o : null, { kind: "refused", reason: "caller_unverified" });
    assert.equal(r.pastGuard, 0);
    assert.equal(r.ran, 0, "the handler never ran");
    assert.equal(r.receipts.length, 1);
    assert.equal(r.receipts[0]?.status, "refused");
    assert.deepEqual(r.receipts[0]?.meta, { reason: "caller_unverified", scheduled: "job_1" });
    assert.equal(r.receipts[0]?.caller.id, r.ins);
  });

  test("quiet on good: the same fire proceeds past the guard with a product (slice), with a product (grant prd), and without the flag", { timeout: 60_000 }, async () => {
    for (const c of [
      { verified: true, product: "listed" },
      { verified: true, product: undefined, prd: "listed" },
      { verified: false, product: undefined },
    ]) {
      const r = await fire(c);
      assert.equal(r.pastGuard, 1, `${JSON.stringify(c)} reaches the step after the guard`);
      assert.ok("e" in r.outcome && r.outcome.e === PAST_GUARD, "stopped by the sentinel, not by a refusal");
      assert.equal(r.receipts.length, 0);
    }
  });
});
