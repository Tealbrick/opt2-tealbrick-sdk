// C367 (spec 0.1.77): P4 caller context on app-initiated calls (SDK-API §18.6, BRIDGE §8.5) and P3 `tb.hold_status` for an app caller
// (SDK-API §4.7). Sender side: `callApp(..., { context })` in every ctx. Target side: receipts, holds_list / receipts_list,
// tb.holds_pending summary, hold status of an app's own holds, and the approved / denied / expired repeat.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { EventContext, Json, OpContext, RunningApp, StartContext } from "@opt2-tealbrick/spec/sdk";
import type { ApprovedHold, SdkOpContext } from "../src/server/context.ts";
import { TbError } from "../src/server/errors.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { callerContextOf, receiptMetaWithContext } from "../src/server/ops.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const PEER = "peer-app";
const CAP = "app_call_context";
const EVO = { workflow: "wf_1", version: 3, run: "run_1", step: "step_1" };
const evoContext = (over: Record<string, Json> = {}): Record<string, Json> => ({ "jotter.workflow": EVO.workflow, "jotter.version": EVO.version, "jotter.run": EVO.run, "jotter.step": EVO.step, ...over });

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dataDir: string;
  startCtx: StartContext | null;
  eventCtx: EventContext | null;
  ran: { note_delete: number };
  /** `ctx.approvedHold` of each note_delete run */
  approvals: (ApprovedHold | null)[];
  /** what the op `note_get` calls through ctx.callApp (set by a test) */
  next: { product: string; op: string; input: Json; opts?: { idempotencyKey?: string; context?: Record<string, Json> } } | null;
  insA: InstanceId;
  insB: InstanceId;
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const peerIns = `ins_${ulid()}` as InstanceId;
  const m: Manifest = fixtureManifest(port);
  m.companions = [{ product: PEER, operations: ["peer_write", "tb.hold_status"], crud: ["create"], purpose: "Write to the peer and read the status of the holds this app raised." }];
  const companionGrant = await signGrant(
    { iss: "tb:portal", sub: `tb:ins:${w.ins}`, aud: `tb:ins:${peerIns}`, iat: nowS(), ws: w.ws, cnf: { brg: w.brg }, crud: ["create"], mode: "bound", held: [], caps: {}, wf: ["peer_write", "tb.hold_status"], polrev: 1 },
    w.portal,
  );
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { grants: [companionGrant], companionTargets: [{ product: PEER, ins: peerIns }] }));
  const b = { w, bridge, dataDir: t.dir, startCtx: null, eventCtx: null, ran: { note_delete: 0 }, approvals: [], next: null, insA: `ins_${ulid()}` as InstanceId, insB: `ins_${ulid()}` as InstanceId } as unknown as Booted;
  b.base = `http://127.0.0.1:${port}`;
  const app = defineApp({
    manifest: m,
    migrations: migrationsDir(t.dir),
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async (_input, ctx: OpContext) => {
        const n = b.next;
        if (!n) return { none: true };
        return (await ctx.callApp(n.product, n.op, n.input, n.opts)) as unknown as Json;
      },
      note_delete: async (_input, ctx) => {
        b.ran.note_delete += 1;
        b.approvals.push((ctx as SdkOpContext).approvedHold);
        return { deleted: true };
      },
      notebook_rename: async () => ({}),
    },
    onStart: async (ctx) => {
      b.startCtx = ctx;
    },
    events: {
      agentsChanged: async (_agents, ctx) => {
        b.eventCtx = ctx;
      },
    },
  });
  let running: RunningApp | undefined;
  try {
    running = await startApp(
      app,
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    await until(async () => running?.status() === "ok" && b.startCtx !== null && b.eventCtx !== null);
  } catch (e) {
    await running?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  b.running = running;
  b.cleanup = async () => {
    await (running as RunningApp).stop();
    await bridge.stop();
    t.cleanup();
  };
  // keep the grants for later slice pushes
  (b as unknown as { grants: string[]; peerIns: InstanceId }).grants = [companionGrant];
  (b as unknown as { grants: string[]; peerIns: InstanceId }).peerIns = peerIns;
  return b;
}

/** pushes a slice (with the companion grant and the given bridge caps) and waits until the app serves it */
async function setCaps(b: Booted, caps: string[] | undefined, extra: Parameters<typeof slice>[2] = {}): Promise<void> {
  const { grants, peerIns } = b as unknown as { grants: string[]; peerIns: InstanceId };
  const before = b.bridge.statuses.length;
  b.bridge.push(await slice(b.w, PRODUCT, { grants, companionTargets: [{ product: PEER, ins: peerIns }], ...(caps ? { bridgeCaps: caps } : {}), ...extra }));
  await until(async () => b.bridge.statuses.length > before && (b.bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === b.w.rev);
}

async function agentCall(b: Booted, op: string, input: Json, opts: { agent?: "a" | "b"; context?: Record<string, Json>; key?: string; held?: boolean } = {}) {
  const g = await grant(b.w, b.w.agents[opts.agent ?? "a"], { held: opts.held === false ? [] : ["destructive"] });
  return post(b, g, op, input, opts.context ?? {}, opts.key);
}

async function appGrant(b: Booted, ins: InstanceId, wf: string[], prd?: string): Promise<string> {
  return signGrant(
    { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read", "delete"], mode: "bound", held: ["destructive"], caps: {}, wf, polrev: 1, ...(prd !== undefined ? { prd } : {}) } as never,
    b.w.portal,
  );
}

async function post(b: Booted, g: string, op: string, input: Json, context: Record<string, Json>, key?: string) {
  const proof = await callProof(b.w, g, op, input, context);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context, ...(key ? { idempotencyKey: key } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function signIn(b: Booted): Promise<{ cookie: string; csrf: string }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket: await ticket(b.w, "/") }) });
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  return { cookie, csrf: s.csrf };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, { method: "POST", headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base }, body: JSON.stringify({ input }) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** raw receipt rows (the DB is the proof of what is stored) */
function rows(b: Booted, where = "1=1"): { id: string; op: string; status: string; caller_type: string; caller_id: string; meta: Record<string, any> }[] {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    return (db.prepare(`SELECT id, op, status, caller_type, caller_id, meta FROM tb_receipts WHERE ${where} ORDER BY created_at, id`).all() as any[]).map((r) => ({ ...r, meta: JSON.parse(r.meta) }));
  } finally {
    db.close();
  }
}

const noRequestId = (body: Record<string, any>) => {
  const { requestId: _r, ...rest } = body.error;
  return JSON.stringify({ error: rest });
};

describe("callApp({ context }) — sender side (SDK-API §18.6)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());
  const callsBefore = () => b.bridge.calls.length;
  const code = (c: string, status?: number) => (e: unknown) => e instanceof TbError && e.code === c && (status === undefined || e.httpStatus === status);

  test("without the cap a non-empty context throws bridge_cap_missing (409, details.cap) before any network call, in every ctx", async () => {
    await setCaps(b, ["owner_rows"]);
    const n = callsBefore();
    const ctx = evoContext();
    for (const call of [
      () => (b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: ctx }),
      () => (b.eventCtx as EventContext).callApp(PEER, "peer_write", {}, { context: ctx }),
    ]) {
      await assert.rejects(call(), (e: unknown) => {
        assert.ok(e instanceof TbError);
        assert.equal(e.code, "bridge_cap_missing");
        assert.equal(e.httpStatus, 409);
        assert.deepEqual(e.details, { cap: CAP });
        assert.match(e.message, /app_call_context/);
        return true;
      });
    }
    b.next = { product: PEER, op: "peer_write", input: {}, opts: { context: ctx } };
    const viaOp = await agentCall(b, "note_get", { id: "x" }, { held: false });
    assert.equal(viaOp.status, 409, JSON.stringify(viaOp.body));
    assert.equal(viaOp.body.error.code, "bridge_cap_missing");
    assert.deepEqual(viaOp.body.error.details, { cap: CAP });
    assert.equal(callsBefore(), n, "no call reached the bridge");
  });

  test("a slice with no caps at all behaves the same", async () => {
    await setCaps(b, undefined);
    await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: evoContext() }), code("bridge_cap_missing", 409));
  });

  test("undefined and {} are NO context: no throw, no cap needed, the field is not sent", async () => {
    await setCaps(b, []);
    for (const opts of [undefined, {}, { context: undefined }, { context: {} }, { idempotencyKey: "idem-1234", context: {} }]) {
      const n = callsBefore();
      const r = await (b.startCtx as StartContext).callApp(PEER, "peer_write", { x: 1 }, opts);
      assert.equal(r.status, "ok");
      assert.equal(b.bridge.calls.length, n + 1);
      assert.equal("context" in (b.bridge.calls.at(-1)?.body ?? {}), false, JSON.stringify(opts));
    }
  });

  test("with the cap the context is sent as CallEnvelope.context: start ctx and event ctx without parentCall, op ctx with it", async () => {
    await setCaps(b, [CAP]);
    const ctx = evoContext();
    await (b.startCtx as StartContext).callApp(PEER, "peer_write", { s: 1 }, { context: ctx, idempotencyKey: "start-key-1" });
    let sent = b.bridge.calls.at(-1)?.body as Record<string, unknown>;
    assert.deepEqual(sent, { target: PEER, op: "peer_write", input: { s: 1 }, idempotencyKey: "start-key-1", context: ctx });
    assert.equal("parentCall" in sent, false);
    await (b.eventCtx as EventContext).callApp(PEER, "peer_write", { e: 1 }, { context: ctx });
    sent = b.bridge.calls.at(-1)?.body as Record<string, unknown>;
    assert.deepEqual(sent.context, ctx);
    assert.equal("parentCall" in sent, false);
    b.next = { product: PEER, op: "peer_write", input: { o: 1 }, opts: { context: ctx } };
    const r = await agentCall(b, "note_get", { id: "o" }, { held: false });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    sent = b.bridge.calls.at(-1)?.body as Record<string, unknown>;
    assert.deepEqual(sent.context, ctx);
    assert.match(String(sent.parentCall), /^call_/);
  });

  test("every ctx has bridgeCaps() (current slice caps)", async () => {
    await setCaps(b, [CAP, "app_hold_status"]);
    assert.deepEqual([...(b.startCtx as StartContext & { bridgeCaps(): readonly string[] }).bridgeCaps()], [CAP, "app_hold_status"]);
    assert.deepEqual([...(b.eventCtx as EventContext & { bridgeCaps(): readonly string[] }).bridgeCaps()], [CAP, "app_hold_status"]);
  });

  test("the shared rules run locally: input_invalid with details.pointer, nothing sent", async () => {
    await setCaps(b, [CAP]);
    const n = callsBefore();
    const cases: [Record<string, Json> | Json, string][] = [
      [{ "kanban.card": "c1" }, "/context/kanban.card"],
      [{ "tb.onBehalfOf": { claim: "x" } }, "/context/tb.onBehalfOf"],
      [{ "jotter.note": "x".repeat(2100) }, "/context"],
      [{ "jotter.a": { b: { c: { d: [1] } } } }, "/context/jotter.a"],
      [{ "jotter/x": 1 }, "/context/jotter~1x"],
      [[1] as Json, "/context"],
    ];
    for (const [context, pointer] of cases) {
      await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: context as Record<string, Json> }), (e: unknown) => {
        assert.ok(e instanceof TbError);
        assert.equal(e.code, "input_invalid");
        assert.equal(e.httpStatus, 400);
        assert.deepEqual(e.details, { pointer });
        assert.ok(!e.message.includes("x".repeat(50)), "never a value");
        return true;
      });
    }
    // the rule uses the SDK's OWN product (jotter), so a key of its own product passes
    await (b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: { "jotter.ok": 1 } });
    assert.equal(callsBefore(), n + 1);
  });

  test("order: companion_undeclared first, then bridge_cap_missing, then input_invalid", async () => {
    const bad = { "kanban.card": "c1" };
    await setCaps(b, ["owner_rows"]);
    const n = callsBefore();
    await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_other", {}, { context: bad }), code("companion_undeclared"));
    await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: bad }), code("bridge_cap_missing", 409));
    await setCaps(b, [CAP]);
    await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_write", {}, { context: bad }), code("input_invalid", 400));
    await assert.rejects((b.startCtx as StartContext).callApp(PEER, "peer_other", {}, { context: bad }), code("companion_undeclared"));
    assert.equal(callsBefore(), n);
  });

  test("P3: callApp(product, tb.hold_status, { holdId }) works when declared (companion entry lists it)", async () => {
    await setCaps(b, ["app_hold_status"]);
    b.bridge.onCall = () => ({ status: 200, body: { status: "ok", output: { status: "pending", decidedAt: null, expiresAt: "2030-01-01T00:00:00.000Z" } } });
    const r = await (b.startCtx as StartContext).callApp(PEER, "tb.hold_status", { holdId: "hld_01" });
    assert.equal(r.status, "ok");
    const c = b.bridge.calls.at(-1) as (typeof b.bridge.calls)[number];
    assert.equal(c.body.op, "tb.hold_status");
    const g = JSON.parse(Buffer.from(c.grant.split(".")[1] as string, "base64url").toString("utf8"));
    assert.deepEqual(g.wf, ["peer_write", "tb.hold_status"]);
    b.bridge.onCall = () => ({ status: 200, body: { status: "ok", output: { done: true } } });
  });
});

describe("target side: receipts, holds, summary, hold status, repeat (SDK-API §4.7, §18.6)", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  const wfA = ["note_delete", "tb.hold_status", "tb.holds_pending", "note_get"];
  const holdOf = async (ins: InstanceId, context: Record<string, Json>, id: string, prd: string | null = "jotter", key = `k_${ulid()}`) => {
    const g = await appGrant(b, ins, wfA, prd ?? undefined);
    const r = await post(b, g, "note_delete", { id }, context, key);
    return { r, g, key };
  };

  test("an app call that is held stores meta.callerContext = only the caller product's keys (never a foreign or tb. key)", async () => {
    const { r } = await holdOf(b.insA, evoContext({ "kanban.card": "c1", "tb.onBehalfOf": { claim: "x" } }), "n-held-1");
    assert.equal(r.status, 202, JSON.stringify(r.body));
    assert.equal(b.ran.note_delete, 0);
    const row = rows(b, `id = '${r.body.holdId}'`)[0];
    assert.deepEqual(row?.meta.callerContext, evoContext());
  });

  test("tb.holds_list and tb.receipts_list return it in meta", async () => {
    const holds = await personOp(b, s, "tb.holds_list", {});
    assert.equal(holds.status, 200);
    const mine = holds.body.output.items.filter((i: any) => i.caller.type === "app");
    assert.ok(mine.length >= 1);
    assert.deepEqual(mine[0].meta.callerContext, evoContext());
    const receipts = await personOp(b, s, "tb.receipts_list", { status: "held" });
    assert.deepEqual(receipts.body.output.items.find((i: any) => i.caller.type === "app")?.meta.callerContext, evoContext());
  });

  test("tb.holds_pending: callerContext summary computed at read time; absent for a hold without it; never the whole context", async () => {
    assert.equal((await holdOf(b.insA, evoContext(), "n-held-sum")).r.status, 202);
    const plain = await holdOf(b.insA, {}, "n-held-plain");
    assert.equal(plain.r.status, 202);
    const g = await appGrant(b, b.insB, ["tb.holds_pending"], "inbox");
    const r = await post(b, g, "tb.holds_pending", {}, {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const withCtx = r.body.output.items.find((i: any) => i.caller.type === "app" && i.callerContext !== undefined);
    assert.ok(withCtx);
    assert.equal(withCtx.callerContext, 'jotter.run="run_1"; jotter.step; jotter.version=3; jotter.workflow="wf_1"');
    assert.deepEqual(Object.keys(withCtx).sort(), ["ageS", "caller", "callerContext", "createdAt", "decidePath", "family", "heldBy", "id", "op", "product", "reason", "summary"]);
    const without = r.body.output.items.find((i: any) => i.id === plain.r.body.holdId);
    assert.ok(without);
    assert.equal("callerContext" in without, false);
    // an agent's hold never has one
    const agent = await agentCall(b, "note_delete", { id: "n-agent" }, { context: evoContext() });
    assert.equal(agent.status, 202);
    const again = await post(b, g, "tb.holds_pending", {}, {});
    assert.equal("callerContext" in again.body.output.items.find((i: any) => i.id === agent.body.holdId), false);
    assert.equal(rows(b, `id = '${agent.body.holdId}'`)[0]?.meta?.callerContext, undefined);
  });

  test("an agent caller never gets meta.callerContext, whatever its context carries", async () => {
    const r = await agentCall(b, "note_delete", { id: "n-agent-2" }, { context: evoContext({ "jotter.x": 1 }), held: false, key: `k_${ulid()}` });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const row = rows(b, `caller_type = 'agent' AND op = 'note_delete'`).at(-1);
    assert.equal(row?.meta?.callerContext, undefined);
  });

  test("the product comes from the grant, not from the body: a body key of another product is never stored; no verified product, no callerContext", async () => {
    const other = await holdOf(b.insA, { "evolution.workflow": "w" }, "n-other", "kanban");
    assert.equal(other.r.status, 202);
    assert.equal(rows(b, `id = '${other.r.body.holdId}'`)[0]?.meta?.callerContext, undefined);
    const own = await holdOf(b.insA, { "evolution.workflow": "w", "kanban.card": "c9" }, "n-own", "kanban");
    assert.deepEqual(rows(b, `id = '${own.r.body.holdId}'`)[0]?.meta.callerContext, { "kanban.card": "c9" });
    const none = await holdOf(b.insA, evoContext(), "n-noprd", null);
    assert.equal(none.r.status, 202);
    assert.equal(rows(b, `id = '${none.r.body.holdId}'`)[0]?.meta?.callerContext, undefined, "no verified product (no grant prd, no slice entry)");
  });

  test("a subset over 2048 bytes (after a same-product hook overwrite) is not stored", async () => {
    const big = await holdOf(b.insA, { "jotter.note": "x".repeat(3000), "jotter.run": "r" }, "n-big");
    assert.equal(big.r.status, 202, JSON.stringify(big.r.body));
    assert.equal(rows(b, `id = '${big.r.body.holdId}'`)[0]?.meta?.callerContext, undefined);
  });

  describe("unit rules", () => {
    const logs: unknown[][] = [];
    const rt = { log: { warn: (...a: unknown[]) => logs.push(a) } } as never;
    test("callerContextOf: app + verified product only; the size limit is JCS bytes", () => {
      const app = { type: "app", product: "jotter" } as never;
      assert.deepEqual(callerContextOf(rt, app, evoContext({ "x.y": 1 })), evoContext());
      assert.equal(callerContextOf(rt, app, { "x.y": 1 }), undefined);
      assert.equal(callerContextOf(rt, { type: "app" } as never, evoContext()), undefined);
      assert.equal(callerContextOf(rt, { type: "agent", product: "jotter" } as never, evoContext()), undefined);
      assert.equal(callerContextOf(rt, { type: "person" } as never, evoContext()), undefined);
      // a lookalike prefix is not the product
      assert.equal(callerContextOf(rt, app, { "jotterx.a": 1 }), undefined);
      const n = logs.length;
      assert.equal(callerContextOf(rt, app, { "jotter.n": "x".repeat(2100) }), undefined);
      assert.equal(logs.length, n + 1, "a warning");
      assert.ok(!JSON.stringify(logs.at(-1)).includes("xxxx"), "no values in the warning");
      assert.ok(callerContextOf(rt, app, { "jotter.n": "x".repeat(2048 - 16) }) !== undefined, "just under the limit (2048 - overhead)");
    });
    test("receiptMetaWithContext: merge rules, 4 KB bound, non-object meta, hold vs run", () => {
      const cc = { "jotter.run": "r1" };
      assert.deepEqual(receiptMetaWithContext(rt, null, cc), { callerContext: cc });
      assert.deepEqual(receiptMetaWithContext(rt, { tool: "t" }, cc), { tool: "t", callerContext: cc });
      assert.deepEqual(receiptMetaWithContext(rt, { tool: "t" }, undefined), { tool: "t" });
      assert.deepEqual(receiptMetaWithContext(rt, [1], cc), [1], "an array meta cannot carry it");
      const fat = { blob: "y".repeat(3000) };
      assert.deepEqual(receiptMetaWithContext(rt, fat, { "jotter.n": "x".repeat(1500) }), fat, "meta + context over 4 KB: the context is left out");
      // approved repeat: the HOLD's callerContext stays; a differing repeat context goes to callerContextRun; JCS key order is irrelevant
      const held = { meta: { callerContext: { "jotter.a": 1, "jotter.b": 2 } } } as never;
      assert.deepEqual(receiptMetaWithContext(rt, null, { "jotter.b": 2, "jotter.a": 1 }, held), { callerContext: { "jotter.a": 1, "jotter.b": 2 } });
      assert.deepEqual(receiptMetaWithContext(rt, null, { "jotter.a": 9 }, held), { callerContext: { "jotter.a": 1, "jotter.b": 2 }, callerContextRun: { "jotter.a": 9 } });
      assert.deepEqual(receiptMetaWithContext(rt, null, undefined, held), { callerContext: { "jotter.a": 1, "jotter.b": 2 } });
      assert.deepEqual(receiptMetaWithContext(rt, null, cc, { meta: null } as never), { callerContextRun: cc });
      assert.equal(receiptMetaWithContext(rt, null, undefined, { meta: null } as never), null);
    });
  });

  describe("approved repeat keeps the hold's callerContext (informational only)", () => {
    test("same context: the run receipt keeps it; a different context goes to callerContextRun; the repeat still matches (context is not an input)", async () => {
      const ran = b.ran.note_delete;
      const first = await holdOf(b.insA, evoContext(), "n-rep-1");
      assert.equal(first.r.status, 202);
      const holdId = first.r.body.holdId as string;
      assert.equal((await personOp(b, s, "tb.holds_decide", { holdId, decision: "approve" })).status, 200);
      // same op, input, key; a different context (the run id changed): still the approved call, runs once
      const g = first.g;
      const repeat = await post(b, g, "note_delete", { id: "n-rep-1" }, evoContext({ "jotter.run": "run_2" }), first.key);
      assert.equal(repeat.status, 200, JSON.stringify(repeat.body));
      assert.equal(b.ran.note_delete, ran + 1);
      const row = rows(b, `id = '${holdId}'`)[0];
      assert.equal(row?.status, "run");
      assert.deepEqual(row?.meta.callerContext, evoContext(), "the hold's context");
      assert.deepEqual(row?.meta.callerContextRun, evoContext({ "jotter.run": "run_2" }), "the repeat's, because it differs");
    });

    test("same context on the repeat: no callerContextRun", async () => {
      const first = await holdOf(b.insA, evoContext(), "n-rep-2");
      const holdId = first.r.body.holdId as string;
      await personOp(b, s, "tb.holds_decide", { holdId, decision: "approve" });
      const repeat = await post(b, first.g, "note_delete", { id: "n-rep-2" }, evoContext(), first.key);
      assert.equal(repeat.status, 200);
      const row = rows(b, `id = '${holdId}'`)[0];
      assert.deepEqual(row?.meta.callerContext, evoContext());
      assert.equal(row?.meta.callerContextRun, undefined);
    });

    test("a call without the same context cannot dodge the approval: the context is not part of the approval match", async () => {
      const first = await holdOf(b.insA, evoContext(), "n-rep-3");
      await personOp(b, s, "tb.holds_decide", { holdId: first.r.body.holdId, decision: "approve" });
      const repeat = await post(b, first.g, "note_delete", { id: "n-rep-3" }, {}, first.key);
      assert.equal(repeat.status, 200);
      assert.deepEqual(rows(b, `id = '${first.r.body.holdId}'`)[0]?.meta.callerContext, evoContext());
    });
  });

  describe("P3: tb.hold_status for an app caller", () => {
    test("its own hold: pending, then approved after the owner decides; output unchanged; no receipt written", async () => {
      const h = await holdOf(b.insA, evoContext(), "n-hs-1");
      const holdId = h.r.body.holdId as string;
      const before = rows(b).length;
      const s1 = await post(b, h.g, "tb.hold_status", { holdId }, {});
      assert.equal(s1.status, 200, JSON.stringify(s1.body));
      assert.equal(s1.body.status, "ok");
      assert.equal(s1.body.output.status, "held", "the receipt status, as for agents (spec text says pending; see report)");
      assert.deepEqual(Object.keys(s1.body.output).sort(), ["expiresAt", "family", "reason", "status"]);
      await personOp(b, s, "tb.holds_decide", { holdId, decision: "approve" });
      const s2 = await post(b, h.g, "tb.hold_status", { holdId }, {});
      assert.equal(s2.body.output.status, "approved");
      assert.ok(typeof s2.body.output.decidedAt === "string");
      assert.equal(rows(b).length, before, "tb.hold_status writes no receipt");
    });

    test("another app's hold, an agent's hold and an unknown id answer the identical 404 hold_not_found as an agent's unknown id (never the id)", async () => {
      const h = await holdOf(b.insA, evoContext(), "n-hs-2");
      const holdId = h.r.body.holdId as string;
      const agentHold = await agentCall(b, "note_delete", { id: "n-hs-agent" });
      assert.equal(agentHold.status, 202);
      const gB = await appGrant(b, b.insB, wfA, "inbox");
      const other = await post(b, gB, "tb.hold_status", { holdId }, {});
      const agentsHold = await post(b, h.g, "tb.hold_status", { holdId: agentHold.body.holdId }, {});
      const unknown = await post(b, h.g, "tb.hold_status", { holdId: "hld_01UNKNOWN0000000000000000" }, {});
      const notHld = await post(b, h.g, "tb.hold_status", { holdId: "rcp_01XYZ" }, {});
      // the reference: what an AGENT gets for an unknown id (the public hold_not_found answer, unchanged)
      const agentUnknown = await agentCall(b, "tb.hold_status", { holdId: "hld_01UNKNOWN0000000000000000" }, { held: false });
      assert.equal(agentUnknown.status, 404);
      assert.equal(agentUnknown.body.error.code, "hold_not_found");
      const same = noRequestId(agentUnknown.body);
      for (const x of [other, agentsHold, unknown, notHld]) {
        assert.equal(x.status, 404, JSON.stringify(x.body));
        assert.equal(noRequestId(x.body), same, "byte-equal to the agent's unknown-id envelope, requestId aside");
      }
      assert.ok(!same.includes("hld_"), "the fixed message never holds an id");
      assert.equal(noRequestId(other.body), same);
      assert.equal(noRequestId(agentsHold.body), same);
      assert.equal(noRequestId(unknown.body), same);
      assert.equal(noRequestId(notHld.body), same);
      assert.ok(!JSON.stringify(other.body).includes(holdId));
    });

    test("an agent still sees only its own holds; its answer is unchanged (hold_not_found)", async () => {
      const mine = await agentCall(b, "note_delete", { id: "n-hs-3" });
      const ok = await agentCall(b, "tb.hold_status", { holdId: mine.body.holdId }, { held: false });
      assert.equal(ok.status, 200);
      assert.equal(ok.body.output.status, "held");
      const foreign = await agentCall(b, "tb.hold_status", { holdId: mine.body.holdId }, { agent: "b", held: false });
      assert.equal(foreign.status, 404);
      assert.equal(foreign.body.error.code, "hold_not_found");
      // an agent asking for an app's hold: not found as well
      const appHold = await holdOf(b.insA, {}, "n-hs-4");
      const cross = await agentCall(b, "tb.hold_status", { holdId: appHold.r.body.holdId }, { held: false });
      assert.equal(cross.status, 404);
    });

    test("approved → the same call (op, input, key) runs exactly once; a second repeat does not run again", async () => {
      const ran = b.ran.note_delete;
      const h = await holdOf(b.insA, evoContext(), "n-once");
      await personOp(b, s, "tb.holds_decide", { holdId: h.r.body.holdId, decision: "approve" });
      const one = await post(b, h.g, "note_delete", { id: "n-once" }, evoContext(), h.key);
      assert.equal(one.status, 200, JSON.stringify(one.body));
      assert.equal(b.ran.note_delete, ran + 1);
      const two = await post(b, h.g, "note_delete", { id: "n-once" }, evoContext(), h.key);
      assert.equal(two.status, 200, "an idempotent replay answers the stored result");
      assert.deepEqual(two.body.output, one.body.output);
      assert.equal(b.ran.note_delete, ran + 1, "the handler ran once");
      const status = await post(b, h.g, "tb.hold_status", { holdId: h.r.body.holdId }, {});
      assert.equal(status.body.output.status, "run");
    });

    test("denied → the repeat does not run (hold_denied); expired → it does not run, before and after the sweep", async () => {
      const ran = b.ran.note_delete;
      const d = await holdOf(b.insA, evoContext(), "n-denied");
      await personOp(b, s, "tb.holds_decide", { holdId: d.r.body.holdId, decision: "deny" });
      const sd = await post(b, d.g, "tb.hold_status", { holdId: d.r.body.holdId }, {});
      assert.equal(sd.body.output.status, "denied");
      const rd = await post(b, d.g, "note_delete", { id: "n-denied" }, evoContext(), d.key);
      assert.equal(rd.status, 403, JSON.stringify(rd.body));
      assert.equal(rd.body.error.code, "hold_denied");
      // expired: the hold's time ran out. Before the sweep it is still `held` (the repeat is answered held, never run); the sweep marks it denied
      const e = await holdOf(b.insA, evoContext(), "n-expired");
      const db = new DatabaseSync(join(b.dataDir, "app.db"));
      try {
        db.prepare("UPDATE tb_receipts SET expires_at = ? WHERE id = ?").run(Date.now() - 1000, e.r.body.holdId);
      } finally {
        db.close();
      }
      const pre = await post(b, e.g, "note_delete", { id: "n-expired" }, evoContext(), e.key);
      assert.equal(pre.status, 202, "still held: not run");
      const db2 = new DatabaseSync(join(b.dataDir, "app.db"));
      try {
        // exactly what Receipts.sweep() does to an expired hold
        db2.prepare("UPDATE tb_receipts SET status = 'denied', decided_by = 'expiry', decided_at = ?, view = NULL WHERE id = ? AND status = 'held'").run(Date.now(), e.r.body.holdId);
      } finally {
        db2.close();
      }
      const post2 = await post(b, e.g, "note_delete", { id: "n-expired" }, evoContext(), e.key);
      assert.equal(post2.status, 403);
      assert.equal(post2.body.error.code, "hold_denied");
      assert.equal(b.ran.note_delete, ran, "the handler never ran for a denied or expired hold");
    });
  });

  // C378: the key binding and the approval signal
  const approve = async (id: unknown) => assert.equal((await personOp(b, s, "tb.holds_decide", { holdId: String(id), decision: "approve" })).status, 200);

  test("C378: another run (another key) with identical input does not use the approval; the waiting run still runs on it", async () => {
    const id = "n-bound-1";
    const before = b.ran.note_delete;
    const a = await holdOf(b.insA, evoContext({ "jotter.run": "run_a" }), id, "jotter", "wfrun:bound:run_a:step");
    assert.equal(a.r.status, 202);
    await approve(a.r.body.holdId);
    const other = await holdOf(b.insA, evoContext({ "jotter.run": "run_b" }), id, "jotter", "wfrun:bound:run_b:step");
    assert.equal(other.r.status, 202, "its own hold");
    assert.notEqual(other.r.body.holdId, a.r.body.holdId);
    assert.equal(b.ran.note_delete, before, "nothing ran on the other run's approval");
    const repeat = await holdOf(b.insA, evoContext({ "jotter.run": "run_a" }), id, "jotter", "wfrun:bound:run_a:step");
    assert.equal(repeat.r.status, 200, "the waiting run is not held again");
    assert.equal(b.ran.note_delete, before + 1);
    assert.deepEqual(b.approvals.at(-1), { id: a.r.body.holdId, family: "destructive" }, "the signal names the hold this call consumed");
  });

  test("C378: both runs approved: each repeat uses its own approval, in any order (no held_again)", async () => {
    const id = "n-bound-2";
    const before = b.ran.note_delete;
    const a = await holdOf(b.insA, {}, id, "jotter", "wfrun:both:run_a:step");
    const c = await holdOf(b.insA, {}, id, "jotter", "wfrun:both:run_c:step");
    assert.deepEqual([a.r.status, c.r.status], [202, 202]);
    await approve(a.r.body.holdId);
    await approve(c.r.body.holdId);
    // run_a repeats first although run_c's approval is the newer one
    assert.equal((await holdOf(b.insA, {}, id, "jotter", "wfrun:both:run_a:step")).r.status, 200);
    assert.equal(b.approvals.at(-1)?.id, a.r.body.holdId);
    assert.equal((await holdOf(b.insA, {}, id, "jotter", "wfrun:both:run_c:step")).r.status, 200);
    assert.equal(b.approvals.at(-1)?.id, c.r.body.holdId);
    assert.equal(b.ran.note_delete, before + 2);
  });

  test("C378: a call with no approval sees approvedHold null; a repeat with the stored result does not run again", async () => {
    const before = b.ran.note_delete;
    const g = await grant(b.w, b.w.agents.a, { held: [] });
    assert.equal((await post(b, g, "note_delete", { id: "n-free" }, {}, `k_${ulid()}`)).status, 200);
    assert.equal(b.approvals.at(-1), null, "ran with no hold: no signal");
    const key = "wfrun:once:run_a:step";
    const a = await holdOf(b.insA, {}, "n-once", "jotter", key);
    await approve(a.r.body.holdId);
    assert.equal((await holdOf(b.insA, {}, "n-once", "jotter", key)).r.status, 200);
    const runs = b.ran.note_delete;
    assert.equal((await holdOf(b.insA, {}, "n-once", "jotter", key)).r.status, 200, "the stored answer");
    assert.equal(b.ran.note_delete, runs, "not run again");
    assert.equal(runs, before + 2);
  });

  test("C378: an agent keeps today's match: an approval made under one key serves a repeat under another", async () => {
    const before = b.ran.note_delete;
    const first = await agentCall(b, "note_delete", { id: "n-agent-keys" }, { key: `k_${ulid()}` });
    assert.equal(first.status, 202);
    await approve(first.body.holdId);
    const repeat = await agentCall(b, "note_delete", { id: "n-agent-keys" }, { key: `k_${ulid()}` });
    assert.equal(repeat.status, 200);
    assert.equal(b.ran.note_delete, before + 1);
    assert.equal(b.approvals.at(-1)?.id, first.body.holdId);
  });
});
