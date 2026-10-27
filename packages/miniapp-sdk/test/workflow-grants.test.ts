// C373 P1 (spec 0.1.82, SDK-API §22): per-workflow companion grants.
// Caller side: app caps in the claim and every push, `callApp(..., { workflow })` (local order, selection by wfl, on-demand fetch, cache until
// half-life, ONE retry, NEVER the base grant), `ctx.workflowGrants.request/status/release`. Target side: `Caller.workflow`, receipt
// `meta.callerWorkflow`, the verifier (wfl accepted, exp − iat ≤ 900).
// Every rule has a quiet-on-good case and a fire-on-bad case.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { signGrant, ulid, WORKFLOW_GRANT_TTL_SEC } from "@opt2-tealbrick/manifest";
import { type InstanceId, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, OpContext, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../src/server/errors.ts";
import { defineApp, type SdkEventContext, type SdkOpContext, type StartContext, startApp } from "../src/server/index.ts";
import { callAppOpts, callerWorkflowOf, withCallerWorkflow, workflowOfGrant } from "../src/server/ops.ts";
import { workflowRequestProblem } from "../src/server/workflow-grants.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, rawSign, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const PEER = "peer-app";
const CAP = "app_workflow_grants";
const WFA = "wf-a";
const WFB = "wf-b";

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dataDir: string;
  startCtx: StartContext | null;
  eventCtx: SdkEventContext | null;
  opCtx: SdkOpContext | null;
  /** what the op `note_get` calls through ctx.callApp (set by a test) */
  next: { product: string; op: string; input: Json; opts?: { workflow?: string } } | null;
  /** what `note_delete` writes to ctx.receipt.meta (set by a test) */
  receiptMeta: Json | undefined;
  seenCaller: { workflow?: string }[];
  peerIns: InstanceId;
  baseGrant: string;
  cleanup(): Promise<void>;
}

const manifestOf = (port: number): Manifest => {
  const m = fixtureManifest(port);
  m.companions = [
    {
      product: PEER,
      operations: ["peer_list", "tb.hold_status"],
      crud: ["read"],
      purpose: "Read the peer list and the status of the holds this app raised.",
      perWorkflow: { operations: ["peer_create", "peer_update", "peer_get"], crud: ["read", "create", "update"] },
    } as Manifest["companions"] extends (infer C)[] | undefined ? C : never,
  ];
  return m;
};

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const peerIns = `ins_${ulid()}` as InstanceId;
  const baseGrant = await signGrant(
    { iss: "tb:portal", sub: `tb:ins:${w.ins}`, aud: `tb:ins:${peerIns}`, iat: nowS(), ws: w.ws, cnf: { brg: w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: ["peer_list", "tb.hold_status"], polrev: 1 },
    w.portal,
  );
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { grants: [baseGrant], companionTargets: [{ product: PEER, ins: peerIns }], bridgeCaps: [CAP] }));
  const b = { w, bridge, dataDir: t.dir, startCtx: null, eventCtx: null, opCtx: null, next: null, receiptMeta: undefined, seenCaller: [], peerIns, baseGrant } as unknown as Booted;
  b.base = `http://127.0.0.1:${port}`;
  const app = defineApp({
    manifest: manifestOf(port),
    migrations: migrationsDir(t.dir),
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async (_input, ctx0: OpContext) => {
        const ctx = ctx0 as unknown as SdkOpContext;
        b.opCtx = ctx;
        const n = b.next;
        if (!n) return { none: true };
        return (await ctx.callApp(n.product, n.op, n.input, n.opts)) as unknown as Json;
      },
      note_delete: async (_input, ctx0: OpContext) => {
        const ctx = ctx0 as unknown as SdkOpContext;
        b.seenCaller.push({ ...(ctx.caller.workflow !== undefined ? { workflow: ctx.caller.workflow } : {}) });
        if (b.receiptMeta !== undefined) ctx.receipt.meta(b.receiptMeta);
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
  return b;
}

/** pushes a slice (base grant, the peer target unless `targets` is given, the given bridge caps) and waits until the app serves it */
async function setSlice(b: Booted, caps: string[] | undefined, targets: { product: string; ins: string }[] = [{ product: PEER, ins: b.peerIns }]): Promise<void> {
  const before = b.bridge.statuses.length;
  b.bridge.push(await slice(b.w, PRODUCT, { grants: [b.baseGrant], companionTargets: targets, ...(caps ? { bridgeCaps: caps } : {}) }));
  await until(async () => b.bridge.statuses.length > before && (b.bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === b.w.rev);
}

/** A workflow grant as Core mints it: companion grant of THIS instance for the peer, with `wfl` and `prd`. */
async function wflGrant(b: Booted, wfl: string, wf: string[], over: { iat?: number; aud?: InstanceId; sub?: string } = {}): Promise<string> {
  return signGrant(
    {
      iss: "tb:portal",
      sub: over.sub ?? `tb:ins:${b.w.ins}`,
      aud: `tb:ins:${over.aud ?? b.peerIns}`,
      iat: over.iat ?? nowS(),
      ws: b.w.ws,
      cnf: { brg: b.w.brg },
      crud: ["read", "create", "update"],
      mode: "bound",
      held: [],
      caps: {},
      wf,
      polrev: 1,
      wfl,
      prd: PRODUCT,
    } as never,
    b.w.portal,
  );
}

const statusOf = (wfl: string, state = "applied") => ({
  wfl,
  state,
  title: "T",
  applied: state === "applied" ? [{ product: PEER, ops: ["peer_create"], crud: ["create"] }] : null,
  appliedDigest: null,
  pending: null,
  rejectedDigest: null,
  updatedAt: null,
});
const refusal = (status: number, code: string, details?: Record<string, unknown>) => ({ status, body: { error: { code, message: code, requestId: "req_test", ...(details ? { details } : {}) } } });
const code = (c: string, status?: number) => (e: unknown) => e instanceof TbError && e.code === c && (status === undefined || e.httpStatus === status);

/** Core-fake behind the bridge relay: `get` with aud mints from `minted[wfl]`; every relay is recorded by the FakeBridge. */
function core(b: Booted, minted: Map<string, string>): void {
  b.bridge.onWorkflowGrant = (kind, body) => {
    const wfl = String(body.wfl);
    if (kind === "get") {
      const grant = minted.get(wfl);
      if (body.aud === undefined) return { status: 200, body: statusOf(wfl) };
      return grant ? { status: 200, body: { status: statusOf(wfl), grant } } : refusal(404, "workflow_grant_missing");
    }
    return { status: 200, body: statusOf(wfl, kind === "release" ? "withdrawn" : "requested") };
  };
}

const okCall = () => ({ status: 200, body: { status: "ok", output: { done: true } } });

describe("A12.app_caps: the SDK reports app_workflow_grants and grant_wfl (no version gate)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());
  test("ClaimRequest.caps and every AppStatus.caps carry both caps", async () => {
    assert.deepEqual(b.bridge.claimBodies[0]?.caps, [CAP, "grant_wfl"]);
    assert.ok(b.bridge.statuses.length >= 1);
    for (const s of b.bridge.statuses) assert.deepEqual(s.caps, [CAP, "grant_wfl"]);
  });
});

describe("callApp({ workflow }) — caller side (SDK-API §22 items 3-6)", () => {
  let b: Booted;
  const minted = new Map<string, string>();
  const calls = () => b.bridge.calls.length;
  const relays = (kind?: string) => b.bridge.workflowRelays.filter((r) => kind === undefined || r.kind === kind).length;
  const call = (op: string, workflow?: string, ctx: "start" | "event" = "start") => ((ctx === "start" ? b.startCtx : b.eventCtx) as StartContext | SdkEventContext).callApp(PEER, op, { x: 1 }, workflow === undefined ? undefined : { workflow });

  /** a new slice that drops the target and a second one that lists it again: no cached workflow grant survives */
  const fresh = async (caps: string[]) => {
    await setSlice(b, caps, []);
    await setSlice(b, caps);
  };

  before(async () => {
    b = await boot();
    core(b, minted);
  });
  after(async () => b.cleanup());

  test("A12.wfl_local_order: pattern first (input_invalid /workflow), then the cap (bridge_cap_missing), then companion_undeclared; nothing is sent", async () => {
    const n = calls();
    const r = relays();
    await fresh([CAP]);
    for (const bad of ["Bad", "ab", "1abc", "a_b_c", "x".repeat(41), ""]) {
      await assert.rejects(call("peer_create", bad), (e: unknown) => {
        assert.ok(e instanceof TbError);
        assert.equal(e.code, "input_invalid");
        assert.equal(e.httpStatus, 400);
        assert.deepEqual(e.details, { pointer: "/workflow" });
        return true;
      });
    }
    await setSlice(b, ["owner_rows"]);
    await assert.rejects(call("peer_create", "Bad"), code("input_invalid", 400), "the pattern is checked before the cap");
    for (const ctx of ["start", "event"] as const) {
      await assert.rejects(call("peer_create", WFA, ctx), (e: unknown) => {
        assert.ok(e instanceof TbError);
        assert.equal(e.code, "bridge_cap_missing");
        assert.equal(e.httpStatus, 409);
        assert.deepEqual(e.details, { cap: CAP });
        return true;
      });
    }
    await setSlice(b, undefined);
    await assert.rejects(call("peer_create", WFA), code("bridge_cap_missing", 409), "a slice with no caps at all");
    await fresh([CAP]);
    // an op outside perWorkflow.operations (and not tb.hold_status of the base entry): companion_undeclared, no fetch
    for (const op of ["peer_delete", "tb.holds_pending", "tb.receipts_list"]) await assert.rejects(call(op, WFA), code("companion_undeclared"), op);
    assert.equal(calls(), n, "no call reached the bridge");
    assert.equal(relays(), r, "no workflow grant was fetched");
  });

  test("A12.wfl_no_base_fallback: an op outside the workflow's wf is not_in_workflow locally; a base-only op is companion_undeclared; the base grant never goes out with `workflow`", async () => {
    await fresh([CAP]);
    minted.set(WFA, await wflGrant(b, WFA, ["peer_create"]));
    const n = calls();
    await assert.rejects(call("peer_update", WFA), (e: unknown) => {
      assert.ok(e instanceof TbError);
      assert.equal(e.code, "not_in_workflow");
      assert.equal(e.httpStatus, 403);
      return true;
    });
    // peer_list is in the BASE grant and the base entry, not in perWorkflow: no fallback to the base grant
    await assert.rejects(call("peer_list", WFA), code("companion_undeclared"));
    assert.equal(calls(), n, "nothing was sent");
    // quiet on good: without `workflow` the base grant goes out, no `workflow` field, and never a grant with wfl
    const r = await call("peer_list");
    assert.equal(r.status, "ok");
    const sent = b.bridge.calls.at(-1) as (typeof b.bridge.calls)[number];
    assert.equal("workflow" in sent.body, false);
    assert.equal(sent.grant, b.baseGrant);
    assert.equal(workflowOfGrant(sent.grant), undefined);
  });

  test("a workflow call presents the workflow grant (TB-Grant) and sets CallEnvelope.workflow, in start, event and op ctx", async () => {
    await fresh([CAP]);
    const g = await wflGrant(b, WFA, ["peer_create", "peer_get"]);
    minted.set(WFA, g);
    const sent = async () => b.bridge.calls.at(-1) as (typeof b.bridge.calls)[number];
    const rs = relays("get");
    assert.equal((await call("peer_create", WFA)).status, "ok");
    const c1 = await sent();
    assert.equal(c1.grant, g);
    assert.equal(workflowOfGrant(c1.grant), WFA);
    assert.deepEqual(c1.body, { target: PEER, op: "peer_create", input: { x: 1 }, workflow: WFA });
    assert.equal("parentCall" in c1.body, false);
    const get = b.bridge.workflowRelays.at(-1);
    assert.equal(get?.kind, "get");
    assert.equal(get?.assertOk, true);
    assert.deepEqual(get?.body, { wfl: WFA, aud: b.peerIns });
    // event ctx: the cached grant is reused (no new fetch)
    assert.equal((await call("peer_get", WFA, "event")).status, "ok");
    assert.equal((await sent()).grant, g);
    assert.equal(relays("get"), rs + 1, "fetched once, then cached");
    // op ctx: parentCall + workflow
    b.next = { product: PEER, op: "peer_create", input: { o: 1 }, opts: { workflow: WFA } };
    const key = await agentCallOp(b);
    assert.equal(key.status, 200, JSON.stringify(key.body));
    const c3 = await sent();
    assert.equal(c3.body.workflow, WFA);
    assert.match(String(c3.body.parentCall), /^call_/);
    assert.equal(c3.grant, g);
    assert.equal(relays("get"), rs + 1, "still cached");
    b.next = null;
  });

  test("two workflows keep two grants: each call carries its own wfl; a grant for another workflow, target or instance is refused (grant_invalid, nothing cached)", async () => {
    await fresh([CAP]);
    const ga = await wflGrant(b, WFA, ["peer_create"]);
    const gb = await wflGrant(b, WFB, ["peer_get"]);
    minted.set(WFA, ga);
    minted.set(WFB, gb);
    await call("peer_create", WFA);
    assert.equal((b.bridge.calls.at(-1) as { grant: string }).grant, ga);
    await call("peer_get", WFB);
    assert.equal(workflowOfGrant((b.bridge.calls.at(-1) as { grant: string }).grant), WFB);
    // wf-b's grant does not allow wf-a's op, and vice versa
    await assert.rejects(call("peer_create", WFB), code("not_in_workflow", 403));
    await assert.rejects(call("peer_get", WFA), code("not_in_workflow", 403));
    // Core (or a broken bridge) hands out a grant that is not for this call
    const n = calls();
    for (const [name, g] of [
      ["other workflow", await wflGrant(b, WFB, ["peer_create"])],
      ["other target", await wflGrant(b, WFA, ["peer_create"], { aud: `ins_${ulid()}` as InstanceId })],
      ["other caller", await wflGrant(b, WFA, ["peer_create"], { sub: `tb:ins:ins_${ulid()}` })],
      ["a base grant", b.baseGrant],
    ] as const) {
      minted.set("wf-c", g);
      await assert.rejects(call("peer_create", "wf-c"), code(name === "a base grant" ? "grant_invalid" : "grant_invalid", 502), name);
    }
    assert.equal(calls(), n, "none of them was sent");
  });

  test("cache: a grant with more than half its life left is reused; one past half-life is fetched again", async () => {
    await fresh([CAP]);
    minted.set("wf-fresh", await wflGrant(b, "wf-fresh", ["peer_create"]));
    const rs = relays("get");
    await call("peer_create", "wf-fresh");
    await call("peer_create", "wf-fresh");
    await call("peer_create", "wf-fresh");
    assert.equal(relays("get"), rs + 1);
    // iat 500 s ago: 400 s left of 900 → less than half: every call fetches
    minted.set("wf-old", await wflGrant(b, "wf-old", ["peer_create"], { iat: nowS() - (WORKFLOW_GRANT_TTL_SEC / 2 + 50) }));
    const ro = relays("get");
    await call("peer_create", "wf-old");
    await call("peer_create", "wf-old");
    assert.equal(relays("get"), ro + 2, "no reuse past half-life");
    // iat 440 s ago: just under half used: reused
    minted.set("wf-half", await wflGrant(b, "wf-half", ["peer_create"], { iat: nowS() - 440 }));
    const rh = relays("get");
    await call("peer_create", "wf-half");
    await call("peer_create", "wf-half");
    assert.equal(relays("get"), rh + 1);
  });

  test("a new slice without the target drops its cached grants; with it again the next call fetches", async () => {
    await fresh([CAP]);
    minted.set(WFA, await wflGrant(b, WFA, ["peer_create"]));
    await call("peer_create", WFA);
    const rs = relays("get");
    await call("peer_create", WFA);
    assert.equal(relays("get"), rs, "cached");
    await setSlice(b, [CAP], []);
    await assert.rejects(call("peer_create", WFA), code("no_grant", 403));
    await fresh([CAP]);
    await call("peer_create", WFA);
    assert.equal(relays("get"), rs + 1, "dropped with the target");
  });

  test("Core refusals are thrown as they come: missing 404, withdrawn 410, unsupported 409 with details.product; nothing is sent, no base fallback", async () => {
    await fresh([CAP]);
    const n = calls();
    minted.delete("wf-none");
    await assert.rejects(call("peer_create", "wf-none"), code("workflow_grant_missing", 404));
    for (const [c, status, details] of [
      ["workflow_grant_withdrawn", 410, undefined],
      ["workflow_grants_unsupported", 409, { product: PEER }],
      ["workflow_grants_full", 409, undefined],
      ["portal_unavailable", 503, undefined],
    ] as const) {
      b.bridge.onWorkflowGrant = () => refusal(status, c, details);
      await assert.rejects(call("peer_create", WFA), (e: unknown) => {
        assert.ok(e instanceof TbError);
        assert.equal(e.code, c);
        assert.equal(e.httpStatus, status);
        if (details) assert.deepEqual(e.details, details);
        return true;
      });
    }
    core(b, minted);
    assert.equal(calls(), n, "the base grant was never presented");
  });

  test("A12.wfl_refresh_once: the bridge answers workflow_grant_withdrawn once → drop, fetch, retry once; twice → thrown", async () => {
    await fresh([CAP]);
    const g1 = await wflGrant(b, "wf-once", ["peer_create"]);
    minted.set("wf-once", g1);
    await call("peer_create", "wf-once"); // cached
    const g2 = await wflGrant(b, "wf-once", ["peer_create"], { iat: nowS() + 1 });
    minted.set("wf-once", g2);
    let n = 0;
    b.bridge.onCall = () => (n++ === 0 ? refusal(403, "workflow_grant_withdrawn") : okCall());
    const c0 = calls();
    const r0 = relays("get");
    assert.equal((await call("peer_create", "wf-once")).status, "ok");
    assert.equal(calls(), c0 + 2, "one retry");
    assert.equal(relays("get"), r0 + 1, "one refetch");
    assert.equal((b.bridge.calls.at(-2) as { grant: string }).grant, g1, "first attempt: the cached grant");
    assert.equal((b.bridge.calls.at(-1) as { grant: string }).grant, g2, "retry: the new grant");
    // quiet: the new grant is cached now
    b.bridge.onCall = okCall;
    await call("peer_create", "wf-once");
    assert.equal(relays("get"), r0 + 1);
    // grant_expired is retried the same way
    n = 0;
    b.bridge.onCall = () => (n++ === 0 ? refusal(401, "grant_expired") : okCall());
    const c1 = calls();
    await call("peer_create", "wf-once");
    assert.equal(calls(), c1 + 2);
    // twice → thrown, exactly two attempts and one refetch
    b.bridge.onCall = () => refusal(403, "workflow_grant_withdrawn");
    const c2 = calls();
    const r2 = relays("get");
    await assert.rejects(call("peer_create", "wf-once"), code("workflow_grant_withdrawn", 403));
    assert.equal(calls(), c2 + 2);
    assert.equal(relays("get"), r2 + 1);
    // any other refusal is not retried
    b.bridge.onCall = () => refusal(403, "crud_exceeds_grant");
    const c3 = calls();
    await assert.rejects(call("peer_create", "wf-once"), code("crud_exceeds_grant", 403));
    assert.equal(calls(), c3 + 1);
    b.bridge.onCall = okCall;
  });

  test("C4: a cached grant the owner withdrew → ONE refetch, then the refusal; the base grant is never tried", async () => {
    await fresh([CAP]);
    minted.set("wf-c4", await wflGrant(b, "wf-c4", ["peer_create"]));
    await call("peer_create", "wf-c4"); // quiet on good: cached and accepted
    b.bridge.onCall = () => refusal(403, "workflow_grant_withdrawn");
    b.bridge.onWorkflowGrant = (kind, body) => (kind === "get" && body.aud !== undefined ? refusal(410, "workflow_grant_withdrawn") : { status: 200, body: statusOf("wf-c4", "withdrawn") });
    const c = calls();
    const r = relays("get");
    await assert.rejects(call("peer_create", "wf-c4"), code("workflow_grant_withdrawn", 410));
    assert.equal(calls(), c + 1, "one attempt with the cached grant");
    assert.equal(relays("get"), r + 1, "one refetch");
    assert.ok(b.bridge.calls.slice(c).every((x) => workflowOfGrant(x.grant) === "wf-c4"));
    b.bridge.onCall = okCall;
    core(b, minted);
  });

  test("tb.hold_status under a workflow: allowed only when the BASE entry lists it, then it needs the workflow grant's wf; tb.holds_pending → companion_undeclared", async () => {
    await fresh([CAP, "app_hold_status"]);
    minted.set("wf-hold", await wflGrant(b, "wf-hold", ["tb.hold_status"]));
    assert.equal((await call("tb.hold_status", "wf-hold")).status, "ok");
    assert.equal(workflowOfGrant((b.bridge.calls.at(-1) as { grant: string }).grant), "wf-hold");
    // a workflow grant without it in wf
    minted.set("wf-nohold", await wflGrant(b, "wf-nohold", ["peer_create"]));
    await assert.rejects(call("tb.hold_status", "wf-nohold"), code("not_in_workflow", 403));
    const n = calls();
    await assert.rejects(call("tb.holds_pending", "wf-hold"), code("companion_undeclared"), "tb.holds_pending with `workflow` is refused locally");
    assert.equal(calls(), n);
  });

  test("the P4 context checks still run after the workflow checks (cap app_call_context)", async () => {
    await fresh([CAP]);
    minted.set(WFA, await wflGrant(b, WFA, ["peer_create"]));
    const n = calls();
    await assert.rejects(
      (b.startCtx as StartContext).callApp(PEER, "peer_create", {}, { workflow: WFA, context: { "jotter.a": 1 } } as never),
      code("bridge_cap_missing", 409),
    );
    await setSlice(b, [CAP, "app_call_context"]);
    assert.equal(((await (b.startCtx as StartContext).callApp(PEER, "peer_create", {}, { workflow: WFA, context: { "jotter.a": 1 } } as never)) as { status: string }).status, "ok");
    const sent = b.bridge.calls.at(-1)?.body as Record<string, unknown>;
    assert.equal(sent.workflow, WFA);
    assert.deepEqual(sent.context, { "jotter.a": 1 });
    assert.equal(calls(), n + 1);
  });
});

/** the op `note_get` (set up by `b.next`) as an agent call: the op ctx path of callApp */
async function agentCallOp(b: Booted) {
  const g = await grant(b.w, b.w.agents.a, { held: [] });
  const input = { id: "x" };
  const proof = await callProof(b.w, g, "note_get", input);
  const res = await fetch(`${b.base}/tb/v1/ops/note_get`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {} }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe("ctx.workflowGrants — request, status, release (SDK-API §22 item 2)", () => {
  let b: Booted;
  const minted = new Map<string, string>();
  const relays = () => b.bridge.workflowRelays;
  const target = (over: Record<string, unknown> = {}) => ({ product: PEER, ops: ["peer_create"], crud: ["create"], ...over });
  const body = (over: Record<string, unknown> = {}) => ({ wfl: WFA, title: "Weekly digest", targets: [target()], ...over });
  const apis = () => [
    ["start", (b.startCtx as StartContext).workflowGrants],
    ["event", (b.eventCtx as SdkEventContext).workflowGrants],
  ] as const;

  before(async () => {
    b = await boot();
    core(b, minted);
  });
  after(async () => b.cleanup());

  test("every ctx has workflowGrants with request, status and release", async () => {
    for (const [name, api] of apis()) {
      assert.ok(api, name);
      for (const m of ["request", "status", "release"] as const) assert.equal(typeof api[m], "function", `${name}.${m}`);
    }
    b.next = null;
    const g = await agentCallOp(b);
    assert.equal(g.status, 200);
    assert.equal(typeof b.opCtx?.workflowGrants?.request, "function", "op ctx");
  });

  test("without the cap every method throws bridge_cap_missing (409, details.cap) before any network call", async () => {
    for (const caps of [["owner_rows"], undefined]) {
      await setSlice(b, caps);
      const n = relays().length;
      for (const [name, api] of apis()) {
        for (const call of [() => api.request(body() as never), () => api.status(WFA), () => api.release(WFA)]) {
          await assert.rejects(call(), (e: unknown) => {
            assert.ok(e instanceof TbError, name);
            assert.equal(e.code, "bridge_cap_missing");
            assert.equal(e.httpStatus, 409);
            assert.deepEqual(e.details, { cap: CAP });
            return true;
          });
        }
      }
      assert.equal(relays().length, n);
    }
  });

  test("request: a valid body is relayed as given and the status comes back; the instance assertion verified", async () => {
    await setSlice(b, [CAP]);
    const full = body({ reason: "Needs to create issues", targets: [target({ ops: ["peer_create", "peer_update"], crud: ["create", "update"] })] });
    const s = await apis()[0][1].request(full as never);
    assert.equal(s.state, "requested");
    const r = relays().at(-1);
    assert.equal(r?.kind, "request");
    assert.equal(r?.assertOk, true);
    assert.deepEqual(r?.body, full);
    // from the event ctx too
    assert.equal((await apis()[1][1].request(body() as never)).wfl, WFA);
  });

  test("request: the local pre-check refuses with validation_failed + details.pointer; nothing is relayed", async () => {
    await setSlice(b, [CAP]);
    const n = relays().length;
    const cases: [Record<string, unknown>, string][] = [
      [body({ wfl: "Bad" }), "/wfl"],
      [body({ title: "" }), "/title"],
      [body({ title: "t".repeat(121) }), "/title"],
      [body({ reason: "r".repeat(281) }), "/reason"],
      [body({ extra: 1 }), "/extra"],
      [body({ targets: [] }), "/targets"],
      [body({ targets: Array.from({ length: 9 }, (_, i) => target({ product: `p-${i}` })) }), "/targets"],
      [body({ targets: [target(), target()] }), "/targets/1/product"],
      [body({ targets: [target({ product: PRODUCT })] }), "/targets/0/product"],
      [body({ targets: [target({ product: "unknown-app" })] }), "/targets/0/product"],
      [body({ targets: [target({ ops: [] })] }), "/targets/0/ops"],
      [body({ targets: [target({ ops: ["peer_create", "peer_create"] })] }), "/targets/0/ops"],
      [body({ targets: [target({ ops: ["peer_list"] })] }), "/targets/0/ops/0"],
      [body({ targets: [target({ ops: ["peer_create", "tb.hold_status"] })] }), "/targets/0/ops/1"],
      [body({ targets: [target({ crud: [] })] }), "/targets/0/crud"],
      [body({ targets: [target({ crud: ["delete"] })] }), "/targets/0/crud/0"],
      [body({ targets: [target({ crud: ["create", "create"] })] }), "/targets/0/crud"],
      [body({ targets: [target({ nope: 1 })] }), "/targets/0/nope"],
    ];
    for (const [bad, pointer] of cases) {
      await assert.rejects(apis()[0][1].request(bad as never), (e: unknown) => {
        assert.ok(e instanceof TbError, pointer);
        assert.equal(e.code, "validation_failed");
        assert.equal(e.httpStatus, 400);
        assert.deepEqual(e.details, { pointer });
        return true;
      }, pointer);
    }
    assert.equal(relays().length, n);
    // the same rules as a pure function (the manifest of the running app)
    const rt = { manifest: manifestOf(1) } as never;
    assert.equal(workflowRequestProblem(rt, body() as never), null);
    assert.equal(workflowRequestProblem(rt, body({ targets: [target({ ops: Array.from({ length: 65 }, (_, i) => `op_${i}`) })] }) as never)?.details?.pointer, "/targets/0/ops");
  });

  test("status relays {wfl} without aud; Core's refusals pass through unchanged", async () => {
    await setSlice(b, [CAP]);
    const s = await apis()[0][1].status(WFA);
    assert.equal(s.state, "applied");
    assert.deepEqual(relays().at(-1)?.body, { wfl: WFA });
    await assert.rejects(apis()[0][1].status("Bad"), code("validation_failed", 400));
    b.bridge.onWorkflowGrant = () => refusal(409, "workflow_grants_full");
    await assert.rejects(apis()[0][1].request(body() as never), code("workflow_grants_full", 409));
    b.bridge.onWorkflowGrant = () => refusal(400, "validation_failed", { pointer: "/targets/0/ops/1" });
    await assert.rejects(apis()[0][1].request(body() as never), (e: unknown) => {
      assert.ok(e instanceof TbError);
      assert.equal(e.code, "validation_failed");
      assert.deepEqual(e.details, { pointer: "/targets/0/ops/1" }, "Core's details.pointer reaches the caller");
      return true;
    });
    b.bridge.onWorkflowGrant = () => refusal(503, "portal_unavailable");
    await assert.rejects(apis()[0][1].status(WFA), code("portal_unavailable", 503));
    b.bridge.onWorkflowGrant = () => ({ status: 200, body: { nope: true } });
    await assert.rejects(apis()[0][1].status(WFA), code("bridge_error", 502));
    core(b, minted);
  });

  test("release is a kill path: it drops every cached grant of that workflow first, even when the relay fails; request drops them too", async () => {
    await setSlice(b, [CAP]);
    minted.set(WFA, await wflGrant(b, WFA, ["peer_create"]));
    minted.set(WFB, await wflGrant(b, WFB, ["peer_get"]));
    const call = (wfl: string, op: string) => (b.startCtx as StartContext).callApp(PEER, op, {}, { workflow: wfl });
    const gets = () => relays().filter((r) => r.kind === "get" && r.body.aud !== undefined).length;
    await call(WFA, "peer_create");
    await call(WFB, "peer_get");
    const g0 = gets();
    await call(WFA, "peer_create");
    await call(WFB, "peer_get");
    assert.equal(gets(), g0, "cached");
    b.bridge.onWorkflowGrant = () => refusal(503, "portal_unavailable");
    await assert.rejects(apis()[0][1].release(WFA), code("portal_unavailable", 503));
    core(b, minted);
    await call(WFB, "peer_get");
    assert.equal(gets(), g0, "wf-b stays cached");
    await call(WFA, "peer_create");
    assert.equal(gets(), g0 + 1, "wf-a was dropped by the failed release");
    const s = await apis()[0][1].release(WFA);
    assert.equal(s.state, "withdrawn");
    assert.deepEqual(relays().at(-1)?.body, { wfl: WFA });
    assert.equal(relays().at(-1)?.kind, "release");
    // request: the applied set may have changed → the next call fetches
    await call(WFA, "peer_create");
    const g1 = gets();
    await apis()[0][1].request(body() as never);
    await call(WFA, "peer_create");
    assert.equal(gets(), g1 + 1);
  });
});

describe("target side: Caller.workflow, receipt meta.callerWorkflow, the verifier (SDK-API §22 item 7)", () => {
  let b: Booted;
  const other = `ins_${ulid()}` as InstanceId;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  /** a companion grant FOR this app from another instance (`prd` "evolution"), with or without `wfl` */
  async function appGrant(wfl: string | undefined, over: { exp?: number } = {}): Promise<string> {
    const claims = {
      iss: "tb:portal",
      sub: `tb:ins:${other}`,
      aud: `tb:ins:${b.w.ins}`,
      iat: nowS(),
      ws: b.w.ws,
      cnf: { brg: b.w.brg },
      crud: ["delete"],
      mode: "bound",
      held: [],
      caps: {},
      wf: ["note_delete", "note_get"],
      polrev: 1,
      prd: "evolution",
      ...(wfl !== undefined ? { wfl } : {}),
    };
    if (over.exp === undefined) return signGrant(claims as never, b.w.portal);
    // a lifetime the signer refuses (> 900 s with wfl): sign the payload directly, as a malicious issuer would
    const ok = JSON.parse(Buffer.from((await signGrant(claims as never, b.w.portal)).split(".")[1] as string, "base64url").toString("utf8"));
    return rawSign({ alg: "EdDSA", typ: TYP.grant, kid: b.w.portal.kid }, { ...ok, exp: ok.iat + over.exp }, b.w.portal);
  }
  const rows = (where = "1=1") => {
    const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
    try {
      return (db.prepare(`SELECT id, op, status, caller_type, meta FROM tb_receipts WHERE ${where} ORDER BY created_at, id`).all() as any[]).map((r) => ({ ...r, meta: JSON.parse(r.meta) }));
    } finally {
      db.close();
    }
  };
  async function post(g: string, op: string, input: Json, key: string) {
    const proof = await callProof(b.w, g, op, input, {});
    const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
      body: JSON.stringify({ input, context: {}, idempotencyKey: key }),
    });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  }

  test("A12.wfl_present: ctx.caller.workflow = the verified wfl; the receipt has meta.callerWorkflow; ctx.receipt.meta({callerWorkflow}) cannot change it", async () => {
    b.receiptMeta = { callerWorkflow: "x", note: 1 };
    b.seenCaller.length = 0;
    const r = await post(await appGrant(WFA), "note_delete", { id: "n1" }, `k_${ulid()}`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(b.seenCaller, [{ workflow: WFA }]);
    const row = rows("caller_type = 'app'").at(-1);
    assert.equal(row?.meta.callerWorkflow, WFA);
    assert.equal(row?.meta.note, 1, "the handler's other meta stays");
  });

  test("A12.wfl_absent: a base grant → no ctx.caller.workflow, no meta.callerWorkflow (a handler-set key is removed)", async () => {
    b.receiptMeta = { callerWorkflow: "x" };
    b.seenCaller.length = 0;
    const r = await post(await appGrant(undefined), "note_delete", { id: "n2" }, `k_${ulid()}`);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(b.seenCaller, [{}]);
    const row = rows("caller_type = 'app'").at(-1);
    assert.equal(row?.meta?.callerWorkflow, undefined);
  });

  test("a refused call (hold, failure) records meta.callerWorkflow as well", async () => {
    b.receiptMeta = undefined;
    const held = await signGrant({ iss: "tb:portal", sub: `tb:ins:${other}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["delete"], mode: "bound", held: ["destructive"], caps: {}, wf: ["note_delete"], polrev: 1, prd: "evolution", wfl: WFB } as never, b.w.portal);
    const r = await post(held, "note_delete", { id: "n3" }, `k_${ulid()}`);
    assert.equal(r.status, 202, JSON.stringify(r.body));
    assert.equal(rows(`id = '${r.body.holdId}'`)[0]?.meta.callerWorkflow, WFB);
  });

  test("A12.wfl_ttl: exp − iat = 900 accepted; 901 → grant_invalid; a wfl that breaks the pattern → grant_invalid; wfl without prd → grant_invalid", async () => {
    const ok = await post(await appGrant(WFA, { exp: 900 }), "note_delete", { id: "n4" }, `k_${ulid()}`);
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const long = await post(await appGrant(WFA, { exp: 901 }), "note_delete", { id: "n5" }, `k_${ulid()}`);
    assert.equal(long.status, 401, JSON.stringify(long.body));
    assert.equal(long.body.error.code, "grant_invalid");
    const good = JSON.parse(Buffer.from((await appGrant(WFA)).split(".")[1] as string, "base64url").toString("utf8"));
    const header = { alg: "EdDSA", typ: TYP.grant, kid: b.w.portal.kid };
    for (const [name, payload] of [
      ["bad pattern", { ...good, wfl: "Bad_Id" }],
      ["no prd", Object.fromEntries(Object.entries(good).filter(([k]) => k !== "prd"))],
      ["12 h", { ...good, exp: good.iat + 43200 }],
    ] as const) {
      const r = await post(await rawSign(header, payload, b.w.portal), "note_delete", { id: "n6" }, `k_${ulid()}`);
      assert.equal(r.body.error.code, "grant_invalid", name);
    }
  });
});

describe("unit rules", () => {
  test("callAppOpts passes `workflow` through, and only when given", () => {
    assert.deepEqual(callAppOpts({ workflow: WFA }, "call_1"), { workflow: WFA, parentCall: "call_1" });
    assert.deepEqual(callAppOpts({ idempotencyKey: "k-123456", context: { "a.b": 1 }, workflow: WFB }, null), { idempotencyKey: "k-123456", context: { "a.b": 1 }, workflow: WFB, parentCall: null });
    assert.deepEqual(callAppOpts(undefined, null), { parentCall: null });
    assert.deepEqual(callAppOpts({}, "c"), { parentCall: "c" });
  });
  test("callerWorkflowOf: app callers only, from the verified claim", () => {
    assert.deepEqual(callerWorkflowOf("app", { wfl: WFA }), { workflow: WFA });
    assert.deepEqual(callerWorkflowOf("app", {}), {});
    assert.deepEqual(callerWorkflowOf("agent", { wfl: WFA }), {});
    assert.deepEqual(callerWorkflowOf("person", { wfl: WFA }), {});
    assert.deepEqual(callerWorkflowOf("app", { wfl: 7 }), {});
  });
  test("withCallerWorkflow: SDK-written, handler value removed, approved repeat keeps the hold's value", () => {
    assert.deepEqual(withCallerWorkflow(null, WFA), { callerWorkflow: WFA });
    assert.deepEqual(withCallerWorkflow({ a: 1, callerWorkflow: "x" }, WFA), { a: 1, callerWorkflow: WFA });
    assert.deepEqual(withCallerWorkflow({ a: 1, callerWorkflow: "x" }, undefined), { a: 1 });
    assert.equal(withCallerWorkflow(null, undefined), null);
    assert.deepEqual(withCallerWorkflow([1], WFA), [1], "an array meta cannot carry it");
    const held = { meta: { callerWorkflow: WFB } } as never;
    assert.deepEqual(withCallerWorkflow(null, WFA, held), { callerWorkflow: WFB });
    assert.deepEqual(withCallerWorkflow({ k: 1 }, undefined, held), { k: 1, callerWorkflow: WFB });
    assert.deepEqual(withCallerWorkflow(null, WFA, { meta: null } as never), { callerWorkflow: WFA });
  });
});
