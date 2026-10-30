// spec 0.1.89 (C380, SDK-API "v0.1.89", BRIDGE §8.8): ctx.ownerDrafts. The cap check comes before any network call; refusals keep Core's code and
// `details`, because the app decides on them (rail off, consent, expiry); `Retry-After` reaches a handler job's retry; no answer is invented.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, OWNER_DRAFTS_CAP, type OwnerDraftRequestBody, type OwnerDraftsApi, ownerDraftsRailOff, type SdkOpContext, startApp, TbError } from "../src/server/index.ts";
import { createOwnerDrafts } from "../src/server/owner-drafts.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const CAPS = { bridgeCaps: [OWNER_DRAFTS_CAP] };
const OK = { draftId: "drf_1", state: "submitted", reviewUrl: "https://portal.test/r/1" };
const GOT = { ...OK, digest: "sha256:bb", expiresAt: "2026-10-31T00:00:00Z", steps: [], receiptId: null };

function manifestWithProbe(port: number): Manifest {
  const m = fixtureManifest(port);
  m.operations.push({ id: "od_call", title: "od_call", description: "od_call", input: { type: "object" as const }, output: { type: "object" as const }, crud: ["read" as const], effect: "read" as const, idempotency: "none" as const, receipt: false, audience: "person" as const });
  return m;
}

type Call = { method: "request" | "get" | "withdraw"; arg: Json };
const invoke = (api: OwnerDraftsApi, c: Call): Promise<unknown> => (api[c.method] as (a: unknown) => Promise<unknown>)(c.arg);
const shape = async (p: Promise<unknown>): Promise<Record<string, Json>> => {
  try {
    return { ok: true, value: (await p) as Json };
  } catch (e) {
    if (!(e instanceof TbError)) throw e;
    return { ok: false, code: e.code, status: e.httpStatus, details: (e.details ?? null) as Json, railOff: ownerDraftsRailOff(e) };
  }
};
const REQUEST: OwnerDraftRequestBody = { key: "pln_1", title: "Governance: stop request", planDigest: "sha256:aa", expiresInSec: 3600, steps: [{ opId: "agents.pause", agt: "agt_01J0000000000000000000000A" as OwnerDraftRequestBody["steps"][number]["agt"] }] };

/** what the start, event and job contexts got */
const other: { start?: OwnerDraftsApi; event?: OwnerDraftsApi; job?: Record<string, Json> } = {};

function testApp(port: number, migrations: string) {
  return defineApp({
    manifest: manifestWithProbe(port),
    migrations,
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      od_call: async (input, c) => {
        const ctx = c as SdkOpContext;
        const i = input as Call & { job?: "get" | "throw"; jobId?: string };
        if (i.job) return { id: ctx.jobs.enqueue("od_job", { mode: i.job }).id };
        if (i.jobId) return ctx.jobs.get(i.jobId) as unknown as Json;
        return shape(invoke(ctx.ownerDrafts, i));
      },
    },
    jobs: {
      od_job: async (input, ctx) => {
        // a job that does not catch: the runner reads the refusal's details.retryAfterMs
        if ((input as { mode: string }).mode === "throw") {
          await ctx.ownerDrafts.withdraw("pln_throw");
          return;
        }
        other.job = await shape(ctx.ownerDrafts.get("pln_job"));
      },
    },
    onStart: async (ctx) => {
      other.start = ctx.ownerDrafts;
    },
    events: {
      agentsChanged: async (_agents, ctx) => {
        other.event = ctx.ownerDrafts;
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  cleanup(): Promise<void>;
}

async function boot(sliceOver: Parameters<typeof slice>[2]): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  let running: RunningApp | undefined;
  try {
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT, sliceOver));
    running = await startApp(
      testApp(port, migrationsDir(t.dir)),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      { ...testRoots(w), port, jobs: { pollMs: 40, drainMs: 300 } },
    );
    const app = running;
    await until(async () => app.status() === "ok");
  } catch (e) {
    await running?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  const app = running;
  return {
    w,
    bridge,
    running: app,
    base: `http://127.0.0.1:${port}`,
    async cleanup() {
      await app.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function personCall(b: Booted, input: Json): Promise<Record<string, any>> {
  const launch = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket: await ticket(b.w, "/configure") }) });
  const cookie = (launch.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/od_call`, { method: "POST", headers: { "content-type": "application/json", cookie, "tb-csrf": s.csrf, origin: b.base }, body: JSON.stringify({ input }) });
  const body = (await res.json()) as Record<string, any>;
  assert.equal(res.status, 200, JSON.stringify(body));
  return body.output;
}

describe("ctx.ownerDrafts, bridge with the cap", () => {
  let b: Booted;
  before(async () => {
    b = await boot(CAPS);
  });
  after(async () => b.cleanup());
  const answer = (a: ReturnType<FakeBridge["onOwnerDraft"]>) => {
    b.bridge.ownerDraftAsks.length = 0;
    b.bridge.onOwnerDraft = () => a;
  };

  test("request, get and withdraw reach the three paths with the exact body, a verified assertion and Core's answer", async () => {
    answer({ status: 200, body: OK });
    assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: true, value: OK });
    const got = { ...GOT, digest: "sha256:bb", expiresAt: "2026-10-31T00:00:00Z", steps: [{ n: 1, opId: "agents.pause", agt: REQUEST.steps[0]?.agt, status: "ok", output: { configRevision: 7 } }], receiptId: "rcp_1" };
    b.bridge.onOwnerDraft = () => ({ status: 200, body: got });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: true, value: got });
    b.bridge.onOwnerDraft = () => ({ status: 200, body: { ...OK, state: "rejected" } });
    assert.deepEqual(await personCall(b, { method: "withdraw", arg: "pln_1" }), { ok: true, value: { ...OK, state: "rejected" } });
    assert.deepEqual(b.bridge.ownerDraftAsks, [
      { path: "/tb/v1/owner-drafts", body: REQUEST, assertOk: true },
      { path: "/tb/v1/owner-drafts/get", body: { key: "pln_1" }, assertOk: true },
      { path: "/tb/v1/owner-drafts/withdraw", body: { key: "pln_1" }, assertOk: true },
    ]);
  });

  test("any 2xx from the relay is an answer", async () => {
    answer({ status: 201, body: OK });
    assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: true, value: OK });
  });

  test("Core's refusals keep code, status and details", async () => {
    const cases: [number, string, Record<string, Json> | undefined][] = [
      [409, "owner_drafts_full", undefined],
      [403, "forbidden", { reason: "topology_consent" }],
      [409, "draft_state", { reason: "expired" }],
      [400, "draft_op_not_draftable", { pointer: "/steps/0/opId" }],
      [400, "validation_failed", { pointer: "/title" }],
      [404, "not_found", { pointer: "/steps/0/agt" }],
      [404, "not_found", { pointer: "/key" }],
      [409, "agent_offboarded", { offboardedAt: "2026-10-30T00:00:00Z" }],
      [403, "paused", undefined],
    ];
    for (const [status, code, details] of cases) {
      answer({ status, body: { error: { code, message: code, requestId: "req_t", ...(details ? { details } : {}) } } });
      assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: false, code, status, details: details ?? null, railOff: false });
    }
  });

  test("the rail is off: a 404 with no pointer, and a standalone bridge", async () => {
    answer({ status: 404, body: { error: { code: "not_found", message: "no", requestId: "req_t" } } });
    assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: false, code: "not_found", status: 404, details: null, railOff: true });
    answer({ status: 409, body: { error: { code: "owner_drafts_unsupported", message: "standalone", requestId: "req_t" } } });
    assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: false, code: "owner_drafts_unsupported", status: 409, details: null, railOff: true });
  });

  test("Retry-After on 429 and 503 becomes details.retryAfterMs, next to Core's details; a bad value is dropped; a huge one is capped", async () => {
    answer({ status: 429, headers: { "retry-after": "7" }, body: { error: { code: "rate_limited", message: "later", requestId: "req_t" } } });
    assert.deepEqual(await personCall(b, { method: "request", arg: REQUEST as unknown as Json }), { ok: false, code: "rate_limited", status: 429, details: { retryAfterMs: 7000 }, railOff: false });
    answer({ status: 503, headers: { "retry-after": "2" }, body: { error: { code: "temporarily_unavailable", message: "later", requestId: "req_t", details: { reason: "draining" } } } });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: false, code: "temporarily_unavailable", status: 503, details: { reason: "draining", retryAfterMs: 2000 }, railOff: false });
    answer({ status: 429, headers: { "retry-after": "soon" }, body: { error: { code: "rate_limited", message: "later", requestId: "req_t" } } });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: false, code: "rate_limited", status: 429, details: null, railOff: false });
    answer({ status: 429, headers: { "retry-after": "999999" }, body: { error: { code: "rate_limited", message: "later", requestId: "req_t" } } });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: false, code: "rate_limited", status: 429, details: { retryAfterMs: 3_600_000 }, railOff: false });
  });

  test("no answer is invented: a 2xx with no readable draft and an error with no envelope are refusals", async () => {
    // `OK` itself: a get answer with no steps gives the plan no proof
    for (const body of ["", "not json", { state: "applied" }, { draftId: "drf_1" }, { draftId: 1, state: "applied" }, { draftId: "drf_1", state: "applied" }, OK, { ...GOT, steps: {} }, { ...GOT, reviewUrl: null }]) {
      answer({ status: 200, body });
      assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: false, code: "portal_unavailable", status: 503, details: null, railOff: false });
    }
    answer({ status: 200, body: GOT });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: true, value: GOT });
    answer({ status: 200, body: { draftId: "drf_1", state: "rejected" } });
    assert.equal((await personCall(b, { method: "withdraw", arg: "pln_1" })).code, "portal_unavailable");
    answer({ status: 502, body: "<html>" });
    assert.deepEqual(await personCall(b, { method: "get", arg: "pln_1" }), { ok: false, code: "app_error", status: 502, details: null, railOff: false });
    answer({ status: 200, body: { error: { code: "conflict", message: "no" } } });
    assert.equal((await personCall(b, { method: "get", arg: "pln_1" })).code, "portal_unavailable");
  });

  test("start, event and job contexts have it too", async () => {
    answer({ status: 200, body: OK });
    await until(async () => (other.start && other.event ? true : null));
    assert.equal((await other.start?.withdraw("pln_s"))?.state, "submitted");
    assert.equal((await other.event?.withdraw("pln_e"))?.state, "submitted");
    answer({ status: 200, body: GOT });
    other.job = undefined;
    await personCall(b, { job: "get" } as unknown as Json);
    const job = await until(async () => other.job);
    assert.deepEqual(job, { ok: true, value: GOT });
    assert.ok(b.bridge.ownerDraftAsks.some((x) => x.body.key === "pln_job" && x.assertOk));
  });

  test("a handler job that does not catch a 429 waits for Retry-After, not its short backoff", async () => {
    answer({ status: 429, headers: { "retry-after": "60" }, body: { error: { code: "rate_limited", message: "later", requestId: "req_t" } } });
    const t0 = Date.now();
    const { id } = await personCall(b, { job: "throw" } as unknown as Json);
    const job = await until(async () => {
      const j = await personCall(b, { jobId: id } as unknown as Json);
      return j.attempts >= 1 && j.status === "queued" ? j : null;
    });
    assert.equal(job.lastError, "rate_limited");
    assert.ok(job.runAt >= t0 + 55_000, `runAt is ${job.runAt - t0} ms away`);
  });
});

describe("ctx.ownerDrafts, bridge without the cap", () => {
  let b: Booted;
  before(async () => {
    b = await boot({ bridgeCaps: ["owner_rows"] });
  });
  after(async () => b.cleanup());

  test("all three methods: bridge_cap_missing 409, details.cap, and nothing goes to the network", async () => {
    b.bridge.ownerDraftAsks.length = 0;
    const calls: Call[] = [
      { method: "request", arg: REQUEST as unknown as Json },
      { method: "get", arg: "pln_1" },
      { method: "withdraw", arg: "pln_1" },
    ];
    for (const c of calls) assert.deepEqual(await personCall(b, c as unknown as Json), { ok: false, code: "bridge_cap_missing", status: 409, details: { cap: OWNER_DRAFTS_CAP }, railOff: true });
    assert.equal(b.bridge.ownerDraftAsks.length, 0);
  });

  test("the cap is read at each call: a new slice with the cap opens the path; one without closes it again", async () => {
    b.bridge.onOwnerDraft = () => ({ status: 200, body: OK });
    const push = async (over: Parameters<typeof slice>[2]) => {
      const before = b.bridge.statuses.length;
      b.bridge.push(await slice(b.w, PRODUCT, over));
      await until(async () => b.bridge.statuses.length > before && (b.bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === b.w.rev);
    };
    await push(CAPS);
    assert.equal((await personCall(b, { method: "withdraw", arg: "pln_1" })).ok, true);
    await push({ bridgeCaps: ["owner_rows"] });
    assert.equal((await personCall(b, { method: "get", arg: "pln_1" })).code, "bridge_cap_missing");
  });
});

describe("createOwnerDrafts, the parts a live bridge cannot reach", () => {
  const client = (): { request(): Promise<never> } => ({
    request: () => {
      throw new Error("must not be called");
    },
  });
  test("cap first: a standalone app with no bridge gets bridge_cap_missing, not no_bridge", async () => {
    const api = createOwnerDrafts({ bridgeCaps: () => [], sliceStale: () => false, bridge: () => null });
    const r = await shape(api.get("pln_1"));
    assert.equal(r.code, "bridge_cap_missing");
    assert.equal(r.railOff, true);
  });
  test("a stale or missing slice shows no caps: still bridge_cap_missing, but the rail is not called off", async () => {
    const api = createOwnerDrafts({ bridgeCaps: () => [], sliceStale: () => true, bridge: () => client() as never });
    assert.deepEqual(await shape(api.get("pln_1")), { ok: false, code: "bridge_cap_missing", status: 409, details: { cap: OWNER_DRAFTS_CAP, reason: "slice_stale" }, railOff: false });
  });
  test("the cap with no claimed bridge yet: no_bridge 503, and the rail is not called off", async () => {
    const api = createOwnerDrafts({ bridgeCaps: () => [OWNER_DRAFTS_CAP], sliceStale: () => false, bridge: () => null });
    assert.deepEqual(await shape(api.withdraw("pln_1")), { ok: false, code: "no_bridge", status: 503, details: null, railOff: false });
  });
  test("a refused cap never touches the client", async () => {
    const api = createOwnerDrafts({ bridgeCaps: () => ["owner_rows"], sliceStale: () => false, bridge: () => client() as never });
    assert.equal((await shape(api.request(REQUEST))).code, "bridge_cap_missing");
  });
  test("ownerDraftsRailOff stays false for what is not about the rail", () => {
    assert.equal(ownerDraftsRailOff(new Error("x")), false);
    assert.equal(ownerDraftsRailOff(null), false);
    assert.equal(ownerDraftsRailOff(new TbError("bridge_cap_missing", "other", 409, { cap: "acting_agents" })), false);
    assert.equal(ownerDraftsRailOff(new TbError("not_found", "m", 403)), false);
    assert.equal(ownerDraftsRailOff(new TbError("bridge_unavailable", "m", 503)), false);
  });
});
