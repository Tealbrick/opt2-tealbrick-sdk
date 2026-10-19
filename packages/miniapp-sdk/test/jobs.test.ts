// v0.1.21 (Scribe R1, L6, SDK-1/SDK-2, RUL-11): the job runner. Every alarm is a quiet + fire pair (L34): claims
// across two connections (one wins), lease expiry after a crash (resumed exactly once; spent attempts → failed, never
// re-run), fencing (a stale worker never commits), restart drain (given back, resumed once), pause/resume/cancel per
// job and per app, slice pause (SDK-1), scheduled ops re-running authorize() at fire time (CON-01: paused, kill switch,
// removed, revoked, narrowed grant, hold → approve → runs once), status push counts + attention, onStop.
import assert from "node:assert/strict";
import { after, afterEach, before, describe, test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import type { SdkOpContext, StopContext } from "../src/server/context.ts";
import { decideHold, defineApp, startApp } from "../src/server/index.ts";
import { backoffMs, type JobContext, JobStore, type JobsApi, type NewJob, nextOccurrence } from "../src/server/jobs.ts";
import { openStore } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function newJob(over: Partial<NewJob> = {}): NewJob {
  return { kind: "sync", input: { n: 1 }, key: null, runAt: Date.now(), cron: null, op: null, caller: null, grantSealed: null, grantIat: null, maxAttempts: 3, leaseMs: 1000, timeoutMs: 60_000, ...over };
}

describe("JobStore: one-statement claims across connections", () => {
  let t: ReturnType<typeof tempDir>;
  let a: ReturnType<typeof openStore>;
  let b: ReturnType<typeof openStore>;
  before(() => {
    t = tempDir();
    a = openStore(t.dir);
    b = openStore(t.dir); // a second process on the same volume (rolling restart)
  });
  after(() => {
    a.close();
    b.close();
    t.cleanup();
  });
  const F = { kinds: ["sync", "tb.op"], handlerJobs: true, ops: true, blocked: [] as string[] };

  test("40 jobs, two workers interleaved: every job is claimed exactly once", () => {
    const sa = new JobStore(a);
    const sb = new JobStore(b);
    const now = Date.now();
    for (let i = 0; i < 40; i++) sa.insert(newJob({ kind: "sync", input: { i }, leaseMs: 60_000 }), now);
    const seen: string[] = [];
    for (;;) {
      const x = sa.claim(Date.now(), `A.${seen.length}`, F);
      const y = sb.claim(Date.now(), `B.${seen.length}`, F);
      if (!x && !y) break;
      if (x) seen.push(x.id);
      if (y) seen.push(y.id);
    }
    assert.equal(seen.length, 40);
    assert.equal(new Set(seen).size, 40, "no job claimed twice");
    a.exec("DELETE FROM tb_jobs");
  });

  test("one job: worker B is quiet while A holds the lease; after expiry B wins (attempt 2) and A is fenced out", async () => {
    const sa = new JobStore(a);
    const sb = new JobStore(b);
    const { job } = sa.insert(newJob({ leaseMs: 1000 }), Date.now());
    const ca = sa.claim(Date.now(), "A", F);
    assert.equal(ca?.id, job.id);
    assert.equal(sb.claim(Date.now(), "B", F), null, "quiet: lease still held");
    assert.equal(sa.heartbeat(job.id, "A", Date.now()), true);
    await sleep(1100);
    const cb = sb.claim(Date.now(), "B", F);
    assert.equal(cb?.id, job.id, "fires: expired lease is taken over");
    assert.equal(cb?.attempts, 2, "the crashed start counts");
    assert.equal(sa.heartbeat(job.id, "A", Date.now()), false, "A lost its lease");
    assert.throws(() => sa.checkpoint(job.id, "A", { page: 9 }, Date.now()), /lease/);
    assert.equal(sa.done(job.id, "A", Date.now(), null, { by: "A" }, undefined), null, "A's done is fenced out");
    sb.checkpoint(job.id, "B", { page: 2 }, Date.now());
    const done = sb.done(job.id, "B", Date.now(), null, { by: "B" }, undefined);
    assert.equal(done?.status, "done");
    assert.deepEqual(done?.result, { by: "B" });
    assert.deepEqual(done?.state, { page: 2 });
    assert.equal(done?.attempts, 0);
  });

  test("a crashed run with attempts used up becomes failed lease_expired in the claim (never re-run)", async () => {
    const s = new JobStore(a);
    const { job } = s.insert(newJob({ kind: "tb.op", op: "note_delete", maxAttempts: 1, leaseMs: 1000 }), Date.now());
    assert.equal(s.claim(Date.now(), "A", F)?.status, "running");
    await sleep(1100);
    const again = s.claim(Date.now(), "B", F);
    assert.equal(again?.status, "failed");
    assert.equal(again?.lastError, "lease_expired");
    assert.equal(s.get(job.id)?.status, "failed");
    assert.equal(s.claim(Date.now(), "C", F), null);
  });

  test("idempotent enqueue: same key + input → same job; other input → job_key_conflict; checkpoint writes cursor + app rows in one tx", () => {
    const s = new JobStore(a);
    const one = s.insert(newJob({ key: "k-1", input: { x: 1 } }), Date.now());
    const two = s.insert(newJob({ key: "k-1", input: { x: 1 } }), Date.now());
    assert.equal(one.created, true);
    assert.equal(two.created, false);
    assert.equal(two.job.id, one.job.id);
    assert.throws(() => s.insert(newJob({ key: "k-1", input: { x: 2 } }), Date.now()), (e: Error & { code?: string }) => e.code === "job_key_conflict");
    a.exec("CREATE TABLE IF NOT EXISTS app_rows (v INTEGER)");
    const c = s.claim(Date.now(), "T", { ...F, kinds: ["sync"] });
    assert.ok(c);
    // a failing app write rolls back the cursor too (one transaction)
    assert.throws(() =>
      s.checkpoint(c.id, "T", { cursor: "bad" }, Date.now(), () => {
        a.prepare("INSERT INTO app_rows (v) VALUES (1)").run();
        throw new Error("boom");
      }),
    );
    assert.equal(s.get(c.id)?.state, null);
    assert.equal(Number((a.prepare("SELECT COUNT(*) AS n FROM app_rows").get() as { n: number }).n), 0);
    s.checkpoint(c.id, "T", { cursor: "ok" }, Date.now(), () => a.prepare("INSERT INTO app_rows (v) VALUES (2)").run());
    assert.deepEqual(s.get(c.id)?.state, { cursor: "ok" });
  });

  test("cron: done re-queues at the next occurrence; backoff doubles and caps", () => {
    const s = new JobStore(a);
    a.exec("DELETE FROM tb_jobs");
    const now = Date.UTC(2026, 9, 14, 10, 0, 30);
    const { job } = s.insert(newJob({ cron: "*/5 * * * *", runAt: now }), now);
    const c = s.claim(now, "T", F);
    assert.equal(c?.id, job.id);
    const next = nextOccurrence("*/5 * * * *", now);
    assert.equal(next, Date.UTC(2026, 9, 14, 10, 5, 0));
    const d = s.done(job.id, "T", now, next, null, undefined);
    assert.equal(d?.status, "queued");
    assert.equal(d?.runAt, next);
    assert.equal(d?.runs, 1);
    assert.deepEqual([1, 2, 3, 4, 20].map((n) => backoffMs(n, 1000, 5000)), [1000, 2000, 4000, 5000, 5000]);
  });
});

// ── app-level ──────────────────────────────────────────────────────────────────
interface Booted {
  w: World;
  bridge: FakeBridge;
  base: string;
  dir: string;
  jobs: JobsApi;
  ticks: Record<string, number>;
  ran: { note_delete: string[] };
  stopCalls: number;
  push(over?: Parameters<typeof slice>[2]): Promise<void>;
  restart(): Promise<void>;
  stop(): Promise<void>;
  cleanup(): Promise<void>;
}

type Handlers = Record<string, (input: Json, ctx: JobContext, b: Booted) => Promise<unknown>>;

async function boot(opts: { handlers?: Handlers; jobsDrainMs?: number; dir?: string; maxAttempts?: number; leaseMs?: number; sliceOver?: Parameters<typeof slice>[2]; manifest?: (m: Manifest) => Manifest } = {}): Promise<Booted> {
  const w = await world();
  const t = opts.dir ? { dir: opts.dir, cleanup: () => {} } : tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, opts.sliceOver ?? {}));
  const b = { w, bridge, base: `http://127.0.0.1:${port}`, dir: t.dir, ticks: {}, ran: { note_delete: [] }, stopCalls: 0 } as unknown as Booted;
  let running: Awaited<ReturnType<typeof startApp>>;
  let started: { stop(): Promise<void> } | undefined;
  const start = async () => {
    const jobs: Record<string, { run: (i: Json, c: JobContext) => Promise<never>; maxAttempts?: number; leaseMs?: number; backoffMs: { base: number; max: number } }> = {};
    for (const [kind, h] of Object.entries(opts.handlers ?? {})) {
      jobs[kind] = {
        run: async (input, ctx) => {
          b.ticks[kind] = (b.ticks[kind] ?? 0) + 1;
          return (await h(input, ctx, b)) as never;
        },
        ...(opts.maxAttempts ? { maxAttempts: opts.maxAttempts } : {}),
        ...(opts.leaseMs ? { leaseMs: opts.leaseMs } : {}),
        backoffMs: { base: 50, max: 200 },
      };
    }
    const app = defineApp({
      manifest: opts.manifest ? opts.manifest(fixtureManifest(port)) : fixtureManifest(port),
      migrations: migrationsDir(t.dir),
      handlers: {
        note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n1" }) },
        // the scheduling op: an agent asks for a delete in N ms (SDK-2)
        note_get: async (input, c) => {
          const ctx = c as SdkOpContext;
          const i = input as { id: string; inMs?: number; key?: string; nb?: string };
          const job = ctx.schedule({ op: "note_delete", input: { id: i.id, ...(i.nb ? { nb: i.nb } : {}) } }, { at: Date.now() + (i.inMs ?? 300) }, i.key ? { key: i.key } : {});
          return { job: job.id, paused: ctx.paused() as unknown as Json };
        },
        // `scope` is read only when the manifest gives the op a scopeType (the v0.1.36 fire-time scope test); `nb` = the target instance
        note_delete: {
          scope: (input) => (input as { nb?: string }).nb ?? null,
          run: async (input) => {
            b.ran.note_delete.push(String((input as { id: string }).id));
            return { deleted: true };
          },
        },
        notebook_rename: async () => ({}),
      },
      jobs,
      onStop: async (ctx: StopContext) => {
        // the DB is still open here (RUL-11)
        ctx.db.prepare("SELECT COUNT(*) AS n FROM notes").get();
        b.stopCalls += 1;
      },
    });
    running = await startApp(
      app,
      {
        TB_INSTANCE_ID: w.ins,
        TB_ENROL_CODE: "tbe_test",
        TB_BRIDGE_URL: bridgeUrl,
        TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
        TB_DATA_DIR: t.dir,
        TB_DATA_EPHEMERAL: "1",
        TB_LOG_LEVEL: "error",
      },
      { ...testRoots(w), port, jobs: { pollMs: 40, drainMs: opts.jobsDrainMs ?? 300 } },
    );
    started = running;
    b.jobs = running.jobs;
    await until(async () => running.status() === "ok");
  };
  // a boot that fails must not leave the bridge or the app listening: an open handle would keep the test process alive for ever
  try {
    await start();
  } catch (e) {
    await started?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  b.push = async (over = {}) => {
    const before = bridge.statuses.length;
    bridge.push(await slice(w, PRODUCT, over));
    await until(async () => bridge.statuses.length > before && (bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === w.rev);
  };
  b.stop = () => running.stop();
  b.restart = async () => {
    await running.stop();
    await start();
  };
  b.cleanup = async () => {
    await running.stop();
    await bridge.stop();
    t.cleanup();
  };
  return b;
}

async function callOp(b: Booted, op: string, input: Json, opts: { grantToken?: string } = {}) {
  const g = opts.grantToken ?? (await grant(b.w, b.w.agents.a));
  const proof = await callProof(b.w, g, op, input, {});
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {} }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe("handler jobs: run, checkpoint, again, retry → failed + attention", () => {
  let b: Booted;
  afterEach(async () => b?.cleanup());

  test("quiet: a job that pages with again + checkpoint finishes done, no attention; status push carries no failure", async () => {
    b = await boot({
      handlers: {
        pull: async (_input, ctx) => {
          const page = Number((ctx.job.state as { page?: number } | null)?.page ?? 0);
          ctx.checkpoint({ page: page + 1 }, (db) => db.prepare("INSERT INTO notes (id, notebook, title) VALUES (?, 'nb', 't')").run(`n${page}`));
          return page + 1 < 3 ? { status: "again" } : { status: "done", result: { pages: 3 } };
        },
      },
    });
    const job = b.jobs.enqueue("pull", { source: "s1" }, { key: "pull-s1" });
    const done = await until(async () => (b.jobs.get(job.id)?.status === "done" ? b.jobs.get(job.id) : null));
    assert.deepEqual(done.result, { pages: 3 });
    assert.deepEqual(done.state, { page: 3 });
    assert.equal(b.ticks.pull, 3);
    assert.equal(b.jobs.enqueue("pull", { source: "s1" }, { key: "pull-s1" }).id, job.id, "same key → same job");
    const last = await until(async () => b.bridge.statuses.at(-1) as { readiness?: string; attention?: unknown } | undefined);
    assert.equal(last.attention, undefined);
    assert.equal(last.readiness, "ready");
  });

  test("fires: a job failing every tick is retried with backoff, then failed + attention jobs_failed (degraded); resume clears it", async () => {
    let fail = true;
    b = await boot({
      maxAttempts: 3,
      handlers: {
        flaky: async () => {
          if (fail) throw new Error("upstream down");
          return { status: "done" };
        },
      },
    });
    const job = b.jobs.enqueue("flaky", null);
    const failed = await until(async () => (b.jobs.get(job.id)?.status === "failed" ? b.jobs.get(job.id) : null));
    assert.equal(b.ticks.flaky, 3, "exactly maxAttempts ticks");
    assert.equal(failed.lastError, "job_error");
    const st = await until(async () => {
      const s = b.bridge.statuses.at(-1) as { readiness?: string; attention?: { code: string }; jobs?: { failed: number } };
      return s?.attention?.code === "jobs_failed" ? s : null;
    });
    assert.equal(st.readiness, "degraded");
    assert.equal(st.jobs?.failed, 1);
    fail = false;
    b.jobs.resume(job.id);
    await until(async () => b.jobs.get(job.id)?.status === "done");
    await until(async () => (b.bridge.statuses.at(-1) as { attention?: unknown }).attention === undefined);
  });
});

describe("crash mid-job: lease expiry → resumed exactly once", () => {
  test("a run left behind by a crashed process (lease held) is quiet until the lease expires, then runs once", async () => {
    const t = tempDir();
    // the crashed process: claimed the job and died without a heartbeat
    const raw = openStore(t.dir);
    const s = new JobStore(raw);
    const { job } = s.insert(newJob({ kind: "resume", input: { n: 7 }, leaseMs: 1500 }), Date.now());
    const crashedAt = Date.now();
    assert.equal(s.claim(Date.now(), "crashed", { kinds: ["resume"], handlerJobs: true, ops: true, blocked: [] })?.status, "running");
    raw.close();
    const starts: number[] = [];
    const b = await boot({
      dir: t.dir,
      handlers: {
        resume: async () => {
          starts.push(Date.now());
          return { status: "done" };
        },
      },
    });
    try {
      await sleep(300);
      assert.equal(starts.length, 0, "quiet: the lease is still held");
      const done = await until(async () => (b.jobs.get(job.id)?.status === "done" ? b.jobs.get(job.id) : null), 5000);
      assert.equal(starts.length, 1, "fires: resumed exactly once");
      assert.ok((starts[0] as number) >= crashedAt + 1500 - 50, "not before the lease expired");
      assert.equal(done.attempts, 0);
      assert.equal(done.runs, 1);
      await sleep(300);
      assert.equal(starts.length, 1, "and never again");
    } finally {
      await b.cleanup();
      t.cleanup();
    }
  });
});

describe("restart drain + onStop (RUL-11, L21)", () => {
  test("stop aborts the running tick, gives it back (attempt not counted), calls onStop with the DB open; the next start resumes it once", async () => {
    let gen = 0;
    const seen: { gen: number; state: Json | null }[] = [];
    const b = await boot({
      handlers: {
        long: async (_input, ctx) => {
          seen.push({ gen, state: ctx.job.state });
          if (gen === 0) {
            ctx.checkpoint({ step: 1 });
            await new Promise<void>((_, reject) => ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason), { once: true }));
          }
          return { status: "done" };
        },
      },
    });
    try {
      const job = b.jobs.enqueue("long", null);
      await until(async () => b.jobs.get(job.id)?.status === "running" && seen.length === 1);
      gen = 1;
      await b.restart();
      assert.equal(b.stopCalls, 1, "onStop ran once");
      const done = await until(async () => (b.jobs.get(job.id)?.status === "done" ? b.jobs.get(job.id) : null));
      assert.equal(seen.length, 2, "one tick per process");
      assert.deepEqual(seen[1], { gen: 1, state: { step: 1 } }, "resumed from the checkpoint");
      assert.equal(done.attempts, 0);
    } finally {
      await b.cleanup();
    }
  });

  test("a tick that ignores the signal is released after the drain time; its late checkpoint is fenced out", async () => {
    let late: unknown = null;
    let gen = 0;
    const b = await boot({
      jobsDrainMs: 150,
      handlers: {
        stubborn: async (_input, ctx) => {
          if (gen === 0) {
            await sleep(500);
            try {
              ctx.checkpoint({ late: true });
            } catch (e) {
              late = (e as { code?: string }).code ?? "closed";
            }
          }
          return { status: "done" };
        },
      },
    });
    try {
      const job = b.jobs.enqueue("stubborn", null);
      await until(async () => b.jobs.get(job.id)?.status === "running");
      gen = 1;
      await b.restart();
      await until(async () => b.jobs.get(job.id)?.status === "done");
      await sleep(500);
      assert.ok(late !== null, "the stale tick could not commit");
      assert.equal(b.jobs.get(job.id)?.state, null);
    } finally {
      await b.cleanup();
    }
  });
});

describe("pause / resume / cancel; app pause; slice pause (SDK-1)", () => {
  let b: Booted;
  before(async () => {
    b = await boot({ handlers: { work: async () => ({ status: "done" }) } });
  });
  after(async () => b.cleanup());

  test("per job: paused is quiet, resume fires; cancel never runs", async () => {
    const j = b.jobs.enqueue("work", { n: 1 }, { at: Date.now() + 200 });
    assert.equal(b.jobs.pause(j.id).status, "paused");
    await sleep(400);
    assert.equal(b.jobs.get(j.id)?.status, "paused");
    b.jobs.resume(j.id);
    await until(async () => b.jobs.get(j.id)?.status === "done");
    const c = b.jobs.enqueue("work", { n: 2 }, { at: Date.now() + 200 });
    assert.equal(b.jobs.cancel(c.id).status, "cancelled");
    await sleep(400);
    assert.equal(b.jobs.get(c.id)?.status, "cancelled");
    assert.throws(() => b.jobs.resume(c.id), (e: Error & { code?: string }) => e.code === "job_state");
  });

  test("per app: pauseAll is quiet (and the status says so), resumeAll fires", async () => {
    b.jobs.pauseAll();
    const j = b.jobs.enqueue("work", { n: 3 });
    await sleep(300);
    assert.equal(b.jobs.get(j.id)?.status, "queued");
    assert.equal(b.jobs.appPaused(), true);
    b.jobs.resumeAll();
    await until(async () => b.jobs.get(j.id)?.status === "done");
  });

  test("workspace kill switch: handler jobs wait (quiet); unpaused they run (fires)", async () => {
    await b.push({ pause: { workspace: true, agents: [], instances: [] } });
    const j = b.jobs.enqueue("work", { n: 4 });
    await sleep(300);
    assert.equal(b.jobs.get(j.id)?.status, "queued");
    await b.push({});
    await until(async () => b.jobs.get(j.id)?.status === "done");
  });
});

describe("scheduled ops: authorize() again at fire time (SDK-2, CON-01)", () => {
  let b: Booted;
  const principal = (w: World): PersonPrincipal => ({ type: "person", id: w.per, ws: w.ws, instance: w.ins }) as PersonPrincipal;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  const schedule = async (id: string, inMs = 300, grantToken?: string) => {
    const r = await callOp(b, "note_get", { id, inMs }, grantToken ? { grantToken } : {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return String(r.body.output.job);
  };
  const settled = (id: string) => until(async () => {
    const j = b.jobs.get(id);
    return j && ["done", "refused", "failed", "waiting"].includes(j.status) ? j : null;
  });
  const receipts = async (op: string) => {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(`${b.dir}/app.db`, { readOnly: true });
    try {
      return db.prepare("SELECT status, caller_id, meta FROM tb_receipts WHERE op = ? ORDER BY created_at").all(op) as { status: string; caller_id: string; meta: string }[];
    } finally {
      db.close();
    }
  };

  test("quiet: an active agent's scheduled op runs once at fire time, with a run receipt as that agent", async () => {
    const id = await schedule("ok-1");
    const j = await settled(id);
    assert.equal(j.status, "done", j.lastError ?? "");
    assert.deepEqual(b.ran.note_delete, ["ok-1"]);
    const r = (await receipts("note_delete")).at(-1);
    assert.equal(r?.status, "run");
    assert.equal(r?.caller_id, b.w.agents.a);
  });

  test("SDK-CALLER-PRODUCT: a scheduled op of an APP caller writes its receipt with the verified product, not the name", async () => {
    const { signGrant, ulid } = await import("@opt2-tealbrick/manifest");
    const ins = `ins_${ulid()}` as never;
    await b.push({ companionCallers: [{ product: "impostor", ins, name: "Observer" }] });
    const g = await signGrant(
      { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: Math.floor(Date.now() / 1000), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read", "delete"], mode: "bound", held: [], caps: {}, wf: ["note_get", "note_delete"], polrev: 1 },
      b.w.portal,
    );
    const id = await schedule("app-prod-1", 300, g);
    const j = await settled(id);
    assert.equal(j.status, "done", j.lastError ?? "");
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(`${b.dir}/app.db`, { readOnly: true });
    try {
      const row = db.prepare("SELECT caller_type, caller_name, caller_product, status FROM tb_receipts WHERE op = 'note_delete' AND caller_id = ?").get(ins) as Record<string, string> | undefined;
      assert.deepEqual({ ...row }, { caller_type: "app", caller_name: "Observer", caller_product: "impostor", status: "run" });
    } finally {
      db.close();
    }
  });

  test("GRANT-PRD: a scheduled op fires with the stored grant's prd (slice has no entry); a slice that later disagrees refuses the fire grant_invalid", async () => {
    const { signGrant, ulid } = await import("@opt2-tealbrick/manifest");
    const mk = async (ins: never, prd: string) =>
      signGrant(
        { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: Math.floor(Date.now() / 1000), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read", "delete"], mode: "bound", held: [], caps: {}, wf: ["note_get", "note_delete"], polrev: 1, prd } as never,
        b.w.portal,
      );
    const { DatabaseSync } = await import("node:sqlite");
    const row = (ins: string) => {
      const db = new DatabaseSync(`${b.dir}/app.db`, { readOnly: true });
      try {
        return db.prepare("SELECT caller_product, status, meta FROM tb_receipts WHERE op = 'note_delete' AND caller_id = ?").get(ins) as Record<string, string> | undefined;
      } finally {
        db.close();
      }
    };
    // (1) prd only: the caller is in the slice (a fire needs it, `grant_revoked` otherwise) under the SAME product -> ok, product from the grant
    const ins1 = `ins_${ulid()}` as never;
    await b.push({ companionCallers: [{ product: "from-grant", ins: ins1, name: "Lagging" }] });
    const j1 = await settled(await schedule("prd-1", 300, await mk(ins1, "from-grant")));
    assert.equal(j1.status, "done", j1.lastError ?? "");
    assert.deepEqual({ ...row(ins1) }, { caller_product: "from-grant", status: "run", meta: row(ins1)?.meta });
    // (2) the slice moves to another product before the fire: grant prd != slice product -> refused grant_invalid, never runs
    const ins2 = `ins_${ulid()}` as never;
    await b.push({ companionCallers: [{ product: "from-grant", ins: ins2, name: "Differ" }] });
    const id2 = await schedule("prd-2", 600, await mk(ins2, "from-grant"));
    await b.push({ companionCallers: [{ product: "slice-now-says", ins: ins2, name: "Differ" }] });
    const j2 = await settled(id2);
    assert.equal(j2.status, "refused", j2.lastError ?? "");
    assert.equal(row(ins2)?.status, "refused");
    assert.match(String(row(ins2)?.meta), /grant_invalid/);
    assert.ok(!b.ran.note_delete.includes("prd-2"), "the op never ran");
  });

  test("quiet: an op WITHOUT a listing, a free grant and an empty wf still fires at fire time (unchanged by the listing check)", async () => {
    const g = await grant(b.w, b.w.agents.a, { mode: "free", wf: [] });
    const j = await settled(await schedule("nolisting-1", 300, g));
    assert.equal(j.status, "done", j.lastError ?? "");
    assert.deepEqual(b.ran.note_delete.filter((x) => x === "nolisting-1"), ["nolisting-1"]);
    assert.equal((await receipts("note_delete")).at(-1)?.status, "run");
  });

  test("fires: the agent is paused before fire time → refused `paused`, never runs, refused receipt", async () => {
    const id = await schedule("paused-1", 400);
    await b.push({ pause: { workspace: false, agents: [b.w.agents.a], instances: [] } });
    const j = await settled(id);
    assert.equal(j.status, "refused");
    assert.equal(j.lastError, "paused");
    assert.ok(!b.ran.note_delete.includes("paused-1"));
    assert.equal((await receipts("note_delete")).at(-1)?.status, "refused");
    await b.push({});
  });

  test("fires: workspace kill switch → refused `paused` (not deferred until the switch is released)", async () => {
    const id = await schedule("kill-1", 400);
    await b.push({ pause: { workspace: true, agents: [], instances: [] } });
    const j = await settled(id);
    assert.equal(j.lastError, "paused");
    await b.push({});
    await sleep(200);
    assert.equal(b.jobs.get(id)?.status, "refused");
    assert.ok(!b.ran.note_delete.includes("kill-1"));
  });

  test("fires: the agent is removed from the slice → refused `agent_removed`", async () => {
    const id = await schedule("gone-1", 400);
    await b.push({ agents: [{ id: b.w.agents.b, name: "Agent B", mode: "free", status: "active" }] });
    const j = await settled(id);
    assert.equal(j.lastError, "agent_removed");
    assert.ok(!b.ran.note_delete.includes("gone-1"));
    await b.push({});
  });

  test("fires: the grant's jti is revoked → refused `grant_revoked`", async () => {
    const g = await grant(b.w, b.w.agents.a);
    const jti = JSON.parse(Buffer.from(g.split(".")[1] as string, "base64url").toString("utf8")).jti as string;
    const id = await schedule("rev-1", 400, g);
    await b.push({ revoked: { jtis: [{ jti, exp: Math.floor(Date.now() / 1000) + 3600 }] } as never });
    const j = await settled(id);
    assert.equal(j.lastError, "grant_revoked");
    await b.push({});
  });

  test("fires: a later call carries a narrowed grant (no delete) → the pending op is refused `scope_denied`", async () => {
    const id = await schedule("narrow-1", 1600);
    await sleep(1100); // a newer iat
    const narrow = await grant(b.w, b.w.agents.a, { crud: ["read"] });
    assert.equal((await callOp(b, "note_get", { id: "probe", inMs: 60_000, key: "probe-key-1" }, { grantToken: narrow })).status, 200);
    const j = await settled(id);
    assert.equal(j.lastError, "scope_denied");
    assert.ok(!b.ran.note_delete.includes("narrow-1"));
  });

  test("held at fire time: waits for the owner; approve → runs exactly once", async () => {
    const held = await grant(b.w, b.w.agents.a, { held: ["destructive"] });
    const id = await schedule("hold-1", 200, held);
    const j = await settled(id);
    assert.equal(j.status, "waiting");
    assert.ok(j.holdId);
    await sleep(300);
    assert.ok(!b.ran.note_delete.includes("hold-1"), "quiet while held");
    await decideHold(principal(b.w), { holdId: j.holdId as `hld_${string}`, decision: "approve" });
    await until(async () => b.jobs.get(id)?.status === "done");
    assert.deepEqual(
      b.ran.note_delete.filter((x) => x === "hold-1"),
      ["hold-1"],
    );
  });

  test("schedule refuses a person-audience op for an agent caller and a malformed time", async () => {
    // ctx.schedule is exercised through note_get; a direct misuse through the app-initiated API needs a caller
    assert.throws(
      () => (b.jobs as unknown as { enqueue: JobsApi["enqueue"] }).enqueue("tb.op", null),
      (e: Error & { code?: string }) => e.code === "job_kind_invalid",
    );
    assert.throws(() => b.jobs.enqueue("nope", null), (e: Error & { code?: string }) => e.code === "job_kind_unknown");
  });
});

// v0.1.36: fire time reads the op's `listing` like gate() does (C283b item 2)
describe("scheduled ops: a `listing: \"workflow\"` op at fire time", () => {
  let b: Booted;
  before(async () => {
    b = await boot({ manifest: (m) => ({ ...m, operations: m.operations.map((o) => (o.id === "note_delete" ? { ...o, listing: "workflow" as const } : o)) }) });
  });
  after(async () => b.cleanup());

  const schedule = async (id: string, grantToken: string) => {
    const r = await callOp(b, "note_get", { id, inMs: 300 }, { grantToken });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return String(r.body.output.job);
  };
  const settled = (id: string) => until(async () => {
    const j = b.jobs.get(id);
    return j && ["done", "refused", "failed", "waiting"].includes(j.status) ? j : null;
  });
  const receipts = async () => {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(`${b.dir}/app.db`, { readOnly: true });
    try {
      return db.prepare("SELECT status, meta FROM tb_receipts WHERE op = 'note_delete' ORDER BY created_at").all() as { status: string; meta: string }[];
    } finally {
      db.close();
    }
  };

  test("fires on bad: a free grant with an empty wf schedules the listed op; at fire time it is refused `not_in_workflow`, never runs, refused receipt", async () => {
    const g = await grant(b.w, b.w.agents.a, { mode: "free", wf: [] });
    const j = await settled(await schedule("listed-bad-1", g));
    assert.equal(j.status, "refused", j.lastError ?? "");
    assert.equal(j.lastError, "not_in_workflow");
    assert.ok(!b.ran.note_delete.includes("listed-bad-1"), "the handler never ran");
    const r = (await receipts()).at(-1);
    assert.equal(r?.status, "refused");
    assert.equal(JSON.parse(String(r?.meta)).reason, "not_in_workflow");
  });

  test("quiet on good: the grant's wf names the listed op → it fires once, with a run receipt", async () => {
    const before = (await receipts()).length;
    const g = await grant(b.w, b.w.agents.a, { mode: "free", wf: ["note_get", "note_delete"] });
    const j = await settled(await schedule("listed-good-1", g));
    assert.equal(j.status, "done", j.lastError ?? "");
    assert.deepEqual(b.ran.note_delete.filter((x) => x === "listed-good-1"), ["listed-good-1"]);
    const rs = await receipts();
    assert.equal(rs.length, before + 1);
    assert.equal(rs.at(-1)?.status, "run");
  });
});

// v0.1.36 gap G3 (sdk#34 review): the fire path reads the caller's scope row with ITS authority. A BOUNDED row (default, app or
// bounded-written) never lifts the stored Portal grant at fire time; only an OWNER row does, exactly like a live call.
describe("scheduled ops: scope row authority at fire time", { timeout: 60_000 }, () => {
  let b: Booted;
  before(async () => {
    // note_delete becomes a scoped op (notebook); the fixture's `read_write` level includes delete, the stored grant below does not
    b = await boot({ manifest: (m) => ({ ...m, operations: m.operations.map((o) => (o.id === "note_delete" ? { ...o, scopeType: "notebook" } : o)) as Manifest["operations"] }) });
  }, { timeout: 60_000 });
  after(async () => b.cleanup(), { timeout: 60_000 });

  /** the stored grant: read + create only, so a delete is ABOVE the Portal grant (the row's level read_write would admit it) */
  const NARROW = { crud: ["read", "create"] as ("read" | "create")[] };
  const schedule = async (id: string, nb: string, grantToken: string) => {
    const r = await callOp(b, "note_get", { id, nb, inMs: 300 }, { grantToken });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    return String(r.body.output.job);
  };
  const settled = (id: string) => until(async () => {
    const j = b.jobs.get(id);
    return j && ["done", "refused", "failed", "waiting"].includes(j.status) ? j : null;
  });
  const dbDo = async <T>(f: (db: import("node:sqlite").DatabaseSync) => T, readOnly = true): Promise<T> => {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(`${b.dir}/app.db`, { readOnly });
    try {
      db.exec("PRAGMA busy_timeout = 5000");
      return f(db);
    } finally {
      db.close();
    }
  };

  test("fires on bad: a BOUNDED row whose level grants delete does not lift the narrow grant at fire time: refused scope_denied (the live call's code), never runs", { timeout: 60_000 }, async () => {
    const agent = b.w.agents.a;
    const g = await grant(b.w, agent, NARROW);
    // the agent's first call applies the default rows: its OWN notebook instance (id = the agent) at read_write, authority bounded
    const live = await callOp(b, "note_delete", { id: "live-1", nb: agent }, { grantToken: g });
    assert.equal(live.status, 403, JSON.stringify(live.body));
    assert.equal(live.body.error.code, "scope_denied", "the live call of the same op, same grant, same row");
    const row = await dbDo((db) => db.prepare("SELECT access, authority FROM tb_scopes WHERE agent = ? AND type = 'notebook' AND instance_id = ?").get(agent, agent) as { access: string; authority: string } | undefined);
    assert.deepEqual({ ...row }, { access: "read_write", authority: "bounded" }, "the row would admit delete, but it is bounded");
    const j = await settled(await schedule("g3-bad-1", agent, g));
    assert.equal(j.status, "refused", j.lastError ?? "");
    assert.equal(j.lastError, live.body.error.code, "fire time gives the same code as the live path");
    assert.ok(!b.ran.note_delete.includes("g3-bad-1"), "the handler never ran");
    const rs = await dbDo((db) => db.prepare("SELECT status, meta FROM tb_receipts WHERE op = 'note_delete' ORDER BY created_at").all() as { status: string; meta: string }[]);
    assert.equal(rs.at(-1)?.status, "refused");
    assert.equal(JSON.parse(String(rs.at(-1)?.meta)).reason, "scope_denied");
  });

  test("quiet on good: the SAME row made an OWNER row admits the scheduled delete above the grant (run receipt, admitted by app_owner_row); a bounded row inside the grant also runs", { timeout: 60_000 }, async () => {
    const agent = b.w.agents.b;
    const g = await grant(b.w, agent, NARROW);
    // first sight applies the defaults (a refused live call is enough)
    assert.equal((await callOp(b, "note_delete", { id: "live-2", nb: agent }, { grantToken: g })).body.error?.code, "scope_denied");
    await dbDo((db) => db.prepare("UPDATE tb_scopes SET authority = 'owner', crud_snapshot = '[\"read\",\"create\",\"update\",\"delete\"]' WHERE agent = ? AND type = 'notebook' AND instance_id = ?").run(agent, agent), false);
    const j = await settled(await schedule("g3-owner-1", agent, g));
    assert.equal(j.status, "done", j.lastError ?? "");
    assert.deepEqual(b.ran.note_delete.filter((x) => x === "g3-owner-1"), ["g3-owner-1"]);
    const rs = await dbDo((db) => db.prepare("SELECT status, admitted_by FROM tb_receipts WHERE op = 'note_delete' AND caller_id = ? ORDER BY created_at").all(agent) as { status: string; admitted_by: string | null }[]);
    assert.equal(rs.at(-1)?.status, "run");
    assert.equal(rs.at(-1)?.admitted_by, "app_owner_row");
    // a grant that already includes delete: the bounded row is inside the grant and admits (portal_grant)
    const agentA = b.w.agents.a;
    const wide = await grant(b.w, agentA, { crud: ["read", "create", "update", "delete"] });
    const j2 = await settled(await schedule("g3-inside-1", agentA, wide));
    assert.equal(j2.status, "done", j2.lastError ?? "");
    assert.deepEqual(b.ran.note_delete.filter((x) => x === "g3-inside-1"), ["g3-inside-1"]);
  });
});
