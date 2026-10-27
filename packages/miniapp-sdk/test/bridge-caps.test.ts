// v0.1.37 (C292, spec 0.1.54): ctx.bridgeCaps() = a frozen copy of the CURRENT verified slice's `bridge.caps`; [] when the slice is
// absent, expired or has none; unknown entries pass through; read again on every call; ADVISORY (nothing authorizes with it).
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { after, before, describe, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, type SdkOpContext, startApp } from "../src/server/index.ts";
import { openStore } from "../src/server/store.ts";
import { TrustState } from "../src/server/trust.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const T = { timeout: 60_000 };

function manifestWithProbes(port: number): Manifest {
  const m = fixtureManifest(port);
  const op = (id: string, audience: "person" | "agent") => ({
    id,
    title: id,
    description: id,
    input: { type: "object" as const },
    output: { type: "object" as const },
    crud: ["read" as const],
    effect: "read" as const,
    idempotency: "none" as const,
    receipt: false,
    audience,
  });
  m.operations.push(op("caps_person", "person"), op("caps_stash", "person"), op("caps_agent", "agent"), op("caps_sched", "agent"));
  return m;
}

/** What a careless app could do: keep the function in a global and call it later. */
const stash: { fn?: () => readonly string[] } = {};
/** What the scheduled op and the handler job saw (written by their handlers) */
const seen: { sched: unknown[]; job: unknown[] } = { sched: [], job: [] };

function testApp(port: number, migrations: string) {
  const caps = (c: SdkOpContext): Record<string, Json> => ({ caps: c.bridgeCaps() as unknown as Json, frozen: Object.isFrozen(c.bridgeCaps()) });
  return defineApp({
    manifest: manifestWithProbes(port),
    migrations,
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      caps_person: async (input, c) => {
        const ctx = c as SdkOpContext;
        const out = caps(ctx);
        if ((input as { mutate?: boolean }).mutate) {
          const first = ctx.bridgeCaps() as unknown as string[];
          const tries: string[] = [];
          try {
            first.push("evil"); // strict mode (ES modules): writing to a frozen array throws
          } catch {
            tries.push("push");
          }
          out.threw = tries;
          out.after = ctx.bridgeCaps() as unknown as Json;
        }
        if ((input as { wait?: boolean }).wait) {
          // two calls inside ONE op run, with a slice update in between
          await new Promise((r) => setTimeout(r, 400));
          out.second = ctx.bridgeCaps() as unknown as Json;
        }
        return out;
      },
      caps_stash: async (_input, c) => {
        stash.fn = (c as SdkOpContext).bridgeCaps;
        return { ok: true };
      },
      caps_agent: async (input, c) => {
        const ctx = c as SdkOpContext;
        const i = input as { schedule?: boolean; job?: boolean };
        if (i.schedule) ctx.schedule({ op: "caps_sched", input: {} }, { at: Date.now() + 150 });
        if (i.job) ctx.jobs.enqueue("caps_job", {});
        return { ...caps(ctx), caller: ctx.caller.type };
      },
      caps_sched: async (_input, c) => {
        seen.sched.push((c as SdkOpContext).bridgeCaps());
        return {};
      },
    },
    jobs: {
      caps_job: async (_input, ctx) => {
        seen.job.push(ctx.bridgeCaps());
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  /** installs a new slice (revision bumped) and waits until the app has applied it */
  push(over?: Parameters<typeof slice>[2]): Promise<void>;
  cleanup(): Promise<void>;
}

const INS_APP = `ins_${ulid()}` as InstanceId;
const LISTED = [{ product: "evolution", ins: INS_APP, name: "Evolution", provider: "railway" }];

async function boot(sliceOver: Parameters<typeof slice>[2] = { bridgeCaps: ["owner_rows"], companionCallers: LISTED }): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  let running: RunningApp | undefined;
  // a boot that fails must not leave the bridge or the app listening: an open handle would keep the test process alive for ever
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
    async push(over = {}) {
      const before = bridge.statuses.length;
      bridge.push(await slice(w, PRODUCT, { companionCallers: LISTED, ...over }));
      await until(async () => bridge.statuses.length > before && (bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === w.rev);
    },
    async cleanup() {
      await app.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function signIn(b: Booted): Promise<{ cookie: string; csrf: string }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, "/configure") }),
  });
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  return { cookie, csrf: s.csrf };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json = {}) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function agentOp(b: Booted, op: string, input: Json, grantToken?: string) {
  const g = grantToken ?? (await grant(b.w, b.w.agents.a));
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: `k_${ulid()}` }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

const appGrant = (b: Booted, wf: string[]): Promise<string> =>
  signGrant({ iss: "tb:portal", sub: `tb:ins:${INS_APP}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf, polrev: 1, prd: "evolution" } as never, b.w.portal);

describe("ctx.bridgeCaps (C292, spec 0.1.54)", T, () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());
  const caps = async () => (await personOp(b, s, "caps_person")).body.output.caps;

  test("a slice with [owner_rows] → ctx.bridgeCaps() = [owner_rows], frozen", T, async () => {
    await b.push({ bridgeCaps: ["owner_rows"] });
    const r = await personOp(b, s, "caps_person", { mutate: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.caps, ["owner_rows"]);
    assert.equal(r.body.output.frozen, true);
    assert.deepEqual(r.body.output.threw, ["push"], "writing to the frozen array throws");
    assert.deepEqual(r.body.output.after, ["owner_rows"], "and changes nothing");
  });

  test("a slice without caps (or with an empty list) → []", T, async () => {
    await b.push({});
    assert.deepEqual(await caps(), []);
    await b.push({ bridgeCaps: [] });
    assert.deepEqual(await caps(), []);
  });

  test("unknown entries pass through (order kept); non-string members and a non-array are dropped", T, async () => {
    await b.push({ bridgeCaps: ["owner_rows", "future_cap"] });
    assert.deepEqual(await caps(), ["owner_rows", "future_cap"]);
    await b.push({ bridgeCaps: ["owner_rows", 7, null, { x: 1 }, "x2"] });
    assert.deepEqual(await caps(), ["owner_rows", "x2"]);
    await b.push({ bridgeCaps: "owner_rows" });
    assert.deepEqual(await caps(), [], "a string is not an array of strings");
    await b.push({ bridgeCaps: { 0: "owner_rows" } });
    assert.deepEqual(await caps(), []);
    await b.push({ bridgeCaps: null });
    assert.deepEqual(await caps(), []);
  });

  test("a slice update changes what a later call sees; a call in flight reads the slice again (no snapshot at op start)", T, async () => {
    await b.push({ bridgeCaps: ["owner_rows"] });
    const pending = personOp(b, s, "caps_person", { wait: true });
    await new Promise((r) => setTimeout(r, 100));
    await b.push({ bridgeCaps: [] });
    const r = await pending;
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.caps, ["owner_rows"], "the first call saw the old slice");
    assert.deepEqual(r.body.output.second, [], "the second call of the same op saw the new slice");
    assert.deepEqual(await caps(), []);
    await b.push({ bridgeCaps: ["owner_rows"] });
    assert.deepEqual(await caps(), ["owner_rows"], "and the next update shows too");
  });

  test("an expired slice (older than 12 h) → []; a stashed function reads the current slice when called later", T, async () => {
    await b.push({ bridgeCaps: ["owner_rows"] });
    assert.equal((await personOp(b, s, "caps_stash")).status, 200);
    const fn = stash.fn;
    assert.ok(fn);
    assert.deepEqual(fn(), ["owner_rows"]);
    const real = Date.now();
    const m = mock.method(Date, "now", () => real + 12 * 3600_000 + 60_000);
    try {
      const out = fn();
      assert.deepEqual(out, []);
      assert.ok(Object.isFrozen(out));
    } finally {
      m.mock.restore();
    }
    assert.deepEqual(fn(), ["owner_rows"], "fresh again when the clock is back");
  });

  test("an agent op, an app (companion) call, a scheduled op and a handler job all see the caps", T, async () => {
    await b.push({ bridgeCaps: ["owner_rows"] });
    seen.sched.length = 0;
    seen.job.length = 0;
    const a = await agentOp(b, "caps_agent", { schedule: true, job: true });
    assert.equal(a.status, 200, JSON.stringify(a.body));
    assert.deepEqual(a.body.output, { caps: ["owner_rows"], frozen: true, caller: "agent" });
    const app = await agentOp(b, "caps_agent", {}, await appGrant(b, ["caps_agent"]));
    assert.equal(app.status, 200, JSON.stringify(app.body));
    assert.deepEqual(app.body.output, { caps: ["owner_rows"], frozen: true, caller: "app" });
    await until(async () => seen.sched.length > 0 && seen.job.length > 0);
    assert.deepEqual(seen.sched, [["owner_rows"]], "the scheduled op (fire-time context)");
    assert.deepEqual(seen.job, [["owner_rows"]], "the handler job context");
  });

  test("no caps on the slice → [] for agent and app calls too", T, async () => {
    await b.push({});
    const a = await agentOp(b, "caps_agent", {});
    assert.deepEqual(a.body.output, { caps: [], frozen: true, caller: "agent" });
    const app = await agentOp(b, "caps_agent", {}, await appGrant(b, ["caps_agent"]));
    assert.deepEqual(app.body.output, { caps: [], frozen: true, caller: "app" });
  });
});

describe("TrustState.bridgeCaps: unit", T, () => {
  const fresh = (caps: unknown) => ({ slice: { bridge: { caps } }, stale: () => false }) as never;
  const run = (self: never) => TrustState.prototype.bridgeCaps.call(self, Date.now());

  test("no slice → frozen []; stale → frozen []; no caps member → []", T, () => {
    const none = run({ slice: null, stale: () => false } as never);
    assert.deepEqual(none, []);
    assert.ok(Object.isFrozen(none));
    assert.deepEqual(run({ slice: { bridge: { caps: ["owner_rows"] } }, stale: () => true } as never), []);
    assert.deepEqual(run(fresh(undefined)), []);
  });

  test("a frozen COPY: changing the slice array afterwards does not change an earlier result", T, () => {
    const raw = ["owner_rows"];
    const one = run(fresh(raw));
    raw.push("later");
    assert.deepEqual(one, ["owner_rows"]);
    assert.ok(Object.isFrozen(one));
    assert.notEqual(one, raw);
  });

  test("app-alone mode (no Core, no slice is ever minted by the SDK) → []", T, () => {
    const t = tempDir();
    const db = openStore(t.dir);
    try {
      const trust = new TrustState(db, `ins_${ulid()}` as InstanceId, { bootstrap: null, alone: { ws: `ws_${ulid()}` as never, ownKey: { kty: "OKP", crv: "Ed25519", x: "AAAA" } as never } });
      assert.equal(trust.stale(Date.now()), false, "app-alone never goes stale");
      assert.deepEqual(trust.bridgeCaps(Date.now()), []);
    } finally {
      db.close();
      t.cleanup();
    }
  });
});

describe("bridgeCaps is advisory: nothing in the SDK reads it for authorization", T, () => {
  const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
  const files = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".ts") ? [join(dir, e.name)] : []));

  test("the name appears only in the slice accessor (trust.ts), the context builders and their types", T, () => {
    // v0.1.38: server/events.ts gates SENDING (never authorization) by the events cap (SDK-API §20, C292)
    // v0.1.41 (C367 P4): server/link.ts gates SENDING `callApp({ context })` by the `app_call_context` cap (SDK-API §18.6; `bridge_cap_missing`), never authorization
    // v0.1.42 (spec 0.1.82, C373 P1): server/workflow-grants.ts gates SENDING workflow calls and the workflow-grant relays by `app_workflow_grants`
    // (SDK-API §22; `bridge_cap_missing`), never authorization
    const allowed = new Set(["server/trust.ts", "server/ops.ts", "server/app.ts", "server/context.ts", "server/runtime.ts", "server/events.ts", "server/link.ts", "server/workflow-grants.ts"]);
    const hits = files(src)
      .filter((f) => /bridgeCaps/.test(readFileSync(f, "utf8")))
      .map((f) => relative(src, f));
    for (const h of hits) assert.ok(allowed.has(h), `${h} references bridgeCaps: authorization code must not read it (C292)`);
    assert.ok(hits.includes("server/trust.ts") && hits.includes("server/ops.ts"), "the scan finds the accessor and the context builder");
  });
});
