// v0.1.32 (SDK-COMPANION-CALLERS, spec 0.1.48): ctx.companionCallers on person ops only; fresh, frozen, [] when stale; provider normalisation.
import assert from "node:assert/strict";
import { after, before, describe, mock, test } from "node:test";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, OpContext, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp } from "../src/server/index.ts";
import { personCompanionCallers } from "../src/server/ops.ts";
import { TrustState } from "../src/server/trust.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

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
  m.operations.push(op("callers_person", "person"), op("callers_stash", "person"), op("callers_agent", "agent"), op("caller_who", "agent"), op("caller_who_person", "person"));
  return m;
}

/** What a careless app could do: keep the function in a global and call it later. */
const stash: { fn?: OpContext["companionCallers"] } = {};

function testApp(port: number, migrations: string) {
  return defineApp({
    manifest: manifestWithProbes(port),
    migrations,
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      callers_person: async (input, ctx: OpContext) => {
        if (!ctx.companionCallers) return { defined: false };
        const first = ctx.companionCallers();
        const out: Record<string, Json> = { defined: true, first: first as unknown as Json, frozen: Object.isFrozen(first) && first.every((c) => Object.isFrozen(c)) };
        if ((input as { mutate?: boolean }).mutate) {
          // strict mode (ES modules): writing to a frozen object throws
          const tries: string[] = [];
          try {
            (first as unknown as unknown[]).push({});
          } catch {
            tries.push("push");
          }
          try {
            (first[0] as { provider: string | null }).provider = "evil";
          } catch {
            tries.push("assign");
          }
          out.threw = tries;
          out.after = ctx.companionCallers() as unknown as Json;
        }
        if ((input as { wait?: boolean }).wait) {
          // two calls inside ONE op run, with a slice update in between
          await new Promise((r) => setTimeout(r, 400));
          out.second = ctx.companionCallers() as unknown as Json;
        }
        return out;
      },
      callers_stash: async (_input, ctx: OpContext) => {
        stash.fn = ctx.companionCallers;
        return { ok: true };
      },
      caller_who: async (_input, ctx: OpContext) => ({ type: ctx.caller.type, product: ctx.caller.product ?? null, hasListed: "listed" in ctx.caller, listed: (ctx.caller as { listed?: boolean }).listed ?? null }),
      caller_who_person: async (_input, ctx: OpContext) => ({ type: ctx.caller.type, hasListed: "listed" in ctx.caller }),
      callers_agent: async (_input, ctx: OpContext) => ({ defined: ctx.companionCallers !== undefined, caller: ctx.caller.type }),
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

const INS_RAILWAY = `ins_${ulid()}` as InstanceId;
const INS_OWN = `ins_${ulid()}` as InstanceId;
const INS_NONE = `ins_${ulid()}` as InstanceId;
const INS_BAD = `ins_${ulid()}` as InstanceId;
const INS_UPPER = `ins_${ulid()}` as InstanceId;

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { companionCallers: LIST }));
  const running = await startApp(
    testApp(port, migrationsDir(t.dir)),
    { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
    testRoots(w),
  );
  await until(async () => running.status() === "ok");
  return {
    w,
    bridge,
    running,
    base: `http://127.0.0.1:${port}`,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

const LIST = [
  { product: "evolution", ins: INS_RAILWAY, name: "Evolution", provider: "railway" },
  { product: "kanban", ins: INS_OWN, name: "Kanban", provider: "own_infra" },
  { product: "inbox", ins: INS_NONE, name: "Inbox" },
  { product: "rules", ins: INS_BAD, name: "Rules", provider: "Not A Key!" },
  { product: "connect", ins: INS_UPPER, name: "Connect", provider: null },
];
const EXPECTED = [
  { product: "evolution", ins: INS_RAILWAY, name: "Evolution", provider: "railway" },
  { product: "kanban", ins: INS_OWN, name: "Kanban", provider: "own_infra" },
  { product: "inbox", ins: INS_NONE, name: "Inbox", provider: null },
  { product: "rules", ins: INS_BAD, name: "Rules", provider: null },
  { product: "connect", ins: INS_UPPER, name: "Connect", provider: null },
];

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

async function appGrant(b: Booted, ins: InstanceId, wf: string[], prd?: string): Promise<string> {
  return signGrant(
    { iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf, polrev: 1, ...(prd !== undefined ? { prd } : {}) } as never,
    b.w.portal,
  );
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

describe("SDK-COMPANION-CALLERS", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  test("a person op sees the verified slice list with provider; absent, invalid or null provider reads as null", async () => {
    const r = await personOp(b, s, "callers_person");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.output.defined, true);
    assert.deepEqual(r.body.output.first, EXPECTED);
    assert.equal(r.body.output.frozen, true, "the array and every entry are frozen");
    for (const e of r.body.output.first) assert.deepEqual(Object.keys(e).sort(), ["ins", "name", "product", "provider"], "no other member (no grant material)");
  });

  test("frozen: mutating the array or an entry throws in strict mode and changes nothing", async () => {
    const r = await personOp(b, s, "callers_person", { mutate: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.threw, ["push", "assign"]);
    assert.deepEqual(r.body.output.after, EXPECTED, "the next call is unchanged");
  });

  test("a slice update between two calls of one op shows (no snapshot taken at op start)", async () => {
    const pending = personOp(b, s, "callers_person", { wait: true });
    await new Promise((r) => setTimeout(r, 100));
    const changed = [{ product: "evolution", ins: INS_RAILWAY, name: "Evolution", provider: "own_infra" }];
    b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: changed }));
    try {
      const r = await pending;
      assert.equal(r.status, 200, JSON.stringify(r.body));
      assert.deepEqual(r.body.output.first, EXPECTED, "the first call saw the old slice");
      assert.deepEqual(r.body.output.second, changed, "the second call of the same op saw the new slice");
      // and a later op sees the new list too
      assert.deepEqual((await personOp(b, s, "callers_person")).body.output.first, changed);
    } finally {
      b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: LIST }));
      await until(async () => ((await personOp(b, s, "callers_person")).body.output.first.length === EXPECTED.length ? true : null));
    }
  });

  test("a stashed function reads the current slice when called later; [] once the slice is older than 12 h", async () => {
    assert.equal((await personOp(b, s, "callers_stash")).status, 200);
    const fn = stash.fn;
    assert.ok(fn);
    assert.deepEqual(fn(), EXPECTED);
    const real = Date.now();
    const m = mock.method(Date, "now", () => real + 12 * 3600_000 + 60_000);
    try {
      const out = fn();
      assert.deepEqual(out, []);
      assert.ok(Object.isFrozen(out));
    } finally {
      m.mock.restore();
    }
    assert.deepEqual(fn(), EXPECTED, "fresh again when the clock is back");
  });

  test("undefined on an agent op and on an app (companion) call", async () => {
    const a = await agentOp(b, "callers_agent", {});
    assert.equal(a.status, 200, JSON.stringify(a.body));
    assert.deepEqual(a.body.output, { defined: false, caller: "agent" });
    const g = await signGrant(
      { iss: "tb:portal", sub: `tb:ins:${INS_RAILWAY}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: ["callers_agent"], polrev: 1 },
      b.w.portal,
    );
    const app = await agentOp(b, "callers_agent", {}, g);
    assert.equal(app.status, 200, JSON.stringify(app.body));
    assert.deepEqual(app.body.output, { defined: false, caller: "app" });
  });
});

describe("SDK-COMPANION-CALLERS: unit", () => {
  test("every call reads the trust state again; stale → frozen []", () => {
    let list = [{ product: "a", ins: "ins_1", name: "A", provider: null as string | null }];
    let stale = false;
    const rt = { trust: { stale: () => stale, companionCallers: () => list } } as never;
    const fn = personCompanionCallers(rt);
    const one = fn();
    assert.deepEqual(one, [{ product: "a", ins: "ins_1", name: "A", provider: null }]);
    assert.ok(Object.isFrozen(one) && Object.isFrozen(one[0]));
    list = [{ product: "a", ins: "ins_1", name: "A", provider: "railway" }];
    assert.equal(fn()[0]?.provider, "railway", "no snapshot");
    assert.equal(one[0]?.provider, null, "an earlier result is a copy");
    stale = true;
    const none = fn();
    assert.deepEqual(none, []);
    assert.ok(Object.isFrozen(none));
  });
});

// ── Caller.listed (Coordinator decision for Connect; SPEC-GAP spec 0.1.49) ─────────────────────────────────────────────
describe("Caller.listed on app callers", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  test("listed → true; the instance dropped from the slice → false; listed again → true", async () => {
    const g = await appGrant(b, INS_RAILWAY, ["caller_who"]);
    const one = await agentOp(b, "caller_who", {}, g);
    assert.equal(one.status, 200, JSON.stringify(one.body));
    assert.deepEqual(one.body.output, { type: "app", product: "evolution", hasListed: true, listed: true });
    b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: LIST.filter((e) => e.ins !== INS_RAILWAY) }));
    try {
      // the grant names the product (prd); the slice no longer lists the instance
      const gp = await appGrant(b, INS_RAILWAY, ["caller_who"], "evolution");
      const two = await until(async () => {
        const r = await agentOp(b, "caller_who", {}, gp);
        return r.body.output?.listed === false ? r : null;
      });
      assert.deepEqual(two.body.output, { type: "app", product: "evolution", hasListed: true, listed: false });
    } finally {
      b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: LIST }));
      await until(async () => ((await agentOp(b, "caller_who", {}, g)).body.output?.listed === true ? true : null));
    }
  });

  test("an app caller that is not listed at all has listed false", async () => {
    const g = await appGrant(b, `ins_${ulid()}` as InstanceId, ["caller_who"]);
    const r = await agentOp(b, "caller_who", {}, g);
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.output.listed, false);
    assert.equal(r.body.output.product, null);
  });

  test("person and agent callers have no `listed` key", async () => {
    const a = await agentOp(b, "caller_who", {});
    assert.deepEqual(a.body.output, { type: "agent", product: null, hasListed: false, listed: null });
    const p = await personOp(b, s, "caller_who_person");
    assert.deepEqual(p.body.output, { type: "person", hasListed: false });
  });

  test("unit: listed under another product → false; stale slice → false; no product → false", () => {
    const trust = (stale: boolean) => ({ stale: () => stale, companionCallers: () => [{ product: "evolution", ins: "ins_1", name: "E", provider: null }] });
    const listed = (stale: boolean, ins: string, product: string | undefined) => TrustState.prototype.companionListed.call(trust(stale) as never, ins, product, Date.now());
    assert.equal(listed(false, "ins_1", "evolution"), true);
    assert.equal(listed(false, "ins_1", "kanban"), false, "listed under another product");
    assert.equal(listed(false, "ins_2", "evolution"), false, "not listed");
    assert.equal(listed(true, "ins_1", "evolution"), false, "expired slice");
    assert.equal(listed(false, "ins_1", undefined), false, "no verified product");
  });
});
