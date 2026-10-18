// v0.1.31 (SDK-INSTANCE-GRANT, spec 0.1.47): ctx.scopeGrants on person ops, ctx.scopeSelfRevoke on agent calls, source/grantedByOp on rows.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest, Scope } from "@opt2-tealbrick/spec/manifest";
import type { Json, OpContext, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import { defineApp, startApp, TbError } from "../src/server/index.ts";
import { grantRefusal, opLife } from "../src/server/ops.ts";
import { createScopeStore, scopeGrantOps } from "../src/server/scopes.ts";
import { openStore, SDK_MIGRATIONS } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

function manifestWithManage(port: number): Manifest {
  const m = fixtureManifest(port);
  const sc = m.scopes?.[0];
  if (!sc) throw new Error("fixture has no scope");
  sc.access = [
    { id: "read", label: "Read", crud: ["read"] },
    { id: "read_write", label: "Read and write", crud: ["read", "create", "update", "delete"] },
    { id: "manage", label: "Manage", crud: ["read", "create", "update", "delete"] },
  ];
  // agents get read_write on their own instance and read on shared ones; `manage` is above the ceiling
  sc.defaultGrants = [
    { kind: "own", access: "read_write" },
    { kind: "shared", access: "read" },
  ];
  const person = (id: string, title: string) => ({
    id,
    title,
    description: title,
    input: { type: "object" as const },
    output: { type: "object" as const },
    crud: ["update" as const],
    effect: "write" as const,
    idempotency: "supported" as const,
    receipt: false,
    audience: "person" as const,
  });
  m.operations.push(person("draft_start", "Start draft"), person("draft_unshare", "Unshare draft"), person("scope_probe_person", "Probe grants"), person("closure_stash", "Stash closures"));
  const agent = (id: string, title: string, effect: "read" | "write", crud: ("read" | "update")[]) => ({
    id,
    title,
    description: title,
    input: { type: "object" as const },
    output: { type: "object" as const },
    crud,
    effect,
    idempotency: "none" as const,
    receipt: false,
    audience: "agent" as const,
  });
  m.operations.push(agent("scope_probe", "Probe agent ctx", "read", ["read"]), { ...agent("scope_leave", "Leave draft", "write", ["update"]), idempotency: "supported" as const });
  return m;
}

/** What a careless app could do: keep the grant closures (and the op signal) in a global and call them later. */
const stash: { grants?: OpContext["scopeGrants"]; self?: OpContext["scopeSelfRevoke"]; signal?: AbortSignal; release?: () => void } = {};

function testApp(port: number, migrations: string) {
  return defineApp({
    manifest: manifestWithManage(port),
    migrations,
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      draft_start: async (input, ctx: OpContext) => {
        const i = input as { agent: string; id: string; access: string; create?: boolean };
        if (i.create !== false) await ctx.scopes.instances.create("notebook", i.id, `Draft ${i.id}`);
        if (!ctx.scopeGrants) return { noGrants: true, row: null };
        return { noGrants: false, row: (await ctx.scopeGrants.grant(i.agent as never, "notebook", i.id, i.access)) as unknown as Json };
      },
      draft_unshare: async (input, ctx: OpContext) => {
        const i = input as { agent: string; id: string };
        await ctx.scopeGrants?.revoke(i.agent as never, "notebook", i.id);
        return { ok: true };
      },
      closure_stash: async (input, ctx: OpContext) => {
        stash.grants = ctx.scopeGrants;
        stash.signal = ctx.signal;
        if ((input as { hang?: boolean }).hang) await new Promise<void>((res) => (stash.release = res));
        return { ok: true };
      },
      scope_probe_person: async (_input, ctx: OpContext) => ({ grants: ctx.scopeGrants !== undefined, self: typeof ctx.scopeSelfRevoke }),
      scope_probe: async (_input, ctx: OpContext) => ({ grants: ctx.scopeGrants !== undefined, self: typeof ctx.scopeSelfRevoke, caller: ctx.caller.type }),
      scope_leave: async (input, ctx: OpContext) => {
        stash.self = ctx.scopeSelfRevoke;
        await ctx.scopeSelfRevoke?.("notebook", (input as { id: string }).id);
        return { ok: ctx.scopeSelfRevoke !== undefined };
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

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const running = await startApp(
    testApp(port, migrationsDir(t.dir)),
    {
      TB_INSTANCE_ID: w.ins,
      TB_ENROL_CODE: "tbe_test",
      TB_BRIDGE_URL: bridgeUrl,
      TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
      TB_DATA_DIR: t.dir,
      TB_DATA_EPHEMERAL: "1",
      TB_LOG_LEVEL: "error",
    },
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

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function agentOp(b: Booted, op: string, input: Json, opts: { agent?: string; grantToken?: string } = {}) {
  const g = opts.grantToken ?? (await grant(b.w, (opts.agent ?? b.w.agents.a) as `agt_${string}`));
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: `k_${ulid()}` }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe("SDK-INSTANCE-GRANT", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
      b = await boot();
      s = await signIn(b);
  });
  after(async () => b.cleanup());

  const rows = async (agent: string) => ((await personOp(b, s, "tb.agents_list", {})).body.output.agents as { id: string; access: Record<string, unknown>[] }[]).find((a) => a.id === agent)?.access ?? [];
  const det = (e: { detail: Json } | undefined): Record<string, Json> => (e?.detail ?? {}) as Record<string, Json>;
  const audit = async () => (await b.running.audit.list({ action: "scope.set" })).items;

  test("a person op grants within bounds: the row has source app + grantedByOp, shows in tb.agents_list, is audited, and the agent can use it", async () => {
    const r = await personOp(b, s, "draft_start", { agent: b.w.agents.b, id: "d1", access: "read_write" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    const row = r.body.output.row;
    assert.deepEqual(row, { agent: b.w.agents.b, type: "notebook", instanceId: "d1", access: "read_write", source: "app", grantedByOp: "draft_start" });
    const listed = (await rows(b.w.agents.b)).find((x) => x.instanceId === "d1");
    assert.deepEqual(listed, row);
    const a = (await audit()).find((x) => det(x).instance === "d1");
    assert.equal(a?.actor, b.w.per);
    assert.equal(a?.target, b.w.agents.b);
    assert.equal(det(a).op, "draft_start");
    assert.equal(det(a).source, "app");
    assert.equal(det(a).access, "read_write");
    assert.ok("callId" in det(a) && "requestId" in det(a));
    assert.equal((await b.running.scopes.access(b.w.agents.b, "notebook", "d1"))?.access, "read_write");
  });

  test("tb.scopes_set writes source owner and clears grantedByOp; defaults report source default", async () => {
    await personOp(b, s, "tb.scopes_set", { agent: b.w.agents.b, type: "notebook", id: "d1", access: "read" });
    const owner = (await rows(b.w.agents.b)).find((x) => x.instanceId === "d1");
    assert.deepEqual(owner, { agent: b.w.agents.b, type: "notebook", instanceId: "d1", access: "read", source: "owner" });
    // agent A calls once: first sight applies the manifest defaults
    assert.equal((await agentOp(b, "scope_probe", {})).status, 200);
    const own = (await rows(b.w.agents.a)).find((x) => x.instanceId === b.w.agents.a);
    assert.equal(own?.source, "default");
    assert.equal("grantedByOp" in (own ?? {}), false);
  });

  test("every bound refuses scope_grant_invalid 400 with a reason", async () => {
    const bad = async (over: Record<string, unknown>, reason: string, create = false) => {
      const r = await personOp(b, s, "draft_start", { agent: b.w.agents.a, id: "d2", access: "read_write", create, ...over });
      assert.equal(r.status, 400, JSON.stringify(r.body));
      assert.equal(r.body.error.code, "scope_grant_invalid");
      assert.equal(r.body.error.details.reason, reason);
    };
    await bad({ access: "manage" }, "above_ceiling", true); // the instance exists now (created here), manage is above the ceiling
    await bad({ access: "owner" }, "level_unknown");
    await bad({ id: "nope" }, "instance_unknown");
    await bad({ agent: `agt_${ulid()}` }, "agent_not_in_slice");
    await bad({ agent: "not-an-agent" }, "agent_invalid");
    assert.equal(await b.running.scopes.access(b.w.agents.a, "notebook", "d2"), null, "nothing was written");
  });

  test("revoke removes the row whatever its source and audits it; a missing row is a no-op", async () => {
    await personOp(b, s, "draft_start", { agent: b.w.agents.b, id: "d3", access: "read" });
    const before = (await audit()).length;
    const r = await personOp(b, s, "draft_unshare", { agent: b.w.agents.b, id: "d3" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(await b.running.scopes.access(b.w.agents.b, "notebook", "d3"), null);
    assert.equal((await audit()).length, before + 1);
    // owner row also removed
    await personOp(b, s, "tb.scopes_set", { agent: b.w.agents.b, type: "notebook", id: "d1", access: "read" });
    await personOp(b, s, "draft_unshare", { agent: b.w.agents.b, id: "d1" });
    assert.equal(await b.running.scopes.access(b.w.agents.b, "notebook", "d1"), null);
    const n = (await audit()).length;
    await personOp(b, s, "draft_unshare", { agent: b.w.agents.b, id: "d1" });
    assert.equal((await audit()).length, n, "no row, no audit");
  });

  test("ctx.scopeGrants is set on person ops only; ctx.scopeSelfRevoke on agent calls only", async () => {
    const p = await personOp(b, s, "scope_probe_person", {});
    assert.deepEqual(p.body.output, { grants: true, self: "undefined" });
    const a = await agentOp(b, "scope_probe", {});
    assert.deepEqual(a.body.output, { grants: false, self: "function", caller: "agent" });
  });

  test("an app caller has neither ctx.scopeGrants nor ctx.scopeSelfRevoke", async () => {
    const callerIns = `ins_${ulid()}` as InstanceId;
    const g = await signGrant(
      { iss: "tb:portal", sub: `tb:ins:${callerIns}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: ["scope_probe"], polrev: 1 },
      b.w.portal,
    );
    const r = await agentOp(b, "scope_probe", {}, { grantToken: g });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output, { grants: false, self: "undefined", caller: "app" });
  });

  test("a forged call path cannot reach grant: an agent cannot call a person op, a person route cannot run an agent op", async () => {
    const viaAgent = await agentOp(b, "draft_start", { agent: b.w.agents.a, id: "own", access: "read_write" });
    assert.equal(viaAgent.status, 403, JSON.stringify(viaAgent.body));
    assert.equal(viaAgent.body.error.code, "audience_not_agent");
    const viaPerson = await personOp(b, s, "scope_leave", { id: "x" });
    assert.equal(viaPerson.status, 403);
    assert.equal(viaPerson.body.error.code, "audience_not_person");
    // no session / no csrf: the person route never reaches the handler
    const anon = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/draft_start`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ input: { agent: b.w.agents.a, id: "own", access: "read_write" } }) });
    assert.equal(anon.status, 401);
    const noCsrf = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/draft_start`, { method: "POST", headers: { "content-type": "application/json", cookie: s.cookie, origin: b.base }, body: JSON.stringify({ input: {} }) });
    assert.ok(noCsrf.status === 403 || noCsrf.status === 401, `status ${noCsrf.status}`);
  });

  test("ctx.scopeSelfRevoke removes only the calling agent's own row and is audited", async () => {
    await personOp(b, s, "draft_start", { agent: b.w.agents.a, id: "d4", access: "read_write" });
    await personOp(b, s, "draft_start", { agent: b.w.agents.b, id: "d4", create: false, access: "read" });
    const before = (await audit()).length;
    const r = await agentOp(b, "scope_leave", { id: "d4" }, { agent: b.w.agents.a });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.output.ok, true);
    assert.equal(await b.running.scopes.access(b.w.agents.a, "notebook", "d4"), null);
    assert.equal((await b.running.scopes.access(b.w.agents.b, "notebook", "d4"))?.access, "read", "another agent's row is untouched");
    const last = (await audit())[0];
    assert.equal(last?.actor, b.w.agents.a, "S4b: the agent is the actor of its own narrowing");
    assert.equal(det(last).source, "agent_self");
    assert.equal((await audit()).length, before + 1);
  });

  // ── S3: the closures live only while the op runs ─────────────────────────────────────────────────────────────────
  const held = (): typeof stash => stash;
  const expired = (e: unknown) => e instanceof TbError && e.code === "scope_grant_expired" && e.httpStatus === 409;
  test("S3: a person-op closure stored in a global throws scope_grant_expired after the op ended (grant and revoke)", async () => {
    await personOp(b, s, "tb.scopes_set", { agent: b.w.agents.a, type: "notebook", id: "d5", access: null }); // no-op, session warm
    stash.grants = undefined;
    const r = await personOp(b, s, "closure_stash", {});
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.ok(stash.grants, "the closure existed during the op");
    await b.running.scopes.instances.create("notebook", "d5", "D5");
    const before = (await audit()).length;
    await assert.rejects(held().grants?.grant(b.w.agents.a as never, "notebook", "d5", "read_write") as Promise<unknown>, expired);
    await assert.rejects(held().grants?.revoke(b.w.agents.a as never, "notebook", "d5") as Promise<void>, expired);
    // the agent's later call cannot use it either
    await agentOp(b, "scope_probe", {}, { agent: b.w.agents.a });
    await assert.rejects(held().grants?.grant(b.w.agents.a as never, "notebook", "d5", "read_write") as Promise<unknown>, expired);
    assert.equal(await b.running.scopes.access(b.w.agents.a, "notebook", "d5"), null, "nothing was written");
    assert.equal((await audit()).length, before, "nothing was audited");
  });

  test("S3: after a client disconnect the closure of the still-running handler throws scope_grant_expired", async () => {
    stash.grants = undefined;
    stash.release = undefined;
    const ac = new AbortController();
    const call = fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/closure_stash`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
      body: JSON.stringify({ input: { hang: true } }),
      signal: ac.signal,
    }).catch(() => null);
    await until(async () => (stash.release ? true : null));
    // while the op runs the closure works
    await b.running.scopes.instances.create("notebook", "d6", "D6");
    const live = await held().grants?.grant(b.w.agents.b as never, "notebook", "d6", "read");
    assert.equal(live?.access, "read");
    ac.abort();
    await call;
    await until(async () => (held().signal?.aborted ? true : null));
    await assert.rejects(held().grants?.grant(b.w.agents.b as never, "notebook", "d6", "read_write") as Promise<unknown>, expired);
    await assert.rejects(held().grants?.revoke(b.w.agents.b as never, "notebook", "d6") as Promise<void>, expired);
    assert.equal((await b.running.scopes.access(b.w.agents.b, "notebook", "d6"))?.access, "read", "the row from the live phase is untouched");
    held().release?.();
  });

  test("S3: the agent closure scopeSelfRevoke throws scope_grant_expired after the agent call ended", async () => {
    await personOp(b, s, "draft_start", { agent: b.w.agents.a, id: "d7", access: "read_write" });
    stash.self = undefined;
    const r = await agentOp(b, "scope_leave", { id: "d7" }, { agent: b.w.agents.a });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    await personOp(b, s, "draft_start", { agent: b.w.agents.a, id: "d7", create: false, access: "read_write" });
    await assert.rejects(held().self?.("notebook", "d7") as Promise<void>, expired);
    assert.equal((await b.running.scopes.access(b.w.agents.a, "notebook", "d7"))?.access, "read_write", "the late call removed nothing");
  });

  test("S3: opLife closes on the handler settling, on the timeout abort and on the disconnect abort", async () => {
    const t = new AbortController();
    const life = opLife(t.signal);
    life.assertOpen();
    t.abort(new TbError("app_timeout", "operation timed out", 504));
    assert.throws(() => life.assertOpen(), expired);
    const d = new AbortController();
    const l2 = opLife(d.signal);
    d.abort(new TbError("client_closed", "client disconnected", 499));
    assert.throws(() => l2.assertOpen(), expired);
    let done!: () => void;
    const l3 = opLife(new AbortController().signal);
    l3.bind(new Promise<void>((res) => (done = res)));
    l3.assertOpen();
    done();
    await new Promise((r) => setImmediate(r));
    assert.throws(() => l3.assertOpen(), expired);
    const l4 = opLife(new AbortController().signal);
    l4.bind(Promise.reject(new Error("handler failed")));
    await new Promise((r) => setImmediate(r));
    assert.throws(() => l4.assertOpen(), expired);
  });

  // ── S4a: no grant to an agent that is paused, not active or gone; the CURRENT slice decides ──────────────────────
  const tryGrant = (agent: string, id: string) => personOp(b, s, "draft_start", { agent, id, access: "read" });
  const setSlice = async (over: Parameters<typeof slice>[2], agent: string, want: (r: { status: number; body: Record<string, any> }) => boolean) => {
    b.bridge.push(await slice(b.w, PRODUCT, over));
    await until(async () => (want(await tryGrant(agent, "pz")) ? true : null));
  };
  const refusedWith = (reason: string) => (r: { status: number; body: Record<string, any> }) => r.status === 400 && r.body.error?.code === "scope_grant_invalid" && r.body.error?.details?.reason === reason;
  const granted = (r: { status: number }) => r.status === 200;
  const both = (statusB: "active" | "paused") => [
    { id: b.w.agents.a, name: "Agent A", mode: "free" as const, status: "active" as const },
    { id: b.w.agents.b, name: "Agent B", mode: "free" as const, status: statusB },
  ];
  test("S4a: an agent that is paused (status, pause list, instance pause, workspace pause) or removed gets no grant; a free agent still does", async () => {
    try {
      await setSlice({ agents: both("paused") }, b.w.agents.b, refusedWith("agent_paused"));
      // the polling above may have granted before the new slice arrived: clear, then prove a refused try writes nothing
      await personOp(b, s, "tb.scopes_set", { agent: b.w.agents.b, type: "notebook", id: "pz", access: null });
      assert.ok(refusedWith("agent_paused")(await tryGrant(b.w.agents.b, "pz")));
      assert.equal(await b.running.scopes.access(b.w.agents.b, "notebook", "pz"), null);
      await setSlice({ pause: { workspace: false, agents: [b.w.agents.b], instances: [] } }, b.w.agents.b, refusedWith("agent_paused"));
      await setSlice({ pause: { workspace: false, agents: [], instances: [b.w.ins] } }, b.w.agents.b, refusedWith("agent_paused"));
      await setSlice({ pause: { workspace: true, agents: [], instances: [] } }, b.w.agents.b, refusedWith("agent_paused"));
      await setSlice({ agents: [{ id: b.w.agents.a, name: "Agent A", mode: "free", status: "active" }] }, b.w.agents.b, refusedWith("agent_not_in_slice"));
      // quiet-on-good: agent A (active, edge, no pause) is granted under the same slice
      assert.equal((await tryGrant(b.w.agents.a, "pz")).status, 200);
    } finally {
      await setSlice({}, b.w.agents.b, granted);
    }
    assert.equal((await b.running.scopes.access(b.w.agents.b, "notebook", "pz"))?.access, "read", "the free agent is granted again");
  });

  test("S4a: an expired slice refuses the grant (slice_stale 503), the decision never reads a stale slice", () => {
    const rtStale = { trust: { stale: () => true, agent: () => ({ id: "agt_x", status: "active" }), paused: () => ({ workspace: false, instance: false, agent: false }) } } as never;
    assert.throws(() => grantRefusal(rtStale, "agt_x", Date.now()), (e: unknown) => e instanceof TbError && e.code === "slice_stale" && e.httpStatus === 503);
    const rtFresh = { trust: { stale: () => false, agent: () => ({ id: "agt_x", status: "active" }), paused: () => ({ workspace: false, instance: false, agent: false }) } } as never;
    assert.equal(grantRefusal(rtFresh, "agt_x", Date.now()), null);
  });
});

describe("SDK-INSTANCE-GRANT: store level", () => {
  const person = { type: "person", id: "per_x", ws: "ws_x", instance: "ins_x" } as unknown as PersonPrincipal;
  const by = (inSlice = true) => ({ principal: person, op: "o", callId: null, requestId: "req_1", refusal: () => (inSlice ? null : { reason: "agent_not_in_slice", message: "no edge" }) });
  function store(defaults: Scope["defaultGrants"]) {
    const t = tempDir();
    const db = openStore(t.dir);
    const m = manifestWithManage(1);
    const sc = m.scopes?.[0];
    if (!sc) throw new Error("no scope");
    sc.defaultGrants = defaults;
    const st = createScopeStore(db, m, createAuditLog(db, []), () => {});
    return { st, db, ops: scopeGrantOps(st), cleanup: t.cleanup };
  }

  test("rows written before 0.1.31 (source NULL) omit source and grantedByOp; the migration is additive", async () => {
    const { st, db, cleanup } = store([{ kind: "own", access: "read_write" }]);
    try {
      db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access) VALUES ('agt_old', 'notebook', 'x', 'read')").run();
      assert.deepEqual(await st.access("agt_old" as never, "notebook", "x"), { agent: "agt_old", type: "notebook", instanceId: "x", access: "read" });
      assert.ok(SDK_MIGRATIONS.some((m) => m.name === "sdk_scope_source" && /ADD COLUMN source/.test(m.sql) && !/DROP|UPDATE|DELETE/i.test(m.sql)));
    } finally {
      cleanup();
    }
  });

  test("agent ceiling: the highest level a default grant gives AGENTS (callers app-only grants do not count); none = grant refused", async () => {
    const a = store([
      { kind: "own", access: "read_write" },
      { kind: "shared", access: "manage", callers: ["app"] },
    ]);
    try {
      assert.equal(a.st.agentCeiling("notebook"), "read_write");
      assert.equal(a.st.agentCeiling("other"), null);
    } finally {
      a.cleanup();
    }
    const b2 = store([{ kind: "shared", access: "manage", callers: ["app"] }]);
    try {
      await b2.st.instances.create("notebook", "i1", "I1");
      await assert.rejects(b2.ops.appGrant(by(), "agt_a", "notebook", "i1", "read"), (e: unknown) => e instanceof TbError && e.code === "scope_grant_invalid" && e.details?.reason === "no_agent_ceiling");
    } finally {
      b2.cleanup();
    }
  });

  test("type_unknown, and a non-person principal is refused 403 before anything is written", async () => {
    const { st, ops, cleanup } = store([{ kind: "own", access: "read_write" }]);
    try {
      await st.instances.create("notebook", "i1", "I1");
      await assert.rejects(ops.appGrant(by(), "agt_a", "bogus", "i1", "read"), (e: unknown) => e instanceof TbError && e.code === "scope_grant_invalid" && e.details?.reason === "type_unknown");
      const forged = { ...by(), principal: { type: "agent", id: "agt_a" } as unknown as PersonPrincipal };
      await assert.rejects(ops.appGrant(forged, "agt_a", "notebook", "i1", "read"), (e: unknown) => e instanceof TbError && e.code === "session_required");
      await assert.rejects(ops.appRevoke(forged, "agt_a", "notebook", "i1"), (e: unknown) => e instanceof TbError && e.code === "session_required");
      assert.equal(await st.access("agt_a" as never, "notebook", "i1"), null);
    } finally {
      cleanup();
    }
  });

  test("the grant paths are not members of the store object that Start/Event contexts hand to app code", () => {
    const { st, cleanup } = store([{ kind: "own", access: "read_write" }]);
    try {
      for (const k of ["appGrant", "appRevoke", "selfRevoke", "grant", "revoke"]) assert.equal(k in st, false, k);
    } finally {
      cleanup();
    }
  });
});
