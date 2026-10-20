// v0.1.35 (C283 A1, spec 0.1.50, C277): the OWNER-set scope row is primary (also above the Portal grant); EVERY other write
// path is bounded. Real HTTP over a fake bridge; the store level and the migration have their own tests. Each test says what
// fails without its guard ("fires on bad").
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { bridgeOpProofClaims, signBridgeOpProof, signGrant, ulid } from "@opt2-tealbrick/manifest";
import { BRIDGE_OP_PATH, type BridgeOp, type InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { DynamicCatalogEntry, Manifest, Operation, Scope } from "@opt2-tealbrick/spec/manifest";
import type { Json, OpContext, PersonPrincipal, Receipt, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { createScopeStore, scopeGrantOps } from "../src/server/scopes.ts";
import { applySdkMigrations, openDb, SDK_MIGRATIONS, SDK_SCHEMA, storedSchema } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

function owner(): Scope {
  return {
    type: "notebook",
    label: "Notebook",
    labelPlural: "Notebooks",
    access: [
      { id: "read", label: "Read", crud: ["read"] },
      { id: "write", label: "Write", crud: ["read", "create", "update"] },
      { id: "manage", label: "Manage", crud: ["read", "create", "update", "delete"] },
    ],
    // agents get write on their own instance and read on shared ones; `manage` is above the agent ceiling
    defaultGrants: [
      { kind: "own", access: "write" },
      { kind: "shared", access: "read" },
    ],
    summaryTemplate: "{count} {labelPlural}",
  };
}

function manifestFor(port: number): Manifest {
  const m = fixtureManifest(port);
  m.scopes = [owner()];
  const agentOp = (id: string, crud: ("read" | "create" | "update" | "delete")[], effect: "read" | "write" | "destructive", over: Partial<Operation> = {}): Operation =>
    ({ id, title: id, description: id, input: { type: "object" }, output: { type: "object" }, crud, effect, idempotency: "supported", receipt: true, audience: "agent", ...over }) as Operation;
  m.operations.push(
    // scoped, delete: above a read/create Portal grant
    agentOp("note_purge", ["delete"], "destructive", { scopeType: "notebook", holdFamily: "destructive" }),
    // v0.1.36: reads what ctx.scope says about the target notebook (can / readable / writable / access.crud)
    agentOp("note_can", ["read"], "read", { scopeType: "notebook", receipt: false }),
    // UNSCOPED, delete: the Portal grant is its only ceiling
    agentOp("purge_all", ["delete"], "destructive", { holdFamily: "destructive" }),
    // an agent / app handler that tries to write an owner row through every handle it can reach
    agentOp("forge_owner", ["read"], "read", { receipt: false }),
    // person op: ctx.scopeGrants.grant
    { ...agentOp("draft_grant", ["update"], "write", { receipt: false }), audience: "person" } as Operation,
    // dynamic op with a scope type (no input/output; crud read, effect read: the entries carry their own)
    {
      id: "tools",
      title: "Tools",
      description: "Search and call tools (test op).",
      crud: ["read"],
      effect: "read",
      scopeType: "notebook",
      idempotency: "supported",
      receipt: false,
      audience: "agent",
      dynamic: { mode: "search", crudCeiling: ["read", "create", "update", "delete"], effectCeiling: "destructive" },
    } as unknown as Operation,
  );
  return m;
}

const CATALOG: DynamicCatalogEntry[] = [
  { name: "read_item", title: "Read", description: "read", inputSchema: { type: "object" }, crud: ["read"], effect: "read" },
  { name: "write_item", title: "Write", description: "write", inputSchema: { type: "object" }, crud: ["create", "update"], effect: "write" },
  { name: "delete_item", title: "Delete", description: "delete", inputSchema: { type: "object" }, crud: ["delete"], effect: "destructive" },
  // an app lying about itself: `admitted` is set by the SDK alone
  { name: "liar_item", title: "Liar", description: "claims owner", inputSchema: { type: "object" }, crud: ["delete"], effect: "destructive", admitted: "owner" },
];

const holder: { running?: RunningApp; w?: World; manifest?: Manifest } = {};

function testApp(port: number, migrations: string) {
  const manifest = manifestFor(port);
  holder.manifest = manifest;
  const person = () => ({ type: "person", id: holder.w?.per, ws: holder.w?.ws, instance: holder.w?.ins }) as unknown as PersonPrincipal;
  return defineApp({
    manifest,
    migrations,
    handlers: {
      note_can: {
        scope: (input) => ((input as { notebook?: string }).notebook ?? null),
        run: async (input, ctx: OpContext) => {
          const id = String((input as { notebook?: string }).notebook ?? "");
          return {
            can: { read: await ctx.scope.can("notebook", id, "read"), create: await ctx.scope.can("notebook", id, "create"), update: await ctx.scope.can("notebook", id, "update"), delete: await ctx.scope.can("notebook", id, "delete") },
            readable: await ctx.scope.readable("notebook"),
            writable: await ctx.scope.writable("notebook"),
            crud: (ctx.scope.access?.crud ?? null) as unknown as Json,
          } as unknown as Json;
        },
      },
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      note_purge: { scope: (input) => ((input as { notebook?: string }).notebook ?? null), run: async () => ({ purged: true }) },
      purge_all: async () => ({ purged: true }),
      forge_owner: async (input) => {
        const i = input as { who: string; id: string };
        // every handle app code can reach: the store of the running app, with a person principal it made up
        await holder.running?.scopes.set(person(), i.who as never, "notebook", i.id, "manage");
        return { tried: true };
      },
      draft_grant: async (input, ctx: OpContext) => {
        const i = input as { agent: string; id: string; access: string };
        return { row: (await ctx.scopeGrants?.grant(i.agent as never, "notebook", i.id, i.access)) as unknown as Json };
      },
    },
    dynamic: {
      tools: {
        catalog: async () => CATALOG.map((e) => ({ ...e })),
        resolve: async (tool) => {
          const e = CATALOG.find((x) => x.name === tool);
          return e ? { tool, crud: e.crud, effect: e.effect } : null;
        },
        call: async () => ({ done: true }),
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dataDir: string;
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  holder.w = w;
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  // a boot that fails must not leave the bridge or the app listening: an open handle would keep the test process alive for ever
  let running: RunningApp | undefined;
  try {
    running = await startApp(
      testApp(port, migrationsDir(t.dir)),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    holder.running = running;
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

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json = {}) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** An agent call; `crud` = the Portal grant's crud (default: read + create, so a delete is ABOVE the grant). */
async function agentOp(b: Booted, op: string, input: Json, opts: { agent?: string; crud?: ("read" | "create" | "update" | "delete")[]; grantToken?: string } = {}) {
  const g = opts.grantToken ?? (await grant(b.w, (opts.agent ?? b.w.agents.a) as `agt_${string}`, { crud: opts.crud ?? ["read", "create"] }));
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: `k_${ulid()}` }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** A companion (app) caller's grant: `sub` = an instance. */
async function appGrant(b: Booted, ins: InstanceId, wf: string[], crud: ("read" | "create" | "update" | "delete")[] = ["read", "create"]): Promise<string> {
  return signGrant({ iss: "tb:portal", sub: `tb:ins:${ins}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud, mode: "bound", held: [], caps: {}, wf, polrev: 1, prd: "evolution" } as never, b.w.portal);
}

async function bridgeOp(b: Booted, bop: BridgeOp, body: Record<string, Json>) {
  const c = bridgeOpProofClaims(bop, body);
  const proof = await signBridgeOpProof(
    { iss: `tb:brg:${b.w.brg}`, sub: `tb:brg:${b.w.brg}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), call: `call_${ulid()}`, bop, ...(c.op !== undefined ? { op: c.op } : {}), ...(c.in !== undefined ? { in: c.in } : {}) } as never,
    b.w.bridgeKey,
  );
  const res = await fetch(`${b.base}/tb/v1/bridge/${BRIDGE_OP_PATH[bop]}`, { method: "POST", headers: { "content-type": "application/json", "tb-call": proof }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as any };
}

describe("C283 A1: owner-set access is primary, everything else is bounded (HTTP)", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  let n = 0;
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  /** a fresh notebook instance for the test; the owner row (via the person route) or a default/bounded row is placed by the test */
  const fresh = async (): Promise<string> => {
    const id = `nb${++n}`;
    await b.running.scopes.instances.create("notebook", id, id);
    return id;
  };
  const setOwner = (agent: string, id: string, access: string | null) => personOp(b, s, "tb.scopes_set", { agent, type: "notebook", id, access });
  const rowOf = (agent: string, id: string) => b.running.scopes.access(agent as never, "notebook", id);
  const receipts = async (op: string): Promise<Receipt[]> => (await b.running.receipts.list({ op })).items;
  const A = () => b.w.agents.a;
  // first sight of agent A (default grants) so later rows are only the ones a test writes
  before(async () => {
    assert.equal((await agentOp(b, "note_create", { notebook: b.w.agents.a, title: "t" })).status, 200);
  });

  test("tb.scopes_set from the owner session writes an owner row; the same call with an unchanged level makes a bounded row primary", async () => {
    const id = await fresh();
    // a bounded row first (what a pre-0.1.35 owner row looks like after the migration)
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id, "manage");
    assert.equal((await rowOf(A(), id))?.authority, "bounded", "fires on bad: the store handle must not write an owner row");
    const r = await setOwner(A(), id, "manage");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.output.access.authority, "owner", "make primary: the level did not change, the authority did");
    assert.equal(r.body.output.access.source, "owner");
    const list = (await personOp(b, s, "tb.agents_list")).body.output.agents.find((a: { id: string }) => a.id === A());
    assert.equal(list.access.find((x: { instanceId: string }) => x.instanceId === id).authority, "owner", "tb.agents_list shows it");
    const audit = (await b.running.audit.list({ action: "scope.set" })).items.find((e) => (e.detail as { instance?: string }).instance === id && (e.detail as { authority?: string }).authority === "owner");
    assert.ok(audit, "the owner write is audited with its authority (S7)");
  });

  test("an owner row ABOVE the Portal grant runs and the receipt says app_owner_row; a bounded row above the grant is refused scope_denied", async () => {
    const id = await fresh();
    await setOwner(A(), id, "manage");
    const ok = await agentOp(b, "note_purge", { notebook: id });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const rcp = (await receipts("note_purge")).find((r) => r.id === ok.body.receiptId);
    assert.equal(rcp?.admittedBy, "app_owner_row");
    // fires on bad: the same row written by any other path is bounded and the Portal grant (read + create) is the ceiling
    const id2 = await fresh();
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id2, "manage");
    const no = await agentOp(b, "note_purge", { notebook: id2 });
    assert.equal(no.status, 403);
    assert.equal(no.body.error.code, "scope_denied");
    const refused = (await receipts("note_purge")).find((r) => r.status === "refused");
    assert.ok(refused);
    assert.equal("admittedBy" in refused, false, "a refusal carries no admittedBy");
  });

  test("within the grant the Portal grant admits: admittedBy portal_grant (default row and an owner row narrower than the grant)", async () => {
    const own = await agentOp(b, "note_create", { notebook: A(), title: "x" });
    assert.equal(own.status, 200);
    assert.equal((await receipts("note_create")).find((r) => r.id === own.body.receiptId)?.admittedBy, "portal_grant");
    // an owner row NARROWER than the grant still narrows (the owner row is the effective crud)
    const id = await fresh();
    await setOwner(A(), id, "read");
    const narrow = await agentOp(b, "note_create", { notebook: id, title: "x" });
    assert.equal(narrow.status, 403, "grant allows create, the owner row is read only");
    assert.equal(narrow.body.error.code, "scope_denied");
  });

  test("an UNSCOPED op above the grant is still refused (the owner row is not consulted); a scoped op with no row is refused", async () => {
    const id = await fresh();
    await setOwner(A(), id, "manage");
    const r = await agentOp(b, "purge_all", {});
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, "scope_denied", "fires on bad: owner rows must not widen an op that has no scope type");
    const none = await agentOp(b, "note_purge", { notebook: "no_such_instance_row" });
    assert.equal(none.status, 403);
  });

  test("ctx.scopeGrants over an owner row makes it bounded; the Portal grant is the ceiling again", async () => {
    const id = await fresh();
    await setOwner(A(), id, "write");
    assert.equal((await rowOf(A(), id))?.authority, "owner");
    // the app (a person op the owner confirmed) grants the same agent the same instance: the row is the app's, bounded
    const g = await personOp(b, s, "draft_grant", { agent: A(), id, access: "write" });
    assert.equal(g.status, 200, JSON.stringify(g.body));
    const after = await rowOf(A(), id);
    assert.equal(after?.source, "app");
    assert.equal(after?.authority, "bounded", "fires on bad: an app row over an owner row must not stay primary");
  });

  test("the store handle (tb.scopes_set's store method) over an owner row, and the manifest defaults, never leave a row primary by themselves", async () => {
    const id = await fresh();
    await setOwner(A(), id, "manage");
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id, "manage");
    assert.equal((await rowOf(A(), id))?.authority, "bounded", "a write through the app-reachable store is bounded, also over an owner row");
    // a default grant does not overwrite an existing row (INSERT OR IGNORE): an owner row stays what the owner made it
    const id2 = await fresh();
    await setOwner(A(), id2, "manage");
    await b.running.scopes.instances.create("notebook", id2, "shared now", { shared: true });
    assert.equal((await rowOf(A(), id2))?.authority, "owner", "an owner edit always wins over defaults (v0.1.13); defaults never write owner");
    assert.equal((await rowOf(A(), id2))?.access, "manage");
  });

  test("an AGENT op cannot write an owner row: tb.scopes_set is refused for an agent grant, and a handler that forges a person principal writes a bounded row", async () => {
    const g = await grant(b.w, A(), { crud: ["read", "create", "update", "delete"] });
    const proof = await callProof(b.w, g, "tb.scopes_set", { agent: A(), type: "notebook", id: "zz", access: "manage" });
    const res = await fetch(`${b.base}/tb/v1/ops/tb.scopes_set`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
      body: JSON.stringify({ input: { agent: A(), type: "notebook", id: "zz", access: "manage" }, context: {} }),
    });
    assert.equal(res.status, 403);
    assert.equal(((await res.json()) as any).error.code, "audience_not_agent");
    // the person route needs a session cookie AND the CSRF header: a bearer grant gets nothing there
    const viaPerson = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/tb.scopes_set`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g}`, origin: b.base },
      body: JSON.stringify({ input: { agent: A(), type: "notebook", id: "zz", access: "manage" } }),
    });
    assert.ok(viaPerson.status === 401 || viaPerson.status === 403, `person route refused: ${viaPerson.status}`);
    // the handler path: the agent op reaches the store handle of the running app and forges a person principal
    const id = await fresh();
    const f = await agentOp(b, "forge_owner", { who: A(), id }, { crud: ["read"] });
    assert.equal(f.status, 200, JSON.stringify(f.body));
    const row = await rowOf(A(), id);
    assert.equal(row?.access, "manage", "the forged write did happen (the store is app code's own)");
    assert.equal(row?.authority, "bounded", "fires on bad: ...but it is not primary");
    const noRun = await agentOp(b, "note_purge", { notebook: id });
    assert.equal(noRun.status, 403, "so it does not widen the agent above the Portal grant");
    assert.equal(noRun.body.error.code, "scope_denied");
  });

  test("an APP (companion) call cannot write an owner row either", async () => {
    const ins = `ins_${ulid()}` as InstanceId;
    b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: [{ product: "evolution", ins, name: "Evolution" }] }));
    const g = await appGrant(b, ins, ["forge_owner", "note_purge"]);
    // 1) the standard op is person-only
    const proof = await callProof(b.w, g, "tb.scopes_set", {});
    const std = await fetch(`${b.base}/tb/v1/ops/tb.scopes_set`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof }, body: JSON.stringify({ input: {}, context: {} }) });
    assert.ok(std.status === 403 || std.status === 400 || std.status === 401, `refused ${std.status}`);
    // 2) the app handler path: a bounded row, so a purge above the app grant stays refused
    const id = await fresh();
    const f = await agentOp(b, "forge_owner", { who: ins, id }, { grantToken: g });
    assert.equal(f.status, 200, JSON.stringify(f.body));
    assert.equal((await rowOf(ins, id))?.authority, "bounded");
    const no = await agentOp(b, "note_purge", { notebook: id }, { grantToken: await appGrant(b, ins, ["note_purge"]) });
    assert.equal(no.status, 403);
    assert.equal(no.body.error.code, "scope_denied");
  });

  test("an op that spans instances (no target) gets owner authority only when EVERY row of the agent is an owner row", async () => {
    const agent = b.w.agents.b;
    assert.equal((await agentOp(b, "note_create", { notebook: agent, title: "t" }, { agent })).status, 200, "first sight of agent B: its own instance + the shared ones, all default rows");
    const i1 = await fresh();
    await setOwner(agent, i1, "manage");
    // B still has default (bounded) rows, so the spanning purge (no `notebook`) is NOT owner-authorised although the best row is an owner row
    const spanning = await agentOp(b, "note_purge", {}, { agent });
    assert.equal(spanning.status, 403, "fires on bad: best access is the owner row, but not every row is an owner row");
    assert.equal(spanning.body.error.code, "scope_denied");
    // a targeted call on the owner instance is admitted by that row alone
    assert.equal((await agentOp(b, "note_purge", { notebook: i1 }, { agent })).status, 200);
    // the owner takes over every other row of B as well: every row involved is an owner row now
    for (const r of await b.running.scopes.list(agent as never)) if (r.authority !== "owner") await setOwner(agent, r.instanceId, "write");
    const all = await agentOp(b, "note_purge", {}, { agent });
    assert.equal(all.status, 200, JSON.stringify(all.body));
    assert.equal((await receipts("note_purge")).find((r) => r.id === all.body.receiptId)?.admittedBy, "app_owner_row");
    // a newly shared instance gives the already-seen agent a default (bounded) row: the spanning call is capped again
    await b.running.scopes.instances.create("notebook", "shared_again", "s", { shared: true });
    assert.equal((await b.running.scopes.access(agent as never, "notebook", "shared_again"))?.authority, "bounded");
    assert.equal((await agentOp(b, "note_purge", {}, { agent })).status, 403);
  });

  test("a paused agent with an owner row is refused `paused`, and a removed agent `agent_unknown`; the owner row never revives either", async () => {
    const agent = b.w.agents.b;
    const id = await fresh();
    await setOwner(agent, id, "manage");
    const pausedSlice = await slice(b.w, PRODUCT, { pause: { workspace: false, agents: [agent], instances: [] } });
    b.bridge.push(pausedSlice);
    try {
      const r = await until(async () => {
        const x = await agentOp(b, "note_purge", { notebook: id }, { agent });
        return x.status === 403 && x.body.error?.code === "paused" ? x : null;
      });
      assert.equal(r.status, 403);
      b.bridge.push(await slice(b.w, PRODUCT, { agents: [{ id: b.w.agents.a, name: "Agent A", mode: "free", status: "active" }] }));
      const gone = await until(async () => {
        const x = await agentOp(b, "note_purge", { notebook: id }, { agent });
        return x.body.error?.code === "agent_unknown" ? x : null;
      });
      assert.equal(gone.status, 403);
    } finally {
      b.bridge.push(await slice(b.w, PRODUCT));
    }
    await until(async () => ((await agentOp(b, "note_purge", { notebook: id }, { agent })).status === 200 ? true : null));
  });

  test("a Portal cap is unchanged by an owner row (S6): the call is held `caps`, and the hold records which rule admitted it", async () => {
    const id = await fresh();
    await setOwner(A(), id, "manage");
    const capped = await agentOp(b, "note_purge", { notebook: id }, { grantToken: await grant(b.w, A(), { crud: ["read", "create"], caps: { destructive: { max: 0, per: "hour" } } }) });
    assert.equal(capped.status, 202, "fires on bad: an owner row must not lift a Portal cap");
    assert.equal(capped.body.status, "held");
    const hold = await b.running.receipts.get(capped.body.holdId);
    assert.equal(hold?.holdFamily, "caps");
    assert.equal(hold?.admittedBy, "app_owner_row");
  });

  test("bridge catalog: an agent's owner rows mark admitted entries; the app's own `admitted` is dropped; no agent in the body, no marks", async () => {
    const agent = b.w.agents.b;
    const id = await fresh();
    await setOwner(agent, id, "manage");
    await setOwner(agent, agent, "manage");
    // every row of B for `notebook` is an owner row now?
    for (const r of await b.running.scopes.list(agent as never)) await setOwner(agent, r.instanceId, "manage");
    const marked = await bridgeOp(b, "catalog", { op: "tools", agent });
    assert.equal(marked.status, 200, JSON.stringify(marked.body));
    const by = (name: string) => marked.body.find((e: DynamicCatalogEntry) => e.name === name);
    assert.equal(by("delete_item").admitted, "owner");
    assert.equal(by("read_item").admitted, "owner", "an owner row admits what its crud contains, also what the grant would admit");
    assert.equal(by("liar_item").admitted, "owner", "liar_item is delete too: marked by the SDK because the owner row admits delete");
    // the same list for an agent WITHOUT owner rows: nothing is marked, and the app's own `admitted` is gone
    const plain = await bridgeOp(b, "catalog", { op: "tools", agent: b.w.agents.a });
    assert.equal(plain.status, 200);
    for (const e of plain.body as DynamicCatalogEntry[]) assert.equal("admitted" in e, false, `${e.name}: fires on bad, an app-set mark must not pass through`);
    const noAgent = await bridgeOp(b, "catalog", { op: "tools" });
    for (const e of noAgent.body as DynamicCatalogEntry[]) assert.equal("admitted" in e, false, "no agent in the body: no marks");
    // a narrower owner row marks only what it admits
    await personOp(b, s, "tb.scopes_set", { agent, type: "notebook", id, access: "read" });
    for (const r of await b.running.scopes.list(agent as never)) await setOwner(agent, r.instanceId, "read");
    const narrow = await bridgeOp(b, "catalog", { op: "tools", agent });
    assert.equal(narrow.body.find((e: DynamicCatalogEntry) => e.name === "read_item").admitted, "owner");
    assert.equal("admitted" in narrow.body.find((e: DynamicCatalogEntry) => e.name === "delete_item"), false);
    // a bounded row (any) in the mix: no mark at all, and an unknown agent id gets none
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, agent as never, "notebook", id, "manage");
    const mixed = await bridgeOp(b, "catalog", { op: "tools", agent });
    for (const e of mixed.body as DynamicCatalogEntry[]) assert.equal("admitted" in e, false, "not every row is an owner row");
    const ghost = await bridgeOp(b, "catalog", { op: "tools", agent: `agt_${ulid()}` });
    for (const e of ghost.body as DynamicCatalogEntry[]) assert.equal("admitted" in e, false);
  });

  test("scope_summary: admittedOps names the STATIC scoped ops an agent's owner rows admit, per agent; absent when none; nothing for a paused agent", async () => {
    const agent = b.w.agents.b;
    // agent B: every row an owner row at `manage`
    for (const r of await b.running.scopes.list(agent as never)) await setOwner(agent, r.instanceId, "manage");
    const sum = await bridgeOp(b, "scope_summary", {});
    assert.equal(sum.status, 200, JSON.stringify(sum.body));
    const forB = sum.body.find((x: { agent: string }) => x.agent === agent);
    assert.deepEqual([...forB.admittedOps].sort(), ["note_can", "note_create", "note_purge"], "static scoped agent ops only (not the dynamic op, not unscoped ops, not person ops)");
    const forA = sum.body.find((x: { agent: string }) => x.agent === A());
    assert.equal("admittedOps" in forA, false, "agent A has bounded rows: nothing admitted by an owner row");
    // paused: no marks
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: false, agents: [agent], instances: [] } }));
    try {
      await until(async () => {
        const x = await bridgeOp(b, "scope_summary", {});
        return "admittedOps" in x.body.find((y: { agent: string }) => y.agent === agent) ? null : x;
      });
    } finally {
      b.bridge.push(await slice(b.w, PRODUCT));
    }
  });

  // v0.1.36 gap G1 (sdk#34 review): toRow reads ONLY the exact stored value 'owner' as primary. The column is NOT NULL DEFAULT 'bounded',
  // so a "corrupted" value is a different string; the store level below covers NULL.
  test("G1: a stored authority that is not exactly 'owner' (Owner, OWNER, x, empty, padded) reads as bounded and the Portal grant stays the ceiling", { timeout: 60_000 }, async () => {
    const setRaw = (agent: string, id: string, value: string) => {
      const db = new DatabaseSync(join(b.dataDir, "app.db"));
      try {
        db.exec("PRAGMA busy_timeout = 5000");
        const r = db.prepare("UPDATE tb_scopes SET authority = ? WHERE agent = ? AND type = 'notebook' AND instance_id = ?").run(value, agent, id);
        assert.equal(Number(r.changes), 1, "the raw write hit the row");
      } finally {
        db.close();
      }
    };
    // control: the exact value 'owner' written raw is primary (so the raw write path really reaches the decision)
    const idOk = await fresh();
    await setOwner(A(), idOk, "manage");
    setRaw(A(), idOk, "owner");
    assert.equal((await rowOf(A(), idOk))?.authority, "owner");
    assert.equal((await agentOp(b, "note_purge", { notebook: idOk })).status, 200, "quiet on good: an exact 'owner' row admits above the grant");
    for (const bad of ["Owner", "OWNER", "x", "", " owner", "owner ", "bounded "]) {
      const id = await fresh();
      await setOwner(A(), id, "manage");
      setRaw(A(), id, bad);
      assert.equal((await rowOf(A(), id))?.authority, "bounded", `fires on bad: ${JSON.stringify(bad)} must read bounded (a "!== bounded" test would make it primary)`);
      const no = await agentOp(b, "note_purge", { notebook: id });
      assert.equal(no.status, 403, `${JSON.stringify(bad)}: ${JSON.stringify(no.body)}`);
      assert.equal(no.body.error.code, "scope_denied", "capped by the Portal grant (read + create)");
    }
  });

  // v0.1.36 gap G4 (sdk#34 review): markable() requires status "active" itself. The slice type allows "active" | "paused", and
  // `paused` is also caught by trust.paused(), so only a status outside the pair separates the two checks. The slice is signed by Portal
  // (the test pushes a value the types do not list, as a newer Portal might); the SDK must fail closed and mark nothing.
  test("G4: an agent in the slice whose status is not 'active' gets no `admitted` marks in catalog and no admittedOps in scope_summary, owner rows or not", { timeout: 60_000 }, async () => {
    const agent = b.w.agents.b;
    assert.equal((await agentOp(b, "note_create", { notebook: agent, title: "t" }, { agent })).status, 200);
    for (const r of await b.running.scopes.list(agent as never)) await setOwner(agent, r.instanceId, "manage");
    const others = [{ id: b.w.agents.a, name: "Agent A", mode: "free", status: "active" }];
    const adm = async () => {
      const cat = await bridgeOp(b, "catalog", { op: "tools", agent });
      const sum = await bridgeOp(b, "scope_summary", {});
      const forB = sum.body.find((x: { agent: string }) => x.agent === agent);
      return { marked: (cat.body as DynamicCatalogEntry[]).filter((e) => e.admitted === "owner").length, ops: forB?.admittedOps as string[] | undefined, listed: forB !== undefined };
    };
    const push = async (status: string) => {
      const before = b.bridge.statuses.length;
      b.bridge.push(await slice(b.w, PRODUCT, { agents: [...others, { id: agent, name: "Agent B", mode: "free", status }] as never }));
      await until(async () => b.bridge.statuses.length > before && (b.bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === b.w.rev);
    };
    try {
      await push("active");
      const good = await adm();
      assert.ok(good.marked > 0, "quiet on good: an active agent with owner rows is marked");
      assert.deepEqual([...(good.ops ?? [])].sort(), ["note_can", "note_create", "note_purge"]);
      for (const status of ["retired", "suspended", ""]) {
        await push(status);
        const bad = await adm();
        assert.equal(bad.listed, true, "still in the slice, so scope_summary lists it");
        assert.equal(bad.marked, 0, `fires on bad: status ${JSON.stringify(status)} must mark no catalog entry`);
        assert.equal(bad.ops, undefined, `fires on bad: status ${JSON.stringify(status)} must name no admittedOps`);
      }
    } finally {
      b.bridge.push(await slice(b.w, PRODUCT));
    }
  });
});

// ── migration (C283a condition 4): owner rows written before schema 8 stay bounded after the upgrade ─────────────────────────
describe("C283 A1: SDK schema 8 sdk_scope_authority + schema 9 sdk_receipt_admitted_by", () => {
  const sha = (text: string) => createHash("sha256").update(text).digest("hex");
  /** a database exactly as SDK 0.1.34 left it: the migrations up to schema 7, recorded the way applySdkMigrations records them */
  function schema7(dir: string): DatabaseSync {
    const db = openDb(dir);
    for (const m of SDK_MIGRATIONS.filter((x) => x.version <= 7)) {
      db.exec(m.sql);
      db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('sdk', ?, ?, ?, ?)").run(m.version, m.name, sha(m.sql), Date.now());
    }
    return db as unknown as DatabaseSync;
  }

  test("a DB at schema 7 with source='owner' rows: after the upgrade EVERY row is 'bounded' and the owner row no longer admits above the grant", async () => {
    const t = tempDir();
    try {
      const db = schema7(t.dir);
      assert.deepEqual(storedSchema(db as never).sdk, 7);
      assert.equal(
        (db.prepare("PRAGMA table_info(tb_scopes)").all() as { name: string }[]).some((c) => c.name === "authority"),
        false,
        "the fixture really is schema 7",
      );
      db.prepare("INSERT INTO tb_scope_instances (type, id, label, shared, created_at) VALUES ('notebook', 'x', 'X', 0, 1)").run();
      const ins = db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source, granted_by_op) VALUES (?, 'notebook', 'x', ?, ?, ?)");
      ins.run("agt_owner_row", "manage", "owner", null);
      ins.run("agt_app_row", "write", "app", "draft_start");
      ins.run("agt_default_row", "read", "default", null);
      ins.run("agt_null_source", "read", null, null);
      const applied = applySdkMigrations(db as never);
      assert.deepEqual(applied.map((m) => `${m.version}:${m.name}`), ["8:sdk_scope_authority", "9:sdk_receipt_admitted_by", "10:sdk_scope_crud_snapshot"]);
      assert.equal(storedSchema(db as never).sdk, SDK_SCHEMA);
      const rows = db.prepare("SELECT agent, source, authority, access FROM tb_scopes ORDER BY agent").all() as { agent: string; source: string | null; authority: string; access: string }[];
      assert.equal(rows.length, 4);
      for (const r of rows) assert.equal(r.authority, "bounded", `${r.agent}: fires on bad, a migration that marked owner rows 'owner' would widen access silently`);
      assert.deepEqual(rows.map((r) => [r.agent, r.source, r.access]), [
        ["agt_app_row", "app", "write"],
        ["agt_default_row", "default", "read"],
        ["agt_null_source", null, "read"],
        ["agt_owner_row", "owner", "manage"],
      ], "source and access are untouched");
      // through the store and the decision: the pre-migration owner row is capped by the Portal grant
      const m = manifestFor(1);
      const st = createScopeStore(db as never, m, createAuditLog(db as never, []), () => {});
      const r = st.resolve("agt_owner_row", "notebook", "x");
      assert.equal(r?.authority, "bounded");
      assert.equal((await st.access("agt_owner_row" as never, "notebook", "x"))?.authority, "bounded");
      // "make primary": the owner re-saves the row (the one owner path), and only then it is owner
      const per = { type: "person", id: "per_x", ws: "ws_x", instance: "ins_x" } as unknown as PersonPrincipal;
      await scopeGrantOps(st).ownerSet(per, "agt_owner_row", "notebook", "x", "manage");
      assert.equal(st.resolve("agt_owner_row", "notebook", "x")?.authority, "owner");
      assert.equal(st.resolve("agt_app_row", "notebook", "x")?.authority, "bounded", "other rows are untouched");
      // a receipt written before schema 9 reads without admittedBy
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("startApp upgrades a schema-7 data dir: the owner row is bounded after boot (standalone), the receipt column exists", async () => {
    const t = tempDir("tb-a1-up-");
    const data = join(t.dir, "data");
    try {
      const db = schema7(data);
      db.prepare("INSERT INTO tb_scope_instances (type, id, label, shared, created_at) VALUES ('notebook', 'x', 'X', 0, 1)").run();
      db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source) VALUES ('agt_owner_row', 'notebook', 'x', 'manage', 'owner')").run();
      db.close();
      const port = await freePort();
      const running = await startApp(testApp(port, migrationsDir(join(t.dir, "code"))), { TB_DATA_DIR: data, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" }, { privilegeProc: { getuid: () => 4242 } }).catch((e) => {
        throw new Error(`${e.message} ${JSON.stringify(e.details)}`);
      });
      try {
        const row = await running.scopes.access("agt_owner_row" as never, "notebook", "x");
        assert.equal(row?.access, "manage");
        assert.equal(row?.source, "owner");
        assert.equal(row?.authority, "bounded", "the upgrade did not make the old owner row primary");
        const h = (await (await fetch(`http://127.0.0.1:${port}/tb/v1/health`)).json()) as { schemaVersion?: { sdk: number } };
        assert.equal(h.schemaVersion?.sdk, SDK_SCHEMA);
      } finally {
        await running.stop();
      }
      const chk = new DatabaseSync(join(data, "app.db"), { readOnly: true });
      assert.ok((chk.prepare("PRAGMA table_info(tb_receipts)").all() as { name: string }[]).some((c) => c.name === "admitted_by"));
      chk.close();
    } finally {
      t.cleanup();
    }
  });

  test("the migrations are additive: no DROP / UPDATE / DELETE, forward-only, and the column default is 'bounded'", () => {
    const m8 = SDK_MIGRATIONS.find((m) => m.name === "sdk_scope_authority");
    assert.ok(m8);
    assert.equal(m8.version, 8);
    assert.match(m8.sql, /ADD COLUMN authority TEXT NOT NULL DEFAULT 'bounded'/);
    assert.doesNotMatch(m8.sql, /DROP|UPDATE|DELETE/i);
    const m9 = SDK_MIGRATIONS.find((m) => m.name === "sdk_receipt_admitted_by");
    assert.ok(m9);
    assert.equal(m9.version, 9);
    assert.doesNotMatch(m9.sql, /DROP|UPDATE|DELETE/i);
  });
});

// ── the decision the SDK takes from the stored row (store → authorize), without HTTP ──────────────────────────────────────
describe("C283 A1: store rows feed authorize()", () => {
  test("ScopeStore.resolve: targeted row authority; spanning op = owner only if every row involved is owner", async () => {
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db);
      const st = createScopeStore(db, manifestFor(1), createAuditLog(db, []), () => {});
      const per = { type: "person", id: "per_x", ws: "ws_x", instance: "ins_x" } as unknown as PersonPrincipal;
      const ops = scopeGrantOps(st);
      await st.instances.create("notebook", "a", "A");
      await st.instances.create("notebook", "b", "B");
      await ops.ownerSet(per, "agt_1", "notebook", "a", "manage");
      assert.equal(st.resolve("agt_1", "notebook", "a")?.authority, "owner");
      assert.equal(st.resolve("agt_1", "notebook", null)?.authority, "owner", "one row, owner");
      assert.equal(st.ownerAdmits("agt_1", "notebook", ["delete"]), true);
      await st.set(per, "agt_1" as never, "notebook", "b", "write"); // app-reachable store: bounded
      assert.equal(st.resolve("agt_1", "notebook", "b")?.authority, "bounded");
      assert.equal(st.resolve("agt_1", "notebook", null)?.authority, "bounded", "best row is the owner row, but a bounded row is involved");
      assert.equal(st.resolve("agt_1", "notebook", null)?.crud.includes("delete"), true, "best access still comes from the owner row");
      assert.equal(st.ownerAdmits("agt_1", "notebook", ["delete"]), false);
      assert.equal(st.resolve("agt_none", "notebook", null), null);
      assert.equal(st.ownerAdmits("agt_none", "notebook", ["read"]), false);
      assert.equal(st.ownerAdmits("agt_1", "no_such_type", ["read"]), false);
      // a non-person principal is refused before anything is written, on both write paths
      await assert.rejects(ops.ownerSet({ type: "agent", id: "agt_1" } as never, "agt_1", "notebook", "a", "manage"), (e: unknown) => (e as { code?: string }).code === "session_required");
      await assert.rejects(st.set({ type: "agent", id: "agt_1" } as never, "agt_1" as never, "notebook", "a", "manage"), (e: unknown) => (e as { code?: string }).code === "session_required");
      // ownerSet(null) removes; an unknown level / instance is refused
      await ops.ownerSet(per, "agt_1", "notebook", "a", null);
      assert.equal(await st.access("agt_1" as never, "notebook", "a"), null);
      await assert.rejects(ops.ownerSet(per, "agt_1", "notebook", "a", "root"), (e: unknown) => (e as { code?: string }).code === "access_level_unknown");
      await assert.rejects(ops.ownerSet(per, "agt_1", "notebook", "nope", "read"), (e: unknown) => (e as { code?: string }).code === "scope_instance_unknown");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  // v0.1.36 gap G1: a NULL authority (a database whose column lost its NOT NULL, or a row written by other code) is bounded too
  test("a NULL or foreign stored authority reads bounded in resolve / access / list, and ownerAdmits is false", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db);
      db.exec("DROP TABLE tb_scopes");
      db.exec(
        "CREATE TABLE tb_scopes (agent TEXT NOT NULL, type TEXT NOT NULL, instance_id TEXT NOT NULL, access TEXT NOT NULL, source TEXT, granted_by_op TEXT, authority TEXT, crud_snapshot TEXT, PRIMARY KEY (agent, type, instance_id)) STRICT",
      );
      const st = createScopeStore(db, manifestFor(1), createAuditLog(db, []), () => {});
      await st.instances.create("notebook", "a", "A");
      const ins = db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source, authority, crud_snapshot) VALUES (?, 'notebook', 'a', 'manage', 'owner', ?, '[\"read\",\"create\",\"update\",\"delete\"]')");
      const values: [string, string | null][] = [["agt_null", null], ["agt_cap", "Owner"], ["agt_x", "x"], ["agt_ok", "owner"]];
      for (const [agent, v] of values) ins.run(agent, v);
      for (const agent of ["agt_null", "agt_cap", "agt_x"]) {
        assert.equal(st.resolve(agent, "notebook", "a")?.authority, "bounded", `fires on bad: ${agent} must not be primary`);
        assert.equal((await st.access(agent as never, "notebook", "a"))?.authority, "bounded");
        assert.equal((await st.list(agent as never)).every((r) => r.authority === "bounded"), true);
        assert.equal(st.ownerAdmits(agent, "notebook", ["delete"]), false);
      }
      assert.equal(st.resolve("agt_ok", "notebook", "a")?.authority, "owner", "quiet on good: the exact value 'owner'");
      assert.equal(st.ownerAdmits("agt_ok", "notebook", ["delete"]), true);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("the owner write path is not a member of the store object that app code holds (fires on bad)", () => {
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db);
      const st = createScopeStore(db, manifestFor(1), createAuditLog(db, []), () => {});
      assert.equal("ownerSet" in st, false);
      assert.equal(typeof (st as unknown as { ownerSet?: unknown }).ownerSet, "undefined");
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

// ── C283b / C283c (spec 0.1.52): an owner row keeps the CRUD it was set with ─────────────────────────────────────────────────────
// The "app update widens a level" is simulated by changing the crud of the level in the manifest object the running app holds
// (the SDK reads the level's crud at call time, exactly what a new manifest version changes). Each test says what fails without
// its guard ("fires on bad"); the mutations that were run are listed in the PR.
describe("C283b/c: an owner row keeps the CRUD it was set with (HTTP)", { timeout: 60_000 }, () => {
  type Crud = ("read" | "create" | "update" | "delete")[];
  const WRITE: Crud = ["read", "create", "update"];
  const WRITE_PLUS_DELETE: Crud = ["read", "create", "update", "delete"];
  let b: Booted;
  let s: { cookie: string; csrf: string };
  let n = 0;
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  const A = () => b.w.agents.a;
  const fresh = async (): Promise<string> => {
    const id = `sn${++n}`;
    await b.running.scopes.instances.create("notebook", id, id);
    return id;
  };
  const setOwner = (agent: string, id: string, access: string | null, acceptOffer?: Json) =>
    personOp(b, s, "tb.scopes_set", { agent, type: "notebook", id, access, ...(acceptOffer !== undefined ? { acceptOffer } : {}) });
  const rowOf = (agent: string, id: string) => b.running.scopes.access(agent as never, "notebook", id);
  const listed = async (agent: string, id: string) =>
    (await personOp(b, s, "tb.agents_list")).body.output.agents.find((a: { id: string }) => a.id === agent).access.find((x: { instanceId: string }) => x.instanceId === id);
  const raw = <T>(fn: (db: DatabaseSync) => T): T => {
    const db = new DatabaseSync(join(b.dataDir, "app.db"));
    try {
      db.exec("PRAGMA busy_timeout = 5000");
      return fn(db);
    } finally {
      db.close();
    }
  };
  const snapshotOf = (agent: string, id: string): string | null =>
    raw((db) => (db.prepare("SELECT crud_snapshot AS c FROM tb_scopes WHERE agent = ? AND type = 'notebook' AND instance_id = ?").get(agent, id) as { c: string | null }).c);
  const level = (id: string) => {
    const l = holder.manifest?.scopes?.[0]?.access.find((a) => a.id === id);
    assert.ok(l, `level ${id}`);
    return l;
  };
  /** an "app update": `levelId` has `crud` while `fn` runs, then the manifest is what it was */
  async function updated(levelId: string, crud: Crud, fn: () => Promise<void>): Promise<void> {
    const l = level(levelId);
    const before = [...l.crud];
    l.crud = [...crud];
    try {
      await fn();
    } finally {
      l.crud = before;
    }
  }
  const purge = (id: string, agent?: string) => agentOp(b, "note_purge", { notebook: id }, agent ? { agent } : {});
  const can = async (id: string) => (await agentOp(b, "note_can", { notebook: id })).body;
  const receipts = async (op: string): Promise<Receipt[]> => (await b.running.receipts.list({ op })).items;

  test("WIDENING: a level widened by an app update does not widen an owner row: refused scope_denied, can() false, the offer is listed (fires on bad: the 0.1.35 rule widened it)", { timeout: 60_000 }, async () => {
    const id = await fresh();
    assert.equal((await setOwner(A(), id, "write")).status, 200);
    assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE), "the owner write stores the level's crud as the snapshot");
    // before the update: create runs (quiet on good), delete is not in `write`
    assert.equal((await agentOp(b, "note_create", { notebook: id, title: "t" })).status, 200);
    assert.equal((await purge(id)).body.error.code, "scope_denied");
    await updated("write", WRITE_PLUS_DELETE, async () => {
      const p = await purge(id);
      assert.equal(p.status, 403, "the widened level must not admit delete for this row");
      assert.equal(p.body.error.code, "scope_denied");
      const c = await can(id);
      assert.equal(c.status, "ok", JSON.stringify(c));
      assert.equal(c.output.can.delete, false, "ctx.scope.can follows the effective crud");
      assert.deepEqual([c.output.can.read, c.output.can.create, c.output.can.update], [true, true, true]);
      assert.deepEqual(c.output.crud, WRITE, "ctx.scope.access.crud is the effective crud");
      assert.ok(c.output.readable.includes(id));
      assert.ok(c.output.writable.includes(id));
      const row = await listed(A(), id);
      assert.deepEqual(row.crud, WRITE, "ScopeGrantRow.crud is effective");
      assert.deepEqual(row.offer, { adds: ["delete"] });
      assert.deepEqual((await rowOf(A(), id))?.offer, { adds: ["delete"] }, "also through the store");
      // a plain re-set of the same level does NOT accept
      assert.equal((await setOwner(A(), id, "write")).status, 200);
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE), "fires on bad: a plain re-set must keep the snapshot");
      assert.equal((await purge(id)).body.error.code, "scope_denied");
      assert.deepEqual((await listed(A(), id)).offer, { adds: ["delete"] });
      // another set of adds → 409 offer_changed, the row is not changed
      for (const adds of [[], ["create"], ["delete", "update"], ["read", "delete"]]) {
        const r = await setOwner(A(), id, "write", { adds });
        assert.equal(r.status, 409, JSON.stringify(adds));
        assert.equal(r.body.error.code, "offer_changed");
      }
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE));
      assert.equal((await purge(id)).body.error.code, "scope_denied");
      // the current adds: accepted, the call runs, the audit says so
      const ok = await setOwner(A(), id, "write", { adds: ["delete"] });
      assert.equal(ok.status, 200, JSON.stringify(ok.body));
      assert.equal(ok.body.output.access.offer, undefined, "no offer left");
      assert.deepEqual(ok.body.output.access.crud, WRITE_PLUS_DELETE);
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE_PLUS_DELETE));
      const run = await purge(id);
      assert.equal(run.status, 200, JSON.stringify(run.body));
      assert.equal((await receipts("note_purge")).find((r) => r.id === run.body.receiptId)?.admittedBy, "app_owner_row");
      assert.equal((await can(id)).output.can.delete, true);
      const accepted = (await b.running.audit.list({ action: "scope.offer_accepted" })).items.find((e) => (e.detail as { instance?: string }).instance === id);
      assert.ok(accepted, "scope.offer_accepted is audited");
      assert.deepEqual(accepted.detail, { type: "notebook", instance: id, access: "write", adds: ["delete"] });
      assert.equal(accepted.target, A());
    });
  });

  test("the adds are compared as a SET (any order, duplicates ignored); a wrong or partial set is refused", { timeout: 60_000 }, async () => {
    const ids = [await fresh(), await fresh(), await fresh()];
    for (const id of ids) assert.equal((await setOwner(A(), id, "read")).status, 200);
    await updated("read", ["read", "create", "delete"], async () => {
      for (const id of ids) assert.deepEqual((await listed(A(), id)).offer, { adds: ["create", "delete"] }, "level order");
      assert.equal((await setOwner(A(), ids[0] as string, "read", { adds: ["create"] })).body.error.code, "offer_changed", "partial");
      assert.equal((await setOwner(A(), ids[0] as string, "read", { adds: ["create", "delete", "update"] })).body.error.code, "offer_changed", "superset");
      assert.equal((await setOwner(A(), ids[0] as string, "read", { adds: ["delete", "create"] })).status, 200, "other order");
      assert.equal((await setOwner(A(), ids[1] as string, "read", { adds: ["delete", "create", "delete", "create"] })).status, 200, "duplicates");
      assert.deepEqual((await rowOf(A(), ids[0] as string))?.crud, ["read", "create", "delete"]);
      assert.equal((await rowOf(A(), ids[0] as string))?.offer, undefined);
      // the third row was never accepted: still an offer
      assert.deepEqual((await rowOf(A(), ids[2] as string))?.offer, { adds: ["create", "delete"] });
    });
  });

  test("acceptOffer with another level or access null → 400 input_invalid (nothing changes, the row is not deleted); a malformed acceptOffer → 400", { timeout: 60_000 }, async () => {
    const id = await fresh();
    await setOwner(A(), id, "write");
    await updated("write", WRITE_PLUS_DELETE, async () => {
      const other = await setOwner(A(), id, "manage", { adds: ["delete"] });
      assert.equal(other.status, 400);
      assert.equal(other.body.error.code, "input_invalid");
      const gone = await setOwner(A(), id, null, { adds: ["delete"] });
      assert.equal(gone.status, 400);
      assert.equal(gone.body.error.code, "input_invalid");
      const row = await rowOf(A(), id);
      assert.ok(row, "fires on bad: access null with acceptOffer must not delete the row");
      assert.equal(row.access, "write");
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE));
      assert.deepEqual(row.offer, { adds: ["delete"] });
      for (const bad of [{ adds: ["nope"] }, {}, { adds: "delete" }, { adds: ["delete"], extra: 1 }, "delete", ["delete"]] as Json[]) {
        const r = await setOwner(A(), id, "write", bad);
        assert.equal(r.status, 400, JSON.stringify(bad));
        assert.equal(r.body.error.code, "input_invalid", JSON.stringify(bad));
      }
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE));
    });
    // without acceptOffer, another level is a new choice: it stores THAT level's crud now (no accept involved)
    await updated("write", WRITE_PLUS_DELETE, async () => {
      assert.equal((await setOwner(A(), id, "manage")).status, 200);
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE_PLUS_DELETE));
      assert.equal((await rowOf(A(), id))?.offer, undefined);
    });
  });

  test("with NO offer only adds [] is accepted (a no-op that keeps the snapshot); any other adds → 409 offer_changed; on a bounded row it makes the row primary", { timeout: 60_000 }, async () => {
    const id = await fresh();
    await setOwner(A(), id, "write");
    assert.equal((await setOwner(A(), id, "write", { adds: [] })).status, 200);
    assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE));
    assert.equal((await b.running.audit.list({ action: "scope.offer_accepted" })).items.filter((e) => (e.detail as { instance?: string }).instance === id).length, 0, "nothing was accepted, nothing is audited as accepted");
    const bad = await setOwner(A(), id, "write", { adds: ["delete"] });
    assert.equal(bad.status, 409, "fires on bad: accepting an offer that does not exist");
    assert.equal(bad.body.error.code, "offer_changed");
    // a bounded row: no offer exists, adds [] works as the "make primary" re-set, adds ["delete"] does not
    const id2 = await fresh();
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id2, "write");
    assert.equal(snapshotOf(A(), id2), null, "a bounded row has no snapshot");
    assert.equal((await setOwner(A(), id2, "write", { adds: ["delete"] })).body.error.code, "offer_changed");
    assert.equal((await rowOf(A(), id2))?.authority, "bounded");
    const made = await setOwner(A(), id2, "write", { adds: [] });
    assert.equal(made.status, 200, JSON.stringify(made.body));
    assert.equal(made.body.output.access.authority, "owner");
    assert.equal(snapshotOf(A(), id2), JSON.stringify(WRITE));
  });

  test("NARROWING applies at once: a narrowed level refuses the call and can(); the row lists no offer (fires on bad: a snapshot-only reader keeps the old crud)", { timeout: 60_000 }, async () => {
    const id = await fresh();
    await setOwner(A(), id, "manage");
    assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE_PLUS_DELETE));
    assert.equal((await can(id)).output.can.delete, true, "quiet on good: before the update");
    await updated("manage", WRITE, async () => {
      const p = await purge(id);
      assert.equal(p.status, 403);
      assert.equal(p.body.error.code, "scope_denied");
      const c = await can(id);
      assert.equal(c.output.can.delete, false);
      assert.deepEqual(c.output.crud, WRITE);
      const row = await listed(A(), id);
      assert.deepEqual(row.crud, WRITE);
      assert.equal(row.offer, undefined, "narrowing is not an offer");
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE_PLUS_DELETE), "the stored snapshot is not rewritten by a read");
    });
    // the update is gone again: the row is what the owner set (snapshot ∩ level)
    assert.equal((await purge(id)).status, 200);
  });

  test("a level removed from the manifest gives []; the row keeps its level name and offers all of the level once it is back", { timeout: 60_000 }, async () => {
    const id = await fresh();
    await setOwner(A(), id, "write");
    const access = holder.manifest?.scopes?.[0]?.access;
    assert.ok(access);
    const i = access.findIndex((a) => a.id === "write");
    const [gone] = access.splice(i, 1);
    try {
      assert.deepEqual((await rowOf(A(), id))?.crud, []);
      assert.equal((await agentOp(b, "note_create", { notebook: id, title: "t" })).status, 403);
    } finally {
      access.splice(i, 0, gone as never);
    }
    assert.equal((await agentOp(b, "note_create", { notebook: id, title: "t" })).status, 200, "the level is back: the snapshot applies again");
  });

  test("a NULL, unparsable or non-array snapshot on an owner row reads [] in every reader and offers the whole level; only an explicit accept recovers it", { timeout: 60_000 }, async () => {
    const bads: (string | null)[] = [null, "", "{", "null", "{}", '"read"', "0", '{"0":"read"}', '["bogus"]', "[1,2]"];
    for (const bad of bads) {
      const id = await fresh();
      await setOwner(A(), id, "manage");
      raw((db) => db.prepare("UPDATE tb_scopes SET crud_snapshot = ? WHERE agent = ? AND type = 'notebook' AND instance_id = ?").run(bad, A(), id));
      const label = JSON.stringify(bad);
      const row = await rowOf(A(), id);
      assert.deepEqual(row?.crud, [], `fires on bad: ${label} must fail closed, never widen`);
      assert.equal(row?.authority, "owner");
      assert.deepEqual(row?.offer, { adds: WRITE_PLUS_DELETE }, `${label}: the whole level is offered`);
      const c = await agentOp(b, "note_create", { notebook: id, title: "t" });
      assert.equal(c.status, 403, label);
      assert.equal(c.body.error.code, "scope_denied", label);
      assert.equal((await purge(id)).body.error.code, "scope_denied", label);
      // a plain re-set keeps the corrupt value (it is not an accept); the explicit accept writes a fresh snapshot
      assert.equal((await setOwner(A(), id, "manage")).status, 200);
      assert.equal((await rowOf(A(), id))?.crud?.length, 0, `${label}: a plain re-set does not repair`);
      assert.equal((await setOwner(A(), id, "manage", { adds: WRITE_PLUS_DELETE })).status, 200, label);
      assert.equal(snapshotOf(A(), id), JSON.stringify(WRITE_PLUS_DELETE), label);
      assert.equal((await purge(id)).status, 200, label);
    }
  });

  test("BOUNDED rows are unchanged: no snapshot, no offer, the crud follows the level, the Portal grant stays the ceiling; every non-owner write path clears a snapshot", { timeout: 60_000 }, async () => {
    const id = await fresh();
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id, "write");
    assert.equal(snapshotOf(A(), id), null);
    await updated("write", WRITE_PLUS_DELETE, async () => {
      const row = await rowOf(A(), id);
      assert.equal(row?.authority, "bounded");
      assert.deepEqual(row?.crud, WRITE_PLUS_DELETE, "a bounded row is the level now");
      assert.equal(row?.offer, undefined, "bounded rows never offer");
      assert.equal((await purge(id)).body.error.code, "scope_denied", "the Portal grant (read, create) is the ceiling");
      const wide = await agentOp(b, "note_purge", { notebook: id }, { crud: WRITE_PLUS_DELETE });
      assert.equal(wide.status, 200, "inside the grant it runs");
      assert.equal((await receipts("note_purge")).find((r) => r.id === wide.body.receiptId)?.admittedBy, "portal_grant");
    });
    // owner row → ctx.scopeGrants and the store handle make it bounded and drop the snapshot
    const id2 = await fresh();
    await setOwner(A(), id2, "write");
    assert.ok(snapshotOf(A(), id2));
    assert.equal((await personOp(b, s, "draft_grant", { agent: A(), id: id2, access: "write" })).status, 200);
    assert.equal(snapshotOf(A(), id2), null, "fires on bad: an app row over an owner row must not keep the snapshot");
    const id3 = await fresh();
    await setOwner(A(), id3, "write");
    await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, A(), "notebook", id3, "write");
    assert.equal(snapshotOf(A(), id3), null, "the store handle writes a bounded row without a snapshot");
    assert.equal((await rowOf(A(), id3))?.authority, "bounded");
  });

  test("bestOf/rank order rows by their EFFECTIVE crud, not by the level now (a widened row does not win a spanning op)", { timeout: 60_000 }, async () => {
    const agent = b.w.agents.b;
    assert.equal((await agentOp(b, "note_create", { notebook: agent, title: "t" }, { agent })).status, 200, "first sight of agent B");
    for (const r of await b.running.scopes.list(agent as never)) await setOwner(agent, r.instanceId, "read");
    const id1 = await fresh();
    const id2 = await fresh();
    const levels = holder.manifest?.scopes?.[0]?.access;
    assert.ok(levels);
    levels.push({ id: "mid", label: "Mid", crud: [...WRITE] });
    try {
      await setOwner(agent, id1, "write");
      await setOwner(agent, id2, "mid");
      await updated("write", WRITE_PLUS_DELETE, async () => {
        // id1: level `write` is 4 actions now, its effective crud 3; id2: `mid` is 3. By the level id1 would win (4 > 3); by the effective crud id2 (same size, later in access[]).
        assert.equal((await b.running.scopes.best(agent as never, "notebook"))?.access, "mid");
        assert.equal((await rowOf(agent, id1))?.crud?.length, 3);
      });
    } finally {
      levels.pop();
    }
    // the rows of the later tests do not depend on these: put agent B's rows back to bounded defaults for isolation
    for (const r of await b.running.scopes.list(agent as never)) await b.running.scopes.set({ type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never, agent as never, "notebook", r.instanceId, "read");
  });

  test("DISPLAY marks follow the effective crud: catalog `admitted` and scope_summary `admittedOps` (fires on bad: the level's crud would mark the widened delete)", { timeout: 60_000 }, async () => {
    const agent = b.w.agents.b;
    assert.equal((await agentOp(b, "note_can", { notebook: agent }, { agent })).status, 200, "agent B has been seen (its rows exist)");
    await fresh();
    const mine = async () => b.running.scopes.list(agent as never);
    for (const r of await mine()) assert.equal((await setOwner(agent, r.instanceId, "write")).status, 200);
    const marks = async () => {
      const cat = await bridgeOp(b, "catalog", { op: "tools", agent });
      const sum = await bridgeOp(b, "scope_summary", {});
      const forB = sum.body.find((x: { agent: string }) => x.agent === agent);
      const adm = (name: string) => (cat.body as DynamicCatalogEntry[]).find((e) => e.name === name)?.admitted;
      return { read: adm("read_item"), write: adm("write_item"), del: adm("delete_item"), ops: [...(forB.admittedOps ?? [])].sort() as string[] };
    };
    const before = await marks();
    assert.deepEqual([before.read, before.write, before.del], ["owner", "owner", undefined]);
    assert.deepEqual(before.ops, ["note_can", "note_create"]);
    await updated("write", WRITE_PLUS_DELETE, async () => {
      const widened = await marks();
      assert.equal(widened.del, undefined, "the widened level is only an offer: delete_item is not marked");
      assert.deepEqual(widened.ops, ["note_can", "note_create"], "note_purge is not admitted by the widened level");
      for (const r of await mine()) assert.deepEqual(r.offer, { adds: ["delete"] });
      for (const r of await mine()) assert.equal((await setOwner(agent, r.instanceId, "write", { adds: ["delete"] })).status, 200);
      const accepted = await marks();
      assert.equal(accepted.del, "owner", "after the owner accepted the offer the mark follows");
      assert.deepEqual(accepted.ops, ["note_can", "note_create", "note_purge"]);
    });
    // back to the original manifest: the accepted rows are the level again (snapshot ∩ level)
    const after = await marks();
    assert.equal(after.del, undefined);
    assert.deepEqual(after.ops, ["note_can", "note_create"]);
  });
});

// ── schema 10 (spec text: "schema 9") sdk_scope_crud_snapshot: the one-time backfill ─────────────────────────────────────────────
describe("C283b/c: SDK schema 10 sdk_scope_crud_snapshot (backfill, once, audited)", { timeout: 60_000 }, () => {
  const sha = (text: string) => createHash("sha256").update(text).digest("hex");
  const CRUD4: ("read" | "create" | "update" | "delete")[] = ["read", "create", "update", "delete"];
  /** a database exactly as SDK 0.1.35 left it: the migrations up to schema 9 */
  function schema9(dir: string): DatabaseSync {
    const db = openDb(dir);
    for (const m of SDK_MIGRATIONS.filter((x) => x.version <= 9)) {
      db.exec(m.sql);
      db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('sdk', ?, ?, ?, ?)").run(m.version, m.name, sha(m.sql), Date.now());
    }
    return db as unknown as DatabaseSync;
  }
  function fill(db: DatabaseSync): void {
    for (const id of ["a", "b", "c", "d"]) db.prepare("INSERT INTO tb_scope_instances (type, id, label, shared, created_at) VALUES ('notebook', ?, ?, 0, 1)").run(id, id);
    const ins = db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES (?, 'notebook', ?, ?, ?, ?)");
    ins.run("agt_o_manage", "a", "manage", "owner", "owner");
    ins.run("agt_o_write", "b", "write", "owner", "owner");
    ins.run("agt_o_gone", "c", "retired_level", "owner", "owner"); // a level the manifest does not have
    ins.run("agt_bounded", "a", "manage", "owner", "bounded");
    ins.run("agt_app", "d", "write", "app", "bounded");
  }
  const person = { type: "person", id: "per_x", ws: "ws_x", instance: "ins_x" } as unknown as PersonPrincipal;

  test("a schema-9 DB: every OWNER row gets the snapshot of its level in the manifest that runs it, with one audit line each; bounded rows keep NULL", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = schema9(t.dir);
      assert.equal(storedSchema(db as never).sdk, 9);
      fill(db);
      const m = manifestFor(1);
      const applied = applySdkMigrations(db as never, undefined, { manifest: m });
      assert.deepEqual(applied.map((x) => `${x.version}:${x.name}`), ["10:sdk_scope_crud_snapshot"]);
      assert.equal(SDK_SCHEMA, 10);
      const rows = (db.prepare("SELECT agent, crud_snapshot AS c FROM tb_scopes ORDER BY agent").all() as { agent: string; c: string | null }[]).map((r) => ({ agent: r.agent, c: r.c }));
      assert.deepEqual(rows, [
        { agent: "agt_app", c: null },
        { agent: "agt_bounded", c: null },
        { agent: "agt_o_gone", c: "[]" },
        { agent: "agt_o_manage", c: JSON.stringify(CRUD4) },
        { agent: "agt_o_write", c: JSON.stringify(["read", "create", "update"]) },
      ]);
      const audit = (db.prepare("SELECT actor, action, target, detail FROM tb_audit WHERE action = 'scope.snapshot_backfill' ORDER BY target").all() as { actor: string; action: string; target: string; detail: string }[]).map((e) => ({ ...e, detail: JSON.parse(e.detail) }));
      assert.deepEqual(audit, [
        { actor: "system", action: "scope.snapshot_backfill", target: "agt_o_gone", detail: { type: "notebook", instance: "c", level: "retired_level", crud: [] } },
        { actor: "system", action: "scope.snapshot_backfill", target: "agt_o_manage", detail: { type: "notebook", instance: "a", level: "manage", crud: CRUD4 } },
        { actor: "system", action: "scope.snapshot_backfill", target: "agt_o_write", detail: { type: "notebook", instance: "b", level: "write", crud: ["read", "create", "update"] } },
      ]);
      // through the store: effective crud = snapshot ∩ level; no offer right after the backfill
      const st = createScopeStore(db as never, m, createAuditLog(db as never, []), () => {});
      assert.deepEqual((await st.access("agt_o_write" as never, "notebook", "b"))?.crud, ["read", "create", "update"]);
      assert.equal((await st.access("agt_o_write" as never, "notebook", "b"))?.offer, undefined);
      assert.deepEqual((await st.access("agt_o_gone" as never, "notebook", "c"))?.crud, []);
      assert.deepEqual((await st.access("agt_bounded" as never, "notebook", "a"))?.crud, CRUD4, "bounded: the level");
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("a widening shipped in the SAME update as the first 0.1.36 boot is baked in (no older record exists): the backfill uses the manifest that runs it", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = schema9(t.dir);
      fill(db);
      const m = manifestFor(1);
      const lvl = m.scopes?.[0]?.access.find((a) => a.id === "write");
      assert.ok(lvl);
      lvl.crud = [...CRUD4];
      applySdkMigrations(db as never, undefined, { manifest: m });
      assert.equal((db.prepare("SELECT crud_snapshot AS c FROM tb_scopes WHERE agent = 'agt_o_write'").get() as { c: string }).c, JSON.stringify(CRUD4));
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("ONCE: a second run backfills nothing; a NULL snapshot afterwards stays NULL and reads [] (fires on bad: a boot-time backfill would widen a corrupted row)", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = schema9(t.dir);
      fill(db);
      const m = manifestFor(1);
      applySdkMigrations(db as never, undefined, { manifest: m });
      const count = () => (db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'scope.snapshot_backfill'").get() as { n: number }).n;
      assert.equal(count(), 3);
      db.prepare("UPDATE tb_scopes SET crud_snapshot = NULL WHERE agent = 'agt_o_manage'").run();
      assert.deepEqual(applySdkMigrations(db as never, undefined, { manifest: m }), [], "nothing pending");
      assert.equal(count(), 3, "no second audit round");
      assert.equal((db.prepare("SELECT crud_snapshot AS c FROM tb_scopes WHERE agent = 'agt_o_manage'").get() as { c: string | null }).c, null, "still NULL");
      const st = createScopeStore(db as never, m, createAuditLog(db as never, []), () => {});
      const row = await st.access("agt_o_manage" as never, "notebook", "a");
      assert.deepEqual(row?.crud, []);
      assert.deepEqual(row?.offer, { adds: CRUD4 });
      assert.equal(st.resolve("agt_o_manage", "notebook", "a")?.crud.length, 0);
      assert.equal(st.ownerAdmits("agt_o_manage", "notebook", ["read"]), false);
      // every reader of ScopeAccessView
      const view = st.view("agt_o_manage", null);
      assert.deepEqual(await view.readable("notebook"), []);
      assert.deepEqual(await view.writable("notebook"), []);
      assert.equal(await view.can("notebook", "a", "read"), false);
      assert.deepEqual((await st.best("agt_o_manage" as never, "notebook"))?.crud, []);
      assert.deepEqual((await st.list("agt_o_manage" as never)).map((r) => r.crud), [[]]);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("owner rows and NO manifest: the migration refuses (sdk_migration_context) and rolls back whole; without owner rows it needs no manifest", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = schema9(t.dir);
      fill(db);
      assert.throws(
        () => applySdkMigrations(db as never),
        (e: unknown) => (e as { code?: string }).code === "sdk_migration_context",
      );
      assert.equal(storedSchema(db as never).sdk, 9, "the migration is not recorded");
      assert.equal((db.prepare("PRAGMA table_info(tb_scopes)").all() as { name: string }[]).some((c) => c.name === "crud_snapshot"), false, "the ALTER rolled back with it");
      assert.equal((db.prepare("SELECT count(*) AS n FROM tb_scopes WHERE authority = 'owner'").get() as { n: number }).n, 3, "owner rows untouched");
      db.close();
      const t2 = tempDir();
      try {
        const db2 = schema9(t2.dir);
        db2.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES ('agt_b', 'notebook', 'a', 'read', 'default', 'bounded')").run();
        assert.deepEqual(applySdkMigrations(db2 as never).map((x) => x.version), [10]);
        db2.close();
      } finally {
        t2.cleanup();
      }
    } finally {
      t.cleanup();
    }
  });

  test("startApp upgrades a schema-9 data dir: the owner row is backfilled from the booting manifest, audited, and keeps its crud", { timeout: 60_000 }, async () => {
    const t = tempDir("tb-c283c-up-");
    const data = join(t.dir, "data");
    try {
      const db = schema9(data);
      db.prepare("INSERT INTO tb_scope_instances (type, id, label, shared, created_at) VALUES ('notebook', 'x', 'X', 0, 1)").run();
      db.prepare("INSERT INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES ('agt_owner_row', 'notebook', 'x', 'write', 'owner', 'owner')").run();
      db.close();
      const port = await freePort();
      const running = await startApp(testApp(port, migrationsDir(join(t.dir, "code"))), { TB_DATA_DIR: data, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" }, { privilegeProc: { getuid: () => 4242 } }).catch((e) => {
        throw new Error(`${e.message} ${JSON.stringify(e.details)}`);
      });
      try {
        const row = await running.scopes.access("agt_owner_row" as never, "notebook", "x");
        assert.equal(row?.authority, "owner");
        assert.deepEqual(row?.crud, ["read", "create", "update"], "fires on bad: a boot that did not pass the manifest would leave [] (or throw)");
        assert.equal(row?.offer, undefined);
        const audit = (await running.audit.list({ action: "scope.snapshot_backfill" })).items;
        assert.equal(audit.length, 1);
        assert.deepEqual(audit[0]?.detail, { type: "notebook", instance: "x", level: "write", crud: ["read", "create", "update"] });
        const h = (await (await fetch(`http://127.0.0.1:${port}/tb/v1/health`)).json()) as { schemaVersion?: { sdk: number } };
        assert.equal(h.schemaVersion?.sdk, SDK_SCHEMA);
      } finally {
        await running.stop();
      }
      // a second boot backfills nothing
      const again = await startApp(testApp(await freePort(), migrationsDir(join(t.dir, "code"))), { TB_DATA_DIR: data, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" }, { privilegeProc: { getuid: () => 4242 } });
      try {
        assert.equal((await again.audit.list({ action: "scope.snapshot_backfill" })).items.length, 1);
      } finally {
        await again.stop();
      }
    } finally {
      t.cleanup();
    }
  });

  test("the migration is additive and forward-only: one ADD COLUMN, no DROP / UPDATE / DELETE in its sql, versions strictly increasing", { timeout: 60_000 }, () => {
    const m = SDK_MIGRATIONS.find((x) => x.name === "sdk_scope_crud_snapshot");
    assert.ok(m);
    assert.equal(m.version, 10);
    assert.match(m.sql, /^ALTER TABLE tb_scopes ADD COLUMN crud_snapshot TEXT;$/);
    assert.doesNotMatch(m.sql, /DROP|UPDATE|DELETE/i);
    assert.equal(typeof m.after, "function", "the backfill is a code step inside the same transaction");
    const versions = SDK_MIGRATIONS.map((x) => x.version);
    assert.deepEqual(versions, [...versions].sort((a, b) => a - b));
    assert.equal(new Set(versions).size, versions.length);
  });

  test("ownerSet at the store level: snapshot at write, kept by a plain re-set, new for another level; the public store handle and app grants write NULL", { timeout: 60_000 }, async () => {
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db as never);
      const m = manifestFor(1);
      const st = createScopeStore(db as never, m, createAuditLog(db as never, []), () => {});
      await st.instances.create("notebook", "x", "X");
      const snap = () => (db.prepare("SELECT crud_snapshot AS c FROM tb_scopes WHERE agent = 'agt_1'").get() as { c: string | null } | undefined)?.c;
      const ops = scopeGrantOps(st);
      await ops.ownerSet(person, "agt_1", "notebook", "x", "write");
      assert.equal(snap(), JSON.stringify(["read", "create", "update"]));
      const lvl = m.scopes?.[0]?.access.find((a) => a.id === "write");
      assert.ok(lvl);
      lvl.crud = [...CRUD4];
      await ops.ownerSet(person, "agt_1", "notebook", "x", "write");
      assert.equal(snap(), JSON.stringify(["read", "create", "update"]), "a plain re-set keeps it");
      await ops.ownerSet(person, "agt_1", "notebook", "x", "manage");
      assert.equal(snap(), JSON.stringify(CRUD4), "another level: that level's crud now");
      await ops.ownerSet(person, "agt_1", "notebook", "x", "write");
      assert.equal(snap(), JSON.stringify(CRUD4), "another level again (manage -> write): write's crud now, which the update widened to 4");
      await assert.rejects(ops.ownerSet(person, "agt_1", "notebook", "x", "manage", { adds: [] }), (e: unknown) => (e as { code?: string }).code === "input_invalid", "acceptOffer for another level is not an accept");
      await st.set(person, "agt_1" as never, "notebook", "x", "write");
      assert.equal(snap(), null, "the store handle writes a bounded row");
      await assert.rejects(ops.ownerSet(person, "agt_1", "notebook", "x", "write", { adds: ["nope" as never] }), (e: unknown) => (e as { code?: string }).code === "input_invalid");
      await assert.rejects(st.set(person, "agt_1" as never, "notebook", "x", "write").then(() => ops.ownerSet(person, "agt_1", "notebook", "x", null, { adds: [] })), (e: unknown) => (e as { code?: string }).code === "input_invalid");
      db.close();
    } finally {
      t.cleanup();
    }
  });
});
