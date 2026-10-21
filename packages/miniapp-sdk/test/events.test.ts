// v0.1.38 (C274c/C274d, spec 0.1.57, SDK-API §20): ctx.emit / ctx.purgeEvents into the transactional outbox (SDK schema 11), the
// sender (only with the `events` cap, in order, retry with the same key, refused → dropped), `eligible` at send time, purge rows on
// scope-row removal / narrowing / owner→bounded, tb.hold.decided (decide + expiry, agent callers only), and the attention order.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { ulid } from "@opt2-tealbrick/manifest";
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, Logger, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { EventOutbox } from "../src/server/events.ts";
import { decideHold, defineApp, type SdkOpContext, startApp } from "../src/server/index.ts";
import { createLogger, SecretRegistry } from "../src/server/log.ts";
import { HOLD_TTL_MS } from "../src/server/receipts.ts";
import { type ScopeStoreInternals, scopeGrantOps } from "../src/server/scopes.ts";
import { pickAttention } from "../src/server/status.ts";
import { appDb, openStore, type RawDb } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const T = { timeout: 60_000 };
const AGT = `agt_${ulid()}` as AgentId;

function eventsManifest(port: number, over: Partial<Manifest> = {}): Manifest {
  const m = fixtureManifest(port);
  m.operations.push(
    { id: "ev_probe", title: "Probe", description: "Event probe.", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: false, audience: "person" },
    { id: "ev_agent", title: "Agent emit", description: "Agent emit.", input: { type: "object" }, output: { type: "object" }, crud: ["read"], effect: "read", idempotency: "none", receipt: false, audience: "agent" },
  );
  m.events = [
    // scoped (note_create has scopeType notebook): reaches agents whose row admits create
    { name: "note.created", title: "A note was created", payloadSchema: { type: "object", additionalProperties: false, required: ["noteId"], properties: { noteId: { type: "string" } } }, visibleWith: "note_create", audience: "granted" },
    // unscoped, target
    { name: "note.pinged", title: "Ping", payloadSchema: { type: "object", properties: { n: { type: "integer" } } }, visibleWith: "note_get", audience: "target" },
  ];
  return { ...m, ...over };
}

const silent: Logger = createLogger("error", new SecretRegistry(), { product: PRODUCT });

/** a store + outbox without HTTP (validation and transaction rules) */
function unit(over: Partial<Manifest> = {}): { db: RawDb; ob: EventOutbox; rows(): { kind: string; key: string; body: Record<string, unknown> }[]; cleanup(): void } {
  const t = tempDir();
  const db = openStore(t.dir);
  const ob = new EventOutbox(db, eventsManifest(0, over), silent);
  return {
    db,
    ob,
    rows: () => (db.prepare("SELECT kind, key, body FROM tb_event_outbox ORDER BY id").all() as { kind: string; key: string; body: string }[]).map((r) => ({ kind: r.kind, key: r.key, body: JSON.parse(r.body) })),
    cleanup: () => {
      db.close();
      t.cleanup();
    },
  };
}

const codeOf = (fn: () => void): string => {
  try {
    fn();
  } catch (e) {
    return (e as { code?: string }).code ?? "thrown";
  }
  return "none";
};

describe("ctx.emit validation and the outbox row (SDK-API §20)", () => {
  test("every refusal throws TbError 400 with its code and writes nothing (one valid emit at the end writes one row)", () => {
    const u = unit();
    try {
      const emit = u.ob.emitFn();
      const subject = { kind: "note", id: "n1" };
      assert.equal(codeOf(() => emit("note.unknown", {}, { subject })), "event_undeclared");
      assert.equal(codeOf(() => emit("tb.hold.decided", { holdId: `hld_${ulid()}`, op: "note_get", decision: "approved" }, { subject, to: [AGT] })), "event_reserved");
      assert.equal(codeOf(() => emit("tb.anything", {}, { subject })), "event_reserved");
      assert.equal(codeOf(() => emit("note.created", { noteId: 1 }, { subject, instanceId: "nb" })), "event_payload_invalid");
      assert.equal(codeOf(() => emit("note.created", { noteId: "x".repeat(3000) }, { subject, instanceId: "nb" })), "event_too_large");
      assert.equal(codeOf(() => emit("note.created", { noteId: "n" }, { subject, instanceId: "nb", summary: "s".repeat(281) })), "event_too_large");
      assert.equal(codeOf(() => emit("note.created", { noteId: "n" }, { subject, instanceId: "nb", key: "short" })), "event_payload_invalid");
      assert.equal(codeOf(() => emit("note.created", { noteId: "n" }, { subject })), "event_instance_invalid", "scoped needs instanceId");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject, to: [AGT], instanceId: "nb" })), "event_instance_invalid", "unscoped refuses one");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject })), "event_target_invalid");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject, to: [] })), "event_target_invalid");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject, to: Array.from({ length: 101 }, () => `agt_${ulid()}` as AgentId) })), "event_target_invalid");
      assert.equal(codeOf(() => emit("note.created", { noteId: "n" }, { subject, instanceId: "nb", to: [AGT] })), "event_target_invalid", "granted refuses to");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject: { kind: "Note", id: "n" }, to: [AGT] })), "event_payload_invalid");
      // the whole wire item without eligible > 4 KiB (specs#33 round 2): 100 agents in `to`, a full summary and some data
      const many = Array.from({ length: 100 }, () => `agt_${ulid()}` as AgentId);
      assert.equal(codeOf(() => emit("note.pinged", { n: 1, pad: "p".repeat(600) }, { subject, to: many, summary: "s".repeat(280), key: "k".repeat(128) })), "event_too_large");
      // the same event with a short to list fits
      assert.equal(codeOf(() => emit("note.pinged", { n: 1, pad: "p".repeat(600) }, { subject, to: many.slice(0, 10), summary: "s".repeat(280), key: "k".repeat(128) })), "none");
      assert.equal(codeOf(() => emit("note.pinged", {}, { subject: { kind: "note", id: "" }, to: [AGT] })), "event_payload_invalid");
      assert.equal(u.rows().length, 1, "only the one that fits");
    } finally {
      u.cleanup();
    }
  });

  test("a valid emit writes one row: default key = a NEW ULID (not the row id), untrusted copied, causedBy from the origin only", () => {
    const u = unit();
    try {
      u.ob.emitFn({ causedBy: AGT })("note.pinged", { n: 1 }, { subject: { kind: "note", id: "n1" }, to: [AGT], summary: "Alice: hi", untrusted: true });
      u.ob.emitFn()("note.created", { noteId: "n2" }, { subject: { kind: "note", id: "n2" }, instanceId: "nb", key: "app-key-0001" });
      const [a, b] = u.rows();
      assert.equal(a?.kind, "emit");
      assert.match(String(a?.key), /^[0-9A-HJKMNP-TV-Z]{26}$/);
      const rowId = (u.db.prepare("SELECT id FROM tb_event_outbox ORDER BY id LIMIT 1").get() as { id: string }).id;
      assert.notEqual(a?.key, rowId);
      assert.equal(a?.body.untrusted, true);
      assert.equal(a?.body.causedBy, AGT);
      assert.deepEqual(a?.body.to, [AGT]);
      assert.equal(b?.key, "app-key-0001");
      assert.equal(b?.body.causedBy, undefined);
      assert.equal(b?.body.instanceId, "nb");
      assert.equal(b?.body.eligible, undefined, "eligible is computed at SEND time");
    } finally {
      u.cleanup();
    }
  });

  test("the row shares only its transaction's fate: rolled back → gone; committed then the code throws → kept", () => {
    const u = unit();
    try {
      const app = appDb(u.db);
      const emit = u.ob.emitFn();
      assert.throws(() =>
        app.transaction(() => {
          emit("note.pinged", { n: 1 }, { subject: { kind: "note", id: "a" }, to: [AGT] });
          throw new Error("rollback");
        }),
      );
      assert.equal(u.rows().length, 0);
      const handler = () => {
        app.transaction(() => emit("note.pinged", { n: 2 }, { subject: { kind: "note", id: "b" }, to: [AGT] }));
        throw new Error("after commit");
      };
      assert.throws(handler);
      assert.equal(u.rows().length, 1);
      // outside a transaction an emit is its own write
      emit("note.pinged", { n: 3 }, { subject: { kind: "note", id: "c" }, to: [AGT] });
      assert.equal(u.rows().length, 2);
    } finally {
      u.cleanup();
    }
  });

  test("a manifest with id tb: every app emit is event_reserved", () => {
    const u = unit({ id: "tb" });
    try {
      assert.equal(codeOf(() => u.ob.emitFn()("note.pinged", {}, { subject: { kind: "note", id: "a" }, to: [AGT] })), "event_reserved");
    } finally {
      u.cleanup();
    }
  });

  test("purgeEvents writes one all-agent purge row; rowNarrowed for agent rows of EVERY scope type (specs#33), never app callers", () => {
    const u = unit();
    try {
      u.ob.purgeFn()("nb");
      u.ob.rowNarrowed(AGT, "notebook", "nb");
      u.ob.rowNarrowed(`ins_${ulid()}`, "notebook", "nb");
      u.ob.rowNarrowed(AGT, "other_type", "nb2");
      const rows = u.rows();
      assert.equal(rows.length, 3);
      assert.deepEqual({ ...rows[2]?.body, key: "k" }, { kind: "purge", key: "k", agent: AGT, instanceId: "nb2" });
      assert.deepEqual({ ...rows[0]?.body, key: "k" }, { kind: "purge", key: "k", instanceId: "nb" });
      assert.deepEqual({ ...rows[1]?.body, key: "k" }, { kind: "purge", key: "k", agent: AGT, instanceId: "nb" });
      assert.equal(codeOf(() => u.ob.purgeFn()("")), "event_instance_invalid");
    } finally {
      u.cleanup();
    }
  });

  test("tb.hold.decided goes to an AGENT caller only (app callers receive no events in v1); platform data is validated", () => {
    const u = unit();
    try {
      const holdId = `hld_${ulid()}`;
      u.ob.holdDecided({ id: holdId, op: "note_delete", caller: { type: "app", id: `ins_${ulid()}` } }, "approved");
      assert.equal(u.rows().length, 0);
      u.ob.holdDecided({ id: holdId, op: "note_delete", caller: { type: "agent", id: AGT } }, "expired");
      const [r] = u.rows();
      assert.deepEqual(r?.body.data, { holdId, op: "note_delete", decision: "expired" });
      assert.deepEqual(r?.body.to, [AGT]);
      assert.equal(r?.body.name, "tb.hold.decided");
      assert.equal(codeOf(() => u.ob.emitPlatform("tb.hold.decided", { holdId: "bad", op: "x", decision: "approved" }, { subject: { kind: "hold", id: "h" }, to: [AGT] })), "event_payload_invalid");
      assert.equal(codeOf(() => u.ob.emitPlatform("note.pinged", {}, { subject: { kind: "hold", id: "h" }, to: [AGT] })), "event_undeclared", "the platform path emits only PLATFORM_EVENTS");
    } finally {
      u.cleanup();
    }
  });

  test("pickAttention: a backup attention is never hidden by the app's; jobs come last", () => {
    const backup = { code: "backup_failed", reason: "The last backup failed." };
    const app = { code: "engine_missing", reason: "No engine." };
    const jobs = { code: "jobs_failed", reason: "1 job failed" };
    assert.equal(pickAttention({ backup, app, jobs })?.code, "backup_failed");
    assert.equal(pickAttention({ backup: { code: "backup_overdue", reason: "x" }, app, jobs })?.code, "backup_overdue");
    assert.equal(pickAttention({ backup: null, app, jobs })?.code, "engine_missing");
    assert.equal(pickAttention({ backup: null, app: null, jobs })?.code, "jobs_failed");
    assert.equal(pickAttention({ backup: null, app: null, jobs: null }), null);
  });
});

// ── over HTTP: the sender, eligible, purges, tb.hold.decided ─────────────────

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dir: string;
  push(over?: Parameters<typeof slice>[2]): Promise<void>;
  cleanup(): Promise<void>;
}

const probe: { ctx?: SdkOpContext } = {};

async function boot(caps: string[] | undefined): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const app = defineApp({
    manifest: eventsManifest(port),
    migrations: migrationsDir(t.dir),
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      ev_probe: async (_input, c) => {
        probe.ctx = c as SdkOpContext;
        return {};
      },
      ev_agent: async (input, c) => {
        const ctx = c as SdkOpContext;
        ctx.emit?.("note.pinged", { n: Number((input as { n?: number }).n ?? 0) }, { subject: { kind: "note", id: "a" }, to: [w.agents.b] });
        return {};
      },
    },
  });
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, caps ? { bridgeCaps: caps } : {}));
  const running = await startApp(
    app,
    { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
    { ...testRoots(w), port, jobs: { pollMs: 40, drainMs: 300 } },
  );
  await until(async () => running.status() === "ok");
  return {
    w,
    bridge,
    running,
    base: `http://127.0.0.1:${port}`,
    dir: t.dir,
    async push(over = {}) {
      const before = bridge.statuses.length;
      bridge.push(await slice(w, PRODUCT, over));
      await until(async () => bridge.statuses.length > before && (bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === w.rev);
    },
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function agentOp(b: Booted, op: string, input: Json, agent: AgentId = b.w.agents.a, held: ("destructive")[] = []) {
  const g = await grant(b.w, agent, { held });
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: `k_${ulid()}` }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

const emitsOf = (b: Booted) => b.bridge.storedEvents.filter((x) => x.kind === "emit");
const ctx = (): SdkOpContext => {
  if (!probe.ctx) throw new Error("no probe context");
  return probe.ctx;
};

describe("the outbox sender over HTTP (fake bridge)", T, () => {
  let b: Booted;
  before(async () => {
    b = await boot(["owner_rows"]);
  });
  after(async () => b.cleanup());

  test("without the events cap nothing is sent; the cap appears → the backlog goes in emit order, assertion-signed", T, async () => {
    // a person op context to emit from (the probe stores its ctx; emit is synchronous and works after the op too)
    const scopes = b.running.scopes as ScopeStoreInternals;
    await scopes.instances.create("notebook", "nb1", "Notebook 1");
    const emit = (await personCtx(b)).emit as NonNullable<SdkOpContext["emit"]>;
    for (let i = 0; i < 3; i++) emit("note.pinged", { n: i }, { subject: { kind: "note", id: `p${i}` }, to: [b.w.agents.a], key: `order-key-${i}` });
    await new Promise((r) => setTimeout(r, 400));
    assert.equal(b.bridge.eventPosts.length, 0, "no events cap: rows wait");
    await b.push({ bridgeCaps: ["owner_rows", "events"] });
    await until(async () => emitsOf(b).length >= 3);
    assert.deepEqual(
      emitsOf(b).map((x) => x.key),
      ["order-key-0", "order-key-1", "order-key-2"],
    );
    assert.ok(b.bridge.eventPosts.every((p) => p.assertOk), "every POST carries a valid instance assertion (htm, htu, bd)");
    await until(async () => countOutbox(b) === 0);
  });

  test("503 then retry: the same key is sent again and stored once; refused → dropped (not retried)", T, async () => {
    let fails = 1;
    b.bridge.onEvents = () => (fails-- > 0 ? { status: 503, body: { error: { code: "app_not_claimed", message: "x", requestId: "r" } } } : null);
    const before = b.bridge.eventPosts.length;
    const emit = ctx().emit as NonNullable<SdkOpContext["emit"]>;
    emit("note.pinged", { n: 9 }, { subject: { kind: "note", id: "r" }, to: [b.w.agents.a], key: "retry-key-0001" });
    await until(async () => emitsOf(b).some((x) => x.key === "retry-key-0001"), 10_000);
    const posts = b.bridge.eventPosts.slice(before).filter((p) => p.items.some((i) => i.key === "retry-key-0001"));
    assert.ok(posts.length >= 2, "the batch was sent again after the 503");
    assert.equal(emitsOf(b).filter((x) => x.key === "retry-key-0001").length, 1);
    b.bridge.onEvents = (items) => ({ status: 200, body: { results: items.map((i) => ({ key: i.key, status: "refused", code: "event_undeclared" })) } });
    emit("note.pinged", { n: 10 }, { subject: { kind: "note", id: "r" }, to: [b.w.agents.a], key: "refused-key-01" });
    await until(async () => b.bridge.eventPosts.some((p) => p.items.some((i) => i.key === "refused-key-01")));
    await until(async () => countOutbox(b) === 0);
    b.bridge.onEvents = null;
  });

  test("causedBy = the verified agent caller; a handler emit inside an agent call", T, async () => {
    const r = await agentOp(b, "ev_agent", { n: 5 });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    await until(async () => emitsOf(b).some((x) => (x.data as { n?: number }).n === 5));
    const e = emitsOf(b).find((x) => (x.data as { n?: number }).n === 5);
    assert.equal(e?.causedBy, b.w.agents.a);
  });

  test("scoped: eligible = agents whose row admits visibleWith.crud, with the row's authority (owner above the grant listed as owner)", T, async () => {
    const scopes = b.running.scopes as ScopeStoreInternals;
    const principal = { type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never;
    await scopes.set(principal, b.w.agents.a, "notebook", "nb1", "read_write"); // bounded, admits create
    await scopeGrantOps(scopes).ownerSet(principal, b.w.agents.b, "notebook", "nb1", "read_write"); // owner
    const third = `agt_${ulid()}` as AgentId;
    await scopes.set(principal, third, "notebook", "nb1", "read"); // read only: does not admit create
    const emit = ctx().emit as NonNullable<SdkOpContext["emit"]>;
    emit("note.created", { noteId: "n1" }, { subject: { kind: "note", id: "n1" }, instanceId: "nb1", key: "scoped-key-001" });
    await until(async () => emitsOf(b).some((x) => x.key === "scoped-key-001"));
    const e = emitsOf(b).find((x) => x.key === "scoped-key-001");
    const eligible = ((e?.eligible ?? []) as { agent: string; authority: string }[]).slice().sort((x, y) => x.agent.localeCompare(y.agent));
    const want = [
      { agent: b.w.agents.a, authority: "bounded" },
      { agent: b.w.agents.b, authority: "owner" },
    ].sort((x, y) => x.agent.localeCompare(y.agent));
    assert.deepEqual(eligible, want);
  });

  test("purge: a removal, a narrowing and owner→bounded each send a purge after the earlier events; purgeEvents = all agents", T, async () => {
    const scopes = b.running.scopes as ScopeStoreInternals;
    const principal = { type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never;
    const emit = ctx().emit as NonNullable<SdkOpContext["emit"]>;
    const at = () => b.bridge.storedEvents.length;
    emit("note.created", { noteId: "n2" }, { subject: { kind: "note", id: "n2" }, instanceId: "nb1", key: "before-purge-1" });
    const ownerOps = scopeGrantOps(scopes);
    await ownerOps.ownerSet(principal, b.w.agents.b, "notebook", "nb1", "read"); // owner row narrowed read_write → read
    await scopes.set(principal, b.w.agents.b, "notebook", "nb1", "read"); // owner → bounded (same crud)
    await scopes.set(principal, b.w.agents.a, "notebook", "nb1", null); // removed
    await scopes.set(principal, b.w.agents.a, "notebook", "nb1", null); // nothing to remove: no purge
    ctx().purgeEvents?.("nb1");
    const start = at();
    await until(async () => b.bridge.storedEvents.filter((x) => x.kind === "purge").length >= 4);
    const purges = b.bridge.storedEvents.filter((x) => x.kind === "purge").map((x) => `${String(x.agent ?? "*")}:${String(x.instanceId)}`);
    assert.deepEqual(purges, [`${b.w.agents.b}:nb1`, `${b.w.agents.b}:nb1`, `${b.w.agents.a}:nb1`, "*:nb1"]);
    const keys = b.bridge.storedEvents.map((x) => x.key);
    assert.ok(keys.indexOf("before-purge-1") < keys.indexOf(b.bridge.storedEvents.find((x) => x.kind === "purge")?.key), "the purge drains after the earlier event");
    assert.ok(start >= 0);
    // a re-set that widens or keeps the row sends no purge
    const n = b.bridge.storedEvents.length;
    await scopes.set(principal, b.w.agents.a, "notebook", "nb1", "read_write");
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(b.bridge.storedEvents.length, n);
  });

  test("tb.hold.decided: approve and deny to the AGENT caller; expiry from the sweep", T, async () => {
    const del = async (agent: AgentId) => agentOp(b, "note_delete", { id: `x${ulid()}` }, agent, ["destructive"]);
    const principal = { type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins } as never;
    const h1 = await del(b.w.agents.a);
    const h2 = await del(b.w.agents.a);
    const h3 = await del(b.w.agents.b);
    for (const h of [h1, h2, h3]) assert.equal(h.status, 202, JSON.stringify(h.body));
    await decideHold(principal, { holdId: h1.body.holdId, decision: "approve" });
    await decideHold(principal, { holdId: h2.body.holdId, decision: "deny" });
    // expiry: the sweep at a time past the TTL
    const receipts = b.running.receipts as unknown as { sweep(now: number): { expired: number } };
    assert.ok(receipts.sweep(Date.now() + HOLD_TTL_MS + 1000).expired >= 1);
    const decided = () => emitsOf(b).filter((x) => x.name === "tb.hold.decided");
    await until(async () => decided().length >= 3);
    const by = (id: string) => decided().find((x) => (x.data as { holdId: string }).holdId === id);
    assert.deepEqual(by(h1.body.holdId)?.data, { holdId: h1.body.holdId, op: "note_delete", decision: "approved" });
    assert.deepEqual(by(h2.body.holdId)?.to, [b.w.agents.a]);
    assert.equal((by(h2.body.holdId)?.data as { decision?: string } | undefined)?.decision, "denied");
    assert.equal((by(h3.body.holdId)?.data as { decision?: string } | undefined)?.decision, "expired");
    assert.deepEqual(by(h3.body.holdId)?.subject, { kind: "hold", id: h3.body.holdId });
    assert.equal(by(h3.body.holdId)?.summary, undefined);
  });
});

/** a person op context (the probe op) to emit from */
async function personCtx(b: Booted): Promise<SdkOpContext> {
  const { ticket } = await import("./helpers.ts");
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, "/configure") }),
  });
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  const r = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/ev_probe`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input: {} }),
  });
  assert.equal(r.status, 200);
  return ctx();
}

/** rows still in the app's outbox (a second read-only connection; WAL) */
function countOutbox(b: Booted): number {
  const db = new DatabaseSync(join(b.dir, "app.db"), { readOnly: true });
  try {
    return Number((db.prepare("SELECT COUNT(*) AS n FROM tb_event_outbox").get() as { n: number }).n);
  } finally {
    db.close();
  }
}

describe("outbox prune and an app without a bridge", () => {
  test("unsent rows older than 7 days are pruned by the sender", T, async () => {
    const u = unit();
    try {
      u.ob.emitFn()("note.pinged", { n: 1 }, { subject: { kind: "note", id: "a" }, to: [AGT] });
      u.db.prepare("UPDATE tb_event_outbox SET created_at = ?").run(Date.now() - 8 * 86_400_000);
      u.ob.start({ bridge: () => null, bridgeCaps: () => [], rowsOn: () => [], inSlice: () => true });
      await until(async () => u.rows().length === 0);
      await u.ob.stop();
    } finally {
      u.cleanup();
    }
  });
});
