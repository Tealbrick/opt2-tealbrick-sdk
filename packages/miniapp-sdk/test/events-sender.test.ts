// v0.1.38 (sdk#41 review, specs#33 sender rules, SDK-API §20): the outbox sender against a scripted bridge — a batch ends after a
// purge, purges for every scope type, `eligible` limited to slice agents (≤ 500), 413 halving and the single-item drop, 401 retry,
// a 200 must answer every item with its own key in order, `events_send_failing` after 10 failed sends, committed rows only,
// a changed scope type drops the row, stop() aborts the send in flight.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { ulid } from "@opt2-tealbrick/manifest";
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger, ScopeGrantRow } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import type { BridgeResponse } from "../src/server/bridge-client.ts";
import { EVENTS_CAP, EventOutbox, type SenderDeps } from "../src/server/events.ts";
import { createLogger, SecretRegistry } from "../src/server/log.ts";
import { createScopeStore } from "../src/server/scopes.ts";
import { pickAttention } from "../src/server/status.ts";
import { openStore, type RawDb } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { tempDir, until } from "./helpers.ts";

const T = { timeout: 30_000 };
const silent: Logger = createLogger("error", new SecretRegistry(), { product: "jotter" });
const agt = () => `agt_${ulid()}` as AgentId;

function manifest(scopedVisibleWith = "note_create"): Manifest {
  const m = fixtureManifest(0);
  m.events = [
    { name: "note.created", title: "Created", payloadSchema: { type: "object", properties: { n: { type: "integer" } } }, visibleWith: scopedVisibleWith, audience: "granted" },
    { name: "note.pinged", title: "Ping", payloadSchema: { type: "object", properties: { n: { type: "integer" } } }, visibleWith: "note_get", audience: "target" },
  ];
  return m;
}

type Items = Record<string, unknown>[];
type Answer = (items: Items, signal?: AbortSignal) => Promise<BridgeResponse> | BridgeResponse;
const stored = (items: Items): BridgeResponse => ({ status: 200, body: { results: items.map((i) => ({ key: i.key, status: "stored", recipients: 0 })) } });

/** an outbox on a fresh store, a scripted bridge (records every POST) and the deps */
function harness(o: { m?: Manifest; answer?: Answer; rows?: (type: string, id: string) => ScopeGrantRow[]; inSlice?: (a: string) => boolean; caps?: string[] } = {}) {
  const t = tempDir();
  const db = openStore(t.dir);
  const posts: Items[] = [];
  let answer: Answer = o.answer ?? stored;
  const ob = new EventOutbox(db, o.m ?? manifest(), silent, { backoffMinMs: 10, backoffMaxMs: 20 });
  const deps: SenderDeps = {
    bridge: () => ({
      request: async (_m: "POST", _p: string, body: unknown, _h?: Record<string, string>, signal?: AbortSignal) => {
        const items = (body as { items: Items }).items;
        posts.push(items);
        return answer(items, signal);
      },
    }),
    bridgeCaps: () => o.caps ?? [EVENTS_CAP],
    rowsOn: o.rows ?? (() => []),
    inSlice: o.inSlice ?? (() => true),
  };
  return {
    db,
    ob,
    posts,
    deps,
    setAnswer(a: Answer) {
      answer = a;
    },
    left: () => Number((db.prepare("SELECT COUNT(*) AS n FROM tb_event_outbox").get() as { n: number }).n),
    async cleanup() {
      await ob.stop();
      db.close();
      t.cleanup();
    },
  };
}
const ping = (h: ReturnType<typeof harness>, n: number, key = `ping-key-${n}-${ulid()}`) => h.ob.emitFn()("note.pinged", { n }, { subject: { kind: "note", id: `n${n}` }, to: [agt()], key });

describe("outbox sender rules (specs#33)", T, () => {
  test("a batch ENDS right after a purge item: [E1, P] then [E2]", T, async () => {
    const h = harness();
    try {
      ping(h, 1, "batch-key-e1");
      h.ob.purgeFn()("nb1");
      ping(h, 2, "batch-key-e2");
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      assert.deepEqual(
        h.posts.map((p) => p.map((i) => (i.kind === "purge" ? "P" : String(i.key)))),
        [["batch-key-e1", "P"], ["batch-key-e2"]],
      );
    } finally {
      await h.cleanup();
    }
  });

  test("purge for EVERY scope type: v2 removed the event (no events at all), a row is revoked → a purge is still sent", T, async () => {
    const v2 = fixtureManifest(0);
    delete v2.events;
    const h = harness({ m: v2 });
    try {
      const scopes = createScopeStore(h.db, v2, createAuditLog(h.db, []), () => {}, (a, t, i) => h.ob.rowNarrowed(a, t, i));
      const principal = { type: "person", id: `per_${ulid()}`, ws: `ws_${ulid()}`, instance: `ins_${ulid()}` } as never;
      const agent = agt();
      await scopes.instances.create("notebook", "nb-old", "Old");
      await scopes.set(principal, agent, "notebook", "nb-old", "read_write");
      await scopes.set(principal, agent, "notebook", "nb-old", null);
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      assert.deepEqual(
        h.posts.flat().map((i) => `${i.kind}:${String(i.agent)}:${String(i.instanceId)}`),
        [`purge:${agent}:nb-old`],
      );
    } finally {
      await h.cleanup();
    }
  });

  test("eligible lists only agents in the current verified slice, at most 500", T, async () => {
    const inSlice = new Set([agt(), agt()]);
    const stale = Array.from({ length: 600 }, () => agt());
    const many = Array.from({ length: 520 }, () => agt());
    const row = (agent: string): ScopeGrantRow => ({ agent: agent as AgentId, type: "notebook", instanceId: "nb", access: "read_write", authority: "bounded", crud: ["read", "create", "update", "delete"] });
    const h = harness({ rows: (_t, id) => (id === "nb" ? [...stale, ...inSlice].map(row) : many.map(row)), inSlice: (a) => inSlice.has(a as AgentId) || many.includes(a as AgentId) });
    try {
      const emit = h.ob.emitFn();
      emit("note.created", { n: 1 }, { subject: { kind: "note", id: "a" }, instanceId: "nb", key: "eligible-key-1" });
      emit("note.created", { n: 2 }, { subject: { kind: "note", id: "b" }, instanceId: "nb-many", key: "eligible-key-2" });
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      const items = h.posts.flat();
      const e1 = items.find((i) => i.key === "eligible-key-1")?.eligible as { agent: string }[];
      const e2 = items.find((i) => i.key === "eligible-key-2")?.eligible as { agent: string }[];
      assert.deepEqual(e1.map((x) => x.agent).sort(), [...inSlice].sort(), "the 600 removed agents' rows are not listed");
      assert.equal(e2.length, 500);
    } finally {
      await h.cleanup();
    }
  });

  test("413 → halve the batch down to 1; a single item still 413 is dropped (event_too_large) and the rest go", T, async () => {
    const big = "too-big-key-01";
    const h = harness({ answer: (items) => (items.length > 1 || items.some((i) => i.key === big) ? { status: 413, body: { error: { code: "payload_too_large" } } } : stored(items)) });
    try {
      ping(h, 1, "half-key-0001");
      ping(h, 2, big);
      ping(h, 3, "half-key-0003");
      ping(h, 4, "half-key-0004");
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      assert.deepEqual(
        h.posts.slice(0, 3).map((p) => p.length),
        [4, 2, 1],
        "4 → 2 → 1 (halved on each 413)",
      );
      assert.ok(h.posts.some((p) => p.length === 1 && p[0]?.key === big), "the oversized item was tried alone");
      const accepted = h.posts.filter((p) => !(p.length > 1 || p.some((i) => i.key === big))).flatMap((p) => p.map((i) => i.key));
      assert.deepEqual(accepted, ["half-key-0001", "half-key-0003", "half-key-0004"], "every other row was sent; the oversized one dropped");
    } finally {
      await h.cleanup();
    }
  });

  test("401 → retried with backoff; a 200 without every item's own key in order → retried; then accepted", T, async () => {
    let n = 0;
    const h = harness({
      answer: (items) => {
        n++;
        if (n === 1) return { status: 401, body: { error: { code: "unauthenticated" } } };
        if (n === 2) return { status: 200, body: { results: items.map((i) => ({ key: i.key, status: "stored" })).reverse() } };
        if (n === 3) return { status: 200, body: { results: items.slice(1).map((i) => ({ key: i.key, status: "stored" })) } };
        return stored(items);
      },
    });
    try {
      ping(h, 1, "retry-key-0001");
      ping(h, 2, "retry-key-0002");
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      assert.equal(h.posts.length, 4);
      assert.ok(h.posts.every((p) => p.map((i) => i.key).join() === "retry-key-0001,retry-key-0002"), "same batch, same keys");
    } finally {
      await h.cleanup();
    }
  });

  test("events_send_failing after 10 consecutive failed sends, until a send succeeds; ordered after backup, before the app", T, async () => {
    // what attention() said when each send started (after n - 1 failures)
    const seen: (string | null)[] = [];
    let ob: EventOutbox | null = null;
    const h = harness({
      answer: (items) => {
        seen.push(ob?.attention()?.code ?? null);
        return seen.length <= 11 ? { status: 503, body: { error: { code: "app_not_claimed" } } } : stored(items);
      },
    });
    ob = h.ob;
    try {
      ping(h, 1);
      h.ob.start(h.deps);
      await until(async () => h.left() === 0);
      assert.equal(seen[9], null, "after 9 failures: none");
      assert.equal(seen[10], "events_send_failing", "after 10 failures");
      assert.equal(seen[11], "events_send_failing", "still, until a send succeeds");
      assert.equal(h.ob.attention(), null, "cleared by a send that succeeded");
    } finally {
      await h.cleanup();
    }
    const ev = { code: "events_send_failing", reason: "x" };
    assert.equal(pickAttention({ backup: { code: "backup_failed", reason: "x" }, events: ev, app: { code: "a", reason: "x" }, jobs: null })?.code, "backup_failed");
    assert.equal(pickAttention({ backup: null, events: ev, app: { code: "a", reason: "x" }, jobs: null })?.code, "events_send_failing");
  });

  test("committed rows only: nothing is sent while a transaction is open; a rollback sends nothing, a commit sends", T, async () => {
    const h = harness();
    try {
      h.ob.start(h.deps);
      h.db.exec("BEGIN");
      ping(h, 1, "tx-key-rolled-1");
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(h.posts.length, 0, "the row of an open transaction is never read");
      h.db.exec("ROLLBACK");
      h.ob.wake();
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(h.posts.length, 0);
      assert.equal(h.left(), 0);
      h.db.exec("BEGIN");
      ping(h, 2, "tx-key-commit-2");
      await new Promise((r) => setTimeout(r, 200));
      assert.equal(h.posts.length, 0);
      h.db.exec("COMMIT");
      await until(async () => h.posts.flat().some((i) => i.key === "tx-key-commit-2"));
    } finally {
      await h.cleanup();
    }
  });

  test("an event whose scope type changed since the emit (app update) is dropped, never sent", T, async () => {
    const t = tempDir();
    const db: RawDb = openStore(t.dir);
    try {
      new EventOutbox(db, manifest("note_create"), silent).emitFn()("note.created", { n: 1 }, { subject: { kind: "note", id: "a" }, instanceId: "nb", key: "changed-key-01" });
      // v2: the event's visibleWith is an unscoped op now
      const v2 = new EventOutbox(db, manifest("note_get"), silent);
      const posts: Items[] = [];
      const request = async (_m: "POST", _p: string, body: unknown): Promise<BridgeResponse> => {
        const items = (body as { items: Items }).items;
        posts.push(items);
        return stored(items);
      };
      v2.start({ bridge: () => ({ request }), bridgeCaps: () => [EVENTS_CAP], rowsOn: () => [], inSlice: () => true });
      await until(async () => Number((db.prepare("SELECT COUNT(*) AS n FROM tb_event_outbox").get() as { n: number }).n) === 0);
      await v2.stop();
      assert.equal(posts.length, 0);
    } finally {
      db.close();
      t.cleanup();
    }
  });

  test("stop() aborts the send in flight; the row stays for the next start", T, async () => {
    let aborted = false;
    const h = harness({
      answer: (_items, signal) =>
        new Promise((_, reject) =>
          signal?.addEventListener("abort", () => {
            aborted = true;
            reject(signal.reason);
          }),
        ),
    });
    try {
      ping(h, 1);
      h.ob.start(h.deps);
      await until(async () => h.posts.length === 1);
      const t0 = Date.now();
      await h.ob.stop();
      assert.ok(aborted && Date.now() - t0 < 1000);
      assert.equal(h.left(), 1);
    } finally {
      await h.cleanup();
    }
  });
});
