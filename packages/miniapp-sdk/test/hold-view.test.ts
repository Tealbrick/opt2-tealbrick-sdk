// SDK-HV-1 (C201, SDK-API §4.6): an outward hold of a DYNAMIC tool shows what the call would act on (the app's async
// `dynamic[op].holdView`), time-boxed, never blocking the hold; the approval is bound to sha256(view) so "approve draft A,
// agent edits it to B, sends B" is held again instead of running B on A's approval.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { decideHold, defineApp, startApp } from "../src/server/index.ts";
import { HOLD_VIEW_BUDGET_MS, HOLD_VIEW_UNREADABLE } from "../src/server/ops.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const SECRET_UPSTREAM_TEXT = "upstream-said-something-private-7731";

const toolsOp = {
  id: "tools",
  title: "Connected tools",
  description: "Search and call connected tools (test op).",
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode: "search", crudCeiling: ["read", "create", "update", "delete"], effectCeiling: "money" },
} as unknown as Operation;

interface Booted {
  w: World;
  base: string;
  dataDir: string;
  /** the "upstream" mailbox: draft id → text (the agent may edit it between hold and retry) */
  drafts: Record<string, string>;
  /** texts actually sent by `call` */
  sent: string[];
  /** holdView calls (tool names) */
  views: string[];
  /** per-test switch: "ok" | "throw" | "hang" | "huge" | "null" | "bad" */
  mode: { value: string };
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const manifest = fixtureManifest(port);
  manifest.operations.push(toolsOp);
  const drafts: Record<string, string> = {};
  const sent: string[] = [];
  const views: string[] = [];
  const mode = { value: "ok" };
  const noop = async () => ({});
  const app = defineApp({
    manifest,
    migrations: migrationsDir(t.dir),
    handlers: { note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: noop }, note_get: noop, note_delete: noop, notebook_rename: noop },
    dynamic: {
      tools: {
        catalog: async () => [],
        resolve: async (tool) => (tool === "send_draft" ? { tool, crud: ["create", "update"], effect: "outward", holdFamily: "outward" } : null),
        call: async (_tool, args) => {
          const text = drafts[String(args.draft_id)];
          if (text === undefined) throw new Error("no such draft");
          sent.push(text);
          return { sent: text };
        },
        holdView: async (tool, args, ctx) => {
          views.push(tool);
          assert.equal(ctx.caller.type, "agent", "holdView gets the caller's OpContext");
          const id = String(args.draft_id);
          switch (mode.value) {
            case "throw":
              throw new Error(SECRET_UPSTREAM_TEXT);
            case "hang":
              return new Promise(() => {});
            case "huge":
              return { view: "x".repeat(16_001) };
            case "null":
              return null;
            case "bad":
              return { view: 42 } as never;
            default: {
              const text = drafts[id];
              if (text === undefined) throw new Error("draft not found");
              return { summary: `Send mail to bob@example.com: ${"s".repeat(400)}`, view: `To: bob@example.com\nSubject: Hello\n\n${text}` };
            }
          }
        },
      },
    },
  });
  const running: RunningApp = await startApp(
    app,
    {
      TB_INSTANCE_ID: w.ins,
      TB_ENROL_CODE: "tbe_test",
      TB_BRIDGE_URL: bridgeUrl,
      TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
      TB_DATA_DIR: t.dir,
      TB_DATA_EPHEMERAL: "1",
      TB_LOG_LEVEL: "warn",
    },
    testRoots(w),
  ).catch(async (e) => {
    await bridge.stop();
    t.cleanup();
    throw e;
  });
  await until(async () => running.status() === "ok");
  return {
    w,
    base: `http://127.0.0.1:${port}`,
    dataDir: t.dir,
    drafts,
    sent,
    views,
    mode,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function send(b: Booted, draftId: string, key?: string) {
  return sendInput(b, { tool: "send_draft", arguments: { draft_id: draftId } }, key);
}

async function sendInput(b: Booted, input: Json, key?: string) {
  const g = await grant(b.w, b.w.agents.a, { held: ["outward"] });
  const proof = await callProof(b.w, g, "tools", input);
  const res = await fetch(`${b.base}/tb/v1/ops/tools`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, ...(key ? { idempotencyKey: key } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

function holdRow(b: Booted, id: string): { status: string; view: string | null; summary: string; meta: Record<string, unknown> } {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    const r = db.prepare("SELECT status, view, summary, meta FROM tb_receipts WHERE id = ?").get(id) as { status: string; view: string | null; summary: string; meta: string } | undefined;
    assert.ok(r, `hold ${id} exists`);
    return { ...r, meta: JSON.parse(r.meta) as Record<string, unknown> };
  } finally {
    db.close();
  }
}

const principal = (w: World): PersonPrincipal => ({ type: "person", id: w.per, ws: w.ws, instance: w.ins }) as PersonPrincipal;
const approve = (b: Booted, holdId: string) => decideHold(principal(b.w), { holdId: holdId as `hld_${string}`, decision: "approve" });

describe("SDK-HV-1 dynamic hold view", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("the hold shows the app's view of the upstream content; summary clamped to 280; meta binds sha256(view)", async () => {
    b.mode.value = "ok";
    b.drafts.d0 = "Hello Bob, the invoice is attached.";
    const r = await send(b, "d0");
    assert.equal(r.status, 202);
    assert.equal(r.body.status, "held");
    const h = holdRow(b, r.body.holdId);
    assert.equal(h.status, "held");
    assert.match(h.view ?? "", /^To: bob@example\.com\nSubject: Hello\n\nHello Bob, the invoice is attached\.$/);
    assert.equal(h.summary.length, 280);
    assert.match(String(h.meta.viewSha256), /^sha256:[0-9a-f]{64}$/);
    assert.equal(h.meta.tool, "send_draft");
    assert.deepEqual(b.sent, [], "nothing is sent while held");
  });

  test("A→B edit attack: approve draft A, the agent edits it to B → the retry is held AGAIN with B's view; B runs only after its own approval", async () => {
    b.mode.value = "ok";
    b.drafts.d1 = "A: pay the usual supplier";
    const first = await send(b, "d1");
    assert.equal(first.status, 202);
    const holdA = String(first.body.holdId);
    assert.match(holdRow(b, holdA).view ?? "", /A: pay the usual supplier/);
    await approve(b, holdA);

    b.drafts.d1 = "B: wire 9,000 EUR to account XY";
    const retry = await send(b, "d1");
    assert.equal(retry.status, 202, "the approval of A does not carry over to B");
    const holdB = String(retry.body.holdId);
    assert.notEqual(holdB, holdA, "a NEW hold");
    const hb = holdRow(b, holdB);
    assert.match(hb.view ?? "", /B: wire 9,000 EUR/);
    assert.equal(hb.status, "held");
    assert.notEqual(hb.meta.viewSha256, holdRow(b, holdA).meta.viewSha256);
    assert.deepEqual(b.sent, [], "B was never sent on A's approval");
    assert.equal(holdRow(b, holdA).status, "approved", "A's approval stays unused (expires on its own)");

    await approve(b, holdB);
    const run = await send(b, "d1");
    assert.equal(run.status, 200);
    assert.deepEqual(b.sent, ["B: wire 9,000 EUR to account XY"]);
    assert.equal(holdRow(b, holdB).status, "run");
    // one approval per call (C8): the same call again is held again
    assert.equal((await send(b, "d1")).status, 202);
    assert.equal(b.sent.length, 1);
  });

  test("unchanged content: the approved retry runs once with what the owner saw", async () => {
    b.mode.value = "ok";
    b.sent.length = 0;
    b.drafts.d2 = "Unchanged text";
    const h = await send(b, "d2");
    await approve(b, String(h.body.holdId));
    const run = await send(b, "d2");
    assert.equal(run.status, 200);
    assert.deepEqual(b.sent, ["Unchanged text"]);
  });

  test("idempotency key: edit after approval → new hold under the same key; then exactly one send; replay answers the stored result", async () => {
    b.mode.value = "ok";
    b.sent.length = 0;
    b.drafts.d3 = "A3";
    const key = "hv1-key-0001";
    const first = await send(b, "d3", key);
    assert.equal(first.status, 202);
    await approve(b, String(first.body.holdId));
    b.drafts.d3 = "B3";
    const second = await send(b, "d3", key);
    assert.equal(second.status, 202);
    assert.notEqual(second.body.holdId, first.body.holdId);
    const again = await send(b, "d3", key);
    assert.equal(again.status, 202);
    assert.equal(again.body.holdId, second.body.holdId, "the key now points at the new hold");
    await approve(b, String(second.body.holdId));
    const run = await send(b, "d3", key);
    assert.equal(run.status, 200);
    const replay = await send(b, "d3", key);
    assert.equal(replay.status, 200);
    assert.deepEqual(replay.body.output, run.body.output);
    assert.deepEqual(b.sent, ["B3"]);
  });

  test("holdView throws → hold still created with the default view and the 'could not read' line; the upstream error text is never logged", async () => {
    b.mode.value = "throw";
    b.drafts.d4 = "C4";
    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
      lines.push(String(chunk));
      return (orig as (...a: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof process.stderr.write;
    let r: Awaited<ReturnType<typeof send>>;
    try {
      r = await send(b, "d4");
    } finally {
      process.stderr.write = orig;
    }
    assert.equal(r.status, 202);
    const h = holdRow(b, r.body.holdId);
    assert.equal(h.status, "held", "a failure never approves");
    // v0.1.42 (C369 D1): the default view is labelled lines over the tool arguments (no catalog entry here: line 1 names the tool)
    assert.ok(h.view?.startsWith(`${HOLD_VIEW_UNREADABLE}\n\nConnected tools: send_draft\n`), h.view ?? "");
    assert.match(h.view ?? "", /\nDraft id: d4$/);
    assert.equal(h.summary, "Connected tools", "the receipt summary carries no input (C90)");
    assert.ok(lines.some((l) => l.includes("hold view failed")), "the failure is logged (code only)");
    assert.ok(!lines.join("").includes(SECRET_UPSTREAM_TEXT), "upstream error text never reaches the log");
  });

  test("fallback approval, content readable at retry → views differ → held again (unseen content never runs on a fallback approval)", async () => {
    b.mode.value = "throw";
    b.sent.length = 0;
    b.drafts.d5 = "Hidden at approval time";
    const h = await send(b, "d5");
    await approve(b, String(h.body.holdId));
    b.mode.value = "ok";
    const retry = await send(b, "d5");
    assert.equal(retry.status, 202);
    assert.notEqual(retry.body.holdId, h.body.holdId);
    assert.match(holdRow(b, retry.body.holdId).view ?? "", /Hidden at approval time/);
    assert.deepEqual(b.sent, []);
  });

  test("C202 fail closed: unreadable at hold AND at retry → the approval is NOT used; a new hold with the 'could not read' line", async () => {
    b.mode.value = "throw";
    b.sent.length = 0;
    b.drafts.d8 = "Never seen by the owner";
    const h = await send(b, "d8");
    assert.equal(h.status, 202);
    await approve(b, String(h.body.holdId));
    const retry = await send(b, "d8");
    assert.equal(retry.status, 202, "a blind approval is never reused");
    assert.notEqual(retry.body.holdId, h.body.holdId);
    assert.ok(holdRow(b, retry.body.holdId).view?.startsWith(HOLD_VIEW_UNREADABLE));
    // approving the new (still unreadable) hold does not help either: unreadable content never runs on an approval
    await approve(b, String(retry.body.holdId));
    assert.equal((await send(b, "d8")).status, 202);
    assert.deepEqual(b.sent, []);
    // once the content can be read, the owner sees it and its approval works
    b.mode.value = "ok";
    const readable = await send(b, "d8");
    assert.equal(readable.status, 202);
    assert.match(holdRow(b, readable.body.holdId).view ?? "", /Never seen by the owner/);
    await approve(b, String(readable.body.holdId));
    assert.equal((await send(b, "d8")).status, 200);
    assert.deepEqual(b.sent, ["Never seen by the owner"]);
  });

  test("oversized or malformed view → fallback (no hold_view_too_large refusal); null → default view without the line", async () => {
    b.mode.value = "huge";
    b.drafts.d6 = "D6";
    const huge = await send(b, "d6");
    assert.equal(huge.status, 202);
    assert.ok(holdRow(b, huge.body.holdId).view?.startsWith(HOLD_VIEW_UNREADABLE));
    b.mode.value = "bad";
    const bad = await send(b, "d6");
    assert.equal(bad.status, 202);
    assert.ok(holdRow(b, bad.body.holdId).view?.startsWith(HOLD_VIEW_UNREADABLE));
    b.mode.value = "null";
    b.sent.length = 0;
    const plain = await send(b, "d6");
    assert.equal(plain.status, 202);
    const hp = holdRow(b, plain.body.holdId);
    assert.equal(hp.view, "Connected tools: send_draft\nDraft id: d6");
    assert.ok(!hp.view?.includes(HOLD_VIEW_UNREADABLE));
    await approve(b, String(plain.body.holdId));
    assert.equal((await send(b, "d6")).status, 200, "a null view is stable: the approval matches");
    assert.deepEqual(b.sent, ["D6"]);
  });

  test("G7 (C275): default view is built from JCS — approve, then a replay with permuted keys runs exactly once", async () => {
    b.mode.value = "null";
    b.sent.length = 0;
    b.drafts.g7a = "G7 A";
    const held = await sendInput(b, { tool: "send_draft", arguments: { draft_id: "g7a", cc: "carol@example.com", z: 1 } });
    assert.equal(held.status, 202);
    const view = holdRow(b, held.body.holdId).view ?? "";
    assert.equal(view, "Connected tools: send_draft\nCc: carol@example.com\nDraft id: g7a\nZ: 1", view);
    await approve(b, String(held.body.holdId));
    // same input, other key order at both levels (what another client or a JSON round trip sends)
    const run = await sendInput(b, { arguments: { z: 1, cc: "carol@example.com", draft_id: "g7a" }, tool: "send_draft" });
    assert.equal(run.status, 200, "the approval matches a permuted-key replay");
    assert.deepEqual(b.sent, ["G7 A"]);
    const again = await sendInput(b, { arguments: { cc: "carol@example.com", draft_id: "g7a", z: 1 }, tool: "send_draft" });
    assert.equal(again.status, 202, "the approval is used once: a further replay is a new hold");
    assert.equal(holdRow(b, again.body.holdId).view, view, "key order never changes the view text");
    assert.deepEqual(b.sent, ["G7 A"], "sent exactly once");
  });

  test("G7 (C275): an identical replay of an approved default-view hold runs once", async () => {
    b.mode.value = "null";
    b.sent.length = 0;
    b.drafts.g7b = "G7 B";
    const input: Json = { tool: "send_draft", arguments: { draft_id: "g7b", cc: "dan@example.com" } };
    const held = await sendInput(b, input);
    assert.equal(held.status, 202);
    await approve(b, String(held.body.holdId));
    assert.equal((await sendInput(b, input)).status, 200);
    assert.equal((await sendInput(b, input)).status, 202, "a second replay needs a new approval");
    assert.deepEqual(b.sent, ["G7 B"]);
  });

  test("G7 (C275): a changed value (any key order) is still held again and never runs on the old approval", async () => {
    b.mode.value = "null";
    b.sent.length = 0;
    b.drafts.g7c = "G7 C";
    const held = await sendInput(b, { tool: "send_draft", arguments: { draft_id: "g7c", cc: "erin@example.com" } });
    assert.equal(held.status, 202);
    await approve(b, String(held.body.holdId));
    const changed = await sendInput(b, { arguments: { cc: "mallory@example.com", draft_id: "g7c" }, tool: "send_draft" });
    assert.equal(changed.status, 202, "another value is another input: a new hold");
    assert.notEqual(changed.body.holdId, held.body.holdId);
    assert.ok(holdRow(b, changed.body.holdId).view?.includes("mallory@example.com"));
    assert.deepEqual(b.sent, [], "nothing runs on the old approval");
  });

  test(`holdView that never answers → the hold is created after the ${HOLD_VIEW_BUDGET_MS} ms budget with the fallback view`, async () => {
    b.mode.value = "hang";
    b.drafts.d7 = "E7";
    const t0 = Date.now();
    const r = await send(b, "d7");
    const took = Date.now() - t0;
    assert.equal(r.status, 202);
    assert.ok(took >= HOLD_VIEW_BUDGET_MS - 50, `waited for the budget (${took} ms)`);
    assert.ok(took < HOLD_VIEW_BUDGET_MS + 10_000, `bounded (${took} ms)`);
    const h = holdRow(b, r.body.holdId);
    assert.equal(h.status, "held");
    assert.ok(h.view?.startsWith(HOLD_VIEW_UNREADABLE));
  });

  test("tb.holds_pending never carries the view (summary only)", async () => {
    const input: Json = { limit: 50 };
    const g = await grant(b.w, b.w.agents.a, { held: ["outward"] });
    const proof = await callProof(b.w, g, "tb.holds_pending", input);
    const res = await fetch(`${b.base}/tb/v1/ops/tb.holds_pending`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
      body: JSON.stringify({ input, context: {} }),
    });
    const body = (await res.json()) as { output: { items: Record<string, unknown>[] } };
    assert.equal(res.status, 200);
    assert.ok(body.output.items.length > 0);
    for (const it of body.output.items) {
      assert.equal(it.view, undefined);
      assert.ok(String(it.summary).length <= 280);
      assert.ok(!JSON.stringify(it).includes("Subject: Hello"));
    }
  });
});
