// spec 0.1.68 (C336 RQ-3, S-8; MANIFEST M-OP-12, SDK-API v0.1.68, CONFORMANCE C-SO-1..5): an op with `secretOutput: true`
// answers APP callers only (agents → 403 `secret_output_app_only` before the handler), cannot be scheduled
// (`secret_output_not_schedulable`), keeps no idempotency row (a same-key replay runs again), writes a receipt with the input
// digest and the `redact(input)` summary only (meta `{secretOutput: true}`; never output, `ctx.receipt` values or a message),
// answers handler errors with their code and the fixed message "operation failed", and never logs the output or a handler
// error message. Real HTTP, fake bridge; a canary output string is searched in every table of the app DB and every SDK log line.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { HookHoldFamily, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { decideHold, defineApp, type SdkOpContext, startApp, TbError } from "../src/server/index.ts";
import type { ClaimedJob } from "../src/server/jobs.ts";
import { fireScheduledOp } from "../src/server/ops.ts";
import type { Runtime } from "../src/server/runtime.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const OP = "credential_issue";
/** the secret: must never reach a receipt, the idempotency store, an error envelope or a log line */
const CANARY = "CANARY-SECRET-7c1e";
const HV = { f: "policy" as HookHoldFamily, r: "Rules: needs the owner", by: "rules/check_policy" };
const CALLER_PRODUCT = "vault-client";

type Mode = "ok" | "throw" | "throw_tb" | "bad_output";

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  dataDir: string;
  appIns: InstanceId;
  runs: { n: number; mode: Mode; scheduled: string | null };
  cleanup(): Promise<void>;
}

function manifest(port: number): Manifest {
  const m = fixtureManifest(port);
  m.operations.push({
    id: OP,
    title: "Issue credential",
    description: "Returns a short-lived credential.",
    input: { type: "object", properties: { purpose: { type: "string" } } },
    output: { type: "object", required: ["token"], properties: { token: { type: "string" } } },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: true,
    audience: "agent",
    // spec 0.1.68: not in the pinned Operation type yet
    secretOutput: true,
  } as Manifest["operations"][number]);
  // C354: the manifest names the bridge capability it needs (spec 0.1.68 `requires.bridgeCaps`, not in the pinned type yet)
  (m as { requires?: Record<string, unknown> }).requires = { ...(m.requires ?? {}), bridgeCaps: ["secret_output"] };
  return m;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const appIns = `ins_${ulid()}` as InstanceId;
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { companionCallers: [{ product: CALLER_PRODUCT, ins: appIns, name: "Vault client" }] }));
  const runs: Booted["runs"] = { n: 0, mode: "ok", scheduled: null };
  let running: RunningApp | undefined;
  try {
    running = await startApp(
      defineApp({
        manifest: manifest(port),
        migrations: migrationsDir(t.dir),
        handlers: {
          note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
          // C-SO-3: an agent op that tries to schedule the secret op
          note_get: async (_input, ctx) => {
            try {
              (ctx as SdkOpContext).schedule({ op: OP, input: { purpose: "later" } }, { at: Date.now() + 60_000 });
              runs.scheduled = "scheduled";
            } catch (e) {
              runs.scheduled = e instanceof TbError ? e.code : "other";
            }
            return {};
          },
          note_delete: async () => ({}),
          notebook_rename: async () => ({}),
          [OP]: {
            // a careless app: its redact(input, output) and ctx.receipt values carry the output; the SDK must store neither
            redact: (input, output) => (output ? `issued ${JSON.stringify(output)}` : `issue for ${(input as { purpose?: string }).purpose ?? "-"}`),
            run: async (_input, ctx) => {
              runs.n += 1;
              const token = `${CANARY}-${runs.n}`;
              ctx.receipt.summary(`token ${token}`);
              ctx.receipt.meta({ token });
              if (runs.mode === "throw") throw new Error(`upstream refused ${token}`);
              if (runs.mode === "throw_tb") throw new TbError("upstream_refused", `upstream refused ${token}`, 502, { token });
              if (runs.mode === "bad_output") return { token: 42, leaked: token } as unknown as Json;
              return { token };
            },
          },
        },
      }),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "debug" },
      testRoots(w),
    );
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
    appIns,
    runs,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

/** A companion (APP) grant of the calling instance for this app. */
const appGrant = (b: Booted): Promise<string> =>
  signGrant({ iss: "tb:portal", sub: `tb:ins:${b.appIns}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: [OP], polrev: 1, prd: CALLER_PRODUCT } as never, b.w.portal);

async function call(b: Booted, op: string, input: Json, opts: { key?: string; hv?: typeof HV; agent?: boolean } = {}) {
  const g = opts.agent ? await grant(b.w, b.w.agents.a) : await appGrant(b);
  const proof = await callProof(b.w, g, op, input, {}, opts.hv ? { hv: opts.hv } : {});
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, ...(opts.key ? { idempotencyKey: opts.key } : {}) }),
  });
  const text = await res.text();
  return { status: res.status, text, body: JSON.parse(text) as Record<string, any> };
}

function rows<T>(b: Booted, sql: string, ...args: string[]): T[] {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    return db.prepare(sql).all(...args) as T[];
  } finally {
    db.close();
  }
}

/** Every text cell of every table in the app DB that contains `needle` (`table.column`). */
function dbHits(b: Booted, needle: string): string[] {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    const hits: string[] = [];
    for (const { name } of db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]) {
      for (const r of db.prepare(`SELECT * FROM "${name.replace(/"/g, '""')}"`).all() as Record<string, unknown>[]) {
        for (const [col, v] of Object.entries(r)) {
          const text = typeof v === "string" ? v : v instanceof Uint8Array ? Buffer.from(v).toString("utf8") : "";
          if (text.includes(needle)) hits.push(`${name}.${col}`);
        }
      }
    }
    return hits;
  } finally {
    db.close();
  }
}

/** Captures the SDK's JSON log lines (stdout and stderr) while `fn` runs; other output passes through. */
async function captureLogs<T>(fn: () => Promise<T>): Promise<{ result: T; lines: string[] }> {
  const lines: string[] = [];
  const wrap = (stream: NodeJS.WriteStream) => {
    const orig = stream.write.bind(stream);
    stream.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
      const s = String(chunk);
      if (s.startsWith('{"at":')) {
        lines.push(s);
        return true;
      }
      return (orig as (...a: unknown[]) => boolean)(chunk, ...rest);
    }) as typeof stream.write;
    return () => {
      stream.write = orig;
    };
  };
  const undoOut = wrap(process.stdout);
  const undoErr = wrap(process.stderr);
  try {
    return { result: await fn(), lines };
  } finally {
    undoOut();
    undoErr();
  }
}

const receiptsOf = (b: Booted) => rows<{ id: string; status: string; summary: string; meta: string; input_digest: string; idempotency_key: string | null }>(b, "SELECT id, status, summary, meta, input_digest, idempotency_key FROM tb_receipts WHERE op = ? ORDER BY created_at, id", OP);
const principal = (w: World): PersonPrincipal => ({ type: "person", id: w.per, ws: w.ws, instance: w.ins }) as PersonPrincipal;

describe("spec 0.1.68 secretOutput (S-8, C-SO-1..5)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  test("C-SO-1: an app call — same-key replay runs again (a new credential), no idempotency row, receipt = input digest + redact(input) only, canary in no table and no log line", async () => {
    b.runs.mode = "ok";
    const key = `k_${ulid()}`;
    const n0 = b.runs.n;
    const r0 = receiptsOf(b).length;
    const { result, lines } = await captureLogs(async () => [await call(b, OP, { purpose: "deploy" }, { key }), await call(b, OP, { purpose: "deploy" }, { key })] as const);
    const [first, second] = result;
    assert.equal(first.status, 200, first.text);
    assert.equal(second.status, 200, second.text);
    assert.equal(first.body.output.token, `${CANARY}-${n0 + 1}`, "the caller gets the output");
    assert.equal(second.body.output.token, `${CANARY}-${n0 + 2}`, "the replay executed again: a new credential, not a stored answer");
    assert.equal(b.runs.n, n0 + 2);
    assert.deepEqual(rows(b, "SELECT key FROM tb_idempotency WHERE op = ?", OP), [], "no idempotency row");
    const rcp = receiptsOf(b).slice(r0);
    assert.equal(rcp.length, 2, "receipt: true → one receipt per run (issuance is audited)");
    for (const r of rcp) {
      assert.equal(r.status, "run");
      assert.deepEqual(JSON.parse(r.meta), { secretOutput: true }, "ctx.receipt.meta from the handler is not stored");
      assert.equal(r.summary, "issue for deploy", "summary = redact(input) only, never redact(input, output) or ctx.receipt.summary");
      assert.match(r.input_digest, /^sha256:[0-9a-f]{64}$/);
      assert.equal(r.idempotency_key, null, "the key is not kept");
    }
    assert.deepEqual(dbHits(b, CANARY), [], "the canary is in no table of the app DB");
    assert.deepEqual(
      lines.filter((l) => l.includes(CANARY)),
      [],
      "no log line carries the output",
    );
  });

  test("C-SO-2: an agent caller is refused 403 secret_output_app_only before the handler; nothing is written", async () => {
    b.runs.mode = "ok";
    const n0 = b.runs.n;
    const r0 = receiptsOf(b).length;
    const r = await call(b, OP, { purpose: "agent" }, { agent: true, key: `k_${ulid()}` });
    assert.equal(r.status, 403, r.text);
    assert.equal(r.body.error.code, "secret_output_app_only");
    assert.equal(b.runs.n, n0, "the handler did not run");
    assert.equal(receiptsOf(b).length, r0);
    assert.deepEqual(rows(b, "SELECT key FROM tb_idempotency WHERE op = ?", OP), []);
  });

  test("C-SO-3: ctx.schedule of the op is refused secret_output_not_schedulable; no job is stored", async () => {
    b.runs.scheduled = null;
    const r = await call(b, "note_get", { id: "x" }, { agent: true });
    assert.equal(r.status, 200, r.text);
    assert.equal(b.runs.scheduled, "secret_output_not_schedulable");
    assert.deepEqual(rows(b, "SELECT id FROM tb_jobs WHERE op = ?", OP), []);
  });

  for (const [mode, code, status] of [
    ["throw", "app_error", 500],
    ["throw_tb", "upstream_refused", 502],
    ["bad_output", "output_invalid", 500],
  ] as const) {
    test(`C-SO-4: a handler failure (${mode}) answers ${code} with the fixed message "operation failed" and no details; the failed receipt and the logs carry neither the canary nor the message`, async () => {
      b.runs.mode = mode;
      const r0 = receiptsOf(b).length;
      const { result, lines } = await captureLogs(() => call(b, OP, { purpose: mode }));
      b.runs.mode = "ok";
      assert.equal(result.status, status, result.text);
      assert.equal(result.body.error.code, code);
      assert.equal(result.body.error.message, "operation failed");
      assert.equal(result.body.error.details, undefined, "no details (no schema errors, no handler details)");
      assert.equal(result.text.includes(CANARY), false, "the envelope never carries the canary");
      assert.equal(result.text.includes("upstream refused"), false, "nor the handler's message");
      const [rcp] = receiptsOf(b).slice(r0);
      assert.equal(rcp?.status, "failed");
      assert.deepEqual(JSON.parse(rcp?.meta ?? "null"), { secretOutput: true, error: code }, "the failed receipt has the code, no message");
      assert.equal(rcp?.summary, `issue for ${mode}`);
      assert.deepEqual(dbHits(b, CANARY), []);
      assert.deepEqual(dbHits(b, "upstream refused"), []);
      if (mode === "throw") assert.ok(lines.some((l) => l.includes('"handler failed"')), "positive control: the failure itself is logged, so the capture works");
      assert.deepEqual(
        lines.filter((l) => l.includes(CANARY) || l.includes("upstream refused")),
        [],
        "no log line carries the secret or the message",
      );
    });
  }

  test("C-SO-5: hold, then approve — the output reaches only the retry; the receipt keeps meta {secretOutput: true}; nothing is stored", async () => {
    b.runs.mode = "ok";
    const input = { purpose: `approve-${ulid()}` };
    const { result, lines } = await captureLogs(async () => {
      const held = await call(b, OP, input, { hv: HV });
      assert.equal(held.status, 202, held.text);
      await decideHold(principal(b.w), { holdId: held.body.holdId, decision: "approve" });
      return { held, run: await call(b, OP, input) };
    });
    assert.equal(result.held.text.includes(CANARY), false, "the held answer carries no output");
    assert.equal(result.run.status, 200, result.run.text);
    assert.ok(String(result.run.body.output.token).startsWith(CANARY), "the retry gets the output");
    assert.equal(result.run.body.receiptId, result.held.body.holdId, "the approved hold is the receipt of the run");
    const [r] = rows<{ status: string; summary: string; meta: string }>(b, "SELECT status, summary, meta FROM tb_receipts WHERE id = ?", result.held.body.holdId);
    assert.equal(r?.status, "run");
    assert.deepEqual(JSON.parse(r?.meta ?? "null"), { secretOutput: true });
    assert.equal(r?.summary.includes(CANARY), false);
    assert.deepEqual(rows(b, "SELECT key FROM tb_idempotency WHERE op = ?", OP), []);
    assert.deepEqual(dbHits(b, CANARY), [], "the canary is in no table of the app DB");
    assert.deepEqual(
      lines.filter((l) => l.includes(CANARY)),
      [],
    );
  });
});

describe("spec 0.1.68 SDK-API v0.1.68 rule 2.6 (C354, QA-SDK51-1): a schedule created before the op had secretOutput", () => {
  for (const caller of [
    { type: "person", id: "per_01JAAAAAAAAAAAAAAAAAAAAAAA", name: "Owner" },
    { type: "agent", id: "agt_01JAAAAAAAAAAAAAAAAAAAAAAA", name: "Agent" },
    { type: "app", id: "ins_01JAAAAAAAAAAAAAAAAAAAAAAA", name: "Vault client" },
  ] as const) {
    test(`a stored job of a ${caller.type} caller is refused secret_output_not_schedulable when it runs; the handler never runs and nothing else is touched`, async () => {
      let ran = 0;
      const touched: string[] = [];
      const op = { id: OP, title: "Issue credential", standard: false, crud: ["read"], effect: "read", audience: "agent", idempotency: "none", receipt: true, secretOutput: true };
      const known: Record<string, unknown> = {
        ops: new Map([[OP, op]]),
        def: { handlers: { [OP]: async () => { ran += 1; return { token: CANARY }; } } },
      };
      // every other member of the runtime records the access: the refusal must come before the slice, grants, receipts or the handler
      const rt = new Proxy(known, {
        get(target, key) {
          if (typeof key === "string" && key in target) return target[key];
          touched.push(String(key));
          return new Proxy(() => {}, { get: () => () => undefined, apply: () => undefined });
        },
      }) as unknown as Runtime;
      // the job as an older release stored it (before the op had secretOutput): op, input, caller, sealed grant
      const job = { id: "job_1", kind: "tb.op", op: OP, input: { purpose: "old" }, key: "k_old_schedule", caller, callerMode: caller.type === "agent" ? "free" : null, grantSealed: caller.type === "person" ? null : "sealed", holdId: null } as unknown as ClaimedJob;
      const outcome = await fireScheduledOp(rt, job, new AbortController().signal);
      assert.deepEqual(outcome, { kind: "refused", reason: "secret_output_not_schedulable" });
      assert.equal(ran, 0, "the handler never runs from a job");
      assert.deepEqual(touched, [], "nothing but the op table is read");
    });
  }
});
