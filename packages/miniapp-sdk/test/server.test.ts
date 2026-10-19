// Server core: real HTTP on an ephemeral port, temp data dirs, a fake bridge, tokens from the manifest package signers.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { Json, OpContext, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { decideHold, defineApp, getKey, onKeysChanged, SESSION_COOKIE, startApp, TbError } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

function testApp(port: number, migrations: string, counters: Record<string, number>) {
  const bump = (k: string) => {
    counters[k] = (counters[k] ?? 0) + 1;
  };
  const manifest = fixtureManifest(port);
  // a person op that requires an idempotency key (C53 / BSA-12: listed in the session answer)
  manifest.operations.push({
    id: "notebook_archive",
    title: "Archive notebook",
    description: "Archive a notebook (owner only).",
    input: { type: "object", required: ["notebook"], properties: { notebook: { type: "string" } } },
    output: { type: "object" },
    crud: ["update"],
    effect: "write",
    idempotency: "required",
    receipt: false,
    audience: "person",
  });
  return defineApp({
    manifest,
    migrations,
    handlers: {
      note_create: {
        scope: (input) => String((input as { notebook: string }).notebook),
        run: async (input, ctx: OpContext) => {
          bump("note_create");
          const i = input as { notebook: string; title: string };
          const id = `n${counters.note_create}`;
          ctx.db.prepare("INSERT INTO notes (id, notebook, title) VALUES (?, ?, ?)").run(id, i.notebook, i.title);
          ctx.receipt.meta({ subjectKind: "as_me" });
          return { id };
        },
        redact: (input) => `note in ${(input as { notebook: string }).notebook}`,
      },
      note_get: async (input, ctx) => {
        bump("note_get");
        return (ctx.db.prepare("SELECT * FROM notes WHERE id = ?").get((input as { id: string }).id) ?? {}) as Json;
      },
      note_delete: async () => {
        bump("note_delete");
        return { deleted: true };
      },
      notebook_rename: async (input) => {
        bump("notebook_rename");
        return { renamed: (input as { label: string }).label };
      },
      notebook_archive: async () => {
        bump("notebook_archive");
        return { archived: true };
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  port: number;
  counters: Record<string, number>;
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const counters: Record<string, number> = {};
  const app = testApp(port, migrationsDir(t.dir), counters);
  const running = await startApp(app, {
    TB_INSTANCE_ID: w.ins,
    TB_ENROL_CODE: "tbe_test",
    TB_BRIDGE_URL: bridgeUrl,
    TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
    TB_DATA_DIR: t.dir,
    TB_DATA_EPHEMERAL: "1",
    TB_LOG_LEVEL: "error",
  }, testRoots(w));
  await until(async () => running.status() === "ok");
  return {
    w,
    bridge,
    running,
    base: `http://127.0.0.1:${port}`,
    port,
    counters,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function callOp(b: Booted, op: string, input: Json, opts: { agent?: string; held?: ("destructive" | "first_contact")[]; idempotencyKey?: string; proof?: string; grant?: string } = {}) {
  const g = opts.grant ?? (await grant(b.w, (opts.agent ?? b.w.agents.a) as `agt_${string}`, { held: opts.held ?? [] }));
  const proof = opts.proof ?? (await callProof(b.w, g, op, input));
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, ...(proof ? { "tb-call": proof } : {}) },
    body: JSON.stringify({ input, context: {}, ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function signIn(b: Booted): Promise<{ cookie: string; csrf: string }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, "/configure") }),
  });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), `/a/${PRODUCT}/configure`);
  const set = res.headers.get("set-cookie") ?? "";
  assert.match(set, /HttpOnly; Secure; SameSite=Lax/);
  assert.match(set, new RegExp(`Path=/a/${PRODUCT}/`));
  const cookie = set.split(";")[0] as string;
  const s = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } });
  const body = (await s.json()) as { csrf: string; principal: { id: string }; idempotencyRequired: string[] };
  assert.equal(body.principal.id, b.w.per);
  // exactly the person-audience ops with idempotency "required" (not agent note_create, not supported/standard ops)
  assert.deepEqual(body.idempotencyRequired, ["notebook_archive"]);
  return { cookie, csrf: body.csrf };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json, opts: { csrf?: string | null; origin?: string | null } = {}) {
  const headers: Record<string, string> = { "content-type": "application/json", cookie: s.cookie };
  const csrf = opts.csrf === undefined ? s.csrf : opts.csrf;
  if (csrf) headers["tb-csrf"] = csrf;
  const origin = opts.origin === undefined ? b.base : opts.origin;
  if (origin) headers.origin = origin;
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, { method: "POST", headers, body: JSON.stringify({ input }) });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe("boot", () => {
  test("refuses an invalid manifest", async () => {
    const t = tempDir();
    const m = { ...fixtureManifest(await freePort()), id: "Not A Slug" };
    const app = defineApp({ manifest: m, migrations: migrationsDir(t.dir), handlers: {} });
    await assert.rejects(startApp(app, { TB_DATA_DIR: t.dir, TB_STANDALONE: "1" }), (e: unknown) => e instanceof TbError && e.code === "manifest_invalid");
    t.cleanup();
  });

  test("refuses missing and extra handlers", async () => {
    const t = tempDir();
    const counters = {};
    const ok = testApp(await freePort(), migrationsDir(t.dir), counters);
    const def = { manifest: ok.manifest, migrations: migrationsDir(t.dir), handlers: { note_get: async () => ({}), bogus_op: async () => ({}) } };
    await assert.rejects(startApp(defineApp(def), { TB_DATA_DIR: t.dir, TB_STANDALONE: "1" }), (e: unknown) => {
      assert.ok(e instanceof TbError);
      assert.equal(e.code, "handlers_invalid");
      assert.match(e.message, /missing handler for operation note_create/);
      assert.match(e.message, /extra handler bogus_op/);
      return true;
    });
    t.cleanup();
  });

  test("refuses a scoped op without scope() and a changed applied migration", async () => {
    const t = tempDir();
    const counters = {};
    const base = testApp(await freePort(), migrationsDir(t.dir), counters);
    const noScope = defineApp({
      manifest: base.manifest,
      migrations: migrationsDir(t.dir),
      handlers: { note_create: async () => ({ id: "x" }), note_get: async () => ({}), note_delete: async () => ({}), notebook_rename: async () => ({}) },
    });
    await assert.rejects(startApp(noScope, { TB_DATA_DIR: t.dir, TB_STANDALONE: "1" }), /needs a scope\(\) function/);
    const r = await startApp(base, { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" });
    await r.stop();
    migrationsDir(t.dir, { "0001_init.sql": "CREATE TABLE notes (id TEXT PRIMARY KEY);" });
    // v0.1.25 (E2/M2): a data-phase failure is failed mode (health + reason), not a rejected boot / crash loop
    const failed = await startApp(base, { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" });
    try {
      assert.equal(failed.status(), "failed");
      assert.equal(failed.failure?.code, "migration_invalid");
      assert.equal(failed.failure?.phase, "schema");
    } finally {
      await failed.stop();
    }
    t.cleanup();
  });

  test("app SQL cannot touch SDK-reserved tb_* tables", async () => {
    const t = tempDir();
    const app = testApp(await freePort(), migrationsDir(t.dir, { "0001_init.sql": "CREATE TABLE notes (id TEXT); DELETE FROM tb_receipts;" }), {});
    const failed = await startApp(app, { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" });
    try {
      assert.equal(failed.status(), "failed");
      assert.equal(failed.failure?.code, "db_reserved");
      assert.equal(failed.failure?.file, "0001_init.sql");
    } finally {
      await failed.stop();
    }
    t.cleanup();
  });
});

describe("agent operations via the bridge", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("claim installed the slice and applied defaultGrants on first sight", async () => {
    assert.equal(b.bridge.claims, 1);
    const rows = await b.running.scopes.list(b.w.agents.a);
    assert.deepEqual(rows, [{ agent: b.w.agents.a, type: "notebook", instanceId: b.w.agents.a, access: "read_write", authority: "bounded", source: "default", crud: ["read", "create", "update", "delete"] }]);
    assert.equal(await b.running.scopes.summary(b.w.agents.a), "1 Notebooks (1 write)");
    const health = (await (await fetch(`${b.base}/tb/v1/health`)).json()) as { status: string; manifestDigest: string };
    assert.equal(health.status, "ok");
    assert.match(health.manifestDigest, /^sha256:[0-9a-f]{64}$/);
  });

  test("valid grant + call proof runs the handler and writes a receipt", async () => {
    const r = await callOp(b, "note_create", { notebook: b.w.agents.a, title: "hello" }, { idempotencyKey: "key-00000001" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.status, "ok");
    assert.deepEqual(r.body.output, { id: "n1" });
    const rec = await b.running.receipts.get(r.body.receiptId);
    assert.equal(rec?.status, "run");
    assert.equal(rec?.summary, `note in ${b.w.agents.a}`);
    assert.deepEqual(rec?.meta, { subjectKind: "as_me" });
    assert.match(rec?.inputDigest ?? "", /^sha256:/);
  });

  test("scope access comes from the app store: another agent's notebook is refused", async () => {
    const r = await callOp(b, "note_create", { notebook: b.w.agents.b, title: "x" }, { idempotencyKey: "key-00000002" });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, "scope_denied");
    const refused = await b.running.receipts.list({ status: "refused" });
    assert.ok(refused.items.some((i) => i.op === "note_create"));
  });

  test("missing proof, wrong aud and tampered input digest are refused", async () => {
    const input = { id: "n1" };
    const g = await grant(b.w, b.w.agents.a);
    const missing = await callOp(b, "note_get", input, { grant: g, proof: "" });
    assert.equal(missing.status, 401);
    assert.equal(missing.body.error.code, "call_proof_invalid");
    const wrongAud = await callOp(b, "note_get", input, { grant: g, proof: await callProof(b.w, g, "note_get", input, {}, { aud: `ins_${"0".repeat(26)}` }) });
    assert.equal(wrongAud.body.error.code, "call_proof_invalid");
    const tampered = await callOp(b, "note_get", input, { grant: g, proof: await callProof(b.w, g, "note_get", input, {}, { inputFor: { id: "other" } }) });
    assert.equal(tampered.status, 401);
    assert.equal(tampered.body.error.code, "call_proof_invalid");
    const wrongOp = await callOp(b, "note_get", input, { grant: g, proof: await callProof(b.w, g, "note_delete", input) });
    assert.equal(wrongOp.body.error.code, "call_proof_invalid");
    const otherGrant = await grant(b.w, b.w.agents.a, { aud: `ins_${"1".repeat(26)}` });
    const badGrant = await callOp(b, "note_get", input, { grant: otherGrant });
    assert.equal(badGrant.status, 401);
    assert.equal(badGrant.body.error.code, "grant_invalid");
    const ok = await callOp(b, "note_get", input, { grant: g });
    assert.equal(ok.status, 200);
    assert.equal(ok.body.output.title, "hello");
  });

  test("a replayed call proof is refused", async () => {
    const input = { id: "n1" };
    const g = await grant(b.w, b.w.agents.a);
    const proof = await callProof(b.w, g, "note_get", input);
    assert.equal((await callOp(b, "note_get", input, { grant: g, proof })).status, 200);
    assert.equal((await callOp(b, "note_get", input, { grant: g, proof })).body.error.code, "call_proof_invalid");
  });

  test("input schema and person-audience ops are refused on /tb/v1/ops", async () => {
    const bad = await callOp(b, "note_get", { nope: 1 });
    assert.equal(bad.status, 400);
    assert.equal(bad.body.error.code, "input_invalid");
    const person = await callOp(b, "notebook_rename", { notebook: "x", label: "y" });
    assert.equal(person.body.error.code, "audience_not_agent");
  });

  test("hold → approve → same input runs once; different input → new hold", async () => {
    const input = { id: "n1" };
    const held = await callOp(b, "note_delete", input, { held: ["destructive"] });
    assert.equal(held.status, 202);
    assert.equal(held.body.status, "held");
    assert.match(held.body.holdId, /^hld_/);
    assert.ok(Date.parse(held.body.expiresAt) > Date.now());
    assert.equal(b.counters.note_delete, undefined);
    // pendingHolds reaches the bridge status push (C16 S2)
    await until(async () => b.bridge.statuses.some((s) => (s as { pendingHolds: number }).pendingHolds >= 1));

    const status = await callOp(b, "tb.hold_status", { holdId: held.body.holdId });
    assert.equal(status.body.output.status, "held");
    const foreign = await callOp(b, "tb.hold_status", { holdId: held.body.holdId }, { agent: b.w.agents.b });
    assert.equal(foreign.status, 404);
    assert.equal(foreign.body.error.code, "hold_not_found");

    const s = await signIn(b);
    const list = await personOp(b, s, "tb.holds_list", {});
    assert.equal(list.status, 200);
    const item = list.body.output.items.find((i: { id: string }) => i.id === held.body.holdId);
    assert.match(item.view, /Delete note/);
    const decided = await personOp(b, s, "tb.holds_decide", { holdId: held.body.holdId, decision: "approve" });
    assert.equal(decided.status, 200, JSON.stringify(decided.body));
    assert.equal(decided.body.output.status, "approved");
    assert.equal(decided.body.output.decidedBy, b.w.per);

    const differentInput = await callOp(b, "note_delete", { id: "n2" }, { held: ["destructive"] });
    assert.equal(differentInput.status, 202);
    assert.notEqual(differentInput.body.holdId, held.body.holdId);

    const retry = await callOp(b, "note_delete", input, { held: ["destructive"] });
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(retry.body.receiptId, held.body.holdId);
    assert.equal(b.counters.note_delete, 1);
    assert.equal((await b.running.receipts.get(held.body.holdId))?.status, "run");
    assert.equal((await b.running.receipts.get(held.body.holdId))?.view, undefined);

    const again = await callOp(b, "note_delete", input, { held: ["destructive"] });
    assert.equal(again.status, 202, "an approval is consumed once");
    assert.equal(b.counters.note_delete, 1);
  });

  test("decideHold denies; a denied hold cannot be decided again", async () => {
    const held = await callOp(b, "note_delete", { id: "n9" }, { held: ["destructive"] });
    const principal = { type: "person" as const, id: b.w.per, ws: b.w.ws, instance: b.w.ins, iss: "tb:portal" as const, sessionExpiresAt: Date.now() + 1000 };
    const r = await decideHold(principal, { holdId: held.body.holdId, decision: "deny" });
    assert.equal(r.status, "denied");
    await assert.rejects(decideHold(principal, { holdId: held.body.holdId, decision: "approve" }), (e: unknown) => e instanceof TbError && e.code === "hold_decided");
    await assert.rejects(decideHold({ ...principal, instance: `ins_${"2".repeat(26)}` }, { holdId: held.body.holdId, decision: "approve" }), /only the owner/);
    const audit = await b.running.audit.list({ action: "hold.decide" });
    assert.ok(audit.items.length >= 2);
  });

  test("idempotency: same key + same input replays; different input → 409", async () => {
    const input = { notebook: b.w.agents.a, title: "idem" };
    const first = await callOp(b, "note_create", input, { idempotencyKey: "idem-key-0001" });
    const count = b.counters.note_create;
    const replay = await callOp(b, "note_create", input, { idempotencyKey: "idem-key-0001" });
    assert.equal(replay.status, 200);
    assert.deepEqual(replay.body.output, first.body.output);
    assert.equal(b.counters.note_create, count);
    const conflict = await callOp(b, "note_create", { ...input, title: "other" }, { idempotencyKey: "idem-key-0001" });
    assert.equal(conflict.status, 409);
    assert.equal(conflict.body.error.code, "idempotency_conflict");
    const missing = await callOp(b, "note_create", input);
    assert.equal(missing.status, 400);
    assert.equal(missing.body.error.code, "idempotency_key_required");
  });

  test("person sign-in: ticket redeemed once, CSRF + Origin required on POST", async () => {
    const t = await ticket(b.w);
    const post = (tk: string) =>
      fetch(`${b.base}/a/${PRODUCT}/tb/launch`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket: tk }) });
    const first = await post(t);
    assert.equal(first.status, 303);
    const second = await post(t);
    assert.equal(second.status, 401);
    assert.match(await second.text(), /ticket_used/);
    const forged = await post(`${t.slice(0, -4)}AAAA`);
    assert.match(await forged.text(), /ticket_invalid/);

    const s = await signIn(b);
    assert.ok(s.cookie.startsWith(`${SESSION_COOKIE}=`));
    const noCsrf = await personOp(b, s, "notebook_rename", { notebook: "x", label: "y" }, { csrf: null });
    assert.equal(noCsrf.status, 403);
    assert.equal(noCsrf.body.error.code, "csrf_invalid");
    const badOrigin = await personOp(b, s, "notebook_rename", { notebook: "x", label: "y" }, { origin: "https://evil.example" });
    assert.equal(badOrigin.body.error.code, "csrf_invalid");
    const ok = await personOp(b, s, "notebook_rename", { notebook: "x", label: "y" });
    assert.equal(ok.status, 200);
    assert.deepEqual(ok.body.output, { renamed: "y" });
    const noKey = await personOp(b, s, "notebook_archive", { notebook: "x" });
    assert.equal(noKey.body.error.code, "idempotency_key_required");
    const keyed = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/notebook_archive`, {
      method: "POST",
      headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
      body: JSON.stringify({ input: { notebook: "x" }, idempotencyKey: crypto.randomUUID() }),
    });
    assert.equal(keyed.status, 200);
    const agentOp = await personOp(b, s, "note_get", { id: "n1" });
    assert.equal(agentOp.body.error.code, "audience_not_person");
    const noSession = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`);
    assert.equal(((await noSession.json()) as { error: { code: string } }).error.code, "session_required");

    const logout = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/logout`, { method: "POST", headers: { cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base } });
    assert.equal(logout.status, 200);
    assert.equal((await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie: s.cookie } })).status, 401);
  });

  test("scopes_set and keys: app-own key wins, value never returned, onKeysChanged fires", async () => {
    const s = await signIn(b);
    const set = await personOp(b, s, "tb.scopes_set", { agent: b.w.agents.b, type: "notebook", id: b.w.agents.a, access: "read" });
    assert.equal(set.status, 200);
    assert.equal(set.body.output.access.access, "read");
    assert.equal((await b.running.scopes.access(b.w.agents.b, "notebook", b.w.agents.a))?.access, "read");

    const seen: string[][] = [];
    const off = onKeysChanged((names) => seen.push(names));
    assert.equal(await getKey("DEMO_API_KEY"), null);
    const put = await personOp(b, s, "tb.key_set", { name: "DEMO_API_KEY", value: "demo-secret-value" });
    assert.equal(put.status, 200);
    assert.equal(JSON.stringify(put.body).includes("demo-secret-value"), false);
    assert.equal(await getKey("DEMO_API_KEY"), "demo-secret-value");
    assert.deepEqual(seen, [["DEMO_API_KEY"]]);
    const st = await personOp(b, s, "tb.keys_status", {});
    assert.deepEqual(st.body.output.keys, [{ name: "DEMO_API_KEY", required: false, present: true, source: "app_own" }]);
    off();
    await assert.rejects(getKey("UNDECLARED"), (e: unknown) => e instanceof TbError && e.code === "key_undeclared");
  });

  test("a paused agent is refused by authorize() step 0 after the slice update", async () => {
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: false, agents: [b.w.agents.a], instances: [] } }));
    const r = await until(async () => {
      const x = await callOp(b, "note_get", { id: "n1" });
      return x.status === 403 ? x : null;
    });
    assert.equal(r.body.error.code, "paused");
    const other = await callOp(b, "note_get", { id: "n1" }, { agent: b.w.agents.b });
    assert.equal(other.status, 200);
  });

  test("TbError carries code and HTTP status", () => {
    const e = new TbError("custom_code", "msg", 418);
    assert.equal(e.code, "custom_code");
    assert.equal(e.httpStatus, 418);
    assert.equal(new TbError("x", "y").httpStatus, 400);
  });
});

describe("app-alone mode", () => {
  test("ops answer no_bridge; health ok; person UI requires a session", async () => {
    const t = tempDir();
    const port = await freePort();
    const running = await startApp(testApp(port, migrationsDir(t.dir), {}), { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" });
    try {
      const base = `http://127.0.0.1:${port}`;
      assert.equal(running.status(), "ok");
      const r = await fetch(`${base}/tb/v1/ops/note_get`, { method: "POST", body: JSON.stringify({ input: {}, context: {} }) });
      assert.equal(r.status, 503);
      assert.equal(((await r.json()) as { error: { code: string } }).error.code, "no_bridge");
      assert.equal((await fetch(`${base}/a/${PRODUCT}/`)).status, 401);
      const page = await fetch(`${base}/a/${PRODUCT}/tb/standalone`);
      assert.match(await page.text(), /Setup code/);
      const openapi = (await (await fetch(`${base}/tb/v1/openapi.json`)).json()) as { paths: Record<string, unknown> };
      assert.ok(openapi.paths["/tb/v1/ops/note_create"]);
      assert.ok(openapi.paths[`/a/${PRODUCT}/tb/v1/ops/tb.holds_decide`]);
    } finally {
      await running.stop();
      t.cleanup();
    }
  });
});

describe("key-set statement rule (spec 0.1.12, CREDENTIALS §9.5)", () => {
  async function bootWith(sliceOver: { portalKeySet?: null }, harness: "test-roots" | "build-roots") {
    const w = await world();
    const t = tempDir();
    const port = await freePort();
    const bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT, sliceOver));
    const env = { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" };
    const running = await startApp(testApp(port, migrationsDir(t.dir), {}), env, harness === "test-roots" ? testRoots(w) : undefined);
    return {
      bridge,
      running,
      async cleanup() {
        await running.stop();
        await bridge.stop();
        t.cleanup();
      },
    };
  }

  test("a statement-less first slice is refused (keyset_missing): claimed, but never installed", async () => {
    const b = await bootWith({ portalKeySet: null }, "test-roots");
    try {
      await until(async () => b.bridge.claims >= 1 && b.bridge.statuses.length >= 1);
      assert.equal(b.running.status(), "slice_stale", "no slice installed although TB_PORTAL_KEYS signed it");
    } finally {
      await b.cleanup();
    }
  });

  test("default build roots: a test-root statement does not verify, so a fake-bridge slice is never accepted", async () => {
    const b = await bootWith({}, "build-roots");
    try {
      await until(async () => b.bridge.claims >= 1 && b.bridge.statuses.length >= 1);
      assert.equal(b.running.status(), "slice_stale");
    } finally {
      await b.cleanup();
    }
  });
});
