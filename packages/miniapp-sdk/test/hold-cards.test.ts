// C369 readable hold cards (miniapp-sdk 0.1.42, spec 0.1.84 reservation, SDK-API §4.8–§4.9):
// D1 default view (every row of the spec fixture), D2 every held op's view is hash-bound and re-checked on the approved repeat,
// D3 Receipt.holdReason on tb.holds_list rows, D4 the sealed input kept with the hold + tb.hold_details (owner only; wiped 7 days
// after the terminal status; never in the export). Fire-on-bad: an agent call, an app call and a non-owner person call to
// tb.hold_details are refused.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { canonicalize, signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import {
  dynamicHoldTitle,
  HOLD_DETAILS_OP,
  HOLD_INPUT_KEEP_MS,
  HOLD_INPUT_MAX_BYTES,
  HOLD_INPUT_REDACTED,
  HOLD_SECRET_KEY_PARTS,
  HOLD_SECRET_KEY_WORDS,
  HOLD_VIEW_HIDDEN,
  HOLD_VIEW_LIMITS,
  HOLD_VIEW_MAX_CHARS,
  type HoldDetails,
  holdViewElidedLine,
  isSecretKey,
  keptHoldInput,
  redactHoldInput,
  renderHoldView,
} from "../src/server/hold-view.ts";
import { decideHold, defineApp, type JobsApi, type SdkOpContext, startApp } from "../src/server/index.ts";
import { holdDetails } from "../src/server/ops.ts";
import { type Receipts, Receipts as ReceiptsImpl } from "../src/server/receipts.ts";
import type { Runtime } from "../src/server/runtime.ts";
import { applySdkMigrations, openDb } from "../src/server/store.ts";
import { bufferSink, readTarGz } from "../src/server/tar.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

// ── D1: the spec fixture (a COPY of opt2-tealbrick-specs packages/spec/examples/hold-view.cases.json, spec 0.1.84 reservation;
// replace the copy with the released file `@opt2-tealbrick/spec/examples/hold-view.cases.json` when the spec pin moves) ─────
interface Case {
  name: string;
  note: string;
  dynamic?: { opTitle: string; tool: string };
  title: string;
  schema: Json;
  input: Json;
  recipients?: Json;
  view: string;
  summary: string;
}
const fx = JSON.parse(readFileSync(new URL("./fixtures/hold-view.cases.json", import.meta.url), "utf8")) as { limits: Record<string, number>; cases: Case[] };

describe("C369 D1 default hold view: the spec fixture", () => {
  test("the fixture has at least 25 rows and repeats the SDK limits", () => {
    assert.ok(fx.cases.length >= 25, `${fx.cases.length} rows`);
    assert.equal(new Set(fx.cases.map((c) => c.name)).size, fx.cases.length, "row names are unique");
    assert.deepEqual(fx.limits, { viewMaxChars: HOLD_VIEW_MAX_CHARS, ...HOLD_VIEW_LIMITS });
  });
  for (const c of fx.cases) {
    test(`row ${c.name}: ${c.note}`, () => {
      if (c.dynamic) assert.equal(dynamicHoldTitle(c.dynamic.opTitle, c.dynamic.tool), c.title, "line 1 of a dynamic op");
      const out = renderHoldView(c.title, c.input, c.schema, c.recipients);
      assert.equal(out.view, c.view);
      assert.equal(out.summary, c.summary);
      assert.ok(out.view.length <= HOLD_VIEW_MAX_CHARS);
      assert.ok(out.summary.length <= HOLD_VIEW_LIMITS.summaryMaxChars);
    });
  }
  test("deterministic: members in another order give the same bytes (the approval hash, G7)", () => {
    const a = renderHoldView("T", { b: { y: 1, x: [1, 2] }, a: "z" }, null);
    const b = renderHoldView("T", { a: "z", b: { x: [1, 2], y: 1 } }, null);
    assert.equal(a.view, b.view);
  });
  test("QA-C369-1: anything not shown → line 2 is the fixed warning with the count; nothing elided → no warning line", () => {
    const rows = fx.cases.filter((c) => c.view.split("\n")[1]?.startsWith("Not every field is shown ("));
    assert.ok(rows.length >= 5, rows.map((r) => r.name).join(","));
    for (const r of rows) assert.match(r.view.split("\n")[1] as string, /^Not every field is shown \([0-9,]+ more\)\. Open More details before you approve\.$/);
    assert.equal(holdViewElidedLine(1234), "Not every field is shown (1,234 more). Open More details before you approve.");
    assert.ok(!renderHoldView("T", { a: 1 }, null).view.includes("Not every field"));
    // the attack row: recipients places first, so the recipient is on the card although the cap drops lines
    const atk = fx.cases.find((c) => c.name === "elision_cap_recipients_first") as Case;
    assert.deepEqual(atk.view.split("\n").slice(0, 4), ["Send mail", holdViewElidedLine(25), "To: attacker@evil.example", "Bcc: boss@evil.example"]);
  });
  test("QA-C369-2: a value under a secret key is (hidden) in the view, never its text", () => {
    const v = renderHoldView("T", { api_key: "sk-live-1", nested: { clientSecret: { a: "deep-secret" } }, to: "b@example.com" }, null).view;
    assert.ok(v.includes(`Api key: ${HOLD_VIEW_HIDDEN}`) && v.includes(`Nested › Client secret: ${HOLD_VIEW_HIDDEN}`));
    assert.ok(!v.includes("sk-live-1") && !v.includes("deep-secret"));
  });
});

describe("C369 D4 kept input: redaction and the 60 000-byte cap", () => {
  test("QA-C369-6 secret-key rule: the folded key contains a part, or a word equals auth/pwd/otp/pin/sig/signature", () => {
    assert.deepEqual([...HOLD_SECRET_KEY_PARTS], ["token", "secret", "password", "passwd", "passphrase", "apikey", "authorization", "cookie", "credential", "bearer", "jwt", "privatekey", "clientsecret"]);
    assert.deepEqual([...HOLD_SECRET_KEY_WORDS], ["auth", "pwd", "otp", "pin", "sig", "signature"]);
    const secret = ["api_key", "apiKey", "APIKEY", "x-api-key", "accessToken", "ACCESSTOKEN", "accesstoken", "Authorization", "session_cookie", "Set-Cookie", "client-secret", "clientSecret", "password", "passwords", "x.credentials", "secrets", "tokens", "privateKey", "private_key", "SECRETKEY", "bearerToken", "jwt", "auth", "x-auth", "auth_header", "pwd", "otp", "pin", "pin_code", "sig", "Signature", "pass_phrase", "passPhrase", "refresh_token", "tokenizer_mode"];
    const plain = ["keyword", "monkey", "to", "subject", "keys_count", "issue_key", "author", "authority", "pinned", "design", "signal", "otpx", "spin"];
    for (const k of secret) assert.ok(isSecretKey(k), k);
    for (const k of plain) assert.ok(!isSecretKey(k), k);
    // only ASCII case folding: U+212A KELVIN SIGN + "ey" never folds to "key"; U+0130 + "n" is not "pin"
    assert.ok(!isSecretKey(`${String.fromCodePoint(0x212a)}eyword`));
    assert.ok(!isSecretKey(`p${String.fromCodePoint(0x130)}n`));
  });
  test("QA-C369-3: `__proto__` members stay data in the kept input (null-prototype objects), at any depth", () => {
    const input = JSON.parse('{"to":"x","__proto__":{"bcc":"e","token":"t"},"n":{"__proto__":"s"},"l":[{"__proto__":1}]}') as Json;
    const out = redactHoldInput(input) as Record<string, any>;
    assert.equal(Object.getPrototypeOf(out), null);
    assert.ok(Object.hasOwn(out, "__proto__"));
    assert.equal(canonicalize(out), '{"__proto__":{"bcc":"e","token":"[redacted]"},"l":[{"__proto__":1}],"n":{"__proto__":"s"},"to":"x"}');
    assert.equal(keptHoldInput(input, canonicalize), canonicalize(out));
  });
  test("every member under a secret key is replaced at every depth; other values stay", () => {
    const input: Json = { to: "bob@example.com", api_key: "sk-live-1", nested: { accessToken: { a: 1 }, list: [{ password: "p", ok: true }] } };
    assert.deepEqual(JSON.parse(JSON.stringify(redactHoldInput(input))), { to: "bob@example.com", api_key: HOLD_INPUT_REDACTED, nested: { accessToken: HOLD_INPUT_REDACTED, list: [{ password: HOLD_INPUT_REDACTED, ok: true }] } });
  });
  test("the kept text is the JCS text of the redacted input; more than 60 000 UTF-8 bytes → not kept", () => {
    assert.equal(keptHoldInput({ b: 1, a: "x" }, canonicalize), '{"a":"x","b":1}');
    const overhead = Buffer.byteLength(canonicalize({ t: "" }), "utf8");
    assert.notEqual(keptHoldInput({ t: "a".repeat(HOLD_INPUT_MAX_BYTES - overhead) }, canonicalize), null, "exactly 60 000 bytes is kept");
    assert.equal(keptHoldInput({ t: "a".repeat(HOLD_INPUT_MAX_BYTES - overhead + 1) }, canonicalize), null, "60 001 bytes is not kept");
    // bytes, not characters: 2-byte characters reach the cap at half the length
    assert.equal(keptHoldInput({ t: "é".repeat(30_000) }, canonicalize), null);
  });
});

describe("C369 D4 tb.hold_details owner check (fire-on-bad, unit)", () => {
  const rt = { trust: { ws: "ws_A" }, instanceId: "ins_A", receipts: { holdDetailsRow: () => assert.fail("the row is never read for a refused caller") } } as unknown as Runtime;
  const owner = { type: "person", id: "per_1", ws: "ws_A", instance: "ins_A", iss: "tb:portal", sessionExpiresAt: Date.now() + 60_000 } as unknown as PersonPrincipal;
  const refused = (p: unknown) => assert.throws(() => holdDetails(rt, p as PersonPrincipal, { holdId: "hld_x" }), (e: { code?: string; httpStatus?: number }) => e.code === "session_required" && e.httpStatus === 403);
  test("a person of another instance, of another workspace, an agent or app principal, or none → 403 session_required, no read", () => {
    refused({ ...owner, instance: "ins_B" });
    refused({ ...owner, ws: "ws_B" });
    refused({ ...owner, type: "agent" });
    refused({ ...owner, type: "app" });
    refused(null);
  });
});

describe("QA-C369-8 boot reseal of kept hold inputs never throws", () => {
  test("stale blob → resealed under the current KEK; a blob no KEK opens → dropped, inputState unreadable; counts returned", () => {
    const t = tempDir();
    try {
      const db = openDb(t.dir);
      applySdkMigrations(db);
      const receipts = new ReceiptsImpl(db);
      // a fake sealer: "cur:" = current KEK, "old:" = TB_KEK_PREVIOUS, "lost:" = a KEK that is gone
      const sealer = {
        stale: (blob: string) => blob.startsWith("old:"),
        sealText: (_p: string, _id: string, text: string) => `cur:${text}`,
        unsealText: (_p: string, _id: string, blob: string) => {
          if (blob.startsWith("cur:") || blob.startsWith("old:")) return blob.slice(4);
          throw new Error("unseal_failed");
        },
      };
      const hold = (prefix: string) =>
        receipts.insert({
          kind: "hld",
          callId: null,
          caller: { type: "agent", id: "agt_1" as never, name: "A" },
          op: "mail_send",
          effect: "outward",
          holdFamily: "outward",
          status: "held",
          inputDigest: "sha256:x" as never,
          summary: "s",
          meta: null,
          idempotencyKey: null,
          view: "v",
          expiresAt: Date.now() + 60_000,
          heldInput: { state: "kept", seal: () => `${prefix}{"a":1}` },
        }).id;
      const ok = hold("cur:");
      const stale = hold("old:");
      const lost = hold("lost:");
      assert.deepEqual(receipts.resealHoldInputs(sealer), { resealed: 1, unreadable: 1 });
      assert.equal(receipts.holdDetailsRow(ok)?.inputSealed, 'cur:{"a":1}');
      assert.equal(receipts.holdDetailsRow(stale)?.inputSealed, 'cur:{"a":1}', "resealed under the current KEK");
      const gone = receipts.holdDetailsRow(lost);
      assert.equal(gone?.inputSealed, null);
      assert.equal(gone?.inputState, "unreadable");
      // a second boot changes nothing and still never throws
      assert.deepEqual(receipts.resealHoldInputs(sealer), { resealed: 0, unreadable: 0 });
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

// ── integration: a booted app ────────────────────────────────────────────────
const PRODUCT = "jotter";
const INS_APP = `ins_${"7".repeat(26)}`;
const SUBJECT = "Quarterly numbers SENTINEL-SUBJECT-41c2";
const share = { label: "Draft v1" };
const ran: Record<string, number> = {};

const sendOp = {
  id: "mail_send",
  title: "Send mail",
  description: "Send a mail (test op, default view).",
  input: {
    type: "object",
    required: ["to", "subject"],
    properties: { to: { type: "string", title: "Recipient" }, subject: { type: "string" }, api_key: { type: "string" }, body: { type: "string" } },
  },
  output: { type: "object" },
  crud: ["update"],
  effect: "outward",
  holdFamily: "outward",
  idempotency: "supported",
  receipt: true,
  audience: "agent",
} as unknown as Operation;
const shareOp = {
  id: "doc_share",
  title: "Share document",
  description: "Share a document (test op, static holdView that reads app state).",
  input: { type: "object", required: ["doc"], properties: { doc: { type: "string" } } },
  output: { type: "object" },
  crud: ["update"],
  effect: "outward",
  holdFamily: "outward",
  idempotency: "supported",
  receipt: true,
  audience: "agent",
} as unknown as Operation;

const toolsOp = {
  id: "tools",
  title: "Connected tools",
  description: "Call connected tools (test op, no app holdView).",
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode: "search", crudCeiling: ["read", "create", "update"], effectCeiling: "outward" },
} as unknown as Operation;

interface Booted {
  w: World;
  base: string;
  dataDir: string;
  running: RunningApp & { jobs: JobsApi };
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { companionCallers: [{ product: "evolution", ins: INS_APP, name: "Evolution" }] }));
  const manifest = fixtureManifest(port);
  manifest.operations.push(sendOp, shareOp, toolsOp);
  const count = (id: string) => {
    ran[id] = (ran[id] ?? 0) + 1;
  };
  const noop = async () => ({});
  const app = defineApp({
    manifest,
    migrations: migrationsDir(t.dir),
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: noop },
      // the scheduling op (S3-9): `{ id, share }` schedules doc_share { doc: share } in 150 ms
      note_get: async (input, c) => {
        const i = input as { id: string; share?: string };
        if (!i.share) return {} as Json;
        const job = (c as SdkOpContext).schedule({ op: "doc_share", input: { doc: i.share } }, { at: Date.now() + 150 });
        return { job: job.id };
      },
      note_delete: noop,
      notebook_rename: noop,
      mail_send: async () => {
        count("mail_send");
        return { sent: true };
      },
      doc_share: {
        run: async () => {
          count("doc_share");
          return { shared: true };
        },
        // C369 D2: a static view that reads app state (like Live-artifacts share/publish)
        holdView: (input) => `Share ${(input as { doc: string }).doc} as "${share.label}"`,
      },
    },
    // a dynamic op without holdView whose resolution names recipient places (C373 shape): the default view shows them first
    dynamic: {
      tools: {
        catalog: async () => [],
        resolve: async (tool) => (tool === "mail_out" ? ({ tool, crud: ["create"], effect: "outward", holdFamily: "outward", recipients: [{ pointer: "/to", kind: "email" }] } as never) : null),
        call: async () => {
          count("tools");
          return { sent: true };
        },
      },
    },
  });
  const running = await startApp(
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
    { ...testRoots(w), jobs: { pollMs: 40, drainMs: 300 } },
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
    running,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function agentCall(b: Booted, op: string, input: Json, grantToken?: string) {
  const g = grantToken ?? (await grant(b.w, b.w.agents.a, { held: ["outward"] }));
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {} }),
  });
  return { status: res.status, text: await res.text() };
}
const body = (r: { text: string }) => JSON.parse(r.text) as Record<string, any>;

async function signIn(b: Booted): Promise<{ cookie: string; csrf: string }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, "/") }),
  });
  assert.equal(res.status, 303);
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  return { cookie, csrf: s.csrf };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string } | null, op: string, input: Json) {
  const headers: Record<string, string> = { "content-type": "application/json", origin: b.base };
  if (s) {
    headers.cookie = s.cookie;
    headers["tb-csrf"] = s.csrf;
  }
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, { method: "POST", headers, body: JSON.stringify({ input }) });
  return { status: res.status, text: await res.text() };
}

function dbRow(b: Booted, id: string): Record<string, unknown> {
  const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
  try {
    return db.prepare("SELECT * FROM tb_receipts WHERE id = ?").get(id) as Record<string, unknown>;
  } finally {
    db.close();
  }
}
function dbExec(b: Booted, sql: string, ...args: (string | number)[]): void {
  const db = new DatabaseSync(join(b.dataDir, "app.db"));
  try {
    db.prepare(sql).run(...args);
  } finally {
    db.close();
  }
}

const principal = (w: World) => ({ type: "person", id: w.per, ws: w.ws, instance: w.ins, iss: "tb:portal", sessionExpiresAt: Date.now() + 60_000 }) as unknown as PersonPrincipal;
const approve = (b: Booted, id: string) => decideHold(principal(b.w), { holdId: id as `hld_${string}`, decision: "approve" });
const deny = (b: Booted, id: string) => decideHold(principal(b.w), { holdId: id as `hld_${string}`, decision: "deny" });

describe("C369 hold cards on a running app (D1–D4)", () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());

  const mail = { to: "bob@example.com", subject: SUBJECT, api_key: "sk-live-SECRET-77" };

  test("D1 + D2: a static op without holdView gets the labelled default view, bound by viewSha256; the receipt summary stays the op title (C90)", async () => {
    const r = await agentCall(b, "mail_send", mail);
    assert.equal(r.status, 202, r.text);
    const id = body(r).holdId as string;
    const row = dbRow(b, id);
    // QA-C369-2: the secret value is (hidden) on the card and in the stored view
    assert.equal(row.view, `Send mail\nApi key: ${HOLD_VIEW_HIDDEN}\nSubject: ${SUBJECT}\nRecipient: bob@example.com`);
    const meta = JSON.parse(String(row.meta)) as Record<string, unknown>;
    assert.match(String(meta.viewSha256), /^sha256:[0-9a-f]{64}$/);
    assert.equal(row.summary, "Send mail", "no input in the receipt summary (tb.holds_pending, C90)");
  });

  test("D3: tb.holds_list rows carry holdReason (≤ 280, the tb.holds_pending value); D4: tb.hold_details gives the owner the redacted input", async () => {
    const r = await agentCall(b, "mail_send", { ...mail, to: "carol@example.com" });
    const id = body(r).holdId as string;
    const list = await personOp(b, s, "tb.holds_list", { status: "held" });
    assert.equal(list.status, 200, list.text);
    const item = (body(list).output.items as Record<string, unknown>[]).find((i) => i.id === id);
    assert.equal(item?.holdReason, "held_family");
    assert.ok(String(item?.view).startsWith("Send mail\n"));

    const d = await personOp(b, s, HOLD_DETAILS_OP, { holdId: id });
    assert.equal(d.status, 200, d.text);
    const out = body(d).output as HoldDetails;
    assert.equal(out.holdId, id);
    assert.equal(out.receiptId, id);
    assert.equal(out.status, "held");
    assert.equal(out.op, "mail_send");
    assert.equal(out.opTitle, "Send mail");
    assert.equal(out.tool, undefined);
    assert.equal(out.family, "outward");
    assert.equal(out.reason, "held_family");
    assert.equal(out.caller.id, b.w.agents.a);
    assert.equal(out.caller.type, "agent");
    assert.match(out.inputDigest, /^sha256:/);
    assert.deepEqual(out.input, { to: "carol@example.com", subject: SUBJECT, api_key: HOLD_INPUT_REDACTED });
    assert.equal(out.inputState, "kept");
    assert.equal(out.inputWipeAt, null, "not terminal yet");
    assert.match(out.createdAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/, "UTC (D6)");
    assert.match(String(out.expiresAt), /Z$/);
    assert.equal(out.decidedAt, null);
    assert.equal(out.viewSha256, JSON.parse(String(dbRow(b, id).meta)).viewSha256);
    assert.ok(!d.text.includes("sk-live-SECRET-77"), "a secret key's value never leaves");
    // sealed at rest: the column holds no plain text of the input
    const sealed = String(dbRow(b, id).input_sealed);
    assert.ok(sealed.length > 0 && !sealed.includes(SUBJECT) && !sealed.includes("carol@example.com"));
    assert.equal(dbRow(b, id).input_state, "kept");
  });

  test("fire-on-bad: an agent call, an app call and a call without a session to tb.hold_details are refused and carry no input", async () => {
    const r = await agentCall(b, "mail_send", { ...mail, to: "dan@example.com" });
    const id = body(r).holdId as string;
    const asAgent = await agentCall(b, HOLD_DETAILS_OP, { holdId: id });
    assert.equal(asAgent.status, 403, asAgent.text);
    assert.equal(body(asAgent).error.code, "audience_not_agent");
    const appGrant = await signGrant(
      { iss: "tb:portal", sub: `tb:ins:${INS_APP}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: [], caps: {}, wf: [HOLD_DETAILS_OP], polrev: 1, prd: "evolution" } as never,
      b.w.portal,
    );
    const asApp = await agentCall(b, HOLD_DETAILS_OP, { holdId: id }, appGrant);
    assert.equal(asApp.status, 403, asApp.text);
    assert.equal(body(asApp).error.code, "audience_not_agent");
    const noSession = await personOp(b, null, HOLD_DETAILS_OP, { holdId: id });
    assert.equal(noSession.status, 401);
    for (const x of [asAgent, asApp, noSession]) assert.ok(!x.text.includes("dan@example.com") && !x.text.includes(SUBJECT));
    // unknown id, a receipt that is not a hold, a bad input
    assert.equal(body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: `hld_${ulid()}` })).error.code, "hold_not_found");
    assert.equal(body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: `rcp_${ulid()}` })).error.code, "hold_not_found");
    assert.equal(body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id, extra: 1 })).error.code, "input_invalid");
  });

  test("D2: the approved repeat of a default-view op runs once; D4: after the run the input stays 7 days, then the sweep wipes it", async () => {
    const input = { ...mail, to: "erin@example.com" };
    const r = await agentCall(b, "mail_send", input);
    const id = body(r).holdId as string;
    await approve(b, id);
    const before = ran.mail_send ?? 0;
    const run = await agentCall(b, "mail_send", input);
    assert.equal(run.status, 200, run.text);
    assert.equal(ran.mail_send, before + 1);
    const d = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.equal(d.status, "run");
    assert.equal(d.inputState, "kept", "still kept inside the 7-day window after the terminal status");
    assert.ok(d.inputWipeAt !== null);
    const wipeAt = Date.parse(d.inputWipeAt as string);
    assert.ok(Math.abs(wipeAt - (Date.now() + HOLD_INPUT_KEEP_MS)) < 60_000, "terminal status + 7 days");
    // one ms before the window ends: still kept; after it: wiped (the sealed column is NULL)
    const receipts = b.running.receipts as unknown as Receipts;
    receipts.sweep(wipeAt - 1);
    assert.notEqual(dbRow(b, id).input_sealed, null);
    receipts.sweep(wipeAt);
    assert.equal(dbRow(b, id).input_sealed, null);
    const wiped = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.equal(wiped.inputState, "wiped");
    assert.equal(wiped.input, null);
    assert.equal(wiped.inputWipeAt, d.inputWipeAt);
  });

  test("D4: a denied hold keeps its input 7 days too; an expired hold the same; past the window tb.hold_details says wiped even before the sweep", async () => {
    const r = await agentCall(b, "mail_send", { ...mail, to: "fay@example.com" });
    const id = body(r).holdId as string;
    await deny(b, id);
    const d = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.equal(d.status, "denied");
    assert.equal(d.inputState, "kept");
    assert.ok(d.inputWipeAt !== null && d.decidedAt !== null);
    // the window ended but no sweep ran yet: never shown
    dbExec(b, "UPDATE tb_receipts SET input_wipe_at = ? WHERE id = ?", Date.now() - 1, id);
    const late = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.equal(late.inputState, "wiped");
    assert.equal(late.input, null);

    const e = await agentCall(b, "mail_send", { ...mail, to: "gus@example.com" });
    const eid = body(e).holdId as string;
    dbExec(b, "UPDATE tb_receipts SET expires_at = ? WHERE id = ?", Date.now() - 1, eid);
    (b.running.receipts as unknown as Receipts).sweep(Date.now());
    const exp = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: eid })).output as HoldDetails;
    assert.equal(exp.status, "denied");
    assert.equal(exp.inputState, "kept");
    assert.ok(exp.inputWipeAt !== null);
  });

  test("D4: an input over 60 000 bytes is not kept (too_large); the hold itself is created as usual", async () => {
    const r = await agentCall(b, "mail_send", { to: "hal@example.com", subject: "big", body: "x".repeat(HOLD_INPUT_MAX_BYTES) });
    assert.equal(r.status, 202, r.text);
    const id = body(r).holdId as string;
    assert.ok(String(dbRow(b, id).view).includes("Body (plain text, first 1,000 characters; 59,000 more not shown):"));
    const d = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.equal(d.inputState, "too_large");
    assert.equal(d.input, null);
    assert.equal(dbRow(b, id).input_sealed, null);
  });

  test("D2 fire-on-bad: a static holdView whose text changed between hold and repeat → the approval is NOT used (new hold); unchanged → runs once", async () => {
    share.label = "Draft v1";
    const first = await agentCall(b, "doc_share", { doc: "d1" });
    assert.equal(first.status, 202, first.text);
    const hold1 = body(first).holdId as string;
    assert.equal(dbRow(b, hold1).view, 'Share d1 as "Draft v1"');
    assert.match(String(JSON.parse(String(dbRow(b, hold1).meta)).viewSha256), /^sha256:/);
    await approve(b, hold1);
    share.label = "Final (public)";
    const before = ran.doc_share ?? 0;
    const retry = await agentCall(b, "doc_share", { doc: "d1" });
    assert.equal(retry.status, 202, "the owner approved another text: the approval does not carry over");
    const hold2 = body(retry).holdId as string;
    assert.notEqual(hold2, hold1);
    assert.equal(dbRow(b, hold2).view, 'Share d1 as "Final (public)"');
    assert.equal(ran.doc_share ?? 0, before, "the handler never ran on the old approval");
    assert.equal(dbRow(b, hold1).status, "approved", "the old approval stays unused until it expires");
    await approve(b, hold2);
    const run = await agentCall(b, "doc_share", { doc: "d1" });
    assert.equal(run.status, 200, run.text);
    assert.equal(ran.doc_share, before + 1);
    assert.equal(dbRow(b, hold2).status, "run");
  });

  test("D2 fail closed: an approval without viewSha256 (a hold of an older SDK) is never used", async () => {
    const input = { ...mail, to: "ivy@example.com" };
    const r = await agentCall(b, "mail_send", input);
    const id = body(r).holdId as string;
    await approve(b, id);
    dbExec(b, "UPDATE tb_receipts SET meta = 'null' WHERE id = ?", id);
    const before = ran.mail_send ?? 0;
    const retry = await agentCall(b, "mail_send", input);
    assert.equal(retry.status, 202, retry.text);
    assert.notEqual(body(retry).holdId, id);
    assert.equal(ran.mail_send ?? 0, before);
  });

  test("QA-C369-4: viewSha256 stays in meta after the approved repeat runs (and in tb.hold_details)", async () => {
    const input = { ...mail, to: "jo@example.com" };
    const id = body(await agentCall(b, "mail_send", input)).holdId as string;
    const hash = JSON.parse(String(dbRow(b, id).meta)).viewSha256 as string;
    await approve(b, id);
    assert.equal((await agentCall(b, "mail_send", input)).status, 200);
    assert.equal(dbRow(b, id).status, "run");
    assert.equal(JSON.parse(String(dbRow(b, id).meta)).viewSha256, hash);
    assert.equal((body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails).viewSha256, hash);
  });

  test("QA-C369-3: a `__proto__` member is held like any member (no 500) and stays in tb.hold_details", async () => {
    const input = JSON.parse('{"to":"kim@example.com","subject":"p","__proto__":{"bcc":"e@example.com"}}') as Json;
    const r = await agentCall(b, "mail_send", input);
    assert.equal(r.status, 202, r.text);
    const id = body(r).holdId as string;
    assert.ok(String(dbRow(b, id).view).includes("Proto › Bcc: e@example.com"));
    const d = body(await personOp(b, s, HOLD_DETAILS_OP, { holdId: id })).output as HoldDetails;
    assert.ok(d.input !== null && Object.hasOwn(d.input as object, "__proto__"));
    assert.deepEqual(Object.getOwnPropertyDescriptor(d.input as object, "__proto__")?.value, { bcc: "e@example.com" });
  });

  test("dynamic default view: line 1 `<op title>: <tool>`, the resolution's recipient places first; tb.holds_pending rows name the tool (static rows do not)", async () => {
    const r = await agentCall(b, "tools", { tool: "mail_out", arguments: { body: "Hi", to: "lee@example.com" } });
    assert.equal(r.status, 202, r.text);
    const id = body(r).holdId as string;
    assert.equal(dbRow(b, id).view, "Connected tools: mail_out\nTo: lee@example.com\nBody: Hi");
    const g = await grant(b.w, b.w.agents.a, { held: ["outward"] });
    const pend = await agentCall(b, "tb.holds_pending", { limit: 100 }, g);
    assert.equal(pend.status, 200, pend.text);
    const items = body(pend).output.items as Record<string, unknown>[];
    assert.equal(items.find((i) => i.id === id)?.tool, "mail_out");
    const statics = items.filter((i) => i.op === "mail_send");
    assert.ok(statics.length > 0 && statics.every((i) => !("tool" in i)));
    assert.ok(!pend.text.includes("lee@example.com"), "no input in tb.holds_pending (C90)");
  });

  test("S3-9: a scheduled op whose own approved hold no longer shows the same view ends refused / hold_view_changed; the handler never runs", async () => {
    share.label = "Sched v1";
    const before = ran.doc_share ?? 0;
    const sch = await agentCall(b, "note_get", { id: "x", share: "s9" });
    assert.equal(sch.status, 200, sch.text);
    const jobId = body(sch).output.job as string;
    const waiting = await until(async () => {
      const j = b.running.jobs.get(jobId);
      return j?.status === "waiting" && j.holdId ? j : null;
    });
    const hid = waiting.holdId as string;
    assert.equal(dbRow(b, hid).view, 'Share s9 as "Sched v1"');
    assert.match(String(JSON.parse(String(dbRow(b, hid).meta)).viewSha256), /^sha256:/);
    share.label = "Sched v2 (changed)";
    await approve(b, hid);
    const done = await until(async () => {
      const j = b.running.jobs.get(jobId);
      return j && j.status !== "waiting" && j.status !== "queued" ? j : null;
    });
    assert.equal(done.status, "refused");
    assert.equal(done.lastError, "hold_view_changed");
    assert.equal(ran.doc_share ?? 0, before);
  });

  test("D4 + QA-C369-2: the export carries neither the sealed input nor the view; meta.viewSha256 stays", async () => {

    const ex = await b.running.backups.exportNow();
    for await (const _ of ex.stream) void _;
    const files = new Map<string, Buffer>();
    // TB_BACKUP_DIR is unset here: the archive is in <TB_DATA_DIR>/backup (env.ts)
    await readTarGz(join(b.dataDir, "backup", ex.file), async (e) => bufferSink(64 * 1024 * 1024, (buf) => files.set(e.name, buf)));
    const lines = (files.get("receipts.jsonl")?.toString() ?? "").split("\n").filter(Boolean);
    assert.ok(lines.length > 0);
    for (const l of lines) {
      const row = JSON.parse(l) as Record<string, unknown>;
      assert.ok(!("input_sealed" in row), "no input_sealed key");
      assert.ok(!("view" in row), "no view key");
    }
    assert.ok(!lines.join("").includes(SUBJECT), "no input text of a hold");
    assert.ok(lines.some((l) => String((JSON.parse(l) as { meta?: string }).meta).includes("viewSha256")));
    assert.ok(lines.some((l) => "input_state" in (JSON.parse(l) as Record<string, unknown>)));
  });
});
