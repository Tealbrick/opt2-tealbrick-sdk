// v0.1.39 (SDK-API §21, CREDENTIALS K14, spec 0.1.64, C326): POST /tb/v1/person-op — a person op relayed by the workspace
// bridge for a native owner session. Real HTTP, a fake bridge, K14 tokens signed with the world's TEST Portal key.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { after, before, describe, test } from "node:test";
import { type Ed25519KeyPair, sha256Bytes, signCompact, signSlice, thumbprint, ulid } from "@opt2-tealbrick/manifest";
import { LIFETIME_S, MAX_JWS_BYTES, TYP } from "@opt2-tealbrick/spec/credentials";
import type { HoldFamily, Operation } from "@opt2-tealbrick/spec/manifest";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import type { Json, PersonPrincipal, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { decideHold, defineApp, familyAllowedFor, familyNeedsPortal, PERSON_OP_HEADER, type SdkOpContext, startApp, TbError } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

/** the one product on the v0.1.64 relay allow-list */
const PRODUCT = "inbox";

function personOpDef(id: string, effect: "read" | "write", input: Operation["input"] = { type: "object" }): Operation {
  return {
    id,
    title: id,
    description: `Test person op ${id}.`,
    input,
    output: { type: "object" },
    crud: effect === "read" ? ["read"] : ["update"],
    effect,
    idempotency: effect === "read" ? "none" : "supported",
    receipt: false,
    audience: "person",
  };
}

function testApp(port: number, migrations: string, effects: Record<string, number>, seen: { via: unknown[] }) {
  const manifest = fixtureManifest(port);
  manifest.id = PRODUCT;
  manifest.name = "Inbox";
  manifest.operations.push(
    personOpDef("items_list", "read"),
    personOpDef("item_get", "read", { type: "object", required: ["id"], properties: { id: { type: "string" } } }),
    personOpDef("item_decide", "write", {
      type: "object",
      required: ["id", "answer"],
      additionalProperties: false,
      properties: { id: { type: "string" }, answer: { type: "string" }, family: { type: ["string", "null"] } },
    }),
    // agent ops that are held for the owner (families money, first_contact)
    {
      id: "pay",
      title: "Pay",
      description: "Pay an invoice.",
      input: { type: "object", required: ["amount"], properties: { amount: { type: "number" } } },
      output: { type: "object" },
      crud: ["update"],
      effect: "money",
      holdFamily: "money",
      idempotency: "supported",
      receipt: true,
      audience: "agent",
    },
    {
      id: "contact",
      title: "Contact",
      description: "Write to a new contact.",
      input: { type: "object", required: ["to"], properties: { to: { type: "string" } } },
      output: { type: "object" },
      crud: ["update"],
      effect: "outward",
      holdFamily: "first_contact",
      idempotency: "supported",
      receipt: true,
      audience: "agent",
    },
  );
  const bump = (k: string) => {
    effects[k] = (effects[k] ?? 0) + 1;
  };
  return defineApp({
    manifest,
    migrations,
    handlers: {
      note_create: { scope: (i) => String((i as { notebook: string }).notebook), run: async () => ({ id: "n1" }) },
      note_get: async () => ({}),
      note_delete: async () => {
        bump("note_delete");
        return { deleted: true };
      },
      notebook_rename: async () => {
        bump("notebook_rename");
        return { renamed: true };
      },
      pay: async () => ({ paid: true }),
      contact: async () => ({ sent: true }),
      items_list: async (_input, ctx) => {
        const c = (ctx as SdkOpContext).caller;
        seen.via.push(c.via);
        bump("items_list");
        return { items: [], caller: c.type, via: c.via ?? null, idempotencyKey: ctx.idempotencyKey, hasScopeGrants: ctx.scopeGrants !== undefined };
      },
      item_get: async (input) => ({ id: (input as { id: string }).id, title: "Grüße ✓" }),
      item_decide: async (input, ctx) => {
        const i = input as { id: string; answer: string; family?: HoldFamily | null };
        const via = (ctx as SdkOpContext).caller.via;
        // an item that carries a hold (C277 A3): the app applies the family rule itself
        if ("family" in i && !familyAllowedFor(via, i.family ?? null)) throw familyNeedsPortal();
        bump("item_decide");
        return { id: i.id, answer: i.answer, via: via ?? null, n: effects.item_decide as Json };
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  effects: Record<string, number>;
  seen: { via: unknown[] };
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const effects: Record<string, number> = {};
  const seen = { via: [] as unknown[] };
  const running = await startApp(
    testApp(port, migrationsDir(t.dir), effects, seen),
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
    effects,
    seen,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

type K14Over = Partial<Record<"iss" | "sub" | "aud" | "ws" | "op" | "bd" | "idk" | "cli" | "pop" | "jti", string>> & { iat?: number; exp?: number; key?: Ed25519KeyPair; typ?: string };

/** K14 as Core mints it (PORTAL-API v0.1.64 B): `bd` = "sha256:" + hex over the UTF-8 bytes of the exact body. */
async function k14(w: World, op: string, body: string, over: K14Over = {}): Promise<string> {
  const iat = over.iat ?? nowS();
  const { key, typ, ...claims } = over;
  return signCompact(
    typ ?? TYP.personOp,
    {
      iss: "tb:portal",
      sub: `tb:per:${w.per}`,
      aud: `tb:ins:${w.ins}`,
      iat,
      exp: iat + LIFETIME_S.personOp,
      jti: ulid(),
      ws: w.ws,
      op,
      bd: sha256Bytes(Buffer.from(body, "utf8")),
      idk: `idk_${ulid()}`,
      cli: "tbm",
      pop: `pop_${ulid()}`,
      ...claims,
    },
    key ?? w.portal,
    MAX_JWS_BYTES,
  );
}

async function relay(b: Booted, token: string | null, body: string, extraHeaders: Record<string, string> = {}) {
  const res = await fetch(`${b.base}/tb/v1/person-op`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(token !== null ? { [PERSON_OP_HEADER]: token } : {}), ...extraHeaders },
    body,
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** relay one call with a fresh K14 for `input` */
async function call(b: Booted, op: string, input: Json, over: K14Over = {}) {
  const body = JSON.stringify(input);
  return relay(b, await k14(b.w, op, body, over), body);
}

async function holdFor(b: Booted, op: string, input: Json, held: HoldFamily[], caps = {}): Promise<string> {
  const g = await grant(b.w, b.w.agents.a, { held, caps });
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": await callProof(b.w, g, op, input) },
    body: JSON.stringify({ input, context: {} }),
  });
  const out = (await res.json()) as { status: string; holdId?: string };
  assert.equal(out.status, "held", JSON.stringify(out));
  return out.holdId as string;
}

function relayedPrincipal(b: Booted, via: "tbm" | undefined): PersonPrincipal {
  return { type: "person", id: b.w.per, ws: b.w.ws, instance: b.w.ins, iss: "tb:portal", sessionExpiresAt: Date.now() + 10_000, ...(via ? { via } : {}) };
}

const code = (r: { body: Record<string, any> }) => r.body.error?.code as string | undefined;

describe("familyAllowedFor (SDK-API §21 family rule, fail closed)", () => {
  test("browser sessions (via undefined) → true for every family and null", () => {
    for (const f of ["money", "destructive", "first_contact", null] as const) assert.equal(familyAllowedFor(undefined, f), true);
  });
  test("via tbm: money / destructive / null / unknown → false; another known family → true", () => {
    assert.equal(familyAllowedFor("tbm", "money"), false);
    assert.equal(familyAllowedFor("tbm", "destructive"), false);
    assert.equal(familyAllowedFor("tbm", null), false);
    assert.equal(familyAllowedFor("tbm", "caps" as HoldFamily), false);
    assert.equal(familyAllowedFor("tbm", "policy" as HoldFamily), false);
    assert.equal(familyAllowedFor("tbm", "new_family" as HoldFamily), false);
    assert.equal(familyAllowedFor("tbm", "first_contact"), true);
    assert.deepEqual([...PERSON_OP_RELAY.refuseFamiliesFor.tbm], ["money", "destructive"]);
  });
  test("deny by default: a via without a refuseFamiliesFor entry (tbd, cli) → false for every family", () => {
    assert.equal(familyAllowedFor("tbd" as never, "first_contact"), false);
    assert.equal(familyAllowedFor("tbd" as never, "money"), false);
    assert.equal(familyAllowedFor("tbd" as never, null), false);
    assert.equal(familyAllowedFor("cli" as "tbm", "first_contact"), false);
  });
});

describe("POST /tb/v1/person-op (K14, SDK-API §21)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("C354: the claim and every status push declare caps [\"person_op\"] (gate by capability, never by version)", async () => {
    assert.ok(b.bridge.claimBodies.length >= 1);
    for (const c of b.bridge.claimBodies) assert.deepEqual(c.caps, ["person_op"], "claim");
    await until(async () => b.bridge.statuses.length > 0);
    for (const s of b.bridge.statuses) assert.deepEqual(s.caps, ["person_op"], "status");
  });

  test("happy path: an allow-listed read op runs and returns its output; the person caller carries via tbm; no cookie, no CSRF", async () => {
    const r = await call(b, "items_list", {}, { idk: "idk_happy_path_0001" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body, { status: "ok", output: { items: [], caller: "person", via: "tbm", idempotencyKey: "idk_happy_path_0001", hasScopeGrants: false } });
    assert.equal(b.seen.via.at(-1), "tbm");
  });

  test("an allow-listed write op from tbm runs once; non-ASCII body bytes hash to the K14 bd", async () => {
    const before = b.effects.item_decide ?? 0;
    const r = await call(b, "item_decide", { id: "itm_1", answer: "Ja, gerne — Grüße ✓ 日本" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.output.answer, "Ja, gerne — Grüße ✓ 日本");
    assert.equal(r.body.output.via, "tbm");
    assert.equal(b.effects.item_decide, before + 1);
    // the same bytes with a digest over the UTF-16 code units (wrong encoding) are refused
    const body = JSON.stringify({ id: "itm_1", answer: "Grüße" });
    const wrong = `sha256:${createHash("sha256").update(Buffer.from(body, "utf16le")).digest("hex")}`;
    const bad = await relay(b, await k14(b.w, "item_decide", body, { bd: wrong }), body);
    assert.equal(bad.status, 401);
    assert.equal(code(bad), "person_op_invalid");
  });

  test("S-PO-1: a K11 launch ticket on this route → 401 person_op_invalid", async () => {
    const r = await relay(b, await ticket(b.w), "{}");
    assert.equal(r.status, 401);
    assert.equal(code(r), "person_op_invalid");
    const none = await relay(b, null, "{}");
    assert.equal(none.status, 401);
    assert.equal(code(none), "person_op_invalid");
  });

  test("S-PO-1b: K14 claims under a K11 typ, a non-Portal signer, or a non-Portal iss → 401", async () => {
    const asTicket = await call(b, "items_list", {}, { typ: TYP.personTicket });
    assert.equal(asTicket.status, 401);
    const byBridge = await call(b, "items_list", {}, { key: b.w.bridgeKey });
    assert.equal(byBridge.status, 401);
    const bridgeIss = await call(b, "items_list", {}, { iss: `tb:brg:${b.w.brg}` });
    assert.equal(bridgeIss.status, 401);
    // the K14 claim set is closed: an extra claim → 401
    const claims = JSON.parse(Buffer.from((await k14(b.w, "items_list", "{}")).split(".")[1] as string, "base64url").toString("utf8")) as Record<string, unknown>;
    const extraClaim = await relay(b, await signCompact(TYP.personOp, { ...claims, pur: "launch" }, b.w.portal, MAX_JWS_BYTES), "{}");
    assert.equal(extraClaim.status, 401);
    assert.equal(b.effects.items_list, 1, "no refused call ran the handler");
  });

  test("S-PO-2: aud of another instance of the same product → 401", async () => {
    const r = await call(b, "items_list", {}, { aud: `tb:ins:ins_${ulid()}` });
    assert.equal(r.status, 401);
    assert.equal(code(r), "person_op_invalid");
  });

  test("S-PO-3: foreign ws → 401", async () => {
    const r = await call(b, "items_list", {}, { ws: `ws_${ulid()}` });
    assert.equal(r.status, 401);
    assert.equal(code(r), "person_op_invalid");
  });

  test("S-PO-4: bd mismatch → 401 and the jti is spent (the same token with the right body → 401)", async () => {
    const good = JSON.stringify({ id: "itm_4", answer: "yes" });
    const token = await k14(b.w, "item_decide", good);
    const before = b.effects.item_decide ?? 0;
    const tampered = await relay(b, token, JSON.stringify({ id: "itm_4", answer: "no" }));
    assert.equal(tampered.status, 401);
    assert.equal(code(tampered), "person_op_invalid");
    const retry = await relay(b, token, good);
    assert.equal(retry.status, 401);
    assert.equal(code(retry), "person_op_invalid");
    assert.equal(b.effects.item_decide ?? 0, before, "nothing ran");
    // whitespace is part of the bytes: a re-serialised body does not match either
    const spaced = await relay(b, await k14(b.w, "item_decide", good), JSON.stringify(JSON.parse(good), null, 1));
    assert.equal(spaced.status, 401);
  });

  test("S-PO-5: replay of a used K14 → 401", async () => {
    const body = "{}";
    const token = await k14(b.w, "items_list", body);
    assert.equal((await relay(b, token, body)).status, 200);
    const again = await relay(b, token, body);
    assert.equal(again.status, 401);
    assert.equal(code(again), "person_op_invalid");
  });

  test("S-PO-6: an op outside the allow-list (a manifest person op, tb.key_set, tb.export, tb.holds_decide) → 403 person_op_not_allowed", async () => {
    const before = b.effects.notebook_rename ?? 0;
    const cases: [string, Json][] = [
      ["notebook_rename", { notebook: "nb", label: "x" }],
      ["tb.key_set", { name: "API_KEY", value: "placeholder" }],
      ["tb.export", {}],
      ["tb.holds_decide", { holdId: `hld_${ulid()}`, decision: "approve" }],
      ["tb.holds_list", {}],
      ["note_delete", { id: "n1" }],
    ];
    for (const [op, input] of cases) {
      const r = await call(b, op, input);
      assert.equal(r.status, 403, `${op}: ${JSON.stringify(r.body)}`);
      assert.equal(code(r), "person_op_not_allowed", op);
    }
    assert.equal(b.effects.notebook_rename ?? 0, before);
  });

  test("an allow-listed op the manifest does not declare → 404 op_not_found; bad input → 400 validation_failed", async () => {
    const missing = await call(b, "item_ack", { id: "itm" });
    assert.equal(missing.status, 404);
    assert.equal(code(missing), "op_not_found");
    const invalid = await call(b, "item_decide", { id: "itm" });
    assert.equal(invalid.status, 400);
    assert.equal(code(invalid), "validation_failed");
    const notObject = await call(b, "item_get", ["x"] as unknown as Json);
    assert.equal(notObject.status, 400);
    assert.equal(code(notObject), "validation_failed");
    const notJson = "{not json";
    const bad = await relay(b, await k14(b.w, "item_get", notJson), notJson);
    assert.equal(bad.status, 400);
    assert.equal(code(bad), "validation_failed");
  });

  test("S-PO-7: cli tbd for a WRITE op and for a READ op, or cli → 401 person_op_invalid (cli ∈ PERSON_OP_RELAY.clients is a V0 check); the jti is not spent", async () => {
    const before = { decide: b.effects.item_decide ?? 0, list: b.effects.items_list ?? 0 };
    // write op (item_decide), read ops (items_list, item_get) with cli tbd; and the CLI client
    for (const [op, input, cli] of [
      ["item_decide", { id: "itm_7", answer: "yes" }, "tbd"],
      ["items_list", {}, "tbd"],
      ["item_get", { id: "itm_7" }, "tbd"],
      ["items_list", {}, "cli"],
    ] as const) {
      const r = await call(b, op, input, { cli });
      assert.equal(r.status, 401, `${op} ${cli}`);
      assert.equal(code(r), "person_op_invalid");
    }
    assert.equal(b.effects.item_decide ?? 0, before.decide, "the write op did not run");
    assert.equal(b.effects.items_list ?? 0, before.list, "the read op did not run");
    // V0 runs before the jti is consumed: a refused cli does not spend a jti (a later valid token with that jti still runs)
    const jti = ulid();
    assert.equal((await call(b, "items_list", {}, { cli: "tbd", jti })).status, 401);
    assert.equal((await call(b, "items_list", {}, { jti })).status, 200);
  });

  test("S-PO-8: tb.holds_decide with via tbm and family money / destructive / unknown (caps) → 403 family_needs_portal; the hold stays held", async () => {
    const money = await holdFor(b, "pay", { amount: 5 }, []);
    const destructive = await holdFor(b, "note_delete", { id: "n8" }, ["destructive"]);
    // a cap hold: family "caps" is not a HoldFamily → unknown → refused (fail closed)
    const caps = await holdFor(b, "note_delete", { id: "n8c" }, [], { destructive: { max: 0, per: "hour" } });
    for (const holdId of [money, destructive, caps]) {
      await assert.rejects(decideHold(relayedPrincipal(b, "tbm"), { holdId: holdId as never, decision: "approve" }), (e: unknown) => e instanceof TbError && e.code === "family_needs_portal" && e.httpStatus === 403);
    }
    // a family the relay may decide (first_contact) passes; a browser session (no via) decides money
    const contact = await holdFor(b, "contact", { to: "a@example.org" }, ["first_contact"]);
    assert.equal((await decideHold(relayedPrincipal(b, "tbm"), { holdId: contact as never, decision: "deny" })).status, "denied");
    assert.equal((await decideHold(relayedPrincipal(b, undefined), { holdId: money as never, decision: "deny" })).status, "denied");
    assert.equal((await decideHold(relayedPrincipal(b, undefined), { holdId: destructive as never, decision: "deny" })).status, "denied");
  });

  test("S-PO-8b: an app decide op with via tbm refuses money / destructive / null families with family_needs_portal (one effect only for allowed)", async () => {
    const before = b.effects.item_decide ?? 0;
    for (const family of ["money", "destructive", null]) {
      const r = await call(b, "item_decide", { id: "itm_8", answer: "yes", family });
      assert.equal(r.status, 403, JSON.stringify(r.body));
      assert.equal(code(r), "family_needs_portal");
    }
    assert.equal(b.effects.item_decide ?? 0, before);
    const ok = await call(b, "item_decide", { id: "itm_8", answer: "yes", family: "first_contact" });
    assert.equal(ok.status, 200);
    assert.equal(b.effects.item_decide, before + 1);
  });

  test("S-PO-9: exp 3 s and 5 s in the past → 401 (only PERSON_OP_RELAY.expLeewayS = 2 s, not LEEWAY_S); lifetime over 10 s → 401; iat 5 s ahead → 401", async () => {
    assert.equal(PERSON_OP_RELAY.expLeewayS, 2);
    assert.equal(LIFETIME_S.personOp, 10);
    // QA-SPEC43-7: an SDK that applied the general LEEWAY_S (30 s) to K14 would accept both of these
    for (const ago of [3, 5]) {
      const exp = nowS() - ago;
      const expired = await call(b, "items_list", {}, { iat: exp - 10, exp });
      assert.equal(expired.status, 401, `exp ${ago} s in the past`);
      assert.equal(code(expired), "person_op_invalid");
    }
    const long = nowS();
    const tooLong = await call(b, "items_list", {}, { iat: long, exp: long + LIFETIME_S.personOp + 1 });
    assert.equal(tooLong.status, 401);
    const ahead = nowS() + 5;
    assert.equal((await call(b, "items_list", {}, { iat: ahead, exp: ahead + 10 })).status, 401);
    // within expLeewayS: exp 1 s ago → accepted
    const recent = nowS() - 1;
    assert.equal((await call(b, "items_list", {}, { iat: recent - 9, exp: recent })).status, 200);
  });

  test("S-PO-11: the same idk twice (two K14) → one effect, the second answer is the stored output; another input → 409", async () => {
    const before = b.effects.item_decide ?? 0;
    const idk = `idk_${ulid()}`;
    const input = { id: "itm_11", answer: "yes" };
    const first = await call(b, "item_decide", input, { idk });
    const second = await call(b, "item_decide", input, { idk });
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.deepEqual(second.body, first.body);
    assert.equal(b.effects.item_decide, before + 1);
    const conflict = await call(b, "item_decide", { id: "itm_11", answer: "no" }, { idk });
    assert.equal(conflict.status, 409);
    assert.equal(code(conflict), "idempotency_conflict");
    assert.equal(b.effects.item_decide, before + 1);
  });

  test("S-PO-11b (core#65 QA INFO-1/2): two valid K14 with the SAME idk and DIFFERENT bodies on a write op → the second is 409 idempotency_conflict; the handler ran once", async () => {
    const before = b.effects.item_decide ?? 0;
    const idk = `idk_${ulid()}`;
    const bodyA = JSON.stringify({ id: "itm_11b", answer: "approve" });
    const bodyB = JSON.stringify({ id: "itm_11b", answer: "deny" });
    // each K14 is valid on its own: its own jti, and bd over its own body
    const first = await relay(b, await k14(b.w, "item_decide", bodyA, { idk }), bodyA);
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(first.body.output.answer, "approve");
    const second = await relay(b, await k14(b.w, "item_decide", bodyB, { idk }), bodyB);
    assert.equal(second.status, 409, JSON.stringify(second.body));
    assert.equal(code(second), "idempotency_conflict");
    assert.equal(b.effects.item_decide, before + 1, "the handler ran once");
  });

  test("the browser person route is unchanged: no via, no K14 accepted there", async () => {
    const r = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/items_list`, { method: "POST", headers: { "content-type": "application/json", [PERSON_OP_HEADER]: await k14(b.w, "items_list", "{}") }, body: JSON.stringify({ input: {} }) });
    assert.equal(r.status, 401);
    assert.equal(((await r.json()) as { error: { code: string } }).error.code, "session_required");
  });

  test("personNbf: a K14 minted before 'sign out everywhere' → 401 (and its jti is spent)", async () => {
    const iat = nowS() - 2;
    const body = "{}";
    const token = await k14(b.w, "items_list", body, { iat, exp: iat + 10 });
    b.bridge.push(await slice(b.w, PRODUCT, { personNbf: nowS() }));
    // wait until the new slice is installed (a K14 older than personNbf is then refused)
    await until(async () => (await call(b, "items_list", {}, { iat: iat - 1, exp: iat + 9 })).status === 401);
    const r = await relay(b, token, body);
    assert.equal(r.status, 401);
    assert.equal(code(r), "person_op_invalid");
    assert.equal((await call(b, "items_list", {})).status, 200, "a K14 minted after personNbf is accepted");
  });

  test("S-PO-10: after the final standalone slice (bridge issuer only) → 503 person_op_unavailable", async () => {
    b.w.rev += 1;
    const self = `tb:ins:${b.w.ins}` as const;
    const final = await signSlice(
      {
        iss: "tb:portal",
        sub: self,
        aud: self,
        iat: nowS(),
        ws: b.w.ws,
        v: 1,
        rev: b.w.rev,
        ins: b.w.ins,
        product: PRODUCT,
        portalKeys: [],
        bridge: { id: b.w.brg, keys: [b.w.bridgeKey.publicJwk] },
        pause: { workspace: false, agents: [], instances: [] },
        revoked: { jtis: [] },
        personNbf: 0,
        grants: [],
        agents: [],
        portalKeySet: b.w.portalKeySet,
        standalone: { issuer: `tb:brg:${b.w.brg}`, kid: thumbprint(b.w.bridgeKey.publicJwk), ownerKeys: [] },
      } as Parameters<typeof signSlice>[0],
      b.w.portal,
    );
    b.bridge.push(final);
    await until(async () => (await call(b, "items_list", {})).status === 503);
    const r = await call(b, "items_list", {});
    assert.equal(r.status, 503);
    assert.equal(code(r), "person_op_unavailable");
  });
});

describe("S-PO-10: app-alone mode → 503 person_op_unavailable", () => {
  test("TB_STANDALONE=1: the route exists and refuses every K14", async () => {
    const w = await world();
    const t = tempDir();
    const port = await freePort();
    const running = await startApp(testApp(port, migrationsDir(t.dir), {}, { via: [] }), { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" });
    try {
      const body = "{}";
      const res = await fetch(`http://127.0.0.1:${port}/tb/v1/person-op`, { method: "POST", headers: { "content-type": "application/json", [PERSON_OP_HEADER]: await k14(w, "items_list", body) }, body });
      assert.equal(res.status, 503);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "person_op_unavailable");
    } finally {
      await running.stop();
      t.cleanup();
    }
  });
});
