// Hook route (`POST /tb/v1/hooks/<id>`, SDK-API §3.2) and companion calls (`ctx.callApp` → `POST /tb/v1/call`,
// SDK-API §9) over real HTTP: a fake bridge, hook proofs and grants from the manifest package signers.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { digest, signGrant, signHookProof, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { HookPhase, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { HookRequest, Json, OpContext, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const PEER = "peer-app";
const match = { products: ["other-app"], operations: ["other_op"] };

function manifestWithHooks(port: number): Manifest {
  const m = fixtureManifest(port);
  m.hooks = [
    { id: "check_before", title: "Before", phase: "before", order: 10, match },
    { id: "check_slow", title: "Slow", phase: "before", order: 20, match, timeoutMs: 150 },
    { id: "tag_context", title: "Context", phase: "context", order: 0, match },
    { id: "redact_after", title: "After", phase: "after", order: 0, match },
  ];
  m.companions = [{ product: PEER, operations: ["peer_write"], crud: ["create"], purpose: "Write to the peer." }];
  return m;
}

/** Hook behaviour is chosen by `call.input.mode` so one handler per phase covers good and bad answers. */
const mode = (req: HookRequest) => String((req.call.input as { mode?: string } | undefined)?.mode ?? "ok");

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  peerIns: InstanceId;
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const peerIns = `ins_${ulid()}` as InstanceId;
  const companionGrant = await signGrant(
    { iss: "tb:portal", sub: `tb:ins:${w.ins}`, aud: `tb:ins:${peerIns}`, iat: nowS(), ws: w.ws, cnf: { brg: w.brg }, crud: ["create"], mode: "bound", held: ["money"], caps: {}, wf: ["peer_write"], polrev: 1 },
    w.portal,
  );
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { grants: [companionGrant] }));
  const app = defineApp({
    manifest: manifestWithHooks(port),
    migrations: migrationsDir(t.dir),
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n1" }) },
      // reads the companion: the result of callApp is the op output
      note_get: async (input, ctx: OpContext) => ({ companion: (await ctx.callApp(PEER, "peer_write", input, { idempotencyKey: "peer-key" })) as unknown as Json }),
      // an operation the manifest does not declare for the companion
      note_delete: async (_input, ctx: OpContext) => (await ctx.callApp(PEER, "peer_other", {})) as unknown as Json,
      notebook_rename: async () => ({}),
    },
    hooks: {
      check_before: async (req) =>
        mode(req) === "deny"
          ? { allow: false, reason: "denied" }
          : mode(req) === "hold"
            ? { allow: false, hold: { family: "policy", reason: "needs owner review" } }
            : mode(req) === "badhold"
              ? ({ allow: true, hold: { family: "policy", reason: "x" } } as never)
              : mode(req) === "bad"
                ? ({ allow: "yes" } as never)
                : { allow: true },
      check_slow: async (req, ctx) => {
        await new Promise((r) => setTimeout(r, 1000).unref());
        return { allow: !ctx.signal.aborted && mode(req) !== "deny" };
      },
      tag_context: async (req) => ({ add: (mode(req) === "bad" ? { "foreign.key": 1 } : { [`${PRODUCT}.caller`]: req.call.caller.id }) as Record<`${string}.${string}`, Json> }),
      redact_after: async (req) => (mode(req) === "bad" ? ({ allow: true } as never) : mode(req) === "pointer" ? { redactions: ["no-slash"] } : { output: { seen: req.phase === "after" ? (req.output as Json) : null }, redactions: ["/secret"] }),
    },
  });
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
    peerIns,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

/**
 * `caller` = the `call.caller` of the request body (default: agent A); `sub` = the proof `sub` (default: the ref of `caller`);
 * `proofCall` = the proof `call` claim (default: the request's `call.id`); `callId` = the request's `call.id`.
 */
async function callHook(
  b: Booted,
  hook: string,
  phase: HookPhase,
  input: Json,
  opts: { proof?: string | null; sentInput?: Json; output?: Json; caller?: Record<string, Json> | null; sub?: string; proofCall?: string; callId?: string } = {},
) {
  const context = { "other-app.flag": true };
  const callerBody = opts.caller === undefined ? { type: "agent", id: b.w.agents.a, mode: "free" } : opts.caller;
  const call = {
    id: opts.callId ?? `call_${ulid()}`,
    ws: b.w.ws,
    ...(callerBody === null ? {} : { caller: callerBody }),
    target: { instance: `ins_${ulid()}`, product: "other-app", op: "other_op", crud: ["create"], effect: "write" },
    input: opts.sentInput ?? input,
  };
  const proof =
    opts.proof === undefined
      ? await signHookProof(
          {
            iss: `tb:brg:${b.w.brg}`,
            sub: (opts.sub ?? (callerBody && callerBody.type === "app" ? `tb:ins:${callerBody.id}` : `tb:agt:${(callerBody as { id?: string } | null)?.id ?? b.w.agents.a}`)) as never,
            aud: `tb:ins:${b.w.ins}`,
            iat: nowS(),
            call: (opts.proofCall ?? call.id) as `call_${string}`,
            hook,
            phase,
            ctx: digest(context),
            in: digest(input),
          },
          b.w.bridgeKey,
        )
      : opts.proof;
  const res = await fetch(`${b.base}/tb/v1/hooks/${hook}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...(proof ? { "tb-call": proof } : {}) },
    body: JSON.stringify({ phase, call, context, ...(phase === "after" ? { output: opts.output ?? { secret: "s", keep: 1 } } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function callOp(b: Booted, op: string, input: Json, idempotencyKey?: string) {
  const g = await grant(b.w, b.w.agents.a);
  const proof = await callProof(b.w, g, op, input);
  const callId = JSON.parse(Buffer.from(proof.split(".")[1] as string, "base64url").toString("utf8")).call as string;
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, ...(idempotencyKey ? { idempotencyKey } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any>, callId };
}

describe("hook route", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  test("each phase answers its shape", async () => {
    assert.deepEqual((await callHook(b, "check_before", "before", { mode: "ok" })).body, { allow: true });
    assert.deepEqual((await callHook(b, "check_before", "before", { mode: "deny" })).body, { allow: false, reason: "denied" });
    // v0.1.13 G1: a hold verdict passes the shared shape rule (SDK ≤ 0.1.15 answered 500 hook_failed)
    const held = await callHook(b, "check_before", "before", { mode: "hold" });
    assert.equal(held.status, 200, JSON.stringify(held.body));
    assert.deepEqual(held.body, { allow: false, hold: { family: "policy", reason: "needs owner review" } });
    assert.deepEqual((await callHook(b, "tag_context", "context", {})).body, { add: { [`${PRODUCT}.caller`]: b.w.agents.a } });
    const a = await callHook(b, "redact_after", "after", {}, { output: { secret: "x" } });
    assert.equal(a.status, 200);
    assert.deepEqual(a.body, { output: { seen: { secret: "x" } }, redactions: ["/secret"] }, "the after hook receives the op output");
  });

  test("a handler slower than the hook timeoutMs → 504 hook_failed (fail closed)", async () => {
    const t0 = Date.now();
    const a = await callHook(b, "check_slow", "before", {});
    assert.equal(a.status, 504);
    assert.equal(a.body.error.code, "hook_failed");
    assert.ok(Date.now() - t0 < 900, "answered at the timeout, not when the handler finished");
  });

  test("answers that break the phase shape → 500 hook_failed", async () => {
    for (const [hook, phase, m] of [
      ["check_before", "before", "bad"],
      ["check_before", "before", "badhold"],
      ["tag_context", "context", "bad"],
      ["redact_after", "after", "bad"],
      ["redact_after", "after", "pointer"],
    ] as const) {
      const a = await callHook(b, hook, phase, { mode: m });
      assert.equal(a.status, 500, `${hook} ${m}`);
      assert.equal(a.body.error.code, "hook_failed", `${hook} ${m}`);
    }
  });

  test("proof missing, input tampered, wrong phase → call_proof_invalid; undeclared hook → unknown_hook", async () => {
    assert.equal((await callHook(b, "check_before", "before", {}, { proof: null })).body.error.code, "call_proof_invalid");
    assert.equal((await callHook(b, "check_before", "before", { mode: "ok" }, { sentInput: { mode: "deny" } })).body.error.code, "call_proof_invalid");
    assert.equal((await callHook(b, "tag_context", "after", {})).status, 401);
    const u = await callHook(b, "nope_hook", "before", {});
    assert.equal(u.status, 404);
    assert.equal(u.body.error.code, "unknown_hook");
  });
});

describe("hook proof binds the caller and the call (C268 A, v0.1.35)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  const refused = (a: { status: number; body: Record<string, any> }, why: string) => {
    assert.equal(a.status, 401, `${why}: ${JSON.stringify(a.body)}`);
    assert.equal(a.body.error.code, "call_proof_invalid", why);
  };
  const other = `agt_${ulid()}`;
  const appIns = `ins_${ulid()}`;

  test("quiet on good: an agent caller and an app caller whose proof sub names them are answered", async () => {
    assert.equal((await callHook(b, "check_before", "before", { mode: "ok" })).status, 200);
    const app = await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "app", id: appIns, product: "evolution" } });
    assert.equal(app.status, 200, JSON.stringify(app.body));
    assert.equal((await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "app", id: appIns } })).status, 200, "an app caller without product");
  });

  test("the proof sub differs from the caller of the body → 401 call_proof_invalid (fires on bad: before 0.1.35 this was answered 200)", async () => {
    // the proof is for agent A, the body says another agent / an app instance / the other way round
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "agent", id: other, mode: "free" }, sub: `tb:agt:${b.w.agents.a}` }), "another agent");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "app", id: appIns }, sub: `tb:agt:${b.w.agents.a}` }), "an app named in the body, an agent in the proof");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "agent", id: appIns, mode: "free" }, sub: `tb:ins:${appIns}` }), "type confusion: an agent in the body, an instance in the proof");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "app", id: appIns }, sub: `tb:ins:ins_${ulid()}` }), "another app instance");
    // every phase
    refused(await callHook(b, "tag_context", "context", {}, { caller: { type: "agent", id: other, mode: "free" }, sub: `tb:agt:${b.w.agents.a}` }), "context phase");
    refused(await callHook(b, "redact_after", "after", {}, { caller: { type: "agent", id: other, mode: "free" }, sub: `tb:agt:${b.w.agents.a}` }), "after phase");
  });

  test("a body without a usable caller (missing, no id, other type, id not a string) never matches → 401", async () => {
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: null, sub: `tb:agt:${b.w.agents.a}` }), "no caller");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "agent" }, sub: `tb:agt:${b.w.agents.a}` }), "no id");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "person", id: "per_x" }, sub: `tb:agt:${b.w.agents.a}` }), "a person caller");
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { caller: { type: "agent", id: 7 }, sub: `tb:agt:${b.w.agents.a}` }), "id not a string");
  });

  test("the proof `call` differs from the call id of the body → 401 call_proof_invalid", async () => {
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { proofCall: `call_${ulid()}` }), "another call id");
    // the body names no call id the proof could match
    refused(await callHook(b, "check_before", "before", { mode: "ok" }, { callId: "" , proofCall: `call_${ulid()}` }), "empty call id");
  });

  test("a mismatch does not burn the proof: the same proof with the right body is still accepted once", async () => {
    const context = { "other-app.flag": true };
    const input = { mode: "ok" };
    const callId = `call_${ulid()}`;
    const proof = await signHookProof({ iss: `tb:brg:${b.w.brg}`, sub: `tb:agt:${b.w.agents.a}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), call: callId as `call_${string}`, hook: "check_before", phase: "before", ctx: digest(context), in: digest(input) }, b.w.bridgeKey);
    const send = async (caller: Record<string, Json>) => {
      const res = await fetch(`${b.base}/tb/v1/hooks/check_before`, {
        method: "POST",
        headers: { "content-type": "application/json", "tb-call": proof },
        body: JSON.stringify({ phase: "before", call: { id: callId, ws: b.w.ws, caller, target: { instance: `ins_${ulid()}`, product: "other-app", op: "other_op", crud: ["create"], effect: "write" }, input }, context }),
      });
      return res.status;
    };
    assert.equal(await send({ type: "agent", id: other, mode: "free" }), 401);
    assert.equal(await send({ type: "agent", id: b.w.agents.a, mode: "free" }), 200);
    assert.equal(await send({ type: "agent", id: b.w.agents.a, mode: "free" }), 401, "one-time");
  });
});

describe("companion calls (ctx.callApp)", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  test("POST /tb/v1/call with TB-Assert, the slice's companion grant and the CallEnvelope; result is the op output", async () => {
    b.bridge.calls = [];
    const r = await callOp(b, "note_get", { id: "n1" });
    assert.equal(r.status, 200);
    assert.deepEqual(r.body.output, { companion: { status: "ok", output: { done: true } } });
    assert.equal(b.bridge.calls.length, 1);
    const c = b.bridge.calls[0] as (typeof b.bridge.calls)[number];
    assert.deepEqual(c.body, { target: PEER, op: "peer_write", input: { id: "n1" }, idempotencyKey: "peer-key", parentCall: r.callId });
    const g = JSON.parse(Buffer.from(c.grant.split(".")[1] as string, "base64url").toString("utf8"));
    assert.equal(g.sub, `tb:ins:${b.w.ins}`);
    assert.equal(g.aud, `tb:ins:${b.peerIns}`);
    assert.deepEqual(g.wf, ["peer_write"]);
    assert.ok(c.assert.length > 20, "instance assertion present");
  });

  test("grant_stale → one slice re-read and one retry; a second refusal surfaces (no loop)", async () => {
    let refuse = 1;
    b.bridge.onCall = () => (refuse-- > 0 ? { status: 403, body: { error: { code: "grant_stale", message: "stale" } } } : { status: 200, body: { status: "ok", output: { done: true } } });
    b.bridge.calls = [];
    const statuses = b.bridge.statuses.length;
    const r = await callOp(b, "note_get", { id: "n2" });
    assert.equal(r.status, 200);
    assert.equal(b.bridge.calls.length, 2);
    assert.ok(b.bridge.statuses.length > statuses, "status exchange between the attempts");
    refuse = 2;
    b.bridge.calls = [];
    const twice = await callOp(b, "note_get", { id: "n3" });
    assert.equal(twice.status, 403);
    assert.equal(twice.body.error.code, "grant_stale");
    assert.equal(b.bridge.calls.length, 2);
  });

  test("grant_expired is treated like grant_stale: one slice re-read, one retry, then the refusal surfaces (SDK-API §9, v0.1.11 (C70))", async () => {
    for (const code of ["grant_stale", "grant_expired"]) {
      let refuse = 1;
      b.bridge.onCall = () => (refuse-- > 0 ? { status: 403, body: { error: { code, message: code } } } : { status: 200, body: { status: "ok", output: { done: true } } });
      b.bridge.calls = [];
      const before = b.bridge.statuses.length;
      const ok = await callOp(b, "note_get", { id: `r-${code}` });
      assert.equal(ok.status, 200, code);
      assert.equal(b.bridge.calls.length, 2, `${code}: refused once, retried once`);
      assert.equal(b.bridge.statuses.length - before, 1, `${code}: exactly one slice re-read before the retry`);
      refuse = 5;
      b.bridge.calls = [];
      const mid = b.bridge.statuses.length;
      const twice = await callOp(b, "note_get", { id: `t-${code}` });
      assert.equal(twice.status, 403, code);
      assert.equal(twice.body.error.code, code);
      assert.equal(b.bridge.calls.length, 2, `${code}: never a third attempt`);
      assert.equal(b.bridge.statuses.length - mid, 1, `${code}: one re-read only`);
    }
  });

  test("other refusals (grant_revoked, grant_invalid) are not retried and trigger no slice re-read", async () => {
    for (const code of ["grant_revoked", "grant_invalid"]) {
      b.bridge.onCall = () => ({ status: 403, body: { error: { code, message: code } } });
      b.bridge.calls = [];
      const before = b.bridge.statuses.length;
      const r = await callOp(b, "note_get", { id: `x-${code}` });
      assert.equal(r.body.error.code, code);
      assert.equal(b.bridge.calls.length, 1, code);
      assert.equal(b.bridge.statuses.length, before, code);
    }
  });

  test("a bridge refusal passes through with its code; an undeclared companion op never reaches the bridge", async () => {
    b.bridge.onCall = () => ({ status: 403, body: { error: { code: "hook_denied", message: "refused by a before hook" } } });
    const r = await callOp(b, "note_get", { id: "n4" });
    assert.equal(r.status, 403);
    assert.equal(r.body.error.code, "hook_denied");
    b.bridge.calls = [];
    const u = await callOp(b, "note_delete", { id: "n5" }, `k-${ulid()}`);
    assert.equal(u.body.error.code, "companion_undeclared");
    assert.equal(b.bridge.calls.length, 0);
  });
});
