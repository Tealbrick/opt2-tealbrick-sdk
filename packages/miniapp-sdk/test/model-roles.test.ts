// v0.1.39 (spec 0.1.63, C322(3), C330(4)): modelRole(role) on op, start and hook contexts and as a free export; the bridge answer
// (200 / 404 role_not_set / 403 role_policy_too_low), the undeclared throw before any request, the cache per keysRev,
// onKeysChanged for binding changes, and readiness (`needs_keys` + attention `model_role_missing`).
import assert from "node:assert/strict";
import { after, before, describe, mock, test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp, StartContext } from "@opt2-tealbrick/spec/sdk";
import { defineApp, getKey, modelRole, onKeysChanged, startApp, TbError } from "../src/server/index.ts";
import { pickAttention } from "../src/server/status.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const T = { timeout: 60_000 };
const SECRET = "sk-role-fixture-not-a-real-key-0001";

const binding = (over: Record<string, unknown> = {}) => ({
  status: 200,
  body: { role: "reasoning", provider: "openai", model: "gpt-5", baseUrl: "https://api.openai.com/v1", key: SECRET, dataPolicy: "zdr", dims: null, ...over },
});
const refusal = (status: number, code: string, details?: unknown) => ({ status, body: { error: { code, message: code, requestId: "req_test", ...(details ? { details } : {}) } } });

function manifestWithRoles(port: number): Manifest {
  const m = fixtureManifest(port);
  // notebook_rename (owner op) becomes the probe: any input, any output
  const probe = m.operations.find((o) => o.id === "notebook_rename");
  if (probe) Object.assign(probe, { input: { type: "object" }, output: { type: "object" } });
  m.runtime.env = [{ name: "JOTTER_VISION", setting: "vision" }];
  m.runtime.services = [
    {
      id: "worker",
      build: { context: "services/worker", dockerfile: "services/worker/Dockerfile" },
      port: 9100,
      resources: { cpu: 0.25, memoryMb: 256 },
      health: { kind: "tcp" },
      startOrder: 0,
    },
  ];
  m.settings = {
    steps: [{ id: "extras", title: "Extras", fields: [{ key: "vision", type: "boolean", label: "Read images", default: false }] }],
    keys: m.settings?.keys ?? [],
    modelRoles: [
      { role: "reasoning", required: true, minPolicy: "zdr", usedBy: ["app"] },
      { role: "embeddings", required: false, usedBy: ["app", "worker"] },
      { role: "vision", required: false, usedBy: ["app"], when: { vision: true } },
      { role: "transcribe", required: false, usedBy: ["worker"], env: { model: "TRANSCRIBE_MODEL" } },
    ],
  } as Manifest["settings"];
  return m;
}

const seen: { start: Promise<unknown> | null; startCtx: StartContext | null } = { start: null, startCtx: null };
/** what the probe app's own `attention()` reports (the ONE attention slot tests) */
const appAttention: { value: { code: string; reason: string } | null } = { value: null };

function testApp(port: number, migrations: string) {
  return defineApp({
    manifest: manifestWithRoles(port),
    migrations,
    attention: async () => appAttention.value,
    onStart: async (ctx) => {
      seen.startCtx = ctx as StartContext;
      seen.start = ctx.modelRole("reasoning");
    },
    handlers: {
      note_create: { scope: () => "n", run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async (input, ctx) => {
        const i = input as { role: string; leak?: boolean };
        try {
          const r = await ctx.modelRole(i.role as never);
          if (i.leak && r?.key) ctx.log.error("leak", { v: r.key });
          return { role: r as unknown as Json };
        } catch (e) {
          return { threw: e instanceof TbError ? e.code : "error" } as Record<string, Json>;
        }
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

async function boot(prepare: (b: FakeBridge) => void = () => {}): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  prepare(bridge);
  let running: RunningApp | undefined;
  try {
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    running = await startApp(
      testApp(port, migrationsDir(t.dir)),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error", JOTTER_VISION: "false" },
      { ...testRoots(w), port },
    );
  } catch (e) {
    await running?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  const app = running;
  return {
    w,
    bridge,
    running: app,
    base: `http://127.0.0.1:${port}`,
    async cleanup() {
      await app.stop();
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

async function roleOp(b: Booted, s: { cookie: string; csrf: string }, input: Json) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/notebook_rename`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as { output: { role?: Record<string, unknown> | null; threw?: string } } };
}

const lastStatus = (b: Booted) => b.bridge.statuses.at(-1) as { readiness?: string; attention?: { code: string; reason: string }; keysRev?: number } | undefined;

describe("modelRole() (SDK-API v0.1.63 additions)", T, () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot((x) => x.modelRoles.set("reasoning", binding()));
    s = await signIn(b);
  });
  after(async () => b.cleanup());
  const fetches = (role: string) => b.bridge.modelRoleFetches.filter((f) => f.role === role).length;

  test("200: the binding without keysRev, fetched with a verified instance assertion; on the op, start and free-export paths", T, async () => {
    const r = await roleOp(b, s, { role: "reasoning" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.role, { role: "reasoning", provider: "openai", model: "gpt-5", baseUrl: "https://api.openai.com/v1", key: SECRET, dataPolicy: "zdr", dims: null });
    assert.ok(!("keysRev" in (r.body.output.role as object)));
    assert.deepEqual(
      b.bridge.modelRoleFetches.filter((f) => f.role === "reasoning").map((f) => f.assertOk),
      [true],
    );
    assert.equal((await modelRole("reasoning"))?.model, "gpt-5");
    assert.equal(((await seen.start) as { provider: string } | null)?.provider, "openai", "StartContext.modelRole");
    assert.equal(fetches("reasoning"), 1, "one fetch serves the op, start and free-export calls (cache per keysRev)");
  });

  test("modelFetch(role) returns null until sdk#53 ships it: fail closed, no bridge request, no key read", T, async () => {
    const before = b.bridge.modelRoleFetches.length;
    assert.equal(await b.running.keys.modelFetch("reasoning"), null);
    assert.equal(await b.running.keys.modelFetch("embeddings"), null);
    assert.equal(b.bridge.modelRoleFetches.length, before);
  });

  test("the returned object is a copy: changing it does not change what the next call returns", T, async () => {
    const a = await modelRole("reasoning");
    assert.ok(a);
    a.model = "tampered";
    assert.equal((await modelRole("reasoning"))?.model, "gpt-5");
  });

  test("the key is registered for log redaction and never reaches a log line", T, async () => {
    const lines: string[] = [];
    const err = mock.method(process.stderr, "write", (chunk: unknown) => {
      lines.push(String(chunk));
      return true;
    });
    try {
      const r = await roleOp(b, s, { role: "reasoning", leak: true });
      assert.equal(r.status, 200);
    } finally {
      err.mock.restore();
    }
    const leak = lines.filter((l) => l.includes('"leak"'));
    assert.equal(leak.length, 1);
    assert.ok(!leak[0]?.includes(SECRET));
    assert.ok(leak[0]?.includes("[redacted]"));
  });

  test("404 role_not_set → null, cached like a binding until keysRev moves", T, async () => {
    assert.equal(await modelRole("embeddings"), null);
    assert.equal(await modelRole("embeddings"), null);
    assert.equal(fetches("embeddings"), 1, "a null is cached like a binding");
  });

  test("403 role_policy_too_low → null; the refusal carries no binding", T, async () => {
    b.bridge.modelRoles.set("embeddings", refusal(403, "role_policy_too_low", { needed: "zdr", have: "standard" }));
    b.bridge.bumpKeys();
    await until(async () => lastStatus(b)?.keysRev === b.bridge.keysRev);
    assert.equal(await modelRole("embeddings"), null);
  });

  test("a role whose `when` is false is not in force: null, no request", T, async () => {
    const before = fetches("vision");
    assert.equal(await modelRole("vision"), null);
    assert.equal(fetches("vision"), before);
    assert.equal(fetches("vision"), 0);
  });

  test("an undeclared role, and a role declared only for a service, throw role_undeclared before any request", T, async () => {
    const before = b.bridge.modelRoleFetches.length;
    await assert.rejects(modelRole("rerank"), (e: unknown) => e instanceof TbError && e.code === "role_undeclared");
    await assert.rejects(modelRole("transcribe"), (e: unknown) => e instanceof TbError && e.code === "role_undeclared");
    await assert.rejects(modelRole("not-a-role" as never), (e: unknown) => e instanceof TbError && e.code === "role_undeclared");
    assert.equal(b.bridge.modelRoleFetches.length, before);
    const viaOp = await roleOp(b, s, { role: "rerank" });
    assert.equal(viaOp.body.output.threw, "role_undeclared");
    await assert.rejects(getKey("reasoning"), (e: unknown) => e instanceof TbError && e.code === "key_undeclared");
  });

  test("any other bridge refusal throws with the bridge's code and is not cached", T, async () => {
    b.bridge.modelRoles.set("embeddings", refusal(403, "paused"));
    b.bridge.bumpKeys();
    await until(async () => lastStatus(b)?.keysRev === b.bridge.keysRev);
    await assert.rejects(modelRole("embeddings"), (e: unknown) => e instanceof TbError && e.code === "paused");
    b.bridge.modelRoles.set("embeddings", binding({ role: "embeddings", provider: "voyage", model: "voyage-3", dims: 1024, key: SECRET }));
    const r = await modelRole("embeddings");
    assert.equal(r?.model, "voyage-3", "the error was not cached");
    assert.equal(r?.dims, 1024);
  });

  test("a malformed bridge answer throws model_role_unavailable", T, async () => {
    b.bridge.modelRoles.set("embeddings", { status: 200, body: { role: "embeddings", model: 7 } });
    b.bridge.bumpKeys();
    await until(async () => lastStatus(b)?.keysRev === b.bridge.keysRev);
    await assert.rejects(modelRole("embeddings"), (e: unknown) => e instanceof TbError && e.code === "model_role_unavailable");
  });

  test("keysRev moved (a binding changed): the cache is dropped, onKeysChanged fires, the next call reads the new binding", T, async () => {
    const changed: string[][] = [];
    const off = onKeysChanged((names) => changed.push(names));
    try {
      assert.equal((await modelRole("reasoning"))?.model, "gpt-5");
      const asked = fetches("reasoning");
      b.bridge.modelRoles.set("reasoning", binding({ model: "gpt-5.1" }));
      b.bridge.bumpKeys();
      await until(async () => changed.length > 0);
      assert.deepEqual(changed[0], [], "no key changed by name: only a binding");
      assert.equal((await modelRole("reasoning"))?.model, "gpt-5.1");
      assert.ok(fetches("reasoning") > asked);
      const again = fetches("reasoning");
      await modelRole("reasoning");
      assert.equal(fetches("reasoning"), again, "cached again for the new keysRev");
    } finally {
      off();
    }
  });
  test("S3-3 (C349): with the workspace paused in the slice, modelRole() and getKey() throw `paused` although the bridge would answer 200; readiness never says `not set` then; released → works", T, async () => {
    assert.ok(await modelRole("reasoning"), "resolves before the pause");
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: true, agents: [], instances: [] } }));
    await until(async () => (await modelRole("reasoning").then(() => null, (e: unknown) => (e instanceof TbError && e.code === "paused" ? true : null))) ?? false);
    await assert.rejects(getKey("DEMO_API_KEY"), (e: unknown) => e instanceof TbError && e.code === "paused");
    const viaOp = await roleOp(b, s, { role: "reasoning" });
    assert.equal(viaOp.body.output.threw, "paused");
    assert.notEqual(lastStatus(b)?.attention?.code, "model_role_missing", "no `Model role not set` text while paused");
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: false, agents: [], instances: [] } }));
    await until(async () => (await modelRole("reasoning").then(() => true, () => null)) ?? false);
    assert.equal((await modelRole("reasoning"))?.model, "gpt-5.1");
  });
});

describe("model role readiness (MANIFEST §7.1)", T, () => {
  test("a required role that does not resolve: needs_keys + attention model_role_missing naming it; cleared when it resolves; back when unset", T, async () => {
    const b = await boot(); // `reasoning` (required) is not set
    try {
      await until(async () => lastStatus(b)?.readiness === "needs_keys");
      assert.equal(b.running.status(), "needs_keys");
      const st = lastStatus(b);
      assert.equal(st?.attention?.code, "model_role_missing");
      assert.match(st?.attention?.reason ?? "", /reasoning/);
      assert.ok(!(st?.attention?.reason ?? "").includes("embeddings"), "an optional role is not named");

      b.bridge.modelRoles.set("reasoning", binding());
      b.bridge.bumpKeys();
      await until(async () => lastStatus(b)?.readiness === "ready");
      assert.equal(b.running.status(), "ok");
      assert.equal(lastStatus(b)?.attention, undefined);

      b.bridge.modelRoles.delete("reasoning");
      b.bridge.bumpKeys();
      await until(async () => lastStatus(b)?.readiness === "needs_keys");
      assert.equal(lastStatus(b)?.attention?.code, "model_role_missing");
    } finally {
      await b.cleanup();
    }
  });

  test("below minPolicy counts as not resolved", T, async () => {
    const b = await boot((x) => x.modelRoles.set("reasoning", refusal(403, "role_policy_too_low", { needed: "zdr", have: "standard" })));
    try {
      await until(async () => lastStatus(b)?.readiness === "needs_keys");
      assert.equal(lastStatus(b)?.attention?.code, "model_role_missing");
    } finally {
      await b.cleanup();
    }
  });

  test("RM-17: a bridge without the route (404 not_found, no refuse code) → null, fail closed: a required role gives needs_keys + model_role_missing, never a guess", T, async () => {
    const b = await boot((x) => {
      x.modelRoutes = false;
      x.modelRoles.set("reasoning", binding()); // would resolve on a bridge that had the route
    });
    try {
      await until(async () => lastStatus(b)?.readiness === "needs_keys");
      assert.equal(lastStatus(b)?.attention?.code, "model_role_missing");
      assert.equal(await modelRole("reasoning"), null);
      assert.equal(await modelRole("embeddings"), null);
      assert.equal(b.running.status(), "needs_keys");
      assert.equal(b.bridge.modelRoleFetches.length, 0, "no key fetch stands in for the role");
    } finally {
      await b.cleanup();
    }
  });
});

describe("ONE attention slot (SDK-API v0.1.63, spec follow-up #49)", T, () => {
  const att = (code: string) => ({ code, reason: code });
  test("pickAttention: a fault outranks every model-role code; model codes show only when nothing else is wrong", () => {
    const missing = att("model_role_missing");
    // the SDK's model_role_missing never hides a fault: backup, events, the app's own, a job fault
    assert.equal(pickAttention({ backup: att("backup_failed"), roles: missing, app: null, jobs: null })?.code, "backup_failed");
    assert.equal(pickAttention({ backup: null, events: att("events_send_failing"), roles: missing, app: null, jobs: null })?.code, "events_send_failing");
    assert.equal(pickAttention({ backup: null, roles: missing, app: att("engine_down"), jobs: null })?.code, "engine_down");
    assert.equal(pickAttention({ backup: null, roles: missing, app: null, jobs: att("jobs_failed") })?.code, "jobs_failed");
    // an app model code (optional, embeddings_changed) is a model code too: a fault of any other source outranks it
    for (const code of ["model_role_optional", "embeddings_changed", "model_role_missing"]) {
      assert.equal(pickAttention({ backup: att("backup_overdue"), app: att(code), jobs: null })?.code, "backup_overdue", code);
      assert.equal(pickAttention({ backup: null, app: att(code), jobs: att("jobs_failed") })?.code, "jobs_failed", code);
    }
    // nothing else wrong: the SDK's model_role_missing, then the app's own model code
    assert.equal(pickAttention({ backup: null, roles: missing, app: att("embeddings_changed"), jobs: null })?.code, "model_role_missing");
    assert.equal(pickAttention({ backup: null, app: att("model_role_optional"), jobs: null })?.code, "model_role_optional");
    assert.equal(pickAttention({ backup: null, roles: missing, app: null, jobs: null })?.code, "model_role_missing");
    assert.equal(pickAttention({ backup: null, app: null, jobs: null }), null);
  });

  test("on the wire: a missing required role AND an app fault → needs_keys with the fault's code; the fault clears → model_role_missing", T, async () => {
    const b = await boot(); // `reasoning` (required) is not set
    try {
      await until(async () => lastStatus(b)?.attention?.code === "model_role_missing");
      appAttention.value = { code: "engine_down", reason: "the engine does not answer" };
      b.bridge.bumpKeys(); // any new status push
      await until(async () => lastStatus(b)?.attention?.code === "engine_down");
      assert.equal(lastStatus(b)?.readiness, "needs_keys", "readiness still says why the app does not work");
      appAttention.value = null;
      b.bridge.bumpKeys();
      await until(async () => lastStatus(b)?.attention?.code === "model_role_missing");
    } finally {
      appAttention.value = null;
      await b.cleanup();
    }
  });
});
