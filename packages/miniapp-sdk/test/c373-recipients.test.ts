// spec 0.1.81 (unreleased label; C373, G-6): the resolve bridge op passes `DynamicResolution.recipients` (recipient PLACES of
// a tool) through, only on an outward resolution and only in the M-OP-14 shape. Real HTTP over a fake bridge. Fires on bad:
// without the pass-through the bridge never sees places (every dynamic outward call reads "unknown"); without the shape and
// effect check an app could hand the bridge a malformed list.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { bridgeOpProofClaims, signBridgeOpProof, ulid } from "@opt2-tealbrick/manifest";
import { BRIDGE_OP_PATH } from "@opt2-tealbrick/spec/credentials";
import type { DynamicResolution, Manifest, Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, nowS, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const SLACK = [{ pointer: "/channel", kind: "slack" }];

// tool → what the app's resolve answers (the recipients member is typed structurally until the spec re-pin)
const RESOLUTIONS: Record<string, DynamicResolution & { recipients?: unknown }> = {
  chat_send: { tool: "chat_send", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: SLACK },
  mail_send: { tool: "mail_send", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: [{ pointer: "/to", kind: "email" }, { pointer: "/cc", kind: "email" }] },
  plain_send: { tool: "plain_send", crud: ["create"], effect: "outward", holdFamily: "outward" },
  write_item: { tool: "write_item", crud: ["create"], effect: "write", recipients: SLACK },
  bad_kind: { tool: "bad_kind", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: [{ pointer: "/to", kind: "fax" }] },
  bad_pointer: { tool: "bad_pointer", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: [{ pointer: "to", kind: "email" }] },
  too_many: { tool: "too_many", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: Array.from({ length: 9 }, (_, i) => ({ pointer: `/r${i}`, kind: "email" })) },
  values_not_places: { tool: "values_not_places", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: ["email:a@example.com"] },
};

function manifestFor(port: number): Manifest {
  const m = fixtureManifest(port);
  m.operations.push({
    id: "tools",
    title: "Tools",
    description: "Search and call tools (test op).",
    crud: ["read"],
    effect: "read",
    idempotency: "supported",
    receipt: false,
    audience: "agent",
    dynamic: { mode: "search", crudCeiling: ["read", "create", "update"], effectCeiling: "outward" },
  } as unknown as Operation);
  return m;
}

describe("C373: resolve passes recipient places through (HTTP)", () => {
  let w: World;
  let bridge: FakeBridge;
  let running: RunningApp;
  let base: string;
  let cleanupDir: () => void;
  before(async () => {
    w = await world();
    const t = tempDir();
    cleanupDir = t.cleanup;
    const port = await freePort();
    bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    const app = defineApp({
      manifest: manifestFor(port),
      migrations: migrationsDir(t.dir),
      handlers: { note_create: { scope: (input: Json) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) }, note_get: async () => ({}), note_delete: async () => ({}), notebook_rename: async () => ({}) },
      dynamic: {
        tools: {
          catalog: async () => [],
          resolve: async (tool: string) => (RESOLUTIONS[tool] as DynamicResolution | undefined) ?? null,
          call: async () => ({ done: true }),
        },
      },
    } as never);
    running = await startApp(
      app,
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    await until(async () => running.status() === "ok");
    base = `http://127.0.0.1:${port}`;
  });
  after(async () => {
    await running?.stop();
    await bridge?.stop();
    cleanupDir?.();
  });

  async function resolve(tool: string): Promise<{ status: number; body: Record<string, Json> }> {
    const body = { op: "tools", tool };
    const c = bridgeOpProofClaims("resolve", body);
    const proof = await signBridgeOpProof(
      { iss: `tb:brg:${w.brg}`, sub: `tb:brg:${w.brg}`, aud: `tb:ins:${w.ins}`, iat: nowS(), call: `call_${ulid()}`, bop: "resolve", ...(c.op !== undefined ? { op: c.op } : {}), ...(c.in !== undefined ? { in: c.in } : {}) } as never,
      w.bridgeKey,
    );
    const res = await fetch(`${base}/tb/v1/bridge/${BRIDGE_OP_PATH.resolve}`, { method: "POST", headers: { "content-type": "application/json", "tb-call": proof }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as Record<string, Json> };
  }

  test("quiet on good: an outward resolution's places are in the answer, exactly as the app gave them", async () => {
    const chat = await resolve("chat_send");
    assert.equal(chat.status, 200);
    assert.deepEqual(chat.body, { tool: "chat_send", crud: ["create"], effect: "outward", holdFamily: "outward", recipients: SLACK });
    const mail = await resolve("mail_send");
    assert.deepEqual(mail.body.recipients, RESOLUTIONS.mail_send?.recipients as Json);
  });

  test("no places from the app → no recipients member (unknown)", async () => {
    const r = await resolve("plain_send");
    assert.equal(r.status, 200);
    assert.equal("recipients" in r.body, false);
  });

  test("fires on bad: a non-outward resolution, a bad kind, a bad pointer, 9 places, values instead of places → dropped, the call class kept", async () => {
    for (const tool of ["write_item", "bad_kind", "bad_pointer", "too_many", "values_not_places"]) {
      const r = await resolve(tool);
      assert.equal(r.status, 200, tool);
      assert.equal("recipients" in r.body, false, tool);
      assert.equal(r.body.tool, tool);
      assert.equal(r.body.effect, RESOLUTIONS[tool]?.effect);
    }
  });
});
