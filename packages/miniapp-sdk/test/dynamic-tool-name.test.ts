// spec 0.1.68 (C336 RQ-2, C354): the requested tool of a dynamic call may be up to 63 chars — a catalog name (≤ 48) or a variant
// the agent requests explicitly, e.g. `<48-char tool>__first_contact`. Before, the dynamic-call input schema refused anything over
// 48 chars, so such a call never reached the app's resolve. Real HTTP, fake bridge; 64 chars is still refused.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const toolsOp = {
  id: "tools",
  title: "Connected tools",
  description: "Search and call connected tools (test op).",
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" },
} as unknown as Operation;
const BASE48 = `g${"m".repeat(47)}`;

describe("spec 0.1.68 dynamic call tool names up to 63 chars", () => {
  let w: World;
  let base = "";
  const resolved: string[] = [];
  const called: string[] = [];
  let cleanup: () => Promise<void> = async () => {};
  before(async () => {
    w = await world();
    const t = tempDir();
    const port = await freePort();
    const bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    const manifest = fixtureManifest(port);
    manifest.operations.push(toolsOp);
    const noop = async () => ({});
    const running: RunningApp = await startApp(
      defineApp({
        manifest,
        migrations: migrationsDir(t.dir),
        handlers: { note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: noop }, note_get: noop, note_delete: noop, notebook_rename: noop },
        dynamic: {
          tools: {
            catalog: async () => [],
            resolve: async (tool) => {
              resolved.push(tool);
              return tool.startsWith("gm") ? { tool, crud: ["read"], effect: "read" } : null;
            },
            call: async (tool) => {
              called.push(tool);
              return { tool };
            },
          },
        },
      }),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "warn" },
      testRoots(w),
    ).catch(async (e) => {
      await bridge.stop();
      t.cleanup();
      throw e;
    });
    await until(async () => running.status() === "ok");
    base = `http://127.0.0.1:${port}`;
    cleanup = async () => {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    };
  });
  after(async () => cleanup());

  const call = async (tool: string) => {
    const g = await grant(w, w.agents.a, { crud: ["read"] });
    const input: Json = { tool, arguments: {} };
    const proof = await callProof(w, g, "tools", input);
    const res = await fetch(`${base}/tb/v1/ops/tools`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof }, body: JSON.stringify({ input, context: {} }) });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };

  test("49 and 63 chars (a 48-char tool + `__first_contact`) reach resolve and the call; 64 chars is refused input_invalid before resolve", async () => {
    for (const tool of [`${BASE48}x`, `${BASE48}__first_contact`]) {
      const r = await call(tool);
      assert.equal(r.status, 200, `${tool.length} chars: ${JSON.stringify(r.body)}`);
      assert.deepEqual(r.body.output, { tool });
      assert.equal(called.at(-1), tool);
    }
    const n = resolved.length;
    const r = await call(`${BASE48}__first_contact_`);
    assert.equal(r.status, 400, JSON.stringify(r.body));
    assert.equal(r.body.error.code, "input_invalid");
    assert.equal(resolved.length, n, "64 chars never reaches resolve");
  });
});
