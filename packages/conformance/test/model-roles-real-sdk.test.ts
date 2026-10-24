// v0.1.63 model roles: an app test can exercise `modelRole()` — the REAL miniapp-sdk of this workspace behind the fake bridge's
// `/tb/v1/model-roles/<role>` (BRIDGE §15.4): needs_keys + attention until the required role is bound, then ready; the binding
// the app reads; a changed binding (new keysRev) read afresh.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { validateManifest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { appEnv, createFakeBridge, freePort, loadSdk, type RealStartContext, realAppManifest, startRealApp } from "../src/index.ts";

const sample = JSON.parse(readFileSync(new URL("./fixtures/sample.manifest.json", import.meta.url), "utf8")) as Manifest;
type RoleCtx = RealStartContext & { modelRole(role: string): Promise<Record<string, unknown> | null> };

test("the real SDK resolves a model role from the fake bridge; readiness follows the binding", { timeout: 60_000 }, async () => {
  const loaded = await loadSdk(new URL("../../miniapp-sdk/src/server/index.ts", import.meta.url).href);
  assert.ok("sdk" in loaded, "error" in loaded ? loaded.error : "");
  const withHealth = structuredClone(sample);
  withHealth.runtime.healthPath = "/tb/v1/health";
  const base = realAppManifest(withHealth, "roles-app", await freePort());
  const withRoles = {
    ...base,
    settings: {
      steps: [],
      modelRoles: [
        { role: "reasoning", required: true, minPolicy: "zdr", usedBy: ["app"] },
        { role: "embeddings", required: false, usedBy: ["app"] },
      ],
    },
  };
  const v = validateManifest(withRoles);
  assert.ok(v.ok, JSON.stringify(v.ok ? [] : v.errors));
  const bridge = await createFakeBridge({ manifest: v.manifest, maxWaitS: 2 });
  const dir = mkdtempSync(join(tmpdir(), "tbconf-model-roles-"));
  let app: Awaited<ReturnType<typeof startRealApp>> | undefined;
  try {
    await bridge.control.publishKeySet(); // test roots: slices carry the root-signed key set the SDK pins
    app = await startRealApp(loaded.sdk, v.manifest, appEnv(bridge, dir), dir, bridge.testRootJwks());
    await bridge.control.waitForClaim();
    const attention = await bridge.control.waitForStatus((s) => s.status.readiness === "needs_keys" && s.status.attention?.code === "model_role_missing");
    assert.match(attention.status.attention?.reason ?? "", /reasoning/);
    assert.ok(!(attention.status.attention?.reason ?? "").includes("embeddings"));

    bridge.control.setRole("reasoning", { provider: "openai", model: "gpt-5", baseUrl: "https://api.openai.com/v1", key: "sk-conf-role-value-0000000001", dataPolicy: "zdr", dims: null });
    await bridge.control.waitForStatus((s) => s.status.readiness === "ready" && s.status.keysRev === bridge.control.keysRev && s.status.attention === undefined);
    const ctx = app.startContext() as RoleCtx | null;
    assert.ok(ctx, "onStart ran");
    assert.deepEqual(await ctx.modelRole("reasoning"), { role: "reasoning", provider: "openai", model: "gpt-5", baseUrl: "https://api.openai.com/v1", key: "sk-conf-role-value-0000000001", dataPolicy: "zdr", dims: null });
    assert.equal(await ctx.modelRole("embeddings"), null, "an unset optional role resolves to null");

    bridge.control.setRole("reasoning", { provider: "openai", model: "gpt-5.1", baseUrl: null, key: "sk-conf-role-value-0000000001", dataPolicy: "local", dims: null });
    await bridge.control.waitForStatus((s) => s.status.keysRev === bridge.control.keysRev);
    assert.equal((await ctx.modelRole("reasoning"))?.model, "gpt-5.1");
    assert.equal(bridge.roleFetches.every((f) => f.ins === bridge.ids.ins && f.svc === undefined), true, "fetched as the app instance");

    bridge.control.deleteRole("reasoning");
    await bridge.control.waitForStatus((s) => s.status.readiness === "needs_keys" && s.status.keysRev === bridge.control.keysRev);
  } finally {
    await app?.stop();
    await bridge.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
