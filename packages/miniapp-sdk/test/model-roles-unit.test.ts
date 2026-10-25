// Model roles, unit level (QA sdk#52 S3-4): the guards of createModelRoles and fetchRoles that the end-to-end tests cannot pin on their
// own: an answer for another role, a bad data policy, "not asked yet" is not "resolved", pause drops the cache, no cache before the claim,
// pause wins over a 200, and the key joins the redaction registry in tb-exec.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { fetchRoles, rolesInForce } from "../src/exec/roles.ts";
import type { BridgeClient, BridgeResponse } from "../src/server/bridge-client.ts";
import { TbError } from "../src/server/errors.ts";
import { SecretRegistry } from "../src/server/log.ts";
import { createModelRoles } from "../src/server/model-roles.ts";

const KEY = "unit-role-key-not-a-secret-0001";
const body = (over: Record<string, unknown> = {}) => ({ role: "reasoning", provider: "openai", model: "gpt-5", baseUrl: "https://api.openai.com/v1", key: KEY, dataPolicy: "zdr", dims: null, keysRev: 4, ...over });
const log = { debug() {}, info() {}, warn() {}, error() {} } as unknown as Logger;
const manifest = {
  runtime: { env: [] },
  settings: { steps: [], modelRoles: [{ role: "reasoning", required: true, usedBy: ["app"] }, { role: "embeddings", required: false, usedBy: ["app"] }] },
} as unknown as Manifest;

function rig(answer: (path: string) => BridgeResponse, o: { claimed?: () => boolean; paused?: () => boolean } = {}) {
  const asked: string[] = [];
  let rev = 1;
  const client = {
    request: async (_m: string, path: string) => {
      asked.push(path);
      return answer(path);
    },
  } as unknown as BridgeClient;
  const secrets = new SecretRegistry();
  const roles = createModelRoles({ manifest, env: {}, secrets, log, bridge: () => (o.claimed && !o.claimed() ? null : client), rev: () => rev, ...(o.paused ? { paused: o.paused } : {}) });
  return { roles, asked, secrets, bump: () => void rev++ };
}
const ok = (b: unknown): BridgeResponse => ({ status: 200, body: b });
const code = (e: unknown) => (e instanceof TbError ? e.code : "other");

describe("createModelRoles guards", () => {
  test("R6: an answer for ANOTHER role is refused (model_role_unavailable), not handed to the app", async () => {
    const { roles } = rig(() => ok(body({ role: "embeddings" })));
    await assert.rejects(roles.modelRole("reasoning"), (e) => code(e) === "model_role_unavailable");
  });

  test("R7: an answer without a valid data policy is refused", async () => {
    for (const dataPolicy of ["strict", undefined, 7]) {
      const { roles } = rig(() => ok(body({ dataPolicy })));
      await assert.rejects(roles.modelRole("reasoning"), (e) => code(e) === "model_role_unavailable", String(dataPolicy));
    }
  });

  test("R13: a required role that has not been asked yet is NOT resolved; refresh with 200 resolves it, with 404 it stays missing", async () => {
    const good = rig(() => ok(body()));
    assert.deepEqual(good.roles.missing(), ["reasoning"], "not asked yet = missing (fail closed)");
    await good.roles.refresh();
    assert.deepEqual(good.roles.missing(), []);
    const none = rig(() => ({ status: 404, body: null }));
    await none.roles.refresh();
    assert.deepEqual(none.roles.missing(), ["reasoning"]);
    assert.equal(none.roles.attention()?.code, "model_role_missing");
  });

  test("P1: a pause (dropCache) drops the cached binding and what readiness knew; the next call asks the bridge again", async () => {
    const r = rig(() => ok(body()));
    await r.roles.refresh();
    assert.equal((await r.roles.modelRole("reasoning"))?.model, "gpt-5");
    assert.equal(r.asked.length, 1, "cached");
    r.roles.dropCache();
    assert.deepEqual(r.roles.missing(), ["reasoning"], "readiness forgot it");
    await r.roles.modelRole("reasoning");
    assert.equal(r.asked.length, 2, "asked again after the drop");
  });

  test("S3-2: before the claim (no bridge client) nothing is cached and nothing is marked resolved; after the claim the same revision asks the bridge", async () => {
    let claimed = false;
    const r = rig(() => ok(body()), { claimed: () => claimed });
    assert.equal(await r.roles.modelRole("reasoning"), null);
    await r.roles.refresh();
    assert.deepEqual(r.roles.missing(), ["reasoning"]);
    assert.equal(r.asked.length, 0);
    claimed = true;
    assert.equal((await r.roles.modelRole("reasoning"))?.provider, "openai", "same keysRev, not a cached null");
    assert.equal(r.asked.length, 1);
  });

  test("S3-3: workspace or instance paused → modelRole throws `paused` although the bridge would answer 200; no `not set` text while paused", async () => {
    let paused = false;
    const r = rig(() => ok(body()), { paused: () => paused });
    assert.ok(await r.roles.modelRole("reasoning"));
    paused = true;
    await assert.rejects(r.roles.modelRole("reasoning"), (e) => code(e) === "paused");
    r.roles.dropCache();
    assert.equal(r.roles.attention(), null, "paused: the owner is not told the role is not set");
    assert.equal(r.asked.length, 1, "nothing is asked while paused");
    paused = false;
    assert.ok(await r.roles.modelRole("reasoning"));
    assert.equal(r.roles.attention(), null, "resolved again");
  });

  test("an undeclared role still throws role_undeclared first (also while paused)", async () => {
    const r = rig(() => ok(body()), { paused: () => true });
    await assert.rejects(r.roles.modelRole("rerank"), (e) => code(e) === "role_undeclared");
  });
});

describe("tb-exec fetchRoles", () => {
  const svcManifest = { runtime: { env: [] }, settings: { steps: [], modelRoles: [{ role: "reasoning", required: true, usedBy: ["engine"], env: { model: "KN_MODEL", key: "KN_KEY" } }] } } as unknown as Manifest;

  test("E8: the role key joins the redaction registry (a log line that carries it is redacted), and is not set when the role is refused", async () => {
    const roles = rolesInForce(svcManifest, "engine", {});
    const secrets = new SecretRegistry();
    const bridge = { fetchModelRole: async () => body() } as never;
    const got = await fetchRoles(roles, bridge, secrets, log, new AbortController().signal);
    assert.equal(got.values.get("KN_KEY"), KEY);
    assert.ok(secrets.matches(KEY), "registered for redaction");
    const none = new SecretRegistry();
    await fetchRoles(roles, { fetchModelRole: async () => null } as never, none, log, new AbortController().signal);
    assert.ok(!none.matches(KEY));
  });
});
