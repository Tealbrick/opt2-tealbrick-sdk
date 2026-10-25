// Fake Portal: bridge-auth + device-auth rows only (default deny), enrolment, config long-poll, ack, device flow.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, signAssertion, ulid, verifyConfig, verifySignedCompact } from "@opt2-tealbrick/manifest";
import { LIFETIME_S, MAX_JWS_BYTES, TYP } from "@opt2-tealbrick/spec/credentials";
import { createFakePortal, FAKE_PORTAL_ROUTES, type FakePortal } from "../src/index.ts";
import { bodyDigest } from "../src/person-op.ts";

const now = () => Math.floor(Date.now() / 1000);

describe("fake portal", () => {
  let p: FakePortal;
  let key: Ed25519KeyPair;
  const call = async (method: string, path: string, body?: unknown, assert_ = true) => {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (assert_) {
      const brg = `tb:brg:${p.bridgeId}` as const;
      headers["TB-Assert"] = await signAssertion("tb-bridge-assert+jwt", { iss: brg, sub: brg, aud: "tb:portal", iat: now() }, key, { method, pathAndQuery: path, body: bytes });
    }
    const res = await fetch(p.url + path, { method, headers, body: bytes });
    const text = await res.text();
    return { status: res.status, type: res.headers.get("content-type") ?? "", text, body: text.startsWith("{") ? JSON.parse(text) : null };
  };
  before(async () => {
    p = await createFakePortal({ pollIntervalS: 0, maxWaitS: 1 });
    key = await generateKeyPair();
  });
  after(() => p.close());

  it("serves only bridge/device rows (+ their public starts); everything else 404", async () => {
    // spec 0.1.64 (BRIDGE §16): + the person-op pull and its result post
    assert.deepEqual(FAKE_PORTAL_ROUTES.map((r) => r.opId).sort(), ["bridge_api.ack", "bridge_api.config", "bridge_api.enrol", "bridge_api.person_op_result", "bridge_api.person_ops", "device.start", "device.token"]);
    for (const [m, path] of [["GET", "/api/v1/workspaces"], ["GET", "/internal/routes"], ["POST", "/api/v1/device/approve"], ["GET", "/api/v1/me"]]) {
      assert.equal((await call(m, path, undefined, false)).status, 404, path);
    }
  });

  it("enrolment: one-time code, own key; config requires the bridge assertion", async () => {
    const code = p.control.issueEnrolCode();
    const body = { code, publicKey: key.publicJwk, version: "1.0.0", sdkMajors: [1, 0], form: "deployed", publicOrigin: "https://bridge.conformance.test" };
    assert.equal((await call("GET", "/api/v1/bridge/config?after=0&wait=0")).status, 401, "not enrolled yet");
    const r = await call("POST", "/api/v1/bridge/enrol", body, false);
    assert.equal(r.status, 200);
    assert.equal(r.body.bridgeId, p.bridgeId);
    assert.equal((await call("POST", "/api/v1/bridge/enrol", body, false)).body.error.code, "enrolment_code_invalid");
    const unsigned = await call("GET", "/api/v1/bridge/config?after=0&wait=0", undefined, false);
    assert.equal(unsigned.status, 401);
  });

  it("config long-poll: 200 application/jose when newer, 304 after the wait, woken by a new revision", async () => {
    const first = await call("GET", "/api/v1/bridge/config?after=0&wait=1");
    assert.equal(first.status, 200);
    assert.match(first.type, /application\/jose/);
    const v = verifyConfig(first.text, { now: now(), self: `tb:brg:${p.bridgeId}`, issuers: keySetFrom({ keys: [p.activeKey().publicJwk] }, "tb:portal") });
    assert.ok(v.ok);
    const idle = await call("GET", `/api/v1/bridge/config?after=${p.rev}&wait=1`);
    assert.equal(idle.status, 304);
    const pending = call("GET", `/api/v1/bridge/config?after=${p.rev}&wait=1`);
    const agt = await p.control.addAgent("Agent X");
    const woken = await pending;
    assert.equal(woken.status, 200);
    const cfg = verifyConfig(woken.text, { now: now(), self: `tb:brg:${p.bridgeId}`, issuers: keySetFrom({ keys: [p.activeKey().publicJwk] }, "tb:portal") });
    assert.ok(cfg.ok && (cfg.body as { agents: { agt: string }[] }).agents.some((a) => a.agt === agt));
  });

  it("ack: recorded with the bridge assertion", async () => {
    const report = { rev: p.rev, appliedAt: new Date().toISOString(), bridge: { id: p.bridgeId, version: "1.0.0", form: "deployed", boot: "b1", sdkMajors: [1], mcpVersions: [] }, portalReachable: true, apps: [], keys: [], scopeSummaries: [], connectionsCreated: [], connectionsRevoked: [], claims: [], rejected: [], toolsOmitted: [] };
    const r = await call("POST", "/api/v1/bridge/ack", report);
    assert.deepEqual(r.body, { accepted: true, configRevision: p.rev });
    assert.equal(p.acks.length, 1);
  });

  it("person-op relay (spec 0.1.64): the long-poll hands each row out once with a Portal-signed K14 over the exact body; results are recorded; untaken rows expire", async () => {
    const ins = `ins_${ulid()}`;
    assert.equal((await call("GET", "/api/v1/bridge/person-ops?wait=0", undefined, false)).status, 401, "bridge assertion required");
    assert.deepEqual((await call("GET", "/api/v1/bridge/person-ops?wait=0")).body, { items: [] });
    const pending = call("GET", "/api/v1/bridge/person-ops?wait=1");
    await new Promise((r) => setTimeout(r, 100));
    const body = '{"q": "Grüße ✓"}';
    const row = await p.queuePersonOp({ ins: ins as never, op: "items_list", body });
    const got = await pending;
    assert.equal(got.status, 200);
    assert.deepEqual(got.body.items, [row.item], "the waiting poll is woken with the row");
    assert.equal(got.body.items[0].body, body);
    const v = verifySignedCompact(row.item.jws, keySetFrom({ keys: [p.activeKey().publicJwk] }, "tb:portal"), TYP.personOp, MAX_JWS_BYTES);
    assert.ok(v.ok, "K14 signed by the Portal key, typ tb-person-op+jwt");
    const c = (v as { payload: Record<string, unknown> }).payload;
    assert.deepEqual(Object.keys(c).sort(), ["aud", "bd", "cli", "exp", "iat", "idk", "iss", "jti", "op", "pop", "sub", "ws"]);
    assert.equal(c.iss, "tb:portal");
    assert.equal(c.sub, `tb:per:${p.owner}`);
    assert.equal(c.aud, `tb:ins:${ins}`);
    assert.equal(c.ws, p.ws);
    assert.equal(c.cli, "tbm");
    assert.equal(c.pop, row.item.id);
    assert.equal(c.bd, bodyDigest(body));
    assert.match(String(c.bd), /^sha256:[0-9a-f]{64}$/);
    assert.equal(Number(c.exp) - Number(c.iat), LIFETIME_S.personOp);
    assert.match(String(c.jti), /^[0-9A-HJKMNP-TV-Z]{26}$/);
    assert.deepEqual((await call("GET", "/api/v1/bridge/person-ops?wait=0")).body, { items: [] }, "handed out once");
    const res = await call("POST", `/api/v1/bridge/person-ops/${row.item.id}/result`, { pop: row.item.id, status: 200, body: "{}" });
    assert.deepEqual(res.body, { ok: true });
    assert.deepEqual(p.personOpResults.map((x) => [x.pop, x.status, x.body]), [[row.item.id, 200, "{}"]]);
    assert.equal((await call("POST", `/api/v1/bridge/person-ops/pop_${ulid()}/result`, { status: 0, body: "" })).status, 404, "unknown pop");
    p.personOpTtlMs = 50;
    try {
      const late = await p.queuePersonOp({ ins: ins as never, op: "items_list", body: "{}" });
      await new Promise((r) => setTimeout(r, 120));
      assert.deepEqual((await call("GET", "/api/v1/bridge/person-ops?wait=0")).body, { items: [] }, "an untaken row expires");
      assert.equal(late.expired, true);
    } finally {
      p.personOpTtlMs = 4000;
    }
    assert.equal(p.personOpPollsMaxOpen, 1);
  });

  it("device flow: kit cannot get owner; pending → approved → one-time; agent scope creates connections", async () => {
    const kitOwner = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "kit", machine_label: "m" }, false);
    assert.equal(kitOwner.body.error.code, "bad_request");
    const ownerKey = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "tbd", machine_label: "m", agents: [] }, false);
    assert.equal(ownerKey.status, 400);
    const agentKey = await generateKeyPair();
    const start = await call("POST", "/api/v1/device/authorize", { scope: "agent", client_id: "kit", machine_label: "mac", harness: "generic", agents: [{ public_key: agentKey.publicJwk }] }, false);
    assert.equal(start.status, 200);
    assert.match(start.body.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    const tok = { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "kit" };
    assert.equal((await call("POST", "/api/v1/device/token", tok, false)).body.error.code, "authorization_pending");
    await p.control.approveDevice(start.body.user_code);
    const done = await call("POST", "/api/v1/device/token", tok, false);
    assert.equal(done.body.scope, "agent");
    assert.equal(done.body.bridge_id, p.bridgeId);
    assert.equal(done.body.connections.length, 1);
    assert.equal("access_token" in done.body, false, "agent scope carries no bearer");
    assert.equal((await call("POST", "/api/v1/device/token", tok, false)).body.error.code, "expired_token");
    const owner = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "tealbrick-cli", machine_label: "m" }, false);
    p.control.denyDevice(owner.body.user_code);
    assert.equal((await call("POST", "/api/v1/device/token", { ...tok, device_code: owner.body.device_code, client_id: "tealbrick-cli" }, false)).body.error.code, "access_denied");
  });

  it("slow_down when polled faster than the interval; offline drops connections", async () => {
    const q = await createFakePortal({ pollIntervalS: 5 });
    try {
      const start = await (await fetch(`${q.url}/api/v1/device/authorize`, { method: "POST", body: JSON.stringify({ scope: "owner", client_id: "tbd", machine_label: "m" }) })).json();
      const tok = JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.device_code, client_id: "tbd" });
      const a = await (await fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok })).json();
      const b = await (await fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok })).json();
      assert.equal(a.error.code, "authorization_pending");
      assert.equal(b.error.code, "slow_down");
      q.control.goOffline(true);
      await assert.rejects(fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok }));
    } finally {
      await q.close();
    }
  });

  it("key rotation reaches the config even when a world froze portalKeys into configExtra (Lead · Bridge finding, C5)", async () => {
    const q = await createFakePortal({ pollIntervalS: 0, maxWaitS: 1 });
    try {
      // what BridgeWorld.publish() does: freeze the current key list into configExtra (merged last)
      q.configExtra = { ...q.configExtra, portalKeys: q.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })) };
      const statuses = () => (q.configBody(q.rev).portalKeys ?? []).map((k) => k.status);
      assert.deepEqual(statuses(), ["active"]);
      await q.control.rotateKey("announce");
      assert.deepEqual(statuses(), ["active", "pending"], "announce carries the pending key");
      await q.control.rotateKey("activate");
      assert.deepEqual(statuses(), ["retired", "active"], "activate applied");
      await q.control.rotateKey("retire");
      assert.deepEqual(statuses(), ["active"], "retired key dropped");
      // standalone worlds keep their empty list
      q.configExtra = { ...q.configExtra, portalKeys: [] };
      await q.control.rotateKey("announce");
      assert.deepEqual(statuses(), []);
    } finally {
      await q.close();
    }
  });
});
