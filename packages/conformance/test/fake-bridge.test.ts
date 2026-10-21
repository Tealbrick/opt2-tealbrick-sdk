// Fake bridge: internal surface (claim, status long-poll, keys, companion call), default deny, control API, mint.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import {
  DEFAULT_HELD_FAMILIES,
  digest,
  type Ed25519KeyPair,
  generateKeyPair,
  keySetFrom,
  keySetFromPortalKeys,
  manifestDigest,
  signInstanceAssertion,
  verifyBridgeOpProof,
  verifyCallProof,
  verifyGrant,
  verifyHookProof,
  verifySlice,
  verifyTicket,
} from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { TrustContext } from "@opt2-tealbrick/spec/sdk";
import { createFakeBridge, type FakeBridge, peek } from "../src/index.ts";

const manifest = JSON.parse(readFileSync(new URL("./fixtures/sample.manifest.json", import.meta.url), "utf8")) as Manifest;
const now = () => Math.floor(Date.now() / 1000);

async function signed(b: FakeBridge, key: Ed25519KeyPair, method: "GET" | "POST", path: string, body?: unknown, headers: Record<string, string> = {}) {
  const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
  const assertion = await signInstanceAssertion({ key, ins: b.ids.ins, bridge: b.ids.bridge, method, pathAndQuery: path, body: bytes, now: now() });
  const res = await fetch(b.url + path, { method, headers: { "content-type": "application/json", "TB-Assert": assertion, ...headers }, body: bytes });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

const claimBody = (b: FakeBridge, key: Ed25519KeyPair, over: Record<string, unknown> = {}) => ({
  code: b.enrolCode,
  instancePublicKey: key.publicJwk,
  manifestDigest: manifestDigest(manifest),
  version: manifest.version,
  sdkVersion: "1.2.3",
  ...over,
});
const post = async (url: string, body: unknown) => {
  const res = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
};

function trustFor(b: FakeBridge, slice: InstanceSlice): TrustContext {
  return {
    now: now(),
    self: `tb:ins:${b.ids.ins}`,
    ws: b.ids.ws,
    bridge: b.ids.bridge,
    issuers: keySetFromPortalKeys(slice.portalKeys),
    bridgeKeys: keySetFrom({ keys: slice.bridge.keys }, `tb:brg:${b.ids.bridge}`),
    revokedJtis: new Set(slice.revoked.jtis.map((j) => j.jti)),
  };
}

describe("fake bridge: claim", () => {
  let b: FakeBridge;
  let key: Ed25519KeyPair;
  before(async () => {
    b = await createFakeBridge({ manifest, maxWaitS: 1 });
    key = await generateKeyPair();
  });
  after(() => b.close());

  it("refuses a wrong manifest digest, an unsupported SDK major and a bad key before using the code", async () => {
    const mm = await post(`${b.url}/tb/v1/claim`, claimBody(b, key, { manifestDigest: `sha256:${"0".repeat(64)}` }));
    assert.equal(mm.status, 409);
    assert.equal((mm.body.error as { code: string }).code, "manifest_mismatch");
    const major = await post(`${b.url}/tb/v1/claim`, claimBody(b, key, { sdkVersion: "7.0.0" }));
    assert.equal((major.body.error as { code: string }).code, "sdk_major_unsupported");
    const badKey = await post(`${b.url}/tb/v1/claim`, claimBody(b, key, { instancePublicKey: { kty: "RSA" } }));
    assert.equal((badKey.body.error as { code: string }).code, "input_invalid");
  });

  it("accepts the enrolment code once and returns the bridge key and a verifiable slice", async () => {
    const r = await post(`${b.url}/tb/v1/claim`, claimBody(b, key));
    assert.equal(r.status, 200);
    assert.equal(r.body.ins, b.ids.ins);
    const sl = verifySlice(String(r.body.slice), { now: now(), self: `tb:ins:${b.ids.ins}`, ws: b.ids.ws, bridge: b.ids.bridge, issuers: keySetFrom(b.portalJwks(), "tb:portal") });
    assert.ok(sl.ok);
    assert.equal(sl.ok && sl.slice.agents.length, 3);
    assert.equal(sl.ok && sl.slice.grants.length, 1, "one companion grant per manifest companion");
    // spec 0.1.15 slice shape (C90, C102, C105a): companionTargets per grant, companionCallers, appsPolicy; the companion
    // grant holds appsPolicy.held = DEFAULT_HELD_FAMILIES (CORE I8)
    assert.ok(sl.ok);
    if (sl.ok) {
      assert.deepEqual(sl.slice.companionTargets, [{ product: "conf-peer", ins: b.ids.peers["conf-peer"] }]);
      assert.deepEqual(sl.slice.companionCallers, []);
      // spec 0.1.18 (C106a, L1): agent A carries scopeRequest {product: self, kind: connect_inbox, createName: conformance}
      assert.deepEqual(sl.slice.agents[0]?.scopeRequest, { product: b.manifest.id, kind: "connect_inbox", createName: "conformance" });
      assert.equal(sl.slice.agents[1]?.scopeRequest, undefined);
      assert.deepEqual(sl.slice.appsPolicy, { held: [...DEFAULT_HELD_FAMILIES] });
      assert.deepEqual((peek(sl.slice.grants[0] as string) as { held: string[] }).held, [...DEFAULT_HELD_FAMILIES]);
    }
    const again = await post(`${b.url}/tb/v1/claim`, claimBody(b, key));
    assert.equal(again.status, 403);
    assert.equal((again.body.error as { code: string }).code, "code_invalid");
    assert.equal((await post(`${b.url}/tb/v1/claim`, claimBody(b, key, { code: "tbe_unknown" }))).status, 403);
  });

  it("status: assertion required; answers at once on a slice change, 204 after the wait", async () => {
    const st = { readiness: "ready", version: "1.0.0", sdkVersion: "1.0.0", scopesRev: 0, sliceRevision: 0, keysRev: 0, pendingHolds: 0 };
    const unsigned = await post(`${b.url}/tb/v1/status?wait=0`, st);
    assert.equal(unsigned.status, 401);
    const first = await signed(b, key, "POST", "/tb/v1/status?wait=1", st);
    assert.equal(first.status, 200);
    assert.equal(first.body.sliceRevision, b.control.sliceRevision);
    const t0 = Date.now();
    const idle = await signed(b, key, "POST", "/tb/v1/status?wait=1", { ...st, sliceRevision: b.control.sliceRevision });
    assert.equal(idle.status, 204);
    assert.ok(Date.now() - t0 >= 900, "held for the wait");
    const pending = signed(b, key, "POST", "/tb/v1/status?wait=1", { ...st, sliceRevision: b.control.sliceRevision });
    const rev = await b.control.pauseWorkspace(true);
    const woken = await pending;
    assert.equal(woken.status, 200);
    assert.equal(woken.body.sliceRevision, rev);
    assert.equal((peek(woken.body.slice) as unknown as InstanceSlice).pause.workspace, true);
    await b.control.pauseWorkspace(false);
    const bad = await signed(b, key, "POST", "/tb/v1/status?wait=0", { readiness: "nope" });
    assert.equal(bad.status, 400);
    assert.equal(b.statuses.length, 3, "only verified, well-formed pushes are recorded");
  });

  it("keys: declared only, not set → 404, set → value + no-store, paused → 403", async () => {
    assert.equal((await signed(b, key, "GET", "/tb/v1/keys/UNDECLARED_KEY")).body.error.code, "key_not_declared");
    assert.equal((await signed(b, key, "GET", "/tb/v1/keys/SAMPLE_API_KEY")).body.error.code, "key_not_set");
    const before = b.control.keysRev;
    b.control.setKey("SAMPLE_API_KEY", "value-1234567890");
    assert.equal(b.control.keysRev, before + 1);
    const ok = await signed(b, key, "GET", "/tb/v1/keys/SAMPLE_API_KEY");
    assert.deepEqual(ok.body, { name: "SAMPLE_API_KEY", value: "value-1234567890", keysRev: before + 1 });
    await b.control.pauseInstance(true);
    assert.equal((await signed(b, key, "GET", "/tb/v1/keys/SAMPLE_API_KEY")).body.error.code, "paused");
    await b.control.pauseInstance(false);
    b.control.deleteKey("SAMPLE_API_KEY");
    assert.equal((await signed(b, key, "GET", "/tb/v1/keys/SAMPLE_API_KEY")).status, 404);
  });

  it("companion call: gate() with the companion grant; hooks fail closed; config expiry; pause", async () => {
    const sl = peek(b.slice as string) as unknown as InstanceSlice;
    const grant = sl.grants[0];
    const env = { target: "conf-peer", op: "peer_get", input: { id: "x" } };
    const ok = await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant });
    assert.deepEqual([ok.status, ok.body.status], [200, "ok"]);
    const notWf = await signed(b, key, "POST", "/tb/v1/call", { ...env, op: "other_op" }, { "TB-Grant": grant });
    assert.equal(notWf.body.error.code, "not_in_workflow");
    const noGrant = await signed(b, key, "POST", "/tb/v1/call", env);
    assert.equal(noGrant.body.error.code, "grant_invalid");
    b.control.injectHook("before", "deny");
    assert.equal((await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant })).body.error.code, "hook_denied");
    b.control.clearHooks();
    b.control.injectHook("context", "error");
    assert.equal((await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant })).body.error.code, "hook_failed");
    b.control.clearHooks();
    b.control.setConfigExpired(true);
    assert.equal((await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant })).body.error.code, "config_expired");
    b.control.setConfigExpired(false);
    await b.control.pauseWorkspace(true);
    assert.equal((await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant })).body.error.code, "paused");
    await b.control.pauseWorkspace(false);
    b.control.setCompanionResponder(() => ({ status: "held", holdId: "hld_X", expiresAt: new Date(0).toISOString() }));
    assert.equal((await signed(b, key, "POST", "/tb/v1/call", env, { "TB-Grant": grant })).status, 202);
    assert.equal(b.companionCalls.length, 2);
  });

  it("replayed instance assertion and unknown routes are refused (default deny)", async () => {
    const assertion = await signInstanceAssertion({ key, ins: b.ids.ins, bridge: b.ids.bridge, method: "GET", pathAndQuery: "/tb/v1/keys/SAMPLE_API_KEY", now: now() });
    const h = { "TB-Assert": assertion };
    await fetch(`${b.url}/tb/v1/keys/SAMPLE_API_KEY`, { headers: h });
    assert.equal((await fetch(`${b.url}/tb/v1/keys/SAMPLE_API_KEY`, { headers: h })).status, 401);
    for (const p of ["/tb/v1/unknown", "/keys", "/admin/v1/pause"]) assert.equal((await fetch(b.url + p, { method: "POST" })).status, 404, p);
    // conformance 0.1.28: /mcp serves the tealbrick/events/* methods to a slice agent only (fake authentication)
    assert.equal((await fetch(`${b.url}/mcp`, { method: "POST" })).status, 401);
  });
});

describe("fake bridge: app events (conformance 0.1.28, BRIDGE §14)", () => {
  // the sample manifest with one unscoped (granted) and one scoped event
  const m = structuredClone(manifest);
  const unscoped = m.operations.find((o) => o.audience === "agent" && !o.scopeType && !o.dynamic);
  m.operations.push({ id: "ev_read", title: "Read", description: "Read.", input: { type: "object" }, output: { type: "object" }, crud: ["read"], effect: "read", idempotency: "none", receipt: false, audience: "agent" } as Manifest["operations"][number]);
  m.events = [
    { name: "x.ping", title: "Ping", payloadSchema: { type: "object", properties: { n: { type: "integer" } } }, visibleWith: unscoped?.id ?? "ev_read", audience: "granted" },
    { name: "x.scoped", title: "Scoped", payloadSchema: { type: "object" }, visibleWith: "item_get", audience: "granted" },
  ];
  let b: FakeBridge;
  let key: Ed25519KeyPair;
  before(async () => {
    b = await createFakeBridge({ manifest: m, maxWaitS: 1 });
    key = await generateKeyPair();
    assert.equal((await post(`${b.url}/tb/v1/claim`, claimBody(b, key, { manifestDigest: manifestDigest(m) }))).status, 200);
  });
  after(() => b.close());
  const it1 = (o: Record<string, unknown>) => ({ kind: "emit", key: `k-${Math.random().toString(36).slice(2, 12)}`, name: "x.ping", at: new Date().toISOString(), subject: { kind: "x", id: "1" }, data: { n: 1 }, ...o });
  const rpc = async (agent: string, method: string, params: Record<string, unknown> = {}) => {
    const res = await fetch(`${b.url}/mcp`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${agent}` }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
    return (await res.json()) as { result?: Record<string, unknown>; error?: { code: number; data?: { code?: string } } };
  };

  it("ingest checks in order, fan-out to the slice agents, dedupe, refusals, poll with cursor", async () => {
    const [x, y] = b.ids.agents;
    const r = await signed(b, key, "POST", "/tb/v1/events", {
      items: [it1({ key: "dup-key-0001", causedBy: x?.id }), it1({ key: "dup-key-0001" }), it1({ name: "x.unknown" }), it1({ name: "tb.custom" }), it1({ data: { n: "x" } }), it1({ name: "x.scoped" })],
    });
    assert.equal(r.status, 200);
    assert.deepEqual(
      (r.body.results as { status: string; code?: string }[]).map((z) => `${z.status}${z.code ? ` ${z.code}` : ""}`),
      ["stored", "duplicate", "refused event_undeclared", "refused event_reserved", "refused event_payload_invalid", "refused event_instance_invalid"],
    );
    const px = await rpc(x?.id as string, "tealbrick/events/poll");
    const py = await rpc(y?.id as string, "tealbrick/events/poll");
    assert.equal(((px.result?.events ?? []) as unknown[]).length, 0, "the causing agent gets nothing");
    const ev = ((py.result?.events ?? []) as { type: string; origin: string; id: string }[])[0];
    assert.equal(ev?.type, `${m.id}.x.ping`);
    assert.equal(ev?.origin, ev?.id);
    const again = await rpc(y?.id as string, "tealbrick/events/poll", { cursor: py.result?.cursor });
    assert.equal(((again.result?.events ?? []) as unknown[]).length, 0);
    assert.equal((await rpc(y?.id as string, "tealbrick/events/poll", { cursor: "not-a-ulid" })).error?.data?.code, "cursor_invalid");
    const list = await rpc(y?.id as string, "tealbrick/events/list");
    assert.ok(((list.result?.types ?? []) as { type: string }[]).some((t) => t.type === "tb.hold.decided"));
    // specs#33: [P, E2] stored, the answer lost, the same batch again → both duplicate, E2 still stored (the purge is not re-applied)
    const yid = y?.id as string;
    const before = await rpc(yid, "tealbrick/events/poll", { cursor: again.result?.cursor });
    const batch = { items: [{ kind: "purge", key: "purge-key-replay1", agent: yid, instanceId: "sp1" }, it1({ key: "e2-key-replay-1", name: "x.scoped", instanceId: "sp1", eligible: [{ agent: yid, authority: "bounded" }], data: {} })] };
    const first = await signed(b, key, "POST", "/tb/v1/events", batch);
    const retry = await signed(b, key, "POST", "/tb/v1/events", batch);
    assert.deepEqual((first.body.results as { status: string }[]).map((z) => z.status), ["stored", "stored"]);
    assert.deepEqual((retry.body.results as { status: string }[]).map((z) => z.status), ["duplicate", "duplicate"]);
    const after = await rpc(yid, "tealbrick/events/poll", { cursor: before.result?.cursor ?? again.result?.cursor });
    assert.equal(((after.result?.events ?? []) as { instanceId?: string }[]).filter((e) => e.instanceId === "sp1").length, 1, "E2 survives the retried purge");
    b.control.failNextEvents(1);
    assert.equal((await signed(b, key, "POST", "/tb/v1/events", { items: [it1({})] })).status, 503);
    assert.equal(b.control.eventItems().at(-1)?.status, 503);
  });
});

describe("fake bridge: control + mint", () => {
  let b: FakeBridge;
  before(async () => {
    b = await createFakeBridge({ manifest });
  });
  after(() => b.close());

  it("Portal key rotation walks pending → active → retired → removed in the slice", async () => {
    const statuses = () => (peek(b.slice as string) as unknown as InstanceSlice).portalKeys.map((k) => k.status).join(",");
    await b.control.rotatePortalKey("announce");
    assert.equal(statuses(), "active,pending");
    await b.control.rotatePortalKey("activate");
    assert.equal(statuses(), "retired,active");
    await b.control.rotatePortalKey("retire");
    assert.equal(statuses(), "active");
    await assert.rejects(b.control.rotatePortalKey("activate"), /no pending/);
  });

  it("revokeJti, personNbf and bridge key rotation land in the next slice", async () => {
    await b.control.revokeJti("01JA2B3C4D5E6F7G8H9JKMNPQR", now() + 600);
    await b.control.setPersonNbf(1234);
    await b.control.rotateBridgeKey({ keepOld: true });
    const sl = peek(b.slice as string) as unknown as InstanceSlice;
    assert.equal(sl.revoked.jtis[0].jti, "01JA2B3C4D5E6F7G8H9JKMNPQR");
    assert.equal(sl.personNbf, 1234);
    assert.equal(sl.bridge.keys.length, 2);
  });

  it("C102 / C105a: listed app callers and the apps policy land in the slice; client grants default to the card / apps policy", async () => {
    const ins = "ins_01JA2B3C4D5E6F7G8H9JKMNPQR" as const;
    await b.control.listCompanionCaller({ product: "tbconf-caller", ins, name: "Caller app" });
    await b.control.setAppsPolicy(["money"]);
    const sl = peek(b.slice as string) as unknown as InstanceSlice;
    assert.deepEqual(sl.companionCallers, [{ product: "tbconf-caller", ins, name: "Caller app" }]);
    assert.deepEqual(sl.appsPolicy, { held: ["money"] });
    assert.deepEqual((peek(sl.grants[0] as string) as { held: string[] }).held, ["money"]);
    // AppClient: an agent grant holds DEFAULT_HELD_FAMILIES, an app-caller grant the apps policy (nothing is sent: unreachable URL)
    const client = b.client("http://127.0.0.1:9");
    const asAgent = await client.callOp("item_get", { space: "s", id: "i" }).catch((e: unknown) => e);
    const asApp = await client.callOp("item_get", { space: "s", id: "i" }, { caller: ins }).catch((e: unknown) => e);
    void asAgent;
    void asApp;
    const sent = b.captured.filter((x) => x.dir === "app-out" && x.path === "/tb/v1/ops/item_get").slice(-2);
    const held = sent.map((x) => (peek(String(x.headers.authorization).replace(/^Bearer /, "")) as { held: string[] }).held);
    assert.deepEqual(held, [[...DEFAULT_HELD_FAMILIES], ["money"]]);
    await b.control.setAppsPolicy(DEFAULT_HELD_FAMILIES);
  });

  it("minted grants, proofs and tickets verify with the manifest verifiers", async () => {
    const sl = peek(b.slice as string) as unknown as InstanceSlice;
    const t = trustFor(b, sl);
    const agent = b.ids.agents[0].id;
    const grant = await b.mint.grant({ sub: `tb:agt:${agent}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free" });
    const g = verifyGrant(grant, t);
    assert.ok(g.ok);
    const input = { a: 1 };
    const proof = await b.mint.callProof({ sub: `tb:agt:${agent}`, aud: `tb:ins:${b.ids.ins}`, gjti: g.ok ? g.claims.jti : "", op: "item_get", input, context: {} });
    assert.ok(verifyCallProof(proof, t, { op: "item_get", inputDigest: digest(input), contextDigest: digest({}), grantJti: g.ok ? g.claims.jti : "" }).ok);
    const hp = await b.mint.hookProof({ sub: `tb:agt:${agent}`, aud: `tb:ins:${b.ids.ins}`, hook: "guard", phase: "before", context: {} });
    assert.ok(verifyHookProof(hp, t, { hook: "guard", phase: "before", contextDigest: digest({}) }).ok);
    const bp = await b.mint.bridgeOpProof({ aud: `tb:ins:${b.ids.ins}`, bop: "mark", body: { call: "x" } });
    assert.ok(verifyBridgeOpProof(bp, t, { bop: "mark", inputDigest: digest({ call: "x" }) }).ok);
    const tk = await b.mint.launchTicket({ person: b.ids.person, aud: `tb:ins:${b.ids.ins}` });
    assert.ok(verifyTicket(tk, t).ok);
    const stranger = await b.mint.grant({ sub: `tb:agt:${agent}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free", key: b.stranger });
    assert.equal(verifyGrant(stranger, t).ok, false);
  });

  it("waitForStatus / waitForClaim time out when the app never reports", async () => {
    await assert.rejects(b.control.waitForStatus(() => true, 100), /timeout/);
    await assert.rejects(b.control.waitForClaim(100), /no claim/);
  });

  it("deferred binding: claim accepted without slice until bind()", async () => {
    const d = await createFakeBridge({ manifest, deferBinding: true });
    try {
      const key = await generateKeyPair();
      const r = await post(`${d.url}/tb/v1/claim`, claimBody(d, key));
      assert.equal(r.status, 200);
      assert.equal(r.body.slice, undefined);
      const st = { readiness: "ready", version: "1.0.0", sdkVersion: "1.0.0", scopesRev: 0, sliceRevision: 0, keysRev: 0, pendingHolds: 0 };
      assert.equal((await signed(d, key, "POST", "/tb/v1/status?wait=0", st)).status, 401, "key not bound yet");
      await d.control.bind();
      assert.equal((await signed(d, key, "POST", "/tb/v1/status?wait=0", st)).status, 200);
    } finally {
      await d.close();
    }
  });
});
