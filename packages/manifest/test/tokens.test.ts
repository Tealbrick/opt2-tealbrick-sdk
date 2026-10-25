// tokens.ts: kind verifiers and issuer-side signers.
import assert from "node:assert/strict";
import { test } from "node:test";
import type { InstanceSlice, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type CallId, type ConnectionId, LEEWAY_S, TYP } from "@opt2-tealbrick/spec/credentials";
import { digest, sha256Bytes } from "../src/jcs.ts";
import { type Issue, memoryReplayGuard, signJws } from "../src/jws.ts";
import { keySetFrom } from "../src/keys.ts";
import { opaqueValue, ulid } from "../src/random.ts";
import {
  bridgeOpBinding,
  bridgeOpProofClaims,
  hookCallerRef,
  signAgentSession,
  signBridgeOpProof,
  signCallProof,
  signConfig,
  signGrant,
  signHookProof,
  signPairingCode,
  signSlice,
  signTicket,
  verifyAgentSession,
  verifyBridgeOpProof,
  verifyCallProof,
  verifyConfig,
  verifyGrant,
  verifyHookProof,
  verifyKeysTicket,
  verifyPairingCode,
  verifySlice,
  verifyTicket,
} from "../src/tokens.ts";
import { NOW, payloadOf, rawSign, world } from "./fixtures.ts";

const code = (r: { ok: boolean; code?: string }) => (r.ok ? "ok" : r.code);

test("verifyGrant: positive (agent and companion), caller mapping", async () => {
  const w = await world();
  const g = await signGrant(w.grantClaims(), w.portal);
  const r = verifyGrant(g, w.trust);
  assert.ok(r.ok);
  assert.deepEqual(r.ok && r.caller, { type: "agent", id: w.agt });
  assert.equal(r.ok && r.claims.exp - r.claims.iat, 43200);
  assert.equal(r.ok && r.token, g);
  const c = await signGrant(w.grantClaims({ sub: `tb:ins:${w.other}`, mode: "bound", wf: ["sync"], held: ["money"], caps: {} }), w.portal);
  const rc = verifyGrant(c, w.trust);
  assert.deepEqual(rc.ok && rc.caller, { type: "app", id: w.other });
});

test("verifyGrant: refusals with grant codes", async () => {
  const w = await world();
  const hdr = { alg: "EdDSA", typ: TYP.grant, kid: w.portal.kid };
  const full = { ...w.grantClaims(), exp: NOW + 43000, jti: ulid() };
  const revokedJti = ulid();
  const ctx = { ...w.trust, revokedJtis: new Set([revokedJti]) };
  const cases: [string, string, string][] = [
    ["foreign aud", await signGrant(w.grantClaims({ aud: `tb:ins:${w.other}` }), w.portal), "grant_invalid"],
    ["aud array", await rawSign(hdr, { ...full, aud: [`tb:ins:${w.ins}`] }, w.portal), "grant_invalid"],
    ["aud missing", await rawSign(hdr, { ...full, aud: undefined }, w.portal), "grant_invalid"],
    ["expired", await signGrant(w.grantClaims({ iat: NOW - 43200, exp: NOW - LEEWAY_S }), w.portal), "grant_expired"],
    ["lifetime > 12 h", await rawSign(hdr, { ...full, exp: full.iat + 43201 }, w.portal), "grant_invalid"],
    ["unannounced kid", await signGrant(w.grantClaims(), w.stranger), "grant_invalid"],
    ["signed by bridge key", await signGrant(w.grantClaims(), w.bridgeKey), "grant_invalid"],
    ["ws mismatch", await signGrant(w.grantClaims({ ws: `ws_${ulid()}` }), w.portal), "grant_invalid"],
    ["cnf.brg mismatch", await signGrant(w.grantClaims({ cnf: { brg: `brg_${ulid()}` } }), w.portal), "grant_invalid"],
    ["revoked jti", await signGrant(w.grantClaims({ jti: revokedJti }), w.portal), "grant_revoked"],
    ["unknown claim", await rawSign(hdr, { ...full, scope: "all" }, w.portal), "grant_invalid"],
    ["bad crud", await rawSign(hdr, { ...full, crud: ["read", "read"] }, w.portal), "grant_invalid"],
    ["companion not bound", await rawSign(hdr, { ...full, sub: `tb:ins:${w.other}` }, w.portal), "grant_invalid"],
    ["person subject", await rawSign(hdr, { ...full, sub: `tb:per:per_${ulid()}` }, w.portal), "grant_invalid"],
    ["standalone iss without trust", await signGrant(w.grantClaims({ iss: `tb:brg:${w.brg}` }), w.bridgeKey), "grant_invalid"],
    ["typ confusion: ticket as grant", await signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, ws: w.ws, pur: "launch", iat: NOW }, w.portal), "grant_invalid"],
    ["clerk-shaped JWT", `${Buffer.from('{"alg":"RS256","typ":"JWT"}').toString("base64url")}.${Buffer.from('{"sub":"user_2"}').toString("base64url")}.AAAA`, "grant_invalid"],
    ["owner CLI opaque", opaqueValue("tbo_"), "grant_invalid"],
  ];
  for (const [name, token, want] of cases) assert.equal(code(verifyGrant(token, ctx)), want, name);
});

test("verifyGrant: standalone issuer named by the slice", async () => {
  const w = await world();
  const issuers = keySetFrom({ keys: [w.bridgeKey.publicJwk] }, `tb:brg:${w.brg}`);
  const g = await signGrant(w.grantClaims({ iss: `tb:brg:${w.brg}` }), w.bridgeKey);
  assert.ok(verifyGrant(g, { ...w.trust, issuers }).ok);
  // a bridge-trusted key cannot mint a grant claiming to be Portal
  const p = await signGrant(w.grantClaims(), w.bridgeKey);
  assert.equal(code(verifyGrant(p, { ...w.trust, issuers })), "grant_invalid");
});

test("signGrant enforces lifetime and claim shape", async () => {
  const w = await world();
  await assert.rejects(signGrant(w.grantClaims({ exp: NOW - 10 + 43201 }), w.portal), /lifetime/);
  await assert.rejects(signGrant(w.grantClaims({ exp: NOW - 10 }), w.portal), /lifetime/);
  await assert.rejects(signGrant(w.grantClaims({ sub: `tb:ins:${w.other}`, mode: "free" }), w.portal), /not bound/);
  await assert.rejects(signGrant(w.grantClaims({ caps: { money: { max: 1, per: "day" } } as never }), w.portal));
});

async function proofs() {
  const w = await world();
  const g = await signGrant(w.grantClaims(), w.portal);
  const gjti = payloadOf(g).jti as string;
  const input = { q: "x" };
  const context = {};
  const call = `call_${ulid()}` as CallId;
  const brg = `tb:brg:${w.brg}` as const;
  const opClaims = { iss: brg, sub: `tb:agt:${w.agt}` as const, aud: `tb:ins:${w.ins}` as const, call, gjti, op: "search", in: digest(input), ctx: digest(context), iat: NOW };
  const bind = { op: "search", inputDigest: digest(input), contextDigest: digest(context), grantJti: gjti, grantSub: `tb:agt:${w.agt}` };
  return { w, g, gjti, call, brg, opClaims, bind, input, context };
}

test("verifyCallProof: positive, bindings, typ/variant confusion, replay", async () => {
  const { w, g, brg, opClaims, bind, call } = await proofs();
  const p = await signCallProof(opClaims, w.bridgeKey);
  assert.ok(verifyCallProof(p, w.trust, bind).ok);
  assert.equal(code(verifyCallProof(p, w.trust, { ...bind, grantJti: ulid() })), "invalid_token");
  assert.equal(code(verifyCallProof(p, w.trust, { ...bind, op: "delete_all" })), "invalid_token");
  assert.equal(code(verifyCallProof(p, w.trust, { ...bind, inputDigest: digest({ q: "y" }) })), "invalid_token");
  assert.equal(code(verifyCallProof(p, w.trust, { ...bind, grantSub: `tb:ins:${w.other}` })), "invalid_token");
  assert.equal(code(verifyCallProof(p, { ...w.trust, self: `tb:ins:${w.other}` }, bind)), "invalid_token");
  assert.equal(code(verifyCallProof(p, { ...w.trust, now: NOW + 60 + LEEWAY_S }, bind)), "invalid_token");
  // signed by Portal (not a slice bridge key)
  assert.equal(code(verifyCallProof(await signCallProof(opClaims, w.portal), w.trust, bind)), "invalid_token");
  // grant presented as call proof and call proof as grant
  assert.equal(code(verifyCallProof(g, w.trust, bind)), "invalid_token");
  assert.equal(code(verifyGrant(p, w.trust)), "grant_invalid");
  // hook proof presented on an op route
  const h = await signHookProof({ iss: brg, sub: `tb:agt:${w.agt}`, aud: `tb:ins:${w.ins}`, call, hook: "audit", phase: "before", ctx: bind.contextDigest, iat: NOW }, w.bridgeKey);
  assert.equal(code(verifyCallProof(h, w.trust, bind)), "invalid_token");
  // two variants at once
  const both = await rawSign({ alg: "EdDSA", typ: TYP.callProof, kid: w.bridgeKey.kid }, { ...opClaims, hook: "x", exp: NOW + 60, jti: ulid() }, w.bridgeKey);
  assert.equal(code(verifyCallProof(both, w.trust, bind)), "invalid_token");
  // lifetime > 60 s
  await assert.rejects(signCallProof({ ...opClaims, exp: NOW + 61 }, w.bridgeKey), /lifetime/);
  // replay
  const replay = memoryReplayGuard();
  assert.ok(verifyCallProof(p, w.trust, bind, replay).ok);
  assert.equal(code(verifyCallProof(p, w.trust, bind, replay)), "invalid_token");
});

test("verifyHookProof: positive, phase / input binding, replay", async () => {
  const { w, brg, call, bind } = await proofs();
  const claims = { iss: brg, sub: `tb:agt:${w.agt}` as const, aud: `tb:ins:${w.ins}` as const, call, hook: "audit", phase: "before" as const, ctx: bind.contextDigest, iat: NOW };
  const h = await signHookProof(claims, w.bridgeKey);
  const hb = { hook: "audit", phase: "before" as const, contextDigest: bind.contextDigest };
  assert.ok(verifyHookProof(h, w.trust, hb).ok);
  assert.equal(code(verifyHookProof(h, w.trust, { ...hb, phase: "after" })), "invalid_token");
  assert.equal(code(verifyHookProof(h, w.trust, { ...hb, hook: "other" })), "invalid_token");
  assert.equal(code(verifyHookProof(h, w.trust, { ...hb, inputDigest: bind.inputDigest })), "invalid_token");
  const hi = await signHookProof({ ...claims, in: bind.inputDigest }, w.bridgeKey);
  assert.ok(verifyHookProof(hi, w.trust, { ...hb, inputDigest: bind.inputDigest }).ok);
  assert.equal(code(verifyHookProof(hi, w.trust, hb)), "invalid_token");
  const op = await signCallProof({ iss: brg, sub: `tb:agt:${w.agt}`, aud: `tb:ins:${w.ins}`, call, gjti: ulid(), op: "x", in: bind.inputDigest, ctx: bind.contextDigest, iat: NOW }, w.bridgeKey);
  assert.equal(code(verifyHookProof(op, w.trust, hb)), "invalid_token");
  const replay = memoryReplayGuard();
  assert.ok(verifyHookProof(h, w.trust, hb, replay).ok);
  assert.equal(code(verifyHookProof(h, w.trust, hb, replay)), "invalid_token");
});

test("verifyHookProof (manifest 0.1.28, C268 B): bd binds the whole body (fires on bad)", { timeout: 60_000 }, async () => {
  const { w, brg, call, bind } = await proofs();
  const claims = { iss: brg, sub: `tb:agt:${w.agt}` as const, aud: `tb:ins:${w.ins}` as const, call, hook: "audit", phase: "before" as const, ctx: bind.contextDigest, iat: NOW };
  const hb = { hook: "audit", phase: "before" as const, contextDigest: bind.contextDigest };
  const body = new TextEncoder().encode('{"call":{"id":"x"},"ctx":{},"in":{}}');
  const bd = sha256Bytes(body);
  const withBd = await signHookProof({ ...claims, bd }, w.bridgeKey);
  // match: ok, also together with `in`, `sub` and `call`
  assert.ok(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: bd }).ok);
  const full = await signHookProof({ ...claims, in: bind.inputDigest, bd }, w.bridgeKey);
  assert.ok(verifyHookProof(full, w.trust, { ...hb, inputDigest: bind.inputDigest, sub: `tb:agt:${w.agt}`, call, bodyDigest: bd }).ok);
  // mismatch (one byte changed), a digest of nothing, and a proof with bd but no bound digest: refused (fail closed)
  const other = sha256Bytes(new TextEncoder().encode('{"call":{"id":"y"},"ctx":{},"in":{}}'));
  assert.equal(code(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: other })), "invalid_token");
  assert.equal(code(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: "" as never })), "invalid_token");
  assert.equal(code(verifyHookProof(withBd, w.trust, hb)), "invalid_token");
  // absent bd: not compared, whatever the caller hashed (a later slice flag makes it required)
  const plain = await signHookProof(claims, w.bridgeKey);
  assert.ok(verifyHookProof(plain, w.trust, hb).ok);
  assert.ok(verifyHookProof(plain, w.trust, { ...hb, bodyDigest: other }).ok);
  // a refused bd does not use up the one-time proof
  const replay = memoryReplayGuard();
  assert.equal(code(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: other }, replay)), "invalid_token");
  assert.ok(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: bd }, replay).ok);
  assert.equal(code(verifyHookProof(withBd, w.trust, { ...hb, bodyDigest: bd }, replay)), "invalid_token");
  // malformed bd is refused by the claim shape, at signing and when a forged token carries it
  for (const bad of ["", "sha256:abc", `sha256:${"A".repeat(64)}`, `sha1:${"a".repeat(40)}`, 7, null, [bd]]) {
    await assert.rejects(signHookProof({ ...claims, bd: bad } as never, w.bridgeKey), /claim bd/, JSON.stringify(bad));
    const forged = await rawSign({ alg: "EdDSA", typ: TYP.callProof, kid: w.bridgeKey.kid }, { ...claims, bd: bad, exp: NOW + 60, jti: ulid() }, w.bridgeKey);
    assert.equal(code(verifyHookProof(forged, w.trust, { ...hb, bodyDigest: bd })), "invalid_token", JSON.stringify(bad));
  }
});

test("call proofs (manifest 0.1.28, C268 B): bd is refused on an op proof and on a bridge-op proof (shape)", { timeout: 60_000 }, async () => {
  const { w, brg, call, opClaims, bind } = await proofs();
  const bd = sha256Bytes(new TextEncoder().encode("{}"));
  await assert.rejects(signCallProof({ ...opClaims, bd } as never, w.bridgeKey), /op proof shape/);
  await assert.rejects(signBridgeOpProof({ iss: brg, sub: brg, aud: `tb:ins:${w.ins}`, call, bop: "scope_summary", iat: NOW, bd } as never, w.bridgeKey), /bridge-op proof shape/);
  // a forged (rawly signed) token with bd on those variants is refused by the verifiers too
  const op = await rawSign({ alg: "EdDSA", typ: TYP.callProof, kid: w.bridgeKey.kid }, { ...opClaims, bd, exp: NOW + 60, jti: ulid() }, w.bridgeKey);
  assert.equal(code(verifyCallProof(op, w.trust, bind)), "invalid_token");
  const bop = await rawSign({ alg: "EdDSA", typ: TYP.callProof, kid: w.bridgeKey.kid }, { iss: brg, sub: brg, aud: `tb:ins:${w.ins}`, call, bop: "scope_summary", bd, iat: NOW, exp: NOW + 60, jti: ulid() }, w.bridgeKey);
  assert.equal(code(verifyBridgeOpProof(bop, w.trust, { bop: "scope_summary" })), "invalid_token");
});

test("verifyHookProof (manifest 0.1.27, C268 A): sub and call are compared when given, never replay-burning on a mismatch (fires on bad)", async () => {
  const { w, brg, call, bind } = await proofs();
  const claims = { iss: brg, sub: `tb:agt:${w.agt}` as const, aud: `tb:ins:${w.ins}` as const, call, hook: "audit", phase: "before" as const, ctx: bind.contextDigest, iat: NOW };
  const hb = { hook: "audit", phase: "before" as const, contextDigest: bind.contextDigest };
  const h = await signHookProof(claims, w.bridgeKey);
  // matching sub + call: ok (and the proof still verifies with neither, as before 0.1.27)
  assert.ok(verifyHookProof(h, w.trust, { ...hb, sub: `tb:agt:${w.agt}`, call }).ok);
  assert.ok(verifyHookProof(await signHookProof(claims, w.bridgeKey), w.trust, hb).ok, "callers that pass neither behave as before");
  // fires on bad: a body that names another caller (an agent, an app instance) or another call than the proof was signed for
  for (const sub of [`tb:agt:${w.other}`, `tb:ins:${w.agt}`, `tb:ins:${w.ins}`, "", `tb:agt:${w.agt}x`]) {
    assert.equal(code(verifyHookProof(await signHookProof(claims, w.bridgeKey), w.trust, { ...hb, sub })), "invalid_token", `sub ${sub}`);
  }
  assert.equal(code(verifyHookProof(await signHookProof(claims, w.bridgeKey), w.trust, { ...hb, call: `call_${ulid()}` as CallId })), "invalid_token");
  assert.equal(code(verifyHookProof(await signHookProof(claims, w.bridgeKey), w.trust, { ...hb, call: "" })), "invalid_token");
  assert.equal(code(verifyHookProof(await signHookProof(claims, w.bridgeKey), w.trust, { ...hb, sub: 7 as never })), "invalid_token");
  // a mismatch does not use up the one-time proof: the right body still verifies once, and only once
  const replay = memoryReplayGuard();
  assert.equal(code(verifyHookProof(h, w.trust, { ...hb, sub: `tb:agt:${w.other}` }, replay)), "invalid_token");
  assert.ok(verifyHookProof(h, w.trust, { ...hb, sub: `tb:agt:${w.agt}`, call }, replay).ok);
  assert.equal(code(verifyHookProof(h, w.trust, { ...hb, sub: `tb:agt:${w.agt}`, call }, replay)), "invalid_token");
});

test("hookCallerRef: agent -> tb:agt:, app -> tb:ins:, everything else never matches a proof", () => {
  assert.equal(hookCallerRef({ type: "agent", id: "agt_1", mode: "free" }), "tb:agt:agt_1");
  assert.equal(hookCallerRef({ type: "app", id: "ins_1", product: "x" }), "tb:ins:ins_1");
  for (const bad of [undefined, null, [], "agent", {}, { type: "agent" }, { type: "agent", id: "" }, { type: "agent", id: 3 }, { type: "person", id: "per_1" }, { type: "system", id: "ins_1" }]) {
    assert.equal(hookCallerRef(bad), "", JSON.stringify(bad));
  }
});

test("verifyBridgeOpProof: positive, bop / op / in binding, iss = sub", async () => {
  const { w, brg, call } = await proofs();
  const body = { op: "tools", tool: "send" };
  const b = await signBridgeOpProof({ iss: brg, sub: brg, aud: `tb:ins:${w.ins}`, call, bop: "resolve", op: "tools", in: digest(body), iat: NOW }, w.bridgeKey);
  const bb = { bop: "resolve" as const, op: "tools", inputDigest: digest(body) };
  assert.ok(verifyBridgeOpProof(b, w.trust, bb).ok);
  assert.equal(code(verifyBridgeOpProof(b, w.trust, { ...bb, bop: "catalog" })), "invalid_token");
  assert.equal(code(verifyBridgeOpProof(b, w.trust, { ...bb, op: undefined })), "invalid_token");
  assert.equal(code(verifyBridgeOpProof(b, w.trust, { ...bb, inputDigest: digest({}) })), "invalid_token");
  await assert.rejects(signBridgeOpProof({ iss: brg, sub: `tb:agt:${w.agt}` as never, aud: `tb:ins:${w.ins}`, call, bop: "mark", iat: NOW }, w.bridgeKey));
  const foreign = await signBridgeOpProof({ iss: `tb:brg:brg_${ulid()}`, sub: `tb:brg:brg_${ulid()}` as never, aud: `tb:ins:${w.ins}`, call, bop: "mark", iat: NOW }, w.bridgeKey).catch(() => "threw");
  assert.equal(foreign, "threw");
  const otherBridge = `tb:brg:brg_${ulid()}` as const;
  const ob = await signBridgeOpProof({ iss: otherBridge, sub: otherBridge, aud: `tb:ins:${w.ins}`, call, bop: "mark", iat: NOW }, w.bridgeKey);
  assert.equal(code(verifyBridgeOpProof(ob, w.trust, { bop: "mark" })), "invalid_token");
  const replay = memoryReplayGuard();
  assert.ok(verifyBridgeOpProof(b, w.trust, bb, replay).ok);
  assert.equal(code(verifyBridgeOpProof(b, w.trust, bb, replay)), "invalid_token");
});

test("verifyTicket / verifyKeysTicket: purpose, audience, lifetime, typ confusion", async () => {
  const w = await world();
  const launch = await signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, ws: w.ws, pur: "launch", path: "/inbox", iat: NOW }, w.portal);
  const r = verifyTicket(launch, w.trust);
  assert.equal(r.ok && r.claims.path, "/inbox");
  assert.equal(code(verifyTicket(launch, { ...w.trust, ws: `ws_${ulid()}` })), "invalid_token");
  assert.equal(code(verifyTicket(launch, { ...w.trust, self: `tb:ins:${w.other}` })), "invalid_token");
  assert.equal(code(verifyTicket(launch, { ...w.trust, now: NOW + 60 + LEEWAY_S })), "invalid_token");
  const keysCtx = { now: NOW, self: `tb:brg:${w.brg}` as const, ws: w.ws, issuers: w.trust.issuers };
  const keys = await signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:brg:${w.brg}`, ws: w.ws, pur: "keys", req: ["OPENAI"], iat: NOW, exp: NOW + 120 }, w.portal);
  assert.ok(verifyKeysTicket(keys, keysCtx).ok);
  assert.equal(code(verifyKeysTicket(launch, keysCtx)), "invalid_token");
  assert.equal(code(verifyTicket(keys, w.trust)), "invalid_token");
  // a keys-ticket claim set aimed at an instance is refused at signing
  await assert.rejects(signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}` as never, ws: w.ws, pur: "keys", iat: NOW }, w.portal));
  await assert.rejects(signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, ws: w.ws, pur: "launch", iat: NOW, exp: NOW + 61 }, w.portal), /lifetime/);
  await assert.rejects(signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, ws: w.ws, pur: "launch", path: "//evil.example", iat: NOW }, w.portal));
  // typ confusion: grant presented as ticket
  assert.equal(code(verifyTicket(await signGrant(w.grantClaims(), w.portal), w.trust)), "invalid_token");
  // person ticket never verifies as an agent session (R-P1)
  assert.equal(code(verifyAgentSession(launch, { now: NOW, self: `tb:brg:${w.brg}`, ws: w.ws, keys: w.trust.issuers })), "invalid_token");
});

test("v0.1.31 K11 `roles` claim (spec 0.1.63): accepted on a keys ticket within its limits; refused otherwise", async () => {
  const w = await world();
  const keysCtx = { now: NOW, self: `tb:brg:${w.brg}` as const, ws: w.ws, issuers: w.trust.issuers };
  const base = { iss: "tb:portal" as const, sub: `tb:per:${w.per}` as const, aud: `tb:brg:${w.brg}` as const, ws: w.ws, pur: "keys" as const, iat: NOW, exp: NOW + 120 };
  const roles = [
    { role: "reasoning" as const, provider: "openai", model: "gpt-5.1", dataPolicy: "zdr" as const },
    { role: "embeddings" as const, provider: "ollama", model: "nomic-embed-text:latest" },
    { role: "rerank" as const },
  ];
  const ok = await signTicket({ ...base, roles }, w.portal);
  const r = verifyKeysTicket(ok, keysCtx);
  assert.ok(r.ok);
  assert.deepEqual(r.ok && r.claims.roles, roles);
  assert.ok(verifyKeysTicket(await signTicket({ ...base, roles: [] }, w.portal), keysCtx).ok);
  assert.ok(verifyKeysTicket(await signTicket({ ...base, roles: Array.from({ length: 8 }, () => ({ role: "utility" as const })) }, w.portal), keysCtx).ok, "8 items is the limit");

  // refused: the signer refuses the claim set, and the verifier refuses the same token signed raw
  const hdr = { alg: "EdDSA", typ: TYP.personTicket, kid: w.portal.kid };
  const jti = ulid();
  const bad: [string, unknown, string?][] = [
    ["9 items", Array.from({ length: 9 }, () => ({ role: "utility" })), undefined],
    ["an unknown role", [{ role: "chat" }], undefined],
    ["an extra key", [{ role: "reasoning", apiKey: "x" }], undefined],
    ["a provider that is no id", [{ role: "reasoning", provider: "Open AI" }], undefined],
    ["a model with // or a space", [{ role: "reasoning", model: "https://x" }], undefined],
    ["a model with a space", [{ role: "reasoning", model: "two words" }], undefined],
    ["an unknown dataPolicy", [{ role: "reasoning", dataPolicy: "strict" }], undefined],
    ["a non-array", { role: "reasoning" }, undefined],
    ["an item that is no object", ["reasoning"], undefined],
  ];
  for (const [name, value] of bad) {
    await assert.rejects(signTicket({ ...base, roles: value as never }, w.portal), name);
    assert.equal(code(verifyKeysTicket(await rawSign(hdr, { ...base, jti, roles: value }, w.portal), keysCtx)), "invalid_token", name);
  }
  // `roles` on a launch ticket, and on a keys ticket aimed at an instance
  const launch = { iss: "tb:portal" as const, sub: base.sub, aud: `tb:ins:${w.ins}` as const, ws: w.ws, pur: "launch" as const, iat: NOW };
  await assert.rejects(signTicket({ ...launch, roles: [{ role: "reasoning" }] } as never, w.portal));
  assert.equal(code(verifyTicket(await rawSign(hdr, { ...launch, jti, exp: NOW + 60, roles: [{ role: "reasoning" }] }, w.portal), w.trust)), "invalid_token");
  assert.ok(verifyTicket(await signTicket(launch, w.portal), w.trust).ok, "a launch ticket without roles still verifies");
  // without `roles` a keys ticket is unchanged (older Core)
  assert.ok(verifyKeysTicket(await signTicket(base, w.portal), keysCtx).ok);
});

function sliceBody(w: Awaited<ReturnType<typeof world>>, over: Record<string, unknown> = {}): Issue<InstanceSlice> {
  return {
    iss: "tb:portal",
    sub: `tb:ins:${w.ins}`,
    aud: `tb:ins:${w.ins}`,
    ws: w.ws,
    v: 1,
    rev: 7,
    iat: NOW - 5,
    ins: w.ins,
    product: "notes",
    portalKeys: [{ jwk: w.portal.publicJwk, status: "active" }],
    bridge: { id: w.brg, keys: [w.bridgeKey.publicJwk] },
    pause: { workspace: false, agents: [], instances: [] },
    revoked: { jtis: [] },
    personNbf: 0,
    grants: [],
    agents: [],
    ...over,
  } as Issue<InstanceSlice>;
}

test("verifySlice: positive and refusals", async () => {
  const w = await world();
  const ctx = { now: NOW, self: w.trust.self, ws: w.ws, bridge: w.brg, issuers: w.trust.issuers };
  const s = await signSlice(sliceBody(w), w.portal);
  const r = verifySlice(s, ctx);
  assert.equal(r.ok && r.slice.rev, 7);
  assert.equal(code(verifySlice(s, { ...ctx, now: NOW + 43200 + LEEWAY_S })), "invalid_token");
  assert.equal(code(verifySlice(s, { ...ctx, self: `tb:ins:${w.other}` })), "invalid_token");
  assert.equal(code(verifySlice(await signSlice(sliceBody(w, { bridge: { id: `brg_${ulid()}`, keys: [] } }), w.portal), ctx)), "invalid_token");
  assert.equal(code(verifySlice(await signSlice(sliceBody(w, { pause: { workspace: "no" } }), w.portal), ctx)), "invalid_token");
  assert.equal(code(verifySlice(await signSlice(sliceBody(w), w.stranger), ctx)), "invalid_token");
  assert.equal(code(verifySlice(await signGrant(w.grantClaims(), w.portal), ctx)), "invalid_token");
  await assert.rejects(signSlice(sliceBody(w, { exp: NOW - 5 + 43201 }), w.portal), /lifetime/);
});

test("verifyConfig: positive returns claims + body; refusals", async () => {
  const w = await world();
  const brg = `tb:brg:${w.brg}` as const;
  const body = {
    iss: "tb:portal",
    sub: brg,
    aud: brg,
    ws: w.ws,
    v: 1,
    rev: 3,
    iat: NOW,
    portalKeys: [],
    pause: { workspace: false, agents: [], instances: [] },
    revoked: { jtis: [] },
    connections: [],
    instanceKeys: [],
    grants: [],
    apps: [],
  } as unknown as Issue<WorkspaceConfig>;
  const c = await signConfig(body, w.portal);
  const ctx = { now: NOW, self: brg, issuers: w.trust.issuers };
  const r = verifyConfig(c, ctx);
  assert.ok(r.ok);
  assert.equal(r.ok && r.claims.rev, 3);
  assert.deepEqual(r.ok && (r.body as { apps: unknown[] }).apps, []);
  assert.equal(r.ok && "apps" in r.claims, false);
  assert.equal(code(verifyConfig(c, { ...ctx, self: `tb:brg:brg_${ulid()}` })), "invalid_token");
  assert.equal(code(verifyConfig(await signConfig({ ...body, iss: brg }, w.bridgeKey), { ...ctx, issuers: w.trust.bridgeKeys })), "invalid_token");
  assert.equal(code(verifyConfig(await signConfig({ ...body, connections: "x" } as never, w.portal), ctx)), "invalid_token");
  assert.equal(code(verifyConfig(await signSlice(sliceBody(w), w.portal), ctx)), "invalid_token");
});

test("verifyPairingCode / verifyAgentSession", async () => {
  const w = await world();
  const brg = `tb:brg:${w.brg}` as const;
  const pc = await signPairingCode({ iss: "tb:portal", sub: `tb:agt:${w.agt}`, aud: brg, ws: w.ws, rid: "r1", iat: NOW }, w.portal);
  const replay = memoryReplayGuard();
  const ctx = { now: NOW, self: brg, ws: w.ws, issuers: w.trust.issuers, revokedJtis: new Set<string>(), replay };
  const r = verifyPairingCode(pc, ctx);
  assert.equal(r.ok && r.claims.rid, "r1");
  assert.equal(code(verifyPairingCode(pc, ctx)), "invalid_token");
  assert.equal(code(verifyPairingCode(pc, { ...ctx, replay: undefined, revokedJtis: new Set([payloadOf(pc).jti as string]) })), "invalid_token");
  assert.equal(code(verifyPairingCode(pc, { ...ctx, replay: undefined, ws: `ws_${ulid()}` })), "invalid_token");
  await assert.rejects(signPairingCode({ iss: "tb:portal", sub: `tb:agt:${w.agt}`, aud: brg, ws: w.ws, iat: NOW, exp: NOW + 601 }, w.portal), /lifetime/);

  const own = keySetFrom({ keys: [w.bridgeKey.publicJwk] }, brg);
  const s = await signAgentSession({ iss: brg, sub: `tb:agt:${w.agt}`, aud: brg, ws: w.ws, con: `con_${ulid()}` as ConnectionId, gen: 2, iat: NOW }, w.bridgeKey);
  const vs = verifyAgentSession(s, { now: NOW, self: brg, ws: w.ws, keys: own });
  assert.equal(vs.ok && vs.claims.gen, 2);
  assert.equal(vs.ok && vs.claims.exp - vs.claims.iat, 900);
  assert.equal(code(verifyAgentSession(s, { now: NOW, self: brg, ws: `ws_${ulid()}`, keys: own })), "invalid_token");
  assert.equal(code(verifyAgentSession(s, { now: NOW + 900 + LEEWAY_S, self: brg, ws: w.ws, keys: own })), "invalid_token");
  // a grant or pairing code is never an agent session
  assert.equal(code(verifyAgentSession(pc, { now: NOW, self: brg, ws: w.ws, keys: w.trust.issuers })), "invalid_token");
  await assert.rejects(signJws(TYP.agentSession, { iss: brg, sub: `tb:agt:${w.agt}`, aud: `tb:brg:brg_${ulid()}`, ws: w.ws, con: `con_${ulid()}`, gen: 1, iat: NOW, exp: NOW + 60, jti: ulid() }, w.bridgeKey));
});

test("verifyCallProof v0.1.13 (G1): `hv` is part of the signed op proof; malformed hv refused; hook proofs never carry it", async () => {
  const { w, brg, opClaims, bind, call } = await proofs();
  const hv = { f: "policy" as const, r: "needs owner review", by: "rules/rules_gate" };
  const p = await signCallProof({ ...opClaims, hv }, w.bridgeKey);
  const r = verifyCallProof(p, w.trust, bind);
  assert.ok(r.ok);
  assert.deepEqual(r.ok && r.claims.hv, hv);
  for (const bad of [
    { ...hv, f: "caps" },
    { ...hv, r: "" },
    { ...hv, r: "x".repeat(281) },
    { ...hv, by: "rules" },
    { ...hv, by: "Rules/x" },
    { ...hv, by: "rules/tb_x" },
    { ...hv, extra: 1 },
  ]) {
    // the closed claim set is enforced when signing too (the same check as verifier step 5)
    await assert.rejects(signCallProof({ ...opClaims, hv: bad as typeof hv }, w.bridgeKey), /claim hv/, JSON.stringify(bad).slice(0, 60));
  }
  // `hv` belongs only to the op variant
  await assert.rejects(signHookProof({ iss: brg, sub: `tb:agt:${w.agt}`, aud: `tb:ins:${w.ins}`, call, hook: "audit", phase: "before", ctx: bind.contextDigest, iat: NOW, hv } as never, w.bridgeKey), /hook proof shape/);
  // an edited hv breaks the signature
  const [h64, p64, s64] = p.split(".");
  const payload = JSON.parse(Buffer.from(p64 as string, "base64url").toString());
  payload.hv = { ...hv, f: "money" };
  const forged = `${h64}.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.${s64}`;
  assert.equal(code(verifyCallProof(forged, w.trust, bind)), "invalid_token");
});

test("bridgeOpBinding (C91): catalog {bop, op} only; resolve {op, in}; mark {in}; scope_summary {}; sign == verify", async () => {
  const { w, call, brg } = await proofs();
  const cat = { op: "tools", query: "gmail list", limit: 5 };
  assert.deepEqual(bridgeOpBinding("catalog", cat), { bop: "catalog", op: "tools" });
  assert.deepEqual(bridgeOpBinding("resolve", { op: "tools", tool: "gmail_list" }), { bop: "resolve", op: "tools", inputDigest: digest({ op: "tools", tool: "gmail_list" }) });
  assert.deepEqual(bridgeOpBinding("mark", { call, mark: "after_failed" }), { bop: "mark", inputDigest: digest({ call, mark: "after_failed" }) });
  assert.deepEqual(bridgeOpBinding("scope_summary", {}), { bop: "scope_summary" });
  for (const [bop, body] of [["catalog", cat], ["resolve", { op: "tools", tool: "x" }], ["mark", { call, mark: "after_failed" }], ["scope_summary", {}]] as const) {
    const t = await signBridgeOpProof({ iss: brg, sub: brg, aud: `tb:ins:${w.ins}`, call: `call_${ulid()}` as CallId, ...bridgeOpProofClaims(bop, body), iat: NOW }, w.bridgeKey);
    assert.ok(verifyBridgeOpProof(t, w.trust, bridgeOpBinding(bop, body)).ok, bop);
  }
  // the live QA S1 bug: a catalog proof that binds `in` is refused by the rule
  const withIn = await signBridgeOpProof({ iss: brg, sub: brg, aud: `tb:ins:${w.ins}`, call, bop: "catalog", op: "tools", in: digest(cat), iat: NOW }, w.bridgeKey);
  assert.equal(code(verifyBridgeOpProof(withIn, w.trust, bridgeOpBinding("catalog", cat))), "invalid_token");
});

test("verifyGrant (C108, tolerant reader): unknown held families are ignored, known ones still hold; malformed held refused", async () => {
  const w = await world();
  const g = await signGrant(w.grantClaims({ held: ["destructive", "future_x"] as never }), w.portal);
  const r = verifyGrant(g, w.trust);
  assert.ok(r.ok);
  assert.deepEqual(r.ok && r.claims.held, ["destructive"]);
  const { authorize } = await import("../src/decision.ts");
  const op = { id: "item_delete", crud: ["read"] as "read"[], effect: "destructive" as const, holdFamily: "destructive" as const };
  const d = authorize({ paused: { workspace: false, instance: false, agent: false }, grant: g, trust: w.trust, op, access: null, usage: {}, approval: "none", holdVerdict: null });
  assert.equal(d.decision, "hold");
  assert.equal(d.holdFamily, "destructive");
  // shape is still checked: not a token-like string, duplicates
  await assert.rejects(signGrant(w.grantClaims({ held: ["Destructive!"] as never }), w.portal));
  await assert.rejects(signGrant(w.grantClaims({ held: ["money", "money"] as never }), w.portal));
});

test("verifyGrant (manifest 0.1.23, GRANT-PRD): a companion grant may carry prd (a product id); the claim is shape-checked and read back", async () => {
  const w = await world();
  const claims = w.grantClaims({}) as unknown as Record<string, unknown>;
  const withPrd = await signGrant({ ...claims, prd: "observer" } as never, w.portal);
  const r = verifyGrant(withPrd, w.trust);
  assert.ok(r.ok);
  assert.equal(r.ok && (r.claims as { prd?: string }).prd, "observer");
  // a grant without prd (older Core) still verifies; a malformed prd is refused at signing and at verification
  assert.ok(verifyGrant(await signGrant(claims as never, w.portal), w.trust).ok);
  for (const bad of ["", "Observer", "a", 7, null, "x".repeat(40)]) await assert.rejects(signGrant({ ...claims, prd: bad } as never, w.portal), `prd ${JSON.stringify(bad)}`);
});

test("verifyGrant (manifest 0.1.23, GRANT-PRD): a hand-signed grant with a malformed prd or any other unknown claim is refused; a valid prd verifies", async () => {
  const w = await world();
  const { rawSign, payloadOf } = await import("./fixtures.ts");
  const base = await signGrant(w.grantClaims({}), w.portal);
  const header = JSON.parse(Buffer.from(base.split(".")[0] as string, "base64url").toString("utf8")) as unknown;
  const claims = payloadOf(base);
  const check = async (extra: Record<string, unknown>) => verifyGrant(await rawSign(header, { ...claims, ...extra }, w.portal), w.trust);
  assert.ok((await check({ prd: "observer" })).ok, "valid prd");
  for (const bad of [7, "", null, "Observer", "a", "x".repeat(40)]) assert.equal(code(await check({ prd: bad })), "grant_invalid", `prd ${JSON.stringify(bad)}`);
  assert.equal(code(await check({ zzz: "observer" })), "grant_invalid", "an unknown other claim is still refused");
  assert.equal(code(await check({ prd: "observer", zzz: 1 })), "grant_invalid");
});
