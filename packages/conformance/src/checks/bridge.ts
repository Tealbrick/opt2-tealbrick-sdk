// Bridge target checks, part 1 (CONFORMANCE §4.4 + bridge cells of §4.2): public / internal surface (B1),
// enrolment (B2), K5 issuance and person-credential refusals (C1–C5, cred.p1.*), MCP surface (B7, B17), call path
// and gate order (B8, B5, B13), hooks (B6), dynamic tools and limits (B16), companion calls, claims and status
// (B18, §5 version matrix). Part 2 (keys, OAuth, config, pause, Portal-down, re-enrolment, standalone, scans) is in
// bridge-flows.ts. Every check asserts an observed value; nothing passes by default.
import { activeKeyRequirements, DEFAULT_HELD_FAMILIES, digest, KNOWN_HOLD_FAMILIES, renderSkill, signAssertion, signInstanceAssertion, thumbprint, ulid, verifyAgentSession } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type ClaimResponse, type EnrolRequest, TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type InstanceId, LIFETIME_S, OAUTH_GRANT_TYPES, TYP } from "@opt2-tealbrick/spec/credentials";
import type { DynamicCatalogEntry, Operation, Skill } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { deployedSettings } from "../bridge-world.ts";
import type { FakeApp, Received } from "../fake-app.ts";
import { errorCode, type HttpAnswer, request } from "../http.ts";
import { rpcMessages, type ToolCallResult } from "../mcp-agent.ts";
import { bad, na, type Outcome, ok, verdict } from "../suite.ts";
import { Mint, newId, nowS, peek, rawSign } from "../tokens.ts";
import { type BridgeCtx, describeCall, httpRefused, isObj, sleep, toolRefused } from "./bridge-ctx.ts";

/**
 * The capability a bridge declares when it implements the C283 A1 owner-row filter: catalog `admitted`, scope_summary `admittedOps`,
 * and a gate() that skips `op.crud ⊆ grant.crud` for ops with a scopeType (spec 0.1.50). Conformance 0.1.27 (C292, C292a, spec 0.1.54)
 * decides the A1 rows by THIS cap in the bridge's StatusReport (`bridge.caps`), never by version: bridge 0.2.4 has no A1 (it ships in 0.2.5),
 * so the earlier "version >= 0.2.4" gate would have failed a real 0.2.4 bridge.
 */
const OWNER_ROWS_CAP = "owner_rows";

/** `StatusReport.bridge.caps` of the latest report the fake Portal received ([] = none declared, or no report yet). Strings only. */
export function reportedBridgeCaps(c: BridgeCtx): string[] {
  const caps: unknown = c.w.portal.acks.at(-1)?.bridge?.caps;
  return Array.isArray(caps) ? caps.filter((x): x is string => typeof x === "string") : [];
}

const NOT_PUBLIC_INTERNAL: [string, string][] = [
  ["POST", "/tb/v1/claim"],
  ["POST", "/tb/v1/status"],
  ["GET", "/tb/v1/keys/ANY_KEY"],
  ["POST", "/tb/v1/call"],
  ["GET", "/metrics"],
];
const UNAUTH = ["unauthenticated", "invalid_token"];

/** Dynamic catalog the generated peer app answers (one entry inside its ceilings, one outside). */
export function peerCatalog(): DynamicCatalogEntry[] {
  const schema = { type: "object", properties: { q: { type: "string" } } } as DynamicCatalogEntry["inputSchema"];
  return [
    { name: "entry_ok", title: "Generated entry", description: "Generated dynamic entry inside the ceilings.", inputSchema: schema, crud: ["read"], effect: "read" },
    { name: "entry_over", title: "Generated entry", description: "Generated dynamic entry outside the ceilings.", inputSchema: schema, crud: ["delete"], effect: "destructive" },
  ];
}

const hdrs = (r: Received) => Object.keys(r.headers).map((k) => k.toLowerCase());

// ── B1 surface ───────────────────────────────────────────────────────────────
export async function surfaceChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("surface")) return;
  await c.run("B1.health", "/healthz and /readyz answer with {status} only", "200 with a body whose only key is status (no details)", async () => {
    const h = await c.get("/healthz");
    const r = await c.get("/readyz");
    const keys = (a: HttpAnswer) => (isObj(a.body) ? Object.keys(a.body).sort().join(",") : typeof a.body);
    return verdict(h.status === 200 && r.status === 200 && keys(h) === "status" && keys(r) === "status", `healthz ${h.status} {${keys(h)}}, readyz ${r.status} {${keys(r)}}`);
  });
  await c.run("B1.mcp_requires_auth", "MCP without a bearer → 401", "POST /mcp without Authorization → 401", async () => {
    const a = await c.post("/mcp", JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }), { "content-type": "application/json", accept: "application/json, text/event-stream" });
    return verdict(a.status === 401, `${a.status}`);
  });
  await c.run("B1.unknown_404", "any undocumented public path → 404", "404 for unknown paths, Portal-looking paths, admin (not standalone), undeclared /p routes, unknown products", async () => {
    const probes: [string, string][] = [
      ["GET", "/"],
      ["GET", "/conformance-unknown"],
      ["GET", "/api/v1/workspaces"],
      ["POST", "/admin/v1/pause"],
      ["GET", `/p/${c.primary.product}/conformance-undeclared`],
      ["GET", "/a/conformance-unknown-product/"],
      ["GET", "/oauth/conformance-unknown"],
    ];
    const seen: string[] = [];
    for (const [m, p] of probes) {
      const a = m === "GET" ? await c.get(p) : await c.post(p, "{}", { "content-type": "application/json" });
      seen.push(`${m} ${p} ${a.status}`);
    }
    return verdict(seen.every((x) => x.endsWith(" 404")), seen.join("; "));
  });
  await c.run("B1.internal_not_public", "internal surface not mounted on the public listener", "claim, status, keys, call, metrics → 404 on the public listener", async () => {
    const seen: string[] = [];
    for (const [m, p] of NOT_PUBLIC_INTERNAL) {
      const a = m === "GET" ? await c.get(p) : await c.post(p, "{}", { "content-type": "application/json" });
      seen.push(`${m} ${p} ${a.status}`);
    }
    return verdict(seen.every((x) => x.endsWith(" 404")), seen.join("; "));
  });
  await c.run("B1.public_not_internal", "public surface not mounted on the internal listener", "/mcp, /oauth/token, /keys, OAuth metadata, /a/<product>/ → 404 on the internal listener", async () => {
    if (!c.int) return bad("no internal listener URL");
    const probes: [string, string][] = [
      ["POST", "/mcp"],
      ["POST", "/oauth/token"],
      ["GET", "/keys"],
      ["GET", "/.well-known/oauth-authorization-server"],
      ["GET", `/a/${c.primary.product}/`],
    ];
    const seen: string[] = [];
    for (const [m, p] of probes) {
      const a = m === "GET" ? await c.get(p, {}, c.int) : await c.post(p, "{}", { "content-type": "application/json" }, c.int);
      seen.push(`${m} ${p} ${a.status}`);
    }
    return verdict(seen.every((x) => x.endsWith(" 404")), seen.join("; "));
  });
  const route = c.primary.manifest.publicRoutes?.[0];
  await c.run("B1.declared_public_route", "declared /p/<product>/<path> proxied with TB-* headers stripped", "declared route reaches the app at the full path without TB-* headers; wrong method → 404/405", async () => {
    if (!route) return bad("example manifest declares no public route");
    const path = `/p/${c.primary.product}${route.path}`;
    const method = route.purpose === "webhook" ? "POST" : "GET";
    const seq = c.w.seqNow();
    const a = method === "POST" ? await c.post(path, "{}", { "content-type": "application/json", [BRIDGE_HEADERS.assertion]: "conformance-strip-me" }) : await c.get(path, { [BRIDGE_HEADERS.assertion]: "conformance-strip-me" });
    const got = c.since(c.primary, seq, "public")[0];
    const wrong = method === "POST" ? await c.get(path) : await c.post(path, "{}");
    if (a.status !== 200 || !got) return bad(`${method} ${path} → ${a.status}; app saw ${got ? got.path : "nothing"}`);
    const tb = hdrs(got).filter((h) => h.startsWith("tb-"));
    return verdict(got.path.startsWith(path) && tb.length === 0 && (wrong.status === 404 || wrong.status === 405), `app path ${got.path}; tb-* headers [${tb.join(",")}]; wrong method ${wrong.status}`);
  });
}

// ── B2 enrolment, C8 env ─────────────────────────────────────────────────────
export function enrolRequests(c: BridgeCtx): EnrolRequest[] {
  return c.w.portal.captured
    .filter((r) => r.method === "POST" && r.path.split("?")[0] === "/api/v1/bridge/enrol")
    .map((r) => {
      try {
        return JSON.parse(r.body) as EnrolRequest;
      } catch {
        return {} as EnrolRequest;
      }
    });
}

export async function enrolChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("enrol")) return;
  await c.run("B2.enrol", "enrolment with the one-time code and an own Ed25519 public key", "one EnrolRequest {code = TB_ENROL_CODE, publicKey public JWK (no d), form, sdkMajors ∋ 1, publicOrigin = TB_PUBLIC_URL}", () => {
    const reqs = enrolRequests(c);
    const e = reqs[0];
    if (reqs.length !== 1 || !e) return bad(`${reqs.length} enrol requests`);
    const jwk = e.publicKey as unknown as Record<string, unknown>;
    const fine =
      e.code === c.h.env.TB_ENROL_CODE &&
      jwk?.kty === "OKP" &&
      jwk?.crv === "Ed25519" &&
      typeof jwk?.x === "string" &&
      !("d" in jwk) &&
      ["deployed", "own_infra"].includes(e.form) &&
      Array.isArray(e.sdkMajors) &&
      e.sdkMajors.includes(1) &&
      e.publicOrigin === c.h.env.TB_PUBLIC_URL;
    return verdict(fine, `code ${e.code === c.h.env.TB_ENROL_CODE ? "=" : "≠"} env; jwk ${String(jwk?.kty)}/${String(jwk?.crv)}${jwk && "d" in jwk ? " WITH d" : ""}; form ${e.form}; sdkMajors [${e.sdkMajors}]; publicOrigin ${e.publicOrigin}`);
  });
  await c.run("B2.own_key", "the enrolled key signs the bridge's assertions and tokens", "acks verified with the enrolled key (fake Portal) and K5 verified with it", async () => {
    const jwk = c.w.bridgeJwk();
    const e = enrolRequests(c)[0];
    if (!jwk || !e?.publicKey) return bad("not enrolled");
    const t = await c.w.keyAgents.free.token();
    if (t) c.accessTokens.add(t);
    const k5 = t ? verifyAgentSession(t, { now: nowS(), self: c.brg as `tb:brg:brg_${string}`, ws: c.w.ws, keys: c.bridgeKeys() }) : null;
    return verdict(c.w.portal.acks.length > 0 && thumbprint(jwk) === thumbprint(e.publicKey) && !!k5?.ok, `acks ${c.w.portal.acks.length}; K5 ${k5?.ok ? "verifies with the enrolled key" : "does not verify"}`);
  });
  await c.run("C8.env", "bridge runs with no secret env but its enrolment code and TB_KEK", "the bridge enrolled and served with env secrets limited to TB_ENROL_CODE and TB_KEK", () => {
    const names = Object.keys(c.h.env).sort();
    const allowed = new Set(["TB_PORTAL_URL", "TB_ENROL_CODE", "TB_KEK", "TB_PUBLIC_URL", "TB_KEYS_PUBLIC_URL", "TB_DATA_DIR", "PORT", "TB_INTERNAL_PORT", "TB_LOG_LEVEL", "TB_OWN_INFRA_ORIGINS", "TBCONF_PORTAL_ROOT_KEYS"]);
    const extra = names.filter((n) => !allowed.has(n));
    return verdict(extra.length === 0 && c.w.portal.acks.length > 0, `env names: ${names.join(", ")}${extra.length ? `; unexpected ${extra.join(",")}` : ""}`);
  });
}

// ── K5 issuance, C2/C3/C5 at /oauth/token and /mcp, C4 person credentials ──
async function tokenWith(c: BridgeCtx, assertion: string): Promise<HttpAnswer> {
  return c.w.keyAgents.free.tokenAnswer(assertion);
}
const noToken = (a: HttpAnswer): Outcome => {
  const b = isObj(a.body) ? a.body : {};
  return verdict(a.status >= 400 && a.status < 500 && typeof b.access_token !== "string", `${a.status} ${typeof b.error === "string" ? b.error : (errorCode(a.body) ?? "")}`);
};
const mcpRefused = (a: HttpAnswer): Outcome => {
  const code = errorCode(a.body);
  return verdict(a.status === 401 && (code === null || UNAUTH.includes(code)), `${a.status}${code ? ` ${code}` : ""}`);
};

export async function authChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("auth")) return;
  const free = c.w.keyAgents.free;
  const brgFor = c.brg as `tb:brg:brg_${string}`;
  await c.run("C1.K5", "K4 agent assertion → K5 access token (jwt-bearer)", "200 access_token typ tb-agent-session+jwt by the bridge key, sub = agent, con, gen, ≤ 900 s, no refresh token", async () => {
    const a = await free.tokenAnswer();
    const b = isObj(a.body) ? a.body : {};
    const t = typeof b.access_token === "string" ? b.access_token : "";
    if (a.status !== 200 || !t) return bad(`${a.status} ${JSON.stringify(a.body).slice(0, 120)}`);
    c.accessTokens.add(t);
    const v = verifyAgentSession(t, { now: nowS(), self: brgFor, ws: c.w.ws, keys: c.bridgeKeys() });
    if (!v.ok) return bad(`access token does not verify: ${v.reason}`);
    const life = v.claims.exp - v.claims.iat;
    const fine = v.claims.sub === `tb:agt:${free.agt}` && v.claims.con === free.con && v.claims.gen === 1 && life <= LIFETIME_S.agentAccess && !("refresh_token" in b);
    if (fine) c.evidence.set("K5", "jwt-bearer → K5");
    return verdict(fine, `sub ${v.claims.sub === `tb:agt:${free.agt}` ? "ok" : v.claims.sub}; con ${v.claims.con === free.con ? "ok" : "≠"}; gen ${v.claims.gen}; lifetime ${life}s; refresh ${"refresh_token" in b ? "present" : "absent"}`);
  });
  await c.run("C2.agent_assert_aud_foreign", "agent assertion for another bridge refused", "4xx, no access token", async () => noToken(await tokenWith(c, await free.assertion({ aud: `tb:brg:${newId("brg")}` }))));
  await c.run("C2.agent_assert_aud_array", "agent assertion with an array aud refused", "4xx, no access token", async () => {
    const ref = `tb:agt:${free.agt}`;
    const t = await rawSign({ alg: "EdDSA", typ: TYP.agentAssertion, kid: thumbprint(free.key.publicJwk) }, { iss: ref, sub: ref, aud: [c.brg], iat: nowS(), exp: nowS() + 60, jti: ulid(), con: free.con }, free.key);
    return noToken(await tokenWith(c, t));
  });
  await c.run("C3.ticket_as_assertion", "person ticket presented as an agent assertion refused", "4xx, no access token", async () => {
    const t = await c.w.launchTicket(c.primary);
    c.secrets.tickets.add(t);
    return noToken(await tokenWith(c, t));
  });
  await c.run("C3.grant_as_assertion", "grant presented as an agent assertion refused", "4xx, no access token", async () => {
    const g = c.w.grantFor("free", c.primary);
    return g ? noToken(await tokenWith(c, g)) : bad("no grant in config");
  });
  await c.run("C3.grant_as_session", "grant presented as K5 at /mcp refused", "401", async () => {
    const g = c.w.grantFor("free", c.primary);
    return g ? mcpRefused(await c.mcpWith(g)) : bad("no grant in config");
  });
  await c.run("C3.pairing_as_session", "pairing code presented as K5 at /mcp refused", "401", async () => {
    const p = await c.w.pairingCode("pairing");
    c.secrets.pairing.add(p);
    return mcpRefused(await c.mcpWith(p));
  });
  await c.run("C5.assert_unannounced_kid", "agent assertion signed by an unknown key refused", "4xx, no access token", async () => noToken(await tokenWith(c, await free.assertion({ key: c.w.stranger }))));
  await c.run("C5.assert_expired", "expired agent assertion refused", "4xx, no access token", async () => {
    const ref = `tb:agt:${free.agt}`;
    const iat = nowS() - 600;
    const t = await rawSign({ alg: "EdDSA", typ: TYP.agentAssertion, kid: thumbprint(free.key.publicJwk) }, { iss: ref, sub: ref, aud: c.brg, iat, exp: iat + 60, jti: ulid(), con: free.con }, free.key);
    return noToken(await tokenWith(c, t));
  });
  await c.run("C6.assert_replay", "agent assertion jti one-time", "first use 200, replay 4xx", async () => {
    const t = await free.assertion();
    const a = await tokenWith(c, t);
    const b = await tokenWith(c, t);
    if (isObj(a.body) && typeof a.body.access_token === "string") c.accessTokens.add(a.body.access_token);
    return verdict(a.status === 200 && b.status >= 400 && b.status < 500, `first ${a.status}, replay ${b.status}`);
  });
  await c.run("B12.connection_unknown", "assertion for a connection not in config → invalid_grant", "400 invalid_grant (connection_unknown)", async () => {
    const { generateKeyPair } = await import("@opt2-tealbrick/manifest");
    const k = await generateKeyPair();
    const t = await free.assertion({ con: newId("con"), key: k });
    const a = await tokenWith(c, t);
    return httpRefused(a, ["invalid_grant"]);
  });
  await c.run("B12.no_custom_grant", "no grant type beyond authorization_code, refresh_token and jwt-bearer", "device_code, password and a custom pairing grant → 400 unsupported_grant_type", async () => {
    const seen: string[] = [];
    for (const gt of [OAUTH_GRANT_TYPES.deviceCode, "password", "urn:tealbrick:params:oauth:grant-type:pairing", "client_credentials"]) {
      const a = await request(`${c.pub}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: gt, code: "x", device_code: "x" }).toString() });
      seen.push(`${gt.split(":").pop()} ${a.status} ${isObj(a.body) ? String(a.body.error ?? "") : ""}`);
    }
    return verdict(seen.every((x) => / 400 unsupported_grant_type$/.test(x)), seen.join("; "));
  });
  // C4 / R-P1: person credentials at agent paths
  await c.run("cred.p1.bridge_rejects_clerk_jwt", "Clerk-shaped person JWT refused at MCP, /oauth/token and internal routes", "/mcp 401; as jwt-bearer assertion 4xx; as TB-Assert at /tb/v1/keys 401", async () => {
    const clerk = Mint.clerkLikeJwt();
    const m = await c.mcpWith(clerk);
    const t = await tokenWith(c, clerk);
    const k = await c.get(`/tb/v1/keys/ANY_KEY`, { [BRIDGE_HEADERS.assertion]: clerk }, c.int);
    const pass = mcpRefused(m).pass === true && noToken(t).pass === true && k.status === 401;
    return verdict(pass, `/mcp ${m.status}; /oauth/token ${t.status}; /tb/v1/keys ${k.status}`);
  });
  await c.run("cred.p1.bridge_rejects_tbo", "owner CLI session (tbo_) refused at MCP and /oauth/token", "/mcp 401; as refresh_token 400 invalid_grant", async () => {
    const tbo = Mint.ownerCliLike();
    const m = await c.mcpWith(tbo);
    const r = await request(`${c.pub}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: OAUTH_GRANT_TYPES.refreshToken, refresh_token: tbo }).toString() });
    return verdict(mcpRefused(m).pass === true && httpRefused(r, ["invalid_grant"]).pass === true, `/mcp ${m.status}; refresh ${httpRefused(r).asserted}`);
  });
  await c.run("C4.owner_assert_at_mcp", "owner assertion refused at MCP", "401", async () => {
    const { generateKeyPair } = await import("@opt2-tealbrick/manifest");
    const k = await generateKeyPair();
    const per = `tb:per:${c.w.person}` as const;
    const a = await signAssertion(TYP.ownerAssertion, { iss: per, sub: per, aud: brgFor, iat: nowS() }, k, { method: "POST", pathAndQuery: "/mcp" });
    return mcpRefused(await c.mcpWith(a));
  });
  await c.run("C4.tickets_at_mcp", "launch and keys tickets refused at MCP", "401 for both", async () => {
    const l = await c.w.launchTicket(c.primary);
    const k = await c.w.keysTicket();
    c.secrets.tickets.add(l);
    c.secrets.tickets.add(k);
    const a = await c.mcpWith(l);
    const b = await c.mcpWith(k);
    return verdict(mcpRefused(a).pass === true && mcpRefused(b).pass === true, `launch ${a.status}; keys ${b.status}`);
  });
}

// ── B7 MCP surface, B17 skills ───────────────────────────────────────────────
interface ListedTool {
  name: string;
  inputSchema?: unknown;
  annotations?: Record<string, unknown>;
}
async function listTools(c: BridgeCtx, slot: Parameters<BridgeCtx["session"]>[0]): Promise<ListedTool[] | null> {
  const s = await c.session(slot);
  const { message } = await s.rpc("tools/list");
  const r = isObj(message?.result) ? message.result : null;
  return r && Array.isArray(r.tools) ? (r.tools as ListedTool[]) : null;
}
const diff = (have: Set<string>, want: Set<string>) => ({ missing: [...want].filter((x) => !have.has(x)), extra: [...have].filter((x) => !want.has(x)) });

function opByTool(c: BridgeCtx, name: string): { app: FakeApp; op: Operation } | null {
  const i = name.indexOf(TOOL_NAME_RULE.separator);
  if (i < 0) return null;
  const app = c.w.apps.find((a) => a.product === name.slice(0, i));
  const op = app?.manifest.operations.find((o) => o.id === name.slice(i + 2));
  return app && op ? { app, op } : null;
}

export async function mcpChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("mcp")) return;
  const catalog = (app: FakeApp, op: Operation) => (app === c.peer && op.dynamic?.mode === "list" ? peerCatalog() : []);
  await c.run("B7.initialize", "MCP initialize negotiates a session", "200 with Mcp-Session-Id and a protocolVersion", async () => {
    const s = await c.session("free", true);
    return verdict(s.sessionId.length > 0, `session ${s.sessionId ? "issued" : "missing"}`);
  });
  const freeList = await listTools(c, "free").catch(() => null);
  await c.run("B7.list_exact", "tools/list = agent-audience ops allowed by the grants (+ hold status, skills)", "listed names minus dynamic names = expected fixed names", () => {
    if (!freeList) return bad("tools/list failed");
    const want = c.expectedTools("free", catalog);
    const have = new Set(freeList.map((t) => t.name).filter((n) => !want.dynamic.has(n)));
    const d = diff(have, want.fixed);
    return verdict(d.missing.length === 0 && d.extra.length === 0, `listed ${freeList.length}; missing [${d.missing.join(",")}]; extra [${d.extra.join(",")}]`);
  });
  const boundList = await listTools(c, "bound").catch(() => null);
  await c.run("B7.no_person_ops", "person-audience ops never listed", "no listed tool maps to a person-audience op (free and bound agents)", () => {
    if (!freeList || !boundList) return bad("tools/list failed");
    const person = [...freeList, ...boundList].map((t) => t.name).filter((n) => opByTool(c, n)?.op.audience === "person");
    return verdict(person.length === 0, person.length ? `person ops listed: ${person.join(",")}` : `${freeList.length + boundList.length} tools, none person-audience`);
  });
  await c.run("B7.bound_list", "Bound agent sees only its workflow ops", "bound tools/list = wf ops + hold status + skills", () => {
    if (!boundList) return bad("tools/list failed");
    const want = c.expectedTools("bound", catalog);
    const d = diff(new Set(boundList.map((t) => t.name)), new Set([...want.fixed, ...want.dynamic]));
    return verdict(d.missing.length === 0 && d.extra.length === 0, `listed [${boundList.map((t) => t.name).join(",")}]; missing [${d.missing.join(",")}]; extra [${d.extra.join(",")}]`);
  });
  await c.run("B7.no_grant_empty", "agent without grants sees no tools", "empty tools/list", async () => {
    const l = await listTools(c, "none");
    return verdict(l !== null && l.length === 0, l ? `${l.length} tools` : "tools/list failed");
  });
  await c.run("B7.input_schema", "tool inputSchema = manifest input", "every listed op tool's inputSchema deep-equals the op input", () => {
    if (!freeList) return bad("tools/list failed");
    const off: string[] = [];
    let n = 0;
    for (const t of freeList) {
      const m = opByTool(c, t.name);
      if (!m || m.op.dynamic || !m.op.input) continue;
      n++;
      if (digest(t.inputSchema as Json) !== digest(m.op.input as unknown as Json)) off.push(t.name);
    }
    return verdict(n > 0 && off.length === 0, `${n} compared; differing [${off.join(",")}]`);
  });
  await c.run("B7.annotations", "annotations from effects", "readOnlyHint = effect read; destructiveHint = destructive; openWorldHint = outward|money", () => {
    if (!freeList) return bad("tools/list failed");
    const off: string[] = [];
    let n = 0;
    for (const t of freeList) {
      const m = opByTool(c, t.name);
      if (!m || m.op.dynamic) continue;
      n++;
      const a = t.annotations ?? {};
      const e = m.op.effect;
      if ((a.readOnlyHint === true) !== (e === "read") || (a.destructiveHint === true) !== (e === "destructive") || (a.openWorldHint === true) !== (e === "outward" || e === "money")) off.push(`${t.name}(${e})`);
    }
    return verdict(n > 0 && off.length === 0, `${n} op tools; wrong [${off.join(",")}]`);
  });
  await c.run("B7.unknown_session_404", "unknown Mcp-Session-Id → 404", "404 so the client re-initializes", async () => {
    const s = await c.session("free");
    const a = await request(`${c.pub}/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${s.token}`, "mcp-session-id": `conformance-${ulid()}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 9, method: "tools/list" }),
    });
    return verdict(a.status === 404, `${a.status}`);
  });
  const skills = c.primary.manifest.skills ?? [];
  const files = c.w.skillFiles().filter((f) => f.product === c.primary.product);
  const agentFree = c.w.agents.free;
  const rendered = (skillId: string): string | null => {
    const decl = skills.find((x) => x.id === skillId);
    const f = files.find((x) => x.id === skillId);
    return decl && f ? renderSkill(decl as Skill, f.content, { agent: { id: agentFree.agt, name: agentFree.name } }) : null;
  };
  await c.run("B7.skills_resources", "skills served as resources with agent variables filled", "resources/list has tealbrick://skills/<product>/<id> per skill; resources/read text = renderSkill(...) with {{agent.*}} filled", async () => {
    if (skills.length === 0) return bad("example manifest has no skills");
    const s = await c.session("free");
    const { message } = await s.rpc("resources/list");
    const list = isObj(message?.result) && Array.isArray(message.result.resources) ? (message.result.resources as { uri?: string }[]) : [];
    const uris = list.map((r) => String(r.uri));
    const want = skills.map((k) => `${TOOL_NAME_RULE.skillUriPrefix}${c.primary.product}/${k.id}`);
    const missing = want.filter((u) => !uris.includes(u));
    if (missing.length) return bad(`missing resources [${missing.join(",")}] (listed ${uris.length})`);
    const first = skills[0] as { id: string };
    const r = await s.rpc("resources/read", { uri: want[0] as string });
    const contents = isObj(r.message?.result) && Array.isArray(r.message.result.contents) ? (r.message.result.contents as { text?: string }[]) : [];
    const text = contents.map((x) => x.text ?? "").join("");
    const exp = rendered(first.id);
    return verdict(exp !== null && text === exp && !text.includes("{{agent."), `read ${text.length} chars; ${text === exp ? "= renderSkill output" : "≠ renderSkill output"}`);
  });
  await c.run("B7.instructions_index", "initialize.instructions: skill index ≤ 4 KB", "instructions name every skill (title or resource URI) and are ≤ 4096 bytes", async () => {
    const s = await c.session("free", true);
    const ins = s.instructions;
    const named = skills.filter((k) => ins.includes(k.title) || ins.includes(`${TOOL_NAME_RULE.skillUriPrefix}${c.primary.product}/${k.id}`));
    return verdict(Buffer.byteLength(ins) <= 4096 && named.length === skills.length && skills.length > 0, `${Buffer.byteLength(ins)} bytes; ${named.length}/${skills.length} skills named`);
  });
  await c.run("B17.listed", "<product>__tb_skills listed for every agent with a grant on that product", "free: every granted product; bound: its product", () => {
    if (!freeList || !boundList) return bad("tools/list failed");
    const want = [...new Set(c.w.grantSpecs.filter((g) => g.role === "free").map((g) => `${g.app.product}__${TOOL_NAME_RULE.skillsOp}`))];
    const fb = `${c.primary.product}__${TOOL_NAME_RULE.skillsOp}`;
    const names = new Set(freeList.map((t) => t.name));
    const missing = want.filter((w) => !names.has(w));
    const boundHas = boundList.some((t) => t.name === fb);
    return verdict(missing.length === 0 && boundHas, `free missing [${missing.join(",")}]; bound ${boundHas ? "has" : "lacks"} ${fb}`);
  });
  await c.run("B17.served_as_rendered", "tb_skills answers from config, rendered, unfiltered, without an app call", "index lists every skill id; {skillId} returns renderSkill(...) verbatim; no request reaches an app", async () => {
    if (skills.length === 0) return bad("no skills");
    const seq = c.w.seqNow();
    const name = `${c.primary.product}__${TOOL_NAME_RULE.skillsOp}`;
    const idx = await c.callTool("free", name, {});
    const one = await c.callTool("free", name, { skillId: (skills[0] as { id: string }).id });
    const idxText = JSON.stringify(idx.raw ?? "");
    const oneText = JSON.stringify(one.raw ?? "");
    const exp = rendered((skills[0] as { id: string }).id) ?? "\u0000";
    const listed = skills.every((k) => idxText.includes(k.id));
    const verbatim = oneText.includes(JSON.stringify(exp).slice(1, -1));
    const appCalls = c.everyApp(seq).length;
    return verdict(c.isOk(idx) && c.isOk(one) && listed && verbatim && appCalls === 0, `index ${describeCall(idx)} (${listed ? "all ids" : "ids missing"}); skill ${verbatim ? "verbatim" : "not verbatim"}; app requests ${appCalls}`);
  });
}

// ── B8 call path, B5 gate order, B13 (bridge side) ───────────────────────────
function lastOp(c: BridgeCtx, app: FakeApp, seq: number, op?: string): Received | undefined {
  return c.since(app, seq, "op").filter((r) => op === undefined || r.name === op)[0];
}

function keyOf(g: { body: string } | undefined | null): string | undefined {
  if (!g) return undefined;
  const k = (JSON.parse(g.body) as { idempotencyKey?: unknown }).idempotencyKey;
  return typeof k === "string" ? k : undefined;
}
/** A schema-agnostic different input: the first string field with "-2" appended, else null. */
function variantOf(input: Json): Json | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  for (const [k, v] of Object.entries(input)) if (typeof v === "string") return { ...input, [k]: `${v}-2` };
  return null;
}

export async function callChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("call")) return;
  const p = c.primary;
  const read = c.readOp(p);
  if (!read) {
    for (const id of ["B8.forward"]) c.s.record(id, "call path", "an agent read op in the example manifest", bad("no agent read op"));
    return;
  }
  const input = c.input(p, read.id);
  const seq = c.w.seqNow();
  const r = await c.call("free", p, read.id, input);
  const got = lastOp(c, p, seq, read.id);
  await c.run("B8.forward", "tools/call forwarded to the app; ok result returned", "MCP result ok with structuredContent = the app output", () => {
    const fine = c.isOk(r) && r.structured?.marker === c.w.canary;
    if (fine) c.evidence.set("K10", "agent grant forwarded and accepted by the app");
    return verdict(fine, describeCall(r));
  });
  await c.run("B8.grant_and_proof", "app receives the config grant and a valid TB-Call proof", "app re-verification passes; grant jti = config grant; proof sub = agent, aud = target, variant op", () => {
    if (!got) return bad("the app received no op call");
    const g = c.w.grantFor("free", p);
    const fine = got.verified && got.variant === "op" && got.grant?.jti === peek(g ?? "")?.jti && got.proof?.sub === `tb:agt:${c.w.agents.free.agt}` && got.proof?.aud === `tb:ins:${p.ins}`;
    return verdict(fine, `verified ${got.verified}${got.reason ? ` (${got.reason})` : ""}; variant ${got.variant}; grant jti ${got.grant?.jti === peek(g ?? "")?.jti ? "= config" : "≠ config"}`);
  });
  await c.run("B8.input_verbatim", "input forwarded verbatim; proof binds input and context digests", "body.input deep-equals the agent arguments; body.context is an object; proof in/ctx verified", () => {
    if (!got) return bad("no op call");
    let body: Record<string, unknown> = {};
    try {
      body = JSON.parse(got.body) as Record<string, unknown>;
    } catch {
      return bad("body not JSON");
    }
    const fine = digest(body.input as Json) === digest(input) && isObj(body.context) && got.proof?.in === digest(input);
    return verdict(fine, `input ${digest(body.input as Json) === digest(input) ? "verbatim" : "changed"}; context ${isObj(body.context) ? "object" : typeof body.context}; proof in ${got.proof?.in === digest(input) ? "bound" : "unbound"}`);
  });
  await c.run("B8.headers", "only the grant and the call proof authenticate the forward", "Authorization = Bearer <grant>, TB-Call present; no K5, session id or x-* identity headers", () => {
    if (!got) return bad("no op call");
    const h = got.headers;
    const g = c.w.grantFor("free", p);
    const leaks = [...c.accessTokens].filter((t) => got.body.includes(t) || Object.values(h).some((v) => v.includes(t))).length;
    const xs = Object.keys(h).filter((k) => /^x-(tb|tealbrick|agent|user|person)/i.test(k) || k === "mcp-session-id");
    return verdict(h.authorization === `Bearer ${g}` && !!h["tb-call"] && leaks === 0 && xs.length === 0, `authorization ${h.authorization === `Bearer ${g}` ? "= grant" : "≠ grant"}; tb-call ${h["tb-call"] ? "present" : "missing"}; K5 leaks ${leaks}; extra [${xs.join(",")}]`);
  });
  const create = c.pick(p, (o) => o.idempotency === "required");
  await c.run("B8.idempotency_forwarded", "_meta idempotency key forwarded as body idempotencyKey", "app body.idempotencyKey = the _meta value", async () => {
    if (!create) return bad("no idempotency: required op");
    const key = c.idemKey();
    const s0 = c.w.seqNow();
    const a = await c.call("free", p, create.id, undefined, key);
    const g = lastOp(c, p, s0, create.id);
    const sent = g ? (JSON.parse(g.body) as { idempotencyKey?: unknown }).idempotencyKey : undefined;
    return verdict(c.isOk(a) && sent === key, `${describeCall(a)}; forwarded key ${sent === key ? "equal" : String(sent)}`);
  });
  // C98 (spec 0.1.14, BRIDGE §7.2): model-driven clients cannot set `_meta`; the bridge derives the key from
  // (connection, MCP session, op, canonical input, 10-min bucket). Root cause recorded (L2): every earlier test set _meta.
  // C98a (spec 0.1.15): the same rule for idempotency `supported` ops (a model-driven retry of a supported op is
  // deduplicated too); `none` ops never get a key
  const supported = c.pick(p, (o) => o.idempotency === "supported");
  await c.run("B8.idempotency_derived", "no _meta key on a required or supported op → the bridge derives one; an identical retry is deduplicated (C98, C98a)", "required op without _meta → ok with a non-empty forwarded idempotencyKey; identical retry (same session, same input) → same key; other input → other key; a supported op (when the example manifest has one) → a non-empty key, the same on retry", async () => {
    if (!create) return bad("no idempotency: required op");
    const input = c.input(p, create.id);
    const s0 = c.w.seqNow();
    const a = await c.call("free", p, create.id, input, null);
    const k1 = keyOf(lastOp(c, p, s0, create.id));
    const s1 = c.w.seqNow();
    const b = await c.call("free", p, create.id, input, null);
    const k2 = keyOf(lastOp(c, p, s1, create.id));
    const other = variantOf(input);
    const s2 = c.w.seqNow();
    const o = other === null ? null : await c.call("free", p, create.id, other, null);
    const k3 = other === null ? undefined : keyOf(lastOp(c, p, s2, create.id));
    const requiredOk = c.isOk(a) && c.isOk(b) && typeof k1 === "string" && k1.length > 0 && k1 === k2 && (other === null || (o !== null && k3 !== k1));
    let supportedOk = true;
    let supShown = "supported op: n/a (none in the example manifest)";
    if (supported) {
      const sin = c.input(p, supported.id);
      const t0 = c.w.seqNow();
      const sa = await c.call("free", p, supported.id, sin, null);
      const s1k = keyOf(lastOp(c, p, t0, supported.id));
      const t1 = c.w.seqNow();
      const sb = await c.call("free", p, supported.id, sin, null);
      const s2k = keyOf(lastOp(c, p, t1, supported.id));
      supportedOk = c.isOk(sa) && c.isOk(sb) && typeof s1k === "string" && s1k.length > 0 && s1k === s2k && s1k !== k1;
      supShown = `supported ${supported.id}: ${describeCall(sa)} key ${s1k ? "derived" : "MISSING"}, retry ${describeCall(sb)} key ${s2k === s1k ? "same" : "DIFFERENT"}`;
    }
    return verdict(requiredOk && supportedOk, `first ${describeCall(a)} key ${k1 ? "derived" : "MISSING"}; retry ${describeCall(b)} key ${k2 === k1 ? "same" : "DIFFERENT"}; other input ${other === null ? "n/a" : k3 !== k1 ? "other key" : "SAME key"}; ${supShown}`);
  });
  await c.run("B8.input_invalid", "input failing the op schema → input_invalid", "isError input_invalid; the app is not called", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", c.tool(p, read.id), { conformance_unexpected: 1 } as Record<string, unknown>);
    const req = (read.input as { required?: unknown } | undefined)?.required;
    const required = Array.isArray(req) && req.length > 0;
    if (!required) return bad("read op has no required field to omit");
    const o = toolRefused(a, ["input_invalid"]);
    return verdict(o.pass === true && !lastOp(c, p, s0), `${o.asserted}; app calls ${c.since(p, s0, "op").length}`);
  });
  await c.run("B8.held", "held answer returned as a non-error result with the hold-status tool", "structuredContent {status: held, holdId, expiresAt, checkWith: <product>__tb_hold_status}, isError false", async () => {
    const holdId = `hld_${ulid()}`;
    p.onOp = () => ({ status: 202, body: { status: "held", holdId, expiresAt: new Date(Date.now() + 3600_000).toISOString() } });
    try {
      const a = await c.call("free", p, read.id);
      const sc = a.structured ?? {};
      const fine = !a.isError && sc.status === "held" && sc.holdId === holdId && typeof sc.expiresAt === "string" && sc.checkWith === `${p.product}__${TOOL_NAME_RULE.holdStatusOp}`;
      return verdict(fine, describeCall(a));
    } finally {
      p.onOp = null;
    }
  });
  await c.run("B8.app_error_passthrough", "app-side refusal codes pass through unchanged", "isError with the app's code (scope_denied)", async () => {
    p.onOp = () => ({ status: 403, body: { error: { code: "scope_denied", message: "conformance", requestId: "req_conformance" } } });
    try {
      return toolRefused(await c.call("free", p, read.id), ["scope_denied"]);
    } finally {
      p.onOp = null;
    }
  });
  await c.run("B8.hold_status", "<product>__tb_hold_status routed to tb.hold_status", "the app receives op tb.hold_status with a verified grant and proof", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", `${p.product}__${TOOL_NAME_RULE.holdStatusOp}`, { holdId: `hld_${ulid()}` });
    const g = lastOp(c, p, s0, "tb.hold_status");
    return verdict(c.isOk(a) && !!g?.verified, `${describeCall(a)}; app ${g ? `received tb.hold_status (verified ${g.verified})` : "received nothing"}`);
  });
  // ── B5 gate order ──
  const refusedNoCall = async (slot: Parameters<BridgeCtx["call"]>[0], app: FakeApp, opId: string, codes: string[]): Promise<Outcome> => {
    const s0 = c.w.seqNow();
    const a = await c.call(slot, app, opId);
    const o = toolRefused(a, codes);
    const calls = c.since(app, s0, "op").length + c.everyApp(s0, "hook").length;
    return verdict(o.pass === true && calls === 0, `${o.asserted}; app requests ${calls}`);
  };
  await c.run("B5.no_grant", "agent without a grant is refused before any app call", "isError no_grant (or unknown_tool: not in its table); no app request", () => refusedNoCall("none", p, read.id, ["no_grant", "unknown_tool"]));
  // spec 0.1.50 (C283 A1): gate() skips the CRUD ceiling for an op WITH a scopeType (the app's own owner-set access may be
  // primary above the Portal grant, the SDK decides); an op without one keeps it. A bridge without the A1 filter refuses both.
  // Conformance 0.1.27 (C292): a bridge that implements it DECLARES `owner_rows` in its StatusReport; the suite decides by that cap, not by version.
  const gateSkipsScoped = reportedBridgeCaps(c).includes(OWNER_ROWS_CAP);
  const aboveFree = (o: Operation) => o.crud.some((x) => !["read", "create", "update"].includes(x));
  const del = c.pick(p, (o) => aboveFree(o) && (!gateSkipsScoped || o.scopeType === undefined));
  await c.run("B5.crud_exceeds_grant", "op crud beyond the grant refused", "isError crud_exceeds_grant (or unknown_tool); no app request; for a bridge that declares the owner_rows cap only an op WITHOUT a scopeType is refused here (B5.gate_scoped_above_grant covers the scoped ones)", () =>
    del ? refusedNoCall("free", p, del.id, ["crud_exceeds_grant", "unknown_tool"]) : gateSkipsScoped ? Promise.resolve(na("every op beyond the free grant's crud has a scopeType: a bridge that declares owner_rows passes those to the app (B5.gate_scoped_above_grant)")) : Promise.resolve(bad("no op outside the free grant's crud")),
  );
  const person = p.manifest.operations.find((o) => o.audience === "person");
  await c.run("B5.audience_not_agent", "person-audience op refused on the agent path", "isError audience_not_agent (or unknown_tool); no app request", () =>
    person ? refusedNoCall("free", p, person.id, ["audience_not_agent", "unknown_tool"]) : bad("no person op"),
  );
  const wf = c.w.grantSpecs.find((g) => g.role === "bound")?.wf ?? [];
  const outside = c.pick(p, (o) => !wf.includes(o.id));
  await c.run("B5.bound_in_wf", "Bound agent may call its workflow op", "ok", async () => {
    const id = wf[0];
    if (!id) return bad("bound grant has no wf");
    const a = await c.call("bound", p, id);
    return verdict(c.isOk(a), describeCall(a));
  });
  await c.run("B5.bound_outside_wf", "Bound agent outside its workflow refused", "isError not_in_workflow (or unknown_tool); no app request", () =>
    outside ? refusedNoCall("bound", p, outside.id, ["not_in_workflow", "unknown_tool"]) : bad("no op outside wf"),
  );
  // grant revoked (step 2), then pause with the grant intact (step 1)
  const g = c.w.grantFor("free", p);
  const jti = String(peek(g ?? "")?.jti ?? "");
  c.w.portal.revoked.push({ jti, exp: nowS() + 3600 });
  await c.apply();
  // the publish re-mints grants: revoke the new jti too so the config entry for (free, primary) is withdrawn
  const g2 = c.w.grantFor("free", p);
  c.w.portal.revoked.push({ jti: String(peek(g2 ?? "")?.jti ?? ""), exp: nowS() + 3600 });
  await c.w.portal.mintRevision();
  await c.w.waitAck(c.w.portal.rev, c.h.timeoutMs);
  await c.run("B5.grant_revoked", "grant whose jti is in revoked.jtis refused", "isError grant_revoked (or no_grant / unknown_tool when dropped at config verify); no app request", () =>
    refusedNoCall("free", p, read.id, ["grant_revoked", "no_grant", "unknown_tool"]),
  );
  c.w.portal.revoked = [];
  c.w.portal.pause.agents.add(c.w.agents.free.agt);
  await c.apply();
  await c.run("B5.paused_first", "pause is gate step 1", "paused agent with a valid grant → isError paused (not a later step's code); no app request", () => refusedNoCall("free", p, read.id, ["paused"]));
  c.w.portal.pause.agents.delete(c.w.agents.free.agt);
  c.w.portal.revoked = [];
  await c.apply();
  await c.run("B5.restored", "unpause and un-revoke restore the agent", "ok after the next config revision", async () => {
    const r = await c.until(async () => {
      const a = await c.call("free", p, read.id);
      return c.isOk(a) ? a : null;
    }, c.h.pauseLatencyMs);
    return verdict(!!r.value, r.value ? `ok after ${r.ms} ms` : "still refused");
  });
  // v0.1.17 (C108, tolerant reader): a newer Core may put a family into an agent grant's `held` that this bridge does
  // not know; the grant stays valid (shape-checked, the unknown family ignored) and the call is forwarded
  const spec = c.w.grantSpecs.find((x) => x.role === "free" && x.app === p);
  const unknownFamily = "future_x";
  await c.run("B5.grant_held_unknown", "an agent grant whose held names an unknown family is still honoured (C108)", `config grant (free agent → primary) with held [...DEFAULT_HELD_FAMILIES, ${unknownFamily}] → the read op is forwarded ok with that grant (never grant_invalid / no_grant)`, async () => {
    if (!spec) return bad("no free-agent grant spec for the primary app");
    spec.held = [...DEFAULT_HELD_FAMILIES, unknownFamily];
    try {
      await c.apply();
      const g = c.w.grantFor("free", p) ?? "";
      const r = await c.until(async () => {
        const s0 = c.w.seqNow();
        const a = await c.call("free", p, read.id);
        const got = lastOp(c, p, s0, read.id);
        return c.isOk(a) && got ? { a, got } : null;
      }, c.h.pauseLatencyMs);
      const v = r.value;
      const carried = !!v && v.got.grant?.jti === peek(g)?.jti && ((peek(g)?.held as string[] | undefined) ?? []).includes(unknownFamily);
      if (!v) {
        const a = await c.call("free", p, read.id);
        return bad(`${describeCall(a)} (the grant with held ${unknownFamily} was not honoured)`);
      }
      return verdict(carried, `${describeCall(v.a)}; forwarded grant ${carried ? `= the config grant (held …, ${unknownFamily})` : "is not the config grant"}`);
    } finally {
      delete spec.held;
      await c.apply();
    }
  });
  // v0.1.19 (C111a, BRIDGE §8.1 gate step 4): a non-empty `wf` limits the ops in ANY mode (not only Bound)
  const freeCrud = spec?.crud ?? [];
  const inFreeCrud = (o: Operation) => o.crud.every((x) => freeCrud.includes(x));
  const wfOther = c.pick(p, (o) => o.id !== read.id && inFreeCrud(o) && !o.dynamic);
  await c.run("B5.free_wf_limits", "a Free grant with a non-empty wf limits the ops (C111a)", `config grant (free agent → primary, mode free) with wf [${read.id}]: ${read.id} is forwarded ok; another agent op within the grant's crud → isError not_in_workflow (or unknown_tool: not listed), no app request`, async () => {
    if (!spec) return bad("no free-agent grant spec for the primary app");
    if (!wfOther) return bad("no second agent op within the free grant's crud");
    spec.wf = [read.id];
    try {
      await c.apply();
      const g = c.w.grantFor("free", p) ?? "";
      const r = await c.until(async () => {
        const s0 = c.w.seqNow();
        const a = await c.call("free", p, read.id);
        const got = lastOp(c, p, s0, read.id);
        return c.isOk(a) && got && got.grant?.jti === peek(g)?.jti ? { a, got } : null;
      }, c.h.pauseLatencyMs);
      if (!r.value) return bad(`${read.id} (in wf) not forwarded with the wf grant: ${describeCall(await c.call("free", p, read.id))}`);
      const o = await refusedNoCall("free", p, wfOther.id, ["not_in_workflow", "unknown_tool"]);
      return verdict(o.pass === true, `in wf ${read.id}: ${describeCall(r.value.a)}; outside wf ${wfOther.id}: ${o.asserted}`);
    } finally {
      spec.wf = [];
      await c.apply();
    }
  });
  // spec 0.1.50 (C283 A1, a bridge that declares owner_rows, C292): the app names a scoped op beyond the grant's crud in scope_summary `admittedOps` for the Free
  // agent (its OWNER rows admit it); the bridge lists the tool and its gate() passes the call to the app, which decides (SDK authorize()).
  const scopedAbove = c.pick(p, (o) => o.scopeType !== undefined && !o.dynamic && !inFreeCrud(o));
  await c.run(
    "B5.gate_scoped_above_grant",
    "a scoped op above the grant's crud that the app admits reaches the app: gate() skips the CRUD ceiling for ops with a scopeType (C283 A1)",
    "the app's scope_summary names a scoped agent op beyond the Free grant's crud in admittedOps for the Free agent → the tool is listed and a tools/call is forwarded to the app (the app answers; the bridge does not refuse crud_exceeds_grant); a bridge whose StatusReport does not declare the owner_rows cap (bridge.caps) is not_applicable, and one that declares it MUST pass (decided by capability, never by version, C292)",
    async () => {
      const caps = reportedBridgeCaps(c);
      if (!caps.includes(OWNER_ROWS_CAP)) return na(`bridge ${enrolRequests(c)[0]?.version ?? "?"} does not declare the ${OWNER_ROWS_CAP} capability in its StatusReport (bridge.caps = ${JSON.stringify(caps)}): the C283 A1 owner-row filter is not announced, so this row does not apply (the suite decides by capability, never by version, C292)`);
      if (!scopedAbove) return na("no scoped agent op beyond the free grant's crud in the primary manifest");
      const agent = c.w.agents.free.agt;
      const was = p.scopeSummary;
      p.scopeSummary = () => [{ agent, label: "conformance", admittedOps: [scopedAbove.id] }];
      try {
        const r = await c.until(async () => {
          const s0 = c.w.seqNow();
          const a = await c.call("free", p, scopedAbove.id);
          const got = lastOp(c, p, s0, scopedAbove.id);
          return got ? { a, got } : null;
        }, c.h.pauseLatencyMs);
        if (!r.value) return bad(`${scopedAbove.id} (crud ${scopedAbove.crud.join("+")}, beyond the free grant's ${freeCrud.join("+")}) named in the app's admittedOps never reached the app: ${describeCall(await c.call("free", p, scopedAbove.id))}`);
        return ok(`${scopedAbove.id} (crud ${scopedAbove.crud.join("+")}, beyond the free grant's ${freeCrud.join("+")}) reached the app after ${r.ms} ms: ${describeCall(r.value.a)}`);
      } finally {
        p.scopeSummary = was;
      }
    },
  );
  const capOp = c.pick(p, (o) => o.effect === "write" && inFreeCrud(o) && !o.dynamic);
  await c.run("B5.free_wf_caps", "a Free grant with wf + caps: caps travel to the app and still hold (C111a)", "config grant (mode free) with wf [<write op>] + caps {write: {max: 0, per: hour}} → the call is forwarded (grant with that wf and caps) and the app's hold (caps) comes back as held", async () => {
    if (!spec) return bad("no free-agent grant spec for the primary app");
    if (!capOp) return na("no write op within the free grant's crud");
    spec.wf = [capOp.id];
    spec.caps = { write: { max: 0, per: "hour" } };
    const holdId = `hld_${ulid()}`;
    // the fake app applies the forwarded grant's caps as the SDK's authorize() does (step 4, any mode since C111a)
    p.onOp = (info) => {
      const caps = info.grant.caps as Record<string, { max?: number }> | undefined;
      if (info.op === capOp.id && caps?.write?.max === 0) return { status: 202, body: { status: "held", holdId, expiresAt: new Date(Date.now() + 3600_000).toISOString() } };
      return { status: 200, body: { status: "ok", output: { op: info.op } } };
    };
    try {
      await c.apply();
      const g = c.w.grantFor("free", p) ?? "";
      const r = await c.until(async () => {
        const s0 = c.w.seqNow();
        const a = await c.call("free", p, capOp.id, undefined, c.idemKey());
        const got = lastOp(c, p, s0, capOp.id);
        return got && got.grant?.jti === peek(g)?.jti ? { a, got } : null;
      }, c.h.pauseLatencyMs);
      if (!r.value) return bad(`${capOp.id} not forwarded with the wf + caps grant: ${describeCall(await c.call("free", p, capOp.id, undefined, c.idemKey()))}`);
      const fg = r.value.got.grant as { mode?: string; wf?: string[]; caps?: Record<string, { max?: number }> };
      const sc = r.value.a.structured ?? {};
      const carried = fg.mode === "free" && JSON.stringify(fg.wf) === JSON.stringify([capOp.id]) && fg.caps?.write?.max === 0;
      const held = !r.value.a.isError && sc.status === "held" && sc.holdId === holdId;
      return verdict(carried && held, `${capOp.id}: ${describeCall(r.value.a)}; forwarded grant mode ${String(fg.mode)}, wf ${JSON.stringify(fg.wf)}, caps.write.max ${String(fg.caps?.write?.max)}`);
    } finally {
      p.onOp = null;
      spec.wf = [];
      delete spec.caps;
      await c.apply();
    }
  });
}

// ── B6 hooks ─────────────────────────────────────────────────────────────────
export async function hookChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("hooks")) return;
  const p = c.primary;
  const peer = c.peer;
  const hooked = c.pick(p, (o) => o.idempotency === "required" && (p.manifest.hooks ?? []).some((h) => h.match.operations?.includes(o.id))) ?? c.pick(p, (o) => o.idempotency === "required");
  if (!peer || !hooked) {
    c.s.record("B6.order", "hooks", "a peer app with hooks", bad("no peer app / hooked op"));
    return;
  }
  const entries = c.w.hookEntries().filter((h) => {
    const m = h.match;
    if (h.enabled === false) return false;
    const prodOk = m.products.includes("*") || m.products.includes(p.product);
    const opOk = !m.operations || m.operations.includes(hooked.id);
    return prodOk && opOk;
  });
  const order = (phase: string) =>
    entries
      .filter((h) => h.phase === phase)
      .sort((a, b) => a.order - b.order || (a.product < b.product ? -1 : a.product > b.product ? 1 : 0))
      .map((h) => `${h.product}.${h.hookId}`);
  const hooksSince = (seq: number) =>
    c.w.apps
      .flatMap((a) => c.since(a, seq, "hook").map((r) => ({ r, id: `${a.product}.${r.name}` })))
      .sort((x, y) => x.r.seq - y.r.seq);
  const reset = () => {
    for (const a of c.w.apps) {
      a.onHook = null;
      a.onOp = null;
    }
  };
  const peerHook = (phase: string) => (peer.manifest.hooks ?? []).find((h) => h.phase === phase)?.id ?? "";

  const seq = c.w.seqNow();
  const r = await c.call("free", p, hooked.id);
  const seen = hooksSince(seq);
  const opRec = lastOp(c, p, seq, hooked.id);
  await c.run("B6.order", "before (order, product) → context → op → after", `hook order before [${order("before").join(",")}], context [${order("context").join(",")}], after [${order("after").join(",")}] around the op`, () => {
    if (!c.isOk(r) || !opRec) return bad(`call ${describeCall(r)}`);
    const before = seen.filter((x) => x.r.seq < opRec.seq).map((x) => x.id);
    const after = seen.filter((x) => x.r.seq > opRec.seq).map((x) => x.id);
    const want = [...order("before"), ...order("context")];
    return verdict(before.join(",") === want.join(",") && after.join(",") === order("after").join(","), `before op [${before.join(",")}], after op [${after.join(",")}]`);
  });
  await c.run("B6.hook_proof", "hook calls carry a valid hook proof and no grant", "every hook request verified (variant hook), no Authorization header", () => {
    if (seen.length === 0) return bad("no hook calls");
    const off = seen.filter((x) => !x.r.verified || x.r.variant !== "hook" || "authorization" in x.r.headers);
    return verdict(off.length === 0, `${seen.length} hook calls; bad [${off.map((x) => `${x.id}:${x.r.reason || x.r.variant}`).join(",")}]`);
  });
  await c.run("B6.no_hook_recursion", "hook calls never trigger hooks", "exactly one request per matching hook for one tool call", () => {
    const want = order("before").length + order("context").length + order("after").length;
    return verdict(seen.length === want, `${seen.length} hook calls for ${want} matching hooks`);
  });
  const failCase = async (phase: string, answer: () => { status: number; body: unknown } | null, codes: string[], maxMs?: number) => {
    const id = peerHook(phase);
    peer.onHook = (hookId) => (hookId === id ? answer() : { status: 200, body: phase === "before" ? { allow: true } : { add: {} } });
    try {
      const s0 = c.w.seqNow();
      const t0 = Date.now();
      const a = await c.call("free", p, hooked.id);
      const ms = Date.now() - t0;
      const o = toolRefused(a, codes);
      const opCalls = c.since(p, s0, "op").length;
      return verdict(o.pass === true && opCalls === 0 && (maxMs === undefined || ms <= maxMs), `${o.asserted}; op calls ${opCalls}; ${ms} ms`);
    } finally {
      reset();
    }
  };
  await c.run("B6.before_denied", "before hook allow:false → hook_denied", "isError hook_denied; op not called", () => failCase("before", () => ({ status: 200, body: { allow: false, reason: "conformance" } }), ["hook_denied"]));
  await c.run("B6.before_failed", "failing before hook → hook_failed (fail closed)", "isError hook_failed; op not called", () => failCase("before", () => ({ status: 500, body: { error: { code: "internal", message: "x", requestId: "req_x" } } }), ["hook_failed"]));
  const beforeTimeout = (peer.manifest.hooks ?? []).find((h) => h.phase === "before")?.timeoutMs ?? 2000;
  await c.run("B6.before_timeout", "slow before hook → hook_failed within its timeout", `isError hook_failed within ${beforeTimeout} ms + 3 s; op not called`, () => failCase("before", () => null, ["hook_failed"], beforeTimeout + 3000));
  await c.run("B6.context_failed", "failing context hook → hook_failed", "isError hook_failed; op not called", () => failCase("context", () => ({ status: 500, body: {} }), ["hook_failed"]));
  await c.run("B6.context_namespace", "context key outside the hook product's namespace → hook_failed", "isError hook_failed; op not called", () => failCase("context", () => ({ status: 200, body: { add: { "conformance-foreign.key": 1 } } }), ["hook_failed"]));
  await c.run("B6.context_merged", "context additions merged and unknown namespaced fields passed through", "op body.context carries the added key with its nested value untouched", async () => {
    const key = `${peer.product}.conformance`;
    const value = { nested: { marker: c.w.canary, list: [1, "two", null] } };
    peer.onHook = (_id, phase) => ({ status: 200, body: phase === "context" ? { add: { [key]: value } } : phase === "before" ? { allow: true } : {} });
    try {
      const s0 = c.w.seqNow();
      const a = await c.call("free", p, hooked.id);
      const g = lastOp(c, p, s0, hooked.id);
      const ctx = g ? (JSON.parse(g.body) as { context?: Record<string, unknown> }).context : undefined;
      return verdict(c.isOk(a) && !!ctx && digest((ctx[key] ?? null) as Json) === digest(value as Json), `${describeCall(a)}; context ${ctx ? Object.keys(ctx).join(",") : "missing"}`);
    } finally {
      reset();
    }
  });
  await c.run("B6.after_failed", "failing after hook → after_failed, output withheld, receipt marked", "isError after_failed; op ran once; bridge-op mark {call, mark: after_failed} with a verified bridge-op proof", async () => {
    const id = peerHook("after");
    peer.onHook = (hookId, phase) => (hookId === id ? { status: 500, body: {} } : { status: 200, body: phase === "before" ? { allow: true } : phase === "context" ? { add: {} } : {} });
    try {
      const s0 = c.w.seqNow();
      const a = await c.call("free", p, hooked.id);
      const opCall = lastOp(c, p, s0, hooked.id);
      const marked = await c.until(async () => c.since(p, s0, "bridge_op").find((x) => x.name === "mark"), 5000);
      const mk = marked.value;
      const body = mk ? (JSON.parse(mk.body) as { call?: unknown; mark?: unknown }) : null;
      const o = toolRefused(a, ["after_failed"]);
      const fine = o.pass === true && !!opCall && !!mk && mk.verified && body?.mark === "after_failed" && body.call === opCall.proof?.call && !JSON.stringify(a.raw).includes(c.w.canary);
      return verdict(fine, `${o.asserted}; op calls ${c.since(p, s0, "op").length}; mark ${mk ? `verified ${mk.verified}, call ${body?.call === opCall?.proof?.call ? "=" : "≠"} op call` : "not sent"}`);
    } finally {
      reset();
    }
  });
  await c.run("B6.after_output", "after hook may replace output or redact it", "replacement output returned; redaction removes the pointer", async () => {
    peer.onHook = (_id, phase) => ({ status: 200, body: phase === "after" ? { output: { replaced: true, marker: "gone" } } : phase === "before" ? { allow: true } : { add: {} } });
    let a: ToolCallResult;
    let b: ToolCallResult;
    try {
      a = await c.call("free", p, hooked.id);
      peer.onHook = (_id, phase) => ({ status: 200, body: phase === "after" ? { redactions: ["/marker"] } : phase === "before" ? { allow: true } : { add: {} } });
      b = await c.call("free", p, hooked.id);
    } finally {
      reset();
    }
    return verdict(a.structured?.replaced === true && !!b.structured && !("marker" in b.structured), `replace ${describeCall(a)}; redact ${describeCall(b)}`);
  });
}

// ── dynamic tools (B7 dynamic, B16 ceilings) ─────────────────────────────────
export async function dynamicChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("dynamic")) return;
  const peer = c.peer;
  const list = peer?.manifest.operations.find((o) => o.dynamic?.mode === "list");
  const search = peer?.manifest.operations.find((o) => o.dynamic?.mode === "search");
  if (!peer || !list || !search) {
    c.s.record("B7.dynamic_list", "dynamic tools", "a generated peer app with list and search ops", bad("no peer app"));
    return;
  }
  const names = new Set(((await listTools(c, "free")) ?? []).map((t) => t.name));
  const [inside, over] = peerCatalog();
  await c.run("B7.dynamic_list", "list-mode op: one tool per catalog entry inside the ceilings", "<product>__<entry> listed for the entry inside the ceilings; the entry outside omitted", () =>
    verdict(names.has(`${peer.product}__${inside?.name}`) && !names.has(`${peer.product}__${over?.name}`), `inside ${names.has(`${peer.product}__${inside?.name}`) ? "listed" : "missing"}; outside ${names.has(`${peer.product}__${over?.name}`) ? "LISTED" : "omitted"}`),
  );
  await c.run("B16.catalog_omitted_reported", "omitted catalog entry reported in the status report", "an ack lists toolsOmitted {ins: peer, name …entry outside the ceilings}", async () => {
    const r = await c.until(async () => c.w.portal.acks.some((a) => (a.toolsOmitted ?? []).some((t) => t.ins === peer.ins && t.name.includes(String(over?.name)))), c.h.timeoutMs);
    return verdict(!!r.value, r.value ? "reported" : `not reported in ${c.w.portal.acks.length} acks`);
  });
  const d = { search: `${peer.product}__${search.id}${TOOL_NAME_RULE.searchSuffix}`, call: `${peer.product}__${search.id}${TOOL_NAME_RULE.callSuffix}` };
  await c.run("B7.dynamic_search", "search-mode op: <product>__<op>_search + _call listed", "both names listed", () => verdict(names.has(d.search) && names.has(d.call), `search ${names.has(d.search)}; call ${names.has(d.call)}`));
  await c.run("B16.search_uses_catalog", "_search answered through the catalog bridge op", "the app receives a verified bridge-op catalog {op, query} and the call returns its entries", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", d.search, { query: "conformance", limit: 5 });
    const cat = c.since(peer, s0, "bridge_op").find((x) => x.name === "catalog");
    const body = cat ? (JSON.parse(cat.body) as { op?: unknown; query?: unknown }) : null;
    return verdict(c.isOk(a) && !!cat?.verified && body?.op === search.id && body.query === "conformance" && JSON.stringify(a.raw).includes(String(inside?.name)), `${describeCall(a)}; catalog ${cat ? `verified ${cat.verified}, op ${String(body?.op)}` : "not called"}`);
  });
  // C107 (spec 0.1.16): outward / money resolutions must carry a holdFamily (the peer's search op ceiling is money)
  const famEntry = KNOWN_HOLD_FAMILIES.find((f) => f === "first_contact") ?? KNOWN_HOLD_FAMILIES[0];
  const resolutions: Record<string, Record<string, Json>> = {
    entry_bad: { crud: ["delete"], effect: "destructive" },
    entry_outward_fam: { crud: ["create"], effect: "outward", holdFamily: famEntry },
    entry_outward_bare: { crud: ["create"], effect: "outward" },
    entry_money_bare: { crud: ["create"], effect: "money" },
  };
  peer.resolve = (b) => {
    const tool = String(b.tool ?? "");
    return { tool, ...(resolutions[tool] ?? { crud: ["read"], effect: "read" }) };
  };
  await c.run("B16.dynamic_call_resolved", "_call resolved before gate() and forwarded to the dynamic op", "verified bridge-op resolve {op, tool}, then the op call carries {tool, arguments}", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", d.call, { tool: "entry_fine", arguments: { q: "x" } });
    const res = c.since(peer, s0, "bridge_op").find((x) => x.name === "resolve");
    const op = lastOp(c, peer, s0, search.id);
    const opInput = op ? (JSON.parse(op.body) as { input?: { tool?: unknown } }).input : undefined;
    return verdict(c.isOk(a) && !!res?.verified && !!op?.verified && opInput?.tool === "entry_fine", `${describeCall(a)}; resolve ${res ? `verified ${res.verified}` : "not called"}; op ${op ? `verified ${op.verified}, tool ${String(opInput?.tool)}` : "not called"}`);
  });
  await c.run("B16.dynamic_ceiling_exceeded", "resolution outside the op's ceilings → dynamic_ceiling_exceeded", "isError dynamic_ceiling_exceeded; op not called", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", d.call, { tool: "entry_bad", arguments: {} });
    const o = toolRefused(a, ["dynamic_ceiling_exceeded"]);
    return verdict(o.pass === true && !lastOp(c, peer, s0, search.id), `${o.asserted}; op calls ${c.since(peer, s0, "op").length}`);
  });
  await c.run("B16.resolve_family", "a resolve answer with effect outward or money and no holdFamily is refused (C107)", `_call of an entry resolved {effect outward, holdFamily ${famEntry}} → forwarded; resolved {effect outward} or {effect money} without holdFamily → isError dynamic_resolve_failed with details.reason family_missing, the op not called`, async () => {
    const seen: string[] = [];
    let pass = true;
    for (const [tool, want] of [["entry_outward_fam", "forward"], ["entry_outward_bare", "refuse"], ["entry_money_bare", "refuse"]] as const) {
      const s0 = c.w.seqNow();
      const a = await c.callTool("free", d.call, { tool, arguments: {} });
      const called = !!lastOp(c, peer, s0, search.id);
      // C107 decision: refused as dynamic_resolve_failed with details.reason "family_missing" (BRIDGE v0.1.17)
      const st = (a.structured ?? {}) as { error?: { code?: unknown; details?: { reason?: unknown } } };
      const reasonOk = st.error?.code === "dynamic_resolve_failed" && st.error?.details?.reason === "family_missing";
      const fine = want === "forward" ? c.isOk(a) && called : a.isError === true && !called && reasonOk;
      pass &&= fine;
      seen.push(`${tool}: ${describeCall(a)}, op ${called ? "called" : "not called"}${fine ? "" : " (WRONG)"}`);
    }
    return verdict(pass, seen.join("; "));
  });
  await c.run("B16.dynamic_entry_call", "list entry tool forwarded to its dynamic op", "op call on the list op with input {tool: entry, arguments}", async () => {
    const s0 = c.w.seqNow();
    const a = await c.callTool("free", `${peer.product}__${inside?.name}`, { q: "x" });
    const op = lastOp(c, peer, s0, list.id);
    const opInput = op ? (JSON.parse(op.body) as { input?: { tool?: unknown } }).input : undefined;
    return verdict(c.isOk(a) && !!op?.verified && opInput?.tool === inside?.name, `${describeCall(a)}; op ${op ? `tool ${String(opInput?.tool)}` : "not called"}`);
  });
}

// ── companion calls, hook re-entry, call depth (B16) ─────────────────────────
export async function companionChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("companion")) return;
  const p = c.primary;
  const peer = c.peer;
  const edge = p.manifest.companions?.[0];
  const back = peer?.manifest.companions?.[0];
  if (!peer || !edge || !back) {
    c.s.record("C1.K10_companion", "companion", "a companion edge in the example manifest", bad("no companion edge"));
    return;
  }
  await c.run("B16.slice_stale", "app with a slice older than its validity → slice_stale", "app-side state (SDK health `slice_stale`), not a bridge decision", () =>
    na("slice_stale is the app SDK's health state (SDK-API); the bridge relays slices and is asserted by B11.keys_rev / B14.slices"),
  );
  const pg = c.w.companionGrants.get(p.ins) ?? null;
  const qg = c.w.companionGrants.get(peer.ins) ?? null;
  const env = (op: string, extra: Record<string, unknown> = {}) => ({ target: peer.product, op, input: c.input(peer, op) as Json, ...extra });
  const opId = edge.operations[0] as string;
  const status = (a: HttpAnswer) => (isObj(a.body) && typeof a.body.status === "string" ? `${a.status} ${a.body.status}` : `${a.status} ${errorCode(a.body) ?? ""}`);
  await c.run("C1.K10_companion", "companion grant (app→app) path", "200 ok; the target receives a verified grant with sub = caller instance", async () => {
    const s0 = c.w.seqNow();
    const a = await p.companion(env(opId) as never, pg);
    const g = lastOp(c, peer, s0, opId);
    const fine = a.status === 200 && !!g?.verified && g.grant?.sub === `tb:ins:${p.ins}`;
    if (fine) c.evidence.set("K10c", "companion grant accepted");
    return verdict(fine, `${status(a)}; target ${g ? `verified ${g.verified}, sub ${String(g.grant?.sub)}` : "not called"}`);
  });
  await c.run("B16.companion_no_grant", "companion call without TB-Grant refused", "4xx; target not called", async () => {
    const s0 = c.w.seqNow();
    const a = await p.companion(env(opId) as never, null);
    return verdict(a.status >= 400 && a.status < 500 && !lastOp(c, peer, s0), status(a));
  });
  await c.run("B16.companion_foreign_grant", "companion grant of another instance refused", "4xx (grant sub ≠ asserting instance); target not called", async () => {
    const s0 = c.w.seqNow();
    const a = await p.companion(env(opId) as never, qg);
    return verdict(a.status >= 400 && a.status < 500 && !lastOp(c, peer, s0), status(a));
  });
  const outside = c.pick(peer, (o) => !edge.operations.includes(o.id) && !o.dynamic);
  await c.run("B16.companion_outside_wf", "companion op outside the declared companion ops refused", "4xx not_in_workflow; target not called", async () => {
    if (!outside) return bad("no op outside the companion edge");
    const s0 = c.w.seqNow();
    const a = await p.companion(env(outside.id) as never, pg);
    return verdict(errorCode(a.body) === "not_in_workflow" && !lastOp(c, peer, s0), status(a));
  });
  await c.run("B16.hook_reentry", "companion call from inside a hook of the same call → hook_reentry", "4xx hook_reentry for the nested call; the outer call completes", async () => {
    let nested: HttpAnswer | null = null;
    const backOp = back.operations[0] as string;
    peer.onHook = async (_id, phase, body) => {
      if (phase === "before" && nested === null) {
        const callId = isObj(body.call) ? String(body.call.id) : "";
        nested = await peer.companion({ target: p.product, op: backOp, input: c.input(p, backOp) as Json, parentCall: callId as never }, qg);
      }
      return { status: 200, body: phase === "before" ? { allow: true } : phase === "context" ? { add: {} } : {} };
    };
    try {
      const read = c.readOp(p);
      const a = await c.call("free", p, read?.id ?? "");
      const n = nested as HttpAnswer | null;
      return verdict(c.isOk(a) && !!n && errorCode(n.body) === "hook_reentry", `outer ${describeCall(a)}; nested ${n ? status(n) : "not made"}`);
    } finally {
      peer.onHook = null;
    }
  });
  await c.run("B16.call_depth", "companion chain deeper than 3 → call_depth_exceeded", "hops 1–3 ok, hop 4 refused with call_depth_exceeded", async () => {
    const hops: string[] = [];
    const backOp = back.operations[0] as string;
    let entered = 0;
    // the agent call enters the first app (entry 1); entry n makes companion hop n; hops beyond 4 are not attempted
    const handler = (app: FakeApp) => async (info: { call: string; op: string }) => {
      const depth = ++entered;
      if (depth <= 4) {
        const to = app === p ? peer : p;
        const op = app === p ? opId : backOp;
        const a = await app.companion({ target: to.product, op, input: c.input(to, op) as Json, parentCall: info.call as never }, app === p ? pg : qg);
        hops[depth - 1] = status(a);
      }
      return { status: 200, body: { status: "ok", output: { depth } } };
    };
    p.onOp = handler(p);
    peer.onOp = handler(peer);
    try {
      const read = c.readOp(p);
      const a = await c.call("free", p, read?.id ?? "");
      const okHops = hops.slice(0, 3).every((h) => h.startsWith("200"));
      const fourth = hops[3] ?? "";
      return verdict(c.isOk(a) && okHops && fourth.includes("call_depth_exceeded"), `outer ${describeCall(a)}; hops [${hops.join(" | ")}]`);
    } finally {
      p.onOp = null;
      peer.onOp = null;
    }
  });
}

// ── claims, status, version matrix (§5), B18, scope summary (B13) ────────────
async function assertedStatus(c: BridgeCtx, app: FakeApp, over: { aud?: string; key?: FakeApp["key"] }): Promise<HttpAnswer> {
  const path = "/tb/v1/status?wait=0";
  const body = new TextEncoder().encode(JSON.stringify({ readiness: "ready", version: app.manifest.version, sdkVersion: `${app.manifest.sdkMajor}.0.0`, scopesRev: 1, sliceRevision: 0, keysRev: 0, pendingHolds: 0 }));
  const ref = `tb:ins:${app.ins}` as const;
  const t = over.aud
    ? await signAssertion(TYP.instanceAssertion, { iss: ref, sub: ref, aud: over.aud as `tb:brg:brg_${string}`, iat: nowS() }, over.key ?? app.key, { method: "POST", pathAndQuery: path, body })
    : await signInstanceAssertion({ key: over.key ?? app.key, ins: app.ins, bridge: c.w.bridgeId, method: "POST", pathAndQuery: path, body, now: nowS() });
  return request(`${c.int}${path}`, { method: "POST", headers: { "content-type": "application/json", [BRIDGE_HEADERS.assertion]: t }, body });
}

export async function claimChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("claim")) return;
  const p = c.primary;
  const { generateKeyPair } = await import("@opt2-tealbrick/manifest");
  const codes = [c.w.newClaimCode(), c.w.newClaimCode(), c.w.newClaimCode(), c.w.newClaimCode()];
  const svc = c.w.newServiceCode();
  await c.apply();
  const [k1, k2, k3, k4] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()]);
  const claimed = await p.claim(codes[0] as string, {}, k1);
  await c.run("C1.K6", "claim with a one-time enrolment code (K6)", "200 ClaimResponse {ins, bridge {id, publicKey = enrolled key}}", () => {
    const b = claimed.body as Partial<ClaimResponse>;
    const jwk = c.w.bridgeJwk();
    const fine = claimed.status === 200 && b.ins === p.ins && b.bridge?.id === c.w.bridgeId && !!jwk && !!b.bridge?.publicKey && thumbprint(b.bridge.publicKey) === thumbprint(jwk);
    if (fine) c.evidence.set("K6", "claim accepted");
    return verdict(fine, `${claimed.status} ins ${b.ins === p.ins ? "ok" : String(b.ins)}; bridge key ${b.bridge?.publicKey && jwk && thumbprint(b.bridge.publicKey) === thumbprint(jwk) ? "= enrolled" : "≠"}`);
  });
  await c.run("C6.claim_replay", "enrolment code reused → code_invalid", "4xx code_invalid", async () => httpRefused(await p.claim(codes[0] as string, {}, k1), ["code_invalid"]));
  await c.run("V5.sdk_0x_served", "SDK 0.x claim accepted (0.x counts as major 1, C44)", "claim with sdkVersion 0.1.2 → 200", async () => {
    const a = await p.claim(codes[1] as string, { sdkVersion: "0.1.2" }, k2);
    return verdict(a.status === 200, `${a.status} ${errorCode(a.body) ?? ""}`);
  });
  await c.run("V5.sdk_major_unsupported", "unserved SDK major → sdk_major_unsupported", "claim with sdkVersion 3.0.0 → 4xx sdk_major_unsupported", async () => httpRefused(await p.claim(codes[2] as string, { sdkVersion: "3.0.0" }, k3), ["sdk_major_unsupported"]));
  await c.run("V5.manifest_mismatch", "claim with a foreign manifest digest → manifest_mismatch", "4xx manifest_mismatch", async () => httpRefused(await p.claim(codes[3] as string, { manifestDigest: digest({ conformance: ulid() }) as never }, k4), ["manifest_mismatch"]));
  await c.run("B3.claim_reported", "claims reported in the status report (digest only)", "an ack lists claims[] {ins, codeDigest = sha256(code), publicKey}; no clear code", async () => {
    const { opaqueDigest } = await import("@opt2-tealbrick/manifest");
    const d = opaqueDigest(codes[0] as string);
    const r = await c.until(async () => c.w.portal.acks.some((a) => (a.claims ?? []).some((x) => x.ins === p.ins && x.codeDigest === d)), c.h.timeoutMs);
    const clear = c.w.portal.captured.some((x) => codes.some((code) => x.body.includes(code)));
    return verdict(!!r.value && !clear, `${r.value ? "reported" : "not reported"}; clear code sent to Portal: ${clear}`);
  });
  await c.run("B19.service_keys_when", "service claim answer lists only the keys in force for the deployed settings", "ClaimResponse.serviceKeys = settings.keys used by the service whose `when` holds (activeKeyRequirements); a key whose `when` is false is absent", async () => {
    if (!svc) return bad("example manifest declares no runtime service");
    const want = activeKeyRequirements(p.manifest, deployedSettings(p.manifest), svc.service).map((k) => k.name).sort();
    const declared = (p.manifest.settings?.keys ?? []).filter((k) => k.usedBy.includes(svc.service)).map((k) => k.name);
    if (declared.length <= want.length) return bad(`derived manifest has no service key whose when is false (declared ${declared.join(",")})`);
    const a = await p.claim(svc.code, { service: svc.service }, await generateKeyPair());
    const b = isObj(a.body) ? (a.body as Partial<ClaimResponse>) : {};
    const got = (b.serviceKeys ?? []).map((k) => k.name).sort();
    const envOk = (b.serviceKeys ?? []).every((k) => typeof k.env === "string" && k.env.length > 0);
    return verdict(a.status === 200 && got.join(",") === want.join(",") && envOk, `${a.status} ${errorCode(a.body) ?? ""}; serviceKeys [${got.join(",")}], in force [${want.join(",")}], declared for the service [${declared.join(",")}]`);
  });
  await c.run("C1.K8", "status push with an instance assertion (K8) accepted", "2xx", async () => {
    const a = await p.status({}, 0);
    if (a.status === 200 || a.status === 204) c.evidence.set("K8", "status accepted");
    return verdict(a.status === 200 || a.status === 204, `${a.status}`);
  });
  await c.run("C2.instance_assert_aud_foreign", "instance assertion for another bridge refused", "401", async () => {
    const a = await assertedStatus(c, p, { aud: `tb:brg:${newId("brg")}` });
    return verdict(a.status === 401, `${a.status}`);
  });
  await c.run("C5.instance_assert_unknown_key", "instance assertion by a key not in instanceKeys refused", "401", async () => {
    const a = await assertedStatus(c, p, { key: c.w.stranger });
    return verdict(a.status === 401, `${a.status}`);
  });
  await c.run("B18.pending_holds", "pendingHolds count reaches the status report", "ack apps[] entry for the instance carries pendingHolds = the pushed count; no hold content", async () => {
    await p.status({ pendingHolds: 7 }, 0);
    const r = await c.until(async () => c.w.portal.acks.find((a) => (a.apps ?? []).some((x) => x.ins === p.ins && x.pendingHolds === 7)), c.h.timeoutMs);
    const holdLeak = c.w.portal.captured.some((x) => /hld_[0-9A-Z]{26}/.test(x.body));
    return verdict(!!r.value && !holdLeak, `${r.value ? "pendingHolds 7 reported" : "not reported"}; hold ids sent to Portal: ${holdLeak}`);
  });
  await c.run("B13.scope_summary", "scopesRev change → scope-summary bridge op; labels in the status report", "verified bridge-op scope_summary (no grant); ack scopeSummaries {agt, ins, label}", async () => {
    const label = "Conformance scope label";
    p.scopeSummary = () => [{ agent: c.w.agents.free.agt as AgentId, label }];
    const s0 = c.w.seqNow();
    await p.status({ scopesRev: 2 + Math.floor(Math.random() * 1000) }, 0);
    const call = await c.until(async () => c.since(p, s0, "bridge_op").find((x) => x.name === "scope_summary"), c.h.timeoutMs);
    const rep = await c.until(async () => c.w.portal.acks.some((a) => (a.scopeSummaries ?? []).some((x) => x.ins === p.ins && x.label === label)), c.h.timeoutMs);
    const v = call.value;
    return verdict(!!v?.verified && v.variant === "bop" && !("authorization" in (v.headers ?? {})) && !!rep.value, `bridge op ${v ? `verified ${v.verified}, variant ${v.variant}` : "not called"}; reported ${!!rep.value}`);
  });
}

export const B13_VARIANTS = async (c: BridgeCtx): Promise<void> => {
  if (!c.on("scan")) return;
  await c.run("B13.variants", "op routes get op proofs, bridge-op routes get bridge-op proofs, hooks get hook proofs", "every request the fake apps received carries the proof variant of its route", () => {
    const all = c.w.apps.flatMap((a) => a.received);
    const wrong = all.filter((r) => (r.kind === "op" && r.variant !== "op") || (r.kind === "bridge_op" && r.variant !== "bop") || (r.kind === "hook" && r.variant !== "hook"));
    const n = all.filter((r) => r.kind === "op" || r.kind === "bridge_op" || r.kind === "hook").length;
    return verdict(n > 0 && wrong.length === 0, `${n} requests; wrong variant [${wrong.map((r) => `${r.kind}:${r.name}:${r.variant}`).slice(0, 8).join(",")}]`);
  });
};

export { type InstanceId, ok, rpcMessages, sleep };
