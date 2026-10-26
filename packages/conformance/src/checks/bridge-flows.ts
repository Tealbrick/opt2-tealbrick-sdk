// Bridge target checks, part 2 (CONFORMANCE §4.4 / §4.3): key page and key fetch (B11), OAuth AS and pairing paths
// A and B (B12, B15), signed config handling (B3, C5 rotation), the pause and revocation matrix at the bridge (P1,
// P3), list_changed (B7), Portal down and the 12 h rule (B4), restart and re-enrolment (B2), standalone handover
// (B14) and the closing scans (B9, C4 payload scan, B11 logs / sealed store, C7 lifetimes, C1 summary).
import { mkdirSync, readdirSync, readFileSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";
import { type Ed25519KeyPair, generateKeyPair, opaqueDigest, opaqueValue, signAssertion, thumbprint, ulid, verifyAgentSession, verifyAssertion, verifyKeysTicket, verifySlice } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, STANDALONE_ADMIN_PATHS } from "@opt2-tealbrick/spec/bridge";
import { LIFETIME_S, OAUTH_GRANT_TYPES, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { CapturedPayload } from "../fake-bridge.ts";
import { errorCode, type HttpAnswer, listen, request } from "../http.ts";
import { type HtmlForm, type OAuthClient, parseForms, pkcePair, redirectParams } from "../mcp-agent.ts";
import { PERSON_OP_RESULT_PATH_RE, PERSON_OPS_CAP, PERSON_OPS_PATH } from "../person-op.ts";
import type { PayloadScan } from "../report.ts";
import { type ScanNeedle, scanPayloads } from "../scan.ts";
import { bad, notRun, type Outcome, ok, verdict } from "../suite.ts";
import { Mint, newId, nowS, peek, rawSign } from "../tokens.ts";
import { enrolRequests } from "./bridge.ts";
import { type BridgeCtx, describeCall, httpRefused, isObj, type KeySlot, sleep, toolRefused } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

const JWS_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g;
const typOf = (t: string): string | null => {
  try {
    const h = JSON.parse(Buffer.from(t.split(".")[0] ?? "", "base64url").toString("utf8")) as { typ?: unknown };
    return typeof h.typ === "string" ? h.typ : null;
  } catch {
    return null;
  }
};
/** first compact JWS with header `typ` found anywhere in `text` */
const findJws = (text: string, typ: string): string | null => [...text.matchAll(JWS_RE)].map((m) => m[0]).find((t) => typOf(t) === typ) ?? null;

// BRIDGE §6.3 rate limit: authorize 20/min/IP. The suite stays below it (18 per rolling minute per bridge origin) so a
// refusal it observes is the bridge's verdict on the input, never the rate limiter.
const AUTHORIZE_LOG = new Map<string, number[]>();
async function authorizeSlot(url: string): Promise<void> {
  const u = new URL(url);
  if (u.pathname !== "/oauth/authorize") return;
  const log = AUTHORIZE_LOG.get(u.origin) ?? [];
  AUTHORIZE_LOG.set(u.origin, log);
  for (;;) {
    const now = Date.now();
    while (log.length && now - (log[0] as number) > 61_000) log.shift();
    if (log.length < 18) {
      log.push(now);
      return;
    }
    await sleep(61_000 - (now - (log[0] as number)) + 100);
  }
}

// ── a tiny browser: cookies across a page flow (the spec fixes the flow, not the form field names) ──
class Browser {
  readonly jar = new Map<string, string>();
  readonly setCookies: string[] = [];
  absorb(a: HttpAnswer): HttpAnswer {
    for (const c of a.headers.getSetCookie?.() ?? []) {
      this.setCookies.push(c);
      const [pair] = c.split(";");
      const i = (pair ?? "").indexOf("=");
      if (i > 0) this.jar.set((pair as string).slice(0, i).trim(), (pair as string).slice(i + 1).trim());
    }
    return a;
  }
  cookie(): Record<string, string> {
    return this.jar.size ? { cookie: [...this.jar].map(([k, v]) => `${k}=${v}`).join("; ") } : {};
  }
  async get(url: string): Promise<HttpAnswer> {
    await authorizeSlot(url);
    return this.absorb(await request(url, { headers: this.cookie() }));
  }
  async post(url: string, fields: Record<string, string>, headers: Record<string, string> = {}): Promise<HttpAnswer> {
    await authorizeSlot(url);
    return this.absorb(await request(url, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...this.cookie(), ...headers }, body: new URLSearchParams(fields).toString() }));
  }
  /** follows one redirect to the bridge (relative, or absolute on the advertised origin `adv`) with the jar */
  async follow(base: string, a: HttpAnswer, adv: string = base): Promise<HttpAnswer> {
    const loc = a.headers.get("location");
    if (a.status < 300 || a.status >= 400 || !loc) return a;
    const u = new URL(loc, base);
    if (u.origin === new URL(base).origin) return this.get(u.toString());
    return u.origin === new URL(adv).origin ? this.get(`${base}${u.pathname}${u.search}`) : a;
  }
  async submit(base: string, form: HtmlForm, values: Record<string, string> = {}, headers: Record<string, string> = {}): Promise<HttpAnswer> {
    return this.post(new URL(form.action || "/", base).toString(), { ...form.fields, ...values }, headers);
  }
}

// ── B11 key page and key fetch ───────────────────────────────────────────────
export async function keyChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("keys")) return;
  const p = c.primary;
  const key = (p.manifest.settings?.keys ?? []).find((k) => k.source === "account_default" && k.usedBy.includes("app"));
  if (!key) {
    c.s.record("B11.not_set", "key fetch", "an account_default key declared by the example manifest", bad("no account_default key"));
    return;
  }
  const value = `tbconfkey${ulid()}${ulid()}`;
  c.secrets.keyValues.add(value);
  await c.run("B11.not_set", "declared key not set → key_not_set", "404 key_not_set", async () => httpRefused(await p.fetchKey(key.name), ["key_not_set"]));
  await c.run("B11.undeclared", "undeclared key → key_not_declared", "403 key_not_declared", async () => httpRefused(await p.fetchKey("CONFORMANCE_UNDECLARED_KEY"), ["key_not_declared"]));
  await c.run("B11.other_app", "key declared by another app → key_not_declared", "403 key_not_declared for an app whose manifest does not declare it", async () =>
    c.peer ? httpRefused(await c.peer.fetchKey(key.name), ["key_not_declared"]) : bad("no second app"),
  );
  await c.run("B11.no_assertion", "key fetch without an instance assertion → 401", "401", async () => {
    const a = await p.fetchKey(key.name, false);
    return verdict(a.status === 401, `${a.status}`);
  });
  const redeem = async (b: Browser, ticket: string) => {
    c.secrets.tickets.add(ticket);
    // SPEC-GAP: BRIDGE §9.3 names no form field for the keys ticket; `ticket` (the launch redeemer's field) is used.
    const a = await b.post(`${c.keysPub}/keys`, { ticket });
    return { a, page: await b.follow(c.keysPub, a, c.w.keysAdvertisedUrl) };
  };
  const redeemed = (r: { a: HttpAnswer; page: HttpAnswer }, b: Browser) => (r.a.status === 200 || (r.a.status >= 300 && r.a.status < 400)) && b.jar.size > 0 && r.page.status === 200;
  const refusedTicket = async (ticket: string): Promise<Outcome> => {
    const b = new Browser();
    const r = await redeem(b, ticket);
    return verdict(!redeemed(r, b) && r.a.status >= 400 && r.a.status < 500, `${r.a.status}; session cookie ${b.jar.size ? "SET" : "none"}`);
  };
  await c.run("B11.ticket_required", "key page needs a keys ticket", "GET /keys without a session → 4xx (or a page without the key list)", async () => {
    const a = await c.get("/keys", {}, c.keysPub);
    return verdict(a.status >= 400 || !a.text.includes(key.name), `${a.status}${a.text.includes(key.name) ? " lists keys" : ""}`);
  });
  await c.run("C3.launch_ticket_at_keys", "launch ticket refused at the key page", "4xx, no session", async () => refusedTicket(await c.w.launchTicket(p)));
  await c.run("C2.keys_ticket_aud_foreign", "keys ticket for another bridge refused", "4xx, no session", async () => refusedTicket(await c.w.keysTicket({ aud: `tb:brg:${newId("brg")}` })));
  await c.run("C5.keys_ticket_unannounced_kid", "keys ticket signed by an unknown key refused", "4xx, no session", async () => refusedTicket(await c.w.keysTicket({ key: c.w.stranger })));
  await c.run("C5.keys_ticket_expired", "expired keys ticket refused", "4xx, no session", async () => refusedTicket(await c.w.keysTicket({ iat: nowS() - 600 })));
  const b = new Browser();
  const ticket = await c.w.keysTicket();
  const r = await redeem(b, ticket);
  await c.run("C1.K11", "keys ticket (K11 pur: keys) opens a key-page session", "200 (or redirect) with a session cookie, then the page (the no-redirect rule is B11.ticket_post_is_form, C52)", () => {
    const fine = redeemed(r, b);
    if (fine) c.evidence.set("K11", "keys ticket redeemed");
    return verdict(fine, `${r.a.status} → page ${r.page.status}; cookies ${b.jar.size}`);
  });
  const https = c.w.keysAdvertisedUrl.startsWith("https:");
  await c.run("B11.cookie_flags", "key-page cookie: HttpOnly, Secure, SameSite=Strict, Path=/keys", `Set-Cookie with HttpOnly, SameSite=Strict, Path=/keys${https ? ", Secure" : " (Secure not required: the advertised public URL of this run is http)"}`, () => {
    const sc = b.setCookies[0] ?? "";
    const has = (re: RegExp) => re.test(sc);
    const fine = has(/;\s*HttpOnly/i) && (!https || has(/;\s*Secure/i)) && has(/;\s*SameSite=Strict/i) && has(/;\s*Path=\/keys\b/i);
    return verdict(fine, sc ? sc.replace(/=[^;]*/, "=…") : "no Set-Cookie");
  });
  await c.run("B11.ticket_post_is_form", "keys-ticket POST is answered with the key form itself (C52)", "200 (no 3xx) + Set-Cookie SameSite=Strict on that response + the response body is the key form (names the key, has a POST form)", () => {
    const sc = r.a.headers.get("set-cookie") ?? "";
    const isForm = r.a.status === 200 && r.a.text.includes(key.name) && parseForms(r.a.text).some((f) => f.method === "post");
    const strict = /;\s*SameSite=Strict/i.test(sc);
    const fine = r.a.status === 200 && isForm && strict;
    const why = r.a.status >= 300 && r.a.status < 400 ? " (redirect: browsers drop the Strict cookie in a chain started by a cross-site POST)" : "";
    return verdict(fine, `${r.a.status}${why}; form in POST answer ${isForm}; Strict cookie ${strict}`);
  });
  await c.run("C6.keys_ticket_replay", "keys ticket one-time", "the same ticket again → 4xx, no session", async () => refusedTicket(ticket));
  await c.run("B11.page_lists", "page lists the account_default requirements, never values", "page names the key and shows no value", () => verdict(r.page.text.includes(key.name), `${r.page.status}; names ${key.name}: ${r.page.text.includes(key.name)}`));
  let submitted: HttpAnswer | null = null;
  await c.run("B11.set_and_fetch", "value written on the page reaches a declaring app via /tb/v1/keys", "app fetch → 200 {name, value, keysRev ≥ 1}, Cache-Control: no-store", async () => {
    const forms = parseForms(r.page.text).filter((f) => f.method === "post");
    // the form for this key: one naming it (field name or hidden value) with a user-fillable input
    const form = forms.find((f) => f.visible.length >= 1 && (f.visible.some((v) => v.includes(key.name)) || Object.values(f.fields).includes(key.name)));
    if (!form) return bad(`no form for ${key.name} on the page (${forms.length} POST forms)`);
    const field = form.visible.find((v) => v.includes(key.name)) ?? (form.visible[0] as string);
    const csrf = Object.entries(form.fields).find(([k]) => /csrf/i.test(k))?.[1];
    submitted = await b.submit(c.keysPub, form, { [field]: value }, csrf ? { [BRIDGE_HEADERS.csrf]: csrf } : {});
    const f = await c.until(async () => {
      const a = await p.fetchKey(key.name);
      return a.status === 200 ? a : null;
    }, c.h.timeoutMs);
    const a = f.value;
    const body = a && isObj(a.body) ? a.body : {};
    const fine = !!a && body.name === key.name && body.value === value && typeof body.keysRev === "number" && body.keysRev >= 1 && /no-store/.test(a.headers.get("cache-control") ?? "");
    return verdict(fine, `submit ${(submitted as HttpAnswer).status}; fetch ${a ? `200 value ${body.value === value ? "=" : "≠"}, keysRev ${String(body.keysRev)}, cache-control ${a.headers.get("cache-control")}` : "never 200"}`);
  });
  await c.run("B11.never_echoed", "values never echoed to the browser", "submit answer and the page afterwards carry no value", async () => {
    const after = await b.get(`${c.keysPub}/keys`);
    const s = submitted as HttpAnswer | null;
    return verdict(!!s && !s.text.includes(value) && !after.text.includes(value), `submit ${s ? (s.text.includes(value) ? "ECHOES" : "clean") : "not sent"}; page ${after.text.includes(value) ? "ECHOES" : "clean"}`);
  });
  await c.run("B11.keys_rev", "status answer carries the new keysRev", "status push with keysRev 0 → 200 AppStatusResponse with keysRev ≥ 1", async () => {
    const a = await p.status({ keysRev: 0, sliceRevision: 0 }, 5);
    const kr = isObj(a.body) ? a.body.keysRev : undefined;
    return verdict(a.status === 200 && typeof kr === "number" && kr >= 1, `${a.status} keysRev ${String(kr)}`);
  });
  await c.run("B11.status_presence", "status report carries presence booleans only", "an ack lists keys[] {name, ins, set: true} with no other field", async () => {
    const got = await c.until(async () => c.w.portal.acks.find((x) => (x.keys ?? []).some((k) => k.name === key.name && k.ins === p.ins && k.set === true)), c.h.timeoutMs);
    const entries = got.value?.keys ?? [];
    const extra = entries.filter((k) => Object.keys(k).sort().join(",") !== "ins,name,set");
    return verdict(!!got.value && extra.length === 0, `${got.value ? "set: true reported" : "not reported"}; entries with other fields ${extra.length}`);
  });
}

// ── B11b key page on its own origin (BRIDGE §3.1 / §9.3 v0.1.10, C59) ──────────
/** `form-action` of a CSP header is exactly `'self'` */
export function cspFormActionSelf(csp: string | null): boolean {
  const d = (csp ?? "")
    .split(";")
    .map((x) => x.trim().split(/\s+/))
    .find((x) => x[0]?.toLowerCase() === "form-action");
  return !!d && d.length === 2 && d[1] === "'self'";
}

export async function keysOriginChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("keys_origin")) return;
  const p = c.primary;
  const keysPub = c.keysPub;
  if (!keysPub) {
    for (const x of ["B11.main_origin_keys_404", "B11.keys_origin_only", "B11.keys_origin_csp", "B11.keys_origin_unset_503"]) c.s.record(x, "key page origin", "TB_KEYS_PUBLIC_URL set by the suite", bad("no keys origin in the bridge env"));
    return;
  }
  if (new URL(keysPub).hostname === new URL(c.pub).hostname) {
    for (const x of ["B11.main_origin_keys_404", "B11.keys_origin_only", "B11.keys_origin_csp", "B11.keys_origin_unset_503"]) c.s.record(x, "key page origin", "the harness public URL differs in host name from the keys origin", bad(`harness publicUrl ${c.pub} uses the keys host name`));
    return;
  }
  const ticket = async () => {
    const t = await c.w.keysTicket();
    c.secrets.tickets.add(t);
    return t;
  };
  await c.run("B11.main_origin_keys_404", "main origin answers 404 for /keys (C59)", "GET /keys and a valid keys-ticket POST /keys on the main origin (TB_PUBLIC_URL host) → 404, no session cookie", async () => {
    const g = await c.get("/keys");
    const f = await c.form("/keys", { ticket: await ticket() });
    const cookie = f.headers.getSetCookie?.().length ?? 0;
    return verdict(g.status === 404 && f.status === 404 && cookie === 0, `GET ${g.status}; ticket POST ${f.status}; cookies ${cookie}`);
  });
  await c.run("B11.keys_origin_only", "keys origin serves only /keys, /healthz, /readyz (C59)", "on the keys origin: /a/*, /mcp, /oauth/*, OAuth metadata, /p/* → 404 (a launch ticket reaches no app); /healthz and /readyz → 200", async () => {
    const route = p.manifest.publicRoutes?.[0];
    const probes: [string, string, Record<string, string> | null][] = [
      ["GET", `/a/${p.product}/`, null],
      ["POST", `/a/${p.product}/tb/launch`, { ticket: await c.w.launchTicket(p) }],
      ["POST", "/mcp", null],
      ["GET", "/oauth/authorize", null],
      ["POST", "/oauth/token", { grant_type: "client_credentials" }],
      ["POST", "/oauth/register", null],
      ["GET", "/.well-known/oauth-authorization-server", null],
      ["GET", "/.well-known/oauth-protected-resource", null],
      ...(route ? [[route.purpose === "webhook" ? "POST" : "GET", `/p/${p.product}${route.path}`, null] as [string, string, null]] : []),
    ];
    const s0 = c.w.seqNow();
    const seen: string[] = [];
    for (const [m, path, fields] of probes) {
      const a = m === "GET" ? await c.get(path, {}, keysPub) : fields ? await c.form(path, fields, {}, keysPub) : await c.post(path, "{}", { "content-type": "application/json" }, keysPub);
      seen.push(`${m} ${path} ${a.status}`);
    }
    const reached = c.everyApp(s0).length;
    const h = await c.get("/healthz", {}, keysPub);
    const r = await c.get("/readyz", {}, keysPub);
    const fine = seen.every((x) => x.endsWith(" 404")) && reached === 0 && h.status === 200 && r.status === 200;
    return verdict(fine, `${seen.join("; ")}; apps reached ${reached}; healthz ${h.status}, readyz ${r.status}`);
  });
  await c.run("B11.keys_origin_csp", "key page carries CSP form-action 'self' (C59)", "keys-ticket POST answer (200) and the session page GET carry Content-Security-Policy with form-action 'self'", async () => {
    const t = await ticket();
    const post = await request(`${keysPub}/keys`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket: t }).toString() });
    const cookie = (post.headers.getSetCookie?.() ?? []).map((x) => x.split(";")[0]).join("; ");
    const page = cookie ? await request(`${keysPub}/keys`, { headers: { cookie } }) : null;
    const a = cspFormActionSelf(post.headers.get("content-security-policy"));
    const b = !!page && cspFormActionSelf(page.headers.get("content-security-policy"));
    return verdict(post.status === 200 && a && !!page && page.status === 200 && b, `ticket POST ${post.status} form-action 'self' ${a}; page ${page ? `${page.status} form-action 'self' ${b}` : "no session cookie"}`);
  });
  await c.run("B11.keys_origin_unset_503", "TB_KEYS_PUBLIC_URL unset → /keys 503 key page not configured (C59)", "bridge restarted without TB_KEYS_PUBLIC_URL: /keys → 503 'key page not configured' on the main origin and the keys host name; after a restart with the env back the keys origin is no longer 503", async () => {
    const restart = c.h.restart;
    if (!restart) return notRun("the bridge cannot be restarted in this mode");
    const keep = c.h.env.TB_KEYS_PUBLIC_URL as string;
    let main: HttpAnswer;
    let keys: HttpAnswer;
    try {
      await restart({ TB_KEYS_PUBLIC_URL: null });
      c.dropSessions();
      main = await c.get("/keys");
      keys = await c.get("/keys", {}, keysPub);
    } finally {
      await restart({ TB_KEYS_PUBLIC_URL: keep });
      c.dropSessions();
    }
    const back = (await c.get("/keys", {}, keysPub)).status;
    const says = (a: HttpAnswer) => /key page not configured/i.test(a.text);
    const fine = main.status === 503 && keys.status === 503 && says(main) && says(keys) && back !== 503;
    return verdict(fine, `main ${main.status}${says(main) ? "" : " (no 'key page not configured')"}; keys host ${keys.status}${says(keys) ? "" : " (no 'key page not configured')"}; after restoring the env /keys ${back}`);
  });
}

// ── B12 OAuth AS, B15 pairing path A ─────────────────────────────────────────
interface Flow {
  client: OAuthClient;
  pkce: { verifier: string; challenge: string };
  state: string;
  b: Browser;
  page: HttpAnswer;
}

export async function oauthChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("oauth")) return;
  const o = c.w.oauth;
  const pairAgent = c.w.agents.pairing;
  await c.run("B12.metadata", "RFC 9728 + RFC 8414 metadata", "resource = <public>/mcp, AS = <public>, bearer header; grants code/refresh/jwt-bearer only; auth none; PKCE S256 only", async () => {
    const pr = await c.get("/.well-known/oauth-protected-resource");
    const pr2 = await c.get("/.well-known/oauth-protected-resource/mcp");
    const as = await c.get("/.well-known/oauth-authorization-server");
    const r = isObj(pr.body) ? pr.body : {};
    const m = isObj(as.body) ? as.body : {};
    const eq = (a: unknown, b: unknown[]) => Array.isArray(a) && a.length === b.length && b.every((x) => a.includes(x));
    const grants = Array.isArray(m.grant_types_supported) ? (m.grant_types_supported as string[]) : [];
    const fine =
      pr.status === 200 &&
      pr2.status === 200 &&
      as.status === 200 &&
      r.resource === `${c.adv}/mcp` &&
      eq(r.authorization_servers, [c.adv]) &&
      eq(r.bearer_methods_supported, ["header"]) &&
      m.issuer === c.adv &&
      m.token_endpoint === `${c.adv}/oauth/token` &&
      m.authorization_endpoint === `${c.adv}/oauth/authorize` &&
      m.registration_endpoint === `${c.adv}/oauth/register` &&
      eq(grants, [OAUTH_GRANT_TYPES.authorizationCode, OAUTH_GRANT_TYPES.refreshToken, OAUTH_GRANT_TYPES.jwtBearer]) &&
      eq(m.token_endpoint_auth_methods_supported, ["none"]) &&
      eq(m.code_challenge_methods_supported, ["S256"]);
    return verdict(fine, `PR ${pr.status}/${pr2.status} resource ${String(r.resource)}; AS ${as.status} issuer ${String(m.issuer)}; grants [${grants.join(",")}]; auth [${String(m.token_endpoint_auth_methods_supported)}]; pkce [${String(m.code_challenge_methods_supported)}]`);
  });
  await c.run("B12.www_authenticate", "401 from /mcp names the resource metadata", "WWW-Authenticate: Bearer resource_metadata=\"<advertised>/.well-known/oauth-protected-resource…\"", async () => {
    const a = await c.post("/mcp", "{}", { "content-type": "application/json" });
    const h = a.headers.get("www-authenticate") ?? "";
    return verdict(a.status === 401 && /^Bearer\b/i.test(h) && h.includes(`resource_metadata="${c.adv}/.well-known/oauth-protected-resource`), `${a.status} ${h || "(no header)"}`);
  });
  const client = await o.client("Conformance connector");
  await c.run("B12.dcr", "dynamic client registration (public client)", "2xx with a client_id", () => verdict(!!client, client ? "client registered" : "registration failed"));
  await c.run("B12.dcr_limits", "DCR refuses > 5 redirect URIs, non-loopback http and confidential clients", "4xx for each", async () => {
    const six = Array.from({ length: 6 }, (_, i) => `http://127.0.0.1:5368${i}/cb`);
    const a = await o.register({ redirect_uris: six, client_name: "x", token_endpoint_auth_method: "none" });
    const b = await o.register({ redirect_uris: ["http://conformance.example/cb"], client_name: "x", token_endpoint_auth_method: "none" });
    const d = await o.register({ redirect_uris: ["http://127.0.0.1:53682/cb"], client_name: "x", token_endpoint_auth_method: "client_secret_basic" });
    const r = (x: HttpAnswer) => x.status >= 400 && x.status < 500;
    return verdict(r(a) && r(b) && r(d), `6 uris ${a.status}; http non-loopback ${b.status}; confidential ${d.status}`);
  });
  if (!client) return;
  const start = async (over: Partial<Parameters<typeof o.authorizeUrl>[1]> = {}, cl: OAuthClient = client): Promise<Flow> => {
    const pkce = pkcePair();
    const state = `st${ulid()}`;
    const b = new Browser();
    const page = await b.get(o.authorizeUrl(cl, { challenge: pkce.challenge, state, ...over }));
    return { client: cl, pkce, state, b, page };
  };
  const refusedAuthorize = (a: HttpAnswer) => {
    const rp = redirectParams(a);
    return (a.status >= 400 && a.status < 500) || (!!rp && "error" in rp);
  };
  await c.run("B12.pkce_required", "authorize needs PKCE S256", "missing challenge and method plain → refused", async () => {
    const a = await start({ omit: ["code_challenge"] });
    const b = await start({ method: "plain" });
    return verdict(refusedAuthorize(a.page) && refusedAuthorize(b.page), `no challenge ${a.page.status}; plain ${b.page.status}`);
  });
  await c.run("B12.resource_required", "authorize needs resource = <public>/mcp", "foreign resource → refused", async () => {
    const a = await start({ resource: "https://conformance.example/mcp" });
    return verdict(refusedAuthorize(a.page), `${a.page.status}`);
  });
  await c.run("B12.redirect_exact", "exact redirect match except the loopback port", "other path → 4xx without redirecting there; other loopback port → page", async () => {
    const other = { ...client, redirectUri: "http://127.0.0.1:53682/conformance-other" };
    const port = { ...client, redirectUri: "http://127.0.0.1:61999/callback" };
    const a = await start({}, other);
    const b = await start({}, port);
    const loc = a.page.headers.get("location") ?? "";
    return verdict(a.page.status >= 400 && a.page.status < 500 && !loc.includes("conformance-other") && b.page.status === 200, `other path ${a.page.status}; other port ${b.page.status}`);
  });
  const f1 = await start();
  await c.run("B12.authorize_page", "authorize page shows the redirect host and the client name marked unverified", "200 page with 127.0.0.1, the client name and the word unverified", () =>
    verdict(f1.page.status === 200 && f1.page.text.includes("127.0.0.1") && f1.page.text.includes(client.clientName) && /unverified/i.test(f1.page.text), `${f1.page.status}; host ${f1.page.text.includes("127.0.0.1")}; name ${f1.page.text.includes(client.clientName)}; unverified ${/unverified/i.test(f1.page.text)}`),
  );
  const paste = async (f: Flow, code: string): Promise<HttpAnswer | null> => {
    c.secrets.pairing.add(code);
    const form = parseForms(f.page.text).find((x) => x.method === "post" && x.visible.length === 1);
    return form ? f.b.submit(c.pub, form, { [form.visible[0] as string]: code }) : null;
  };
  const codeOf = (a: HttpAnswer | null) => (a ? (redirectParams(a)?.code ?? null) : null);
  const code1 = await c.w.pairingCode("pairing");
  const pasted = await paste(f1, code1);
  const rp = pasted ? redirectParams(pasted) : null;
  await c.run("C1.K2b", "pairing code (path B) → authorization code redirect", "redirect to the registered redirect_uri with code (tbac_), state, iss = <public>", () => {
    const loc = pasted?.headers.get("location") ?? "";
    const fine = !!rp && String(rp.code).startsWith("tbac_") && rp.state === f1.state && rp.iss === c.adv && loc.startsWith(client.redirectUri);
    if (fine) c.evidence.set("K2b", "pairing code redeemed (path B)");
    return verdict(fine, pasted ? `${pasted.status} code ${rp?.code ? `${String(rp.code).slice(0, 5)}…` : "none"}, state ${rp?.state === f1.state ? "=" : "≠"}, iss ${String(rp?.iss)}` : "no paste form on the page");
  });
  const ex = rp?.code ? await o.exchange(client, rp.code, f1.pkce.verifier) : null;
  const exb = ex && isObj(ex.body) ? ex.body : {};
  const access = typeof exb.access_token === "string" ? exb.access_token : "";
  const refresh = typeof exb.refresh_token === "string" ? exb.refresh_token : "";
  if (access) c.accessTokens.add(access);
  if (refresh) c.refreshTokens.add(refresh);
  const v = access ? verifyAgentSession(access, { now: nowS(), self: c.brg as `tb:brg:brg_${string}`, ws: c.w.ws, keys: c.bridgeKeys() }) : null;
  const pairedCon = v?.ok ? v.claims.con : null;
  await c.run("B12.token_exchange", "authorization_code + PKCE → access + refresh", "200 K5 for the pairing agent (≤ 900 s) + refresh tbr_", () => {
    if (!ex) return bad("no authorization code");
    const fine = ex.status === 200 && !!v?.ok && v.claims.sub === `tb:agt:${pairAgent.agt}` && v.claims.exp - v.claims.iat <= LIFETIME_S.agentAccess && refresh.startsWith("tbr_");
    return verdict(fine, `${ex.status}; K5 ${v?.ok ? `sub ${v.claims.sub === `tb:agt:${pairAgent.agt}` ? "= pairing agent" : v.claims.sub}` : "invalid"}; refresh ${refresh ? refresh.slice(0, 4) : "none"}`);
  });
  await c.run("B12.pairing_session", "pairing connection reaches MCP with its grants", "initialize 200 and tools/list includes a read tool of the granted app", async () => {
    if (!access) return bad("no access token");
    const { McpSession } = await import("../mcp-agent.ts");
    const s = new McpSession(c.pub, access, c.w.log);
    const init = await s.initialize();
    const tools = await s.listTools();
    const read = c.readOp(c.primary);
    return verdict(init.status === 200 && !!tools && !!read && tools.includes(c.tool(c.primary, read.id)), `${init.status}; ${tools ? tools.length : "no"} tools`);
  });
  await c.run("B12.connection_reported", "new pairing connection reported in the status report", "ack connectionsCreated {con, agt, method: pairing, pairingJti, clientName}", async () => {
    const jti = String(peek(code1)?.jti ?? "");
    const r = await c.until(async () => c.w.portal.acks.some((a) => (a.connectionsCreated ?? []).some((x) => x.con === pairedCon && x.agt === pairAgent.agt && x.method === "pairing" && x.pairingJti === jti && x.clientName === client.clientName)), c.h.timeoutMs);
    return verdict(!!r.value, r.value ? "reported" : "not reported");
  });
  await c.run("C6.oauth_code_replay", "authorization code one-time", "second exchange → 400 invalid_grant", async () => (rp?.code ? httpRefused(await o.exchange(client, rp.code, f1.pkce.verifier), ["invalid_grant"]) : bad("no code")));
  await c.run("C6.pairing_replay", "pairing code one-time", "the same code on a new authorize page → no authorization code", async () => {
    const f = await start();
    const a = await paste(f, code1);
    return verdict(!!a && !codeOf(a), a ? `${a.status} ${codeOf(a) ? "CODE ISSUED" : "refused"}` : "no paste form");
  });
  const pasteRefused = async (code: string): Promise<Outcome> => {
    const f = await start();
    const a = await paste(f, code);
    return verdict(!!a && !codeOf(a), a ? `${a.status} ${codeOf(a) ? "CODE ISSUED" : "refused"}` : "no paste form");
  };
  await c.run("C2.pairing_aud_foreign", "pairing code for another bridge refused", "no authorization code", async () => pasteRefused(await c.w.pairingCode("pairing", { aud: `tb:brg:${newId("brg")}` })));
  await c.run("C5.pairing_unannounced_kid", "pairing code signed by an unknown key refused", "no authorization code", async () => pasteRefused(await c.w.pairingCode("pairing", { key: c.w.stranger })));
  await c.run("C5.pairing_expired", "expired pairing code refused", "no authorization code", async () => pasteRefused(await c.w.pairingCode("pairing", { iat: nowS() - 700 })));
  await c.run("B12.pairing_rid_on_paste", "pairing code with rid refused on path B", "no authorization code (rid present ⇔ path A)", async () => pasteRefused(await c.w.pairingCode("pairing", { rid: ulid() })));
  await c.run("B12.pkce_wrong_verifier", "wrong PKCE verifier refused", "400 invalid_grant", async () => {
    const f = await start();
    const a = await paste(f, await c.w.pairingCode("pairing"));
    const code = codeOf(a);
    return code ? httpRefused(await o.exchange(client, code, pkcePair().verifier), ["invalid_grant"]) : bad("no authorization code");
  });
  // refresh rotation (CORE I12)
  let r1 = "";
  let r2 = "";
  await c.run("B12.refresh_rotation", "refresh rotates", "200 with a new access token and a new refresh token", async () => {
    if (!refresh) return bad("no refresh token");
    const a = await o.refresh(refresh);
    const b = isObj(a.body) ? a.body : {};
    r1 = typeof b.refresh_token === "string" ? b.refresh_token : "";
    if (r1) c.refreshTokens.add(r1);
    return verdict(a.status === 200 && typeof b.access_token === "string" && !!r1 && r1 !== refresh, `${a.status}; new refresh ${r1 && r1 !== refresh}`);
  });
  await c.run("B12.refresh_grace", "previous refresh token accepted once within 30 s", "reuse of the rotated token right away → 200 (rotates again)", async () => {
    if (!refresh) return bad("no refresh token");
    const a = await o.refresh(refresh);
    const b = isObj(a.body) ? a.body : {};
    r2 = typeof b.refresh_token === "string" ? b.refresh_token : "";
    if (r2) c.refreshTokens.add(r2);
    return verdict(a.status === 200 && !!r2, `${a.status}`);
  });
  await c.run("B12.refresh_reuse_revokes", "any other reuse revokes the connection", "third use of the first token → invalid_grant; the newest refresh then refused; reported refresh_reuse", async () => {
    if (!refresh) return bad("no refresh token");
    const a = await o.refresh(refresh);
    const latest = r2 || r1;
    const b = latest ? await o.refresh(latest) : null;
    const rep = await c.until(async () => c.w.portal.acks.some((x) => (x.connectionsRevoked ?? []).some((y) => y.con === pairedCon && y.reason === "refresh_reuse")), c.h.timeoutMs);
    return verdict(httpRefused(a, ["invalid_grant"]).pass === true && !!b && httpRefused(b, ["invalid_grant"]).pass === true && !!rep.value, `reuse ${a.status}; newest ${b?.status ?? "-"}; reported ${!!rep.value}`);
  });
  await c.run("B12.revoke", "RFC 7009 revoke ends the connection", "/oauth/revoke 200; the refresh token then refused; reported client_revoke", async () => {
    const f = await start();
    const a = await paste(f, await c.w.pairingCode("pairing"));
    const code = codeOf(a);
    if (!code) return bad("no authorization code");
    const e = await o.exchange(client, code, f.pkce.verifier);
    const eb = isObj(e.body) ? e.body : {};
    const rt = String(eb.refresh_token ?? "");
    c.refreshTokens.add(rt);
    const con = typeof eb.access_token === "string" ? peek(eb.access_token)?.con : null;
    const rv = await request(`${c.pub}/oauth/revoke`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ token: rt, token_type_hint: "refresh_token" }).toString() });
    const after = await o.refresh(rt);
    const rep = await c.until(async () => c.w.portal.acks.some((x) => (x.connectionsRevoked ?? []).some((y) => y.con === con && y.reason === "client_revoke")), c.h.timeoutMs);
    return verdict(rv.status === 200 && httpRefused(after, ["invalid_grant"]).pass === true && !!rep.value, `revoke ${rv.status}; refresh after ${after.status}; reported ${!!rep.value}`);
  });

  // ── B15 path A (Approve in Portal) ──
  const portalOrigin = new URL(c.w.portal.url).origin;
  const stateForm = async (f: Flow): Promise<{ form: HtmlForm; state: string } | null> => {
    const scan = (text: string) => {
      for (const form of parseForms(text)) {
        const st = Object.values(form.fields).find((v) => typOf(v) === TYP.pairState);
        if (st && /\/pair$/.test(new URL(form.action || "/", c.pub).pathname)) return { form, state: st };
      }
      return null;
    };
    const direct = scan(f.page.text);
    if (direct) return direct;
    const approve = parseForms(f.page.text).find((x) => x.method === "post" && x.visible.length === 0 && new URL(x.action || "/", c.pub).origin === new URL(c.pub).origin);
    if (!approve) return null;
    const a = await f.b.submit(c.pub, approve);
    const page = await f.b.follow(c.pub, a, c.adv);
    if (process.env.TB_CONFORMANCE_DEBUG) process.stderr.write(`[B15] approve → ${a.status}\n${page.text.slice(0, 1500)}\n`);
    return scan(page.text);
  };
  const t0 = Date.now();
  const fa = await start();
  const sf = await stateForm(fa);
  const st = sf ? verifyAssertion(sf.state, c.bridgeKeys(), { typ: TYP.pairState, aud: "tb:portal", now: nowS() }) : null;
  const claims = st?.ok ? (st.claims as unknown as Record<string, unknown>) : null;
  if (sf) c.evidence.set("pairState", sf.state);
  await c.run("B15.state", "Approve in Portal: bridge-signed pairing state to <portal>/pair", "form POST to the Portal /pair with a tb-pair-state+jwt (bridge key, aud tb:portal, rid, ret = own callback, rh, cn, ≤ 600 s)", () => {
    if (!sf) return bad("no form posting a pairing state to /pair");
    if (!claims) return bad(`state does not verify with the bridge key: ${st && !st.ok ? st.reason : "?"}`);
    const life = Number(claims.exp) - Number(claims.iat);
    const toPortal = new URL(sf.form.action, c.pub).origin === portalOrigin || new URL(sf.form.action, c.pub).pathname === "/pair";
    const fine = typeof claims.rid === "string" && claims.ret === `${c.adv}/oauth/pair/callback` && (claims.rh === "127.0.0.1" || claims.rh === "127.0.0.1:53682") && claims.cn === client.clientName && life <= LIFETIME_S.pairState && toPortal;
    return verdict(fine, `action ${sf.form.action}; ret ${String(claims.ret)}; rh ${String(claims.rh)}; cn ${String(claims.cn)}; lifetime ${life}s`);
  });
  const callback = async (f: Flow, ret: string, code: string) => {
    c.secrets.pairing.add(code);
    return f.b.post(c.local(ret), { code });
  };
  let k2bA = "";
  await c.run("B15.callback", "Portal's form POST of a K2b with rid completes the authorization", "POST <ret> code=<K2b with rid> → redirect with code/state/iss; exchange → K5", async () => {
    if (!claims) return bad("no pairing state");
    k2bA = await c.w.pairingCode("pairing", { rid: String(claims.rid) });
    const a = await callback(fa, String(claims.ret), k2bA);
    const p = redirectParams(a);
    if (!p?.code || p.state !== fa.state) return bad(`${a.status} ${p ? JSON.stringify(Object.keys(p)) : "no redirect"}`);
    const e = await o.exchange(client, p.code, fa.pkce.verifier);
    const eb = isObj(e.body) ? e.body : {};
    if (typeof eb.access_token === "string") c.accessTokens.add(eb.access_token);
    if (typeof eb.refresh_token === "string") c.refreshTokens.add(eb.refresh_token);
    return verdict(e.status === 200 && typeof eb.access_token === "string", `callback ${a.status}; exchange ${e.status}`);
  });
  await c.run("B15.no_portal_call", "no bridge→Portal server call on path A", "Portal saw only config / ack traffic during the flow", () => {
    const during = c.w.portal.captured.filter((x) => x.at >= t0 && !/^\/api\/v1\/bridge\/(config|ack)/.test(x.path));
    return verdict(during.length === 0, during.length ? `unexpected: ${during.map((x) => `${x.method} ${x.path}`).join(", ")}` : "none");
  });
  await c.run("B15.code_one_time", "the same K2b at the callback twice refused", "no second authorization code", async () => {
    if (!k2bA || !claims) return bad("no path A code");
    const a = await callback(fa, String(claims.ret), k2bA);
    return verdict(!redirectParams(a)?.code, `${a.status}`);
  });
  await c.run("B15.rid_mismatch", "K2b whose rid is not the pending request refused", "no authorization code", async () => {
    const f = await start();
    const s2 = await stateForm(f);
    const cl = s2 ? (peek(s2.state) ?? {}) : {};
    if (!s2) return bad("no pairing state");
    const a = await callback(f, String(cl.ret), await c.w.pairingCode("pairing", { rid: ulid() }));
    return verdict(!redirectParams(a)?.code, `${a.status}`);
  });
  await c.run("B15.rid_missing", "K2b without rid at the path-A callback refused", "no authorization code", async () => {
    const f = await start();
    const s2 = await stateForm(f);
    const cl = s2 ? (peek(s2.state) ?? {}) : {};
    if (!s2) return bad("no pairing state");
    const a = await callback(f, String(cl.ret), await c.w.pairingCode("pairing"));
    return verdict(!redirectParams(a)?.code, `${a.status}`);
  });
}

// ── B3 config handling, C5 Portal key rotation ───────────────────────────────
export async function configChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("config")) return;
  const p = c.primary;
  const read = c.readOp(p);
  const lastAck = () => c.w.portal.acks.at(-1);
  await c.run("B3.applied", "signed config applied and acknowledged", "ack with rev = the published revision", async () => {
    const r = await c.apply();
    const fine = r.acked;
    if (fine) c.evidence.set("K9", "config applied");
    return verdict(fine, `rev ${r.rev} ${r.acked ? "acked" : "not acked"}`);
  });
  await c.run("B3.ack_shape", "status report shape: ids, versions, apps, presence booleans", "bridge.id, version, form, boot, sdkMajors ∋ 1, mcpVersions; an apps[] entry per instance; keys[] booleans", () => {
    const a = lastAck();
    if (!a) return bad("no ack");
    const insOk = c.w.apps.every((x) => (a.apps ?? []).some((y) => y.ins === x.ins));
    const fine = a.bridge?.id === c.w.bridgeId && typeof a.bridge.version === "string" && typeof a.bridge.boot === "string" && (a.bridge.sdkMajors ?? []).includes(1) && Array.isArray(a.bridge.mcpVersions) && a.bridge.mcpVersions.length > 0 && insOk && (a.keys ?? []).every((k) => typeof k.set === "boolean");
    return verdict(fine, `bridge ${a.bridge?.id === c.w.bridgeId ? "id ok" : "id ≠"} v${a.bridge?.version} sdkMajors [${a.bridge?.sdkMajors}] mcp [${a.bridge?.mcpVersions}]; apps ${insOk ? "all" : "missing"}`);
  });
  const stillWorks = async (): Promise<string | null> => {
    if (!read) return "no read op";
    const r = await c.call("free", p, read.id);
    return c.isOk(r) ? null : describeCall(r);
  };
  const forged = async (label: string, over: Parameters<typeof c.w.serveForged>[0]): Promise<Outcome> => {
    const seen = c.w.portal.acks.length;
    const rev = await c.w.serveForged({ ...over, body: { pause: { workspace: true, agents: [], instances: [] }, ...(over.body ?? {}) } });
    await sleep(2500);
    const broke = await stillWorks();
    const ackedForged = c.w.portal.acks.slice(seen).some((a) => a.rev === rev);
    return verdict(!broke && !ackedForged, `${label}: ${broke ? `pause applied (${broke})` : "last good kept"}; forged rev ${ackedForged ? "ACKED" : "not acked"}`);
  };
  await c.run("B3.bad_signature", "config signed by an untrusted key dropped", "last good config kept (the forged pause has no effect)", () => forged("stranger key", { key: c.w.stranger }));
  await c.run("B3.lower_rev", "config with a lower revision refused", "last good config kept", () => forged("lower rev", { rev: Math.max(1, (lastAck()?.rev ?? 2) - 1) }));
  await c.run("B3.foreign_workspace", "config for another workspace refused", "last good config kept", () => forged("foreign ws", { body: { ws: newId("ws") as never } }));
  await c.run("B3.foreign_audience", "config for another bridge refused", "last good config kept", () => forged("foreign aud", { body: { aud: `tb:brg:${newId("brg")}` as never, sub: `tb:brg:${newId("brg")}` as never } }));
  await c.run("B3.expired", "expired config refused", "last good config kept", () => forged("expired", { iat: nowS() - LIFETIME_S.configOrSlice - 300 }));
  await c.run("B3.recovers", "a valid revision after refused documents applies", "ack of the next valid revision; calls keep working", async () => {
    const r = await c.apply();
    const broke = await stillWorks();
    return verdict(r.acked && !broke, `rev ${r.rev} ${r.acked ? "acked" : "not acked"}${broke ? `; ${broke}` : ""}`);
  });
  await c.run("B3.bad_grant_dropped", "a bad grant entry is dropped and reported, not the whole document", "document applied (ack); rejected[] carries grant_invalid; other grants work", async () => {
    await c.w.publish();
    const bogus = await c.w.mint.grant({ sub: `tb:agt:${c.w.agents.free.agt}`, aud: `tb:ins:${p.ins}`, crud: ["read"], mode: "free", key: c.w.stranger });
    c.w.portal.configExtra = { ...c.w.portal.configExtra, grants: [...(c.w.portal.configExtra.grants ?? []), bogus] };
    const rev = await c.w.portal.mintRevision();
    const acked = await c.w.waitAck(rev, c.h.timeoutMs);
    const rej = await c.until(async () => c.w.portal.acks.some((a) => (a.rejected ?? []).some((x) => x.code === "grant_invalid")), c.h.timeoutMs);
    const broke = await stillWorks();
    return verdict(acked && !!rej.value && !broke, `rev ${rev} ${acked ? "acked" : "not acked"}; grant_invalid ${rej.value ? "reported" : "not reported"}${broke ? `; ${broke}` : ""}`);
  });
  await c.run("C5.portal_key_rotation", "announced Portal key accepted after activation; retired key dropped", "configs signed by the newly active (previously pending) key applied; grants signed by it forwarded", async () => {
    const saved = c.w.portal.keys.map((k) => ({ ...k }));
    await c.w.portal.control.rotateKey("announce");
    const a1 = await c.w.waitAck(c.w.portal.rev, c.h.timeoutMs);
    await c.w.portal.control.rotateKey("activate");
    const a2 = await c.w.waitAck(c.w.portal.rev, c.h.timeoutMs);
    const r = a2 ? await c.apply() : { acked: false };
    const broke = r.acked ? await stillWorks() : "not reached";
    let r2 = { acked: false };
    let broke2: string | null = "not reached";
    if (r.acked && !broke) {
      await c.w.portal.control.rotateKey("retire");
      r2 = await c.apply();
      broke2 = await stillWorks();
    }
    const fine = a1 && a2 && r.acked && r2.acked && !broke && !broke2;
    if (!fine) {
      // keep the rest of the run meaningful: back to the key the bridge still trusts
      c.w.portal.keys = saved;
      await c.apply();
    }
    return verdict(fine, `announce ${a1 ? "acked" : "not acked"}; activate ${a2 ? "acked" : "NOT applied"}; re-minted ${r.acked}; retire ${r2.acked}${broke ? `; calls: ${broke}` : ""}${!broke && broke2 ? `; after retire: ${broke2}` : ""}`);
  });
  await c.apply();
}

// ── P1 pause matrix at the bridge, P3 agent revocation ───────────────────────
async function refusedWithin(c: BridgeCtx, fn: () => Promise<Outcome>): Promise<{ o: Outcome; ms: number }> {
  let last: Outcome = bad("not tried");
  const r = await c.until(async () => {
    last = await fn();
    return last.pass === true ? last : null;
  }, c.h.pauseLatencyMs);
  return { o: r.value ?? last, ms: r.ms };
}

export async function pauseChecks(c: BridgeCtx): Promise<void> {
  const p = c.primary;
  const peer = c.peer;
  const read = c.readOp(p);
  const lat = `≤ ${c.h.pauseLatencyMs / 1000} s`;
  if (!read) return;
  const key = (p.manifest.settings?.keys ?? []).find((k) => k.source === "account_default")?.name ?? "CONFORMANCE_KEY";
  const callOk = async (slot: KeySlot, app = p, op = read.id) => {
    const r = await c.call(slot, app, op);
    return verdict(c.isOk(r), describeCall(r));
  };
  const launch = async () => {
    const t = await c.w.launchTicket(p);
    c.secrets.tickets.add(t);
    const s0 = c.w.seqNow();
    const a = await c.form(`/a/${p.product}/tb/launch`, { ticket: t });
    return { a, reached: c.since(p, s0, "ui").length > 0 };
  };
  const keysPage = async () => {
    const t = await c.w.keysTicket();
    c.secrets.tickets.add(t);
    return c.keysForm(t);
  };
  const restore = async (label: string) => {
    await c.apply();
    await c.run(`${label}.restored`, "pause lifted", `calls work again ${lat} after the unpause revision`, async () => {
      const r = await c.until(async () => ((await callOk("free")).pass ? true : null), c.h.pauseLatencyMs);
      return verdict(!!r.value, r.value ? `ok after ${r.ms} ms` : "still refused after unpause");
    });
  };

  if (c.on("pause.workspace")) {
    c.w.portal.pause.workspace = true;
    await c.apply();
    const s0 = c.w.seqNow();
    const m = await refusedWithin(c, async () => toolRefused(await c.call("free", p, read.id), ["paused"]));
    await c.run("P1.workspace.mcp", "kill switch: MCP tools/call refused paused", `isError paused ${lat}`, () => verdict(m.o.pass === true, `${m.o.asserted} after ${m.ms} ms`));
    await c.run("P1.workspace.no_app_traffic", "kill switch: no hook or op call reaches any app", "no op / hook requests while paused", () => {
      const n = c.everyApp(s0, "op").length + c.everyApp(s0, "hook").length;
      return verdict(n === 0, `${n} requests`);
    });
    await c.run("P1.workspace.tools_list", "kill switch: tools/list empty, instructions say paused", "empty list; initialize.instructions mention paused", async () => {
      const s = await c.session("free", true);
      const tools = await s.listTools();
      return verdict(!!tools && tools.length === 0 && /paused/i.test(s.instructions), `${tools?.length ?? "-"} tools; instructions ${/paused/i.test(s.instructions) ? "say paused" : "silent"}`);
    });
    await c.run("P1.workspace.companion", "kill switch: companion call refused", "4xx paused", async () => {
      const edge = p.manifest.companions?.[0];
      if (!peer || !edge) return bad("no companion edge");
      return httpRefused(await p.companion({ target: peer.product, op: edge.operations[0] as string, input: c.input(peer, edge.operations[0] as string) as Json }, c.w.companionGrants.get(p.ins) ?? null), ["paused"]);
    });
    await c.run("P1.workspace.key_fetch", "kill switch: key fetch refused", "403 paused", async () => httpRefused(await p.fetchKey(key), ["paused"]));
    await c.run("P1.workspace.status_allowed", "kill switch: status push still accepted (the pause reaches the app)", "2xx", async () => {
      const a = await p.status({}, 0);
      return verdict(a.status === 200 || a.status === 204, `${a.status}`);
    });
    await c.run("P1.workspace.k5_issued", "kill switch: K5 issuance continues", "jwt-bearer → 200", async () => {
      const t = await c.w.keyAgents.free.token();
      if (t) c.accessTokens.add(t);
      return verdict(!!t, t ? "issued" : "refused");
    });
    await c.run("P1.workspace.k2b_refused", "kill switch: pairing redemption refused", "no authorization code", async () => pasteOnce(c, await c.w.pairingCode("pairing")));
    await c.run("P1.workspace.launch_up", "kill switch: person launch not paused", "launch POST proxied to the app", async () => {
      const l = await launch();
      return verdict(l.reached && l.a.status < 500, `${l.a.status}; app ${l.reached ? "reached" : "not reached"}`);
    });
    await c.run("P1.workspace.keys_page_up", "kill switch: key page not paused", "keys ticket redeemed (200 or redirect)", async () => {
      const a = await keysPage();
      return verdict(a.status === 200 || (a.status >= 300 && a.status < 400), `${a.status}`);
    });
    c.w.portal.pause.workspace = false;
    await restore("P1.workspace");
  }
  if (c.on("pause.agent")) {
    c.w.portal.pause.agents.add(c.w.agents.free.agt);
    c.w.portal.pause.agents.add(c.w.agents.pairing.agt);
    await c.apply();
    const m = await refusedWithin(c, async () => toolRefused(await c.call("free", p, read.id), ["paused"]));
    await c.run("P1.agent.mcp", "agent pause: its calls refused", `isError paused ${lat}`, () => verdict(m.o.pass === true, `${m.o.asserted} after ${m.ms} ms`));
    await c.run("P1.agent.others", "agent pause: other agents unaffected", "Bound agent call in its workflow ok", async () => {
      const wf = c.w.grantSpecs.find((g) => g.role === "bound")?.wf[0];
      return wf ? callOk("bound", p, wf) : bad("no wf");
    });
    await c.run("P1.agent.tools_list", "agent pause: tools/list empty", "empty list", async () => {
      const tools = await (await c.session("free", true)).listTools();
      return verdict(!!tools && tools.length === 0, `${tools?.length ?? "-"} tools`);
    });
    await c.run("P1.agent.k2b_refused", "agent pause: pairing code for that agent refused", "no authorization code", async () => pasteOnce(c, await c.w.pairingCode("pairing")));
    c.w.portal.pause.agents.clear();
    await restore("P1.agent");
  }
  if (c.on("pause.connection")) {
    const s2 = await c.session("free2", true);
    const con = c.w.keyAgents.free2.con;
    await c.w.portal.control.revokeConnection(con);
    await c.w.waitAck(c.w.portal.rev, c.h.timeoutMs);
    const m = await refusedWithin(c, async () => {
      const a = await request(`${c.pub}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${s2.token}`, ...(s2.sessionId ? { "mcp-session-id": s2.sessionId } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      return verdict(a.status === 401, `${a.status}`);
    });
    await c.run("P1.connection.k5_refused", "connection revoke: its K5 refused", `401 ${lat}`, () => verdict(m.o.pass === true, `${m.o.asserted} after ${m.ms} ms`));
    await c.run("P1.connection.issuance_refused", "connection revoke: no new K5 for it", "jwt-bearer → 4xx", async () => httpRefused(await c.w.keyAgents.free2.tokenAnswer()));
    await c.run("P1.connection.other_connection", "connection revoke: the agent's other connection keeps working", "call with the other key connection ok", () => callOk("free"));
    c.w.portal.connections = c.w.portal.connections.map((x) => (x.con === con ? { ...x, status: "active" as const } : x));
    await c.apply();
  }
  if (c.on("pause.instance") && peer) {
    // hook app paused: its before hooks fail closed for every call in the chain
    c.w.portal.pause.instances.add(peer.ins);
    await c.apply();
    const hooked = c.pick(p, (o) => o.idempotency === "required") ?? read;
    const s0 = c.w.seqNow();
    const hm = await refusedWithin(c, async () => toolRefused(await c.call("free", p, hooked.id), ["hook_failed", "paused"]));
    await c.run("P1.instance.hook_app_paused", "paused hook app: calls through its before hooks refused; no hook call to it", `isError hook_failed (or paused) ${lat}; the paused app receives no hook call`, () => {
      const n = c.since(peer, s0, "hook").length;
      return verdict(hm.o.pass === true && n === 0, `${hm.o.asserted}; hook calls to the paused app ${n}`);
    });
    c.w.hooksOn = false;
    await c.apply();
    const peerOp = c.readOp(peer) ?? c.agentOps(peer)[0];
    const im = peerOp ? await refusedWithin(c, async () => toolRefused(await c.call("free", peer, peerOp.id), ["paused", "unknown_tool"])) : null;
    await c.run("P1.instance.mcp", "instance pause: calls to it refused", `isError paused ${lat}`, () => (im ? verdict(im.o.pass === true, `${im.o.asserted} after ${im.ms} ms`) : bad("no peer op")));
    await c.run("P1.instance.tools_removed", "instance pause: its tools leave tools/list, others stay", "no tool of the paused app; the other app's tools listed", async () => {
      const tools = (await (await c.session("free", true)).listTools()) ?? [];
      const peerTools = tools.filter((t) => t.startsWith(`${peer.product}__`));
      return verdict(peerTools.length === 0 && tools.includes(c.tool(p, read.id)), `${peerTools.length} tools of the paused app; other app ${tools.includes(c.tool(p, read.id)) ? "listed" : "missing"}`);
    });
    await c.run("P1.instance.other_app", "instance pause: other apps unaffected", "call to the other app ok", () => callOk("free"));
    const edge = p.manifest.companions?.[0];
    const back = peer.manifest.companions?.[0];
    await c.run("P1.instance.companion", "instance pause: companion calls to or from it refused", "target paused → 4xx paused; caller paused → 4xx paused", async () => {
      if (!edge || !back) return bad("no companion edges");
      const a = await p.companion({ target: peer.product, op: edge.operations[0] as string, input: c.input(peer, edge.operations[0] as string) as Json }, c.w.companionGrants.get(p.ins) ?? null);
      const b = await peer.companion({ target: p.product, op: back.operations[0] as string, input: c.input(p, back.operations[0] as string) as Json }, c.w.companionGrants.get(peer.ins) ?? null);
      return verdict(errorCode(a.body) === "paused" && errorCode(b.body) === "paused", `to paused ${a.status} ${errorCode(a.body)}; from paused ${b.status} ${errorCode(b.body)}`);
    });
    c.w.portal.pause.instances.clear();
    c.w.portal.pause.instances.add(p.ins);
    await c.apply();
    const km = await refusedWithin(c, async () => httpRefused(await p.fetchKey(key), ["paused"]));
    await c.run("P1.instance.key_fetch", "instance pause: its key fetch refused", `403 paused ${lat}`, () => verdict(km.o.pass === true, `${km.o.asserted} after ${km.ms} ms`));
    await c.run("P1.instance.status_allowed", "instance pause: status push still accepted", "2xx", async () => {
      const a = await p.status({}, 0);
      return verdict(a.status === 200 || a.status === 204, `${a.status}`);
    });
    c.w.portal.pause.instances.clear();
    c.w.hooksOn = true;
    await restore("P1.instance");
  }
  if (c.on("revoke")) {
    const sr = await c.session("revoked", true);
    c.w.revokeAgent("revoked");
    await c.apply();
    const m = await refusedWithin(c, async () => {
      const a = await request(`${c.pub}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${sr.token}`, ...(sr.sessionId ? { "mcp-session-id": sr.sessionId } : {}) }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }) });
      return verdict(a.status === 401, `${a.status}`);
    });
    await c.run("P3.session_refused", "revoked agent: its K5 refused", `401 ${lat}`, () => verdict(m.o.pass === true, `${m.o.asserted} after ${m.ms} ms`));
    await c.run("P3.issuance_refused", "revoked agent: no new K5", "jwt-bearer → 4xx", async () => httpRefused(await c.w.keyAgents.revoked.tokenAnswer()));
    await c.run("P3.others_unaffected", "revoked agent: other agents unaffected", "free agent call ok", () => callOk("free"));
  }
}

async function pasteOnce(c: BridgeCtx, code: string): Promise<Outcome> {
  c.secrets.pairing.add(code);
  const client = await c.w.oauth.client("Conformance pause probe");
  if (!client) return bad("DCR failed");
  const pk = pkcePair();
  const b = new Browser();
  const page = await b.get(c.w.oauth.authorizeUrl(client, { challenge: pk.challenge, state: `st${ulid()}` }));
  const form = parseForms(page.text).find((x) => x.method === "post" && x.visible.length === 1);
  if (!form) return bad(`no paste form (${page.status})`);
  const a = await b.submit(c.pub, form, { [form.visible[0] as string]: code });
  return verdict(!redirectParams(a)?.code, `${a.status} ${redirectParams(a)?.code ? "CODE ISSUED" : "refused"}`);
}

// ── B7 list_changed ──────────────────────────────────────────────────────────
export async function listChangedChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("list_changed")) return;
  const peer = c.peer;
  if (!peer) return;
  const s = await c.session("free", true);
  await s.listTools(); // a client lists before it can be told the list changed
  const n = s.listen();
  await sleep(500);
  const saved = c.w.grantSpecs;
  c.w.grantSpecs = saved.filter((g) => !(g.role === "free" && g.app === peer));
  await c.apply();
  const got = await n.waitFor("notifications/tools/list_changed", c.h.timeoutMs);
  const tools = (await s.listTools()) ?? [];
  await c.run("B7.list_changed", "tools change after a config revision → notifications/tools/list_changed", "notification on the session's GET stream; the next tools/list reflects the change", () =>
    verdict(got && !tools.some((t) => t.startsWith(`${peer.product}__`)), `notification ${got ? "received" : "not received"}; tools of the removed grant ${tools.filter((t) => t.startsWith(`${peer.product}__`)).length}`),
  );
  n.close();
  c.w.grantSpecs = saved;
  await c.apply();
}

// ── B4 Portal down and the 12 h rule ─────────────────────────────────────────
export async function portalDownChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("portal_down")) return;
  const p = c.primary;
  const read = c.readOp(p);
  if (!read) return;
  const ctl = c.w.portal.control;
  ctl.goOffline(true);
  c.w.portal.dropConnections();
  await sleep(1500);
  await c.run("B4.offline_calls_continue", "Portal down: calls keep working on the last good config", "tools/call ok while the Portal drops every connection", async () => {
    const r = await c.call("free", p, read.id);
    return verdict(c.isOk(r), describeCall(r));
  });
  ctl.goOffline(false);
  const ttl = 25;
  const iat = nowS() - LIFETIME_S.configOrSlice + ttl;
  const pub = await c.until(async () => {
    const r = await c.apply({ iat });
    return r.acked ? r : null;
  }, c.h.timeoutMs * 4, 1000);
  ctl.goOffline(true);
  c.w.portal.dropConnections();
  const expired = pub.value !== null;
  if (expired) await sleep(Math.max(0, (iat + LIFETIME_S.configOrSlice - nowS() + 3) * 1000));
  const need = (fn: () => Promise<Outcome>) => async () => (expired ? fn() : notRun("the bridge did not apply the short-lived config (no ack) — the 12 h rule could not be reached"));
  await c.run("B4.config_expired", "config older than 12 h: agent calls fail closed", "isError config_expired", need(async () => toolRefused(await c.call("free", p, read.id), ["config_expired"])));
  await c.run("B4.companion_expired", "config older than 12 h: app→app calls fail closed", "refused with envelope code config_expired (HTTP status not fixed by BRIDGE §5.4)", need(async () => {
    const edge = p.manifest.companions?.[0];
    if (!c.peer || !edge) return bad("no companion edge");
    const a = await p.companion({ target: c.peer.product, op: edge.operations[0] as string, input: c.input(c.peer, edge.operations[0] as string) as Json }, c.w.companionGrants.get(p.ins) ?? null);
    return verdict(a.status >= 400 && errorCode(a.body) === "config_expired", `${a.status} ${errorCode(a.body) ?? ""}`);
  }));
  await c.run("B4.launch_up", "config older than 12 h: person launch stays up", "launch POST proxied to the app", need(async () => {
    const t = await c.w.launchTicket(p);
    c.secrets.tickets.add(t);
    const s0 = c.w.seqNow();
    const a = await c.form(`/a/${p.product}/tb/launch`, { ticket: t });
    return verdict(c.since(p, s0, "ui").length > 0 && a.status < 500, `${a.status}`);
  }));
  await c.run("B4.keys_page_up", "config older than 12 h: key page stays up", "keys ticket redeemed", need(async () => {
    const t = await c.w.keysTicket();
    c.secrets.tickets.add(t);
    const a = await c.keysForm(t);
    return verdict(a.status === 200 || (a.status >= 300 && a.status < 400), `${a.status}`);
  }));
  await c.run("B4.app_paths_up", "config older than 12 h: key fetch and status stay up", "key fetch not refused config_expired; status 2xx", need(async () => {
    const key = (p.manifest.settings?.keys ?? []).find((k) => k.source === "account_default")?.name ?? "CONFORMANCE_KEY";
    const k = await p.fetchKey(key);
    const s = await p.status({}, 0);
    return verdict((k.status === 200 || errorCode(k.body) === "key_not_set") && (s.status === 200 || s.status === 204), `key fetch ${k.status} ${errorCode(k.body) ?? ""}; status ${s.status}`);
  }));
  ctl.goOffline(false);
}

// ── B2 restart and re-enrolment ──────────────────────────────────────────────
export async function reenrolChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("reenrol")) return;
  const ids = ["C6.enrol_code_once", "B2.restart_serves_last_good", "B2.reenrol_new_key", "B2.reenrol_old_key_refused", "B2.reenrol_state_kept"];
  const restart = c.h.restart;
  if (!restart) {
    for (const id of ids) c.s.record(id, "restart / re-enrolment", "a restartable bridge (--start or --cmd)", notRun("the bridge cannot be restarted in this mode"));
    return;
  }
  const p = c.primary;
  const read = c.readOp(p);
  if (!read) return;
  const before = enrolRequests(c).length;
  const oldToken = (await c.session("free")).token;
  await restart();
  c.dropSessions();
  await c.run("C6.enrol_code_once", "restart with the same code does not enrol again", "no new EnrolRequest after a restart", () => verdict(enrolRequests(c).length === before, `${enrolRequests(c).length - before} new enrol requests`));
  await c.run("B2.restart_serves_last_good", "restart serves the last good config from the volume", "tools/call ok after restart without a new revision", async () => {
    let last = "";
    const r = await c.until(async () => {
      const a = await c.call("free", p, read.id);
      last = describeCall(a);
      return c.isOk(a) ? a : null;
    }, c.h.timeoutMs * 2);
    return verdict(!!r.value, r.value ? `ok after ${r.ms} ms` : `calls refused after restart: ${last}`);
  });
  const code = c.w.portal.issueEnrolCode();
  await restart({ TB_ENROL_CODE: code });
  c.dropSessions();
  const reqs = enrolRequests(c);
  await c.run("B2.reenrol_new_key", "new TB_ENROL_CODE → enrolment with a NEW key", "a second EnrolRequest with the new code and a different key", () => {
    const first = reqs[0];
    const last = reqs.at(-1);
    const fine = reqs.length === before + 1 && last?.code === code && !!first?.publicKey && !!last.publicKey && thumbprint(first.publicKey) !== thumbprint(last.publicKey);
    return verdict(fine, `${reqs.length} enrol requests; new code ${last?.code === code}; key ${first?.publicKey && last?.publicKey && thumbprint(first.publicKey) !== thumbprint(last.publicKey) ? "new" : "same"}`);
  });
  await c.run("B2.reenrol_old_key_refused", "K5 signed by the old key refused after re-enrolment", "401 at /mcp", async () => {
    const a = await c.mcpWith(oldToken);
    return verdict(a.status === 401, `${a.status}`);
  });
  await c.run("B2.reenrol_state_kept", "re-enrolment keeps the volume state", "new K5 and a call ok without a new config revision; proofs verify with the new key", async () => {
    const s0 = c.w.seqNow();
    let last = "";
    const r = await c.until(async () => {
      const a = await c.call("free", p, read.id);
      last = describeCall(a);
      return c.isOk(a) ? a : null;
    }, c.h.timeoutMs * 2);
    const got = c.since(p, s0, "op").find((x) => x.verified);
    return verdict(!!r.value && !!got, r.value ? "ok" : `calls refused: ${last}`);
  });
}

// ── B14 standalone handover (last: one-way) ──────────────────────────────────
export async function standaloneChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("standalone")) return;
  const p = c.primary;
  const read = c.readOp(p);
  if (!read) return;
  // after B4 the config loop may sit in network backoff (≤ 240 s); a restart (same volume, same code) starts it afresh
  if (c.h.restart) {
    await c.h.restart();
    c.dropSessions();
  }
  await c.w.publish({ standalone: true });
  const sa = c.w.standalone;
  if (!sa) return;
  const brg = c.brg as `tb:brg:brg_${string}`;
  const handed = await c.until(
    async () => {
      const s0 = c.w.seqNow();
      const r = await c.call("free", p, read.id);
      const g = c.since(p, s0, "op").find((x) => x.verified);
      return c.isOk(r) && g?.grant?.iss === brg ? g : null;
    },
    c.h.restart ? Math.max(c.h.timeoutMs, 60_000) : 300_000,
    1000,
  );
  const tHand = Date.now();
  await c.run("B14.bridge_grants", "after handover the app receives bridge-issued grants", "forwarded grant iss = tb:brg:<id>, accepted by an app trusting only the standalone issuer", () => verdict(!!handed.value, handed.value ? `after ${handed.ms} ms` : "no bridge-issued grant forwarded"));
  await c.run("B14.slices", "after handover slices are bridge-issued", "status answer slice verifies with the bridge key (iss tb:brg), carries standalone, no portalKeys", async () => {
    const a = await p.status({ sliceRevision: 0 }, 0);
    const slice = isObj(a.body) && typeof a.body.slice === "string" ? a.body.slice : "";
    const v = slice ? verifySlice(slice, { now: nowS(), self: `tb:ins:${p.ins}`, ws: c.w.ws, bridge: c.w.bridgeId, issuers: c.bridgeKeys() }) : null;
    return verdict(!!v?.ok && !!v.slice.standalone && v.slice.portalKeys.length === 0, `${a.status}; slice ${v ? (v.ok ? "verifies with the bridge key" : v.reason) : "absent"}`);
  });
  await c.run("B14.portal_tokens_refused", "Portal-signed tokens refused after handover", "Portal pairing code → no code; Portal keys ticket → 4xx; Portal launch ticket → 4xx, app not reached", async () => {
    const pc = await pasteOnce(c, await c.w.pairingCode("pairing"));
    const kt = await c.w.keysTicket();
    const k = await c.keysForm(kt);
    const lt = await c.w.launchTicket(p);
    const s0 = c.w.seqNow();
    const l = await c.form(`/a/${p.product}/tb/launch`, { ticket: lt });
    const reached = c.since(p, s0, "ui").length;
    return verdict(pc.pass === true && k.status >= 400 && k.status < 500 && l.status >= 400 && l.status < 500 && reached === 0, `pairing ${pc.asserted}; keys ${k.status}; launch ${l.status}, app reached ${reached}`);
  });
  const admin = async (path: string, body: unknown, key: Ed25519KeyPair | null = sa.ownerKey): Promise<HttpAnswer> => {
    const raw = new TextEncoder().encode(JSON.stringify(body));
    const per = `tb:per:${sa.owner}` as const;
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (key) headers[BRIDGE_HEADERS.assertion] = await signAssertion(TYP.ownerAssertion, { iss: per, sub: per, aud: brg, iat: nowS() }, key, { method: "POST", pathAndQuery: path, body: raw });
    return request(`${c.pub}${path}`, { method: "POST", headers, body: raw });
  };
  await c.run("B14.admin_auth", "admin ops need an owner assertion by a key in ownerKeys; never accepted at MCP", "no assertion → 401; unknown key → 401; owner assertion at /mcp → 401", async () => {
    const a = await admin(STANDALONE_ADMIN_PATHS.pause, {}, null);
    const b = await admin(STANDALONE_ADMIN_PATHS.pause, {}, await generateKeyPair());
    const per = `tb:per:${sa.owner}` as const;
    const m = await c.mcpWith(await signAssertion(TYP.ownerAssertion, { iss: per, sub: per, aud: brg, iat: nowS() }, sa.ownerKey, { method: "POST", pathAndQuery: "/mcp" }));
    return verdict(a.status === 401 && b.status === 401 && m.status === 401, `none ${a.status}; unknown key ${b.status}; at /mcp ${m.status}`);
  });
  await c.run("B14.admin_pause", "admin pause / resume (workspace)", "pause → calls refused paused; resume → calls ok", async () => {
    const a = await admin(STANDALONE_ADMIN_PATHS.pause, {});
    const refused = await refusedWithin(c, async () => toolRefused(await c.call("free", p, read.id), ["paused"]));
    const b = await admin(STANDALONE_ADMIN_PATHS.resume, {});
    const back = await c.until(async () => c.isOk(await c.call("free", p, read.id)), c.h.pauseLatencyMs);
    return verdict(a.status < 300 && refused.o.pass === true && b.status < 300 && !!back.value, `pause ${a.status} → ${refused.o.asserted}; resume ${b.status} → ${back.value ? "ok" : "still refused"}`);
  });
  await c.run("B14.admin_pause_agent", "admin pause / resume of one agent", "that agent refused paused, the Bound agent unaffected; resume restores", async () => {
    const agt = c.w.agents.free.agt;
    const a = await admin(STANDALONE_ADMIN_PATHS.pause, { agt });
    const refused = await refusedWithin(c, async () => toolRefused(await c.call("free", p, read.id), ["paused"]));
    const wf = c.w.grantSpecs.find((g) => g.role === "bound")?.wf[0] ?? read.id;
    const other = await c.call("bound", p, wf);
    const b = await admin(STANDALONE_ADMIN_PATHS.resume, { agt });
    const back = await c.until(async () => c.isOk(await c.call("free", p, read.id)), c.h.pauseLatencyMs);
    return verdict(a.status < 300 && refused.o.pass === true && c.isOk(other) && b.status < 300 && !!back.value, `pause ${a.status} → ${refused.o.asserted}; bound ${describeCall(other)}; resume ${b.status} → ${back.value ? "ok" : "still refused"}`);
  });
  await c.run("B14.admin_ticket", "admin ticket: K11 signed by the bridge key", "a keys ticket (iss tb:brg) that opens the key page", async () => {
    const a = await admin(STANDALONE_ADMIN_PATHS.ticket, { pur: "keys" });
    const t = findJws(a.text, TYP.personTicket);
    if (!t) return bad(`${a.status}: no ticket in the answer`);
    c.secrets.tickets.add(t);
    const v = verifyKeysTicket(t, { now: nowS(), self: brg, ws: c.w.ws, issuers: c.bridgeKeys() });
    const k = await c.keysForm(t);
    return verdict(v.ok && (k.status === 200 || (k.status >= 300 && k.status < 400)), `${a.status}; ticket ${v.ok ? "verifies with the bridge key" : v.reason}; key page ${k.status}`);
  });
  await c.run("B14.admin_revoke_connection", "admin revoke-connection: its K5 stops at once", "the revoked connection's K5 → 401; other connections work", async () => {
    const s2 = await c.session("free2", true);
    const a = await admin(STANDALONE_ADMIN_PATHS.revokeConnection, { con: c.w.keyAgents.free2.con });
    const m = await refusedWithin(c, async () => verdict((await c.mcpWith(s2.token)).status === 401, "probe"));
    const other = await c.call("free", p, read.id);
    return verdict(a.status < 300 && m.o.pass === true && c.isOk(other), `revoke ${a.status}; old K5 ${m.o.pass ? "refused" : "accepted"}; other ${describeCall(other)}`);
  });
  await c.run("B14.admin_only_four", "exactly four admin ops; adding agents / edges not possible", "other /admin/v1/* paths → 404 even with a valid owner assertion", async () => {
    const seen: string[] = [];
    for (const path of ["/admin/v1/agents", "/admin/v1/connections", "/admin/v1/edges", "/admin/v1/config", "/admin/v1/apps"]) seen.push(`${path} ${(await admin(path, {})).status}`);
    return verdict(seen.every((x) => x.endsWith(" 404")), seen.join("; "));
  });
  await c.run("B14.no_pull", "after handover the bridge stops pulling config", "no new config request from 3 s to 8 s after the handover", async () => {
    await sleep(Math.max(0, tHand + 3000 - Date.now()));
    const t1 = Date.now();
    await sleep(5000);
    const n = c.w.portal.requests.filter((r) => r.at >= t1 && r.path === "/api/v1/bridge/config").length;
    return verdict(!!handed.value && n === 0, `${n} config requests`);
  });
}

// ── closing scans ────────────────────────────────────────────────────────────
function files(dir: string, out: string[] = [], depth = 0): string[] {
  if (depth > 8) return out;
  let names: string[] = [];
  try {
    names = readdirSync(dir);
  } catch {
    return out;
  }
  for (const n of names) {
    const f = join(dir, n);
    try {
      const st = statSync(f);
      if (st.isDirectory()) files(f, out, depth + 1);
      else if (st.isFile() && st.size <= 16 * 1024 * 1024) out.push(f);
    } catch {
      // vanished
    }
  }
  return out;
}

/** Runs the closing scans; returns the report's captured-payload summary (person-credential scan of everything + payload scan of Portal traffic). */
export async function scanChecks(c: BridgeCtx): Promise<PayloadScan> {
  const portal = c.w.portal.captured;
  const proofs = c.w.apps.flatMap((a) => a.received).filter((r) => r.proof);
  const callIds = [...new Set(proofs.map((r) => String(r.proof?.call ?? "")).filter((x) => x.length > 8))];
  const payloadNeedles: ScanNeedle[] = [
    { label: "tool input / output canary", values: [c.w.canary] },
    { label: "idempotency key", values: [...c.secrets.idempotency] },
    { label: "call id", values: callIds },
    { label: "key value", values: [...c.secrets.keyValues] },
  ];
  // conformance 0.1.31 (spec 0.1.64, BRIDGE §16): the person-op pull and result posts are bridge→Portal paths ONLY for a bridge that
  // declares `person_ops` in its StatusReports (any report of the run: the reference bridge drops the cap after the standalone
  // handover, and polls before its first report); a bridge that never declares it and calls them still fails
  const relay = c.w.portal.acks.some((a) => Array.isArray(a.bridge?.caps) && (a.bridge.caps as unknown[]).includes(PERSON_OPS_CAP));
  await c.run("B9.portal_paths", "only enrol / config / ack traffic to Portal", "every captured Portal request is POST enrol, GET config or POST ack; with the person_ops cap also GET /bridge/person-ops and POST /bridge/person-ops/{pop}/result", () => {
    const allowed = (m: string, path: string) =>
      (m === "POST" && path === "/api/v1/bridge/enrol") ||
      (m === "GET" && path === "/api/v1/bridge/config") ||
      (m === "POST" && path === "/api/v1/bridge/ack") ||
      (relay && ((m === "GET" && path === PERSON_OPS_PATH) || (m === "POST" && PERSON_OP_RESULT_PATH_RE.test(path))));
    const off = portal.filter((r) => !allowed(r.method, r.path.split("?")[0] ?? ""));
    return verdict(off.length === 0 && portal.length > 0, `${portal.length} requests; person_ops cap ${relay ? "declared" : "not declared"}; other [${[...new Set(off.map((r) => `${r.method} ${r.path.split("?")[0]}`))].join(",")}]`);
  });
  const asPayload = (where: string, r: { method: string; path: string; headers: Record<string, string>; body: string; at?: number }): CapturedPayload => ({ dir: "app-out", method: r.method, path: `${where} ${r.path}`, headers: r.headers, body: r.body, at: r.at ?? 0 });
  const portalPayloads = portal.map((r) => asPayload("portal", r));
  const portalScan = scanPayloads(portalPayloads, payloadNeedles, { select: (x) => `portal ${x.path.split(" ")[1]?.split("?")[0] ?? ""}` }, []);
  await c.run("B9.no_payload", "no tool payload or call metadata sent to Portal", "no input / output canary, idempotency key, call id or key value in any Portal request", () =>
    verdict(portalScan.findings.length === 0, portalScan.findings.length ? portalScan.findings.join("; ") : `${portalScan.payloads} requests clean`),
  );
  const agentFacing = c.w.log.map((l, i) => ({ dir: "app-in" as const, method: "ANSWER", path: `agent ${l.where}`, headers: l.headers, body: l.body, at: i }));
  const appOut = c.w.apps.flatMap((a) => a.received.filter((r) => r.kind !== "ui").map((r) => asPayload(`app ${a.product}`, r)));
  const personNeedles: ScanNeedle[] = [
    { label: "owner CLI session (tbo_)", pattern: /\btbo_[A-Za-z0-9_-]{43}\b/ },
    { label: "Clerk-shaped person JWT", values: [Mint.clerkLikeJwt().split(".")[0] as string] },
    { label: "person ticket handed to the bridge", values: [...c.secrets.tickets] },
  ];
  const all = [...agentFacing, ...appOut, ...portalPayloads];
  const personScan = scanPayloads(all, personNeedles, { select: (x) => x.path.split(" ").slice(0, 2).join(" ") }, [TYP.personTicket, TYP.ownerAssertion]);
  await c.run("cred.p1.payload_scan_no_person_cred", "no agent-facing answer, app call or Portal request carries a person credential", "scan of every captured agent answer, bridge→app request (except person launch) and Portal request is clean", () =>
    verdict(personScan.findings.length === 0 && personScan.payloads > 0, personScan.findings.length ? personScan.findings.join("; ") : `${personScan.payloads} payloads clean`),
  );
  const secretValues = [...c.secrets.keyValues, ...c.secrets.tickets, ...c.secrets.pairing, ...c.accessTokens, ...c.refreshTokens, c.h.env.TB_KEK ?? "", c.h.env.TB_ENROL_CODE ?? "", ...enrolRequests(c).map((e) => e.code)].filter((v) => v && v.length >= 16);
  await c.run("B11.no_log", "secrets never logged", "bridge stdout/stderr contain no key value, ticket, pairing code, token, enrolment code or KEK", () => {
    const logs = c.h.logs();
    if (logs === null) return notRun("this harness cannot capture the bridge's logs (use --cmd or --start)");
    const hits = secretValues.filter((v) => logs.includes(v)).length;
    const jws = [...logs.matchAll(JWS_RE)].length;
    return verdict(hits === 0 && jws === 0, `${logs.length} log bytes; secret values found ${hits}; compact JWS found ${jws}`);
  });
  await c.run("B11.sealed", "volume holds no clear secret", "no file under TB_DATA_DIR contains a key value, the KEK, an enrolment code, a refresh token or a clear private key", () => {
    const list = files(c.h.dataDir);
    const vals = [...c.secrets.keyValues, c.h.env.TB_KEK ?? "", ...enrolRequests(c).map((e) => e.code), ...c.refreshTokens].filter((v) => v && v.length >= 16);
    const hits: string[] = [];
    for (const f of list) {
      const t = readFileSync(f).toString("latin1");
      if (vals.some((v) => t.includes(v)) || /PRIVATE KEY-----/.test(t) || /"d"\s*:\s*"[A-Za-z0-9_-]{40,}"/.test(t)) hits.push(f.slice(c.h.dataDir.length));
    }
    return verdict(list.length > 0 && hits.length === 0, `${list.length} files; with clear secrets [${hits.join(",")}]`);
  });
  await c.run("C7.lifetimes", "no issued token exceeds its kind's lifetime", "K5 ≤ 900 s; call / hook / bridge-op proofs ≤ 60 s; bridge assertions ≤ 60 s; pairing state ≤ 600 s", () => {
    const over: string[] = [];
    const check = (label: string, tokens: string[], max: number) => {
      for (const t of tokens) {
        const l = (() => {
          const v = peek(t);
          return v && typeof v.exp === "number" && typeof v.iat === "number" ? v.exp - v.iat : null;
        })();
        if (l === null || l > max) over.push(`${label} ${l ?? "?"}s`);
      }
    };
    check("K5", [...c.accessTokens], LIFETIME_S.agentAccess);
    check("proof", c.w.apps.flatMap((a) => a.received.map((r) => r.headers["tb-call"]).filter((x): x is string => !!x)), LIFETIME_S.proof);
    check("bridge assertion", portal.map((r) => r.headers["tb-assert"]).filter((x): x is string => !!x), LIFETIME_S.proof);
    const ps = c.evidence.get("pairState");
    if (ps) check("pair state", [ps], LIFETIME_S.pairState);
    return verdict(over.length === 0 && c.accessTokens.size > 0, `${c.accessTokens.size} K5, ${proofs.length} proofs checked; over [${over.slice(0, 6).join(",")}]`);
  });
  await c.run("C1", "every credential kind the bridge handles: positive path", "K5, K2b, K6, K7, K8, K9, K10 (agent + companion), K11 each succeeded", () => {
    if (c.w.portal.acks.length > 0) c.evidence.set("K7", "bridge assertions accepted");
    const want = ["K2b", "K5", "K6", "K7", "K8", "K9", "K10", "K10c", "K11"];
    const missing = want.filter((k) => !c.evidence.has(k));
    return verdict(missing.length === 0, missing.length ? `missing positive path: ${missing.join(", ")}` : `all ${want.length} positive paths observed`);
  });
  return { payloads: personScan.payloads, patterns: [...personScan.patterns, ...portalScan.patterns.map((p) => `Portal: ${p}`)], findings: [...personScan.findings, ...portalScan.findings] };
}

export { ok };

// ── B21 app addresses (BSD-07, BRIDGE §5.7) ──────────────────────────────────
export async function addressChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("addresses")) return;
  const p = c.primary;
  const read = c.readOp(p);
  if (!read) {
    for (const x of BRIDGE_GROUPS.addresses ?? []) c.s.record(x.id, x.title, "an agent read op on the primary app", bad("example manifest has no agent read op"));
    return;
  }
  const hits: string[] = [];
  const srv = createServer((req, res) => {
    hits.push(`${req.method} ${req.url}`);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", output: {} }));
  });
  const foreign = new URL(await listen(srv)).origin;
  const reported = async () => (await c.until(async () => c.w.portal.acks.some((a) => (a.rejected ?? []).some((x) => x.code === "internal_url_refused")), c.h.timeoutMs)).value === true;
  try {
    await c.run("B21.own_infra_allowed", "ownInfra entry whose origin is in TB_OWN_INFRA_ORIGINS is routed", "config with ownInfra: true + allow-listed origins applied; tools/call ok", async () => {
      const r = await c.apply();
      const a = await c.call("free", p, read.id);
      return verdict(r.acked && c.isOk(a), `rev ${r.rev} ${r.acked ? "acked" : "not acked"}; call ${describeCall(a)}`);
    });
    await c.run("B21.internal_url_external", "foreign internalUrl (ownInfra, not allow-listed) is not routed", "config applied (ack); call not ok; 0 requests at the foreign origin; rejected[] internal_url_refused", async () => {
      c.w.appOverrides.set(p.ins, { internalUrl: foreign, ownInfra: true });
      const r = await c.apply();
      const a = await c.call("free", p, read.id);
      await sleep(500);
      const rep = await reported();
      return verdict(r.acked && !c.isOk(a) && hits.length === 0 && rep, `rev ${r.rev} ${r.acked ? "acked" : "not acked"}; call ${describeCall(a)}; requests at the foreign origin ${hits.length}${hits.length ? ` (${hits.slice(0, 3).join(", ")})` : ""}; internal_url_refused ${rep ? "reported" : "NOT reported"}`);
    });
    await c.run("B21.own_infra_flag_required", "allow-listed origin without ownInfra: true is not routed", "call not ok; the app receives no op call", async () => {
      c.w.appOverrides.set(p.ins, { ownInfra: false });
      await c.apply();
      const s0 = c.w.seqNow();
      const a = await c.call("free", p, read.id);
      const got = c.since(p, s0, "op").length;
      return verdict(!c.isOk(a) && got === 0, `call ${describeCall(a)}; op calls at the app ${got}`);
    });
    await c.run("B21.neighbour_url_refused", "neighbour claim with a foreign internalUrl → 403 internal_url_refused", "403 internal_url_refused; no manifest fetch at the foreign origin", async () => {
      c.w.appOverrides.delete(p.ins);
      const code = opaqueValue("tbe_");
      c.w.enrolCodes.push({ digest: opaqueDigest(code), kind: "neighbour", ins: newId("ins") as never, product: p.product, exp: nowS() + 3600 });
      await c.apply();
      const before = hits.length;
      const a = await p.claim(code, { internalUrl: foreign }, await generateKeyPair());
      const o = httpRefused(a, ["internal_url_refused"]);
      return verdict(o.pass === true && a.status === 403 && hits.length === before, `${o.asserted}; requests at the foreign origin ${hits.length - before}`);
    });
  } finally {
    c.w.appOverrides.clear();
    await c.apply();
    srv.closeAllConnections();
    await new Promise((r) => srv.close(r));
  }
}

// ── B20 key-set statements at the bridge (CREDENTIALS §9.5, BRIDGE §4–5) ─────
export async function keySetChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("keyset")) return;
  if (!c.w.testRoots) {
    const why = "--no-test-roots: the bridge pins its build's Portal Root Keys; run with test roots (the default) and a start module that passes env.TBCONF_PORTAL_ROOT_KEYS to the bridge's programmatic start option (CONFORMANCE §7)";
    for (const x of BRIDGE_GROUPS.keyset ?? []) if (!c.s.has(x.id)) c.s.record(x.id, x.title, "bridge verifies configs against the newest root-signed statement", notRun(why));
    return;
  }
  const p = c.primary;
  const read = c.readOp(p);
  const stillWorks = async (): Promise<string | null> => {
    if (!read) return "no read op";
    const r = await c.call("free", p, read.id);
    return c.isOk(r) ? null : describeCall(r);
  };
  /** A forged-pause config built by `over` must be dropped: calls keep working and its rev is never acked. */
  const dropped = async (label: string, over: Parameters<typeof c.w.serveForged>[0]): Promise<Outcome> => {
    const seen = c.w.portal.acks.length;
    const rev = await c.w.serveForged({ ...over, body: { pause: { workspace: true, agents: [], instances: [] }, ...(over.body ?? {}) } });
    await sleep(2500);
    const broke = await stillWorks();
    const acked = c.w.portal.acks.slice(seen).some((a) => a.rev === rev);
    return verdict(!broke && !acked, `${label}: ${broke ? `forged pause applied (${broke})` : "last good kept"}; forged rev ${acked ? "ACKED" : "not acked"}`);
  };
  const body = (o: Record<string, unknown>) => o as never;
  await c.run("B20.kss_enrolled", "enrolment and configs carry portalKeySet; configs applied", "the enrolment response held a statement signed by the test root; the next config revision is acked and calls work", async () => {
    const r = await c.apply();
    const broke = await stillWorks();
    return verdict(r.acked && !broke && c.w.portal.enrolKeySet !== null, `seq ${c.w.keySet?.seq}; rev ${r.rev} ${r.acked ? "acked" : "not acked"}${broke ? `; ${broke}` : ""}`);
  });
  await c.run("B20.portal_keys_ignored", "a key listed only in portalKeys cannot sign", "config (active key) adds a stranger key to portalKeys → applied; a following config signed by the stranger is dropped", async () => {
    const extra = [...c.w.portal.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })), { jwk: c.w.stranger.publicJwk, status: "active" }];
    await c.w.serveForged({ body: body({ portalKeys: extra }) });
    await sleep(2500);
    return dropped("stranger signs after a portalKeys-only announcement", { key: c.w.stranger, body: body({ portalKeys: extra }) });
  });
  await c.run("B20.kss_unknown_root", "statement signed by an unknown root → config dropped", "last good config kept", async () =>
    dropped("unknown root", { body: body({ portalKeySet: await c.w.signKeySet((c.w.keySet?.seq ?? 0) + 5, undefined, c.w.stranger) }) }),
  );
  await c.run("B20.kss_rollback", "lower-seq statement → config dropped", "after seq + 1 is applied, a config carrying the older statement is dropped", async () => {
    const old = c.w.keySet?.jws ?? "";
    const seq = (c.w.keySet?.seq ?? 0) + 1;
    const jws = await c.w.signKeySet(seq);
    c.w.keySet = { seq, jws, keys: c.w.keySet?.keys ?? "" };
    c.w.portal.enrolKeySet = jws;
    const r = await c.apply();
    if (!r.acked) return bad(`seq ${seq} config not acked`);
    return dropped("rollback", { body: body({ portalKeySet: old }) });
  });
  await c.run("B20.kss_missing", "config without portalKeySet after a pin → dropped", "last good config kept", async () => {
    const seen = c.w.portal.acks.length;
    const b0 = { ...c.w.portal.configBody(c.w.portal.rev + 1), pause: { workspace: true, agents: [], instances: [] } } as Record<string, unknown>;
    delete b0.portalKeySet;
    const rev = c.w.portal.rev + 1;
    const key = c.w.portal.activeKey();
    c.w.portal.serveRaw(await rawSignConfig(b0, key));
    await sleep(2500);
    const broke = await stillWorks();
    const acked = c.w.portal.acks.slice(seen).some((a) => a.rev === rev);
    return verdict(!broke && !acked, `${broke ? `forged pause applied (${broke})` : "last good kept"}; rev ${rev} ${acked ? "ACKED" : "not acked"}`);
  });
  await c.run("B20.kss_compromise", "compromise rotation: the dropped kid is refused at once", "statement seq + 1 lists only a fresh key: config signed by the stolen key dropped; config by the fresh key applied", async () => {
    const stolen = c.w.portal.activeKey();
    c.w.portal.keys = [{ key: await generateKeyPair(), status: "active" }];
    const portalKeySet = await c.w.ensureKeySet();
    c.w.portal.configExtra = { ...c.w.portal.configExtra, portalKeySet, portalKeys: c.w.portal.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })) };
    // the fake apps already trust only the fresh key, so calls cannot probe the gap here: the forged rev must not be acked
    const seen = c.w.portal.acks.length;
    const forgedRev = await c.w.serveForged({ key: stolen });
    await sleep(2500);
    const ackedForged = c.w.portal.acks.slice(seen).some((a) => a.rev === forgedRev);
    const r = await c.apply();
    const broke = await stillWorks();
    return verdict(!ackedForged && r.acked && !broke, `stolen-key rev ${forgedRev} ${ackedForged ? "ACKED" : "not acked"}; fresh-key rev ${r.rev} ${r.acked ? "acked" : "not acked"}${broke ? `; calls: ${broke}` : ""}`);
  });
  await reenrolKeySetChecks(c, stillWorks);
}

/** C63a: re-enrolment of a pinned bridge without a valid statement; strict first enrolment (spec 0.1.12). */
async function reenrolKeySetChecks(c: BridgeCtx, stillWorks: () => Promise<string | null>): Promise<void> {
  const restart = c.h.restart;
  if (!restart) {
    c.s.record("B20.kss_reenrol_missing", "re-enrolment without a statement", "a restartable bridge (--start or --cmd)", notRun("the bridge cannot be restarted in this mode"));
    c.s.record("B20.kss_enrol_missing", "strict first enrolment", "a restartable bridge (--start or --cmd)", notRun("the bridge cannot be restarted in this mode"));
    return;
  }
  const p = c.w.portal;
  const origCode = c.h.env.TB_ENROL_CODE as string;
  const origDir = c.h.env.TB_DATA_DIR as string;
  const oldKey = p.bridgeKey;
  const current = p.enrolKeySet;
  /** restart with `extra`; a bridge that refuses by exiting counts as a refusal (the harness throws) */
  const tryRestart = async (extra: Record<string, string>): Promise<boolean> => {
    try {
      await restart(extra);
      return true;
    } catch {
      return false;
    }
  };
  const waitEnrol = async (before: number) => (await c.until(async () => enrolRequests(c).length > before, c.h.timeoutMs)).value === true;
  const restore = async () => {
    p.bridgeKey = oldKey;
    p.enrolKeySet = current;
    await tryRestart({ TB_ENROL_CODE: origCode, TB_DATA_DIR: origDir });
    c.dropSessions();
  };
  await c.run("B20.kss_reenrol_missing", "re-enrolment of a pinned bridge without a valid portalKeySet refused", "for an EnrolResponse without portalKeySet and one by an unknown root: the bridge sends the enrol request, refuses it and keeps its old key and pin (a config under the old identity is acked; calls work)", async () => {
    const out: string[] = [];
    let pass = true;
    try {
      for (const [label, kss] of [["no statement", null], ["unknown root", await c.w.signKeySet((c.w.keySet?.seq ?? 0) + 5, undefined, c.w.stranger)]] as const) {
        p.enrolKeySet = kss;
        const before = enrolRequests(c).length;
        const up = await tryRestart({ TB_ENROL_CODE: p.issueEnrolCode() });
        const seen = await waitEnrol(before);
        // Core refused nothing: give the old identity back so a bridge that kept it can pull again
        p.bridgeKey = oldKey;
        if (!up) await tryRestart({});
        c.dropSessions();
        const r = await c.apply();
        const broke = r.acked ? await stillWorks() : "not reached";
        pass &&= seen && r.acked && !broke;
        out.push(`${label}: enrol request ${seen ? "sent" : "NOT sent"}${up ? "" : " (process exited)"}; old-identity rev ${r.rev} ${r.acked ? "acked" : "NOT acked"}${broke ? `; calls: ${broke}` : ""}`);
      }
    } finally {
      await restore();
    }
    return verdict(pass, out.join("; "));
  });
  await c.run("B20.kss_enrol_missing", "strict: first enrolment without portalKeySet refused (spec 0.1.12)", "a bridge on a fresh data dir gets an EnrolResponse without portalKeySet: no config is acked under the new key", async () => {
    const fresh = join(origDir, "kss-enrol-missing");
    mkdirSync(fresh, { recursive: true });
    try {
      p.enrolKeySet = null;
      const before = enrolRequests(c).length;
      const up = await tryRestart({ TB_ENROL_CODE: p.issueEnrolCode(), TB_DATA_DIR: fresh });
      const seen = await waitEnrol(before);
      if (!seen) return bad(`no enrol request from the fresh bridge${up ? "" : " (process exited before enrolling)"}`);
      const seenAcks = p.acks.length;
      const rev = await c.w.publish();
      const acked = (await c.until(async () => p.acks.slice(seenAcks).some((a) => a.rev >= rev), c.h.timeoutMs)).value === true;
      return verdict(!acked, `fresh bridge ${up ? "running" : "exited"}; rev ${rev} ${acked ? "ACKED (enrolment accepted without a statement)" : "not acked"}`);
    } finally {
      await restore();
      await c.apply();
    }
  });
}

/** Signs `body` as a config JWS without the claim checks signConfig enforces (forged documents). */
function rawSignConfig(body: Record<string, unknown>, key: Ed25519KeyPair): Promise<string> {
  return rawSign({ alg: "EdDSA", typ: TYP.config, kid: thumbprint(key.publicJwk) }, { ...body, exp: (body.iat as number) + 43200, jti: ulid() }, key);
}
