// Portal Core target — LIVE layer against a running gateway (`tb-conformance core --url <gateway origin>`):
// default deny (R1), /internal/* unreachable, every credentialed gateway row refused without a valid credential with
// the ONE error envelope and no data, device-token polling errors (R7), webhook signature, enrolment code, header
// hygiene and CORS. Never signs in, never creates accounts. With `readonly` (--live-readonly) only side-effect-free
// probes run: GETs, and POSTs that are refused before any state change by construction (no credential, an unknown
// one-time code, an invalid signature, or no matching row). Probes that would write (device.start) report not_run.
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { request as httpsRequest } from "node:https";
import { generateKeyPair, opaqueValue } from "@opt2-tealbrick/manifest";
import { DEVICE_FLOW, OPAQUE_PREFIX } from "@opt2-tealbrick/spec/credentials";
import { type DeviceOwnerTokenResult, type DeviceStart, type HarnessOptionId, ROUTES, type RouteOp } from "@opt2-tealbrick/spec/routes";
import type { CheckResult } from "../report.ts";
import { bad, notRun, type Outcome, Suite, verdict } from "../suite.ts";
import { newId } from "../tokens.ts";
import { authProbeRows, CORE_LIVE_CHECKS } from "./core-ids.ts";

/** F75/L1: the device.start probes send a harness option id from the spec list (Core judges the id by that list); typed, so a rename breaks the build. */
const PROBE_HARNESS: HarnessOptionId = "generic-mcp";

/** CORE §11 API base path. */
export const API_BASE = "/api/v1";
export const NEEDS_QA = "needs a test account (QA)";

/** `read`: GET/OPTIONS; `refused`: a write refused before any state change by construction; `write`: may create state. */
export type Safety = "read" | "refused" | "write";

export interface ProbeRequest {
  method: string;
  /** raw path + query, sent verbatim (no client-side normalisation of `..` or `%2e`) */
  path: string;
  headers?: Record<string, string>;
  body?: string;
  safety: Safety;
  label: string;
}

export interface ProbeAnswer {
  status: number;
  headers: Record<string, string>;
  text: string;
  /** parsed JSON when the body is JSON, else the text */
  body: unknown;
  /** body cut at the byte cap or by the timeout (e.g. a stream opened without auth) */
  truncated: boolean;
}

export class ProbeBlocked extends Error {}

export interface LiveClientOptions {
  /** gateway origin, e.g. https://portal.example (no path) */
  origin: string;
  readonly: boolean;
  /** ≥ this many ms between two requests (default 220 → ≤ 5 req/s) */
  minIntervalMs?: number;
  /** hard request budget (default 600) */
  maxRequests?: number;
  timeoutMs?: number;
  bodyCapBytes?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const flat = (h: IncomingHttpHeaders): Record<string, string> => Object.fromEntries(Object.entries(h).map(([k, v]) => [k, Array.isArray(v) ? v.join(", ") : String(v ?? "")]));

/** Rate-limited, budgeted HTTP client that sends raw paths and records every exchange for the hygiene scans. */
export class LiveClient {
  readonly opts: Required<LiveClientOptions>;
  readonly exchanges: { req: ProbeRequest; answer: ProbeAnswer }[] = [];
  sent = 0;
  #nextAt = 0;

  constructor(opts: LiveClientOptions) {
    const origin = new URL(opts.origin).origin;
    this.opts = { minIntervalMs: 220, maxRequests: 600, timeoutMs: 15_000, bodyCapBytes: 64 * 1024, ...opts, origin };
  }

  async probe(req: ProbeRequest): Promise<ProbeAnswer> {
    if (req.safety === "write" && this.opts.readonly) throw new ProbeBlocked(`${req.label}: would write (not sent with --live-readonly)`);
    if (req.safety === "read" && req.method !== "GET" && req.method !== "OPTIONS" && req.method !== "HEAD") throw new ProbeBlocked(`${req.label}: ${req.method} is not a read`);
    let answer = await this.#send(req);
    if (answer.status === 429) {
      const wait = Math.min(10, Math.max(1, Number(answer.headers["retry-after"] ?? "5") || 5));
      await sleep(wait * 1000);
      answer = await this.#send(req);
    }
    this.exchanges.push({ req, answer });
    return answer;
  }

  async #send(req: ProbeRequest): Promise<ProbeAnswer> {
    if (this.sent >= this.opts.maxRequests) throw new ProbeBlocked(`request budget of ${this.opts.maxRequests} exhausted`);
    const wait = this.#nextAt - Date.now();
    if (wait > 0) await sleep(wait);
    this.#nextAt = Date.now() + this.opts.minIntervalMs;
    this.sent++;
    const u = new URL(this.opts.origin);
    const send = u.protocol === "https:" ? httpsRequest : httpRequest;
    const body = req.body === undefined ? undefined : Buffer.from(req.body);
    return new Promise<ProbeAnswer>((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      let truncated = false;
      let status = 0;
      let headers: Record<string, string> = {};
      let done = false;
      const finish = () => {
        if (done) return;
        done = true;
        const text = Buffer.concat(chunks).toString("utf8");
        let parsed: unknown = text;
        if ((headers["content-type"] ?? "").includes("json") && text !== "" && !truncated) {
          try {
            parsed = JSON.parse(text);
          } catch {
            parsed = text;
          }
        }
        resolve({ status, headers, text, body: parsed, truncated });
      };
      const r = send(
        {
          protocol: u.protocol,
          hostname: u.hostname,
          port: u.port || undefined,
          method: req.method,
          path: req.path,
          headers: { accept: "application/json", "user-agent": "tb-conformance-core", ...(body ? { "content-length": String(body.length) } : {}), ...req.headers },
          agent: false,
        },
        (res) => {
          status = res.statusCode ?? 0;
          headers = flat(res.headers);
          res.on("data", (c: Buffer) => {
            size += c.length;
            if (size > this.opts.bodyCapBytes) {
              truncated = true;
              res.destroy();
              return;
            }
            chunks.push(c);
          });
          res.on("end", finish);
          res.on("close", () => {
            if (!res.complete) truncated = true;
            finish();
          });
        },
      );
      const timer = setTimeout(() => {
        truncated = true;
        r.destroy(new Error("timeout"));
      }, this.opts.timeoutMs);
      r.on("error", (e) => {
        clearTimeout(timer);
        if (status !== 0) finish();
        else reject(e);
      });
      r.on("close", () => clearTimeout(timer));
      r.end(body);
    });
  }
}

// ── answer predicates ────────────────────────────────────────────────────────
interface Envelope {
  code: string;
  message: string;
  requestId: string;
}

/** The ONE error envelope (CORE §8) and nothing else: `{error: {code, message, requestId, details?}}`. */
export function envelopeOnly(body: unknown): Envelope | null {
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  const keys = Object.keys(body);
  if (keys.length !== 1 || keys[0] !== "error") return null;
  const e = (body as { error: unknown }).error as Record<string, unknown> | null;
  if (!e || typeof e !== "object") return null;
  if (typeof e.code !== "string" || typeof e.message !== "string" || typeof e.requestId !== "string") return null;
  if (Object.keys(e).some((k) => !["code", "message", "requestId", "details"].includes(k))) return null;
  return { code: e.code, message: e.message, requestId: e.requestId };
}

/** A Core internal document (route registry or health) — must never be served through the gateway. */
export function isInternalDoc(a: ProbeAnswer): boolean {
  const b = a.body as Record<string, unknown> | null;
  if (!b || typeof b !== "object" || Array.isArray(b)) return false;
  return Array.isArray(b.routes) || ("db" in b && "ok" in b);
}

const describe = (a: ProbeAnswer): string => {
  const env = envelopeOnly(a.body);
  if (env) return `${a.status} ${env.code}`;
  const ct = (a.headers["content-type"] ?? "").split(";")[0] || "no content-type";
  return `${a.status} ${ct}${a.truncated ? " (stream/truncated)" : ""}${a.text ? ` body ${a.text.length} B` : ""}`;
};

/** status ∈ statuses and the body is exactly the error envelope with a code from `codes` (any when omitted). */
function refusal(a: ProbeAnswer, statuses: readonly number[], codes?: readonly string[]): boolean {
  const env = envelopeOnly(a.body);
  return statuses.includes(a.status) && env !== null && (!codes || codes.includes(env.code)) && !a.truncated;
}

// ── probes ───────────────────────────────────────────────────────────────────
const json = { "content-type": "application/json" };
const ID_PREFIX: Record<string, string> = { ws: "ws", agt: "agt", ins: "ins", con: "con", edg: "edg", lic: "lic", ord: "ord", drf: "drf", osn: "osn" };

/** Concrete path for a row: `{ws}` → a fresh well-formed id of the right prefix; other params → "probe". */
export function concretePath(row: RouteOp): string {
  return API_BASE + row.path.replace(/\{([^}]+)\}/g, (_m, name: string) => (ID_PREFIX[name] ? newId(ID_PREFIX[name]) : "probe"));
}

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
/** Unsigned (`alg: none`) JWT — a forged credential every verifier must refuse. */
function forgedJwt(typ: string, claims: Record<string, unknown>): string {
  return `${b64({ alg: "none", typ })}.${b64(claims)}.`;
}

/** Invalid credential for a row's auth class (forged, never a real one). */
function invalidCredential(row: RouteOp): Record<string, string> {
  const now = Math.floor(Date.now() / 1000);
  if (row.auth.includes("bridge")) return { "tb-assert": forgedJwt("tb-bridge-assert+jwt", { iss: `tb:brg:${newId("brg")}`, aud: "tb:portal", iat: now, exp: now + 60, jti: newId("call") }) };
  if (row.auth.includes("owner-cli")) return { authorization: `Bearer ${opaqueValue(OPAQUE_PREFIX.ownerCliSession)}` };
  return { authorization: `Bearer ${forgedJwt("JWT", { sub: "user_tbconformance", iat: now, exp: now + 60 })}` };
}

function rowProbe(row: RouteOp, headers: Record<string, string>, label: string): ProbeRequest {
  const write = row.method !== "GET";
  return {
    method: row.method,
    path: concretePath(row),
    headers: { ...(write && row.method !== "DELETE" ? json : {}), ...(row.idempotent ? { "idempotency-key": `tbconf_${newId("x").slice(2)}` } : {}), ...headers },
    ...(write && row.method !== "DELETE" ? { body: "{}" } : {}),
    // no credential (or a forged one): the router refuses before the handler runs
    safety: write ? "refused" : "read",
    label,
  };
}

export interface CoreLiveOptions {
  client: LiveClient;
  routes?: readonly RouteOp[];
  /** the spec's ErrorCode union (R1.status_mapping); omitted → only the status table is checked */
  errorCodes?: readonly string[];
}

// SPEC-GAP: the PORTAL-API §1.4 status table is markdown only (no const table in @opt2-tealbrick/spec), so it is
// transcribed here; `method_not_allowed` is in ErrorCode but not in the table (405 is the only sensible status).
const STATUS_TABLE: [number[], string[]][] = [
  [[400], ["bad_request", "validation_failed", "idempotency_key_required", "draft_invalid", "draft_op_not_draftable", "draft_ref_invalid", "draft_ref_money", "recipe_not_portable", "policy_invalid", "authorization_pending", "slow_down", "access_denied", "expired_token"]],
  [[401], ["unauthenticated", "bridge_key_revoked", "enrolment_code_invalid", "stripe_signature_invalid"]],
  [[402], ["licence_required"]],
  [[403], ["forbidden"]],
  [[404], ["not_found"]],
  [[405], ["method_not_allowed"]],
  [[409], ["conflict", "revision_conflict", "idempotency_conflict", "licence_already_assigned", "licence_not_active", "workspace_paused", "workspace_standalone", "workspace_not_empty", "bridge_not_ready", "destination_in_use", "deploy_in_progress", "instance_exists", "draft_state"]],
  [[413], ["payload_too_large"]],
  [[429], ["rate_limited"]],
  [[422], ["manifest_invalid", "release_not_deployable", "offer_unavailable"]],
  [[502], ["provider_unavailable", "provider_reauth_required", "checkout_failed"]],
  [[502, 409], ["provider_not_linked"]],
  [[504], ["upstream_timeout"]],
  [[500], ["internal"]],
];
const STATUS_OF: Record<string, number[]> = Object.fromEntries(STATUS_TABLE.flatMap(([st, codes]) => codes.map((code) => [code, st])));

const STACK_RE = /\bat [\w$.<>]+ \(|\.(?:ts|js|mjs|cjs):\d+:\d+|node_modules[\\/]|Traceback \(most recent|\bException:|\bTypeError:|\bReferenceError:/;
const INTERNAL_HOST_RE = /\.railway\.internal\b|\.svc\.cluster\.local\b|\blocalhost:\d+|\b127\.0\.0\.1\b|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b/;
/** Secret material that must never appear in an unauthenticated answer: opaque credentials, token fields, private JWK parts. */
const SECRET_RE = new RegExp(
  `(?:${Object.values(OPAQUE_PREFIX).join("|")})[A-Za-z0-9_-]{16,}|"(?:access_token|refresh_token|device_code|user_code|id_token|client_secret)"\\s*:|"d"\\s*:\\s*"[A-Za-z0-9_-]{20,}"|-----BEGIN [A-Z ]*PRIVATE KEY-----|\\bsk_(?:live|test)_[A-Za-z0-9]{8,}|\\bwhsec_[A-Za-z0-9]{8,}`,
);
const OPAQUE_SHAPE = (prefix: string) => new RegExp(`^${prefix}[A-Za-z0-9_-]{43}$`);
const USER_CODE_HALF = `[${DEVICE_FLOW.userCodeAlphabet}]{${DEVICE_FLOW.userCodeLength / 2}}`;
const DEVICE_CODE_RE = OPAQUE_SHAPE(OPAQUE_PREFIX.deviceCode);
const USER_CODE_RE = new RegExp(`^${USER_CODE_HALF}-${USER_CODE_HALF}$`);
const OWNER_TOKEN_RE = OPAQUE_SHAPE(OPAQUE_PREFIX.ownerCliSession);

/** The secret outputs the spec itself puts in public answers (types/routes.ts), each with its exact value shape. */
const DEVICE_START_SECRETS = { device_code: DEVICE_CODE_RE, user_code: USER_CODE_RE } satisfies Partial<Record<keyof DeviceStart, RegExp>>;
const OWNER_TOKEN_SECRETS = { access_token: OWNER_TOKEN_RE } satisfies Partial<Record<keyof DeviceOwnerTokenResult, RegExp>>;

/** Spec-mandated secret fields of a 200 answer of `opId`: `DeviceStart` for device.start, `DeviceOwnerTokenResult`
 * for device.token (`DeviceAgentTokenResult` carries none). Only top-level fields whose value has the spec shape. */
function specSecretFields(opId: string, body: Record<string, unknown>): string[] {
  const table: Record<string, RegExp> | null = opId === "device.start" ? DEVICE_START_SECRETS : opId === "device.token" && body.scope === "owner" ? OWNER_TOKEN_SECRETS : null;
  if (!table) return [];
  return Object.entries(table)
    .filter(([k, re]) => typeof body[k] === "string" && re.test(body[k]))
    .map(([k]) => k);
}

/**
 * R1 secret scan of one public-row answer. The spec-defined device-flow outputs (the `device_code`/`user_code` of a
 * 200 device.start answer, the `access_token` of a 200 owner device.token answer) are exempt — R7.start_shape asserts
 * their shape. Everything else in the answer, including any extra field next to them, is scanned.
 */
export function secretInPublicAnswer(opId: string, answer: Pick<ProbeAnswer, "status" | "text" | "body">): boolean {
  const b = answer.body;
  const obj = answer.status === 200 && b !== null && typeof b === "object" && !Array.isArray(b) ? (b as Record<string, unknown>) : null;
  const exempt = obj ? specSecretFields(opId, obj) : [];
  if (!obj || exempt.length === 0) return SECRET_RE.test(answer.text);
  const rest = Object.fromEntries(Object.entries(obj).filter(([k]) => !exempt.includes(k)));
  // a duplicate key in the raw text would hide a value from JSON.parse: count the exempt keys in the text too
  const dup = exempt.some((k) => answer.text.split(`"${k}"`).length > 2);
  return dup || SECRET_RE.test(JSON.stringify(rest));
}

const BANNER_HEADERS = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-debug-token", "x-debug", "x-stack", "x-backend-server", "x-upstream"];

/** Checks that need a signed-in test account, Core's private network, DB access or the deployment record. */
const DEFERRED: readonly [string, string][] = [
  ["R1.route_doc", "needs Core's private network (GET /internal/routes is not reachable through the gateway by design)"],
  ["R1.core_private", "needs the deployment record (QA: no public domain on the Core service)"],
  ["R2.live_owner_cli_refused", NEEDS_QA],
  ["R3", NEEDS_QA],
  ["R6", "needs a Core DB inspection hook (QA)"],
  ["cred.dev.approve_requires_user_code", NEEDS_QA],
  ["cred.dev.one_time", NEEDS_QA],
  ["cred.dev.expiry", NEEDS_QA],
  ["R9.idle_24h", NEEDS_QA],
  ["R10.live_replay", NEEDS_QA],
  ["R11.flow", NEEDS_QA],
  ["R12", NEEDS_QA],
  // conformance 0.1.30 (spec 0.1.73, C354): needs a test workspace whose bridge does not declare lazy_tools + a lazy release
  ["R-LZ-1", NEEDS_QA],
  ["C7", NEEDS_QA],
  ["P2", NEEDS_QA],
];

export async function runCoreLive(o: CoreLiveOptions): Promise<CheckResult[]> {
  const c = o.client;
  const routes = o.routes ?? ROUTES;
  const s = new Suite();
  const title = new Map(CORE_LIVE_CHECKS.map((x) => [x.id, x.title]));
  const run = (id: string, expected: string, fn: () => Promise<Outcome>) =>
    s.run(id, title.get(id) ?? id, expected, async () => {
      try {
        return await fn();
      } catch (e) {
        if (e instanceof ProbeBlocked) return notRun(e.message);
        throw e;
      }
    });
  const evil = "https://tb-conformance.invalid";
  const deferred = new Map(DEFERRED);

  // reachability: a gateway that does not answer HTTP fails every live probe at once (no per-probe timeouts)
  try {
    await c.probe({ method: "GET", path: `${API_BASE}/me`, safety: "read", label: "reachability" });
  } catch (e) {
    const why = `gateway unreachable: ${e instanceof Error ? e.message : String(e)}`;
    for (const x of CORE_LIVE_CHECKS) s.record(x.id, x.title, "gateway answers HTTP", deferred.has(x.id) ? notRun(deferred.get(x.id) as string) : bad(why));
    return s.results;
  }

  // R1 default deny
  await run("R1.unknown_path", "404 not_found, envelope only", async () => {
    const paths: [string, string][] = [
      ["GET", `${API_BASE}/tb-conformance-${newId("x").slice(2).toLowerCase()}`],
      ["GET", `${API_BASE}/workspaces/${newId("ws")}/tb-conformance`],
      ["GET", `${API_BASE}/admin`],
      ["GET", `${API_BASE}/.well-known/jwks.json`],
      ["GET", `${API_BASE}/me/extra`],
      ["POST", `${API_BASE}/tools/call`],
    ];
    const seen: string[] = [];
    let pass = true;
    for (const [method, path] of paths) {
      const a = await c.probe({ method, path, safety: method === "GET" ? "read" : "refused", label: "unknown path", ...(method === "POST" ? { headers: json, body: "{}" } : {}) });
      const good = refusal(a, [404]);
      pass &&= good;
      seen.push(`${method} ${path.slice(API_BASE.length)} → ${describe(a)}`);
    }
    return verdict(pass, seen.join("; "));
  });
  await run("R1.unknown_method", "404/405 envelope (no row for this method)", async () => {
    const probes: [string, string][] = [
      ["DELETE", `${API_BASE}/me`],
      ["PATCH", `${API_BASE}/catalog`],
      ["PUT", `${API_BASE}/device/token`],
    ];
    const seen: string[] = [];
    let pass = true;
    for (const [method, path] of probes) {
      const a = await c.probe({ method, path, safety: "refused", label: "unknown method", ...(method !== "DELETE" ? { headers: json, body: "{}" } : {}) });
      pass &&= refusal(a, [404], ["not_found"]) || refusal(a, [405], ["method_not_allowed"]);
      seen.push(`${method} ${path.slice(API_BASE.length)} → ${describe(a)}`);
    }
    return verdict(pass, seen.join("; "));
  });
  await run("R1.traversal", "never an internal document, never 2xx JSON", async () => {
    const raw = [
      `${API_BASE}/../internal/routes`,
      `${API_BASE}/%2e%2e/internal/routes`,
      `${API_BASE}/%2E%2E/%2E%2E/internal/health`,
      `${API_BASE}//internal/routes`,
      `${API_BASE}/me/..%2f..%2finternal/routes`,
      `${API_BASE}/internal%2froutes`,
    ];
    const seen: string[] = [];
    let pass = true;
    for (const path of raw) {
      const a = await c.probe({ method: "GET", path, safety: "read", label: "traversal" });
      const leak = isInternalDoc(a) || (a.status >= 200 && a.status < 300 && typeof a.body === "object");
      pass &&= !leak;
      seen.push(`${path} → ${describe(a)}${leak ? " LEAK" : ""}`);
    }
    return verdict(pass, seen.join("; "));
  });
  await run("R1.internal_unreachable", "/api/v1/internal/* → 404 envelope; /internal/* at the origin serves no Core document", async () => {
    const seen: string[] = [];
    let pass = true;
    for (const r of routes.filter((x) => x.exposure === "internal")) {
      const a = await c.probe({ method: r.method, path: `${API_BASE}${r.path}`, safety: "read", label: "internal via gateway" });
      pass &&= refusal(a, [404]) && !isInternalDoc(a);
      seen.push(`${API_BASE}${r.path} → ${describe(a)}`);
      const b = await c.probe({ method: r.method, path: r.path, safety: "read", label: "internal at origin" });
      pass &&= !isInternalDoc(b);
      seen.push(`${r.path} → ${describe(b)}${isInternalDoc(b) ? " LEAK" : ""}`);
    }
    return verdict(pass, seen.join("; "));
  });

  // every credentialed gateway row: no credential, then a forged one
  for (const row of authProbeRows(routes)) {
    await run(`R1.auth.${row.opId}`, "401 unauthenticated|bridge_key_revoked or 403 forbidden, envelope only, both probes", async () => {
      const okAns = (a: ProbeAnswer) => refusal(a, [401], ["unauthenticated", "bridge_key_revoked"]) || refusal(a, [403], ["forbidden"]);
      const why = (a: ProbeAnswer) => (a.status === 404 ? " (row not served)" : a.status === 405 ? " (method not served)" : a.status >= 200 && a.status < 300 ? " (DATA WITHOUT AUTH)" : "");
      const none = await c.probe(rowProbe(row, {}, `${row.opId} no credential`));
      // --live-readonly: a forged person credential is sent to reads only — on a broken verifier a mutation would write
      if (c.opts.readonly && row.method !== "GET" && !row.auth.includes("bridge")) {
        return verdict(okAns(none), `none → ${describe(none)}${why(none)}; forged → not sent (mutation, --live-readonly)`);
      }
      const forged = await c.probe(rowProbe(row, invalidCredential(row), `${row.opId} forged credential`));
      return verdict(okAns(none) && okAns(forged), `none → ${describe(none)}${why(none)}; forged → ${describe(forged)}${why(forged)}`);
    });
  }

  // device flow (R7, R8)
  const deviceToken = routes.find((r) => r.opId === "device.token");
  const deviceStart = routes.find((r) => r.opId === "device.start");
  const tokenPath = `${API_BASE}${deviceToken?.path ?? "/device/token"}`;
  const startPath = `${API_BASE}${deviceStart?.path ?? "/device/authorize"}`;
  const grant = "urn:ietf:params:oauth:grant-type:device_code";
  const hasToken = (a: ProbeAnswer) => /access_token|tbo_/.test(a.text);
  await run("R7.unknown_device_code", "400 envelope, code expired_token|access_denied, no token", async () => {
    const a = await c.probe({ method: "POST", path: tokenPath, headers: json, body: JSON.stringify({ grant_type: grant, device_code: opaqueValue(OPAQUE_PREFIX.deviceCode), client_id: "tealbrick-cli" }), safety: "refused", label: "device.token unknown code" });
    return verdict(refusal(a, [400], ["expired_token", "access_denied"]) && !hasToken(a), describe(a));
  });
  await run("R7.malformed_poll", "400 envelope (bad_request|validation_failed|expired_token|access_denied)", async () => {
    const a = await c.probe({ method: "POST", path: tokenPath, headers: json, body: JSON.stringify({ grant_type: "password", device_code: "x", client_id: "tealbrick-cli" }), safety: "refused", label: "device.token wrong grant" });
    return verdict(refusal(a, [400], ["bad_request", "validation_failed", "expired_token", "access_denied"]) && !hasToken(a), describe(a));
  });
  const pub = async () => (await generateKeyPair()).publicJwk;
  const startProbe = (input: unknown, label: string): ProbeRequest => ({ method: "POST", path: startPath, headers: json, body: JSON.stringify(input), safety: "write", label });
  const refusedStart = (a: ProbeAnswer) => refusal(a, [400, 403, 422], ["bad_request", "validation_failed", "forbidden"]) && !/device_code|user_code/.test(a.text);
  await run("cred.p1.kit_cannot_get_owner", "4xx envelope, no device code", async () => {
    const a = await c.probe(startProbe({ scope: "owner", client_id: "kit", machine_label: "tb-conformance" }, "device.start kit+owner"));
    return verdict(refusedStart(a), describe(a));
  });
  await run("R8.owner_no_key", "4xx envelope, no device code", async () => {
    const a = await c.probe(startProbe({ scope: "owner", client_id: "tealbrick-cli", machine_label: "tb-conformance", agents: [{ public_key: await pub() }] }, "device.start owner+key"));
    return verdict(refusedStart(a), describe(a));
  });
  await run("R8.agent_batch_limit", `4xx envelope for ${DEVICE_FLOW.maxAgentPairs + 1} keys`, async () => {
    if (c.opts.readonly) return notRun("device.start is not called with --live-readonly");
    const key = await pub();
    const agents = Array.from({ length: DEVICE_FLOW.maxAgentPairs + 1 }, () => ({ public_key: key }));
    const a = await c.probe(startProbe({ scope: "agent", client_id: "kit", machine_label: "tb-conformance", harness: PROBE_HARNESS, agents }, "device.start 65 keys"));
    return verdict(refusedStart(a), describe(a));
  });
  let pendingCode: string | null = null;
  await run("R7.start_shape", `device code ${OPAQUE_PREFIX.deviceCode}…, user code XXXX-XXXX, expires_in ${DEVICE_FLOW.expiresIn}, interval ${DEVICE_FLOW.interval}`, async () => {
    if (c.opts.readonly) return notRun("device.start writes a device request: not called with --live-readonly");
    const a = await c.probe(startProbe({ scope: "agent", client_id: "kit", machine_label: "tb-conformance", harness: PROBE_HARNESS, agents: [{ public_key: await pub() }] }, "device.start agent"));
    const b = a.body as Record<string, unknown> | null;
    if (a.status !== 200 || !b || typeof b !== "object") return bad(describe(a));
    const issues: string[] = [];
    if (typeof b.device_code !== "string" || !DEVICE_CODE_RE.test(b.device_code)) issues.push("device_code format");
    if (typeof b.user_code !== "string" || !USER_CODE_RE.test(b.user_code)) issues.push("user_code format");
    if (b.expires_in !== DEVICE_FLOW.expiresIn) issues.push(`expires_in ${String(b.expires_in)}`);
    if (b.interval !== DEVICE_FLOW.interval) issues.push(`interval ${String(b.interval)}`);
    if (typeof b.device_code === "string") pendingCode = b.device_code;
    return verdict(issues.length === 0, issues.length ? issues.join(", ") : "200 shape as specified (values not recorded)");
  });
  await run("R7.poll_pending", "1st poll authorization_pending|slow_down, immediate 2nd poll slow_down (400 envelopes)", async () => {
    if (c.opts.readonly) return notRun("needs a device request from device.start (not called with --live-readonly)");
    if (!pendingCode) return bad("no device code from R7.start_shape");
    const poll = () => c.probe({ method: "POST", path: tokenPath, headers: json, body: JSON.stringify({ grant_type: grant, device_code: pendingCode, client_id: "kit" }), safety: "refused", label: "device.token pending" });
    const p1 = await poll();
    const p2 = await poll();
    return verdict(refusal(p1, [400], ["authorization_pending", "slow_down"]) && refusal(p2, [400], ["slow_down"]) && !hasToken(p1) && !hasToken(p2), `${describe(p1)}; ${describe(p2)}`);
  });

  // enrolment code, Stripe webhook
  const enrol = routes.find((r) => r.opId === "bridge_api.enrol");
  await run("C6.enrol_unknown_code", "401 enrolment_code_invalid", async () => {
    const body = { code: opaqueValue(OPAQUE_PREFIX.enrolmentCode), publicKey: await pub(), version: "0.1.0", sdkMajors: [1], form: "deployed", publicOrigin: "https://tb-conformance.invalid" };
    const a = await c.probe({ method: "POST", path: `${API_BASE}${enrol?.path ?? "/bridge/enrol"}`, headers: json, body: JSON.stringify(body), safety: "refused", label: "bridge enrol unknown code" });
    return verdict(refusal(a, [401], ["enrolment_code_invalid"]) && !/portalKeys|bridgeId/.test(a.text), describe(a));
  });
  const hook = routes.find((r) => r.opId === "stripe.webhook");
  const hookPath = `${API_BASE}${hook?.path ?? "/stripe/webhook"}`;
  const event = JSON.stringify({ id: "evt_tbconformance_probe", type: "tb.conformance.probe", livemode: false, data: { object: {} } });
  await run("R11.webhook_bad_signature", "4xx envelope stripe_signature_invalid", async () => {
    const sig = `t=${Math.floor(Date.now() / 1000)},v1=${"0".repeat(64)}`;
    const a = await c.probe({ method: "POST", path: hookPath, headers: { ...json, "stripe-signature": sig }, body: event, safety: "refused", label: "stripe webhook bad signature" });
    return verdict(refusal(a, [401], ["stripe_signature_invalid"]), describe(a));
  });
  await run("R11.webhook_no_signature", "4xx envelope (stripe_signature_invalid|unauthenticated|bad_request)", async () => {
    const a = await c.probe({ method: "POST", path: hookPath, headers: json, body: event, safety: "refused", label: "stripe webhook no signature" });
    return verdict(refusal(a, [401], ["stripe_signature_invalid", "unauthenticated"]), describe(a));
  });

  const clerk = routes.find((r) => r.opId === "clerk.webhook");
  if (clerk) {
    await run("R11.clerk_webhook_bad_signature", "401 envelope clerk_signature_invalid (C49; svix verified before any state change)", async () => {
      const headers = { ...json, "svix-id": "msg_tbconformance", "svix-timestamp": String(Math.floor(Date.now() / 1000)), "svix-signature": `v1,${Buffer.alloc(32).toString("base64")}` };
      const body = JSON.stringify({ type: "tb.conformance.probe", object: "event", data: {} });
      const a = await c.probe({ method: "POST", path: `${API_BASE}${clerk.path}`, headers, body, safety: "refused", label: "clerk webhook bad signature" });
      return verdict(refusal(a, [401], ["clerk_signature_invalid"]), describe(a));
    });
  }

  // explicit public rows: answered without a credential, never a secret in an unauthenticated answer
  await run("R1.public_rows", "each probed public row answers without a credential (no 401 unauthenticated, 404, 405, 5xx); no secret in any answer beyond the spec-defined device-flow outputs", async () => {
    const pubRows = routes.filter((r) => r.exposure === "gateway" && r.auth.every((a) => a === "public" || a === "device" || a === "stripe-webhook"));
    const seen: string[] = [];
    let pass = true;
    for (const r of pubRows) {
      const hits = c.exchanges.filter(({ req }) => req.method === r.method && req.path.split("?")[0] === API_BASE + r.path);
      if (hits.length === 0) {
        seen.push(`${r.opId}: not probed${c.opts.readonly && r.method !== "GET" && r.opId === "device.start" ? " (writes; --live-readonly)" : ""}`);
        continue;
      }
      for (const { answer } of hits) {
        const env = envelopeOnly(answer.body);
        // the webhook may answer a missing signature with `unauthenticated` (R11.webhook_no_signature); other public rows never
        const demandsAuth = answer.status === 401 && env?.code === "unauthenticated" && !r.auth.some((a) => a === "stripe-webhook") && r.opId !== "clerk.webhook";
        const served = !demandsAuth && answer.status !== 404 && answer.status !== 405 && answer.status < 500 && answer.status !== 0;
        const leak = secretInPublicAnswer(r.opId, answer);
        pass &&= served && !leak;
        seen.push(`${r.opId} → ${describe(answer)}${demandsAuth ? " (DEMANDS A CREDENTIAL)" : ""}${served ? "" : " (NOT SERVED)"}${leak ? " (SECRET IN ANSWER)" : ""}`);
      }
    }
    const probed = seen.filter((x) => !x.includes("not probed")).length;
    if (probed === 0) return notRun(seen.join("; "));
    return verdict(pass, seen.join("; "));
  });

  // CORS: dedicated probes + every exchange
  await run("R1.cors", "no ACAO * or reflected foreign origin together with ACAC true", async () => {
    await c.probe({ method: "OPTIONS", path: `${API_BASE}/me`, headers: { origin: evil, "access-control-request-method": "POST", "access-control-request-headers": "authorization, content-type" }, safety: "read", label: "CORS preflight" });
    await c.probe({ method: "GET", path: `${API_BASE}/catalog`, headers: { origin: evil }, safety: "read", label: "CORS simple" });
    const bad = c.exchanges
      .filter(({ answer }) => {
        const acao = answer.headers["access-control-allow-origin"];
        return (acao === "*" || acao === evil) && answer.headers["access-control-allow-credentials"] === "true";
      })
      .map(({ req, answer }) => `${req.method} ${req.path}: ACAO ${answer.headers["access-control-allow-origin"]} + credentials`);
    const reflected = c.exchanges.filter(({ answer }) => answer.headers["access-control-allow-origin"] === evil).length;
    return verdict(bad.length === 0, bad.length ? bad.slice(0, 5).join("; ") : `${c.exchanges.length} responses: no credentialed wildcard/reflection (foreign origin reflected ${reflected}×)`);
  });
  // every error envelope seen: a known code, served with the status PORTAL-API §1.4 maps it to
  await run("R1.status_mapping", "every error envelope: code ∈ ErrorCode, HTTP status per PORTAL-API §1.4", async () => {
    const known = new Set(o.errorCodes ?? []);
    const issues = new Set<string>();
    let n = 0;
    for (const { req, answer } of c.exchanges) {
      const env = envelopeOnly(answer.body);
      if (!env) continue;
      n++;
      const where = `${req.method} ${req.path.length > 60 ? `${req.path.slice(0, 60)}…` : req.path}`;
      if (known.size > 0 && !known.has(env.code)) issues.add(`${where}: code ${env.code} not in ErrorCode`);
      const want = STATUS_OF[env.code];
      if (want && !want.includes(answer.status)) issues.add(`${where}: ${env.code} with ${answer.status} (expected ${want.join("/")})`);
      if (answer.status < 400) issues.add(`${where}: error envelope with ${answer.status}`);
    }
    if (n === 0) return notRun("no error envelope seen");
    const f = [...issues];
    return verdict(f.length === 0, f.length ? `${f.length} findings: ${f.slice(0, 6).join("; ")}` : `${n} error envelopes: codes known, statuses as mapped`);
  });
  // header + error-body hygiene over everything seen
  await run("R1.no_internals", "no banner header, stack trace or internal host in headers or error bodies", async () => {
    const findings = new Set<string>();
    for (const { req, answer } of c.exchanges) {
      const where = `${req.method} ${req.path.length > 60 ? `${req.path.slice(0, 60)}…` : req.path}`;
      for (const h of BANNER_HEADERS) if (answer.headers[h] !== undefined) findings.add(`${where}: header ${h}`);
      const server = answer.headers.server ?? "";
      if (/\/\s*\d|\d+\.\d+/.test(server)) findings.add(`${where}: server header carries a version`);
      const hv = Object.values(answer.headers).join("\n");
      if (STACK_RE.test(hv)) findings.add(`${where}: stack trace in a header`);
      if (INTERNAL_HOST_RE.test(hv)) findings.add(`${where}: internal host in a header`);
      const isJson = answer.status >= 400 && (answer.headers["content-type"] ?? "").includes("json");
      if (isJson && STACK_RE.test(answer.text)) findings.add(`${where}: stack trace in the body`);
      if (isJson && INTERNAL_HOST_RE.test(answer.text)) findings.add(`${where}: internal host in the body`);
    }
    const f = [...findings];
    return verdict(f.length === 0, f.length ? `${f.length} findings: ${f.slice(0, 6).join("; ")}` : `${c.exchanges.length} responses clean`);
  });

  for (const [id, why] of DEFERRED) s.record(id, title.get(id) ?? id, "real assertion with a signed-in principal", notRun(why));
  return s.results;
}

/** Every live id reported as not_run (no --url). */
export function liveNotRun(reason: string): CheckResult[] {
  return CORE_LIVE_CHECKS.map((x) => ({ id: x.id, title: x.title, status: "not_run", asserted: reason, expected: "live probe against a running gateway" }));
}

