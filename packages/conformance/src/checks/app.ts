// App target checks (CONFORMANCE §4.5 A1–A11, plus the app-side cells of §4.2 C2–C8, §4.3 P1, B8 and B13). Every op
// the checks call is picked from the manifest by shape (audience, crud, effect, idempotency, scopeType) — never by
// product id. Inputs are generated from the op's JSON Schema with every string set to a scope instance id the caller
// can access (from the person op `tb.agents_list`), or come from caller-supplied fixtures.
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { digest, type Ed25519KeyPair, HOLDS_PENDING_OP, hookResponseProblem, KNOWN_HOLD_FAMILIES, manifestDigest, normalizeTag, opaqueDigest, PUBLIC_ROUTE_PURPOSES, ulid, validateInput, withStandardOps } from "@opt2-tealbrick/manifest";
import { type HoldVerdictClaim, type InstanceId, TYP } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Hook, Manifest, Operation, ProductId } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { AppClient, CallOptions, OpAnswer, PersonSession } from "../app-client.ts";
import { tamperValue } from "../app-client.ts";
import type { FakeBridge } from "../fake-bridge.ts";
import { SDK_EXPORTS } from "../generated/sdk-exports.ts";
import { errorCode } from "../http.ts";
import type { AppDriver } from "../multi-app.ts";
import type { PayloadScan } from "../report.ts";
import { sampleInput } from "../sample.ts";
import { scanPayloads } from "../scan.ts";
import { SDK_COVERAGE } from "../sdk-coverage.ts";
import { jsonPointer, resolvePlaceholders, runSetup } from "../setup.ts";
import { bad, na, notRun, type Outcome, ok, refusedWith, type Suite, verdict } from "../suite.ts";
import { Mint, newId, nowS, peek } from "../tokens.ts";
import { versionBelow } from "../version.ts";
import { CAPS_AGENT_PLACEHOLDER, type ConformanceConfig, type InputCaller, type NarrowingFixture, type SetupStep } from "../waivers.ts";
import { CHECK_IDS } from "./catalog.ts";

export interface AppTargetContext {
  bridge: FakeBridge;
  /** current client (replaced after a restart) */
  client(): AppClient;
  manifest: Manifest;
  env: Record<string, string>;
  /** stops and starts the app on the same data dir with `extraEnv` merged; absent in --url mode */
  restart?: (extraEnv?: Record<string, string>) => Promise<void>;
  /** triggers one backup (programmatic harness: RunningApp.backups.runNow) */
  backupNow?: () => Promise<void>;
  /** known-good inputs per op id (fixtures) */
  inputs: Record<string, Json>;
  /** deploy template JSON for A9 */
  deployTemplate?: unknown;
  timeoutMs: number;
  /** v0.1.11: the app pins the fake bridge's TEST root pair (runApp `testRoots`, default on); A13 runs only then */
  testRoots?: boolean;
  /** v0.1.18: per-caller fixtures (`inputsAs.<caller>.<op>` overrides `inputs.<op>` for that caller) */
  inputsAs?: ConformanceConfig["inputsAs"];
  /** v0.1.18: setup steps run once before the checks; their captures fill `${name}` placeholders */
  setup?: readonly SetupStep[];
  /** v0.1.18: dynamic op id → tool names A11.resolve_family resolves instead of the catalog's */
  dynamic?: ConformanceConfig["dynamic"];
  /** v0.1.23 (C115): the tag-filtered read A11.narrowing_empty_anyof sends (tealbrick-conformance.json `narrowing`) */
  narrowing?: NarrowingFixture;
  /** report notes (setup step results are appended) */
  notes?: string[];
  /**
   * CONF-MULTIAPP (conformance 0.1.20, group X): runs after every app check and before the payload scan, with a driver that
   * calls this app's agent ops (generated / fixture inputs) so the app makes its real companion calls to the real peers.
   */
  multi?: (driver: AppDriver) => Promise<void>;
}

const PROOF_CODES = ["call_proof_invalid"] as const;
const GRANT_INVALID = ["grant_invalid"] as const;
const AUTH_CODES = new Set(["call_proof_invalid", "invalid_token", "unauthenticated", "grant_invalid", "grant_expired", "grant_revoked"]);
const PERSON_AT_AGENT = ["call_proof_invalid", "grant_invalid", "unauthenticated", "invalid_token"];
const CAPPABLE = new Set(["write", "outward", "destructive"]);
// TB_DATA_EPHEMERAL (SDK-API §13 v0.1.12, tests / conformance only): the runner's temp data dirs are not volumes
const ALLOWED_ENV = new Set(["TB_INSTANCE_ID", "TB_ENROL_CODE", "TB_BRIDGE_URL", "TB_PORTAL_KEYS", "TB_KEK", "TB_DATA_DIR", "TB_DATA_EPHEMERAL", "TB_BACKUP_DIR", "TB_LOG_LEVEL", "TB_RESTORE_FROM"]);
const SECRET_ENV = new Set(["TB_ENROL_CODE", "TB_KEK"]);

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const isHeld = (a: { status: number; body: unknown }) => a.status === 202 && isObj(a.body) && a.body.status === "held" && typeof a.body.holdId === "string" && a.body.holdId.startsWith("hld_");
const isOk = (a: { status: number; body: unknown }) => a.status === 200 && isObj(a.body) && a.body.status === "ok";
const holdIdOf = (a: { body: unknown }) => (isObj(a.body) && typeof a.body.holdId === "string" ? a.body.holdId : "");
const show = (a: { status: number; body: unknown }) => {
  const code = errorCode(a.body);
  if (code) return `${a.status} ${code}`;
  if (isObj(a.body) && typeof a.body.status === "string") return `${a.status} ${a.body.status}${a.body.holdId ? ` ${a.body.holdId}` : ""}`;
  return `${a.status}`;
};
const subset = (a: readonly string[], b: readonly string[]) => a.every((x) => b.includes(x));

interface ScopeRow {
  agent: string;
  type: string;
  instanceId: string;
  access: string;
}

function collectRows(v: unknown, out: ScopeRow[], depth = 0): void {
  if (depth > 6) return;
  if (Array.isArray(v)) for (const x of v) collectRows(x, out, depth + 1);
  else if (isObj(v)) {
    if (typeof v.agent === "string" && typeof v.type === "string" && typeof v.instanceId === "string" && typeof v.access === "string") {
      out.push({ agent: v.agent, type: v.type, instanceId: v.instanceId, access: v.access });
    }
    for (const x of Object.values(v)) collectRows(x, out, depth + 1);
  }
}

/** First miniapp-sdk release that reads the grant's `prd` (spec 0.1.46, GRANT-PRD). */
const GRANT_PRD_SINCE = "0.1.28";

/** Runs every app-target check into `s`; returns the payload scan for the report. */
export async function runAppChecks(s: Suite, ctx: AppTargetContext): Promise<PayloadScan> {
  const b = ctx.bridge;
  const m = ctx.manifest;
  const c = () => ctx.client();
  const T = ctx.timeoutMs;
  const [agentA, agentB] = b.ids.agents;
  const product = m.id;
  const agentOps = m.operations.filter((o) => o.audience === "agent" && !o.dynamic);
  const personOps = withStandardOps(m).filter((o) => o.audience === "person");
  const secrets = { tickets: [] as string[], cookies: [] as string[], keyValues: [] as string[], clerk: [] as string[], owner: [] as string[] };
  const okAnswers: OpAnswer[] = [];
  const track = (a: OpAnswer) => {
    if (isOk(a)) okAnswers.push(a);
    return a;
  };

  // ── account-default keys: set values so the app can fetch them; their values must never leak ──
  const defaultKeys = (m.settings?.keys ?? []).filter((k) => k.source === "account_default" && k.usedBy.includes("app"));
  for (const k of defaultKeys) {
    const value = `tbconf-${ulid()}-${ulid()}`;
    secrets.keyValues.push(value);
    b.control.setKey(k.name, value);
  }

  // ── setup fixtures (CONFORMANCE v0.1.18): once, after the first status push, before the checks ──
  // `as: app` is the suite's companion app caller: the SAME instance id every A12.* / A15 app call uses, so an app that
  // keys data by caller (Knowledge: areas per caller) can create that caller's area first.
  const appCaller = newId("ins") as InstanceId;
  const callerKey = (id: string): InputCaller | null => (id === agentA.id ? "agentA" : id === agentB.id ? "agentB" : id === appCaller ? "app" : null);
  let setupSess: PersonSession | null = null;
  // package 0.1.21: `as: "capsAgent"` steps are deferred to A3.caps_count (the fresh caps agent does not exist yet)
  const capsSteps = (ctx.setup ?? []).filter((st) => st.as === "capsAgent");
  const setup = await runSetup((ctx.setup ?? []).filter((st) => st.as !== "capsAgent"), { "tb.agentA": agentA.id, "tb.agentB": agentB.id, "tb.app": appCaller, "tb.instance": b.ids.ins }, async (as, opId, input) => {
    if (as === "owner") {
      if (!setupSess) {
        setupSess = await c().signIn();
        if (setupSess) secrets.cookies.push(setupSess.cookie);
      }
      if (!setupSess) return { ok: false, output: undefined, shown: "owner sign-in failed" };
      const r = await c().personOp(setupSess, opId, input);
      return { ok: r.status === 200 && r.output !== undefined, output: r.output, shown: show(r) };
    }
    const view = withStandardOps(m).find((o) => o.id === opId);
    const key = view && view.idempotency !== "none" ? `conf-setup-${ulid()}` : undefined;
    // a fixture call holds nothing (`held: []`): it prepares data, it does not probe the hold rules
    if (as === "capsAgent") return { ok: false, output: undefined, shown: "capsAgent steps run inside A3.caps_count" };
    const a = await c().callOp(opId, input, { ...(as === "app" ? { caller: appCaller } : { agent: as === "agentA" ? agentA.id : agentB.id }), held: [], ...(key ? { idempotencyKey: key } : {}) });
    return { ok: isOk(a), output: isObj(a.body) ? a.body.output : undefined, shown: show(a) };
  });
  ctx.notes?.push(...setup.notes);
  /** A check that resolved an input through a blocked capture reports not_run naming the step (never a silent pass). */
  let taint: string[] = [];
  let inRun = false;
  const blockedOutcome = (o: Outcome): Outcome =>
    notRun(`${[...new Set(taint)].join("; ")} — this check needs its captures (otherwise ${o.status ?? (o.pass ? "pass" : "fail")}: ${o.asserted.slice(0, 200)})`);
  s.guard = {
    begin: () => {
      taint = [];
      inRun = true;
    },
    end: (o) => {
      inRun = false;
      return taint.length ? blockedOutcome(o) : o;
    },
    record: (o) => (inRun && taint.length ? blockedOutcome(o) : o),
  };
  const rawFixture = (op: { id: string }, caller: string): Json | undefined => {
    const k = callerKey(caller);
    return (k ? ctx.inputsAs?.[k]?.[op.id] : undefined) ?? ctx.inputs[op.id];
  };
  /** The fixture for `op` called by `caller` with placeholders resolved; a blocked placeholder taints the running check. */
  const fixtureFor = (op: { id: string }, caller: string): Json | undefined => {
    const raw = rawFixture(op, caller);
    if (raw === undefined) return undefined;
    const r = resolvePlaceholders(raw, setup);
    taint.push(...r.blocked);
    return r.value;
  };
  /** Why the fixture for `op` / `caller` cannot be resolved (a failed setup step), else null. */
  const blockedFor = (op: { id: string } | undefined, caller: string): string | null => {
    const raw = op ? rawFixture(op, caller) : undefined;
    if (raw === undefined) return null;
    const r = resolvePlaceholders(raw, setup);
    return r.blocked.length ? r.blocked.join("; ") : null;
  };

  // ── A1 claim via the bridge ──
  await s.run("A1", "claim via the bridge with the enrolment code; instance key generated", "one claim with TB_ENROL_CODE, manifestDigest = digest(manifest), then status pushes signed by the claimed key", () => {
    const claim = b.claims.find((x) => x.request.code === ctx.env.TB_ENROL_CODE);
    if (!claim) return bad(`no claim with the enrolment code (claims seen: ${b.claims.length})`);
    if (claim.request.manifestDigest !== manifestDigest(m)) return bad(`claim manifestDigest ${claim.request.manifestDigest} ≠ ${manifestDigest(m)}`);
    const st = b.statuses.find((x) => x.ins === b.ids.ins);
    return verdict(!!st, st ? `claimed (sdk ${claim.request.sdkVersion}); status push kid ${st.assertion.kid.slice(0, 8)}…` : "claimed but no verified status push");
  });
  await s.run("A1.no_claim_route", "no claim route other than the SDK's", "the app answers 404/405 on /tb/v1/claim (and the other bridge-only paths)", async () => {
    const probes = [
      ["POST", "/tb/v1/claim"],
      ["GET", "/tb/v1/claim"],
      ["POST", "/tb/v1/status"],
      ["GET", "/tb/v1/keys/ANY"],
      ["POST", "/tb/v1/call"],
    ] as const;
    const seen: string[] = [];
    for (const [method, path] of probes) {
      const a = method === "GET" ? await c().get(path) : await c().post(path, "{}");
      seen.push(`${method} ${path} ${a.status}`);
      if (a.status !== 404 && a.status !== 405) return bad(seen.join("; "));
    }
    return ok(seen.join("; "));
  });
  await s.run("A1.manifest_served", "GET /tb/v1/manifest = the deployed manifest", "served manifest digest = manifestDigest(manifest)", async () => {
    const a = await c().get("/tb/v1/manifest");
    if (a.status !== 200 || !isObj(a.body)) return bad(`${a.status}`);
    const d = manifestDigest(a.body as unknown as Manifest);
    return verdict(d === manifestDigest(m), d);
  });
  await s.run("A1.health", "GET /tb/v1/health derived status, keys as booleans", "200 {status, sdk, version, manifestDigest, keys[{name, present: boolean, source}]}, no key values", async () => {
    const a = await c().get("/tb/v1/health");
    const h = a.body as Record<string, unknown>;
    if (a.status !== 200 || !isObj(h)) return bad(`${a.status}`);
    const statuses = ["ok", "needs_claim", "needs_keys", "slice_stale", "restoring", "failed"];
    if (!statuses.includes(String(h.status))) return bad(`status ${String(h.status)}`);
    if (h.manifestDigest !== manifestDigest(m)) return bad(`manifestDigest ${String(h.manifestDigest)}`);
    if (!Array.isArray(h.keys) || !h.keys.every((k) => isObj(k) && typeof k.name === "string" && typeof k.present === "boolean")) return bad("keys[] not name + boolean");
    if (secrets.keyValues.some((v) => a.text.includes(v))) return bad("health echoes a key value");
    return ok(`status ${String(h.status)}, sdk ${String(h.sdk)}, ${h.keys.length} keys`);
  });
  await s.run("M4.openapi", "OpenAPI generated from the manifest", "GET /tb/v1/openapi.json is OpenAPI 3.1 and lists every agent op under /tb/v1/ops", async () => {
    const a = await c().get("/tb/v1/openapi.json");
    if (a.status !== 200 || !isObj(a.body)) return bad(`${a.status}`);
    const doc = a.body as { openapi?: unknown; paths?: Record<string, unknown> };
    const paths = Object.keys(doc.paths ?? {});
    const missing = agentOps.filter((o) => !paths.some((p) => p.endsWith(`/ops/${o.id}`)));
    if (!String(doc.openapi).startsWith("3.1")) return bad(`openapi ${String(doc.openapi)}`);
    return verdict(missing.length === 0, missing.length ? `missing ops: ${missing.map((o) => o.id).join(",")}` : `${paths.length} paths, all ${agentOps.length} agent ops present`);
  });

  // ── A6 person sign-in (first: the scope discovery below needs a session) ──
  let sess: PersonSession | null = null;
  await s.run("A6", "launch ticket redeemed; one session cookie", "303 to /a/<product>/…, Set-Cookie tb_session (HttpOnly, SameSite=Lax, Path=/a/<product>/, ≤ 8 h)", async () => {
    const l = await c().launch();
    secrets.tickets.push(l.ticket);
    if (l.status !== 303 || !l.cookie) return bad(`${show(l)}; cookie ${l.cookie ? "set" : "absent"}`);
    secrets.cookies.push(l.cookie);
    const attrs = l.setCookie.toLowerCase();
    const maxAge = /max-age=(\d+)/.exec(attrs);
    const problems = [
      !attrs.includes("httponly") && "HttpOnly",
      !attrs.includes("samesite=lax") && "SameSite=Lax",
      !attrs.includes(`path=/a/${product}/`) && `Path=/a/${product}/`,
      maxAge && Number(maxAge[1]) > 8 * 3600 && "Max-Age ≤ 28800",
    ].filter(Boolean);
    const loc = l.location ?? "";
    if (!loc.includes(`/a/${product}`)) problems.push(`Location ${loc}`);
    const ss = await c().session(l.cookie);
    if (ss.status !== 200 || !ss.csrf) problems.push(`session ${ss.status}`);
    else sess = { cookie: l.cookie, csrf: ss.csrf };
    return verdict(problems.length === 0, problems.length ? `missing: ${problems.join(", ")}` : `303 → ${loc}; cookie attributes ok`);
  });
  await s.run("A6.principal", "one principal shape", "session → {principal: {type: person, id: per_ (ticket sub), ws, instance}, csrf}", async () => {
    if (!sess) return bad("no session");
    const ss = await c().session((sess as PersonSession).cookie);
    const p = ss.principal ?? {};
    const good = p.type === "person" && p.id === b.ids.person && p.ws === b.ids.ws && p.instance === b.ids.ins;
    return verdict(good, `type ${String(p.type)}, id ${p.id === b.ids.person ? "= ticket sub" : String(p.id)}, ws ${p.ws === b.ids.ws ? "ok" : String(p.ws)}, instance ${p.instance === b.ids.ins ? "ok" : String(p.instance)}`);
  });
  await s.run("C6.ticket_replay", "person ticket one-time (cred one-time codes)", "the same launch ticket redeemed twice → refused ticket_used", async () => {
    const l = await c().launch();
    secrets.tickets.push(l.ticket);
    if (l.cookie) secrets.cookies.push(l.cookie);
    if (l.status !== 303) return bad(`first redemption ${show(l)}`);
    return refusedWith(await c().launch({ ticket: l.ticket }), ["ticket_used", "ticket_invalid"]);
  });
  for (const [id, tamper, title] of [
    ["C2.ticket_aud_foreign", "aud", "launch ticket for another instance"],
    ["C5.ticket_expired", "expired", "expired launch ticket"],
    ["C5.ticket_unannounced_kid", "key", "launch ticket signed by an unannounced key"],
    ["C2.ticket_ws_foreign", "ws", "launch ticket for another workspace"],
    ["C3.grant_as_ticket", "grant_as_ticket", "grant presented as a launch ticket"],
  ] as const) {
    await s.run(id, title, "refused ticket_invalid", async () => refusedWith(await c().launch({ tamper }), ["ticket_invalid"]));
  }
  await s.run("A6.csrf", "one CSRF header", "person op without TB-CSRF → 403 csrf_invalid; with it → 200", async () => {
    if (!sess) return bad("no session");
    const no = await c().personOp(sess, "tb.agents_list", {}, { omitCsrf: true });
    const yes = await c().personOp(sess, "tb.agents_list", {});
    return verdict(no.code === "csrf_invalid" && no.status === 403 && yes.status === 200, `without: ${show(no)}; with: ${show(yes)}`);
  });
  await s.run("A6.session_required", "person ops need the session", "person op without cookie → refused session_required", async () => {
    const a = await c().personOp({ cookie: "invalid-session-value", csrf: "x" }, "tb.agents_list", {});
    return refusedWith(a, ["session_required"]);
  });

  // ── scope discovery (tb.agents_list) and op selection ──
  let rows: ScopeRow[] = [];
  const refreshRows = async () => {
    if (!sess) return;
    const r = await c().personOp(sess, "tb.agents_list", {});
    rows = [];
    collectRows(r.output, rows);
  };
  await refreshRows();
  const levelCrud = (type: string, level: string): CrudAction[] => m.scopes?.find((x) => x.type === type)?.access.find((a) => a.id === level)?.crud ?? [];
  const fillFor = (op: Operation, agent: string): string | null => {
    if (!op.scopeType) return "conformance";
    const row = rows.find((r) => r.agent === agent && r.type === op.scopeType && subset(op.crud, levelCrud(r.type, r.access)));
    return row ? row.instanceId : null;
  };
  const inputFor = (op: Operation, agent: string = agentA.id): Json => fixtureFor(op, agent) ?? sampleInput(op.input, fillFor(op, agent) ?? "conformance");
  /** Schema-valid inputs that differ from `input` in one place (optional property added, or one string changed). */
  const variants = (op: Operation, input: Json): Json[] => {
    const out = schemaVariants(op, input);
    if (out.length === 0) out.push(tamperValue(input));
    return out.slice(0, 4);
  };
  /** Like `variants`, but only schema-valid ones (no blind fallback). */
  const schemaVariants = (op: Operation, input: Json): Json[] => {
    const out: Json[] = [];
    const valid = (x: Json) => validateInput({ ...op, standard: false }, x).ok;
    if (isObj(input) && isObj(op.input)) {
      const props = isObj(op.input.properties) ? (op.input.properties as Record<string, unknown>) : {};
      for (const [k, sch] of Object.entries(props)) {
        if (k in input) continue;
        const one = sampleInput({ type: "object", required: [k], properties: { [k]: sch } }, "conformance-variant") as Record<string, Json>;
        const cand = { ...(input as Record<string, Json>), [k]: one[k] ?? null };
        if (valid(cand)) out.push(cand);
      }
      for (const k of Object.keys(input).reverse()) {
        const v = (input as Record<string, Json>)[k];
        if (typeof v !== "string") continue;
        const cand = { ...(input as Record<string, Json>), [k]: `${v}-variant` };
        if (valid(cand)) out.push(cand);
      }
    }
    return out.slice(0, 4);
  };
  /**
   * A5 (v0.1.13, Inbox): the "other input" for the 409 probe. A free-text string field (its schema has no enum,
   * pattern, format or const) changed, else a schema-valid variant of another field, else null (n/a). Never the first
   * string blindly: an enum / pattern field would make the app answer input_invalid instead of 409.
   */
  const otherInput = (op: Operation, input: Json): { input: Json; how: string } | null => {
    const valid = (x: Json) => validateInput({ ...op, standard: false }, x).ok;
    if (isObj(input) && isObj(op.input)) {
      const props = isObj(op.input.properties) ? (op.input.properties as Record<string, unknown>) : {};
      for (const k of Object.keys(input).reverse()) {
        const v = (input as Record<string, Json>)[k];
        const sch = props[k];
        if (typeof v !== "string" || !isObj(sch) || ["enum", "pattern", "format", "const"].some((x) => x in sch)) continue;
        const types = Array.isArray(sch.type) ? sch.type : [sch.type ?? "string"];
        if (!types.includes("string")) continue;
        const last = v.slice(-1) === "x" ? "y" : "x";
        for (const changed of [`${v}-tampered`, `${v.slice(0, -1)}${last}`]) {
          const cand = { ...(input as Record<string, Json>), [k]: changed };
          if (changed !== v && valid(cand)) return { input: cand, how: `free-text field ${k}` };
        }
      }
    }
    const alt = schemaVariants(op, input).find((x) => digest(x) !== digest(input));
    return alt === undefined ? null : { input: alt, how: "schema-valid variant" };
  };
  const reachable = (op: Operation) => rawFixture(op, agentA.id) !== undefined || fillFor(op, agentA.id) !== null;
  const holdable = (op: Operation) => op.effect === "money" || op.holdFamily !== undefined || CAPPABLE.has(op.effect);
  const holdOpts = (op: Operation): CallOptions =>
    op.effect === "money" ? {} : op.holdFamily ? { held: [op.holdFamily] } : { caps: { [op.effect]: { max: 0, per: "hour" } } };
  const rank = (op: Operation) => (reachable(op) ? 0 : 2) + (op.scopeType ? 1 : 0);
  const byRank = (ops: Operation[]) => [...ops].sort((x, y) => rank(x) - rank(y));
  const holdOp = byRank(agentOps.filter(holdable))[0];
  const idemOp = byRank(agentOps.filter((o) => holdable(o) && o.idempotency !== "none"))[0];
  // Fleet (2026-10-12): an app whose agent ops are all read-only has no hold chain to test → not_applicable, not fail
  const NO_HOLDABLE = "no holdable agent op (all agent ops are read-only, no holdFamily)";
  const noHold = (why: string) => {
    // v0.1.18: the hold op's fixture needs a capture of a failed setup step → the whole hold chain is not_run
    const blocked = blockedFor(holdOp, agentA.id);
    return blocked ? notRun(`${blocked} — ${why}`) : holdOp ? bad(why) : na(NO_HOLDABLE);
  };
  const idemKey = (op: Operation | undefined) => (op && op.idempotency !== "none" ? `conf-${ulid()}` : undefined);

  // ── A8 default scope grants ──
  await s.run("A8", "default scope grants applied on first sight of an agent edge", "for every scopes[].defaultGrants kind own: each slice agent holds a row of that type with that access", () => {
    const owns = (m.scopes ?? []).flatMap((sc) => sc.defaultGrants.filter((g) => g.kind === "own").map((g) => ({ type: sc.type, access: g.access })));
    if (owns.length === 0) return na("manifest declares no own defaultGrants");
    if (!sess) return bad("no person session to read tb.agents_list");
    const missing: string[] = [];
    for (const a of [agentA, agentB]) for (const g of owns) if (!rows.some((r) => r.agent === a.id && r.type === g.type && r.access === g.access)) missing.push(`${a.name}:${g.type}=${g.access}`);
    return verdict(missing.length === 0, missing.length ? `missing: ${missing.join(", ")}` : `${owns.length} own grants present for 2 agents (${rows.length} rows)`);
  });
  await s.run("A8.applied_once", "defaults applied once; owner edits win", "after tb.scopes_set and a new slice with the same agents, the edited access stays", async () => {
    const sc = (m.scopes ?? []).find((x) => x.access.length > 1 && rows.some((r) => r.agent === agentB.id && r.type === x.type));
    if (!sc) return na("no scope type with ≥ 2 access levels and an agent row");
    if (!sess) return bad("no session");
    const row = rows.find((r) => r.agent === agentB.id && r.type === sc.type) as ScopeRow;
    const other = sc.access.find((a) => a.id !== row.access)?.id as string;
    const set = await c().personOp(sess, "tb.scopes_set", { agent: agentB.id, type: sc.type, id: row.instanceId, access: other });
    if (set.status !== 200) return bad(`tb.scopes_set ${show(set)}`);
    await b.control.waitForSliceRevision(await b.control.republish(), T);
    await refreshRows();
    const now = rows.find((r) => r.agent === agentB.id && r.type === sc.type && r.instanceId === row.instanceId);
    await c().personOp(sess, "tb.scopes_set", { agent: agentB.id, type: sc.type, id: row.instanceId, access: row.access });
    await refreshRows();
    return verdict(now?.access === other, `after re-sight: ${now?.access ?? "none"} (edited to ${other}, default ${row.access})`);
  });
  await s.run("A8.scope_summary", "scope summary bridge op", "POST /tb/v1/bridge/scope-summary (bridge-op proof) → [{agent ∈ slice agents, label ≤ 80}]", async () => {
    const a = await c().callBridgeOp("scope_summary", {});
    if (a.status !== 200 || !Array.isArray(a.body)) return bad(show(a));
    const ids = new Set(b.ids.agents.map((x) => x.id));
    const good = a.body.every((e) => isObj(e) && ids.has(e.agent as never) && typeof e.label === "string" && e.label.length <= 80);
    return verdict(good && a.body.length > 0, `${a.body.length} entries${good ? "" : " (shape/label violation)"}`);
  });

  // ── A2 the app re-verifies every grant and call proof (probe: tb.hold_status, valid grant suffices, I4) ──
  const hs = { holdId: `hld_${ulid()}` };
  let baseline: OpAnswer | null = null;
  await s.run("A2", "a correct bridge call passes proof + grant verification", "tb.hold_status with a valid grant + op proof is not refused by an auth code (200 or 404 hold_not_found)", async () => {
    baseline = await c().callOp("tb.hold_status", hs);
    const code = baseline.code;
    return verdict(!AUTH_CODES.has(code ?? "") && (baseline.status === 200 || baseline.status === 404), show(baseline));
  });
  const negatives: [string, string, CallOptions["tamper"], readonly string[]][] = [
    ["A2.no_proof", "request without TB-Call (direct call on the private network)", "no_proof", PROOF_CODES],
    ["B8.tampered_input", "input changed after the bridge signed it", "input", PROOF_CODES],
    ["A2.tampered_context", "context changed after the bridge signed it", "context", PROOF_CODES],
    ["A2.proof_op", "proof for another operation", "op", PROOF_CODES],
    ["A2.proof_gjti", "proof bound to another grant (gjti)", "gjti", PROOF_CODES],
    ["A2.proof_sub", "proof for another caller (sub)", "sub", PROOF_CODES],
    ["C5.proof_unannounced_kid", "proof signed by a key not in slice bridge.keys", "proof_key", PROOF_CODES],
    ["C5.proof_expired", "expired call proof", "proof_expired", PROOF_CODES],
    ["C2.proof_aud_foreign", "proof for another instance", "proof_aud", PROOF_CODES],
    ["C2.proof_aud_missing", "proof without aud", "proof_aud_missing", PROOF_CODES],
    ["A2.no_grant", "proof without the grant", "no_grant", ["call_proof_invalid", "grant_invalid", "unauthenticated"]],
    ["C5.grant_unannounced_kid", "grant signed by an unannounced key", "grant_key", GRANT_INVALID],
    ["C5.grant_expired", "expired grant", "grant_expired", ["grant_expired"]],
    ["C5.grant_not_yet_valid", "grant with iat in the future", "grant_future", GRANT_INVALID],
    ["C2.grant_aud_foreign", "grant for another instance", "grant_aud", GRANT_INVALID],
    ["C2.grant_aud_missing", "grant without aud", "grant_aud_missing", GRANT_INVALID],
    ["C2.grant_aud_array", "grant with aud as an array", "grant_aud_array", GRANT_INVALID],
    ["A2.grant_ws", "grant for another workspace", "grant_ws", GRANT_INVALID],
    ["A2.grant_cnf", "grant bound to another bridge (cnf.brg)", "grant_cnf", GRANT_INVALID],
  ];
  for (const [id, title, tamper, codes] of negatives) {
    await s.run(id, title, `refused ${codes.join("|")}`, async () => refusedWith(await c().callOp("tb.hold_status", hs, { tamper }), codes));
  }
  await s.run("C5.grant_wrong_issuer", "grant with a foreign issuer", "grant iss tb:brg:<other> signed by a trusted key → refused grant_invalid", async () => {
    const grant = await b.mint.grant({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free", iss: `tb:brg:${newId("brg")}` as `tb:brg:brg_${string}` });
    return refusedWith(await c().callOp("tb.hold_status", hs, { grant }), GRANT_INVALID);
  });
  await s.run("A2.grant_revoked", "grant withdrawn via slice revoked.jtis", "after the slice lists the grant jti → refused grant_revoked", async () => {
    const grant = await b.mint.grant({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free" });
    const before = await c().callOp("tb.hold_status", hs, { grant });
    if (AUTH_CODES.has(before.code ?? "")) return bad(`before revocation already ${show(before)}`);
    const g = peek(grant) as { jti: string; exp: number };
    await b.control.waitForSliceRevision(await b.control.revokeJti(g.jti, g.exp), T);
    return refusedWith(await c().callOp("tb.hold_status", hs, { grant }), ["grant_revoked"]);
  });
  await s.run("C6.call_proof_replay", "call proof one-time (replay set)", "the same request (same proof jti) sent twice → second refused call_proof_invalid", async () => {
    const first = await c().callOp("tb.hold_status", hs);
    if (AUTH_CODES.has(first.code ?? "")) return bad(`first call ${show(first)}`);
    return refusedWith(await c().resend(first), PROOF_CODES);
  });

  // ── C3 typ confusion + C4 person credentials at the app op route ──
  const ticket = await b.mint.launchTicket({ person: b.ids.person, aud: `tb:ins:${b.ids.ins}` });
  secrets.tickets.push(ticket);
  const clerk = Mint.clerkLikeJwt();
  const tbo = Mint.ownerCliLike();
  secrets.clerk.push(clerk);
  secrets.owner.push(tbo);
  const aGrant = await b.mint.grant({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free" });
  const hookProof = await b.mint.hookProof({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, hook: "tb_conformance", phase: "before", context: {} });
  const bopProof = await b.mint.bridgeOpProof({ aud: `tb:ins:${b.ids.ins}`, bop: "scope_summary" });
  const confusion: [string, string, CallOptions, readonly string[]][] = [
    ["C3.ticket_as_grant", "person ticket presented as the grant", { grant: ticket }, ["grant_invalid", "call_proof_invalid"]],
    ["C3.session_as_grant", "agent session (K5) presented as the grant", { grant: await b.mint.agentSession(agentA.id) }, ["grant_invalid", "call_proof_invalid"]],
    ["C3.grant_as_proof", "grant presented as the call proof", { proof: aGrant }, PROOF_CODES],
    ["C3.hook_proof_at_op", "hook proof presented at an op route", { proof: hookProof }, PROOF_CODES],
    ["B13.bridge_op_proof_at_op", "bridge-op proof presented at /tb/v1/ops", { proof: bopProof }, PROOF_CODES],
    ["cred.p1.app_op_rejects_person", "Clerk-like person JWT at an app op route (C4)", { authorization: `Bearer ${clerk}` }, PERSON_AT_AGENT],
    ["C4.owner_cli_session_at_op", "owner CLI session (tbo_) at an app op route", { authorization: `Bearer ${tbo}` }, PERSON_AT_AGENT],
  ];
  for (const [id, title, opts, codes] of confusion) {
    await s.run(id, title, `refused ${codes.join("|")}`, async () => refusedWith(await c().callOp("tb.hold_status", hs, opts), codes));
  }
  await s.run("C4.session_cookie_at_op", "app UI session cookie at an agent route", "cookie + CSRF without grant/proof at /tb/v1/ops → refused", async () => {
    if (!sess) return bad("no session");
    const headers = { cookie: `tb_session=${(sess as PersonSession).cookie}`, "tb-csrf": (sess as PersonSession).csrf };
    return refusedWith(await c().callOp("tb.hold_status", hs, { tamper: "no_proof", authorization: "", headers }), PERSON_AT_AGENT);
  });

  // ── B13 bridge-op routes accept only the bridge-op proof ──
  for (const [id, title, tamper] of [
    ["B13.op_proof_at_bridge_route", "op proof at /tb/v1/bridge/scope-summary", "op_proof"],
    ["B13.hook_proof_at_bridge_route", "hook proof at /tb/v1/bridge/scope-summary", "hook_proof"],
    ["B13.no_proof_at_bridge_route", "no proof at /tb/v1/bridge/scope-summary", "no_proof"],
    ["B13.bop_mismatch", "bridge-op proof for another bop", "bop_mismatch"],
  ] as const) {
    await s.run(id, title, "refused call_proof_invalid", async () => refusedWith(await c().callBridgeOp("scope_summary", {}, { tamper }), PROOF_CODES));
  }

  // ── hooks (B6 app side): EVERY declared hook, called like the bridge calls it for a matching operation ──
  // The target is taken from the hook's own `match` (product, operation, effect), the call carries an input (so the
  // proof binds `in`) and the context an unknown namespaced field (CORE §8: context is extensible).
  const hooks = m.hooks ?? [];
  const HOOK_INPUT: Json = { probe: "tb-conformance" };
  const hookReq = (h: Hook): { call: Record<string, Json>; context: Record<string, Json>; output?: Json } => {
    const effect = h.match.effects?.[0] ?? "write";
    return {
      call: {
        id: newId("call"),
        ws: b.ids.ws,
        caller: { type: "agent", id: agentA.id, mode: "free" },
        target: {
          instance: newId("ins"),
          product: h.match.products.find((x) => x !== "*") ?? "tb-conformance-target",
          op: h.match.operations?.[0] ?? "probe_op",
          crud: effect === "read" ? ["read"] : ["create"],
          effect,
        },
        input: HOOK_INPUT,
      },
      context: { "tb-conformance.probe": true },
      ...(h.phase === "after" ? { output: { probe: "tb-conformance" } } : {}),
    };
  };
  // v0.1.13: the ONE shape rule (manifest hookResponseProblem): before answers may carry a hold verdict, context keys
  // must be `<product>.` and never the bridge's reserved `tb.` namespace
  await s.run("A2.hook_valid", "every declared hook answers a valid hook call", "each hook: 200 with its phase shape (before {allow, reason?, hold?: {family, reason} only with allow false}, context {add} keys `<product>.` never `tb.`, after {output?, redactions?: JSON pointers})", async () => {
    if (hooks.length === 0) return na("manifest declares no hooks");
    const seen: string[] = [];
    let pass = true;
    for (const h of hooks) {
      const a = await c().callHook(h.id, h.phase, hookReq(h));
      const problem = a.status !== 200 ? show(a) : hookResponseProblem(h.phase, a.body, product);
      pass &&= problem === null;
      seen.push(`${h.id} (${h.phase}, order ${h.order}): ${problem ?? `200 ${JSON.stringify(Object.keys(a.body as object))}`}`);
    }
    return verdict(pass, seen.join("; "));
  });
  // SPEC-GAP: SDK-API §3.2 names `call_proof_invalid` for /tb/v1/ops only; the same code is expected on hook and bridge-op routes.
  for (const [id, title, tamper] of [
    ["A2.hook_no_proof", "hook call without proof", "no_proof"],
    ["A2.hook_wrong_phase", "hook proof for another phase", "phase"],
    ["A2.hook_op_proof", "op proof presented at a hook route", "op_proof"],
    ["A2.hook_tampered_context", "hook context changed after signing", "context"],
    ["A2.hook_tampered_input", "hook call input changed after signing (proof `in`)", "input"],
    ["C5.hook_proof_unannounced_kid", "hook proof signed by a key not in slice bridge.keys", "proof_key"],
  ] as const) {
    await s.run(id, title, "refused call_proof_invalid at every declared hook", async () => {
      if (hooks.length === 0) return na("manifest declares no hooks");
      const seen: string[] = [];
      for (const h of hooks) {
        const o = refusedWith(await c().callHook(h.id, h.phase, hookReq(h), { tamper }), PROOF_CODES);
        seen.push(`${h.id}: ${o.asserted}`);
        if (!o.pass) return bad(seen.join("; "));
      }
      return ok(seen.join("; "));
    });
  }
  await s.run("C6.hook_proof_replay", "hook proof one-time (replay set)", "the same hook request sent twice → second refused call_proof_invalid", async () => {
    const h = hooks[0];
    if (!h) return na("manifest declares no hooks");
    const first = await c().callHook(h.id, h.phase, hookReq(h));
    if (first.status !== 200) return bad(`first call ${show(first)}`);
    return refusedWith(await c().resend(first), PROOF_CODES);
  });
  await s.run("A2.hook_unknown", "undeclared hook id", "a valid hook proof for an undeclared hook id → 404 unknown_hook", async () => {
    const h = hooks[0];
    if (!h) return na("manifest declares no hooks");
    const a = await c().callHook("tb_conformance_undeclared", h.phase, hookReq(h));
    return verdict(a.status === 404 && a.code === "unknown_hook", show(a));
  });

  // ── A3 authorize() ──
  await s.run("A3.audience", "person-audience ops unreachable on the agent route", "a person op at /tb/v1/ops → refused audience_not_agent", async () => {
    const op = personOps[0];
    const a = await c().callOp(op.id, {}, { crud: op.crud });
    return refusedWith(a, ["audience_not_agent", "unknown_tool"]);
  });
  await s.run("A3.crud_ceiling", "grant.crud ∩ access.crud", "an op whose crud exceeds grant.crud → refused scope_denied", async () => {
    const op = agentOps.find((o) => o.crud.some((x) => x !== "read")) ?? agentOps[0];
    if (!op) return na("no agent op");
    const narrower: CrudAction[] = (["create", "read", "update", "delete"] as CrudAction[]).filter((x) => !op.crud.includes(x)).slice(0, 1);
    const a = await c().callOp(op.id, inputFor(op), { crud: narrower.length ? narrower : [], idempotencyKey: idemKey(op) });
    return refusedWith(a, ["scope_denied", "crud_exceeds_grant"]);
  });
  let hold: { op: Operation; input: Json; answer: OpAnswer; key?: string } | null = null;
  await s.run("A3.hold", "held family / caps / money → {status: held, holdId}", "202 {status: held, holdId: hld_…, expiresAt}", async () => {
    if (!holdOp) return na("no agent op with a write/outward/destructive/money effect or a holdFamily");
    const input = inputFor(holdOp);
    const key = idemKey(holdOp);
    const a = track(await c().callOp(holdOp.id, input, { ...holdOpts(holdOp), idempotencyKey: key }));
    if (isHeld(a)) hold = { op: holdOp, input, answer: a, ...(key ? { key } : {}) };
    return verdict(isHeld(a), `${holdOp.id} (${holdOp.effect}${holdOp.holdFamily ? `/${holdOp.holdFamily}` : ""}): ${show(a)}${reachable(holdOp) ? "" : " — no scope instance found; supply inputs fixture"}`);
  });
  await s.run("A3.held_family", "op holdFamily ∈ grant.held → hold", "202 held with the family in grant.held", async () => {
    const op = byRank(agentOps.filter((o) => o.holdFamily && o.effect !== "money"))[0];
    if (!op) return na("no agent op declares a holdFamily (other than money)");
    const a = track(await c().callOp(op.id, inputFor(op), { held: [op.holdFamily as never], idempotencyKey: idemKey(op) }));
    return verdict(isHeld(a), `${op.id}: ${show(a)}`);
  });
  await s.run("A3.money", "money always held", "a money op with grant.held = [] → 202 held", async () => {
    const op = byRank(agentOps.filter((o) => o.effect === "money"))[0];
    if (!op) return na("no money op declared");
    const a = track(await c().callOp(op.id, inputFor(op), { held: [], idempotencyKey: idemKey(op) }));
    return verdict(isHeld(a), `${op.id}: ${show(a)}`);
  });
  await s.run("A3.caps", "Free caps exceeded → hold", "caps {<effect>: {max: 0}} on a write/outward/destructive op → 202 held", async () => {
    const op = byRank(agentOps.filter((o) => CAPPABLE.has(o.effect)))[0];
    if (!op) return na("no write/outward/destructive op");
    const a = track(await c().callOp(op.id, inputFor(op), { caps: { [op.effect]: { max: 0, per: "hour" } }, idempotencyKey: idemKey(op) }));
    return verdict(isHeld(a), `${op.id}: ${show(a)}`);
  });

  // v0.1.19 (C111a): caps apply in ANY mode; a Free grant with a non-empty wf still carries and applies its caps
  await s.run("A3.free_wf_caps", "a Free grant with a non-empty wf keeps its caps (C111a)", "grant mode free, wf [<write op>], caps {write: {max: 0, per: hour}}, held [] → the write op in wf → 202 held (caps)", async () => {
    const op = byRank(agentOps.filter((o) => o.effect === "write" && !o.holdFamily))[0];
    if (!op) return na("no agent op with effect write");
    const a = track(await c().callOp(op.id, inputFor(op), { mode: "free", wf: [op.id], held: [], caps: { write: { max: 0, per: "hour" } }, idempotencyKey: idemKey(op) }));
    return verdict(isHeld(a), `${op.id} (free, wf [${op.id}], caps write max 0): ${show(a)}`);
  });

  // v0.1.18 (spec 0.1.31, SDK-02/SDK-04, L27): `max: 0` holds even when nothing is ever counted. With `max: 1` the first
  // call must RUN and the second must be HELD — for a receipt:false op (the old SDK counted receipts only) and a
  // receipt:true op. Each op gets a fresh agent (its own usage window); a warm-up refusal (crud too narrow) applies first
  // sight so a scoped op finds the agent's own instance.
  await s.run(
    "A3.caps_count",
    "Free caps count every run (receipt or not)",
    "fresh agent, caps {<effect>: {max: 1, per: hour}}, held []: first call → 200 ok, second → 202 held (caps); for one receipt:false and one receipt:true capped op",
    async () => {
      const capped = byRank(agentOps.filter((o) => CAPPABLE.has(o.effect) && !o.holdFamily));
      const picks = [capped.find((o) => !o.receipt), capped.find((o) => o.receipt)].filter((o): o is Operation => o !== undefined);
      if (picks.length === 0) return na("no write/outward/destructive agent op without a holdFamily");
      const seen: string[] = [];
      let ran = 0;
      for (const op of picks) {
        const { agent, rev } = await b.control.addAgent(`Conformance caps ${op.id}`.slice(0, 80));
        await b.control.waitForSliceRevision(rev, T);
        // first sight without usage: a call whose grant crud is too narrow is refused before any run
        const narrow = (["read", "create", "update", "delete"] as CrudAction[]).filter((x) => !op.crud.includes(x)).slice(0, 1);
        // the warm-up is refused before any run, so its input may name a capsAgent capture that does not exist yet: not a taint
        const taint0 = taint.length;
        await c().callOp(op.id, inputFor(op, agent.id), { agent: agent.id, crud: narrow, held: [] });
        taint.length = taint0;
        await refreshRows();
        // package 0.1.21 (Connect waiver): `as: "capsAgent"` setup steps run AS this fresh agent, now that it exists and has
        // seen its instance, before its capped calls (an op that acts on data the caps agent owns). Each successful step that
        // takes a cap slot of the same effect (a run takes one, receipt or not) raises `max`, so the probe still sees "1 more".
        let used = 0;
        if (capsSteps.length) {
          const before = setup.notes.length;
          await runSetup(capsSteps, { [CAPS_AGENT_PLACEHOLDER]: agent.id }, async (_as, opId, input) => {
            const view = withStandardOps(m).find((o) => o.id === opId);
            const key = view && view.idempotency !== "none" ? `conf-setup-${ulid()}` : undefined;
            const a = await c().callOp(opId, input, { agent: agent.id, held: [], ...(key ? { idempotencyKey: key } : {}) });
            if (isOk(a) && view && !view.standard && view.effect === op.effect) used++;
            return { ok: isOk(a), output: isObj(a.body) ? a.body.output : undefined, shown: show(a) };
          }, setup);
          ctx.notes?.push(...setup.notes.slice(before));
        }
        const input = fixtureFor(op, agent.id) ?? sampleInput(op.input, fillFor(op, agent.id) ?? "conformance");
        const caps = { [op.effect]: { max: used + 1, per: "hour" } };
        const first = track(await c().callOp(op.id, input, { agent: agent.id, held: [], caps, idempotencyKey: idemKey(op) }));
        const second = track(await c().callOp(op.id, input, { agent: agent.id, held: [], caps, idempotencyKey: idemKey(op) }));
        const tag = `${op.id} (receipt ${op.receipt}): first ${show(first)}, second ${show(second)}`;
        seen.push(tag);
        if (isOk(first)) {
          if (!isHeld(second)) return bad(seen.join("; "));
          ran++;
        } else if (isHeld(first)) return bad(`${seen.join("; ")} — held before any run`);
      }
      return ran > 0 ? ok(seen.join("; ")) : notRun(`${seen.join("; ")} — the handler rejected the generated input; supply an inputs fixture`);
    },
  );

  // v0.1.17 (C108, tolerant reader): a newer Core may hold a family this app's build does not know; the grant stays
  // valid (verifyGrant ignores the unknown family) and the known families still hold
  const UNKNOWN_FAMILY = "future_x";
  await s.run("C3.grant_held_unknown", "a grant whose held names an unknown family is accepted (C108 tolerant reader)", `grant held [destructive, ${UNKNOWN_FAMILY}]: tb.hold_status not refused (200 or 404 hold_not_found, never grant_invalid); a destructive op (holdFamily destructive) with that grant → 202 held (that part n/a when there is none)`, async () => {
    const held = ["destructive", UNKNOWN_FAMILY];
    const probe = await c().callOp("tb.hold_status", hs, { held });
    const accepted = !AUTH_CODES.has(probe.code ?? "") && (probe.status === 200 || probe.status === 404);
    const op = byRank(agentOps.filter((o) => o.holdFamily === "destructive"))[0];
    if (!op) return verdict(accepted, `tb.hold_status: ${show(probe)}; destructive part n/a (no agent op with holdFamily destructive)`);
    const a = track(await c().callOp(op.id, inputFor(op), { held, idempotencyKey: idemKey(op) }));
    return verdict(accepted && isHeld(a), `tb.hold_status: ${show(probe)}; ${op.id} (destructive): ${show(a)}`);
  });
  await s.run("A3.run", "an allowed call runs and writes its receipt", "a receipt op the grant and scope allow (no hold) → 200 {status: ok, output, receiptId}", async () => {
    const op = byRank(agentOps.filter((o) => o.receipt && o.effect !== "money")).sort((x, y) => Number(x.effect !== "write") - Number(y.effect !== "write"))[0];
    if (!op) return na("no agent op with receipt true (other than money)");
    // the grant deliberately holds nothing (`held: []`): a destructive / first_contact receipt op must run here too
    const a = track(await c().callOp(op.id, inputFor(op), { held: [], idempotencyKey: idemKey(op) }));
    if (isOk(a)) return verdict(isObj(a.body) && typeof a.body.receiptId === "string", `${op.id}: ${show(a)}${isObj(a.body) && a.body.receiptId ? ` receipt ${String(a.body.receiptId)}` : " (no receiptId)"}`);
    const authLike = AUTH_CODES.has(a.code ?? "") || ["scope_denied", "paused", "audience_not_agent", "input_invalid"].includes(a.code ?? "") || isHeld(a);
    return authLike ? bad(`${op.id}: ${show(a)}`) : notRun(`${op.id}: handler rejected the generated input (${show(a)}); supply an inputs fixture`);
  });

  // ── A4 holds / receipts ──
  await s.run("A4.hold_status", "agents poll their own holds only", "tb.hold_status: owner agent → {status: held}; another agent → refused/not found", async () => {
    if (!hold) return noHold("no hold was created (A3.hold)");
    const id = holdIdOf(hold.answer);
    const own = await c().callOp("tb.hold_status", { holdId: id });
    const out = isObj(own.body) && isObj(own.body.output) ? own.body.output : {};
    const foreign = await c().callOp("tb.hold_status", { holdId: id }, { agent: agentB.id });
    const foreignOut = isObj(foreign.body) && isObj(foreign.body.output) ? foreign.body.output : null;
    return verdict(isOk(own) && out.status === "held" && foreign.status >= 400 && !foreignOut, `own: ${show(own)} ${String(out.status)}; other agent: ${show(foreign)}`);
  });
  await s.run("A4.decide_person_only", "approvals only through person-audience ops", "tb.holds_decide on the agent route → refused; via the person session → ok", async () => {
    if (!hold) return noHold("no hold");
    const viaAgent = await c().callOp("tb.holds_decide", { holdId: holdIdOf(hold.answer), decision: "approve" }, { crud: ["update"] });
    return verdict(viaAgent.status >= 400 && viaAgent.status < 500, `agent route: ${show(viaAgent)}`);
  });
  await s.run("A4.holds_list", "one table: holds are receipt rows", "person tb.holds_list contains the hold with status held", async () => {
    if (!hold || !sess) return noHold("no hold/session");
    const r = await c().personOp(sess, "tb.holds_list", {});
    const items = isObj(r.output) && Array.isArray(r.output.items) ? r.output.items : [];
    const row = items.find((x) => isObj(x) && x.id === holdIdOf((hold as { answer: OpAnswer }).answer));
    return verdict(isObj(row) && row.status === "held", row ? `row status ${String((row as Record<string, unknown>).status)}` : `${show(r)}, ${items.length} items, hold missing`);
  });
  await s.run("A4.receipt_digest", "receipt stores input digest, never raw input", "receipt row: inputDigest = sha256(JCS input); the canonical input is not in the receipt list", async () => {
    if (!hold || !sess) return noHold("no hold/session");
    const r = await c().personOp(sess, "tb.receipts_list", {});
    const items = isObj(r.output) && Array.isArray(r.output.items) ? r.output.items : [];
    const h = hold as { input: Json; answer: OpAnswer };
    const row = items.find((x) => isObj(x) && x.id === holdIdOf(h.answer)) as Record<string, unknown> | undefined;
    if (!row) return bad(`${show(r)}; hold row missing`);
    const raw = JSON.stringify(h.input);
    const leaked = raw.length > 12 && r.text.includes(raw.slice(1, -1));
    const forbidden = ["input", "body", "arguments"].filter((k) => k in row);
    return verdict(row.inputDigest === digest(h.input) && !leaked && forbidden.length === 0, `inputDigest ${row.inputDigest === digest(h.input) ? "matches" : String(row.inputDigest)}; raw input ${leaked ? "LEAKED" : "absent"}${forbidden.length ? `; fields ${forbidden.join(",")}` : ""}`);
  });

  // ── A5 idempotency ──
  await s.run("A5", "idempotency: same key + same input → same result; different input → 409", "replay → same holdId/output; other input (a free-text field changed, else a schema-valid variant; else n/a) with the same key → 409 idempotency_conflict", async () => {
    if (!idemOp) return na("no holdable agent op with idempotency required|supported");
    const key = `conf-${ulid()}`;
    const input = inputFor(idemOp);
    const o = holdOpts(idemOp);
    const other = otherInput(idemOp, input);
    if (!other) return na(`${idemOp.id}: no free-text string field and no schema-valid variant of its input (A5 never tampers an enum / pattern / format / const field)`);
    const a1 = track(await c().callOp(idemOp.id, input, { ...o, idempotencyKey: key }));
    const a2 = track(await c().callOp(idemOp.id, input, { ...o, idempotencyKey: key }));
    const a3 = await c().callOp(idemOp.id, other.input, { ...o, idempotencyKey: key });
    const same = (isHeld(a1) && isHeld(a2) && holdIdOf(a1) === holdIdOf(a2)) || (isOk(a1) && isOk(a2) && JSON.stringify((a1.body as Record<string, unknown>).output) === JSON.stringify((a2.body as Record<string, unknown>).output));
    return verdict(same && a3.status === 409 && a3.code === "idempotency_conflict", `first ${show(a1)}; replay ${show(a2)}; other input (${other.how}) ${show(a3)}`);
  });
  await s.run("A5.required", "idempotency required and missing → 400", "an op with idempotency required called without a key → 400 idempotency_key_required", async () => {
    const op = byRank(agentOps.filter((o) => o.idempotency === "required"))[0];
    if (!op) return na("no op with idempotency required");
    return refusedWith(await c().callOp(op.id, inputFor(op), holdOpts(op)), ["idempotency_key_required"]);
  });

  // ── A12 companion calls (SDK-API §9 "Companion call", BRIDGE §8.3): only when the manifest declares companions ──
  // SPEC-GAP: CONFORMANCE §4.5 has no app-side companion check (A1–A11); A12 asserts the SDK-API §9 rules on the calls
  // the app makes while the checks above run its agent ops (or, if none did, one call per reachable agent op).
  const companions = m.companions ?? [];
  // v0.1.13 (C85): a companion call WITHOUT parentCall is app-initiated by definition (A16); A12 covers in-handler calls
  const handlerCalls = () => b.companionCalls.filter((k) => k.envelope.parentCall !== undefined);
  let companionOp: { op: Operation; input: Json } | null = null;
  const findCompanionOp = async (): Promise<void> => {
    if (companionOp || companions.length === 0) return;
    for (const op of byRank(agentOps.filter((o) => o.effect !== "money"))) {
      const before = handlerCalls().length;
      const input = inputFor(op);
      const a = track(await c().callOp(op.id, input, { idempotencyKey: idemKey(op) }));
      if (handlerCalls().length > before && isOk(a)) {
        companionOp = { op, input };
        return;
      }
    }
  };
  await s.run("A12.companion_inbound", "a companion app calls this app (inbound app→app)", "op call with a bound companion grant (sub tb:ins:<other app>, wf = [op]) and its proof → runs (200 ok / 202 held; a scoped op may answer scope_denied), never an auth refusal", async () => {
    const op = [...agentOps].filter((o) => o.effect !== "money").sort((x, y) => Number(!!x.scopeType) - Number(!!y.scopeType) || Number(x.effect === "read") - Number(y.effect === "read"))[0];
    if (!op) return na("no agent operation");
    const a = track(await c().callOp(op.id, fixtureFor(op, appCaller) ?? inputFor(op), { caller: appCaller, idempotencyKey: idemKey(op) }));
    const pass = isOk(a) || isHeld(a) || (!!op.scopeType && a.code === "scope_denied");
    return verdict(pass, `${op.id} from tb:ins:${appCaller.slice(0, 12)}…: ${show(a)}`);
  });
  await s.run("A12.companion_call", "app→app call through the bridge with the companion grant", "POST /tb/v1/call: TB-Assert valid, TB-Grant = the slice's companion grant (sub self, aud target, mode bound, wf = declared ops), target/op declared in companions[], parentCall = the running call's id; the op answers ok", async () => {
    if (companions.length === 0) return na("manifest declares no companions");
    await findCompanionOp();
    const calls = handlerCalls();
    if (calls.length === 0) return na("no agent op made a companion call with the generated inputs (companion use from person ops or jobs is not observable here; calls without parentCall are app-initiated, A16); supply an inputs fixture");
    const parents = new Set(okAnswers.map((a) => a.callId).filter((x): x is string => !!x));
    const problems: string[] = [];
    for (const k of calls) {
      const decl = companions.find((x) => x.product === k.envelope.target);
      const g = peek(k.grant) as { sub?: string; aud?: string; mode?: string; wf?: string[] } | null;
      const where = `${k.envelope.target}.${k.envelope.op}`;
      if (!decl?.operations.includes(k.envelope.op)) problems.push(`${where} not declared`);
      if (k.caller !== b.ids.ins) problems.push(`${where} asserted by ${k.caller}`);
      if (g?.sub !== `tb:ins:${b.ids.ins}` || g?.aud !== `tb:ins:${b.ids.peers[k.envelope.target]}` || g?.mode !== "bound") problems.push(`${where} grant sub/aud/mode ${g?.sub}/${g?.aud}/${g?.mode}`);
      if (decl && [...(g?.wf ?? [])].sort().join(",") !== [...decl.operations].sort().join(",")) problems.push(`${where} grant wf ${String(g?.wf)}`);
      if (!k.envelope.parentCall || !parents.has(k.envelope.parentCall)) problems.push(`${where} parentCall ${String(k.envelope.parentCall)} is not a call the app answered ok`);
    }
    const first = calls[0];
    return verdict(
      problems.length === 0,
      problems.length ? problems.slice(0, 4).join("; ") : `${calls.length} calls, e.g. ${first.envelope.target}.${first.envelope.op} (parentCall ${first.envelope.parentCall}, idempotencyKey ${first.envelope.idempotencyKey ? "sent" : "none"}); grants and envelopes ok`,
    );
  });
  await s.run("A12.companion_refresh_retry", "companion grant_stale → re-read the slice once and retry", "bridge refuses once with grant_stale → the SDK retries once and the op answers ok; refused twice → the op fails after exactly 2 attempts (no loop)", async () => {
    if (companions.length === 0) return na("manifest declares no companions");
    await findCompanionOp();
    if (!companionOp) return na("no agent op made a companion call with the generated inputs; supply an inputs fixture");
    const { op, input } = companionOp as { op: Operation; input: Json };
    const attempts = () => b.companionCalls.length + b.companionRefusals.length;
    // SPEC-GAP: SDK-API §9 names `grant_stale`, BRIDGE §8.4 does not list it (it lists grant_expired, which the SDK treats the same).
    b.control.refuseNextCompanionCalls([{ status: 403, code: "grant_stale" }]);
    let n0 = attempts();
    const once = track(await c().callOp(op.id, input, { idempotencyKey: idemKey(op) }));
    const onceAttempts = attempts() - n0;
    b.control.refuseNextCompanionCalls([
      { status: 403, code: "grant_stale" },
      { status: 403, code: "grant_stale" },
    ]);
    n0 = attempts();
    const twice = await c().callOp(op.id, input, { idempotencyKey: idemKey(op) });
    const twiceAttempts = attempts() - n0;
    b.companionRefuseQueue.length = 0;
    return verdict(isOk(once) && onceAttempts === 2 && !isOk(twice) && twiceAttempts === 2, `${op.id}: refused once → ${show(once)} after ${onceAttempts} attempts; refused twice → ${show(twice)} after ${twiceAttempts} attempts`);
  });

  // ── A12 app callers (SDK-API v0.1.14 C102 Caller.name; v0.1.15 C105a: app calls are held like agent calls) ──
  // An inbound app caller presents a companion grant (sub tb:ins:<caller>) whose `held` = the workspace apps policy
  // (fake bridge default DEFAULT_HELD_FAMILIES). A scoped op needs a scope instance the caller can reach: first the
  // caller's own instance (MANIFEST §6 `own`, the SDK names it after the caller), else the owner grants the caller
  // agent A's instance through tb.scopes_set (a person op any owner may use).
  const appCall = async (caller: InstanceId, op: Operation, extra: CallOptions = {}): Promise<{ answer: OpAnswer; input: Json; key?: string; how: string }> => {
    const tries: { input: Json; how: string; grant?: ScopeRow }[] = [];
    // v0.1.18: an `inputsAs.app` fixture is the app caller's own input (e.g. the area its setup step created)
    const own = callerKey(caller) === "app" && ctx.inputsAs?.app?.[op.id] !== undefined;
    if (own) tries.push({ input: fixtureFor(op, caller) as Json, how: "inputsAs.app fixture" });
    else {
      if (op.scopeType && ctx.inputs[op.id] === undefined) tries.push({ input: sampleInput(op.input, caller), how: "own instance" });
      const row = op.scopeType ? rows.find((r) => r.agent === agentA.id && r.type === op.scopeType && subset(op.crud, levelCrud(r.type, r.access))) : undefined;
      tries.push({ input: inputFor(op), how: row ? "agent A's instance, granted by the owner" : "generated input", ...(row ? { grant: row } : {}) });
    }
    let last: { answer: OpAnswer; input: Json; key?: string; how: string } | null = null;
    for (const t of tries) {
      if (t.grant && sess) await c().personOp(sess, "tb.scopes_set", { agent: caller, type: t.grant.type, id: t.grant.instanceId, access: t.grant.access });
      const key = idemKey(op);
      const answer = track(await c().callOp(op.id, t.input, { caller, ...(key ? { idempotencyKey: key } : {}), ...extra }));
      last = { answer, input: t.input, ...(key ? { key } : {}), how: t.how };
      if (answer.code !== "scope_denied") return last;
    }
    return last as { answer: OpAnswer; input: Json; key?: string; how: string };
  };
  /** The receipt row id of an answer: receiptId (ran) or holdId (held; holds are receipt rows). */
  const rowIdOf = (a: OpAnswer) => (isHeld(a) ? holdIdOf(a) : isOk(a) && isObj(a.body) && typeof a.body.receiptId === "string" ? a.body.receiptId : null);
  const receiptRows = async (): Promise<Record<string, unknown>[]> => {
    if (!sess) return [];
    const r = await c().personOp(sess, "tb.receipts_list", {});
    return (isObj(r.output) && Array.isArray(r.output.items) ? r.output.items : []).filter(isObj);
  };
  await s.run("A12.caller_name", "an app caller is named from slice companionCallers; an unlisted one by its instance id (C102)", "a caller listed in companionCallers {product, ins, name} calls a receipt op (companion grant sub tb:ins:<ins>) → its tb.receipts_list row has caller.name = that name; an unlisted caller's row has caller.name = its instance id", async () => {
    const op = byRank(agentOps.filter((o) => o.receipt)).sort((x, y) => Number(x.effect === "money") - Number(y.effect === "money"))[0];
    if (!op) return na("no agent op with receipt: true");
    if (!sess) return bad("no person session");
    // v0.1.18: ONE app caller identity (the setup `as: app` caller): first unlisted, then listed in companionCallers
    const name = `Conformance caller ${ulid().slice(-6)}`;
    const unlisted = appCaller;
    const two = await appCall(unlisted, op);
    await b.control.waitForSliceRevision(await b.control.listCompanionCaller({ product: "tbconf-caller" as ProductId, ins: appCaller, name }), T);
    const one = await appCall(appCaller, op);
    const shown = `${op.id}: listed ${show(one.answer)} (${one.how}); unlisted ${show(two.answer)} (${two.how})`;
    const [id1, id2] = [rowIdOf(one.answer), rowIdOf(two.answer)];
    if (!id1 || !id2) {
      const authLike = [one.answer, two.answer].some((a) => AUTH_CODES.has(a.code ?? "") || a.code === "audience_not_agent");
      return authLike ? bad(shown) : notRun(`${shown} — no receipt row to read; supply an inputs fixture an app caller can run`);
    }
    const items = await receiptRows();
    const nameOf = (id: string) => {
      const row = items.find((x) => x.id === id);
      return row && isObj(row.caller) ? row.caller.name : undefined;
    };
    const [n1, n2] = [nameOf(id1), nameOf(id2)];
    return verdict(n1 === name && n2 === unlisted, `${shown}; row caller.name: listed ${n1 === name ? "= companionCallers name" : JSON.stringify(n1)}, unlisted ${n2 === unlisted ? "= instance id" : JSON.stringify(n2)}`);
  });
  // spec 0.1.44 (SDK-CALLER-PRODUCT, security): `caller.product` of a receipt row = the VERIFIED product of the app caller
  // (slice companionCallers entry by the grant's caller instance), never a product looked up by the caller's NAME. Apps
  // decide per calling app (Rules, Connect data sharing, Observer) on it; a companion named "Observer" must not be Observer.
  await s.run("A12.caller_product_verified", "an app caller's receipt reports the verified product of its companionCallers entry, not a product found by name (SDK-CALLER-PRODUCT)", "two instances are listed in companionCallers under the SAME name \"Observer\": a decoy (product tbconf-observer, listed first) and the calling app caller (product tbconf-impostor); the caller runs a receipt op (companion grant sub tb:ins:<ins>) → its tb.receipts_list row has caller.product = tbconf-impostor and caller.name = Observer", async () => {
    const op = byRank(agentOps.filter((o) => o.receipt)).sort((x, y) => Number(x.effect === "money") - Number(y.effect === "money"))[0];
    if (!op) return na("no agent op with receipt: true");
    if (!sess) return bad("no person session");
    const name = "Observer";
    const decoy = `ins_${ulid()}` as InstanceId;
    await b.control.listCompanionCaller({ product: "tbconf-observer" as ProductId, ins: decoy, name });
    await b.control.waitForSliceRevision(await b.control.listCompanionCaller({ product: "tbconf-impostor" as ProductId, ins: appCaller, name }), T);
    const one = await appCall(appCaller, op);
    const shown = `${op.id}: ${show(one.answer)} (${one.how})`;
    const id = rowIdOf(one.answer);
    if (!id) {
      const authLike = AUTH_CODES.has(one.answer.code ?? "") || one.answer.code === "audience_not_agent";
      return authLike ? bad(shown) : notRun(`${shown} — no receipt row to read; supply an inputs fixture an app caller can run`);
    }
    const row = (await receiptRows()).find((x) => x.id === id);
    const caller = row && isObj(row.caller) ? row.caller : undefined;
    const got = `caller.product ${JSON.stringify(caller?.product)}, caller.name ${JSON.stringify(caller?.name)}`;
    if (caller?.product === "tbconf-observer") return bad(`${shown}; ${got}: the product was taken from the caller NAME (the decoy "tbconf-observer" has the same name), not from the entry of the grant's caller instance`);
    return verdict(caller?.product === "tbconf-impostor" && caller?.name === name, `${shown}; row ${got} (expected product "tbconf-impostor" from the companionCallers entry of ${appCaller}, name "${name}")`);
  });
  // spec 0.1.46 (GRANT-PRD): a companion grant carries `prd` = the product of its calling instance, signed with the grant.
  // `Caller.product` = the grant's `prd` FIRST, the slice companionCallers entry only when `prd` is absent (a grant minted
  // before Core sends it); both present and different = the call is refused `grant_invalid` (never "pick one").
  /** GRANT-PRD is an SDK >= 0.1.28 rule: an older SDK (version from its claim) is not_applicable by version, not a fail. */
  const prdGate = (): Outcome | null => {
    const v = b.claims[0]?.request.sdkVersion;
    return versionBelow(v, GRANT_PRD_SINCE) ? na(`SDK ${v} predates ${GRANT_PRD_SINCE} (GRANT-PRD, spec 0.1.46): not applicable by version`) : null;
  };
  const prdOp = () => byRank(agentOps.filter((o) => o.receipt)).sort((x, y) => Number(x.effect === "money") - Number(y.effect === "money"))[0];
  /** One app-caller call (nothing held: it probes the product, not the hold rules) and the product of its receipt row. */
  const prdCall = async (op: Operation, prd: string | undefined) => {
    const one = await appCall(appCaller, op, { held: [], ...(prd !== undefined ? { prd } : {}) });
    const shown = `${op.id}: ${show(one.answer)} (${one.how})`;
    const id = rowIdOf(one.answer);
    const row = id ? (await receiptRows()).find((x) => x.id === id) : undefined;
    const caller = row && isObj(row.caller) ? row.caller : undefined;
    return { one, shown, id, product: caller?.product, hasRow: !!row };
  };
  const prdNoRow = (shown: string, a: OpAnswer) =>
    AUTH_CODES.has(a.code ?? "") || a.code === "audience_not_agent" ? bad(shown) : notRun(`${shown} — no receipt row to read; supply an inputs fixture an app caller can run`);
  await s.run("A12.grant_prd_first", "an app caller's product comes from the companion grant's prd when the slice has no entry for it yet (GRANT-PRD)", "the caller instance is NOT in companionCallers (the slice lags one revision behind the new edge); its companion grant carries prd = tbconf-prd; the caller runs a receipt op → its tb.receipts_list row has caller.product = tbconf-prd", async () => {
    const gate = prdGate();
    if (gate) return gate;
    const op = prdOp();
    if (!op) return na("no agent op with receipt: true");
    if (!sess) return bad("no person session");
    await b.control.waitForSliceRevision(await b.control.unlistCompanionCaller(appCaller), T);
    const r = await prdCall(op, "tbconf-prd");
    if (!r.id) return prdNoRow(r.shown, r.one.answer);
    return verdict(r.product === "tbconf-prd", `${r.shown}; row caller.product ${JSON.stringify(r.product)} (expected "tbconf-prd" from the grant's prd, the slice has no entry for ${appCaller})`);
  });
  await s.run("A12.grant_prd_mismatch", "a grant prd that differs from the slice product of the same instance is refused grant_invalid (GRANT-PRD)", "the caller instance is listed in companionCallers with product tbconf-slice; its companion grant carries prd = tbconf-grant → the call is refused 403 grant_invalid, nothing runs and no receipt row names either product; the same instance with prd = tbconf-slice runs (quiet on good)", async () => {
    const gate = prdGate();
    if (gate) return gate;
    const op = prdOp();
    if (!op) return na("no agent op with receipt: true");
    if (!sess) return bad("no person session");
    await b.control.waitForSliceRevision(await b.control.listCompanionCaller({ product: "tbconf-slice" as ProductId, ins: appCaller, name: `Conformance caller ${ulid().slice(-6)}` }), T);
    const good = await prdCall(op, "tbconf-slice");
    const bad1 = await appCall(appCaller, op, { held: [], prd: "tbconf-grant" });
    const shown = `${op.id}: equal ${show(good.one.answer)}; differing ${show(bad1.answer)} (${bad1.how})`;
    if (!good.id) return prdNoRow(shown, good.one.answer);
    if (good.product !== "tbconf-slice") return bad(`${shown}; a grant whose prd equals the slice product must run with caller.product "tbconf-slice", got ${JSON.stringify(good.product)}`);
    if (isOk(bad1.answer) || isHeld(bad1.answer)) {
      const id = rowIdOf(bad1.answer);
      const row = id ? (await receiptRows()).find((x) => x.id === id) : undefined;
      const got = row && isObj(row.caller) ? JSON.stringify(row.caller.product) : "no row";
      return bad(`${shown}; the app ran/held a call whose grant prd (tbconf-grant) differs from the slice product (tbconf-slice); it took caller.product ${got} instead of refusing`);
    }
    return verdict(bad1.answer.status === 403 && bad1.answer.code === "grant_invalid", `${shown}; expected 403 grant_invalid`);
  });
  await s.run("A12.grant_prd_absent", "a grant without prd (an older Core) takes the product from the slice entry (GRANT-PRD)", "the caller instance is listed in companionCallers with product tbconf-slice-only; its companion grant carries no prd → the receipt row has caller.product = tbconf-slice-only", async () => {
    const gate = prdGate();
    if (gate) return gate;
    const op = prdOp();
    if (!op) return na("no agent op with receipt: true");
    if (!sess) return bad("no person session");
    await b.control.waitForSliceRevision(await b.control.listCompanionCaller({ product: "tbconf-slice-only" as ProductId, ins: appCaller, name: `Conformance caller ${ulid().slice(-6)}` }), T);
    const r = await prdCall(op, undefined);
    if (!r.id) return prdNoRow(r.shown, r.one.answer);
    return verdict(r.product === "tbconf-slice-only", `${r.shown}; row caller.product ${JSON.stringify(r.product)} (expected "tbconf-slice-only" from the slice entry)`);
  });
  await s.run("A12.app_caller_held", "an app caller's first_contact call is held from the companion grant held (C105a); the approval runs once (C8)", "app caller with a companion grant held = appsPolicy.held (DEFAULT_HELD_FAMILIES) calls a first_contact op → 202 held + holdId; approve via the person session; same input + same idempotency key → ok (not held); same call with a new key → held again (new holdId)", async () => {
    const op = byRank(agentOps.filter((o) => o.holdFamily === "first_contact"))[0];
    if (!op) return na("no agent op with holdFamily first_contact");
    if (!sess) return bad("no person session");
    if (!b.appsPolicy.held.includes("first_contact")) return bad(`fake bridge apps policy ${b.appsPolicy.held.join(",")} does not hold first_contact`);
    const caller = appCaller;
    const first = await appCall(caller, op);
    if (!isHeld(first.answer)) return bad(`${op.id} by app caller (${first.how}): ${show(first.answer)} (expected 202 held)`);
    const id = holdIdOf(first.answer);
    const d = await c().personOp(sess, "tb.holds_decide", { holdId: id, decision: "approve" });
    if (d.status !== 200) return bad(`approve ${show(d)}`);
    const same = track(await c().callOp(op.id, first.input, { caller, ...(first.key ? { idempotencyKey: first.key } : {}) }));
    const again = track(await c().callOp(op.id, first.input, { caller, ...(idemKey(op) ? { idempotencyKey: idemKey(op) } : {}) }));
    const pass = isOk(same) && isHeld(again) && holdIdOf(again) !== id;
    return verdict(pass, `${op.id} (${first.how}): first ${show(first.answer)}; after approval same input${first.key ? " + key" : ""} ${show(same)}; again${first.key ? " (new key)" : ""} ${show(again)}`);
  });
  // v0.1.18 (C106a, Connect F21): the fake slice carries agents[].scopeRequest for agent A; whether the app reads it
  // (ctx.agentScopeRequest) is not observable black-box
  s.record("A12.scope_request", "agent A's slice scopeRequest reaches the app (C106a)", `slice agents[].scopeRequest {product: ${product}, kind: connect_inbox, createName: conformance} for agent A → ctx.agentScopeRequest(agt)`, na("black-box apps need not expose the slice scopeRequest (CONFORMANCE v0.1.18); the fake slice carries it for agent A; the SDK's ctx.agentScopeRequest is covered by SDK unit tests"));

  // ── A11 resolve answers carry a hold family (MANIFEST v0.1.16 C107) ──
  // v0.1.18: `dynamic.<op>.resolveTools` (tealbrick-conformance.json) names the tools to resolve instead of the catalog
  // (an app whose catalog is empty without its engine makes them resolvable in its conformance start module); a listed
  // tool that does not resolve FAILS (the app promised it).
  await s.run("A11.resolve_family", "resolve answers with effect outward or money carry a holdFamily (C107)", "for every dynamic op: each catalog entry (or each configured dynamic.<op>.resolveTools name) resolved through the bridge op resolve {op, tool}; a resolution with effect outward|money has a known holdFamily (money → money); a configured tool that does not resolve fails", async () => {
    const dyn = m.operations.filter((o) => o.audience === "agent" && o.dynamic);
    const configured = ctx.dynamic ?? {};
    const strays = Object.keys(configured).filter((id) => !dyn.some((o) => o.id === id));
    if (strays.length) return bad(`tealbrick-conformance.json dynamic names ${strays.join(", ")}: not a dynamic agent op of this manifest`);
    if (dyn.length === 0) return na("no dynamic op declared");
    const problems: string[] = [];
    const seen: string[] = [];
    let resolved = 0;
    for (const op of dyn) {
      const listed = configured[op.id]?.resolveTools;
      let names: string[];
      if (listed) names = listed;
      else {
        const body: Record<string, Json> = op.dynamic?.mode === "search" ? { op: op.id, query: "", limit: 50 } : { op: op.id };
        const cat = await c().callBridgeOp("catalog", body);
        const list = Array.isArray(cat.body) ? cat.body : isObj(cat.body) && Array.isArray(cat.body.entries) ? cat.body.entries : null;
        if (cat.status !== 200 || !list) {
          problems.push(`${op.id}: catalog ${show(cat)}`);
          continue;
        }
        names = list.filter(isObj).slice(0, 50).map((e) => String(e.name));
      }
      for (const name of names) {
        const r = await c().callBridgeOp("resolve", { op: op.id, tool: name });
        if (r.status !== 200 || !isObj(r.body)) {
          if (listed) problems.push(`${op.id}/${name}: listed in dynamic.${op.id}.resolveTools but resolve answered ${r.status === 200 ? "null" : show(r)}`);
          else seen.push(`${op.id}/${name}: resolve ${show(r)}`);
          continue;
        }
        resolved++;
        const eff = String(r.body.effect);
        const hf = r.body.holdFamily;
        if (eff !== "outward" && eff !== "money") continue;
        const known = typeof hf === "string" && (KNOWN_HOLD_FAMILIES as readonly string[]).includes(hf);
        if (!known || (eff === "money" && hf !== "money")) problems.push(`${op.id}/${name}: effect ${eff}, holdFamily ${hf === undefined ? "MISSING" : String(hf)}`);
        else seen.push(`${op.id}/${name}: ${eff}/${String(hf)}`);
      }
    }
    if (problems.length) return bad(problems.slice(0, 6).join("; "));
    if (resolved === 0) return notRun(`no catalog entry resolved (${seen.slice(0, 4).join("; ") || "empty catalogs"}); list tools in tealbrick-conformance.json dynamic.<op>.resolveTools`);
    const via = dyn.filter((o) => configured[o.id]).length;
    return ok(`${resolved} resolutions of ${dyn.length} dynamic op(s)${via ? ` (${via} via configured resolveTools)` : ""}; outward/money ones carry a family${seen.length ? `: ${seen.slice(0, 4).join("; ")}` : ""}`);
  });

  // ── A11 rules.narrowing: an empty anyOf passes NOTHING (SDK-API §18 v0.1.23, C115) ──
  // `narrowing {op, input?, tag?}` (tealbrick-conformance.json) names a tag-filtered read. Items = the entries of every
  // array-valued field of `output` (or `output` itself when it is an array). n/a without the fixture.
  await s.run(
    "A11.narrowing_empty_anyof",
    "rules.narrowing memoryTags {anyOf: []} returns no items (C115)",
    "the configured narrowing.op as agent A: no rules.narrowing → ok with ≥ 1 item; rules.narrowing {v: 1, ruleId, reason, memoryTags: {anyOf: []}} → ok with no items, or 409 narrowing_unsupported; with narrowing.tag: {anyOf: [tag]} → only items whose tags hold it (normalised), ≥ 1 and ≤ the unfiltered count (or narrowing_unsupported)",
    async () => {
      const cfg = ctx.narrowing;
      if (!cfg) return na("no narrowing fixture in tealbrick-conformance.json (an app without tag-filtered reads)");
      const op = m.operations.find((o) => o.id === cfg.op);
      if (op?.audience !== "agent" || op.dynamic || op.crud.length !== 1 || op.crud[0] !== "read") return bad(`tealbrick-conformance.json narrowing.op ${JSON.stringify(cfg.op)}: not a static agent read op (crud [read]) of this manifest`);
      let input: Json;
      if (cfg.input !== undefined) {
        const r = resolvePlaceholders(cfg.input, setup);
        taint.push(...r.blocked);
        input = r.value;
      } else input = inputFor(op);
      const narrowed = (memoryTags: { anyOf: string[] } | null) =>
        c().callOp(op.id, input, { agent: agentA.id, ...(idemKey(op) ? { idempotencyKey: idemKey(op) } : {}), context: memoryTags ? { "rules.narrowing": { v: 1, ruleId: "conf", reason: "conformance", memoryTags } } : {} });
      // package 0.1.15 (Knowledge sweep): ONE items array — narrowing.itemsPath, else the output itself when it is an
      // array, else its only array field; several array fields (e.g. a status list next to the results) and no itemsPath
      // → not_run (counting every array gave a false FAIL)
      let ambiguous: string[] | null = null;
      const itemsOf = (a: OpAnswer): unknown[] => {
        const out = isObj(a.body) ? a.body.output : undefined;
        if (cfg.itemsPath !== undefined) {
          const v = jsonPointer(out, cfg.itemsPath);
          return Array.isArray(v) ? v : [];
        }
        if (Array.isArray(out)) return out;
        if (!isObj(out)) return [];
        const arrays = Object.entries(out).filter(([, v]) => Array.isArray(v));
        if (arrays.length > 1) ambiguous = arrays.map(([k]) => k);
        return arrays.length === 1 ? (arrays[0]?.[1] as unknown[]) : [];
      };
      const unsupported = (a: OpAnswer) => a.status === 409 && errorCode(a.body) === "narrowing_unsupported";
      const plain = await narrowed(null);
      if (!isOk(plain)) return bad(`${op.id} without rules.narrowing: ${show(plain)} (expected 200 ok)`);
      const all = itemsOf(plain).length;
      if (ambiguous) return notRun(`${op.id} output has several array fields (${(ambiguous as string[]).join(", ")}): name the result items with narrowing.itemsPath (JSON pointer) in tealbrick-conformance.json`);
      if (all === 0) return notRun(`${op.id} without rules.narrowing returned no items: the fixture (setup + narrowing.input) must yield tagged items, else an empty anyOf cannot be told apart`);
      const empty = await narrowed({ anyOf: [] });
      const emptyN = isOk(empty) ? itemsOf(empty).length : null;
      const emptyOk = unsupported(empty) || emptyN === 0;
      const parts = [`unfiltered ${all} item(s)`, `anyOf [] → ${show(empty)}${emptyN === null ? "" : `, ${emptyN} item(s)${emptyN ? " (an empty anyOf must pass NOTHING)" : ""}`}`];
      let tagOk = true;
      if (cfg.tag !== undefined) {
        const want = normalizeTag(cfg.tag);
        const tagged = await narrowed({ anyOf: [cfg.tag] });
        if (unsupported(tagged)) parts.push(`anyOf [${JSON.stringify(cfg.tag)}] → ${show(tagged)}`);
        else if (!isOk(tagged)) {
          tagOk = false;
          parts.push(`anyOf [${JSON.stringify(cfg.tag)}] → ${show(tagged)} (expected 200 ok or narrowing_unsupported)`);
        } else {
          const items = itemsOf(tagged);
          const off = items.filter((x) => !isObj(x) || !Array.isArray(x.tags) || !x.tags.some((t) => typeof t === "string" && normalizeTag(t) === want)).length;
          tagOk = off === 0 && items.length >= 1 && items.length <= all;
          parts.push(`anyOf [${JSON.stringify(cfg.tag)}] → ${items.length} item(s)${off ? `, ${off} without the tag` : ""}${items.length === 0 ? " (none: the fixture promises an item with the tag)" : ""}${items.length > all ? " (more than unfiltered)" : ""}`);
        }
      } else parts.push("anyOf [tag] not checked (no narrowing.tag)");
      return verdict(emptyOk && tagOk, `${op.id}: ${parts.join("; ")}`);
    },
  );

  // ── A10 post-approval retry + P1 held release while paused + C8 no standing approval ──
  let retry: OpAnswer | null = null;
  const decide = async (id: string, decision: "approve" | "deny") => (sess ? c().personOp(sess, "tb.holds_decide", { holdId: id, decision }) : null);
  await s.run("A10", "approved hold runs only on the same input", "after approval: different input → new hold; same input (+ key) → runs (not held), hold row → run|failed", async () => {
    if (!hold || !sess) return noHold("no hold/session");
    const h = hold as { op: Operation; input: Json; answer: OpAnswer; key?: string };
    const id = holdIdOf(h.answer);
    const d = await decide(id, "approve");
    if (d?.status !== 200) return bad(`approve ${d ? show(d) : "no session"}`);
    let other: OpAnswer | null = null;
    for (const v of variants(h.op, h.input)) {
      other = await c().callOp(h.op.id, v, { ...holdOpts(h.op), idempotencyKey: idemKey(h.op) });
      if (isHeld(other) || isOk(other)) break;
    }
    const otherOk = other !== null && isHeld(other) && holdIdOf(other) !== id;
    const pausedRev = await b.control.pauseWorkspace(true);
    await b.control.waitForSliceRevision(pausedRev, T);
    const whilePaused = await c().callOp(h.op.id, h.input, { ...holdOpts(h.op), ...(h.key ? { idempotencyKey: h.key } : {}) });
    await b.control.waitForSliceRevision(await b.control.pauseWorkspace(false), T);
    retry = track(await c().callOp(h.op.id, h.input, { ...holdOpts(h.op), ...(h.key ? { idempotencyKey: h.key } : {}) }));
    const st = await c().callOp("tb.hold_status", { holdId: id });
    const status = isObj(st.body) && isObj(st.body.output) ? String(st.body.output.status) : "?";
    s.record("P1.held_release_paused", "held action released while paused is refused (A)", "approved hold retried under the workspace kill switch → refused paused; approval kept", {
      pass: whilePaused.code === "paused",
      asserted: `while paused: ${show(whilePaused)}`,
    });
    const ran = retry.status !== 202 && !AUTH_CODES.has(retry.code ?? "") && (status === "run" || status === "failed");
    return verdict(otherOk && ran, `other input: ${other ? show(other) : "none"}; same input: ${show(retry)}; hold row ${status}`);
  });
  if (!s.has("P1.held_release_paused")) s.record("P1.held_release_paused", "held action released while paused is refused (A)", "approved hold retried under the workspace kill switch → refused paused", noHold("A10 did not reach the paused retry"));
  await s.run("A3.no_standing_approval", "no always-allow record after an approval (C8)", "the same call again after the approved retry → held again (new holdId)", async () => {
    if (!hold || !retry) return noHold("A10 did not complete");
    const h = hold as { op: Operation; input: Json; answer: OpAnswer };
    const again = track(await c().callOp(h.op.id, h.input, { ...holdOpts(h.op), idempotencyKey: idemKey(h.op) }));
    return verdict(isHeld(again) && holdIdOf(again) !== holdIdOf(h.answer), show(again));
  });
  await s.run("A4.mark_after_failed", "bridge mark → receipt after_failed", "POST /tb/v1/bridge/mark {call, mark: after_failed} → the receipt of that call is after_failed (direct run: its call id; post-approval retry: the held call's id)", async () => {
    // Rule (Lead · Specs, accepting SPEC-GAP 3 of SDK-API §4.3): the receipt of a post-approval retry keeps the held
    // call's id, so `mark` for it names the held call.
    if (!sess) return bad("no session");
    const targets: { rid: string; call: string; kind: string }[] = [];
    const direct = okAnswers.find((a) => isObj(a.body) && typeof a.body.receiptId === "string" && a.body.receiptId.startsWith("rcp_"));
    if (direct) targets.push({ rid: String((direct.body as Record<string, unknown>).receiptId), call: String(direct.callId), kind: "direct run" });
    const held = hold as { answer: OpAnswer } | null;
    const r0 = retry as OpAnswer | null;
    if (held && r0 && isOk(r0) && isObj(r0.body) && r0.body.receiptId === holdIdOf(held.answer)) targets.push({ rid: holdIdOf(held.answer), call: String(held.answer.callId), kind: "post-approval retry (held call id)" });
    if (targets.length === 0) {
      // Fleet (v0.1.13): nothing to mark when no agent op writes a receipt
      if (!agentOps.some((o) => o.receipt)) return na("no agent op has receipt: true");
      return notRun("no call ran ok with a receipt (supply an inputs fixture for a receipt op)");
    }
    const seen: string[] = [];
    for (const t of targets) {
      const a = await c().callBridgeOp("mark", { call: t.call, mark: "after_failed" });
      if (a.status !== 200) return bad(`mark (${t.kind}) ${show(a)}`);
    }
    const r = await c().personOp(sess, "tb.receipts_list", {});
    const items = isObj(r.output) && Array.isArray(r.output.items) ? r.output.items : [];
    let pass = true;
    for (const t of targets) {
      const row = items.find((x) => isObj(x) && x.id === t.rid) as Record<string, unknown> | undefined;
      pass &&= row?.status === "after_failed";
      seen.push(`${t.kind} ${t.rid}: ${String(row?.status ?? "missing")}`);
    }
    return verdict(pass, seen.join("; "));
  });

  // ── A14 hook hold verdict at the app (SDK-API v0.1.13 authorize step 2b; CREDENTIALS v0.1.13 `hv`) ──
  // The fake bridge signs `hv` into the op proof as a bridge with a holding before hook would. The probe op prefers a
  // non-money op that is NOT holdable on its own (read), so the hold can only come from the verdict.
  const ownBefore = hooks.find((h) => h.phase === "before");
  const HV_BY = `${ownBefore ? product : "tbconf-rules"}/${ownBefore?.id ?? "conformance_policy"}`;
  const hvClaim = (r: string): HoldVerdictClaim => ({ f: "policy", r, by: HV_BY });
  const hvOp = byRank(agentOps.filter((o) => o.effect !== "money")).sort((x, y) => rank(x) - rank(y) || Number(holdable(x)) - Number(holdable(y)))[0];
  const NO_HV_OP = "no agent op other than money (a money op is always held, so a verdict hold is not observable)";
  const hvCall = (input: Json, reason: string, opts: CallOptions = {}) => c().callOp((hvOp as Operation).id, input, { hv: hvClaim(reason), idempotencyKey: idemKey(hvOp), ...opts });
  const listHolds = async (): Promise<Record<string, unknown>[]> => {
    if (!sess) return [];
    const r = await c().personOp(sess, "tb.holds_list", {});
    return (isObj(r.output) && Array.isArray(r.output.items) ? r.output.items : []).filter(isObj);
  };
  const openHolds = async () => (await listHolds()).filter((x) => x.status === "held").length;
  let hvHold: { op: Operation; input: Json; id: string } | null = null;
  await s.run("A14.hook_hold", "op proof with a hook hold verdict (hv) → held, heldBy recorded", `proof hv {f: policy, r, by: "${HV_BY}"} on an op the grant would run → 202 held; tb.holds_list row holdFamily policy, heldBy = hv.by (tb.hold_status family / reason accepted, not required)`, async () => {
    if (!hvOp) return na(NO_HV_OP);
    if (!sess) return bad("no person session");
    const input = inputFor(hvOp);
    const reason = `conformance policy hold ${ulid()}`;
    const a = track(await hvCall(input, reason));
    if (!isHeld(a)) return bad(`${hvOp.id} (${hvOp.effect}) with hv: ${show(a)}${reachable(hvOp) ? "" : " — no scope instance found; supply inputs fixture"}`);
    const id = holdIdOf(a);
    hvHold = { op: hvOp, input, id };
    const row = (await listHolds()).find((x) => x.id === id);
    const st = await c().callOp("tb.hold_status", { holdId: id });
    const out = isObj(st.body) && isObj(st.body.output) ? st.body.output : {};
    const extra = `${out.family !== undefined ? `, family ${String(out.family)}` : ""}${out.reason !== undefined ? `, reason ${out.reason === reason ? "= hv.r" : String(out.reason)}` : ""}`;
    return verdict(row?.holdFamily === "policy" && row.heldBy === HV_BY, `${hvOp.id}: ${show(a)}; holds_list ${row ? `holdFamily ${String(row.holdFamily)}, heldBy ${String(row.heldBy)}` : "row missing"}; hold_status ${show(st)} ${String(out.status)}${extra}`);
  });
  await s.run("A14.hold_retry_once", "approved verdict hold runs once on the same input; another input → new hold", "after approval: other input + hv → new hold; same input + hv → runs (not held); same input + hv again → held again (new holdId)", async () => {
    if (!hvOp) return na(NO_HV_OP);
    if (!hvHold || !sess) return bad("A14.hook_hold created no hold");
    const h = hvHold as { op: Operation; input: Json; id: string };
    const d = await decide(h.id, "approve");
    if (d?.status !== 200) return bad(`approve ${d ? show(d) : "no session"}`);
    // try schema-valid variants until one is not refused by the app's own checks (a variant may target a scope
    // instance the caller cannot reach → scope_denied; that says nothing about the hold rule, as in A10)
    let other: OpAnswer | null = null;
    for (const alt of schemaVariants(h.op, h.input)) {
      other = await hvCall(alt, "conformance other input");
      if (isHeld(other) || isOk(other)) break;
    }
    const otherOk = other === null || other.status >= 400 || (isHeld(other) && holdIdOf(other) !== h.id);
    const once = track(await hvCall(h.input, "conformance retry"));
    const twice = track(await hvCall(h.input, "conformance retry again"));
    const pass = otherOk && isOk(once) && isHeld(twice) && holdIdOf(twice) !== h.id;
    return verdict(pass, `other input: ${other ? `${show(other)}${other.status >= 400 ? " (every variant refused by the app: new-hold part not provable)" : ""}` : "n/a (no schema-valid variant)"}; same input: ${show(once)}; again: ${show(twice)}`);
  });
  await s.run("A14.scope_wins", "a scope refusal beats a hook hold verdict", "op whose crud exceeds grant.crud, proof with hv → refused scope_denied (not held)", async () => {
    const op = agentOps.find((o) => o.crud.some((x) => x !== "read")) ?? agentOps[0];
    if (!op) return na("no agent op");
    const narrower: CrudAction[] = (["create", "read", "update", "delete"] as CrudAction[]).filter((x) => !op.crud.includes(x)).slice(0, 1);
    const a = await c().callOp(op.id, inputFor(op), { crud: narrower, hv: hvClaim("conformance scope probe"), idempotencyKey: idemKey(op) });
    const o = refusedWith(a, ["scope_denied", "crud_exceeds_grant"]);
    return { ...o, asserted: `${op.id} (grant crud [${narrower.join(",")}]) + hv: ${o.asserted}` };
  });

  // ── A15 tb.holds_pending (SDK-API v0.1.13 G4): summaries only; agent → own holds; companion app → all; paging ──
  await s.run("A15.holds_pending", "tb.holds_pending: summaries only, agent sees own holds, companion app sees all, paging", "holds by agents A and B: A sees its hold and not B's; an app caller (grant wf [tb.holds_pending]) sees both; no item has input / view / meta; limit 1 + cursor pages without repeats", async () => {
    if (!hvOp) return na(NO_HV_OP);
    const hA = await hvCall(inputFor(hvOp, agentA.id), "conformance pending A", { agent: agentA.id });
    const hB = await hvCall(inputFor(hvOp, agentB.id), "conformance pending B", { agent: agentB.id });
    if (!isHeld(hA) || !isHeld(hB)) return bad(`holds not created: A ${show(hA)}; B ${show(hB)}`);
    const [idA, idB] = [holdIdOf(hA), holdIdOf(hB)];
    const peerIns = appCaller;
    /** every page of tb.holds_pending for one caller; null on a non-ok answer */
    const all = async (opts: CallOptions, limit?: number): Promise<{ items: Record<string, unknown>[]; pages: number; shown: string } | null> => {
      const items: Record<string, unknown>[] = [];
      let cursor: string | null = null;
      for (let pages = 1; pages <= 200; pages++) {
        const a = await c().callOp(HOLDS_PENDING_OP, { ...(limit ? { limit } : {}), ...(cursor ? { cursor } : {}) }, opts);
        const out = isObj(a.body) && isObj(a.body.output) ? a.body.output : null;
        if (!isOk(a) || !out || !Array.isArray(out.items)) return { items, pages, shown: show(a) };
        if (limit !== undefined && out.items.length > limit) return { items, pages, shown: `page ${pages}: ${out.items.length} items > limit ${limit}` };
        items.push(...out.items.filter(isObj));
        cursor = typeof out.nextCursor === "string" ? out.nextCursor : null;
        if (!cursor) return { items, pages, shown: "ok" };
      }
      return { items, pages: 200, shown: "more than 200 pages" };
    };
    const asA = await all({ agent: agentA.id });
    const asApp = await all({ caller: peerIns });
    const paged = await all({ caller: peerIns }, 1);
    if (!asA || !asApp || !paged) return bad("no answer");
    const problems: string[] = [];
    const ids = (x: { items: Record<string, unknown>[] }) => x.items.map((i) => String(i.id));
    if (asA.shown !== "ok") problems.push(`agent: ${asA.shown}`);
    if (!ids(asA).includes(idA)) problems.push("agent A misses its own hold");
    if (ids(asA).includes(idB)) problems.push("agent A sees agent B's hold");
    const foreign = asA.items.filter((i) => isObj(i.caller) && i.caller.id !== agentA.id).length;
    if (foreign) problems.push(`agent A sees ${foreign} items of other callers`);
    if (asApp.shown !== "ok" || !ids(asApp).includes(idA) || !ids(asApp).includes(idB)) problems.push(`app caller: ${asApp.shown}, sees A ${ids(asApp).includes(idA)}, B ${ids(asApp).includes(idB)}`);
    const leaky = [...asA.items, ...asApp.items].filter((i) => ["input", "view", "meta"].some((k) => k in i)).length;
    if (leaky) problems.push(`${leaky} items carry input / view / meta`);
    const pIds = ids(paged);
    if (paged.shown !== "ok" || paged.pages < 2 || new Set(pIds).size !== pIds.length || !pIds.includes(idA) || !pIds.includes(idB)) problems.push(`paging (limit 1): ${paged.shown}, ${paged.pages} pages, ${pIds.length} items, ${new Set(pIds).size} distinct`);
    return verdict(problems.length === 0, problems.length ? problems.join("; ") : `agent A: ${asA.items.length} items (own only); app caller: ${asApp.items.length} items; limit 1: ${paged.pages} pages, no repeats; summaries only`);
  });

  // ── A17 pending count + status push (SDK-API v0.1.13 C86 + clarification: statusChanged on every hold change) ──
  await s.run("A17.status_changed", "a new hold is pushed to the bridge within 2 s", "after a hold is created, a status push with pendingHolds ≥ the open holds arrives within 2 s (no slice change in between)", async () => {
    if (!hvOp) return na(NO_HV_OP);
    if (!sess) return bad("no person session");
    const t0 = Date.now();
    const a = await hvCall(inputFor(hvOp), "conformance status push probe");
    if (!isHeld(a)) return bad(`no hold: ${show(a)}`);
    const tHeld = Date.now();
    const open = await openHolds();
    const seen = await b.control.waitForStatus((x) => x.at >= t0 && x.status.pendingHolds >= open, Math.max(0, tHeld + 2000 - Date.now())).catch(() => null);
    const last = b.statuses.at(-1);
    return verdict(!!seen, seen ? `push ${seen.at - tHeld} ms after the hold answer, pendingHolds ${seen.status.pendingHolds} (open holds ${open})` : `no push with pendingHolds ≥ ${open} within 2 s (last push ${last ? `${last.status.pendingHolds} at ${last.at - tHeld} ms` : "none"})`);
  });
  await s.run("A17.pending_count", "status pendingHolds counts the open holds and drops after a decision", "after a new hold: the next status push (slice republished) has pendingHolds ≥ the open holds (tb.holds_list); after denying it the next push is lower", async () => {
    if (!hvOp) return na(NO_HV_OP);
    if (!sess) return bad("no person session");
    const a = await hvCall(inputFor(hvOp), "conformance pending count probe");
    if (!isHeld(a)) return bad(`no hold: ${show(a)}`);
    const open1 = await openHolds();
    const st1 = await b.control.waitForSliceRevision(await b.control.republish(), T);
    const d = await decide(holdIdOf(a), "deny");
    if (d?.status !== 200) return bad(`deny ${d ? show(d) : "no session"}`);
    const open2 = await openHolds();
    const st2 = await b.control.waitForSliceRevision(await b.control.republish(), T);
    const [n1, n2] = [st1.status.pendingHolds, st2.status.pendingHolds];
    return verdict(n1 >= open1 && n2 < n1 && n2 >= open2, `with the hold: pendingHolds ${n1} (open ${open1}); after deny: ${n2} (open ${open2})`);
  });

  // ── P1 pause cells for the app (A refuses ≤ 60 s after B) ──
  // Probed with a manifest op: `tb.hold_status` (valid grant suffices, I4) is not required to run authorize() step 0.
  const pauseOp = holdOp ?? agentOps[0];
  // hold options only for a holdable op: a read op with `caps: {read: …}` is an invalid grant (Fleet, 2026-10-12)
  const pauseCall = (agent = agentA.id) => c().callOp(pauseOp.id, inputFor(pauseOp, agent), { agent, ...(holdable(pauseOp) ? holdOpts(pauseOp) : {}), idempotencyKey: idemKey(pauseOp) });
  if (pauseOp) {
    await s.run("P1.workspace", "workspace kill switch → app refuses agent grants", "slice pause.workspace → op call refused paused", async () => {
      const rev = await b.control.pauseWorkspace(true);
      const seen = await b.control.waitForSliceRevision(rev, T);
      const a = await pauseCall();
      await b.control.waitForSliceRevision(await b.control.pauseWorkspace(false), T);
      const o = refusedWith(a, ["paused"]);
      return { ...o, asserted: `${o.asserted}; status push accepted while paused (slice rev ${seen.status.sliceRevision})` };
    });
    await s.run("P1.agent", "agent pause → that agent refused, others unaffected", "slice pause.agents=[A] → A refused paused; B not refused paused", async () => {
      await b.control.waitForSliceRevision(await b.control.pauseAgent(agentA.id, true), T);
      const a = await pauseCall(agentA.id);
      const other = await pauseCall(agentB.id);
      await b.control.waitForSliceRevision(await b.control.pauseAgent(agentA.id, false), T);
      return verdict(a.code === "paused" && other.code !== "paused", `A: ${show(a)}; B: ${show(other)}`);
    });
    await s.run("P1.instance", "instance pause → app refuses all ops on itself", "slice pause.instances=[self] → refused paused", async () => {
      await b.control.waitForSliceRevision(await b.control.pauseInstance(true), T);
      const a = await pauseCall();
      await b.control.waitForSliceRevision(await b.control.pauseInstance(false), T);
      return refusedWith(a, ["paused"]);
    });
  } else {
    for (const id of ["P1.workspace", "P1.agent", "P1.instance"]) s.record(id, "pause cell", "op call refused paused", na("manifest declares no agent operation"));
  }

  // ── C5 key rotation (Portal key and bridge key) ──
  await s.run("C5.portal_key_rotation", "Portal key rotation: announced key accepted after activation; removed key refused", "grant by new key ok after activate; grant by old key ok while retired-listed, refused after removal", async () => {
    const old = b.activePortalKey();
    await b.control.waitForSliceRevision(await b.control.rotatePortalKey("announce"), T);
    await b.control.waitForSliceRevision(await b.control.rotatePortalKey("activate"), T);
    const byNew = await c().callOp("tb.hold_status", hs);
    const byOldRetired = await c().callOp("tb.hold_status", hs, { grantKey: old });
    await b.control.waitForSliceRevision(await b.control.rotatePortalKey("retire"), T);
    const byOldRemoved = await c().callOp("tb.hold_status", hs, { grantKey: old });
    const pass = !AUTH_CODES.has(byNew.code ?? "") && !AUTH_CODES.has(byOldRetired.code ?? "") && byOldRemoved.code === "grant_invalid";
    return verdict(pass, `new: ${show(byNew)}; old (retired): ${show(byOldRetired)}; old (removed): ${show(byOldRemoved)}`);
  });
  await s.run("C5.bridge_key_rotation", "bridge re-enrolment: proofs by the new key accepted, old key refused", "after a slice with only the new bridge key: new-key proof ok, old-key proof refused", async () => {
    const old = b.bridgeKeys[0];
    await b.control.waitForSliceRevision(await b.control.rotateBridgeKey(), T);
    const byNew = await c().callOp("tb.hold_status", hs);
    const grant = await b.mint.grant({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, crud: ["read"], mode: "free" });
    const proof = await b.mint.callProof({ sub: `tb:agt:${agentA.id}`, aud: `tb:ins:${b.ids.ins}`, gjti: String(peek(grant)?.jti), op: "tb.hold_status", input: hs, context: {}, key: old });
    const byOld = await c().callOp("tb.hold_status", hs, { grant, proof });
    return verdict(!AUTH_CODES.has(byNew.code ?? "") && byOld.code === "call_proof_invalid", `new: ${show(byNew)}; old: ${show(byOld)}`);
  });

  // ── A6 session end: personNbf, logout ──
  await s.run("A6.person_nbf", "sign out everywhere (slice personNbf)", "a session created before personNbf → session_required", async () => {
    const fresh = await c().signIn();
    if (!fresh) return bad("sign-in failed");
    secrets.cookies.push(fresh.cookie);
    await b.control.waitForSliceRevision(await b.control.setPersonNbf(nowS() + 1), T);
    const a = await c().personOp(fresh, "tb.agents_list", {});
    return refusedWith(a, ["session_required"]);
  });
  await new Promise((r) => setTimeout(r, 1100));
  sess = await c().signIn();
  if (sess) secrets.cookies.push(sess.cookie);
  await s.run("A6.logout", "logout ends the session", "POST …/tb/v1/logout → the cookie no longer works (session_required)", async () => {
    const fresh = await c().signIn();
    if (!fresh) return bad("sign-in failed");
    secrets.cookies.push(fresh.cookie);
    const out = await c().logout(fresh);
    const after = await c().personOp(fresh, "tb.agents_list", {});
    const o = refusedWith(after, ["session_required"]);
    return { ...o, asserted: `logout ${out.status}; after: ${o.asserted}` };
  });

  // ── A7 data plumbing ──
  await s.run("A7.export", "export produces the documented format", "tb.export → gzip tar with meta.json {format: tealbrick.export/1, files[] sha256} + receipts.jsonl + audit.jsonl; no tb_keys/sessions", async () => {
    if (!sess) return bad("no session");
    const a = await c().personOp(sess, "tb.export", {});
    if (a.status !== 200) return bad(show(a));
    const { readTar } = await import("../tar.ts");
    const entries = readTar(a.bytes);
    const metaEntry = entries.find((e) => e.name === "meta.json");
    if (!metaEntry) return bad(`no meta.json (${entries.map((e) => e.name).join(",")})`);
    const meta = JSON.parse(new TextDecoder().decode(metaEntry.data)) as { format?: string; files?: { file: string; sha256: string }[] };
    const names = entries.map((e) => e.name);
    const { createHash } = await import("node:crypto");
    const shaBad = (meta.files ?? []).filter((f) => {
      const e = entries.find((x) => x.name === f.file);
      return !e || createHash("sha256").update(e.data).digest("hex") !== f.sha256.replace(/^sha256:/, "");
    });
    const forbidden = names.filter((n) => /tb_keys|tb_sessions|tb_used_jti/.test(n));
    const good = meta.format === "tealbrick.export/1" && names.includes("receipts.jsonl") && names.includes("audit.jsonl") && shaBad.length === 0 && forbidden.length === 0;
    return verdict(good, `format ${meta.format}; ${names.length} files; sha mismatches ${shaBad.length}; forbidden ${forbidden.join(",") || "none"}`);
  });
  const extraHold = holdOp ? await c().callOp(holdOp.id, inputFor(holdOp), { ...holdOpts(holdOp), idempotencyKey: idemKey(holdOp) }) : null;
  await s.run("A7.restart", "migrations repeatable; state survives a restart; no re-claim", "restart on the same data dir: no new claim, same instance key kid, holds still readable", async () => {
    if (!ctx.restart) return notRun("needs a restartable app (runApp start()/--cmd)");
    // without a holdable op the persisted facts are the claim record and the instance key (no new claim, same kid)
    if (holdOp && (!extraHold || !isHeld(extraHold))) return noHold("no hold to persist");
    const claims = b.claims.length;
    const kid = b.statuses.at(-1)?.assertion.kid;
    const n = b.statuses.length;
    await ctx.restart();
    const st = await b.control.waitForStatus((x) => b.statuses.indexOf(x) >= n, T);
    const hsAns = extraHold && isHeld(extraHold) ? await c().callOp("tb.hold_status", { holdId: holdIdOf(extraHold) }) : null;
    const status = hsAns === null ? "n/a (no holdable op)" : isObj(hsAns.body) && isObj(hsAns.body.output) ? hsAns.body.output.status : null;
    s.record("A1.key_persisted", "instance key kept sealed on the volume", "after restart the status push is signed by the same instance key, with no new claim", {
      pass: st.assertion.kid === kid && b.claims.length === claims,
      asserted: `kid ${st.assertion.kid === kid ? "unchanged" : "CHANGED"}; claims ${claims} → ${b.claims.length}`,
    });
    const statePass = hsAns === null ? st.assertion.kid === kid : status === "held";
    return verdict(b.claims.length === claims && statePass, `claims ${claims} → ${b.claims.length}; ${hsAns === null ? `instance key kid ${st.assertion.kid === kid ? "unchanged" : "CHANGED"} (no holdable op)` : `hold after restart: ${String(status)}`}`);
  });
  if (!s.has("A1.key_persisted")) s.record("A1.key_persisted", "instance key kept sealed on the volume", "after restart the same key, no new claim", ctx.restart ? bad("restart did not complete") : notRun("needs a restartable app"));
  await s.run("A7.backup_roundtrip", "backup to TB_BACKUP_DIR + restore round-trip", "archive tb-backup-*.tar.gz with meta {format tealbrick.backup/1, parts sha256}; TB_RESTORE_FROM restores the state at backup time", async () => {
    if (!ctx.backupNow || !ctx.restart) return notRun("needs start() returning backupNow (programmatic harness) and a restartable app");
    if (holdOp && (!extraHold || !isHeld(extraHold))) return noHold("no hold to back up");
    const dir = ctx.env.TB_BACKUP_DIR;
    const before = new Set(readdirSync(dir));
    await ctx.backupNow();
    const file = readdirSync(dir).filter((f) => /^tb-backup-.*\.tar\.gz$/.test(f) && !before.has(f)).sort().at(-1);
    if (!file) return bad(`no new tb-backup-*.tar.gz in TB_BACKUP_DIR`);
    const { readTar } = await import("../tar.ts");
    const { createHash } = await import("node:crypto");
    const entries = readTar(new Uint8Array(readFileSync(join(dir, file))));
    const metaE = entries.find((e) => e.name === "meta.json");
    const meta = metaE ? (JSON.parse(new TextDecoder().decode(metaE.data)) as { format?: string; manifestDigest?: string; instance?: string; parts?: { file: string; sha256: string; bytes: number }[] }) : null;
    if (meta?.format !== "tealbrick.backup/1") return bad(`meta ${meta ? meta.format : "missing"}`);
    const partBad = (meta.parts ?? []).filter((p) => {
      const e = entries.find((x) => x.name === p.file);
      return !e || e.data.length !== p.bytes || createHash("sha256").update(e.data).digest("hex") !== p.sha256.replace(/^sha256:/, "");
    });
    if (partBad.length || meta.manifestDigest !== manifestDigest(m) || meta.instance !== b.ids.ins) return bad(`parts bad ${partBad.length}; digest ${meta.manifestDigest === manifestDigest(m) ? "ok" : "mismatch"}; instance ${meta.instance === b.ids.ins ? "ok" : "mismatch"}`);
    if (!holdOp || !extraHold) {
      // no holdable op: archive shape checked above; the restore must boot with the same instance (status push)
      const n0 = b.statuses.length;
      await ctx.restart({ TB_RESTORE_FROM: file });
      const st0 = await b.control.waitForStatus((x) => b.statuses.indexOf(x) >= n0, T);
      return verdict(st0.assertion.kid === b.statuses[n0 - 1]?.assertion.kid, `archive ${file} (${meta.parts?.length ?? 0} parts); restored and booted, instance key ${st0.assertion.kid === b.statuses[n0 - 1]?.assertion.kid ? "unchanged" : "CHANGED"} (no holdable op to probe state)`);
    }
    const after = await c().callOp(holdOp.id, inputFor(holdOp), { ...holdOpts(holdOp), idempotencyKey: idemKey(holdOp) });
    const n = b.statuses.length;
    await ctx.restart({ TB_RESTORE_FROM: file });
    await b.control.waitForStatus((x) => b.statuses.indexOf(x) >= n, T);
    const kept = await c().callOp("tb.hold_status", { holdId: holdIdOf(extraHold) });
    const gone = isHeld(after) ? await c().callOp("tb.hold_status", { holdId: holdIdOf(after) }) : null;
    const keptOk = isObj(kept.body) && isObj(kept.body.output) && kept.body.output.status === "held";
    const goneOk = gone !== null && gone.status === 404;
    return verdict(keptOk && goneOk, `archive ${file} (${meta.parts?.length ?? 0} parts); hold before backup: ${show(kept)}; hold after backup: ${gone ? show(gone) : "not created"}`);
  });

  // ── A1 reclaim (SDK-API §13 v0.1.12, spine S1): a refused identity is replaced only with a NEW enrolment code ──
  await s.run("A1.reclaim_on_new_code", "refused identity + new enrolment code → a fresh claim; same code → none", "bridge forgets the instance key: restart with the claimed code → no claim within 3 s; restart with a new code → one claim with it, then a status push accepted again", async () => {
    if (!ctx.restart) return notRun("needs a restartable app (runApp start()/--cmd)");
    const restore = b.control.forgetInstanceKey();
    try {
      const n = b.claims.length;
      await ctx.restart();
      await new Promise((r) => setTimeout(r, 3000));
      const sameCode = b.claims.length - n;
      const code = b.control.issueEnrolCode();
      const want = opaqueDigest(code);
      await ctx.restart({ TB_ENROL_CODE: code });
      const end = Date.now() + T;
      while (Date.now() < end && !b.claims.slice(n).some((x) => x.codeDigest === want)) await new Promise((r) => setTimeout(r, 100));
      const claim = b.claims.slice(n).find((x) => x.codeDigest === want);
      const pushed = claim ? await b.control.waitForStatus((x) => x.at >= claim.at, T).then(() => true, () => false) : false;
      return verdict(sameCode === 0 && claim !== undefined && pushed, `same code: ${sameCode} claim(s); new code: ${claim ? "claimed" : "NO claim"}; status after reclaim ${pushed ? "accepted" : "missing"}`);
    } finally {
      restore();
    }
  });

  // ── C7 lifetimes, C8 no shared secret ──
  await s.run("C7.assertion_lifetime", "no long-lived bearer from the app", "every instance assertion seen has exp − iat ≤ 60 s", () => {
    const lt = b.statuses.map((x) => x.assertion.exp - x.assertion.iat);
    if (lt.length === 0) return bad("no assertions seen");
    return verdict(Math.max(...lt) <= 60, `${lt.length} assertions, max lifetime ${Math.max(...lt)} s`);
  });
  await s.run("C8.no_shared_secret", "no shared secret between app and bridge", "requests to the bridge carry no Authorization header; every request after the claim carries TB-Assert", () => {
    const reqs = b.captured.filter((p) => p.dir === "bridge-in");
    const withAuth = reqs.filter((p) => "authorization" in p.headers).length;
    const unasserted = reqs.filter((p) => !p.path.startsWith("/tb/v1/claim") && !("tb-assert" in p.headers)).length;
    return verdict(reqs.length > 0 && withAuth === 0 && unasserted === 0, `${reqs.length} requests; with Authorization ${withAuth}; without TB-Assert ${unasserted}`);
  });
  await s.run("C8.env", "only the enrolment code and TB_KEK as secret env", "TB_* env given to the app ⊆ SDK-API §13 names; secret values only TB_ENROL_CODE and TB_KEK", () => {
    const names = Object.keys(ctx.env).filter((k) => k.startsWith("TB_"));
    const unknown = names.filter((k) => !ALLOWED_ENV.has(k));
    return verdict(unknown.length === 0, `env ${names.join(",")}; secret ${names.filter((n) => SECRET_ENV.has(n)).join(",")}${unknown.length ? `; unknown ${unknown.join(",")}` : ""}`);
  });
  await s.run("C8.keys_via_bridge", "keys only from /tb/v1/keys, declared names only, values never echoed", "no key_not_declared refusal recorded; key values absent from every app answer", () => {
    const undeclared = b.violations.filter((v) => v.code === "key_not_declared").length;
    const answers = b.captured.filter((p) => p.dir === "app-in");
    const leaked = secrets.keyValues.filter((v) => answers.some((p) => p.body.includes(v))).length;
    if (defaultKeys.length === 0) return verdict(undeclared === 0, `no account_default keys declared; undeclared fetches ${undeclared}`);
    return verdict(undeclared === 0 && leaked === 0, `${b.keyFetches.length} fetches of ${defaultKeys.length} declared keys; undeclared ${undeclared}; leaked ${leaked}`);
  });

  // ── A9 public address ──
  await s.run("A9", "app has no public address", "manifest declares no public exposure (only bridge-served publicRoutes, no public-binding env), the app answers on a private address; with a deploy template: no app service has a public domain", () => {
    if (ctx.deployTemplate === undefined) {
      // Manifest level (Lead · Specs): the schema has no public-address field (strict, M1); publicRoutes are served only
      // through the bridge at /p/<product>/… (viewer routes, spec 0.1.43: through the workspace views service at /v/<product>/…,
      // never the app); runtime.port is the internal listen port.
      const problems: string[] = [];
      for (const r of m.publicRoutes ?? []) if (!r.path.startsWith("/") || !(PUBLIC_ROUTE_PURPOSES as readonly string[]).includes(r.purpose)) problems.push(`publicRoute ${r.path}`);
      const envs = [...(m.runtime.env ?? []), ...(m.runtime.services ?? []).flatMap((x) => x.env ?? [])];
      for (const e of envs) if (/^(PORT|HOST|HOSTNAME|BIND|LISTEN)$|PUBLIC_(URL|DOMAIN|HOST)/.test(e.name)) problems.push(`env ${e.name}`);
      const host = new URL(c().url).hostname.replace(/^\[|\]$/g, "");
      const priv = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|localhost$)|\.internal$/.test(host);
      if (!priv) problems.push(`app reached at non-private host ${host}`);
      return verdict(problems.length === 0, problems.length ? problems.join("; ") : `manifest-level; the live project check is QA (CONFORMANCE open Q1). ${m.publicRoutes?.length ?? 0} bridge-served publicRoutes; listen port ${m.runtime.port} internal; reached at ${host}`);
    }
    // SPEC-GAP: CONFORMANCE open question 1 — the deploy template format is not specified; any `*domain*` key with a
    // value on a non-bridge service counts as a public address.
    const offenders: string[] = [];
    const walk = (v: unknown, path: string, service: string | null) => {
      if (Array.isArray(v)) {
        for (const [i, x] of v.entries()) walk(x, `${path}[${i}]`, service);
      } else if (isObj(v)) {
        const name = typeof v.name === "string" ? v.name : service;
        for (const [k, x] of Object.entries(v)) {
          if (/domain/i.test(k) && x !== null && x !== false && !(Array.isArray(x) && x.length === 0) && x !== "" && !/bridge/i.test(String(name))) offenders.push(`${path}.${k} (${name ?? "?"})`);
          walk(x, `${path}.${k}`, name);
        }
      }
    };
    walk(ctx.deployTemplate, "$", null);
    return verdict(offenders.length === 0, offenders.length ? `public domains: ${offenders.join(", ")}` : "no public domain on app services");
  });

  // ── A13 key-set statements on slices (CREDENTIALS §9.5, v0.1.11) ──
  // CONF-MULTIAPP group X (only with --peers) runs INSIDE the key-set group, before its last check, which leaves the app
  // on a fresh data dir that never installs another slice; the driver calls the app's agent ops so it makes its real companion calls
  const multi = ctx.multi
    ? async () => {
        await ctx.multi?.({
          client: c,
          drive: async (done) => {
            const tried: string[] = [];
            for (const op of byRank(agentOps.filter((o) => o.effect !== "money")).slice(0, 40)) {
              if (done()) break;
              const key = idemKey(op);
              // nothing held: the call must RUN the handler, that is where the app calls its companion
              const a = await c().callOp(op.id, inputFor(op), { held: [], ...(key ? { idempotencyKey: key } : {}) }).catch((e: unknown) => ({ status: 0, body: String(e) }));
              tried.push(`${op.id} ${show(a)}`);
            }
            return tried;
          },
        });
      }
    : undefined;
  await keySetChecks(s, ctx, hs, multi);

  // ── A16 app-initiated calls (SDK-API v0.1.13 C85; observed only) ──
  await s.run("A16.call_outside_handler", "app-initiated companion calls carry a valid assertion and the app's companion grant", "every /tb/v1/call without parentCall seen by the fake bridge: instance assertion accepted, TB-Grant = a companion grant of this app's slice (sub tb:ins:<self>), no auth refusal; n/a when none is seen", () => {
    const forgotten = (at: number) => b.forgotten.some((w) => at >= w.from && (w.to === null || at <= w.to));
    const seen = b.callAttempts.filter((x) => x.envelope !== null && x.envelope.parentCall === undefined && !forgotten(x.at));
    if (seen.length === 0) return na("no app-initiated call (no parentCall) seen during the run (observed only)");
    const problems: string[] = [];
    for (const x of seen) {
      const where = `${String(x.envelope?.target)}.${String(x.envelope?.op)}`;
      if (x.caller !== b.ids.ins) problems.push(`${where}: instance assertion ${x.caller ? `of ${x.caller}` : `refused (${x.code})`}`);
      else if (!x.grant) problems.push(`${where}: no TB-Grant`);
      else if (!b.sliceGrants.has(x.grant) || peek(x.grant)?.sub !== `tb:ins:${b.ids.ins}`) problems.push(`${where}: TB-Grant is not a companion grant of this app's slice`);
      else if (x.code && AUTH_CODES.has(x.code)) problems.push(`${where}: refused ${x.code}`);
    }
    return verdict(problems.length === 0, problems.length ? problems.slice(0, 4).join("; ") : `${seen.length} app-initiated calls (e.g. ${String(seen[0]?.envelope?.target)}.${String(seen[0]?.envelope?.op)}), assertion and slice companion grant ok`);
  });

  // ── A11 SDK coverage ──
  await s.run("A11", "every exported function of types/sdk.ts has a check", "each generated SDK export maps to ≥ 1 catalogued check id", () => coverageOutcome());

  // ── payload scan (cred.p1.payload_scan_no_person_cred) ──
  const scan = scanPayloads(
    b.captured,
    [
      { label: "launch ticket value", values: secrets.tickets },
      { label: "app session cookie value", values: secrets.cookies },
      { label: "Clerk-like person JWT", values: secrets.clerk },
      { label: "owner CLI session (tbo_)", pattern: /\btbo_[A-Za-z0-9_-]{43}\b/ },
      { label: "account-default key value", values: secrets.keyValues },
    ],
    { select: (p) => (p.dir === "bridge-in" ? `app→bridge ${p.path.split("?")[0]}` : p.dir === "app-in" && p.path.startsWith("/tb/v1/") ? `app answer ${p.path.split("?")[0]}` : null) },
    [TYP.personTicket],
  );
  s.record("cred.p1.payload_scan_no_person_cred", "no person credential or key value in agent-facing payloads (C4)", "0 findings in app→bridge requests and agent-route answers", {
    pass: scan.findings.length === 0,
    asserted: `${scan.payloads} payloads; ${scan.findings.length} findings${scan.findings.length ? `: ${scan.findings.join("; ")}` : ""}`,
  });
  s.guard = null;
  return scan;
}

/** A11: generated export list vs the coverage map vs the check catalogue. */
export function coverageOutcome(): Outcome {
  const unmapped = SDK_EXPORTS.filter((e) => !(SDK_COVERAGE[e.name]?.length > 0)).map((e) => e.name);
  const unknownIds = Object.entries(SDK_COVERAGE).flatMap(([n, ids]) => ids.filter((id) => !CHECK_IDS.has(id)).map((id) => `${n}→${id}`));
  const stale = Object.keys(SDK_COVERAGE).filter((n) => !SDK_EXPORTS.some((e) => e.name === n));
  const pass = unmapped.length === 0 && unknownIds.length === 0 && stale.length === 0;
  return verdict(pass, pass ? `${SDK_EXPORTS.length} exports, all mapped to catalogued checks` : `unmapped ${unmapped.join(",") || "-"}; unknown ids ${unknownIds.join(",") || "-"}; stale ${stale.join(",") || "-"}`);
}

/** A13 ids (CONFORMANCE §4.5 v0.1.11): the slice key-set rule at the app. */
export const A13_IDS = {
  "A13.kss_pinned": "slice with a root-signed portalKeySet installed and pinned",
  "A13.portal_keys_ignored": "a key added only to slice portalKeys is not trusted",
  "A13.kss_unknown_root": "statement signed by an unknown root → slice refused",
  "A13.kss_rollback": "statement with a lower seq → slice refused",
  "A13.kss_missing": "slice without portalKeySet after a pin → refused (no downgrade)",
  "A13.kss_rotation": "normal rotation (announce / activate / retire statements) applied",
  "A13.kss_compromise": "compromise rotation: slices and grants by the dropped kid refused at once",
  "A13.kss_first_missing": "first slice without portalKeySet refused",
} as const;

async function keySetChecks(s: Suite, ctx: AppTargetContext, hs: Json, multi?: () => Promise<void>): Promise<void> {
  const b = ctx.bridge;
  const c = () => ctx.client();
  const T = ctx.timeoutMs;
  if (!ctx.testRoots) {
    const why = "--no-test-roots: the app pins its build's Portal Root Keys; run with test roots (the default) and a start module that passes env.TBCONF_PORTAL_ROOT_KEYS to startApp(app, env, { portalRootKeys })";
    for (const [id, title] of Object.entries(A13_IDS)) if (!s.has(id)) s.record(id, title, "app verifies slices against the newest root-signed statement", notRun(why));
    await multi?.();
    return;
  }
  const installed = async (rev: number) => {
    try {
      await b.control.waitForSliceRevision(rev, T);
      return true;
    } catch {
      return false;
    }
  };
  /** `rev` was refused: a status push after it still reports an older slice revision. */
  const refused = async (rev: number): Promise<Outcome> => {
    const t0 = Date.now();
    const seen = await b.control.waitForStatus((x) => x.at > t0 + 1500, T).catch(() => null);
    if (!seen) return bad(`no status push after slice rev ${rev}`);
    return verdict(seen.status.sliceRevision < rev, `slice rev ${rev} ${seen.status.sliceRevision < rev ? "refused" : "INSTALLED"} (app reports ${seen.status.sliceRevision})`);
  };
  /** After a refused slice: a normal slice brings the app back to the current state. */
  const recover = async () => installed(await b.control.republish());
  const grantRefused = async (key: Ed25519KeyPair) => {
    const a = await c().callOp("tb.hold_status", hs, { grantKey: key });
    return { pass: a.code === "grant_invalid", shown: show(a) };
  };

  const pinned = await s.run("A13.kss_pinned", A13_IDS["A13.kss_pinned"], "the first slice carrying portalKeySet (seq 1) is installed; tokens by the statement's active key work", async () => {
    const rev = await b.control.publishKeySet();
    const ok1 = await installed(rev);
    const a = ok1 ? await c().callOp("tb.hold_status", hs) : null;
    return verdict(ok1 && !!a && !AUTH_CODES.has(a.code ?? ""), `slice rev ${rev} ${ok1 ? "installed" : "NOT installed"}${a ? `; call ${show(a)}` : ""}`);
  });
  if (pinned.pass !== true) {
    for (const [id, title] of Object.entries(A13_IDS)) if (!s.has(id)) s.record(id, title, "statement pinned first", bad("A13.kss_pinned failed"));
    return;
  }
  await s.run("A13.portal_keys_ignored", A13_IDS["A13.portal_keys_ignored"], "slice (signed by the active key) lists a stranger key as active in portalKeys only → grant by the stranger refused grant_invalid", async () => {
    const rev = await b.control.serveSlice({ extraPortalKeys: [{ jwk: b.stranger.publicJwk, status: "active" }] });
    if (!(await installed(rev))) return bad(`slice rev ${rev} not installed`);
    const g = await grantRefused(b.stranger);
    await recover();
    return verdict(g.pass, `stranger grant: ${g.shown}`);
  });
  await s.run("A13.kss_unknown_root", A13_IDS["A13.kss_unknown_root"], "slice with a statement (seq + 5) signed by a non-pinned root is not installed", async () => {
    const rev = await b.control.serveSlice({ portalKeySet: await b.signKeySet(b.keySet.seq + 5, undefined, b.stranger) });
    const o = await refused(rev);
    await recover();
    return o;
  });
  await s.run("A13.kss_rollback", A13_IDS["A13.kss_rollback"], "after seq 2 is pinned, a slice carrying the seq 1 statement is not installed", async () => {
    const old = b.keySet.kss as string;
    if (!(await installed(await b.control.publishKeySet()))) return bad("seq 2 not installed");
    const rev = await b.control.serveSlice({ portalKeySet: old });
    const o = await refused(rev);
    await recover();
    return o;
  });
  await s.run("A13.kss_missing", A13_IDS["A13.kss_missing"], "slice without portalKeySet (signed by the active key) is not installed", async () => {
    const rev = await b.control.serveSlice({ portalKeySet: null });
    const o = await refused(rev);
    await recover();
    return o;
  });
  await s.run("A13.kss_rotation", A13_IDS["A13.kss_rotation"], "3 statements (announce / activate / retire): each slice installed; grant by the new key ok; by the dropped key grant_invalid", async () => {
    const old = b.activePortalKey();
    const r1 = await installed(await b.control.rotatePortalKey("announce"));
    const r2 = r1 && (await installed(await b.control.rotatePortalKey("activate")));
    const byNew = r2 ? await c().callOp("tb.hold_status", hs) : null;
    const r3 = r2 && (await installed(await b.control.rotatePortalKey("retire")));
    const g = r3 ? await grantRefused(old) : { pass: false, shown: "not reached" };
    return verdict(r3 && !!byNew && !AUTH_CODES.has(byNew.code ?? "") && g.pass, `announce ${r1}; activate ${r2}; retire ${r3}; new key ${byNew ? show(byNew) : "-"}; dropped key ${g.shown} (seq ${b.keySet.seq})`);
  });
  await s.run("A13.kss_compromise", A13_IDS["A13.kss_compromise"], "statement seq + 1 drops the active (stolen) kid: the slice signed by it is not installed, the next slice by the fresh key is; a grant by the stolen key → grant_invalid", async () => {
    const stolen = b.activePortalKey();
    const bad1 = await refused(await b.control.compromisePortalKey({ signWith: stolen }));
    const good = await recover();
    const g = good ? await grantRefused(stolen) : { pass: false, shown: "not reached" };
    return verdict(bad1.pass === true && good && g.pass, `${bad1.asserted}; fresh-key slice ${good ? "installed" : "NOT installed"}; stolen-key grant ${g.shown}`);
  });
  // CONF-MULTIAPP group X (--peers): the app is healthy and trusts the current keys here; the next check breaks that on purpose
  await multi?.();
  // runs last: it leaves the app on a fresh data dir (only A11 and the payload scan follow)
  await s.run("A13.kss_first_missing", A13_IDS["A13.kss_first_missing"], "an app on a fresh data dir claims and gets a first slice without portalKeySet: it never reports that slice revision", async () => {
    if (!ctx.restart) return notRun("needs a restartable app (runApp start()/--cmd)");
    const fresh = join(ctx.env.TB_DATA_DIR as string, "kss-first-missing");
    mkdirSync(join(fresh, "backup"), { recursive: true });
    b.keySet.on = false;
    const rev = await b.control.republish();
    const code = b.control.issueEnrolCode();
    const n = b.claims.length;
    // a redeploy writes the CURRENT Portal keys into TB_PORTAL_KEYS, so the first slice is refused only for lacking a statement
    await ctx.restart({ TB_DATA_DIR: fresh, TB_BACKUP_DIR: join(fresh, "backup"), TB_ENROL_CODE: code, TB_PORTAL_KEYS: JSON.stringify(b.portalJwks()) });
    const claimed = await (async () => {
      const end = Date.now() + T;
      while (Date.now() < end) {
        if (b.claims.length > n) return b.claims.at(-1);
        await new Promise((r) => setTimeout(r, 100));
      }
      return undefined;
    })();
    if (!claimed) return bad("the fresh app did not claim");
    await new Promise((r) => setTimeout(r, 3000));
    const after = b.statuses.filter((x) => x.at >= claimed.at);
    const installed = after.some((x) => x.status.sliceRevision >= rev);
    return verdict(!installed, `fresh claim ok; ${after.length} status pushes; slice rev ${rev} ${installed ? "INSTALLED without a statement" : "refused"}`);
  });
}
