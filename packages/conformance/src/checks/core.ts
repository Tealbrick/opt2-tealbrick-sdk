// Portal Core target — STATIC layer (CONFORMANCE §4.6 R1, R2, R4, R5, R7–R10; CREDENTIALS §6 cred.dev.*; PORTAL-API
// §1–§6). Every assertion runs on the route table imported from @opt2-tealbrick/spec/routes and on the spec's
// declaration files (route input/output interfaces), so a Core built from ROUTES inherits these guarantees and a
// broken table (or a broken copy of it) is caught here. The live layer is ./core-live.ts.
import { AUDIT_ACTIONS, RATE_CLASSES, REGISTRIES, type RouteOp, TRANSPORTS } from "@opt2-tealbrick/spec/routes";
import type { CheckResult } from "../report.ts";
import { type Outcome, Suite, verdict } from "../suite.ts";
import { CORE_STATIC_CHECKS } from "./core-ids.ts";
import { type FieldInfo, fieldsOf, members, normName, stringUnion, type TypeIndex } from "./core-types.ts";

export interface CoreStaticInput {
  routes: readonly RouteOp[];
  types: TypeIndex;
  /** product ids that must never appear as a route segment (spec example manifests + extras) */
  productIds: readonly string[];
}

/** PORTAL-API §1.2 (spec 0.1.58: `host` = K13 host assertion, only on `host.*` rows) */
const AUTH_CLASSES = ["browser", "owner-cli", "bridge", "device", "public", "stripe-webhook", "host"] as const;
const PERSON = new Set(["browser", "owner-cli"]);
/** PORTAL-API §1.1 "Explicit public rows": nothing else is reachable without a credential. */
/** v0.1.64: + `portal.info` (PORTAL-API §D, a native client asks it before sign-in). */
const EXPLICIT_PUBLIC = ["device.start", "device.token", "bridge_api.enrol", "stripe.webhook", "clerk.webhook", "portal.signing_keys", "portal.info"] as const;
/** RFC 8628 polling codes carried as `error.code` (CORE §8, C15). */
const DEVICE_POLL_CODES = ["authorization_pending", "slow_down", "access_denied", "expired_token"] as const;

/** Input field names that could carry an app key value (option B: no op accepts one — PORTAL-API §5.6, §6). */
const KEY_VALUE_NAMES = new Set(["value", "values", "secret", "secrets", "password", "passphrase", "apikey", "apikeys", "privatekey", "keyvalue", "keyvalues", "env", "envvars", "environment", "credential", "credentials", "d"]);
/** Input field names that carry a one-time code / opaque token: allowed only where bodies are never logged. */
const CREDENTIAL_INPUT_NAMES = new Set(["code", "token", "devicecode", "usercode", "ticket", "assertion", "accesstoken", "refreshtoken", "sessiontoken"]);
/** Never in any owner-cli output, at any depth (`code` is checked top-level only: error objects carry `code`). */
const DEEP_SECRET_NAMES = new Set(["ticket", "devicecode", "usercode", "accesstoken", "sessiontoken", "refreshtoken", "pairingcode", "enrolmentcode"]);

/**
 * R5 forbidden list (PORTAL-API §6) as path / op-id tokens. `connect-request` (pairing) and `owner-sessions` are
 * allowed rows, so the list names `connector(s)` and `rooms|chat`, not `connect` or `sessions`.
 */
const FORBIDDEN_TOKENS: Record<string, string> = {
  tool: "tool execution",
  tools: "tool execution",
  execute: "tool execution",
  exec: "relay / local-exec",
  invoke: "tool execution",
  call: "tool execution",
  calls: "tool execution",
  mcp: "hosted MCP endpoint",
  connector: "connector ops",
  connectors: "connector ops",
  channel: "channel ops",
  channels: "channel ops",
  broker: "broker ops",
  bot: "bot tokens",
  bots: "bot tokens",
  relay: "relay",
  frame: "relay frames",
  frames: "relay frames",
  queue: "hosted call queue",
  queues: "hosted call queue",
  fleet: "Fleet",
  team: "teams",
  teams: "teams",
  membership: "memberships",
  memberships: "memberships",
  member: "memberships",
  members: "memberships",
  daemon: "daemons",
  daemons: "daemons",
  peer: "peers",
  peers: "peers",
  admin: "admin routes",
  staff: "staff routes",
  invite: "invites",
  invites: "invites",
  sso: "SSO",
  password: "password login",
  login: "password login",
  room: "rooms",
  rooms: "rooms",
  chat: "chat",
  chats: "chat",
  preview: "chat previews",
  previews: "chat previews",
  partition: "app data",
  partitions: "app data",
  area: "app data",
  areas: "app data",
  receipt: "app data (receipts)",
  receipts: "app data (receipts)",
  hold: "app data (holds)",
  holds: "app data (holds)",
  approvals: "app data (approvals view)",
  reveal: "key value reveal",
  upload: "key upload",
  env: "env reveal / apply-env",
  secret: "key value",
  secrets: "key value",
  introspect: "grant introspection",
  introspection: "grant introspection",
  grant: "grant check / redeem",
  grants: "grant check / redeem",
  redeem: "grant redeem",
  jwks: "JWKS for agents",
  "well-known": "OpenID / JWKS discovery",
  openid: "OpenID discovery",
  oidc: "OpenID discovery",
  passthrough: "passthrough prefix",
  proxy: "passthrough prefix",
  legacy: "legacy alias",
};

const tokens = (s: string): string[] => {
  const l = s.toLowerCase();
  const out = l.split(/[^a-z0-9]+/).filter(Boolean);
  if (l.includes("well-known")) out.push("well-known");
  return out;
};
const segs = (path: string): string[] => path.split("/").filter(Boolean);
const params = (path: string): string[] => [...path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
const normPath = (path: string): string => path.replace(/\{[^}]+\}/g, "{}");
const list = (xs: readonly string[], max = 8): string => (xs.length <= max ? xs.join("; ") : `${xs.slice(0, max).join("; ")}; … (+${xs.length - max})`);
const clean = (what: string, bad: readonly string[]): Outcome => verdict(bad.length === 0, bad.length === 0 ? what : list(bad));

/** Top-level field names of a schema (one level, through aliases, unions and intersections). */
function topNames(fs: readonly FieldInfo[]): string[] {
  return [...new Set(fs.filter((f) => f.depth === 0).map((f) => f.name))];
}

export function runCoreStatic(input: CoreStaticInput): CheckResult[] {
  const { routes, types } = input;
  const s = new Suite();
  const title = new Map(CORE_STATIC_CHECKS.map((c) => [c.id, c.title]));
  const rec = (id: string, expected: string, o: Outcome) => s.record(id, title.get(id) ?? id, expected, o);
  const fields = (schema: string) => fieldsOf(types, schema);
  const schemaNames = new Set(members(types.get("SchemaMap")?.text ?? "").map((m) => m.name));
  const secretBearing = stringUnion(types, "SecretBearingSchema");
  const secretKeys = new Set(stringUnion(types, "SecretKey").map(normName));
  const ownerCli = routes.filter((r) => r.auth.includes("owner-cli"));

  // ── R1: the table itself ──
  const dupOps = routes.map((r) => r.opId).filter((id, i, a) => a.indexOf(id) !== i);
  rec("R1.table.unique_ops", "no duplicate opId", clean(`${routes.length} unique op ids`, dupOps.map((d) => `duplicate ${d}`)));
  const keys = routes.map((r) => `${r.method} ${normPath(r.path)}`);
  const dupPaths = keys.filter((k, i) => keys.indexOf(k) !== i);
  rec("R1.table.unique_paths", "no duplicate method + path", clean(`${routes.length} unique method + path pairs`, dupPaths.map((d) => `duplicate ${d}`)));

  const fieldIssues: string[] = [];
  if (schemaNames.size === 0) fieldIssues.push("SchemaMap not found in the spec declaration files");
  for (const r of routes) {
    if (r.auth.length === 0) fieldIssues.push(`${r.opId}: no auth class`);
    for (const a of r.auth) if (!(AUTH_CLASSES as readonly string[]).includes(a)) fieldIssues.push(`${r.opId}: unknown auth ${a}`);
    if (r.exposure !== "gateway" && r.exposure !== "internal") fieldIssues.push(`${r.opId}: exposure ${String(r.exposure)}`);
    if (!(r.transport in TRANSPORTS)) fieldIssues.push(`${r.opId}: transport ${r.transport}`);
    if (!(r.rate in RATE_CLASSES)) fieldIssues.push(`${r.opId}: rate ${r.rate}`);
    if (!(r.registry in REGISTRIES)) fieldIssues.push(`${r.opId}: registry ${r.registry}`);
    if (r.audit !== null && !(AUDIT_ACTIONS as readonly string[]).includes(r.audit)) fieldIssues.push(`${r.opId}: audit ${r.audit}`);
    if (r.bodyLog !== "none" && r.bodyLog !== "meta") fieldIssues.push(`${r.opId}: bodyLog ${String(r.bodyLog)}`);
    if (schemaNames.size > 0) for (const n of [r.input, r.output]) if (!schemaNames.has(n)) fieldIssues.push(`${r.opId}: schema ${n} not in SchemaMap`);
  }
  rec("R1.table.row_fields", "every row fully typed (CORE §0, PORTAL-API §1.3)", clean(`${routes.length} rows checked`, fieldIssues));

  const internalIssues = routes.flatMap((r) => {
    const internalPath = r.path.startsWith("/internal/");
    if (r.exposure === "internal" && !internalPath) return [`${r.opId}: internal row on ${r.path}`];
    if (r.exposure === "gateway" && r.path.startsWith("/internal")) return [`${r.opId}: gateway row on ${r.path}`];
    return [];
  });
  rec("R1.table.internal_paths", "internal ⇔ /internal/ path", clean(`${routes.filter((r) => r.exposure === "internal").length} internal rows, all on /internal/`, internalIssues));

  const bindIssues: string[] = [];
  for (const r of routes) {
    const names = new Set(fields(r.input).filter((f) => f.depth === 0).map((f) => f.name));
    for (const p of params(r.path)) if (!names.has(p)) bindIssues.push(`${r.opId}: path param {${p}} not an input field of ${r.input}`);
    if (r.query.length > 0 && r.method !== "GET") bindIssues.push(`${r.opId}: query keys on ${r.method}`);
    for (const q of r.query) if (!names.has(q)) bindIssues.push(`${r.opId}: query key ${q} not an input field of ${r.input}`);
  }
  rec("R1.table.bindings", "`{name}` and query keys bind to same-named input fields (PORTAL-API §1.3)", clean("every path param and query key binds to an input field", bindIssues));

  const credentialFree = routes.filter((r) => r.exposure === "gateway" && !r.auth.some((a) => PERSON.has(a) || a === "bridge" || a === "host")).map((r) => r.opId);
  const extra = credentialFree.filter((id) => !(EXPLICIT_PUBLIC as readonly string[]).includes(id));
  const missing = EXPLICIT_PUBLIC.filter((id) => !credentialFree.includes(id));
  rec(
    "R1.table.explicit_public",
    `exactly ${EXPLICIT_PUBLIC.join(", ")} (PORTAL-API §1.1)`,
    clean(`credential-free gateway rows: ${credentialFree.join(", ")}`, [...extra.map((x) => `unexpected credential-free row ${x}`), ...missing.map((x) => `missing explicit row ${x}`)]),
  );
  const mixed = routes.filter((r) => r.auth.some((a) => PERSON.has(a)) && r.auth.some((a) => !PERSON.has(a))).map((r) => `${r.opId}: ${r.auth.join("+")}`);
  rec("R1.table.p1_disjoint", "person and non-person classes never on one row (PORTAL-API §1.2 P1)", clean("no row mixes person and non-person auth", mixed));

  // ── R2: owner native session (K3) = reads + drafts.* (+ logout) ──
  // v0.1.64 (C326, C332): + the session's own push device and the allow-listed person-op relay (PORTAL-API §1.2)
  const ocBad = ownerCli.filter((r) => r.method !== "GET" && !r.opId.startsWith("drafts.") && !r.opId.startsWith("push_devices.") && r.opId !== "person_ops.call" && r.opId !== "owner_sessions.logout").map((r) => `${r.opId} (${r.method})`);
  rec("R2.owner_cli_rows", "owner-cli ⊆ GET ∪ drafts.* ∪ owner_sessions.logout ∪ push_devices.* ∪ person_ops.call", clean(`${ownerCli.length} owner-cli rows: reads + drafts.* + logout + push device + person-op relay only`, ocBad));
  rec(
    "R2.owner_cli_no_confirm",
    "no owner-cli row has confirm: true",
    clean(
      "no confirm row reachable with K3",
      ownerCli.filter((r) => r.confirm).map((r) => r.opId),
    ),
  );
  const applyIssues: string[] = [];
  for (const id of ["drafts.apply", "drafts.reject"]) {
    const r = routes.find((x) => x.opId === id);
    if (!r) applyIssues.push(`${id} missing`);
    else if (r.auth.length !== 1 || r.auth[0] !== "browser") applyIssues.push(`${id} auth ${r.auth.join("+")}`);
  }
  const apply = routes.find((x) => x.opId === "drafts.apply");
  if (apply && !(apply.confirm && apply.idempotent)) applyIssues.push(`drafts.apply confirm=${apply.confirm} idempotent=${apply.idempotent}`);
  rec("R2.apply_browser_only", "apply/reject browser-only; apply confirm + Idempotency-Key (PORTAL-API §3)", clean("drafts.apply and drafts.reject browser-only; apply confirm + idempotent", applyIssues));
  const draftBad = routes
    .filter((r) => r.draftable)
    .filter((r) => r.method === "GET" || !r.auth.includes("browser") || r.auth.some((a) => !PERSON.has(a)) || r.opId.startsWith("drafts."))
    .map((r) => `${r.opId} (${r.method}, ${r.auth.join("+")})`);
  rec("R2.draftable_rows", "draftable ⇒ non-GET browser mutation (RT2)", clean(`${routes.filter((r) => r.draftable).length} draftable rows, all browser mutations`, draftBad));

  // ── R4: no key values ──
  const keyInputs: string[] = [];
  const credInputs: string[] = [];
  for (const r of routes) {
    for (const f of fields(r.input)) {
      const n = normName(f.name);
      // the APNs environment of a push device (sandbox | production) is no app environment
      if (KEY_VALUE_NAMES.has(n) && !(r.opId === "push_devices.register" && n === "environment")) keyInputs.push(`${r.opId}: ${r.input}.${f.path}`);
      if (CREDENTIAL_INPUT_NAMES.has(n) && r.bodyLog !== "none") credInputs.push(`${r.opId}: ${r.input}.${f.path} on bodyLog ${r.bodyLog}`);
    }
  }
  rec("R4.no_key_input", "no input field named like a key value (PORTAL-API §5.6, §6)", clean(`${routes.length} input schemas scanned (deep)`, keyInputs));
  rec("R4.secret_inputs_unlogged", "code / token inputs only on bodyLog: none rows (PORTAL-API §1.3)", clean("every code / token input is on a bodyLog: none row", credInputs));
  const keyRows = routes.filter((r) => r.method === "GET" && segs(r.path).at(-1) === "keys");
  const keyIssues: string[] = keyRows.length === 0 ? ["no key status row (GET …/keys) in the table"] : [];
  for (const r of keyRows) {
    const fs = fields(r.output);
    if (fs.length === 0) keyIssues.push(`${r.opId}: output ${r.output} not found`);
    for (const f of fs) {
      if (KEY_VALUE_NAMES.has(normName(f.name))) keyIssues.push(`${r.opId}: ${r.output}.${f.path} could carry a value`);
      if (["set", "present"].includes(f.name) && !/^boolean(\s*\|\s*null)?$/.test(f.type)) keyIssues.push(`${r.opId}: ${r.output}.${f.path} is ${f.type}, not boolean`);
    }
    if (!fs.some((f) => f.name === "set" || f.name === "present")) keyIssues.push(`${r.opId}: ${r.output} has no presence boolean`);
  }
  rec("R4.key_status_booleans", "presence booleans only (CORE §10)", clean(`${keyRows.map((r) => `${r.opId} → ${r.output}`).join(", ")}: booleans only`, keyIssues));

  // ── R5: ops that must not exist ──
  const forbidden: string[] = [];
  for (const r of routes) {
    for (const t of new Set([...tokens(r.opId), ...tokens(r.path)])) {
      // v0.1.64 (C326): `person_ops.call` is the allow-listed person-op relay, not tool execution (PORTAL-API §1.2)
      if (r.opId === "person_ops.call" && t === "call") continue;
      const why = FORBIDDEN_TOKENS[t];
      if (why) forbidden.push(`${r.opId} ${r.method} ${r.path}: "${t}" (${why})`);
    }
    const ss = segs(r.path);
    const last = ss.at(-1);
    if (r.method !== "GET" && (last === "keys" || last === "key") && ss.at(-2) !== "tickets") forbidden.push(`${r.opId} ${r.method} ${r.path}: key write (key values never pass through Portal)`);
  }
  rec("R5.forbidden_ops", "none of the PORTAL-API §6 op families", clean(`${routes.length} rows scanned against ${Object.keys(FORBIDDEN_TOKENS).length} forbidden tokens`, forbidden));
  const products = new Set(input.productIds.map((p) => p.toLowerCase()));
  const productRows = routes.filter((r) => segs(r.path).some((x) => products.has(x.toLowerCase())) || products.has(r.opId.split(".")[0])).map((r) => `${r.opId} ${r.path}`);
  rec("R5.no_product_routes", "product ids are data, never route segments (PORTAL-API §6)", clean(`no segment equals a product id (${[...products].length} ids)`, productRows));
  const passthrough = routes
    .filter((r) => !r.path.startsWith("/") || /[*+]|\{[^}]*[.*+][^}]*\}|\/$|\/\/|\/v\d+(\/|$)|\.\./.test(r.path))
    .map((r) => `${r.opId} ${r.path}`);
  rec("R5.no_passthrough", "no catch-all, version segment or alias (PORTAL-API §1.1, §6)", clean("every path is a fixed template", passthrough));

  // ── R7 / R8 / cred.dev: device flow rows ──
  const devIssues: string[] = [];
  const start = routes.find((r) => r.opId === "device.start");
  const token = routes.find((r) => r.opId === "device.token");
  if (start?.auth.join() !== "public" || start.bodyLog !== "none" || start.idempotent) devIssues.push(`device.start ${start ? `${start.auth.join("+")}, bodyLog ${start.bodyLog}, idempotent ${start.idempotent}` : "missing"}`);
  if (token?.auth.join() !== "device" || token.bodyLog !== "none" || token.idempotent || token.rate !== "device_poll")
    devIssues.push(`device.token ${token ? `${token.auth.join("+")}, bodyLog ${token.bodyLog}, idempotent ${token.idempotent}, rate ${token.rate}` : "missing"}`);
  const errCodes = stringUnion(types, "ErrorCode");
  for (const c of DEVICE_POLL_CODES) if (!errCodes.includes(c)) devIssues.push(`ErrorCode lacks ${c}`);
  rec("R7.device_rows", "CREDENTIALS §6 + PORTAL-API §1.4", clean("device.start public / device.token device-auth, bodyLog none, not idempotent; RFC 8628 codes in ErrorCode", devIssues));

  const ucIssues: string[] = [];
  for (const id of ["device.lookup", "device.approve", "device.deny"]) {
    const r = routes.find((x) => x.opId === id);
    if (!r) {
      ucIssues.push(`${id} missing`);
      continue;
    }
    if (r.auth.join() !== "browser") ucIssues.push(`${id} auth ${r.auth.join("+")}`);
    const uc = fields(r.input).find((f) => f.depth === 0 && normName(f.name) === "usercode");
    if (!uc || uc.optional) ucIssues.push(`${id}: ${r.input} ${uc ? "userCode optional" : "has no userCode"}`);
  }
  rec("R8.user_code_required", "B2: approval bound to the user code (CREDENTIALS §6)", clean("lookup / approve / deny: browser-only, userCode required", ucIssues));
  const lookup = routes.find((r) => r.opId === "device.lookup");
  const listers: string[] = [];
  if (!lookup) listers.push("device.lookup missing");
  else {
    const re = new RegExp(`\\b${lookup.output}\\b`);
    for (const r of routes) {
      if (r.opId === lookup.opId) continue;
      const decl = types.get(r.output);
      if (r.output === lookup.output || re.test(decl?.text ?? "") || re.test(decl?.extends ?? "") || fields(r.output).some((f) => re.test(f.type))) listers.push(`${r.opId} returns ${lookup.output}`);
    }
  }
  rec("cred.dev.no_unbound_list", "no op lists pending device requests (CREDENTIALS §6)", clean(`only device.lookup returns a ${lookup?.output ?? "device request"}`, listers));
  const clearUc = routes
    .filter((r) => r.opId !== "device.start")
    .flatMap((r) => fields(r.output).filter((f) => normName(f.name) === "usercode").map((f) => `${r.opId}: ${r.output}.${f.path}`));
  rec("cred.dev.no_clear_user_code", "user code in clear only in the start response (CREDENTIALS §6)", clean("no other output has a user code field", clearUc));

  // ── R9 / R10: secrets never reach K3 and never sit in the idempotency store ──
  const ocOut: string[] = [];
  if (secretBearing.length === 0) ocOut.push("SecretBearingSchema not found in the spec declaration files");
  if (secretKeys.size === 0) ocOut.push("SecretKey not found in the spec declaration files");
  for (const r of ownerCli) {
    if (secretBearing.includes(r.output)) ocOut.push(`${r.opId}: output ${r.output} is secret-bearing`);
    const fs = fields(r.output);
    for (const n of topNames(fs)) if (secretKeys.has(normName(n))) ocOut.push(`${r.opId}: ${r.output}.${n} (top-level secret key)`);
    for (const f of fs) if (DEEP_SECRET_NAMES.has(normName(f.name))) ocOut.push(`${r.opId}: ${r.output}.${f.path}`);
  }
  rec("R9.owner_cli_outputs", "no K3-reachable output carries a code, ticket or token (S1, B4)", clean(`${ownerCli.length} owner-cli outputs scanned (deep)`, ocOut));
  const secretRows = routes.filter((r) => secretBearing.includes(r.output));
  const soBad = secretRows.filter((r) => r.bodyLog !== "none" || r.idempotent || r.auth.includes("owner-cli")).map((r) => `${r.opId}: bodyLog ${r.bodyLog}, idempotent ${r.idempotent}, auth ${r.auth.join("+")}`);
  if (secretBearing.length === 0) soBad.push("SecretBearingSchema not found");
  rec("R9.secret_outputs", "RT8", clean(`${secretRows.length} secret-bearing rows: bodyLog none, not idempotent, not owner-cli`, soBad));
  const undeclared = [...new Set(routes.map((r) => r.output))]
    .filter((o) => !secretBearing.includes(o))
    .filter((o) => topNames(fields(o)).some((n) => secretKeys.has(normName(n))))
    .map((o) => `${o} has a top-level secret field but is not in SecretBearingSchema`);
  if (secretKeys.size === 0) undeclared.push("SecretKey not found");
  rec("R9.secret_list_complete", "SecretBearingSchema names every code / ticket / token output", clean(`declared: ${secretBearing.join(", ")}`, undeclared));
  const idem = routes.filter((r) => r.bodyLog === "none" && r.idempotent).map((r) => r.opId);
  rec("R10.no_idempotent_secret_rows", "no row with bodyLog: none and idempotent: true (RT6, B8)", clean(`${routes.filter((r) => r.bodyLog === "none").length} bodyLog: none rows, none idempotent`, idem));

  return s.results;
}
