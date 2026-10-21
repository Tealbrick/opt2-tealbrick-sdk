// Per-app conformance config (v0.1.18: one loader for `waivers`, `setup`, `inputs`, `inputsAs`, `dynamic`; v0.1.23
// (package 0.1.14): `narrowing`).
// Waivers (CONFORMANCE v0.1.13, Fleet C89): `--waive <checkId>@<untilVersion>` (repeatable) and an optional
// `tealbrick-conformance.json` next to the manifest `{ "waivers": [{ "id", "until", "reason" }] }`. A waived check that
// would fail / not_run reports `waived` while this package's version < `until` (report.ts applyWaivers). Unknown ids
// and malformed entries are usage errors (exit 2): a waiver must never silently cover nothing.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CONTRACT_IDS } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { isCheckId } from "./checks/catalog.ts";
import type { Waiver } from "./report.ts";

/** This package's version (`package.json` one level above src/ and dist/). */
export const CONFORMANCE_VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

/** File name of the per-app conformance config (waivers + setup fixtures), read from the manifest's directory. */
export const WAIVER_FILE = "tealbrick-conformance.json";

const VERSION_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** Thrown for a malformed or unknown waiver or a malformed config file; the CLI answers it with exit 2 (usage error). */
export class WaiverError extends Error {}
/** The same usage error under its v0.1.18 name (the file holds more than waivers). */
export const ConfigError = WaiverError;

function checked(w: Waiver, where: string): Waiver {
  if (!isCheckId(w.id)) throw new WaiverError(`${where}: unknown check id ${JSON.stringify(w.id)}`);
  if (!VERSION_RE.test(w.until)) throw new WaiverError(`${where}: until ${JSON.stringify(w.until)} is not a version (x.y.z)`);
  if (w.reason.trim().length === 0) throw new WaiverError(`${where}: reason required`);
  return w;
}

/** `<checkId>@<untilVersion>`; the reason is "--waive (command line)". */
export function parseWaiveFlag(value: string): Waiver {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) throw new WaiverError(`--waive ${JSON.stringify(value)}: expected <checkId>@<untilVersion>`);
  return checked({ id: value.slice(0, at), until: value.slice(at + 1), reason: "--waive (command line)" }, "--waive");
}

/** Waivers from `tealbrick-conformance.json` beside `manifestPath` ([] when the file is absent). */
export function loadWaiverFile(manifestPath: string): Waiver[] {
  return loadConformanceConfig(manifestPath).waivers;
}

// ── the one per-app config file (CONFORMANCE v0.1.18, package 0.1.12): waivers + setup fixtures ──
// `{ waivers?, setup?, inputs?, inputsAs?, dynamic? }` (see CONFORMANCE "v0.1.18 — package 0.1.12"). Every malformed
// part is a usage error (exit 2), like a malformed waiver: a fixture must never silently cover nothing.

/**
 * Who a setup step calls as: the person session, fake agent A / B, the suite's companion app caller (A12.*), or (package
 * 0.1.21) `capsAgent`: the FRESH agent A3.caps_count creates for each capped op. A `capsAgent` step is deferred: it runs
 * once that agent exists (after its first-sight call), before its capped calls, once per fresh agent.
 */
export const SETUP_CALLERS = ["owner", "agentA", "agentB", "app", "capsAgent"] as const;
export type SetupCaller = (typeof SETUP_CALLERS)[number];
/** Callers `inputsAs` may name (the owner calls person ops; their inputs are never generated). */
export const INPUT_CALLERS = ["agentA", "agentB", "app"] as const;
export type InputCaller = (typeof INPUT_CALLERS)[number];
/**
 * Built-in placeholder values the suite fills in (SPEC-GAP: CONFORMANCE v0.1.18 names only captures; a fixture that
 * grants the app caller or an agent a scope needs their run-random ids): `${tb.agentA}`, `${tb.agentB}`, `${tb.app}`
 * (the companion app caller's instance id), `${tb.instance}` (the app under test).
 */
export const BUILTIN_PLACEHOLDERS = ["tb.agentA", "tb.agentB", "tb.app", "tb.instance", "tb.capsAgent"] as const;
/**
 * `${tb.capsAgent}` (package 0.1.21): the id of the fresh agent A3.caps_count is about to call as. It has a value only in
 * `capsAgent` setup steps and in `inputs` / `inputsAs` (resolved when a check needs them); an ordinary setup step that
 * names it is a usage error.
 */
export const CAPS_AGENT_PLACEHOLDER = "tb.capsAgent";

export interface SetupStep {
  id: string;
  as: SetupCaller;
  op: string;
  input: Json;
  /** capture name → JSON pointer (RFC 6901) into the step's `output` */
  capture: Record<string, string>;
}

/**
 * CONF-MULTIAPP (package 0.1.20): one REAL peer app of the app under test, at a released version of the signed release
 * index. `channel` defaults to "stable"; "dev" admits a pre-release pair. `settings` reach the peer's start module in
 * the harness-only env TBCONF_PEER_SETTINGS (JSON), e.g. `{"engine": "stub"}` for a peer that needs a companion service.
 */
export interface PeerSpec {
  product: string;
  version: string;
  channel: "stable" | "dev";
  settings?: Record<string, Json>;
}
/** At most this many peers per run (CI cost: each is a download, a frozen install, a build and a boot). */
export const MAX_PEERS = 3;
/** `contractOps` value: the companion op of a declared peer whose output is the contract (X4). */
export interface ContractOp {
  peer: string;
  op: string;
}

export interface ConformanceConfig {
  waivers: Waiver[];
  /** CONF-MULTIAPP: real peer apps for `--peers` (empty = none) */
  peers: PeerSpec[];
  /** CONF-MULTIAPP (X4): contract id → the `<peer product>.<op>` whose real output is validated against the pinned schema */
  contractOps: Record<string, ContractOp>;
  setup: SetupStep[];
  /** known-good inputs per op id (merged over `--inputs`; the file wins per key) */
  inputs: Record<string, Json>;
  /** per-caller inputs; `inputsAs.<caller>.<op>` overrides `inputs.<op>` for that caller */
  inputsAs: Partial<Record<InputCaller, Record<string, Json>>>;
  /** dynamic op id → tool names A11.resolve_family resolves instead of the catalog's */
  dynamic: Record<string, { resolveTools: string[] }>;
  /** v0.1.23 (C115, package 0.1.14): the tag-filtered read A11.narrowing_empty_anyof sends (absent → not_applicable) */
  narrowing?: NarrowingFixture;
  /** package 0.1.22 (SDK-INSTANCE-GRANT): the person op that grants an agent access to one scope instance (absent → the A18 checks are not_applicable) */
  scopeGrantOp?: ScopeGrantFixture;
  /** package 0.1.23 (SDK-COMPANION-CALLERS): the person op whose output is `ctx.companionCallers()` (absent → the A19 checks are not_applicable) */
  companionCallersOp?: CompanionCallersFixture;
  /** package 0.1.23 (HOOK-CALLER-PRODUCT): a product-keyed before hook (absent → A2.hook_app_caller_fail_closed is not_applicable) */
  hookCallerProduct?: HookCallerProductFixture;
  /** package 0.1.23 (Caller.listed, SPEC-GAP spec 0.1.49): a static agent op whose output exposes `ctx.caller.listed` (absent → A19.caller_listed is not_applicable) */
  callerListedOp?: CallerListedFixture;
  /** conformance 0.1.27 (C292, spec 0.1.54): a person op whose output is `ctx.bridgeCaps()` (absent → the A22 rows are not_applicable) */
  bridgeCapsOp?: BridgeCapsFixture;
  eventsProbe?: EventsProbeFixture;
}

/**
 * `narrowing` (CONFORMANCE v0.1.23, C115): `op` = an agent read op that filters its items by `rules.narrowing`
 * memoryTags; `input` = its input (placeholders allowed; default: generated from the schema); `tag` = a tag the
 * setup gave at least one item (optional: without it the `anyOf: [tag]` part is not checked); `itemsPath` (package
 * 0.1.15) = JSON pointer to the result items array in the op output (default: the output itself when it is an array, else
 * its ONLY array field; several array fields and no itemsPath → the check reports not_run naming them).
 */
export interface NarrowingFixture {
  op: string;
  input?: Json;
  tag?: string;
  itemsPath?: string;
}

/**
 * `scopeGrantOp` (package 0.1.22, SDK-INSTANCE-GRANT, spec 0.1.47): `op` = a PERSON op of the app that calls
 * `ctx.scopeGrants.grant`; `input` = its input for a grant WITHIN the manifest's agent ceiling (placeholders allowed, e.g.
 * `${tb.agentA}`); `aboveCeiling` = its input for a grant ABOVE the ceiling (must be refused 400 `scope_grant_invalid`);
 * `agentProbe` (optional) = an AGENT op whose output carries a boolean at `path` (JSON pointer, default `/scopeGrants`) that is
 * `ctx.scopeGrants !== undefined`; the check requires `false`. Absent `scopeGrantOp` = the app does not use the API.
 */
export interface ScopeGrantFixture {
  op: string;
  input: Json;
  aboveCeiling: Json;
  agentProbe?: { op: string; input?: Json; path?: string };
}

/**
 * `companionCallersOp` (package 0.1.23, SDK-COMPANION-CALLERS, spec 0.1.48): `op` = a PERSON op of the app that returns what
 * `ctx.companionCallers()` gave it, at `path` (JSON pointer into the op output, default `/companionCallers`); `input` (optional)
 * = its input (placeholders allowed). `agentProbe` (optional) = a static AGENT op whose output carries the same value at its
 * `path` (default `/companionCallers`); the check requires it ABSENT (undefined, null or false): any list on an agent call fails.
 */
export interface CompanionCallersFixture {
  op: string;
  path?: string;
  input?: Json;
  agentProbe?: { op: string; path?: string; input?: Json };
}

/**
 * `hookCallerProduct` (package 0.1.23, HOOK-CALLER-PRODUCT, spec 0.1.45): `hook` = the id of a BEFORE hook of the app whose
 * criteria key on the calling app's product; `product` = a product those criteria name; `op` / `input` (optional) = the
 * target op and call input of the probe request. With that product the hook answers per the app's rule (recorded, must be
 * valid); the SAME caller WITHOUT `product` must fail CLOSED (allow false, or a hold verdict).
 */
export interface HookCallerProductFixture {
  hook: string;
  product: string;
  op?: string;
  input?: Json;
}

/**
 * `callerListedOp` (package 0.1.23, `Caller.listed`, SPEC-GAP spec 0.1.49): `op` = a static AGENT op an app caller may run
 * (the suite's `as: app` caller; `inputsAs.app` fixtures apply) whose output carries `ctx.caller.listed` at `path` (JSON pointer,
 * default `/listed`). `input` (optional) = its input for the app caller (placeholders allowed).
 */
export interface CallerListedFixture {
  op: string;
  path?: string;
  input?: Json;
}

/**
 * `bridgeCapsOp` (conformance 0.1.27, C292, spec 0.1.54, SDK >= 0.1.37): `op` = a PERSON op of the app that returns what
 * `ctx.bridgeCaps()` gave it, at `path` (JSON pointer into the op output, default `/bridgeCaps`); `input` (optional) = its input
 * (placeholders allowed). The A22 rows publish slices with other `bridge.caps` and require the value to follow them.
 */
export interface BridgeCapsFixture {
  op: string;
  path?: string;
  input?: Json;
}

/**
 * `eventsProbe` (conformance 0.1.28, C274c, spec 0.1.57, SDK >= 0.1.38): `op` = a PERSON op the A-EV rows drive with
 * `{case, key?, instanceId?, kind?}` (cases: emit, rollback, commit_throw, invalid {kind: payload | undeclared | reserved} → output
 * {code}, scoped, purge); `event` = the declared event `emit` sends; `scopedEvent` = a declared SCOPED event `scoped` sends (optional:
 * without it A-EV-6 and A-EV-7 are not_applicable); `instanceId` = the scope instance of `scoped` and `purge` (placeholders allowed).
 */
export interface EventsProbeFixture {
  op: string;
  event: string;
  scopedEvent?: string;
  instanceId?: Json;
}

export const EMPTY_CONFIG: ConformanceConfig = Object.freeze({ waivers: [], peers: [], contractOps: {}, setup: [], inputs: {}, inputsAs: {}, dynamic: {} });

/** A whole-string placeholder `${name}`; any other string (also one that merely contains `${`) is a literal. */
export const PLACEHOLDER_RE = /^\$\{([A-Za-z_][A-Za-z0-9_.]*)\}$/;
const CAPTURE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const STEP_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const TOP_KEYS = new Set(["waivers", "peers", "contractOps", "setup", "inputs", "inputsAs", "dynamic", "narrowing", "scopeGrantOp", "companionCallersOp", "hookCallerProduct", "callerListedOp", "bridgeCapsOp", "eventsProbe", "$schema", "$comment"]);
const PEER_KEYS = new Set(["product", "version", "channel", "settings"]);
const PRODUCT_RE = /^[a-z][a-z0-9-]{1,31}$/;
const SEMVER_RE = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;
const OP_RE = /^(?!tb_)[a-z][a-z0-9_]{1,39}$/;
const NARROWING_KEYS = new Set(["op", "input", "tag", "itemsPath"]);
const COMPANION_CALLERS_KEYS = new Set(["op", "path", "input", "agentProbe"]);
const COMPANION_PROBE_KEYS = new Set(["op", "path", "input"]);
const CALLER_LISTED_KEYS = new Set(["op", "path", "input"]);
const BRIDGE_CAPS_KEYS = new Set(["op", "path", "input"]);
const EVENTS_PROBE_KEYS = new Set(["op", "event", "scopedEvent", "instanceId"]);
const HOOK_CALLER_PRODUCT_KEYS = new Set(["hook", "product", "op", "input"]);
const SCOPE_GRANT_KEYS = new Set(["op", "input", "aboveCeiling", "agentProbe"]);
const SCOPE_PROBE_KEYS = new Set(["op", "input", "path"]);
const STEP_KEYS = new Set(["id", "as", "op", "input", "capture"]);

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Every placeholder name in `v` (whole-string values only). */
export function placeholderNames(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") {
    const m = PLACEHOLDER_RE.exec(v);
    if (m) out.push(m[1] as string);
  } else if (Array.isArray(v)) for (const x of v) placeholderNames(x, out);
  else if (isRecord(v)) for (const x of Object.values(v)) placeholderNames(x, out);
  return out;
}

/** Validates a parsed `tealbrick-conformance.json` (`where` names the file in errors). */
export function parseConformanceConfig(doc: unknown, where: string): ConformanceConfig {
  if (!isRecord(doc)) throw new WaiverError(`${where}: must be a JSON object`);
  for (const k of Object.keys(doc)) if (!TOP_KEYS.has(k)) throw new WaiverError(`${where}: unknown key ${JSON.stringify(k)} (allowed: waivers, peers, contractOps, setup, inputs, inputsAs, dynamic, narrowing, scopeGrantOp, companionCallersOp, hookCallerProduct, callerListedOp, bridgeCapsOp, eventsProbe)`);
  const waivers = parseWaivers(doc.waivers, where);
  const peers = parsePeers(doc.peers, where);
  const contractOps = parseContractOps(doc.contractOps, peers, where);
  const builtins = new Set<string>(BUILTIN_PLACEHOLDERS);
  const captured = new Set<string>();
  const known = (names: string[], at: string, by: "an earlier setup step" | "any setup step") => {
    for (const n of names) if (!builtins.has(n) && !captured.has(n)) throw new WaiverError(`${where}: ${at}: placeholder \${${n}} is not captured by ${by} (built-ins: ${BUILTIN_PLACEHOLDERS.join(", ")})`);
  };
  const setup: SetupStep[] = [];
  if (doc.setup !== undefined) {
    if (!Array.isArray(doc.setup)) throw new WaiverError(`${where}: setup must be an array`);
    const ids = new Set<string>();
    for (const [i, x] of doc.setup.entries()) {
      const at = `setup[${i}]`;
      if (!isRecord(x)) throw new WaiverError(`${where}: ${at} must be an object`);
      for (const k of Object.keys(x)) if (!STEP_KEYS.has(k)) throw new WaiverError(`${where}: ${at}: unknown key ${JSON.stringify(k)} (allowed: id, as, op, input, capture)`);
      if (typeof x.id !== "string" || !STEP_ID_RE.test(x.id)) throw new WaiverError(`${where}: ${at}.id must be a string of letters, digits, _ . - (≤ 64)`);
      if (ids.has(x.id)) throw new WaiverError(`${where}: ${at}.id ${JSON.stringify(x.id)} is not unique`);
      ids.add(x.id);
      if (!(SETUP_CALLERS as readonly unknown[]).includes(x.as)) throw new WaiverError(`${where}: ${at}.as must be one of ${SETUP_CALLERS.join(", ")}`);
      if (typeof x.op !== "string" || x.op.length === 0) throw new WaiverError(`${where}: ${at}.op must be an operation id`);
      const input = (x.input ?? {}) as Json;
      known(placeholderNames(input), `${at}.input`, "an earlier setup step");
      if (x.as !== "capsAgent" && placeholderNames(input).includes(CAPS_AGENT_PLACEHOLDER)) throw new WaiverError(`${where}: ${at}.input: \${${CAPS_AGENT_PLACEHOLDER}} has a value only in steps with "as": "capsAgent"`);
      const capture: Record<string, string> = {};
      if (x.capture !== undefined) {
        if (!isRecord(x.capture)) throw new WaiverError(`${where}: ${at}.capture must be an object {name: JSON pointer}`);
        for (const [name, ptr] of Object.entries(x.capture)) {
          if (!CAPTURE_NAME_RE.test(name)) throw new WaiverError(`${where}: ${at}.capture: name ${JSON.stringify(name)} must match ${CAPTURE_NAME_RE.source}`);
          if (captured.has(name)) throw new WaiverError(`${where}: ${at}.capture: ${name} is already captured by an earlier step`);
          if (typeof ptr !== "string" || (ptr !== "" && !ptr.startsWith("/"))) throw new WaiverError(`${where}: ${at}.capture.${name} must be a JSON pointer ("" or "/…")`);
          capture[name] = ptr;
        }
        for (const name of Object.keys(capture)) captured.add(name);
      }
      setup.push({ id: x.id, as: x.as as SetupCaller, op: x.op, input, capture });
    }
  }
  const opMap = (v: unknown, at: string): Record<string, Json> => {
    if (v === undefined) return {};
    if (!isRecord(v)) throw new WaiverError(`${where}: ${at} must be an object {<opId>: input}`);
    known(placeholderNames(v), at, "any setup step");
    return v as Record<string, Json>;
  };
  const inputs = opMap(doc.inputs, "inputs");
  const inputsAs: ConformanceConfig["inputsAs"] = {};
  if (doc.inputsAs !== undefined) {
    if (!isRecord(doc.inputsAs)) throw new WaiverError(`${where}: inputsAs must be an object {<caller>: {<opId>: input}}`);
    for (const [who, v] of Object.entries(doc.inputsAs)) {
      if (!(INPUT_CALLERS as readonly string[]).includes(who)) throw new WaiverError(`${where}: inputsAs.${who}: caller must be one of ${INPUT_CALLERS.join(", ")}`);
      inputsAs[who as InputCaller] = opMap(v, `inputsAs.${who}`);
    }
  }
  const dynamic: ConformanceConfig["dynamic"] = {};
  if (doc.dynamic !== undefined) {
    if (!isRecord(doc.dynamic)) throw new WaiverError(`${where}: dynamic must be an object {<dynamicOpId>: {resolveTools: [names]}}`);
    for (const [op, v] of Object.entries(doc.dynamic)) {
      const tools = isRecord(v) ? v.resolveTools : undefined;
      if (!isRecord(v) || Object.keys(v).some((k) => k !== "resolveTools") || !Array.isArray(tools) || tools.length === 0 || !tools.every((t) => typeof t === "string" && t.length > 0)) {
        throw new WaiverError(`${where}: dynamic.${op} must be {resolveTools: [non-empty tool names]}`);
      }
      dynamic[op] = { resolveTools: [...(tools as string[])] };
    }
  }
  let narrowing: NarrowingFixture | undefined;
  if (doc.narrowing !== undefined) {
    const n = doc.narrowing;
    const shape = `${where}: narrowing must be {op: "<agent read op id>", input?: <input>, tag?: "<tag>"}`;
    if (!isRecord(n)) throw new WaiverError(shape);
    for (const k of Object.keys(n)) if (!NARROWING_KEYS.has(k)) throw new WaiverError(`${where}: narrowing: unknown key ${JSON.stringify(k)} (allowed: op, input, tag, itemsPath)`);
    if (typeof n.op !== "string" || n.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    // SDK-API §18: tags ≤ 64 chars (compared after normalizeTag = trim + lower case)
    if (n.tag !== undefined && (typeof n.tag !== "string" || n.tag.trim().length === 0 || n.tag.length > 64)) throw new WaiverError(`${where}: narrowing.tag must be a non-empty string of ≤ 64 characters`);
    if (n.itemsPath !== undefined && (typeof n.itemsPath !== "string" || !(n.itemsPath === "" || n.itemsPath.startsWith("/")))) throw new WaiverError(`${where}: narrowing.itemsPath must be a JSON pointer ("" or "/…")`);
    if (n.input !== undefined) known(placeholderNames(n.input), "narrowing.input", "any setup step");
    narrowing = { op: n.op, ...(n.input !== undefined ? { input: n.input as Json } : {}), ...(typeof n.tag === "string" ? { tag: n.tag } : {}), ...(typeof n.itemsPath === "string" ? { itemsPath: n.itemsPath } : {}) };
  }
  let scopeGrantOp: ScopeGrantFixture | undefined;
  if (doc.scopeGrantOp !== undefined) {
    const g = doc.scopeGrantOp;
    const shape = `${where}: scopeGrantOp must be {op: "<person op id>", input: <grant within the ceiling>, aboveCeiling: <grant above the ceiling>, agentProbe?: {op, input?, path?}}`;
    if (!isRecord(g)) throw new WaiverError(shape);
    for (const k of Object.keys(g)) if (!SCOPE_GRANT_KEYS.has(k)) throw new WaiverError(`${where}: scopeGrantOp: unknown key ${JSON.stringify(k)} (allowed: op, input, aboveCeiling, agentProbe)`);
    if (typeof g.op !== "string" || g.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    if (g.input === undefined || g.aboveCeiling === undefined) throw new WaiverError(`${shape}; input and aboveCeiling are both required`);
    known(placeholderNames(g.input), "scopeGrantOp.input", "any setup step");
    known(placeholderNames(g.aboveCeiling), "scopeGrantOp.aboveCeiling", "any setup step");
    let agentProbe: ScopeGrantFixture["agentProbe"];
    if (g.agentProbe !== undefined) {
      const p = g.agentProbe;
      if (!isRecord(p)) throw new WaiverError(`${where}: scopeGrantOp.agentProbe must be {op, input?, path?}`);
      for (const k of Object.keys(p)) if (!SCOPE_PROBE_KEYS.has(k)) throw new WaiverError(`${where}: scopeGrantOp.agentProbe: unknown key ${JSON.stringify(k)} (allowed: op, input, path)`);
      if (typeof p.op !== "string" || p.op.length === 0) throw new WaiverError(`${where}: scopeGrantOp.agentProbe.op must be an agent operation id`);
      if (p.path !== undefined && (typeof p.path !== "string" || !(p.path === "" || p.path.startsWith("/")))) throw new WaiverError(`${where}: scopeGrantOp.agentProbe.path must be a JSON pointer ("" or "/…")`);
      if (p.input !== undefined) known(placeholderNames(p.input), "scopeGrantOp.agentProbe.input", "any setup step");
      agentProbe = { op: p.op, ...(p.input !== undefined ? { input: p.input as Json } : {}), ...(typeof p.path === "string" ? { path: p.path } : {}) };
    }
    scopeGrantOp = { op: g.op, input: g.input as Json, aboveCeiling: g.aboveCeiling as Json, ...(agentProbe ? { agentProbe } : {}) };
  }
  let companionCallersOp: CompanionCallersFixture | undefined;
  if (doc.companionCallersOp !== undefined) {
    const g = doc.companionCallersOp;
    const shape = `${where}: companionCallersOp must be {op: "<person op id>", path?: "<JSON pointer, default /companionCallers>", input?, agentProbe?: {op: "<agent op id>", path?, input?}}`;
    if (!isRecord(g)) throw new WaiverError(shape);
    for (const k of Object.keys(g)) if (!COMPANION_CALLERS_KEYS.has(k)) throw new WaiverError(`${where}: companionCallersOp: unknown key ${JSON.stringify(k)} (allowed: op, path, input, agentProbe)`);
    if (typeof g.op !== "string" || g.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    if (g.path !== undefined && (typeof g.path !== "string" || !(g.path === "" || g.path.startsWith("/")))) throw new WaiverError(`${where}: companionCallersOp.path must be a JSON pointer ("" or "/…")`);
    if (g.input !== undefined) known(placeholderNames(g.input), "companionCallersOp.input", "any setup step");
    let agentProbe: CompanionCallersFixture["agentProbe"];
    if (g.agentProbe !== undefined) {
      const p = g.agentProbe;
      if (!isRecord(p)) throw new WaiverError(`${where}: companionCallersOp.agentProbe must be {op, path?, input?}`);
      for (const k of Object.keys(p)) if (!COMPANION_PROBE_KEYS.has(k)) throw new WaiverError(`${where}: companionCallersOp.agentProbe: unknown key ${JSON.stringify(k)} (allowed: op, path, input)`);
      if (typeof p.op !== "string" || p.op.length === 0) throw new WaiverError(`${where}: companionCallersOp.agentProbe.op must be an agent operation id`);
      if (p.path !== undefined && (typeof p.path !== "string" || !(p.path === "" || p.path.startsWith("/")))) throw new WaiverError(`${where}: companionCallersOp.agentProbe.path must be a JSON pointer ("" or "/…")`);
      if (p.input !== undefined) known(placeholderNames(p.input), "companionCallersOp.agentProbe.input", "any setup step");
      agentProbe = { op: p.op, ...(typeof p.path === "string" ? { path: p.path } : {}), ...(p.input !== undefined ? { input: p.input as Json } : {}) };
    }
    companionCallersOp = { op: g.op, ...(typeof g.path === "string" ? { path: g.path } : {}), ...(g.input !== undefined ? { input: g.input as Json } : {}), ...(agentProbe ? { agentProbe } : {}) };
  }
  let hookCallerProduct: HookCallerProductFixture | undefined;
  if (doc.hookCallerProduct !== undefined) {
    const h = doc.hookCallerProduct;
    const shape = `${where}: hookCallerProduct must be {hook: "<before hook id>", product: "<product the criteria key on>", op?: "<target op id>", input?: <json>}`;
    if (!isRecord(h)) throw new WaiverError(shape);
    for (const k of Object.keys(h)) if (!HOOK_CALLER_PRODUCT_KEYS.has(k)) throw new WaiverError(`${where}: hookCallerProduct: unknown key ${JSON.stringify(k)} (allowed: hook, product, op, input)`);
    if (typeof h.hook !== "string" || h.hook.length === 0) throw new WaiverError(`${shape}; hook missing`);
    if (typeof h.product !== "string" || !PRODUCT_RE.test(h.product)) throw new WaiverError(`${where}: hookCallerProduct.product must be a product id (${PRODUCT_RE})`);
    if (h.op !== undefined && (typeof h.op !== "string" || h.op.length === 0)) throw new WaiverError(`${where}: hookCallerProduct.op must be an operation id`);
    if (h.input !== undefined) known(placeholderNames(h.input), "hookCallerProduct.input", "any setup step");
    hookCallerProduct = { hook: h.hook, product: h.product, ...(typeof h.op === "string" ? { op: h.op } : {}), ...(h.input !== undefined ? { input: h.input as Json } : {}) };
  }
  let callerListedOp: CallerListedFixture | undefined;
  if (doc.callerListedOp !== undefined) {
    const g = doc.callerListedOp;
    const shape = `${where}: callerListedOp must be {op: "<agent op id>", path?: "<JSON pointer, default /listed>", input?}`;
    if (!isRecord(g)) throw new WaiverError(shape);
    for (const k of Object.keys(g)) if (!CALLER_LISTED_KEYS.has(k)) throw new WaiverError(`${where}: callerListedOp: unknown key ${JSON.stringify(k)} (allowed: op, path, input)`);
    if (typeof g.op !== "string" || g.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    if (g.path !== undefined && (typeof g.path !== "string" || !(g.path === "" || g.path.startsWith("/")))) throw new WaiverError(`${where}: callerListedOp.path must be a JSON pointer ("" or "/…")`);
    if (g.input !== undefined) known(placeholderNames(g.input), "callerListedOp.input", "any setup step");
    callerListedOp = { op: g.op, ...(typeof g.path === "string" ? { path: g.path } : {}), ...(g.input !== undefined ? { input: g.input as Json } : {}) };
  }
  let bridgeCapsOp: BridgeCapsFixture | undefined;
  if (doc.bridgeCapsOp !== undefined) {
    const g = doc.bridgeCapsOp;
    const shape = `${where}: bridgeCapsOp must be {op: "<person op id>", path?: "<JSON pointer, default /bridgeCaps>", input?}`;
    if (!isRecord(g)) throw new WaiverError(shape);
    for (const k of Object.keys(g)) if (!BRIDGE_CAPS_KEYS.has(k)) throw new WaiverError(`${where}: bridgeCapsOp: unknown key ${JSON.stringify(k)} (allowed: op, path, input)`);
    if (typeof g.op !== "string" || g.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    if (g.path !== undefined && (typeof g.path !== "string" || !(g.path === "" || g.path.startsWith("/")))) throw new WaiverError(`${where}: bridgeCapsOp.path must be a JSON pointer ("" or "/…")`);
    if (g.input !== undefined) known(placeholderNames(g.input), "bridgeCapsOp.input", "any setup step");
    bridgeCapsOp = { op: g.op, ...(typeof g.path === "string" ? { path: g.path } : {}), ...(g.input !== undefined ? { input: g.input as Json } : {}) };
  }
  let eventsProbe: EventsProbeFixture | undefined;
  if (doc.eventsProbe !== undefined) {
    const g = doc.eventsProbe;
    const shape = `${where}: eventsProbe must be {op: "<person op id>", event: "<declared event name>", scopedEvent?: "<declared scoped event name>", instanceId?}`;
    if (!isRecord(g)) throw new WaiverError(shape);
    for (const k of Object.keys(g)) if (!EVENTS_PROBE_KEYS.has(k)) throw new WaiverError(`${where}: eventsProbe: unknown key ${JSON.stringify(k)} (allowed: op, event, scopedEvent, instanceId)`);
    if (typeof g.op !== "string" || g.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    if (typeof g.event !== "string" || g.event.length === 0) throw new WaiverError(`${shape}; event missing`);
    if (g.scopedEvent !== undefined && (typeof g.scopedEvent !== "string" || g.scopedEvent.length === 0)) throw new WaiverError(`${shape}; scopedEvent must be a name`);
    if (g.instanceId !== undefined) known(placeholderNames(g.instanceId), "eventsProbe.instanceId", "any setup step");
    eventsProbe = { op: g.op, event: g.event, ...(typeof g.scopedEvent === "string" ? { scopedEvent: g.scopedEvent } : {}), ...(g.instanceId !== undefined ? { instanceId: g.instanceId as Json } : {}) };
  }
  return { waivers, peers, contractOps, setup, inputs, inputsAs, dynamic, ...(narrowing ? { narrowing } : {}), ...(scopeGrantOp ? { scopeGrantOp } : {}), ...(companionCallersOp ? { companionCallersOp } : {}), ...(hookCallerProduct ? { hookCallerProduct } : {}), ...(callerListedOp ? { callerListedOp } : {}), ...(bridgeCapsOp ? { bridgeCapsOp } : {}), ...(eventsProbe ? { eventsProbe } : {}) };
}

/** `peers` (CONF-MULTIAPP): 0..MAX_PEERS entries `{product, version, channel?, settings?}`; an unknown key, a duplicate product or a malformed value is a usage error. */
function parsePeers(list: unknown, where: string): PeerSpec[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) throw new WaiverError(`${where}: peers must be an array of {product, version, channel?, settings?}`);
  if (list.length > MAX_PEERS) throw new WaiverError(`${where}: at most ${MAX_PEERS} peers (got ${list.length})`);
  const seen = new Set<string>();
  return list.map((x, i) => {
    const at = `peers[${i}]`;
    if (!isRecord(x)) throw new WaiverError(`${where}: ${at} must be an object {product, version, channel?, settings?}`);
    for (const k of Object.keys(x)) if (!PEER_KEYS.has(k)) throw new WaiverError(`${where}: ${at}: unknown key ${JSON.stringify(k)} (allowed: product, version, channel, settings)`);
    if (typeof x.product !== "string" || !PRODUCT_RE.test(x.product)) throw new WaiverError(`${where}: ${at}.product must be a product id (${PRODUCT_RE.source})`);
    if (seen.has(x.product)) throw new WaiverError(`${where}: ${at}.product ${JSON.stringify(x.product)} is listed twice`);
    seen.add(x.product);
    if (typeof x.version !== "string" || !SEMVER_RE.test(x.version)) throw new WaiverError(`${where}: ${at}.version must be an exact released version (x.y.z), not a range`);
    if (x.channel !== undefined && x.channel !== "stable" && x.channel !== "dev") throw new WaiverError(`${where}: ${at}.channel must be "stable" or "dev"`);
    let settings: Record<string, Json> | undefined;
    if (x.settings !== undefined) {
      if (!isRecord(x.settings)) throw new WaiverError(`${where}: ${at}.settings must be an object`);
      if (Object.keys(x.settings).length > 32 || JSON.stringify(x.settings).length > 4096) throw new WaiverError(`${where}: ${at}.settings is too large (≤ 32 keys, ≤ 4 KiB)`);
      settings = x.settings as Record<string, Json>;
    }
    return { product: x.product, version: x.version, channel: x.channel === "dev" ? "dev" : "stable", ...(settings ? { settings } : {}) };
  });
}

/** `contractOps` (CONF-MULTIAPP X4): `{"<contract id>": "<peer product>.<op id>"}`; the peer must be declared in `peers`. */
function parseContractOps(v: unknown, peers: readonly PeerSpec[], where: string): Record<string, ContractOp> {
  if (v === undefined) return {};
  if (!isRecord(v)) throw new WaiverError(`${where}: contractOps must be an object {"<contract id>": "<peer product>.<op id>"}`);
  const out: Record<string, ContractOp> = {};
  for (const [id, target] of Object.entries(v)) {
    if (!(CONTRACT_IDS as readonly string[]).includes(id)) throw new WaiverError(`${where}: contractOps: unknown contract ${JSON.stringify(id)} (known: ${CONTRACT_IDS.join(", ")})`);
    const dot = typeof target === "string" ? target.indexOf(".") : -1;
    const peer = dot > 0 ? (target as string).slice(0, dot) : "";
    const op = dot > 0 ? (target as string).slice(dot + 1) : "";
    if (!PRODUCT_RE.test(peer) || !OP_RE.test(op)) throw new WaiverError(`${where}: contractOps.${id} must be "<peer product>.<op id>"`);
    if (!peers.some((p) => p.product === peer)) throw new WaiverError(`${where}: contractOps.${id}: ${peer} is not a declared peer`);
    out[id] = { peer, op };
  }
  return out;
}

function parseWaivers(list: unknown, where: string): Waiver[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) throw new WaiverError(`${where}: waivers must be an array`);
  return list.map((x, i) => {
    const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
    if (typeof o.id !== "string" || typeof o.until !== "string" || typeof o.reason !== "string") throw new WaiverError(`${where}: waivers[${i}] needs string id, until and reason`);
    return checked({ id: o.id, until: o.until, reason: o.reason }, `${where} waivers[${i}]`);
  });
}

/** `tealbrick-conformance.json` beside `manifestPath` (EMPTY_CONFIG when the file is absent); throws WaiverError (usage error) when malformed. */
export function loadConformanceConfig(manifestPath: string): ConformanceConfig {
  const path = join(dirname(manifestPath), WAIVER_FILE);
  if (!existsSync(path)) return EMPTY_CONFIG;
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new WaiverError(`${path}: not JSON (${e instanceof Error ? e.message : String(e)})`);
  }
  return parseConformanceConfig(doc, path);
}
