// Minimal deployed bridge for the bridge target's sensitivity tests (NOT a product bridge): enrolment, signed config
// pull + ack, jwt-bearer K5, MCP initialize / tools/list / tools/call with gate() and forward (grant + call proof).
// Key page on its own origin (BRIDGE §3.1 / §9.3 v0.1.10, C59): keys-ticket POST → form + session, session GET.
// v0.1.13 (spine013): before / context / after hooks with the hold-verdict chain (hv in the op proof), the reserved
// `tb.` context namespace + `_meta` tealbrick/onBehalfOf, and the companion path /tb/v1/call (app-initiated calls).
// C85 + v0.1.14 (A2A-10): calls in flight per instance (target or answering one of its hooks), hook re-entry and depth
// from a VALID parentCall only; anything else is app-initiated: per-caller token bucket (burst 30, 2/s → rate_limited +
// Retry-After) and a `call.app_initiated` JSON log line (kept in MiniState.logs, which the tests hand the runner).
// v0.1.24 (C117): the chain = the hooks DECLARED in the deployed apps' manifests (fetched at config apply); config
// hooks[] is the owner switch (enabled: false → skipped); a declared hook absent from it, or whose app is down → hook_failed.
// Flags break exactly one rule each so a test can assert the matching check flips from pass to fail.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  bridgeOpProofClaims,
  deriveIdempotencyKey,
  digest,
  dynamicToolNames,
  type Ed25519KeyPair,
  gate,
  generateKeyPair,
  holdVerdictClaim,
  hookResponseProblem,
  isPrivateInternalUrl,
  KNOWN_HOLD_FAMILIES,
  keySetFrom,
  keySetFromPortalKeys,
  mcpToolName,
  onBehalfOfFromMeta,
  opaqueDigest,
  portalRootKeys,
  reduceBeforeChain,
  signAgentSession,
  signAssertion,
  signBridgeOpProof,
  signCallProof,
  signHookProof,
  TYP,
  trustedPortalKeys,
  ulid,
  validateInput,
  verifyAgentSession,
  verifyAssertion,
  verifyConfig,
  verifyGrant,
  verifyKeysTicket,
  withStandardOps,
} from "@opt2-tealbrick/manifest";
import type { ClaimRecord, EnrolResponse, HookEntry, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, BRIDGE_OP_PATH, type BridgeOp, type Ed25519PublicJwk, type HoldVerdictClaim, type PortalKeyEntry } from "@opt2-tealbrick/spec/credentials";
import type { DynamicCatalogEntry, Manifest, Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import { EventLog, type EventLogFaults } from "../../src/event-log.ts";
import { type MiniPersonOpFaults, runMiniPersonOps } from "./mini-person-ops.ts";

export interface MiniFlags {
  /** pre-C98: a required op without a _meta key is refused input_invalid, a supported one is forwarded keyless (no derived key) */
  noDerivedKey?: boolean;
  /** pre-C98a (bridge 0.1.16): derives the key for required ops only; a supported op is forwarded keyless (fails B8.idempotency_derived) */
  deriveRequiredOnly?: boolean;
  /** pre-C107: forwards a resolve answer with effect outward / money and no holdFamily (fails B16.resolve_family) */
  resolveNoFamilyCheck?: boolean;
  /** pre-C108 strict reader: drops a config grant whose held names an unknown family (fails B5.grant_held_unknown) */
  strictHeld?: boolean;
  skipPause?: boolean;
  noProof?: boolean;
  listPerson?: boolean;
  leakToPortal?: boolean;
  acceptPerson?: boolean;
  /** serves /keys on the main origin too (C59) */
  keysOnMain?: boolean;
  /** the keys origin falls through to every main-origin route (C59) */
  keysOriginOpen?: boolean;
  /** key page without Content-Security-Policy (C59) */
  noKeysCsp?: boolean;
  /** answers 404 instead of 503 when TB_KEYS_PUBLIC_URL is unset (C59) */
  noUnset503?: boolean;
  /** routes to any internalUrl (no BSD-07 check) */
  noAddressCheck?: boolean;
  /** ignores portalKeySet: portalKeys replace the trusted set (pre-v0.1.11 rule) */
  ignoreKeySet?: boolean;
  /** accepts a re-enrolment whose EnrolResponse carries no valid portalKeySet (drops its pin) */
  acceptStrippedReenrol?: boolean;
  /** v0.1.13: a kept hold stops the before chain (a later refuse cannot win; fails B22.hold_verdict) */
  holdStopsChain?: boolean;
  /** v0.1.13: the verdict travels in a separate header, not signed in the proof (fails B22.hold_verdict, B22.hv_tamper) */
  hvOutsideProof?: boolean;
  /** v0.1.13: a hold verdict is cached per (caller, op, input); the retry skips the before chain (fails B22.hold_retry_refused) */
  cacheHoldVerdict?: boolean;
  /** v0.1.13: ignores _meta tealbrick/onBehalfOf (fails B23.on_behalf_of) */
  noOnBehalfOf?: boolean;
  /** v0.1.13: lets a context hook write tb.* keys (fails B23.reserved_tb_namespace) */
  allowTbContext?: boolean;
  /** v0.1.13: app-initiated companion calls skip the hooks (fails B24.app_initiated) */
  appCallsSkipHooks?: boolean;
  /** v0.1.13: companion calls are not gated by the grant's workflow (fails B24.no_grant) */
  companionNoWfCheck?: boolean;
  /** pre-0.1.17 bridge (L2): a before hook answering a hold verdict is treated as hook_failed (fails B25.real_hook_hold) */
  holdAsHookFailed?: boolean;
  /** pre-C111a gate: `wf` limits Bound grants only, a Free grant's non-empty wf is ignored (fails B5.free_wf_limits) */
  wfOnlyBound?: boolean;
  /** C91 (QA S1): signs catalog bridge-op proofs with `in` (the SDK binds {bop, op} only; fails B25.real_catalog_search) */
  catalogWithIn?: boolean;
  /** the bridge version reported at enrolment and in acks (default "0.0.0": predates 0.2.2, so B28 is not_applicable) */
  version?: string;
  /**
   * spec 0.1.54 (C292, conformance 0.1.27): implements the C283 A1 owner-row filter (lists the ops an app's scope_summary names in admittedOps)
   * and DECLARES it: every ack carries bridge.caps ["owner_rows"]. Independent of `version` (the suite decides by the cap, never by version)
   */
  ownerRows?: boolean;
  /** spec 0.1.54: the caps the acks declare INSTEAD of the ones `ownerRows` implies (e.g. ["future_cap"], or ["owner_rows"] without implementing it) */
  declaredCaps?: string[];
  /**
   * spec 0.1.57 (C274c, conformance 0.1.28): implements BRIDGE §14 (ingest POST /tb/v1/events, the per-agent log, tealbrick/events/*
   * on /mcp and the GET /mcp frames) with the reference EventLog and DECLARES the `events` cap in every ack (with owner_rows)
   */
  events?: boolean;
  /** conformance 0.1.28: one §14 rule broken (B-EV sensitivity) */
  eventFaults?: EventLogFaults;
  /** with `events`: waits this long before answering each ingest (a compliant but slow bridge: B-EV-8/11 run out of their budget) */
  slowEventsMs?: number;
  /** without `events`: answers tealbrick/events/* with an empty result instead of -32601 (fails B-EV-18) */
  eventsMethodsAnswerEmpty?: boolean;
  /** spec 0.1.50 (C283 A1): declares owner_rows but never lists the ops an app's scope_summary names in admittedOps (fails B5.gate_scoped_above_grant) */
  ignoresAdmittedOps?: boolean;
  /** pre-C283 gate: refuses a scoped op above the grant's crud with crud_exceeds_grant although it lists it (fails B5.gate_scoped_above_grant) */
  oldGateCrud?: boolean;
  /** spec 0.1.45 (bridge < 0.2.2): hook requests carry no call.caller.product (fails B28.hook_caller_product) */
  noHookCallerProduct?: boolean;
  /** spec 0.1.45 (security): takes call.caller.product from the call input when it names one (fails B28.hook_caller_product) */
  hookCallerProductFromInput?: boolean;
  /** spec 0.1.45: also gives AGENT callers a product (the first deployed app's; fails B28.hook_caller_product) */
  hookCallerProductForAgents?: boolean;
  /** C85: hooks of an app-initiated call see caller type `system`, not `app` (fails B26.app_initiated_real) */
  appInitiatedAsSystem?: boolean;
  /** C85: no rate limit for app-initiated calls (fails B26.app_initiated_rate) */
  noAppRateLimit?: boolean;
  /** C85: no `call.app_initiated` log line (fails B26.app_initiated_audit) */
  noAppInitiatedAudit?: boolean;
  /** A2A-10: any parentCall makes a child call, even an id the bridge never issued (fails B26.parent_call_forged) */
  parentTrusted?: boolean;
  /** A2A-10: a parentCall in flight for ANY instance counts (fails B26.parent_call_foreign: hook_reentry) */
  parentAnyInstance?: boolean;
  /** A2A-10: finished calls stay valid parents (fails B26.parent_call_expired) */
  parentKeepsFinished?: boolean;
  /** C117: builds the chain from config hooks[] only: a declared hook absent from it is not run and refuses nothing (fails B27.hook_declared_absent, B25.real_hook_after_update) */
  trustConfigHooks?: boolean;
  /** v0.1.25: refuses a declared, unlisted hook but reports no rejected hook_not_listed (fails B27.hook_declared_absent) */
  noHookNotListedReport?: boolean;
  /** C117: ignores the owner switch: a hook listed with enabled: false still runs (fails B27.hook_disabled_skipped) */
  ignoreHookEnabled?: boolean;
  /** C117: a hook whose app refuses the connection (down) is skipped instead of hook_failed (fails B27.hook_app_down) */
  skipDownHookApp?: boolean;
  /** spec 0.1.64 (BRIDGE §16, conformance 0.1.31): runs the person-op relay (mini-person-ops.ts) and DECLARES the `person_ops` cap */
  personOps?: boolean;
  /** conformance 0.1.31: one §16 rule broken (R-PO sensitivity) */
  personOpFaults?: MiniPersonOpFaults;
  /** runs the relay WITHOUT declaring the cap (fails R-PO-1 and B9.portal_paths) */
  personOpsWithoutCap?: boolean;
}

/** Identity kept across restarts of one mini bridge (same volume): a restart does not enrol again. */
export interface MiniState {
  key?: Ed25519KeyPair;
  enrol?: EnrolResponse;
  usedJtis?: Set<string>;
  pinned?: { seq: number; kss: string } | null;
  trusted?: PortalKeyEntry[];
  /** the enrolment code S1 was made with (a different TB_ENROL_CODE at boot = re-enrolment, BRIDGE §4.3) */
  code?: string;
  /** one volume per TB_DATA_DIR (a fresh data dir is a fresh bridge) */
  byDir?: Record<string, MiniState>;
  /** the bridge's log lines (JSON), across restarts: the tests pass them to the runner as captured logs */
  logs?: string[];
}

const nowS = () => Math.floor(Date.now() / 1000);
const ON_BEHALF_OF = "tealbrick/onBehalfOf";
const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
};
const read = async (req: IncomingMessage) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
};
const listen = (srv: Server, port: number) => new Promise<void>((r) => srv.listen(port, "127.0.0.1", () => r()));
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const peekJwt = (t: string): Record<string, unknown> => {
  try {
    return JSON.parse(Buffer.from(t.split(".")[1] ?? "", "base64url").toString()) as Record<string, unknown>;
  } catch {
    return {};
  }
};

export async function startMiniBridge(env: Record<string, string>, flags: MiniFlags = {}, root: MiniState = {}) {
  root.byDir ??= {};
  root.logs ??= [];
  const logLines = root.logs;
  root.byDir[env.TB_DATA_DIR as string] ??= {};
  const state = root.byDir[env.TB_DATA_DIR as string] as MiniState;
  const portal = env.TB_PORTAL_URL as string;
  const pub = env.TB_PUBLIC_URL as string;
  const keysHost = env.TB_KEYS_PUBLIC_URL ? new URL(env.TB_KEYS_PUBLIC_URL).hostname : null;
  const usedJtis = state.usedJtis ?? new Set<string>();
  state.usedJtis = usedJtis;
  const keySessions = new Set<string>();
  // v0.1.11: roots come from the harness-only TBCONF_PORTAL_ROOT_KEYS (a product bridge takes them through its
  // programmatic start option), else the build-pinned dev roots; BSD-07 allow-list from the owner-set TB_OWN_INFRA_ORIGINS
  const roots = env.TBCONF_PORTAL_ROOT_KEYS ? (JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS) as never[]) : portalRootKeys("dev");
  const allowList = (env.TB_OWN_INFRA_ORIGINS ?? "").split(",").map((x) => x.trim()).filter(Boolean);
  // enrolment (first start) or re-enrolment (new TB_ENROL_CODE): a new key; S1 changes only if the response passes
  // the key-set rule (CREDENTIALS §9.5: a pinned bridge needs a valid statement; strict builds need one at first enrolment)
  if (!state.enrol || state.code !== env.TB_ENROL_CODE) {
    const key = await generateKeyPair();
    const enrol = (await (
      await fetch(`${portal}/api/v1/bridge/enrol`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: env.TB_ENROL_CODE, publicKey: key.publicJwk, version: flags.version ?? "0.0.0", sdkMajors: [1, 0], form: "deployed", publicOrigin: pub }),
      })
    ).json()) as EnrolResponse;
    const lax = flags.ignoreKeySet || (flags.acceptStrippedReenrol && !!state.enrol);
    // `lax` = a DEFECTIVE bridge (fault injection): it skips the key-set rule and trusts the document's `portalKeys`
    const t = lax ? null : trustedPortalKeys(enrol as { portalKeySet?: string }, state.pinned ?? null, roots);
    if (t && !t.ok) {
      if (!state.enrol) throw new Error(`enrolment refused: ${t.code}`);
      // re-enrolment refused: keep S1 (old key, identity, pin)
    } else {
      state.key = key;
      state.enrol = enrol;
      state.code = env.TB_ENROL_CODE;
      if (t) {
        state.pinned = { seq: t.seq, kss: t.kss };
        state.trusted = t.keys.keys.map((k) => ({ jwk: k.jwk, status: k.status }));
      } else {
        if (flags.acceptStrippedReenrol) state.pinned = null;
        state.trusted = enrol.portalKeys;
      }
    }
  }
  const key = state.key as Ed25519KeyPair;
  const enrol = state.enrol as EnrolResponse;
  let pinned = state.pinned ?? null;
  let trusted: PortalKeyEntry[] = state.trusted ?? enrol.portalKeys;
  const brg = `tb:brg:${enrol.bridgeId}` as const;
  const rejected = new Map<string, number>();
  const reject = (code: string, kind = "config", ins = "") => rejected.set(`${kind}|${code}|${ins}`, (rejected.get(`${kind}|${code}|${ins}`) ?? 0) + 1);
  const routable = (a: { internalUrl: string; ownInfra?: boolean }) => flags.noAddressCheck || isPrivateInternalUrl(a.internalUrl, { ownInfra: a.ownInfra === true, allowList });
  let cfg: WorkspaceConfig | null = null;
  const verdictCache = new Map<string, HoldVerdictClaim>();
  const claimsSeen: ClaimRecord[] = [];
  const usedCodes = new Set<string>();
  const manifests = new Map<string, Manifest>();
  const boot = randomUUID();
  let stopped = false;

  const portalCall = async (method: string, path: string, body?: unknown, timeoutMs = 5000) => {
    const raw = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const assertion = await signAssertion("tb-bridge-assert+jwt", { iss: brg, sub: brg, aud: "tb:portal", iat: nowS() }, key, { method, pathAndQuery: path, body: raw });
    return fetch(`${portal}${path}`, { method, headers: { "content-type": "application/json", "TB-Assert": assertion }, body: raw, signal: AbortSignal.timeout(timeoutMs) });
  };
  /** spec 0.1.54 (C292): StatusReport.bridge.caps of every ack */
  const declaredCaps: string[] = flags.declaredCaps ?? [...(flags.ownerRows || flags.events ? ["owner_rows"] : []), ...(flags.events ? ["events"] : []), ...(flags.personOps ? ["person_ops"] : [])];
  const ack = (extra: Record<string, unknown> = {}) =>
    cfg &&
    portalCall("POST", enrol.ackPath, {
      rev: cfg.rev,
      appliedAt: new Date().toISOString(),
      bridge: { id: enrol.bridgeId, version: flags.version ?? "0.0.0", form: "deployed", boot, sdkMajors: [1, 0], mcpVersions: ["2025-06-18"], ...(declaredCaps.length > 0 ? { caps: declaredCaps } : {}) },
      portalReachable: true,
      apps: cfg.apps.map((a) => ({ ins: a.ins, state: "ok", version: a.version, sdkVersion: null, manifestDigest: a.manifestDigest, lastSeen: null, pendingHolds: 0 })),
      keys: [],
      scopeSummaries: [],
      connectionsCreated: [],
      connectionsRevoked: [],
      claims: claimsSeen,
      rejected: [...rejected].map(([k, count]) => {
        const [kind, code, ins] = k.split("|");
        return { kind, code, count, ...(ins ? { ins } : {}) };
      }),
      toolsOmitted: [],
      ...extra,
    }).catch(() => undefined);

  void (async () => {
    while (!stopped) {
      try {
        const path = `${enrol.configPath}?after=${cfg?.rev ?? 0}&wait=1`;
        const r = await portalCall("GET", path);
        if (r.status === 200) {
          const jws = await r.text();
          const peeked = JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString() || "{}") as { portalKeySet?: string };
          const t = flags.ignoreKeySet ? null : trustedPortalKeys(peeked, pinned, roots);
          const signers = t === null ? keySetFromPortalKeys(trusted) : t.ok ? t.signers : null;
          const v = signers ? verifyConfig(jws, { now: nowS(), self: brg, issuers: signers }) : null;
          const body = v?.ok ? (v.body as WorkspaceConfig) : null;
          if (body && body.ws === enrol.workspaceId && (!cfg || body.rev > cfg.rev)) {
            for (const a of body.apps as (WorkspaceConfig["apps"][number] & { ownInfra?: boolean })[]) {
              if (!routable(a)) reject("internal_url_refused");
              else if (!manifests.has(a.ins)) await fetchManifest(a);
            }
            cfg = body;
            await refreshCatalogs();
            if (t?.ok) {
              pinned = { seq: t.seq, kss: t.kss };
              trusted = t.keys.keys.map((k) => ({ jwk: k.jwk, status: k.status }));
            } else trusted = body.portalKeys;
            state.pinned = pinned;
            state.trusted = trusted;
            await ack();
          }
        }
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  })();

  // spec 0.1.64 (BRIDGE §16): the person-op relay
  if (flags.personOps || flags.personOpsWithoutCap) runMiniPersonOps({ portalCall, config: () => cfg, stopped: () => stopped, log: (l) => logLines.push(l), faults: flags.personOpFaults ?? {} });

  /** an app that is not up yet (a real SDK app deployed before it claims) is fetched again later */
  async function fetchManifest(a: { ins: string; internalUrl: string }): Promise<void> {
    try {
      const r = await fetch(`${a.internalUrl}/tb/v1/manifest`, { signal: AbortSignal.timeout(3000) });
      if (r.status === 200) manifests.set(a.ins, (await r.json()) as Manifest);
    } catch {
      // not reachable yet
    }
  }
  /** spec 0.1.50 (C283 A1): lists the static scoped ops an app's scope_summary names in `admittedOps` for an agent (only a bridge that implements the filter: `ownerRows`) */
  const adoptsAdmitted = flags.ownerRows === true && !flags.ignoresAdmittedOps;
  /** `<ins>|<agent>` → op ids the app admits (read at every tools/list and tools/call) */
  const admittedOps = new Map<string, Set<string>>();
  const refreshAdmitted = async () => {
    admittedOps.clear();
    for (const a of (cfg?.apps ?? []) as (WorkspaceConfig["apps"][number] & { ownInfra?: boolean })[]) {
      if (!routable(a)) continue;
      const r = await bridgeOp(a.ins, "scope_summary", {});
      if (r.status !== 200 || !Array.isArray(r.body)) continue;
      for (const e of r.body as { agent?: unknown; admittedOps?: unknown }[]) if (typeof e.agent === "string" && Array.isArray(e.admittedOps)) admittedOps.set(`${a.ins}|${e.agent}`, new Set(e.admittedOps.map(String)));
    }
  };
  const ensureManifests = async () => {
    for (const a of (cfg?.apps ?? []) as (WorkspaceConfig["apps"][number] & { ownInfra?: boolean })[]) if (routable(a) && !manifests.has(a.ins)) await fetchManifest(a);
    if (adoptsAdmitted) await refreshAdmitted();
  };
  /** bridge op call (C16 B5) with THE binding rule (bridgeOpProofClaims, C91) */
  const bridgeOp = async (ins: string, bop: BridgeOp, body: Json): Promise<{ status: number; body: unknown }> => {
    const app = (cfg as WorkspaceConfig).apps.find((a) => a.ins === ins);
    const claims = bridgeOpProofClaims(bop, body);
    const proof = await signBridgeOpProof({ iss: brg, sub: brg, aud: `tb:ins:${ins}` as never, call: `call_${ulid()}` as never, ...claims, ...(flags.catalogWithIn && bop === "catalog" ? { in: digest(body) } : {}), iat: nowS() }, key);
    try {
      const r = await fetch(`${app?.internalUrl}/tb/v1/bridge/${BRIDGE_OP_PATH[bop]}`, { method: "POST", headers: { "content-type": "application/json", "TB-Call": proof }, body: JSON.stringify(body), signal: AbortSignal.timeout(5000) });
      return { status: r.status, body: await r.json().catch(() => null) };
    } catch {
      return { status: 0, body: null };
    }
  };
  /** list-mode dynamic ops: catalog entries per `<ins>/<op>`, read at every applied config (BRIDGE §7.2) */
  const listEntries = new Map<string, DynamicCatalogEntry[]>();
  async function refreshCatalogs(): Promise<void> {
    for (const a of cfg?.apps ?? []) {
      const m = manifests.get(a.ins);
      for (const o of m?.operations ?? []) {
        if (o.dynamic?.mode !== "list") continue;
        const r = await bridgeOp(a.ins, "catalog", { op: o.id });
        if (r.status === 200 && Array.isArray(r.body)) listEntries.set(`${a.ins}/${o.id}`, r.body as DynamicCatalogEntry[]);
      }
    }
  }
  const RANK: Record<string, number> = { read: 0, write: 1, outward: 2, destructive: 2, money: 3 };
  const inCeiling = (o: Operation, x: { crud: string[]; effect: string }) => {
    const d = o.dynamic;
    return !!d && x.crud.every((c) => (d.crudCeiling as string[]).includes(c)) && (RANK[x.effect] ?? 9) <= (RANK[d.effectCeiling] ?? 0);
  };

  /** the pre-C108 strict reader: any family outside this build's vocabulary invalidates the grant */
  const strictRefused = (jws: string) => {
    const held = (JSON.parse(Buffer.from(jws.split(".")[1] as string, "base64url").toString()) as { held?: unknown }).held;
    return Array.isArray(held) && held.some((f) => !(KNOWN_HOLD_FAMILIES as readonly unknown[]).includes(f));
  };
  const grantsOf = (agt: string) => {
    const c = cfg as WorkspaceConfig;
    return c.grants.map((g) => verifyGrant(g, { now: nowS(), self: `tb:ins:${JSON.parse(Buffer.from(g.split(".")[1] as string, "base64url").toString()).aud.slice(7)}` as never, ws: c.ws, bridge: enrol.bridgeId, issuers: keySetFromPortalKeys(trusted), bridgeKeys: { keys: [] }, revokedJtis: new Set(c.revoked.jtis.map((j) => j.jti)) })).flatMap((v, i) => (v.ok && v.claims.sub === `tb:agt:${agt}` && !(flags.strictHeld && strictRefused(c.grants[i] as string)) ? [{ jws: c.grants[i] as string, claims: v.claims }] : []));
  };
  const tools = (agt: string) => {
    const c = cfg as WorkspaceConfig;
    const out: { name: string; ins: string; op: string; inputSchema: unknown; kind?: "search" | "call" | "entry"; entry?: DynamicCatalogEntry }[] = [];
    if (!flags.skipPause && (c.pause.workspace || c.pause.agents.includes(agt as never))) return out;
    for (const g of grantsOf(agt)) {
      const ins = g.claims.aud.slice(7);
      const m = manifests.get(ins);
      const entry = c.apps.find((a) => a.ins === ins) as (WorkspaceConfig["apps"][number] & { ownInfra?: boolean }) | undefined;
      if (!m || !entry || !routable(entry)) continue;
      for (const o of withStandardOps(m)) {
        if (!o.standard && o.dynamic) {
          if (!o.crud.every((x) => g.claims.crud.includes(x)) || (g.claims.mode === "bound" && !g.claims.wf.includes(o.id))) continue;
          if (o.dynamic.mode === "search") {
            const d = dynamicToolNames(m.id, o.id);
            out.push({ name: d.search, ins, op: o.id, inputSchema: { type: "object" }, kind: "search" }, { name: d.call, ins, op: o.id, inputSchema: { type: "object" }, kind: "call" });
          } else
            for (const e of listEntries.get(`${ins}/${o.id}`) ?? [])
              if (inCeiling(o, e) && e.crud.every((x) => g.claims.crud.includes(x))) out.push({ name: mcpToolName(m.id, e.name), ins, op: o.id, inputSchema: e.inputSchema, kind: "entry", entry: e });
          continue;
        }
        if (o.standard || o.dynamic) continue;
        if (o.audience !== "agent" && !flags.listPerson) continue;
        const crudOk = o.crud.every((x) => g.claims.crud.includes(x));
        // spec 0.1.50: a scoped op above the grant is listed when the app's scope_summary names it in admittedOps for this agent
        const admitted = adoptsAdmitted && o.scopeType !== undefined && (admittedOps.get(`${ins}|${agt}`)?.has(o.id) ?? false);
        if ((!crudOk && !admitted) || (g.claims.mode === "bound" && !g.claims.wf.includes(o.id))) continue;
        out.push({ name: mcpToolName(m.id, o.id), ins, op: o.id, inputSchema: o.input });
      }
      out.push({ name: mcpToolName(m.id, "tb_hold_status"), ins, op: "tb.hold_status", inputSchema: { type: "object" } }, { name: mcpToolName(m.id, "tb_skills"), ins, op: "", inputSchema: { type: "object" } });
    }
    return out;
  };
  /** calls in flight (A2A-10): target instance, apps answering one of its hooks now, chain depth, finished */
  const calls = new Map<string, { target: string; inHook: Map<string, number>; depth: number; done: boolean }>();
  /** C85: per-caller-instance token bucket for app-initiated calls (burst 30, 120/min) */
  const buckets = new Map<string, { tokens: number; at: number }>();
  const take = (ins: string): number => {
    const now = Date.now();
    const b = buckets.get(ins) ?? { tokens: 30, at: now };
    b.tokens = Math.min(30, b.tokens + ((now - b.at) / 1000) * 2);
    b.at = now;
    buckets.set(ins, b);
    if (b.tokens >= 1) {
      b.tokens -= 1;
      return 0;
    }
    return Math.max(1, Math.ceil((1 - b.tokens) / 2));
  };
  const toolError = (code: string, details?: Record<string, unknown>) => {
    const error = { code, message: code, requestId: "req_mini", ...(details ? { details } : {}) };
    return { isError: true, content: [{ type: "text", text: JSON.stringify({ error }) }], structuredContent: { error } };
  };

  /** skipDownHookApp: the answer of a hook call whose app refused the connection */
  const DOWN = { status: -1, body: null } as const;
  /** one hook call (hook proof, BRIDGE §8.1 steps 6/7/12); null on transport failure or timeout */
  const hookCall = async (h: HookEntry, phase: "before" | "context" | "after", sub: string, callId: string, call: Record<string, Json>, context: Record<string, Json>, output?: Json): Promise<{ status: number; body: unknown } | null> => {
    const app = (cfg as WorkspaceConfig).apps.find((a) => a.ins === h.ins);
    if (!app) return null;
    // P1: a paused hook app gets no hook call; its hook fails closed
    if (!flags.skipPause && (cfg as WorkspaceConfig).pause.instances.includes(h.ins as never)) return null;
    const live = calls.get(callId);
    live?.inHook.set(h.ins, (live.inHook.get(h.ins) ?? 0) + 1);
    try {
      return await hookFetch(app.internalUrl, h, phase, sub, callId, call, context, output);
    } finally {
      const n = (live?.inHook.get(h.ins) ?? 1) - 1;
      if (n > 0) live?.inHook.set(h.ins, n);
      else live?.inHook.delete(h.ins);
    }
  };
  const hookFetch = async (internalUrl: string, h: HookEntry, phase: "before" | "context" | "after", sub: string, callId: string, call: Record<string, Json>, context: Record<string, Json>, output?: Json): Promise<{ status: number; body: unknown } | null> => {
    const proof = await signHookProof({ iss: brg, sub: sub as never, aud: `tb:ins:${h.ins}` as never, call: callId as never, hook: h.hookId, phase, ctx: digest(context), in: digest(call.input ?? null), iat: nowS() }, key);
    try {
      const r = await fetch(`${internalUrl}/tb/v1/hooks/${h.hookId}`, {
        method: "POST",
        headers: { "content-type": "application/json", "TB-Call": proof },
        body: JSON.stringify({ phase, call, context, ...(phase === "after" ? { output: output ?? null } : {}) }),
        signal: AbortSignal.timeout(h.timeoutMs + 200),
      });
      return { status: r.status, body: await r.json().catch(() => null) };
    } catch (e) {
      // skipDownHookApp: a refused connection (not a timeout) reads as "app down → skip the hook"
      if (flags.skipDownHookApp && !(e instanceof Error && e.name === "TimeoutError")) return DOWN;
      return null;
    }
  };
  /**
   * The call pipeline after gate(): before chain (refuse > hold > allow, first hold kept: reduceBeforeChain), context
   * hooks (namespace + reserved tb.), the op call with grant + op proof (hv when a hold is kept), after hooks.
   */
  const pipeline = async (o: { caller: { type: "agent" | "app" | "system"; id: string; mode?: string }; grant: string; grantJti: string; ins: string; m: Manifest; op: OperationView; input: Json; context: Record<string, Json>; idem?: string; hooks: boolean; depth?: number }): Promise<{ error: string } | { status: number; body: Record<string, unknown> }> => {
    const callId = `call_${ulid()}`;
    const live = { target: o.ins, inHook: new Map<string, number>(), depth: o.depth ?? 0, done: false };
    calls.set(callId, live);
    try {
      return await runPipeline(o, callId);
    } finally {
      live.done = true;
      if (!flags.parentKeepsFinished) calls.delete(callId);
    }
  };
  const runPipeline = async (o: Parameters<typeof pipeline>[0], callId: string): Promise<{ error: string } | { status: number; body: Record<string, unknown> }> => {
    const c = cfg as WorkspaceConfig;
    const sub = `tb:${o.caller.type === "agent" ? "agt" : "ins"}:${o.caller.id}`;
    const op = o.op;
    const call: Record<string, Json> = { id: callId, ws: c.ws, caller: o.caller as unknown as Json, target: { instance: o.ins, product: o.m.id, op: op.id, crud: op.crud, effect: op.effect }, input: o.input };
    const matches = (h: { match: HookEntry["match"] }) => (h.match.products.includes("*") || h.match.products.includes(o.m.id)) && (!h.match.operations || h.match.operations.includes(op.id)) && (!h.match.effects || h.match.effects.includes(op.effect));
    // C117: config hooks[] is the owner switch (enabled: false → skipped); the chain itself is the declared hooks
    const matching = (phase: string) =>
      (o.hooks ? (c.hooks ?? []) : [])
        .filter((h) => (flags.ignoreHookEnabled || h.enabled !== false) && h.phase === phase && matches(h))
        .sort((a, b) => a.order - b.order || (a.product < b.product ? -1 : a.product > b.product ? 1 : 0));
    // C117 (BRIDGE v0.1.24): a matching hook DECLARED in the manifest of a deployed app but absent from config hooks[]
    // refuses the call (fail closed; never forwarded without it)
    if (o.hooks && !flags.trustConfigHooks)
      for (const a of c.apps) {
        const dm = manifests.get(a.ins);
        for (const h of dm?.hooks ?? [])
          if (matches(h) && !(c.hooks ?? []).some((e) => e.ins === a.ins && e.hookId === h.id)) {
            // v0.1.25 (bridge 0.1.22): reported as rejected {kind: config, code: hook_not_listed, ins: the hook app}
            if (!flags.noHookNotListedReport) reject("hook_not_listed", "config", a.ins);
            return { error: "hook_failed" };
          }
      }
    let context = { ...o.context };
    const cacheKey = `${sub}|${op.id}|${digest(o.input)}`;
    let hv: HoldVerdictClaim | undefined = flags.cacheHoldVerdict ? verdictCache.get(cacheKey) : undefined;
    if (!hv) {
      const answers: { by: string; answer: { allow: boolean; reason?: string; hold?: never } }[] = [];
      for (const h of matching("before")) {
        const r = await hookCall(h, "before", sub, callId, call, context);
        if (r === DOWN) continue;
        if (r?.status !== 200 || hookResponseProblem("before", r.body, h.product)) return { error: "hook_failed" };
        const answer = r.body as { allow: boolean; reason?: string; hold?: never };
        if (flags.holdAsHookFailed && answer.hold) return { error: "hook_failed" };
        answers.push({ by: `${h.product}/${h.hookId}`, answer });
        if (!answer.allow && !answer.hold) break;
        if (flags.holdStopsChain && answer.hold) break;
      }
      const red = reduceBeforeChain(answers);
      if (red.kind === "refuse") return { error: "hook_denied" };
      if (red.kind === "hold") {
        hv = holdVerdictClaim(red) as HoldVerdictClaim;
        verdictCache.set(cacheKey, hv);
      }
    }
    for (const h of matching("context")) {
      const r = await hookCall(h, "context", sub, callId, call, context);
      if (r === DOWN) continue;
      if (r?.status !== 200 || !isObj(r.body) || !isObj(r.body.add)) return { error: "hook_failed" };
      const add = r.body.add as Record<string, Json>;
      const checked = flags.allowTbContext ? { add: Object.fromEntries(Object.entries(add).filter(([k]) => !k.startsWith("tb."))) } : r.body;
      if (hookResponseProblem("context", checked, h.product)) return { error: "hook_failed" };
      context = { ...context, ...add };
    }
    const app = c.apps.find((a) => a.ins === o.ins);
    const proof = await signCallProof({ iss: brg, sub: sub as never, aud: `tb:ins:${o.ins}` as never, call: callId as never, gjti: o.grantJti, op: op.id, in: digest(o.input), ctx: digest(context), iat: nowS(), ...(hv && !flags.hvOutsideProof ? { hv } : {}) }, key);
    const r = await fetch(`${app?.internalUrl}/tb/v1/ops/${op.id}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${o.grant}`, ...(flags.noProof ? {} : { "TB-Call": proof }), ...(hv && flags.hvOutsideProof ? { "TB-Hold-Verdict": JSON.stringify(hv) } : {}) },
      body: JSON.stringify({ input: o.input, context, ...(o.idem ? { idempotencyKey: o.idem } : {}) }),
    });
    let body = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (r.status === 200) {
      for (const h of matching("after")) {
        const a = await hookCall(h, "after", sub, callId, call, context, (body.output ?? null) as Json);
        if (a === DOWN) continue;
        if (a?.status !== 200 || hookResponseProblem("after", a.body, h.product)) {
          // the op ran: its receipt is marked after_failed (bridge op mark, BRIDGE §8.1 step 12)
          await bridgeOp(o.ins, "mark", { call: callId, mark: "after_failed" });
          return { error: "after_failed" };
        }
        if (isObj(a.body) && "output" in a.body) body = { ...body, output: a.body.output };
      }
    }
    return { status: r.status, body };
  };

  const callTool = async (agt: string, name: string, args: Json, idem?: string, meta?: Record<string, unknown>, session = ""): Promise<unknown> => {
    const c = cfg as WorkspaceConfig;
    const t = tools(agt).find((x) => x.name === name);
    if (!t) return toolError(flags.skipPause ? "unknown_tool" : c.pause.workspace || c.pause.agents.includes(agt as never) ? "paused" : "unknown_tool");
    const m = manifests.get(t.ins) as Manifest;
    const declared = withStandardOps(m).find((o) => o.id === t.op);
    const g = grantsOf(agt).find((x) => x.claims.aud === `tb:ins:${t.ins}`);
    if (!declared || !g) return toolError("no_grant");
    if (!t.kind && !declared.standard && !validateInput(declared, args).ok) return toolError("input_invalid");
    if (!t.kind && !declared.standard && declared.idempotency !== "none" && !idem) {
      // C98 / C98a: derive the key (shared rule) for required AND supported ops instead of refusing model-driven
      // clients that cannot set _meta; `noDerivedKey` = the pre-C98 bridge (required refused, supported keyless)
      if (flags.noDerivedKey) {
        if (declared.idempotency === "required") return toolError("input_invalid");
      } else if (declared.idempotency === "required" || !flags.deriveRequiredOnly) idem = deriveIdempotencyKey({ connection: agt, session, op: declared.id, input: args, now: Date.now() });
    }
    // dynamic ops (BRIDGE §7.2 / §8): _search answers from the catalog bridge op; _call resolves first; a list entry
    // carries its catalog crud / effect; gate() runs on the effective op
    let op = declared;
    if (t.kind === "search") {
      const q = isObj(args) ? args : {};
      const r = await bridgeOp(t.ins, "catalog", { op: t.op, query: String(q.query ?? ""), ...(typeof q.limit === "number" ? { limit: q.limit } : {}) });
      if (r.status !== 200 || !Array.isArray(r.body)) return toolError((isObj(r.body) && isObj(r.body.error) ? String(r.body.error.code) : null) ?? "app_unavailable");
      return { content: [{ type: "text", text: JSON.stringify(r.body) }], structuredContent: { entries: r.body } };
    }
    if (t.kind === "call" || t.kind === "entry") {
      const a = isObj(args) ? args : {};
      const tool = t.kind === "entry" ? (t.entry as DynamicCatalogEntry).name : String(a.tool ?? "");
      let eff: { crud: string[]; effect: string } | null = t.kind === "entry" ? (t.entry as DynamicCatalogEntry) : null;
      if (t.kind === "call") {
        const r = await bridgeOp(t.ins, "resolve", { op: t.op, tool });
        eff = r.status === 200 && isObj(r.body) && Array.isArray(r.body.crud) ? (r.body as { crud: string[]; effect: string }) : null;
        if (!eff) return toolError("unknown_tool");
        // C107 (spec 0.1.16): an outward / money resolution must name its hold family (money → money)
        const hf = (r.body as { holdFamily?: unknown }).holdFamily;
        const famOk = eff.effect === "money" ? hf === "money" : eff.effect !== "outward" || (typeof hf === "string" && (KNOWN_HOLD_FAMILIES as readonly string[]).includes(hf));
        if (!famOk && !flags.resolveNoFamilyCheck) return toolError("dynamic_resolve_failed", { reason: "family_missing" });
      }
      if (!inCeiling(declared as Operation, eff as { crud: string[]; effect: string })) return toolError("dynamic_ceiling_exceeded");
      op = { ...declared, crud: (eff as { crud: string[] }).crud, effect: (eff as { effect: string }).effect } as OperationView;
      args = { tool, arguments: (t.kind === "entry" ? args : (a.arguments ?? {})) as Json };
    }
    const trust = { now: nowS(), self: `tb:ins:${t.ins}` as never, ws: c.ws, bridge: enrol.bridgeId, issuers: keySetFromPortalKeys(trusted), bridgeKeys: { keys: [] }, revokedJtis: new Set(c.revoked.jtis.map((j) => j.jti)) };
    const paused = flags.skipPause ? { workspace: false, agent: false, connection: false, instance: false } : { workspace: c.pause.workspace, agent: c.pause.agents.includes(agt as never), connection: false, instance: c.pause.instances.includes(t.ins as never) };
    const d = gate({ paused, grant: g.jws, trust, op, declaredScopeTypes: (m.scopes ?? []).map((x) => x.type) });
    if (flags.oldGateCrud && d.decision === "pass" && !op.standard && op.scopeType !== undefined && !op.crud.every((x) => g.claims.crud.includes(x))) return toolError("crud_exceeds_grant");
    const preC111a = flags.wfOnlyBound && d.decision === "refuse" && d.reason === "not_in_workflow" && g.claims.mode !== "bound";
    if (d.decision === "refuse" && !preC111a) return toolError(d.reason);
    const context: Record<string, Json> = {};
    // BRIDGE §8.5: the claim lands in tb.onBehalfOf before the hooks; an invalid one is dropped and reported
    if (meta && ON_BEHALF_OF in meta && !flags.noOnBehalfOf) {
      const obo = onBehalfOfFromMeta(meta[ON_BEHALF_OF]);
      if (obo) context["tb.onBehalfOf"] = obo as unknown as Json;
      else reject("on_behalf_of_invalid", "claim");
    }
    const fwd = await pipeline({ caller: { type: "agent", id: agt, mode: g.claims.mode, ...(flags.hookCallerProductForAgents ? { product: [...manifests.values()][0]?.id } : {}) } as never, grant: g.jws, grantJti: g.claims.jti, ins: t.ins, m, op, input: args, context, ...(idem ? { idem } : {}), hooks: true });
    if ("error" in fwd) return toolError(fwd.error);
    const r = fwd;
    const body = r.body;
    if (flags.leakToPortal) await ack({ lastCall: { name, input: args, output: body } });
    if (r.status === 200) return { content: [{ type: "text", text: JSON.stringify(body.output) }], structuredContent: body.output };
    if (r.status === 202) return { content: [{ type: "text", text: "held" }], structuredContent: { status: "held", holdId: body.holdId, expiresAt: body.expiresAt, checkWith: mcpToolName(m.id, "tb_hold_status") } };
    const code = (body.error as { code?: string } | undefined)?.code ?? "app_error";
    return toolError(code);
  };

  // ── spec 0.1.57 (BRIDGE §14): the per-agent event log (reference implementation, conformance src/event-log.ts) ──
  const peekClaims = (jws: string): Record<string, unknown> => {
    try {
      return JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString()) as Record<string, unknown>;
    } catch {
      return {};
    }
  };
  const evLog = new EventLog(
    {
      manifest: (ins) => (cfg?.apps.some((a) => a.ins === ins) ? (manifests.get(ins) ?? null) : null),
      grantees: (ins) => [...new Set((cfg?.grants ?? []).map(peekClaims).filter((g) => g.aud === `tb:ins:${ins}` && String(g.sub).startsWith("tb:agt:")).map((g) => String(g.sub).slice(7) as AgentId))],
      claims: (agent, ins) => grantsOf(agent).find((g) => g.claims.aud === `tb:ins:${ins}`)?.claims ?? null,
      agentPaused: (agent) => !!cfg && (cfg.pause.workspace || cfg.pause.agents.includes(agent as never)),
      instancePaused: (ins) => !!cfg && cfg.pause.instances.includes(ins as never),
      hookMatches: (ins, opId) => {
        const m = manifests.get(ins);
        const op = m ? withStandardOps(m).find((o) => o.id === opId) : undefined;
        if (!m || !op) return false;
        return (cfg?.hooks ?? []).some((h) => h.enabled !== false && (h.phase === "before" || h.phase === "after") && (h.match.products.includes("*") || h.match.products.includes(m.id)) && (!h.match.operations || h.match.operations.includes(op.id)) && (!h.match.effects || h.match.effects.includes(op.effect)));
      },
    },
    flags.eventFaults ?? {},
  );

  const authAgent = (req: IncomingMessage): string | null => {
    const bearer = /^Bearer (\S+)$/.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const c = cfg;
    if (!c) return null;
    if (flags.acceptPerson && (bearer.startsWith("tbo_") || bearer.split(".").length === 3) && !bearer.startsWith("eyJhbGciOiJFZERTQSI")) return c.connections[0]?.agt ?? null;
    const v = verifyAgentSession(bearer, { now: nowS(), self: brg, ws: c.ws, keys: keySetFrom({ keys: [key.publicJwk] }, brg) });
    if (!v.ok) return null;
    const con = c.connections.find((x) => x.con === v.claims.con && x.status === "active" && x.gen === v.claims.gen && `tb:agt:${x.agt}` === v.claims.sub);
    return con ? con.agt : null;
  };

  const publicServer = createServer((req, res) => {
    handlePublic(req, res).catch((e: unknown) => send(res, 500, { error: { code: "internal", message: String(e), requestId: "req_mini" } }));
  });
  const keyPage = (req: IncomingMessage, res: ServerResponse, raw: Buffer) => {
    const html = (status: number, body: string, extra: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...(flags.noKeysCsp ? {} : { "content-security-policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'" }), ...extra });
      res.end(body);
    };
    const page = () => `<!doctype html><form method="post" action="/keys"><input type="hidden" name="csrf" value="${randomUUID()}"><label>MINI_KEY <input name="MINI_KEY"></label></form>`;
    const sid = /(?:^|;\s*)tb_keys=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    if (sid && keySessions.has(sid)) return html(200, page());
    const ticket = req.method === "POST" ? new URLSearchParams(raw.toString()).get("ticket") : null;
    if (!ticket) return send(res, 401, { error: { code: "unauthenticated", message: "keys ticket required", requestId: "req_mini" } });
    const v = verifyKeysTicket(ticket, { now: nowS(), self: brg, ws: enrol.workspaceId, issuers: keySetFromPortalKeys(trusted) });
    if (!v.ok || usedJtis.has(v.claims.jti)) return send(res, 400, { error: { code: "ticket_invalid", message: "keys ticket refused", requestId: "req_mini" } });
    usedJtis.add(v.claims.jti);
    const id = randomUUID();
    keySessions.add(id);
    return html(200, page(), { "set-cookie": `tb_keys=${id}; HttpOnly; Secure; SameSite=Strict; Path=/keys` });
  };
  const handlePublic = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const raw = await read(req);
    if (path === "/healthz" || path === "/readyz") return send(res, 200, { status: "ok" });
    const onKeys = keysHost !== null && (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase() === keysHost;
    if (onKeys && path === "/keys") return keyPage(req, res, raw);
    if (onKeys && !flags.keysOriginOpen) return send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
    if (path === "/keys") {
      if (!keysHost && !flags.noUnset503) {
        res.writeHead(503, { "content-type": "text/plain; charset=utf-8" });
        return void res.end("key page not configured");
      }
      if (flags.keysOnMain) return keyPage(req, res, raw);
      return send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
    }
    if (path === "/oauth/token" && req.method === "POST") {
      const f = new URLSearchParams(raw.toString());
      const a = f.get("assertion") ?? "";
      const claims = (() => {
        try {
          return JSON.parse(Buffer.from(a.split(".")[1] ?? "", "base64url").toString()) as { con?: string };
        } catch {
          return {};
        }
      })();
      const con = cfg?.connections.find((x) => x.con === claims.con && x.status === "active" && x.publicKey);
      const v = con?.publicKey ? verifyAssertion(a, keySetFrom({ keys: [con.publicKey] }, `tb:agt:${con.agt}`), { typ: "tb-agent-assert+jwt", aud: brg, now: nowS() }) : null;
      if (f.get("grant_type") === "refresh_token") return send(res, 400, { error: "invalid_grant" });
      if (f.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") return send(res, 400, { error: "unsupported_grant_type" });
      if (!con || !v?.ok) return send(res, 400, { error: "invalid_grant", error_description: "connection_unknown" });
      const token = await signAgentSession({ iss: brg, sub: `tb:agt:${con.agt}`, aud: brg, ws: (cfg as WorkspaceConfig).ws, con: con.con, gen: con.gen, iat: nowS() }, key);
      return send(res, 200, { access_token: token, token_type: "Bearer", expires_in: 900 });
    }
    if (path === "/mcp") {
      const agt = authAgent(req);
      if (!agt) return send(res, 401, { error: { code: "unauthenticated", message: "agent session required", requestId: "req_mini" } }, { "www-authenticate": `Bearer resource_metadata="${pub}/.well-known/oauth-protected-resource"` });
      if (req.method === "GET" && flags.events) {
        // BRIDGE §14.3: the session's SSE stream carries notifications/tealbrick/event frames (SSE id = event.id)
        res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
        const frame = (e: { id: string }) => res.write(`id: ${e.id}\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/tealbrick/event", params: { event: e } })}\n\n`);
        const off = evLog.subscribe(agt as AgentId, frame);
        req.once("close", off);
        return;
      }
      if (req.method !== "POST") return send(res, 405, {});
      const msg = JSON.parse(raw.toString() || "{}") as { id?: unknown; method?: string; params?: Record<string, unknown> };
      if (msg.id === undefined) return void res.writeHead(202).end();
      const c = cfg as WorkspaceConfig;
      let result: unknown = {};
      if (msg.method === "initialize") {
        const paused = c.pause.workspace || c.pause.agents.includes(agt as never);
        return send(res, 200, { jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "mini", version: "0.0.0" }, instructions: paused ? "paused by the owner" : "" } }, { "mcp-session-id": randomUUID() });
      }
      if (msg.method === "tools/list" || msg.method === "tools/call") await ensureManifests();
      if (flags.events && typeof msg.method === "string" && msg.method.startsWith("tealbrick/events/")) {
        await ensureManifests();
        const r = evLog.rpc(agt as AgentId, c.apps.map((a) => a.ins), msg.method, msg.params);
        if (r) return send(res, 200, { jsonrpc: "2.0", id: msg.id, ...r });
      }
      // BRIDGE §14.3: a bridge without the cap answers the events methods with -32601 (method not found)
      if (!flags.events && !flags.eventsMethodsAnswerEmpty && typeof msg.method === "string" && msg.method.startsWith("tealbrick/events/"))
        return send(res, 200, { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
      if (msg.method === "tools/list") result = { tools: tools(agt).map((t) => ({ name: t.name, inputSchema: t.inputSchema })) };
      if (msg.method === "tools/call") {
        const meta = msg.params?._meta as Record<string, unknown> | undefined;
        result = await callTool(agt, String(msg.params?.name), (msg.params?.arguments ?? {}) as Json, typeof meta?.["tealbrick/idempotencyKey"] === "string" ? (meta["tealbrick/idempotencyKey"] as string) : undefined, meta, String(req.headers["mcp-session-id"] ?? ""));
      }
      return send(res, 200, { jsonrpc: "2.0", id: msg.id, result });
    }
    send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
  };
  /** the asserting instance (TB-Assert verified against config instanceKeys), else null */
  const instanceOf = (req: IncomingMessage, raw: Buffer): string | null => {
    const token = String(req.headers["tb-assert"] ?? "");
    const ins = String(peekJwt(token).iss ?? "").replace(/^tb:ins:/, "");
    const ik = (cfg?.instanceKeys ?? []).find((k) => k.ins === ins);
    const v = ik ? verifyAssertion(token, keySetFrom({ keys: [ik.jwk] }, `tb:ins:${ins}` as never), { typ: TYP.instanceAssertion, aud: brg, now: nowS(), method: req.method ?? "POST", pathAndQuery: req.url ?? "/", ...(raw.length ? { body: new Uint8Array(raw) } : {}) } as never) : null;
    return v?.ok ? ins : null;
  };
  const internalServer = createServer(async (req, res) => {
    const raw = await read(req);
    const path = new URL(req.url ?? "/", "http://x").pathname;
    // status push + slice long-poll (BRIDGE §10.3): the instance's slice once Core bound its key
    if (path === "/tb/v1/status" && req.method === "POST") {
      const ins = instanceOf(req, raw);
      if (!ins) return send(res, 401, { error: { code: "unauthenticated", message: "instance assertion refused", requestId: "req_mini" } });
      const pushed = (JSON.parse(raw.toString() || "{}") as { sliceRevision?: number }).sliceRevision;
      const wait = Math.min(10, Number(new URL(req.url ?? "/", "http://x").searchParams.get("wait") ?? 0) || 0);
      const end = Date.now() + wait * 1000;
      for (;;) {
        const a = cfg?.apps.find((x) => x.ins === ins);
        const rev = a ? Number(peekJwt(a.slice).rev) : 0;
        if (a && rev !== pushed) return send(res, 200, { slice: a.slice, sliceRevision: rev, keysRev: 0 });
        if (Date.now() >= end || stopped || res.destroyed) return void res.writeHead(204).end();
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    if (path === "/tb/v1/claim" && req.method === "POST") {
      const b = JSON.parse(raw.toString() || "{}") as { code?: string; internalUrl?: string; instancePublicKey?: Ed25519PublicJwk; manifestDigest?: string; version?: string };
      const d = opaqueDigest(String(b.code ?? ""));
      // instance claim (K6): one-time code of the config, reported (digest only) in the next status report
      const inst = cfg?.enrolCodes.find((e) => e.digest === d && e.kind === "instance");
      if (inst && !usedCodes.has(d) && b.instancePublicKey) {
        usedCodes.add(d);
        claimsSeen.push({ kind: "instance", ins: inst.ins, publicKey: b.instancePublicKey, manifestDigest: b.manifestDigest as never, version: String(b.version ?? "0.0.0") as never, codeDigest: d, claimedAt: new Date().toISOString() as never });
        void ack();
        const app = cfg?.apps.find((a) => a.ins === inst.ins);
        const bound = cfg?.instanceKeys.some((k) => k.ins === inst.ins);
        return send(res, 200, { ins: inst.ins, bridge: { id: enrol.bridgeId, publicKey: key.publicJwk, internalUrl: `http://127.0.0.1:${env.TB_INTERNAL_PORT}` }, ...(app && bound ? { slice: app.slice } : {}) });
      }
      // neighbour claims (BSD-07 address rule); service claims are not implemented by this minimal bridge
      const entry = cfg?.enrolCodes.find((e) => e.digest === d && e.kind === "neighbour");
      if (!entry) return send(res, 400, { error: { code: "code_invalid", message: "code_invalid", requestId: "req_mini" } });
      if (!flags.noAddressCheck && !isPrivateInternalUrl(String(b.internalUrl ?? ""), { ownInfra: true, allowList }))
        return send(res, 403, { error: { code: "internal_url_refused", message: "internal_url_refused", requestId: "req_mini" } });
      if (flags.noAddressCheck && b.internalUrl) await fetch(`${b.internalUrl}/tb/v1/manifest`).catch(() => undefined);
      return send(res, 503, { error: { code: "app_unavailable", message: "not implemented", requestId: "req_mini" } });
    }
    // companion path (BRIDGE §8.3; v0.1.13 C85: app-initiated calls without parentCall take the same pipeline)
    if (path === "/tb/v1/call" && req.method === "POST") {
      const c = cfg;
      const err = (status: number, code: string) => send(res, status, { error: { code, message: code, requestId: "req_mini" } });
      if (!c) return err(503, "config_expired");
      const ins = instanceOf(req, raw);
      if (!ins) return err(401, "unauthenticated");
      const env = JSON.parse(raw.toString() || "{}") as { target?: string; op?: string; input?: Json; idempotencyKey?: string; parentCall?: string };
      const grant = String(req.headers["tb-grant"] ?? "");
      if (!grant || peekJwt(grant).sub !== `tb:ins:${ins}`) return err(403, "grant_invalid");
      const target = c.apps.find((a) => a.product === env.target);
      const m = target ? manifests.get(target.ins) : undefined;
      const op = m ? withStandardOps(m).find((o) => o.id === env.op) : undefined;
      if (!target || !m || !op) return err(404, "unknown_tool");
      const trust = { now: nowS(), self: `tb:ins:${target.ins}` as never, ws: c.ws, bridge: enrol.bridgeId, issuers: keySetFromPortalKeys(trusted), bridgeKeys: { keys: [] }, revokedJtis: new Set(c.revoked.jtis.map((j) => j.jti)) };
      const paused = { workspace: c.pause.workspace, agent: false, connection: false, instance: c.pause.instances.includes(ins as never) || c.pause.instances.includes(target.ins) };
      const g = verifyGrant(grant, trust);
      if (!g.ok) return err(403, g.code);
      if (!flags.companionNoWfCheck) {
        const d = gate({ paused, grant, trust, op, declaredScopeTypes: (m.scopes ?? []).map((x) => x.type) });
        if (d.decision === "refuse") return err(403, d.reason);
      }
      // A2A-10: a parentCall counts only while that call is in flight FOR this caller (its target, or the caller answers
      // one of its hooks now); anything else (forged, foreign, finished) is ignored → app-initiated (C85)
      const parent = typeof env.parentCall === "string" ? calls.get(env.parentCall) : undefined;
      const valid = !!parent && (flags.parentKeepsFinished || !parent.done) && (flags.parentAnyInstance || parent.target === ins || parent.inHook.has(ins));
      let depth = 1;
      if (valid && parent) {
        if (parent.inHook.size > 0) return err(409, "hook_reentry");
        depth = parent.depth + 1;
        if (depth > 3) return err(409, "call_depth_exceeded");
      } else if (!(flags.parentTrusted && typeof env.parentCall === "string")) {
        const wait = flags.noAppRateLimit ? 0 : take(ins);
        if (wait > 0) return send(res, 429, { error: { code: "rate_limited", message: "rate_limited", requestId: "req_mini" } }, { "retry-after": String(wait) });
        if (!flags.noAppInitiatedAudit) logLines.push(JSON.stringify({ ts: new Date().toISOString(), level: "info", evt: "call.app_initiated", ins, product: target.product, op: op.id, parentCall: null }));
      }
      const appInitiated = !valid && !(flags.parentTrusted && typeof env.parentCall === "string");
      // spec 0.1.45 (HOOK-CALLER-PRODUCT, bridge 0.2.2): an app caller's product from the signed config's instance table
      // (here: the deployed app's manifest), never from the input; the faults omit it or read it from the input
      const asApp = !(appInitiated && flags.appInitiatedAsSystem);
      const inputProduct = isObj(env.input) && typeof env.input.product === "string" ? env.input.product : undefined;
      const product = !asApp || flags.noHookCallerProduct ? undefined : flags.hookCallerProductFromInput ? inputProduct : manifests.get(ins)?.id;
      const caller = { type: asApp ? ("app" as const) : ("system" as const), id: ins, ...(product !== undefined ? { product } : {}) };
      const fwd = await pipeline({ caller, grant, grantJti: g.claims.jti, ins: target.ins, m, op, input: (env.input ?? null) as Json, context: {}, ...(env.idempotencyKey ? { idem: env.idempotencyKey } : {}), hooks: !flags.appCallsSkipHooks, depth });
      if ("error" in fwd) return err(fwd.error === "hook_denied" ? 403 : 502, fwd.error);
      return send(res, fwd.status, fwd.body);
    }
    // spec 0.1.57 (BRIDGE §14.1): app event ingest, instance assertion of a deployed app
    if (path === "/tb/v1/events" && req.method === "POST" && flags.events) {
      const ins = instanceOf(req, raw);
      if (!ins) return send(res, 401, { error: { code: "unauthenticated", message: "instance assertion refused", requestId: "req_mini" } });
      const app = cfg?.apps.find((a) => a.ins === ins);
      if (!app) return send(res, 503, { error: { code: "app_not_claimed", message: "app_not_claimed", requestId: "req_mini" } });
      await ensureManifests();
      if (flags.slowEventsMs) await new Promise((r) => setTimeout(r, flags.slowEventsMs));
      const items = (JSON.parse(raw.toString() || "{}") as { items?: unknown }).items;
      if (!Array.isArray(items) || items.length < 1 || items.length > 100) return send(res, 400, { error: { code: "input_invalid", message: "items 1..100", requestId: "req_mini" } });
      return send(res, 200, evLog.ingest(ins as never, app.product, items));
    }
    // key fetch is not implemented by this minimal bridge: every caller is unauthenticated
    if (path.startsWith("/tb/v1/keys/")) return send(res, 401, { error: { code: "unauthenticated", message: "instance assertion required", requestId: "req_mini" } });
    send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
  });
  await listen(publicServer, Number(env.PORT));
  await listen(internalServer, Number(env.TB_INTERNAL_PORT));
  return {
    publicUrl: `http://127.0.0.1:${env.PORT}`,
    internalUrl: `http://127.0.0.1:${env.TB_INTERNAL_PORT}`,
    stop: async () => {
      stopped = true;
      publicServer.closeAllConnections();
      internalServer.closeAllConnections();
      await Promise.all([new Promise((r) => publicServer.close(r)), new Promise((r) => internalServer.close(r))]);
    },
  };
}
