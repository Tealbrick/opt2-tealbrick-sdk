// A tiny app built ONLY on node:http + @opt2-tealbrick/manifest: a minimal correct implementation of the app side of
// the call path (claim, slice long-poll, call proof + grant re-verification, authorize(), holds/receipts, idempotency,
// person launch/session/CSRF, hooks, bridge ops, export, backup/restore). Each `faults` switch breaks exactly one rule
// so the suite's sensitivity can be proven: the faulty variant MUST fail the matching checks.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import {
  authorize,
  bridgeOpBinding,
  digest,
  type Ed25519KeyPair,
  exportPrivateKey,
  generateKeyPair,
  hookCallerRef,
  importKeyPair,
  KNOWN_HOLD_FAMILIES,
  kekFromEnv,
  keySetFrom,
  keySetFromPortalKeys,
  manifestDigest,
  memoryReplayGuard,
  portalRootKeys,
  seal,
  sealAad,
  sha256Bytes,
  signInstanceAssertion,
  tagsMatch,
  trustedPortalKeys,
  unseal,
  validateInput,
  verifyBridgeOpProof,
  verifyCallProof,
  verifyGrant,
  verifyHookProof,
  verifySlice,
  verifyTicket,
  withStandardOps,
} from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId, SealedBlob, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Effect, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView, TrustContext } from "@opt2-tealbrick/spec/sdk";
import { applyLevelCrud, LEVEL_CRUD_ENV, parseLevelCrud } from "../../src/level-crud.ts";
import { readTar } from "../../src/tar.ts";
import { writeTarGz } from "./tar-write.ts";

export interface MiniAppFaults {
  skipProofVerify?: boolean;
  skipGrantVerify?: boolean;
  ignorePause?: boolean;
  /** QA-SPEC49-25 (P4): an app that decides "agent paused" from `slice.pause.agents` only, never from `agents[].status` */
  pauseAgentsListOnly?: boolean;
  /** RM-17 (A23): a required model role the bridge cannot serve (404, no route) is taken as resolved: a guess */
  modelRoleGuess?: boolean;
  ticketReusable?: boolean;
  noIdempotencyConflict?: boolean;
  servesClaimRoute?: boolean;
  standingApproval?: boolean;
  noCsrf?: boolean;
  storesRawInput?: boolean;
  ignorePersonNbf?: boolean;
  newKeyOnRestart?: boolean;
  noProofReplayGuard?: boolean;
  /** companion call: no slice re-read + retry on grant_stale (SDK-API §9) */
  noCompanionRetry?: boolean;
  /** before hook answers an extra key (phase shape, BRIDGE §8.2) */
  badHookShape?: boolean;
  /** ignores portalKeySet: keeps the pre-v0.1.11 rule (portalKeys replace the trusted set; CREDENTIALS §9.5) */
  ignoreKeySet?: boolean;
  /** keeps a refused identity even when TB_ENROL_CODE changed (fails A1.reclaim_on_new_code, SDK-API §13 v0.1.12) */
  noReclaim?: boolean;
  /** v0.1.13: ignores the proof's hook hold verdict `hv` (fails A14.hook_hold) */
  ignoreHoldVerdict?: boolean;
  /** v0.1.13: an approval never satisfies a hook verdict (fails A14.hold_retry_once) */
  hvIgnoresApproval?: boolean;
  /** v0.1.13: holds on a verdict before the scope checks (fails A14.scope_wins) */
  hvBeforeScope?: boolean;
  /** v0.1.13: tb.holds_pending shows an agent every hold (fails A15.holds_pending) */
  holdsPendingAll?: boolean;
  /** v0.1.13: its app-initiated companion call presents no TB-Grant (fails A16.call_outside_handler) */
  appInitiatedNoGrant?: boolean;
  /** v0.1.13: no status push when a hold changes (fails A17.status_changed) */
  noStatusChanged?: boolean;
  /** v0.1.13: status pendingHolds always 0 (fails A17.pending_count) */
  pendingHoldsZero?: boolean;
  /** v0.1.14 (C102): names app callers by their instance id, ignoring slice companionCallers (fails A12.caller_name) */
  callerNameIgnoresSlice?: boolean;
  /** spec 0.1.44 (SDK-CALLER-PRODUCT, security): looks the caller's product up by its NAME (first companionCallers entry with that name) instead of by its instance (fails A12.caller_product_verified) */
  callerProductFromName?: boolean;
  /** pre-0.1.44: never sets caller.product (fails A12.caller_product_verified) */
  noCallerProduct?: boolean;
  /** the SDK release the app reports in its claim (default `<sdkMajor>.0.0`); below 0.1.28 the GRANT-PRD checks are not_applicable */
  reportedSdkVersion?: string;
  /** pre-0.1.46 (GRANT-PRD): ignores the grant's `prd`, takes the product from the slice only (fails A12.grant_prd_first: a caller not yet in the slice has no product) */
  callerProductIgnoresPrd?: boolean;
  /** spec 0.1.46 (GRANT-PRD, security): prefers the slice entry over the grant's `prd` and never refuses a disagreement (fails A12.grant_prd_mismatch) */
  callerProductPrefersSlice?: boolean;
  /** spec 0.1.46 (GRANT-PRD): picks the grant's `prd` over a disagreeing slice entry instead of refusing the call (fails A12.grant_prd_mismatch) */
  callerProductMismatchPicksGrant?: boolean;
  /** v0.1.15 (C105a): never holds an app caller (ignores the companion grant's held; fails A12.app_caller_held) */
  appCallerNoHold?: boolean;
  /** v0.1.16 (C107): resolve answers drop holdFamily (outward / money entries; fails A11.resolve_family) */
  resolveNoFamily?: boolean;
  /** pre-C108 strict reader: a grant whose held names an unknown family is refused grant_invalid (fails C3.grant_held_unknown) */
  strictHeld?: boolean;
  /** pre-C111a: caps ignored when a Free grant carries a non-empty wf (fails A3.free_wf_caps) */
  capsIgnoredWithWf?: boolean;
  /** v0.1.18 (SDK-02): never counts usage (only `max: 0` holds; fails A3.caps_count) */
  capsUncounted?: boolean;
  /** v0.1.18 (SDK-02, miniapp-sdk ≤ 0.1.21): counts only runs that write a receipt (fails A3.caps_count on a receipt:false op) */
  capsCountReceiptsOnly?: boolean;
  /**
   * v0.1.18 (Knowledge-like, NOT a fault): keys app-caller data by caller. An app caller's `area_create` creates an area
   * of its own (output {id}); any other op by an app caller must name one of ITS areas in the scope field, else
   * 403 area_required (area-less app callers are refused; the owner's tb.scopes_set does not help). Needs an
   * `area_create` op in the manifest; A12.caller_name passes only with a setup step + inputsAs.app fixture.
   */
  areaPerAppCaller?: boolean;
  /**
   * package 0.1.21 (Connect-like, NOT a fault): an AGENT's `post_create` makes a post that agent owns (output {id}); a
   * `post_cancel` {id} of a post the caller does not own answers 404 post_not_found (so A3.caps_count's capped op needs
   * data the fresh caps agent owns: setup `as: "capsAgent"`). Needs `post_create` / `post_cancel` ops in the manifest.
   */
  postsPerAgent?: boolean;
  /**
   * v0.1.18 (NOT a fault): the dynamic catalog is empty (an engine that lists nothing without its backend) but resolve
   * still answers the known tools; an unknown tool resolves to null (200 null). A11.resolve_family needs
   * dynamic.<op>.resolveTools.
   */
  emptyCatalog?: boolean;
  /** v0.1.23 (C115): the tag-filtered read treats `anyOf: []` as "no constraint" (manifest 0.1.15 bug; fails A11.narrowing_empty_anyof) */
  emptyAnyOfNoFilter?: boolean;
  /** spec 0.1.47 (SDK-INSTANCE-GRANT): the person op `scope_grant` skips the agent ceiling (fails A18.scope_grant_ceiling) */
  scopeGrantNoCeiling?: boolean;
  /** spec 0.1.47: the agent probe op `scope_probe` reports ctx.scopeGrants on an AGENT call (fails A18.scope_grant_agent_absent) */
  scopeGrantsOnAgent?: boolean;
  /** spec 0.1.47: a grant above the ceiling is not refused but clamped to the ceiling level and answered 200 (fails A18.scope_grant_ceiling: a level changed) */
  scopeGrantClamps?: boolean;
  /** spec 0.1.47: the grant row gets the lowest level whatever was asked (fails A18.scope_grant_within: wrong level) */
  scopeGrantWrongLevel?: boolean;
  /** spec 0.1.47: the grant row is written without source / grantedByOp (fails A18.scope_grant_within) */
  scopeGrantNoSource?: boolean;
  /** spec 0.1.48 (SDK-COMPANION-CALLERS): the agent probe op `companion_callers_probe` carries the list on an AGENT call (fails A19.companion_callers_agent_absent) */
  companionCallersOnAgent?: boolean;
  /** spec 0.1.48: the person op `companion_callers` drops `provider` (fails A19.companion_callers_person) */
  companionCallersNoProvider?: boolean;
  /** spec 0.1.48: the person op answers the slice list as of the FIRST slice (a snapshot, not the current slice; fails A19.companion_callers_person) */
  companionCallersSnapshot?: boolean;
  /** spec 0.1.48: the person op leaks the companion grant material next to each entry (fails A19.companion_callers_person) */
  companionCallersLeaksGrant?: boolean;
  /** spec 0.1.54 (C292, conformance 0.1.27): the person op `bridge_caps` answers the caps of the FIRST slice (a snapshot, not the current slice; fails A22.bridge_caps_equal) */
  bridgeCapsSnapshot?: boolean;
  /** spec 0.1.54: the person op drops entries it does not know (only owner_rows passes; fails A22.bridge_caps_equal) */
  bridgeCapsDropsUnknown?: boolean;
  /** spec 0.1.54: the person op keeps the last non-empty caps it saw when a later slice has none (fails A22.bridge_caps_absent) */
  bridgeCapsSticky?: boolean;
  /** spec 0.1.54: the person op ignores the slice lifetime and still answers the caps of an expired slice (fails A22.bridge_caps_expired) */
  bridgeCapsIgnoresExpiry?: boolean;
  /** Caller.listed (SPEC-GAP spec 0.1.49): the probe op `caller_listed` answers listed true whatever the slice says (fails A19.caller_listed) */
  callerListedAlwaysTrue?: boolean;
  /**
   * spec 0.1.45 (HOOK-CALLER-PRODUCT, NOT a fault): the before hooks key on the calling app's product. A call from an app caller
   * with THIS product is refused (the app's rule); from an app with another product it is allowed; an app caller without
   * `call.caller.product` is refused too (fail closed). Other callers are allowed.
   */
  hookKeyedOnProduct?: string;
  /** spec 0.1.45: an app caller without `call.caller.product` is ALLOWED by a product-keyed hook (fails A2.hook_app_caller_fail_closed) */
  hookOpenWithoutProduct?: boolean;
  /** spec 0.1.45: an app caller WITH a product gets an invalid before answer (fails A2.hook_app_caller_product) */
  hookBadShapeWithProduct?: boolean;
  /** spec 0.1.45: an app caller WITHOUT a product gets an invalid before answer (fails A2.hook_app_caller_no_product) */
  hookBadShapeNoProduct?: boolean;
  /** package 0.1.15 (NOT a fault, Knowledge-like): the recall output also carries a status array `areas` next to `items` */
  recallStatusArray?: boolean;
  /** spec 0.1.50 (C283 A1): `tb.scopes_set` writes the row but marks it `bounded` (an owner row never goes above the grant; fails A20.owner_row_above_grant) */
  scopesSetBounded?: boolean;
  /** spec 0.1.50: every row is primary, defaults included (a bounded row above the grant runs; fails A20.bounded_above_grant_refused) */
  allRowsPrimary?: boolean;
  /** spec 0.1.50: the agent route executes `tb.scopes_set` and writes an owner row (fails A20.agent_cannot_write_owner_row) */
  agentSetsOwner?: boolean;
  /** spec 0.1.50: the companion (app) route executes `tb.scopes_set` and writes an owner row (fails A20.app_cannot_write_owner_row) */
  appSetsOwner?: boolean;
  /** spec 0.1.50: the person op `scope_grant` leaves an owner row primary (keeps its authority; fails A20.scope_grants_bounded) */
  scopeGrantKeepsOwner?: boolean;
  /** spec 0.1.50: an owner row also widens an op WITHOUT a scope type (fails A20.unscoped_above_grant_refused) */
  ownerWidensUnscoped?: boolean;
  /** spec 0.1.50: an owner row revives a paused agent (fails A20.paused_agent_owner_row) */
  ownerRevivesPaused?: boolean;
  /** like the real SDK: tb.holds_list / tb.receipts_list answer newest first, this many rows a page, with an offset `nextCursor` (default: one page with everything, oldest first) */
  listPageSize?: number;
  /** spec 0.1.50: scope rows carry no `authority` member in tb.agents_list (fails A20.owner_row_above_grant) */
  noAuthorityField?: boolean;
  /** spec 0.1.50: receipts of scoped calls carry no `admittedBy` (fails A20.owner_row_above_grant) */
  noAdmittedBy?: boolean;
  /** spec 0.1.50: the catalog marks every entry `admitted: "owner"` for every agent (fails A20.catalog_admitted) */
  catalogMarksAll?: boolean;
  /** spec 0.1.50: the catalog never marks an entry (fails A20.catalog_admitted) */
  catalogNoMarks?: boolean;
  /** spec 0.1.50: scope_summary names every static scoped op as admitted for every agent (fails A20.admitted_ops) */
  admittedOpsAlways?: boolean;
  /** spec 0.1.50: scope_summary never names an admitted op (fails A20.admitted_ops) */
  noAdmittedOps?: boolean;
  /** spec 0.1.49 (C261): an app caller without a verified product is NOT refused although the slice says `appCallers: "verified"` (fails A12.caller_unverified_refused) */
  noCallerUnverified?: boolean;
  /** spec 0.1.50 (C268 A): the hook route does not compare the proof `sub` with the caller of the body (fails A2.hook_sub_mismatch) */
  hookIgnoresSub?: boolean;
  /** spec 0.1.50 (C268 A): the hook route does not compare the proof `call` with the call id of the body (fails A2.hook_call_mismatch) */
  hookIgnoresCall?: boolean;
  /** spec 0.1.52 (C283c): an owner row has no snapshot; its crud is the level's crud NOW (the 0.1.35 rule; fails A21.owner_row_widened_level) */
  ownerRowFollowsLevel?: boolean;
  /** spec 0.1.52: an owner row's crud is its snapshot only, not intersected with the level now (fails A21.owner_row_narrowed_level) */
  ownerRowSnapshotOnly?: boolean;
  /** spec 0.1.52: a plain re-set of the same level takes the new level crud (accepts the offer; fails A21.owner_row_widened_level) */
  plainResetAccepts?: boolean;
  /** spec 0.1.52: acceptOffer is not compared with the current offer (any adds accept; fails A21.owner_row_widened_level) */
  acceptNoCompare?: boolean;
  /** spec 0.1.52: acceptOffer with NO offer accepts any adds (fails A21.accept_offer_rules) */
  acceptPhantomOk?: boolean;
  /** spec 0.1.52: acceptOffer with access null deletes the row (fails A21.accept_offer_rules) */
  acceptNullDeletes?: boolean;
  /** spec 0.1.52: acceptOffer for another level than the row's is allowed and changes the level (fails A21.accept_offer_rules) */
  acceptOtherLevelOk?: boolean;
  /** spec 0.1.52: a widened level lists no offer (fails A21.owner_row_widened_level) */
  noOffer?: boolean;
  /** spec 0.1.52: scope rows carry no effective `crud` member (fails A21.owner_row_widened_level / A21.owner_row_narrowed_level) */
  noEffectiveCrud?: boolean;
  /** spec 0.1.52: the start module does not apply TBCONF_LEVEL_CRUD (the A21 update rows FAIL for an app that reports SDK >= 0.1.36 or declares proofClaims [bd], conformance 0.1.26) */
  ignoresLevelCrud?: boolean;
  /** spec 0.1.52 (C268 B): the hook route accepts any `bd` (compares nothing; fails A2.hook_bd_binds_body) */
  hookIgnoresBd?: boolean;
  /** conformance 0.1.26 (mutation c): bd is the sha256 of a RE-SERIALISATION of the parsed body (JSON.stringify(JSON.parse(raw))), not of the bytes received (fails A2.hook_bd_raw_bytes) */
  hookHashesReserialised?: boolean;
  /** spec 0.1.52: a proof that carries `bd` is not verified at all, on any route (fails A2.hook_bd_malformed and A2.proof_bd_other_variants) */
  bdProofsUnverified?: boolean;
  /** spec 0.1.52: the claim and the status pushes declare no proofClaims (fails A2.proof_claims_declared) */
  noProofClaims?: boolean;
}

/**
 * v0.1.23 (C115): a manifest op with this id is a tag-filtered memory read (SDK-API §18 `rules.narrowing`): output
 * `{items: [{id, tags}], nextCursor}` over RECALL_ITEMS, filtered with the shared `tagsMatch` (L1); an unknown `v` →
 * 409 narrowing_unsupported. The tests add it to a manifest variant only.
 */
export const RECALL_OP = "memory_recall";
/** The recall op's items; RECALL_TAG (any case) is carried by exactly one of them. */
export const RECALL_TAG = "conformance";
const RECALL_ITEMS = [
  { id: "mem_1", tags: [" Conformance "] },
  { id: "mem_2", tags: ["other"] },
  { id: "mem_3", tags: [] as string[] },
] as const;

/** Catalog of every dynamic op of the mini app (DynamicCatalogEntry): a read entry, an outward and a money entry. */
const DYN_ENTRIES = [
  { name: "dyn_read", title: "Read entry", description: "Generated read entry.", inputSchema: { type: "object", properties: {} }, crud: ["read"], effect: "read" },
  { name: "dyn_send", title: "Send entry", description: "Generated outward entry.", inputSchema: { type: "object", properties: {} }, crud: ["create"], effect: "outward", holdFamily: "first_contact" },
  { name: "dyn_pay", title: "Pay entry", description: "Generated money entry.", inputSchema: { type: "object", properties: {} }, crud: ["create"], effect: "money", holdFamily: "money" },
] as const;

interface Receipt {
  id: string;
  callId: string | null;
  caller: { type: "agent" | "app"; id: string; name: string; product?: string };
  op: string;
  effect: string;
  holdFamily: string | null;
  /** v0.1.13: `<product>/<hookId>` of the holding before hook, else null */
  heldBy: string | null;
  /** v0.1.13: the hook verdict reason or the SDK hold reason */
  reason: string | null;
  status: string;
  inputDigest: string;
  summary: string;
  meta: Json;
  idempotencyKey: string | null;
  /** spec 0.1.50 (C283 A1): which rule admitted a scoped call */
  admittedBy?: "app_owner_row" | "portal_grant";
  view?: string;
  input?: Json;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
  decidedBy: string | null;
  consumed?: boolean;
}

const CAPPED = new Set(["write", "outward", "destructive"]);

interface State {
  claimed: boolean;
  /** v0.1.13 (C85): the one app-initiated companion call of this data dir was made */
  bgCallDone?: boolean;
  /** v0.1.12: sha256 of the enrolment code the claim was made with */
  codeDigest?: string;
  bridgeId: string | null;
  slice: string | null;
  /** v0.1.11: pinned key-set statement + its keys */
  kss?: { seq: number; kss: string; keys: InstanceSlice["portalKeys"] } | null;
  receipts: Receipt[];
  idem: Record<string, { inputDigest: string; kind: "held" | "result"; holdId?: string; output?: Json }>;
  /** v0.1.18 (SDK-02): one cap slot per run of a capped effect (receipt or not) */
  capSlots?: { caller: string; effect: string; at: number }[];
  scopes: { agent: string; type: string; instanceId: string; access: string; source?: string; grantedByOp?: string; authority?: "owner" | "bounded"; /** spec 0.1.52: the level's crud when the owner set the row */ crudSnapshot?: string[] }[];
  defaultsApplied: string[];
  sessions: { digest: string; per: string; createdAt: number; csrf: string; expiresAt: number }[];
  usedJti: string[];
  /** areaPerAppCaller: app caller instance id → its area ids */
  areas?: Record<string, string[]>;
  /** postsPerAgent: post id → the agent that owns it */
  posts?: Record<string, string>;
  audit: { id: string; at: number; actor: string; action: string; target: string | null }[];
}

const nowS = () => Math.floor(Date.now() / 1000);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const sha = (s: string | Uint8Array) => createHash("sha256").update(s).digest("hex");
const peek = (t: string): Record<string, unknown> => {
  try {
    return JSON.parse(Buffer.from(t.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
};
class E extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export async function startMiniApp(released: Manifest, env: Record<string, string>, faults: MiniAppFaults = {}, port = 0) {
  // spec 0.1.52 (conformance 0.1.25): an A21 row simulates "an app update" by restarting with TBCONF_LEVEL_CRUD; this start module applies it
  const manifest = faults.ignoresLevelCrud ? released : applyLevelCrud(released, parseLevelCrud(env[LEVEL_CRUD_ENV]));
  const ins = env.TB_INSTANCE_ID as InstanceId;
  const dataDir = env.TB_DATA_DIR;
  const backupDir = env.TB_BACKUP_DIR;
  const bridgeUrl = env.TB_BRIDGE_URL;
  const kek = kekFromEnv(env.TB_KEK);
  const product = manifest.id;
  const mDigest = manifestDigest(manifest);
  const ops = withStandardOps(manifest);
  const replay = memoryReplayGuard();
  const statePath = join(dataDir, "state.json");
  mkdirSync(join(dataDir, "tb"), { recursive: true });

  // restore at boot (before anything else), then load state
  if (env.TB_RESTORE_FROM) {
    const entries = readTar(new Uint8Array(readFileSync(join(backupDir, env.TB_RESTORE_FROM))));
    const meta = JSON.parse(new TextDecoder().decode(entries.find((e) => e.name === "meta.json")?.data)) as { parts: { file: string; sha256: string }[] };
    for (const p of meta.parts) {
      const e = entries.find((x) => x.name === p.file);
      if (!e || sha(e.data) !== p.sha256) throw new Error("restore_failed");
    }
    writeFileSync(statePath, entries.find((e) => e.name === "app.db")?.data ?? "{}");
  }
  const st: State = existsSync(statePath)
    ? (JSON.parse(readFileSync(statePath, "utf8")) as State)
    : { claimed: false, bridgeId: null, slice: null, receipts: [], idem: {}, scopes: [], defaultsApplied: [], sessions: [], usedJti: [], audit: [] };
  const save = () => writeFileSync(statePath, JSON.stringify(st));

  // instance key, sealed on the volume
  const keyPath = join(dataDir, "tb", "instance-key");
  let key: Ed25519KeyPair;
  if (existsSync(keyPath) && !faults.newKeyOnRestart) {
    key = await importKeyPair(unseal(JSON.parse(readFileSync(keyPath, "utf8")) as SealedBlob, { current: kek }, sealAad("instance-key", ins)));
  } else {
    key = await generateKeyPair({ extractable: true });
    writeFileSync(keyPath, JSON.stringify(seal(await exportPrivateKey(key), kek, sealAad("instance-key", ins))));
  }

  let slice: InstanceSlice | null = st.slice ? (peek(st.slice) as unknown as InstanceSlice) : null;
  /** the first slice this process installed (companionCallersSnapshot fault) */
  let firstSlice: InstanceSlice | null = null;
  /** the last non-empty `bridge.caps` this process saw (bridgeCapsSticky fault) */
  let lastCaps: string[] = [];
  let keysRev = 0;
  const keyCache = new Map<string, string>();
  const declaredKeys = (manifest.settings?.keys ?? []).filter((k) => k.source === "account_default" && k.usedBy.includes("app"));

  const trust = (): TrustContext | null =>
    slice && st.bridgeId
      ? {
          now: nowS(),
          self: `tb:ins:${ins}`,
          ws: slice.ws as WorkspaceId,
          bridge: st.bridgeId as BridgeId,
          issuers: keySetFromPortalKeys(st.kss ? st.kss.keys : slice.portalKeys),
          bridgeKeys: keySetFrom({ keys: slice.bridge.keys }, `tb:brg:${st.bridgeId as BridgeId}`),
          revokedJtis: new Set(slice.revoked.jtis.map((j) => j.jti)),
        }
      : null;

  /** v0.1.18 (SDK-02): Free cap usage = this caller's cap slots of the effect inside the window */
  const capUsage = (caller: string, caps: Record<string, { max: number; per: "hour" | "day" } | undefined>): Partial<Record<Effect, number>> => {
    if (faults.capsUncounted) return {};
    const out: Partial<Record<Effect, number>> = {};
    for (const [effect, cap] of Object.entries(caps)) {
      if (!cap) continue;
      const since = Date.now() - (cap.per === "day" ? 86_400_000 : 3_600_000);
      out[effect as Effect] = (st.capSlots ?? []).filter((x) => x.caller === caller && x.effect === effect && x.at >= since).length;
    }
    return out;
  };
  const ensureAgent = (agent: string) => {
    for (const sc of manifest.scopes ?? []) {
      const k = `${agent}:${sc.type}`;
      if (st.defaultsApplied.includes(k)) continue;
      st.defaultsApplied.push(k);
      for (const g of sc.defaultGrants) if (g.kind === "own") st.scopes.push({ agent, type: sc.type, instanceId: `${sc.type}-${agent.slice(-8).toLowerCase()}`, access: g.access });
    }
  };

  // key-set rule (CREDENTIALS §9.5, strict since spec 0.1.12): roots from the harness-only TBCONF_PORTAL_ROOT_KEYS (a
  // test app; the SDK gets them through startApp's harness option), else the build-pinned dev roots like the SDK
  const roots = env.TBCONF_PORTAL_ROOT_KEYS ? (JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS) as never[]) : portalRootKeys("dev");
  /** false when the slice was refused */
  function installSlice(token: string): boolean {
    // `ignoreKeySet` = a DEFECTIVE app (fault injection): it skips the key-set rule and trusts the slice's `portalKeys`
    const t = faults.ignoreKeySet ? null : trustedPortalKeys(peek(token), st.kss ? { seq: st.kss.seq, kss: st.kss.kss } : null, roots);
    if (t && !t.ok) return false;
    const issuers = t ? t.signers : slice ? keySetFromPortalKeys(slice.portalKeys) : keySetFrom(JSON.parse(env.TB_PORTAL_KEYS) as never, "tb:portal");
    const r = verifySlice(token, { now: nowS(), self: `tb:ins:${ins}`, ws: (slice?.ws ?? peek(token).ws) as WorkspaceId, bridge: st.bridgeId as BridgeId, issuers });
    if (!r.ok) return false;
    if (slice && r.slice.rev <= slice.rev) return true;
    if (t) st.kss = { seq: t.seq, kss: t.kss, keys: t.keys.keys.map((k) => ({ jwk: k.jwk, status: k.status })) };
    slice = r.slice;
    firstSlice ??= r.slice;
    if (Array.isArray(r.slice.bridge.caps) && r.slice.bridge.caps.length > 0) lastCaps = [...r.slice.bridge.caps];
    st.slice = token;
    for (const a of slice.agents) ensureAgent(a.id);
    if (slice.pause.workspace || slice.pause.instances.includes(ins)) keyCache.clear();
    save();
    return true;
  }

  async function bridge(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal, extra: Record<string, string> = {}, assert = true): Promise<{ status: number; body: unknown }> {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const headers: Record<string, string> = { "content-type": "application/json", ...extra };
    if (st.bridgeId && assert) headers["TB-Assert"] = await signInstanceAssertion({ key, ins, bridge: st.bridgeId as BridgeId, method, pathAndQuery: path, body: bytes, now: nowS() });
    const res = await fetch(bridgeUrl + path, { method, headers, body: bytes, signal });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  }

  /** model roles (spec 0.1.63): required roles of the app the bridge cannot serve (unset, below policy, no route) keep it needs_keys */
  const requiredRoles = ((manifest.settings as { modelRoles?: { role: string; required: boolean; usedBy: string[] }[] } | undefined)?.modelRoles ?? []).filter((r) => r.required && r.usedBy.includes("app"));
  let roleMissing: string[] = [];
  async function refreshRoles(): Promise<void> {
    const missing: string[] = [];
    for (const r of requiredRoles) {
      const a = await bridge("GET", `/tb/v1/model-roles/${r.role}`);
      // 404 (role_not_set, or no route at all) and 403 role_policy_too_low = not resolved; a guess takes the 404 for resolved
      if (!(a.status === 200 || (faults.modelRoleGuess && a.status === 404))) missing.push(r.role);
    }
    roleMissing = missing;
  }
  const roleStatus = () => (roleMissing.length > 0 ? { readiness: "needs_keys", attention: { code: "model_role_missing", reason: `Model role not set: ${roleMissing.join(", ")}.` } } : { readiness: "ready" });
  async function fetchKeys(): Promise<void> {
    keyCache.clear();
    for (const k of declaredKeys) {
      const r = await bridge("GET", `/tb/v1/keys/${k.name}`);
      if (r.status === 200 && isObj(r.body)) keyCache.set(k.name, String(r.body.value));
    }
    await refreshRoles();
  }

  // claim (once; again only after a refused identity with a NEW enrolment code, SDK-API §13 v0.1.12)
  async function claim(reclaim: boolean): Promise<void> {
    const r = await bridge("POST", "/tb/v1/claim", { code: env.TB_ENROL_CODE, instancePublicKey: key.publicJwk, manifestDigest: mDigest, version: manifest.version, sdkVersion: faults.reportedSdkVersion ?? `${manifest.sdkMajor}.0.0`, ...(faults.noProofClaims ? {} : { proofClaims: ["bd"] }) }, undefined, {}, false);
    if (r.status !== 200 || !isObj(r.body) || r.body.ins !== ins) throw new Error(`claim failed: ${r.status}`);
    st.claimed = true;
    st.codeDigest = sha(env.TB_ENROL_CODE ?? "");
    st.bridgeId = String((r.body.bridge as Record<string, unknown>).id);
    if (reclaim) {
      st.slice = null;
      slice = null;
    }
    save();
    if (typeof r.body.slice === "string") installSlice(r.body.slice);
  }
  if (!st.claimed) await claim(false);
  let reclaimTried = false;

  // status push + long-poll; statusChanged() (SDK-API v0.1.13 C86) ends the current long-poll so the next push carries
  // the new pendingHolds at once
  const stop = new AbortController();
  const pending = () => (faults.pendingHoldsZero ? 0 : st.receipts.filter((x) => x.status === "held").length);
  let poll = new AbortController();
  let dirty = false;
  const statusChanged = () => {
    if (faults.noStatusChanged) return;
    dirty = true;
    poll.abort();
  };
  let bgTried = false;
  /** v0.1.13 (C85): one app-initiated companion call (no parentCall) once a slice with grants is installed */
  const background = () => {
    if (bgTried || st.bgCallDone || !slice || (slice.grants ?? []).length === 0 || !manifest.companions?.length) return;
    bgTried = true;
    void callCompanion(null).then(
      () => {
        st.bgCallDone = true;
        save();
      },
      () => undefined,
    );
  };
  const loop = (async () => {
    let first = true;
    while (!stop.signal.aborted) {
      try {
        background();
        poll = new AbortController();
        if (first) await refreshRoles().catch(() => undefined);
        const now = first || dirty;
        dirty = false;
        const r = await bridge(
          "POST",
          `/tb/v1/status?wait=${now ? 0 : 60}`,
          { ...roleStatus(), version: manifest.version, sdkVersion: `${manifest.sdkMajor}.0.0`, scopesRev: 0, sliceRevision: slice?.rev ?? 0, keysRev, pendingHolds: pending(), ...(faults.noProofClaims ? {} : { proofClaims: ["bd"] }) },
          AbortSignal.any([stop.signal, poll.signal]),
        );
        first = false;
        if (r.status === 401 && !faults.noReclaim && !reclaimTried && env.TB_ENROL_CODE && sha(env.TB_ENROL_CODE) !== st.codeDigest) {
          reclaimTried = true;
          await claim(true).catch(() => undefined);
          continue;
        }
        if (r.status === 401) await new Promise((res) => setTimeout(res, 300));
        if (r.status === 200 && isObj(r.body)) {
          if (typeof r.body.slice === "string" && !installSlice(r.body.slice)) await new Promise((res) => setTimeout(res, 300));
          if (typeof r.body.keysRev === "number" && r.body.keysRev !== keysRev) {
            keysRev = r.body.keysRev;
            await fetchKeys();
          }
        }
      } catch {
        if (stop.signal.aborted) break;
        if (!poll.signal.aborted) await new Promise((res) => setTimeout(res, 200));
      }
    }
  })();

  /** Companion call (SDK-API §9): the slice grant whose `wf` = the declared operations; grant_stale → re-read once, retry. */
  async function callCompanion(parentCall: string | null): Promise<Json> {
    const c = manifest.companions?.[0];
    if (!c) return null;
    const want = [...c.operations].sort().join(",");
    for (let attempt = 0; ; attempt++) {
      const grant = (slice?.grants ?? []).find((g) => [...((peek(g).wf as string[]) ?? [])].sort().join(",") === want);
      if (!grant) throw new E(403, "no_grant");
      const env = { target: c.product, op: c.operations[0], input: {}, ...(parentCall ? { parentCall } : {}) };
      const r = await bridge("POST", "/tb/v1/call", env, undefined, parentCall === null && faults.appInitiatedNoGrant ? {} : { "TB-Grant": grant });
      if (r.status === 200 || r.status === 202) return r.body as Json;
      const code = String(((r.body as { error?: { code?: string } } | null)?.error?.code) ?? "app_error");
      if (attempt === 0 && code === "grant_stale" && !faults.noCompanionRetry) {
        const s0 = await bridge("POST", "/tb/v1/status?wait=0", { ...roleStatus(), version: manifest.version, sdkVersion: `${manifest.sdkMajor}.0.0`, scopesRev: 0, sliceRevision: 0, keysRev, pendingHolds: pending(), ...(faults.noProofClaims ? {} : { proofClaims: ["bd"] }) });
        if (s0.status === 200 && isObj(s0.body) && typeof s0.body.slice === "string") installSlice(s0.body.slice);
        continue;
      }
      throw new E(r.status, code);
    }
  }

  // ── HTTP ──
  const read = async (req: IncomingMessage) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8");
  };
  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };
  const fail = (res: ServerResponse, e: E) => json(res, e.status, { error: { code: e.code, message: e.code, requestId: `req_${randomBytes(6).toString("hex")}` } });
  const pausedFor = (agent: string | null) => {
    if (faults.ignorePause || !slice) return { workspace: false, instance: false, agent: false };
    return { workspace: slice.pause.workspace, instance: slice.pause.instances.includes(ins), agent: agent !== null && (slice.pause.agents.includes(agent as never) || (!faults.pauseAgentsListOnly && slice.agents.some((a) => a.id === agent && a.status === "paused"))) };
  };
  const levelCrud = (type: string, level: string) => manifest.scopes?.find((s) => s.type === type)?.access.find((a) => a.id === level)?.crud ?? [];
  type ScopeRow = State["scopes"][number];
  /**
   * spec 0.1.52 (C283c): the crud a stored row gives. A bounded row: its level's crud now. An OWNER row: its snapshot ∩ the level's crud
   * now (a narrowed level applies at once, a widened one does not; no snapshot = []). The faults drop the snapshot or the intersection.
   */
  const rowCrud = (r: ScopeRow): readonly string[] => {
    const level = levelCrud(r.type, r.access);
    if (r.authority !== "owner" || faults.ownerRowFollowsLevel) return level;
    const snap = r.crudSnapshot ?? [];
    return faults.ownerRowSnapshotOnly ? snap : level.filter((c) => snap.includes(c));
  };
  /** the actions the level grants now that the owner row's snapshot does not (the offer) */
  const rowOffer = (r: ScopeRow): string[] => (r.authority !== "owner" || faults.noOffer ? [] : levelCrud(r.type, r.access).filter((c) => !(r.crudSnapshot ?? []).includes(c)));
  /**
   * spec 0.1.50 (C283 A1): do the OWNER rows of `agent` admit `crud` for `type` across instances? The agent must have rows, EVERY row
   * an owner row, and the best row's crud (the one with most actions) must contain `crud`. Display only (catalog / scope_summary).
   */
  const ownerAdmits = (agent: string, type: string, crud: readonly string[]): boolean => {
    const rows = st.scopes.filter((r) => r.agent === agent && r.type === type);
    if (rows.length === 0 || !rows.every((r) => r.authority === "owner")) return false;
    const best = rows.map((r) => rowCrud(r)).sort((x, y) => y.length - x.length)[0] ?? [];
    return crud.every((c) => (best as readonly string[]).includes(c));
  };
  /** the agent is in the slice, active and not paused: only then does a display mark apply */
  const markable = (agent: string): boolean => {
    const a = (slice?.agents ?? []).find((x) => x.id === agent);
    const p = pausedFor(agent);
    return !!a && a.status === "active" && !p.workspace && !p.instance && !p.agent;
  };
  const newId = (p: string) => `${p}_${randomBytes(16).toString("hex").toUpperCase().slice(0, 26)}`;

  async function agentOp(req: IncomingMessage, res: ServerResponse, opId: string, raw: string): Promise<void> {
    const body = JSON.parse(raw || "{}") as { input: Json; context?: Record<string, Json>; idempotencyKey?: string };
    const t = trust();
    if (!t) throw new E(503, "slice_stale");
    const grant = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    const proof = String(req.headers["tb-call"] ?? "");
    const g0 = peek(grant);
    let callId: string | null = null;
    let hv: { f: string; r: string; by: string } | null = null;
    if (!faults.skipProofVerify && !(faults.bdProofsUnverified && peek(proof).bd !== undefined)) {
      const p = verifyCallProof(proof, t, { op: opId, inputDigest: digest(body.input), contextDigest: digest(body.context ?? {}), grantJti: String(g0.jti ?? ""), grantSub: String(g0.sub ?? "") }, faults.noProofReplayGuard ? undefined : replay);
      if (!p.ok) throw new E(401, "call_proof_invalid");
      callId = p.claims.call;
      hv = p.claims.hv ?? null;
    }
    let callerId: string;
    let callerType: "agent" | "app" = "agent";
    let held: string[] = [];
    if (faults.strictHeld && Array.isArray(g0.held) && g0.held.some((f) => !(KNOWN_HOLD_FAMILIES as readonly unknown[]).includes(f))) throw new E(401, "grant_invalid");
    if (!faults.skipGrantVerify) {
      const g = verifyGrant(grant, t);
      if (!g.ok) throw new E(g.code.startsWith("grant_") ? 401 : 403, g.code);
      callerId = g.caller.id;
      callerType = g.caller.type;
      held = g.claims.held;
    } else {
      callerId = String(g0.sub ?? "tb:agt:unknown").split(":")[2] ?? "unknown";
    }
    void held;
    // spec 0.1.49 (C261): with the slice flag an app caller must have a verified product (grant prd, else its companionCallers entry)
    if (callerType === "app" && !faults.noCallerUnverified && slice?.appCallers === "verified") {
      const product = typeof g0.prd === "string" ? g0.prd : (slice.companionCallers ?? []).find((x) => x.ins === callerId)?.product;
      if (product === undefined) throw new E(403, "caller_unverified");
    }
    const op = ops.find((o) => o.id === opId);
    if (!op) throw new E(404, "unknown_tool");
    // faults: the agent / companion route executes the owner-only tb.scopes_set (spec 0.1.50: refused audience_not_agent)
    if (op.id === "tb.scopes_set" && (callerType === "agent" ? faults.agentSetsOwner : faults.appSetsOwner)) {
      const i = (body.input ?? {}) as Record<string, unknown>;
      st.scopes = st.scopes.filter((r) => !(r.agent === i.agent && r.type === i.type && r.instanceId === i.id));
      if (i.access !== null) st.scopes.push({ agent: String(i.agent), type: String(i.type), instanceId: String(i.id), access: String(i.access), source: "owner", authority: "owner" });
      save();
      return json(res, 200, { status: "ok", output: { access: (i.access ?? null) as Json } });
    }
    if (op.audience !== "agent") throw new E(403, "audience_not_agent");
    if (op.standard) {
      if (op.id === "tb.holds_pending") {
        // SDK-API v0.1.13 G4: summaries only; an agent sees its own held receipts, an app caller all; oldest first
        const q = (body.input ?? {}) as { limit?: number; cursor?: string };
        const limit = Math.min(100, Math.max(1, q.limit ?? 50));
        const from = q.cursor ? Number(Buffer.from(q.cursor, "base64url").toString()) || 0 : 0;
        const mine = st.receipts.filter((x) => x.status === "held" && (callerType === "app" || faults.holdsPendingAll || x.caller.id === callerId)).sort((x, y) => x.createdAt - y.createdAt);
        const items = mine.slice(from, from + limit).map((x) => ({
          id: x.id,
          product,
          op: x.op,
          family: x.holdFamily,
          reason: x.reason ?? "held",
          heldBy: x.heldBy,
          summary: x.summary,
          caller: x.caller,
          createdAt: new Date(x.createdAt).toISOString(),
          ageS: Math.floor((Date.now() - x.createdAt) / 1000),
          decidePath: `/holds/${x.id}`,
        }));
        const nextCursor = from + limit < mine.length ? Buffer.from(String(from + limit)).toString("base64url") : null;
        return json(res, 200, { status: "ok", output: { items, nextCursor } as unknown as Json });
      }
      if (op.id !== "tb.hold_status") throw new E(403, "audience_not_agent");
      const h = st.receipts.find((x) => x.id === String((body.input as Record<string, unknown>)?.holdId) && x.caller.id === callerId);
      if (!h) throw new E(404, "hold_not_found");
      return json(res, 200, { status: "ok", output: { status: h.status, expiresAt: h.expiresAt ? new Date(h.expiresAt).toISOString() : null, family: h.holdFamily, reason: h.reason } });
    }
    if (!validateInput(op, body.input).ok) throw new E(400, "input_invalid");
    let ownArea = false;
    if (faults.areaPerAppCaller && callerType === "app") {
      if (!st.areas) st.areas = {};
      const areas = st.areas;
      if (op.id === "area_create") {
        const id = newId("area");
        areas[callerId] = [...(areas[callerId] ?? []), id];
        save();
        return json(res, 200, { status: "ok", output: { id, name: (body.input as Record<string, Json>).name ?? null } });
      }
      const named = Object.values((body.input ?? {}) as Record<string, unknown>).filter((v): v is string => typeof v === "string");
      if (!named.some((v) => (areas[callerId] ?? []).includes(v))) throw new E(403, "area_required");
      ownArea = true;
    }
    if (faults.postsPerAgent && op.id === "post_cancel" && st.posts?.[String((body.input as Record<string, unknown>)?.id)] !== callerId) throw new E(404, "post_not_found");
    ensureAgent(callerId);
    const inputDigest = digest(body.input);
    const idemKey = op.idempotency === "none" ? null : (body.idempotencyKey ?? null);
    if (op.idempotency === "required" && !idemKey) throw new E(400, "idempotency_key_required");
    const ik = idemKey ? `${callerId}:${op.id}:${idemKey}` : null;
    const prior = ik ? st.idem[ik] : undefined;
    if (prior && prior.inputDigest !== inputDigest && !faults.noIdempotencyConflict) throw new E(409, "idempotency_conflict");
    if (prior?.kind === "result" && prior.inputDigest === inputDigest) return json(res, 200, { status: "ok", output: prior.output });
    if (prior?.kind === "held" && prior.inputDigest === inputDigest) {
      const h = st.receipts.find((x) => x.id === prior.holdId);
      if (h?.status === "held") return json(res, 202, { status: "held", holdId: h.id, expiresAt: new Date(h.expiresAt ?? 0).toISOString() });
      if (h?.status === "denied") throw new E(403, "hold_denied");
    }
    const scoped = op.standard ? undefined : op.scopeType;
    let access: { level: string; crud: typeof op.crud; authority?: "owner" | "bounded" } | null = null;
    if (scoped) {
      // the scope instance: the first required string naming one of the caller's scope rows (else the first string)
      const strs = (op.standard ? [] : ((op.input?.required as string[]) ?? [])).map((k) => (body.input as Record<string, unknown>)[k]).filter((v): v is string => typeof v === "string");
      const sid = strs.find((v) => st.scopes.some((r) => r.agent === callerId && r.type === scoped && r.instanceId === v)) ?? strs[0] ?? "";
      const row = st.scopes.find((r) => r.agent === callerId && r.type === scoped && r.instanceId === sid);
      // spec 0.1.50 (C283 A1): only the owner's tb.scopes_set marks a row primary (`allRowsPrimary` is the fault: every row is)
      access = row ? { level: row.access, crud: [...rowCrud(row)] as typeof op.crud, authority: faults.allRowsPrimary || row.authority === "owner" ? "owner" : "bounded" } : null;
      // areaPerAppCaller: the caller's own area grants it full access to that scope instance
      if (ownArea) access = { level: "own_area", crud: ["create", "read", "update", "delete"] };
    }
    const approved = faults.standingApproval
      ? st.receipts.find((x) => x.caller.id === callerId && x.op === op.id && (x.status === "approved" || x.status === "run"))
      : st.receipts.find((x) => x.caller.id === callerId && x.op === op.id && x.inputDigest === inputDigest && x.status === "approved" && !x.consumed);
    const eff = op as Extract<OperationView, { standard: false }>;
    const holdVerdict = hv && !faults.ignoreHoldVerdict ? { family: hv.f as never, reason: hv.r, by: hv.by } : null;
    const d = faults.hvBeforeScope && holdVerdict && !pausedFor(callerId).workspace
      ? ({ decision: "hold", reason: "held_by_hook", holdFamily: holdVerdict.family, heldBy: holdVerdict.by } as const)
      : authorize({
      paused: pausedFor(callerId),
      grant,
      trust: t,
      op: { id: op.id, crud: op.crud, effect: op.effect, ...(eff.holdFamily ? { holdFamily: eff.holdFamily } : {}), ...(scoped ? { scopeType: scoped } : {}) },
      access,
      usage: capUsage(callerId, (g0.caps ?? {}) as Record<string, { max: number; per: "hour" | "day" } | undefined>),
      approval: approved && !(faults.hvIgnoresApproval && holdVerdict) ? "approved" : "none",
      holdVerdict,
    });
    if (faults.capsIgnoredWithWf && d.decision === "hold" && d.reason === "caps_exceeded" && Array.isArray(g0.wf) && g0.wf.length > 0) {
      // a pre-C111a app: a workflow grant runs past its caps
    } else if (faults.appCallerNoHold && callerType === "app" && d.decision === "hold") {
      // a broken app that runs every app→app call (C105a violated)
    } else if (faults.skipGrantVerify && d.decision === "refuse" && d.reason.startsWith("grant_")) {
      // a broken app that never verifies the grant runs anyway
    } else if (faults.ownerWidensUnscoped && d.decision === "refuse" && d.reason === "scope_denied" && !scoped && st.scopes.some((r) => r.agent === callerId && r.authority === "owner")) {
      // a broken app that lets any owner row widen an op without a scope type
    } else if (faults.ownerRevivesPaused && d.decision === "refuse" && d.reason === "paused" && st.scopes.some((r) => r.agent === callerId && r.authority === "owner")) {
      // a broken app that lets an owner row revive a paused agent
    } else if (d.decision === "refuse") throw new E(403, d.reason);
    // C102: an app caller is named from slice companionCallers (verified grant sub), fallback the instance id
    const callerName = callerType === "app" && !faults.callerNameIgnoresSlice ? ((slice?.companionCallers ?? []).find((x) => x.ins === callerId)?.name ?? callerId) : callerId;
    // spec 0.1.44 (SDK-CALLER-PRODUCT): app callers only; the product of the companionCallers entry whose `ins` is the verified
    // grant's caller instance. The fault looks it up by NAME instead (the impostor-by-name hole).
    const listed = slice?.companionCallers ?? [];
    // spec 0.1.46 (GRANT-PRD): the verified grant's `prd` first, the slice entry only when `prd` is absent; both present and
    // different = 403 grant_invalid. The faults: slice only (pre-0.1.46), slice preferred (no refusal), grant picked (no refusal).
    const sliceProduct = listed.find((x) => x.ins === callerId)?.product;
    const grantPrd = callerType === "app" && !faults.callerProductIgnoresPrd && typeof g0.prd === "string" ? g0.prd : undefined;
    if (grantPrd !== undefined && sliceProduct !== undefined && grantPrd !== sliceProduct && !faults.callerProductPrefersSlice && !faults.callerProductMismatchPicksGrant) throw new E(403, "grant_invalid");
    const callerProduct =
      callerType !== "app" || faults.noCallerProduct
        ? undefined
        : faults.callerProductFromName
          ? listed.find((x) => x.name === callerName)?.product
          : faults.callerProductPrefersSlice
            ? (sliceProduct ?? grantPrd)
            : (grantPrd ?? sliceProduct);
    const base = {
      callId,
      caller: { type: callerType, id: callerId, name: callerName, ...(callerProduct !== undefined ? { product: callerProduct } : {}) },
      op: op.id,
      effect: op.effect,
      inputDigest,
      summary: op.title,
      meta: null,
      idempotencyKey: idemKey,
      createdAt: Date.now(),
      decidedAt: null,
      decidedBy: null,
      ...(d.decision !== "refuse" && "admittedBy" in d && d.admittedBy && !faults.noAdmittedBy ? { admittedBy: d.admittedBy } : {}),
      ...(faults.storesRawInput ? { input: body.input } : {}),
    };
    const capsSkipped = faults.capsIgnoredWithWf && d.decision === "hold" && d.reason === "caps_exceeded" && Array.isArray(g0.wf) && g0.wf.length > 0;
    if (d.decision === "hold" && !(faults.appCallerNoHold && callerType === "app") && !capsSkipped) {
      const h: Receipt = { ...base, id: newId("hld"), holdFamily: d.holdFamily ?? null, heldBy: d.heldBy ?? null, reason: d.heldBy && holdVerdict ? holdVerdict.reason : d.reason, status: "held", expiresAt: Date.now() + 15 * 60_000, view: op.title };
      st.receipts.push(h);
      if (ik) st.idem[ik] = { inputDigest, kind: "held", holdId: h.id };
      save();
      statusChanged();
      return json(res, 202, { status: "held", holdId: h.id, expiresAt: new Date(h.expiresAt ?? 0).toISOString() });
    }
    // v0.1.18 (SDK-02): the run takes a cap slot before it runs (receipt or not)
    if (CAPPED.has(op.effect) && !(faults.capsCountReceiptsOnly && !op.receipt)) {
      if (!st.capSlots) st.capSlots = [];
      st.capSlots.push({ caller: callerId, effect: op.effect, at: Date.now() });
    }
    if (op.id === RECALL_OP) {
      // SDK-API §18 rules.narrowing (G5): absent → unfiltered; unknown v → narrowing_unsupported; memoryTags via tagsMatch
      const n = body.context?.["rules.narrowing"];
      let items = [...RECALL_ITEMS];
      if (n !== undefined) {
        if (!isObj(n) || n.v !== 1) throw new E(409, "narrowing_unsupported");
        const mt = isObj(n.memoryTags) ? (n.memoryTags as { anyOf?: string[]; noneOf?: string[] }) : undefined;
        const tags = faults.emptyAnyOfNoFilter && mt?.anyOf?.length === 0 ? { ...(mt.noneOf ? { noneOf: mt.noneOf } : {}) } : mt;
        items = items.filter((x) => tagsMatch(tags, x.tags));
      }
      return json(res, 200, { status: "ok", output: { items: items.map((x) => ({ id: x.id, tags: [...x.tags] })), nextCursor: null, ...(faults.recallStatusArray ? { areas: [{ id: "a1", state: "ok" }, { id: "a2", state: "ok" }] } : {}) } });
    }
    // read ops also read the companion product (app→app through the bridge)
    const companion = op.crud.includes("read") ? await callCompanion(callId) : null;
    const output: Json = { ok: true, op: op.id, ...(companion ? { companion } : {}), ...(op.id === "scope_probe" ? { scopeGrants: faults.scopeGrantsOnAgent === true } : {}), ...(op.id === "caller_listed" ? { listed: callerType === "app" && (faults.callerListedAlwaysTrue || (callerProduct !== undefined && listed.some((x) => x.ins === callerId && x.product === callerProduct))) } : {}), ...(op.id === "companion_callers_probe" && faults.companionCallersOnAgent ? { companionCallers: (slice?.companionCallers ?? []) as unknown as Json } : {}) };
    if (faults.postsPerAgent && op.id === "post_create") {
      const id = newId("post");
      st.posts = { ...(st.posts ?? {}), [id]: callerId };
      (output as Record<string, Json>).id = id;
    }
    let receiptId: string | undefined;
    if (approved) {
      approved.status = "run";
      approved.consumed = true; // the receipt keeps the held call's id (accepted rule, SDK-API §4.3)
      receiptId = approved.id;
    } else if (op.receipt) {
      const r: Receipt = { ...base, id: newId("rcp"), holdFamily: null, heldBy: null, reason: null, status: "run", expiresAt: null };
      st.receipts.push(r);
      receiptId = r.id;
    }
    if (ik) st.idem[ik] = { inputDigest, kind: "result", output };
    save();
    json(res, 200, { status: "ok", output, ...(receiptId ? { receiptId } : {}) });
  }

  function session(req: IncomingMessage) {
    const m = /tb_session=([^;]+)/.exec(String(req.headers.cookie ?? ""));
    const s = m ? st.sessions.find((x) => x.digest === sha(m[1])) : undefined;
    if (!s || s.expiresAt < Date.now()) throw new E(401, "session_required");
    if (!faults.ignorePersonNbf && slice && s.createdAt < slice.personNbf * 1000) throw new E(401, "session_required");
    return s;
  }

  /** one page of a person list op: everything at once, or (faults.listPageSize) newest first with an offset cursor */
  function listPage(rows: Receipt[], cursor: unknown): Json {
    const size = faults.listPageSize;
    if (!size) return { items: rows as unknown as Json, nextCursor: null };
    const newest = [...rows].reverse();
    const from = typeof cursor === "string" ? Number(cursor) : 0;
    if (!Number.isSafeInteger(from) || from < 0) throw new E(400, "cursor_invalid");
    return { items: newest.slice(from, from + size) as unknown as Json, nextCursor: from + size < newest.length ? String(from + size) : null };
  }

  async function personOp(req: IncomingMessage, res: ServerResponse, opId: string, raw: string): Promise<void> {
    const s = session(req);
    if (!faults.noCsrf && req.headers["tb-csrf"] !== s.csrf) throw new E(403, "csrf_invalid");
    const input = ((JSON.parse(raw || "{}") as { input?: Record<string, unknown> }).input ?? {}) as Record<string, unknown>;
    const op = ops.find((o) => o.id === opId);
    if (!op) throw new E(404, "unknown_tool");
    if (op.audience !== "person") throw new E(403, "audience_not_person");
    let out: Json;
    switch (opId) {
      case "tb.holds_list":
        out = listPage(st.receipts.filter((x) => ["held", "approved", "denied"].includes(x.status)), input.cursor);
        break;
      case "tb.receipts_list":
        out = listPage(st.receipts, input.cursor);
        break;
      case "tb.holds_decide": {
        const h = st.receipts.find((x) => x.id === input.holdId && x.status === "held");
        if (!h) throw new E(404, "hold_not_found");
        h.status = input.decision === "approve" ? "approved" : "denied";
        h.decidedAt = Date.now();
        h.decidedBy = s.per;
        st.audit.push({ id: newId("aud"), at: Date.now(), actor: s.per, action: "hold.decide", target: h.id });
        statusChanged();
        out = h as unknown as Json;
        break;
      }
      case "tb.agents_list":
        out = { agents: (slice?.agents ?? []).map((a) => ({ ...a, access: st.scopes.filter((r) => r.agent === a.id).map((r) => {
            const { authority, crudSnapshot: _snapshot, ...rest } = r;
            const offer = rowOffer(r);
            const row = { ...rest, ...(faults.noEffectiveCrud ? {} : { crud: [...rowCrud(r)] }), ...(offer.length > 0 ? { offer: { adds: offer } } : {}) };
            return faults.noAuthorityField ? row : { ...row, authority: authority ?? "bounded" };
          }) })) as unknown as Json };
        break;
      case "tb.scopes_set": {
        const same = (r: ScopeRow) => r.agent === input.agent && r.type === input.type && r.instanceId === input.id;
        const prior = st.scopes.find(same);
        const level = input.access === null ? null : String(input.access);
        // spec 0.1.52 (C283b/C283c): acceptOffer {adds} accepts the CURRENT offer at the row's own level (compared as a set)
        const accepting = input.acceptOffer !== undefined;
        const ao = input.acceptOffer;
        if (accepting && (!isObj(ao) || Object.keys(ao).some((k) => k !== "adds") || !Array.isArray(ao.adds) || !ao.adds.every((x) => ["read", "create", "update", "delete"].includes(String(x))))) throw new E(400, "input_invalid");
        const adds = accepting ? (ao as { adds: string[] }).adds.map(String) : [];
        if (accepting && level === null && !faults.acceptNullDeletes) throw new E(400, "input_invalid");
        if (accepting && level !== null && prior && prior.access !== level && !faults.acceptOtherLevelOk) throw new E(400, "input_invalid");
        const offer = prior ? rowOffer(prior) : [];
        if (accepting && level !== null && !faults.acceptNoCompare && !(faults.acceptPhantomOk && offer.length === 0) && !(adds.length > 0 || offer.length > 0 ? new Set(adds).size === new Set(offer).size && adds.every((x) => offer.includes(x)) : true)) throw new E(409, "offer_changed");
        st.scopes = st.scopes.filter((r) => !same(r));
        // spec 0.1.50 (C283 A1): the owner's person op writes a PRIMARY row (also an unchanged level: "make primary");
        // spec 0.1.52: with the level's crud now as its snapshot, except a plain re-set of an owner row at its own level, which keeps it
        if (level !== null) {
          const keep = !faults.plainResetAccepts && prior?.authority === "owner" && prior.access === level && !(accepting && offer.length > 0);
          const snapshot = keep ? (prior?.crudSnapshot ?? []) : [...levelCrud(String(input.type), level)];
          st.scopes.push({ agent: String(input.agent), type: String(input.type), instanceId: String(input.id), access: level, source: "owner", authority: faults.scopesSetBounded ? "bounded" : "owner", crudSnapshot: snapshot });
        }
        out = { access: input.access as Json };
        break;
      }
      case "scope_grant": {
        // spec 0.1.47 (SDK-INSTANCE-GRANT): bounds = scope type + level exist, level <= the highest level the defaults give agents
        const sc = manifest.scopes?.find((x) => x.type === "space");
        const rank = (lvl: string) => levelCrud("space", lvl).length * 1000 + (sc?.access.findIndex((a) => a.id === lvl) ?? -1);
        const ceiling = (sc?.defaultGrants ?? []).filter((g) => !g.callers || g.callers.includes("agent")).map((g) => g.access).sort((x, y) => rank(y) - rank(x))[0];
        let lvl = String(input.access);
        if (!sc?.access.some((a) => a.id === lvl)) throw new E(400, "scope_grant_invalid");
        const above = ceiling === undefined || rank(lvl) > rank(ceiling);
        if (above && faults.scopeGrantClamps && ceiling !== undefined) lvl = ceiling;
        else if (!faults.scopeGrantNoCeiling && above) throw new E(400, "scope_grant_invalid");
        if (faults.scopeGrantWrongLevel) lvl = sc?.access[0]?.id ?? lvl;
        if (!(slice?.agents ?? []).some((a) => a.id === input.agent)) throw new E(400, "scope_grant_invalid");
        const prior = st.scopes.find((r) => r.agent === input.agent && r.type === "space" && r.instanceId === input.id);
        st.scopes = st.scopes.filter((r) => !(r.agent === input.agent && r.type === "space" && r.instanceId === input.id));
        // spec 0.1.50: an app row is bounded, also over an owner row (the fault keeps the old authority)
        st.scopes.push({ agent: String(input.agent), type: "space", instanceId: String(input.id), access: lvl, authority: faults.scopeGrantKeepsOwner ? (prior?.authority ?? "bounded") : "bounded", ...(faults.scopeGrantNoSource ? {} : { source: "app", grantedByOp: "scope_grant" }) });
        out = { ok: true };
        break;
      }
      case "bridge_caps": {
        // spec 0.1.54 (C292): what ctx.bridgeCaps() gave the handler = the CURRENT slice's bridge.caps (strings; unknown entries pass
        // through); [] when the slice has none or has expired (12 h after its iat). A person op still runs on an expired slice.
        const cur = faults.bridgeCapsSnapshot ? firstSlice : slice;
        const expired = !faults.bridgeCapsIgnoresExpiry && (!cur || nowS() > cur.iat + 12 * 3600);
        let caps: string[] = expired ? [] : Array.isArray(cur?.bridge.caps) ? cur.bridge.caps.filter((x): x is string => typeof x === "string") : [];
        if (faults.bridgeCapsSticky && !expired && caps.length === 0) caps = [...lastCaps];
        if (faults.bridgeCapsDropsUnknown) caps = caps.filter((x) => x === "owner_rows");
        out = { bridgeCaps: caps };
        break;
      }
      case "companion_callers": {
        // spec 0.1.48 (SDK-COMPANION-CALLERS): what ctx.companionCallers() gave the handler = the CURRENT slice list
        const list = (faults.companionCallersSnapshot ? firstSlice : slice)?.companionCallers ?? [];
        out = {
          companionCallers: list.map((e) => ({
            product: e.product,
            ins: e.ins,
            name: e.name,
            ...(faults.companionCallersNoProvider ? {} : { provider: e.provider ?? null }),
            ...(faults.companionCallersLeaksGrant ? { grant: "tbg.leak" } : {}),
          })) as unknown as Json,
        };
        break;
      }
      case "tb.export": {
        const files = [
          { file: "receipts.jsonl", data: Buffer.from(st.receipts.map((r) => JSON.stringify(r)).join("\n")) },
          { file: "audit.jsonl", data: Buffer.from(st.audit.map((r) => JSON.stringify(r)).join("\n")) },
        ];
        const meta = { format: "tealbrick.export/1", product, version: manifest.version, instance: ins, sdk: "0.0.0-test", createdAt: new Date().toISOString(), files: files.map((f) => ({ file: f.file, rows: f.data.toString().split("\n").filter(Boolean).length, sha256: sha(f.data) })) };
        const tgz = writeTarGz([{ name: "meta.json", data: Buffer.from(JSON.stringify(meta)) }, ...files.map((f) => ({ name: f.file, data: f.data }))]);
        writeFileSync(join(backupDir, `tb-export-${Date.now()}.tar.gz`), tgz);
        res.writeHead(200, { "content-type": "application/gzip" });
        return void res.end(tgz);
      }
      default:
        out = {};
    }
    save();
    json(res, 200, { status: "ok", output: out });
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    const raw = await read(req);
    const base = `/a/${product}`;
    try {
      if (req.method === "GET" && path === "/tb/v1/manifest") return json(res, 200, manifest);
      if (req.method === "GET" && path === "/tb/v1/health")
        return json(res, 200, { status: "ok", sdk: "0.0.0-test", version: manifest.version, manifestDigest: mDigest, keys: declaredKeys.map((k) => ({ name: k.name, present: keyCache.has(k.name), source: keyCache.has(k.name) ? "account_default" : null })) });
      if (req.method === "GET" && path === "/tb/v1/openapi.json")
        return json(res, 200, { openapi: "3.1.0", info: { title: manifest.name, version: manifest.version }, paths: Object.fromEntries(ops.filter((o) => o.audience === "agent").map((o) => [`/tb/v1/ops/${o.id}`, { post: {} }])) });
      if (faults.servesClaimRoute && path === "/tb/v1/claim") return json(res, 200, { ok: true });
      if (req.method === "POST" && path.startsWith("/tb/v1/ops/")) return await agentOp(req, res, decodeURIComponent(path.slice(11)), raw);
      if (req.method === "POST" && path.startsWith("/tb/v1/hooks/")) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const hook = manifest.hooks?.find((h) => h.id === path.slice(13));
        if (!hook) throw new E(404, "unknown_hook");
        const b = JSON.parse(raw) as { phase: string; call: { input?: Json; caller?: unknown }; context: Json };
        // spec 0.1.50 (C268 A): the proof names the caller (`sub`) and the call (`call`) of the request; the faults skip one comparison
        const callBody = b.call as unknown as { id?: unknown; caller?: unknown };
        const hookProofToken = String(req.headers["tb-call"] ?? "");
        // spec 0.1.52 (C268 B): bd = sha256 of the raw body bytes received (the faults compare nothing / skip the whole verification)
        const bdClaim = peek(hookProofToken).bd;
        const p = faults.bdProofsUnverified && bdClaim !== undefined ? { ok: true as const } : verifyHookProof(
          hookProofToken,
          t,
          {
            hook: hook.id,
            phase: hook.phase,
            contextDigest: digest(b.context),
            bodyDigest: faults.hookIgnoresBd ? (typeof bdClaim === "string" ? (bdClaim as never) : undefined) : sha256Bytes(Buffer.from(faults.hookHashesReserialised ? JSON.stringify(b) : raw)),
            ...(b.call.input !== undefined ? { inputDigest: digest(b.call.input) } : {}),
            ...(faults.hookIgnoresSub ? {} : { sub: hookCallerRef(callBody.caller) }),
            ...(faults.hookIgnoresCall ? {} : { call: typeof callBody.id === "string" ? callBody.id : "" }),
          },
          replay,
        );
        if (!p.ok) throw new E(401, "call_proof_invalid");
        if (b.phase !== hook.phase) throw new E(400, "input_invalid");
        if (hook.phase === "before") {
          const caller = (b.call as unknown as { caller?: { type?: string; product?: string } }).caller;
          if (caller?.type === "app") {
            if (caller.product !== undefined ? faults.hookBadShapeWithProduct : faults.hookBadShapeNoProduct) return json(res, 200, { allow: "yes" });
            if (faults.hookKeyedOnProduct !== undefined) {
              if (caller.product === undefined) return json(res, 200, faults.hookOpenWithoutProduct ? { allow: true } : { allow: false, reason: "caller product unknown" });
              if (caller.product === faults.hookKeyedOnProduct) return json(res, 200, { allow: false, reason: "calls from this product are refused" });
            }
          }
        }
        return json(res, 200, hook.phase === "before" ? { allow: true, ...(faults.badHookShape ? { tb_extra: 1 } : {}) } : hook.phase === "context" ? { add: { [`${product}.seen`]: true } } : {});
      }
      if (req.method === "POST" && path.startsWith("/tb/v1/bridge/")) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const name = path.slice(14);
        const bop = name === "scope-summary" ? "scope_summary" : name;
        const b = JSON.parse(raw || "{}") as Record<string, Json>;
        const bopToken = String(req.headers["tb-call"] ?? "");
        const p = faults.bdProofsUnverified && peek(bopToken).bd !== undefined ? { ok: true as const } : verifyBridgeOpProof(bopToken, t, bridgeOpBinding(bop as never, b), replay);
        if (!p.ok) throw new E(401, "call_proof_invalid");
        if (bop === "scope_summary") {
          // spec 0.1.50: admittedOps = the static scoped agent ops this agent's OWNER rows admit (absent when none)
          const staticScoped = manifest.operations.filter((o) => o.audience === "agent" && !o.dynamic && o.scopeType !== undefined);
          return json(
            res,
            200,
            (slice?.agents ?? []).map((a) => {
              const admittedOps = faults.noAdmittedOps ? [] : staticScoped.filter((o) => (faults.admittedOpsAlways ? true : markable(a.id) && ownerAdmits(a.id, o.scopeType as string, o.crud))).map((o) => o.id);
              return { agent: a.id, label: `${st.scopes.filter((r) => r.agent === a.id).length} spaces`, ...(admittedOps.length > 0 ? { admittedOps } : {}) };
            }),
          );
        }
        if (bop === "catalog" || bop === "resolve") {
          const dyn = ops.find((o): o is Extract<OperationView, { standard: false }> => o.id === b.op && !o.standard && !!o.dynamic);
          if (!dyn) throw new E(404, "unknown_tool");
          if (bop === "catalog") {
            if (faults.emptyCatalog) return json(res, 200, []);
            // spec 0.1.50: `admitted: "owner"` only when body.agent's OWNER rows admit the entry's crud for the op's scope type
            const agent = typeof b.agent === "string" ? b.agent : null;
            const scopeType = dyn.scopeType;
            return json(
              res,
              200,
              DYN_ENTRIES.map((e) => {
                const mark = !faults.catalogNoMarks && (faults.catalogMarksAll || (agent !== null && scopeType !== undefined && markable(agent) && ownerAdmits(agent, scopeType, e.crud)));
                return mark ? { ...e, admitted: "owner" } : e;
              }),
            );
          }
          const e = DYN_ENTRIES.find((x) => x.name === b.tool);
          if (!e && faults.emptyCatalog) return json(res, 200, null);
          if (!e) throw new E(404, "unknown_tool");
          const fam = "holdFamily" in e && !faults.resolveNoFamily ? { holdFamily: e.holdFamily } : {};
          return json(res, 200, { tool: e.name, crud: e.crud, effect: e.effect, ...fam });
        }
        if (bop === "mark") {
          const r = st.receipts.find((x) => x.callId === b.call);
          if (r) r.status = "after_failed";
          save();
          return json(res, 200, { ok: true, marked: !!r });
        }
        throw new E(404, "unknown_tool");
      }
      if (req.method === "POST" && path === `${base}/tb/launch`) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const ticket = new URLSearchParams(raw).get("ticket") ?? "";
        const v = verifyTicket(ticket, t);
        if (!v.ok) throw new E(401, "ticket_invalid");
        if (st.usedJti.includes(v.claims.jti) && !faults.ticketReusable) throw new E(401, "ticket_used");
        st.usedJti.push(v.claims.jti);
        const value = randomBytes(32).toString("base64url");
        st.sessions.push({ digest: sha(value), per: v.claims.sub.slice(7), createdAt: Date.now(), csrf: randomBytes(16).toString("base64url"), expiresAt: Date.now() + 8 * 3600_000 });
        save();
        res.writeHead(303, { location: `${base}/`, "set-cookie": `tb_session=${value}; Path=${base}/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800` });
        return void res.end();
      }
      if (req.method === "GET" && path === `${base}/tb/v1/session`) {
        const s = session(req);
        return json(res, 200, { principal: { type: "person", id: s.per, ws: slice?.ws, instance: ins, iss: "tb:portal", sessionExpiresAt: s.expiresAt }, csrf: s.csrf });
      }
      if (req.method === "POST" && path === `${base}/tb/v1/logout`) {
        const s = session(req);
        st.sessions = st.sessions.filter((x) => x !== s);
        save();
        return json(res, 200, { ok: true });
      }
      if (req.method === "POST" && path.startsWith(`${base}/tb/v1/ops/`)) return await personOp(req, res, decodeURIComponent(path.slice(`${base}/tb/v1/ops/`.length)), raw);
      throw new E(404, "not_found");
    } catch (e) {
      fail(res, e instanceof E ? e : new E(500, "app_error"));
    }
  }

  const server = createServer((req, res) => void handle(req, res));
  await new Promise<void>((r) => server.listen(port || Number(env.TBCONF_PORT ?? 0), "127.0.0.1", () => r()));
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    async stop() {
      stop.abort();
      await loop;
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
    async backupNow() {
      const db = Buffer.from(JSON.stringify(st));
      const meta = { format: "tealbrick.backup/1", product, version: manifest.version, manifestDigest: mDigest, instance: ins, sdk: "0.0.0-test", createdAt: new Date().toISOString(), parts: [{ name: "app.db", file: "app.db", sha256: sha(db), bytes: db.length }] };
      writeFileSync(join(backupDir, `tb-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz`), writeTarGz([{ name: "meta.json", data: Buffer.from(JSON.stringify(meta)) }, { name: "app.db", data: db }]));
    },
  };
}
