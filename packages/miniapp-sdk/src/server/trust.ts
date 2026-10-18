// Trust state of the instance (SDK-API §9 Slice, §12, CREDENTIALS §9.2 + §9.5): the last good instance slice, the trusted
// issuer set (the keys of the newest root-signed key-set statement → standalone issuer; before the first slice the
// bootstrap TB_PORTAL_KEYS; or the own key in app-alone mode), the pinned statement, call-proof keys,
// revoked jtis and pause state. Verification itself is `@opt2-tealbrick/manifest` (trustedPortalKeys, verifyJws, verifySlice).
import {
  keySetFrom,
  type PinnedKeySet,
  type PortalRootChannel,
  portalRootKeys,
  thumbprint,
  trustedPortalKeys,
  verifyJws,
  verifySlice,
} from "@opt2-tealbrick/manifest";
import type { InstanceSlice, ScopeRequest } from "@opt2-tealbrick/spec/bridge";
import { type BridgeId, type Ed25519PublicJwk, type InstanceId, type InstanceRef, LIFETIME_S, TYP, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { ProductId } from "@opt2-tealbrick/spec/manifest";
import type { KeySet, Logger, Refusal, SliceAgent, TrustContext } from "@opt2-tealbrick/spec/sdk";
import { metaDelete, metaGet, metaSet, type RawDb } from "./store.ts";

interface StoredSlice {
  token: string;
  slice: InstanceSlice;
  /** the issuer set the slice established (key-set statement keys, or the standalone issuer) */
  issuers: KeySet;
  /** v0.1.11 (C62/C63): the pinned key-set statement; once set, every later slice must carry a newer-or-equal one */
  kss?: PinnedKeySet;
}

/**
 * Root set this SDK build pins (C63): miniapp-sdk 0.1.x is a DEV-channel build until the cutover release, which
 * switches this constant to "prod" (production roots from the ceremony). A build constant, never read from env.
 */
export const PORTAL_ROOT_CHANNEL: PortalRootChannel = "dev";

export interface SliceChange {
  added: SliceAgent[];
  removed: SliceAgent[];
  pausedNow: boolean;
}

const nowS = (ms: number) => Math.floor(ms / 1000);
/** spec 0.1.48 (SDK-COMPANION-CALLERS): a provider key of slice `companionCallers[].provider` */
const PROVIDER_KEY = /^[a-z][a-z0-9_]{1,31}$/;

export class TrustState {
  readonly self: InstanceRef;
  readonly instanceId: InstanceId;
  #db: RawDb;
  #bootstrap: KeySet | null;
  #alone: { ws: WorkspaceId; ownKey: Ed25519PublicJwk } | null;
  #stored: StoredSlice | null;
  /** v0.1.12 reclaim: the pinned statement kept after {@link TrustState.dropSlice} (rollback protection survives) */
  #pin: PinnedKeySet | null;
  #bridge: BridgeId | null = null;
  #roots: Ed25519PublicJwk[];

  /**
   * `roots`: test-harness hook only (startApp `harness.portalRootKeys`); production uses the build-pinned roots of
   * {@link PORTAL_ROOT_CHANNEL}. The key-set statement is always required (C133: no transition path).
   */
  constructor(
    db: RawDb,
    instanceId: InstanceId,
    opts: {
      bootstrap: KeySet | null;
      alone?: { ws: WorkspaceId; ownKey: Ed25519PublicJwk };
      roots?: Ed25519PublicJwk[];
    },
  ) {
    this.#db = db;
    this.instanceId = instanceId;
    this.self = `tb:ins:${instanceId}`;
    this.#bootstrap = opts.bootstrap;
    this.#alone = opts.alone ?? null;
    this.#stored = metaGet<StoredSlice>(db, "slice");
    this.#pin = metaGet<PinnedKeySet>(db, "kss_pin");
    this.#roots = opts.roots ?? portalRootKeys(PORTAL_ROOT_CHANNEL);
  }

  /** The pinned key-set statement's `seq`, or null (nothing pinned yet). */
  get keySetSeq(): number | null {
    return (this.#stored?.kss ?? this.#pin)?.seq ?? null;
  }

  /**
   * v0.1.12 reclaim (SDK-API §13 note): a new claim replaced the refused identity, so the old identity's slice (bridge
   * id, agents, grants, rev) is dropped; the pinned key-set statement is kept (no key-set rollback through a reclaim).
   */
  dropSlice(): void {
    const kss = this.#stored?.kss ?? this.#pin;
    this.#stored = null;
    this.#pin = kss ?? null;
    metaDelete(this.#db, "slice");
    if (kss) metaSet(this.#db, "kss_pin", kss);
  }

  get slice(): InstanceSlice | null {
    return this.#stored?.slice ?? null;
  }
  get ws(): WorkspaceId | null {
    return this.#alone?.ws ?? this.#stored?.slice.ws ?? null;
  }
  /** Bridge id from the claim record (before the first slice) or the slice. */
  get bridgeId(): BridgeId | null {
    return this.#stored?.slice.bridge.id ?? this.#bridge;
  }
  setBridge(id: BridgeId): void {
    this.#bridge = id;
  }

  /** Issuers trusted for grants, tickets and slices. */
  issuers(): KeySet {
    if (this.#alone) return keySetFrom({ keys: [this.#alone.ownKey] }, this.self);
    return this.#stored?.issuers ?? this.#bootstrap ?? { keys: [] };
  }

  /** CORE C9: a slice older than 12 h → ops answer `slice_stale`. App-alone mode has no slice and never goes stale. */
  stale(nowMs: number): boolean {
    if (this.#alone) return false;
    const s = this.slice;
    return s === null || nowS(nowMs) > s.iat + LIFETIME_S.configOrSlice;
  }

  /** TrustContext for the manifest verifiers; null until a slice exists (or always available in app-alone mode). */
  context(nowMs: number): TrustContext | null {
    const ws = this.ws;
    if (this.#alone && ws) {
      return { now: nowS(nowMs), self: this.self, ws, bridge: "brg_00000000000000000000000000" as BridgeId, issuers: this.issuers(), bridgeKeys: { keys: [] }, revokedJtis: new Set() };
    }
    const s = this.slice;
    if (!s || !ws) return null;
    return {
      now: nowS(nowMs),
      self: this.self,
      ws,
      bridge: s.bridge.id,
      issuers: this.issuers(),
      bridgeKeys: keySetFrom({ keys: s.bridge.keys }, `tb:brg:${s.bridge.id}`),
      revokedJtis: new Set(s.revoked.jtis.map((j) => j.jti)),
    };
  }

  /**
   * Slice pause (CORE I1): workspace kill switch, this instance, the calling agent (listed or status `paused`).
   * v0.1.22 (SDK-05, fail closed): an agent id that is NOT in the slice counts as paused — the same answer the op route
   * gives it (`agent_unknown`), so `ctx.paused(agent)` never reports a removed or unknown agent as free to act.
   */
  paused(callerId: string | null): { workspace: boolean; instance: boolean; agent: boolean } {
    const s = this.slice;
    if (!s) return { workspace: false, instance: false, agent: false };
    const agentEntry = callerId ? s.agents.find((a) => a.id === callerId) : undefined;
    return {
      workspace: s.pause.workspace,
      instance: s.pause.instances.includes(this.instanceId),
      agent: callerId !== null && (!agentEntry || (s.pause.agents as string[]).includes(callerId) || agentEntry.status === "paused"),
    };
  }

  agent(id: string): SliceAgent | undefined {
    return this.slice?.agents.find((a) => a.id === id);
  }

  /** v0.1.13 (C86): Portal GUI origin from the slice (no trailing `/`), null until a slice carries one. */
  get portalUrl(): string | null {
    const u = this.slice?.portalUrl;
    return typeof u === "string" && /^https?:\/\/[^/?#\s]+\/?$/.test(u) ? u.replace(/\/$/, "") : null;
  }

  /**
   * Companion grant targets `{product, ins}` from the verified slice (Core fills it).
   * SPEC-GAP: spec 0.1.14 InstanceSlice.companionTargets — not in the 0.1.13 types; malformed entries are skipped.
   */
  /**
   * v0.1.14 (C102): the apps holding companion grants that target this instance (slice `companionCallers`); the SDK
   * names app callers from it (matched by the verified grant `sub`). Malformed entries are skipped.
   * v0.1.32 (SDK-COMPANION-CALLERS, spec 0.1.48): also carries `provider` (where that instance runs): a string matching
   * `^[a-z][a-z0-9_]{1,31}$` is kept; null, absent or any other value reads as null (unknown).
   */
  companionCallers(): { product: string; ins: string; name: string; provider: string | null }[] {
    const raw = this.slice?.companionCallers;
    if (!Array.isArray(raw)) return [];
    return raw
      .filter((e) => e && typeof e.product === "string" && typeof e.ins === "string" && typeof e.name === "string" && e.name !== "")
      .map((e) => ({ product: e.product, ins: e.ins, name: e.name, provider: typeof e.provider === "string" && PROVIDER_KEY.test(e.provider) ? e.provider : null }));
  }

  /**
   * v0.1.27 (SDK-CALLER-PRODUCT, spec 0.1.44): the VERIFIED product id of the app caller instance `ins` = the slice
   * `companionCallers[]` entry whose `ins` equals it (Portal-signed slice). The FALLBACK source of `Caller.product` (the
   * grant's `prd` wins, see resolveCallerProduct): never derived from a name. undefined = `ins` is not a companion caller in the current slice.
   */
  companionProduct(ins: string): string | undefined {
    return this.companionCallers().find((x) => x.ins === ins)?.product;
  }

  /**
   * v0.1.32 (`Caller.listed`): is `ins` listed in the CURRENT slice `companionCallers` under `product`? false when the slice is
   * missing or stale (checked at `nowMs`), when `product` is unknown, or when `ins` is listed under another product.
   */
  companionListed(ins: string, product: string | undefined, nowMs: number): boolean {
    if (product === undefined || this.stale(nowMs)) return false;
    return this.companionCallers().some((x) => x.ins === ins && x.product === product);
  }

  /** v0.1.18 (C106a): the slice's scopeRequest of `agt`, only when it targets `product` */
  agentScopeRequest(agt: string, product: string): ScopeRequest | null {
    const r = this.slice?.agents.find((a) => a.id === agt)?.scopeRequest;
    return r && r.product === product ? { product: r.product, kind: r.kind, ...(r.id !== undefined ? { id: r.id } : {}), ...(r.createName !== undefined ? { createName: r.createName } : {}) } : null;
  }

  /** v0.1.15 (C105a): slice `appsPolicy.held`, or null */
  appsPolicy(): string[] | null {
    const held = this.slice?.appsPolicy?.held;
    return Array.isArray(held) ? held.filter((h) => typeof h === "string") : null;
  }

  companionTargets(): { product: string; ins: string }[] {
    const raw = (this.slice as (InstanceSlice & { companionTargets?: unknown }) | null)?.companionTargets;
    if (!Array.isArray(raw)) return [];
    const out: { product: string; ins: string }[] = [];
    for (const t of raw as unknown[]) {
      const e = t as { product?: unknown; ins?: unknown } | null;
      if (e && typeof e === "object" && typeof e.product === "string" && e.product !== "" && typeof e.ins === "string" && e.ins !== "") out.push({ product: e.product, ins: e.ins });
    }
    return out;
  }

  /**
   * Verifies and installs a slice (`rev` must increase). The first slice teaches `ws` (ClaimResponse carries none).
   * Key-set rule first (CREDENTIALS §9.5, `trustedPortalKeys`): a slice MUST carry `portalKeySet`; it is verified
   * against the build-pinned roots and the pinned statement, the statement's active | pending keys must sign the slice
   * and the statement is pinned with it. A slice without one is refused (`keyset_missing`), pinned or not (C133: no
   * transition path). After a `standalone` slice only the standalone issuer is trusted and `portalKeySet` is ignored.
   */
  install(token: string, nowMs: number): { ok: true; changed: SliceChange | null } | Refusal {
    const bridge = this.bridgeId;
    if (!bridge) return { ok: false, code: "slice_invalid", reason: "bridge unknown before claim" };
    const pinned = this.#stored?.kss ?? this.#pin ?? null;
    let issuers = this.issuers();
    let signers = issuers;
    let kss: PinnedKeySet | undefined = pinned ?? undefined;
    if (!this.#stored?.slice.standalone) {
      const t = trustedPortalKeys(peekPayload(token) ?? {}, pinned, this.#roots);
      if (!t.ok) return t;
      issuers = t.keys;
      signers = t.signers;
      kss = { seq: t.seq, kss: t.kss };
    }
    const issList = [...new Set(signers.keys.map((k) => k.issuer as string))];
    const pre = verifyJws<InstanceSlice>(token, signers, { typ: TYP.slice, aud: this.self, iss: issList, now: nowS(nowMs), maxLifetimeS: LIFETIME_S.configOrSlice });
    if (!pre.ok) return pre;
    const ws = this.ws ?? pre.claims.ws;
    const v = verifySlice(token, { now: nowS(nowMs), self: this.self, ws, bridge, issuers: signers });
    if (!v.ok) return v;
    const slice = v.slice;
    const prev = this.#stored?.slice ?? null;
    if (prev && slice.rev <= prev.rev) return { ok: true, changed: null };
    // KSS rule: the statement's keys ARE the trusted set.
    let next = issuers;
    if (slice.standalone) {
      // BRIDGE §11: from the final Portal-signed slice on, only the standalone issuer is trusted
      const key = slice.bridge.keys.find((k) => thumbprint(k) === slice.standalone?.kid);
      next = key ? keySetFrom({ keys: [key] }, slice.standalone.issuer) : { keys: [] };
    }
    this.#stored = { token, slice, issuers: next, ...(kss ? { kss } : {}) };
    metaSet(this.#db, "slice", this.#stored);
    const before = new Map((prev?.agents ?? []).map((a) => [a.id, a]));
    const after = new Map(slice.agents.map((a) => [a.id, a]));
    const wasPaused = prev ? prev.pause.workspace || prev.pause.instances.includes(this.instanceId) : false;
    const isPaused = slice.pause.workspace || slice.pause.instances.includes(this.instanceId);
    return {
      ok: true,
      changed: {
        added: slice.agents.filter((a) => !before.has(a.id)),
        removed: [...before.values()].filter((a) => !after.has(a.id)),
        pausedNow: isPaused && !wasPaused,
      },
    };
  }
}

/** Unverified JWS payload (only to read `portalKeySet`, which is self-authenticating: root-signed). */
function peekPayload(token: string): Record<string, unknown> | null {
  const part = typeof token === "string" ? token.split(".")[1] : undefined;
  if (!part) return null;
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8")) as unknown;
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

/** The outcome of {@link resolveCallerProduct}: the `{ product? }` to spread into a Caller, or a grant/slice conflict. */
export type CallerProductResult = { ok: true; caller: { product?: ProductId } } | { ok: false; grantProduct: string; sliceProduct: string | null };

/**
 * THE one place a product is attached to an app Caller (v0.1.28, GRANT-PRD, spec 0.1.46; before: v0.1.27 SDK-CALLER-PRODUCT).
 * Every Caller built for an app (live op call, scheduled-op fire, handler job context) goes through this.
 *  - `claims` = the claims of the caller's VERIFIED grant (or null when the context has no grant, e.g. a handler job).
 *  - Sources, in order: (1) the grant's `prd` (signed with the grant, no lag) - (2) the slice `companionCallers[]` entry
 *    whose `ins` is the caller instance, only when `prd` is absent (grants minted before Core sends it).
 *  - Both present for the same instance and different: `{ ok: false }` (the caller refuses `grant_invalid`, never "pick one").
 *    A `prd` that is present but not a non-empty string is a malformed signed claim: also a conflict (fail closed).
 *  - Agents, persons and an app in neither source get `{}`. An agent grant's `prd` is never read. A name is never read.
 * A conflict is logged here as a warning with both product values (no token, no other grant claim).
 */
export function resolveCallerProduct(
  rt: { trust: Pick<TrustState, "companionProduct">; log?: Pick<Logger, "warn"> },
  caller: { type: string; id: string },
  claims: object | null,
): CallerProductResult {
  if (caller.type !== "app") return { ok: true, caller: {} };
  const sliceProduct = rt.trust.companionProduct(caller.id);
  const prd = claims ? (claims as { prd?: unknown }).prd : undefined;
  if (prd === undefined) return { ok: true, caller: sliceProduct === undefined ? {} : { product: sliceProduct as ProductId } };
  if (typeof prd !== "string" || prd === "" || (sliceProduct !== undefined && sliceProduct !== prd)) {
    const grantProduct = typeof prd === "string" ? prd : "(malformed)";
    rt.log?.warn("caller product differs between the grant and the instance slice; the call is refused", {
      caller: caller.id,
      grantProduct,
      sliceProduct: sliceProduct ?? null,
    });
    return { ok: false, grantProduct, sliceProduct: sliceProduct ?? null };
  }
  return { ok: true, caller: { product: prd as ProductId } };
}
