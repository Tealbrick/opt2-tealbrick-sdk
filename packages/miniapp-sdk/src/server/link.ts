// The instance ↔ bridge link (SDK-API §9, BRIDGE §8.3, §10): ONE claim path, the status push + slice/keys long-poll,
// and companion calls. One credential: the instance key K8 (instance assertions in TB-Assert).
import {
  type AppStatus,
  type AppStatusResponse,
  BRIDGE_HEADERS,
  BRIDGE_INTERNAL_PATHS,
  type CallEnvelope,
  type ClaimResponse,
  type OpResult,
} from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, Ed25519PublicJwk, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { CompanionResult, HealthStatus, Json, Logger } from "@opt2-tealbrick/spec/sdk";
import type { BridgeClient } from "./bridge-client.ts";
import { errorFrom, SDK_PROOF_CLAIMS } from "./bridge-client.ts";
import { enrolCodeDigest, identityRefused, reclaimCode, waitForMountedDataDir } from "./claim-guard.ts";
import { TbError } from "./errors.ts";
import type { JobsSummary } from "./jobs.ts";
import { peekClaims } from "./ops.ts";
import type { Runtime } from "./runtime.ts";
import { upgradeHealth } from "./server.ts";
import { metaGet, metaSet } from "./store.ts";

export interface ClaimRecord {
  ins: InstanceId;
  bridge: { id: BridgeId; publicKey: Ed25519PublicJwk; internalUrl: string };
  claimedAt: number;
  /** v0.1.12: sha256 digest of the enrolment code this record was claimed with (never the code); absent before 0.1.12 */
  codeDigest?: `sha256:${string}`;
}

const BACKOFF_MIN_MS = 1000;
const BACKOFF_MAX_MS = 60_000;
const STATUS_WAIT_S = 60;

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    t.unref();
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        resolve();
      },
      { once: true },
    );
  });

function jobsField(rt: Runtime): { jobs?: JobsSummary } {
  try {
    const j = rt.jobs.summary();
    return j.queued + j.running + j.waiting + j.paused + j.failed > 0 || j.appPaused ? { jobs: j } : {};
  } catch {
    return {};
  }
}

export function readiness(h: HealthStatus): AppStatus["readiness"] {
  return h === "ok" ? "ready" : h === "needs_keys" ? "needs_keys" : "degraded";
}

export class BridgeLink {
  readonly #rt: Runtime;
  readonly #client: BridgeClient;
  readonly #log: Logger;
  readonly #stop = new AbortController();
  #poll: AbortController | null = null;
  #dirty = false;
  #running: Promise<void> | null = null;
  /** digests of enrolment codes already tried for a reclaim in this process (one attempt per code) */
  readonly #tried = new Set<string>();

  constructor(rt: Runtime, client: BridgeClient) {
    this.#rt = rt;
    this.#client = client;
    this.#log = rt.log;
  }

  static record(rt: Runtime): ClaimRecord | null {
    return metaGet<ClaimRecord>(rt.db, "claim");
  }

  start(): void {
    this.#running = this.#loop().catch((e) => this.#log.error("bridge link stopped", { error: e instanceof Error ? e.message : "unknown" }));
  }

  async stop(): Promise<void> {
    this.#stop.abort();
    this.#poll?.abort();
    await this.#running;
  }

  /** Sends a status report at once (pendingHolds / scopesRev changed, C16 S2). */
  kick(): void {
    this.#dirty = true;
    this.#poll?.abort();
  }

  /** One status exchange without waiting (companion `grant_stale` → re-read the slice once). */
  async refreshNow(): Promise<void> {
    const r = await this.#client.request("POST", `${BRIDGE_INTERNAL_PATHS.status}?wait=0`, await this.#status());
    if (r.status === 200) await this.#apply(r.body as AppStatusResponse);
  }

  async #status(): Promise<AppStatus> {
    const rt = this.#rt;
    const attention = await rt.attention();
    const ready = readiness(rt.health());
    const u = upgradeHealth(rt);
    const status: AppStatus & Record<string, unknown> = {
      // v0.1.20 (spec 0.1.28, F89): an app attention turns `ready` into `degraded`; needs_keys/degraded stay as they are
      readiness: attention && ready === "ready" ? "degraded" : ready,
      version: rt.manifest.version,
      sdkVersion: rt.sdkVersion,
      proofClaims: [...SDK_PROOF_CLAIMS],
      scopesRev: rt.scopes.rev(),
      sliceRevision: rt.trust.slice?.rev ?? 0,
      keysRev: rt.keys.keysRev(),
      // v0.1.13 (C86): held receipts + defineApp pendingCount() (clamped 0..10 000, 1 s timeout)
      pendingHolds: await rt.pendingHolds(),
      ...(attention ? { attention } : {}),
      // v0.1.21 (R1): job counts when the app has any (SPEC-GAP: AppStatus.jobs, additive)
      ...jobsField(rt),
      // v0.1.25 (E2, SPEC-GAP additive): schema + rollback facts for Core's health gate (needs a bridge that forwards them)
      schemaVersion: u.schemaVersion,
      minCompatibleCode: u.minCompatibleCode,
      ...(u.preUpdateSnapshot ? { preUpdateSnapshot: u.preUpdateSnapshot } : {}),
    };
    return status;
  }

  /** Returns false when the answered slice was refused (the bridge would answer the same slice again at once). */
  async #apply(r: AppStatusResponse): Promise<boolean> {
    const installed = typeof r?.slice === "string" ? await installSlice(this.#rt, r.slice) : true;
    if (typeof r?.keysRev === "number") await this.#rt.keys.onKeysRev(r.keysRev);
    return installed;
  }

  /** The claim gate (v0.1.12): never redeem the one-time code while TB_DATA_DIR is not on a mounted volume. */
  async #mounted(): Promise<boolean> {
    const rt = this.#rt;
    return waitForMountedDataDir(rt.cfg.dataDir, {
      ephemeral: rt.cfg.dataEphemeral,
      ...(rt.mountinfoPath ? { mountinfoPath: rt.mountinfoPath } : {}),
      log: this.#log,
      signal: this.#stop.signal,
      onBlocked: (blocked) => {
        if (blocked) rt.state.attention = "data_dir_not_mounted";
        else if (rt.state.attention === "data_dir_not_mounted") rt.state.attention = null;
      },
    });
  }

  /** ONE claim path: the first claim (`code` = TB_ENROL_CODE) and a reclaim after a refused identity. */
  async #claim(reclaim = false): Promise<boolean> {
    const rt = this.#rt;
    const code = rt.cfg.enrolCode;
    if (!code) {
      this.#log.error("TB_ENROL_CODE missing and no claim record: issue a new enrolment code in Portal");
      return false;
    }
    if (!(await this.#mounted())) return false;
    const r = await this.#client.claim(
      { code, instancePublicKey: rt.instanceKey.publicJwk, manifestDigest: rt.digest, version: rt.manifest.version, sdkVersion: rt.sdkVersion, proofClaims: [...SDK_PROOF_CLAIMS] },
      this.#stop.signal,
    );
    if (r.status !== 200) throw errorFrom(r, "claim_failed");
    const body = r.body as ClaimResponse;
    if (body?.ins !== rt.instanceId) {
      rt.state.failed = true;
      throw new TbError("instance_mismatch", "claim response names another instance than TB_INSTANCE_ID", 500);
    }
    const record: ClaimRecord = { ins: body.ins, bridge: body.bridge, claimedAt: Date.now(), codeDigest: enrolCodeDigest(code) };
    // reclaim: the new record replaces the refused one, and the old identity's slice goes with it (sealed app data,
    // the instance key and the pinned key-set statement stay)
    if (reclaim) rt.trust.dropSlice();
    metaSet(rt.db, "claim", record);
    rt.trust.setBridge(body.bridge.id);
    rt.state.claimed = true;
    if (rt.state.attention === "identity_refused") rt.state.attention = null;
    await rt.audit.record({ actor: "system", action: "claim.complete", target: rt.instanceId, detail: { bridge: body.bridge.id, ...(reclaim ? { reclaim: true } : {}) } });
    if (typeof body.slice === "string") await installSlice(rt, body.slice);
    rt.onClaimed();
    return true;
  }

  /**
   * The bridge refused the stored identity (401 `unauthenticated`): needs_attention `identity_refused` (logged once per
   * episode). With a NEW TB_ENROL_CODE (digest ≠ the record's) claim again once; otherwise keep refusing with backoff.
   * Returns true when a reclaim succeeded.
   */
  async #onRefused(): Promise<boolean> {
    const rt = this.#rt;
    if (rt.state.attention !== "identity_refused") {
      rt.state.attention = "identity_refused";
      this.#log.warn("identity_refused", { hint: "the bridge refuses the stored instance identity; a new enrolment code (Portal Retry) lets the app claim again" });
    }
    if (!reclaimCode(rt.cfg.enrolCode, BridgeLink.record(rt)?.codeDigest, this.#tried)) return false;
    this.#log.info("reclaim", { reason: "identity_refused" });
    try {
      return await this.#claim(true);
    } catch (e) {
      if (rt.state.attention === null) rt.state.attention = "identity_refused";
      this.#log.warn("reclaim failed", { code: e instanceof TbError ? e.code : "error" });
      return false;
    }
  }

  async #loop(): Promise<void> {
    const rt = this.#rt;
    let backoff = BACKOFF_MIN_MS;
    while (!this.#stop.signal.aborted && !rt.state.failed) {
      try {
        if (!rt.state.claimed) {
          if (!(await this.#claim())) {
            await sleep(BACKOFF_MAX_MS, this.#stop.signal);
            continue;
          }
          void rt.keys.refresh();
        }
        this.#poll = new AbortController();
        const wait = this.#dirty ? 0 : STATUS_WAIT_S;
        this.#dirty = false;
        const status = await this.#status();
        const sentAt = Date.now();
        const r = await this.#client.request(
          "POST",
          `${BRIDGE_INTERNAL_PATHS.status}?wait=${wait}`,
          status,
          {},
          AbortSignal.any([this.#stop.signal, this.#poll.signal]),
        );
        let refused = false;
        if ((r.status === 200 || r.status === 204) && rt.state.attention === "identity_refused") {
          rt.state.attention = null;
          this.#log.info("identity accepted again");
        }
        if (r.status === 200) refused = !(await this.#apply(r.body as AppStatusResponse));
        else if (r.status !== 204) throw errorFrom(r, "status_failed");
        backoff = BACKOFF_MIN_MS;
        // a refused slice (e.g. keyset_rollback) is answered again at once: never a busy loop
        if (refused) await sleep(BACKOFF_MIN_MS, this.#stop.signal);
        // a bridge that answers a long-poll at once with 204 must not turn this loop into a busy loop
        if (wait > 0 && r.status === 204 && Date.now() - sentAt < BACKOFF_MIN_MS) await sleep(BACKOFF_MIN_MS, this.#stop.signal);
      } catch (e) {
        if (this.#stop.signal.aborted) break;
        if (this.#poll?.signal.aborted) continue; // kicked: report again at once
        if (rt.state.claimed && identityRefused(e)) {
          if (await this.#onRefused()) {
            backoff = BACKOFF_MIN_MS;
            continue;
          }
        } else this.#log.warn("bridge exchange failed", { code: e instanceof TbError ? e.code : "error" });
        if (rt.state.failed) break;
        await sleep(backoff + Math.floor(Math.random() * 250), this.#stop.signal);
        backoff = Math.min(BACKOFF_MAX_MS, backoff * 2);
      }
    }
  }

  /**
   * Companion call `POST /tb/v1/call` with TB-Assert + TB-Grant (SDK-API §9, BRIDGE §8.3). `parentCall: null` = an
   * app-initiated call (v0.1.13 C85: StartContext / EventContext / timers): the envelope carries no parentCall.
   */
  async call<O = Json>(product: string, op: string, input: Json, opts: { idempotencyKey?: string; parentCall: string | null }): Promise<CompanionResult<O>> {
    const rt = this.#rt;
    // a product declaration first; else the wildcard companion (M-CP-3: only tb.holds_pending) for any product
    const declared =
      rt.manifest.companions?.find((c) => c.product === product && c.operations.includes(op)) ??
      (product !== "*" ? rt.manifest.companions?.find((c) => c.product === "*" && c.operations.includes(op)) : undefined);
    if (!declared) throw new TbError("companion_undeclared", `companion operation not declared: ${product}.${op}`, 500);
    const p = rt.trust.paused(null);
    if (p.workspace || p.instance) throw new TbError("paused", "this instance is paused", 403);
    const envelope: CallEnvelope = {
      target: product,
      op,
      input,
      ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}),
      ...(opts.parentCall ? { parentCall: opts.parentCall as CallEnvelope["parentCall"] } : {}),
    };
    for (let attempt = 0; ; attempt++) {
      const grant = companionGrant(rt, product, declared.product === "*" ? null : declared.operations, op);
      if (!grant) throw new TbError("no_grant", `no companion grant for ${product} in the slice`, 403);
      const r = await this.#client.request("POST", BRIDGE_INTERNAL_PATHS.call, envelope, { [BRIDGE_HEADERS.companionGrant]: grant });
      if (r.status === 200 || r.status === 202) return r.body as OpResult<O>;
      const err = errorFrom(r, "app_error");
      if (attempt === 0 && (err.code === "grant_stale" || err.code === "grant_expired")) {
        await this.refreshNow();
        continue;
      }
      throw err;
    }
  }
}

/**
 * The slice's `grants` carry no product label. SPEC-GAP: the SDK picks the grant whose `wf` equals the manifest-declared
 * companion operations for that product (I8: companion grants carry `wf` = those operations); the bridge verifies it.
 * v0.1.14 addition: when the slice's `companionTargets` names the product's instance, the grant's `aud` must be that
 * instance. A wildcard companion (`ops` null) needs that mapping: its per-app grants differ only by `aud`.
 */
function companionGrant(rt: Runtime, product: string, ops: readonly string[] | null, op: string): string | null {
  const want = ops ? [...ops].sort().join(",") : null;
  const auds = new Set(rt.trust.companionTargets().filter((t) => t.product === product).map((t) => `tb:ins:${t.ins}`));
  if (!want && auds.size === 0) return null;
  for (const g of rt.trust.slice?.grants ?? []) {
    const c = peekClaims(g);
    if (!Array.isArray(c?.wf) || c.sub !== rt.trust.self) continue;
    const wf = c.wf as string[];
    if (want ? [...wf].sort().join(",") !== want : !wf.includes(op)) continue;
    if (auds.size > 0 && !auds.has(String(c.aud))) continue;
    return g;
  }
  return null;
}

/**
 * Verifies + installs a slice, then runs the side effects: first sight (§7.2), agentRemoved, v0.1.13 (Fleet)
 * agentsChanged, pause → drop key cache.
 */
export async function installSlice(rt: Runtime, token: string): Promise<boolean> {
  const r = rt.trust.install(token, Date.now());
  if (!r.ok) {
    rt.log.warn("slice rejected", { code: r.code });
    return false;
  }
  const slice = rt.trust.slice;
  // v0.1.38 (C274c): a new slice may carry the `events` cap: the outbox sender looks at once (rows waited for it)
  rt.events.wake();
  if (!r.changed || !slice) return true;
  for (const a of slice.agents) await rt.ensureAgent(a);
  for (const a of r.changed.removed) {
    rt.db.prepare("UPDATE tb_agents SET in_slice = 0 WHERE agent = ?").run(a.id);
    try {
      await rt.def.events?.agentRemoved?.(a, rt.eventContext());
    } catch (e) {
      rt.log.warn("agentRemoved failed", { agent: a.id, error: e instanceof Error ? e.message : "unknown" });
    }
  }
  await rt.notifyAgents();
  const p = rt.trust.paused(null);
  if (p.workspace || p.instance) rt.keys.dropCache();
  return true;
}
