// App events (SDK-API §20, MANIFEST §16, BRIDGE §14; spec 0.1.57, C274c/C274d): `ctx.emit` / `ctx.purgeEvents` write ONE row
// of the transactional outbox `tb_event_outbox` (SDK schema 11) with the raw handle of the SAME connection, so the row shares
// the fate of the transaction that is open (rolled back → gone; committed → sent, even when the handler throws later). The
// sender drains the outbox in id order to `POST /tb/v1/events`, only while the slice says the bridge has the `events` cap.
import {
  EVENT_BATCH_MAX,
  EVENT_ELIGIBLE_MAX,
  EVENT_INSTANCE_ID_MAX,
  EVENT_KEY_RE,
  EVENT_SUBJECT_ID_MAX,
  EVENT_SUBJECT_KIND_RE,
  EVENT_SUMMARY_MAX,
  EVENT_TO_MAX,
  EVENT_WINDOW_MS,
  eventDecl,
  eventScopeType,
  eventVisibleCrud,
  isReservedEventName,
  type ResolvedEventDecl,
  ulid,
  validateEventPayload,
} from "@opt2-tealbrick/manifest";
import { BRIDGE_INTERNAL_PATHS, type EventEligible, type EventEmitItem, type EventIngestItem, type EventIngestResult, type EventPurgeItem, type HoldDecidedData } from "@opt2-tealbrick/spec/bridge";
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { EmitFn, EmitOptions, Json, Logger, PurgeEventsFn, ScopeGrantRow } from "@opt2-tealbrick/spec/sdk";
import type { BridgeResponse } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import type { RawDb, Row } from "./store.ts";

/** The capability a bridge declares (StatusReport → slice `bridge.caps`) when it implements BRIDGE §14 in full. */
export const EVENTS_CAP = "events";
/** Max request body to the bridge (BRIDGE §14.1: ≤ 512 KiB); the sender stays below it with a margin. */
const BATCH_MAX_BYTES = 480 * 1024;
/** Retry backoff after a transport error, 429 or 5xx (same keys: the bridge dedupes). */
const BACKOFF_MIN_MS = 1_000;
const BACKOFF_MAX_MS = 60_000;
/** Slow fallback timer: the sender is woken on release and on every installed slice; this only catches anything missed. */
export const SENDER_FALLBACK_MS = 30_000;
/** SDK-API §20 (specs#33): after this many consecutive failed sends (any cause) the app reports `events_send_failing`. */
export const SEND_FAILING_AFTER = 10;
/** while a transaction is open on the connection the sender waits this long and looks again (it drains COMMITTED rows only) */
const TX_WAIT_MS = 50;
const AGENT_RE = /^agt_[0-9A-HJKMNP-TV-Z]{26}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const subset = (a: readonly string[], b: readonly string[]): boolean => a.every((x) => b.includes(x));

/**
 * The outbox body of one row (`body` column): the ingest item without `eligible`, which the sender computes at SEND time, plus
 * `scopeType` = the scope type of the event when it was emitted (null = unscoped; SDK-internal, never sent): a row whose
 * `visibleWith` scope type changed by an app update before it was sent is dropped (SDK-API §20, specs#33).
 */
type EmitBody = Omit<EventEmitItem, "eligible"> & { scopeType?: string | null };
type PurgeBody = EventPurgeItem;

/** Who emits: `causedBy` = the verified agent caller of the op (absent for persons, apps, events, start, jobs). */
export interface EmitOrigin {
  causedBy?: AgentId;
}

/** What the sender needs from the running app (late-bound: the outbox exists before the bridge link). */
export interface SenderDeps {
  /** the claimed bridge client, or null (no claim yet / app-alone mode) */
  bridge(): { request(method: "POST", path: string, body: unknown, headers?: Record<string, string>, signal?: AbortSignal): Promise<BridgeResponse> } | null;
  /** the CURRENT slice's `bridge.caps` (C292): the sender sends only while it includes "events"; never read for authorization */
  bridgeCaps(): readonly string[];
  /** the scope rows on one instance with their EFFECTIVE crud and authority (scopes.ts `rowsOn`) */
  rowsOn(type: string, instanceId: string): ScopeGrantRow[];
  /** true when the agent is in the CURRENT verified slice (`eligible` lists only those, SDK-API §20) */
  inSlice(agent: string): boolean;
}

const bad = (code: string, message: string): TbError => new TbError(code, message, 400);

/**
 * THE outbox of one app process. `emit` / `purge` are synchronous writes; `start()` runs the sender (claimed bridge mode only).
 */
export class EventOutbox {
  readonly #db: RawDb;
  readonly #m: Manifest;
  readonly #log: Logger;
  #deps: SenderDeps | null = null;
  #timer: NodeJS.Timeout | null = null;
  #running = false;
  #again = false;
  #stopped = false;
  #backoff = 0;
  #retryAt = 0;
  #inflight: Promise<void> | null = null;
  /** aborts the send in flight on stop() */
  #abort: AbortController | null = null;
  /** consecutive failed sends (any cause); reset by a send the bridge answered in full */
  #failures = 0;
  /** batch size: halved on a 413 (down to 1), doubled again after each answered send (up to EVENT_BATCH_MAX) */
  #limit = EVENT_BATCH_MAX;

  readonly #backoffMin: number;
  readonly #backoffMax: number;

  /** `timing` is for tests only (the retry backoff bounds); production uses 1 s … 60 s. */
  constructor(db: RawDb, manifest: Manifest, log: Logger, timing: { backoffMinMs?: number; backoffMaxMs?: number } = {}) {
    this.#db = db;
    this.#m = manifest;
    this.#log = log;
    this.#backoffMin = timing.backoffMinMs ?? BACKOFF_MIN_MS;
    this.#backoffMax = timing.backoffMaxMs ?? BACKOFF_MAX_MS;
  }

  /** `ctx.emit` for one context: app names only (a `tb.*` name is refused `event_reserved`). */
  emitFn(origin: EmitOrigin = {}): EmitFn {
    return (name, data, opts) => this.emit(name, data, opts, origin, false);
  }

  /** `ctx.purgeEvents`: one all-agent purge row for the instance (the app deletes or disconnects it). */
  purgeFn(): PurgeEventsFn {
    return (instanceId) => {
      if (typeof instanceId !== "string" || instanceId.length < 1 || instanceId.length > EVENT_INSTANCE_ID_MAX) throw bad("event_instance_invalid", "instanceId must be 1..256 characters");
      this.#insert("purge", { kind: "purge", key: `purge:${ulid()}`, instanceId });
    };
  }

  /** The SDK's own platform events (`tb.hold.decided`): the reserved-name check is skipped, every other check runs. */
  emitPlatform(name: string, data: Json, opts: EmitOptions): void {
    this.emit(name, data, opts, {}, true);
  }

  /** `tb.hold.decided` to the hold's AGENT caller (app callers receive no events in v1). Runs inside the decision's transaction. */
  holdDecided(hold: { id: string; op: string; caller: { type: string; id: string } }, decision: HoldDecidedData["decision"]): void {
    if (hold.caller.type !== "agent") return;
    this.emitPlatform("tb.hold.decided", { holdId: hold.id, op: hold.op, decision } as unknown as Json, { subject: { kind: "hold", id: hold.id }, to: [hold.caller.id as AgentId] });
  }

  /**
   * A scope row of `agent` on (`type`, `instanceId`) was removed, its effective crud narrowed or it lost owner authority: a purge
   * row in the SAME transaction (the caller runs it inside the row change). Agent rows of EVERY scope type (specs#33: an app update
   * may have removed the event while older events of it are still stored); app callers receive no events.
   */
  rowNarrowed(agent: string, _type: string, instanceId: string): void {
    if (!agent.startsWith("agt_")) return;
    this.#insert("purge", { kind: "purge", key: `purge:${ulid()}`, agent: agent as AgentId, instanceId });
  }

  emit(name: string, data: Json, opts: EmitOptions, origin: EmitOrigin, platform: boolean): void {
    if (typeof name !== "string") throw bad("event_undeclared", "event name must be a string");
    // SDK-API §20: only the SDK emits platform events; a manifest `tb` emits no app events (its wire types read as platform types)
    if ((isReservedEventName(name) && !platform) || (!platform && this.#m.id === "tb")) throw bad("event_reserved", `event ${name} is in the platform's tb. namespace`);
    const decl: ResolvedEventDecl | null = eventDecl(this.#m, name);
    if (!decl || decl.platform !== platform) throw bad("event_undeclared", `event ${name} is not declared in the manifest`);
    const o: Partial<EmitOptions> = isObj(opts) ? opts : {};
    const payload = validateEventPayload(decl, data);
    if (!payload.ok) throw new TbError(payload.code, payload.code === "event_too_large" ? "event data exceeds 2 KiB (JCS)" : "event data does not match the payloadSchema", 400, { errors: payload.errors });
    if (o.key !== undefined && (typeof o.key !== "string" || !EVENT_KEY_RE.test(o.key))) throw bad("event_payload_invalid", "key must match ^[A-Za-z0-9._:-]{8,128}$");
    if (o.summary !== undefined && typeof o.summary !== "string") throw bad("event_payload_invalid", "summary must be a string");
    // BRIDGE §14.1 (specs#33): the summary length counts UTF-16 code units, i.e. a JavaScript string length
    if (typeof o.summary === "string" && o.summary.length > EVENT_SUMMARY_MAX) throw bad("event_too_large", `summary exceeds ${EVENT_SUMMARY_MAX} characters`);
    const scopeType = eventScopeType(this.#m, decl);
    const scoped = scopeType !== null;
    if (scoped && (typeof o.instanceId !== "string" || o.instanceId.length < 1 || o.instanceId.length > EVENT_INSTANCE_ID_MAX))
      throw bad("event_instance_invalid", `event ${name} is scoped: instanceId (1..256 characters) is required`);
    if (!scoped && o.instanceId !== undefined) throw bad("event_instance_invalid", `event ${name} is not scoped: no instanceId`);
    if (decl.audience === "target") {
      const to = o.to;
      if (!Array.isArray(to) || to.length < 1 || to.length > EVENT_TO_MAX || !to.every((a) => typeof a === "string" && AGENT_RE.test(a)))
        throw bad("event_target_invalid", `event ${name} has audience target: to = 1..${EVENT_TO_MAX} agent ids`);
    } else if (o.to !== undefined) throw bad("event_target_invalid", `event ${name} has audience granted: no to`);
    const s = o.subject;
    if (!isObj(s) || typeof s.kind !== "string" || !EVENT_SUBJECT_KIND_RE.test(s.kind) || typeof s.id !== "string" || s.id.length < 1 || s.id.length > EVENT_SUBJECT_ID_MAX)
      throw bad("event_payload_invalid", "subject must be {kind: ^[a-z][a-z0-9_]{0,31}$, id: 1..256 characters}");
    if (o.untrusted !== undefined && o.untrusted !== true) throw bad("event_payload_invalid", "untrusted must be true when present");
    const body: EmitBody = {
      kind: "emit",
      // default = a NEW ULID made at emit (not the row id): unique across restores and reinstalls
      key: o.key ?? ulid(),
      name,
      at: new Date().toISOString() as EmitBody["at"],
      subject: { kind: s.kind, id: s.id },
      ...(scoped ? { instanceId: o.instanceId as string } : {}),
      ...(typeof o.summary === "string" ? { summary: o.summary } : {}),
      ...(o.untrusted === true ? { untrusted: true as const } : {}),
      data: data as EmitBody["data"],
      ...(decl.audience === "target" ? { to: [...(o.to as AgentId[])] } : {}),
      ...(origin.causedBy ? { causedBy: origin.causedBy } : {}),
      scopeType,
    };
    this.#insert("emit", body);
  }

  #insert(kind: "emit" | "purge", body: EmitBody | PurgeBody): void {
    this.#db.prepare("INSERT INTO tb_event_outbox (id, kind, key, body, created_at) VALUES (?, ?, ?, ?, ?)").run(ulid(), kind, body.key, JSON.stringify(body), Date.now());
    // released = committed: a transaction callback is synchronous, so by the next macrotask it has committed or rolled back
    if (this.#deps) setImmediate(() => this.wake());
  }

  /** Rows waiting in the outbox (health / tests). */
  pending(): number {
    return Number((this.#db.prepare("SELECT COUNT(*) AS n FROM tb_event_outbox").get() as Row).n);
  }

  // ── sender ──────────────────────────────────────────────────────────────────

  /** Starts the background sender (bridge mode, after the claim record exists). */
  start(deps: SenderDeps): void {
    this.#deps = deps;
    this.#stopped = false;
    this.#arm(SENDER_FALLBACK_MS);
    this.wake();
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
    // a send in flight is aborted (its rows stay and go again after the next start, same keys)
    this.#abort?.abort(new TbError("app_stopping", "the app is stopping", 503));
    await this.#inflight?.catch(() => {});
  }

  /**
   * SDK-API §20 (specs#33): `events_send_failing` after SEND_FAILING_AFTER consecutive failed sends (any cause), until a send
   * succeeds, so the owner sees it long before the 7-day prune. Null otherwise.
   */
  attention(): { code: string; reason: string } | null {
    if (this.#failures < SEND_FAILING_AFTER) return null;
    return { code: "events_send_failing", reason: `The app could not send its events to the bridge (${this.#failures} tries in a row). Agents are not told about changes until this works again.` };
  }

  #arm(ms: number): void {
    if (this.#stopped) return;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = setTimeout(() => this.wake(), ms);
    this.#timer.unref();
  }

  /** Sends what is released, now (on release, on a new slice, on the fallback timer). Never throws. */
  wake(): void {
    if (this.#stopped || !this.#deps) return;
    if (this.#running) {
      this.#again = true;
      return;
    }
    this.#running = true;
    this.#inflight = (async () => {
      try {
        do {
          this.#again = false;
          await this.#drain();
        } while (this.#again && !this.#stopped);
      } catch (e) {
        this.#log.warn("event sender failed", { error: e instanceof Error ? e.message : "unknown" });
      } finally {
        this.#running = false;
      }
    })();
  }

  async #drain(): Promise<void> {
    const deps = this.#deps;
    if (!deps) return;
    // COMMITTED rows only (specs#33): never read or delete while a transaction is open on this connection (app code may hold
    // one across an await with raw BEGIN); look again shortly
    if (this.#inTx()) {
      this.#arm(TX_WAIT_MS);
      return;
    }
    const now = Date.now();
    // the bridge window: an unsent row older than 7 days would be outside its dedupe window anyway
    const pruned = Number(this.#db.prepare("DELETE FROM tb_event_outbox WHERE created_at < ?").run(now - EVENT_WINDOW_MS).changes ?? 0);
    if (pruned > 0) this.#log.info("event outbox rows pruned unsent after 7 days", { count: pruned });
    if (now < this.#retryAt) {
      this.#arm(this.#retryAt - now);
      return;
    }
    for (;;) {
      if (this.#stopped) return;
      // C292: by capability, never by bridge version; without the cap rows wait
      if (!deps.bridgeCaps().includes(EVENTS_CAP)) break;
      const bridge = deps.bridge();
      if (!bridge) break;
      if (this.#inTx()) {
        this.#arm(TX_WAIT_MS);
        return;
      }
      const rows = this.#db.prepare("SELECT id, kind, key, body FROM tb_event_outbox ORDER BY id LIMIT ?").all(this.#limit) as Row[];
      if (rows.length === 0) break;
      const batch: { id: string; item: EventIngestItem }[] = [];
      const drop: { id: string; why: string }[] = [];
      let bytes = 16;
      for (const r of rows) {
        const item = this.#item(r, deps);
        if ("drop" in item) {
          drop.push({ id: String(r.id), why: item.drop });
          continue;
        }
        const size = Buffer.byteLength(JSON.stringify(item)) + 1;
        if (batch.length > 0 && bytes + size > BATCH_MAX_BYTES) break;
        bytes += size;
        batch.push({ id: String(r.id), item });
        // a batch ENDS after a purge (specs#33): a lost answer + retry never re-sends a purge ahead of a later event
        if (item.kind === "purge") break;
      }
      if (drop.length > 0) {
        const del = this.#db.prepare("DELETE FROM tb_event_outbox WHERE id = ?");
        for (const d of drop) {
          this.#log.warn("event dropped before sending", { reason: d.why });
          del.run(d.id);
        }
      }
      if (batch.length === 0) continue;
      const ac = new AbortController();
      this.#abort = ac;
      let res: BridgeResponse;
      try {
        res = await bridge.request("POST", BRIDGE_INTERNAL_PATHS.events, { items: batch.map((b) => b.item) }, {}, ac.signal);
      } catch (e) {
        if (this.#stopped) return;
        this.#fail(`transport: ${e instanceof TbError ? e.code : "error"}`);
        return;
      } finally {
        this.#abort = null;
      }
      if (res.status === 413) {
        if (batch.length > 1) {
          // halve and retry at once, down to one item
          this.#limit = Math.max(1, Math.floor(batch.length / 2));
          this.#failures++;
          continue;
        }
        // one item still too large: a permanent refusal, so one oversized row never blocks the outbox
        await this.#settled();
        const one = batch[0] as (typeof batch)[number];
        this.#log.warn("event refused by the bridge", { kind: one.item.kind, name: one.item.kind === "emit" ? one.item.name : null, key: one.item.key, code: "event_too_large" });
        this.#db.prepare("DELETE FROM tb_event_outbox WHERE id = ?").run(one.id);
        this.#limit = Math.min(EVENT_BATCH_MAX, this.#limit * 2);
        this.#failures = 0;
        continue;
      }
      const results = res.status === 200 && isObj(res.body) && Array.isArray(res.body.results) ? (res.body as unknown as EventIngestResult).results : null;
      const answered =
        results !== null &&
        results.length === batch.length &&
        results.every((r, i) => isObj(r) && r.key === batch[i]?.item.key && (r.status === "stored" || r.status === "duplicate" || r.status === "refused"));
      if (!answered) {
        // 401, 429, 5xx, 503 app_not_claimed, any other status, or a 200 that does not answer every item with its own key in
        // order: retry the whole batch (same keys, the bridge dedupes)
        this.#fail(`bridge answered ${res.status}${res.status === 200 ? " without one result per item (its own key, in order)" : ""}`);
        return;
      }
      this.#backoff = 0;
      this.#retryAt = 0;
      this.#failures = 0;
      this.#limit = Math.min(EVENT_BATCH_MAX, this.#limit * 2);
      await this.#settled();
      const del = this.#db.prepare("DELETE FROM tb_event_outbox WHERE id = ?");
      batch.forEach((b, i) => {
        const r = (results as EventIngestResult["results"])[i];
        if (r?.status === "refused") this.#log.warn("event refused by the bridge", { kind: b.item.kind, name: b.item.kind === "emit" ? b.item.name : null, key: b.item.key, code: typeof r.code === "string" ? r.code : "refused" });
        del.run(b.id);
      });
    }
    this.#arm(SENDER_FALLBACK_MS);
  }

  /** a transaction is open on the connection (node:sqlite `isTransaction`; false where the runtime lacks it) */
  #inTx(): boolean {
    return (this.#db as RawDb & { isTransaction?: boolean }).isTransaction === true;
  }

  /** waits until no transaction is open (deletes of sent rows never join an app transaction that may roll back) */
  async #settled(): Promise<void> {
    while (this.#inTx()) await new Promise((r) => setTimeout(r, TX_WAIT_MS));
  }

  #fail(reason: string): void {
    this.#failures++;
    this.#backoff = this.#backoff === 0 ? this.#backoffMin : Math.min(this.#backoffMax, this.#backoff * 2);
    this.#retryAt = Date.now() + this.#backoff;
    this.#log.warn("event send failed; retrying", { reason, retryInMs: this.#backoff, failures: this.#failures });
    this.#arm(this.#backoff);
  }

  /**
   * The wire item of one row, or `{drop}`. A scoped emit gets `eligible` NOW (MANIFEST §16.2 rule 2): agent rows on (scopeType,
   * instanceId) whose effective crud ⊇ visibleWith.crud, LIMITED to agents in the current verified slice, at most 500, ∩ `to` for
   * a target event. A row whose scope type changed since the emit (an app update) is dropped, never sent with `eligible` computed
   * on another type (SDK-API §20, specs#33).
   */
  #item(r: Row, deps: SenderDeps): EventIngestItem | { drop: string } {
    const parsed = JSON.parse(String(r.body)) as EmitBody | PurgeBody;
    if (parsed.kind !== "emit") return parsed;
    const { scopeType: recorded, ...body } = parsed;
    const decl = eventDecl(this.#m, body.name);
    // undeclared now (an update removed the event): sent as it is, the bridge refuses it (event_undeclared) and the row goes
    if (!decl) return body;
    const type = eventScopeType(this.#m, decl);
    if (recorded !== undefined && recorded !== type) return { drop: `event ${body.name}: scope type ${recorded ?? "none"} at emit, ${type ?? "none"} now` };
    if (!type || body.instanceId === undefined) return body;
    const need: CrudAction[] = eventVisibleCrud(this.#m, decl);
    const to = body.to ? new Set<string>(body.to) : null;
    const eligible: EventEligible[] = deps
      .rowsOn(type, body.instanceId)
      .filter((row) => row.agent.startsWith("agt_") && deps.inSlice(row.agent) && subset(need, row.crud ?? []) && (to === null || to.has(row.agent)))
      .slice(0, EVENT_ELIGIBLE_MAX)
      .map((row) => ({ agent: row.agent, authority: row.authority === "owner" ? "owner" : "bounded" }));
    return { ...body, eligible };
  }
}
