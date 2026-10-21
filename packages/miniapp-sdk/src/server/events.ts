// App events (SDK-API §20, MANIFEST §16, BRIDGE §14; spec 0.1.57, C274c/C274d): `ctx.emit` / `ctx.purgeEvents` write ONE row
// of the transactional outbox `tb_event_outbox` (SDK schema 11) with the raw handle of the SAME connection, so the row shares
// the fate of the transaction that is open (rolled back → gone; committed → sent, even when the handler throws later). The
// sender drains the outbox in id order to `POST /tb/v1/events`, only while the slice says the bridge has the `events` cap.
import {
  EVENT_BATCH_MAX,
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
const AGENT_RE = /^agt_[0-9A-HJKMNP-TV-Z]{26}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const subset = (a: readonly string[], b: readonly string[]): boolean => a.every((x) => b.includes(x));

/** The outbox body of one row (`body` column): the ingest item without `eligible`, which the sender computes at SEND time. */
type EmitBody = Omit<EventEmitItem, "eligible">;
type PurgeBody = EventPurgeItem;

/** Who emits: `causedBy` = the verified agent caller of the op (absent for persons, apps, events, start, jobs). */
export interface EmitOrigin {
  causedBy?: AgentId;
}

/** What the sender needs from the running app (late-bound: the outbox exists before the bridge link). */
export interface SenderDeps {
  /** the claimed bridge client, or null (no claim yet / app-alone mode) */
  bridge(): { request(method: "POST", path: string, body: unknown): Promise<BridgeResponse> } | null;
  /** the CURRENT slice's `bridge.caps` (C292): the sender sends only while it includes "events"; never read for authorization */
  bridgeCaps(): readonly string[];
  /** the scope rows on one instance with their EFFECTIVE crud and authority (scopes.ts `rowsOn`) */
  rowsOn(type: string, instanceId: string): ScopeGrantRow[];
}

const bad = (code: string, message: string): TbError => new TbError(code, message, 400);

/**
 * THE outbox of one app process. `emit` / `purge` are synchronous writes; `start()` runs the sender (claimed bridge mode only).
 */
export class EventOutbox {
  readonly #db: RawDb;
  readonly #m: Manifest;
  readonly #log: Logger;
  /** scope types some declared event is scoped on (purge rows are written only for rows of these types) */
  readonly #scopedTypes: ReadonlySet<string>;
  #deps: SenderDeps | null = null;
  #timer: NodeJS.Timeout | null = null;
  #running = false;
  #again = false;
  #stopped = false;
  #backoff = 0;
  #retryAt = 0;
  #inflight: Promise<void> | null = null;

  constructor(db: RawDb, manifest: Manifest, log: Logger) {
    this.#db = db;
    this.#m = manifest;
    this.#log = log;
    const types = new Set<string>();
    for (const e of manifest.events ?? []) {
      const t = eventScopeType(manifest, e);
      if (t) types.add(t);
    }
    this.#scopedTypes = types;
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
   * row in the SAME transaction (the caller runs it inside the row change). Only agent rows of a type some event is scoped on.
   */
  rowNarrowed(agent: string, type: string, instanceId: string): void {
    if (!agent.startsWith("agt_") || !this.#scopedTypes.has(type)) return;
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
    if (typeof o.summary === "string" && o.summary.length > EVENT_SUMMARY_MAX) throw bad("event_too_large", `summary exceeds ${EVENT_SUMMARY_MAX} characters`);
    const scoped = eventScopeType(this.#m, decl) !== null;
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
    await this.#inflight?.catch(() => {});
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
    const now = Date.now();
    // the bridge window: an unsent row older than 7 days would be outside its dedupe window anyway
    const pruned = Number(this.#db.prepare("DELETE FROM tb_event_outbox WHERE created_at < ?").run(now - EVENT_WINDOW_MS).changes ?? 0);
    if (pruned > 0) this.#log.warn("event outbox rows pruned unsent after 7 days", { count: pruned });
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
      const rows = this.#db.prepare("SELECT id, kind, key, body FROM tb_event_outbox ORDER BY id LIMIT ?").all(EVENT_BATCH_MAX) as Row[];
      if (rows.length === 0) break;
      const batch: { id: string; item: EventIngestItem }[] = [];
      let bytes = 16;
      for (const r of rows) {
        const item = this.#item(r, deps);
        const size = Buffer.byteLength(JSON.stringify(item)) + 1;
        if (batch.length > 0 && bytes + size > BATCH_MAX_BYTES) break;
        bytes += size;
        batch.push({ id: String(r.id), item });
      }
      let res: BridgeResponse;
      try {
        res = await bridge.request("POST", BRIDGE_INTERNAL_PATHS.events, { items: batch.map((b) => b.item) });
      } catch (e) {
        this.#fail(`transport: ${e instanceof TbError ? e.code : "error"}`);
        return;
      }
      const results = res.status === 200 && isObj(res.body) && Array.isArray(res.body.results) ? (res.body as unknown as EventIngestResult).results : null;
      if (!results || results.length !== batch.length) {
        // 401/413/429/5xx/503 app_not_claimed, or a 200 that does not answer every item: retry the whole batch (same keys)
        this.#fail(`bridge answered ${res.status}${res.status === 200 ? " without one result per item" : ""}`);
        return;
      }
      this.#backoff = 0;
      this.#retryAt = 0;
      const del = this.#db.prepare("DELETE FROM tb_event_outbox WHERE id = ?");
      batch.forEach((b, i) => {
        const r = results[i];
        if (r?.status === "refused") this.#log.warn("event refused by the bridge", { kind: b.item.kind, name: b.item.kind === "emit" ? b.item.name : null, key: b.item.key, code: typeof r.code === "string" ? r.code : "refused" });
        del.run(b.id);
      });
    }
    this.#arm(SENDER_FALLBACK_MS);
  }

  #fail(reason: string): void {
    this.#backoff = this.#backoff === 0 ? BACKOFF_MIN_MS : Math.min(BACKOFF_MAX_MS, this.#backoff * 2);
    this.#retryAt = Date.now() + this.#backoff;
    this.#log.warn("event send failed; retrying", { reason, retryInMs: this.#backoff });
    this.#arm(this.#backoff);
  }

  /** The wire item of one row. A scoped emit gets `eligible` NOW (MANIFEST §16.2 rule 2), ∩ `to` for a target event. */
  #item(r: Row, deps: SenderDeps): EventIngestItem {
    const body = JSON.parse(String(r.body)) as EmitBody | PurgeBody;
    if (body.kind !== "emit") return body;
    const decl = eventDecl(this.#m, body.name);
    const type = decl ? eventScopeType(this.#m, decl) : null;
    if (!decl || !type || body.instanceId === undefined) return body;
    const need: CrudAction[] = eventVisibleCrud(this.#m, decl);
    const to = body.to ? new Set<string>(body.to) : null;
    const eligible: EventEligible[] = deps
      .rowsOn(type, body.instanceId)
      .filter((row) => row.agent.startsWith("agt_") && subset(need, row.crud ?? []) && (to === null || to.has(row.agent)))
      .map((row) => ({ agent: row.agent, authority: row.authority === "owner" ? "owner" : "bounded" }));
    return { ...body, eligible };
  }
}
