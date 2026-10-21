// A reference per-agent event log (BRIDGE §14, MANIFEST §16.2; spec 0.1.57, C274c/C274d) for the conformance doubles: the
// fake bridge of the app target (POST /tb/v1/events + the `tealbrick/events/*` methods) and the test mini bridge. NOT a product
// bridge: one process, memory only. The declaration lookup, the payload check and the grant rule come from
// @opt2-tealbrick/manifest (eventDecl, validateEventPayload, eventVisibleToGrant: L1). Faults (`EventLogFaults`) break exactly
// one rule each so the sensitivity tests can show the matching B-EV row flips from pass to fail.
import {
  canonicalize,
  EVENT_BATCH_MAX,
  EVENT_DATA_MAX_BYTES,
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
  eventVisibleToGrant,
  isReservedEventName,
  type ResolvedEventDecl,
  ulid,
  validateEventPayload,
} from "@opt2-tealbrick/manifest";
import { type AgentEvent, EVENT_MCP_METHODS, type EventIngestResult, type EventRefuseCode, type EventsListResult, type EventsPollResult, PLATFORM_EVENTS } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

/** Retention per agent (C274d ruling 3): 7 days or 10 000 rows, whichever first. */
export const EVENT_RETENTION_ROWS = 10_000;
export const EVENT_ITEM_MAX_BYTES = 4096;
const ULID_RE = /^[0-9A-HJKMNP-TV-Z]{26}$/;
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** What the log needs to know about the world (the bridge's own state). */
export interface EventLogWorld {
  /** the serving manifest of an app instance (null = not deployed) */
  manifest(ins: InstanceId): Manifest | null;
  /** every agent with a grant (any) to `ins`, in a stable order */
  grantees(ins: InstanceId): AgentId[];
  /** the VALID grant claims of `agent` for `ins` (null = none, revoked or expired) */
  claims(agent: AgentId, ins: InstanceId): { mode: string; wf: readonly string[]; crud: readonly CrudAction[] } | null;
  /** agent or workspace pause (holds the whole stream) */
  agentPaused(agent: AgentId): boolean;
  /** app instance pause (holds that instance's rows) */
  instancePaused(ins: InstanceId): boolean;
  /** an enabled before/after hook matches the op of that app (MANIFEST §16.2 rule 6) */
  hookMatches(ins: InstanceId, opId: string): boolean;
}

/** One rule broken on purpose (test doubles only). */
export interface EventLogFaults {
  /** delivers to the causing agent (rule 3) */
  deliverToCause?: boolean;
  /** ignores `eligible` (rule 2): every candidate with a grant gets a scoped event */
  ignoreEligible?: boolean;
  /** no re-check at delivery: a revoked grant still gets its stored rows */
  noDeliveryRecheck?: boolean;
  /** keeps the summary when a hook matches (rule 6) */
  keepSummaryWithHook?: boolean;
  /** no dedupe by (instance, key) */
  noDedupe?: boolean;
  /** a held row keeps its old id on resume (the cursor skips it) */
  noReId?: boolean;
  /** never answers truncated */
  noTruncated?: boolean;
  /** accepts app names in tb. and product tb */
  noReserved?: boolean;
  /** stores events whose payload fails the schema */
  noPayloadCheck?: boolean;
  /** purge does nothing */
  noPurge?: boolean;
}

interface Row {
  id: string;
  origin: string;
  ingestAt: number;
  ins: InstanceId;
  /** the declaration the row was checked against (name) and its op / scope type at write time */
  name: string;
  opId: string;
  scopeType: string | null;
  authority: "owner" | "bounded" | null;
  held: boolean;
  event: Omit<AgentEvent, "id" | "origin">;
}

type ItemResult = EventIngestResult["results"][number];

export class EventLog {
  readonly #w: EventLogWorld;
  readonly faults: EventLogFaults;
  readonly #rows = new Map<AgentId, Row[]>();
  readonly #keys = new Map<string, number>();
  readonly #dropped = new Map<AgentId, string>();
  readonly #truncFlag = new Set<AgentId>();
  readonly #subs = new Map<AgentId, Set<(e: AgentEvent) => void>>();
  /** test clock (ms) */
  now: () => number = Date.now;

  constructor(world: EventLogWorld, faults: EventLogFaults = {}) {
    this.#w = world;
    this.faults = faults;
  }

  /** Rows stored for an agent (tests). */
  stored(agent: AgentId): readonly Row[] {
    return this.#rows.get(agent) ?? [];
  }

  // ── ingest (BRIDGE §14.1) ───────────────────────────────────────────────────
  ingest(ins: InstanceId, product: string, items: unknown[]): EventIngestResult {
    this.#syncPauses();
    return { results: items.slice(0, EVENT_BATCH_MAX).map((it) => this.#one(ins, product, it)) };
  }

  #one(ins: InstanceId, product: string, it: unknown): ItemResult {
    const key = isObj(it) && typeof it.key === "string" ? it.key : "";
    const refuse = (code: EventRefuseCode): ItemResult => ({ key, status: "refused", code });
    if (!isObj(it)) return refuse("event_payload_invalid");
    if (it.kind === "purge") {
      if (typeof it.instanceId !== "string" || !EVENT_KEY_RE.test(key)) return refuse("event_payload_invalid");
      if (!this.faults.noPurge) this.purge(ins, it.instanceId, typeof it.agent === "string" ? (it.agent as AgentId) : null);
      return { key, status: "stored" };
    }
    if (it.kind !== "emit" || typeof it.name !== "string") return refuse("event_payload_invalid");
    const m = this.#w.manifest(ins);
    if (!m) return refuse("event_undeclared");
    // 1. the declaration
    if (!this.faults.noReserved && (product === "tb" || (isReservedEventName(it.name) && !Object.hasOwn(PLATFORM_EVENTS, it.name)))) return refuse("event_reserved");
    const decl: ResolvedEventDecl | null = eventDecl(m, it.name);
    if (!decl && this.faults.noReserved && isReservedEventName(it.name)) return refuse("event_undeclared");
    if (!decl) return refuse("event_undeclared");
    // 2. shape
    if (!EVENT_KEY_RE.test(key)) return refuse("event_payload_invalid");
    const s = it.subject;
    if (!isObj(s) || typeof s.kind !== "string" || !EVENT_SUBJECT_KIND_RE.test(s.kind) || typeof s.id !== "string" || s.id.length < 1 || s.id.length > EVENT_SUBJECT_ID_MAX) return refuse("event_payload_invalid");
    if (typeof it.at !== "string") return refuse("event_payload_invalid");
    if (it.summary !== undefined && (typeof it.summary !== "string" || it.summary.length > EVENT_SUMMARY_MAX)) return refuse(typeof it.summary === "string" ? "event_too_large" : "event_payload_invalid");
    if (Buffer.byteLength(JSON.stringify(it)) > EVENT_ITEM_MAX_BYTES) return refuse("event_too_large");
    if (!this.faults.noPayloadCheck) {
      const p = validateEventPayload(decl, it.data);
      if (!p.ok) return refuse(p.code);
    } else if (!isObj(it.data) || Buffer.byteLength(canonicalize(it.data as Json)) > EVENT_DATA_MAX_BYTES) return refuse("event_too_large");
    if (Array.isArray(it.eligible) && it.eligible.length > EVENT_ELIGIBLE_MAX) return refuse("event_payload_invalid");
    // 3. scoped ⇔ instanceId and eligible
    const scopeType = eventScopeType(m, decl);
    const hasIns = typeof it.instanceId === "string" && it.instanceId.length >= 1 && it.instanceId.length <= EVENT_INSTANCE_ID_MAX;
    if (scopeType !== null ? !hasIns || !Array.isArray(it.eligible) : it.instanceId !== undefined || it.eligible !== undefined) return refuse("event_instance_invalid");
    // 4. audience
    const to = it.to;
    if (decl.audience === "target" ? !Array.isArray(to) || to.length < 1 || to.length > EVENT_TO_MAX || !to.every((a) => typeof a === "string") : to !== undefined) return refuse("event_target_invalid");
    // 5. dedupe per (app instance, key), 7 days
    const now = this.now();
    for (const [k, at] of this.#keys) if (at < now - EVENT_WINDOW_MS) this.#keys.delete(k);
    const dk = `${ins}|${key}`;
    if (!this.faults.noDedupe && this.#keys.has(dk)) return { key, status: "duplicate" };
    this.#keys.set(dk, now);
    // fan-out at write time (MANIFEST §16.2 rules 1–4)
    const eligible = new Map<string, "owner" | "bounded">();
    if (Array.isArray(it.eligible)) for (const e of it.eligible) if (isObj(e) && typeof e.agent === "string") eligible.set(e.agent, e.authority === "owner" ? "owner" : "bounded");
    const candidates = decl.audience === "target" ? [...new Set(to as AgentId[])] : this.#w.grantees(ins);
    const causedBy = typeof it.causedBy === "string" ? (it.causedBy as AgentId) : undefined;
    let recipients = 0;
    const base = {
      type: decl.platform ? it.name : `${product}.${it.name}`,
      app: product as AgentEvent["app"],
      ...(scopeType !== null ? { instanceId: it.instanceId as string } : {}),
      at: it.at as AgentEvent["at"],
      subject: { kind: s.kind, id: s.id },
      ...(typeof it.summary === "string" ? { summary: it.summary } : {}),
      ...(it.untrusted === true ? { untrusted: true as const } : {}),
      data: it.data as AgentEvent["data"],
      ...(causedBy ? { causedBy } : {}),
    };
    for (const agent of candidates) {
      if (!this.faults.deliverToCause && agent === causedBy) continue;
      const authority = scopeType !== null ? (eligible.get(agent) ?? null) : null;
      if (scopeType !== null && authority === null && !this.faults.ignoreEligible) continue;
      const claims = this.#w.claims(agent, ins);
      if (!claims || !eventVisibleToGrant(m, decl, claims, authority)) continue;
      const id = ulid();
      const row: Row = { id, origin: id, ingestAt: now, ins, name: it.name, opId: decl.visibleWith, scopeType, authority, held: this.#w.instancePaused(ins), event: base };
      const list = this.#rows.get(agent) ?? [];
      list.push(row);
      this.#rows.set(agent, list);
      recipients++;
      this.#retain(agent);
      if (!row.held && !this.#w.agentPaused(agent)) this.#notify(agent);
    }
    return { key, status: "stored", recipients };
  }

  /** Deletes the stored rows of (agent | every agent, app instance, instanceId), delivered or not. */
  purge(ins: InstanceId, instanceId: string, agent: AgentId | null): void {
    for (const [a, list] of this.#rows) {
      if (agent !== null && a !== agent) continue;
      this.#rows.set(
        a,
        list.filter((r) => !(r.ins === ins && r.event.instanceId === instanceId)),
      );
    }
  }

  #retain(agent: AgentId): void {
    const list = this.#rows.get(agent) ?? [];
    const now = this.now();
    // cheap exit: within the row limit and the oldest row (rows are kept in id order ≈ ingest order) inside the window
    if (list.length <= EVENT_RETENTION_ROWS && (list[0]?.ingestAt ?? now) >= now - EVENT_WINDOW_MS) return;
    const byIngest = [...list].sort((x, y) => x.ingestAt - y.ingestAt || (x.origin < y.origin ? -1 : 1));
    const drop = new Set<Row>();
    for (const r of byIngest) if (r.ingestAt < now - EVENT_WINDOW_MS) drop.add(r);
    const over = list.length - drop.size - EVENT_RETENTION_ROWS;
    for (let i = 0, n = 0; n < over && i < byIngest.length; i++) {
      const r = byIngest[i] as Row;
      if (drop.has(r)) continue;
      drop.add(r);
      n++;
    }
    if (drop.size === 0) return;
    let hi = this.#dropped.get(agent) ?? "";
    for (const r of drop) {
      if (r.id > hi) hi = r.id;
      if (r.held) this.#truncFlag.add(agent);
    }
    this.#dropped.set(agent, hi);
    this.#rows.set(
      agent,
      list.filter((r) => !drop.has(r)),
    );
  }

  /** Applies instance resumes: held rows of a resumed instance get a NEW id, in old-id order (BRIDGE §14.2). */
  #syncPauses(): void {
    for (const [agent, list] of this.#rows) {
      const released = list.filter((r) => r.held && !this.#w.instancePaused(r.ins)).sort((x, y) => (x.id < y.id ? -1 : 1));
      if (released.length === 0) continue;
      for (const r of released) {
        r.held = false;
        if (!this.faults.noReId) r.id = ulid();
      }
      list.sort((x, y) => (x.id < y.id ? -1 : 1));
      this.#notify(agent);
    }
  }

  // ── delivery (BRIDGE §14.3) ──────────────────────────────────────────────────

  /** `tealbrick/events/list`. */
  list(agent: AgentId, instances: readonly InstanceId[]): EventsListResult {
    const types: EventsListResult["types"] = [];
    for (const ins of instances) {
      const m = this.#w.manifest(ins);
      const claims = this.#w.claims(agent, ins);
      if (!m || !claims) continue;
      for (const d of m.events ?? []) {
        const scoped = eventScopeType(m, d) !== null;
        if (!eventVisibleToGrant(m, d, claims, scoped ? "owner" : null)) continue;
        types.push({ type: `${m.id}.${d.name}`, app: m.id as AgentEvent["app"], title: d.title, payloadSchema: d.payloadSchema, scoped, delivery: ["poll", "stream"] });
      }
      const hd = PLATFORM_EVENTS["tb.hold.decided"];
      types.push({ type: "tb.hold.decided", app: m.id as AgentEvent["app"], title: hd.title, payloadSchema: hd.payloadSchema as never, scoped: false, delivery: ["poll", "stream"] });
    }
    return { types };
  }

  /** `tealbrick/events/poll`; `{error}` = JSON-RPC -32602 cursor_invalid. */
  poll(agent: AgentId, cursor: string | undefined, limit = 50): EventsPollResult | { error: "cursor_invalid" } {
    this.#syncPauses();
    if (cursor !== undefined && !ULID_RE.test(cursor)) return { error: "cursor_invalid" };
    if (this.#w.agentPaused(agent)) return { events: [], cursor: cursor ?? null, truncated: false, paused: true };
    this.#retain(agent);
    const truncated = this.#truncated(agent, cursor);
    const lim = Math.max(1, Math.min(100, Math.trunc(limit) || 50));
    const out: AgentEvent[] = [];
    const list = this.#rows.get(agent) ?? [];
    const keep: Row[] = [];
    for (const r of list) {
      if (out.length >= lim || (cursor !== undefined && r.id <= cursor)) {
        keep.push(r);
        continue;
      }
      if (this.#w.instancePaused(r.ins)) {
        r.held = true;
        keep.push(r);
        continue;
      }
      const e = this.#deliverable(agent, r);
      if (e === null) continue; // dropped (rule 1 failed or op gone)
      keep.push(r);
      out.push(e);
    }
    this.#rows.set(agent, keep);
    return { events: out, cursor: out.at(-1)?.id ?? cursor ?? null, truncated };
  }

  /** `tealbrick/events/stream`: the start position and `truncated`; frames go to `subscribe` listeners. */
  stream(agent: AgentId, cursor: string | undefined): { cursor: string | null; truncated: boolean; paused?: true } | { error: "cursor_invalid" } {
    if (cursor !== undefined && !ULID_RE.test(cursor)) return { error: "cursor_invalid" };
    if (this.#w.agentPaused(agent)) return { cursor: cursor ?? null, truncated: false, paused: true };
    return { cursor: cursor ?? null, truncated: this.#truncated(agent, cursor) };
  }

  /** Live frames for an agent (the SSE stream of the fake bridge). Returns an unsubscribe function. */
  subscribe(agent: AgentId, fn: (e: AgentEvent) => void): () => void {
    const set = this.#subs.get(agent) ?? new Set();
    set.add(fn);
    this.#subs.set(agent, set);
    return () => set.delete(fn);
  }

  #notify(agent: AgentId): void {
    const set = this.#subs.get(agent);
    if (!set?.size) return;
    const last = (this.#rows.get(agent) ?? []).at(-1);
    if (!last) return;
    const e = this.#deliverable(agent, last);
    if (e) for (const fn of set) fn(e);
  }

  #truncated(agent: AgentId, cursor: string | undefined): boolean {
    if (this.faults.noTruncated) return false;
    if (this.#truncFlag.delete(agent)) return true;
    const d = this.#dropped.get(agent);
    return d !== undefined && (cursor === undefined || cursor < d);
  }

  /** Rules 1 and 6 at delivery against the CURRENT manifest and grants; null = drop. */
  #deliverable(agent: AgentId, r: Row): AgentEvent | null {
    const m = this.#w.manifest(r.ins);
    if (!m) return this.faults.noDeliveryRecheck ? this.#envelope(r, false) : null;
    const isPlatform = isReservedEventName(r.name);
    const op = isPlatform ? null : m.operations.find((o) => o.id === r.opId);
    if (!isPlatform && (!op || (op.scopeType ?? null) !== r.scopeType)) return null;
    if (!this.faults.noDeliveryRecheck) {
      const claims = this.#w.claims(agent, r.ins);
      if (!claims || !eventVisibleToGrant(m, { visibleWith: r.opId as never }, claims, r.authority)) return null;
    }
    const strip = !this.faults.keepSummaryWithHook && this.#w.hookMatches(r.ins, r.opId);
    return this.#envelope(r, strip);
  }

  #envelope(r: Row, strip: boolean): AgentEvent {
    const { summary, ...rest } = r.event;
    return { id: r.id as AgentEvent["id"], origin: r.origin as AgentEvent["origin"], ...rest, ...(summary !== undefined && !strip ? { summary } : {}) };
  }

  /**
   * JSON-RPC dispatch of the three methods for one verified agent (`instances` = the app instances it may list). Returns the
   * JSON-RPC `result` or `error`, or null for a method this log does not serve.
   */
  rpc(agent: AgentId, instances: readonly InstanceId[], method: string, params: unknown): { result: unknown } | { error: { code: number; message: string; data?: unknown } } | null {
    const p = isObj(params) ? params : {};
    const cursor = typeof p.cursor === "string" ? p.cursor : undefined;
    const bad = { error: { code: -32602, message: "cursor not issued by this bridge", data: { code: "cursor_invalid" } } };
    if (method === EVENT_MCP_METHODS.list) return { result: this.list(agent, instances) };
    if (method === EVENT_MCP_METHODS.poll) {
      const r = this.poll(agent, cursor, typeof p.limit === "number" ? p.limit : 50);
      return "error" in r ? bad : { result: r };
    }
    if (method === EVENT_MCP_METHODS.stream) {
      const r = this.stream(agent, cursor);
      return "error" in r ? bad : { result: r };
    }
    return null;
  }
}
