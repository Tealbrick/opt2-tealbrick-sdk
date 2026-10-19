// Receipts and holds — ONE table `tb_receipts` (SDK-API §4); idempotency results in `tb_idempotency` (§4.4).
import { ulid } from "@opt2-tealbrick/manifest";
import type { FreeCaps, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { Effect, HoldFamily } from "@opt2-tealbrick/spec/manifest";
import type { AdmittedBy, Json, Receipt, ReceiptQuery, ReceiptStatus, ReceiptStore } from "@opt2-tealbrick/spec/sdk";
import { clampLimit, decodeCursor, encodeCursor } from "./audit.ts";
import { type RawDb, type Row, tx } from "./store.ts";

export const HOLD_TTL_MS = 15 * 60_000;
/** After approval the agent repeats the same call within 15 min (§4.3). */
export const APPROVAL_WINDOW_MS = 15 * 60_000;
export const IDEMPOTENCY_TTL_MS = 24 * 3600_000;
export const RECEIPT_RETENTION_MS = 90 * 86400_000;
const CAP_WINDOW_MS = { hour: 3600_000, day: 86400_000 } as const;
/** v0.1.13 (G4): tb.holds_pending page size (1..100, default 50) */
export const HOLDS_PENDING_MAX = 100;

/**
 * v0.1.13: the reason shown by tb.hold_status / tb.holds_pending — the stored hook verdict reason or SDK hold reason;
 * rows from before 0.1.13 (no `hold_reason`) derive the SDK reason code from the family. Never input, view or meta.
 */
export function holdReasonOf(stored: unknown, family: unknown): string {
  if (typeof stored === "string" && stored !== "") return stored;
  return family === "money" ? "held_money" : family === "caps" ? "caps_exceeded" : "held_family";
}

/** One pending hold (status `held`) as a summary row (tb.holds_pending): no input, view or meta. */
export interface PendingHoldRow {
  id: string;
  op: string;
  family: Receipt["holdFamily"];
  reason: string;
  heldBy: string | null;
  summary: string;
  caller: Receipt["caller"];
  createdAt: number;
}

export interface NewReceipt {
  kind: "hld" | "rcp";
  callId: Receipt["callId"];
  caller: Receipt["caller"];
  op: string;
  effect: Effect;
  holdFamily: HoldFamily | "caps" | "policy" | null;
  /** v0.1.13 (G1): `<product>/<hookId>` of the before hook whose verdict held the call */
  heldBy?: string | null;
  /** v0.1.13: hook verdict reason or the SDK hold reason code (never input, view or meta; C90) */
  holdReason?: string | null;
  /** v0.1.35 (C283 A1, S7): which rule admitted a SCOPED call; absent for unscoped and refused calls */
  admittedBy?: AdmittedBy | null;
  status: ReceiptStatus;
  inputDigest: Sha256Digest;
  summary: string;
  meta: Json;
  idempotencyKey: string | null;
  view?: string | null;
  expiresAt?: number | null;
}

/**
 * One `tb_idempotency` row (§4.4). v0.1.22 (SDK-01): `pending` = reserved before the handler runs (one wins, the INSERT
 * is the lock); `unknown` = a pending row of a process that died mid-run (boot recovery): the outcome is unknown, so the
 * key is never run again — it answers 409 `idempotency_outcome_unknown` until its 24 h life ends.
 */
export type IdempotencyRow =
  | { kind: "result"; inputDigest: string; output: string }
  | { kind: "held"; inputDigest: string; holdId: string }
  | { kind: "pending"; inputDigest: string }
  | { kind: "unknown"; inputDigest: string };

/** Effects with a Free cap (CORE I14); `money` has none (always held), `read` none. */
export type CappedEffect = "write" | "outward" | "destructive";
export const CAPPED_EFFECTS: readonly CappedEffect[] = ["write", "outward", "destructive"];
export const isCappedEffect = (e: string): e is CappedEffect => (CAPPED_EFFECTS as readonly string[]).includes(e);

/** The stored caller; `product` (v0.1.27, SDK-CALLER-PRODUCT) only for an app caller whose receipt recorded one (older rows: absent). */
function callerOf(r: Row): Receipt["caller"] {
  const type = String(r.caller_type) as "agent" | "app";
  const caller: Receipt["caller"] = { type, id: String(r.caller_id) as Receipt["caller"]["id"], name: String(r.caller_name) };
  if (type === "app" && typeof r.caller_product === "string" && r.caller_product !== "") caller.product = r.caller_product as NonNullable<Receipt["caller"]["product"]>;
  return caller;
}

function toReceipt(r: Row, withView: boolean): Receipt {
  const rec: Receipt = {
    id: String(r.id) as Receipt["id"],
    callId: (r.call_id as Receipt["callId"]) ?? null,
    caller: callerOf(r),
    op: String(r.op),
    effect: String(r.effect) as Effect,
    holdFamily: (r.hold_family as Receipt["holdFamily"]) ?? null,
    heldBy: (r.held_by as string | null | undefined) ?? null,
    ...(r.admitted_by === "app_owner_row" || r.admitted_by === "portal_grant" ? { admittedBy: r.admitted_by } : {}),
    status: String(r.status) as ReceiptStatus,
    inputDigest: String(r.input_digest) as Sha256Digest,
    summary: String(r.summary),
    meta: JSON.parse(String(r.meta)) as Json,
    idempotencyKey: (r.idempotency_key as string | null) ?? null,
    createdAt: Number(r.created_at),
    decidedAt: r.decided_at === null ? null : Number(r.decided_at),
    expiresAt: r.expires_at === null ? null : Number(r.expires_at),
    decidedBy: (r.decided_by as Receipt["decidedBy"]) ?? null,
  };
  if (withView && typeof r.view === "string") rec.view = r.view;
  return rec;
}

function toIdemRow(r: Row): IdempotencyRow {
  const inputDigest = String(r.input_digest);
  if (r.kind === "held") return { kind: "held", inputDigest, holdId: String(r.hold_id) };
  if (r.kind === "pending") return { kind: "pending", inputDigest };
  if (r.kind === "unknown") return { kind: "unknown", inputDigest };
  return { kind: "result", inputDigest, output: String(r.output) };
}

export class Receipts implements ReceiptStore {
  readonly #db: RawDb;
  constructor(db: RawDb) {
    this.#db = db;
  }

  async get(id: Receipt["id"]): Promise<Receipt | null> {
    return this.getSync(id);
  }
  getSync(id: string): Receipt | null {
    const r = this.#db.prepare("SELECT * FROM tb_receipts WHERE id = ?").get(id) as Row | undefined;
    return r ? toReceipt(r, true) : null;
  }

  async list(q: ReceiptQuery): Promise<{ items: Receipt[]; nextCursor: string | null }> {
    const limit = clampLimit(q.limit);
    const cur = decodeCursor(q.cursor);
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (q.caller) {
      where.push("caller_id = ?");
      args.push(q.caller);
    }
    if (q.op) {
      where.push("op = ?");
      args.push(q.op);
    }
    const statuses = q.status === undefined ? [] : Array.isArray(q.status) ? q.status : [q.status];
    if (statuses.length) {
      where.push(`status IN (${statuses.map(() => "?").join(",")})`);
      args.push(...statuses);
    }
    if (cur) {
      where.push("(created_at < ? OR (created_at = ? AND id < ?))");
      args.push(cur.at, cur.at, cur.id);
    }
    const rows = this.#db
      .prepare(`SELECT * FROM tb_receipts ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC, id DESC LIMIT ?`)
      .all(...args, limit + 1) as Row[];
    const items = rows.slice(0, limit).map((r) => toReceipt(r, true));
    const last = items.at(-1);
    return { items, nextCursor: rows.length > limit && last ? encodeCursor(last.createdAt, last.id) : null };
  }

  async usage(caller: string, caps: FreeCaps, now: number): Promise<Partial<Record<Effect, number>>> {
    return this.usageSync(caller, caps, now);
  }

  /**
   * v0.1.22 (SDK-02): Free cap counters no longer depend on receipts. Usage = this caller's cap slots (`tb_cap_usage`:
   * every run of a write/outward/destructive op, receipt or not, reserved BEFORE the handler and given back only when
   * the run fails or is refused) + its approved, not yet consumed holds of that effect, inside the cap window.
   */
  usageSync(caller: string, caps: FreeCaps, now: number): Partial<Record<Effect, number>> {
    const out: Partial<Record<Effect, number>> = {};
    const slots = this.#db.prepare("SELECT COUNT(*) AS n FROM tb_cap_usage WHERE caller_id = ? AND effect = ? AND created_at >= ?");
    const approved = this.#db.prepare(
      "SELECT COUNT(*) AS n FROM tb_receipts WHERE caller_id = ? AND effect = ? AND status = 'approved' AND consumed = 0 AND created_at >= ?",
    );
    for (const [effect, cap] of Object.entries(caps) as [Effect, { max: number; per: "hour" | "day" } | undefined][]) {
      if (!cap) continue;
      const since = now - CAP_WINDOW_MS[cap.per];
      out[effect] = Number((slots.get(caller, effect, since) as Row).n) + Number((approved.get(caller, effect, since) as Row).n);
    }
    return out;
  }

  /**
   * v0.1.22 (SDK-02): counts usage, decides and — when the decision is `run` and the effect is capped — reserves the cap
   * slot, all in ONE immediate transaction (a concurrent burst cannot beat the cap). Returns the decision and the slot id.
   */
  decideAndReserve<D extends { decision: string }>(caller: string, caps: FreeCaps, effect: Effect, op: string, now: number, decide: (usage: Partial<Record<Effect, number>>) => D): { decision: D; slot: string | null } {
    return tx(this.#db, () => {
      const decision = decide(this.usageSync(caller, caps, now));
      if (decision.decision !== "run" || !isCappedEffect(effect)) return { decision, slot: null };
      const slot = `cap_${ulid(now)}`;
      this.#db.prepare("INSERT INTO tb_cap_usage (id, caller_id, effect, op, state, created_at) VALUES (?, ?, ?, ?, 'reserved', ?)").run(slot, caller, effect, op, now);
      return { decision, slot };
    });
  }
  /** The run happened (or its outcome is unknown: fail closed) → the slot stays counted. */
  capCommit(slot: string): void {
    this.#db.prepare("UPDATE tb_cap_usage SET state = 'used' WHERE id = ?").run(slot);
  }
  /** The run failed or was refused before it ran → the slot is given back (spec: failed runs do not count). */
  capRelease(slot: string): void {
    this.#db.prepare("DELETE FROM tb_cap_usage WHERE id = ?").run(slot);
  }

  async holdStatus(caller: string, holdId: string): Promise<{ status: ReceiptStatus; decidedAt: number | null; expiresAt: number | null } | null> {
    const r = this.holdStatusSync(caller, holdId);
    return r ? { status: r.status, decidedAt: r.decidedAt, expiresAt: r.expiresAt } : null;
  }

  /** holdStatus plus (v0.1.13 clarification) the hold `family` and `reason` (hook verdict reason or SDK hold reason). */
  holdStatusSync(
    caller: string,
    holdId: string,
  ): { status: ReceiptStatus; decidedAt: number | null; expiresAt: number | null; family: Receipt["holdFamily"]; reason: string } | null {
    const r = this.#db
      .prepare("SELECT status, decided_at, expires_at, hold_family, hold_reason FROM tb_receipts WHERE id = ? AND caller_id = ? AND id LIKE 'hld\\_%' ESCAPE '\\'")
      .get(holdId, caller) as Row | undefined;
    if (!r) return null;
    return {
      status: String(r.status) as ReceiptStatus,
      decidedAt: r.decided_at === null ? null : Number(r.decided_at),
      expiresAt: r.expires_at === null ? null : Number(r.expires_at),
      family: (r.hold_family as Receipt["holdFamily"]) ?? null,
      reason: holdReasonOf(r.hold_reason, r.hold_family),
    };
  }

  /** v0.1.13: the stored hold reason of a hold (person page), null for a non-hold id. */
  holdReason(id: string): string | null {
    const r = this.#db.prepare("SELECT hold_family, hold_reason FROM tb_receipts WHERE id = ? AND id LIKE 'hld\\_%' ESCAPE '\\'").get(id) as Row | undefined;
    return r ? holdReasonOf(r.hold_reason, r.hold_family) : null;
  }

  /**
   * v0.1.13 (G4): pending (`held`, not yet expired) holds, oldest first; `caller` null = every caller of the instance.
   * Summary columns only (never input digest, view or meta).
   */
  pending(q: { caller: string | null; limit?: number; cursor?: string }, now: number): { items: PendingHoldRow[]; nextCursor: string | null } {
    const limit = clampLimit(q.limit, HOLDS_PENDING_MAX);
    const cur = decodeCursor(q.cursor);
    const where = ["status = 'held'", "(expires_at IS NULL OR expires_at > ?)"];
    const args: (string | number)[] = [now];
    if (q.caller !== null) {
      where.push("caller_id = ?");
      args.push(q.caller);
    }
    if (cur) {
      where.push("(created_at > ? OR (created_at = ? AND id > ?))");
      args.push(cur.at, cur.at, cur.id);
    }
    const rows = this.#db
      .prepare(
        `SELECT id, op, hold_family, hold_reason, held_by, summary, caller_type, caller_id, caller_name, caller_product, created_at FROM tb_receipts
          WHERE ${where.join(" AND ")} ORDER BY created_at ASC, id ASC LIMIT ?`,
      )
      .all(...args, limit + 1) as Row[];
    const items = rows.slice(0, limit).map(
      (r): PendingHoldRow => ({
        id: String(r.id),
        op: String(r.op),
        family: (r.hold_family as Receipt["holdFamily"]) ?? null,
        reason: holdReasonOf(r.hold_reason, r.hold_family),
        heldBy: (r.held_by as string | null) ?? null,
        summary: String(r.summary),
        caller: callerOf(r),
        createdAt: Number(r.created_at),
      }),
    );
    const last = items.at(-1);
    return { items, nextCursor: rows.length > limit && last ? encodeCursor(last.createdAt, last.id) : null };
  }

  // ── internal (SDK only) ──
  insert(n: NewReceipt, now = Date.now()): Receipt {
    const id = `${n.kind}_${ulid(now)}`;
    this.#db
      .prepare(
        `INSERT INTO tb_receipts (id, call_id, caller_type, caller_id, caller_name, op, effect, hold_family, status, input_digest,
          summary, meta, idempotency_key, view, created_at, expires_at, held_by, hold_reason, caller_product, admitted_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        n.callId,
        n.caller.type,
        n.caller.id,
        n.caller.name,
        n.op,
        n.effect,
        n.holdFamily,
        n.status,
        n.inputDigest,
        n.summary,
        JSON.stringify(n.meta ?? null),
        n.idempotencyKey,
        n.view ?? null,
        now,
        n.expiresAt ?? null,
        n.heldBy ?? null,
        n.holdReason ?? null,
        n.caller.type === "app" ? (n.caller.product ?? null) : null,
        n.admittedBy ?? null,
      );
    return this.getSync(id) as Receipt;
  }

  /** Terminal statuses drop the hold view (§4.1). */
  finish(id: string, status: ReceiptStatus, patch: { summary?: string; meta?: Json; consumed?: boolean; admittedBy?: AdmittedBy } = {}): void {
    const keepView = status === "held" || status === "approved";
    this.#db
      .prepare(
        `UPDATE tb_receipts SET status = ?, summary = COALESCE(?, summary), meta = COALESCE(?, meta),
          consumed = CASE WHEN ? THEN 1 ELSE consumed END, view = CASE WHEN ? THEN view ELSE NULL END, admitted_by = COALESCE(?, admitted_by) WHERE id = ?`,
      )
      .run(status, patch.summary ?? null, patch.meta === undefined ? null : JSON.stringify(patch.meta), patch.consumed ? 1 : 0, keepView ? 1 : 0, patch.admittedBy ?? null, id);
  }

  decide(id: string, status: "approved" | "denied", by: Receipt["decidedBy"], now: number): void {
    this.#db
      .prepare(
        `UPDATE tb_receipts SET status = ?, decided_at = ?, decided_by = ?, expires_at = ?,
          view = CASE WHEN ? = 'approved' THEN view ELSE NULL END WHERE id = ? AND status = 'held'`,
      )
      .run(status, now, by, status === "approved" ? now + APPROVAL_WINDOW_MS : null, status, id);
  }

  /** The approved, unconsumed hold for this exact call (§4.3), if still inside its retry window. */
  findApproved(callerId: string, op: string, inputDigest: string, now: number): Receipt | null {
    const r = this.#db
      .prepare(
        "SELECT * FROM tb_receipts WHERE caller_id = ? AND op = ? AND input_digest = ? AND status = 'approved' AND consumed = 0 AND expires_at > ? ORDER BY decided_at DESC LIMIT 1",
      )
      .get(callerId, op, inputDigest, now) as Row | undefined;
    return r ? toReceipt(r, false) : null;
  }

  /** Atomically claims an approved row for execution; false if someone else consumed it first. */
  consume(id: string): boolean {
    return Number(this.#db.prepare("UPDATE tb_receipts SET consumed = 1 WHERE id = ? AND status = 'approved' AND consumed = 0").run(id).changes) === 1;
  }

  byCall(callId: string): Receipt | null {
    const r = this.#db.prepare("SELECT * FROM tb_receipts WHERE call_id = ? ORDER BY created_at DESC LIMIT 1").get(callId) as Row | undefined;
    return r ? toReceipt(r, false) : null;
  }

  pendingCount(): number {
    return Number((this.#db.prepare("SELECT COUNT(*) AS n FROM tb_receipts WHERE status = 'held'").get() as Row).n);
  }

  /** Expires pending holds (→ denied by "expiry"), drops views of lapsed approvals, purges old rows and keys. `expired`
   *  > 0 → the caller pushes the status (v0.1.13: statusChanged on hold expiry). */
  sweep(now: number): { expired: number } {
    const expired = Number(
      this.#db
        .prepare("UPDATE tb_receipts SET status = 'denied', decided_by = 'expiry', decided_at = ?, view = NULL WHERE status = 'held' AND expires_at <= ?")
        .run(now, now).changes,
    );
    this.#db.prepare("UPDATE tb_receipts SET view = NULL WHERE status = 'approved' AND view IS NOT NULL AND expires_at <= ?").run(now);
    this.#db.prepare("DELETE FROM tb_receipts WHERE created_at < ?").run(now - RECEIPT_RETENTION_MS);
    this.#db.prepare("DELETE FROM tb_idempotency WHERE expires_at <= ?").run(now);
    this.#db.prepare("DELETE FROM tb_cap_usage WHERE created_at < ?").run(now - CAP_WINDOW_MS.day);
    return { expired };
  }

  // ── idempotency (§4.4): key scope = (caller id, op, key) ──
  idemGet(callerId: string, op: string, key: string, now: number): IdempotencyRow | null {
    const r = this.#db
      .prepare("SELECT kind, input_digest, output, hold_id FROM tb_idempotency WHERE caller_id = ? AND op = ? AND key = ? AND expires_at > ?")
      .get(callerId, op, key, now) as Row | undefined;
    return r ? toIdemRow(r) : null;
  }

  /**
   * v0.1.22 (SDK-01): reserves `(caller, op, key)` BEFORE the handler runs. One INSERT wins (the primary key is the
   * lock; an expired row is taken over); a live row is returned to the caller instead (result, held, pending, unknown).
   */
  idemReserve(callerId: string, op: string, key: string, inputDigest: string, now: number): { kind: "reserved" } | { kind: "existing"; row: IdempotencyRow } {
    const won = this.#db
      .prepare(
        `INSERT INTO tb_idempotency (caller_id, op, key, input_digest, kind, output, hold_id, created_at, expires_at) VALUES (?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)
         ON CONFLICT (caller_id, op, key) DO UPDATE SET input_digest = excluded.input_digest, kind = 'pending', output = NULL, hold_id = NULL,
           created_at = excluded.created_at, expires_at = excluded.expires_at WHERE tb_idempotency.expires_at <= excluded.created_at`,
      )
      .run(callerId, op, key, inputDigest, now, now + IDEMPOTENCY_TTL_MS).changes;
    if (Number(won) === 1) return { kind: "reserved" };
    const r = this.#db.prepare("SELECT kind, input_digest, output, hold_id FROM tb_idempotency WHERE caller_id = ? AND op = ? AND key = ?").get(callerId, op, key) as Row | undefined;
    // the row vanished between the two statements (sweep): try once more
    return r ? { kind: "existing", row: toIdemRow(r) } : this.idemReserve(callerId, op, key, inputDigest, now);
  }
  /** A held key whose hold was decided (approved, or ended without a run): the retry takes it over (held → pending). */
  idemTakeHeld(callerId: string, op: string, key: string, holdId: string): boolean {
    return (
      Number(
        this.#db.prepare("UPDATE tb_idempotency SET kind = 'pending', hold_id = NULL WHERE caller_id = ? AND op = ? AND key = ? AND kind = 'held' AND hold_id = ?").run(callerId, op, key, holdId).changes,
      ) === 1
    );
  }
  /** The reserved run failed or was refused: the key is free again (a retry runs). */
  idemRelease(callerId: string, op: string, key: string): void {
    this.#db.prepare("DELETE FROM tb_idempotency WHERE caller_id = ? AND op = ? AND key = ? AND kind = 'pending'").run(callerId, op, key);
  }
  /** Boot: pending keys belong to a process that died mid-run → `unknown` (never re-run; they expire with the key). */
  idemRecoverCrashed(_now: number): number {
    return Number(this.#db.prepare("UPDATE tb_idempotency SET kind = 'unknown' WHERE kind = 'pending'").run().changes);
  }
  idemPut(callerId: string, op: string, key: string, inputDigest: string, v: { output: string } | { holdId: string }, now: number): void {
    this.#db
      .prepare(
        `INSERT INTO tb_idempotency (caller_id, op, key, input_digest, kind, output, hold_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (caller_id, op, key) DO UPDATE SET kind = excluded.kind, output = excluded.output, hold_id = excluded.hold_id`,
      )
      .run(
        callerId,
        op,
        key,
        inputDigest,
        "output" in v ? "result" : "held",
        "output" in v ? v.output : null,
        "holdId" in v ? v.holdId : null,
        now,
        now + IDEMPOTENCY_TTL_MS,
      );
  }
}
