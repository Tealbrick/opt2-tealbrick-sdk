// v0.1.21 (Scribe R1, L6, SDK-1/SDK-2, RUL-11): THE background job mechanism of an app. One table `tb_jobs`, one
// runner per process. Every state change is ONE statement (claim, heartbeat, finish, pause, resume, cancel: UPDATE …
// RETURNING; enqueue: INSERT … ON CONFLICT DO NOTHING RETURNING), never check-then-write (QA SDK-01/02, L31). A claim
// takes a lease (token + expiry) that a heartbeat extends; every later write of that run is fenced by the token, so a
// worker that lost its lease (crash, timeout, pause, cancel) can never commit. A crashed run is resumed by the next
// claim once its lease expired; a stopping process releases its runs at once (L21: restarts are invisible).
//
// Two job sorts share the table and the runner:
// - handler jobs: `defineApp({ jobs: { <kind>: handler } })`, ticks that resume from the last `ctx.checkpoint(state)`;
// - scheduled ops (`ctx.schedule({ op, input }, { at | cron })`): fire-time `authorize()` with the stored caller
//   (ops.ts `fireScheduledOp`), so a paused, removed or revoked caller is refused when the op would run (CON-01).
import { CronError, digest, type ModelRole, nextCronTime, parseCron, type ResolvedModelRole, ulid, validateInput } from "@opt2-tealbrick/manifest";
import type { Caller, Db, Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";
import type { SdkEventContext } from "./context.ts";
import { TbError } from "./errors.ts";
import type { Runtime } from "./runtime.ts";
import { metaGet, metaSet, type RawDb, type Row, tx } from "./store.ts";
import { resolveCallerProduct } from "./trust.ts";

// ── limits and defaults ──────────────────────────────────────────────────────
export const JOB_KIND_RE = /^[a-z][a-z0-9_.-]{0,63}$/;
/** the internal kind of scheduled ops; app kinds may not start with `tb.` */
export const OP_JOB_KIND = "tb.op";
const KEY_RE = /^[\x21-\x7e]{1,128}$/;
export const JOB_INPUT_MAX_BYTES = 64 * 1024;
export const JOB_STATE_MAX_BYTES = 64 * 1024;
export const JOB_RESULT_MAX_BYTES = 16 * 1024;
/** `at` at most this far ahead (a cron has the manifest cron horizon) */
export const SCHEDULE_MAX_AHEAD_MS = 366 * 86_400_000;
export const JOB_DEFAULTS = {
  leaseMs: 30_000,
  timeoutMs: 10 * 60_000,
  maxAttempts: 5,
  backoffBaseMs: 1000,
  backoffMaxMs: 5 * 60_000,
} as const;
/** scheduled ops: one attempt by default (an outward op must not run twice after an unknown outcome, SDK-07) */
export const OP_JOB_MAX_ATTEMPTS = 1;
/** = ops.ts OP_TIMEOUT_MS: a scheduled op gets the same 30 s as a called one */
export const OP_JOB_TIMEOUT_MS = 30_000;
export const RUNNER_DEFAULTS = { pollMs: 1000, concurrency: 4, drainMs: 5000, onStopMs: 5000 } as const;
/** a scheduled op waiting for an owner decision re-checks its hold this often (a decision kicks it at once) */
export const HOLD_RECHECK_MS = 15_000;
/** a due job not started for this long (nothing pausing it) counts as stuck → attention `jobs_stuck` */
export const STUCK_AFTER_MS = 10 * 60_000;
/** terminal jobs are purged this long after they finished (their idempotency key is free again then) */
export const JOB_RETENTION_MS = 30 * 86_400_000;
const APP_PAUSE_KEY = "jobs_paused";
const GRANT_PURPOSE = "job-grant";

export type JobStatus = "queued" | "running" | "waiting" | "paused" | "done" | "failed" | "cancelled" | "refused";
export const TERMINAL: readonly JobStatus[] = ["done", "failed", "cancelled", "refused"];

/** A job as the app sees it (no grant, no lease token). Times are epoch ms. */
export interface Job {
  id: string;
  kind: string;
  key: string | null;
  input: Json;
  /** the cursor of the last `ctx.checkpoint(state)` (null before the first) */
  state: Json | null;
  status: JobStatus;
  /** scheduled op id (kind `tb.op`), else null */
  op: string | null;
  caller: { type: Caller["type"]; id: string; name: string } | null;
  runAt: number;
  cron: string | null;
  /** consecutive starts without a successful tick (a crash counts) */
  attempts: number;
  maxAttempts: number;
  lastError: string | null;
  result: Json | null;
  holdId: string | null;
  pausedBy: string | null;
  /** completed occurrences (cron) or ticks that returned `done` */
  runs: number;
  createdAt: number;
  updatedAt: number;
  finishedAt: number | null;
}

/** What a handler tick returns. `void` = done. */
export type JobOutcome =
  | { status: "done"; result?: Json; state?: Json }
  /** run again (live jobs, paging): `afterMs` from now (default 0), optional new cursor; resets `attempts` */
  | { status: "again"; afterMs?: number; state?: Json }
  /** a failure with a known wait (e.g. Retry-After): counts as an attempt; waits max(backoff, afterMs) */
  | { status: "retry"; afterMs?: number; error: string };

export interface JobContext extends SdkEventContext, JobsView {
  /** the job at claim time */
  job: Job;
  /** aborts on: timeout, lease lost, pause (job or app), cancel, app stop; pass it to every upstream call */
  signal: AbortSignal;
  /**
   * ONE transaction: the new cursor + the app's own writes (`write(db)`, synchronous) + a heartbeat. Throws
   * `job_lease_lost` (and writes nothing) when this run lost its lease, so a stale worker never commits (L31).
   */
  checkpoint<T = void>(state: Json, write?: (db: Db) => T): T;
  secrets: AppSecrets;
  getKey(name: string): Promise<string | null>;
  /** v0.1.63: the binding of a model role the manifest declares for `app` (SDK-API "v0.1.63 additions") */
  modelRole(role: ModelRole): Promise<ResolvedModelRole | null>;
  callServiceHelper<O = Json>(serviceId: string, path: string, body: Json): Promise<O>;
}
// biome-ignore lint/suspicious/noConfusingVoidType: a tick that returns nothing is done (handlers may omit the return)
export type JobHandler = (input: Json, ctx: JobContext) => Promise<JobOutcome | void>;
export interface JobSpec {
  run: JobHandler;
  /** default 5; a crash mid-tick counts */
  maxAttempts?: number;
  /** lease length, heartbeat every third of it; default 30 s (1 s .. 10 min) */
  leaseMs?: number;
  /** one tick; default 10 min; on timeout the signal aborts and the tick counts as failed */
  timeoutMs?: number;
  /** exponential backoff base/max; default 1 s / 5 min */
  backoffMs?: { base?: number; max?: number };
}

export type ScheduleTarget = { op: string; input: Json } | { job: string; input?: Json };
export type ScheduleWhen = { at: Date | number } | { cron: string };
export interface EnqueueOptions {
  /** idempotency key (per kind; per caller + op for scheduled ops): the same key + input returns the existing job */
  key?: string;
  /** first run (default now) */
  at?: Date | number;
  /** recurring (5-field cron, UTC); each occurrence runs once, missed ones coalesce */
  cron?: string;
  maxAttempts?: number;
}
export interface JobsApi {
  enqueue(kind: string, input?: Json, opts?: EnqueueOptions): Job;
  get(id: string): Job | null;
  list(q?: { kind?: string; status?: JobStatus | JobStatus[]; limit?: number }): Job[];
  /** queued | waiting | running → paused (a running handler tick aborts and resumes later from its checkpoint) */
  pause(id: string): Job;
  /** paused (or a failed handler job) → queued, now */
  resume(id: string): Job;
  /** → cancelled; a running scheduled op cannot be cancelled (`job_running`) */
  cancel(id: string): Job;
  /** every job of this app instance: nothing is claimed until resumeAll (running ticks abort and resume later) */
  pauseAll(): void;
  resumeAll(): void;
  appPaused(): boolean;
}
/** SDK-1 (R2): the slice pause as the SDK applies it to incoming calls (`TrustState.paused`) */
export interface PauseView {
  workspace: boolean;
  instance: boolean;
  agent: boolean;
}
/** ctx members added by v0.1.21 on OpContext, StartContext, EventContext and JobContext */
export interface JobsView {
  jobs: JobsApi;
  /** SDK-2: a scheduled op (fire-time authorize with this ctx's caller) or a scheduled handler job */
  schedule(target: ScheduleTarget, when: ScheduleWhen, opts?: { key?: string; maxAttempts?: number }): Job;
  /** SDK-1: slice pause for `agent` (default: this ctx's agent caller, else none) */
  paused(agent?: string | null): PauseView;
}

/** Status push summary (SPEC-GAP: AppStatus.jobs is not in spec 0.1.28; additive, readers ignore it). */
export interface JobsSummary {
  queued: number;
  running: number;
  waiting: number;
  paused: number;
  failed: number;
  stuck: number;
  appPaused: boolean;
}

// ── rows ─────────────────────────────────────────────────────────────────────
const parse = (v: unknown): Json | null => (typeof v === "string" ? (JSON.parse(v) as Json) : null);

export function toJob(r: Row): Job {
  return {
    id: String(r.id),
    kind: String(r.kind),
    key: (r.key as string | null) ?? null,
    input: parse(r.input) as Json,
    state: parse(r.state),
    status: String(r.status) as JobStatus,
    op: (r.op as string | null) ?? null,
    caller: r.caller_type ? { type: String(r.caller_type) as Caller["type"], id: String(r.caller_id), name: String(r.caller_name) } : null,
    runAt: Number(r.run_at),
    cron: (r.cron as string | null) ?? null,
    attempts: Number(r.attempts),
    maxAttempts: Number(r.max_attempts),
    lastError: (r.last_error as string | null) ?? null,
    result: parse(r.result),
    holdId: (r.hold_id as string | null) ?? null,
    pausedBy: (r.paused_by as string | null) ?? null,
    runs: Number(r.runs),
    createdAt: Number(r.created_at),
    updatedAt: Number(r.updated_at),
    finishedAt: r.finished_at === null || r.finished_at === undefined ? null : Number(r.finished_at),
  };
}

/** Internal row view for the runner (adds the lease token and the sealed grant). */
export interface ClaimedJob extends Job {
  token: string;
  leaseMs: number;
  timeoutMs: number;
  callerMode: string | null;
  grantSealed: string | null;
}
function toClaimed(r: Row): ClaimedJob {
  return {
    ...toJob(r),
    token: String(r.lease_token ?? ""),
    leaseMs: Number(r.lease_ms),
    timeoutMs: Number(r.timeout_ms),
    callerMode: (r.caller_mode as string | null) ?? null,
    grantSealed: (r.grant_sealed as string | null) ?? null,
  };
}

function jsonText(v: Json | undefined | null, max: number, code: string): string | null {
  if (v === undefined || v === null) return null;
  const s = JSON.stringify(v);
  if (Buffer.byteLength(s) > max) throw new TbError(code, `job value exceeds ${max} bytes`, 400);
  return s;
}
const toMs = (v: Date | number): number => (v instanceof Date ? v.getTime() : v);

export function backoffMs(attempts: number, base: number, max: number): number {
  return Math.min(max, base * 2 ** Math.max(0, attempts - 1));
}

export interface NewJob {
  kind: string;
  input: Json;
  key: string | null;
  runAt: number;
  cron: string | null;
  op: string | null;
  caller: { type: Caller["type"]; id: string; name: string; mode: string | null } | null;
  grantSealed: string | null;
  grantIat: number | null;
  maxAttempts: number;
  leaseMs: number;
  timeoutMs: number;
}

/**
 * The SQL of `tb_jobs`. Every method is one statement (or one transaction for checkpoint), safe across connections:
 * two processes on one data volume (a rolling restart) or two runners on one connection never both win a claim.
 */
export class JobStore {
  readonly #db: RawDb;
  constructor(db: RawDb) {
    this.#db = db;
  }

  /** INSERT … ON CONFLICT (dedupe) DO NOTHING RETURNING; an existing job with the same key + input is returned. */
  insert(n: NewJob, now: number): { job: Job; created: boolean } {
    const input = jsonText(n.input, JOB_INPUT_MAX_BYTES, "job_input_too_large") ?? "null";
    const inputDigest = digest(n.input ?? null);
    const dedupe = n.key === null ? null : n.op ? `${OP_JOB_KIND}\n${n.caller?.id ?? ""}\n${n.op}\n${n.key}` : `${n.kind}\n${n.key}`;
    const row = this.#db
      .prepare(
        `INSERT INTO tb_jobs (id, kind, dedupe, key, input, input_digest, state, status, run_at, cron, op, caller_type, caller_id,
           caller_name, caller_mode, grant_sealed, grant_iat, attempts, max_attempts, lease_ms, timeout_ms, runs, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, NULL, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 0, ?, ?)
         ON CONFLICT (dedupe) DO NOTHING RETURNING *`,
      )
      .get(
        `job_${ulid(now)}`,
        n.kind,
        dedupe,
        n.key,
        input,
        inputDigest,
        n.runAt,
        n.cron,
        n.op,
        n.caller?.type ?? null,
        n.caller?.id ?? null,
        n.caller?.name ?? null,
        n.caller?.mode ?? null,
        n.grantSealed,
        n.grantIat,
        n.maxAttempts,
        n.leaseMs,
        n.timeoutMs,
        now,
        now,
      ) as Row | undefined;
    if (row) return { job: toJob(row), created: true };
    const prior = this.#db.prepare("SELECT * FROM tb_jobs WHERE dedupe = ?").get(dedupe) as Row | undefined;
    if (!prior) throw new TbError("job_conflict", "job key conflict; retry", 409);
    if (String(prior.input_digest) !== inputDigest) throw new TbError("job_key_conflict", "this job key was used with a different input", 409);
    return { job: toJob(prior), created: false };
  }

  get(id: string): Job | null {
    const r = this.#db.prepare("SELECT * FROM tb_jobs WHERE id = ?").get(id) as Row | undefined;
    return r ? toJob(r) : null;
  }

  list(q: { kind?: string; status?: JobStatus | JobStatus[]; limit?: number } = {}): Job[] {
    const where: string[] = [];
    const args: (string | number)[] = [];
    if (q.kind) {
      where.push("kind = ?");
      args.push(q.kind);
    }
    const st = q.status === undefined ? [] : Array.isArray(q.status) ? q.status : [q.status];
    if (st.length) {
      where.push(`status IN (${st.map(() => "?").join(",")})`);
      args.push(...st);
    }
    const limit = Math.min(500, Math.max(1, Math.floor(q.limit ?? 100)));
    const rows = this.#db.prepare(`SELECT * FROM tb_jobs ${where.length ? `WHERE ${where.join(" AND ")}` : ""} ORDER BY created_at DESC, id DESC LIMIT ?`).all(...args, limit) as Row[];
    return rows.map(toJob);
  }

  /**
   * THE claim: one UPDATE … RETURNING picks the next due job (queued/waiting with run_at ≤ now, or running with an
   * expired lease), takes a new lease and counts the attempt. A crashed run whose attempts are used up becomes `failed`
   * (`lease_expired`) in the same statement instead of running again. `kinds`: the kinds this process can run.
   * `handlerJobs: false` (slice pause, stale slice) leaves handler jobs alone; scheduled ops are still claimed so that
   * their fire-time authorize refuses them. `blocked`: caller ids whose handler jobs wait (agent paused).
   */
  claim(now: number, token: string, f: { kinds: readonly string[]; handlerJobs: boolean; ops: boolean; blocked: readonly string[] }): ClaimedJob | null {
    const eligible = `((status IN ('queued', 'waiting') AND run_at <= :now) OR (status = 'running' AND lease_until <= :now))
      AND kind IN (SELECT value FROM json_each(:kinds))
      AND NOT EXISTS (SELECT 1 FROM tb_meta WHERE key = '${APP_PAUSE_KEY}' AND value = 'true')
      AND ((op IS NOT NULL AND :ops = 1) OR (op IS NULL AND :handlers = 1 AND (caller_id IS NULL OR caller_id NOT IN (SELECT value FROM json_each(:blocked)))))`;
    const spent = "(status = 'running' AND attempts >= max_attempts)";
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET
           last_error = CASE WHEN ${spent} THEN 'lease_expired' ELSE last_error END,
           finished_at = CASE WHEN ${spent} THEN :now ELSE finished_at END,
           lease_token = CASE WHEN ${spent} THEN NULL ELSE :token END,
           lease_until = CASE WHEN ${spent} THEN NULL ELSE :now + lease_ms END,
           attempts = CASE WHEN ${spent} THEN attempts ELSE attempts + 1 END,
           status = CASE WHEN ${spent} THEN 'failed' ELSE 'running' END,
           updated_at = :now
         WHERE id = (SELECT id FROM tb_jobs WHERE ${eligible} ORDER BY run_at, id LIMIT 1) AND ${eligible}
         RETURNING *`,
      )
      .get({ now, token, kinds: JSON.stringify(f.kinds), handlers: f.handlerJobs ? 1 : 0, ops: f.ops ? 1 : 0, blocked: JSON.stringify(f.blocked) }) as Row | undefined;
    return r ? toClaimed(r) : null;
  }

  /** Lease extension; false = the lease is gone (cancelled, paused, timed out, taken over). */
  heartbeat(id: string, token: string, now: number): boolean {
    return !!this.#db.prepare("UPDATE tb_jobs SET lease_until = ? + lease_ms, updated_at = ? WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING id").get(now, now, id, token);
  }

  /** Cursor + app writes + heartbeat in ONE transaction, fenced by the lease token. */
  checkpoint<T>(id: string, token: string, state: Json, now: number, write?: () => T): T {
    const text = jsonText(state, JOB_STATE_MAX_BYTES, "job_state_too_large");
    return tx(this.#db, () => {
      const ok = this.#db
        .prepare("UPDATE tb_jobs SET state = ?, lease_until = ? + lease_ms, updated_at = ? WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING id")
        .get(text, now, now, id, token);
      if (!ok) throw new TbError("job_lease_lost", "this job run lost its lease (cancelled, paused, timed out or taken over)", 409);
      return write ? write() : (undefined as T);
    });
  }

  /** Tick returned done: one-shot → done; cron → queued at the next occurrence. Fenced. */
  done(id: string, token: string, now: number, nextRun: number | null, result: Json | undefined, state: Json | undefined): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = CASE WHEN ? IS NULL THEN 'done' ELSE 'queued' END, run_at = COALESCE(?, run_at),
           result = ?, state = COALESCE(?, state), attempts = 0, lease_token = NULL, lease_until = NULL, last_error = NULL,
           hold_id = NULL, runs = runs + 1, finished_at = CASE WHEN ? IS NULL THEN ? ELSE NULL END, updated_at = ?
         WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(nextRun, nextRun, jsonText(result, JOB_RESULT_MAX_BYTES, "job_result_too_large"), jsonText(state, JOB_STATE_MAX_BYTES, "job_state_too_large"), nextRun, now, now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** Tick returned again: queued at now + afterMs, attempts reset. Fenced. */
  again(id: string, token: string, now: number, afterMs: number, state: Json | undefined): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'queued', run_at = ?, state = COALESCE(?, state), attempts = 0, lease_token = NULL,
           lease_until = NULL, last_error = NULL, updated_at = ? WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(now + Math.max(0, afterMs), jsonText(state, JOB_STATE_MAX_BYTES, "job_state_too_large"), now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** Tick failed: retry after `waitMs`, or `failed` once attempts are used up. Fenced. */
  fail(id: string, token: string, now: number, waitMs: number, error: string): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END, run_at = ?,
           last_error = ?, lease_token = NULL, lease_until = NULL,
           finished_at = CASE WHEN attempts >= max_attempts THEN ? ELSE NULL END, updated_at = ?
         WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(now + Math.max(0, waitMs), error.slice(0, 200), now, now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** Terminal outcome of a scheduled op (`failed` with an unknown outcome, or `refused` by authorize). Fenced. */
  finish(id: string, token: string, now: number, status: "failed" | "refused" | "done", error: string | null, result?: Json): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = ?, last_error = ?, result = COALESCE(?, result), lease_token = NULL, lease_until = NULL,
           finished_at = ?, runs = runs + CASE WHEN ? = 'done' THEN 1 ELSE 0 END, updated_at = ?
         WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(status, error, jsonText(result, JOB_RESULT_MAX_BYTES, "job_result_too_large"), now, status, now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** A scheduled op is held: wait for the owner (re-check at `recheckAt`); the attempt is given back. Fenced. */
  wait(id: string, token: string, now: number, holdId: string, recheckAt: number): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'waiting', hold_id = ?, run_at = ?, attempts = MAX(0, attempts - 1), lease_token = NULL,
           lease_until = NULL, updated_at = ? WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(holdId, recheckAt, now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** Stop/pause interrupted the run: back to queued (or kept paused), the attempt is given back. Fenced. */
  release(id: string, token: string, now: number, runAt = now): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'queued', run_at = ?, attempts = MAX(0, attempts - 1), lease_token = NULL, lease_until = NULL,
           updated_at = ? WHERE id = ? AND lease_token = ? AND status = 'running' RETURNING *`,
      )
      .get(runAt, now, id, token) as Row | undefined;
    return r ? toJob(r) : null;
  }

  pause(id: string, by: string, now: number): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'paused', paused_by = ?, lease_token = NULL, lease_until = NULL, updated_at = ?
         WHERE id = ? AND (status IN ('queued', 'waiting') OR (status = 'running' AND op IS NULL)) RETURNING *`,
      )
      .get(by, now, id) as Row | undefined;
    return r ? toJob(r) : null;
  }

  resume(id: string, now: number): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'queued', run_at = CASE WHEN run_at > ? AND status = 'paused' THEN run_at ELSE ? END, paused_by = NULL,
           attempts = 0, last_error = CASE WHEN status = 'failed' THEN NULL ELSE last_error END, finished_at = NULL, updated_at = ?
         WHERE id = ? AND (status = 'paused' OR (status = 'failed' AND op IS NULL)) RETURNING *`,
      )
      .get(now, now, now, id) as Row | undefined;
    return r ? toJob(r) : null;
  }

  cancel(id: string, now: number): Job | null {
    const r = this.#db
      .prepare(
        `UPDATE tb_jobs SET status = 'cancelled', lease_token = NULL, lease_until = NULL, finished_at = ?, updated_at = ?
         WHERE id = ? AND (status IN ('queued', 'waiting', 'paused', 'failed') OR (status = 'running' AND op IS NULL)) RETURNING *`,
      )
      .get(now, now, id) as Row | undefined;
    return r ? toJob(r) : null;
  }

  /** a decided hold: its waiting scheduled op re-checks now */
  holdDecided(holdId: string, now: number): number {
    return Number(this.#db.prepare("UPDATE tb_jobs SET run_at = ? WHERE hold_id = ? AND status = 'waiting'").run(now, holdId).changes);
  }

  /** a newer verified grant of a caller replaces the stored one of its pending scheduled ops (owner narrowing applies) */
  hasPendingOps(callerId: string, iat: number): boolean {
    return !!this.#db.prepare("SELECT 1 FROM tb_jobs WHERE caller_id = ? AND op IS NOT NULL AND status IN ('queued', 'waiting', 'paused') AND grant_iat < ? LIMIT 1").get(callerId, iat);
  }

  /** v0.1.42 (spec 0.1.82, C373 P1): the pending scheduled ops of a caller with a stored grant older than `iat` (id + sealed grant), so the
   *  refresh can keep each op's workflow identity (a grant with `wfl` only replaces a grant with the same `wfl`; a base grant only a base grant) */
  pendingOpGrants(callerId: string, iat: number): { id: string; sealed: string | null }[] {
    const rows = this.#db.prepare("SELECT id, grant_sealed FROM tb_jobs WHERE caller_id = ? AND op IS NOT NULL AND status IN ('queued', 'waiting', 'paused') AND grant_iat < ?").all(callerId, iat) as Row[];
    return rows.map((r) => ({ id: String(r.id), sealed: (r.grant_sealed as string | null) ?? null }));
  }
  refreshGrantRows(ids: readonly string[], sealed: string, iat: number): number {
    let n = 0;
    const st = this.#db.prepare("UPDATE tb_jobs SET grant_sealed = ?, grant_iat = ? WHERE id = ? AND grant_iat < ?");
    for (const id of ids) n += Number(st.run(sealed, iat, id, iat).changes);
    return n;
  }

  appPaused(): boolean {
    return metaGet<boolean>(this.#db, APP_PAUSE_KEY) === true;
  }
  setAppPaused(paused: boolean): void {
    metaSet(this.#db, APP_PAUSE_KEY, paused);
  }

  /**
   * Counts for the status push. `stuck` = due for more than 10 min and not started, a lease expired more than 10 min
   * ago, or a kind this process has no handler for; jobs the owner paused (app pause, slice pause, a paused agent) are
   * waiting by choice and never stuck.
   */
  summary(now: number, f: { kinds: readonly string[]; handlerJobs: boolean; blocked: readonly string[] }): JobsSummary {
    const appPaused = this.appPaused();
    const r = this.#db
      .prepare(
        `SELECT
           SUM(status = 'queued') AS queued, SUM(status = 'running') AS running, SUM(status = 'waiting') AS waiting,
           SUM(status = 'paused') AS paused, SUM(status = 'failed') AS failed,
           SUM(:appPaused = 0
               AND (op IS NOT NULL OR (:handlers = 1 AND (caller_id IS NULL OR caller_id NOT IN (SELECT value FROM json_each(:blocked)))))
               AND ((status = 'queued' AND run_at <= :old) OR (status = 'running' AND lease_until <= :old)
                    OR (status IN ('queued', 'waiting') AND kind NOT IN (SELECT value FROM json_each(:kinds))))) AS stuck
         FROM tb_jobs WHERE status IN ('queued', 'running', 'waiting', 'paused', 'failed')`,
      )
      .get({ appPaused: appPaused ? 1 : 0, handlers: f.handlerJobs ? 1 : 0, blocked: JSON.stringify(f.blocked), old: now - STUCK_AFTER_MS, kinds: JSON.stringify(f.kinds) }) as Row;
    const n = (v: unknown) => Number(v ?? 0);
    return { queued: n(r.queued), running: n(r.running), waiting: n(r.waiting), paused: n(r.paused), failed: n(r.failed), stuck: n(r.stuck), appPaused };
  }

  /** purge terminal jobs finished before the retention window */
  sweep(now: number): number {
    return Number(this.#db.prepare("DELETE FROM tb_jobs WHERE status IN ('done', 'failed', 'cancelled', 'refused') AND finished_at < ?").run(now - JOB_RETENTION_MS).changes);
  }

  /** KEK rotation: reseal stored grants (like tb_keys) */
  reseal(sealer: { stale(b: string): boolean; unsealText(p: string, id: string, b: string): string; sealText(p: string, id: string, t: string): string }): void {
    for (const r of this.#db.prepare("SELECT id, caller_id, grant_sealed FROM tb_jobs WHERE grant_sealed IS NOT NULL").all() as Row[]) {
      const blob = String(r.grant_sealed);
      if (!sealer.stale(blob)) continue;
      const v = sealer.unsealText(GRANT_PURPOSE, String(r.caller_id), blob);
      this.#db.prepare("UPDATE tb_jobs SET grant_sealed = ? WHERE id = ?").run(sealer.sealText(GRANT_PURPOSE, String(r.caller_id), v), String(r.id));
    }
  }
}

export const sealGrant = (rt: Pick<Runtime, "sealer">, callerId: string, token: string): string => rt.sealer.sealText(GRANT_PURPOSE, callerId, token);
export const unsealGrant = (rt: Pick<Runtime, "sealer">, callerId: string, blob: string): string => rt.sealer.unsealText(GRANT_PURPOSE, callerId, blob);

/** Outcome of one scheduled-op fire (ops.ts `fireScheduledOp`). */
export type OpFireOutcome =
  | { kind: "done"; result: Json }
  | { kind: "refused"; reason: string }
  | { kind: "wait"; holdId: string }
  | { kind: "defer"; reason: string }
  | { kind: "failed"; error: string };

/** The caller recorded with a scheduled op (from the scheduling ctx); null = app-initiated. */
export interface JobCaller {
  caller: Caller;
  /** verified grant token of an agent/app caller (sealed at rest) */
  grant: { token: string; iat: number } | null;
}

interface Local {
  job: ClaimedJob;
  ac: AbortController;
  /** resolves the race early: timeout, lease lost, drain deadline */
  force: (why: "timeout" | "lease_lost" | "released") => void;
  done: Promise<void>;
  detached: boolean;
  stopReason: "paused" | "stopping" | null;
}

type Fire = (rt: Runtime, job: ClaimedJob, signal: AbortSignal) => Promise<OpFireOutcome>;

/**
 * The one runner of a process: polls (and is kicked on enqueue/resume/decide), claims while below `concurrency`,
 * heartbeats every lease/3, enforces the tick timeout, and drains on stop.
 */
export class JobRunner {
  readonly store: JobStore;
  readonly #rt: Runtime;
  readonly #specs: Map<string, Required<Pick<JobSpec, "maxAttempts" | "leaseMs" | "timeoutMs">> & { run: JobHandler; base: number; max: number }>;
  readonly #fire: Fire;
  readonly #opts: { pollMs: number; concurrency: number; drainMs: number };
  readonly #owner = ulid();
  readonly #local = new Map<string, Local>();
  #timer: NodeJS.Timeout | null = null;
  #kicked = false;
  #ticking = false;
  #started = false;
  #stopping = false;

  constructor(rt: Runtime, specs: Record<string, JobHandler | JobSpec> | undefined, fire: Fire, opts: Partial<{ pollMs: number; concurrency: number; drainMs: number }> = {}) {
    this.#rt = rt;
    this.store = new JobStore(rt.db);
    this.#fire = fire;
    this.#opts = { pollMs: opts.pollMs ?? RUNNER_DEFAULTS.pollMs, concurrency: opts.concurrency ?? RUNNER_DEFAULTS.concurrency, drainMs: opts.drainMs ?? RUNNER_DEFAULTS.drainMs };
    this.#specs = new Map();
    for (const [kind, h] of Object.entries(specs ?? {})) {
      const s: JobSpec = typeof h === "function" ? { run: h } : h;
      this.#specs.set(kind, {
        run: s.run,
        maxAttempts: s.maxAttempts ?? JOB_DEFAULTS.maxAttempts,
        leaseMs: s.leaseMs ?? JOB_DEFAULTS.leaseMs,
        timeoutMs: s.timeoutMs ?? JOB_DEFAULTS.timeoutMs,
        base: s.backoffMs?.base ?? JOB_DEFAULTS.backoffBaseMs,
        max: s.backoffMs?.max ?? JOB_DEFAULTS.backoffMaxMs,
      });
    }
  }

  /** kinds this process runs (+ scheduled ops) */
  kinds(): string[] {
    return [OP_JOB_KIND, ...this.#specs.keys()];
  }
  hasKind(kind: string): boolean {
    return this.#specs.has(kind);
  }
  spec(kind: string) {
    return this.#specs.get(kind);
  }

  start(): void {
    if (this.#started || this.#stopping) return;
    this.#started = true;
    this.#timer = setInterval(() => void this.tick(), this.#opts.pollMs);
    this.#timer.unref();
    this.kick();
  }

  kick(): void {
    if (!this.#started || this.#stopping || this.#kicked) return;
    this.#kicked = true;
    setImmediate(() => {
      this.#kicked = false;
      void this.tick();
    });
  }

  /** test/diagnostics: ids running in this process */
  runningHere(): string[] {
    return [...this.#local.keys()];
  }

  /** Which jobs may be claimed now (SDK-1: the slice pause is read before every claim). */
  #filter(): { kinds: string[]; handlerJobs: boolean; ops: boolean; blocked: string[] } {
    const rt = this.#rt;
    const now = Date.now();
    const bridged = !rt.cfg.standalone;
    // no current slice (bridge mode): pause state unknown → nothing runs (L33: fail closed); app-alone never goes stale
    if (bridged && (!rt.state.claimed || rt.trust.stale(now))) return { kinds: [], handlerJobs: false, ops: false, blocked: [] };
    const p = rt.trust.paused(null);
    const s = rt.trust.slice;
    const blocked = s ? [...new Set([...(s.pause.agents as string[]), ...s.agents.filter((a) => a.status === "paused").map((a) => a.id)])] : [];
    return { kinds: this.kinds(), handlerJobs: !(p.workspace || p.instance), ops: true, blocked };
  }

  async tick(): Promise<void> {
    if (this.#ticking || this.#stopping || !this.#started) return;
    this.#ticking = true;
    try {
      while (!this.#stopping && this.#local.size < this.#opts.concurrency) {
        const f = this.#filter();
        if (f.kinds.length === 0) break;
        const job = this.store.claim(Date.now(), `${this.#owner}.${ulid()}`, f);
        if (!job) break;
        if (job.status === "failed") {
          // a crashed run whose attempts were used up (lease_expired): visible, never re-run
          this.#rt.log.warn("job failed", { job: job.id, kind: job.kind, error: "lease_expired" });
          this.#rt.statusChanged();
          continue;
        }
        this.#launch(job);
      }
    } catch (e) {
      this.#rt.log.warn("job claim failed", { error: e instanceof Error ? e.message : "unknown" });
    } finally {
      this.#ticking = false;
    }
  }

  #launch(job: ClaimedJob): void {
    const ac = new AbortController();
    let force!: Local["force"];
    const forced = new Promise<"timeout" | "lease_lost" | "released">((resolve) => {
      force = resolve;
    });
    const local: Local = { job, ac, force: (w) => force(w), done: Promise.resolve(), detached: false, stopReason: null };
    this.#local.set(job.id, local);
    const hbEvery = Math.max(250, Math.floor(job.leaseMs / 3));
    const hb = setInterval(() => {
      if (local.detached) return;
      try {
        if (!this.store.heartbeat(job.id, job.token, Date.now())) {
          ac.abort(new TbError("job_lease_lost", "lease lost", 409));
          local.force("lease_lost");
        }
      } catch {
        /* db closed during stop */
      }
    }, hbEvery);
    hb.unref();
    const timeoutMs = job.op ? OP_JOB_TIMEOUT_MS : job.timeoutMs;
    const to = setTimeout(() => {
      ac.abort(new TbError(job.op ? "app_timeout" : "job_timeout", "job tick timed out", 504));
      local.force("timeout");
    }, timeoutMs);
    to.unref();
    local.done = (async () => {
      try {
        await (job.op ? this.#runOp(local, forced) : this.#runHandler(local, forced));
      } catch (e) {
        this.#rt.log.warn("job write failed", { job: job.id, error: e instanceof Error ? e.message : "unknown" });
      } finally {
        clearInterval(hb);
        clearTimeout(to);
        this.#local.delete(job.id);
        if (!local.detached) {
          this.#rt.statusChanged();
          this.kick();
        }
      }
    })();
  }

  async #runHandler(local: Local, forced: Promise<"timeout" | "lease_lost" | "released">): Promise<void> {
    const { job, ac } = local;
    const rt = this.#rt;
    const spec = this.#specs.get(job.kind);
    if (!spec) return void this.store.release(job.id, job.token, Date.now(), Date.now() + 60_000);
    // SDK-1: a handler job started by an agent stops with that agent; a removed agent / revoked app ends it (refused)
    const gone = this.#callerGone(job);
    if (gone) {
      this.store.finish(job.id, job.token, Date.now(), "refused", gone);
      rt.log.info("job refused", { job: job.id, kind: job.kind, reason: gone });
      return;
    }
    const ctx = jobContext(rt, this, job, ac.signal);
    const settled = Promise.resolve()
      .then(() => spec.run(job.input, ctx))
      .then(
        (v) => ({ ok: true as const, v }),
        (e: unknown) => ({ ok: false as const, e }),
      );
    const first = await Promise.race([settled, forced]);
    if (local.detached) return;
    const now = Date.now();
    if (first === "lease_lost") return;
    if (first === "released") {
      this.store.release(job.id, job.token, now);
      return;
    }
    if (first === "timeout") {
      const j = this.store.fail(job.id, job.token, now, backoffMs(job.attempts, spec.base, spec.max), "job_timeout");
      this.#logFail(j, "job_timeout");
      return;
    }
    if (!first.ok) {
      // aborted by pause/stop: the run is given back, not counted
      if (local.stopReason && ac.signal.aborted) {
        this.store.release(job.id, job.token, now);
        return;
      }
      const code = first.e instanceof TbError ? first.e.code : "job_error";
      if (code === "job_lease_lost") return;
      const retryAfter = first.e instanceof TbError && typeof first.e.details?.retryAfterMs === "number" ? first.e.details.retryAfterMs : 0;
      if (!(first.e instanceof TbError)) rt.log.warn("job tick failed", { job: job.id, kind: job.kind, error: first.e instanceof Error ? first.e.message.slice(0, 200) : "unknown" });
      const j = this.store.fail(job.id, job.token, now, Math.max(backoffMs(job.attempts, spec.base, spec.max), retryAfter), code);
      this.#logFail(j, code);
      return;
    }
    const out = first.v ?? { status: "done" as const };
    try {
      if (out.status === "again") this.store.again(job.id, job.token, now, out.afterMs ?? 0, out.state);
      else if (out.status === "retry") {
        const j = this.store.fail(job.id, job.token, now, Math.max(backoffMs(job.attempts, spec.base, spec.max), out.afterMs ?? 0), String(out.error || "job_retry"));
        this.#logFail(j, String(out.error || "job_retry"));
      } else if (out.status === "done") this.store.done(job.id, job.token, now, nextOccurrence(job.cron, now), out.result, out.state);
      else throw new TbError("job_outcome_invalid", "a job handler returns { status: done | again | retry } or nothing", 500);
    } catch (e) {
      const code = e instanceof TbError ? e.code : "job_outcome_invalid";
      const j = this.store.fail(job.id, job.token, now, backoffMs(job.attempts, spec.base, spec.max), code);
      this.#logFail(j, code);
    }
  }

  async #runOp(local: Local, forced: Promise<"timeout" | "lease_lost" | "released">): Promise<void> {
    const { job, ac } = local;
    const settled = this.#fire(this.#rt, job, ac.signal).then(
      (v) => v,
      (e: unknown): OpFireOutcome => ({ kind: "failed", error: e instanceof TbError ? e.code : "app_error" }),
    );
    const first = await Promise.race([settled, forced]);
    if (local.detached) return;
    const now = Date.now();
    if (first === "lease_lost") return;
    // the op may be mid-send: never run it again (SDK-07: an unknown outcome is failed, not retried)
    if (first === "timeout" || first === "released") {
      this.store.finish(job.id, job.token, now, "failed", first === "timeout" ? "app_timeout" : "unknown_outcome");
      return;
    }
    switch (first.kind) {
      case "done":
        if (job.cron) this.store.done(job.id, job.token, now, nextOccurrence(job.cron, now), first.result, undefined);
        else this.store.finish(job.id, job.token, now, "done", null, first.result);
        return;
      case "refused":
        this.store.finish(job.id, job.token, now, "refused", first.reason);
        this.#rt.log.info("scheduled op refused", { job: job.id, op: job.op, reason: first.reason });
        return;
      case "wait":
        this.store.wait(job.id, job.token, now, first.holdId, now + HOLD_RECHECK_MS);
        return;
      case "defer":
        this.store.release(job.id, job.token, now, now + 60_000);
        return;
      case "failed":
        if (job.cron) {
          // a failed occurrence of a recurring op: the next occurrence still runs (fresh authorize each time)
          this.store.done(job.id, job.token, now, nextOccurrence(job.cron, now), undefined, undefined);
          this.#rt.log.warn("scheduled op failed", { job: job.id, op: job.op, error: first.error });
        } else this.store.finish(job.id, job.token, now, "failed", first.error);
        return;
    }
  }

  /** a handler job's recorded caller: agent no longer in the slice → `caller_removed`; app no longer a caller → `grant_revoked` */
  #callerGone(job: Job): string | null {
    const c = job.caller;
    const rt = this.#rt;
    if (!c || rt.cfg.standalone) return null;
    if (c.type === "agent") return rt.trust.agent(c.id) ? null : "caller_removed";
    if (c.type === "app") return rt.trust.companionCallers().some((x) => x.ins === c.id) ? null : "grant_revoked";
    return null;
  }

  #logFail(j: Job | null, code: string): void {
    if (j?.status === "failed") this.#rt.log.warn("job failed", { job: j.id, kind: j.kind, error: code, attempts: j.attempts });
  }

  /** a job paused/cancelled in this process: abort its run now (other processes notice at the next heartbeat) */
  interrupt(id: string, why: "paused" | "cancelled"): void {
    const l = this.#local.get(id);
    if (!l) return;
    l.stopReason = "paused";
    l.ac.abort(new TbError(why === "paused" ? "job_paused" : "job_cancelled", `job ${why}`, 409));
    // its lease token was cleared by the same statement: any later write of the run is fenced out
    l.force("lease_lost");
  }

  /** app pause: abort every local run; each gives its attempt back (release) when it settles or after the drain time */
  async interruptAll(): Promise<void> {
    await this.#drain("paused");
    this.kick();
  }

  async #drain(why: "paused" | "stopping"): Promise<void> {
    // an app pause lets an in-flight scheduled op finish (it may be mid-send); a stop aborts it (unknown_outcome)
    const runs = [...this.#local.values()].filter((l) => why === "stopping" || !l.job.op);
    for (const l of runs) {
      l.stopReason = why;
      l.ac.abort(new TbError(why === "paused" ? "job_paused" : "app_stopping", why === "paused" ? "jobs paused" : "app is stopping", 503));
    }
    const all = Promise.allSettled(runs.map((l) => l.done));
    let t: NodeJS.Timeout | undefined;
    const deadline = new Promise<void>((r) => {
      t = setTimeout(r, this.#opts.drainMs);
      t.unref();
    });
    await Promise.race([all, deadline]);
    if (t) clearTimeout(t);
    for (const l of runs) if (this.#local.has(l.job.id)) l.force("released");
    await Promise.race([Promise.allSettled(runs.map((l) => l.done)), new Promise((r) => setTimeout(r, 100).unref())]);
  }

  /** status push: counts (AppStatus.jobs, SPEC-GAP) */
  summary(): JobsSummary {
    const rt = this.#rt;
    const p = rt.trust.paused(null);
    const s = rt.trust.slice;
    const blocked = s ? [...new Set([...(s.pause.agents as string[]), ...s.agents.filter((a) => a.status === "paused").map((a) => a.id)])] : [];
    return this.store.summary(Date.now(), { kinds: this.kinds(), handlerJobs: !(p.workspace || p.instance), blocked });
  }

  /** L3: failed / stuck jobs need the owner (the app's own attention() wins when it reports one) */
  attention(): { code: string; reason: string } | null {
    const j = this.summary();
    if (j.failed > 0) return { code: "jobs_failed", reason: `${j.failed} background job${j.failed === 1 ? "" : "s"} failed and need${j.failed === 1 ? "s" : ""} a retry or cancel` };
    if (j.stuck > 0) return { code: "jobs_stuck", reason: `${j.stuck} background job${j.stuck === 1 ? " is" : "s are"} overdue and not running` };
    return null;
  }

  /** stop claiming at once (before onStop); stop() then drains */
  halt(): void {
    if (this.#timer) clearInterval(this.#timer);
    this.#timer = null;
    this.#started = false;
  }

  /** stop claiming, abort runs, give handler runs back (fenced), fail in-flight scheduled ops as unknown_outcome */
  async stop(): Promise<void> {
    if (this.#stopping) return;
    this.halt();
    await this.#drain("stopping");
    this.#stopping = true;
    for (const l of this.#local.values()) l.detached = true;
  }
}

export function nextOccurrence(cron: string | null, now: number): number | null {
  if (!cron) return null;
  const d = nextCronTime(cron, now);
  return d ? d.getTime() : null;
}

function checkCron(cron: string): void {
  try {
    parseCron(cron);
  } catch (e) {
    if (e instanceof CronError) throw new TbError("schedule_invalid", `not a valid 5-field cron: ${cron}`, 400);
    throw e;
  }
}

function firstRun(now: number, opts: { at?: Date | number; cron?: string }): { runAt: number; cron: string | null } {
  if (opts.at !== undefined && opts.cron !== undefined) throw new TbError("schedule_invalid", "give at or cron, not both", 400);
  if (opts.cron !== undefined) {
    if (typeof opts.cron !== "string") throw new TbError("schedule_invalid", "cron must be a string", 400);
    checkCron(opts.cron);
    const next = nextOccurrence(opts.cron, now);
    if (next === null) throw new TbError("schedule_invalid", "this cron never fires", 400);
    return { runAt: next, cron: opts.cron };
  }
  if (opts.at === undefined) return { runAt: now, cron: null };
  const at = toMs(opts.at);
  if (!Number.isFinite(at)) throw new TbError("schedule_invalid", "at must be a time", 400);
  if (at > now + SCHEDULE_MAX_AHEAD_MS) throw new TbError("schedule_invalid", "at is more than 366 days ahead", 400);
  return { runAt: Math.max(now, Math.floor(at)), cron: null };
}

const attemptsOf = (n: number | undefined, dflt: number): number => {
  if (n === undefined) return dflt;
  if (!Number.isInteger(n) || n < 1 || n > 100) throw new TbError("schedule_invalid", "maxAttempts must be 1..100", 400);
  return n;
};

/**
 * ctx.jobs / ctx.schedule / ctx.paused for one context. `who` = the ctx's caller (op handlers), the job's caller
 * (job ticks), or null (onStart, events, onStop: app-initiated).
 */
export function jobsView(rt: Runtime, runner: JobRunner, who: JobCaller | null): JobsView {
  const store = runner.store;
  const callerRow = who ? { type: who.caller.type, id: String(who.caller.id), name: who.caller.name, mode: who.caller.mode } : null;
  const need = (j: Job | null, id: string, verb: string): Job => {
    if (j) return j;
    const cur = store.get(id);
    if (!cur) throw new TbError("job_not_found", "no such job", 404);
    if (verb === "cancel" && cur.status === "running") throw new TbError("job_running", "a running scheduled op cannot be cancelled", 409);
    throw new TbError("job_state", `cannot ${verb} a job that is ${cur.status}`, 409);
  };
  const enqueue = (kind: string, input: Json = null, opts: EnqueueOptions = {}): Job => {
    if (typeof kind !== "string" || !JOB_KIND_RE.test(kind) || kind.startsWith("tb.")) throw new TbError("job_kind_invalid", "not a job kind", 400);
    const spec = runner.spec(kind);
    if (!spec) throw new TbError("job_kind_unknown", `no handler for job kind ${kind} (defineApp jobs)`, 400);
    if (opts.key !== undefined && (typeof opts.key !== "string" || !KEY_RE.test(opts.key))) throw new TbError("job_key_invalid", "job key must be 1..128 printable characters", 400);
    const now = Date.now();
    const first = firstRun(now, opts);
    const r = store.insert(
      {
        kind,
        input,
        key: opts.key ?? null,
        ...first,
        op: null,
        caller: callerRow,
        grantSealed: null,
        grantIat: null,
        maxAttempts: attemptsOf(opts.maxAttempts, spec.maxAttempts),
        leaseMs: spec.leaseMs,
        timeoutMs: spec.timeoutMs,
      },
      now,
    );
    if (r.created) {
      runner.kick();
      rt.statusChanged();
    }
    return r.job;
  };
  const scheduleOp = (opId: string, input: Json, when: ScheduleWhen, opts: { key?: string; maxAttempts?: number }): Job => {
    if (!who) throw new TbError("schedule_caller_required", "a scheduled op runs as a caller: schedule it from an op handler (or a job it started)", 400);
    const op: OperationView | undefined = rt.ops.get(opId);
    if (!op || op.standard || op.dynamic) throw new TbError("unknown_tool", `not a schedulable operation: ${opId}`, 404);
    const audience = who.caller.type === "person" ? "person" : "agent";
    if (op.audience !== audience) throw new TbError(audience === "person" ? "audience_not_person" : "audience_not_agent", `a ${who.caller.type} caller cannot schedule ${opId}`, 403);
    const v = validateInput(op, input);
    if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
    if (who.caller.type !== "person" && !who.grant) throw new TbError("schedule_caller_required", "no verified grant for this caller", 400);
    if (opts.key !== undefined && (typeof opts.key !== "string" || !KEY_RE.test(opts.key))) throw new TbError("job_key_invalid", "job key must be 1..128 printable characters", 400);
    const now = Date.now();
    const first = firstRun(now, "cron" in when ? { cron: when.cron } : { at: when.at });
    const r = store.insert(
      {
        kind: OP_JOB_KIND,
        input,
        key: opts.key ?? null,
        ...first,
        op: op.id,
        caller: callerRow,
        grantSealed: who.grant ? sealGrant(rt, String(who.caller.id), who.grant.token) : null,
        grantIat: who.grant?.iat ?? null,
        maxAttempts: attemptsOf(opts.maxAttempts, OP_JOB_MAX_ATTEMPTS),
        leaseMs: JOB_DEFAULTS.leaseMs,
        timeoutMs: OP_JOB_TIMEOUT_MS,
      },
      now,
    );
    if (r.created) {
      runner.kick();
      rt.statusChanged();
    }
    return r.job;
  };
  const jobs: JobsApi = {
    enqueue,
    get: (id) => store.get(String(id)),
    list: (q) => store.list(q ?? {}),
    pause(id) {
      const j = need(store.pause(String(id), who ? String(who.caller.id) : "app", Date.now()), String(id), "pause");
      runner.interrupt(j.id, "paused");
      rt.statusChanged();
      return j;
    },
    resume(id) {
      const j = need(store.resume(String(id), Date.now()), String(id), "resume");
      runner.kick();
      rt.statusChanged();
      return j;
    },
    cancel(id) {
      const j = need(store.cancel(String(id), Date.now()), String(id), "cancel");
      runner.interrupt(j.id, "cancelled");
      rt.statusChanged();
      return j;
    },
    pauseAll() {
      store.setAppPaused(true);
      void runner.interruptAll();
      rt.statusChanged();
    },
    resumeAll() {
      store.setAppPaused(false);
      runner.kick();
      rt.statusChanged();
    },
    appPaused: () => store.appPaused(),
  };
  return {
    jobs,
    schedule(target, when, opts = {}) {
      if (!when || typeof when !== "object" || (!("at" in when) && !("cron" in when))) throw new TbError("schedule_invalid", "when must be { at } or { cron }", 400);
      if (target && typeof target === "object" && "op" in target) return scheduleOp(target.op, target.input, when, opts);
      if (target && typeof target === "object" && "job" in target) return enqueue(target.job, target.input ?? null, { ...opts, ...("cron" in when ? { cron: when.cron } : { at: when.at }) });
      throw new TbError("schedule_invalid", "target must be { op, input } or { job, input? }", 400);
    },
    paused(agent) {
      const id = agent === undefined ? (who?.caller.type === "agent" ? String(who.caller.id) : null) : agent;
      return rt.trust.paused(id);
    },
  };
}

function jobContext(rt: Runtime, runner: JobRunner, job: ClaimedJob, signal: AbortSignal): JobContext {
  // a handler job holds no grant: the product is the slice entry (v0.1.27) via the one helper (no `prd` to read here)
  const cp = job.caller ? resolveCallerProduct(rt, job.caller, null) : null;
  const who: JobCaller | null = job.caller
    ? { caller: { type: job.caller.type, id: job.caller.id as Caller["id"], name: job.caller.name, mode: (job.callerMode as Caller["mode"]) ?? null, ...(cp?.ok ? cp.caller : {}) }, grant: null }
    : null;
  const view = jobsView(rt, runner, who);
  return {
    ...rt.eventContext(),
    ...view,
    job: toJobPublic(job),
    signal,
    checkpoint<T = void>(state: Json, write?: (db: Db) => T): T {
      return runner.store.checkpoint(job.id, job.token, state, Date.now(), write ? () => write(rt.appDb) : undefined);
    },
    secrets: rt.secretsStore,
    getKey: (n) => rt.keys.getKey(n),
    modelRole: (r) => rt.keys.modelRole(r),
    callServiceHelper: (s, p, b) => rt.callServiceHelper(s, p, b),
  };
}

function toJobPublic(j: ClaimedJob): Job {
  const { token: _t, leaseMs: _l, timeoutMs: _o, callerMode: _m, grantSealed: _g, ...rest } = j;
  return rest;
}
