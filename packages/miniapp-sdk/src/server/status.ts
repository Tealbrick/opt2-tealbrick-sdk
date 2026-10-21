// v0.1.13 (C86): status push pacing (`ctx.statusChanged()`) and `AppStatus.pendingHolds` = held receipts +
// `defineApp({ pendingCount })` (clamped 0..10 000, 1 s timeout, error/timeout → 0 with a rate-limited WARNING).
import type { Db, Logger } from "@opt2-tealbrick/spec/sdk";

/** One push per second at most (C86). */
export const STATUS_PUSH_INTERVAL_MS = 1000;
export const PENDING_COUNT_TIMEOUT_MS = 1000;
export const PENDING_COUNT_MAX = 10_000;
/** pendingCount failure warnings: at most one per minute, the next one carries the suppressed count. */
export const PENDING_WARN_INTERVAL_MS = 60_000;

/**
 * `statusChanged()`: the status goes out within 1 s; calls are coalesced (debounced) and pushes are at least 1 s apart.
 * `push` triggers the bridge link's status exchange (BridgeLink.kick); a no-op without a bridge (app-alone mode).
 */
export class StatusPusher {
  readonly #push: () => void;
  readonly #now: () => number;
  #timer: NodeJS.Timeout | null = null;
  #last = Number.NEGATIVE_INFINITY;
  #stopped = false;
  /** pushes sent (tests) */
  pushes = 0;

  constructor(push: () => void, now: () => number = Date.now) {
    this.#push = push;
    this.#now = now;
  }

  request(): void {
    if (this.#timer || this.#stopped) return;
    const delay = Math.max(0, this.#last + STATUS_PUSH_INTERVAL_MS - this.#now());
    this.#timer = setTimeout(() => {
      this.#timer = null;
      this.#last = this.#now();
      this.pushes += 1;
      this.#push();
    }, delay);
    this.#timer.unref();
  }

  stop(): void {
    this.#stopped = true;
    if (this.#timer) clearTimeout(this.#timer);
    this.#timer = null;
  }
}

/** Wraps the app's `pendingCount(db)`: 1 s timeout, clamp 0..10 000, failures count 0 and warn (≤ 1/min + suppressed). */
export class PendingCounter {
  readonly #fn: ((db: Db) => Promise<number>) | undefined;
  readonly #db: Db;
  readonly #log: Logger;
  readonly #now: () => number;
  readonly #timeoutMs: number;
  #lastWarn = Number.NEGATIVE_INFINITY;
  #suppressed = 0;

  constructor(fn: ((db: Db) => Promise<number>) | undefined, db: Db, log: Logger, opts: { now?: () => number; timeoutMs?: number } = {}) {
    this.#fn = fn;
    this.#db = db;
    this.#log = log;
    this.#now = opts.now ?? Date.now;
    this.#timeoutMs = opts.timeoutMs ?? PENDING_COUNT_TIMEOUT_MS;
  }

  async count(): Promise<number> {
    const fn = this.#fn;
    if (!fn) return 0;
    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), this.#timeoutMs);
        timer.unref();
      });
      const n = await Promise.race([Promise.resolve().then(() => fn(this.#db)), timeout]);
      if (typeof n !== "number" || Number.isNaN(n)) throw new Error("not a number");
      return Math.min(PENDING_COUNT_MAX, Math.max(0, Math.floor(n)));
    } catch (e) {
      this.#warn(e instanceof Error && e.message === "timeout" ? "timeout" : "error");
      return 0;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  #warn(reason: "timeout" | "error"): void {
    const now = this.#now();
    if (now - this.#lastWarn < PENDING_WARN_INTERVAL_MS) {
      this.#suppressed += 1;
      return;
    }
    this.#lastWarn = now;
    const suppressed = this.#suppressed;
    this.#suppressed = 0;
    // no error message: app errors may carry app data; the reason is enough for the operator
    this.#log.warn("pendingCount failed", { reason, counted: 0, ...(suppressed > 0 ? { suppressed } : {}) });
  }
}

/**
 * v0.1.38 (admin queue c/5b): ONE attention for `AppStatus.attention`, by severity (the owner sees one line):
 * 1. the SDK's backup attention (invalid or never-firing schedule, failed, overdue): data protection is broken and nothing else
 *    shows it; 2. the app's own `attention()` (it knows why it is degraded); 3. the SDK's job attention (failed, stuck jobs).
 * Before 0.1.38 the app's attention came first and hid a failed or overdue backup.
 */
export function pickAttention(a: { backup: Attention | null; app: Attention | null; jobs: Attention | null }): Attention | null {
  return a.backup ?? a.app ?? a.jobs;
}

/** v0.1.20 (spec 0.1.28, F89): `AppStatus.attention` limits (BRIDGE §10.3). */
export const ATTENTION_CODE = /^[a-z][a-z0-9_]{0,39}$/u;
export const ATTENTION_REASON_MAX = 200;

/** App-reported condition for the owner (spec 0.1.28 `AppAttention`). */
export interface Attention {
  code: string;
  reason: string;
}

/**
 * Wraps the app's `attention(db)` (spec 0.1.28, QA F89 / L3): read at every status push, 1 s timeout; an error, a
 * timeout or a malformed value counts as none and warns (≤ 1/min + suppressed count, never the app's message). The
 * reason is trimmed, control characters removed and cut to 200 chars.
 */
export class AttentionReader {
  readonly #fn: ((db: Db) => Promise<Attention | null>) | undefined;
  readonly #db: Db;
  readonly #log: Logger;
  readonly #now: () => number;
  readonly #timeoutMs: number;
  #lastWarn = Number.NEGATIVE_INFINITY;
  #suppressed = 0;

  constructor(fn: ((db: Db) => Promise<Attention | null>) | undefined, db: Db, log: Logger, opts: { now?: () => number; timeoutMs?: number } = {}) {
    this.#fn = fn;
    this.#db = db;
    this.#log = log;
    this.#now = opts.now ?? Date.now;
    this.#timeoutMs = opts.timeoutMs ?? PENDING_COUNT_TIMEOUT_MS;
  }

  async read(): Promise<Attention | null> {
    const fn = this.#fn;
    if (!fn) return null;
    let timer: NodeJS.Timeout | undefined;
    try {
      const timeout = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("timeout")), this.#timeoutMs);
        timer.unref();
      });
      const value = await Promise.race([Promise.resolve().then(() => fn(this.#db)), timeout]);
      if (value === null || value === undefined) return null;
      const reason = typeof value.reason === "string" ? value.reason.replace(/\p{Cc}+/gu, " ").trim().slice(0, ATTENTION_REASON_MAX) : "";
      if (typeof value.code !== "string" || !ATTENTION_CODE.test(value.code) || !reason) throw new Error("invalid");
      return { code: value.code, reason };
    } catch (e) {
      this.#warn(e instanceof Error && e.message === "timeout" ? "timeout" : e instanceof Error && e.message === "invalid" ? "invalid" : "error");
      return null;
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  #warn(reason: "timeout" | "error" | "invalid"): void {
    const now = this.#now();
    if (now - this.#lastWarn < PENDING_WARN_INTERVAL_MS) {
      this.#suppressed += 1;
      return;
    }
    this.#lastWarn = now;
    const suppressed = this.#suppressed;
    this.#suppressed = 0;
    this.#log.warn("attention failed", { reason, reported: "none", ...(suppressed > 0 ? { suppressed } : {}) });
  }
}
