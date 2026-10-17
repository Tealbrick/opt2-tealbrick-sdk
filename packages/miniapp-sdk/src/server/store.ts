// The ONE store (SDK-API §7.1): node:sqlite at TB_DATA_DIR/app.db, WAL, one process; the ONE migration runner
// (SDK set first, then the app's forward-only NNNN_<name>.sql|.ts files). App code gets a `Db` handle that the
// SQLite authorizer keeps away from SDK-reserved `tb_*` tables.
import { createHash } from "node:crypto";
import { mkdirSync, readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { constants, DatabaseSync, type SQLInputValue } from "node:sqlite";
import { pathToFileURL } from "node:url";
import type { Db } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";

export type RawDb = DatabaseSync;
export type Row = Record<string, unknown>;

/** SDK-internal migrations (scope "sdk"), applied before any app migration. Forward-only; never edit an entry. */
export const SDK_MIGRATIONS: readonly { version: number; name: string; sql: string }[] = [
  {
    version: 1,
    name: "sdk_baseline",
    sql: `
CREATE TABLE tb_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) STRICT;
CREATE TABLE tb_receipts (
  id TEXT PRIMARY KEY, call_id TEXT, caller_type TEXT NOT NULL, caller_id TEXT NOT NULL, caller_name TEXT NOT NULL,
  op TEXT NOT NULL, effect TEXT NOT NULL, hold_family TEXT, status TEXT NOT NULL, input_digest TEXT NOT NULL,
  summary TEXT NOT NULL, meta TEXT NOT NULL, idempotency_key TEXT, view TEXT,
  created_at INTEGER NOT NULL, decided_at INTEGER, expires_at INTEGER, decided_by TEXT, consumed INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX tb_receipts_match ON tb_receipts (caller_id, op, input_digest, status);
CREATE INDEX tb_receipts_status ON tb_receipts (status, expires_at);
CREATE INDEX tb_receipts_usage ON tb_receipts (caller_id, effect, created_at);
CREATE INDEX tb_receipts_order ON tb_receipts (created_at, id);
CREATE INDEX tb_receipts_call ON tb_receipts (call_id);
CREATE TABLE tb_idempotency (
  caller_id TEXT NOT NULL, op TEXT NOT NULL, key TEXT NOT NULL, input_digest TEXT NOT NULL,
  kind TEXT NOT NULL, output TEXT, hold_id TEXT, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
  PRIMARY KEY (caller_id, op, key)
) STRICT;
CREATE TABLE tb_scope_instances (
  type TEXT NOT NULL, id TEXT NOT NULL, label TEXT NOT NULL, shared INTEGER NOT NULL DEFAULT 0, owner_agent TEXT,
  created_at INTEGER NOT NULL, PRIMARY KEY (type, id)
) STRICT;
CREATE TABLE tb_scopes (agent TEXT NOT NULL, type TEXT NOT NULL, instance_id TEXT NOT NULL, access TEXT NOT NULL,
  PRIMARY KEY (agent, type, instance_id)) STRICT;
CREATE TABLE tb_scope_defaults (agent TEXT NOT NULL, type TEXT NOT NULL, applied_at INTEGER NOT NULL,
  PRIMARY KEY (agent, type)) STRICT;
CREATE TABLE tb_agents (agent TEXT PRIMARY KEY, name TEXT NOT NULL, first_seen INTEGER NOT NULL, in_slice INTEGER NOT NULL) STRICT;
CREATE TABLE tb_sessions (digest TEXT PRIMARY KEY, person TEXT NOT NULL, ws TEXT NOT NULL, instance TEXT NOT NULL,
  iss TEXT NOT NULL, csrf TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL) STRICT;
CREATE TABLE tb_used_jti (jti TEXT PRIMARY KEY, exp INTEGER NOT NULL) STRICT;
CREATE TABLE tb_keys (name TEXT PRIMARY KEY, sealed TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;
CREATE TABLE tb_audit (id TEXT PRIMARY KEY, at INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
  target TEXT, detail TEXT NOT NULL) STRICT;
CREATE INDEX tb_audit_order ON tb_audit (at, id);
`,
  },
  {
    version: 2,
    name: "sdk_app_secrets",
    sql: "CREATE TABLE tb_secrets (name TEXT PRIMARY KEY, sealed TEXT NOT NULL, updated_at INTEGER NOT NULL) STRICT;",
  },
  {
    // v0.1.13 (G1): `held_by` = Receipt.heldBy (`<product>/<hookId>` of the before hook whose verdict held the call);
    // `hold_reason` = the hook verdict reason or the SDK hold reason code (tb.hold_status / tb.holds_pending). Old rows: null.
    version: 3,
    name: "sdk_receipt_held_by",
    sql: "ALTER TABLE tb_receipts ADD COLUMN held_by TEXT;\nALTER TABLE tb_receipts ADD COLUMN hold_reason TEXT;",
  },
  {
    // v0.1.21 (Scribe R1, L6, SDK-2): THE job table (jobs.ts). `dedupe` = idempotency key scope (kind + key, or caller +
    // op + key for scheduled ops); `lease_token` fences every write of a run; `grant_sealed` = the caller's newest
    // verified grant for fire-time authorize (sealed like tb_keys).
    version: 4,
    name: "sdk_jobs",
    sql: `
CREATE TABLE tb_jobs (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, dedupe TEXT UNIQUE, key TEXT, input TEXT NOT NULL, input_digest TEXT NOT NULL,
  state TEXT, status TEXT NOT NULL, run_at INTEGER NOT NULL, cron TEXT, op TEXT,
  caller_type TEXT, caller_id TEXT, caller_name TEXT, caller_mode TEXT, grant_sealed TEXT, grant_iat INTEGER,
  hold_id TEXT, attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL, lease_ms INTEGER NOT NULL,
  timeout_ms INTEGER NOT NULL, lease_token TEXT, lease_until INTEGER, last_error TEXT, result TEXT, paused_by TEXT,
  runs INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, finished_at INTEGER
) STRICT;
CREATE INDEX tb_jobs_due ON tb_jobs (status, run_at);
CREATE INDEX tb_jobs_lease ON tb_jobs (status, lease_until);
CREATE INDEX tb_jobs_caller ON tb_jobs (caller_id, status);
CREATE INDEX tb_jobs_hold ON tb_jobs (hold_id);
CREATE INDEX tb_jobs_order ON tb_jobs (created_at, id);
`,
  },
  {
    // v0.1.22 (SDK-02): Free cap slots, independent of receipts. One row per run of a write/outward/destructive op
    // (receipt or not), reserved before the handler in the same transaction as the decision; deleted when the run fails
    // or is refused; kept when it ran or its outcome is unknown. Backfilled from the receipts that counted before.
    version: 5,
    name: "sdk_cap_usage",
    sql: `
CREATE TABLE tb_cap_usage (
  id TEXT PRIMARY KEY, caller_id TEXT NOT NULL, effect TEXT NOT NULL, op TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX tb_cap_usage_count ON tb_cap_usage (caller_id, effect, created_at);
INSERT INTO tb_cap_usage (id, caller_id, effect, op, state, created_at)
  SELECT 'cap_' || id, caller_id, effect, op, 'used', created_at FROM tb_receipts
  WHERE status = 'run' AND effect IN ('write', 'outward', 'destructive');
`,
  },
  {
    // v0.1.27 (SDK-CALLER-PRODUCT, spec 0.1.44): `caller_product` = Receipt.caller.product, the VERIFIED product id of an app
    // caller (slice companionCallers entry by instance), set when the receipt/hold is written. Additive and nullable;
    // existing rows keep NULL (product absent: it cannot be verified after the fact) and nothing is rewritten.
    version: 6,
    name: "sdk_receipt_caller_product",
    sql: "ALTER TABLE tb_receipts ADD COLUMN caller_product TEXT;",
  },
  {
    // v0.1.31 (SDK-INSTANCE-GRANT, spec 0.1.47): `source` = who wrote the scope row ('default' manifest defaultGrants,
    // 'owner' tb.scopes_set, 'app' ctx.scopeGrants.grant inside a person op), `granted_by_op` = that op id (source 'app').
    // Additive and nullable; existing rows keep NULL (the writer is not known after the fact: ScopeGrantRow.source is
    // then absent) and nothing is rewritten.
    version: 7,
    name: "sdk_scope_source",
    sql: "ALTER TABLE tb_scopes ADD COLUMN source TEXT;\nALTER TABLE tb_scopes ADD COLUMN granted_by_op TEXT;",
  },
];

function sha256(text: string | Uint8Array): string {
  return createHash("sha256").update(text).digest("hex");
}

/** v0.1.25 (E2/M3): the newest SDK migration this SDK knows; a DB with a higher applied SDK version is refused. */
export const SDK_SCHEMA: number = SDK_MIGRATIONS.reduce((n, m) => Math.max(n, m.version), 0);

/**
 * Opens TB_DATA_DIR/app.db (WAL, foreign keys, busy timeout) and creates the two bootstrap tables that live outside the
 * migration set: `tb_migrations` and (v0.1.25, E2/M2) `tb_migration_lock`. No migration runs here.
 */
export function openDb(dataDir: string): RawDb {
  mkdirSync(dataDir, { recursive: true });
  const db = new DatabaseSync(join(dataDir, "app.db"));
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA synchronous = NORMAL;");
  db.exec(
    "CREATE TABLE IF NOT EXISTS tb_migrations (scope TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL, applied_at INTEGER NOT NULL, PRIMARY KEY (scope, version)) STRICT",
  );
  db.exec("CREATE TABLE IF NOT EXISTS tb_migration_lock (id INTEGER PRIMARY KEY CHECK (id = 1), holder TEXT NOT NULL, until INTEGER NOT NULL) STRICT");
  return db;
}

/** v0.1.25 (E2): the schema a database is at = the highest applied migration per scope (0 = none). */
export interface SchemaVersion {
  app: number;
  sdk: number;
}

export function storedSchema(db: RawDb): SchemaVersion {
  const rows = db.prepare("SELECT scope, max(version) AS v FROM tb_migrations GROUP BY scope").all() as Row[];
  const of = (scope: string) => Number(rows.find((r) => r.scope === scope)?.v ?? 0);
  return { app: of("app"), sdk: of("sdk") };
}

/** SDK migrations not applied yet; `sdk_schema_newer` when the DB carries an SDK migration this SDK does not know. */
export function pendingSdkMigrations(db: RawDb): (typeof SDK_MIGRATIONS)[number][] {
  const applied = new Map(
    (db.prepare("SELECT version, sha256 FROM tb_migrations WHERE scope = 'sdk'").all() as Row[]).map((r) => [Number(r.version), String(r.sha256)]),
  );
  for (const v of applied.keys())
    if (v > SDK_SCHEMA)
      throw new TbError("sdk_schema_newer", `the database is at SDK schema ${Math.max(...applied.keys())}; this SDK knows ${SDK_SCHEMA}. A newer version wrote this data: run that version or restore a backup taken before it`, 500, {
        stored: Math.max(...applied.keys()),
        code: SDK_SCHEMA,
      });
  const out: (typeof SDK_MIGRATIONS)[number][] = [];
  for (const m of SDK_MIGRATIONS) {
    const have = applied.get(m.version);
    if (have === undefined) out.push(m);
    else if (have !== sha256(m.sql)) throw new TbError("migration_invalid", `SDK migration ${m.version} changed after it was applied`, 500);
  }
  return out;
}

/** Applies the pending SDK migrations (one transaction each); `onEach` runs after every committed migration. */
export function applySdkMigrations(db: RawDb, onEach?: (m: { version: number; name: string }) => void): { version: number; name: string }[] {
  const done: { version: number; name: string }[] = [];
  for (const m of pendingSdkMigrations(db)) {
    tx(db, () => {
      db.exec(m.sql);
      db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('sdk', ?, ?, ?, ?)").run(m.version, m.name, sha256(m.sql), Date.now());
    });
    done.push({ version: m.version, name: m.name });
    onEach?.(m);
  }
  return done;
}

/** Opens TB_DATA_DIR/app.db and applies the SDK migration set (restore, tests). startApp runs the steps itself (E2 lock + snapshot). */
export function openStore(dataDir: string): RawDb {
  const db = openDb(dataDir);
  try {
    applySdkMigrations(db);
  } catch (e) {
    db.close();
    throw e;
  }
  return db;
}

// ── transactions (one runner; nested calls become savepoints) ──
const depth = new WeakMap<RawDb, number>();

export function tx<T>(db: RawDb, fn: () => T): T {
  const d = depth.get(db) ?? 0;
  const sp = `tbsp${d}`;
  db.exec(d === 0 ? "BEGIN IMMEDIATE" : `SAVEPOINT ${sp}`);
  depth.set(db, d + 1);
  try {
    const out = fn();
    if (out instanceof Promise) throw new TbError("db_transaction_async", "transaction callbacks must be synchronous", 500);
    db.exec(d === 0 ? "COMMIT" : `RELEASE ${sp}`);
    return out;
  } catch (e) {
    db.exec(d === 0 ? "ROLLBACK" : `ROLLBACK TO ${sp}; RELEASE ${sp}`);
    throw e;
  } finally {
    depth.set(db, d);
  }
}

// ── tb_meta key/value ──
export function metaGet<T>(db: RawDb, key: string): T | null {
  const row = db.prepare("SELECT value FROM tb_meta WHERE key = ?").get(key) as Row | undefined;
  return row ? (JSON.parse(String(row.value)) as T) : null;
}
export function metaSet(db: RawDb, key: string, value: unknown): void {
  db.prepare("INSERT INTO tb_meta (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value").run(key, JSON.stringify(value));
}
export function metaDelete(db: RawDb, key: string): void {
  db.prepare("DELETE FROM tb_meta WHERE key = ?").run(key);
}

// ── App handle: SQLite authorizer denies every access to `tb_*` objects while app SQL compiles or runs ──
const RESERVED = /^tb_/i;
type Authorizer = (action: number, a1: string | null, a2: string | null, dbName: string | null, trigger: string | null) => number;
type AuthorizerDb = RawDb & { setAuthorizer?: (cb: Authorizer | null) => void };

const appAuthorizer: Authorizer = (action, a1, a2) => {
  if (action === constants.SQLITE_FUNCTION || action === constants.SQLITE_SAVEPOINT || action === constants.SQLITE_TRANSACTION) return constants.SQLITE_OK;
  return RESERVED.test(a1 ?? "") || RESERVED.test(a2 ?? "") ? constants.SQLITE_DENY : constants.SQLITE_OK;
};

function guarded<T>(db: RawDb, fn: () => T): T {
  const adb = db as AuthorizerDb;
  if (typeof adb.setAuthorizer !== "function") return fn();
  adb.setAuthorizer(appAuthorizer);
  try {
    return fn();
  } catch (e) {
    const msg = e instanceof Error ? e.message : "";
    if (/prohibited|not authorized/i.test(msg)) throw new TbError("db_reserved", "tb_* tables are reserved for the SDK", 500);
    throw e;
  } finally {
    adb.setAuthorizer(null);
  }
}

/**
 * Fallback for runtimes without `setAuthorizer`: reject SQL naming any `tb_*` identifier. KEPT on purpose (C133 audit V-19):
 * `setAuthorizer` exists from Node 24.10.0, `engines` says `>=24`, so Node 24.0–24.9 still run this SDK and would
 * otherwise let app SQL touch the SDK's reserved tables. It is a security guard, not an old-format reader.
 */
function legacyGuard(sql: string): void {
  if (/(^|[^a-z0-9_])tb_[a-z0-9_]*/i.test(sql)) throw new TbError("db_reserved", "tb_* tables are reserved for the SDK", 500);
}

/** The app's SQLite handle (OpContext.db): app tables only. */
export function appDb(db: RawDb): Db {
  const hasAuthorizer = typeof (db as AuthorizerDb).setAuthorizer === "function";
  const check = (sql: string) => {
    if (!hasAuthorizer) legacyGuard(sql);
  };
  return {
    exec(sql) {
      check(sql);
      guarded(db, () => db.exec(sql));
    },
    prepare(sql) {
      check(sql);
      const stmt = guarded(db, () => db.prepare(sql));
      const params = (p: unknown[]) => p as SQLInputValue[];
      return {
        run: (...p) => {
          const r = guarded(db, () => stmt.run(...params(p)));
          return { changes: Number(r.changes), lastInsertRowid: r.lastInsertRowid };
        },
        get: (...p) => guarded(db, () => stmt.get(...params(p))) as Row | undefined,
        all: (...p) => guarded(db, () => stmt.all(...params(p))) as Row[],
      };
    },
    transaction: (fn) => tx(db, fn),
  };
}

// ── App migrations (forward-only, gap-free from 0001, one transaction each) ──
const FILE_RE = /^(\d{4})_([a-z0-9][a-z0-9_-]*)\.(sql|ts)$/;

export interface AppliedMigration {
  version: number;
  name: string;
}

export interface MigrationFile {
  version: number;
  name: string;
  file: string;
  kind: "sql" | "ts";
  sum: string;
  body: Buffer;
}

/** v0.1.25: reads and checks the app's migration directory (names, gap-free from 0001); no database access. */
export function scanMigrations(dir: string): MigrationFile[] {
  const abs = resolve(dir);
  let names: string[];
  try {
    names = readdirSync(abs);
  } catch {
    throw new TbError("migration_invalid", `migrations directory not found: ${dir}`, 500);
  }
  const files: MigrationFile[] = [];
  for (const f of names.sort()) {
    if (!/\.(sql|ts)$/.test(f)) continue;
    const m = FILE_RE.exec(f);
    if (!m || /(^|_)down(_|$)/.test(m[2] as string)) throw new TbError("migration_invalid", `invalid migration file name: ${f}`, 500);
    const body = readFileSync(join(abs, f));
    files.push({ version: Number(m[1]), name: m[2] as string, file: f, kind: m[3] as "sql" | "ts", sum: sha256(body), body });
  }
  files.forEach((f, i) => {
    if (f.version !== i + 1) throw new TbError("migration_invalid", `migrations must be gap-free from 0001 (at ${f.file})`, 500);
  });
  return files;
}

/**
 * The app migrations not applied yet. v0.1.25 (E2/M3): an applied migration this code does not have is
 * `app_schema_newer` (a newer version wrote the data: a rollback without a restore), not "missing"; a changed file
 * stays `migration_invalid`.
 */
export function pendingAppMigrations(db: RawDb, files: readonly MigrationFile[]): MigrationFile[] {
  const applied = db.prepare("SELECT version, name, sha256 FROM tb_migrations WHERE scope = 'app' ORDER BY version").all() as Row[];
  const newest = applied.reduce((n, a) => Math.max(n, Number(a.version)), 0);
  if (newest > files.length)
    throw new TbError(
      "app_schema_newer",
      `the database is at app schema ${newest}; this version has ${files.length} migrations. A newer version wrote this data: run that version or restore its pre-update snapshot`,
      500,
      { stored: newest, code: files.length },
    );
  for (const a of applied) {
    const f = files[Number(a.version) - 1];
    if (!f) throw new TbError("migration_invalid", `applied migration ${a.version} is missing`, 500);
    if (f.sum !== a.sha256) throw new TbError("migration_invalid", `applied migration ${f.file} changed`, 500);
  }
  return files.slice(applied.length);
}

/** Applies `files` in order, one transaction each; `onEach` runs after every committed file (lock heartbeat). */
export async function applyAppMigrations(db: RawDb, dir: string, files: readonly MigrationFile[], onEach?: (f: MigrationFile) => void): Promise<AppliedMigration[]> {
  const abs = resolve(dir);
  const handle = appDb(db);
  const done: AppliedMigration[] = [];
  for (const f of files) {
    let up: ((d: Db) => unknown) | null = null;
    if (f.kind === "ts") {
      const mod = (await import(pathToFileURL(join(abs, f.file)).href)) as { up?: unknown };
      if (typeof mod.up !== "function") throw new TbError("migration_invalid", `${f.file} must export function up(db)`, 500, { file: f.file });
      up = mod.up as (d: Db) => unknown;
    }
    try {
      tx(db, () => {
        if (up) {
          if (up(handle) instanceof Promise) throw new TbError("migration_invalid", `${f.file}: up(db) must be synchronous`, 500);
        } else handle.exec(f.body.toString("utf8"));
        db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('app', ?, ?, ?, ?)").run(f.version, f.name, f.sum, Date.now());
      });
    } catch (e) {
      // the file name travels with the error (failed-mode health, E2/M2); never the SQL or data
      if (e instanceof TbError) throw new TbError(e.code, e.message, e.httpStatus, { ...(e.details ?? {}), file: f.file });
      throw new TbError("migration_failed", `migration ${f.file} failed: ${e instanceof Error ? e.message : "error"}`, 500, { file: f.file });
    }
    done.push({ version: f.version, name: f.name });
    onEach?.(f);
  }
  return done;
}

/** Applies the app's migration directory; any changed, missing, misnamed or down migration → `migration_invalid`. */
export async function runAppMigrations(db: RawDb, dir: string): Promise<AppliedMigration[]> {
  return applyAppMigrations(db, dir, pendingAppMigrations(db, scanMigrations(dir)));
}
