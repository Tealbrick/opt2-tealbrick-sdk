// Backups, restore, export (SDK-API §7.3, MANIFEST §11): the ONE backup format (`tb-backup-<UTC ts>.tar.gz`, meta.json
// `tealbrick.backup/1`), the ONE export format (`tb-export-<ts>.tar.gz`, `tealbrick.export/1`), the cron runner with
// retention, and restore at boot (`TB_RESTORE_FROM`). The server core calls exactly `restoreAtBoot` (before the store
// opens and migrations run) and `createBackupApi` (once the store is open).
// Never archived: the instance key and the KEK (TB_DATA_DIR/tb/). App-own keys and `ctx.secrets` travel only sealed
// inside app.db (backups); the export never carries tb_keys, tb_secrets, tb_sessions or tb_used_jti.
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, existsSync } from "node:fs";
import { copyFile, lstat, mkdir, readdir, readFile, realpath, rename, rm, stat, statfs, unlink, writeFile } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { ReadableStream } from "node:stream/web";
import { type Ed25519KeyPair, manifestDigest, signInstanceAssertion, ulid } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest, Service } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, BackupApi, BackupHealth, BackupMeta, ExportMeta, Logger } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "./audit.ts";
import { nextRun, parseCron } from "./cron.ts";
import { TbError } from "./errors.ts";
import { serviceHost, TB_EXEC_CONTROL_PORT } from "./service-helper.ts";
import { metaGet, metaSet, openStore, type RawDb, type Row, type SchemaVersion, storedSchema } from "./store.ts";
import { bufferSink, fileSink, readTarGz, type TarSource, writeTarGz } from "./tar.ts";
import { compareVersions, type PreUpdateSnapshot } from "./upgrade.ts";

export interface BackupContext {
  manifest: Manifest;
  dataDir: string;
  backupDir: string;
  instanceId: string;
  sdkVersion: string;
  log: Logger;
  hooks: { beforeBackup?(): Promise<void>; afterRestore?(): Promise<void> } | undefined;
  /** process env (service private addresses, SDK-API §11 via `serviceHost`) */
  env: Record<string, string | undefined>;
  /** the instance key K8: signs the tb-exec control-port assertion */
  instanceKey(): Promise<Ed25519KeyPair>;
  /** the claimed bridge; null → taken from the stored claim record */
  bridgeId(): BridgeId | null;
  /** tb-exec control port; TB_EXEC_CONTROL_PORT unless a test overrides it */
  execPort?: number;
  /** v0.1.22 (SDK-03): called when the backup state changes (status push: attention / health) */
  onStateChange?(): void;
  /** test clock (SDK-03 overdue rule); default Date.now */
  now?(): number;
  /**
   * v0.1.25 (E2/M3): the schema this code can run (app = number of migration files, sdk = SDK_SCHEMA). Restore refuses
   * an archive whose database is newer. Absent (old callers, tests) → no schema check.
   */
  codeSchema?: SchemaVersion;
}

export type { BackupHealth };

/** Persisted in tb_meta so a restart keeps the record (a full volume that fails every night stays visible). */
interface BackupState {
  /** first time this SDK tracked backups for the instance: the overdue clock starts here when no backup succeeded yet */
  since: number;
  lastOkAt: number | null;
  lastFailedAt: number | null;
  lastError: string | null;
  failures: number;
}
const BACKUP_STATE_KEY = "backup_state";

const BACKUP_FORMAT = "tealbrick.backup/1";
const EXPORT_FORMAT = "tealbrick.export/1";
/** v0.1.26 (OD-3): index of the app files an export carries under `files/` (absent when the manifest has no backups.files) */
export const EXPORT_FILES_INDEX = "files.json";
const BACKUP_RE = /^tb-backup-\d{8}T\d{6}\.\d{3}Z\.tar\.gz$/;
/**
 * v0.1.25 (E2/M1): the pre-update snapshot. ONE deterministic name per target version, so Core can name it in
 * TB_RESTORE_FROM without reading the volume: `tb-preupdate-to-<version>.tar.gz` (`+` → `_`). A newer snapshot for the
 * same target replaces the older one. Kept apart from the cron backups (own retention, never in `backups.list()`).
 */
export const PREUPDATE_PREFIX = "tb-preupdate-to-";
export const PREUPDATE_RE = /^tb-preupdate-to-[0-9A-Za-z._-]+\.tar\.gz$/;
export const PREUPDATE_RETAIN = 3;
export const preUpdateName = (toVersion: string): string => `${PREUPDATE_PREFIX}${toVersion.replace(/\+/g, "_")}.tar.gz`;
const META = "meta.json";
const DB_FILE = "app.db";
const META_MAX_BYTES = 1024 * 1024;
const EXEC_TIMEOUT_MS = 30 * 60_000;
const MAX_TIMER_MS = 2 ** 31 - 1;
/** tb_meta key: the archive the current app.db was restored from (TB_RESTORE_FROM is ignored once it matches) */
const RESTORED_KEY = "restore_applied";
const HEX64 = /^[0-9a-f]{64}$/;

type ExecTarget = { ins: InstanceId; bridge: BridgeId; key: Ed25519KeyPair };
type ClaimView = { ins?: InstanceId; bridge?: { id?: BridgeId } };

const message = (e: unknown) => (e instanceof Error ? e.message : "unknown error");

/** `20261011T031700.123Z` — sortable, unique per millisecond. */
function stamp(ms: number): string {
  return new Date(ms).toISOString().replace(/[-:]/g, "");
}

async function freshArchive(dir: string, prefix: string): Promise<{ file: string; createdAt: string }> {
  for (let t = Date.now(); ; t++) {
    const file = `${prefix}${stamp(t)}.tar.gz`;
    if (!existsSync(join(dir, file))) return { file, createdAt: new Date(t).toISOString() };
  }
}

async function hashFile(path: string): Promise<{ sha256: string; bytes: number }> {
  const hash = createHash("sha256");
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
    bytes += (chunk as Buffer).length;
  }
  return { sha256: hash.digest("hex"), bytes };
}

/** rename, or copy + unlink across volumes */
async function move(from: string, to: string): Promise<void> {
  try {
    await rename(from, to);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EXDEV") throw e;
    await copyFile(from, to);
    await unlink(from);
  }
}

const within = (root: string, p: string) => p === root || p.startsWith(root + sep);

/**
 * Root of an app data volume. SPEC-GAP: TB_DATA_DIR is "the data volume mount" (SDK-API §13) while a manifest may
 * declare several data volumes; the first `data` volume is TB_DATA_DIR, any other is its manifest `mountPath`.
 */
function volumeRoot(ctx: BackupContext, volume: string): string | null {
  const data = ctx.manifest.runtime.volumes.filter((v) => v.purpose === "data");
  const i = data.findIndex((v) => v.id === volume);
  if (i < 0) return null;
  return i === 0 ? resolve(ctx.dataDir) : resolve((data[i] as { mountPath: string }).mountPath);
}

/** Never archived nor overwritten by a restore: instance key + KEK dir, the live database files, backup dir, staging. */
function excluded(ctx: BackupContext): string[] {
  const d = resolve(ctx.dataDir);
  return [join(d, "tb"), ...["", "-wal", "-shm", "-journal"].map((s) => join(d, DB_FILE + s)), resolve(ctx.backupDir), join(d, ".tb-restore")];
}

function backupServices(ctx: BackupContext): (Service & { backup: NonNullable<Service["backup"]> })[] {
  return (ctx.manifest.runtime.services ?? []).filter((s): s is Service & { backup: NonNullable<Service["backup"]> } => !!s.backup);
}

// ── tb-exec control port (SDK-API §11): instance assertion, private network only ──
async function exec(ctx: BackupContext, target: ExecTarget, serviceId: string, path: string, body: Uint8Array<ArrayBuffer>, contentType: string, code: string): Promise<Response> {
  const host = serviceHost(ctx.manifest, ctx.env, serviceId);
  if (!host) throw new TbError(code, `no private address for service ${serviceId}`, 503);
  const assertion = await signInstanceAssertion({ key: target.key, ins: target.ins, bridge: target.bridge, method: "POST", pathAndQuery: path, body, now: Math.floor(Date.now() / 1000) });
  let res: Response;
  try {
    res = await fetch(`http://${host.includes(":") ? `[${host}]` : host}:${ctx.execPort ?? TB_EXEC_CONTROL_PORT}${path}`, {
      method: "POST",
      headers: { "content-type": contentType, [BRIDGE_HEADERS.assertion]: assertion },
      body,
      redirect: "error",
      signal: AbortSignal.timeout(EXEC_TIMEOUT_MS),
    });
  } catch {
    throw new TbError(code, `tb-exec of service ${serviceId} not reachable`, 503);
  }
  if (!res.ok) {
    await res.body?.cancel();
    throw new TbError(code, `tb-exec of service ${serviceId} answered ${res.status}`, 502);
  }
  return res;
}

// ── backup ──
/** True when `p` (as the OS resolves it, symlinks followed) is inside `root` (also resolved); a missing path is inside. */
async function realWithin(root: string, p: string): Promise<boolean> {
  try {
    return within(await realpath(root), await realpath(p));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return true;
    throw e;
  }
}

async function collectFiles(ctx: BackupContext): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const skip = excluded(ctx);
  for (const f of ctx.manifest.backups.files ?? []) {
    const root = volumeRoot(ctx, f.volume);
    if (!root) throw new TbError("backup_failed", `backups.files volume ${f.volume} is not an app data volume`, 500);
    const walk = async (abs: string): Promise<void> => {
      if (skip.some((x) => within(x, abs))) return;
      let st: Awaited<ReturnType<typeof lstat>>;
      try {
        st = await lstat(abs);
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === "ENOENT") return;
        throw e;
      }
      if (st.isDirectory()) for (const n of (await readdir(abs)).sort()) await walk(join(abs, n));
      else if (st.isFile()) out.set(`files/${f.volume}/${relative(root, abs).split(sep).join("/")}`, abs);
      // symlinks and special files are not archived
    };
    const start = resolve(root, f.path);
    if (!within(root, start)) throw new TbError("backup_failed", `backups.files path escapes its volume: ${f.path}`, 500);
    // v0.1.26 (OD-3): a symlinked parent directory must not lead out of the volume either (lstat of the leaf alone follows it)
    if (!(await realWithin(root, start))) throw new TbError("backup_failed", `backups.files path escapes its volume through a symlink: ${f.path}`, 500);
    await walk(start);
  }
  return out;
}

type ArchiveOpts = {
  /** fixed archive name (pre-update snapshot; replaces an existing file atomically); default a fresh `tb-backup-<ts>` */
  name?: string;
  /** extra meta.json members (additive: `kind`, `schema`, …); older SDKs ignore them */
  extra?: Record<string, unknown>;
  /** run the app's beforeBackup hook (cron + runNow: yes; boot-time snapshot: no, the app is not started) */
  hook: boolean;
};

async function runBackup(ctx: BackupContext, db: RawDb, audit: AuditLog, isStopped: () => boolean): Promise<{ file: string; meta: BackupMeta }> {
  const result = await buildArchive(ctx, db, { hook: true });
  if (!isStopped()) await audit.record({ actor: "system", action: "backup.create", target: result.file, detail: { parts: result.meta.parts.length } });
  await prune(ctx);
  ctx.log.info("backup created", { file: result.file, parts: result.meta.parts.length });
  return result;
}

async function buildArchive(ctx: BackupContext, db: RawDb, opts: ArchiveOpts): Promise<{ file: string; meta: BackupMeta }> {
  await mkdir(ctx.backupDir, { recursive: true });
  const staging = join(ctx.backupDir, `.tb-staging-${ulid()}`);
  await mkdir(staging);
  let result: { file: string; meta: BackupMeta };
  try {
    if (opts.hook) await ctx.hooks?.beforeBackup?.();
    const parts: BackupMeta["parts"] = [];
    const sources: TarSource[] = [];
    const add = async (name: string, file: string, path: string) => {
      const h = await hashFile(path);
      parts.push({ name, file, sha256: h.sha256, bytes: h.bytes });
      sources.push({ name: file, path, size: h.bytes });
    };
    const dbCopy = join(staging, DB_FILE);
    db.prepare("VACUUM INTO ?").run(dbCopy);
    await add("db", DB_FILE, dbCopy);
    for (const [file, abs] of await collectFiles(ctx)) {
      const copy = join(staging, `part-${parts.length}`);
      await copyFile(abs, copy);
      await add(`file:${file.slice("files/".length)}`, file, copy);
    }
    const services = backupServices(ctx).filter((s) => {
      if (serviceHost(ctx.manifest, ctx.env, s.id)) return true;
      // SPEC-GAP: "per deployed service" — a service without a private address in this deployment is not deployed
      ctx.log.warn("service not deployed; left out of the backup", { service: s.id });
      return false;
    });
    if (services.length) {
      const target = await execTarget(ctx, null);
      if (!target) throw new TbError("backup_failed", "service dumps need a claimed instance (bridge)", 503);
      for (const s of services) {
        const res = await exec(ctx, target, s.id, "/tb/v1/exec/backup", new TextEncoder().encode("{}"), "application/json", "backup_failed");
        if (!res.body) throw new TbError("backup_failed", `tb-exec of service ${s.id} sent no dump`, 502);
        const out = join(staging, `service-${s.id}`);
        await pipeline(Readable.fromWeb(res.body as ReadableStream<Uint8Array>), createWriteStream(out, { flags: "wx" }));
        await add(`service:${s.id}`, `services/${s.id}.${s.backup.extension}`, out);
      }
    }
    const { file, createdAt } = opts.name ? { file: opts.name, createdAt: new Date((ctx.now ?? Date.now)()).toISOString() } : await freshArchive(ctx.backupDir, "tb-backup-");
    const meta: BackupMeta = {
      format: BACKUP_FORMAT,
      product: ctx.manifest.id,
      version: ctx.manifest.version,
      manifestDigest: manifestDigest(ctx.manifest),
      instance: ctx.instanceId as InstanceId,
      sdk: ctx.sdkVersion,
      createdAt,
      parts,
      ...(opts.extra ?? {}),
    };
    const metaPath = join(staging, META);
    await writeFile(metaPath, JSON.stringify(meta, null, 2));
    const tmp = join(staging, "archive.tar.gz");
    await writeTarGz(tmp, [{ name: META, path: metaPath, size: (await stat(metaPath)).size }, ...sources]);
    await rename(tmp, join(ctx.backupDir, file));
    result = { file, meta };
  } catch (e) {
    ctx.log.error("backup failed", { error: message(e) });
    throw e instanceof TbError && e.code === "backup_failed" ? e : new TbError("backup_failed", `backup failed: ${message(e)}`, 500);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
  return result;
}

/**
 * v0.1.25 (E2/M1): the pre-update snapshot, written at boot BEFORE any pending migration runs (same format as a
 * backup; meta `kind: "preupdate"`, `version` = the app version that wrote the data, `fromVersion`/`toVersion`,
 * `schema` = the database schema in the archive). Fails closed: `preupdate_snapshot_no_space` when the backup volume
 * has less free space than 2 × the database, `preupdate_snapshot_failed` on any other error (the caller then migrates
 * nothing). Keeps the newest PREUPDATE_RETAIN snapshots.
 */
export async function writePreUpdateSnapshot(
  ctx: BackupContext,
  db: RawDb,
  opts: { from: string | null; to: string; schema: SchemaVersion; freeBytes?: (dir: string) => Promise<number> },
): Promise<PreUpdateSnapshot> {
  await mkdir(ctx.backupDir, { recursive: true });
  const dbBytes = await dbSize(ctx.dataDir);
  const free = await (opts.freeBytes ?? freeSpace)(ctx.backupDir);
  if (free < 2 * dbBytes)
    throw new TbError("preupdate_snapshot_no_space", `the backup volume has ${free} bytes free; the snapshot needs ${2 * dbBytes}`, 507, { free, needed: 2 * dbBytes });
  const name = preUpdateName(opts.to);
  let out: { file: string; meta: BackupMeta };
  try {
    out = await buildArchive(ctx, db, {
      name,
      hook: false,
      // `version` = the data's version: restore by the previous code passes its "not newer than me" check. A database
      // from before 0.1.25 records no version: "0.0.0" (the schema check on the archived database still applies).
      extra: { kind: "preupdate", version: opts.from ?? "0.0.0", fromVersion: opts.from, toVersion: opts.to, schema: opts.schema },
    });
  } catch (e) {
    throw new TbError("preupdate_snapshot_failed", `pre-update snapshot failed: ${message(e)}`, 500);
  }
  const h = await hashFile(join(ctx.backupDir, out.file));
  await prunePreUpdate(ctx, name);
  ctx.log.info("pre-update snapshot written", { file: out.file, from: opts.from, to: opts.to, bytes: h.bytes });
  return { file: out.file, sha256: h.sha256, bytes: h.bytes, createdAt: out.meta.createdAt, from: opts.from, to: opts.to, schema: opts.schema };
}

async function dbSize(dataDir: string): Promise<number> {
  let n = 0;
  for (const s of ["", "-wal"]) {
    try {
      n += (await stat(join(dataDir, DB_FILE + s))).size;
    } catch {
      // absent
    }
  }
  return n;
}

async function freeSpace(dir: string): Promise<number> {
  try {
    const s = await statfs(dir);
    return Number(s.bavail) * Number(s.bsize);
  } catch {
    return Number.POSITIVE_INFINITY; // statfs unsupported: the write itself fails on a full volume
  }
}

/** Keeps the newest PREUPDATE_RETAIN pre-update snapshots (by mtime), never `keep`. */
async function prunePreUpdate(ctx: BackupContext, keep: string): Promise<void> {
  const names = (await readdir(ctx.backupDir)).filter((n) => PREUPDATE_RE.test(n));
  const dated: { n: string; t: number }[] = [];
  for (const n of names) dated.push({ n, t: n === keep ? Number.POSITIVE_INFINITY : (await stat(join(ctx.backupDir, n))).mtimeMs });
  dated.sort((a, b) => b.t - a.t);
  for (const { n } of dated.slice(PREUPDATE_RETAIN)) {
    await rm(join(ctx.backupDir, n), { force: true });
    ctx.log.info("pre-update snapshot pruned", { file: n });
  }
}

/** Keeps the newest `backups.retain` archives. */
async function prune(ctx: BackupContext): Promise<void> {
  const names = (await readdir(ctx.backupDir)).filter((n) => BACKUP_RE.test(n)).sort();
  for (const n of names.slice(0, Math.max(0, names.length - ctx.manifest.backups.retain))) {
    await rm(join(ctx.backupDir, n), { force: true });
    ctx.log.info("backup pruned", { file: n });
  }
}

function checkMeta(raw: Buffer | null): BackupMeta | null {
  if (!raw) return null;
  let m: Partial<BackupMeta>;
  try {
    m = JSON.parse(raw.toString("utf8")) as Partial<BackupMeta>;
  } catch {
    return null;
  }
  const str = (v: unknown) => typeof v === "string" && v.length > 0;
  if (m?.format !== BACKUP_FORMAT || !str(m.product) || !str(m.version) || !str(m.createdAt) || typeof m.instance !== "string" || !Array.isArray(m.parts)) return null;
  const ok = m.parts.every((p) => str(p?.name) && str(p?.file) && typeof p.sha256 === "string" && HEX64.test(p.sha256) && Number.isSafeInteger(p.bytes) && p.bytes >= 0);
  return ok ? (m as BackupMeta) : null;
}

async function readMeta(archive: string): Promise<BackupMeta | null> {
  let raw: Buffer | null = null;
  await readTarGz(archive, async (e) => {
    if (raw) return "stop";
    return e.name === META ? bufferSink(META_MAX_BYTES, (b) => (raw = b)) : null;
  });
  return checkMeta(raw);
}

async function listBackups(ctx: BackupContext): Promise<{ file: string; meta: BackupMeta }[]> {
  let names: string[];
  try {
    names = (await readdir(ctx.backupDir)).filter((n) => BACKUP_RE.test(n)).sort().reverse();
  } catch {
    return [];
  }
  const out: { file: string; meta: BackupMeta }[] = [];
  for (const file of names) {
    try {
      const meta = await readMeta(join(ctx.backupDir, file));
      if (meta) out.push({ file, meta });
      else ctx.log.warn("backup archive has no valid meta.json", { file });
    } catch (e) {
      ctx.log.warn("backup archive unreadable", { file, error: message(e) });
    }
  }
  return out;
}

// ── export (tb.export) ──
/** JSONL value encoding: BLOBs as `{ "$base64": "…" }`, 64-bit integers beyond 2^53 as strings. */
function jsonValue(_key: string, v: unknown): unknown {
  if (v instanceof Uint8Array) return { $base64: Buffer.from(v).toString("base64") };
  if (typeof v === "bigint") return v.toString();
  return v;
}

const quoteIdent = (name: string) => `"${name.replace(/"/g, '""')}"`;

async function runExport(ctx: BackupContext, db: RawDb): Promise<{ file: string; meta: ExportMeta; stream: globalThis.ReadableStream<Uint8Array> }> {
  await mkdir(ctx.backupDir, { recursive: true });
  const staging = join(ctx.backupDir, `.tb-staging-${ulid()}`);
  await mkdir(staging);
  try {
    // one consistent snapshot, read off the live connection
    const snapshot = join(staging, "snapshot.db");
    db.prepare("VACUUM INTO ?").run(snapshot);
    const snap = new DatabaseSync(snapshot, { readOnly: true });
    const files: ExportMeta["files"] = [];
    const sources: TarSource[] = [];
    try {
      const dump = async (file: string, sql: string) => {
        const path = join(staging, `part-${sources.length}.jsonl`);
        const out = createWriteStream(path, { flags: "wx" });
        const hash = createHash("sha256");
        let rows = 0;
        let bytes = 0;
        await pipeline(
          Readable.from(
            (function* () {
              for (const row of snap.prepare(sql).iterate()) {
                const line = Buffer.from(`${JSON.stringify(row, jsonValue)}\n`, "utf8");
                hash.update(line);
                rows += 1;
                bytes += line.length;
                yield line;
              }
            })(),
          ),
          out,
        );
        files.push({ file, rows, sha256: hash.digest("hex") });
        sources.push({ name: file, path, size: bytes });
      };
      const tables = snap
        .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'tb\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\' ORDER BY name")
        .all() as { name: string }[];
      // SPEC-GAP: §7.3 names "one JSONL file per app table" beside receipts.jsonl/audit.jsonl; app tables live under
      // tables/ so an app table called `receipts` or `audit` cannot collide with them.
      for (const t of tables) await dump(`tables/${encodeURIComponent(t.name)}.jsonl`, `SELECT * FROM ${quoteIdent(t.name)}`);
      await dump("receipts.jsonl", "SELECT * FROM tb_receipts ORDER BY created_at, id");
      await dump("audit.jsonl", "SELECT * FROM tb_audit ORDER BY at, id");
      // v0.1.26 (OD-3): the manifest `backups.files` paths travel under files/<volume>/<path> with a files.json index
      // [{path, volume, bytes, sha256}] (additive: an app without backups.files gets exactly the archive it had before).
      // Same walk as the backup (collectFiles): inside the volume, symlinks and special files left out, the live
      // database / instance key / backup dir excluded. Each file is copied to staging first so the hash is of the bytes archived.
      if (ctx.manifest.backups.files?.length) {
        const index: { path: string; volume: string; bytes: number; sha256: string }[] = [];
        for (const [entry, abs] of await collectFiles(ctx)) {
          const copy = join(staging, `file-${index.length}`);
          await copyFile(abs, copy);
          const h = await hashFile(copy);
          const [volume, ...rest] = entry.slice("files/".length).split("/");
          index.push({ path: rest.join("/"), volume: volume as string, bytes: h.bytes, sha256: h.sha256 });
          sources.push({ name: entry, path: copy, size: h.bytes });
        }
        const indexPath = join(staging, "files.json");
        await writeFile(indexPath, JSON.stringify(index, null, 2));
        sources.push({ name: EXPORT_FILES_INDEX, path: indexPath, size: (await stat(indexPath)).size });
      }
    } finally {
      snap.close();
    }
    const { file, createdAt } = await freshArchive(ctx.backupDir, "tb-export-");
    const meta: ExportMeta = { format: EXPORT_FORMAT, product: ctx.manifest.id, version: ctx.manifest.version, instance: ctx.instanceId as InstanceId, sdk: ctx.sdkVersion, createdAt, files };
    const metaPath = join(staging, META);
    await writeFile(metaPath, JSON.stringify(meta, null, 2));
    const tmp = join(staging, "archive.tar.gz");
    await writeTarGz(tmp, [{ name: META, path: metaPath, size: (await stat(metaPath)).size }, ...sources]);
    // SPEC-GAP: retention covers backups only; export archives stay on the backup volume until removed.
    const final = join(ctx.backupDir, file);
    await rename(tmp, final);
    ctx.log.info("export created", { file, files: files.length });
    return { file, meta, stream: Readable.toWeb(createReadStream(final)) as unknown as globalThis.ReadableStream<Uint8Array> };
  } catch (e) {
    ctx.log.error("export failed", { error: message(e) });
    throw new TbError("export_failed", `export failed: ${message(e)}`, 500);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

// ── restore (TB_RESTORE_FROM, at boot) ──
function readStored(dbPath: string): { restored: string | null; claim: ClaimView | null } {
  if (!existsSync(dbPath)) return { restored: null, claim: null };
  let db: DatabaseSync | null = null;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
    return { restored: metaGet<string>(db, RESTORED_KEY), claim: metaGet<ClaimView>(db, "claim") };
  } catch {
    return { restored: null, claim: null };
  } finally {
    db?.close();
  }
}

async function execTarget(ctx: BackupContext, claim: ClaimView | null): Promise<ExecTarget | null> {
  const stored = claim ?? readStored(join(ctx.dataDir, DB_FILE)).claim;
  const bridge = ctx.bridgeId() ?? stored?.bridge?.id ?? null;
  const ins = (ctx.instanceId || stored?.ins || null) as InstanceId | null;
  if (!bridge || !ins) return null;
  return { ins, bridge, key: await ctx.instanceKey() };
}

interface VerifiedArchive {
  meta: BackupMeta;
  db: string;
  files: { staged: string; target: string }[];
  services: { id: string; staged: string }[];
}

/** Extracts every part into `dir` and checks it against meta.json (sha256, size, a known destination). */
async function extractVerified(ctx: BackupContext, archive: string, dir: string): Promise<VerifiedArchive> {
  const got = new Map<string, { path: string; sha256: string; bytes: number }>();
  let raw: Buffer | null = null;
  await readTarGz(archive, async (e) => {
    if (e.name === META) return bufferSink(META_MAX_BYTES, (b) => (raw = b));
    const path = join(dir, `part-${got.size}`);
    const sink = await fileSink(path, (r) => got.set(e.name, { path, ...r }));
    got.set(e.name, { path, sha256: "", bytes: -1 });
    return sink;
  });
  const meta = checkMeta(raw);
  if (!meta) throw new TbError("restore_failed", "archive has no valid meta.json", 500, { reason: "meta_invalid" });
  if (meta.product !== ctx.manifest.id) throw new TbError("restore_failed", `archive belongs to product ${meta.product}`, 500, { reason: "product_mismatch" });
  // v0.1.25 (E2/M3): never restore data a NEWER app version wrote (this code cannot read it; older data migrates forward)
  let newer: boolean;
  try {
    newer = compareVersions(meta.version, ctx.manifest.version) > 0;
  } catch {
    throw new TbError("restore_failed", `archive version ${meta.version} is not a version`, 500, { reason: "version_invalid" });
  }
  if (newer) throw new TbError("restore_failed", `archive was written by version ${meta.version}; this is ${ctx.manifest.version}`, 500, { reason: "version_newer" });
  const listed = new Set(meta.parts.map((p) => p.file));
  for (const name of got.keys()) if (!listed.has(name)) throw new TbError("restore_failed", `archive entry ${name} is not listed in meta.json`, 500);
  const out: VerifiedArchive = { meta, db: "", files: [], services: [] };
  const skip = excluded(ctx);
  const fileVolumes = new Set((ctx.manifest.backups.files ?? []).map((f) => f.volume));
  for (const p of meta.parts) {
    const g = got.get(p.file);
    if (!g) throw new TbError("restore_failed", `part ${p.file} is missing from the archive`, 500);
    if (g.sha256 !== p.sha256 || g.bytes !== p.bytes) throw new TbError("restore_failed", `part ${p.file} fails its sha256 check`, 500);
    if (p.file === DB_FILE) {
      out.db = g.path;
      continue;
    }
    const fm = /^files\/([^/]+)\/(.+)$/.exec(p.file);
    if (fm) {
      const root = fileVolumes.has(fm[1] as string) ? volumeRoot(ctx, fm[1] as string) : null;
      const target = root ? resolve(root, fm[2] as string) : null;
      if (!root || !target || !within(root, target) || target === root || skip.some((x) => within(x, target)))
        throw new TbError("restore_failed", `part ${p.file} has no destination in this manifest`, 500);
      out.files.push({ staged: g.path, target });
      continue;
    }
    const sm = /^services\/(.+)$/.exec(p.file);
    const svc = sm ? backupServices(ctx).find((s) => sm[1] === `${s.id}.${s.backup.extension}`) : undefined;
    if (!svc) throw new TbError("restore_failed", `part ${p.file} has no destination in this manifest`, 500);
    out.services.push({ id: svc.id, staged: g.path });
  }
  if (!out.db) throw new TbError("restore_failed", "archive has no app.db part", 500);
  // v0.1.25 (E2/M3): the archived database itself must not be at a schema this code does not have (meta can lie or be old)
  if (ctx.codeSchema) {
    const got = schemaOfFile(out.db);
    if (got === null) throw new TbError("restore_failed", "archived app.db cannot be read", 500, { reason: "db_invalid" });
    if (got.app > ctx.codeSchema.app || got.sdk > ctx.codeSchema.sdk)
      throw new TbError("restore_failed", `archived data is at schema app ${got.app} / sdk ${got.sdk}; this code has app ${ctx.codeSchema.app} / sdk ${ctx.codeSchema.sdk}`, 500, {
        reason: "schema_newer",
      });
  }
  return out;
}

/** Schema of a database file (read only); `{0,0}` without tb_migrations; null when unreadable. */
function schemaOfFile(path: string): SchemaVersion | null {
  if (!existsSync(path)) return null;
  let db: DatabaseSync | null = null;
  try {
    db = new DatabaseSync(path, { readOnly: true });
    const has = db.prepare("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'tb_migrations'").get() as Row | undefined;
    return has ? storedSchema(db) : { app: 0, sdk: 0 };
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

/** v0.1.25: what restoreAtBoot did (startApp logs it and reports `lastRestore` in health). */
export interface RestoreOutcome {
  archive: string;
  applied: boolean;
  /** already_applied: this archive (name + createdAt) was restored before; snapshot_missing / same_schema: pre-update rules */
  skipped?: "already_applied" | "snapshot_missing" | "same_schema";
  /** archive createdAt = the data cut-off of an applied restore */
  createdAt?: string;
  version?: string;
}

/**
 * Runs before the store opens. `TB_RESTORE_FROM` set → verify every part of that archive (in TB_BACKUP_DIR), then
 * replace app.db and the files, restore each service through tb-exec, call `afterRestore`, record `backup.restore`.
 * Any failure → `restore_failed` with app.db and files rolled back. The same archive on a later boot is ignored.
 *
 * v0.1.25 (E2/M3) — refusals BEFORE anything is replaced: another product, an archive written by a NEWER app version,
 * an archived database at a schema newer than this code (`details.reason`). Pre-update snapshots
 * (`tb-preupdate-to-<v>.tar.gz`, the rollback Core asks for after a failed update) follow two extra rules:
 * - missing → nothing to undo when the current data is at a schema this code runs (the failed version stopped before its
 *   snapshot, so it migrated nothing): skipped. Missing with newer data → `restore_failed` reason `snapshot_missing`.
 * - the current data is at the snapshot's schema (the failed version migrated nothing): skipped, data kept.
 * "Already applied" compares name AND createdAt, so a newer snapshot under the same name is restored again.
 */
export async function restoreAtBoot(ctx: BackupContext, restoreFrom: string | null): Promise<RestoreOutcome | null> {
  if (restoreFrom === null) return null;
  const fail = (reason: string, code = "restore_failed") => {
    ctx.log.error("restore failed", { archive: restoreFrom, reason });
    return new TbError("restore_failed", `restore failed: ${reason}`, 500, { reason: code });
  };
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(restoreFrom) || restoreFrom.includes("..")) throw fail("TB_RESTORE_FROM must be an archive file name in TB_BACKUP_DIR", "name_invalid");
  const archive = join(ctx.backupDir, restoreFrom);
  const dbPath = join(ctx.dataDir, DB_FILE);
  const preupdate = PREUPDATE_RE.test(restoreFrom);
  const current = existsSync(dbPath) ? schemaOfFile(dbPath) : null;
  const runnable = (s: SchemaVersion | null) => !s || !ctx.codeSchema || (s.app <= ctx.codeSchema.app && s.sdk <= ctx.codeSchema.sdk);
  if (!existsSync(archive)) {
    if (preupdate && runnable(current)) {
      ctx.log.info("pre-update snapshot not found and the data is at a schema this version runs; nothing to restore", { archive: restoreFrom });
      return { archive: restoreFrom, applied: false, skipped: "snapshot_missing" };
    }
    throw fail(`archive ${restoreFrom} not found in TB_BACKUP_DIR`, preupdate ? "snapshot_missing" : "archive_missing");
  }
  const head = await readMeta(archive).catch(() => null);
  const marker = head ? `${restoreFrom}@${head.createdAt}` : restoreFrom;
  const before = readStored(dbPath);
  if (before.restored === marker || (!preupdate && before.restored === restoreFrom)) {
    ctx.log.info("restore already applied; TB_RESTORE_FROM ignored", { archive: restoreFrom });
    return { archive: restoreFrom, applied: false, skipped: "already_applied" };
  }
  const headSchema = (head as { schema?: SchemaVersion } | null)?.schema;
  if (preupdate && current && headSchema && current.app === headSchema.app && current.sdk === headSchema.sdk && runnable(current)) {
    ctx.log.info("data is at the pre-update schema (the failed version changed no schema); restore skipped, data kept", { archive: restoreFrom });
    return { archive: restoreFrom, applied: false, skipped: "same_schema" };
  }
  const staging = join(ctx.dataDir, ".tb-restore");
  await rm(staging, { recursive: true, force: true });
  await mkdir(join(staging, "in"), { recursive: true });
  await mkdir(join(staging, "old"));
  const undo: (() => Promise<void>)[] = [];
  const replace = async (target: string, staged: string | null) => {
    const old = join(staging, "old", String(undo.length));
    let had = false;
    try {
      await move(target, old);
      had = true;
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    undo.push(async () => {
      await rm(target, { force: true });
      if (had) await move(old, target);
    });
    if (staged) {
      await mkdir(dirname(target), { recursive: true });
      await move(staged, target);
    }
  };
  let keepStaging = false;
  let outcome: RestoreOutcome = { archive: restoreFrom, applied: false };
  try {
    const v = await extractVerified(ctx, archive, join(staging, "in"));
    const target = v.services.length ? await execTarget(ctx, before.claim ?? readStored(v.db).claim) : null;
    if (v.services.length && !target) throw new TbError("restore_failed", "service restore needs a claimed instance (bridge)", 503);
    for (const s of ["-wal", "-shm", "-journal"]) await replace(dbPath + s, null);
    await replace(dbPath, v.db);
    for (const f of v.files) await replace(f.target, f.staged);
    const db = openStore(ctx.dataDir, { manifest: ctx.manifest });
    try {
      metaSet(db, RESTORED_KEY, marker);
      // v0.1.25: a snapshot taken during an upgrade carries that boot's migration lock row; it means nothing here
      db.exec("DELETE FROM tb_migration_lock");
      await createAuditLog(db, []).record({ actor: "system", action: "backup.restore", target: restoreFrom, detail: { createdAt: v.meta.createdAt, version: v.meta.version, instance: v.meta.instance } });
    } finally {
      db.close();
    }
    for (const s of v.services) {
      const res = await exec(ctx, target as ExecTarget, s.id, "/tb/v1/exec/restore", await readFile(s.staged), "application/octet-stream", "restore_failed");
      const body = (await res.json().catch(() => null)) as { ok?: unknown } | null;
      if (body?.ok !== true) throw new TbError("restore_failed", `tb-exec of service ${s.id} did not confirm the restore`, 502);
    }
    await ctx.hooks?.afterRestore?.();
    ctx.log.info("restore applied", { archive: restoreFrom, createdAt: v.meta.createdAt, parts: v.meta.parts.length });
    outcome = { archive: restoreFrom, applied: true, createdAt: v.meta.createdAt, version: v.meta.version };
  } catch (e) {
    for (const u of undo.reverse()) {
      try {
        await u();
      } catch (ue) {
        keepStaging = true;
        ctx.log.error("restore rollback step failed; previous files kept for manual recovery", { staging, error: message(ue) });
      }
    }
    const reason = e instanceof TbError && typeof e.details?.reason === "string" ? e.details.reason : "restore_failed";
    throw fail(message(e), reason);
  } finally {
    if (!keepStaging) await rm(staging, { recursive: true, force: true });
  }
  return outcome;
}

/** Backup runner (cron, UTC, retention) + export (tb.export). Returns the RunningApp `backups` member and a stop function. */
export function createBackupApi(ctx: BackupContext & { db: RawDb; audit: AuditLog }): {
  api: BackupApi;
  stop(): void;
  health(): BackupHealth;
  attention(): { code: string; reason: string } | null;
} {
  let stopped = false;
  let timer: NodeJS.Timeout | null = null;
  let chain: Promise<unknown> = Promise.resolve();
  const now = ctx.now ?? Date.now;
  const serial = <T>(fn: () => Promise<T>): Promise<T> => {
    const run = chain.then(fn, fn);
    chain = run.catch(() => undefined);
    return run;
  };
  // v0.1.22 (SDK-03, L3): every backup run (scheduled or runNow) records its outcome; failures are never swallowed
  const readState = (): BackupState => {
    const s = metaGet<BackupState>(ctx.db, BACKUP_STATE_KEY);
    if (s && typeof s.since === "number") return s;
    const fresh: BackupState = { since: now(), lastOkAt: null, lastFailedAt: null, lastError: null, failures: 0 };
    metaSet(ctx.db, BACKUP_STATE_KEY, fresh);
    return fresh;
  };
  readState();
  const record = (patch: (s: BackupState) => BackupState): void => {
    try {
      metaSet(ctx.db, BACKUP_STATE_KEY, patch(readState()));
    } catch (e) {
      ctx.log.error("backup state not recorded", { error: message(e) });
    }
    ctx.onStateChange?.();
  };
  const api: BackupApi = {
    runNow: () =>
      serial(() => runBackup(ctx, ctx.db, ctx.audit, () => stopped)).then(
        (r) => {
          record((s) => ({ ...s, lastOkAt: now(), failures: 0, lastError: null }));
          return r;
        },
        (e: unknown) => {
          record((s) => ({ ...s, lastFailedAt: now(), failures: s.failures + 1, lastError: e instanceof TbError ? e.code : "backup_failed" }));
          throw e;
        },
      ),
    list: () => listBackups(ctx),
    exportNow: () => serial(() => runExport(ctx, ctx.db)),
  };
  let cron: ReturnType<typeof parseCron> | null = null;
  let schedule: BackupHealth["schedule"] = "ok";
  try {
    cron = parseCron(ctx.manifest.backups.schedule);
    if (!nextRun(cron, new Date(now()))) schedule = "never_fires";
  } catch (e) {
    schedule = "invalid";
    ctx.log.error("backup schedule invalid; scheduled backups disabled", { error: message(e) });
  }
  /** one schedule period = the gap between the next two fire times (0 when unknown) */
  const period = (): number => {
    if (!cron) return 0;
    const a = nextRun(cron, new Date(now()));
    const b = a ? nextRun(cron, a) : null;
    return a && b ? b.getTime() - a.getTime() : 0;
  };
  const health = (): BackupHealth => {
    const s = readState();
    const p = period();
    const newest = s.lastOkAt ?? s.since;
    return {
      schedule,
      lastOkAt: s.lastOkAt === null ? null : (new Date(s.lastOkAt).toISOString() as BackupHealth["lastOkAt"]),
      lastFailedAt: s.lastFailedAt === null ? null : (new Date(s.lastFailedAt).toISOString() as BackupHealth["lastFailedAt"]),
      lastError: s.lastError,
      failures: s.failures,
      // no good backup for more than two periods (the first period counts from `since`)
      overdue: schedule === "ok" && p > 0 && now() - newest > 2 * p,
    };
  };
  const attention = (): { code: string; reason: string } | null => {
    if (schedule === "invalid") return { code: "backup_schedule_invalid", reason: "The backup schedule is not valid, so no scheduled backup runs. Update the app." };
    if (schedule === "never_fires") return { code: "backup_schedule_never", reason: "The backup schedule never fires, so no scheduled backup runs. Update the app." };
    const h = health();
    const last = h.lastOkAt ? `The newest good backup is from ${h.lastOkAt.slice(0, 16).replace("T", " ")} UTC.` : "There is no good backup yet.";
    if (h.failures > 0) return { code: "backup_failed", reason: `${h.failures === 1 ? "The last backup" : `The last ${h.failures} backups`} failed (${h.lastError ?? "backup_failed"}). ${last}` };
    if (h.overdue) return { code: "backup_overdue", reason: `No backup ran for more than two schedule periods. ${last}` };
    return null;
  };
  const arm = (): void => {
    if (stopped || !cron) return;
    const next = nextRun(cron, new Date());
    if (!next) {
      ctx.log.warn("backup schedule never fires", { schedule: ctx.manifest.backups.schedule });
      return;
    }
    timer = setTimeout(
      () => {
        if (stopped) return;
        if (Date.now() < next.getTime()) return arm();
        api.runNow().then(
          () => arm(),
          () => arm(),
        );
      },
      Math.min(Math.max(0, next.getTime() - Date.now()), MAX_TIMER_MS),
    );
    timer.unref();
  };
  arm();
  return {
    api,
    health,
    attention,
    stop() {
      stopped = true;
      if (timer) clearTimeout(timer);
    },
  };
}
