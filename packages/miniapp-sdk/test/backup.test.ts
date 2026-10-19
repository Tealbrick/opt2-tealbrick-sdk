// Backups, restore, export (SDK-API §7.3): real archives in temp dirs, a fake tb-exec control port that verifies the
// instance assertion, a startApp round trip, and the refusals (tampered part, traversal, foreign product).
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, ulid, verifyAssertion } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type BridgeId, type InstanceId, type Sha256Digest, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { BackupMeta, ExportMeta } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import { type BackupContext, createBackupApi, restoreAtBoot } from "../src/server/backup.ts";
import { nextRun, parseCron } from "../src/server/cron.ts";
import { TbError } from "../src/server/errors.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { createLogger, SecretRegistry } from "../src/server/log.ts";
import { Receipts } from "../src/server/receipts.ts";
import { openStore, type RawDb } from "../src/server/store.ts";
import { bufferSink, readTarGz, writeTarGz } from "../src/server/tar.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { freePort, migrationsDir, nowS, tempDir } from "./helpers.ts";

const quiet = createLogger("error", new SecretRegistry(), {}, { write() {} });
const plain = (rows: unknown[]) => rows.map((r) => ({ ...(r as object) }));
const isCode = (code: string) => (e: unknown) => e instanceof TbError && e.code === code;
const sha = (b: Uint8Array) => createHash("sha256").update(b).digest("hex");

async function entries(file: string): Promise<Map<string, Buffer>> {
  const out = new Map<string, Buffer>();
  await readTarGz(file, async (e) => bufferSink(64 * 1024 * 1024, (b) => out.set(e.name, b)));
  return out;
}

/** Hand-built ustar (no safety checks) for the refusal tests. */
function rawTarGz(items: { name: string; body: Buffer; type?: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const it of items) {
    const h = Buffer.alloc(512);
    h.write(it.name, 0, 100, "utf8");
    h.write("0000644\0", 100, "latin1");
    h.write("0000000\0", 108, "latin1");
    h.write("0000000\0", 116, "latin1");
    h.write(`${it.body.length.toString(8).padStart(11, "0")}\0`, 124, "latin1");
    h.write("00000000000\0", 136, "latin1");
    h.fill(0x20, 148, 156);
    h.write(it.type ?? "0", 156, "latin1");
    h.write("ustar\u000000", 257, "latin1");
    let sum = 0;
    for (const b of h) sum += b;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "latin1");
    blocks.push(h, it.body, Buffer.alloc((512 - (it.body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(blocks));
}

interface FakeExec {
  port: number;
  dumps: number;
  restores: Buffer[];
  rejected: number;
  stop(): Promise<void>;
}

/** tb-exec control port double: accepts only instance assertions from `key` for `brg`, no `svc`. */
async function fakeExec(key: Ed25519KeyPair, ins: InstanceId, brg: BridgeId, dump: Buffer): Promise<FakeExec> {
  const keys = keySetFrom({ keys: [key.publicJwk] }, `tb:ins:${ins}`);
  const state = { dumps: 0, restores: [] as Buffer[], rejected: 0 };
  const server: Server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = Buffer.concat(chunks);
    const token = String(req.headers[BRIDGE_HEADERS.assertion.toLowerCase()] ?? "");
    const r = verifyAssertion(token, keys, { typ: TYP.instanceAssertion, aud: `tb:brg:${brg}`, now: nowS(), method: req.method ?? "", pathAndQuery: req.url ?? "", body });
    if (!r.ok || r.claims.svc !== undefined) {
      state.rejected += 1;
      res.writeHead(401);
      return void res.end();
    }
    if (req.url === "/tb/v1/exec/backup") {
      state.dumps += 1;
      res.writeHead(200, { "content-type": "application/octet-stream" });
      return void res.end(dump);
    }
    if (req.url === "/tb/v1/exec/restore") {
      state.restores.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end('{"ok":true}');
    }
    res.writeHead(404);
    res.end();
  });
  const port = await freePort();
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", r));
  return Object.assign(state, {
    port,
    stop: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  });
}

interface Rig {
  dir: string;
  ctx: BackupContext;
  db: RawDb;
  api: ReturnType<typeof createBackupApi>;
  key: Ed25519KeyPair;
  ins: InstanceId;
  brg: BridgeId;
  reopen(): void;
  cleanup(): Promise<void>;
}

async function rig(opts: { retain?: number; files?: Manifest["backups"]["files"]; service?: { dump: Buffer; bridgeForCtx?: BridgeId } } = {}): Promise<Rig & { exec: FakeExec | null }> {
  const t = tempDir("tb-backup-test-");
  const dataDir = join(t.dir, "data");
  const manifest = fixtureManifest(1);
  manifest.backups = { schedule: "17 3 * * *", retain: opts.retain ?? 3, ...(opts.files ? { files: opts.files } : {}) };
  const key = await generateKeyPair();
  const ins = `ins_${ulid()}` as InstanceId;
  const brg = `brg_${ulid()}` as BridgeId;
  const env: Record<string, string> = {};
  let exec: FakeExec | null = null;
  if (opts.service) {
    exec = await fakeExec(key, ins, brg, opts.service.dump);
    manifest.runtime.services = [
      {
        id: "pg",
        build: { context: "svc", dockerfile: "Dockerfile" },
        port: 5432,
        resources: { cpu: 0.5, memoryMb: 256 },
        health: { kind: "tcp" },
        startOrder: 1,
        backup: { dump: ["pg_dump"], restore: ["psql"], extension: "sql" },
      },
    ];
    manifest.runtime.env = [{ name: "PG_URL", value: "postgres://{{services.pg.host}}:5432/app" }];
    env.PG_URL = "postgres://127.0.0.1:5432/app";
  }
  const ctx: BackupContext = {
    manifest,
    dataDir,
    backupDir: join(dataDir, "backup"),
    instanceId: ins,
    sdkVersion: "0.1.0",
    log: quiet,
    hooks: undefined,
    env,
    instanceKey: async () => key,
    bridgeId: () => opts.service?.bridgeForCtx ?? brg,
    ...(exec ? { execPort: exec.port } : {}),
  };
  const r = {
    dir: t.dir,
    ctx,
    db: openStore(dataDir),
    api: null as unknown as ReturnType<typeof createBackupApi>,
    key,
    ins,
    brg,
    exec,
    reopen() {
      r.api?.stop();
      r.db = openStore(dataDir);
      r.api = createBackupApi({ ...ctx, db: r.db, audit: createAuditLog(r.db, []) });
    },
    async cleanup() {
      r.api.stop();
      if (r.db.isOpen) r.db.close();
      await exec?.stop();
      t.cleanup();
    },
  };
  r.db.exec("CREATE TABLE notes (id TEXT PRIMARY KEY, title TEXT NOT NULL); CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)");
  r.db.exec("INSERT INTO notes VALUES ('n1', 'first'), ('n2', 'second'); INSERT INTO blobs VALUES (1, x'00ff10')");
  r.api = createBackupApi({ ...ctx, db: r.db, audit: createAuditLog(r.db, []) });
  return r;
}

const titles = (db: DatabaseSync | RawDb) => (db.prepare("SELECT title FROM notes ORDER BY id").all() as { title: string }[]).map((x) => x.title);

test("cron: the 5-field subset, UTC, next run and refusals", () => {
  const daily = parseCron("17 3 * * *");
  assert.equal(nextRun(daily, new Date("2026-10-11T03:16:30Z"))?.toISOString(), "2026-10-11T03:17:00.000Z");
  assert.equal(nextRun(daily, new Date("2026-10-11T03:17:00Z"))?.toISOString(), "2026-10-12T03:17:00.000Z");
  assert.equal(nextRun(parseCron("*/15 * * * *"), new Date("2026-10-11T10:16:00Z"))?.toISOString(), "2026-10-11T10:30:00.000Z");
  // 2026-10-11 is a Sunday; 7 = Sunday
  assert.equal(nextRun(parseCron("0 0 * * 7"), new Date("2026-10-11T00:00:00Z"))?.toISOString(), "2026-10-18T00:00:00.000Z");
  // both day fields restricted → either matches (Monday the 12th comes before the 1st)
  assert.equal(nextRun(parseCron("0 0 1 * 1"), new Date("2026-10-11T12:00:00Z"))?.toISOString(), "2026-10-12T00:00:00.000Z");
  assert.equal(nextRun(parseCron("30 4 1-3 12 *"), new Date("2026-10-11T00:00:00Z"))?.toISOString(), "2026-12-01T04:30:00.000Z");
  assert.equal(nextRun(parseCron("0 12 5/10 * *"), new Date("2026-10-06T00:00:00Z"))?.toISOString(), "2026-10-15T12:00:00.000Z");
  assert.equal(nextRun(parseCron("0 0 31 2 *"), new Date("2026-01-01T00:00:00Z")), null);
  for (const bad of ["60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "* * * *", "*/0 * * * *", "5-1 * * * *", "a * * * *"])
    assert.throws(() => parseCron(bad), isCode("backup_invalid"), bad);
});

test("tar: round trip incl. a long name via the ustar prefix; unsafe names refused on write and read", async () => {
  const t = tempDir();
  try {
    const long = `${"d".repeat(120)}/${"f".repeat(90)}.bin`;
    writeFileSync(join(t.dir, "a"), "alpha");
    writeFileSync(join(t.dir, "b"), Buffer.alloc(1500, 7));
    await writeTarGz(join(t.dir, "x.tar.gz"), [
      { name: "a.txt", path: join(t.dir, "a"), size: 5 },
      { name: long, path: join(t.dir, "b"), size: 1500 },
    ]);
    const got = await entries(join(t.dir, "x.tar.gz"));
    assert.deepEqual([...got.keys()], ["a.txt", long]);
    assert.equal(got.get("a.txt")?.toString(), "alpha");
    assert.equal(got.get(long)?.length, 1500);
    await assert.rejects(writeTarGz(join(t.dir, "y.tar.gz"), [{ name: "z".repeat(256), path: join(t.dir, "a"), size: 5 }]), isCode("archive_invalid"));
    await assert.rejects(writeTarGz(join(t.dir, "y2.tar.gz"), [{ name: "../a", path: join(t.dir, "a"), size: 5 }]), isCode("archive_invalid"));
    for (const [name, type] of [
      ["../evil", "0"],
      ["/etc/evil", "0"],
      ["ok/../../evil", "0"],
      ["link", "2"],
      ["dir", "5"],
    ] as const) {
      writeFileSync(join(t.dir, "bad.tar.gz"), rawTarGz([{ name, body: Buffer.from("x"), type }]));
      await assert.rejects(entries(join(t.dir, "bad.tar.gz")), isCode("archive_invalid"), name);
    }
    writeFileSync(join(t.dir, "dup.tar.gz"), rawTarGz([{ name: "a", body: Buffer.from("x") }, { name: "a", body: Buffer.from("y") }]));
    await assert.rejects(entries(join(t.dir, "dup.tar.gz")), isCode("archive_invalid"));
    const plain = gunzipSync(rawTarGz([{ name: "a", body: Buffer.alloc(2000, 1) }]));
    writeFileSync(join(t.dir, "trunc.tar.gz"), gzipSync(plain.subarray(0, 1200)));
    await assert.rejects(entries(join(t.dir, "trunc.tar.gz")), isCode("archive_invalid"));
    const badSum = Buffer.from(plain);
    badSum[0] = 0x62;
    writeFileSync(join(t.dir, "sum.tar.gz"), gzipSync(badSum));
    await assert.rejects(entries(join(t.dir, "sum.tar.gz")), isCode("archive_invalid"));
  } finally {
    t.cleanup();
  }
});

test("runNow: archive with correct meta, sha256 per part, files, service dump over an asserted control port; secrets stay out", async () => {
  const dump = Buffer.from("-- pg dump\nCREATE TABLE t();\n");
  const r = await rig({ files: [{ volume: "data", path: "." }], service: { dump } });
  try {
    mkdirSync(join(r.ctx.dataDir, "uploads", "deep"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "uploads", "deep", "a.txt"), "upload-a");
    mkdirSync(join(r.ctx.dataDir, "tb"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "tb", "kek"), "KEK-MUST-NOT-LEAVE");
    writeFileSync(join(r.ctx.dataDir, "tb", "instance-key"), "INSTANCE-KEY-MUST-NOT-LEAVE");
    r.db.prepare("INSERT INTO tb_secrets (name, sealed, updated_at) VALUES ('s', 'SEALED-SECRET-BLOB', 1)").run();

    const { file, meta } = await r.api.api.runNow();
    assert.match(file, /^tb-backup-\d{8}T\d{6}\.\d{3}Z\.tar\.gz$/);
    assert.equal(meta.format, "tealbrick.backup/1");
    assert.equal(meta.product, "jotter");
    assert.equal(meta.version, "1.0.0");
    assert.equal(meta.instance, r.ins);
    assert.equal(meta.sdk, "0.1.0");
    assert.match(meta.manifestDigest, /^sha256:[0-9a-f]{64}$/);
    assert.ok(!Number.isNaN(Date.parse(meta.createdAt)));
    assert.deepEqual(meta.parts.map((p) => p.file).sort(), ["app.db", "files/data/uploads/deep/a.txt", "services/pg.sql"]);

    const got = await entries(join(r.ctx.backupDir, file));
    assert.deepEqual(JSON.parse(got.get("meta.json")?.toString() ?? "null"), meta);
    for (const p of meta.parts) {
      const body = got.get(p.file) as Buffer;
      assert.equal(sha(body), p.sha256, p.file);
      assert.equal(body.length, p.bytes);
    }
    assert.equal(got.get("files/data/uploads/deep/a.txt")?.toString(), "upload-a");
    assert.deepEqual(got.get("services/pg.sql"), dump);
    assert.equal(r.exec?.dumps, 1);
    assert.equal(r.exec?.rejected, 0);
    const all = Buffer.concat([...got.values()]).toString("latin1");
    assert.ok(!all.includes("KEK-MUST-NOT-LEAVE") && !all.includes("INSTANCE-KEY-MUST-NOT-LEAVE"));
    // ctx.secrets travel sealed inside app.db
    const snap = join(r.dir, "snap.db");
    writeFileSync(snap, got.get("app.db") as Buffer);
    const sdb = new DatabaseSync(snap, { readOnly: true });
    assert.deepEqual(plain(sdb.prepare("SELECT sealed FROM tb_secrets").all()), [{ sealed: "SEALED-SECRET-BLOB" }]);
    assert.deepEqual(titles(sdb), ["first", "second"]);
    sdb.close();
    const audit = plain(r.db.prepare("SELECT actor, action, target FROM tb_audit").all());
    assert.deepEqual(audit, [{ actor: "system", action: "backup.create", target: file }]);
    assert.deepEqual(
      readdirSync(r.ctx.backupDir).filter((n) => n.startsWith(".")),
      [],
    );
  } finally {
    await r.cleanup();
  }
});

test("runNow: a control port that refuses the assertion fails the backup and leaves no archive", async () => {
  const r = await rig({ service: { dump: Buffer.from("x"), bridgeForCtx: `brg_${ulid()}` as BridgeId } });
  try {
    await assert.rejects(r.api.api.runNow(), isCode("backup_failed"));
    assert.equal(r.exec?.rejected, 1);
    assert.deepEqual(readdirSync(r.ctx.backupDir), []);
  } finally {
    await r.cleanup();
  }
});

test("retention keeps the newest backups.retain archives; list() reads their meta newest first", async () => {
  const r = await rig({ retain: 2 });
  try {
    const a = await r.api.api.runNow();
    const b = await r.api.api.runNow();
    const c = await r.api.api.runNow();
    assert.deepEqual(readdirSync(r.ctx.backupDir).sort(), [b.file, c.file]);
    const listed = await r.api.api.list();
    assert.deepEqual(
      listed.map((x) => x.file),
      [c.file, b.file],
    );
    assert.deepEqual(listed[0]?.meta, c.meta);
    assert.ok(!listed.some((x) => x.file === a.file));
  } finally {
    await r.cleanup();
  }
});

test("restoreAtBoot: round trip restores rows, files and the service; audited; ignored on the next boot", async () => {
  const dump = Buffer.from("SERVICE-DUMP-BYTES");
  const r = await rig({ files: [{ volume: "data", path: "uploads" }], service: { dump } });
  try {
    mkdirSync(join(r.ctx.dataDir, "uploads"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "v1");
    const { file } = await r.api.api.runNow();
    r.db.exec("DELETE FROM notes; INSERT INTO notes VALUES ('n9', 'after backup')");
    writeFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "v2");
    r.api.stop();
    r.db.close();

    let restored = 0;
    await restoreAtBoot({ ...r.ctx, hooks: { afterRestore: async () => {
          restored += 1;
        },
      } }, file);
    assert.equal(restored, 1);
    assert.equal(readFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "utf8"), "v1");
    assert.deepEqual(r.exec?.restores, [dump]);
    assert.ok(!existsSync(join(r.ctx.dataDir, ".tb-restore")));
    r.reopen();
    assert.deepEqual(titles(r.db), ["first", "second"]);
    assert.deepEqual(plain(r.db.prepare("SELECT action, target FROM tb_audit WHERE action = 'backup.restore'").all()), [{ action: "backup.restore", target: file }]);

    // later boots with the same variable: nothing happens
    r.db.exec("INSERT INTO notes VALUES ('n3', 'third')");
    r.api.stop();
    r.db.close();
    await restoreAtBoot(r.ctx, file);
    assert.equal(r.exec?.restores.length, 1);
    r.reopen();
    assert.deepEqual(titles(r.db), ["first", "second", "third"]);
  } finally {
    await r.cleanup();
  }
});

test("restoreAtBoot: a schema-9 archive with an owner row is migrated to the crud snapshot with the running manifest (C283c, an E3 restore re-runs the backfill once)", { timeout: 60_000 }, async () => {
  const r = await rig();
  try {
    // make the data exactly what SDK 0.1.35 left: schema 9 (no crud_snapshot column, no migration 10), one owner row and one bounded row
    r.db.exec("INSERT INTO tb_scope_instances (type, id, label, shared, created_at) VALUES ('notebook', 'x', 'X', 0, 1)");
    r.db.exec("INSERT INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES ('agt_owner', 'notebook', 'x', 'read_write', 'owner', 'owner'), ('agt_def', 'notebook', 'x', 'read', 'default', 'bounded')");
    r.db.exec("ALTER TABLE tb_scopes DROP COLUMN crud_snapshot");
    r.db.exec("DELETE FROM tb_migrations WHERE scope = 'sdk' AND version = 10");
    const { file } = await r.api.api.runNow();
    r.api.stop();
    r.db.close();
    await restoreAtBoot(r.ctx, file);
    r.reopen();
    const snap = (agent: string) => (r.db.prepare("SELECT crud_snapshot AS c FROM tb_scopes WHERE agent = ?").get(agent) as { c: string | null }).c;
    assert.equal(snap("agt_owner"), JSON.stringify(["read", "create", "update", "delete"]), "fires on bad: a restore that opened the store without the manifest would throw or leave the row without a snapshot");
    assert.equal(snap("agt_def"), null);
    assert.equal(r.db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'scope.snapshot_backfill'").get()?.n, 1);
  } finally {
    await r.cleanup();
  }
});

test("restoreAtBoot: a tampered part, a foreign product or a bad name is refused and nothing is applied", async () => {
  const r = await rig();
  try {
    const { file, meta } = await r.api.api.runNow();
    r.db.exec("DELETE FROM notes WHERE id = 'n1'");
    r.api.stop();
    r.db.close();
    const got = await entries(join(r.ctx.backupDir, file));
    const repack = async (name: string, metaJson: object, db: Buffer) => {
      const dir = join(r.dir, `pack-${name}`);
      mkdirSync(dir);
      writeFileSync(join(dir, "meta.json"), JSON.stringify(metaJson));
      writeFileSync(join(dir, "app.db"), db);
      await writeTarGz(join(r.ctx.backupDir, name), [
        { name: "meta.json", path: join(dir, "meta.json"), size: readFileSync(join(dir, "meta.json")).length },
        { name: "app.db", path: join(dir, "app.db"), size: db.length },
      ]);
    };
    const db = Buffer.from(got.get("app.db") as Buffer);
    const flipped = Buffer.from(db);
    flipped[flipped.length - 1] = (flipped[flipped.length - 1] as number) ^ 0xff;
    await repack("tampered.tar.gz", meta, flipped);
    await assert.rejects(restoreAtBoot(r.ctx, "tampered.tar.gz"), (e: unknown) => isCode("restore_failed")(e) && /sha256/.test((e as Error).message));
    await repack("foreign.tar.gz", { ...meta, product: "other" }, db);
    await assert.rejects(restoreAtBoot(r.ctx, "foreign.tar.gz"), isCode("restore_failed"));
    const unlisted: BackupMeta = { ...meta, parts: [] };
    await repack("unlisted.tar.gz", unlisted, db);
    await assert.rejects(restoreAtBoot(r.ctx, "unlisted.tar.gz"), isCode("restore_failed"));
    for (const bad of ["../x.tar.gz", "sub/x.tar.gz", "missing.tar.gz", ""]) await assert.rejects(restoreAtBoot(r.ctx, bad), isCode("restore_failed"), bad);
    await restoreAtBoot(r.ctx, null);
    r.reopen();
    assert.deepEqual(titles(r.db), ["second"]);
    assert.equal(r.db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'backup.restore'").get()?.n, 0);
  } finally {
    await r.cleanup();
  }
});

test("restoreAtBoot: a failing service restore rolls app.db and files back", async () => {
  const r = await rig({ files: [{ volume: "data", path: "uploads" }], service: { dump: Buffer.from("dump") } });
  try {
    mkdirSync(join(r.ctx.dataDir, "uploads"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "v1");
    const { file } = await r.api.api.runNow();
    r.db.exec("DELETE FROM notes WHERE id = 'n2'");
    writeFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "v2");
    writeFileSync(join(r.ctx.dataDir, "uploads", "new.txt"), "kept");
    r.api.stop();
    r.db.close();
    await r.exec?.stop();
    let afterRestore = 0;
    await assert.rejects(restoreAtBoot({ ...r.ctx, hooks: { afterRestore: async () => {
          afterRestore += 1;
        },
      } }, file), isCode("restore_failed"));
    assert.equal(afterRestore, 0);
    assert.equal(readFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "utf8"), "v2");
    assert.equal(readFileSync(join(r.ctx.dataDir, "uploads", "new.txt"), "utf8"), "kept");
    assert.ok(!existsSync(join(r.ctx.dataDir, ".tb-restore")));
    r.reopen();
    assert.deepEqual(titles(r.db), ["first"]);
    assert.equal(r.db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'backup.restore'").get()?.n, 0);
  } finally {
    r.exec = null;
    await r.cleanup();
  }
});

test("restoreAtBoot: a path-traversal archive is refused and writes nothing outside", async () => {
  const r = await rig({ files: [{ volume: "data", path: "uploads" }] });
  try {
    r.api.stop();
    r.db.close();
    const meta = { format: "tealbrick.backup/1", product: "jotter", version: "1.0.0", manifestDigest: `sha256:${"0".repeat(64)}`, instance: r.ins, sdk: "0.1.0", createdAt: new Date().toISOString(), parts: [] };
    mkdirSync(r.ctx.backupDir, { recursive: true });
    writeFileSync(join(r.ctx.backupDir, "evil.tar.gz"), rawTarGz([{ name: "meta.json", body: Buffer.from(JSON.stringify(meta)) }, { name: "../../evil.txt", body: Buffer.from("pwned") }]));
    await assert.rejects(restoreAtBoot(r.ctx, "evil.tar.gz"), isCode("restore_failed"));
    assert.ok(!existsSync(join(r.dir, "evil.txt")) && !existsSync(join(r.ctx.dataDir, "evil.txt")));
    // a listed part whose destination escapes the volume is refused as well
    const body = Buffer.from("pwned");
    const meta2 = { ...meta, parts: [{ name: "file", file: "files/data/uploads/../../../evil.txt", sha256: sha(body), bytes: body.length }] };
    writeFileSync(join(r.ctx.backupDir, "evil2.tar.gz"), rawTarGz([{ name: "meta.json", body: Buffer.from(JSON.stringify(meta2)) }, { name: "files/data/uploads/x", body }]));
    await assert.rejects(restoreAtBoot(r.ctx, "evil2.tar.gz"), isCode("restore_failed"));
    assert.ok(!existsSync(join(r.dir, "evil.txt")));
  } finally {
    await r.cleanup();
  }
});

test("v0.1.13 (G1): receipt heldBy is in the export and survives a backup round trip", async () => {
  const r = await rig();
  try {
    const hold = new Receipts(r.db).insert({
      kind: "hld",
      callId: null,
      caller: { type: "agent", id: "agt_1" as AgentId, name: "A" },
      op: "note_get",
      effect: "read",
      holdFamily: "policy",
      heldBy: "rules/check_policy",
      holdReason: "needs the owner",
      status: "held",
      inputDigest: "sha256:x" as Sha256Digest,
      summary: "s",
      meta: null,
      idempotencyKey: null,
      view: "v",
      expiresAt: Date.now() + 60_000,
    });
    const ex = await r.api.api.exportNow();
    for await (const _ of ex.stream) void _;
    const exported = JSON.parse((await entries(join(r.ctx.backupDir, ex.file))).get("receipts.jsonl")?.toString() ?? "null") as Record<string, unknown>;
    assert.equal(exported.held_by, "rules/check_policy");
    const { file } = await r.api.api.runNow();
    r.db.exec("DELETE FROM tb_receipts");
    r.api.stop();
    r.db.close();
    await restoreAtBoot(r.ctx, file);
    r.reopen();
    const back = new Receipts(r.db).getSync(hold.id);
    assert.equal(back?.heldBy, "rules/check_policy");
    assert.equal(back?.holdFamily, "policy");
    assert.equal(new Receipts(r.db).holdStatusSync("agt_1", hold.id)?.reason, "needs the owner");
  } finally {
    await r.cleanup();
  }
});

test("exportNow: JSONL per app table + receipts + audit; secrets and SDK internals excluded; stream equals the file", async () => {
  const r = await rig();
  try {
    r.db.prepare("INSERT INTO tb_secrets (name, sealed, updated_at) VALUES ('s', 'SEALED-SECRET-BLOB', 1)").run();
    r.db.prepare("INSERT INTO tb_keys (name, sealed, updated_at) VALUES ('K', 'SEALED-KEY-BLOB', 1)").run();
    r.db.prepare("INSERT INTO tb_sessions VALUES ('SESSION-DIGEST', 'per_x', 'ws_x', 'ins_x', 'iss', 'CSRF-VALUE', 1, 2)").run();
    r.db.prepare("INSERT INTO tb_used_jti VALUES ('JTI-VALUE', 1)").run();
    r.db
      .prepare("INSERT INTO tb_receipts (id, caller_type, caller_id, caller_name, op, effect, status, input_digest, summary, meta, created_at) VALUES ('rcp_1', 'agent', 'agt_1', 'A', 'note_create', 'write', 'run', 'sha256:x', 'note', '{}', 5)")
      .run();
    await createAuditLog(r.db, []).record({ actor: "system", action: "key.set", target: "K", detail: null });

    const { file, meta, stream } = await r.api.api.exportNow();
    assert.match(file, /^tb-export-\d{8}T\d{6}\.\d{3}Z\.tar\.gz$/);
    const chunks: Uint8Array[] = [];
    for await (const c of stream) chunks.push(c);
    const disk = readFileSync(join(r.ctx.backupDir, file));
    assert.ok(Buffer.concat(chunks).equals(disk));

    const m = meta as ExportMeta;
    assert.equal(m.format, "tealbrick.export/1");
    assert.equal(m.product, "jotter");
    assert.equal(m.instance, r.ins);
    assert.deepEqual(
      m.files.map((f) => [f.file, f.rows]),
      [
        ["tables/blobs.jsonl", 1],
        ["tables/notes.jsonl", 2],
        ["receipts.jsonl", 1],
        ["audit.jsonl", 1],
      ],
    );
    const got = await entries(join(r.ctx.backupDir, file));
    assert.deepEqual([...got.keys()].sort(), ["audit.jsonl", "meta.json", "receipts.jsonl", "tables/blobs.jsonl", "tables/notes.jsonl"]);
    assert.deepEqual(JSON.parse(got.get("meta.json")?.toString() ?? "null"), meta);
    for (const f of m.files) assert.equal(sha(got.get(f.file) as Buffer), f.sha256, f.file);
    const notes = (got.get("tables/notes.jsonl")?.toString() ?? "").trim().split("\n").map((l) => JSON.parse(l));
    assert.deepEqual(notes, [
      { id: "n1", title: "first" },
      { id: "n2", title: "second" },
    ]);
    assert.deepEqual(JSON.parse(got.get("tables/blobs.jsonl")?.toString() ?? "null"), { id: 1, data: { $base64: Buffer.from([0, 255, 16]).toString("base64") } });
    assert.equal(JSON.parse(got.get("receipts.jsonl")?.toString() ?? "null").id, "rcp_1");
    const all = Buffer.concat([...got.values()]).toString("utf8");
    for (const secret of ["SEALED-SECRET-BLOB", "SEALED-KEY-BLOB", "SESSION-DIGEST", "CSRF-VALUE", "JTI-VALUE", "tb_migrations"]) assert.ok(!all.includes(secret), secret);
    // export archives are not backups: list() ignores them
    assert.deepEqual(await r.api.api.list(), []);
  } finally {
    await r.cleanup();
  }
});

test("startApp wiring: RunningApp.backups backs up, TB_RESTORE_FROM restores at the next boot", async () => {
  const t = tempDir("tb-backup-app-");
  const migrations = migrationsDir(t.dir);
  const app = (port: number) =>
    defineApp({
      manifest: fixtureManifest(port),
      migrations,
      handlers: {
        note_create: { scope: () => "nb", run: async () => ({ id: "x" }) },
        note_get: async () => ({}),
        note_delete: async () => ({}),
        notebook_rename: async () => ({}),
      },
    });
  const env = { TB_DATA_DIR: t.dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" };
  const dbFile = join(t.dir, "app.db");
  const withDb = <T>(fn: (db: DatabaseSync) => T): T => {
    const db = new DatabaseSync(dbFile);
    try {
      return fn(db);
    } finally {
      db.close();
    }
  };
  try {
    let running = await startApp(app(await freePort()), env);
    withDb((db) => db.exec("INSERT INTO notes VALUES ('n1', 'nb', 'kept')"));
    const { file } = await running.backups.runNow();
    assert.equal((await running.backups.list())[0]?.file, file);
    assert.ok(existsSync(join(t.dir, "backup", file)), "TB_BACKUP_DIR defaults to <TB_DATA_DIR>/backup (C28)");
    await running.stop();
    withDb((db) => db.exec("DELETE FROM notes"));

    running = await startApp(app(await freePort()), { ...env, TB_RESTORE_FROM: file });
    await running.stop();
    assert.deepEqual(
      withDb((db) => plain(db.prepare("SELECT title FROM notes").all())),
      [{ title: "kept" }],
    );
    assert.equal(withDb((db) => db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'backup.restore'").get())?.n, 1);
    // v0.1.25 (E2/M2): a failed restore is failed mode with the reason; the data is untouched
    const failed = await startApp(app(await freePort()), { ...env, TB_RESTORE_FROM: "nope.tar.gz" });
    try {
      assert.equal(failed.status(), "failed");
      assert.deepEqual([failed.failure?.phase, failed.failure?.code, failed.failure?.reason], ["restore", "restore_failed", "archive_missing"]);
    } finally {
      await failed.stop();
    }
  } finally {
    t.cleanup();
  }
});

// ── v0.1.22 (SDK-03, L3): a failed, overdue or unparsable scheduled backup is never silent ──
test("SDK-03: a failed backup raises attention backup_failed and shows in health; a good one clears it; the state survives a restart", async () => {
  const r = await rig();
  try {
    r.api.stop();
    let pushes = 0;
    const blocked = join(r.dir, "not-a-dir");
    writeFileSync(blocked, "x");
    const failing = createBackupApi({ ...r.ctx, backupDir: blocked, onStateChange: () => pushes++, db: r.db, audit: createAuditLog(r.db, []) });
    assert.equal(failing.attention(), null, "quiet on good: no failure yet");
    await assert.rejects(failing.api.runNow());
    await assert.rejects(failing.api.runNow());
    failing.stop();
    assert.equal(pushes, 2, "every outcome pushes the status");
    const h = failing.health();
    assert.equal(h.failures, 2);
    assert.equal(h.lastOkAt, null);
    assert.ok(h.lastFailedAt);
    assert.equal(h.schedule, "ok");
    const a = failing.attention();
    assert.equal(a?.code, "backup_failed");
    assert.match(a?.reason ?? "", /The last 2 backups failed .*no good backup yet/);
    assert.ok((a?.reason.length ?? 0) <= 200);
    // a restart (new api on the same db) keeps the record
    r.api = createBackupApi({ ...r.ctx, db: r.db, audit: createAuditLog(r.db, []) });
    assert.equal(r.api.attention()?.code, "backup_failed");
    await r.api.api.runNow();
    assert.equal(r.api.attention(), null, "a good backup clears it");
    assert.equal(r.api.health().failures, 0);
    assert.ok(r.api.health().lastOkAt);
  } finally {
    await r.cleanup();
  }
});

test("SDK-03: an unparsable schedule → attention backup_schedule_invalid + health schedule invalid (was: one log line)", async () => {
  const r = await rig();
  try {
    r.api.stop();
    const manifest = { ...r.ctx.manifest, backups: { ...r.ctx.manifest.backups, schedule: "61 3 * * *" } };
    r.api = createBackupApi({ ...r.ctx, manifest, db: r.db, audit: createAuditLog(r.db, []) });
    assert.equal(r.api.health().schedule, "invalid");
    assert.equal(r.api.attention()?.code, "backup_schedule_invalid");
  } finally {
    await r.cleanup();
  }
});

test("SDK-03: no good backup for more than two schedule periods → backup_overdue (injected clock)", async () => {
  const r = await rig();
  try {
    r.api.stop();
    // the rig already started the overdue clock (`since`) at its first createBackupApi, a moment ago
    const t0 = Date.now();
    let clock = t0;
    r.api = createBackupApi({ ...r.ctx, now: () => clock, db: r.db, audit: createAuditLog(r.db, []) });
    clock = t0 + 2 * 86_400_000 - 60_000;
    assert.equal(r.api.health().overdue, false, "quiet inside two daily periods");
    assert.equal(r.api.attention(), null);
    clock = t0 + 2 * 86_400_000 + 60_000;
    assert.equal(r.api.health().overdue, true);
    assert.equal(r.api.attention()?.code, "backup_overdue");
    await r.api.api.runNow();
    assert.equal(r.api.health().overdue, false, "a good backup restarts the clock");
  } finally {
    await r.cleanup();
  }
});

type FileIndex = { path: string; volume: string; bytes: number; sha256: string }[];

test("v0.1.26 (OD-3): exportNow carries the backups.files paths under files/ with a files.json index; the live db, tb/ and symlinks stay out", async () => {
  const r = await rig({ files: [{ volume: "data", path: "uploads" }] });
  try {
    const up = join(r.ctx.dataDir, "uploads");
    mkdirSync(join(up, "deep"), { recursive: true });
    writeFileSync(join(up, "a.txt"), "upload-a");
    writeFileSync(join(up, "deep", "b.bin"), Buffer.from([0, 1, 2, 255]));
    // a file outside the declared path, the instance key dir and a symlink to a secret outside the volume
    writeFileSync(join(r.ctx.dataDir, "other.txt"), "NOT-DECLARED");
    mkdirSync(join(r.ctx.dataDir, "tb"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "tb", "kek"), "KEK-MUST-NOT-LEAVE");
    writeFileSync(join(r.dir, "outside-secret.txt"), "OUTSIDE-SECRET");
    symlinkSync(join(r.dir, "outside-secret.txt"), join(up, "link.txt"));

    const { file, meta, stream } = await r.api.api.exportNow();
    for await (const _ of stream) void _;
    const got = await entries(join(r.ctx.backupDir, file));
    assert.deepEqual([...got.keys()].sort(), ["audit.jsonl", "files.json", "files/data/uploads/a.txt", "files/data/uploads/deep/b.bin", "meta.json", "receipts.jsonl", "tables/blobs.jsonl", "tables/notes.jsonl"]);
    const index = JSON.parse(got.get("files.json")?.toString() ?? "null") as FileIndex;
    assert.deepEqual(index, [
      { path: "uploads/a.txt", volume: "data", bytes: 8, sha256: sha(Buffer.from("upload-a")) },
      { path: "uploads/deep/b.bin", volume: "data", bytes: 4, sha256: sha(Buffer.from([0, 1, 2, 255])) },
    ]);
    for (const f of index) assert.equal(sha(got.get(`files/${f.volume}/${f.path}`) as Buffer), f.sha256, f.path);
    // meta.files still lists the JSONL parts only (readers of the format are not surprised)
    assert.deepEqual((meta as ExportMeta).files.map((f) => f.file), ["tables/blobs.jsonl", "tables/notes.jsonl", "receipts.jsonl", "audit.jsonl"]);
    const all = Buffer.concat([...got.values()]).toString("utf8");
    for (const leak of ["OUTSIDE-SECRET", "KEK-MUST-NOT-LEAVE", "NOT-DECLARED"]) assert.ok(!all.includes(leak), leak);
  } finally {
    await r.cleanup();
  }
});

test("v0.1.26 (OD-3): an export refuses a backups.files path that leaves the volume, also through a symlinked directory", async () => {
  const outside = (dir: string) => {
    mkdirSync(join(dir, "outside"), { recursive: true });
    writeFileSync(join(dir, "outside", "secret.txt"), "OUTSIDE-SECRET");
    return join(dir, "outside");
  };
  // 1. the declared path itself climbs out
  const r1 = await rig({ files: [{ volume: "data", path: "../outside" }] });
  try {
    outside(r1.dir);
    await assert.rejects(r1.api.api.exportNow(), isCode("export_failed"));
    assert.deepEqual(readdirSync(r1.ctx.backupDir).filter((n) => n.startsWith("tb-export-")), [], "no archive is left behind");
  } finally {
    await r1.cleanup();
  }
  // 2. a symlinked parent directory leads out (the leaf lstat alone would follow it)
  const r2 = await rig({ files: [{ volume: "data", path: "link/inner" }] });
  try {
    const target = outside(r2.dir);
    mkdirSync(join(target, "inner"), { recursive: true });
    writeFileSync(join(target, "inner", "x.txt"), "OUTSIDE-SECRET");
    symlinkSync(target, join(r2.ctx.dataDir, "link"));
    await assert.rejects(r2.api.api.exportNow(), isCode("export_failed"));
    await assert.rejects(r2.api.api.runNow(), isCode("backup_failed"), "the backup shares the rule");
  } finally {
    await r2.cleanup();
  }
  // 3. a declared path that is itself a symlink to a directory outside is refused as well
  const r3 = await rig({ files: [{ volume: "data", path: "uploads" }] });
  try {
    symlinkSync(outside(r3.dir), join(r3.ctx.dataDir, "uploads"));
    await assert.rejects(r3.api.api.exportNow(), isCode("export_failed"));
  } finally {
    await r3.cleanup();
  }
});

test("v0.1.26 (OD-3): an app without backups.files exports exactly as before (no files.json, no files/)", async () => {
  const r = await rig();
  try {
    mkdirSync(join(r.ctx.dataDir, "uploads"), { recursive: true });
    writeFileSync(join(r.ctx.dataDir, "uploads", "a.txt"), "upload-a");
    const { file } = await r.api.api.exportNow();
    const names = [...(await entries(join(r.ctx.backupDir, file))).keys()].sort();
    assert.deepEqual(names, ["audit.jsonl", "meta.json", "receipts.jsonl", "tables/blobs.jsonl", "tables/notes.jsonl"]);
  } finally {
    await r.cleanup();
  }
});
