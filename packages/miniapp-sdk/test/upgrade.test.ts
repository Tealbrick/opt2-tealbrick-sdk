// v0.1.25 (E2: UPGRADE-SAFETY M1–M3): pre-update snapshot, migration lock, failed-mode boot, version-aware restore,
// schema-newer refusal. Real SQLite files in temp dirs; the lock tests use an injected clock (L39: no wall-clock race);
// the crash test SIGKILLs a real child process in the middle of a migration.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { PREUPDATE_RETAIN, preUpdateName } from "../src/server/backup.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { SDK_SCHEMA } from "../src/server/store.ts";
import { type Clock, compareVersions } from "../src/server/upgrade.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, slice, tempDir, testRoots, until, world } from "./helpers.ts";

const V1 = { "0001_init.sql": "CREATE TABLE notes (id TEXT PRIMARY KEY, notebook TEXT NOT NULL, title TEXT NOT NULL);" };
const V2 = { ...V1, "0002_add_tags.sql": "ALTER TABLE notes ADD COLUMN tags TEXT NOT NULL DEFAULT '';", "0003_tag_index.sql": "CREATE INDEX notes_tags ON notes (tags);" };
const V2_BROKEN = { ...V1, "0002_add_tags.sql": V2["0002_add_tags.sql"], "0003_tag_index.sql": "CREATE INDEX notes_tags ON no_such_table (tags);" };

const handlers = {
  note_create: { scope: () => "nb", run: async () => ({ id: "x" }) },
  note_get: async () => ({}),
  note_delete: async () => ({}),
  notebook_rename: async () => ({}),
};

function appAt(version: string, migrations: string, port: number) {
  const manifest = fixtureManifest(port);
  manifest.version = version;
  return defineApp({ manifest, migrations, handlers });
}

/**
 * CI runs as root: without this the first startApp drops THIS test process to uid 1000 (C53), which then cannot reach the
 * temp dirs. Tests keep their uid (the privilege drop has its own tests).
 */
const KEEP_UID = { privilegeProc: { getuid: () => 4242 } };
const boot = (app: Parameters<typeof startApp>[0], env: Record<string, string>, harness: Parameters<typeof startApp>[2] = {}) => startApp(app, env, { ...KEEP_UID, ...harness });

/** One data dir; `files` per app version live in their own code dir (an image per version). */
function rig() {
  const t = tempDir("tb-upgrade-");
  const data = join(t.dir, "data");
  const code = (name: string, files: Record<string, string>) => migrationsDir(join(t.dir, `code-${name}`), files);
  const env = { TB_DATA_DIR: data, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" };
  const sql = <T>(fn: (db: DatabaseSync) => T): T => {
    const db = new DatabaseSync(join(data, "app.db"));
    try {
      return fn(db);
    } finally {
      db.close();
    }
  };
  const rows = () => sql((db) => db.prepare("SELECT id, title FROM notes ORDER BY id").all().map((r) => ({ ...r })));
  const appVersions = () => sql((db) => db.prepare("SELECT version FROM tb_migrations WHERE scope = 'app' ORDER BY version").all().map((r) => Number(r.version)));
  const meta = (key: string) => sql((db) => {
    const r = db.prepare("SELECT value FROM tb_meta WHERE key = ?").get(key) as { value: string } | undefined;
    return r ? JSON.parse(r.value) : null;
  });
  const backups = () => (existsSync(join(data, "backup")) ? readdirSync(join(data, "backup")).filter((n) => n.endsWith(".tar.gz")).sort() : []);
  return { t, data, code, env, sql, rows, appVersions, meta, backups, snapPath: (v: string) => join(data, "backup", preUpdateName(v)) };
}

/** Fake clock: `sleep` advances time and runs `onSleep` (the "other instance" progresses while this one waits). */
function fakeClock(start = Date.now(), onSleep?: (n: number) => Promise<void> | void): Clock & { t: number } {
  let n = 0;
  const c = {
    t: start,
    now: () => c.t,
    sleep: async (ms: number) => {
      c.t += ms;
      n += 1;
      await onSleep?.(n);
    },
  };
  return c;
}

async function health(port: number) {
  const res = await fetch(`http://127.0.0.1:${port}/tb/v1/health`);
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function seedV1(r: ReturnType<typeof rig>) {
  const v1 = r.code("v1", V1);
  const a = await boot(appAt("1.0.0", v1, await freePort()), r.env);
  await a.stop();
  r.sql((db) => db.exec("INSERT INTO notes VALUES ('n1', 'nb', 'first'), ('n2', 'nb', 'second')"));
  return v1;
}

test("M1: an update with pending migrations writes the pre-update snapshot first; health exposes schema + minCompatibleCode", async () => {
  const r = rig();
  try {
    await seedV1(r);
    assert.equal(r.meta("app_version"), "1.0.0");
    assert.equal(r.meta("min_compatible_code"), "1.0.0", "the first boot applied 0001");
    const port = await freePort();
    const b = await boot(appAt("2.0.0", r.code("v2", V2), port), r.env);
    try {
      assert.equal(b.status(), "ok");
      const h = await health(port);
      assert.deepEqual(h.body.schemaVersion, { app: 3, sdk: SDK_SCHEMA });
      assert.equal(h.body.minCompatibleCode, "2.0.0");
      assert.equal(h.body.preUpdateSnapshot.file, "tb-preupdate-to-2.0.0.tar.gz");
      assert.equal(h.body.preUpdateSnapshot.from, "1.0.0");
      assert.equal(h.body.preUpdateSnapshot.to, "2.0.0");
    } finally {
      await b.stop();
    }
    assert.ok(existsSync(r.snapPath("2.0.0")), "same volume, recorded path");
    assert.deepEqual(r.appVersions(), [1, 2, 3]);
    assert.equal(r.meta("upgrade_in_progress"), null, "cleared with the success write");
    assert.equal(r.meta("last_preupdate").file, "tb-preupdate-to-2.0.0.tar.gz");
    // the snapshot holds the data from BEFORE the update (schema app 1)
    const snapMeta = JSON.parse(execTarMeta(r.snapPath("2.0.0")));
    assert.equal(snapMeta.kind, "preupdate");
    assert.equal(snapMeta.version, "1.0.0");
    assert.deepEqual(snapMeta.schema, { app: 1, sdk: SDK_SCHEMA });
    assert.equal(r.sql((db) => db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'backup.create' AND target = 'tb-preupdate-to-2.0.0.tar.gz'").get())?.n, 1);
    // a plain restart of the same version writes no new snapshot
    const mtime = statSync(r.snapPath("2.0.0")).mtimeMs;
    const c = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env);
    await c.stop();
    assert.equal(statSync(r.snapPath("2.0.0")).mtimeMs, mtime);
  } finally {
    r.t.cleanup();
  }
});

/** meta.json of an archive (first tar entry) without the SDK's reader: gunzip + ustar header. */
function execTarMeta(file: string): string {
  const tar = gunzipSync(readFileSync(file));
  const size = Number.parseInt(tar.subarray(124, 135).toString("latin1"), 8);
  assert.equal(tar.subarray(0, 9).toString("latin1"), "meta.json");
  return tar.subarray(512, 512 + size).toString("utf8");
}

test("M2: a migration that fails half-way → failed mode with the reason (no exit); restart keeps the snapshot; rollback restores the data", async () => {
  const r = rig();
  try {
    const v1 = await seedV1(r);
    const v2 = r.code("v2b", V2_BROKEN);
    const port = await freePort();
    const b = await boot(appAt("2.0.0", v2, port), r.env);
    let sha: string;
    try {
      assert.equal(b.status(), "failed");
      assert.deepEqual([b.failure?.phase, b.failure?.code, b.failure?.file], ["app_migrations", "migration_failed", "0003_tag_index.sql"]);
      const h = await health(port);
      assert.equal(h.status, 200, "health answers (Railway sees the process up; Core reads the state)");
      assert.equal(h.body.status, "failed");
      assert.equal(h.body.attention.code, "migration_failed");
      assert.deepEqual(h.body.schemaVersion, { app: 2, sdk: SDK_SCHEMA }, "0002 committed, 0003 rolled back (one transaction per file)");
      assert.deepEqual(h.body.codeSchema, { app: 3, sdk: SDK_SCHEMA });
      assert.equal(h.body.preUpdateSnapshot.file, "tb-preupdate-to-2.0.0.tar.gz");
      assert.doesNotMatch(JSON.stringify(h.body), /no_such_table/, "no SQL in health");
      sha = h.body.preUpdateSnapshot.sha256;
      const op = await fetch(`http://127.0.0.1:${port}/tb/v1/ops/note_get`, { method: "POST", body: "{}" });
      assert.equal(op.status, 503);
      assert.equal(((await op.json()) as { error: { code: string } }).error.code, "app_failed");
      assert.throws(() => b.receipts, /app_failed|failed to boot/);
    } finally {
      await b.stop();
    }
    assert.equal(r.meta("app_version"), "1.0.0", "no success write");
    assert.equal(r.meta("upgrade_in_progress").to, "2.0.0");
    // a restart of the broken version (Railway restart) fails the same way and does NOT overwrite the snapshot with
    // the half-migrated data
    const b2 = await boot(appAt("2.0.0", v2, await freePort()), r.env);
    assert.equal(b2.status(), "failed");
    await b2.stop();
    // the old code on the half-migrated data refuses explicitly (was: "applied migration 2 is missing")
    const old = await boot(appAt("1.0.0", v1, await freePort()), r.env);
    assert.equal(old.status(), "failed");
    assert.equal(old.failure?.code, "app_schema_newer");
    await old.stop();
    // rollback = old image + TB_RESTORE_FROM=<the deterministic snapshot name> (what Core sets)
    const rbPort = await freePort();
    const rb = await boot(appAt("1.0.0", v1, rbPort), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    try {
      assert.equal(rb.status(), "ok");
      const h = await health(rbPort);
      assert.deepEqual(h.body.schemaVersion, { app: 1, sdk: SDK_SCHEMA });
    } finally {
      await rb.stop();
    }
    assert.deepEqual(r.rows(), [{ id: "n1", title: "first" }, { id: "n2", title: "second" }]);
    assert.deepEqual(r.appVersions(), [1]);
    const restored = r.meta("restore_applied") as string;
    assert.match(restored, /^tb-preupdate-to-2\.0\.0\.tar\.gz@/);
    // TB_RESTORE_FROM still set (Core clears it after health): a restart does not restore again; new writes survive
    r.sql((db) => db.exec("INSERT INTO notes VALUES ('n3', 'nb', 'after rollback')"));
    const rb2 = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    assert.equal(rb2.status(), "ok");
    await rb2.stop();
    assert.equal(r.rows().length, 3);
    void sha;
  } finally {
    r.t.cleanup();
  }
});

test("M2: failed mode pushes the failure to the bridge (readiness degraded + attention migration_failed + failure detail)", async () => {
  const w = await world();
  const r = rig();
  const bridge = new FakeBridge(w);
  try {
    const bridgeUrl = await bridge.start(await slice(w, "jotter"));
    const env = { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: r.data, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" };
    const a = await boot(appAt("1.0.0", r.code("v1", V1), await freePort()), env, testRoots(w));
    await until(async () => a.status() === "ok");
    await a.stop();
    const healthy = bridge.statuses.at(-1) as Record<string, any>;
    assert.deepEqual(healthy.schemaVersion, { app: 1, sdk: SDK_SCHEMA }, "a healthy status carries the schema too");
    assert.equal(healthy.minCompatibleCode, "1.0.0");
    assert.deepEqual(healthy.proofClaims, ["bd"], "v0.1.36 (C268 B): every status push declares the proof claims");
    bridge.statuses.length = 0;
    const b = await boot(appAt("2.0.0", r.code("v2b", V2_BROKEN), await freePort()), env, testRoots(w));
    try {
      const s = await until(async () => bridge.statuses.find((x) => (x as { readiness?: string }).readiness === "degraded") as Record<string, any> | undefined);
      assert.equal(s.version, "2.0.0");
      assert.equal(s.attention.code, "migration_failed");
      assert.deepEqual(s.proofClaims, ["bd"], "also in failed mode: the bridge keeps the capability of the app instance");
      assert.equal(s.failure.code, "migration_failed");
      assert.equal(s.failure.file, "0003_tag_index.sql");
      assert.equal(s.preUpdateSnapshot.file, "tb-preupdate-to-2.0.0.tar.gz");
    } finally {
      await b.stop();
      await bridge.stop();
    }
  } finally {
    // a failed assertion before the inner try must not leave the bridge listening (an open handle keeps the test process alive)
    await bridge.stop();
    r.t.cleanup();
  }
});

test("M2 lock: a second instance waits for the first (injected clock), then finds nothing to do; one snapshot, each migration once", async () => {
  const r = rig();
  try {
    await seedV1(r);
    const v2 = r.code("v2", V2);
    // instance A holds the lock (it is about to migrate)
    r.sql((db) => db.prepare("INSERT INTO tb_migration_lock (id, holder, until) VALUES (1, 'A', ?)").run(Date.now() + 60_000));
    let aRan = false;
    const clock = fakeClock(Date.now(), async (n) => {
      if (n !== 2 || aRan) return;
      aRan = true; // while B waits: A (same holder id as the row) migrates and releases
      const a = await boot(appAt("2.0.0", v2, await freePort()), r.env, { migrationLock: { holder: "A" } });
      assert.equal(a.status(), "ok");
      await a.stop();
    });
    const b = await boot(appAt("2.0.0", v2, await freePort()), r.env, { clock, migrationLock: { holder: "B" } });
    try {
      assert.ok(aRan);
      assert.equal(b.status(), "ok");
    } finally {
      await b.stop();
    }
    assert.deepEqual(r.appVersions(), [1, 2, 3]);
    assert.equal(r.sql((db) => db.prepare("SELECT count(*) AS n FROM tb_audit WHERE action = 'migration.apply'").get())?.n, 3, "0001 at v1, 0002+0003 once (by A)");
    assert.equal(r.backups().filter((n) => n.startsWith("tb-preupdate-")).length, 1);
    assert.equal(r.sql((db) => db.prepare("SELECT count(*) AS n FROM tb_migration_lock").get())?.n, 0, "released");
  } finally {
    r.t.cleanup();
  }
});

test("M2 lock: a live holder that never finishes → failed mode migration_locked after the wait; nothing migrated", async () => {
  const r = rig();
  try {
    await seedV1(r);
    const clock = fakeClock(Date.now(), () => {
      // the holder keeps its lease alive (heartbeat) while B waits
      r.sql((db) => db.prepare("UPDATE tb_migration_lock SET until = ?").run(clock.t + 60_000));
    });
    r.sql((db) => db.prepare("INSERT INTO tb_migration_lock (id, holder, until) VALUES (1, 'other', ?)").run(clock.t + 60_000));
    const b = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env, { clock, migrationLock: { waitMs: 10_000 } });
    assert.equal(b.status(), "failed");
    assert.deepEqual([b.failure?.phase, b.failure?.code], ["lock", "migration_locked"]);
    await b.stop();
    assert.deepEqual(r.appVersions(), [1]);
    assert.ok(!existsSync(r.snapPath("2.0.0")), "no snapshot without the lock");
  } finally {
    r.t.cleanup();
  }
});

test("M2 crash: SIGKILL in the middle of a migration → restart takes the stale lock over, reuses the snapshot, finishes; rollback restores", async () => {
  const r = rig();
  try {
    const v1 = await seedV1(r);
    const flag = join(r.t.dir, "hang");
    const inside = join(r.t.dir, "inside");
    writeFileSync(flag, "1");
    // 0003 hangs while the flag file exists (only the first run): the child is killed inside its transaction
    const hang = `import { existsSync, writeFileSync } from "node:fs";
export function up(db) {
  db.exec("CREATE INDEX notes_tags ON notes (tags)");
  if (existsSync(${JSON.stringify(flag)})) {
    writeFileSync(${JSON.stringify(inside)}, "1");
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600000);
  }
}
`;
    const v2 = r.code("v2c", { ...V1, "0002_add_tags.sql": V2["0002_add_tags.sql"], "0003_tag_index.ts": hang });
    const port = await freePort();
    const sdk = fileURLToPath(new URL("../src/server/index.ts", import.meta.url));
    const fixture = fileURLToPath(new URL("./fixtures/manifest.ts", import.meta.url));
    const script = join(r.t.dir, "child.ts");
    writeFileSync(
      script,
      `import { defineApp, startApp } from ${JSON.stringify(sdk)};
import { fixtureManifest } from ${JSON.stringify(fixture)};
const manifest = fixtureManifest(${port}); manifest.version = "2.0.0";
const h = { note_create: { scope: () => "nb", run: async () => ({}) }, note_get: async () => ({}), note_delete: async () => ({}), notebook_rename: async () => ({}) };
await startApp(defineApp({ manifest, migrations: ${JSON.stringify(v2)}, handlers: h }), { TB_DATA_DIR: ${JSON.stringify(r.data)}, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" }, { privilegeProc: { getuid: () => 4242 } });
`,
    );
    const child = spawn(process.execPath, [script], { stdio: "ignore" });
    const exited = new Promise<void>((res) => child.once("exit", () => res()));
    await until(async () => existsSync(inside), 30_000);
    child.kill("SIGKILL");
    await exited;
    assert.deepEqual(r.appVersions(), [1, 2], "0002 committed; 0003 was in flight (rolled back)");
    assert.equal(r.meta("upgrade_in_progress").to, "2.0.0");
    const snapSha = r.meta("upgrade_in_progress").snapshot.sha256;
    const holder = r.sql((db) => (db.prepare("SELECT holder FROM tb_migration_lock").get() as { holder: string } | undefined)?.holder);
    assert.ok(holder, "the killed child still holds the lock row");
    rmSync(flag);
    // restart (Railway restarts the container): the lease must have run out; a fake clock 3 minutes ahead
    const clock = fakeClock(Date.now() + 3 * 60_000);
    const b = await boot(appAt("2.0.0", v2, await freePort()), r.env, { clock });
    try {
      assert.equal(b.status(), "ok");
    } finally {
      await b.stop();
    }
    assert.deepEqual(r.appVersions(), [1, 2, 3]);
    assert.equal(r.meta("last_preupdate").sha256, snapSha, "the snapshot of the pre-update data was kept, not rewritten from half-migrated data");
    // rollback still possible
    const rb = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    assert.equal(rb.status(), "ok");
    await rb.stop();
    assert.deepEqual(r.appVersions(), [1]);
    assert.equal(r.rows().length, 2);
  } finally {
    r.t.cleanup();
  }
});

test("M3: restore refuses a NEWER app version, a newer schema and another product before replacing anything; older data migrates forward", async () => {
  const r = rig();
  try {
    const v1 = await seedV1(r);
    const v2 = r.code("v2", V2);
    const b = await boot(appAt("2.0.0", v2, await freePort()), r.env);
    const { file: v2Backup } = await b.backups.runNow();
    await b.stop();
    // the v1 code is given a v2 backup (written by a newer version)
    const before = r.appVersions();
    const a = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: v2Backup });
    assert.equal(a.status(), "failed");
    assert.deepEqual([a.failure?.phase, a.failure?.code, a.failure?.reason], ["restore", "restore_failed", "version_newer"]);
    await a.stop();
    assert.deepEqual(r.appVersions(), before, "nothing replaced");
    // a 1.0.0 code that claims a newer version number but has fewer migrations: the archived DB schema is checked
    const fake = await boot(appAt("3.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: v2Backup });
    assert.equal(fake.status(), "failed");
    assert.equal(fake.failure?.reason, "schema_newer");
    await fake.stop();
    // another product
    const other = fixtureManifest(await freePort());
    other.id = "other-app";
    other.version = "9.0.0";
    const o = await boot(defineApp({ manifest: other, migrations: v2, handlers }), { ...r.env, TB_RESTORE_FROM: v2Backup });
    assert.equal(o.failure?.reason, "product_mismatch");
    await o.stop();
    // the pre-update snapshot (v1 data) restored by the v2 code: older data, migrated forward on the same boot
    const c = await boot(appAt("2.0.0", v2, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    assert.equal(c.status(), "ok");
    await c.stop();
    assert.deepEqual(r.appVersions(), [1, 2, 3]);
  } finally {
    r.t.cleanup();
  }
});

test("M3: rollback rules of a pre-update snapshot: missing + compatible data → skipped; same schema → data kept; missing + newer data → refused", async () => {
  const r = rig();
  try {
    const v1 = await seedV1(r);
    // missing snapshot, data at the old schema (the failed version stopped before its snapshot)
    const a = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    assert.equal(a.status(), "ok");
    await a.stop();
    // a version change without a migration (1.0.1 has the same files): snapshot written; rolling back keeps the data
    const b = await boot(appAt("1.0.1", r.code("v101", V1), await freePort()), r.env);
    await b.stop();
    assert.ok(existsSync(r.snapPath("1.0.1")));
    r.sql((db) => db.exec("INSERT INTO notes VALUES ('n9', 'nb', 'written by 1.0.1')"));
    const c = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("1.0.1") });
    assert.equal(c.status(), "ok");
    await c.stop();
    assert.equal(r.rows().length, 3, "same schema: no restore, the 1.0.1 write is kept");
    // missing snapshot with data newer than the code → refused
    const d = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env);
    await d.stop();
    rmSync(r.snapPath("2.0.0"));
    const e = await boot(appAt("1.0.0", v1, await freePort()), { ...r.env, TB_RESTORE_FROM: preUpdateName("2.0.0") });
    assert.equal(e.status(), "failed");
    assert.equal(e.failure?.reason, "snapshot_missing");
    await e.stop();
  } finally {
    r.t.cleanup();
  }
});

test("M3: data newer than the code → failed mode schema_newer (app and SDK scope); health shows schemaVersion + minCompatibleCode", async () => {
  const r = rig();
  try {
    const v1 = await seedV1(r);
    const b = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env);
    await b.stop();
    const port = await freePort();
    const a = await boot(appAt("1.0.0", v1, port), r.env);
    try {
      assert.equal(a.failure?.code, "app_schema_newer");
      const h = await health(port);
      assert.equal(h.body.attention.code, "schema_newer");
      assert.deepEqual(h.body.schemaVersion, { app: 3, sdk: SDK_SCHEMA });
      assert.equal(h.body.minCompatibleCode, "2.0.0", "the code needed to run this data");
    } finally {
      await a.stop();
    }
    r.sql((db) => db.prepare("INSERT INTO tb_migrations (scope, version, name, sha256, applied_at) VALUES ('sdk', ?, 'future', 'x', 0)").run(SDK_SCHEMA + 1));
    const c = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env);
    assert.equal(c.failure?.code, "sdk_schema_newer");
    await c.stop();
  } finally {
    r.t.cleanup();
  }
});

test("M1: no free space for the snapshot → failed mode preupdate_snapshot_no_space, nothing migrated (fail closed)", async () => {
  const r = rig();
  try {
    await seedV1(r);
    const b = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env, { freeBytes: async () => 0 });
    assert.deepEqual([b.failure?.phase, b.failure?.code], ["snapshot", "preupdate_snapshot_no_space"]);
    await b.stop();
    assert.deepEqual(r.appVersions(), [1]);
    assert.equal(r.meta("upgrade_in_progress"), null);
  } finally {
    r.t.cleanup();
  }
});

test("M1: retention keeps the newest 3 pre-update snapshots; cron backups are separate (list() never shows them)", async () => {
  const r = rig();
  try {
    await seedV1(r);
    const v1 = r.code("v1", V1);
    for (const v of ["1.0.1", "1.0.2", "1.0.3", "1.0.4"]) {
      const a = await boot(appAt(v, v1, await freePort()), r.env);
      if (v === "1.0.4") assert.deepEqual(await a.backups.list(), []);
      await a.stop();
      await new Promise((res) => setTimeout(res, 15)); // distinct mtimes
    }
    const snaps = r.backups().filter((n) => n.startsWith("tb-preupdate-"));
    assert.equal(snaps.length, PREUPDATE_RETAIN);
    assert.deepEqual(snaps, ["tb-preupdate-to-1.0.2.tar.gz", "tb-preupdate-to-1.0.3.tar.gz", "tb-preupdate-to-1.0.4.tar.gz"]);
  } finally {
    r.t.cleanup();
  }
});

test("a fresh install writes no snapshot; semver compare", async () => {
  const r = rig();
  try {
    const a = await boot(appAt("2.0.0", r.code("v2", V2), await freePort()), r.env);
    await a.stop();
    assert.deepEqual(r.backups(), []);
    assert.equal(r.meta("app_version"), "2.0.0");
    assert.equal(compareVersions("1.2.3", "1.10.0"), -1);
    assert.equal(compareVersions("1.0.0-rc.2", "1.0.0"), -1);
    assert.equal(compareVersions("1.0.0-rc.10", "1.0.0-rc.2"), 1);
    assert.equal(compareVersions("2.0.0", "2.0.0"), 0);
  } finally {
    r.t.cleanup();
  }
});
