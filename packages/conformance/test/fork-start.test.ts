// CLI `--start` runs the harness module in a child process (forkStart): the app's own process changes (the SDK's
// root → uid 1000 drop, simulated here by a module that makes its process unable to write the report dir) never reach
// the runner, each (re)start is a fresh child, and boot failures surface as clear errors.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { createFakeBridge } from "../src/fake-bridge.ts";
import { checkStartModule, forkStart } from "../src/fork-start.ts";
import type { Manifest } from "../src/manifest-type.ts";
import { appEnv } from "../src/run-app.ts";
import { freePort } from "./apps/free-port.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const manifest = fileURLToPath(new URL("./fixtures/sample.manifest.json", import.meta.url));
const probe = fileURLToPath(new URL("./apps/probe-start.ts", import.meta.url));
const sdkStart = fileURLToPath(new URL("./apps/sdk-start.ts", import.meta.url));

type Report = { ok: boolean; target: string; checks: { id: string; status: string }[] };
const tmp = (p: string) => mkdtempSync(join(tmpdir(), p));
const alive = (pid: number) => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};
/** suite-shaped env (no real secrets needed for these harness tests) */
const suiteEnv = (dir: string) => ({ TB_INSTANCE_ID: "ins_test", TB_DATA_DIR: dir, TB_BACKUP_DIR: join(dir, "backup") });

describe("CLI --start runs the app in a child process", () => {
  it("the app runs under other pids than the runner (fresh child per restart) with the suite env, and its sabotaged process does not stop --report", () => {
    const dir = tmp("tbconf-fork-");
    try {
      const reportDir = join(dir, "out");
      mkdirSync(reportDir);
      const pids = join(dir, "pids.jsonl");
      const r = spawnSync(process.execPath, [cli, "app", "--start", probe, "--manifest", manifest, "--timeout", "8000", "--report", "out/r"], {
        cwd: dir, // relative --report: the child's chdir must not move it
        encoding: "utf8",
        timeout: 120_000,
        env: { ...process.env, TBTEST_PIDS: pids, TBTEST_MODE: "sabotage", TBTEST_REPORT_DIR: reportDir },
      });
      assert.ok(existsSync(join(reportDir, "r.json")), `report not written: ${r.stderr.slice(-1500)}`);
      const report = JSON.parse(readFileSync(join(reportDir, "r.json"), "utf8")) as Report;
      const bad = report.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable").map((c) => `${c.id}:${c.status}`);
      assert.deepEqual(bad, [], r.stderr.slice(-1500));
      assert.equal(r.status, 0);
      assert.match(readFileSync(join(reportDir, "r.md"), "utf8"), /# Conformance report: app/);
      const starts = readFileSync(pids, "utf8").trim().split("\n").map((l) => JSON.parse(l) as { pid: number; suiteEnvInherited: boolean });
      assert.ok(starts.length >= 2, "restart checks start the app more than once");
      assert.ok(starts.every((s) => s.pid !== r.pid && s.pid !== process.pid), "the app never runs in the runner's process");
      assert.equal(new Set(starts.map((s) => s.pid)).size, starts.length, "every (re)start is a fresh process");
      assert.ok(starts.every((s) => s.suiteEnvInherited), "the child's process env carries the suite's TB_* names");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("control: the same sabotage in-process takes the runner's report writes with it", async () => {
    const dir = tmp("tbconf-fork-ctl-");
    const mod = (await import("./apps/probe-start.ts")) as { sabotage(d: string): void; unsabotage(): void };
    try {
      mod.sabotage(dir);
      assert.throws(() => writeFileSync(join(dir, "r.json"), "{}"), /EACCES/);
    } finally {
      mod.unsabotage();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("root CI: CLI app --start on the real miniapp-sdk startApp (uid drop) still writes --report into a root-owned dir", { skip: process.getuid?.() !== 0 ? "not root: the SDK only drops privileges when started as root (runs in root CI containers)" : false }, async () => {
    const dir = tmp("tbconf-root-");
    // app files must be readable by the dropped app (as in an image); mkdtemp creates 0700. The report dir stays 0700.
    chmodSync(dir, 0o755);
    try {
      const { fixtureManifest } = (await import(new URL("../../miniapp-sdk/test/fixtures/manifest.ts", import.meta.url).href)) as { fixtureManifest(port: number): unknown };
      const mPath = join(dir, "manifest.json");
      writeFileSync(mPath, JSON.stringify(fixtureManifest(await freePort())));
      const migrations = join(dir, "migrations");
      mkdirSync(migrations);
      writeFileSync(join(migrations, "0001_init.sql"), "CREATE TABLE notes (id TEXT PRIMARY KEY, notebook TEXT NOT NULL, title TEXT NOT NULL);");
      const reportDir = join(dir, "out"); // created by root, mode 0700 under a 0700 mkdtemp dir
      mkdirSync(reportDir, { mode: 0o700 });
      const r = spawnSync(process.execPath, [cli, "app", "--start", sdkStart, "--manifest", mPath, "--timeout", "8000", "--report", join(reportDir, "r")], {
        encoding: "utf8",
        timeout: 180_000,
        env: { ...process.env, TBTEST_SDK_MANIFEST: mPath, TBTEST_SDK_MIGRATIONS: migrations },
      });
      assert.notEqual(r.status, 2, `runner failed (exit 2): ${r.stderr.slice(-1500)}`);
      assert.ok(existsSync(join(reportDir, "r.json")) && existsSync(join(reportDir, "r.md")), r.stderr.slice(-1500));
      const report = JSON.parse(readFileSync(join(reportDir, "r.json"), "utf8")) as Report;
      assert.equal(report.target, "app");
      assert.equal(process.getuid?.(), 0, "the test process is still root");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("forkStart / checkStartModule", () => {
  it("boots start(env) in a child, proxies string fields and methods, and stop() ends the child", async () => {
    const dir = tmp("tbconf-fork-unit-");
    const bridge = await createFakeBridge({ manifest: JSON.parse(readFileSync(manifest, "utf8")) as Manifest });
    try {
      const env = appEnv(bridge, dir);
      const app = await forkStart<{ url: string; backupNow(): Promise<void> }>(probe, { output: () => undefined })(env);
      assert.notEqual(app.pid, process.pid);
      assert.ok(alive(app.pid));
      assert.match(app.url, /^http:\/\/127\.0\.0\.1:\d+$/);
      await bridge.control.waitForClaim(15_000);
      await app.backupNow();
      assert.ok(readdirSync(env.TB_BACKUP_DIR as string).length > 0, "backupNow ran in the child");
      await app.stop();
      assert.equal(alive(app.pid), false, "stop() ends the child");
      await assert.rejects(app.backupNow(), /app process exited/);
      await app.stop(); // idempotent
    } finally {
      await bridge.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("start() rejection, early exit, boot timeout and calls after exit are clear errors; children never outlive them", async () => {
    const dir = tmp("tbconf-fork-neg-");
    const pids = join(dir, "pids.jsonl");
    const prev = { ...process.env };
    const lastPid = () => (JSON.parse(readFileSync(pids, "utf8").trim().split("\n").at(-1) as string) as { pid: number }).pid;
    try {
      process.env.TBTEST_PIDS = pids;
      process.env.TBTEST_MODE = "throw";
      await assert.rejects(forkStart(probe, { output: () => undefined })(suiteEnv(dir)), /start\(env\) failed: boom from start/);
      process.env.TBTEST_MODE = "exit";
      await assert.rejects(forkStart(probe, { output: () => undefined })(suiteEnv(dir)), /app process exited \(code 3/);
      process.env.TBTEST_MODE = "hang";
      await assert.rejects(forkStart(probe, { bootTimeoutMs: 1500, output: () => undefined })(suiteEnv(dir)), /did not resolve within 1500 ms \(child killed\)/);
      const hung = lastPid();
      for (let i = 0; i < 50 && alive(hung); i++) await new Promise((r) => setTimeout(r, 50));
      assert.equal(alive(hung), false, "the timed-out child is killed");
      assert.notEqual(hung, process.pid);
    } finally {
      process.env = prev;
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("checkStartModule accepts a start module and refuses a module without start(env)", async () => {
    await checkStartModule(probe);
    await assert.rejects(checkStartModule(manifest), /--start .*sample\.manifest\.json/);
    const dir = tmp("tbconf-fork-chk-");
    try {
      const noStart = join(dir, "no-start.ts");
      writeFileSync(noStart, "export const x = 1;\n");
      await assert.rejects(checkStartModule(noStart), /no default-exported start\(env\) function/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
