// A generated app runs the conformance suite it pins (template 0.1.19). Since conformance 0.1.26 the two A21 update rows
// (owner rows keep their CRUD when a level changes, spec 0.1.52) FAIL for an app on SDK >= 0.1.36 whose start module ignores
// TBCONF_LEVEL_CRUD. This test generates an app, installs it exactly as CI does (pnpm install --frozen-lockfile --ignore-scripts
// from the dist tarballs), runs `tb-conformance app` against it and checks both rows: PASS with the generated start module,
// FAIL when the applyLevelCrud line is removed. It starts pnpm from npm_execpath, else `corepack pnpm`, and needs the network (or a warm pnpm store). Every child process runs in
// its own process group under a wall-clock limit and is killed with the group; nothing is left running.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { createMiniapp } from "../src/create.ts";

interface Ran {
  status: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

interface Report {
  ok: boolean;
  counts: Record<string, number>;
  sdk: { reported: string | null };
  checks: { id: string; status: string; asserted: string }[];
}

/** The environment of a child that must not inherit this test run's npm/pnpm/test-runner settings. */
function cleanEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!/^(npm_|pnpm_|NODE_TEST|NODE_OPTIONS$)/i.test(k)) env[k] = v;
  env.CI = "1";
  return env;
}

/** Runs `cmd` in its own process group; after `limitMs` the whole group is killed (SIGKILL) and `timedOut` is set. */
function run(cmd: string, args: string[], cwd: string, limitMs: number): Promise<Ran> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { cwd, env: cleanEnv(), detached: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    const killGroup = () => {
      try {
        if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
      } catch {
        // the group is already gone
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killGroup();
    }, limitMs);
    child.stdout.on("data", (d: Buffer) => {
      stdout += d.toString("utf8");
    });
    child.stderr.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
    });
    child.once("error", (e) => {
      clearTimeout(timer);
      killGroup();
      reject(e);
    });
    child.once("close", (status) => {
      clearTimeout(timer);
      killGroup();
      resolve({ status, stdout, stderr, timedOut });
    });
  });
}

/** pnpm the way the repo scripts start it: the running pnpm (npm_execpath, set when pnpm runs the test script), else `corepack pnpm` (the CI image has no pnpm on PATH). */
const NPM_EXECPATH = process.env.npm_execpath;
function runPnpm(args: string[], cwd: string, limitMs: number): Promise<Ran> {
  return NPM_EXECPATH ? run(process.execPath, [NPM_EXECPATH, ...args], cwd, limitMs) : run("corepack", ["pnpm", ...args], cwd, limitMs);
}

const tail = (r: Ran) => `exit ${r.status}${r.timedOut ? " (wall-clock limit)" : ""}\n${r.stderr.slice(-1500)}\n${r.stdout.slice(-1500)}`;
const A21 = ["A21.owner_row_widened_level", "A21.owner_row_narrowed_level"] as const;

describe("a generated app runs the conformance suite it pins", () => {
  let root = "";
  let dir = "";

  before(
    async () => {
      root = mkdtempSync(join(tmpdir(), "create-tb-miniapp-conf-"));
      dir = join(root, "conf-app");
      createMiniapp({ dir, id: "conf-app", name: "Conf App" });
      const install = await runPnpm(["install", "--frozen-lockfile", "--ignore-scripts"], dir, 100_000);
      assert.equal(install.status, 0, `pnpm install --frozen-lockfile: ${tail(install)}`);
      const kit = await run(process.execPath, ["--run", "kit"], dir, 50_000);
      assert.equal(kit.status, 0, `node --run kit: ${tail(kit)}`);
    },
    { timeout: 120_000 },
  );

  after(() => {
    if (root) rmSync(root, { recursive: true, force: true });
  });

  /** `tb-conformance app` with the given start module, exactly as the generated `conformance` script calls it, as JSON. */
  async function conformance(start: string): Promise<Report> {
    const r = await run(join(dir, "node_modules", ".bin", "tb-conformance"), ["app", "--start", start, "--manifest", "tealbrick.manifest.json", "--test-roots", "--json"], dir, 55_000);
    assert.equal(r.timedOut, false, `tb-conformance hit the wall-clock limit: ${tail(r)}`);
    try {
      return JSON.parse(r.stdout) as Report;
    } catch {
      assert.fail(`tb-conformance printed no JSON report: ${tail(r)}`);
    }
  }

  it("A21 owner_row_widened_level and owner_row_narrowed_level PASS with the generated start module", { timeout: 60_000 }, async () => {
    const report = await conformance("conformance.start.ts");
    assert.equal(report.sdk.reported, "0.1.36", "the app reports the SDK that makes the A21 update rows mandatory (not not_applicable by version)");
    for (const id of A21) {
      const row = report.checks.find((c) => c.id === id);
      assert.ok(row, `${id} is in the report`);
      assert.equal(row.status, "pass", `${id}: ${row.status} ${row.asserted}`);
    }
    assert.equal(report.ok, true, `conformance: ${JSON.stringify(report.counts)} ${report.checks.filter((c) => c.status === "fail").map((c) => `${c.id}: ${c.asserted}`).join("; ")}`);
    assert.equal(report.counts.fail, 0);
  });

  it("A21 owner_row_widened_level and owner_row_narrowed_level FAIL when the start module does not apply the level crud", { timeout: 60_000 }, async () => {
    const original = readFileSync(join(dir, "conformance.start.ts"), "utf8");
    const line = /^[ \t]*const leveled = applyLevelCrud\(.*\);$/m;
    assert.match(original, line, "the generated start module applies the level crud in one line");
    const without = original.replace(line, "  const leveled = manifest;");
    assert.notEqual(without, original);
    assert.doesNotMatch(without, /applyLevelCrud\(/, "no applyLevelCrud call is left");
    writeFileSync(join(dir, "conformance.without.start.ts"), without);
    const report = await conformance("conformance.without.start.ts");
    for (const id of A21) {
      const row = report.checks.find((c) => c.id === id);
      assert.ok(row, `${id} is in the report`);
      assert.equal(row.status, "fail", `${id}: ${row.status} ${row.asserted}`);
      assert.match(row.asserted, /did not apply TBCONF_LEVEL_CRUD/);
    }
    assert.equal(report.ok, false);
  });
});
