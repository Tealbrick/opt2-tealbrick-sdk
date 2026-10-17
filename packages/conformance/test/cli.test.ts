// CLI: manifest target, pending targets, app --cmd against the mini app, usage errors.
import assert from "node:assert/strict";
import { readFileSync as readPkg } from "node:fs";

const PKG_VERSION = (JSON.parse(readPkg(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { freePort } from "./apps/free-port.ts";

const cli = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const manifest = fileURLToPath(new URL("./fixtures/sample.manifest.json", import.meta.url));
const serve = fileURLToPath(new URL("./apps/serve-cli.ts", import.meta.url));
const startModule = fileURLToPath(new URL("./apps/start-module.ts", import.meta.url));
const run = (args: string[]) => spawnSync(process.execPath, [cli, ...args], { encoding: "utf8", timeout: 120_000 });

describe("tb-conformance CLI", () => {
  it("manifest <file> prints markdown and exits 0; --json prints the report", () => {
    const md = run(["manifest", manifest]);
    assert.equal(md.status, 0, md.stdout + md.stderr);
    assert.match(md.stdout, /# Conformance report: manifest/);
    const js = run(["manifest", manifest, "--json"]);
    const report = JSON.parse(js.stdout) as { ok: boolean; target: string; checks: unknown[] };
    assert.deepEqual([report.ok, report.target], [true, "manifest"]);
  });

  it("core against nothing exits 1; bridge without --start/--cmd, relay without --cmd, unknown target and missing args exit 2", () => {
    assert.equal(run(["bridge", "--url", "http://127.0.0.1:1", "--json"]).status, 2, "the suite starts the bridge with its own env");
    assert.equal(run(["relay", "--json"]).status, 2);
    assert.equal(run(["core", "--url", "http://127.0.0.1:1"]).status, 1);
    assert.equal(run(["nope"]).status, 2);
    assert.equal(run([]).status, 2);
    assert.equal(run(["app", "--manifest", manifest]).status, 2);
    assert.equal(run(["app", "--manifest", manifest, "--url", "http://127.0.0.1:1"]).status, 2, "--url needs --env-out");
    assert.equal(run(["app", "--start", startModule, "--manifest", manifest, "--test-roots", "--no-test-roots"]).status, 2, "--test-roots (the default) and --no-test-roots exclude each other");
  });

  it("waivers (C89): --waive and tealbrick-conformance.json turn a failing check into waived until the version; unknown ids exit 2", () => {
    const wrong = `sha256:${"1".repeat(64)}`;
    const failing = run(["manifest", manifest, "--expect-digest", wrong, "--json"]);
    assert.equal(failing.status, 1);
    const waived = run(["manifest", manifest, "--expect-digest", wrong, "--waive", "M3@99.0.0", "--json"]);
    assert.equal(waived.status, 0, waived.stderr);
    const r = JSON.parse(waived.stdout) as { ok: boolean; counts: Record<string, number>; checks: { id: string; status: string; asserted: string }[]; waivers: { id: string; state: string; realStatus: string }[] };
    const m3 = r.checks.find((c) => c.id === "M3");
    assert.equal(m3?.status, "waived");
    assert.match(m3?.asserted ?? "", /^fail: .*waived until 99\.0\.0: --waive \(command line\)$/);
    assert.equal(r.counts.waived, 1);
    assert.deepEqual(r.waivers.map((w) => [w.id, w.state, w.realStatus]), [["M3", "applied", "fail"]]);
    const expired = run(["manifest", manifest, "--expect-digest", wrong, "--waive", `M3@${PKG_VERSION}`]);
    assert.equal(expired.status, 1, "at or after `until` the waiver is ignored");
    assert.ok(expired.stdout.includes(`waiver M3@${PKG_VERSION} ignored: conformance ${PKG_VERSION} ≥ ${PKG_VERSION}`), expired.stdout.slice(0, 400));
    assert.match(expired.stdout, /## Waivers/);
    assert.equal(run(["manifest", manifest, "--waive", "Z9.nope@1.0.0"]).status, 2, "unknown check id");
    assert.equal(run(["manifest", manifest, "--waive", "M3"]).status, 2, "missing @until");
    const dir = mkdtempSync(join(tmpdir(), "tbconf-waive-"));
    try {
      const copy = join(dir, "app.manifest.json");
      writeFileSync(copy, readFileSync(manifest, "utf8"));
      writeFileSync(join(dir, "tealbrick-conformance.json"), JSON.stringify({ waivers: [{ id: "M3", until: "9.9.9", reason: "digest pinned by the release record (Fleet)" }] }));
      const f = run(["manifest", copy, "--expect-digest", wrong, "--json"]);
      assert.equal(f.status, 0, f.stderr);
      assert.match((JSON.parse(f.stdout) as { checks: { id: string; asserted: string }[] }).checks.find((c) => c.id === "M3")?.asserted ?? "", /waived until 9\.9\.9: digest pinned by the release record \(Fleet\)/);
      writeFileSync(join(dir, "tealbrick-conformance.json"), JSON.stringify({ waivers: [{ id: "A99.unknown", until: "9.9.9", reason: "x" }] }));
      assert.equal(run(["manifest", copy]).status, 2, "unknown id in the file");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("v0.1.18: a malformed tealbrick-conformance.json (setup / inputs / inputsAs / dynamic) is a usage error (exit 2) before the app starts", () => {
    const dir = mkdtempSync(join(tmpdir(), "tbconf-config-"));
    try {
      const copy = join(dir, "app.manifest.json");
      writeFileSync(copy, readFileSync(manifest, "utf8"));
      const cases: [unknown, RegExp][] = [
        [{ setup: [{ id: "s1", as: "robot", op: "item_create" }] }, /setup\[0\]\.as must be one of owner, agentA, agentB, app, capsAgent/],
        [{ setup: [{ id: "s1", as: "app", op: "area_create", capture: { area: "id" } }] }, /capture\.area must be a JSON pointer/],
        [{ setup: [{ id: "s1", as: "app", op: "a", input: { x: "${later}" } }, { id: "s2", as: "app", op: "b", capture: { later: "/id" } }] }, /setup\[0\]\.input: placeholder \$\{later\} is not captured by an earlier setup step/],
        [{ inputs: { item_create: { space: "${nope}" } } }, /inputs: placeholder \$\{nope\} is not captured by any setup step/],
        [{ inputsAs: { owner: { item_create: {} } } }, /inputsAs\.owner: caller must be one of agentA, agentB, app/],
        [{ dynamic: { item_lookup: { resolveTools: [] } } }, /dynamic\.item_lookup must be \{resolveTools: \[non-empty tool names\]\}/],
        [{ setupp: [] }, /unknown key "setupp"/],
      ];
      for (const [doc, msg] of cases) {
        writeFileSync(join(dir, "tealbrick-conformance.json"), JSON.stringify(doc));
        const r = run(["app", "--start", startModule, "--manifest", copy, "--json"]);
        assert.equal(r.status, 2, `${JSON.stringify(doc)}: ${r.stderr.slice(0, 300)}`);
        assert.match(r.stderr, msg);
        assert.equal(r.stdout, "", "nothing ran");
      }
      writeFileSync(join(dir, "tealbrick-conformance.json"), "{ not json");
      assert.equal(run(["app", "--start", startModule, "--manifest", copy]).status, 2, "not JSON");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("app --start <module> runs every check (restart + backup round-trip included) and exits 0 (--test-roots: accepted no-op, the default)", () => {
    const r = run(["app", "--start", startModule, "--manifest", manifest, "--timeout", "8000", "--test-roots", "--json"]);
    const report = JSON.parse(r.stdout) as { ok: boolean; checks: { id: string; status: string }[] };
    const bad = report.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable").map((c) => `${c.id}:${c.status}`);
    assert.deepEqual(bad, [], r.stderr.slice(-2000));
    assert.equal(r.status, 0);
    assert.equal(run(["app", "--start", manifest, "--manifest", manifest]).status, 2, "a module without start() is a usage error");
  });

  it("app --cmd boots the app with the conformance env (TBCONF_PORTAL_ROOT_KEYS included by default), writes --report files and exits by result", async () => {
    const port = await freePort();
    const dir = mkdtempSync(join(tmpdir(), "tbconf-cli-"));
    try {
      const tpl = join(dir, "template.json");
      writeFileSync(tpl, JSON.stringify({ services: [{ name: "app" }] }));
      const base = join(dir, "report");
      const r = run(["app", "--cmd", `"${process.execPath}" "${serve}" ${port}`, "--url", `http://127.0.0.1:${port}`, "--manifest", manifest, "--deploy-template", tpl, "--timeout", "8000", "--report", base]);
      const report = JSON.parse(readFileSync(`${base}.json`, "utf8")) as { ok: boolean; checks: { id: string; status: string }[] };
      const bad = report.checks.filter((c) => c.status !== "pass" && c.status !== "not_applicable").map((c) => `${c.id}:${c.status}`);
      // --cmd has no backupNow hook → the backup round-trip is the one check that cannot run (not_run fails the run)
      assert.deepEqual(bad, ["A7.backup_roundtrip:not_run"], r.stdout.slice(-2000) + r.stderr.slice(-2000));
      assert.equal(r.status, 1);
      assert.match(readFileSync(`${base}.md`, "utf8"), /A7\.backup_roundtrip/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
