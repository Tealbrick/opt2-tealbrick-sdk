#!/usr/bin/env node
// tb-conformance — CONFORMANCE §2 targets:
//   tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file> [options]
//     --start: the module default-exports `start(env) → Promise<{ url, stop, backupNow? }>` (runApp's harness contract);
//     the CLI runs it in a child process (forkStart), a fresh one per (re)start, so the app's own process changes (the
//     SDK's root → uid 1000 drop) never reach the suite
//     --peers (CONF-MULTIAPP, package 0.1.20): also run the REAL peer apps declared in tealbrick-conformance.json `peers`
//     (released versions from the signed release index) behind the fake bridge and report group X; --no-peers: off (default)
//   tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>] [--repo <dir>]
//     --repo: the repository root for M6 (build paths are repo-relative; skill files are relative to <file>'s directory)
//   tb-conformance core [--url <gateway origin>] [--live-readonly] [--max-requests <n>] [--interval-ms <ms>]
//     static route-table checks; with --url also live probes (--live-readonly: no sign-in, no writes)
//   tb-conformance bridge (--start <module.ts> | --cmd "<command>") [--groups a,b] [--pause-latency <ms>]
//     --start: default export `start(env) → Promise<{ publicUrl, internalUrl, stop }>`, run in a child process like the
//     app's; --cmd: a separate process with
//     the suite env (TB_PORTAL_URL, TB_ENROL_CODE, TB_KEK, TB_PUBLIC_URL, TB_KEYS_PUBLIC_URL, TB_DATA_DIR, PORT, TB_INTERNAL_PORT) merged
//   tb-conformance relay --cmd "<stdio relay command>" [--login-cmd "<agent login command>"]
// Key-set statements (spec 0.1.12, CREDENTIALS §9.5): app and bridge runs are strict and use TEST Portal Root Keys by
// default: the fake bridge / Portal publish statements signed by a test root and pass its public JWKs in the
// harness-only TBCONF_PORTAL_ROOT_KEYS. A --start module must hand them to startApp(app, env, { portalRootKeys }) (or
// the bridge's programmatic start option); a --cmd command must do the same or the run needs --no-test-roots (then a
// strict build cannot boot against the fakes: it accepts only statements signed by its pinned roots).
// Output: markdown (default) or JSON (--json); --report <base> also writes <base>.json and <base>.md. Exit code 0 only
// when every check passes (CONFORMANCE §6).
import type { ChildProcess } from "node:child_process";
import { readFileSync, realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import type { BridgeStartResult } from "./bridge-world.ts";
import { spawnCommand } from "./command.ts";
import { checkStartModule, forkStart } from "./fork-start.ts";
import { request } from "./http.ts";
import { applyAllowNotRun, applyWaivers, exitCode, type Report, renderMarkdown, resultLabel, type Waiver } from "./report.ts";
import { type AppStartResult, loadManifest, runApp } from "./run-app.ts";
import { runBridgeTarget } from "./run-bridge.ts";
import { runCoreTarget } from "./run-core.ts";
import { runRelayTarget } from "./run-relay.ts";
import { runManifestTarget } from "./targets.ts";
import { CONFORMANCE_VERSION, type ConformanceConfig, EMPTY_CONFIG, loadConformanceConfig, parseWaiveFlag, WAIVER_FILE, WaiverError } from "./waivers.ts";

const USAGE = `usage:
  tb-conformance app (--start <module.ts> | --cmd "<command>" [--url <origin>] | --url <origin> --env-out <file>) --manifest <file>
                     [--inputs <file.json>] [--deploy-template <file.json>] [--no-test-roots] [--timeout <ms>] [--json] [--report <base>]
      test roots (default): the suite signs key-set statements with a TEST root and passes its public JWKs in env.TBCONF_PORTAL_ROOT_KEYS;
        the start module must pass them to startApp(app, env, { portalRootKeys }) (see create-tealbrick-miniapp conformance.start.ts);
        a --cmd / --url app must honour TBCONF_PORTAL_ROOT_KEYS the same way, or run with --no-test-roots
      --no-test-roots: no test roots (A13 not_run); a spec-0.1.12 app then refuses every fake-bridge slice and the run fails at boot
      --test-roots: accepted, no-op (the default)
      --peers: also boot the REAL peer apps of ${WAIVER_FILE} "peers": [{"product", "version", "channel"?, "settings"?}] (max 3) behind the fake
        bridge (group X: peer boot, real companion calls, refusals, contract schema, hold round trip). Each peer is the source at the commit
        of its record in the SIGNED release index, installed with pnpm --frozen-lockfile --ignore-scripts and built; needs pnpm, network
        (registry, codeload.github.com) and test roots; adds minutes to the run. --no-peers: off (the default). --clean-peers: remove the
        peer checkouts (<tmp>/tbconf-peers) after the run
  tb-conformance manifest <file> [--scan <dir>]... [--expect-digest <sha256:…>] [--repo <dir>] [--json] [--report <base>]
  tb-conformance core [--url <gateway origin>] [--live-readonly] [--max-requests <n>] [--interval-ms <ms>] [--json] [--report <base>]
  tb-conformance bridge (--start <module.ts> | --cmd "<command>") [--groups <a,b>] [--pause-latency <ms>] [--no-test-roots] [--timeout <ms>] [--json] [--report <base>]
      --groups: e.g. spine013 = the spec 0.1.13 checks B22–B24 (hold verdict, reserved context, app-initiated calls); leave it out for a bridge older than 0.1.14;
        c117 = B27.hook_*: chain from the hooks declared in the deployed manifests, config hooks[] enabled switch (spec 0.1.24); leave it out for an older bridge;
        real_app = B25: a REAL @opt2-tealbrick/miniapp-sdk app (started in this process) behind the bridge (C91); B26: its app-initiated
          callApp (C85: rate limit, call.app_initiated audit from the --cmd / --start logs) and ignored parentCalls (v0.1.14 A2A-10)
      --sdk-module <specifier|file URL>: the SDK for real_app (default: the installed @opt2-tealbrick/miniapp-sdk)
      test roots (default): the start module (or --cmd command) passes env.TBCONF_PORTAL_ROOT_KEYS to the bridge's programmatic start option
      --no-test-roots: B20 not_run; a spec-0.1.12 bridge then refuses the fake Portal's enrolment and the run fails at boot
  tb-conformance relay --cmd "<stdio relay command>" [--login-cmd "<agent login command>"] [--timeout <ms>] [--json] [--report <base>]
  every target: [--allow-not-run]  exit 0 when nothing failed and the only non-passes are not_run (default: not_run fails, CONFORMANCE §6;
                                   discouraged since v0.1.13: prefer a dated waiver)
                [--waive <checkId>@<untilVersion>]...  a failing / not_run check reports "waived" (not counted) while this
                                   conformance version < untilVersion; at or after it the waiver is ignored and noted.
                                   app / manifest: also ${WAIVER_FILE} next to the manifest {"waivers": [{"id", "until", "reason"}]}.
                                   Unknown check ids are a usage error.
  app: ${WAIVER_FILE} next to the manifest may also hold setup fixtures (v0.1.18; malformed → usage error):
      "setup": [{"id", "as": "owner"|"agentA"|"agentB"|"app"|"capsAgent", "op", "input", "capture": {"<name>": "<JSON pointer into output>"}}]
        run once after the first status push, before the checks, in order; "app" = the suite's companion app caller (A12.*);
        "capsAgent" (0.1.21) = the fresh agent A3.caps_count creates per capped op: those steps run as that agent once it
        exists, just before its capped calls (see README "Setup as the caps agent")
      "inputs": {"<opId>": input}  merged over --inputs (the file wins per key)
      "inputsAs": {"agentA"|"agentB"|"app": {"<opId>": input}}  overrides "inputs" for that caller
      "dynamic": {"<dynamicOpId>": {"resolveTools": ["<tool>"]}}  A11.resolve_family resolves these instead of the catalog
      "narrowing": {"op": "<tag-filtered agent read op>", "input"?: input, "tag"?: "<tag of a setup item>"}  A11.narrowing_empty_anyof
        (C115) sends that read with context rules.narrowing memoryTags {anyOf: []} (no items, or narrowing_unsupported), {anyOf: [tag]}, none
      "\${name}" (whole string values) = a captured value, or \${tb.agentA} \${tb.agentB} \${tb.app} \${tb.instance} (\${tb.capsAgent} in capsAgent steps and inputs);
      a check that needs a capture of a failed step reports not_run naming the step and its answer`;

const readJson = (p: string): unknown => JSON.parse(readFileSync(p, "utf8"));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Spawns `cmd` directly (no shell, C55) with the conformance env; ready when `url` answers HTTP. */
function commandHarness(cmd: string, url: string, bootMs: number) {
  return async (env: Record<string, string>): Promise<AppStartResult> => {
    const child: ChildProcess = spawnCommand(cmd, { env: { ...process.env, ...env }, stdio: ["ignore", "inherit", "inherit"], detached: true });
    const deadline = Date.now() + bootMs;
    for (;;) {
      if (child.exitCode !== null) throw new Error(`app command exited with ${child.exitCode}`);
      try {
        await request(`${url}/tb/v1/health`, { timeoutMs: 1000 });
        break;
      } catch {
        if (Date.now() > deadline) throw new Error(`app did not answer at ${url} within ${bootMs} ms`);
        await sleep(200);
      }
    }
    return {
      url,
      stop: async () => {
        if (child.exitCode !== null || child.pid === undefined) return;
        const exited = new Promise((r) => child.once("exit", r));
        try {
          process.kill(-child.pid, "SIGTERM");
        } catch {
          child.kill("SIGTERM");
        }
        await Promise.race([exited, sleep(5000)]);
        if (child.exitCode === null) {
          try {
            process.kill(-child.pid, "SIGKILL");
          } catch {
            child.kill("SIGKILL");
          }
        }
      },
    };
  };
}

/** `--start <module>`: default export (or named `start`) = the harness `start(env)`, checked up front (usage error),
 * then run in a child process per start (forkStart). */
async function loadStart<T extends object>(path: string, output?: (chunk: Buffer) => void): Promise<(env: Record<string, string>) => Promise<T>> {
  await checkStartModule(path);
  return forkStart<T>(path, output ? { output } : {});
}

function emit(report: Report, json: boolean, base?: string): void {
  if (base) {
    writeFileSync(`${base}.json`, `${JSON.stringify(report, null, 2)}\n`);
    writeFileSync(`${base}.md`, renderMarkdown(report));
  }
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderMarkdown(report));
}

export async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      url: { type: "string" },
      cmd: { type: "string" },
      start: { type: "string" },
      manifest: { type: "string" },
      inputs: { type: "string" },
      "deploy-template": { type: "string" },
      "env-out": { type: "string" },
      timeout: { type: "string" },
      scan: { type: "string", multiple: true },
      "expect-digest": { type: "string" },
      repo: { type: "string" },
      "live-readonly": { type: "boolean", default: false },
      "max-requests": { type: "string" },
      "interval-ms": { type: "string" },
      groups: { type: "string" },
      "pause-latency": { type: "string" },
      "login-cmd": { type: "string" },
      "echo-logs": { type: "boolean", default: false },
      "test-roots": { type: "boolean", default: false },
      peers: { type: "boolean", default: false },
      "no-peers": { type: "boolean", default: false },
      "clean-peers": { type: "boolean", default: false },
      "no-test-roots": { type: "boolean", default: false },
      json: { type: "boolean", default: false },
      "allow-not-run": { type: "boolean", default: false },
      report: { type: "string" },
      waive: { type: "string", multiple: true },
      "sdk-module": { type: "string" },
      help: { type: "boolean", default: false },
    },
  });
  const [target, file] = positionals;
  if (values.help || !target) {
    process.stderr.write(`${USAGE}\n`);
    return values.help ? 0 : 2;
  }
  if (values["test-roots"] && values["no-test-roots"]) throw new Error("use one of --test-roots (the default) and --no-test-roots");
  const testRoots = !values["no-test-roots"];
  if (values.peers && values["no-peers"]) throw new Error("use one of --peers and --no-peers (the default)");
  if ((values.peers || values["clean-peers"]) && target !== "app") throw new Error("--peers and --clean-peers apply to the app target only");
  // waivers and the config file are checked before anything runs: an unknown id or a malformed entry is a usage error (exit 2)
  let waivers: Waiver[];
  let config: ConformanceConfig = EMPTY_CONFIG;
  try {
    const manifestFile = target === "manifest" ? (file ?? values.manifest) : target === "app" ? values.manifest : undefined;
    if (manifestFile) config = loadConformanceConfig(manifestFile);
    waivers = [...(values.waive ?? []).map(parseWaiveFlag), ...config.waivers];
  } catch (e) {
    if (!(e instanceof WaiverError)) throw e;
    process.stderr.write(`tb-conformance: ${e.message}\n${USAGE}\n`);
    return 2;
  }
  let report: Report;
  switch (target) {
    case "manifest": {
      const path = file ?? values.manifest;
      if (!path) throw new Error("manifest: file required");
      report = await runManifestTarget({ manifestPath: path, ...(values.scan ? { scanDirs: values.scan } : {}), ...(values["expect-digest"] ? { expectDigest: values["expect-digest"] } : {}), ...(values.repo ? { repoDir: values.repo } : {}) });
      break;
    }
    case "app": {
      if (!values.manifest) throw new Error("app: --manifest <file> required");
      if (!values.start && !values.cmd && !values.url) throw new Error("app: --start, --cmd or --url required");
      if ([values.start, values.cmd].filter(Boolean).length > 1) throw new Error("app: use one of --start and --cmd");
      if (!values.start && !values.cmd && !values["env-out"]) throw new Error("app: --url mode needs --env-out <file> (the env the app must boot with)");
      if (values.peers && config.peers.length === 0) {
        process.stderr.write(`tb-conformance: --peers needs "peers" in ${WAIVER_FILE} next to the manifest (none declared)\n${USAGE}\n`);
        return 2;
      }
      const envOut = values["env-out"];
      const manifest = loadManifest({ manifestPath: values.manifest }) as { runtime?: { port?: number } };
      const timeoutMs = values.timeout ? Number(values.timeout) : 20_000;
      const url = (values.url ?? `http://127.0.0.1:${manifest.runtime?.port ?? 8080}`).replace(/\/$/, "");
      const harness = values.start ? await loadStart<AppStartResult>(values.start) : null;
      report = await runApp({
        manifestPath: values.manifest,
        ...(harness
          ? { start: harness }
          : values.cmd
            ? { start: commandHarness(values.cmd, url, Math.max(timeoutMs, 30_000)) }
            : {
                url,
                // the env holds this run's one-time enrolment code and KEK: written to a 0600 file, never printed
                onEnv: (env: Record<string, string>) => {
                  writeFileSync(envOut as string, Object.entries(env).map(([k, v]) => `${k}=${v}`).join("\n").concat("\n"), { mode: 0o600 });
                  process.stderr.write(`tb-conformance: boot the app at ${url} with the env in ${envOut}; waiting for its claim\n`);
                },
                bootTimeoutMs: 120_000,
              }),
        ...(values.inputs ? { inputs: readJson(values.inputs) as Record<string, never> } : {}),
        config,
        ...(values["deploy-template"] ? { deployTemplate: readJson(values["deploy-template"]) } : {}),
        testRoots,
        timeoutMs,
        ...(values.peers ? { peers: { ...(values["clean-peers"] ? { cleanup: true } : {}) } } : {}),
      });
      break;
    }
    case "core": {
      const num = (v: string | undefined, name: string) => {
        if (v === undefined) return undefined;
        const n = Number(v);
        if (!Number.isInteger(n) || n < 0) throw new Error(`core: --${name} must be a non-negative integer`);
        return n;
      };
      const maxRequests = num(values["max-requests"], "max-requests");
      const minIntervalMs = num(values["interval-ms"], "interval-ms");
      report = await runCoreTarget({
        ...(values.url ? { url: values.url } : {}),
        liveReadonly: values["live-readonly"],
        ...(maxRequests !== undefined ? { maxRequests } : {}),
        ...(minIntervalMs !== undefined ? { minIntervalMs } : {}),
      });
      const k = report.counts;
      process.stderr.write(`tb-conformance core: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run, ${k.not_implemented} not_implemented → ${resultLabel(report)}\n`);
      break;
    }
    case "bridge": {
      if (!values.start === !values.cmd) throw new Error("bridge: exactly one of --start <module.ts> and --cmd \"<command>\" (the deployed bridge is started by the suite with its env)");
      const ms = (v: string | undefined, name: string) => {
        if (v === undefined) return undefined;
        const n = Number(v);
        if (!Number.isInteger(n) || n <= 0) throw new Error(`bridge: --${name} must be a positive integer (ms)`);
        return n;
      };
      const timeoutMs = ms(values.timeout, "timeout");
      const pauseLatencyMs = ms(values["pause-latency"], "pause-latency");
      // --start: the child's stdout/stderr still go to this process's stderr and are kept for the log checks (B11, B26)
      const startLogs = { text: "" };
      const keep = (chunk: Buffer) => {
        startLogs.text += chunk.toString("utf8");
        process.stderr.write(chunk);
      };
      report = await runBridgeTarget({
        ...(values.start ? { start: await loadStart<BridgeStartResult>(values.start, keep), subject: `start(env) module ${values.start} (child process)`, logs: () => startLogs.text } : { cmd: values.cmd as string }),
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
        ...(pauseLatencyMs !== undefined ? { pauseLatencyMs } : {}),
        ...(values.groups ? { groups: values.groups.split(",").map((g) => g.trim()).filter(Boolean) } : {}),
        echoLogs: values["echo-logs"],
        ...(values["sdk-module"] ? { sdkModule: values["sdk-module"] } : {}),
        testRoots,
      });
      const k = report.counts;
      process.stderr.write(`tb-conformance bridge: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run, ${k.not_applicable} not_applicable → ${resultLabel(report)}\n`);
      break;
    }
    case "relay": {
      if (!values.cmd) throw new Error('relay: --cmd "<stdio relay command>" required');
      const timeoutMs = values.timeout ? Number(values.timeout) : undefined;
      report = await runRelayTarget({ cmd: values.cmd, ...(values["login-cmd"] ? { loginCmd: values["login-cmd"] } : {}), ...(timeoutMs ? { timeoutMs } : {}) });
      const k = report.counts;
      process.stderr.write(`tb-conformance relay: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run → ${resultLabel(report)}\n`);
      break;
    }
    default:
      process.stderr.write(`unknown target ${target}\n${USAGE}\n`);
      return 2;
  }
  applyWaivers(report, waivers, CONFORMANCE_VERSION);
  if (values["allow-not-run"] === true) applyAllowNotRun(report);
  emit(report, values.json, values.report);
  return exitCode(report, { allowNotRun: values["allow-not-run"] === true });
}

const isEntry = (() => {
  try {
    return realpathSync(process.argv[1] ?? "") === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();
/**
 * Exits after stdout and stderr have been flushed. `process.exit` right after a large `write` to a PIPE loses what the pipe
 * (64 KiB) did not take yet: a report over 64 KiB was cut off mid-string when a parent read it (conformance 0.1.25: the report
 * grew past that with the A21 rows). A write callback fires when everything written before it has been handed to the OS.
 */
function exitFlushed(code: number): void {
  process.exitCode = code;
  process.stdout.write("", () => process.stderr.write("", () => process.exit(code)));
}
if (isEntry) {
  main(process.argv.slice(2)).then(exitFlushed, (e) => {
    process.stderr.write(`tb-conformance: ${e instanceof Error ? e.message : String(e)}\n`);
    exitFlushed(2);
  });
}
