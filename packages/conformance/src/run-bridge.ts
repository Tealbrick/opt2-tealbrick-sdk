// Bridge target runner (CONFORMANCE §2 "Bridge (deployed form)"): builds the world (fake Portal, fake apps from the
// example manifests, agents), starts the bridge under test with the BRIDGE §4.1 env (TB_PORTAL_URL, TB_ENROL_CODE,
// TB_KEK, TB_PUBLIC_URL, TB_KEYS_PUBLIC_URL, TB_DATA_DIR, PORT, TB_INTERNAL_PORT) either through `start(env)` (in-process; the CLI's
// `--start` wraps it in a child process with forkStart) or as a separate
// process (`cmd`), waits for enrolment and the first applied config, runs every check group and returns the §6 report.
import type { ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { type BridgeStart, type BridgeStartResult, BridgeWorld } from "./bridge-world.ts";
import { authChecks, B13_VARIANTS, callChecks, claimChecks, companionChecks, dynamicChecks, enrolChecks, enrolRequests, hookChecks, mcpChecks, peerCatalog, surfaceChecks } from "./checks/bridge.ts";
import { c117Checks } from "./checks/bridge-c117.ts";
import { BridgeCtx, type BridgeHarness } from "./checks/bridge-ctx.ts";
import { eventChecks } from "./checks/bridge-events.ts";
import { addressChecks, configChecks, keyChecks, keySetChecks, keysOriginChecks, listChangedChecks, oauthChecks, pauseChecks, portalDownChecks, reenrolChecks, scanChecks, standaloneChecks } from "./checks/bridge-flows.ts";
import { BRIDGE_CRED_CASES, BRIDGE_GROUP_ORDER, BRIDGE_GROUPS } from "./checks/bridge-ids.ts";
import { p3p4Checks } from "./checks/bridge-p3p4.ts";
import { realAppChecks } from "./checks/bridge-real.ts";
import { spine013Checks } from "./checks/bridge-spine013.ts";
import { spawnCommand } from "./command.ts";
import { request } from "./http.ts";
import { buildReport, type PayloadScan, type Report } from "./report.ts";
import { bad, notRun, Suite, verdict } from "./suite.ts";

export interface RunBridgeOptions {
  /** programmatic harness, called in-process (the CLI's `--start <module>` passes forkStart(module): a child process) */
  start?: BridgeStart;
  /** report subject override */
  subject?: string;
  /** shell command started as a separate process with the suite env merged into the current env */
  cmd?: string;
  /** per-wait timeout in ms (acks, notifications); default 15 000 */
  timeoutMs?: number;
  /** boot (listen + enrol + first config) timeout in ms; default 60 000 */
  bootTimeoutMs?: number;
  /** pause / revocation latency bound in ms; default 60 000 (CREDENTIALS §13) */
  pauseLatencyMs?: number;
  /** check groups to run (default: all; tests select) */
  groups?: string[];
  /** example manifests override (default: @opt2-tealbrick/spec examples) */
  manifests?: Manifest[];
  keepData?: boolean;
  /** forward the bridge's stdout/stderr to this process's stderr as well (debugging) */
  echoLogs?: boolean;
  /**
   * with `start`: the bridge's captured log text so far (the CLI's `--start` collects the child's stdout/stderr). B11.no_log
   * and the C85 audit checks (B26) read it; without it (and without `cmd`) they report not_run.
   */
  logs?: () => string;
  /**
   * v0.1.11 (C62/C63): the bridge's start module honours `TBCONF_PORTAL_ROOT_KEYS` (JSON public JWKs; a harness-only
   * name the bridge itself never reads) by passing it to the bridge's programmatic start option for its pinned roots.
   * Default true (spec 0.1.12); `false` (CLI `--no-test-roots`): the B20 key-set group reports not_run, and a strict
   * bridge (it pins its build's roots, which no test can sign for) cannot enrol at the fake Portal.
   */
  testRoots?: boolean;
  /** C91 group real_app: module specifier / URL of the SDK to start the real app with (default: the installed @opt2-tealbrick/miniapp-sdk) */
  sdkModule?: string;
  /**
   * conformance 0.1.28 (CONFORMANCE v0.1.57): time budget of the B-EV volume rows (retention / rate-limit flood, B-EV-8 and B-EV-11);
   * default 300 000 ms. A flood that does not finish within it leaves those rows not_run, and B-EV-17 not_run when nothing else
   * kept it from passing.
   */
  eventVolumeBudgetMs?: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Boot-failure hint when the bridge enrolled but applied no config (a spec-0.1.12 bridge pins its Portal Root Keys). */
export const PINNED_BRIDGE_ROOTS_HINT =
  "bridge build pins Portal Root Keys: run with test roots (start module must pass env.TBCONF_PORTAL_ROOT_KEYS to the bridge's programmatic start option, CONFORMANCE §7)";

export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as { port: number }).port;
      srv.close(() => resolve(port));
    });
  });
}

async function waitHttp(url: string, ms: number, alive: () => boolean = () => true): Promise<void> {
  const end = Date.now() + ms;
  for (;;) {
    if (!alive()) throw new Error("bridge process exited during boot");
    try {
      const a = await request(url, { timeoutMs: 1500 });
      if (a.status === 200) return;
    } catch {
      // not up yet
    }
    if (Date.now() > end) throw new Error(`no 200 from ${url} within ${ms} ms`);
    await sleep(200);
  }
}

/** `cmd` as a separate process (own process group); stdout/stderr captured for the log scan (B11). */
export function processHarness(cmd: string, logs: { text: string }, echo = false): BridgeStart {
  return async (env) => {
    const merged: NodeJS.ProcessEnv = { ...process.env, ...env };
    // a name the suite removed for this start (B11.keys_origin_unset_503) must not leak in from the parent env
    if (!("TB_KEYS_PUBLIC_URL" in env)) delete merged.TB_KEYS_PUBLIC_URL;
    const child: ChildProcess = spawnCommand(cmd, { env: merged, stdio: ["ignore", "pipe", "pipe"], detached: true });
    const take = (d: Buffer) => {
      logs.text += d.toString("utf8");
      if (echo) process.stderr.write(d);
    };
    child.stdout?.on("data", take);
    child.stderr?.on("data", take);
    const publicUrl = `http://127.0.0.1:${env.PORT}`;
    const internalUrl = `http://127.0.0.1:${env.TB_INTERNAL_PORT}`;
    try {
      await waitHttp(`${publicUrl}/healthz`, 60_000, () => child.exitCode === null);
    } catch (e) {
      kill(child);
      throw new Error(`${e instanceof Error ? e.message : String(e)}; exit ${child.exitCode}; last output: ${logs.text.slice(-400)}`);
    }
    return { publicUrl, internalUrl, stop: () => kill(child) };
  };
}

async function kill(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
  const exited = new Promise((r) => child.once("exit", r));
  const sig = (s: NodeJS.Signals) => {
    try {
      process.kill(-(child.pid as number), s);
    } catch {
      child.kill(s);
    }
  };
  sig("SIGTERM");
  await Promise.race([exited, sleep(5000)]);
  if (child.exitCode === null) {
    sig("SIGKILL");
    await Promise.race([exited, sleep(2000)]);
  }
}

type Group = (c: BridgeCtx) => Promise<unknown>;
const RUNNERS: [string[], Group][] = [
  [["surface"], surfaceChecks],
  [["enrol"], enrolChecks],
  [["auth"], authChecks],
  [["mcp"], mcpChecks],
  [["call"], callChecks],
  [["hooks"], hookChecks],
  [["dynamic"], dynamicChecks],
  [["companion"], companionChecks],
  [["spine013"], spine013Checks],
  [["c117"], c117Checks],
  [["real_app"], realAppChecks],
  [["events"], eventChecks],
  [["b31", "b32"], p3p4Checks],
  [["claim"], claimChecks],
  [["keys"], keyChecks],
  [["keys_origin"], keysOriginChecks],
  [["oauth"], oauthChecks],
  [["config"], configChecks],
  [["addresses"], addressChecks],
  [["keyset"], keySetChecks],
  [["pause.workspace", "pause.agent", "pause.connection", "pause.instance", "revoke"], pauseChecks],
  [["list_changed"], listChangedChecks],
  [["reenrol"], reenrolChecks],
  [["portal_down"], portalDownChecks],
  [["standalone"], standaloneChecks],
];

export async function runBridgeTarget(opts: RunBridgeOptions): Promise<Report> {
  if (!opts.start === !opts.cmd) throw new TypeError("runBridgeTarget: exactly one of start and cmd");
  const startedAt = new Date();
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const bootMs = opts.bootTimeoutMs ?? 60_000;
  const s = new Suite();
  const notes: string[] = [];
  const logs = { text: "" };
  const start = opts.start ?? processHarness(opts.cmd as string, logs, opts.echoLogs);
  const testRoots = opts.testRoots !== false;
  const world = await BridgeWorld.create({ ...(opts.manifests ? { manifests: opts.manifests } : {}), testRoots });
  if (world.peer) world.peer.catalog = () => peerCatalog();
  const dataDir = mkdtempSync(join(tmpdir(), "tb-conformance-bridge-"));
  const [pub, int] = [await freePort(), await freePort()];
  // C91: the real SDK app's listen port is reserved now, so its origin is on the owner allow-list (TB_OWN_INFRA_ORIGINS)
  world.realAppPort = await freePort();
  // C367 (B31 / B32): the ports of the generated real target (its proxy, the app itself) and real caller, likewise on the owner allow-list
  world.capPorts = [await freePort(), await freePort(), await freePort()];
  let env: Record<string, string> = {
    TB_PORTAL_URL: world.portal.url,
    TB_ENROL_CODE: world.portal.issueEnrolCode(),
    TB_KEK: randomBytes(32).toString("base64url"),
    // advertised public origin: https as in every deployment (TLS terminated in front of PORT; CREDENTIALS §10 `ret`
    // must be https); the suite connects to the plain listener on 127.0.0.1:PORT
    TB_PUBLIC_URL: `https://127.0.0.1:${pub}`,
    // key page on its own origin (BRIDGE §3.1 v0.1.10, C59): a second host name of the same listener, https like the
    // main origin (the Secure cookie rule follows it); the suite reaches it as http://localhost:PORT so `Host` carries
    // the keys host name. A harness's publicUrl must therefore not use the host name localhost.
    TB_KEYS_PUBLIC_URL: `https://localhost:${pub}`,
    TB_DATA_DIR: dataDir,
    PORT: String(pub),
    TB_INTERNAL_PORT: String(int),
    // BSD-07 (BRIDGE §5.7): the fake apps run on this host = own infrastructure; the owner-set allow-list names them
    TB_OWN_INFRA_ORIGINS: world.ownInfraOrigins().join(","),
    ...(testRoots ? { TBCONF_PORTAL_ROOT_KEYS: JSON.stringify(world.testRootJwks()) } : {}),
  };
  world.env = env;
  world.portal.bridgePublicUrl = env.TB_PUBLIC_URL as string;
  const subject = opts.subject ?? (opts.cmd ? `process: ${opts.cmd}` : "in-process start(env) module");
  let running: BridgeStartResult | null = null;
  const selected = opts.groups ? new Set(opts.groups) : null;
  try {
    try {
      running = await start(env);
      world.bridge = running;
      const enrolled = await waitFor(() => world.portal.bridgeKey !== null, bootMs);
      if (!enrolled) throw new Error(`no enrolment at the fake Portal within ${bootMs} ms`);
      const rev = await world.publish();
      if (!(await world.waitAck(rev, bootMs))) throw new Error(`config rev ${rev} not acknowledged within ${bootMs} ms (acks seen: ${world.portal.acks.map((a) => a.rev).join(",") || "none"})`);
    } catch (e) {
      const why = `boot failed: ${e instanceof Error ? e.message : String(e)}`;
      for (const g of BRIDGE_GROUP_ORDER) for (const c of BRIDGE_GROUPS[g] ?? []) s.record(c.id, c.title, "the bridge boots, enrols and applies the first config", bad(why));
      notes.push(why);
      // enrolled at the fake Portal but no config acknowledged: the bridge refused the EnrolResponse (key-set rule)
      if (world.portal.bridgeKey !== null && world.portal.acks.length === 0) notes.push(testRoots ? `${PINNED_BRIDGE_ROOTS_HINT} (test roots were offered; the bridge did not pin them)` : `${PINNED_BRIDGE_ROOTS_HINT} (--no-test-roots given)`);
      return buildReport({ target: "bridge", subject, startedAt, checks: s.results, notes });
    }
    const harness: BridgeHarness = {
      world,
      get env() {
        return env;
      },
      restart: async (extra: Record<string, string | null> = {}) => {
        await running?.stop();
        const next: Record<string, string> = { ...env };
        for (const [k, v] of Object.entries(extra)) {
          if (v === null) delete next[k];
          else next[k] = v;
        }
        env = next;
        world.env = env;
        running = await start(env);
        world.bridge = running;
        await waitHttp(`${running.publicUrl}/healthz`, bootMs);
      },
      logs: () => (opts.cmd ? logs.text : opts.logs ? opts.logs() : null),
      dataDir,
      timeoutMs,
      pauseLatencyMs: opts.pauseLatencyMs ?? 60_000,
      groups: selected,
      ...(opts.sdkModule ? { sdkModule: opts.sdkModule } : {}),
      ...(opts.eventVolumeBudgetMs !== undefined ? { eventVolumeBudgetMs: opts.eventVolumeBudgetMs } : {}),
    };
    const c = new BridgeCtx(harness, s);
    for (const [groups, fn] of RUNNERS) {
      if (selected && !groups.some((g) => selected.has(g))) continue;
      const before = s.results.length;
      try {
        await fn(c);
      } catch (e) {
        const why = `group ${groups.join("/")} aborted: ${e instanceof Error ? e.message : String(e)}`;
        notes.push(why);
        for (const g of groups) if (!selected || selected.has(g)) for (const x of BRIDGE_GROUPS[g] ?? []) if (!s.has(x.id)) s.record(x.id, x.title, "group completes", bad(why));
      }
      if (s.results.length === before && groups.some((g) => !selected || selected.has(g))) notes.push(`group ${groups.join("/")} recorded nothing`);
    }
    let scan: PayloadScan | undefined;
    if (!selected || selected.has("scan")) {
      try {
        await B13_VARIANTS(c);
        scan = await scanChecks(c);
      } catch (e) {
        notes.push(`scans aborted: ${e instanceof Error ? e.message : String(e)}`);
      }
      await s.run("C9.case_ids", "CREDENTIALS §18 case ids reported verbatim", `ids ${BRIDGE_CRED_CASES.join(", ")} present with an executed result`, () => {
        const missing = BRIDGE_CRED_CASES.filter((id) => !s.results.some((r) => r.id === id && (r.status === "pass" || r.status === "fail")));
        return verdict(missing.length === 0, missing.length ? `not executed: ${missing.join(", ")}` : "all present");
      });
    }
    // every catalogued id appears: unselected → not_run, selected but never reached → fail
    for (const g of BRIDGE_GROUP_ORDER)
      for (const x of BRIDGE_GROUPS[g] ?? []) {
        if (s.has(x.id)) continue;
        if (selected && !selected.has(g)) s.record(x.id, x.title, "group selected", notRun(`group ${g} not selected in this run`));
        else s.record(x.id, x.title, "check executed", bad("not reached (a prerequisite of its group was missing)"));
      }
    const e = enrolRequests(c)[0];
    const report = buildReport({ target: "bridge", subject, startedAt, checks: s.results, ...(scan ? { payloadScan: scan } : {}), sdk: { majors: e?.sdkMajors ?? [], reported: e?.version ?? null }, notes });
    const k = report.counts;
    report.notes.push(`summary: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run, ${k.not_applicable} not_applicable (${s.results.length} checks); bridge version ${e?.version ?? "?"}`);
    return report;
  } finally {
    await running?.stop().catch(() => undefined);
    await world.close().catch(() => undefined);
    if (!opts.keepData) rmSync(dataDir, { recursive: true, force: true });
  }
}

async function waitFor(fn: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return true;
    await sleep(100);
  }
  return fn();
}
