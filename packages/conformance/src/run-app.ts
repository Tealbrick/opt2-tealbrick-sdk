// App target runner (CONFORMANCE §2 "App, Portal mode"): boots (or points at) an app wired to the fake bridge through
// the SDK-API §13 env names, waits for its claim and first slice, runs the manifest checks and every app check, and
// returns the §6 report. `start(env)` is the programmatic harness: it boots the app with `env` and returns its URL,
// a stop function and optionally `backupNow` (RunningApp.backups.runNow) for the A7 round-trip. `start` runs IN this
// process; the CLI's `--start <module>` passes forkStart(module), which boots the module in a child process per start.
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { manifestDigest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { AppClient } from "./app-client.ts";
import { runAppChecks } from "./checks/app.ts";
import { APP_CHECK_IDS } from "./checks/catalog.ts";
import { runManifestChecks } from "./checks/manifest.ts";
import { createFakeBridge, type FakeAgent, type FakeBridge } from "./fake-bridge.ts";
import { request } from "./http.ts";
import { type MultiAppDeps, preparePeers, runPeerChecks } from "./multi-app.ts";
import { type PeerSourceOptions, removePeerCaches } from "./peer-source.ts";
import { buildReport, type PayloadScan, type Report } from "./report.ts";
import { bad, Suite } from "./suite.ts";
import { type ConformanceConfig, EMPTY_CONFIG, loadConformanceConfig, type PeerSpec } from "./waivers.ts";

export interface AppStartResult {
  /** private-network origin of the app (e.g. http://127.0.0.1:8080) */
  url: string;
  stop(): Promise<void>;
  /** triggers one backup into TB_BACKUP_DIR (A7 round-trip) */
  backupNow?(): Promise<void>;
}

export interface RunAppOptions {
  /** parsed manifest JSON (or use `manifestPath`) */
  manifest?: unknown;
  manifestPath?: string;
  /** programmatic harness: boot the app with `env` (called in-process; wrap with forkStart(module) for a child process) */
  start?: (env: Record<string, string>) => Promise<AppStartResult>;
  /** an app booted elsewhere with the env passed to `onEnv` (no restart / backup checks: they report not_run) */
  url?: string;
  onEnv?: (env: Record<string, string>) => void;
  /** extra env merged into the app env */
  env?: Record<string, string>;
  /** known-good inputs per op id (generic fixtures; never needed for the standard ops); the config file's `inputs` win per key */
  inputs?: Record<string, Json>;
  /**
   * v0.1.18: the per-app `tealbrick-conformance.json` (setup, inputs, inputsAs, dynamic, narrowing; waivers are applied by the
   * caller). Default: loaded from beside `manifestPath` (a malformed file throws WaiverError); `null`: none.
   */
  config?: ConformanceConfig | null;
  /** generated deploy template JSON (A9) */
  deployTemplate?: unknown;
  /** per-wait timeout in ms (slice install, status push); default 20 000 */
  timeoutMs?: number;
  /** claim + first slice timeout in ms; default 30 000 */
  bootTimeoutMs?: number;
  /** data directory for the app (default: a fresh temp dir, removed afterwards) */
  dataDir?: string;
  keepData?: boolean;
  /** source trees for M5 */
  scanDirs?: string[];
  agents?: FakeAgent[];
  /**
   * v0.1.11 (C62/C63): the harness wires the TEST Portal Root Keys: the app env gets `TBCONF_PORTAL_ROOT_KEYS` (JSON
   * array of public JWKs; not a TB_* name, read only by the start module, which passes it to
   * `startApp(app, env, { portalRootKeys })`). Default true (spec 0.1.12: a strict app accepts no slice whose statement
   * is not signed by a root it pins); `false` (CLI `--no-test-roots`): the A13 key-set checks report not_run and a
   * strict app cannot boot against the fake bridge (the boot failure says so).
   */
  testRoots?: boolean;
  /**
   * CONF-MULTIAPP (conformance 0.1.20, CLI `--peers`): run REAL peer apps (released SDK apps from the signed release
   * index) behind the fake bridge and report group X. `specs` default: `config.peers` (tealbrick-conformance.json).
   * `source` makes the index lookup and the checkout injectable (the suite's own tests use local fixture apps and no
   * network); `cleanup` removes the peer checkouts after the run. Off unless set; needs test roots.
   */
  peers?: { specs?: PeerSpec[]; source?: PeerSourceOptions; cleanup?: boolean };
}

/** Harness-only env name carrying the test root JWKs (never read by the SDK or the bridge; CONFORMANCE §7). */
export const TEST_ROOTS_ENV = "TBCONF_PORTAL_ROOT_KEYS";
/** v0.1.21: the free port the suite picked for a `start(env)` app (harness-only name; the app's own code never reads it). */
export const PORT_ENV = "TBCONF_PORT";

/** A free TCP port on 127.0.0.1 (bind port 0, read it, close). */
export function freeTcpPort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const a = srv.address();
      const p = a && typeof a === "object" ? a.port : 0;
      srv.close(() => resolve(p));
    });
  });
}

/** Boot-failure hint when the app claimed but installed no slice (a spec-0.1.12 app pins its Portal Root Keys). */
export const PINNED_ROOTS_HINT =
  "app build pins Portal Root Keys: run with test roots (start module must pass env.TBCONF_PORTAL_ROOT_KEYS to startApp — see create-tealbrick-miniapp conformance.start.ts)";

export function loadManifest(opts: { manifest?: unknown; manifestPath?: string }): unknown {
  if (opts.manifest !== undefined) return opts.manifest;
  if (!opts.manifestPath) throw new TypeError("runApp: manifest or manifestPath required");
  return JSON.parse(readFileSync(opts.manifestPath, "utf8"));
}

/** The env an app under test boots with (SDK-API §13); the only secrets are TB_ENROL_CODE and TB_KEK (C8). TB_DATA_EPHEMERAL=1 always (tests / conformance only). */
export function appEnv(bridge: FakeBridge, dataDir: string, extra: Record<string, string> = {}): Record<string, string> {
  const backup = join(dataDir, "backup");
  mkdirSync(backup, { recursive: true });
  return {
    TB_INSTANCE_ID: bridge.ids.ins,
    TB_ENROL_CODE: bridge.enrolCode,
    TB_BRIDGE_URL: bridge.url,
    TB_PORTAL_KEYS: JSON.stringify(bridge.portalJwks()),
    TB_KEK: randomBytes(32).toString("base64url"),
    TB_DATA_DIR: dataDir,
    TB_BACKUP_DIR: backup,
    TB_LOG_LEVEL: "warn",
    // SDK-API §13 v0.1.12: temp data dirs are not volumes; without this a Linux runner would never let the app claim
    TB_DATA_EPHEMERAL: "1",
    ...extra,
  };
}

export async function runApp(opts: RunAppOptions): Promise<Report> {
  const startedAt = new Date();
  const json = loadManifest(opts);
  const mres = await runManifestChecks(json, {
    ...(opts.manifestPath ? { manifestPath: opts.manifestPath } : {}),
    ...(opts.scanDirs ? { scanDirs: opts.scanDirs } : {}),
    m5NotApplicable: "M5 applies to Core / bridge / SDK source trees (run `tb-conformance manifest <file> --scan <dir>`)",
  });
  const s = new Suite();
  s.results.push(...mres.results);
  const manifest = mres.manifest;
  const subjectOf = (url: string) => `${manifest ? `${manifest.id}@${manifest.version}` : "invalid manifest"} at ${url}`;
  if (!manifest) {
    for (const id of APP_CHECK_IDS) s.record(id, "app check", "app checks need a valid manifest", bad("manifest invalid (M1)"));
    return buildReport({ target: "app", subject: subjectOf(opts.url ?? "(not started)"), startedAt, checks: s.results, notes: [...mres.notes] });
  }
  if (!opts.start && !opts.url) throw new TypeError("runApp: start or url required");

  const config = opts.config === undefined ? (opts.manifestPath ? loadConformanceConfig(opts.manifestPath) : EMPTY_CONFIG) : (opts.config ?? EMPTY_CONFIG);
  const testRoots = opts.testRoots !== false;
  const bridge = await createFakeBridge({ manifest: manifest as Manifest, ...(opts.agents ? { agents: opts.agents } : {}) });
  // an app that requires a statement must get one in its very first slice (claim answer)
  if (testRoots) await bridge.control.publishKeySet();
  const ownDir = opts.dataDir === undefined;
  const dataDir = opts.dataDir ?? mkdtempSync(join(tmpdir(), "tb-conformance-"));
  // v0.1.21 (conformance 0.1.13): a free port per run (TBCONF_PORT; the start module passes it to startApp's harness port), so two
  // runs on one machine never clash; a start module that ignores it keeps manifest runtime.port (no regression). `opts.env`
  // (or a caller-set TBCONF_PORT) pins it.
  const port = opts.start ? await freeTcpPort() : null;
  const env = appEnv(bridge, dataDir, { ...(testRoots ? { [TEST_ROOTS_ENV]: JSON.stringify(bridge.testRootJwks()) } : {}), ...(port ? { [PORT_ENV]: String(port) } : {}), ...opts.env });
  const timeoutMs = opts.timeoutMs ?? 20_000;
  let app: AppStartResult | null = null;
  let client: AppClient | null = null;
  let scan: PayloadScan | undefined;
  const loadedPeers: Parameters<typeof removePeerCaches>[0][number][] = [];
  const notes: string[] = [...mres.notes];
  try {
    if (opts.start) app = await opts.start(env);
    else opts.onEnv?.(env);
    const url = app?.url ?? (opts.url as string);
    if (port && env[PORT_ENV] === String(port)) notes.push(`app port: ${new URL(url).port || "?"} (suite offered TBCONF_PORT=${port}${new URL(url).port === String(port) ? "" : "; the start module ignored it and used its own port — update conformance.start.ts from create-tealbrick-miniapp ≥ 0.1.9"})`);
    client = bridge.client(url);
    try {
      await bridge.control.waitForClaim(opts.bootTimeoutMs ?? 30_000);
      await bridge.control.waitForSliceRevision(1, opts.bootTimeoutMs ?? 30_000);
      // the URL must reach the app under test (not e.g. another process holding the port)
      const h = await request(`${url}/tb/v1/health`, { timeoutMs: 5000 }).catch((e: unknown) => ({ status: 0, body: String(e) }));
      const served = (h.body as { manifestDigest?: unknown } | null)?.manifestDigest;
      if (h.status !== 200 || served !== manifestDigest(manifest as Manifest)) {
        throw new Error(`${url} does not answer as the app under test (GET /tb/v1/health → ${h.status}${served ? `, manifestDigest ${String(served)}` : ""}); is another process listening on that port?`);
      }
    } catch (e) {
      const why = `boot failed: ${e instanceof Error ? e.message : String(e)} (claims ${bridge.claims.length}, status pushes ${bridge.statuses.length}, refusals ${bridge.violations.map((v) => v.code).join(",") || "none"})`;
      for (const id of APP_CHECK_IDS) s.record(id, "app check", "app claims and installs its first slice", bad(why));
      const bootNotes = [why, ...mres.notes];
      // claimed but no slice installed: the app refused the fake bridge's slice (key-set rule, CREDENTIALS §9.5)
      if (bridge.claims.length > 0 && !bridge.statuses.some((x) => x.status.sliceRevision >= 1)) {
        bootNotes.push(testRoots ? `${PINNED_ROOTS_HINT} (test roots were offered in ${TEST_ROOTS_ENV}; the app did not pin them)` : `${PINNED_ROOTS_HINT} (--no-test-roots given)`);
      }
      return buildReport({ target: "app", subject: subjectOf(url), startedAt, checks: s.results, sdk: { majors: bridge.sdkMajors, reported: null }, notes: bootNotes });
    }
    const start = opts.start;
    // CONF-MULTIAPP: peers are downloaded / installed / built BEFORE the checks (a failure is that peer's X1 row, never an abort)
    const peerSpecs = opts.peers ? (opts.peers.specs ?? config.peers) : [];
    if (opts.peers && peerSpecs.length === 0) throw new TypeError("runApp: peers requested but none declared (tealbrick-conformance.json peers)");
    const prepared = peerSpecs.length > 0 ? await preparePeers(peerSpecs, opts.peers?.source ?? {}, notes) : [];
    loadedPeers.push(...prepared.flatMap((p) => ("peer" in p ? [p.peer] : [])));
    const deps: MultiAppDeps = { appEnv, freeTcpPort, testRootsEnv: TEST_ROOTS_ENV, portEnv: PORT_ENV };
    scan = await runAppChecks(s, {
      bridge,
      client: () => client as AppClient,
      manifest: manifest as Manifest,
      env,
      ...(start
        ? {
            restart: async (extra: Record<string, string> = {}) => {
              await app?.stop();
              app = await start({ ...env, ...extra });
              client = bridge.client(app.url);
            },
          }
        : {}),
      ...(app?.backupNow ? { backupNow: () => (app as AppStartResult).backupNow?.() ?? Promise.resolve() } : {}),
      inputs: { ...(opts.inputs ?? {}), ...config.inputs },
      inputsAs: config.inputsAs,
      setup: config.setup,
      dynamic: config.dynamic,
      ...(config.narrowing ? { narrowing: config.narrowing } : {}),
      ...(config.scopeGrantOp ? { scopeGrantOp: config.scopeGrantOp } : {}),
      ...(config.companionCallersOp ? { companionCallersOp: config.companionCallersOp } : {}),
      ...(config.hookCallerProduct ? { hookCallerProduct: config.hookCallerProduct } : {}),
      ...(config.callerListedOp ? { callerListedOp: config.callerListedOp } : {}),
      ...(config.bridgeCapsOp ? { bridgeCapsOp: config.bridgeCapsOp } : {}),
      ...(config.eventsProbe ? { eventsProbe: config.eventsProbe } : {}),
      ...(prepared.length > 0
        ? { multi: (driver) => runPeerChecks({ suite: s, deps, app: { manifest: manifest as Manifest, bridge, driver, timeoutMs }, prepared, config, testRoots, notes }) }
        : {}),
      notes,
      testRoots,
      ...(opts.deployTemplate !== undefined ? { deployTemplate: opts.deployTemplate } : {}),
      timeoutMs,
    });
    if (!opts.start) notes.push("--url mode: restart and backup checks need a restartable app (start()/--cmd) and report not_run");
    return buildReport({
      target: "app",
      subject: subjectOf(client.url),
      startedAt,
      checks: s.results,
      ...(scan ? { payloadScan: scan } : {}),
      sdk: { majors: bridge.sdkMajors, reported: bridge.claims[0]?.request.sdkVersion ?? null },
      notes,
    });
  } finally {
    await app?.stop().catch(() => undefined);
    await bridge.close();
    if (opts.peers?.cleanup) removePeerCaches(loadedPeers);
    if (ownDir && !opts.keepData) rmSync(dataDir, { recursive: true, force: true });
  }
}
