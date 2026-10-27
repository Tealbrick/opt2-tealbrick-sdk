// defineApp / startApp (SDK-API §3): the manifest is the only source; the app registers handlers by operation id and
// the SDK derives routes, validation, OpenAPI, status and standard ops. startApp refuses to boot on an invalid
// manifest, handler set or migration set.
import { existsSync, readFileSync } from "node:fs";
import type { Server } from "node:http";
import { join } from "node:path";
import { isValidLaunchPath, keySetFrom, type ModelRole, manifestDigest, memoryReplayGuard, type ResolvedModelRole, sdkMajorOf, ulid, validateManifest, withStandardOps } from "@opt2-tealbrick/manifest";
import type { ScopeRequest } from "@opt2-tealbrick/spec/bridge";
import type { Ed25519PublicJwk, InstanceId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { App, AppDefinition, HealthStatus, HoldDecideInput, OperationView, PersonPrincipal, Receipt, RunningApp, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { createAppSecrets } from "./app-secrets.ts";
import { createAuditLog } from "./audit.ts";
import { type BackupContext, createBackupApi, type RestoreOutcome, restoreAtBoot, writePreUpdateSnapshot } from "./backup.ts";
import { BridgeClient } from "./bridge-client.ts";
import { logMountAtBoot } from "./claim-guard.ts";
import type { SdkAppDefinition, SdkEventContext, StartContext } from "./context.ts";
import { readEnv, type SdkConfig } from "./env.ts";
import { TbError } from "./errors.ts";
import { EventOutbox } from "./events.ts";
import { startFailedMode } from "./failed.ts";
import { JOB_KIND_RE, JobRunner, type JobsApi, jobsView, RUNNER_DEFAULTS, sealGrant, unsealGrant } from "./jobs.ts";
import { createKeys } from "./keys.ts";
import { BridgeLink } from "./link.ts";
import { createLogger, SecretRegistry } from "./log.ts";
import { callAppOpts, decide, fireScheduledOp, workflowOfGrant } from "./ops.ts";
import { createPersonAuth } from "./person.ts";
import { dropPrivileges, type PrivilegeProc } from "./privilege.ts";
import { Receipts } from "./receipts.ts";
import type { Runtime } from "./runtime.ts";
import { createScopeStore } from "./scopes.ts";
import { createSealer, loadInstanceKey, resolveKeks, type Sealer } from "./secrets.ts";
import { createHttpServer } from "./server.ts";
import { createServiceHelperCaller } from "./service-helper.ts";
import type { WorkflowGrantsApi } from "./spec-p1.temp.ts";
import { AttentionReader, PendingCounter, pickAttention, StatusPusher } from "./status.ts";
import {
  type AppliedMigration,
  appDb,
  applyAppMigrations,
  applySdkMigrations,
  metaGet,
  metaSet,
  openDb,
  pendingAppMigrations,
  pendingSdkMigrations,
  type RawDb,
  type Row,
  type SchemaVersion,
  SDK_SCHEMA,
  scanMigrations,
  storedSchema,
} from "./store.ts";
import { TrustState } from "./trust.ts";
import { type BootFailure, type BootPhase, bootFailure, type Clock, META, MigrationLock, type PreUpdateSnapshot, readUpgradeMeta, realClock, recordBoot } from "./upgrade.ts";
import { workflowGrantsWithoutBridge } from "./workflow-grants.ts";

export const SDK_VERSION: string = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;
/**
 * SDK major the manifest `sdkMajor` must equal. SPEC-GAP: the schema requires `sdkMajor ≥ 1` while the SDK ships as
 * 0.x during the opt2 build; 0.x is treated as major 1.
 */
export const SDK_MAJOR: number = sdkMajorOf(SDK_VERSION);

const SWEEP_MS = 60_000;
const definitions = new WeakMap<App, SdkAppDefinition<string>>();
let current: Runtime | null = null;

/** Registers handlers by operation id. Validation happens in startApp (boot refuses on error). */
export function defineApp<A extends string = never>(def: SdkAppDefinition<A>): App {
  const manifest = def.manifest;
  let digest: `sha256:${string}`;
  let operations: OperationView[];
  try {
    digest = manifestDigest(manifest);
    operations = withStandardOps(manifest);
  } catch {
    throw new TbError("manifest_invalid", "manifest is not a manifest object", 500);
  }
  const app: App = Object.freeze({ manifest, digest, operations: Object.freeze(operations) });
  definitions.set(app, def as SdkAppDefinition<string>);
  return app;
}

/** Boot checks of the handler set against the manifest (SDK-API §3): exactly one handler per non-dynamic op, etc. */
function checkDefinition(def: AppDefinition<string> | SdkAppDefinition<string>, m: Manifest): string[] {
  const problems: string[] = [];
  const ops = new Map(m.operations.map((o) => [o.id, o]));
  for (const o of m.operations) {
    const h = def.handlers[o.id];
    if (o.dynamic) {
      if (h) problems.push(`handler for dynamic operation ${o.id} (use dynamic.${o.id})`);
      if (!def.dynamic?.[o.id]) problems.push(`missing dynamic handlers for ${o.id}`);
      continue;
    }
    if (!h) problems.push(`missing handler for operation ${o.id}`);
    else if (o.scopeType && (typeof h === "function" || typeof h.scope !== "function")) problems.push(`operation ${o.id} has scopeType ${o.scopeType} and needs a scope() function`);
    else if (typeof h !== "function" && typeof h.run !== "function") problems.push(`handler for ${o.id} has no run()`);
  }
  for (const id of Object.keys(def.handlers)) if (!ops.has(id)) problems.push(`extra handler ${id} (not a manifest operation)`);
  for (const id of Object.keys(def.dynamic ?? {})) if (!ops.get(id)?.dynamic) problems.push(`extra dynamic handlers ${id}`);
  const hooks = new Set((m.hooks ?? []).map((h) => h.id));
  for (const id of hooks) if (typeof def.hooks?.[id] !== "function") problems.push(`missing hook handler ${id}`);
  for (const id of Object.keys(def.hooks ?? {})) if (!hooks.has(id)) problems.push(`extra hook handler ${id}`);
  const routes = new Set((m.publicRoutes ?? []).map((r) => r.path));
  for (const p of routes) if (typeof def.publicRoutes?.[p] !== "function") problems.push(`missing public route handler ${p}`);
  for (const p of Object.keys(def.publicRoutes ?? {})) if (!routes.has(p)) problems.push(`extra public route handler ${p}`);
  if (typeof def.migrations !== "string" || def.migrations === "") problems.push("migrations directory is required");
  for (const a of def.auditActions ?? []) if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(a)) problems.push(`audit action ${a} must look like noun.verb`);
  // v0.1.21 (R1): job kinds
  const d = def as SdkAppDefinition<string>;
  for (const [kind, h] of Object.entries(d.jobs ?? {})) {
    if (!JOB_KIND_RE.test(kind) || kind.startsWith("tb.")) problems.push(`job kind ${kind} must match ${JOB_KIND_RE.source} and not start with tb.`);
    const run = typeof h === "function" ? h : h?.run;
    if (typeof run !== "function") problems.push(`job kind ${kind} has no handler`);
    if (typeof h === "object" && h) {
      if (h.maxAttempts !== undefined && (!Number.isInteger(h.maxAttempts) || h.maxAttempts < 1 || h.maxAttempts > 100)) problems.push(`job kind ${kind}: maxAttempts must be 1..100`);
      if (h.leaseMs !== undefined && (!Number.isInteger(h.leaseMs) || h.leaseMs < 1000 || h.leaseMs > 600_000)) problems.push(`job kind ${kind}: leaseMs must be 1000..600000`);
      if (h.timeoutMs !== undefined && (!Number.isInteger(h.timeoutMs) || h.timeoutMs < 1000 || h.timeoutMs > 86_400_000)) problems.push(`job kind ${kind}: timeoutMs must be 1000..86400000`);
    }
  }
  if (d.onStop !== undefined && typeof d.onStop !== "function") problems.push("onStop must be a function");
  return problems;
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

/**
 * v0.1.25: what startApp returns. `failure` is set (and `status()` is "failed") when the data phase failed: the process
 * then serves failed mode only, and every other member throws `app_failed`.
 */
export type StartedApp = RunningApp & { readonly port: number; readonly jobs: JobsApi; readonly failure?: BootFailure };

interface DataPhase {
  db: RawDb;
  migrated: AppliedMigration[];
  schema: SchemaVersion;
  codeSchema: SchemaVersion;
  minCompatibleCode: string | null;
  minCompatibleSdk: string | null;
  /** the pre-update snapshot written (or reused after a crash) by THIS boot */
  snapshot: PreUpdateSnapshot | null;
  lastPreUpdate: PreUpdateSnapshot | null;
  restore: RestoreOutcome | null;
}

class DataPhaseError extends Error {
  readonly failure: BootFailure;
  readonly schema: SchemaVersion | null;
  readonly codeSchema: SchemaVersion;
  readonly minCompatibleCode: string | null;
  readonly snapshot: PreUpdateSnapshot | null;
  constructor(failure: BootFailure, schema: SchemaVersion | null, codeSchema: SchemaVersion, minCompatibleCode: string | null, snapshot: PreUpdateSnapshot | null) {
    super(`boot failed in ${failure.phase}: ${failure.code}`);
    this.failure = failure;
    this.schema = schema;
    this.codeSchema = codeSchema;
    this.minCompatibleCode = minCompatibleCode;
    this.snapshot = snapshot;
  }
}

/**
 * The data phase (E2). Order: scan migrations → restore (TB_RESTORE_FROM) → open → refuse data newer than the code →
 * when anything is pending or the app version changed: take the migration lock, re-check (another instance may have
 * migrated meanwhile), write the pre-update snapshot (or reuse the one of an interrupted upgrade to the same version),
 * then SDK migrations and app migrations with a lock heartbeat after each, then ONE tb_meta write (L31) and release.
 * A fresh database (no migration applied yet) has nothing to snapshot.
 */
async function dataPhase(
  manifest: Manifest,
  def: SdkAppDefinition<string>,
  cfg: SdkConfig,
  env: Record<string, string | undefined>,
  log: ReturnType<typeof createLogger>,
  sealer: Sealer,
  harness: { clock?: Clock; migrationLock?: { leaseMs?: number; waitMs?: number; holder?: string }; freeBytes?: (dir: string) => Promise<number> } | undefined,
): Promise<DataPhase> {
  const clock = harness?.clock ?? realClock;
  let phase: BootPhase = "app_migrations";
  let db: RawDb | null = null;
  let lock: MigrationLock | null = null;
  let codeSchema: SchemaVersion = { app: 0, sdk: SDK_SCHEMA };
  let snapshot: PreUpdateSnapshot | null = null;
  const backupCtx = (rawDb: RawDb | null): BackupContext => ({
    manifest,
    dataDir: cfg.dataDir,
    backupDir: cfg.backupDir,
    instanceId: cfg.instanceId ?? "",
    sdkVersion: SDK_VERSION,
    log,
    hooks: def.backup,
    env,
    instanceKey: () => loadInstanceKey(cfg.dataDir, sealer),
    bridgeId: () => (rawDb ? (metaGet<{ bridge?: { id?: string } }>(rawDb, "claim")?.bridge?.id ?? null) : null) as never,
    codeSchema,
    now: clock.now,
  });
  try {
    const files = scanMigrations(def.migrations);
    codeSchema = { app: files.length, sdk: SDK_SCHEMA };
    phase = "restore";
    const restore = await restoreAtBoot(backupCtx(null), cfg.restoreFrom);
    if (restore && !restore.applied) log.info("restore skipped", { archive: restore.archive, reason: restore.skipped ?? "none" });
    phase = "open";
    db = openDb(cfg.dataDir);
    phase = "schema";
    const stored = storedSchema(db);
    let pendingSdk = pendingSdkMigrations(db);
    let pendingApp = pendingAppMigrations(db, files);
    const fresh = stored.app === 0 && stored.sdk === 0;
    const before = readUpgradeMeta(db);
    if (pendingSdk.length || pendingApp.length || (!fresh && before.appVersion !== manifest.version)) {
      phase = "lock";
      lock = new MigrationLock(db, { clock, ...(harness?.migrationLock ?? {}) });
      await lock.acquire();
      if (lock.takenOverFrom) log.warn("migration lock taken over from a stopped instance", { from: lock.takenOverFrom });
      // re-check under the lock: the instance we waited for may have done it all
      phase = "schema";
      pendingSdk = pendingSdkMigrations(db);
      pendingApp = pendingAppMigrations(db, files);
      const now = readUpgradeMeta(db);
      if (!fresh && (pendingSdk.length || pendingApp.length || now.appVersion !== manifest.version)) {
        phase = "snapshot";
        const reuse = now.upgrade && now.upgrade.to === manifest.version && existsSync(join(cfg.backupDir, now.upgrade.snapshot.file)) ? now.upgrade.snapshot : null;
        if (reuse) {
          // an upgrade to this version was interrupted (crash, kill): its snapshot holds the data from BEFORE it; keep it
          snapshot = reuse;
          log.warn("resuming an interrupted upgrade; keeping its pre-update snapshot", { file: reuse.file, from: reuse.from, to: reuse.to });
        } else {
          snapshot = await writePreUpdateSnapshot(backupCtx(db), db, { from: now.appVersion, to: manifest.version, schema: storedSchema(db), ...(harness?.freeBytes ? { freeBytes: harness.freeBytes } : {}) });
          metaSet(db, META.upgrade, { from: now.appVersion, to: manifest.version, snapshot, startedAt: clock.now() });
        }
        lock.heartbeat();
      }
    }
    phase = "sdk_migrations";
    const sdkDone = applySdkMigrations(db, () => lock?.heartbeat(), { manifest });
    phase = "app_migrations";
    const migrated = await applyAppMigrations(db, def.migrations, pendingAppMigrations(db, files), () => lock?.heartbeat());
    const schema = storedSchema(db);
    const prev = readUpgradeMeta(db);
    const min = recordBoot(db, {
      version: manifest.version,
      sdkVersion: SDK_VERSION,
      schema,
      appMigrated: migrated.length > 0,
      sdkMigrated: sdkDone.length > 0,
      prev: { minCompatibleCode: prev.minCompatibleCode, minCompatibleSdk: prev.minCompatibleSdk },
      snapshot,
    });
    lock?.release();
    return { db, migrated, schema, codeSchema, ...min, snapshot, lastPreUpdate: prev.lastPreUpdate, restore };
  } catch (e) {
    const failure = bootFailure(phase, e, clock.now());
    log.error("boot data phase failed", { phase, code: failure.code, ...(failure.file ? { file: failure.file } : {}), error: e instanceof Error ? e.message : "unknown" });
    let schema: SchemaVersion | null = null;
    let minCompatibleCode: string | null = null;
    try {
      if (db) {
        schema = storedSchema(db);
        minCompatibleCode = readUpgradeMeta(db).minCompatibleCode;
      }
    } catch {
      // unreadable database: health says so with schemaVersion null
    }
    lock?.release();
    try {
      db?.close();
    } catch {
      // already closed
    }
    throw new DataPhaseError(failure, schema, codeSchema, minCompatibleCode, snapshot);
  }
}

/** The RunningApp of a failed boot: status "failed", the failure, stop(); everything else throws `app_failed`. */
function failedApp(f: { port: number; stop(): Promise<void> }, failure: BootFailure): StartedApp {
  const unavailable = (): never => {
    throw new TbError("app_failed", `the app failed to boot (${failure.code})`, 503);
  };
  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    stopped ??= (async () => {
      process.off("SIGTERM", onSignal);
      process.off("SIGINT", onSignal);
      await f.stop();
    })();
    return stopped;
  };
  const onSignal = () => void stop();
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
  const out = { port: f.port, failure, status: () => "failed" as const, stop };
  for (const k of ["receipts", "scopes", "keys", "audit", "backups", "jobs"]) Object.defineProperty(out, k, { get: unavailable, enumerable: false });
  return out as unknown as StartedApp;
}

/** Reads only the TB_* names of `env`; refuses to boot on an invalid manifest, handler set or migration set. */
/**
 * `harness` is for test harnesses only, never read from env and never set by Portal: `privilegeProc` (not part of
 * types/sdk.ts) replaces the real process facade of the privilege drop so a root test runner is not dropped to uid 1000
 * by an app it starts in-process; `portalRootKeys` (types/sdk.ts v0.1.11 `StartHooks`, C63) replaces the build-pinned
 * Portal Root Keys so a conformance start module can sign key-set statements with a test root pair; `mountinfoPath`
 * (v0.1.12) replaces /proc/self/mountinfo for the first-claim mount check of TB_DATA_DIR; `port` (v0.1.21, conformance
 * 0.1.13) replaces manifest `runtime.port` (0 = any free port) so two harness runs on one machine never clash; the chosen
 * port is `RunningApp.port`. Production never passes it.
 */
export async function startApp(
  app: App,
  env: Record<string, string | undefined>,
  harness?: {
    privilegeProc?: PrivilegeProc;
    portalRootKeys?: Ed25519PublicJwk[];
    mountinfoPath?: string;
    port?: number;
    /** v0.1.21: job runner pacing for tests (poll, drain) */
    jobs?: Partial<{ pollMs: number; concurrency: number; drainMs: number }>;
    /** v0.1.25 (E2): injected clock for the migration lock (lease, wait) and snapshot times */
    clock?: Clock;
    /** v0.1.25 (E2): migration lock lease / wait / holder id (tests: double instance, crashed holder) */
    migrationLock?: { leaseMs?: number; waitMs?: number; holder?: string };
    /** v0.1.25 (E2): free bytes on the backup volume (tests: the no-space guard) */
    freeBytes?: (dir: string) => Promise<number>;
  },
): Promise<StartedApp> {
  const def = definitions.get(app);
  if (!def) throw new TbError("app_invalid", "startApp needs the value returned by defineApp", 500);
  const v = validateManifest(def.manifest);
  if (!v.ok) throw new TbError("manifest_invalid", "manifest does not validate", 500, { errors: v.errors });
  const manifest = v.manifest;
  if (manifest.sdkMajor !== SDK_MAJOR) throw new TbError("sdk_major_unsupported", `manifest sdkMajor ${manifest.sdkMajor} differs from SDK major ${SDK_MAJOR}`, 500);
  const problems = checkDefinition(def as AppDefinition<string>, manifest);
  if (problems.length) throw new TbError("handlers_invalid", problems.join("; "), 500, { problems });

  const cfg = readEnv(env);
  const secrets = new SecretRegistry();
  const log = createLogger(cfg.logLevel, secrets, { product: manifest.id });
  for (const name of cfg.unknown) log.warn("env_unknown", { name });
  if (!cfg.standalone && (!cfg.instanceId || !cfg.bridgeUrl || !cfg.portalKeys))
    throw new TbError("env_invalid", "TB_INSTANCE_ID, TB_BRIDGE_URL and TB_PORTAL_KEYS are required unless TB_STANDALONE=1", 500);

  // C53 / BSA-05: started as root → hand the volumes to uid 1000 and drop before any file, key or listener opens.
  if (dropPrivileges(cfg, harness?.privilegeProc)) log.info("privileges_dropped", { uid: 1000 });
  // v0.1.12 (spine S1): one line with the TB_DATA_DIR mount state; the claim path gates the first claim on it
  logMountAtBoot(cfg.dataDir, { ephemeral: cfg.dataEphemeral, ...(harness?.mountinfoPath ? { mountinfoPath: harness.mountinfoPath } : {}), log });

  const sealer = createSealer(resolveKeks(cfg.dataDir, cfg.kek, cfg.kekPrevious));
  // v0.1.25 (E2, UPGRADE-SAFETY M1–M3): restore → schema check → lock → pre-update snapshot → migrations. Any failure
  // here → failed mode (health + status push with the reason), never an exit and a crash loop (M2, L3).
  let data: DataPhase;
  try {
    data = await dataPhase(manifest, def, cfg, env, log, sealer, harness);
  } catch (e) {
    if (!(e instanceof DataPhaseError)) throw e;
    const failed = await startFailedMode({
      manifest,
      digest: v.digest,
      sdkVersion: SDK_VERSION,
      cfg,
      log,
      sealer,
      failure: e.failure,
      schemaVersion: e.schema,
      codeSchema: e.codeSchema,
      minCompatibleCode: e.minCompatibleCode,
      preUpdateSnapshot: e.snapshot,
      port: harness?.port ?? manifest.runtime.port,
    });
    return failedApp(failed, e.failure);
  }
  const db = data.db;
  const closeOnFail = <T>(fn: () => T): T => {
    try {
      return fn();
    } catch (e) {
      db.close();
      throw e;
    }
  };
  const migrated = data.migrated;
  const audit = createAuditLog(db, def.auditActions ?? []);
  if (data.snapshot) await audit.record({ actor: "system", action: "backup.create", target: data.snapshot.file, detail: { kind: "preupdate", from: data.snapshot.from, to: data.snapshot.to } });
  for (const m of migrated) await audit.record({ actor: "system", action: "migration.apply", target: `${String(m.version).padStart(4, "0")}_${m.name}`, detail: null });

  // reseal app-own keys after a KEK rotation (CREDENTIALS §9.1)
  closeOnFail(() => {
    for (const r of db.prepare("SELECT name, sealed FROM tb_keys").all() as Row[]) {
      if (!sealer.stale(String(r.sealed))) continue;
      const value = sealer.unsealText("app-key", String(r.name), String(r.sealed));
      db.prepare("UPDATE tb_keys SET sealed = ? WHERE name = ?").run(sealer.sealText("app-key", String(r.name), value), String(r.name));
    }
  });

  // identity: TB_INSTANCE_ID, or (app-alone) an ins_/ws_ pair generated at first boot
  let instanceId: InstanceId;
  let aloneWs: WorkspaceId | null = null;
  if (cfg.standalone) {
    const id = metaGet<{ ins: InstanceId; ws: WorkspaceId }>(db, "standalone_identity") ?? { ins: `ins_${ulid()}` as InstanceId, ws: `ws_${ulid()}` as WorkspaceId };
    metaSet(db, "standalone_identity", id);
    instanceId = id.ins;
    aloneWs = id.ws;
  } else instanceId = cfg.instanceId as InstanceId;
  const instanceKey = await loadInstanceKey(cfg.dataDir, sealer);
  const trust = new TrustState(db, instanceId, {
    bootstrap: cfg.portalKeys ? keySetFrom(cfg.portalKeys, "tb:portal") : null,
    ...(aloneWs ? { alone: { ws: aloneWs, ownKey: instanceKey.publicJwk } } : {}),
    ...(harness?.portalRootKeys ? { roots: harness.portalRootKeys } : {}),
  });

  const ops = new Map(withStandardOps(manifest).map((o) => [o.id, o]));
  const state: Runtime["state"] = { claimed: false, failed: false, restoring: false, stopping: false, attention: null };
  let link: BridgeLink | null = null;
  const bridge = cfg.standalone || !cfg.bridgeUrl ? null : new BridgeClient({ baseUrl: cfg.bridgeUrl, instanceId, key: instanceKey, bridgeId: () => trust.bridgeId });
  const receipts = new Receipts(db);
  // v0.1.22 (SDK-01): keys reserved by a process that stopped mid-run have an unknown outcome — never run them again
  const crashedKeys = receipts.idemRecoverCrashed(Date.now());
  if (crashedKeys > 0) log.warn("idempotency keys of an interrupted run marked unknown_outcome", { count: crashedKeys });
  const kick = () => link?.kick();
  // v0.1.13 (C86): statusChanged() pacing (≤ 1 push/s) and pendingHolds = held receipts + the app's pendingCount()
  const pusher = new StatusPusher(kick);
  const counter = new PendingCounter(def.pendingCount, appDb(db), log);
  // v0.1.20 (spec 0.1.28, F89): app-reported attention rides the status push (readiness degraded while present)
  const attentionReader = new AttentionReader(def.attention, appDb(db), log);
  // v0.1.38 (C274c/C274d, SDK-API §20): THE event outbox; scope-row narrowing and hold decisions write into it in their own transaction
  const events = new EventOutbox(db, manifest, log);
  receipts.onHoldDecided((hold, decision) => events.holdDecided(hold, decision));
  const scopes = createScopeStore(db, manifest, audit, kick, (agent, type, instanceId) => events.rowNarrowed(agent, type, instanceId));
  const appHandle = appDb(db);
  const appSecrets = createAppSecrets(db, sealer, secrets);
  closeOnFail(() => appSecrets.reseal());
  // v0.1.13 (C85/C86): callApp without parentCall (app-initiated), statusChanged and ownerLink outside op handlers
  const appCallApp: StartContext["callApp"] = (product, op, input, opts) => {
    if (!link) return Promise.reject(new TbError("no_bridge", "companion calls need the bridge", 503));
    return link.call(product, op, input, callAppOpts(opts, null));
  };
  // v0.1.42 (spec 0.1.82, C373 P1, SDK-API §22): `ctx.workflowGrants` on every ctx; the link owns the cache (memory only)
  const workflowGrants: WorkflowGrantsApi = {
    request: (body) => (link ? link.workflowGrants.api().request(body) : workflowGrantsWithoutBridge({ trust }).request(body)),
    status: (wfl) => (link ? link.workflowGrants.api().status(wfl) : workflowGrantsWithoutBridge({ trust }).status(wfl)),
    release: (wfl) => (link ? link.workflowGrants.api().release(wfl) : workflowGrantsWithoutBridge({ trust }).release(wfl)),
  };
  /** v0.1.13 (C86) ownerLink / v0.1.20 ownerLinkFor: ONE builder; the path passes the shared launch-path rule (L1). */
  const ownerLinkFor = (product: string, path: string): string | null => {
    if (typeof product !== "string" || !/^[a-z][a-z0-9-]{1,31}$/.test(product)) throw new TbError("product_invalid", "not a product id", 400);
    if (typeof path !== "string" || !isValidLaunchPath(path)) throw new TbError("path_invalid", "owner link path must be an app-relative launch path", 400);
    const portal = trust.portalUrl;
    const ws = trust.ws;
    if (!portal || !ws) return null;
    return `${portal}/w/${ws}/open?product=${encodeURIComponent(product)}&path=${encodeURIComponent(path)}`;
  };
  const ownerLink = (path: string): string | null => ownerLinkFor(manifest.id, path);
  const companionTargets = (): string[] => [...new Set(trust.companionTargets().map((t) => t.product))].sort();
  const statusChanged = (): void => pusher.request();
  const appsPolicy = (): readonly string[] | null => trust.appsPolicy();
  // v0.1.37 (C292): read from the CURRENT slice at every call (never a snapshot); advisory, no authorization reads it
  const bridgeCaps = (): readonly string[] => trust.bridgeCaps(Date.now());
  const agentScopeRequest = (agt: string): ScopeRequest | null => trust.agentScopeRequest(agt, manifest.id);
  // v0.1.21: the job runner exists from right after `rt` below; event contexts are only built after that
  let runner: JobRunner | null = null;
  const jobRunner = (): JobRunner => {
    if (!runner) throw new TbError("app_not_running", "the job runner is not ready", 500);
    return runner;
  };
  const eventContext = (): SdkEventContext => ({
    db: appHandle,
    log,
    scopes,
    callApp: appCallApp,
    workflowGrants,
    statusChanged,
    ownerLink,
    companionTargets,
    appsPolicy,
    bridgeCaps,
    // v0.1.38 (C274c): event, start and job-handler contexts emit too; no call, so no `causedBy`
    emit: events.emitFn(),
    purgeEvents: events.purgeFn(),
    agentScopeRequest,
    ownerLinkFor,
    ...jobsView(rt, jobRunner(), null),
  });
  /** Fleet: last agent list handed to events.agentsChanged in this process (null = none yet since boot) */
  let notifiedAgents: string | null = null;
  const keys = createKeys({
    db,
    manifest,
    env,
    sealer,
    secrets,
    audit,
    log,
    bridge: () => (state.claimed ? bridge : null),
    rolesChanged: () => statusChanged(),
    paused: () => {
      const p = trust.paused(null);
      return p.workspace || p.instance;
    },
    emit: async (names) => {
      try {
        await def.events?.keysChanged?.(names, eventContext());
      } catch (e) {
        log.warn("keysChanged failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    },
  });
  const person = createPersonAuth({ db, product: manifest.id, launchPath: manifest.ui?.launchPath ?? "/", trust, audit, log, instanceKey, standalone: cfg.standalone,
    idempotencyRequired: manifest.operations.filter((o) => o.audience === "person" && o.idempotency === "required").map((o) => o.id),
  });
  const backup = createBackupApi({
    manifest,
    dataDir: cfg.dataDir,
    backupDir: cfg.backupDir,
    instanceId,
    sdkVersion: SDK_VERSION,
    log,
    hooks: def.backup,
    env,
    instanceKey: async () => instanceKey,
    bridgeId: () => trust.bridgeId,
    db,
    audit,
    // v0.1.22 (SDK-03): a backup outcome changes attention / health → push the status
    onStateChange: statusChanged,
  });
  const helper = createServiceHelperCaller({ manifest, env, instanceId, instanceKey, bridgeId: () => trust.bridgeId });
  let onStartRan = false;

  const rt: Runtime = {
    def,
    manifest,
    product: manifest.id,
    digest: v.digest,
    ops,
    sdkVersion: SDK_VERSION,
    cfg,
    env,
    db,
    appDb: appHandle,
    log,
    secrets,
    sealer,
    instanceId,
    instanceKey,
    trust,
    receipts,
    scopes,
    keys,
    audit,
    person,
    secretsStore: appSecrets,
    backups: backup.api,
    bridge,
    events,
    get jobs() {
      return jobRunner();
    },
    noteGrant(callerId, token, iat) {
      try {
        const store = jobRunner().store;
        if (!store.hasPendingOps(callerId, iat)) return;
        // v0.1.42 (spec 0.1.82, C373 P1): a newer grant replaces only stored grants of the SAME workflow identity (`wfl`, or none): a
        // workflow grant never widens a base-grant op or another workflow's op, and a base grant never replaces a workflow grant
        const wfl = workflowOfGrant(token);
        const ids = store
          .pendingOpGrants(callerId, iat)
          .filter((r) => (r.sealed === null ? undefined : workflowOfGrant(unsealGrant(rt, callerId, r.sealed))) === wfl)
          .map((r) => r.id);
        if (ids.length) store.refreshGrantRows(ids, sealGrant(rt, callerId, token), iat);
      } catch (e) {
        log.warn("job grant refresh failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    },
    replay: memoryReplayGuard(),
    state,
    upgrade: {
      schemaVersion: data.schema,
      codeSchema: data.codeSchema,
      minCompatibleCode: data.minCompatibleCode,
      minCompatibleSdk: data.minCompatibleSdk,
      preUpdateSnapshot: data.snapshot ?? data.lastPreUpdate,
      lastRestore: data.restore,
    },
    mountinfoPath: harness?.mountinfoPath,
    health(): HealthStatus {
      if (state.failed) return "failed";
      if (state.restoring) return "restoring";
      if (!cfg.standalone) {
        // data_dir_not_mounted (no claim yet) and identity_refused (claim refused) both need a (new) claim
        if (!state.claimed || state.attention) return "needs_claim";
        if (trust.stale(Date.now())) return "slice_stale";
      }
      // v0.1.63: a required model role that does not resolve is `needs_keys` too (attention `model_role_missing`, see `attention`)
      return keys.needsKeys() || keys.rolesMissing().length > 0 ? "needs_keys" : "ok";
    },
    extras() {
      const slice = trust.slice;
      return {
        publicUrl: (slice?.bridge as { publicUrl?: unknown } | undefined)?.publicUrl?.toString() ?? null,
        // v0.1.26 (LA-1): tb-views origin; only a non-empty string counts, anything else (absent, null) is null
        viewUrl: typeof slice?.bridge.viewUrl === "string" && slice.bridge.viewUrl !== "" ? slice.bridge.viewUrl : null,
        workspace: (() => {
          // spec 0.1.3 (C31): non-null; before the first verified slice there is no workspace to give
          if (!trust.ws) throw new TbError("workspace_unknown", "the workspace is not known yet (no verified slice)", 503);
          return trust.ws;
        })(),
        scopes: { instances: scopes.instances },
        secrets: appSecrets,
      };
    },
    kickStatus: kick,
    statusChanged,
    async pendingHolds() {
      return receipts.pendingCount() + (await counter.count());
    },
    // v0.1.21: failed / stuck jobs raise attention when the app reports none (L3); v0.1.22 (SDK-03): a failed, overdue
    // or unparsable scheduled backup comes before them
    // v0.1.38 (admin queue c/5b): by severity, not first-non-null: a failed or overdue backup is never hidden by an app attention
    // v0.1.63: `model_role_missing` is the reason for needs_keys, so it comes before the app's own attention
    attention: async () => pickAttention({ backup: backup.attention(), events: events.attention(), roles: keys.rolesAttention(), app: await attentionReader.read(), jobs: jobRunner().attention() }),
    backupHealth: () => backup.health(),
    ownerLink,
    ownerLinkFor,
    companionTargets,
    appsPolicy,
    bridgeCaps,
    agentScopeRequest,
    eventContext,
    async notifyAgents() {
      const agents = trust.slice?.agents;
      if (!agents) return;
      // ids, names, mode, status (Fleet); order-insensitive
      const key = JSON.stringify(agents.map((a) => [a.id, a.name, a.mode, a.status]).sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0)));
      if (key === notifiedAgents) return;
      notifiedAgents = key;
      try {
        await def.events?.agentsChanged?.(agents.map((a) => ({ ...a })), eventContext());
      } catch (e) {
        log.warn("agentsChanged failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    },
    onClaimed() {
      if (onStartRan || !def.onStart) return;
      onStartRan = true;
      const ctx: StartContext = { ...eventContext(), secrets: appSecrets, getKey: (n) => keys.getKey(n), modelRole: (r) => keys.modelRole(r), callServiceHelper: helper };
      def.onStart(ctx).catch((e) => log.error("onStart failed", { error: e instanceof Error ? e.message : "unknown" }));
    },
    async refreshSlice() {
      await link?.refreshNow();
    },
    async ensureAgent(agent: SliceAgent) {
      const seen = db.prepare("SELECT in_slice FROM tb_agents WHERE agent = ?").get(agent.id) as Row | undefined;
      const inSlice = trust.agent(agent.id) ? 1 : 0;
      if (seen) {
        if (Number(seen.in_slice) !== inSlice) db.prepare("UPDATE tb_agents SET in_slice = ?, name = ? WHERE agent = ?").run(inSlice, agent.name, agent.id);
        return;
      }
      db.prepare("INSERT OR IGNORE INTO tb_agents (agent, name, first_seen, in_slice) VALUES (?, ?, ?, ?)").run(agent.id, agent.name, Date.now(), inSlice);
      try {
        await def.events?.agentAdded?.(agent, eventContext());
      } catch (e) {
        log.warn("agentAdded failed", { agent: agent.id, error: e instanceof Error ? e.message : "unknown" });
      }
      await scopes.applyDefaults(agent);
    },
    async callApp(product, op, input, opts) {
      if (!link) throw new TbError("no_bridge", "companion calls need the bridge", 503);
      return link.call(product, op, input, opts);
    },
    workflowGrants,
    callServiceHelper: helper,
  };

  runner = new JobRunner(rt, def.jobs, fireScheduledOp, harness?.jobs ?? {});
  closeOnFail(() => runner?.store.reseal(sealer));

  // claim record → bridge known; slice from the DB is already installed in TrustState
  if (!cfg.standalone && bridge) {
    const record = BridgeLink.record(rt);
    if (record) {
      if (record.ins !== instanceId) {
        db.close();
        throw new TbError("instance_mismatch", "stored claim names another instance than TB_INSTANCE_ID", 500);
      }
      trust.setBridge(record.bridge.id);
      state.claimed = true;
    }
    link = new BridgeLink(rt, bridge);
  } else person.standaloneBoot(cfg.standaloneReset);

  const server = createHttpServer(rt);
  const wantPort = harness?.port ?? manifest.runtime.port;
  try {
    await listen(server, wantPort);
  } catch (e) {
    db.close();
    throw new TbError("listen_failed", `cannot listen on port ${wantPort}: ${e instanceof Error ? e.message : "error"}`, 500);
  }
  const addr = server.address();
  const port = addr && typeof addr === "object" ? addr.port : wantPort;
  if (cfg.standalone || state.claimed) rt.onClaimed();
  // Fleet: the stored slice is the first slice after boot (a bridge answers a long-poll with 204 while it is current)
  if (trust.slice) void rt.notifyAgents();
  link?.start();
  // v0.1.38 (C274c): the outbox sender; it sends only while the slice says the bridge has the `events` cap (app-alone mode never sends,
  // its loop only prunes rows older than 7 days)
  events.start({ bridge: () => (link && state.claimed ? bridge : null), bridgeCaps, rowsOn: (type, instanceId) => scopes.rowsOn(type, instanceId), inSlice: (agent) => !trust.stale(Date.now()) && trust.agent(agent) !== undefined });
  runner.start();
  const sweep = setInterval(() => {
    try {
      const now = Date.now();
      if (receipts.sweep(now).expired > 0) statusChanged(); // v0.1.13: a hold expired
      person.sweep(now);
      runner?.store.sweep(now);
    } catch (e) {
      log.warn("sweep failed", { error: e instanceof Error ? e.message : "unknown" });
    }
  }, SWEEP_MS);
  sweep.unref();

  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    stopped ??= (async () => {
      state.stopping = true;
      process.off("SIGTERM", onSignal);
      process.off("SIGINT", onSignal);
      // v0.1.21 (RUL-11, L21): no new job starts; the app's onStop stops its own timers; running jobs drain (handler
      // ticks are given back and resume at the next start, in-flight scheduled ops end as unknown_outcome)
      runner?.halt();
      if (def.onStop) {
        let t: NodeJS.Timeout | undefined;
        try {
          await Promise.race([
            def.onStop({ ...eventContext(), secrets: appSecrets }),
            new Promise<void>((_, reject) => {
              t = setTimeout(() => reject(new Error("timeout")), RUNNER_DEFAULTS.onStopMs);
              t.unref();
            }),
          ]);
        } catch (e) {
          log.warn("onStop failed", { error: e instanceof Error ? e.message : "unknown" });
        } finally {
          if (t) clearTimeout(t);
        }
      }
      await runner?.stop();
      clearInterval(sweep);
      pusher.stop();
      backup.stop();
      await link?.stop();
      await events.stop();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeIdleConnections();
        setTimeout(() => server.closeAllConnections(), 10_000).unref();
      });
      if (current === rt) current = null;
      db.close();
    })();
    return stopped;
  };
  const onSignal = () => {
    void stop();
  };
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
  current = rt;
  log.info("app started", { port, instance: instanceId, standalone: cfg.standalone, status: rt.health() });

  return {
    port,
    status: () => rt.health(),
    receipts,
    scopes,
    keys,
    audit,
    backups: backup.api,
    // v0.1.21: the app-initiated jobs API (main modules, tests)
    jobs: jobsView(rt, runner, null).jobs,
    stop,
  };
}

function running(): Runtime {
  if (!current) throw new TbError("app_not_running", "no app is running (call startApp first)", 500);
  return current;
}

/** Person only (tb.holds_decide, SDK-API §4.5). */
export function decideHold(principal: PersonPrincipal, input: HoldDecideInput): Promise<Receipt> {
  return decide(running(), principal, input);
}

/** App-own value > workspace default (SDK-API §8). */
export function getKey(name: string): Promise<string | null> {
  return running().keys.getKey(name);
}

/** v0.1.63 (SDK-API "v0.1.63 additions"): the binding of a model role the manifest declares for `app`; null = unset or below `minPolicy`. */
export function modelRole(role: ModelRole): Promise<ResolvedModelRole | null> {
  return running().keys.modelRole(role);
}

export function onKeysChanged(cb: (names: string[]) => void): () => void {
  return running().keys.onKeysChanged(cb);
}

