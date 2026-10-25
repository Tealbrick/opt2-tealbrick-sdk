// tb-exec orchestration (SDK-API §11, C2, C6, C33): claim as service → fetch declared keys (and, v0.1.63, the model roles that
// list this service with `env`) → start helper, helper proxy, control port and the upstream child → status long-poll
// (BRIDGE §10.3) → restart the child when key or role values change → exit with the child's code.
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { conditionHolds, type ModelRole, settingsFromEnv } from "@opt2-tealbrick/manifest";
import type { AppStatus } from "@opt2-tealbrick/spec/bridge";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { identityRefused, logMountAtBoot, reclaimCode } from "../server/claim-guard.ts";
import { TbError } from "../server/errors.ts";
import { createLogger, type LogSink, SecretRegistry } from "../server/log.ts";
import { dropPrivileges, type PrivilegeProc } from "../server/privilege.ts";
import { TB_EXEC_CONTROL_PORT } from "../server/service-helper.ts";
import { parseArgs } from "./args.ts";
import { ServiceBridge } from "./bridge.ts";
import { HelperProcess, Upstream } from "./child.ts";
import { childEnv, type ExecConfig, loadExecConfig, SDK_VERSION } from "./config.ts";
import { type ClaimRecord, claimOrLoad, claimWith, loadServiceKey, retryable } from "./identity.ts";
import { carriedSettings, type ExecRole, fetchRoles, rolesInForce } from "./roles.ts";
import { startControlServer, startHelperProxy } from "./servers.ts";
import { signalExitCode, sleep } from "./util.ts";
import { appAssertionVerifier } from "./verify.ts";

export const STOP_SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT", "SIGQUIT"];
export const FORWARDED_SIGNALS: readonly NodeJS.Signals[] = [...STOP_SIGNALS, "SIGHUP", "SIGUSR1", "SIGUSR2"];

export interface TbExecOptions {
  /** tests only: injected process facade for the privilege drop (default: the real process) */
  privilegeProc?: PrivilegeProc;
  argv: readonly string[];
  env: Record<string, string | undefined>;
  /** listen address of the helper proxy and control port (default all interfaces of the private network) */
  host?: string;
  /** default 7077; tests override */
  controlPort?: number;
  logSink?: LogSink;
  /** tests only: mountinfo file for the first-claim mount check of TB_DATA_DIR (default /proc/self/mountinfo) */
  mountinfoPath?: string;
}

export interface TbExecHandle {
  /** tb-exec's exit code: the child's code, 128 + n when stopped by a signal before start, 2 usage, 1 failure */
  exited: Promise<number>;
  signal(sig: NodeJS.Signals): void;
}

interface FetchedKeys {
  /** env name → value (memory only): keys, then model role env (M-MR-4: the names never collide) */
  values: Map<string, string>;
  missing: string[];
  /** v0.1.63: model roles that did not resolve, and the required ones among them (the upstream waits for those) */
  missingRoles: ModelRole[];
  blockingRoles: ModelRole[];
  rev: number;
  /** digest of the values, to restart only on a real change */
  fingerprint: string;
}

/** C54: tb-exec drops privileges for a companion service only when `runtime.services[].dropPrivileges === true`. */
export function shouldDropForService(service: { dropPrivileges?: boolean }): boolean {
  return service.dropPrivileges === true;
}

/**
 * The bridge's `serviceKeys` list is authoritative, but a key whose manifest `when` is false for the settings this
 * service can see is dropped (ONE evaluation: manifest `conditionHolds` / `settingsFromEnv`). Only settings carried in
 * this service's env are judged; a key whose condition references a setting the env does not carry is kept.
 */
export function keysInForce(
  manifest: Manifest,
  serviceId: string,
  listed: { name: string; env: string }[],
  env: Record<string, string | undefined>,
  log?: Logger,
): { name: string; env: string }[] {
  const carried = carriedSettings(manifest, env);
  const settings = settingsFromEnv(manifest, env);
  const reqs = new Map((manifest.settings?.keys ?? []).filter((k) => k.usedBy.includes(serviceId)).map((k) => [k.name, k]));
  return listed.filter((k) => {
    const req = reqs.get(k.name);
    if (!req?.when) return true;
    if (!Object.keys(req.when).every((s) => carried.has(s))) return true;
    const ok = conditionHolds(req.when, settings);
    if (!ok) log?.info("key not in force", { key: k.name });
    return ok;
  });
}

async function fetchKeys(rec: ClaimRecord, roles: readonly ExecRole[], bridge: ServiceBridge, secrets: SecretRegistry, log: Logger, signal: AbortSignal): Promise<FetchedKeys> {
  const values = new Map<string, string>();
  const missing: string[] = [];
  let rev = 0;
  const fp = createHash("sha256");
  for (const k of rec.serviceKeys) {
    let delay = 1000;
    for (;;) {
      try {
        const r = await bridge.fetchKey(k.name, signal);
        if (r) {
          secrets.add(r.value);
          values.set(k.env, r.value);
          rev = Math.max(rev, r.keysRev);
          fp.update(`${k.env}\0${createHash("sha256").update(r.value, "utf8").digest("hex")}\0`);
        } else missing.push(k.name);
        break;
      } catch (e) {
        if (signal.aborted) throw e;
        if (!retryable(e)) {
          log.warn("key not delivered", { key: k.name, code: e instanceof TbError ? e.code : "key_fetch_failed" });
          missing.push(k.name);
          break;
        }
        await sleep(delay, signal);
        delay = Math.min(delay * 2, 30_000);
      }
    }
  }
  const fromRoles = await fetchRoles(roles, bridge, secrets, log, signal);
  for (const [name, v] of fromRoles.values) values.set(name, v);
  for (const part of fromRoles.parts) fp.update(part);
  return { values, missing, missingRoles: fromRoles.missing, blockingRoles: fromRoles.blocking, rev: Math.max(rev, fromRoles.rev), fingerprint: fp.digest("hex") };
}

async function closeAll(servers: Server[]): Promise<void> {
  await Promise.all(
    servers.map(
      (s) =>
        new Promise<void>((r) => {
          s.close(() => r());
          s.closeAllConnections();
        }),
    ),
  );
}

function checkHelperFlags(cfg: ExecConfig, helperCmd: string | null): void {
  if (cfg.service.helper && helperCmd === null) throw new TbError("helper_flags_required", "the service declares a helper: pass --helper-cmd and --helper-target", 500);
  if (!cfg.service.helper && helperCmd !== null) throw new TbError("helper_undeclared", "--helper-cmd given but the service declares no helper", 500);
}

export function startTbExec(o: TbExecOptions): TbExecHandle {
  const secrets = new SecretRegistry();
  let log = createLogger("info", secrets, { component: "tb-exec" }, o.logSink);
  const startup = new AbortController();
  let stopSignal: NodeJS.Signals | null = null;
  let upstream: Upstream | null = null;
  let helper: HelperProcess | null = null;

  async function main(): Promise<number> {
    const args = parseArgs(o.argv);
    const cfg = loadExecConfig(o.env, args.manifestPath);
    log = createLogger(cfg.env.logLevel, secrets, { component: "tb-exec", svc: cfg.service.id }, o.logSink);
    for (const name of cfg.env.unknown) log.warn("env_unknown", { name });
    checkHelperFlags(cfg, args.helperCmd);
    // C53 / BSA-05: started as root → hand the volumes to uid 1000 and drop before the key, any listener or the
    // children (the upstream and helper inherit uid/gid 1000).
    // C54: companions drop only when the manifest opts in (upstream images such as Postgres switch users themselves).
    if (shouldDropForService(cfg.service) && dropPrivileges(cfg.env, o.privilegeProc)) log.info("privileges_dropped", { uid: 1000 });
    // v0.1.12 (spine S1): one line with the TB_DATA_DIR mount state; the first claim waits for a mounted volume
    const gate = o.mountinfoPath ? { mountinfoPath: o.mountinfoPath } : {};
    logMountAtBoot(cfg.env.dataDir, { ephemeral: cfg.env.dataEphemeral, ...gate, log });
    const key = await loadServiceKey(cfg);
    const bridge = new ServiceBridge({ baseUrl: cfg.bridgeUrl, instanceId: cfg.instanceId, service: cfg.service.id, key });
    const inForce = (c: ClaimRecord): ClaimRecord => ({ ...c, serviceKeys: keysInForce(cfg.manifest, cfg.service.id, c.serviceKeys, o.env, log) });
    let rec = inForce(await claimOrLoad(cfg, key, bridge, log, startup.signal, gate));
    // v0.1.63: the model roles this service is listed for with `env` (resolved with the service key, like keys)
    const roles = rolesInForce(cfg.manifest, cfg.service.id, o.env);
    // a role-bound service never inherits proxy variables: a proxy would resolve the name itself and skip the endpoint check
    const envOpts = { stripProxy: roles.length > 0 };
    let keys = await fetchKeys(rec, roles, bridge, secrets, log, startup.signal);
    // Required keys block the upstream (Knowledge S2): it waits in needs_keys and keys are re-pulled with backoff.
    const required = new Set((cfg.manifest.settings?.keys ?? []).filter((k) => k.required && k.usedBy.includes(cfg.service.id)).map((k) => k.name));
    const blocking = (k: FetchedKeys): string[] => [...k.missing.filter((n) => required.has(n)), ...k.blockingRoles.map((r) => `role:${r}`)];
    if (keys.missing.length > 0 || keys.blockingRoles.length > 0) log.warn("needs_keys", { missing: keys.missing, missingRoles: keys.missingRoles, blocking: blocking(keys) });
    if (startup.signal.aborted) throw new TbError("stopped", "stopped before start", 500);

    // the app key accepted on the control / helper ports follows the claim record (a reclaim may bring a new one)
    let appVerify = appAssertionVerifier(rec);
    const verify: typeof appVerify = (req, body) => appVerify(req, body);
    const host = o.host ?? "0.0.0.0";
    const servers: Server[] = [];
    const up = new Upstream(args.command, log);
    upstream = up;
    try {
      if (cfg.service.helper && args.helperTarget && args.helperCmd) {
        helper = new HelperProcess(args.helperCmd, childEnv(o.env, new Map(), envOpts), log);
        helper.start();
        servers.push(await startHelperProxy({ port: cfg.service.helper.port, host, paths: cfg.service.helper.paths, target: args.helperTarget, verify, log }));
      }
      if (cfg.service.backup) servers.push(await startControlServer({ port: o.controlPort ?? TB_EXEC_CONTROL_PORT, host, backup: cfg.service.backup, verify, env: () => childEnv(o.env, keys.values, envOpts), log }));
    } catch (e) {
      await helper?.stop();
      await closeAll(servers);
      throw e;
    }
    if (stopSignal) {
      await helper?.stop();
      await closeAll(servers);
      return signalExitCode(stopSignal);
    }
    if (blocking(keys).length === 0) up.start(childEnv(o.env, keys.values, envOpts));
    else log.warn("upstream waits for required keys", { missing: blocking(keys) });

    /** start the waiting upstream once no required key is missing; restart a running one when values changed */
    const applyKeys = async (changed: boolean): Promise<void> => {
      if (up.stopping) return;
      if (!up.started) {
        if (blocking(keys).length === 0) {
          log.info("required keys present; starting upstream");
          up.start(childEnv(o.env, keys.values, envOpts));
        }
        return;
      }
      if (changed) await up.restart(childEnv(o.env, keys.values, envOpts));
    };

    // Status long-poll: echo the bridge's slice revision, act on a new keysRev (restart only when values changed).
    const polling = new AbortController();
    let sliceRevision = 0;
    // v0.1.12: identity refused by the bridge → needs_attention `identity_refused` (logged once per episode); a NEW
    // TB_ENROL_CODE (digest ≠ the record's) claims again once, replacing the record; an unchanged code keeps refusing.
    const tried = new Set<string>();
    let refused = false;
    const onRefused = async (): Promise<boolean> => {
      if (!refused) {
        refused = true;
        log.warn("identity_refused", { hint: "the bridge refuses the stored service identity; a new enrolment code (Portal Retry) lets the service claim again" });
      }
      const code = reclaimCode(cfg.env.enrolCode, rec.codeDigest, tried);
      if (!code) return false;
      log.info("reclaim", { reason: "identity_refused" });
      try {
        rec = inForce(await claimWith(cfg, code, key, bridge, log, polling.signal, gate));
      } catch (e) {
        log.warn("reclaim failed", { code: e instanceof TbError ? e.code : "error" });
        return false;
      }
      refused = false;
      appVerify = appAssertionVerifier(rec);
      sliceRevision = 0;
      const next = await fetchKeys(rec, roles, bridge, secrets, log, polling.signal);
      const restart = next.fingerprint !== keys.fingerprint;
      keys = next;
      if (!polling.signal.aborted) await applyKeys(restart);
      return true;
    };
    const loop = (async () => {
      let delay = 1000;
      while (!polling.signal.aborted) {
        const body: AppStatus = {
          readiness: keys.missing.length > 0 || keys.blockingRoles.length > 0 ? "needs_keys" : "ready",
          version: cfg.manifest.version,
          sdkVersion: SDK_VERSION,
          scopesRev: 0,
          sliceRevision,
          keysRev: keys.rev,
          pendingHolds: 0,
          // v0.1.63 (MANIFEST §7.1): a required role that does not resolve names itself to the owner
          ...(keys.blockingRoles.length > 0 ? { attention: { code: "model_role_missing", reason: `Model role not set: ${keys.blockingRoles.join(", ")}. Set it on the Keys and models page.` } } : {}),
        };
        try {
          const r = await bridge.status(body, polling.signal);
          delay = 1000;
          if (refused) {
            refused = false;
            log.info("identity accepted again");
          }
          if (!r) continue;
          const changed = r.sliceRevision !== sliceRevision || r.keysRev !== keys.rev;
          sliceRevision = r.sliceRevision;
          if (r.keysRev !== keys.rev) {
            const next = await fetchKeys(rec, roles, bridge, secrets, log, polling.signal);
            next.rev = Math.max(next.rev, r.keysRev);
            const restart = next.fingerprint !== keys.fingerprint;
            keys = next;
            if (!polling.signal.aborted) await applyKeys(restart);
          }
          if (!changed) await sleep(1000, polling.signal); // a bridge answering 200 without a change must not spin
        } catch (e) {
          if (polling.signal.aborted) break;
          if (identityRefused(e)) {
            if (await onRefused()) {
              delay = 1000;
              continue;
            }
          } else log.warn("status retry", { code: e instanceof TbError ? e.code : "status_failed", inMs: delay });
          await sleep(delay, polling.signal);
          delay = Math.min(delay * 2, 30_000);
        }
      }
    })();

    // Re-pull keys with backoff (5 s → 60 s) while a required key is missing; start the upstream when they arrive.
    const keyRetry = (async () => {
      let delay = 5000;
      while (!polling.signal.aborted && !up.stopping && blocking(keys).length > 0) {
        try {
          await sleep(delay, polling.signal);
        } catch {
          break;
        }
        delay = Math.min(delay * 2, 60_000);
        const next = await fetchKeys(rec, roles, bridge, secrets, log, polling.signal).catch(() => null);
        if (!next || polling.signal.aborted) continue;
        next.rev = Math.max(next.rev, keys.rev);
        const restart = next.fingerprint !== keys.fingerprint;
        keys = next;
        await applyKeys(restart);
      }
    })();

    const code = await up.exited;
    polling.abort();
    await loop;
    await keyRetry;
    await helper?.stop();
    await closeAll(servers);
    return code;
  }

  const exited = main().catch((e: unknown) => {
    if (stopSignal) return signalExitCode(stopSignal);
    const err = e instanceof TbError ? e : new TbError("internal_error", e instanceof Error ? e.message : "internal error", 500);
    log.error("tb-exec failed", { code: err.code, message: err.message });
    return err.code === "usage" ? 2 : 1;
  });

  return {
    exited,
    signal(sig) {
      if (STOP_SIGNALS.includes(sig) && !stopSignal) stopSignal = sig;
      if (upstream) {
        upstream.signal(sig);
        helper?.signal(sig);
      } else if (STOP_SIGNALS.includes(sig)) startup.abort();
    },
  };
}
