// Relay target runner (CONFORMANCE §2 `tb-conformance relay --cmd "<stdio relay command>"`): the suite plays the
// deployed bridge (FakeUpstream) and the Portal device flow (FakePortal), optionally provisions the agent credential
// with `--login-cmd` (RFC 8628 device flow, scope agent, approved by the suite as the owner), then starts the relay
// with HOME / XDG_CONFIG_HOME / TMPDIR in a fresh directory, drives it over stdio and checks B10 + C4 at the relay.
import type { ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import { RELAY_CHECKS } from "./checks/catalog.ts";
import { cannedUpstream, type RelayContext, relayDiskCheck, runRelayChecks, type StdioPeer, snapshot } from "./checks/relay.ts";
import { spawnCommand } from "./command.ts";
import { FakePortal } from "./fake-portal.ts";
import { FakeUpstream } from "./fake-upstream.ts";
import { buildReport, type Report } from "./report.ts";
import { bad, notRun, Suite } from "./suite.ts";
import { Mint, newId } from "./tokens.ts";

export interface RunRelayOptions {
  /** the stdio relay command (e.g. `tealbrick bridge serve --stdio`) */
  cmd: string;
  /** agent sign-in command run first with the same env (e.g. `tealbrick agent login`); the suite approves its device request */
  loginCmd?: string;
  timeoutMs?: number;
  keepHome?: boolean;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Every target process this module started and has not stopped yet. They run detached (own process group, so `stop` can
 * signal the whole group), which means a terminal signal or the death of the runner does NOT reach them. This set is the
 * safety net for every runner exit path other than `stop` itself: a normal or `process.exit` end, SIGINT and SIGTERM.
 * (A SIGKILL of the runner cannot be caught; the relay then ends by itself when its stdin pipe closes.)
 */
const live = new Set<ChildProcess>();
let guarded = false;

function killLive(): void {
  for (const child of live) {
    if (child.pid === undefined || child.exitCode !== null || child.signalCode !== null) continue;
    try {
      process.kill(-child.pid, "SIGKILL");
    } catch {
      try {
        child.kill("SIGKILL");
      } catch {
        // already gone
      }
    }
  }
  live.clear();
}

function track(child: ChildProcess): ChildProcess {
  live.add(child);
  child.once("exit", () => live.delete(child));
  if (!guarded) {
    guarded = true;
    process.once("exit", killLive);
    for (const sig of ["SIGINT", "SIGTERM"] as const) {
      process.once(sig, () => {
        killLive();
        process.exit(128 + (sig === "SIGINT" ? 2 : 15));
      });
    }
  }
  return child;
}

function stop(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return resolve();
    const t = setTimeout(() => {
      try {
        process.kill(-(child.pid as number), "SIGKILL");
      } catch {
        child.kill("SIGKILL");
      }
    }, 5000);
    child.once("exit", () => {
      clearTimeout(t);
      resolve();
    });
    try {
      process.kill(-(child.pid as number), "SIGTERM");
    } catch {
      child.kill("SIGTERM");
    }
  });
}

export async function runRelayTarget(opts: RunRelayOptions): Promise<Report> {
  const startedAt = new Date();
  const T = opts.timeoutMs ?? 15_000;
  const s = new Suite();
  const notes: string[] = [];
  const portal = await FakePortal.create({ maxWaitS: 1, pollIntervalS: 0 });
  const upstream = await FakeUpstream.create({ bridgeId: portal.bridgeId, ws: portal.ws, connections: () => portal.connections });
  portal.bridgePublicUrl = upstream.url;
  const canary = `cnry${randomBytes(9).toString("hex")}`;
  cannedUpstream(upstream, canary);
  const home = mkdtempSync(join(tmpdir(), "tb-conformance-relay-"));
  const heapDir = join(home, "cwd");
  for (const d of [join(home, ".config"), join(home, "tmp"), heapDir]) mkdirSync(d, { recursive: true });
  const ticket = await new Mint({ ws: portal.ws, bridge: portal.bridgeId, portalKey: () => portal.activeKey(), bridgeKey: () => portal.activeKey(), stranger: portal.activeKey() }).launchTicket({ person: newId("per") as never, aud: `tb:ins:${newId("ins")}` as never });
  const personValues = [Mint.ownerCliLike(), Mint.clerkLikeJwt(), ticket];
  const base: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (v !== undefined && !/^(HOME|XDG_CONFIG_HOME|TMPDIR|TB_[A-Z_]+|NODE_OPTIONS)$/.test(k)) base[k] = v;
  const env: Record<string, string> = {
    ...base,
    HOME: home,
    XDG_CONFIG_HOME: join(home, ".config"),
    TMPDIR: join(home, "tmp"),
    TB_PORTAL_URL: portal.url,
    TB_CREDENTIAL_STORE: "file",
    // person credentials present on the machine (TBD / owner CLI): the relay must never present them (R-P1)
    TB_OWNER_SESSION: personValues[0] as string,
    CLERK_SESSION_TOKEN: personValues[1] as string,
    TB_PERSON_TICKET: personValues[2] as string,
  };
  let relay: ChildProcess | null = null;
  try {
    // ── 1. agent sign-in (device flow, scope agent) ──
    let loggedIn = false;
    if (opts.loginCmd) {
      const agt = newId("agt") as AgentId;
      portal.agents.push({ agt, name: "Conformance relay agent", mode: "free" });
      const out: string[] = [];
      const login = track(spawnCommand(opts.loginCmd, { env, cwd: home, stdio: ["ignore", "pipe", "pipe"], detached: true }));
      login.stdout?.on("data", (d: Buffer) => out.push(d.toString("utf8")));
      login.stderr?.on("data", (d: Buffer) => out.push(d.toString("utf8")));
      const exited = new Promise<number | null>((r) => login.once("exit", (code) => r(code)));
      const end = Date.now() + Math.max(T, 90_000);
      let approved = false;
      while (Date.now() < end && login.exitCode === null) {
        if (!approved) approved = await portal.control.approvePending([agt]);
        await sleep(200);
      }
      if (login.exitCode === null) await stop(login);
      const code = await Promise.race([exited, sleep(1000).then(() => login.exitCode)]);
      loggedIn = code === 0 && approved && portal.connections.some((c) => c.agt === agt);
      if (!loggedIn) notes.push(`agent login failed: exit ${code}, approved ${approved}; output: ${out.join("").slice(-400)}`);
    } else notes.push("no --login-cmd: the relay is started without an agent credential from this run");
    const portalBaseline = portal.requests.length;
    const issuedBefore = upstream.issued.size;
    // ── 2. relay over stdio ──
    const before = snapshot(home, [heapDir]);
    relay = track(spawnCommand(opts.cmd, { env: { ...env, NODE_OPTIONS: "--heapsnapshot-signal=SIGUSR2" }, cwd: heapDir, stdio: ["pipe", "pipe", "pipe"], detached: true }));
    const child = relay;
    const received: Record<string, unknown>[] = [];
    const waiters = new Set<() => void>();
    let stderr = "";
    child.stderr?.on("data", (d: Buffer) => {
      stderr += d.toString("utf8");
    });
    createInterface({ input: child.stdout as NodeJS.ReadableStream }).on("line", (line) => {
      try {
        const m = JSON.parse(line) as unknown;
        if (m && typeof m === "object" && !Array.isArray(m)) received.push(m as Record<string, unknown>);
      } catch {
        // stdout must carry JSON-RPC only; non-JSON lines are ignored here (B10 asserts answers, not noise)
      }
      for (const w of [...waiters]) w();
    });
    const peer: StdioPeer = {
      send: (m) => child.stdin?.write(`${JSON.stringify(m)}\n`),
      received,
      heapDir,
      pids: () => (child.pid ? [child.pid] : []),
      response: (id, ms) =>
        new Promise((resolve) => {
          const check = () => {
            const m = received.find((x) => x.id === id && ("result" in x || "error" in x));
            if (m) {
              clearTimeout(t);
              waiters.delete(check);
              resolve(m);
            }
          };
          const t = setTimeout(() => {
            waiters.delete(check);
            resolve(null);
          }, ms);
          waiters.add(check);
          check();
        }),
    };
    await sleep(300);
    if (child.exitCode !== null || child.signalCode !== null) {
      const why = `relay exited at start (code ${child.exitCode}): ${stderr.slice(-300)}`;
      for (const c of RELAY_CHECKS) s.record(c.id, c.title, "the relay serves stdio", c.id === "B10.key_connection" && !loggedIn ? notRun("no --login-cmd: no agent credential from this run") : bad(why));
      return buildReport({ target: "relay", subject: opts.cmd, startedAt, checks: s.results, notes: [...notes, why] });
    }
    const ctx: RelayContext = { s, peer, upstream, portalRequestsSince: () => portal.requests.length - portalBaseline, home, before, personValues, canary, timeoutMs: T, loggedIn, issuedBefore };
    try {
      await runRelayChecks(ctx);
    } catch (e) {
      notes.push(`relay checks aborted: ${e instanceof Error ? e.message : String(e)}`);
    }
    child.stdin?.end();
    await Promise.race([new Promise((r) => child.once("exit", r)), sleep(5000)]);
    await stop(child);
    await relayDiskCheck(ctx);
    for (const c of RELAY_CHECKS) if (!s.has(c.id)) s.record(c.id, c.title, "check executed", c.id === "B10.key_connection" ? notRun("no login") : bad("not reached"));
    const report = buildReport({ target: "relay", subject: `${opts.cmd}${opts.loginCmd ? ` (login: ${opts.loginCmd})` : ""}`, startedAt, checks: s.results, notes });
    const k = report.counts;
    report.notes.push(`summary: ${k.pass} pass, ${k.fail} fail, ${k.not_run} not_run (${s.results.length} checks); upstream requests ${upstream.requests.length}`);
    return report;
  } finally {
    if (relay) await stop(relay);
    await upstream.close();
    await portal.close();
    if (!opts.keepHome) rmSync(home, { recursive: true, force: true });
  }
}
