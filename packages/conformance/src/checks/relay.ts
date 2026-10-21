// Relay target checks (CONFORMANCE §4.4 B10 + C4 at the relay, `cred.p1.relay_rejects_person`): the stdio relay is
// driven over JSON-RPC lines while the suite plays the deployed bridge (FakeUpstream) and records every upstream
// request. Asserted: stdio only (no listener in the relay's process tree), verbatim forwarding with no local checks,
// upstream traffic limited to /oauth/token + /mcp, nothing persisted, no grant / config / ticket in its heap, and no
// person credential ever presented upstream.
import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, readlinkSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { digest } from "@opt2-tealbrick/manifest";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { FakeUpstream } from "../fake-upstream.ts";
import { bad, notRun, type Suite, verdict } from "../suite.ts";

export interface StdioPeer {
  /** sends one JSON-RPC message as a line on the relay's stdin */
  send(m: Record<string, unknown>): void;
  /** every JSON-RPC message the relay wrote to stdout */
  readonly received: Record<string, unknown>[];
  /** resolves with the response of request `id` or null after `ms` */
  response(id: number | string, ms: number): Promise<Record<string, unknown> | null>;
  /** pids of the relay process tree */
  pids(): number[];
  /** directory where `--heapsnapshot-signal` snapshots land (the relay's cwd) */
  heapDir: string;
}

export interface RelayContext {
  s: Suite;
  peer: StdioPeer;
  upstream: FakeUpstream;
  /** fake Portal requests after the agent login */
  portalRequestsSince(): number;
  /** directories the relay can write (HOME, XDG_CONFIG_HOME, TMPDIR) and their snapshot before serving */
  home: string;
  before: Map<string, string>;
  /** person credentials present in the relay's environment (never to be presented upstream) */
  personValues: string[];
  /** canned upstream canary (tool results) */
  canary: string;
  timeoutMs: number;
  loggedIn: boolean;
  /** K5 tokens the upstream issued before the relay started (the login's own exchange) */
  issuedBefore: number;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const JWS_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g;
const typOf = (t: string): string | null => {
  try {
    const h = JSON.parse(Buffer.from(t.split(".")[0] ?? "", "base64url").toString("utf8")) as { typ?: unknown };
    return typeof h.typ === "string" ? h.typ : null;
  } catch {
    return null;
  }
};
const typsIn = (text: string, typs: readonly string[]) => [...new Set([...text.matchAll(JWS_RE)].map((m) => typOf(m[0])).filter((t): t is string => !!t && typs.includes(t)))];

/** Snapshot of every regular file under `dir`: path → size:mtime. */
export function snapshot(dir: string, skip: string[] = []): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (d: string, depth: number) => {
    if (depth > 10 || skip.some((s) => d.startsWith(s))) return;
    let names: string[] = [];
    try {
      names = readdirSync(d);
    } catch {
      return;
    }
    for (const n of names) {
      const f = join(d, n);
      try {
        const st = statSync(f);
        if (st.isDirectory()) walk(f, depth + 1);
        else if (st.isFile()) out.set(f, `${st.size}:${st.mtimeMs}`);
      } catch {
        // vanished
      }
    }
  };
  walk(dir, 0);
  return out;
}

/** Canned upstream answers (set before the relay starts). */
export function cannedUpstream(u: FakeUpstream, canary: string): { okTool: string; pausedTool: string; personLooking: string } {
  const okTool = "conformance__echo";
  const pausedTool = "conformance__paused_op";
  const personLooking = "conformance__owner_only_view";
  u.initializeResult = { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: true }, resources: { listChanged: true } }, serverInfo: { name: "tb-conformance-upstream", version: "0.1.0" }, instructions: `Conformance upstream ${canary}` };
  u.toolsList = {
    tools: [
      { name: okTool, description: "Generated", inputSchema: { type: "object", properties: { q: { type: "string" } }, required: ["q"] }, annotations: { readOnlyHint: true } },
      { name: pausedTool, description: "Generated", inputSchema: { type: "object" } },
      { name: personLooking, description: "Generated (a relay must not filter what the bridge lists)", inputSchema: { type: "object" } },
    ],
  };
  u.toolResults.set(okTool, { content: [{ type: "text", text: JSON.stringify({ marker: canary }) }], structuredContent: { marker: canary, nested: { list: [1, "two", null] } } });
  u.toolResults.set(pausedTool, { isError: true, content: [{ type: "text", text: '{"error":{"code":"paused","message":"paused by the owner","requestId":"req_fake"}}' }], structuredContent: { error: { code: "paused", message: "paused by the owner", requestId: "req_fake" } } });
  u.unknownToolResult = { isError: true, content: [{ type: "text", text: '{"error":{"code":"unknown_tool","message":"no such tool","requestId":"req_fake"}}' }], structuredContent: { error: { code: "unknown_tool", message: "no such tool", requestId: "req_fake" } } };
  return { okTool, pausedTool, personLooking };
}

/**
 * Linux fallback for B10.stdio_only when lsof is missing: socket inodes held by the processes' fds, matched against
 * /proc/net/{tcp,tcp6} rows in state 0A (LISTEN) and any /proc/net/{udp,udp6} row. null when /proc is not available.
 */
export function procListeners(pids: number[], root = "/proc"): string[] | null {
  if (!existsSync(join(root, "net", "tcp"))) return null;
  const inodes = new Set<string>();
  for (const pid of pids) {
    let fds: string[] = [];
    try {
      fds = readdirSync(join(root, String(pid), "fd"));
    } catch {
      continue;
    }
    for (const fd of fds) {
      try {
        const m = /^socket:\[(\d+)\]$/.exec(readlinkSync(join(root, String(pid), "fd", fd)));
        if (m) inodes.add(m[1] as string);
      } catch {
        // fd closed meanwhile
      }
    }
  }
  const found: string[] = [];
  for (const table of ["tcp", "tcp6", "udp", "udp6"]) {
    let text = "";
    try {
      text = readFileSync(join(root, "net", table), "utf8");
    } catch {
      continue;
    }
    for (const line of text.split("\n").slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length < 10) continue;
      const [local, , state, inode] = [f[1], f[2], f[3], f[9]];
      const listening = table.startsWith("udp") || state === "0A";
      if (listening && inodes.has(inode as string)) found.push(`${table} ${local}`);
    }
  }
  return found;
}

function processTree(root: number[]): number[] {
  try {
    const rows = execFileSync("ps", ["-A", "-o", "pid=,ppid="], { encoding: "utf8" })
      .trim()
      .split("\n")
      .map((l) => l.trim().split(/\s+/).map(Number) as [number, number]);
    const out = new Set(root);
    let grew = true;
    while (grew) {
      grew = false;
      for (const [pid, ppid] of rows) if (out.has(ppid) && !out.has(pid)) {
        out.add(pid);
        grew = true;
      }
    }
    return [...out];
  } catch {
    return root;
  }
}

export { processTree };

export async function runRelayChecks(x: RelayContext): Promise<void> {
  const { s, peer, upstream: u } = x;
  const T = x.timeoutMs;
  const canned = { ok: "conformance__echo", paused: "conformance__paused_op", person: "conformance__owner_only_view" };
  let id = 0;
  const rpc = async (method: string, params?: Record<string, unknown>) => {
    const n = ++id;
    peer.send({ jsonrpc: "2.0", id: n, method, ...(params ? { params } : {}) });
    return { id: n, res: await peer.response(n, T) };
  };
  const same = (a: unknown, b: unknown) => digest((a ?? null) as Json) === digest((b ?? null) as Json);
  const res = (r: Record<string, unknown> | null) => (r && isObj(r.result) ? r.result : null);

  const init = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "tb-conformance", version: "0.1.0" } });
  peer.send({ jsonrpc: "2.0", method: "notifications/initialized" });
  const list = await rpc("tools/list");
  const okCall = await rpc("tools/call", { name: canned.ok, arguments: { q: "conformance" } });
  const unknown = await rpc("tools/call", { name: "conformance__not_listed", arguments: { unexpected: true } });
  const invalid = await rpc("tools/call", { name: canned.ok, arguments: { wrong_type: 42 } });
  const paused = await rpc("tools/call", { name: canned.paused, arguments: {} });
  await s.run("B10.key_connection", "relay authenticates as the agent with a key connection", "device-flow login (scope agent) created a key connection; the relay itself obtained a K5 via jwt-bearer and used it", () => {
    if (!x.loggedIn) return notRun("no --login-cmd: the relay has no agent credential from this run");
    const own = [...u.issued].slice(x.issuedBefore);
    const used = u.requests.some((r) => r.path.startsWith("/mcp") && own.some((t) => r.headers.authorization === `Bearer ${t}`));
    return verdict(own.length > 0 && used, `${own.length} K5 issued to the relay (jwt-bearer); used on /mcp: ${used}`);
  });
  await s.run("B10.forwards_verbatim", "relay forwards the deployed bridge's answers verbatim", "initialize, tools/list (incl. a person-looking name) and tools/call results (ok, paused refusal) deep-equal the upstream answers", () => {
    const rows = [
      ["initialize", same(res(init.res), u.initializeResult)],
      ["tools/list", same(res(list.res), u.toolsList)],
      ["tools/call ok", same(res(okCall.res), u.toolResults.get(canned.ok))],
      ["tools/call paused", same(res(paused.res), u.toolResults.get(canned.paused))],
    ] as const;
    return verdict(rows.every(([, v]) => v), rows.map(([k, v]) => `${k} ${v ? "=" : "≠"}`).join("; "));
  });
  await s.run("B10.no_local_checks", "relay duplicates no checks", "every tools/call (incl. an unlisted tool and invalid arguments) reaches the deployed bridge; its refusal comes back unchanged", () => {
    const upstreamCalls = u.requests.filter((r) => r.rpc === "tools/call").map((r) => r.rpcId);
    const sent = [okCall.id, unknown.id, invalid.id, paused.id];
    const reached = sent.filter((n) => upstreamCalls.includes(n));
    return verdict(reached.length === sent.length && same(res(unknown.res), u.unknownToolResult), `${reached.length}/${sent.length} calls reached upstream by id (${upstreamCalls.length} upstream tools/call); unlisted tool answer ${same(res(unknown.res), u.unknownToolResult) ? "=" : "≠"} upstream`);
  });
  await s.run("B10.notifications", "server notifications forwarded to stdio", "notifications/tools/list_changed pushed on the upstream GET stream appears on stdout", async () => {
    const open = await waitFor(() => u.streams > 0, T);
    if (!open) return verdict(false, "the relay opened no notification stream");
    u.notify({ jsonrpc: "2.0", method: "notifications/tools/list_changed" });
    const got = await waitFor(() => peer.received.some((m) => m.method === "notifications/tools/list_changed"), T);
    return verdict(got, got ? "forwarded" : "not forwarded");
  });
  // conformance 0.1.29 (BRIDGE §14.3 client duties; C274c S5): the relay keeps an app event subscription alive. Gated by
  // what the fake upstream offers (C292 pattern), never by the relay's version. Frames reach a session's GET stream only
  // after that session subscribed (the fake models it), so a relay that skips any step loses the next event.
  const evOf = (n: number) => ({ id: `01JCONF0EVENT000000000000${n}`, origin: `01JCONF0EVENT000000000000${n}`, type: "conformance.item.assigned", app: "conformance", at: "2026-10-21T00:00:00Z", subject: { kind: "issue", id: `iss_conformance_${n}` }, data: {} });
  const ev = evOf(1);
  const noEvents = () => notRun("the fake upstream offers no tealbrick/events/* methods");
  const frames = (from: number, event: Record<string, unknown>) => peer.received.slice(from).filter((m) => m.method === "notifications/tealbrick/event" && same(m, FakeUpstream.eventFrame(event)));
  let streamId: number | undefined;
  await s.run("B10.events_forwarded", "app event frames forwarded to stdio verbatim", "tealbrick/events/stream reaches the upstream (same id) and its answer comes back unchanged; a notifications/tealbrick/event frame (SSE id = event id) on the subscribed GET stream appears on stdout as the whole JSON-RPC message, deep-equal", async () => {
    if (!u.events) return noEvents();
    const outBefore = peer.received.length;
    const sub = await rpc("tealbrick/events/stream", {});
    const upstreamSub = u.requests.find((r) => r.rpc === "tealbrick/events/stream" && r.rpcId === sub.id);
    const answered = same(res(sub.res), { cursor: null, truncated: false });
    if (!upstreamSub || !answered) return verdict(false, `stream request reached the upstream with id ${sub.id}: ${!!upstreamSub}; answer ${answered ? "=" : "≠"} upstream`);
    streamId = sub.id;
    if (!(await waitFor(() => u.subscribedStreams() > 0, T))) return verdict(false, "no GET stream open on the subscribed session");
    u.notifyEvent(ev);
    const got = await waitFor(() => frames(outBefore, ev).length > 0, T);
    return verdict(got && frames(outBefore, ev).length === 1, got ? `forwarded whole (${frames(outBefore, ev).length}×)` : "the frame did not reach stdout deep-equal");
  });
  await s.run("B10.events_last_event_id", "a GET reconnect carries Last-Event-ID", "the upstream ends the GET stream; the relay's next GET /mcp on the same session carries Last-Event-ID = the id of the last event frame", async () => {
    if (!u.events) return noEvents();
    if (streamId === undefined) return notRun("B10.events_forwarded did not subscribe");
    const before = u.requests.length;
    u.endStreams();
    const isGet = (r: { method: string; path: string }) => r.method === "GET" && r.path.split("?")[0] === "/mcp";
    const again = await waitFor(() => u.requests.slice(before).some(isGet), Math.max(T, 15_000));
    const get = u.requests.slice(before).find(isGet);
    return verdict(again && get?.headers["last-event-id"] === ev.id, again ? `reconnect Last-Event-ID ${JSON.stringify(get?.headers["last-event-id"] ?? null)}` : "no reconnect");
  });
  await s.run("B10.events_resubscribe", "a lost session → re-initialize + stream from the last event, delivery resumes", "the upstream forgets every session (404); the relay sends initialize, then tealbrick/events/stream on the NEW session with cursor = the last event id, opens a GET on it, and the next event reaches stdout; the suite sends nothing meanwhile and the relay writes no answer of its own to stdout (no result/error, no second answer to an id)", async () => {
    if (!u.events) return noEvents();
    if (streamId === undefined) return notRun("B10.events_forwarded did not subscribe");
    const before = u.requests.length;
    const outBefore = peer.received.length;
    const sessionsBefore = u.issuedSessions.length;
    u.forgetSessions();
    const resub = () => u.requests.slice(before).find((r) => r.rpc === "tealbrick/events/stream");
    const ok = await waitFor(() => !!resub(), Math.max(T, 20_000));
    const r = resub();
    let cursor: unknown = null;
    try {
      cursor = (JSON.parse(r?.body ?? "{}") as { params?: { cursor?: unknown } }).params?.cursor ?? null;
    } catch {
      cursor = null;
    }
    const fresh = u.issuedSessions.slice(sessionsBefore);
    const onNew = !!r && fresh.includes(r.headers["mcp-session-id"] ?? "");
    // delivery resumes only on an open GET of the re-subscribed session
    const getOpen = onNew && (await waitFor(() => u.subscribedStreams(r?.headers["mcp-session-id"]) > 0, Math.max(T, 15_000)));
    const ev2 = evOf(2);
    if (getOpen) u.notifyEvent(ev2);
    const delivered = getOpen && (await waitFor(() => frames(outBefore, ev2).length > 0, T));
    await sleep(Math.max(1000, T / 4));
    const answers = peer.received.slice(outBefore).filter((m) => m.result !== undefined || m.error !== undefined);
    const seen = new Set<unknown>();
    const twice = peer.received.filter((m) => (m.result !== undefined || m.error !== undefined) && (seen.has(m.id) || !seen.add(m.id)));
    const pass = ok && onNew && cursor === ev.id && getOpen && delivered && answers.length === 0 && twice.length === 0;
    return verdict(pass, ok ? `new sessions ${fresh.length}; stream on a new session ${onNew}; cursor ${JSON.stringify(cursor)}; GET on it ${getOpen}; next event on stdout ${delivered}; relay-own answers on stdout ${answers.length}; ids answered twice ${twice.length}` : "no tealbrick/events/stream after the session was lost");
  });
  await s.run("B10.stdio_only", "relay speaks stdio only (no listener)", "no TCP LISTEN or UDP socket in the relay's process tree", () => {
    const pids = processTree(peer.pids());
    let out = "";
    try {
      out = execFileSync("lsof", ["-nP", "-a", "-p", pids.join(","), "-i"], { encoding: "utf8" });
    } catch (e) {
      const st = (e as { status?: number; stdout?: string }).status;
      if (st === 1) out = (e as { stdout?: string }).stdout ?? "";
      else {
        // C55: CI images lack lsof → Linux /proc fallback (socket inodes of the tree's fds vs /proc/net tables)
        const viaProc = procListeners(pids);
        if (viaProc === null) return notRun(`lsof unavailable and no /proc: ${e instanceof Error ? e.message.slice(0, 80) : String(e)}`);
        return verdict(viaProc.length === 0, `${pids.length} processes (via /proc); listeners [${viaProc.join("; ")}]`);
      }
    }
    const lines = out.split("\n").filter((l) => /\(LISTEN\)|\bUDP\b/.test(l));
    return verdict(lines.length === 0, `${pids.length} processes; listeners [${lines.map((l) => l.replace(/\s+/g, " ").split(" ").slice(-2).join(" ")).join("; ")}]`);
  });
  await s.run("B10.memory_snapshot", "no grant, config, slice or person ticket in the relay's heap", "heap snapshot (--heapsnapshot-signal) holds no compact JWS of those typs", async () => {
    // C55: signal only the target process (the directly spawned relay), never a whole tree (dash dies on SIGUSR2)
    for (const p of peer.pids().slice(0, 1)) {
      try {
        process.kill(p, "SIGUSR2");
      } catch {
        // gone
      }
    }
    const found = await waitFor(() => readdirSync(peer.heapDir).some((f) => f.endsWith(".heapsnapshot")), Math.max(T, 20_000));
    if (!found) return notRun("no heap snapshot written (the relay is not a Node process honouring NODE_OPTIONS --heapsnapshot-signal)");
    await sleep(1500);
    const typs: string[] = [];
    for (const f of readdirSync(peer.heapDir).filter((n) => n.endsWith(".heapsnapshot"))) typs.push(...typsIn(readFileSync(join(peer.heapDir, f), "utf8"), [TYP.grant, TYP.config, TYP.slice, TYP.personTicket, TYP.ownerAssertion]));
    return verdict(typs.length === 0, typs.length ? `found ${[...new Set(typs)].join(", ")}` : "clean");
  });
  // person credentials: none presented upstream; then a refused upstream must not make the relay try anything else
  u.refuseAll = true;
  const afterRefuse = u.requests.length;
  const refusedCall = await rpc("tools/call", { name: canned.ok, arguments: { q: "x" } });
  await sleep(500);
  await s.run("cred.p1.relay_rejects_person", "relay never presents or forwards a person credential", "no person value from its environment in any upstream or Portal request; after the bridge refuses the agent, the relay answers an error and presents no other credential", () => {
    const leaks = u.requests.filter((r) => x.personValues.some((v) => r.body.includes(v) || Object.values(r.headers).some((h) => h.includes(v))));
    const auth = u.requests.slice(afterRefuse).filter((r) => r.headers.authorization && !/^Bearer /.test(r.headers.authorization));
    const answered = !!refusedCall.res && (isObj(refusedCall.res.error) || (isObj(refusedCall.res.result) && refusedCall.res.result.isError === true));
    return verdict(leaks.length === 0 && auth.length === 0 && answered && x.portalRequestsSince() === 0, `person values upstream ${leaks.length}; non-bearer auth ${auth.length}; refused call answered ${answered ? "with an error" : "NOT"}; Portal requests while serving ${x.portalRequestsSince()}`);
  });
  await s.run("C4.relay_k5_only", "upstream MCP requests carry only bridge-issued K5", "every upstream /mcp request has Authorization: Bearer <K5 issued by the deployed bridge>", () => {
    const mcp = u.requests.filter((r) => r.path.startsWith("/mcp"));
    const off = mcp.filter((r) => !u.issued.has(/^Bearer (\S+)$/.exec(r.headers.authorization ?? "")?.[1] ?? ""));
    return verdict(mcp.length > 0 && off.length === 0, `${mcp.length} upstream MCP requests; other credentials ${off.length}`);
  });
  await s.run("B10.upstream_paths", "upstream traffic only /oauth/token and /mcp", "no request to any other bridge path (no /tb/v1/*, no config) and none to Portal while serving", () => {
    const off = u.requests.filter((r) => !(r.path.split("?")[0] === "/oauth/token" && r.method === "POST") && !(r.path.split("?")[0] === "/mcp" && ["POST", "GET", "DELETE"].includes(r.method)));
    return verdict(off.length === 0 && x.portalRequestsSince() === 0, `${u.requests.length} upstream requests; other [${off.map((r) => `${r.method} ${r.path}`).join(",")}]; Portal ${x.portalRequestsSince()}`);
  });
}

/** After the relay stopped: nothing persisted that is a grant, config, slice, token or upstream payload. */
export async function relayDiskCheck(x: RelayContext): Promise<void> {
  await x.s.run("B10.no_state_on_disk", "relay holds no grants, keys, config or tokens on disk", "files new or changed under HOME / XDG_CONFIG_HOME / TMPDIR while serving carry no JWS of those typs and no upstream payload", () => {
    const after = snapshot(x.home, [x.peer.heapDir]);
    const changed = [...after].filter(([f, v]) => x.before.get(f) !== v).map(([f]) => f);
    const bad_: string[] = [];
    for (const f of changed) {
      const t = readFileSync(f).toString("latin1");
      if (typsIn(t, [TYP.agentSession, TYP.grant, TYP.config, TYP.slice, TYP.personTicket]).length > 0 || t.includes(x.canary) || [...x.upstream.issued].some((k) => t.includes(k))) bad_.push(relative(x.home, f));
    }
    return verdict(bad_.length === 0, `${changed.length} files new or changed${changed.length ? ` [${changed.map((f) => relative(x.home, f)).slice(0, 6).join(",")}]` : ""}; with state [${bad_.join(",")}]`);
  });
}

async function waitFor(fn: () => boolean, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (fn()) return true;
    await sleep(100);
  }
  return fn();
}

export { bad };
