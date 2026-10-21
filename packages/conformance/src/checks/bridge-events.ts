// B-EV (conformance 0.1.28, spec 0.1.57, BRIDGE §14.4): app events on a bridge that DECLARES the `events` capability. One row per
// case of BRIDGE §14.4, in that order. Gated by the capability the bridge reports in its StatusReport (`bridge.caps`), never by
// version (C292): without it every row is not_applicable. The suite plays the apps (fake apps that declare events, listed in the
// config only for this group: a bridge without the cap would refuse a manifest with `events`) and the agents (MCP sessions,
// mcp-agent.ts) on their existing `/mcp` session (`tealbrick/events/{list,poll,stream}`). Consumers dedupe by `origin`; the
// cursor is `id`.
import { ulid } from "@opt2-tealbrick/manifest";
import { EVENT_MCP_METHODS } from "@opt2-tealbrick/spec/bridge";
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import { EVENT_HOOK_ID, EVENT_READ_OP } from "../bridge-world.ts";
import type { FakeApp } from "../fake-app.ts";
import type { McpSession } from "../mcp-agent.ts";
import { bad, na, notRun, type Outcome, ok, verdict } from "../suite.ts";
import { reportedBridgeCaps } from "./bridge.ts";
import { type BridgeCtx, isObj, type KeySlot, sleep } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

export const EVENTS_CAP = "events";
/** Retention per agent (BRIDGE §14.2): 10 000 rows (7 days is not observable in a run). */
const RETENTION_ROWS = 10_000;
/** CONFORMANCE v0.1.57: the rows that need volume (retention, rate limits) and get their own time budget */
const VOLUME_ROWS = new Set(["B-EV-8", "B-EV-11"]);
const VOLUME_BUDGET_MS = 300_000;

type Ev = { id: string; origin: string; type: string; app: string; instanceId?: string; summary?: string; data: Record<string, unknown>; causedBy?: string };
type Poll = { events: Ev[]; cursor: string | null; truncated: boolean; paused?: boolean } | { problem: string };

/** the rows in BRIDGE §14.4 order, then B-EV-18 (titles in bridge-ids.ts, group `events`) */
const ALL_ROWS: [string, string][] = (BRIDGE_GROUPS.events ?? []).map((x) => [x.id, x.title]);
/** B-EV-1..17 (the §14.4 cases; B-EV-18 is the no-cap row) */
const ROWS: [string, string][] = ALL_ROWS.filter(([id]) => id !== "B-EV-18");
export const EVENT_CHECK_TITLES: Record<string, string> = Object.fromEntries(ALL_ROWS);

/** true when one StatusReport declares the events cap */
const declares = (ack: { bridge?: { caps?: unknown } }): boolean => {
  const caps = ack.bridge?.caps;
  return Array.isArray(caps) && caps.includes(EVENTS_CAP);
};

export async function eventChecks(c: BridgeCtx): Promise<void> {
  const caps = reportedBridgeCaps(c);
  const acks = c.w.portal.acks;
  const declaring = acks.filter(declares).length;
  if (!caps.includes(EVENTS_CAP)) {
    const why = `the bridge does not declare the ${EVENTS_CAP} capability in its StatusReport (bridge.caps = ${JSON.stringify(caps)}): BRIDGE §14 is not announced, so this row does not apply (decided by capability, never by version, C292)`;
    for (const [id, title] of ROWS.slice(0, -1)) await c.run(id, title, "BRIDGE §14.4", () => na(why));
    await c.run("B-EV-17", EVENT_CHECK_TITLES["B-EV-17"] as string, "every StatusReport declares events, or none does", () =>
      declaring === 0 ? na(why) : bad(`${declaring} of ${acks.length} StatusReports declared ${EVENTS_CAP}, the latest does not: a bridge declares it in EVERY report or never`),
    );
    // CONFORMANCE v0.1.57 (specs#33): a bridge WITHOUT the cap answers tealbrick/events/* with JSON-RPC -32601 (runtimes keep their polls)
    await c.run("B-EV-18", EVENT_CHECK_TITLES["B-EV-18"] as string, "the free agent calls tealbrick/events/list, poll and stream on its /mcp session → each answer is a JSON-RPC error with code -32601", async () => {
      const s = await c.session("free");
      const seen: string[] = [];
      for (const method of [EVENT_MCP_METHODS.list, EVENT_MCP_METHODS.poll, EVENT_MCP_METHODS.stream]) {
        const { message } = await s.rpc(method, {});
        const code = isObj(message?.error) ? Number(message.error.code) : null;
        seen.push(`${method} → ${code ?? JSON.stringify(message?.result ?? null).slice(0, 60)}`);
        if (code !== -32601) return bad(`${seen.join("; ")} (expected -32601 method not found from a bridge without the ${EVENTS_CAP} cap)`);
      }
      return ok(seen.join("; "));
    });
    return;
  }
  const ev = c.w.eventApps;
  if (!ev) {
    for (const [id, title] of ALL_ROWS) await c.run(id, title, "BRIDGE §14.4", () => notRun("the suite could not derive event apps from the example manifest (eventManifest)"));
    return;
  }
  const { a, b, tb } = ev;
  const agents = { free: c.w.agents.free.agt, bound: c.w.agents.bound.agt, none: c.w.agents.none.agt };
  const scopedOp = a.manifest.events?.find((e) => e.name === "conf.scoped")?.visibleWith;
  const T = c.h.timeoutMs;

  // ── list the event apps for this group (grants: free on a, b, tb; bound on a with wf [read, scoped read]) ──
  const specsBefore = [...c.w.grantSpecs];
  const hookKey = `${a.product}.${EVENT_HOOK_ID}`;
  c.w.eventAppsListed = true;
  c.w.hookState.set(hookKey, "disabled");
  c.w.hookState.set(`${b.product}.${EVENT_HOOK_ID}`, "disabled");
  const boundSpec = { role: "bound" as const, app: a, crud: ["read", "create", "update", "delete"] as ("read" | "create" | "update" | "delete")[], mode: "bound" as const, wf: [EVENT_READ_OP, ...(scopedOp ? [scopedOp] : [])] };
  c.w.grantSpecs.push(
    { role: "free", app: a, crud: ["read", "create", "update"], mode: "free", wf: [] },
    { role: "free", app: b, crud: ["read", "create", "update"], mode: "free", wf: [] },
    { role: "free", app: tb, crud: ["read"], mode: "free", wf: [] },
    boundSpec,
  );
  try {
    const applied = await c.apply();
    if (!applied.acked) {
      for (const [id, title] of ALL_ROWS) await c.run(id, title, "BRIDGE §14.4", () => bad(`the config listing the event apps (rev ${applied.rev}) was not acknowledged`));
      return;
    }
    await runRows(c, { a, b, tb, agents, scopedOp, T, boundSpec, hookKey });
  } finally {
    c.w.eventAppsListed = false;
    c.w.grantSpecs = specsBefore;
    c.w.hookState.delete(hookKey);
    c.w.hookState.delete(`${b.product}.${EVENT_HOOK_ID}`);
    c.w.portal.pause.instances.delete(a.ins);
    await c.apply().catch(() => undefined);
    c.dropSessions();
  }
}

interface Env {
  a: FakeApp;
  b: FakeApp;
  tb: FakeApp;
  agents: { free: AgentId; bound: AgentId; none: AgentId };
  scopedOp: string | undefined;
  T: number;
  boundSpec: { wf: string[] };
  hookKey: string;
}

async function runRows(c: BridgeCtx, e: Env): Promise<void> {
  const { a, b, tb, agents, T } = e;
  const subject = { kind: "conf", id: "c1" };
  const item = (o: { name?: string; n?: number; data?: unknown; key?: string; to?: string[]; instanceId?: string; eligible?: { agent: string; authority: string }[]; causedBy?: string; summary?: string }) => ({
    kind: "emit",
    key: o.key ?? `conf-${ulid()}`,
    name: o.name ?? "conf.ping",
    at: new Date().toISOString(),
    subject,
    data: o.data ?? { n: o.n ?? 0 },
    ...(o.to ? { to: o.to } : {}),
    ...(o.instanceId !== undefined ? { instanceId: o.instanceId } : {}),
    ...(o.eligible ? { eligible: o.eligible } : {}),
    ...(o.causedBy ? { causedBy: o.causedBy } : {}),
    ...(o.summary ? { summary: o.summary } : {}),
  });
  /** posts items (429 → waits Retry-After and retries, within `ms`); returns the per-item results or the problem */
  const post = async (app: FakeApp, items: unknown[], ms = T): Promise<{ results: { key: string; status: string; code?: string }[] } | { problem: string }> => {
    const end = Date.now() + ms;
    for (;;) {
      const r = await app.postEvents(items);
      if (r.status === 200 && isObj(r.body) && Array.isArray(r.body.results)) return { results: r.body.results as { key: string; status: string; code?: string }[] };
      if (r.status === 429 && Date.now() < end) {
        await sleep(Math.max(250, Number(r.headers.get("retry-after") ?? "1") * 1000));
        continue;
      }
      return { problem: `POST /tb/v1/events → ${r.status} ${r.text.slice(0, 160)}` };
    }
  };
  const emit = async (app: FakeApp, items: ReturnType<typeof item>[]): Promise<string | null> => {
    const r = await post(app, items);
    if ("problem" in r) return r.problem;
    const off = r.results.filter((x) => x.status !== "stored");
    return off.length ? `ingest answered ${off.map((x) => `${x.status}${x.code ? ` ${x.code}` : ""}`).join(", ")}` : null;
  };
  const sessions = new Map<KeySlot, McpSession>();
  const sess = async (slot: KeySlot, fresh = false): Promise<McpSession> => {
    const have = sessions.get(slot);
    if (have && !fresh) return have;
    const s = await c.session(slot, fresh);
    sessions.set(slot, s);
    return s;
  };
  const poll = async (slot: KeySlot, cursor?: string | null, limit = 100): Promise<Poll> => {
    const s = await sess(slot);
    const { message } = await s.rpc(EVENT_MCP_METHODS.poll, { ...(cursor ? { cursor } : {}), limit });
    if (!message) return { problem: "no JSON-RPC answer to tealbrick/events/poll" };
    if (isObj(message.error)) return { problem: `tealbrick/events/poll → error ${JSON.stringify(message.error).slice(0, 160)}` };
    const r = message.result;
    if (!isObj(r) || !Array.isArray(r.events)) return { problem: `tealbrick/events/poll → ${JSON.stringify(r).slice(0, 160)}` };
    return { events: r.events as Ev[], cursor: typeof r.cursor === "string" ? r.cursor : null, truncated: r.truncated === true, ...(r.paused === true ? { paused: true } : {}) };
  };
  /** every event after `cursor` (pages through), and the last cursor */
  const drain = async (slot: KeySlot, cursor: string | null): Promise<{ events: Ev[]; cursor: string | null; truncated: boolean } | { problem: string }> => {
    const all: Ev[] = [];
    let cur = cursor;
    let truncated = false;
    for (let i = 0; i < 200; i++) {
      const p = await poll(slot, cur);
      if ("problem" in p) return p;
      truncated ||= p.truncated;
      all.push(...p.events);
      cur = p.cursor ?? cur;
      if (p.events.length < 100) break;
    }
    return { events: all, cursor: cur, truncated };
  };
  /** the current end of an agent's stream (paged from the last end this group saw: one agent may hold > 10 000 rows) */
  const ends = new Map<KeySlot, string | null>();
  const head = async (slot: KeySlot): Promise<string | null> => {
    const d = await drain(slot, ends.get(slot) ?? null);
    const cur = "problem" in d ? (ends.get(slot) ?? null) : d.cursor;
    ends.set(slot, cur);
    return cur;
  };
  const nOf = (x: Ev) => (isObj(x.data) ? x.data.n : undefined);
  const mine = (evs: Ev[], app: FakeApp) => evs.filter((x) => x.app === app.product);
  const settle = () => sleep(Math.min(1500, T));
  const results = new Map<string, Outcome>();
  const run = async (id: string, expected: string, fn: () => Promise<Outcome>) => {
    const o = await c.run(id, EVENT_CHECK_TITLES[id] as string, expected, fn);
    results.set(id, o);
  };

  await run("B-EV-1", "free agent: tealbrick/events/stream {cursor} → {cursor, truncated}; GET /mcp open; app a emits conf.ping → a notifications/tealbrick/event frame with that event within 3 s", async () => {
    const s = await sess("free");
    const cursor = await head("free");
    const { message } = await s.rpc(EVENT_MCP_METHODS.stream, cursor ? { cursor } : {});
    if (!message || !isObj(message.result) || typeof message.result.truncated !== "boolean") return bad(`tealbrick/events/stream → ${JSON.stringify(message).slice(0, 200)}`);
    const n = s.listen();
    try {
      await sleep(300);
      const t0 = Date.now();
      const problem = await emit(a, [item({ n: 101 })]);
      if (problem) return bad(problem);
      const got = await new Promise<boolean>((resolve) => {
        const end = Date.now() + 3000;
        const tick = () => {
          const hit = n.messages.some((m) => m.method === EVENT_MCP_METHODS.notification && isObj(m.params) && isObj(m.params.event) && isObj(m.params.event.data) && m.params.event.data.n === 101);
          if (hit) return resolve(true);
          if (Date.now() > end) return resolve(false);
          setTimeout(tick, 50);
        };
        tick();
      });
      const frame = n.messages.find((m) => m.method === EVENT_MCP_METHODS.notification);
      const evt = isObj(frame?.params) && isObj(frame.params.event) ? (frame.params.event as Ev) : null;
      if (!got || !evt) return bad(`no ${EVENT_MCP_METHODS.notification} frame with the event within 3 s`);
      const shape = typeof evt.id === "string" && typeof evt.origin === "string" && evt.type === `${a.product}.conf.ping` && evt.app === a.product;
      return verdict(shape, `${Date.now() - t0} ms; type ${evt.type}, id/origin ${typeof evt.id}/${typeof evt.origin}`);
    } finally {
      n.close();
    }
  });

  await run("B-EV-2", "the agent with no grant: app a emits conf.ping (granted) → its poll shows nothing of app a and tealbrick/events/list has no entry of app a; the free agent (positive control) gets it", async () => {
    const c0 = await head("none");
    const f0 = await head("free");
    const problem = await emit(a, [item({ n: 201 })]);
    if (problem) return bad(problem);
    await settle();
    const none = await drain("none", c0);
    const free = await drain("free", f0);
    if ("problem" in none) return bad(none.problem);
    if ("problem" in free) return bad(free.problem);
    const s = await sess("none");
    const { message } = await s.rpc(EVENT_MCP_METHODS.list);
    const types = isObj(message?.result) && Array.isArray(message.result.types) ? (message.result.types as { app?: string }[]) : null;
    if (!types) return bad(`tealbrick/events/list → ${JSON.stringify(message).slice(0, 160)}`);
    if (!mine(free.events, a).some((x) => nOf(x) === 201)) return bad("positive control: the free agent did not get the event");
    const listed = types.filter((t) => t.app === a.product).length;
    return verdict(mine(none.events, a).length === 0 && listed === 0, `none: ${mine(none.events, a).length} event(s), ${listed} list entr(y/ies) of ${a.product}; free got it`);
  });

  const scopedGate = (): Outcome | null => (e.scopedOp ? null : na("the example manifest has no scoped agent read op: the event apps declare no scoped event"));

  await run("B-EV-3", "conf.scoped for instance i3 with eligible [] → the free agent gets nothing; with eligible [free: bounded] → it does (positive control)", async () => {
    const g = scopedGate();
    if (g) return g;
    const f0 = await head("free");
    const p1 = await emit(a, [item({ name: "conf.scoped", n: 301, instanceId: "conf-i3", eligible: [] })]);
    const p2 = await emit(a, [item({ name: "conf.scoped", n: 302, instanceId: "conf-i3", eligible: [{ agent: agents.free, authority: "bounded" }] })]);
    if (p1 || p2) return bad(String(p1 ?? p2));
    await settle();
    const d = await drain("free", f0);
    if ("problem" in d) return bad(d.problem);
    const ns = mine(d.events, a).map(nOf);
    return verdict(!ns.includes(301) && ns.includes(302), `outside eligible: ${ns.includes(301) ? "DELIVERED" : "nothing"}; in eligible: ${ns.includes(302) ? "delivered" : "MISSING"}`);
  });

  await run("B-EV-4", "conf.ping with causedBy = the free agent → the free agent gets nothing; the bound agent (wf has the read op) gets it", async () => {
    const f0 = await head("free");
    const b0 = await head("bound");
    const p = await emit(a, [item({ n: 401, causedBy: agents.free })]);
    if (p) return bad(p);
    await settle();
    const f = await drain("free", f0);
    const bd = await drain("bound", b0);
    if ("problem" in f) return bad(f.problem);
    if ("problem" in bd) return bad(bd.problem);
    const toCause = mine(f.events, a).some((x) => nOf(x) === 401);
    const toOther = mine(bd.events, a).some((x) => nOf(x) === 401);
    return verdict(!toCause && toOther, `causing agent: ${toCause ? "DELIVERED" : "nothing"}; other agent: ${toOther ? "delivered" : "MISSING"}`);
  });

  await run("B-EV-5", "the free agent stores its cursor, its session is dropped; 3 emits; a NEW session polls with that cursor → exactly those 3, in emit order", async () => {
    const c0 = await head("free");
    sessions.delete("free");
    c.dropSessions();
    const p = await emit(a, [item({ n: 501 }), item({ n: 502 }), item({ n: 503 })]);
    if (p) return bad(p);
    await settle();
    await sess("free", true);
    const d = await drain("free", c0);
    if ("problem" in d) return bad(d.problem);
    const ns = d.events.map(nOf);
    return verdict(JSON.stringify(ns) === JSON.stringify([501, 502, 503]), `after reconnect: ${JSON.stringify(ns)}`);
  });

  await run("B-EV-6", "conf.ping stored for the bound agent; before it reads, its grant's wf drops the read op (config) → its poll does not deliver it", async () => {
    const b0 = await head("bound");
    const p = await emit(a, [item({ n: 601 })]);
    if (p) return bad(p);
    await settle();
    const wf = [...e.boundSpec.wf];
    e.boundSpec.wf = wf.filter((x) => x !== EVENT_READ_OP);
    if (e.boundSpec.wf.length === 0) e.boundSpec.wf = [c.w.primary.manifest.operations.find((o) => o.audience === "agent")?.id ?? EVENT_READ_OP];
    try {
      const r = await c.apply();
      if (!r.acked) return bad("the narrowed grant was not acknowledged");
      const d = await drain("bound", b0);
      if ("problem" in d) return bad(d.problem);
      const got = mine(d.events, a).some((x) => nOf(x) === 601);
      return verdict(!got, got ? "delivered after the grant no longer admits the op" : "not delivered after the grant changed");
    } finally {
      e.boundSpec.wf = wf;
      await c.apply();
    }
  });

  await run("B-EV-7", "app a paused; a emits E1, E2; app b emits F1; the free agent polls (F1 only) and moves its cursor past E1/E2's first ids; a resumed; a emits E3 → the next poll gives E1, E2, E3 in that order, E1/E2 with NEW ids (id ≠ origin, id > cursor) and their first ids as origin", async () => {
    const c0 = await head("free");
    c.w.portal.pause.instances.add(a.ins);
    try {
      if (!(await c.apply()).acked) return bad("the instance pause was not acknowledged");
      const p1 = await emit(a, [item({ n: 701 }), item({ n: 702 })]);
      const p2 = await emit(b, [item({ n: 703 })]);
      if (p1 || p2) return bad(String(p1 ?? p2));
      await settle();
      const d1 = await drain("free", c0);
      if ("problem" in d1) return bad(d1.problem);
      const ns1 = d1.events.map(nOf);
      if (ns1.includes(701) || ns1.includes(702)) return bad(`a paused instance's events were delivered: ${JSON.stringify(ns1)}`);
      if (!ns1.includes(703)) return bad(`the other app's event F1 was not delivered: ${JSON.stringify(ns1)}`);
      const c1 = d1.cursor;
      c.w.portal.pause.instances.delete(a.ins);
      if (!(await c.apply()).acked) return bad("the resume was not acknowledged");
      const p3 = await emit(a, [item({ n: 704 })]);
      if (p3) return bad(p3);
      await settle();
      const d2 = await drain("free", c1);
      if ("problem" in d2) return bad(d2.problem);
      const got = mine(d2.events, a);
      const ns = got.map(nOf);
      if (JSON.stringify(ns) !== JSON.stringify([701, 702, 704])) return bad(`after resume: ${JSON.stringify(ns)} (expected [701,702,704])`);
      const held = got.slice(0, 2);
      const fresh = held.every((x) => x.id !== x.origin && c1 !== null && x.id > c1);
      return verdict(fresh, fresh ? "held events after the resume with new ids and their first ids as origin, before the later event" : `ids/origins ${JSON.stringify(held.map((x) => [x.id, x.origin]))} (cursor ${c1})`);
    } finally {
      c.w.portal.pause.instances.delete(a.ins);
    }
  });

  // B-EV-8 and B-EV-11 share one flood: > 10 000 rows for the free agent from app b while one row of the paused app a is held
  let flood: { problem: string; budget?: true } | { cursorBefore: string | null; heldN: number; first: Ev[]; truncatedAny: boolean; truncatedOld: boolean; ns: unknown[] } | null = null;
  const budgetMs = c.h.eventVolumeBudgetMs ?? VOLUME_BUDGET_MS;
  const sendFlood = async (): Promise<NonNullable<typeof flood>> => {
    const deadline = Date.now() + budgetMs;
    const cursorBefore = await head("free");
    c.w.portal.pause.instances.add(a.ins);
    try {
      if (!(await c.apply()).acked) return { problem: "the instance pause was not acknowledged" };
      const ph = await emit(a, [item({ n: 800 })]);
      if (ph) return { problem: ph };
      const total = RETENTION_ROWS + 100;
      for (let i = 0; i < total; i += 100) {
        if (Date.now() > deadline) return { problem: `the flood did not finish within its time budget of ${budgetMs} ms (${i} of ${total} events sent)`, budget: true };
        const batch = Array.from({ length: 100 }, (_, k) => item({ n: 100_000 + i + k }));
        const r = await post(b, batch, Math.max(1000, deadline - Date.now()));
        if ("problem" in r) return Date.now() > deadline ? { problem: `the flood did not finish within its time budget of ${budgetMs} ms: ${r.problem}`, budget: true } : { problem: `flood batch ${i / 100}: ${r.problem}` };
      }
      // the next poll, whatever the cursor, answers truncated for the removed held row
      const s = await sess("free");
      const { message } = await s.rpc(EVENT_MCP_METHODS.poll, { limit: 1, ...(cursorBefore ? { cursor: cursorBefore } : {}) });
      const r1 = isObj(message?.result) ? message.result : null;
      const truncatedAny = r1?.truncated === true;
      const old = await poll("free", cursorBefore, 100);
      if ("problem" in old) return { problem: old.problem };
      return { cursorBefore, heldN: 800, first: old.events, truncatedAny, truncatedOld: old.truncated, ns: old.events.map(nOf) };
    } finally {
      c.w.portal.pause.instances.delete(a.ins);
      await c.apply();
    }
  };
  const doFlood = async (): Promise<NonNullable<typeof flood>> => {
    flood ??= await sendFlood();
    return flood;
  };
  await run("B-EV-8", `app a paused; a emits one event (held); app b emits ${RETENTION_ROWS + 100} events to the free agent (retention 10 000 rows removes the oldest, the held one first) → the next poll answers truncated: true`, async () => {
    const f = await doFlood();
    if ("problem" in f) return f.budget ? notRun(f.problem) : bad(`the flood could not be sent: ${f.problem}`);
    return verdict(f.truncatedAny, f.truncatedAny ? "truncated: true after the held row was removed" : "no truncated: true after retention removed the held row");
  });

  await run("B-EV-9", "the before hook of app a on the read op enabled → conf.ping with a summary arrives WITHOUT summary; every hook switched off by the owner (a wildcard hook would strip it too) → with it", async () => {
    const f0 = await head("free");
    const hooksOn = c.w.hooksOn;
    c.w.hooksOn = true;
    c.w.hookState.delete(e.hookKey);
    try {
      if (!(await c.apply()).acked) return bad("enabling the hook was not acknowledged");
      const p1 = await emit(a, [item({ n: 901, summary: "Conformance summary" })]);
      if (p1) return bad(p1);
      await settle();
      // rule 6 applies at DELIVERY: read while the hook is on
      const d1 = await drain("free", f0);
      if ("problem" in d1) return bad(d1.problem);
      c.w.hookState.set(e.hookKey, "disabled");
      c.w.hooksOn = false;
      if (!(await c.apply()).acked) return bad("switching the hooks off was not acknowledged");
      const p2 = await emit(a, [item({ n: 902, summary: "Conformance summary" })]);
      if (p2) return bad(p2);
      await settle();
      const d2 = await drain("free", d1.cursor);
      if ("problem" in d2) return bad(d2.problem);
      ends.set("free", d2.cursor);
      const with1 = d1.events.find((x) => nOf(x) === 901);
      const with2 = d2.events.find((x) => nOf(x) === 902);
      if (!with1 || !with2) return bad(`events missing: hook on ${JSON.stringify(d1.events.map(nOf))}, hook off ${JSON.stringify(d2.events.map(nOf))}`);
      return verdict(with1.summary === undefined && with2.summary === "Conformance summary", `hook on: summary ${with1.summary === undefined ? "absent" : "PRESENT"}; hook off: summary ${with2.summary === undefined ? "MISSING" : "present"}`);
    } finally {
      c.w.hookState.set(e.hookKey, "disabled");
      c.w.hooksOn = hooksOn;
      await c.apply();
    }
  });

  await run("B-EV-10", "the app with product tb emits conf.ping → refused event_reserved", async () => {
    const r = await post(tb, [item({ n: 1001 })]);
    if ("problem" in r) return bad(r.problem);
    const x = r.results[0];
    return verdict(x?.status === "refused" && x.code === "event_reserved", `${x?.status} ${x?.code ?? ""}`);
  });

  await run("B-EV-11", "after the flood: a poll with the cursor from before it → truncated: true and the oldest KEPT rows follow in order (rows older than 7 days: not observable in a run)", async () => {
    const f = await doFlood();
    if ("problem" in f) return f.budget ? notRun(f.problem) : bad(`the flood could not be sent: ${f.problem}`);
    const ns = f.ns.filter((x): x is number => typeof x === "number" && x >= 100_000);
    const ascending = ns.every((x, i) => i === 0 || x > (ns[i - 1] as number));
    return verdict(f.truncatedOld && ns.length > 0 && (ns[0] as number) > 100_000 && ascending, `truncated ${f.truncatedOld}; first kept flood event n=${ns[0] ?? "none"} (the first ${ns[0] === undefined ? "?" : (ns[0] as number) - 100_000} removed), ascending ${ascending}`);
  });

  await run("B-EV-12", "app a: an undeclared name → event_undeclared; an app tb.* name → event_reserved; an invalid payload → event_payload_invalid; nothing reaches the free agent", async () => {
    const f0 = await head("free");
    const r = await post(a, [item({ name: "conf.undeclared", n: 1201 }), item({ name: "tb.conformance", n: 1202 }), item({ data: { n: "not an integer" } })]);
    if ("problem" in r) return bad(r.problem);
    const got = r.results.map((x) => `${x.status}${x.code ? ` ${x.code}` : ""}`);
    const want = ["refused event_undeclared", "refused event_reserved", "refused event_payload_invalid"];
    await settle();
    const d = await drain("free", f0);
    if ("problem" in d) return bad(d.problem);
    const stored = mine(d.events, a).length;
    return verdict(JSON.stringify(got) === JSON.stringify(want) && stored === 0, `${got.join("; ")}; delivered ${stored}`);
  });

  await run("B-EV-13", "the same item (same key) posted twice → stored, then duplicate; the free agent gets ONE event", async () => {
    const f0 = await head("free");
    const it = item({ n: 1301 });
    const r1 = await post(a, [it]);
    const r2 = await post(a, [it]);
    if ("problem" in r1) return bad(r1.problem);
    if ("problem" in r2) return bad(r2.problem);
    await settle();
    const d = await drain("free", f0);
    if ("problem" in d) return bad(d.problem);
    const n = d.events.filter((x) => nOf(x) === 1301).length;
    return verdict(r1.results[0]?.status === "stored" && r2.results[0]?.status === "duplicate" && n === 1, `${r1.results[0]?.status} then ${r2.results[0]?.status}; delivered ${n}×`);
  });

  await run("B-EV-14", "conf.scoped with eligible [bound] only → the bound agent gets it, the free agent (outside eligible) does not", async () => {
    const g = scopedGate();
    if (g) return g;
    const f0 = await head("free");
    const b0 = await head("bound");
    const p = await emit(a, [item({ name: "conf.scoped", n: 1401, instanceId: "conf-i14", eligible: [{ agent: agents.bound, authority: "bounded" }] })]);
    if (p) return bad(p);
    await settle();
    const f = await drain("free", f0);
    const bd = await drain("bound", b0);
    if ("problem" in f) return bad(f.problem);
    if ("problem" in bd) return bad(bd.problem);
    const toFree = f.events.some((x) => nOf(x) === 1401);
    const toBound = bd.events.some((x) => nOf(x) === 1401);
    return verdict(!toFree && toBound, `outside eligible: ${toFree ? "DELIVERED" : "nothing"}; in eligible: ${toBound ? "delivered" : "MISSING"}`);
  });

  await run("B-EV-15", "conf.scoped for instances i15a and i15b (eligible [free]) not yet read; purge {agent: free, instanceId: i15a} → the free agent's next poll has only the i15b event", async () => {
    const g = scopedGate();
    if (g) return g;
    const f0 = await head("free");
    const el = [{ agent: agents.free, authority: "bounded" }];
    const p = await emit(a, [item({ name: "conf.scoped", n: 1501, instanceId: "conf-i15a", eligible: el }), item({ name: "conf.scoped", n: 1502, instanceId: "conf-i15b", eligible: el })]);
    if (p) return bad(p);
    const r = await post(a, [{ kind: "purge", key: `purge-${ulid()}`, agent: agents.free, instanceId: "conf-i15a" }]);
    if ("problem" in r) return bad(r.problem);
    await settle();
    const d = await drain("free", f0);
    if ("problem" in d) return bad(d.problem);
    const ns = d.events.map(nOf);
    return verdict(!ns.includes(1501) && ns.includes(1502), `purge ${r.results[0]?.status}; after it: ${JSON.stringify(ns.filter((x) => x === 1501 || x === 1502))}`);
  });

  await run("B-EV-16", "conf.scoped for instance i16 (eligible [free, bound]) not yet read; purge {instanceId: i16} without agent → neither agent gets it", async () => {
    const g = scopedGate();
    if (g) return g;
    const f0 = await head("free");
    const b0 = await head("bound");
    const p = await emit(a, [item({ name: "conf.scoped", n: 1601, instanceId: "conf-i16", eligible: [{ agent: agents.free, authority: "bounded" }, { agent: agents.bound, authority: "bounded" }] })]);
    if (p) return bad(p);
    const r = await post(a, [{ kind: "purge", key: `purge-${ulid()}`, instanceId: "conf-i16" }]);
    if ("problem" in r) return bad(r.problem);
    await settle();
    const f = await drain("free", f0);
    const bd = await drain("bound", b0);
    if ("problem" in f) return bad(f.problem);
    if ("problem" in bd) return bad(bd.problem);
    const left = [...f.events, ...bd.events].filter((x) => nOf(x) === 1601).length;
    return verdict(left === 0, `purge ${r.results[0]?.status}; rows of i16 delivered after it: ${left}`);
  });

  await run("B-EV-17", "every StatusReport the fake Portal received in this run declares events, and every one of B-EV-1..16 PASSED (not_applicable or not_run counts as not passed)", async () => {
    const acks = c.w.portal.acks;
    const missing = acks.filter((x) => !declares(x)).length;
    const notPassed = ROWS.slice(0, -1)
      .map(([id]) => [id, results.get(id)] as const)
      .filter(([, o]) => !o || !(o.status === "pass" || (o.status === undefined && o.pass === true)))
      .map(([id, o]) => `${id} ${o?.status ?? (o?.pass === false ? "fail" : "missing")}`);
    if (missing > 0) return bad(`${missing} of ${acks.length} StatusReports of this run do not declare ${EVENTS_CAP} (a bridge declares it in EVERY report or never)`);
    if (notPassed.length === 0) return ok(`all ${acks.length} StatusReports declare ${EVENTS_CAP}; B-EV-1..16 all passed`);
    // CONFORMANCE v0.1.57: when ONLY volume rows did not RUN within their budget, the certifying row is not_run (never a fail of a
    // compliant but slow bridge, never a pass)
    const onlyVolumeNotRun = ROWS.slice(0, -1).every(([id]) => {
      const o = results.get(id);
      const passed = !!o && (o.status === "pass" || (o.status === undefined && o.pass === true));
      return passed || (VOLUME_ROWS.has(id) && o?.status === "not_run");
    });
    if (onlyVolumeNotRun) return notRun(`only the volume rows did not run within their time budget (${notPassed.join(", ")}): the cap is neither certified nor refused`);
    return bad(`the bridge declares ${EVENTS_CAP} but these rows did not pass: ${notPassed.join(", ")}`);
  });
  await c.run("B-EV-18", EVENT_CHECK_TITLES["B-EV-18"] as string, "a bridge WITHOUT the cap answers tealbrick/events/* with -32601", () => na(`the bridge declares the ${EVENTS_CAP} capability: the no-cap row does not apply`));
}
