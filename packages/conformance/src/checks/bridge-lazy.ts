// B30 (conformance 0.1.30, spec 0.1.73, BRIDGE §7.5, MANIFEST §5.5): lazy tools on a bridge that DECLARES `lazy_tools`. Gated by
// the capability in the bridge's StatusReport (`bridge.caps`), never by version (C292): without it every row is not_applicable.
// The suite lists its lazy-tools app (bridge-world.ts `lazyManifest`) only for this group: a bridge without the cap refuses a
// manifest with `listing: "lazy"` at claim. Grants: the free agent read/create/update (Free), the bound agent every action but
// wf = [hot, find] (Bound), the none agent nothing.
import { TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
import { LAZY_FIND_WORD, LAZY_HOOK_ID, LAZY_OPS } from "../bridge-world.ts";
import type { FakeApp } from "../fake-app.ts";
import type { ToolCallResult } from "../mcp-agent.ts";
import { bad, na, notRun, type Outcome, ok, verdict } from "../suite.ts";
import { reportedBridgeCaps } from "./bridge.ts";
import { type BridgeCtx, describeCall, isObj, toolRefused } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

export const LAZY_CAP = "lazy_tools";
/** spec 0.1.73 TOOL_NAME_RULE.moreSearchOp / moreCallOp; the suite pins spec 0.1.57 until its pin bump (then the fallback goes) */
const RULE = TOOL_NAME_RULE as typeof TOOL_NAME_RULE & { moreSearchOp?: string; moreCallOp?: string };
export const MORE_SEARCH_OP = RULE.moreSearchOp ?? "tb_more_search";
export const MORE_CALL_OP = RULE.moreCallOp ?? "tb_more_call";

const ROWS: [string, string][] = (BRIDGE_GROUPS.lazy ?? []).map((x) => [x.id, x.title]);
const SECTION = "BRIDGE §7.5";

type Hit = { tool?: unknown; title?: unknown; description?: unknown; inputSchema?: unknown; effect?: unknown };
const hits = (r: ToolCallResult): Hit[] | null => (r.structured && Array.isArray(r.structured.tools) ? (r.structured.tools as Hit[]) : null);

export async function lazyChecks(c: BridgeCtx): Promise<void> {
  const caps = reportedBridgeCaps(c);
  if (!caps.includes(LAZY_CAP)) {
    const why = `the bridge does not declare the ${LAZY_CAP} capability in its StatusReport (bridge.caps = ${JSON.stringify(caps)}): ${SECTION} is not announced, so this row does not apply (decided by capability, never by version, C292)`;
    for (const [id, title] of ROWS) await c.run(id, title, SECTION, () => na(why));
    return;
  }
  const app = c.w.lazyApp;
  if (!app) {
    for (const [id, title] of ROWS) await c.run(id, title, SECTION, () => notRun("the suite's manifest validator refuses listing \"lazy\" (it pins a spec before 0.1.73): no lazy-tools app"));
    return;
  }
  const specsBefore = [...c.w.grantSpecs];
  c.w.lazyAppListed = true;
  c.w.grantSpecs.push(
    { role: "free", app, crud: ["read", "create", "update"], mode: "free", wf: [] },
    { role: "bound", app, crud: ["read", "create", "update", "delete"], mode: "bound", wf: [LAZY_OPS.hot, LAZY_OPS.find] },
    // QA-SDK47D-2: the agent without grants gets, for this group only, a Bound grant that reaches a read, a destructive and a
    // money op and NO outward op, so openWorldHint can only come from money and destructiveHint from the destructive op
    { role: "none", app, crud: ["read", "create", "update", "delete"], mode: "bound", wf: [LAZY_OPS.find, LAZY_OPS.drop, LAZY_OPS.pay] },
  );
  // the fake app holds `send` (202 held) and answers every other op ok
  const prevOnOp = app.onOp;
  app.onOp = async (info) =>
    info.op === LAZY_OPS.send
      ? { status: 202, body: { status: "held", holdId: "hld_conformance_lazy", expiresAt: new Date(Date.now() + 900_000).toISOString() } }
      : { status: 200, body: { status: "ok", output: { op: info.op } } };
  try {
    const applied = await c.apply();
    if (!applied.acked) {
      for (const [id, title] of ROWS) await c.run(id, title, SECTION, () => bad(`the config listing the lazy-tools app (rev ${applied.rev}) was not acknowledged`));
      return;
    }
    c.dropSessions();
    await rows(c, app);
  } finally {
    app.onOp = prevOnOp;
    c.w.lazyAppListed = false;
    c.w.grantSpecs = specsBefore;
    await c.apply().catch(() => undefined);
    c.dropSessions();
  }
}

async function rows(c: BridgeCtx, app: FakeApp): Promise<void> {
  const p = app.product;
  const name = (op: string) => `${p}${TOOL_NAME_RULE.separator}${op}`;
  const SEARCH = name(MORE_SEARCH_OP);
  const CALL = name(MORE_CALL_OP);
  const visibleLazy = [LAZY_OPS.find, LAZY_OPS.make, LAZY_OPS.send].map(name).sort();
  const title = (id: string) => ROWS.find(([x]) => x === id)?.[1] ?? id;
  const ops = (seq: number, op?: string) => c.since(app, seq, "op").filter((r) => op === undefined || r.name === op);

  await c.run("B30.lazy_hidden", title("B30.lazy_hidden"), "free agent tools/list: the hot op and the pair, none of the lazy ops", async () => {
    const names = await (await c.session("free")).listTools();
    if (!names) return bad("tools/list answered no tool array");
    const mine = names.filter((n) => n.startsWith(`${p}${TOOL_NAME_RULE.separator}`));
    const missing = [name(LAZY_OPS.hot), SEARCH, CALL].filter((n) => !mine.includes(n));
    const leaked = [...visibleLazy, name(LAZY_OPS.drop)].filter((n) => mine.includes(n));
    return verdict(missing.length === 0 && leaked.length === 0, `listed ${JSON.stringify(mine)}; missing ${JSON.stringify(missing)}; lazy ops listed ${JSON.stringify(leaked)}`);
  });

  await c.run("B30.lazy_annotations", title("B30.lazy_annotations"), `${MORE_CALL_OP} = the widest over the ops THIS agent reaches through it, lazy and listed: bound (hot outward + find read) and free → readOnlyHint false, destructiveHint false, openWorldHint true; none (Bound: find read + drop destructive + pay money) → destructiveHint true, openWorldHint true; ${MORE_SEARCH_OP} readOnlyHint true`, async () => {
    const wants = {
      bound: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
      free: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
      none: { readOnlyHint: false, destructiveHint: true, openWorldHint: true },
    } as const;
    const out: string[] = [];
    let pass = true;
    for (const slot of ["bound", "free", "none"] as const) {
      const want = wants[slot];
      const { message } = await (await c.session(slot)).rpc("tools/list");
      const tools = isObj(message?.result) && Array.isArray(message.result.tools) ? (message.result.tools as { name?: unknown; annotations?: Record<string, unknown> }[]) : [];
      const a = tools.find((t) => t.name === CALL)?.annotations ?? null;
      const sa = tools.find((t) => t.name === SEARCH)?.annotations ?? null;
      const got = a ? { readOnlyHint: a.readOnlyHint === true, destructiveHint: a.destructiveHint === true, openWorldHint: a.openWorldHint === true } : null;
      const okCall = got !== null && JSON.stringify(got) === JSON.stringify(want);
      const okSearch = sa?.readOnlyHint === true;
      pass &&= okCall && okSearch;
      out.push(`${slot}: ${CALL} ${JSON.stringify(a)} (expected ${JSON.stringify(want)}), ${SEARCH} ${JSON.stringify(sa)}`);
    }
    return verdict(pass, `${out.join("; ")} — lazy ops alone would give bound readOnlyHint true; "none" reaches destructive + money and no outward op`);
  });

  await c.run("B30.lazy_search", title("B30.lazy_search"), `"*" → exactly the visible lazy ops {tool, title, description, inputSchema, effect} + total; "${LAZY_FIND_WORD}" ranks ${LAZY_OPS.find} first; the app receives nothing`, async () => {
    const seq = c.w.seqNow();
    const all = await c.callTool("free", SEARCH, { query: "*" });
    const h = hits(all);
    if (!c.isOk(all) || !h) return bad(`"*": ${describeCall(all)}`);
    const got = h.map((x) => String(x.tool)).sort();
    if (JSON.stringify(got) !== JSON.stringify(visibleLazy)) return bad(`"*" returned ${JSON.stringify(got)}, expected ${JSON.stringify(visibleLazy)}`);
    if (all.structured?.total !== visibleLazy.length) return bad(`total ${JSON.stringify(all.structured?.total)}, expected ${visibleLazy.length}`);
    const shape = h.every((x) => typeof x.title === "string" && typeof x.description === "string" && isObj(x.inputSchema) && typeof x.effect === "string");
    if (!shape) return bad(`a hit lacks title / description / inputSchema / effect: ${JSON.stringify(h).slice(0, 200)}`);
    const one = await c.callTool("free", SEARCH, { query: LAZY_FIND_WORD, limit: 1 });
    const first = hits(one)?.[0]?.tool;
    if (first !== name(LAZY_OPS.find)) return bad(`"${LAZY_FIND_WORD}" first hit ${JSON.stringify(first)} (${describeCall(one)})`);
    const seen = c.since(app, seq).filter((r) => r.kind === "op" || r.kind === "bridge_op" || r.kind === "hook");
    if (seen.length) return bad(`the app received ${seen.map((r) => `${r.kind} ${r.name}`).join(", ")} for a search`);
    return ok(`"*" → ${got.join(", ")} (total ${visibleLazy.length}); "${LAZY_FIND_WORD}" → ${String(first)}; no app request`);
  });

  await c.run("B30.lazy_grant", title("B30.lazy_grant"), `free agent: ${LAZY_OPS.drop} (delete, above the grant) via ${MORE_CALL_OP} and by name → unknown_tool; bound agent (wf = [hot, find]): "*" → only ${LAZY_OPS.find}, ${LAZY_OPS.make} via ${MORE_CALL_OP} → unknown_tool; the app sees nothing`, async () => {
    const seq = c.w.seqNow();
    const viaCall = await c.callTool("free", CALL, { tool: name(LAZY_OPS.drop), arguments: {} });
    const direct = await c.callTool("free", name(LAZY_OPS.drop), {});
    const r1 = toolRefused(viaCall, ["unknown_tool"]);
    const r2 = toolRefused(direct, ["unknown_tool"]);
    const boundAll = hits(await c.callTool("bound", SEARCH, { query: "*" }))?.map((h) => String(h.tool)) ?? null;
    const boundOk = JSON.stringify(boundAll) === JSON.stringify([name(LAZY_OPS.find)]);
    const boundCall = await c.callTool("bound", CALL, { tool: name(LAZY_OPS.make), arguments: { title: "x" } });
    const r3 = toolRefused(boundCall, ["unknown_tool"]);
    const reached = ops(seq);
    return verdict(
      !!r1.pass && !!r2.pass && !!r3.pass && boundOk && reached.length === 0,
      `free via call ${r1.asserted}; free by name ${r2.asserted}; bound "*" ${JSON.stringify(boundAll)}; bound ${LAZY_OPS.make} via call ${r3.asserted}; ops at the app ${reached.length}`,
    );
  });

  await c.run("B30.lazy_call_same_route", title("B30.lazy_call_same_route"), `${LAZY_OPS.make} via ${MORE_CALL_OP} = direct: verified op proof for the op, input = arguments, the hook names the op, equal derived keys; ${LAZY_OPS.send} → held handle; invalid arguments → input_invalid`, async () => {
    const seq = c.w.seqNow();
    const args = { title: "conformance lazy" };
    const via = await c.callTool("free", CALL, { tool: name(LAZY_OPS.make), arguments: args });
    const direct = await c.callTool("free", name(LAZY_OPS.make), args);
    if (!c.isOk(via) || !c.isOk(direct)) return bad(`via ${describeCall(via)}; direct ${describeCall(direct)}`);
    const got = ops(seq, LAZY_OPS.make);
    if (got.length !== 2 || !got.every((r) => r.verified)) return bad(`the app received ${got.length} verified ${LAZY_OPS.make} calls (expected 2): ${got.map((r) => r.reason || "ok").join("; ")}`);
    const bodies = got.map((r) => JSON.parse(r.body) as { input?: unknown; idempotencyKey?: unknown });
    if (JSON.stringify(bodies[0]?.input) !== JSON.stringify(args)) return bad(`input via ${MORE_CALL_OP} = ${JSON.stringify(bodies[0]?.input)}, expected the arguments ${JSON.stringify(args)}`);
    if (typeof bodies[0]?.idempotencyKey !== "string" || bodies[0]?.idempotencyKey !== bodies[1]?.idempotencyKey) return bad(`derived keys differ: ${JSON.stringify(bodies.map((b) => b.idempotencyKey))} (the app could not deduplicate the two paths)`);
    if (got.some((r) => r.proof?.op !== LAZY_OPS.make)) return bad(`proof op ${JSON.stringify(got.map((r) => r.proof?.op))}`);
    const hooks = c.since(app, seq, "hook").filter((r) => r.name === LAZY_HOOK_ID);
    if (hooks.length < 2 || hooks.some((r) => !r.body.includes(LAZY_OPS.make) || r.body.includes(MORE_CALL_OP))) return bad(`the before hook saw ${hooks.length} calls; envelopes ${hooks.map((r) => r.body.slice(0, 80)).join(" | ")}`);
    const held = await c.callTool("free", CALL, { tool: name(LAZY_OPS.send), arguments: {} });
    const s = held.structured ?? {};
    if (held.isError || s.status !== "held" || s.checkWith !== name(TOOL_NAME_RULE.holdStatusOp)) return bad(`${LAZY_OPS.send} via ${MORE_CALL_OP}: ${describeCall(held)}`);
    const before = ops(seq).length;
    const invalid = await c.callTool("free", CALL, { tool: name(LAZY_OPS.make), arguments: {} });
    const r = toolRefused(invalid, ["input_invalid"]);
    if (!r.pass || ops(seq).length !== before) return bad(`invalid arguments: ${r.asserted}; reached the app ${ops(seq).length - before}`);
    return ok(`2 verified ${LAZY_OPS.make} calls, equal keys, hook envelopes name the op; held → checkWith ${String(s.checkWith)}; invalid → ${r.asserted}`);
  });

  await c.run("B30.lazy_unknown", title("B30.lazy_unknown"), `${MORE_CALL_OP} with an unknown op, another product's op, a standard op, the pair itself → unknown_tool; the app sees nothing`, async () => {
    const seq = c.w.seqNow();
    const other = c.readOp(c.primary);
    const names = ["conf_lazy_nope", name("conf_lazy_nope"), ...(other ? [c.tool(c.primary, other.id)] : []), TOOL_NAME_RULE.holdStatusOp, name(TOOL_NAME_RULE.holdStatusOp), SEARCH, CALL];
    const out: string[] = [];
    let pass = true;
    for (const tool of names) {
      const r = toolRefused(await c.callTool("free", CALL, { tool, arguments: {} }), ["unknown_tool"]);
      pass &&= !!r.pass;
      out.push(`${tool}: ${r.asserted}`);
    }
    const reached = c.everyApp(seq, "op").length + ops(seq).length;
    return verdict(pass && reached === 0, `${out.join("; ")}; ops at apps ${reached}`);
  });

  await c.run("B30.lazy_hot_and_direct", title("B30.lazy_hot_and_direct"), `the listed ${LAZY_OPS.hot} via ${MORE_CALL_OP} → ok (decision: allowed); ${LAZY_OPS.find} by its own name → ok`, async (): Promise<Outcome> => {
    const seq = c.w.seqNow();
    const hot = await c.callTool("free", CALL, { tool: LAZY_OPS.hot, arguments: {} });
    const direct = await c.callTool("free", name(LAZY_OPS.find), {});
    const a = ops(seq, LAZY_OPS.hot).filter((r) => r.verified).length;
    const b = ops(seq, LAZY_OPS.find).filter((r) => r.verified).length;
    return verdict(c.isOk(hot) && c.isOk(direct) && a === 1 && b === 1, `hot via call ${describeCall(hot)} (app ${a}); lazy by name ${describeCall(direct)} (app ${b})`);
  });
}
