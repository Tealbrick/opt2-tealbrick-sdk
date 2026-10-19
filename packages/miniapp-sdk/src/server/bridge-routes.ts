// Grantless bridge→app routes (SDK-API §3.2): hook calls (`verifyHookProof`) and the bridge ops catalog, resolve,
// mark, scope-summary (`verifyBridgeOpProof`, C16 B5). No receipts, no hooks, no agent action.
import type { IncomingMessage, ServerResponse } from "node:http";
import { bridgeOpBinding, digest, hookCallerRef, hookResponseProblem, mcpToolName, toolNameFits, verifyBridgeOpProof, verifyHookProof } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type HookRequest, type ScopeSummaryResult } from "@opt2-tealbrick/spec/bridge";
import type { BridgeOp } from "@opt2-tealbrick/spec/credentials";
import { type DynamicCatalogEntry, EFFECTS, HOOK_PHASES, type Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, TrustContext } from "@opt2-tealbrick/spec/sdk";
import type { SdkHookContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { header, readJson, requestId, sendError, sendJson } from "./http.ts";
import { withinCeiling } from "./ops.ts";
import type { Runtime } from "./runtime.ts";

const HOOK_DEFAULT_TIMEOUT_MS = 2000;
const CATALOG_LIST_MAX = 256;
const ENTRY_NAME_RE = /^[a-z][a-z0-9_]{1,47}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function ready(rt: Runtime): TrustContext {
  if (rt.cfg.standalone) throw new TbError("no_bridge", "app-alone mode serves persons only", 503);
  const now = Date.now();
  if (rt.trust.stale(now)) throw new TbError("slice_stale", "instance slice missing or older than 12 h", 503);
  const ctx = rt.trust.context(now);
  if (!ctx) throw new TbError("slice_stale", "no instance slice", 503);
  return ctx;
}

function hookContext(rt: Runtime, timeoutMs: number): SdkHookContext {
  return { log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n), signal: AbortSignal.timeout(timeoutMs), secrets: rt.secretsStore };
}

async function withTimeout<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(new TbError("hook_failed", "handler timed out", 504)), { once: true })),
  ]);
}

// The phase's answer shape is the ONE shared rule (manifest `hookResponseProblem`, L1): before {allow, reason?, hold?}
// (v0.1.13 G1 hold verdict), context keys `<product>.` and never `tb.*`, after {output?, redactions?}. The SDK used its
// own key list until 0.1.16 and turned every `hold` answer into hook_failed (samples v0.2.0 finding).
// ── POST /tb/v1/hooks/:hookId ────────────────────────────────────────────────
export async function handleHook(rt: Runtime, req: IncomingMessage, res: ServerResponse, hookId: string): Promise<void> {
  const rid = requestId();
  try {
    const trust = ready(rt);
    const body = await readJson(req);
    const hook = rt.manifest.hooks?.find((h) => h.id === hookId);
    const handler = rt.def.hooks?.[hookId];
    if (!hook || !handler) throw new TbError("unknown_hook", `hook not declared: ${hookId}`, 404);
    if (!isObj(body) || !HOOK_PHASES.includes(body.phase as never) || !isObj(body.call) || !isObj(body.context)) throw new TbError("input_invalid", "body must be a HookRequest", 400);
    const r = body as unknown as HookRequest;
    const proof = verifyHookProof(
      header(req, BRIDGE_HEADERS.callProof) ?? "",
      trust,
      {
        hook: hookId,
        phase: hook.phase,
        contextDigest: digest(r.context as Json),
        ...(r.call.input !== undefined ? { inputDigest: digest(r.call.input as Json) } : {}),
        // v0.1.35 (C268 A): the proof names the caller (`sub`) and the call (`call`) the bridge signed for; the body must name the
        // SAME caller and call id, else 401 call_proof_invalid. A body without a usable caller ref or call id binds "" and never matches.
        sub: hookCallerRef((r.call as { caller?: unknown }).caller),
        call: typeof r.call.id === "string" ? r.call.id : "",
      },
      rt.replay,
    );
    if (!proof.ok) throw new TbError("call_proof_invalid", "hook call proof missing or not valid", 401);
    if (r.phase !== hook.phase) throw new TbError("input_invalid", "phase does not match the declared hook", 400);
    const ctx = hookContext(rt, hook.timeoutMs ?? HOOK_DEFAULT_TIMEOUT_MS);
    const out = (await withTimeout(handler(r, ctx), ctx.signal)) as unknown;
    const problem = hookResponseProblem(r.phase, out, rt.product);
    if (problem) throw new TbError("hook_failed", problem, 500);
    sendJson(res, 200, out);
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : new TbError("hook_failed", "hook failed", 500));
  }
}

// ── POST /tb/v1/bridge/<bop> ─────────────────────────────────────────────────
function dynamicOp(rt: Runtime, opId: unknown): Operation {
  const op = rt.manifest.operations.find((o) => o.id === opId);
  if (!op?.dynamic) throw new TbError("unknown_tool", "not a dynamic operation", 404);
  return op;
}

function entryValid(rt: Runtime, op: Operation, e: DynamicCatalogEntry): boolean {
  return (
    ENTRY_NAME_RE.test(e.name) &&
    toolNameFits(mcpToolName(rt.product, e.name)) &&
    !rt.manifest.operations.some((o) => o.id === e.name) &&
    EFFECTS.includes(e.effect) &&
    withinCeiling(op, e) &&
    isObj(e.inputSchema) &&
    e.inputSchema.type === "object"
  );
}

/**
 * v0.1.35 (C283 A1): may the DISPLAY marks (`admitted`, `admittedOps`) be given for `agentId`? Only an agent that is in the verified
 * slice, active, and not paused (workspace, this app, itself): an owner row never revives a paused or removed agent, not even on a list.
 */
function markable(rt: Runtime, agentId: string): boolean {
  const a = rt.trust.agent(agentId);
  if (a?.status !== "active") return false;
  const p = rt.trust.paused(agentId);
  return !p.workspace && !p.instance && !p.agent;
}

export async function handleBridgeOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, bop: BridgeOp): Promise<void> {
  const rid = requestId();
  try {
    const trust = ready(rt);
    const body = await readJson(req);
    if (!isObj(body)) throw new TbError("input_invalid", "body must be an object", 400);
    // THE binding rule (SDK-API §3.2, C91), shared with the bridge and conformance: catalog {op}, resolve {op, in},
    // mark {in}, scope_summary {}.
    const proof = verifyBridgeOpProof(header(req, BRIDGE_HEADERS.callProof) ?? "", trust, bridgeOpBinding(bop, body as Json), rt.replay);
    if (!proof.ok) throw new TbError("call_proof_invalid", "bridge-op proof missing or not valid", 401);
    switch (bop) {
      case "catalog": {
        const op = dynamicOp(rt, body.op);
        const d = rt.def.dynamic?.[op.id];
        if (!d) throw new TbError("unknown_tool", "no dynamic handler", 404);
        const limit = typeof body.limit === "number" ? Math.max(1, Math.min(CATALOG_LIST_MAX, Math.trunc(body.limit))) : undefined;
        const query = typeof body.query === "string" ? { query: body.query, ...(limit ? { limit } : {}) } : null;
        const entries = await d.catalog(query, hookContext(rt, 5000));
        const valid = entries.filter((e) => {
          const ok = entryValid(rt, op, e);
          if (!ok) rt.log.warn("dynamic catalog entry dropped", { op: op.id, name: String(e?.name) });
          return ok;
        });
        const max = op.dynamic?.mode === "list" ? CATALOG_LIST_MAX : (limit ?? CATALOG_LIST_MAX);
        // v0.1.35 (C283 A1, spec 0.1.50): `admitted` is set by the SDK ALONE. A value the app's own catalog put on an entry is dropped
        // (display only, but an app must not list its own entries above the Portal grant), then an entry is marked "owner" iff the body's
        // `agent` has OWNER rows for the op's scope type that admit the entry's crud (every row an owner row, best row's crud).
        const agent = typeof body.agent === "string" && op.scopeType !== undefined && markable(rt, body.agent) ? body.agent : null;
        const out = valid.slice(0, max).map((e): DynamicCatalogEntry => {
          const { admitted: _dropped, ...entry } = e;
          return agent !== null && op.scopeType !== undefined && rt.scopes.ownerAdmits(agent, op.scopeType, entry.crud) ? { ...entry, admitted: "owner" } : entry;
        });
        return sendJson(res, 200, out);
      }
      case "resolve": {
        const op = dynamicOp(rt, body.op);
        const d = rt.def.dynamic?.[op.id];
        if (typeof body.tool !== "string" || !d) throw new TbError("input_invalid", "body must be { op, tool }", 400);
        const r = await d.resolve(body.tool, hookContext(rt, 2000));
        if (!r) throw new TbError("dynamic_resolve_failed", "unknown dynamic tool", 404);
        if (!withinCeiling(op, r)) throw new TbError("dynamic_ceiling_exceeded", "resolved tool exceeds the operation's ceiling", 403);
        return sendJson(res, 200, { tool: body.tool, crud: r.crud, effect: r.effect, ...(r.holdFamily ? { holdFamily: r.holdFamily } : {}) });
      }
      case "mark": {
        if (typeof body.call !== "string" || body.mark !== "after_failed") throw new TbError("input_invalid", "body must be { call, mark: after_failed }", 400);
        const rec = rt.receipts.byCall(body.call);
        if (rec) rt.receipts.finish(rec.id, "after_failed");
        return sendJson(res, 200, { ok: true, marked: rec !== null });
      }
      case "scope_summary": {
        const out: ScopeSummaryResult[] = [];
        // v0.1.35 (C283 A1): `admittedOps` = this agent's STATIC agent ops with a scopeType whose crud its OWNER rows admit (possibly
        // above the Portal grant); absent when none. Display only: the SDK still authorizes every call.
        const staticOps = rt.manifest.operations.filter((o) => !o.dynamic && o.audience === "agent" && o.scopeType !== undefined);
        for (const a of rt.trust.slice?.agents ?? []) {
          const admittedOps = markable(rt, a.id) ? staticOps.filter((o) => o.scopeType !== undefined && rt.scopes.ownerAdmits(a.id, o.scopeType, o.crud)).map((o) => o.id) : [];
          out.push({ agent: a.id, label: await rt.scopes.summary(a.id), ...(admittedOps.length > 0 ? { admittedOps } : {}) });
        }
        return sendJson(res, 200, out);
      }
    }
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : new TbError("app_error", "bridge op failed", 500));
  }
}
