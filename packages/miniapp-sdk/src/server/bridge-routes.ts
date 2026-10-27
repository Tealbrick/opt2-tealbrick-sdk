// Grantless bridge→app routes (SDK-API §3.2): hook calls (`verifyHookProof`) and the bridge ops catalog, resolve,
// mark, scope-summary (`verifyBridgeOpProof`, C16 B5). No receipts, no hooks, no agent action.
import type { IncomingMessage, ServerResponse } from "node:http";
import { bridgeOpBinding, digest, hookCallerRef, hookResponseProblem, mcpToolName, recipientSpecsProblem, sha256Bytes, toolNameFits, verifyBridgeOpProof, verifyHookProof } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type HookRequest, type ScopeSummaryResult } from "@opt2-tealbrick/spec/bridge";
import type { BridgeOp } from "@opt2-tealbrick/spec/credentials";
import { type DynamicCatalogEntry, EFFECTS, HOOK_PHASES, type Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, TrustContext } from "@opt2-tealbrick/spec/sdk";
import type { SdkHookContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { header, readJson, readRaw, requestId, sendError, sendJson } from "./http.ts";
import { withinCeiling } from "./ops.ts";
import type { Runtime } from "./runtime.ts";
import type { ScopeSourceItem } from "./scopes.ts";

/** QA sdk#50: the bridge reads a bridge-op answer up to 256 KiB; the scope summary stays below this. */
export const SCOPE_SUMMARY_MAX_BYTES = 192 * 1024;

/**
 * Keeps a `scope_summary` answer under SCOPE_SUMMARY_MAX_BYTES (many agents × 20 sources could pass the bridge's read cap):
 * `sources` are display only, so they go first, from the last agent backwards; a dropped member is ABSENT (not reported), never
 * `[]` (which says "nothing assigned"). Labels and `admittedOps` (which decide what tools/list shows) stay.
 */
export function boundScopeSummary<T extends { sources?: unknown[] }>(rows: T[], maxBytes = SCOPE_SUMMARY_MAX_BYTES): T[] {
  let size = Buffer.byteLength(JSON.stringify(rows), "utf8");
  if (size <= maxBytes) return rows;
  const out = rows.map((r) => ({ ...r }));
  for (let i = out.length - 1; i >= 0 && size > maxBytes; i--) {
    const row = out[i] as T;
    if (!row.sources?.length) continue;
    size -= Buffer.byteLength(JSON.stringify({ sources: row.sources }), "utf8") - 2;
    delete row.sources;
  }
  return out;
}

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
  return { log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n), modelRole: (r) => rt.keys.modelRole(r), signal: AbortSignal.timeout(timeoutMs), secrets: rt.secretsStore };
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
/** The hook body: the raw bytes parsed once. Empty or not JSON → 400 `input_invalid` (the digest was taken from the same bytes). */
function parseHookBody(raw: Buffer): unknown {
  if (raw.length === 0) throw new TbError("input_invalid", "hook body is empty", 400);
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new TbError("input_invalid", "body is not JSON", 400);
  }
}

// ── POST /tb/v1/hooks/:hookId ────────────────────────────────────────────────
export async function handleHook(rt: Runtime, req: IncomingMessage, res: ServerResponse, hookId: string): Promise<void> {
  const rid = requestId();
  try {
    const trust = ready(rt);
    // v0.1.36 (C268 B/C268c, spec 0.1.52): read the RAW bytes, hash them BEFORE parsing (a proof's `bd` = sha256 of exactly these
    // bytes), then parse the SAME bytes: the handler gets the object the digest covers. An empty or non-JSON body is refused 400.
    const raw = await readRaw(req);
    const bodyDigest = sha256Bytes(raw);
    const body = parseHookBody(raw);
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
        // v0.1.36 (C268 B): when the proof carries `bd`, it must equal the digest of the raw body received; absent = not compared
        bodyDigest,
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
        // spec 0.1.81 (unreleased label; C373, G-6): recipient PLACES of this tool (pointers into the call's arguments) pass through
        // only on an outward resolution and only in the M-OP-14 shape; anything else is dropped with a warning (absent = unknown, so
        // a policy fails closed). Never a value: a resolution is per tool and the bridge caches it. Read structurally until the
        // spec pin types `DynamicResolution.recipients`.
        const places = (r as { recipients?: unknown }).recipients;
        const keep = places !== undefined && r.effect === "outward" && recipientSpecsProblem(places) === null;
        if (places !== undefined && !keep) rt.log.warn("dynamic resolution recipients dropped", { op: op.id, tool: body.tool });
        return sendJson(res, 200, { tool: body.tool, crud: r.crud, effect: r.effect, ...(r.holdFamily ? { holdFamily: r.holdFamily } : {}), ...(keep ? { recipients: places as Json } : {}) });
      }
      case "mark": {
        if (typeof body.call !== "string" || body.mark !== "after_failed") throw new TbError("input_invalid", "body must be { call, mark: after_failed }", 400);
        const rec = rt.receipts.byCall(body.call);
        if (rec) rt.receipts.finish(rec.id, "after_failed");
        return sendJson(res, 200, { ok: true, marked: rec !== null });
      }
      case "scope_summary": {
        const out: (ScopeSummaryResult & { sources: ScopeSourceItem[] })[] = [];
        // v0.1.35 (C283 A1): `admittedOps` = this agent's STATIC agent ops with a scopeType whose crud its OWNER rows admit (possibly
        // above the Portal grant); absent when none. Display only: the SDK still authorizes every call.
        const staticOps = rt.manifest.operations.filter((o) => !o.dynamic && o.audience === "agent" && o.scopeType !== undefined);
        for (const a of rt.trust.slice?.agents ?? []) {
          const admittedOps = markable(rt, a.id) ? staticOps.filter((o) => o.scopeType !== undefined && rt.scopes.ownerAdmits(a.id, o.scopeType, o.crud)).map((o) => o.id) : [];
          // spec 0.1.65 (C331 D8): the agent's scope instances for the canvas (display only)
          out.push({ agent: a.id, label: await rt.scopes.summary(a.id), ...(admittedOps.length > 0 ? { admittedOps } : {}), sources: await rt.scopes.sources(a.id) });
        }
        return sendJson(res, 200, boundScopeSummary(out));
      }
    }
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : new TbError("app_error", "bridge op failed", 500));
  }
}
