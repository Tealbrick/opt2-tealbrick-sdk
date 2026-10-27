// Operation pipeline (SDK-API §3.2, §4, §6): bridge-forwarded agent/app calls on /tb/v1/ops/:op and person calls on
// /a/<product>/tb/v1/ops/:op. Order on /tb/v1/ops: call proof → verifyGrant → op/audience → input schema → idempotency
// → authorize() (step 0 = slice pause) → handler. Holds and receipts are rows of the one receipts table.
import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { authorize, CALLER_CONTEXT_MAX_BYTES, canonicalize, DECISION_REASON, digest, EFFECTS, HOLDS_PENDING_OP, opInGrantWorkflow, validateAgainstSchema, validateInput, verifyCallProof, verifyGrant } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type CompanionCaller, type OpCallBody, type OpResult } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, CallId, InstanceId, PersonId, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, DynamicResolution, Effect, HoldFamily, Operation } from "@opt2-tealbrick/spec/manifest";
import type {
  AuthorizeInput,
  Caller,
  Decision,
  HandlerSpec,
  HoldDecideInput,
  HoldsPendingItem,
  HoldsPendingOutput,
  Json,
  OpContext,
  OperationView,
  PersonPrincipal,
  Receipt,
  ReceiptStatus,
  ScopeAccessView,
  ScopeGrantApi,
  StandardOpId,
  VerifiedGrant,
} from "@opt2-tealbrick/spec/sdk";
import type { ContextExtras, SdkHookContext, SdkOpContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { header, readJson, requestId, sendError, sendJson } from "./http.ts";
import { type ClaimedJob, jobsView, type OpFireOutcome, unsealGrant } from "./jobs.ts";
import { HOLD_TTL_MS, type NewReceipt, type Receipts } from "./receipts.ts";
import type { Runtime } from "./runtime.ts";
import { scopeGrantOps } from "./scopes.ts";
import { resolveCallerProduct } from "./trust.ts";

export const OP_TIMEOUT_MS = 30_000;
const SUMMARY_MAX = 280;
const META_MAX_BYTES = 4096;
const HOLD_VIEW_MAX = 16_000;
const IDEM_KEY_RE = /^[\x21-\x7e]{8,128}$/;
const IDEM_PURPOSE = "idempotency";
/** v0.1.23 (SDK-HV-1, SDK-API §4.6): time budget of a dynamic op's async `holdView`. */
export const HOLD_VIEW_BUDGET_MS = 5_000;
/** v0.1.23: the line the owner sees when the app could not read the content of a held dynamic call. */
export const HOLD_VIEW_UNREADABLE = "Tealbrick could not read the content of this request.";

type ManifestOp = Operation & { standard: false };
interface EffectiveOp {
  id: string;
  crud: CrudAction[];
  effect: Effect;
  holdFamily?: HoldFamily;
  scopeType?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const iso = (ms: number) => new Date(ms).toISOString();

/**
 * Unverified read of a compact JWS payload. Used ONLY to pick binding values (the grant `jti`/`sub` that the call proof
 * must name, the companion grant for a product); every token is verified by `@opt2-tealbrick/manifest` before trust.
 */
export function peekClaims(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part || part.length > 16384) return null;
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

/**
 * v0.1.35 (C261, spec 0.1.49): with the verified slice flag `appCallers: "verified"` an APP caller must have a verified product
 * (the grant's `prd`, else its slice `companionCallers` entry; `resolveCallerProduct`). 403 `caller_unverified`, retryable (a newer
 * slice or a bridge that mints `prd` fixes it), nothing runs. The message names the fix.
 */
export const CALLER_UNVERIFIED_MESSAGE = "the calling app is not verified for this workspace yet: update the bridge, or retry after the workspace config refreshes";
export function callerUnverified(rt: Pick<Runtime, "trust">, caller: { type: string; product?: unknown }): boolean {
  return caller.type === "app" && caller.product === undefined && rt.trust.appCallersVerified();
}
const callerUnverifiedError = (): TbError => new TbError("caller_unverified", CALLER_UNVERIFIED_MESSAGE, 403, { retryable: true });

/**
 * v0.1.35 (C283 A1): the access the app's own store gives `callerId` on `type` for a call (never from the caller): the level, its
 * crud and the row's `authority` ("owner" = primary, also above the Portal grant; "bounded" = the grant stays the ceiling).
 * No row = level "none", no crud, bounded. For an op that spans instances (`target` null) `authority` is "owner" only when
 * every row of the caller for the type is an owner row (ScopeStoreInternals.resolve).
 */
function scopeAccessOf(rt: Pick<Runtime, "scopes">, callerId: string, type: string, target: string | null): NonNullable<AuthorizeInput["access"]> {
  const r = rt.scopes.resolve(callerId, type, target);
  return r ? { level: r.level, crud: r.crud, authority: r.authority } : { level: "none", crud: [], authority: "bounded" };
}

export function handlerSpec(rt: Runtime, opId: string): HandlerSpec | null {
  const h = rt.def.handlers[opId];
  if (!h) return null;
  return typeof h === "function" ? { run: h } : h;
}

export function clampSummary(s: string): string {
  return s.length <= SUMMARY_MAX ? s : `${s.slice(0, SUMMARY_MAX - 1)}…`;
}

/** Body of the bridge→app op call (CORE §8). */
function parseOpBody(body: unknown): { input: Json; context: Record<string, Json>; idempotencyKey: string | null } {
  if (!isObj(body) || !("input" in body)) throw new TbError("input_invalid", "body must be { input, context, idempotencyKey? }", 400);
  const ctx = body.context ?? {};
  if (!isObj(ctx)) throw new TbError("input_invalid", "context must be an object", 400);
  const key = body.idempotencyKey;
  if (key !== undefined && key !== null && typeof key !== "string") throw new TbError("idempotency_key_invalid", "idempotencyKey must be a string", 400);
  return { input: body.input as Json, context: ctx as Record<string, Json>, idempotencyKey: typeof key === "string" ? key : null };
}

function idempotencyKeyFor(op: { idempotency: string }, key: string | null): string | null {
  if (op.idempotency === "none") return null;
  if (key === null) {
    if (op.idempotency === "required") throw new TbError("idempotency_key_required", "this operation requires an idempotency key", 400);
    return null;
  }
  if (!IDEM_KEY_RE.test(key)) throw new TbError("idempotency_key_invalid", "idempotency key must be 8..128 printable characters", 400);
  return key;
}

/** Collects `ctx.receipt` values set by the handler. */
export function receiptHelpers(): { helpers: OpContext["receipt"]; summary: string | null; meta: Json | undefined } {
  const state: { summary: string | null; meta: Json | undefined } = { summary: null, meta: undefined };
  return {
    get summary() {
      return state.summary;
    },
    get meta() {
      return state.meta;
    },
    helpers: {
      summary(text) {
        state.summary = clampSummary(String(text));
      },
      meta(value) {
        if (Buffer.byteLength(JSON.stringify(value ?? null)) > META_MAX_BYTES) throw new TbError("receipt_meta_too_large", "receipt meta must be ≤ 4 KB", 500);
        state.meta = value;
      },
    },
  };
}

/**
 * v0.1.77 (C367 P4, SDK-API §18.6 item 5): `meta.callerContext` of the receipts of an APP call = the final op `context` keys under
 * `<verified caller product>.` (the product comes from the verified grant / slice, never from the body); undefined for an agent or person
 * caller, without a verified product, or with no such key. Informational only: nothing in authorize(), the approval match, idempotency or
 * policy reads it. A subset over CALLER_CONTEXT_MAX_BYTES (JCS) is not stored (only a same-product hook overwrite can cause that): a warning, no values.
 */
export function callerContextOf(rt: Pick<Runtime, "log">, caller: Pick<Caller, "type" | "product">, context: Record<string, Json>): Record<string, Json> | undefined {
  if (caller.type !== "app" || caller.product === undefined) return undefined;
  const prefix = `${caller.product}.`;
  const subset: Record<string, Json> = {};
  for (const k of Object.keys(context)) if (k.startsWith(prefix)) subset[k] = context[k] as Json;
  if (Object.keys(subset).length === 0) return undefined;
  try {
    if (Buffer.byteLength(canonicalize(subset), "utf8") <= CALLER_CONTEXT_MAX_BYTES) return subset;
  } catch {
    /* not storable: the warning below */
  }
  rt.log.warn("caller context not stored", { reason: "too_large" });
  return undefined;
}

/**
 * Adds the caller context to a receipt `meta`. `current` = this call's subset; `held` = the approved hold this call repeats, if any.
 * A repeat keeps the HOLD's `callerContext`; when its own context differs (JCS compare) it goes under `callerContextRun`. Same storage rules
 * for both: `meta` must be an object (or empty) and stay within 4 KB, else the context is left out (a warning, never the values).
 */
export function receiptMetaWithContext(rt: Pick<Runtime, "log">, meta: Json, current: Record<string, Json> | undefined, held: Pick<Receipt, "meta"> | null = null): Json {
  let stored: Json | undefined = current;
  let run: Json | undefined;
  if (held) {
    const heldCc = isObj(held.meta) ? (held.meta.callerContext as Json | undefined) : undefined;
    if (heldCc !== undefined) {
      stored = heldCc;
      if (current !== undefined && canonicalize(current) !== canonicalize(heldCc)) run = current;
    } else {
      stored = undefined;
      run = current;
    }
  }
  if (stored === undefined && run === undefined) return meta;
  if (meta !== null && meta !== undefined && !isObj(meta)) {
    rt.log.warn("caller context not stored", { reason: "meta_not_object" });
    return meta;
  }
  const merged: Json = { ...((meta ?? {}) as Record<string, Json>), ...(stored !== undefined ? { callerContext: stored } : {}), ...(run !== undefined ? { callerContextRun: run } : {}) };
  if (Buffer.byteLength(JSON.stringify(merged)) > META_MAX_BYTES) {
    rt.log.warn("caller context not stored", { reason: "meta_too_large" });
    return meta ?? null;
  }
  return merged;
}

export function buildContext(
  rt: Runtime,
  op: OperationView,
  caller: Caller,
  grant: VerifiedGrant | null,
  scope: ScopeAccessView,
  callId: CallId | null,
  idempotencyKey: string | null,
  context: Record<string, Json>,
  receipt: OpContext["receipt"],
  signal: AbortSignal,
  extras: ContextExtras = rt.extras(),
): SdkOpContext {
  return {
    ...extras,
    // v0.1.32 (`Caller.listed`, SPEC-GAP spec 0.1.49): app callers only, evaluated from the CURRENT slice when the context is built
    // (a live call, a scheduled fire and a resumed held job each build their own); no key on person and agent callers
    caller: caller.type === "app" ? { ...caller, listed: rt.trust.companionListed(caller.id, caller.product, Date.now()) } : caller,
    grant,
    op,
    scope,
    callId,
    idempotencyKey,
    context,
    receipt,
    getKey: (name) => rt.keys.getKey(name),
    modelRole: (role) => rt.keys.modelRole(role),
    callApp: (product, opId, input, opts) => rt.callApp(product, opId, input, { idempotencyKey: opts?.idempotencyKey, ...(opts?.context !== undefined ? { context: opts.context } : {}), parentCall: callId }),
    callServiceHelper: (serviceId, path, body) => rt.callServiceHelper(serviceId, path, body),
    db: rt.appDb,
    log: rt.log,
    signal,
    // v0.1.13 (C86)
    statusChanged: () => rt.statusChanged(),
    ownerLink: (path) => rt.ownerLink(path),
    ownerLinkFor: (product: string, path: string) => rt.ownerLinkFor(product, path),
    // v0.1.14 addition (SPEC-GAP: InstanceSlice.companionTargets)
    companionTargets: () => rt.companionTargets(),
    appsPolicy: () => rt.appsPolicy(),
    // v0.1.37 (C292, spec 0.1.54): every op context (person, agent, app, scheduled and resumed calls) reads the CURRENT slice; advisory
    bridgeCaps: () => rt.bridgeCaps(),
    // spec 0.1.80 (C373, G-2): display only; every op context reads the CURRENT slice
    topology: () => rt.topology(),
    // v0.1.38 (C274c/C274d, SDK-API §20): synchronous outbox writes; `causedBy` = the VERIFIED agent caller of this call (never app code)
    emit: rt.events.emitFn(caller.type === "agent" ? { causedBy: caller.id as AgentId } : {}),
    purgeEvents: rt.events.purgeFn(),
    agentScopeRequest: (agt: string) => rt.agentScopeRequest(agt),
    // v0.1.21 (R1, SDK-1/SDK-2): ctx.jobs, ctx.schedule (fire-time authorize with THIS caller), ctx.paused
    ...jobsView(rt, rt.jobs, { caller, grant: grant ? { token: grant.token, iat: grant.claims.iat } : null }),
  };
}

/**
 * v0.1.31 (SDK-INSTANCE-GRANT): the life of the grant closures of ONE op run. They work only while the handler runs: they
 * stop when the handler promise settles (`bind`), on the 30 s timeout and on a client disconnect (the signal aborts). A
 * closure that app code stored in a global and calls later (another call, a timer) throws 409 `scope_grant_expired`.
 */
export interface OpLife {
  assertOpen(): void;
  close(): void;
  /** closes when `handler` settles (either way) */
  bind(handler: Promise<unknown>): void;
}
export function opLife(signal: AbortSignal): OpLife {
  let open = true;
  const close = () => {
    open = false;
  };
  signal.addEventListener("abort", close, { once: true });
  return {
    assertOpen() {
      if (!open || signal.aborted) throw new TbError("scope_grant_expired", "the operation that held this scope grant API has ended", 409);
    },
    close,
    bind(handler) {
      handler.then(close, close);
    },
  };
}

/** Why a grant may not go to `agent` right now, from the CURRENT verified slice (never a stale one); null = may. */
export function grantRefusal(rt: Runtime, agent: string, now: number): { reason: string; message: string } | null {
  if (rt.trust.stale(now)) throw new TbError("slice_stale", "instance slice missing or older than 12 h", 503);
  const entry = rt.trust.agent(agent);
  if (!entry) return { reason: "agent_not_in_slice", message: "the agent has no edge to this app" };
  const p = rt.trust.paused(agent);
  if (entry.status !== "active" || p.workspace || p.instance || p.agent) return { reason: "agent_paused", message: "the agent (or its workspace or this app) is paused or not active" };
  return null;
}

/**
 * v0.1.31 (SDK-INSTANCE-GRANT, spec 0.1.47): `ctx.scopeGrants` of a live PERSON op. Called from exactly one place
 * (`handlePersonOp`, after the session and CSRF checks); agent, app, scheduled and public contexts never get it. Bounds and
 * the audit row live in `ScopeGrantOps` (scopes.ts); the "has an edge to this app" check reads the verified slice.
 */
function personScopeGrants(rt: Runtime, principal: PersonPrincipal, opId: string, requestId: string, life: OpLife): ScopeGrantApi {
  const by = { principal, op: opId, callId: null, requestId, refusal: (agent: string) => grantRefusal(rt, agent, Date.now()) };
  const ops = scopeGrantOps(rt.scopes);
  return {
    grant: async (agent, type, instanceId, access) => {
      life.assertOpen();
      return ops.appGrant(by, agent, type, instanceId, access);
    },
    revoke: async (agent, type, instanceId) => {
      life.assertOpen();
      return ops.appRevoke(by, agent, type, instanceId);
    },
  };
}

/**
 * v0.1.32 (SDK-COMPANION-CALLERS, spec 0.1.48): `ctx.companionCallers` of a live PERSON op, set at the same single place as
 * `ctx.scopeGrants`. Every call reads the CURRENT verified slice (never a snapshot from the start of the op) and returns a
 * frozen array of frozen copies `{product, ins, name, provider}`; [] while the slice is missing or older than 12 h (the
 * same stale check the op route uses). No grant material, no handle on the slice: display and binding data only.
 */
export function personCompanionCallers(rt: Pick<Runtime, "trust">): NonNullable<OpContext["companionCallers"]> {
  return () => {
    if (rt.trust.stale(Date.now())) return Object.freeze([]);
    return Object.freeze(rt.trust.companionCallers().map((c) => Object.freeze({ product: c.product, ins: c.ins, name: c.name, provider: c.provider }))) as readonly CompanionCaller[];
  };
}

/** v0.1.31 (SDK-INSTANCE-GRANT): `ctx.scopeSelfRevoke` of a live AGENT call: removes only the calling agent's OWN row. */
function agentSelfRevoke(rt: Runtime, opId: string, agentId: string, callId: CallId | null, life: OpLife): NonNullable<OpContext["scopeSelfRevoke"]> {
  const ops = scopeGrantOps(rt.scopes);
  return async (type, instanceId) => {
    life.assertOpen();
    return ops.selfRevoke(agentId, opId, callId, type, instanceId);
  };
}

/** AbortSignal for one handler run: client disconnect or 30 s op timeout (SDK-API §3.1). */
function opSignal(req: IncomingMessage, res: ServerResponse): { signal: AbortSignal; done(): void } {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new TbError("app_timeout", "operation timed out", 504)), OP_TIMEOUT_MS);
  timer.unref();
  const onClose = () => {
    if (!res.writableEnded) ac.abort(new TbError("client_closed", "client disconnected", 499));
  };
  req.socket.once("close", onClose);
  return {
    signal: ac.signal,
    done() {
      clearTimeout(timer);
      req.socket.off("close", onClose);
    },
  };
}

/**
 * Starts one handler run. `raced` answers the caller: the output, or the abort reason (30 s timeout, client gone).
 * `actual` is the handler itself (validated output or its error): it may end AFTER `raced` (SDK-07), and the SDK keeps the
 * idempotency key and the cap slot reserved until it does (v0.1.22, SDK-01/SDK-02).
 */
export function startHandler(rt: Runtime, op: OperationView, input: Json, ctx: OpContext, dynamicTool: { tool: string; args: Record<string, unknown> } | null): { raced: Promise<Json>; actual: Promise<Json> } {
  const run = async (): Promise<Json> => {
    if (dynamicTool) {
      const d = rt.def.dynamic?.[op.id];
      if (!d) throw new TbError("dynamic_resolve_failed", "no dynamic handler", 500);
      return d.call(dynamicTool.tool, dynamicTool.args, ctx);
    }
    const spec = handlerSpec(rt, op.id);
    if (!spec) throw new TbError("unknown_tool", "no handler for this operation", 404);
    return spec.run(input, ctx);
  };
  const actual = (async () => {
    const output = await run();
    if (output === undefined) throw new TbError("output_invalid", "handler returned no output", 500);
    if (!op.standard && !op.dynamic && op.output) {
      const v = validateAgainstSchema(op.output, output);
      if (!v.ok) throw new TbError("output_invalid", "handler output does not match the manifest output schema", 500, { errors: v.errors });
    }
    return output;
  })();
  const aborted = new Promise<never>((_, reject) => {
    if (ctx.signal.aborted) reject(ctx.signal.reason);
    ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason), { once: true });
  });
  aborted.catch(() => {});
  return { raced: Promise.race([actual, aborted]), actual };
}

export async function runHandler(rt: Runtime, op: OperationView, input: Json, ctx: OpContext, dynamicTool: { tool: string; args: Record<string, unknown> } | null): Promise<Json> {
  const h = startHandler(rt, op, input, ctx, dynamicTool);
  h.actual.catch(() => {});
  return h.raced;
}

// ── Idempotency reservation (§4.4, v0.1.22 SDK-01) ───────────────────────────
/** Runs in THIS process per (caller, op, key): a concurrent duplicate waits for the first run's end. */
const inflight = new WeakMap<Receipts, Map<string, Promise<void>>>();
/** Rounds a duplicate may wait (each up to the op timeout) before it answers 409 `idempotency_in_flight`. */
const IDEM_WAIT_ROUNDS = 3;

/** A reserved key: exactly one of `result`, `held`, `release` ends it (later calls are no-ops). */
export interface IdemLease {
  readonly key: string;
  result(output: Json): void;
  held(holdId: string): void;
  release(): void;
}

type IdemClaim =
  | { kind: "lease"; lease: IdemLease }
  | { kind: "result"; output: Json }
  | { kind: "held"; holdId: string; expiresAt: number };

function waitFor(p: Promise<void>, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    const t = setTimeout(() => resolve(false), ms);
    t.unref();
    p.then(() => {
      clearTimeout(t);
      resolve(true);
    });
  });
}

/**
 * Reserves `(caller, op, key)` before authorize() and the handler (one INSERT wins in the app DB). A live duplicate:
 * same input → waits for the first run and answers its stored result (or its hold); a failed first run frees the key
 * and the duplicate runs (a normal retry); still running after the wait → 409 `idempotency_in_flight`; a key left
 * pending by a process that died mid-run → 409 `idempotency_outcome_unknown` (never re-run). Different input → 409
 * `idempotency_conflict`. An approved (or otherwise decided) hold under the key is taken over by its retry.
 */
async function claimIdempotency(rt: Runtime, callerId: string, opId: string, key: string, inputDigest: string, sealId: string): Promise<IdemClaim> {
  const map = inflight.get(rt.receipts) ?? new Map<string, Promise<void>>();
  inflight.set(rt.receipts, map);
  const k = `${callerId}\u0000${opId}\u0000${key}`;
  const lease = (): IdemClaim => {
    let done!: () => void;
    map.set(
      k,
      new Promise<void>((r) => {
        done = r;
      }),
    );
    let open = true;
    const end = (fn: () => void) => {
      if (!open) return;
      open = false;
      try {
        fn();
      } finally {
        map.delete(k);
        done();
      }
    };
    return {
      kind: "lease",
      lease: {
        key,
        result: (output) => end(() => rt.receipts.idemPut(callerId, opId, key, inputDigest, { output: rt.sealer.sealText(IDEM_PURPOSE, sealId, JSON.stringify(output)) }, Date.now())),
        held: (holdId) => end(() => rt.receipts.idemPut(callerId, opId, key, inputDigest, { holdId }, Date.now())),
        release: () => end(() => rt.receipts.idemRelease(callerId, opId, key)),
      },
    };
  };
  let waits = 0;
  for (;;) {
    const now = Date.now();
    const r = rt.receipts.idemReserve(callerId, opId, key, inputDigest, now);
    if (r.kind === "reserved") return lease();
    const row = r.row;
    if (row.inputDigest !== inputDigest) throw new TbError("idempotency_conflict", "idempotency key was used with a different input", 409);
    if (row.kind === "result") return { kind: "result", output: JSON.parse(rt.sealer.unsealText(IDEM_PURPOSE, sealId, row.output)) as Json };
    if (row.kind === "unknown") throw new TbError("idempotency_outcome_unknown", "an earlier call with this key stopped mid-run; its outcome is unknown, so it is not run again", 409);
    if (row.kind === "held") {
      const h = rt.receipts.getSync(row.holdId);
      if (h?.status === "held") return { kind: "held", holdId: h.id, expiresAt: h.expiresAt ?? now };
      if (h?.status === "denied") throw new TbError("hold_denied", "the owner denied this call (or it expired)", 403);
      // approved (or gone): the retry takes the key over and runs (§4.3); a concurrent retry that lost waits below
      if (rt.receipts.idemTakeHeld(callerId, opId, key, row.holdId)) return lease();
      continue;
    }
    // pending: a run of this key is in progress
    const p = map.get(k);
    if (!p || waits >= IDEM_WAIT_ROUNDS) throw new TbError("idempotency_in_flight", "a call with this idempotency key is still running; retry later", 409);
    if (!(await waitFor(p, OP_TIMEOUT_MS))) waits = IDEM_WAIT_ROUNDS;
    else waits += 1;
  }
}

function toTbError(e: unknown, rt: Runtime): TbError {
  if (e instanceof TbError) return e;
  rt.log.error("handler failed", { error: e instanceof Error ? e.message : "unknown" });
  return new TbError("app_error", "the operation failed", 500);
}

/** Dynamic ops (MANIFEST §5.3): crud/effect/holdFamily come from the app's own `resolve`, never from the agent. */
async function resolveDynamic(rt: Runtime, op: ManifestOp, input: Json): Promise<{ eff: EffectiveOp; tool: string; args: Record<string, unknown> }> {
  if (!isObj(input) || typeof input.tool !== "string" || !isObj(input.arguments)) throw new TbError("input_invalid", "dynamic call input must be { tool, arguments }", 400);
  const d = rt.def.dynamic?.[op.id];
  const hctx: SdkHookContext = { log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n), modelRole: (r) => rt.keys.modelRole(r), signal: AbortSignal.timeout(2000), secrets: rt.secretsStore };
  const res: DynamicResolution | null = d ? await d.resolve(input.tool, hctx) : null;
  if (!res) throw new TbError("dynamic_resolve_failed", "unknown dynamic tool", 404);
  if (!withinCeiling(op, res)) throw new TbError("dynamic_ceiling_exceeded", "resolved tool exceeds the operation's ceiling", 403);
  return {
    eff: { id: op.id, crud: res.crud, effect: res.effect, ...(res.holdFamily ? { holdFamily: res.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) },
    tool: input.tool,
    args: input.arguments,
  };
}

export function withinCeiling(op: Operation, r: { crud: CrudAction[]; effect: Effect }): boolean {
  const c = op.dynamic;
  if (!c) return false;
  return r.crud.length > 0 && r.crud.every((x) => c.crudCeiling.includes(x)) && EFFECTS.indexOf(r.effect) <= EFFECTS.indexOf(c.effectCeiling);
}

// ── Hold view of a dynamic tool call (v0.1.23, SDK-HV-1, SDK-API §4.6) ─────
/** What the owner sees on a hold of a dynamic call: view text, summary (null = op title) and the hash the approval binds. */
export interface DynamicHoldText {
  view: string;
  summary: string | null;
  viewSha256: string;
  /** false = the fallback view (the app could not read the content); such a view never satisfies an approval (C202) */
  readable: boolean;
}

// v0.1.33 (G7, C275): the JSON is built from the JCS form (the same canonicalize() as the input digest), so a replay of the
// same input with its keys in another order gives the SAME view text and hash and the approval matches; key order of the
// caller never reaches the view. Indented for the owner (JSON.parse keeps the JCS key order; integer-like keys sort first).
const defaultHoldView = (op: { title: string }, input: Json): string => `${op.title}\n${JSON.stringify(JSON.parse(canonicalize(input)), null, 2)}`;
export const holdViewDigest = (view: string): string => `sha256:${createHash("sha256").update(view, "utf8").digest("hex")}`;

/**
 * Awaits the app's `dynamic[op].holdView(tool, args, ctx)` within HOLD_VIEW_BUDGET_MS. Never throws: a throw, a timeout,
 * a malformed answer or a view over 16 000 chars → the default view with the "could not read" line first (the hold is still
 * created; it is never approved by a failure). `null` → the default view. Returns null when the app has no holdView.
 * `makeCtx(signal)` builds the OpContext of the call (same caller, scope access and account the call would use).
 */
export async function dynamicHoldText(rt: Runtime, op: OperationView, input: Json, tool: { tool: string; args: Record<string, unknown> }, makeCtx: (signal: AbortSignal) => OpContext, budgetMs = HOLD_VIEW_BUDGET_MS): Promise<DynamicHoldText | null> {
  const fn = rt.def.dynamic?.[op.id]?.holdView;
  if (!fn) return null;
  const fallback = (): DynamicHoldText => {
    const view = `${HOLD_VIEW_UNREADABLE}\n\n${defaultHoldView(op, input)}`;
    return { view, summary: null, viewSha256: holdViewDigest(view), readable: false };
  };
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new TbError("hold_view_timeout", "hold view took too long", 504)), budgetMs);
  timer.unref();
  try {
    const aborted = new Promise<never>((_, reject) => ac.signal.addEventListener("abort", () => reject(ac.signal.reason), { once: true }));
    aborted.catch(() => {});
    const r = await Promise.race([fn(tool.tool, tool.args, makeCtx(ac.signal)), aborted]);
    if (r === null) {
      const view = defaultHoldView(op, input);
      return { view, summary: null, viewSha256: holdViewDigest(view), readable: true };
    }
    if (!isObj(r) || typeof r.view !== "string" || r.view.length === 0 || r.view.length > HOLD_VIEW_MAX || (r.summary !== undefined && typeof r.summary !== "string")) {
      rt.log.warn("hold view not usable", { op: op.id, reason: isObj(r) && typeof r.view === "string" && r.view.length > HOLD_VIEW_MAX ? "hold_view_too_large" : "hold_view_invalid" });
      return fallback();
    }
    return { view: r.view, summary: typeof r.summary === "string" && r.summary.trim() ? clampSummary(r.summary) : null, viewSha256: holdViewDigest(r.view), readable: true };
  } catch (e) {
    // the code only: never the upstream text (it may carry content the agent sent)
    rt.log.warn("hold view failed", { op: op.id, code: e instanceof TbError ? e.code : "hold_view_failed" });
    return fallback();
  } finally {
    clearTimeout(timer);
    if (!ac.signal.aborted) ac.abort(new TbError("hold_view_done", "hold view finished", 499));
  }
}

function grantFailStatus(code: string): number {
  return code.startsWith("grant_") ? 401 : 403;
}

// ── POST /tb/v1/ops/:op ──────────────────────────────────────────────────────
export async function handleAgentOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, opId: string): Promise<void> {
  const rid = requestId();
  try {
    if (rt.cfg.standalone) throw new TbError("no_bridge", "app-alone mode serves persons only", 503);
    const now = Date.now();
    const body = parseOpBody(await readJson(req));
    if (rt.trust.stale(now)) throw new TbError("slice_stale", "instance slice missing or older than 12 h", 503);
    const trust = rt.trust.context(now);
    if (!trust) throw new TbError("slice_stale", "no instance slice", 503);
    const auth = header(req, "authorization") ?? "";
    const grantToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const proofToken = header(req, BRIDGE_HEADERS.callProof) ?? "";
    const inputDigest = digest(body.input);
    const contextDigest = digest(body.context);
    const peek = peekClaims(grantToken);
    const proof = verifyCallProof(
      proofToken,
      trust,
      { op: opId, inputDigest, contextDigest, grantJti: typeof peek?.jti === "string" ? peek.jti : "", grantSub: typeof peek?.sub === "string" ? peek.sub : "" },
      rt.replay,
    );
    if (!proof.ok) throw new TbError("call_proof_invalid", "call proof missing or not valid", 401);
    const g = verifyGrant(grantToken, trust);
    if (!g.ok) throw new TbError(g.code, "grant not valid", grantFailStatus(g.code));
    // v0.1.28 (GRANT-PRD, spec 0.1.46): Caller.product = the verified grant's `prd` first, the slice companionCallers entry only
    // when `prd` is absent; both present and different = refused (403 grant_invalid), before the grant is stored for fires.
    const cp = resolveCallerProduct(rt, g.caller, g.claims);
    if (!cp.ok) throw new TbError("grant_invalid", "the grant and the instance slice disagree on the caller product", 403);
    // v0.1.21: the caller's newest verified grant replaces the stored one of its pending scheduled ops (owner narrowing,
    // revocation by jti and a re-minted grant all reach the fire-time authorize)
    rt.noteGrant(g.caller.id, grantToken, g.claims.iat);
    const op = rt.ops.get(opId);
    if (!op) throw new TbError("unknown_tool", `unknown operation ${opId}`, 404);
    if (op.audience !== "agent") throw new TbError("audience_not_agent", "operation is not agent-audience", 403);
    const callerId = g.caller.id as AgentId | InstanceId;
    const sliceAgent = g.caller.type === "agent" ? rt.trust.agent(callerId) : undefined;
    const caller: Caller = {
      type: g.caller.type,
      id: callerId,
      // v0.1.14 (C102): app callers are named from slice companionCallers (verified grant sub), fallback the instance id
      name: sliceAgent?.name ?? (g.caller.type === "app" ? (rt.trust.companionCallers().find((x) => x.ins === callerId)?.name ?? callerId) : callerId),
      mode: g.caller.type === "agent" ? (sliceAgent?.mode ?? g.claims.mode) : null,
      // v0.1.28 (GRANT-PRD): app callers only; grant `prd` first, then the slice companionCallers entry of the verified `ins`
      // (v0.1.27 SDK-CALLER-PRODUCT). Never derived from the name. One helper: resolveCallerProduct.
      ...cp.caller,
    };
    const callId = proof.claims.call;
    // v0.1.22 (SDK-05, fail closed): an agent that is not in the verified slice is refused — no invented agent record,
    // no scope defaults. Removal then never depends on Core listing the grant jti in `revoked`. The status loop is
    // kicked so a just-added agent is served as soon as the newer slice arrives.
    if (g.caller.type === "agent" && !sliceAgent) {
      rt.kickStatus();
      throw new TbError("agent_unknown", "this agent is not in the instance slice", 403);
    }

    // v0.1.35 (C261): an app caller with no verified product is refused before ANYTHING else runs (standard ops included: no
    // hold status, no pending list, no defaults, no idempotency key, no cap slot); the refusal is audited as a refused receipt
    if (callerUnverified(rt, caller)) {
      rt.receipts.insert({
        callId,
        caller: receiptCallerOf(caller, callerId),
        op: op.id,
        effect: op.effect,
        inputDigest: inputDigest as Sha256Digest,
        idempotencyKey: null,
        kind: "rcp",
        holdFamily: null,
        status: "refused",
        summary: clampSummary(op.title),
        meta: { reason: "caller_unverified" },
      });
      rt.statusChanged();
      throw callerUnverifiedError();
    }
    // v0.1.77 (C367 P4): informational only (never read by authorize(), the approval match, idempotency or policy)
    const callerCtx = callerContextOf(rt, caller, body.context);
    // tb.hold_status: valid grant suffices (I4); only the caller's own holds; no receipt.
    if (op.standard && op.id === "tb.hold_status") {
      const v = validateInput(op, body.input);
      if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
      // ONE lookup keyed by (id, caller type, caller id): a foreign hold and an unknown id take the same path and give the same answer.
      // `hold_not_found` is a public code and stays for every caller, agent and app (SDK-API §4.7, C367); the message never holds the holdId.
      const hs = rt.receipts.holdStatusSync(callerId, String((body.input as { holdId: string }).holdId), g.caller.type);
      if (!hs) throw new TbError("hold_not_found", "no such hold for this caller", 404);
      const output: Json = {
        status: hs.status,
        expiresAt: hs.expiresAt === null ? null : iso(hs.expiresAt),
        ...(hs.decidedAt !== null ? { decidedAt: iso(hs.decidedAt) } : {}),
        // v0.1.13 clarification (additive): why it was held — hook verdict reason or SDK hold reason code only (C90)
        family: hs.family,
        reason: hs.reason,
      };
      return sendJson(res, 200, { status: "ok", output } satisfies OpResult);
    }
    // v0.1.13 (G4) tb.holds_pending: valid grant suffices (I4); no receipt.
    if (op.standard && op.id === HOLDS_PENDING_OP) {
      const v = validateInput(op, body.input);
      if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
      const output = holdsPending(rt, g.caller.type, callerId, g.claims.wf, body.input as { limit?: number; cursor?: string }, now);
      return sendJson(res, 200, { status: "ok", output: output as unknown as Json } satisfies OpResult);
    }
    if (op.standard) throw new TbError("audience_not_agent", "operation is not agent-audience", 403);

    // effective op (dynamic → resolved values) and input schema
    let eff: EffectiveOp = { id: op.id, crud: op.crud, effect: op.effect, ...(op.holdFamily ? { holdFamily: op.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) };
    let dyn: { tool: string; args: Record<string, unknown> } | null = null;
    const v = validateInput(op, body.input);
    if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
    if (op.dynamic) {
      const r = await resolveDynamic(rt, op, body.input);
      eff = r.eff;
      dyn = { tool: r.tool, args: r.args };
    }

    // first sight (§7.2): agent from the slice (an agent outside it was refused above), or a companion app caller
    if (sliceAgent) await rt.ensureAgent(sliceAgent);
    else rt.scopes.applyDefaultsFor(callerId, caller.name);

    // idempotency (§4.4; v0.1.22 SDK-01): the key is reserved HERE, before authorize() and the handler
    const idemKey = idempotencyKeyFor(op, body.idempotencyKey);
    let idem: IdemLease | null = null;
    if (idemKey) {
      const c = await claimIdempotency(rt, callerId, op.id, idemKey, inputDigest, `${callerId}:${op.id}:${idemKey}`);
      if (c.kind === "result") return sendJson(res, 200, { status: "ok", output: c.output } satisfies OpResult);
      if (c.kind === "held") return sendJson(res, 202, { status: "held", holdId: c.holdId as `hld_${string}`, expiresAt: iso(c.expiresAt) } satisfies OpResult);
      idem = c.lease;
    }
    // cap slot (v0.1.22 SDK-02): reserved in the same transaction as the decision; given back on refusal/failure
    let slot: string | null = null;
    let handed = false;
    try {
      // scope access (from the app's own store, never from the caller)
      const spec = handlerSpec(rt, op.id);
      let access: AuthorizeInput["access"] = null;
      let viewAccess: ScopeAccessView["access"] = null;
      if (eff.scopeType) {
        const target = spec?.scope ? spec.scope(body.input, caller) : null;
        access = scopeAccessOf(rt, callerId, eff.scopeType, target);
        viewAccess = { type: eff.scopeType, id: target, level: access.level, crud: access.crud, authority: access.authority ?? "bounded" };
      }

      // v0.1.23 (SDK-HV-1): one OpContext factory for the hold view = the context the call itself would get
      const viewCtx = (signal: AbortSignal) => buildContext(rt, op, caller, g, rt.scopes.view(callerId, viewAccess), callId, idemKey, body.context, receiptHelpers().helpers, signal);
      let approved = rt.receipts.findApproved(callerId, op.id, inputDigest, Date.now());
      // v0.1.23 (SDK-HV-1): the approval is bound to the view the owner saw. Same input digest is not enough for a dynamic
      // call whose content lives upstream (approve draft A, the agent edits it to B, sends B): compute the view again and
      // use the approval only if it is the same text; else the call is decided as if no approval existed (a NEW hold).
      let heldText: DynamicHoldText | null = null;
      if (approved && dyn && rt.def.dynamic?.[op.id]?.holdView) {
        heldText = await dynamicHoldText(rt, op, body.input, dyn, viewCtx);
        const want = isObj(approved.meta) ? approved.meta.viewSha256 : undefined;
        // v0.1.24 (C202, fail closed): content that cannot be read NOW never runs on an approval, even when the owner
        // approved a hold that was also unreadable (an agent that can make the read fail must not reuse a blind approval)
        if (!heldText?.readable || typeof want !== "string" || want !== heldText.viewSha256) {
          rt.log.info("approval not used: the hold view changed", { op: op.id, hold: approved.id });
          approved = null;
        }
      }
      const now2 = Date.now();
      const d = rt.receipts.decideAndReserve(callerId, g.claims.caps ?? {}, eff.effect, op.id, now2, (usage) =>
        authorize({
          paused: rt.trust.paused(g.caller.type === "agent" ? callerId : null),
          grant: grantToken,
          trust,
          op: eff,
          access,
          usage,
          approval: approved ? "approved" : "none",
          // v0.1.13 (G1): the bridge-attested before-hook hold verdict; an approval for this exact call satisfies it
          holdVerdict: proof.claims.hv ? { family: proof.claims.hv.f, reason: proof.claims.hv.r, by: proof.claims.hv.by } : null,
        }),
      );
      const decision = d.decision;
      slot = d.slot;
      // v0.1.35 (C283 A1, S7): which rule admitted a SCOPED call is recorded on its receipt (never on a refusal)
      const admit = decision.decision !== "refuse" && decision.admittedBy ? { admittedBy: decision.admittedBy } : {};
      const receiptCaller = receiptCallerOf(caller, callerId);
      const base = { callId, caller: receiptCaller, op: op.id, effect: eff.effect, inputDigest: inputDigest as Sha256Digest, idempotencyKey: idemKey };
      const meta0: Json = dyn ? { tool: dyn.tool } : null;

      if (decision.decision === "refuse") {
        rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: receiptMetaWithContext(rt, { reason: decision.reason }, callerCtx) });
        throw new TbError(decision.reason, `refused: ${decision.reason}`, grantFailStatus(decision.reason));
      }
      if (decision.decision === "hold") {
        // v0.1.23 (SDK-HV-1): a dynamic op with holdView → the app's view of the upstream content (time-boxed, never blocks)
        if (dyn && !heldText) heldText = await dynamicHoldText(rt, op, body.input, dyn, viewCtx);
        const holdMeta: Json = heldText && dyn ? { tool: dyn.tool, viewSha256: heldText.viewSha256 } : meta0;
        const hold = createHold(rt, base, spec, op, body.input, decision, decision.reason === DECISION_REASON.heldByHook ? (proof.claims.hv?.r ?? null) : null, receiptMetaWithContext(rt, holdMeta, callerCtx), Date.now(), heldText);
        idem?.held(hold.id);
        rt.statusChanged();
        return sendJson(res, 202, { status: "held", holdId: hold.id, expiresAt: iso(hold.expiresAt ?? now2 + HOLD_TTL_MS) } satisfies OpResult);
      }

      // run
      if (approved && !rt.receipts.consume(approved.id)) throw new TbError("hold_consumed", "this approval was already used", 409);
      const rh = receiptHelpers();
      const sig = opSignal(req, res);
      const ctx = buildContext(rt, op, caller, g, rt.scopes.view(callerId, viewAccess), callId, idemKey, body.context, rh.helpers, sig.signal);
      // v0.1.31 (SDK-INSTANCE-GRANT): only a live AGENT call (caller type from the verified grant) may narrow its own access
      const life = opLife(sig.signal);
      if (caller.type === "agent") ctx.scopeSelfRevoke = agentSelfRevoke(rt, op.id, callerId, callId, life);
      const writeReceipt = approved !== null || op.receipt || (dyn !== null && eff.effect !== "read");
      const h = startHandler(rt, op, body.input, ctx, dyn);
      life.bind(h.actual);
      // the key and the slot end with the HANDLER, not with the answer: a run that outlives the 30 s timeout or the
      // client keeps both reserved until it ends (a retry never starts a second run; SDK-07)
      handed = true;
      const runSlot = slot;
      const lease = idem;
      h.actual.then(
        (output) => {
          if (runSlot) rt.receipts.capCommit(runSlot);
          lease?.result(output);
        },
        () => {
          if (runSlot) rt.receipts.capRelease(runSlot);
          lease?.release();
        },
      );
      let output: Json;
      try {
        output = await h.raced;
      } catch (e) {
        const err = toTbError(e, rt);
        const meta = rh.meta ?? meta0;
        if (approved) rt.receipts.finish(approved.id, "failed", { meta: receiptMetaWithContext(rt, meta, callerCtx, approved), ...admit });
        else if (writeReceipt) rt.receipts.insert({ ...base, ...admit, kind: "rcp", holdFamily: null, status: "failed", summary: rh.summary ?? clampSummary(op.title), meta: receiptMetaWithContext(rt, { ...(isObj(meta) ? meta : {}), error: err.code }, callerCtx) });
        throw err;
      } finally {
        sig.done();
      }
      const summary = rh.summary ?? clampSummary(spec?.redact ? spec.redact(body.input, output) : op.title);
      let receiptId: string | undefined;
      if (approved) {
        rt.receipts.finish(approved.id, "run", { summary, meta: receiptMetaWithContext(rt, rh.meta ?? meta0, callerCtx, approved), ...admit });
        receiptId = approved.id;
      } else if (writeReceipt) {
        receiptId = rt.receipts.insert({ ...base, ...admit, kind: "rcp", holdFamily: null, status: "run", summary, meta: receiptMetaWithContext(rt, rh.meta ?? meta0, callerCtx) }).id;
      }
      sendJson(res, 200, receiptId ? ({ status: "ok", output, receiptId } satisfies OpResult) : ({ status: "ok", output } satisfies OpResult));
    } catch (e) {
      if (!handed) {
        if (slot) rt.receipts.capRelease(slot);
        idem?.release();
      }
      throw e;
    }
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : toTbError(e, rt));
  }
}

/** The caller a receipt / hold records (app callers carry the verified `product`). */
function receiptCallerOf(caller: Caller, id: AgentId | InstanceId): Receipt["caller"] {
  return { type: caller.type as "agent" | "app", id, name: caller.name, ...(caller.type === "app" && caller.product !== undefined ? { product: caller.product } : {}) };
}

type ReceiptBase = Pick<NewReceipt, "callId" | "caller" | "op" | "effect" | "inputDigest" | "idempotencyKey">;

/** A hold receipt for a `hold` decision (called op or scheduled op); refuses `hold_view_too_large`. */
function createHold(rt: Runtime, base: ReceiptBase, spec: HandlerSpec | null, op: OperationView, input: Json, decision: Decision, hookReason: string | null, meta: Json, now: number, text: DynamicHoldText | null = null) {
  const view = text ? text.view : spec?.holdView ? spec.holdView(input) : defaultHoldView(op, input);
  if (view.length > HOLD_VIEW_MAX) {
    rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: { reason: "hold_view_too_large" } });
    throw new TbError("hold_view_too_large", "hold view exceeds 16 000 characters", 500);
  }
  const summary = text?.summary ?? clampSummary(spec?.redact ? spec.redact(input) : op.title);
  // v0.1.13 (G1): heldBy + the reason (hook verdict reason, else the SDK decision reason code; C90: never input/view/meta)
  return rt.receipts.insert(
    {
      ...base,
      kind: "hld",
      holdFamily: decision.holdFamily ?? null,
      heldBy: decision.heldBy ?? null,
      ...(decision.admittedBy ? { admittedBy: decision.admittedBy } : {}),
      holdReason: hookReason ?? decision.reason,
      status: "held",
      summary,
      meta,
      view,
      expiresAt: now + HOLD_TTL_MS,
    },
    now,
  );
}

// ── Scheduled ops (v0.1.21, SDK-2 / CON-01) ─────────────────────────────────
/**
 * Fire time of `ctx.schedule({ op, input }, …)`: THE app decision function `authorize()` runs again with the stored
 * caller against the CURRENT slice (pause: workspace kill switch, instance, agent; revoked jtis; issuer keys), the
 * current scope access, current usage (caps) and a current approval, and the receipt of the actual run is written.
 * Before that: an agent caller must still be in the slice (`agent_removed`), an app caller still a companion caller
 * (`grant_revoked`), and the op must still be in the grant's workflow (`not_in_workflow`, gate() step 4).
 * The grant is the caller's newest verified grant (refreshed on each of its calls). Its 12 h expiry is the one check
 * replaced: authorize() reads it at a time inside its validity, and caller presence in the Portal-signed slice
 * (≤ 12 h fresh, else nothing fires) stands in for it. SPEC-GAP (SDK-API §19): bridge before-hooks (Rules) are not
 * re-run at fire time; they ran for the scheduling call.
 */
export async function fireScheduledOp(rt: Runtime, job: ClaimedJob, signal: AbortSignal): Promise<OpFireOutcome> {
  const now = Date.now();
  const op = job.op ? rt.ops.get(job.op) : undefined;
  if (!op || op.standard || op.dynamic) return { kind: "refused", reason: "unknown_tool" };
  const who = job.caller;
  if (!who) return { kind: "refused", reason: "schedule_caller_required" };
  if (!rt.cfg.standalone && rt.trust.stale(now)) return { kind: "defer", reason: "slice_stale" };
  const input = job.input;
  const inputDigest = digest(input) as Sha256Digest;
  const spec = handlerSpec(rt, op.id);
  // product: the slice entry until the stored grant is verified below; then the grant's `prd` takes over (GRANT-PRD)
  const initial = resolveCallerProduct(rt, who, null);
  let caller: Caller = { type: who.type, id: who.id as Caller["id"], name: who.name, mode: (job.callerMode as Caller["mode"]) ?? null, ...(initial.ok ? initial.caller : {}) };
  const effect = op.effect;

  if (who.type === "person") {
    const p = rt.trust.paused(null);
    if (p.workspace || p.instance) return { kind: "refused", reason: DECISION_REASON.paused };
    const rh = receiptHelpers();
    const ctx = buildContext(rt, op, caller, null, rt.scopes.view(null, null), null, job.key, {}, rh.helpers, signal);
    const output = await runHandler(rt, op, input, ctx, null);
    return { kind: "done", result: output };
  }

  const callerId = who.id as AgentId | InstanceId;
  const receiptCaller = receiptCallerOf(caller, callerId);
  const base: ReceiptBase = { callId: null, caller: receiptCaller, op: op.id, effect, inputDigest, idempotencyKey: job.key };
  const refuse = (reason: string): OpFireOutcome => {
    rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: { reason, scheduled: job.id } });
    rt.statusChanged();
    return { kind: "refused", reason };
  };
  // the caller must still exist (an agent removed from the slice, an app whose companion grant was revoked)
  if (who.type === "agent" && !rt.trust.agent(callerId)) return refuse("agent_removed");
  if (who.type === "app" && !rt.trust.companionCallers().some((c) => c.ins === callerId)) return refuse("grant_revoked");
  if (!job.grantSealed) return refuse("grant_invalid");
  const token = unsealGrant(rt, callerId, job.grantSealed);
  const trust = rt.trust.context(now);
  if (!trust) return { kind: "defer", reason: "slice_stale" };
  const exp = Number(peekClaims(token)?.exp ?? 0);
  const at = { ...trust, now: Math.min(trust.now, exp - 1) };
  const g = verifyGrant(token, at);
  if (!g.ok) return refuse(g.code);
  if (g.caller.id !== callerId) return refuse("grant_invalid");
  // v0.1.28 (GRANT-PRD): the stored grant's `prd` first; a grant/slice disagreement refuses the fire like a live call
  const cp = resolveCallerProduct(rt, who, g.claims);
  if (!cp.ok) return refuse("grant_invalid");
  caller = { type: caller.type, id: caller.id, name: caller.name, mode: caller.mode, ...cp.caller };
  base.caller = receiptCallerOf(caller, callerId);
  // v0.1.35 (C261): a scheduled fire, and the resume of a held one, is a call like any other: no verified product, no run
  if (callerUnverified(rt, caller)) return refuse("caller_unverified");
  // v0.1.36: the op's listing counts like in gate() (a `listing: "workflow"` op passes only when the grant's wf names it, in any mode)
  if (!opInGrantWorkflow(g.claims, op.id, op.listing)) return refuse(DECISION_REASON.notInWorkflow);

  let access: AuthorizeInput["access"] = null;
  let viewAccess: ScopeAccessView["access"] = null;
  if (op.scopeType) {
    const target = spec?.scope ? spec.scope(input, caller) : null;
    access = scopeAccessOf(rt, callerId, op.scopeType, target);
    viewAccess = { type: op.scopeType, id: target, level: access.level, crud: access.crud, authority: access.authority ?? "bounded" };
  }
  // a hold created at an earlier fire: denied/expired ends the job; still held waits; approved runs once (C8)
  if (job.holdId) {
    const h = rt.receipts.getSync(job.holdId);
    if (h?.status === "held") return { kind: "wait", holdId: h.id };
    if (h?.status !== "approved") return { kind: "refused", reason: "hold_denied" };
  }
  const approved = rt.receipts.findApproved(callerId, op.id, inputDigest, now);
  // v0.1.22 (SDK-02): usage, decision and the cap slot in one transaction (receipt or not)
  const { decision, slot } = rt.receipts.decideAndReserve(callerId, g.claims.caps ?? {}, effect, op.id, now, (usage) =>
    authorize({
      paused: rt.trust.paused(who.type === "agent" ? callerId : null),
      grant: token,
      trust: at,
      op: { id: op.id, crud: op.crud, effect, ...(op.holdFamily ? { holdFamily: op.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) },
      access,
      usage,
      approval: approved ? "approved" : "none",
      holdVerdict: null,
    }),
  );
  if (decision.decision === "refuse") return refuse(decision.reason);
  const admit = decision.admittedBy ? { admittedBy: decision.admittedBy } : {};
  if (decision.decision === "hold") {
    if (job.holdId) return { kind: "refused", reason: "hold_consumed" };
    const hold = createHold(rt, base, spec, op, input, decision, null, { scheduled: job.id }, now);
    rt.statusChanged();
    return { kind: "wait", holdId: hold.id };
  }
  if (approved && !rt.receipts.consume(approved.id)) {
    if (slot) rt.receipts.capRelease(slot);
    return { kind: "refused", reason: "hold_consumed" };
  }
  const rh = receiptHelpers();
  const ctx = buildContext(rt, op, caller, g, rt.scopes.view(callerId, viewAccess), null, job.key, {}, rh.helpers, signal);
  const writeReceipt = approved !== null || op.receipt;
  const h = startHandler(rt, op, input, ctx, null);
  // the slot ends with the handler itself (a run past its timeout still counts when it completes)
  h.actual.then(
    () => {
      if (slot) rt.receipts.capCommit(slot);
    },
    () => {
      if (slot) rt.receipts.capRelease(slot);
    },
  );
  let output: Json;
  try {
    output = await h.raced;
  } catch (e) {
    const err = toTbError(e, rt);
    const meta = rh.meta ?? null;
    if (approved) rt.receipts.finish(approved.id, "failed", { meta, ...admit });
    else if (writeReceipt) rt.receipts.insert({ ...base, ...admit, kind: "rcp", holdFamily: null, status: "failed", summary: rh.summary ?? clampSummary(op.title), meta: { ...(isObj(meta) ? meta : {}), error: err.code } });
    return { kind: "failed", error: err.code };
  }
  const summary = rh.summary ?? clampSummary(spec?.redact ? spec.redact(input, output) : op.title);
  if (approved) rt.receipts.finish(approved.id, "run", { summary, meta: rh.meta ?? null, ...admit });
  else if (writeReceipt) rt.receipts.insert({ ...base, ...admit, kind: "rcp", holdFamily: null, status: "run", summary, meta: rh.meta ?? null });
  return { kind: "done", result: output };
}

// ── tb.holds_pending (v0.1.13, G4) ───────────────────────────────────────────
/**
 * An AGENT caller sees only its own pending holds; an APP caller whose companion grant names tb.holds_pending (`wf`)
 * sees every pending hold of the instance. SPEC-GAP: an app caller WITHOUT it in `wf` (I4 lets any valid grant through)
 * sees only its own holds, like an agent. Summaries only: never input, view or meta.
 */
export function holdsPending(
  rt: Runtime,
  callerType: "agent" | "app",
  callerId: string,
  wf: readonly string[],
  input: { limit?: number; cursor?: string },
  now: number,
): HoldsPendingOutput {
  const all = callerType === "app" && wf.includes(HOLDS_PENDING_OP);
  const page = rt.receipts.pending({ caller: all ? null : callerId, limit: input.limit ?? 50, ...(input.cursor ? { cursor: input.cursor } : {}) }, now);
  const items = page.items.map(
    (h): HoldsPendingItem => ({
      id: h.id as HoldsPendingItem["id"],
      product: rt.product,
      op: h.op,
      family: h.family ?? "policy",
      reason: h.reason.slice(0, SUMMARY_MAX),
      heldBy: h.heldBy,
      summary: h.summary,
      caller: h.caller,
      createdAt: iso(h.createdAt) as HoldsPendingItem["createdAt"],
      ageS: Math.max(0, Math.floor((now - h.createdAt) / 1000)),
      decidePath: `/holds/${h.id}`,
      // v0.1.77 (C367 P4): the summary of the receipt's meta.callerContext, read time only; never the whole context
      ...(h.callerContext !== undefined ? { callerContext: h.callerContext } : {}),
    }),
  );
  return { items, nextCursor: page.nextCursor };
}

// ── Hold decide (person only, §4.5) ──────────────────────────────────────────
export async function decide(rt: Runtime, principal: PersonPrincipal, input: HoldDecideInput): Promise<Receipt> {
  if (principal?.type !== "person" || principal.instance !== rt.instanceId) throw new TbError("session_required", "only the owner can decide holds", 403);
  if (input.decision !== "approve" && input.decision !== "deny") throw new TbError("input_invalid", "decision must be approve or deny", 400);
  const now = Date.now();
  const row = typeof input.holdId === "string" && input.holdId.startsWith("hld_") ? rt.receipts.getSync(input.holdId) : null;
  if (!row) throw new TbError("hold_not_found", "no such hold", 404);
  if (row.status === "held" && row.expiresAt !== null && row.expiresAt <= now) {
    rt.receipts.sweep(now);
    rt.statusChanged();
    throw new TbError("hold_expired", "the hold expired before a decision", 409);
  }
  if (row.status !== "held") throw new TbError("hold_decided", `hold is already ${row.status}`, 409);
  rt.receipts.decide(row.id, input.decision === "approve" ? "approved" : "denied", principal.id, now);
  await rt.audit.record({
    actor: principal.id,
    action: "hold.decide",
    target: row.id,
    detail: { decision: input.decision, op: row.op, caller: row.caller.id, ...(input.note ? { note: input.note.slice(0, 1000) } : {}) },
  });
  rt.statusChanged();
  // v0.1.21: a scheduled op waiting for this hold re-checks now
  if (rt.jobs.store.holdDecided(row.id, now) > 0) rt.jobs.kick();
  return rt.receipts.getSync(row.id) as Receipt;
}

// ── POST /a/<product>/tb/v1/ops/:op (person session + TB-CSRF) ─────────────
const HOLD_STATUSES: readonly ReceiptStatus[] = ["held", "approved", "denied"];

async function runStandardPersonOp(rt: Runtime, principal: PersonPrincipal, id: StandardOpId, input: Record<string, unknown>, res: ServerResponse): Promise<Json | null> {
  switch (id) {
    case "tb.holds_list": {
      const status = input.status as ReceiptStatus | undefined;
      if (status !== undefined && !HOLD_STATUSES.includes(status)) throw new TbError("input_invalid", "status must be held, approved or denied", 400);
      const r = await rt.receipts.list({ status: status ?? [...HOLD_STATUSES], cursor: input.cursor as string | undefined });
      return { items: r.items as unknown as Json, nextCursor: r.nextCursor };
    }
    case "tb.holds_decide":
      return (await decide(rt, principal, input as unknown as HoldDecideInput)) as unknown as Json;
    case "tb.receipts_list": {
      const r = await rt.receipts.list({
        caller: input.caller as AgentId | undefined,
        op: input.op as string | undefined,
        status: input.status as ReceiptStatus | undefined,
        cursor: input.cursor as string | undefined,
      });
      return { items: r.items as unknown as Json, nextCursor: r.nextCursor };
    }
    case "tb.agents_list": {
      const agents = rt.trust.slice?.agents ?? [];
      const out: Json[] = [];
      for (const a of agents) out.push({ id: a.id, name: a.name, mode: a.mode, status: a.status, access: (await rt.scopes.list(a.id)) as unknown as Json });
      return { agents: out };
    }
    case "tb.scopes_set": {
      const { agent, type, id: inst, access, acceptOffer } = input as { agent: AgentId; type: string; id: string; access: string | null; acceptOffer?: { adds: CrudAction[] } };
      // v0.1.35 (C283 A1): THE one place an owner row is written: the verified owner session of this person route. Agent and app
      // callers never reach runStandardPersonOp (audience person); app code holding the store can only write bounded rows.
      await scopeGrantOps(rt.scopes).ownerSet(principal, agent, type, inst, access, acceptOffer);
      return { access: (await rt.scopes.access(agent, type, inst)) as unknown as Json };
    }
    case "tb.keys_status":
      return { keys: (await rt.keys.status()) as unknown as Json };
    case "tb.key_set":
      await rt.keys.set(principal, String(input.name), String(input.value));
      return { ok: true };
    case "tb.key_delete":
      await rt.keys.remove(principal, String(input.name));
      return { ok: true };
    case "tb.export": {
      const ex = await rt.backups.exportNow();
      res.writeHead(200, { "content-type": "application/gzip", "content-disposition": `attachment; filename="${ex.file.split("/").pop()}"`, "cache-control": "no-store" });
      const reader = ex.stream.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
      return null;
    }
    default:
      throw new TbError("audience_not_person", "operation is not person-audience", 403);
  }
}

export async function handlePersonOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, opId: string): Promise<void> {
  const rid = requestId();
  try {
    const session = rt.person.requireSession(req);
    rt.person.requireCsrf(req, session);
    const raw = await readJson(req);
    if (!isObj(raw)) throw new TbError("input_invalid", "body must be { input, idempotencyKey? }", 400);
    const input = (raw.input ?? {}) as Json;
    const op = rt.ops.get(opId);
    if (!op) throw new TbError("unknown_tool", `unknown operation ${opId}`, 404);
    if (op.audience !== "person") throw new TbError("audience_not_person", "operation is not person-audience", 403);
    const v = validateInput(op, input);
    if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
    const principal = session.principal;
    if (op.standard) {
      const out = await runStandardPersonOp(rt, principal, op.id, input as Record<string, unknown>, res);
      if (out !== null) sendJson(res, 200, { status: "ok", output: out } satisfies OpResult);
      return;
    }
    const inputDigest = digest(input);
    const idemKey = idempotencyKeyFor(op, typeof raw.idempotencyKey === "string" ? raw.idempotencyKey : null);
    // v0.1.22 (SDK-01): reserved before the handler, like agent calls
    let idem: IdemLease | null = null;
    if (idemKey) {
      const c = await claimIdempotency(rt, principal.id, op.id, idemKey, inputDigest, `${principal.id}:${op.id}:${idemKey}`);
      if (c.kind === "result") return sendJson(res, 200, { status: "ok", output: c.output } satisfies OpResult);
      if (c.kind === "held") throw new TbError("idempotency_conflict", "idempotency key belongs to a held call", 409);
      idem = c.lease;
    }
    const caller: Caller = { type: "person", id: principal.id as PersonId, name: "owner", mode: null };
    const rh = receiptHelpers();
    let sig: ReturnType<typeof opSignal> | null = null;
    let output: Json;
    try {
      sig = opSignal(req, res);
      const ctx = buildContext(rt, op, caller, null, rt.scopes.view(null, null), null, idemKey, {}, rh.helpers, sig.signal, { ...rt.extras(), workspace: principal.ws });
      // v0.1.31 (SDK-INSTANCE-GRANT): THE one place ctx.scopeGrants is set: a live person op (verified session + CSRF + the owner's confirm)
      const life = opLife(sig.signal);
      ctx.scopeGrants = personScopeGrants(rt, principal, op.id, rid, life);
      // v0.1.32 (SDK-COMPANION-CALLERS): same place, person ops only; each call reads the current slice
      ctx.companionCallers = personCompanionCallers(rt);
      const h = startHandler(rt, op, input, ctx, null);
      life.bind(h.actual);
      const lease = idem;
      idem = null;
      h.actual.then(
        (out) => lease?.result(out),
        () => lease?.release(),
      );
      output = await h.raced;
    } catch (e) {
      idem?.release();
      throw e;
    } finally {
      sig?.done();
    }
    sendJson(res, 200, { status: "ok", output } satisfies OpResult);
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : toTbError(e, rt));
  }
}

export type { OpCallBody };
