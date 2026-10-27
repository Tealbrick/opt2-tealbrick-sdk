// Per-workflow companion grants, caller side (SDK-API §22, BRIDGE §8.6; spec 0.1.82, C373 P1).
// The ONE place that fetches, caches and drops workflow grants (K10 with `wfl`) and that implements `ctx.workflowGrants`.
// Workflow grants live in memory only: never in the DB, a log or a receipt. They are short-lived (WORKFLOW_GRANT_TTL_SEC) and are
// re-fetched at half-life, so a withdrawal reaches this cache within one fetch; the bridge refuses a withdrawn grant at once.
import {
  APP_WORKFLOW_GRANTS_CAP,
  WORKFLOW_GRANT_PATHS,
  WORKFLOW_GRANT_REQUEST_LIMITS,
  WORKFLOW_ID_PATTERN,
  type WorkflowGrantGetResult,
  type WorkflowGrantRequestBody,
  type WorkflowGrantStatus,
} from "@opt2-tealbrick/manifest";
import { type Companion, CRUD_ACTIONS, type CrudAction } from "@opt2-tealbrick/spec/manifest";
import type { BridgeClient } from "./bridge-client.ts";
import { type BridgeResponse, errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import { peekClaims } from "./ops.ts";
import type { Runtime } from "./runtime.ts";
import type { WorkflowGrantsApi } from "./spec-p1.temp.ts";

const WORKFLOW_ID_RE = new RegExp(WORKFLOW_ID_PATTERN);
type PerWorkflowEntry = Companion & { perWorkflow?: { operations: string[]; crud: CrudAction[] } };

/** A cached workflow grant and the claims the SDK reads from it (the bridge and the target verify the signature). */
export interface CachedWorkflowGrant {
  token: string;
  aud: string;
  wf: readonly string[];
  iat: number;
  exp: number;
}

export const isWorkflowId = (v: unknown): v is string => typeof v === "string" && WORKFLOW_ID_RE.test(v);

/** `bridge_cap_missing` (409, details.cap), the P3/P4 shape; thrown before any network call. */
export function requireWorkflowCap(rt: Pick<Runtime, "trust">): void {
  if (!rt.trust.bridgeCaps(Date.now()).includes(APP_WORKFLOW_GRANTS_CAP)) {
    throw new TbError("bridge_cap_missing", `the workspace bridge does not declare the capability ${APP_WORKFLOW_GRANTS_CAP}; call without a workflow`, 409, {
      cap: APP_WORKFLOW_GRANTS_CAP,
    });
  }
}

/** The manifest entry for ONE product (never `"*"`) and its `perWorkflow` ceiling, if any. */
export function perWorkflowEntry(rt: Pick<Runtime, "manifest">, product: string): PerWorkflowEntry | undefined {
  if (product === "*") return undefined;
  return (rt.manifest.companions as PerWorkflowEntry[] | undefined)?.find((c) => c.product === product);
}

/**
 * Core's refusal as it came through the bridge relay (code, message, status) WITH its `details` (a plain object): the caller needs
 * `details.product` of `workflow_grants_unsupported` and `details.pointer` of `validation_failed` (SDK-API §22 items 2, 3).
 */
function coreError(r: BridgeResponse, fallback: string): TbError {
  const e = errorFrom(r, fallback);
  const d = (r.body as { error?: { details?: unknown } } | null)?.error?.details;
  return d && typeof d === "object" && !Array.isArray(d) ? new TbError(e.code, e.message, e.httpStatus, d as Record<string, unknown>) : e;
}

const validation = (pointer: string, message: string) => new TbError("validation_failed", message, 400, { pointer });

/**
 * The local pre-check of a request (SDK-API §22 item 2: "the SDK may check this locally first"); Core always checks again. The first
 * failing rule wins: `wfl`, `title`, `reason`, `targets` (1..8, unique product, not the own product, a declared `perWorkflow` entry),
 * `ops` (1..64 unique, ⊆ `perWorkflow.operations`), `crud` (1..4 unique crud actions, ⊆ `perWorkflow.crud`).
 */
export function workflowRequestProblem(rt: Pick<Runtime, "manifest">, body: WorkflowGrantRequestBody): TbError | null {
  const b = body as unknown as Record<string, unknown> | null;
  if (!b || typeof b !== "object" || Array.isArray(b)) return validation("", "the request is not an object");
  const extra = Object.keys(b).filter((k) => k !== "wfl" && k !== "title" && k !== "targets" && k !== "reason");
  if (extra.length) return validation(`/${extra[0]}`, "unknown field");
  if (!isWorkflowId(b.wfl)) return validation("/wfl", "wfl is not a workflow id");
  const L = WORKFLOW_GRANT_REQUEST_LIMITS;
  if (typeof b.title !== "string" || b.title.trim() === "" || [...b.title].length > L.titleMaxChars) return validation("/title", `title must be 1..${L.titleMaxChars} characters`);
  if (b.reason !== undefined && (typeof b.reason !== "string" || [...b.reason].length > L.reasonMaxChars)) return validation("/reason", `reason must be at most ${L.reasonMaxChars} characters`);
  const targets = b.targets;
  if (!Array.isArray(targets) || targets.length < 1 || targets.length > L.targetsMax) return validation("/targets", `targets must have 1..${L.targetsMax} entries`);
  const seen = new Set<string>();
  for (const [i, raw] of targets.entries()) {
    const p = `/targets/${i}`;
    const t = raw as Record<string, unknown> | null;
    if (!t || typeof t !== "object" || Array.isArray(t)) return validation(p, "target is not an object");
    const tExtra = Object.keys(t).filter((k) => k !== "product" && k !== "ops" && k !== "crud");
    if (tExtra.length) return validation(`${p}/${tExtra[0]}`, "unknown field");
    if (typeof t.product !== "string" || seen.has(t.product)) return validation(`${p}/product`, "product missing or repeated");
    seen.add(t.product);
    if (t.product === rt.manifest.id) return validation(`${p}/product`, "an app does not request a workflow grant for itself");
    const pw = perWorkflowEntry(rt, t.product)?.perWorkflow;
    if (!pw) return validation(`${p}/product`, `no companions[].perWorkflow for ${t.product}`);
    const ops = t.ops;
    if (!Array.isArray(ops) || ops.length < 1 || ops.length > L.opsPerTargetMax || new Set(ops).size !== ops.length) return validation(`${p}/ops`, `ops must be 1..${L.opsPerTargetMax} unique op ids`);
    for (const [j, op] of ops.entries()) if (typeof op !== "string" || !pw.operations.includes(op)) return validation(`${p}/ops/${j}`, "op is not in perWorkflow.operations");
    const crud = t.crud;
    if (!Array.isArray(crud) || crud.length < 1 || new Set(crud).size !== crud.length) return validation(`${p}/crud`, "crud must be 1..4 unique crud actions");
    for (const [j, c] of crud.entries()) {
      if (!(CRUD_ACTIONS as readonly unknown[]).includes(c) || !pw.crud.includes(c as CrudAction)) return validation(`${p}/crud/${j}`, "crud is not in perWorkflow.crud");
    }
  }
  return null;
}

/**
 * The cache and the relays. One instance per running app (owned by the bridge link). Keyed by (workflow, target instance).
 */
export class WorkflowGrants {
  readonly #rt: Pick<Runtime, "manifest" | "trust">;
  readonly #client: BridgeClient;
  readonly #cache = new Map<string, CachedWorkflowGrant>();

  constructor(rt: Pick<Runtime, "manifest" | "trust">, client: BridgeClient) {
    this.#rt = rt;
    this.#client = client;
  }

  static #key(wfl: string, aud: string): string {
    return `${wfl}\n${aud}`;
  }

  /** Number of cached grants (tests). */
  get size(): number {
    return this.#cache.size;
  }

  /** The target instance of `product` from the CURRENT slice `companionTargets` (sorted by id; the first one). */
  targetOf(product: string): string | null {
    const ins = this.#rt.trust
      .companionTargets()
      .filter((t) => t.product === product)
      .map((t) => t.ins)
      .sort();
    return ins[0] ?? null;
  }

  /** Drops the cached grants of `wfl` (all targets, or one). */
  drop(wfl: string, aud?: string): void {
    for (const k of [...this.#cache.keys()]) if (k.startsWith(`${wfl}\n`) && (aud === undefined || k === WorkflowGrants.#key(wfl, aud))) this.#cache.delete(k);
  }

  /** A new slice: drop the grants for targets no longer listed in `companionTargets` (SDK-API §22 item 6). */
  onSlice(): void {
    const live = new Set(this.#rt.trust.companionTargets().map((t) => t.ins));
    for (const [k, g] of this.#cache) if (!live.has(g.aud)) this.#cache.delete(k);
  }

  /**
   * The grant for (wfl, product): the cached one while more than half its life is left, else a fresh one from Core through the bridge relay
   * (`workflow-grants/get` with `aud`). `fresh` skips the cache. Core's refusals are thrown as they come (`workflow_grant_missing` 404,
   * `workflow_grant_withdrawn` 410, `workflow_grants_unsupported` 409 + details.product). A minted grant that does not name this
   * instance, this target and this workflow is refused (`grant_invalid`, nothing cached).
   */
  async grantFor(wfl: string, product: string, fresh = false): Promise<CachedWorkflowGrant> {
    const aud = this.targetOf(product);
    if (!aud) throw new TbError("no_grant", `no companion target for ${product} in the slice`, 403);
    const key = WorkflowGrants.#key(wfl, aud);
    const now = Math.floor(Date.now() / 1000);
    const hit = this.#cache.get(key);
    if (!fresh && hit && now < hit.iat + Math.floor((hit.exp - hit.iat) / 2)) return hit;
    this.#cache.delete(key);
    const r = await this.#client.request("POST", WORKFLOW_GRANT_PATHS.workflowGrantGet, { wfl, aud });
    if (r.status !== 200) throw coreError(r, "workflow_grant_missing");
    const token = (r.body as WorkflowGrantGetResult | null)?.grant;
    if (typeof token !== "string") throw new TbError("workflow_grant_missing", `no applied workflow grant for ${wfl} on ${product}`, 404);
    const c = peekClaims(token);
    const wf = c?.wf;
    if (
      !c ||
      c.wfl !== wfl ||
      c.sub !== this.#rt.trust.self ||
      c.aud !== `tb:ins:${aud}` ||
      !Array.isArray(wf) ||
      !wf.every((x) => typeof x === "string") ||
      !Number.isSafeInteger(c.iat) ||
      !Number.isSafeInteger(c.exp) ||
      (c.exp as number) <= now
    ) {
      throw new TbError("grant_invalid", "the workflow grant does not match this caller, target and workflow", 502);
    }
    const g: CachedWorkflowGrant = { token, aud, wf: wf as string[], iat: c.iat as number, exp: c.exp as number };
    this.#cache.set(key, g);
    return g;
  }

  async #relay(path: string, body: unknown): Promise<WorkflowGrantStatus> {
    const r = await this.#client.request("POST", path, body);
    if (r.status !== 200) throw coreError(r, "bridge_error");
    const res = r.body as WorkflowGrantStatus | WorkflowGrantGetResult | null;
    // `/get` answers {status, grant?}; `/request` and `/release` answer the status itself
    const status = res && typeof res === "object" && "status" in res && typeof res.status === "object" ? res.status : res;
    if (!status || typeof status !== "object" || typeof (status as WorkflowGrantStatus).state !== "string") throw new TbError("bridge_error", "the bridge answered no workflow grant status", 502);
    return status as WorkflowGrantStatus;
  }

  /** `ctx.workflowGrants` (SDK-API §22 item 2). Cap first (409), then the local pre-check (400 validation_failed), then the relay. */
  api(): WorkflowGrantsApi {
    const rt = this.#rt;
    return {
      request: async (body) => {
        requireWorkflowCap(rt);
        const problem = workflowRequestProblem(rt, body);
        if (problem) throw problem;
        const s = await this.#relay(WORKFLOW_GRANT_PATHS.workflowGrantRequest, body);
        // the applied set may have changed (narrowed at once, or widened earlier): the next call fetches a fresh grant
        this.drop(body.wfl);
        return s;
      },
      status: async (wfl) => {
        requireWorkflowCap(rt);
        if (!isWorkflowId(wfl)) throw validation("/wfl", "wfl is not a workflow id");
        return this.#relay(WORKFLOW_GRANT_PATHS.workflowGrantGet, { wfl });
      },
      release: async (wfl) => {
        requireWorkflowCap(rt);
        if (!isWorkflowId(wfl)) throw validation("/wfl", "wfl is not a workflow id");
        // kill path: the cache goes first, whatever the relay answers
        this.drop(wfl);
        return this.#relay(WORKFLOW_GRANT_PATHS.workflowGrantRelease, { wfl });
      },
    };
  }
}

/** `ctx.workflowGrants` without a bridge (standalone mode): the cap check first (the slice has no caps), then `no_bridge`. */
export function workflowGrantsWithoutBridge(rt: Pick<Runtime, "trust">): WorkflowGrantsApi {
  const refuse = async (): Promise<never> => {
    requireWorkflowCap(rt);
    throw new TbError("no_bridge", "workflow grants need the bridge", 503);
  };
  return { request: refuse, status: refuse, release: refuse };
}
