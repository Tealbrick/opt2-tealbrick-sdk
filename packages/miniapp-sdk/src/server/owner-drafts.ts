// `ctx.ownerDrafts` (spec 0.1.89, C380, SDK-API "v0.1.89", BRIDGE §8.8, cap `owner_drafts`): an app asks Portal to prepare a stop for the owner.
// The app only asks. The owner approves in the browser, and Core applies. Op, start, event and job contexts all get this ONE object.
// Nothing is logged here: a get answer holds step output, and BRIDGE §8.8 says that body is never logged.
import type { AgentId, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { BridgeClient, BridgeResponse } from "./bridge-client.ts";
import { TbError } from "./errors.ts";

// LOCAL COPY of spec 0.1.89 (bridge.ts, sdk.ts): the SDK pins an older spec. Drop this block when the pin moves.
export const OWNER_DRAFTS_CAP = "owner_drafts";
const OWNER_DRAFT_PATHS = { request: "/tb/v1/owner-drafts", get: "/tb/v1/owner-drafts/get", withdraw: "/tb/v1/owner-drafts/withdraw" } as const;
export const OWNER_DRAFT_OPS = ["agents.pause", "agents.offboard", "agents.rotate"] as const;
export type OwnerDraftOpId = (typeof OWNER_DRAFT_OPS)[number];
/** Core refuses more with 400 `validation_failed`; over `openMax` 409 `owner_drafts_full`; over `perHour` 429 `rate_limited`. A plan with more agents than `stepsMax` splits. */
export const OWNER_DRAFT_LIMITS = { titleMaxChars: 120, stepsMax: 100, expiresInSecMin: 60, expiresInSecMax: 86400, openMax: 10, perHour: 30 } as const;
export const OWNER_DRAFT_KEY_PATTERN = "^pln_[A-Za-z0-9._:-]{1,124}$";
export interface OwnerDraftRequestBody {
  /** `^pln_[A-Za-z0-9._:-]{1,124}$`, unique per (ins, key): one plan, or one numbered part of a split plan */
  key: string;
  /** generic, e.g. "Governance: stop request": never a person or a reason. 1..120 chars. Core writes the headline. */
  title: string;
  /** the app's own digest of its plan; shown as "reported by the app", never the bound digest */
  planDigest: Sha256Digest;
  /** 60..86400 */
  expiresInSec: number;
  /** 1..100, in order; each (opId, agt) once; no other member */
  steps: { opId: OwnerDraftOpId; agt: AgentId }[];
}
/** `DraftState`, or `expired` = `expiresAt` passed and the draft was not applied. */
export type OwnerDraftState = "open" | "submitted" | "applying" | "applied" | "failed" | "rejected" | "expired";
export interface OwnerDraftStatus {
  draftId: `drf_${string}`;
  state: OwnerDraftState;
  /** the Portal page where the owner approves */
  reviewUrl: string;
}
export interface OwnerDraftGetResult extends OwnerDraftStatus {
  /** Core's bound digest of the stored steps */
  digest: Sha256Digest;
  expiresAt: string;
  steps: { n: number; opId: OwnerDraftOpId; agt: AgentId; status: "pending" | "ok" | "failed" | "skipped"; output?: unknown; error?: { code: string; message: string } }[];
  /** null until the draft was applied */
  receiptId: `rcp_${string}` | null;
}
export interface OwnerDraftsApi {
  /** Same key and same steps: same answer. Same key and other steps: the open draft is rejected and replaced. */
  request(body: OwnerDraftRequestBody): Promise<OwnerDraftStatus>;
  get(key: string): Promise<OwnerDraftGetResult>;
  /** Rejects the open draft of this key. Applied or applying: 409 `draft_state`. */
  withdraw(key: string): Promise<OwnerDraftStatus>;
}
export interface OwnerDraftsView {
  /** `bridge_cap_missing` (409, `details.cap`) before any network call without the cap; every refusal is a TbError with the bridge's or Core's code and `details` */
  ownerDrafts: OwnerDraftsApi;
}

/** A longer wait than this is not believed: Core's own window (`perHour`) is one hour. */
const RETRY_AFTER_MAX_MS = 3_600_000;

function retryAfterMs(header: string | undefined): number | null {
  if (header === undefined || !/^\d{1,9}$/.test(header.trim())) return null;
  return Math.min(Number(header.trim()) * 1000, RETRY_AFTER_MAX_MS);
}

/**
 * A refusal keeps Core's `details`, because the app acts on them: `pointer` (no pointer on a 404 = the rail is off), `reason` (the consent is off, the draft expired).
 * `Retry-After` becomes `details.retryAfterMs`, which a handler job's retry already reads. errorFrom() has no `details`; it is left as it is, so its other callers answer as before.
 */
function refusal(r: BridgeResponse): TbError {
  const e = (r.body as { error?: { code?: unknown; message?: unknown; details?: unknown } } | null)?.error;
  const details: Record<string, unknown> = e?.details !== null && typeof e?.details === "object" && !Array.isArray(e.details) ? { ...(e.details as Record<string, unknown>) } : {};
  const wait = retryAfterMs(r.retryAfter);
  if (wait !== null) details.retryAfterMs = wait;
  return new TbError(typeof e?.code === "string" ? e.code : "app_error", typeof e?.message === "string" ? e.message : `bridge answered ${r.status}`, r.status >= 400 ? r.status : 502, Object.keys(details).length > 0 ? details : undefined);
}

export function createOwnerDrafts(io: { bridgeCaps(): readonly string[]; sliceStale(): boolean; bridge(): BridgeClient | null }): OwnerDraftsApi {
  const post = async <T>(path: string, body: unknown, readable: (a: Record<string, unknown>) => boolean = () => true): Promise<T> => {
    // A slice that is missing or older than 12 h shows no caps at all. That says nothing about the bridge, so `reason` keeps it apart from a real "no cap" (ownerDraftsRailOff).
    if (!io.bridgeCaps().includes(OWNER_DRAFTS_CAP)) throw new TbError("bridge_cap_missing", `the workspace bridge does not declare the capability ${OWNER_DRAFTS_CAP}`, 409, { cap: OWNER_DRAFTS_CAP, ...(io.sliceStale() ? { reason: "slice_stale" } : {}) });
    const bridge = io.bridge();
    if (!bridge) throw new TbError("no_bridge", "owner drafts need the bridge", 503);
    const r = await bridge.request("POST", path, body);
    if (r.status < 200 || r.status >= 300) throw refusal(r);
    // the same rule as BRIDGE §8.8: no answer is invented. A plan never moves on a body it cannot read.
    const a = r.body as Record<string, unknown> | null;
    if (typeof a?.draftId !== "string" || typeof a.state !== "string" || typeof a.reviewUrl !== "string" || !readable(a)) throw new TbError("portal_unavailable", "the bridge answered without a readable owner draft", 503);
    return r.body as T;
  };
  return {
    request: (body) => post<OwnerDraftStatus>(OWNER_DRAFT_PATHS.request, body),
    get: (key) => post<OwnerDraftGetResult>(OWNER_DRAFT_PATHS.get, { key }, (a) => Array.isArray(a.steps)),
    withdraw: (key) => post<OwnerDraftStatus>(OWNER_DRAFT_PATHS.withdraw, { key }),
  };
}

/**
 * CORE v0.1.89: true when the rail is not there, so the app stays in Portal link mode: a bridge without the cap, a standalone bridge, or
 * a 404 with no `details.pointer` (Core's flag is off, or Core is older). False for a 404 WITH a pointer (a real answer about an agent or a key), and for a
 * stale slice (`details.reason` "slice_stale"): the rail may be there and a draft may be open, so the app tries again and does not fall back.
 */
export function ownerDraftsRailOff(e: unknown): boolean {
  if (!(e instanceof TbError)) return false;
  if (e.code === "bridge_cap_missing") return e.details?.cap === OWNER_DRAFTS_CAP && e.details.reason === undefined;
  if (e.code === "owner_drafts_unsupported") return true;
  return e.httpStatus === 404 && e.code === "not_found" && e.details?.pointer === undefined;
}
