// TEMP until spec 0.1.82 pin (C373 P1, per-workflow companion grants).
// A byte-for-byte mirror of the P1 additions on the spec branch `spec/c373-p1-workflow-grants` (Tealbrick/opt2-tealbrick-specs,
// packages/spec/src/{credentials,manifest}.ts and schemas/manifest.schema.json). When the manifest package pins spec 0.1.82,
// delete this file and import every name below from `@opt2-tealbrick/spec/*` instead (the names and values are the spec's).
// Nothing here is a second definition: it is the spec text, held locally for the time between the two releases.
import type { CallEnvelope, CompactJws, EpochS, HookCallInfo, IsoTime, JsonValue } from "@opt2-tealbrick/spec/bridge";
import type { CompanionGrantClaims, InstanceId, InstanceRef, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, ProductId, SnakeId } from "@opt2-tealbrick/spec/manifest";
import manifestSchema from "@opt2-tealbrick/spec/schemas/manifest.schema.json" with { type: "json" };

// ── spec/credentials (v0.1.82) ────────────────────────────────────────────────
/** v0.1.82 (C373, P1): lifetime of a per-workflow companion grant (a K10 grant with `wfl`), exp − iat, seconds. Such a grant is
 *  minted on demand (never in a slice or the config), so its short life bounds how long a withdrawal record must live. */
export const WORKFLOW_GRANT_TTL_SEC = 900;
/** The workflow id of the CALLER app (`wfl` claim). Not `wf`: `wf` stays the list of allowed operation ids. */
export type WorkflowId = string;
/** `wfl` claim, `CallEnvelope.workflow`, `CallAppOptions.workflow`, withdrawal records: 3..40 chars. */
export const WORKFLOW_ID_PATTERN = "^[a-z][a-z0-9-]{2,39}$";
/** v0.1.82 (C373, P1): a companion grant WITH `wfl` (a "workflow grant"), minted by Core on demand through the bridge relay
 *  `bridge_api.workflow_grant_get`; never carried in a slice or in the config. `exp − iat` ≤ WORKFLOW_GRANT_TTL_SEC; `prd` always present. */
export type WorkflowGrantClaims = CompanionGrantClaims & { wfl: WorkflowId; prd: ProductId };

// ── spec/manifest (v0.1.82) ───────────────────────────────────────────────────
/** v0.1.82 (C373, P1): `companions[].perWorkflow`. M-CP-4 checks it against the target like M-CP-2 checks `operations`/`crud`. */
export interface CompanionPerWorkflow {
  /** 1..PER_WORKFLOW_OPS_MAX unique op ids of the target; never a standard (`tb.*`) op */
  operations: SnakeId[];
  crud: CrudAction[];
}
/** v0.1.82 (C373, P1): most ops in one `perWorkflow.operations` (schema maxItems), and in one target of a workflow grant request. */
export const PER_WORKFLOW_OPS_MAX = 64;

// ── schemas/manifest.schema.json (v0.1.82) ─────────────────────────────────────
type SchemaNode = Record<string, unknown>;
/**
 * The 0.1.78 manifest schema with the 0.1.82 `$defs.companion` change applied (a deep copy; the imported object is not touched):
 * `perWorkflow` (closed object, required operations + crud) and "not for product `*`".
 */
export function manifestSchemaP1(): SchemaNode {
  const s = structuredClone(manifestSchema) as SchemaNode;
  const companion = (s.$defs as Record<string, SchemaNode>).companion as SchemaNode;
  if ((companion.properties as SchemaNode).perWorkflow) return s; // already in the pinned spec
  companion.if = { properties: { product: { const: "*" } } };
  // biome-ignore lint/suspicious/noThenProperty: the JSON Schema keyword `then` (a schema object, never awaited)
  companion.then = { not: { required: ["perWorkflow"] } };
  (companion.properties as SchemaNode).perWorkflow = {
    description:
      'v0.1.82 (C373, P1, M-CP-4): ceiling for per-workflow grants; its ops are not in the base grant. One product only (not "*"); never a tb.* op.',
    type: "object",
    additionalProperties: false,
    required: ["operations", "crud"],
    properties: {
      operations: { type: "array", minItems: 1, maxItems: PER_WORKFLOW_OPS_MAX, uniqueItems: true, items: { $ref: "#/$defs/snakeId" } },
      crud: { $ref: "#/$defs/crudSet" },
    },
  };
  return s;
}

// ── spec/bridge (v0.1.82; BRIDGE §8.6) ────────────────────────────────────────
/** v0.1.82 (C373, P1): the bridge error codes of per-workflow companion grants (members of the spec's `BridgeErrorCode`). */
export type WorkflowGrantErrorCode =
  /** 403: the grant's `wfl` ≠ `CallEnvelope.workflow` (also when the envelope names none) */
  | "workflow_mismatch"
  /** 403: the envelope names a workflow but the presented grant has no `wfl` (a base grant is never used for a workflow call) */
  | "workflow_grant_required"
  /** 403 at the bridge (withdrawal record, `wflEpoch`, or no enabled companion edge); 410 from Core on `workflow_grant_get` */
  | "workflow_grant_withdrawn"
  /** 404 from Core: no applied workflow grant for (caller, workflow[, target]) */
  | "workflow_grant_missing"
  /** 409: the gate is off for this target (bridge cap, caller SDK, target SDK; standalone); `details.product` names it */
  | "workflow_grants_unsupported"
  /** 409 from Core: the caller has WORKFLOW_GRANTS_MAX requested + applied records */
  | "workflow_grants_full";
/** v0.1.82 (C373, P1): one withdrawal record (config only, never in a slice). The bridge refuses a presented grant with `wfl` when `sub`
 *  and `wfl` equal the grant's, `aud` is absent or equals the grant's, and grant `iat ≤ at` (`workflow_grant_withdrawn`). */
export interface WorkflowGrantWithdrawal {
  sub: InstanceRef;
  wfl: WorkflowId;
  /** absent = every target of that workflow */
  aud?: InstanceRef;
  at: EpochS;
}
/** v0.1.82 (C373, P1): config fields (`ConfigCredentialFields`), sent only to a bridge that declares `app_workflow_grants`. */
export interface WorkflowGrantConfigFields {
  workflowGrantsWithdrawn?: WorkflowGrantWithdrawal[];
  /** per caller instance ref: every wfl grant of that caller with `iat ≤` this value is withdrawn */
  wflEpoch?: Record<InstanceRef, EpochS>;
}
/** v0.1.82 (C373, P1): the cap name of per-workflow companion grants (one of BRIDGE_CAPS). */
export const WORKFLOW_GRANTS_CAP = "app_workflow_grants" as const;
/** v0.1.82 (C373, P1): live withdrawal records per caller instance that Core keeps in the config (then a `wflEpoch` bump). */
export const WORKFLOW_WITHDRAWN_MAX = 64;
/** v0.1.82 (C373, P1): `CallEnvelope.workflow` — the caller's workflow id this call runs for; MUST equal the presented grant's `wfl`
 *  (`workflow_mismatch`); with a grant that has no `wfl` → `workflow_grant_required`. Gate-relevant; `context` stays informational. */
export type CallEnvelopeP1<I = JsonValue> = CallEnvelope<I> & { workflow?: WorkflowId };
/** v0.1.82 (C373 P1): `HookCallInfo.caller.workflow` = the VERIFIED `wfl` of the presented grant (app callers with a workflow grant only). */
export type HookCallerP1 = HookCallInfo["caller"] & { workflow?: WorkflowId };
/** One target of a workflow grant: the target product, the ops and crud the workflow needs there. */
export interface WorkflowGrantTarget {
  product: ProductId;
  /** 1..PER_WORKFLOW_OPS_MAX unique, each in the caller's `companions[product].perWorkflow.operations` (no `tb.*`) */
  ops: SnakeId[];
  /** 1..4 unique, ⊆ `perWorkflow.crud` ∩ the companion edge crud */
  crud: CrudAction[];
}
/** Limits of a request (Core refuses more with 400 `validation_failed` + `details.pointer`). */
export const WORKFLOW_GRANT_REQUEST_LIMITS = { titleMaxChars: 120, reasonMaxChars: 280, targetsMax: 8, opsPerTargetMax: 64 } as const;
/** The bridge's own bucket for the three relays, per caller instance (separate from the call bucket); over it → 429 `rate_limited`. */
export const WORKFLOW_GRANT_RELAY_LIMIT = { perMinute: 240, burst: 60 } as const;
/** `POST /tb/v1/workflow-grants/request` body (app → bridge); relayed as `bridge_api.workflow_grant_request` with the TB-Assert instance. */
export interface WorkflowGrantRequestBody {
  wfl: WorkflowId;
  /** shown to the owner; 1..120 chars, plain text */
  title: string;
  /** 1..8 targets, unique `product`, never the caller's own product */
  targets: WorkflowGrantTarget[];
  /** shown to the owner as "reported by the app"; ≤ 280 chars */
  reason?: string;
}
/** `POST /tb/v1/workflow-grants/get` body. Without `aud` = status only. With `aud` = status + a minted grant when applied for that target. */
export interface WorkflowGrantGetBody {
  wfl: WorkflowId;
  aud?: InstanceId;
}
/** `POST /tb/v1/workflow-grants/release` body. Kill path: the record is withdrawn at once. */
export interface WorkflowGrantReleaseBody {
  wfl: WorkflowId;
}
/** State of one (caller instance, workflow) record. `none` = Core has no record. */
export type WorkflowGrantState = "none" | "requested" | "applied" | "rejected" | "withdrawn";
/** The answer of all three relays (and `ctx.workflowGrants.*`). */
export interface WorkflowGrantStatus {
  wfl: WorkflowId;
  state: WorkflowGrantState;
  title: string | null;
  /** the applied set (state `applied` only, else null) */
  applied: WorkflowGrantTarget[] | null;
  /** digest of the applied set's request (the canonical body), else null */
  appliedDigest: Sha256Digest | null;
  /** an open owner draft: the first request (state `requested`) or a widening of the applied set (state `applied`) */
  pending: { digest: Sha256Digest; targets: WorkflowGrantTarget[]; reviewUrl: string } | null;
  /** digest of the last request the owner rejected while no newer request is open, else null */
  rejectedDigest: Sha256Digest | null;
  updatedAt: IsoTime | null;
}
/** Answer of `workflow-grants/get`: `grant` (a K10 compact JWS with `wfl`) only with `aud` and state `applied` for that target. */
export interface WorkflowGrantGetResult {
  status: WorkflowGrantStatus;
  grant?: CompactJws;
}
/** v0.1.82 (C373, P1; BRIDGE §8.6): the three `BRIDGE_INTERNAL_PATHS` entries (TB-Assert; the bridge adds the verified instance). */
export const WORKFLOW_GRANT_PATHS = {
  workflowGrantRequest: "/tb/v1/workflow-grants/request",
  workflowGrantGet: "/tb/v1/workflow-grants/get",
  workflowGrantRelease: "/tb/v1/workflow-grants/release",
} as const;
