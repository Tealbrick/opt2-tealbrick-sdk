// TEMP until spec 0.1.82 pin (C373 P1, per-workflow companion grants; SDK-API §22).
// A mirror of the P1 additions to `@opt2-tealbrick/spec/sdk` on the spec branch `spec/c373-p1-workflow-grants`. When this package pins
// spec 0.1.82, delete this file: `CallAppOptions.workflow`, `Caller.workflow`, `WorkflowGrantsApi` and the contexts' `workflowGrants`
// come from `@opt2-tealbrick/spec/sdk` itself (same names, same shapes).
import type { WorkflowGrantRequestBody, WorkflowGrantStatus, WorkflowId } from "@opt2-tealbrick/manifest";
import type { CallAppOptions, Caller } from "@opt2-tealbrick/spec/sdk";

/** v0.1.82 `CallAppOptions.workflow`: run this call under the owner-approved grant of this workflow (WORKFLOW_ID_PATTERN). The SDK
 *  selects or fetches the workflow grant for (workflow, target), sets `CallEnvelope.workflow`, and NEVER falls back to the base grant. */
export type CallAppOptionsP1 = CallAppOptions & { workflow?: WorkflowId };
/** v0.1.82 `Caller.workflow`: app callers only — the VERIFIED `wfl` of the presented companion grant. Absent for a base grant. */
export type CallerP1 = Caller & { workflow?: WorkflowId };
/** v0.1.82 (SDK-API §22): `ctx.workflowGrants`. Every method throws `bridge_cap_missing` (409, `details.cap: "app_workflow_grants"`) before
 *  any network call when the slice bridge caps lack it; Core refusals surface as TbError with Core's code. */
export interface WorkflowGrantsApi {
  /** Narrower or equal to the applied set → applied at once. Wider → an owner draft. Same body again → same answer. */
  request(body: WorkflowGrantRequestBody): Promise<WorkflowGrantStatus>;
  status(wfl: WorkflowId): Promise<WorkflowGrantStatus>;
  /** Withdraw the whole record (kill path) and drop every cached grant of that workflow. */
  release(wfl: WorkflowId): Promise<WorkflowGrantStatus>;
}
