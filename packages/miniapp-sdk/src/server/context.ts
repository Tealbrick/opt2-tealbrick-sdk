// Context members added by Coordinator C31 on top of types/sdk.ts §B (SPEC-GAP until the spec package declares them):
// `publicUrl` (slice `bridge.publicUrl`), `viewUrl` (slice `bridge.viewUrl`, 0.1.26), `workspace`, `scopes.instances` and `secrets` (the ONE app-secret store).
import type { ScopeRequest } from "@opt2-tealbrick/spec/bridge";
import type { WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { AppDefinition, CallAppOptions, Caller, CompanionResult, EventContext, HookContext, Json, OpContext, PublicHandler, ScopeStore, SliceAgent, StartContext as SpecStartContext } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";
import type { JobHandler, JobSpec, JobsView } from "./jobs.ts";
import type { OwnerDraftsView } from "./owner-drafts.ts";
import type { SliceTopologyView } from "./topology.ts";

export interface ContextExtras {
  /** bridge public origin (`https://<bridge>`) for third-party callbacks `…/p/<product><path>`; null until the slice names it */
  publicUrl: string | null;
  /**
   * v0.1.26 (LA-1, C232, spec 0.1.43): the workspace views service origin (`https://<tb-views>`) from the verified slice
   * (`bridge.viewUrl`); null until Core created tb-views. Re-read from the CURRENT slice on every context, so it changes
   * when a new slice arrives. While it is null an app answers 409 `view_origin_missing` (`requireViewUrl`).
   */
  viewUrl: string | null;
  /** workspace from the verified slice; before the first slice the SDK refuses with 503 workspace_unknown */
  workspace: WorkspaceId;
  scopes: Pick<ScopeStore, "instances">;
  secrets: AppSecrets;
}
/**
 * v0.1.32 (Coordinator decision for Connect): `listed` on APP callers = the verified caller instance is in the CURRENT signed
 * slice `companionCallers` under the SAME verified product as `caller.product`; false when the slice is stale or the caller
 * is not listed (or listed under another product). ABSENT (no key) on person and agent callers.
 * Typed in spec 0.1.49 (`Caller.listed`); `SdkCaller` stays exported as an alias for code written against the 0.1.48 types.
 */
export type SdkCaller = Caller;
export type SdkOpContext = Omit<OpContext, "callApp"> & { caller: SdkCaller; callApp: ActingCallApp } & ContextExtras & CompanionTargetsView & JobsView & ApprovalView & ActingView & SendTimeView & OwnerDraftsView;
export type SdkHookContext = HookContext & { secrets: AppSecrets };
export type SdkPublicContext = Parameters<PublicHandler>[1] & ContextExtras;
export type { AppSecrets };

/**
 * v0.1.44 (C378, SPEC-GAP SDK-API §4.3): the owner approval THIS call runs on. Set only by the SDK, and only after it found the approved
 * hold of this exact call and consumed it, so one approval proves one call. Null on every other call and on the hold-view context. It
 * lets a handler keep an action to approved calls whatever held them (a hold family of the grant, or a bridge-attested Rules hold).
 */
export interface ApprovedHold {
  readonly id: string;
  /** the family the hold was made under; null when the hold record has none */
  readonly family: string | null;
}
export interface ApprovalView {
  approvedHold: ApprovedHold | null;
}

/**
 * spec 0.1.88 (C378, SDK-API "v0.1.88", BRIDGE §8.7, bridge cap `acting_agents`). LOCAL TYPES: the SDK pins an older spec; drop them when the pin moves.
 * `tb.acting` is verified by the bridge and covered by the proof. NARROW ONLY: an app may refuse or hold on it, never allow more because of it.
 */
export interface ActingAgent {
  id: string;
  via: "parent_call" | "ticket";
  job?: string;
}
export interface ActingContext {
  v: 1;
  agents: ActingAgent[];
}
/** The durable job a set of tickets belongs to. Keep it in the app's own database, never in a log or a workflow payload. */
export interface ActingEnvelope {
  job: string;
  tickets: string[];
}
export type ActingCallApp = <O = Json>(product: string, op: string, input: Json, opts?: CallAppOptions & { acting?: ActingEnvelope }) => Promise<CompanionResult<O>>;
export interface ActingView {
  /** the agents this call acts for, from `tb.acting`; null = none (an agent caller, or the app's own work) */
  acting(): ActingContext | null;
  /** tickets of the current call for one durable job (op handlers only; `bridge_cap_missing` without the cap; `acting_call_invalid` when the call acts for no agent) */
  actingTickets(job: string): Promise<string[]>;
}
/** The caller a send-time check asks about: the one who asked for the work. A claimed caller is enough, because nothing runs and the app only checks itself. */
export type SendTimeCaller = { type: "agent"; id: string } | { type: "app"; id: string };
export type SendTimeOutcome =
  /** go on; `approvedHold` = the owner's approval this run consumed */
  | { decision: "run"; approvedHold: ApprovedHold | null }
  /** wait for the owner: keep `holdId` with the job and ask again later */
  | { decision: "wait"; holdId: string }
  /** do not run. `hold_denied` = the owner said no or the hold expired */
  | { decision: "refused"; code: string; reason: string }
  /** no answer now (bridge or hook unavailable): nothing ran; ask again later */
  | { decision: "defer"; code: string };
/** spec 0.1.88: the send-time check for work an app accepted earlier and runs later, on any context. Writes a hold only when the answer is a hold. */
export interface SendTimeView {
  sendTimeCheck(input: { op: string; input: Json; caller: SendTimeCaller; holdId?: string | null; summary?: string }): Promise<SendTimeOutcome>;
}

/**
 * v0.1.14 addition (Lead, item 10): the target products of this app's companion grants, from the verified slice's
 * `companionTargets` (de-duplicated, sorted; [] when the slice has none). A wildcard companion (`product: "*"`) uses it
 * to know which apps it can call `tb.holds_pending` on.
 * SPEC-GAP: spec 0.1.14 InstanceSlice.companionTargets — not in the 0.1.13 types; read defensively.
 */
export interface CompanionTargetsView {
  companionTargets(): string[];
  /** v0.1.15 (C105a): the workspace apps policy's held families from the slice (display only; enforcement is the
   *  companion grant `held` claim at the target app), or null when the slice has none */
  appsPolicy(): readonly string[] | null;
  /**
   * v0.1.37 (C292, spec 0.1.54): the capabilities the workspace bridge declared (`slice.bridge.caps`, e.g. "owner_rows"), from the
   * CURRENT verified slice on every call: a frozen array of strings; [] when the slice is absent, expired (older than 12 h) or
   * carries none. Unknown entries pass through. Decide by capability, never by bridge version. ADVISORY: it never widens access
   * (the SDK authorizes every call; nothing in the SDK reads it for authorization). Also on start, event and job-handler contexts.
   */
  bridgeCaps(): readonly string[];
  /**
   * spec 0.1.87 (C373, G-2): the workspace grant picture (`slice.topology`, compact tuple form) from the CURRENT verified slice on
   * every call: a frozen deep copy; null when the slice is absent, expired (older than 12 h), has none (the manifest lacks
   * `needsTopology` or the owner did not grant the `topology` consent) or it is malformed. A row with an index out of range is
   * dropped and the copy says `truncated: true`. `agentIds` = the agent ids of the SAME slice in slice order: resolve `agentIdx` as
   * `agentIds[agentIdx]` (never against another read of the agents, which a newer slice may reorder). Never throws. DISPLAY ONLY: never authorize with it (the SDK authorizes every call from
   * the grant); stale until the next slice revision. Also on start, event and job-handler contexts.
   */
  topology(): SliceTopologyView | null;
  /** v0.1.18 (C106a, Connect F21): the slice's `agents[].scopeRequest` for `agt` when it targets THIS product, else null */
  agentScopeRequest(agt: string): ScopeRequest | null;
  /** v0.1.20: `<portalUrl>/w/<ws>/open?product=<product>&path=<path>` for ANOTHER app (shared launch-path rule; null until portalUrl) */
  ownerLinkFor(product: string, path: string): string | null;
}

/** v0.1.13 (C33, C85, C86): `onStart` runs once after boot and (bridge mode) after the claim succeeded; errors are logged. */
export type StartContext = Omit<SpecStartContext, "callApp"> & { callApp: ActingCallApp } & CompanionTargetsView & JobsView & SendTimeView & OwnerDraftsView;
/** v0.1.13: the ctx every event handler gets (C85 callApp without parentCall, C86 statusChanged / ownerLink). */
export type SdkEventContext = Omit<EventContext, "callApp"> & { callApp: ActingCallApp } & CompanionTargetsView & JobsView & SendTimeView & OwnerDraftsView;
/** AppEvents (types/sdk.ts) with the SDK event ctx; a handler typed against the spec EventContext still fits. */
export interface SdkAppEvents {
  agentAdded?(agent: SliceAgent, ctx: SdkEventContext): Promise<void>;
  agentRemoved?(agent: SliceAgent, ctx: SdkEventContext): Promise<void>;
  keysChanged?(names: string[], ctx: SdkEventContext): Promise<void>;
  /** v0.1.13 (Fleet): full agent list, once per installed slice whose agents differ, and once after boot */
  agentsChanged?(agents: SliceAgent[], ctx: SdkEventContext): Promise<void>;
}
/** v0.1.21 (RUL-11): the ctx of `onStop` (the DB is still open; jobs no longer start) */
export type StopContext = SdkEventContext & { secrets: AppSecrets };
export type SdkAppDefinition<A extends string = never> = Omit<AppDefinition<A>, "onStart" | "events"> & {
  onStart?(ctx: StartContext): Promise<void>;
  events?: SdkAppEvents;
  /**
   * v0.1.21 (Scribe R1, L6): background job kinds → handler. A tick resumes from the last `ctx.checkpoint(state)`;
   * leases, heartbeats, retries with backoff, pause/resume/cancel and restart draining are the SDK's.
   */
  jobs?: Record<string, JobHandler | JobSpec>;
  /**
   * v0.1.21 (RUL-11): called once from `stop()` (SIGTERM/SIGINT or RunningApp.stop) after the job runner stopped
   * claiming and before running jobs are drained and the DB closes: stop the app's own timers here. 5 s timeout.
   */
  onStop?(ctx: StopContext): Promise<void>;
};
