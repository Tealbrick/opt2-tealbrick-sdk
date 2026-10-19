// @opt2-tealbrick/miniapp-sdk — server entry (SDK-API §3–§13, types/sdk.ts §B).

/** C64: the ONE privilege drop (from @opt2-tealbrick/manifest; startApp and tb-exec call it). */
export { dropPrivileges, PrivilegeDropError, type PrivilegeProc, RUN_GID, RUN_UID, SDK_AUDIT_ACTIONS } from "@opt2-tealbrick/manifest";
export type {
  App,
  AppDefinition,
  AppEvents,
  AppStatus,
  AuditEntry,
  AuditLog,
  BackupApi,
  BackupMeta,
  CallEnvelope,
  Caller,
  ClaimRequest,
  ClaimResponse,
  CompanionResult,
  Db,
  DynamicHandlers,
  DynamicHoldView,
  EventContext,
  ExportMeta,
  Handler,
  HandlerSpec,
  Health,
  HealthStatus,
  HoldDecideInput,
  HoldsPendingInput,
  HoldsPendingItem,
  HoldsPendingOutput,
  HookContext,
  HookHandler,
  HookRequest,
  HookResponseByPhase,
  IdempotencyCheck,
  InstanceSlice,
  Json,
  KeyApi,
  KeyStatus,
  Logger,
  OpCallBody,
  OpContext,
  OperationView,
  OpResult,
  PersonPrincipal,
  PublicHandler,
  Receipt,
  ReceiptHelpers,
  ReceiptQuery,
  ReceiptStatus,
  ReceiptStore,
  RunningApp,
  ScopeAccessView,
  ScopeGrantRow,
  ScopeInstance,
  ScopeStore,
  ScopeSummaryResult,
  SdkEnv,
  SessionInfo,
  SliceAgent,
} from "@opt2-tealbrick/spec/sdk";
export { AGENT_DOCUMENT_UNAVAILABLE_HTML, type AgentDocumentDeps, type AgentDocumentStats, agentDocumentPrecheck, agentDocumentStats, fillTextSlots, MAX_ATTRIBUTE_BUDGET, MAX_ATTRIBUTES_PER_TAG, MAX_ELEMENTS, MAX_TAGS, NO_SCRIPT_CSP, type SanitizeAgentDocumentOptions, type SanitizeAgentDocumentResult, sanitizeAgentDocument } from "./agent-document.ts";
export { decideHold, defineApp, getKey, onKeysChanged, SDK_MAJOR, SDK_VERSION, startApp } from "./app.ts";
// v0.1.29 (C238, C230): agent documents. Server entry only; the rule list is AGENT_DOCUMENT_RULES (@opt2-tealbrick/manifest 0.1.24).
// v0.1.34 (C259): the ONE bounded parse5 parse (ported from live-artifacts), exported so Live Artifacts imports it instead of a copy.
export { boundedParse, boundedTreeAdapter, maxOutputLength, PARSE_ATTRIBUTE_BUDGET, PARSE_MAX_ATTRIBUTES, PARSE_MAX_CHILD_WORK, type ParseBounds, ParseLimitExceeded } from "./bounded-parse.ts";
export type {
  AppSecrets,
  CompanionTargetsView,
  ContextExtras,
  SdkAppDefinition,
  SdkAppEvents,
  SdkCaller,
  SdkEventContext,
  SdkHookContext,
  SdkOpContext,
  SdkPublicContext,
  StartContext,
  StopContext,
} from "./context.ts";
export { requireViewUrl, TbError, VIEW_ORIGIN_MISSING, viewOriginMissing } from "./errors.ts";
// v0.1.21 (Scribe R1, SDK-1/SDK-2, RUL-11): the job runner
export type {
  EnqueueOptions,
  Job,
  JobContext,
  JobHandler,
  JobOutcome,
  JobSpec,
  JobStatus,
  JobsApi,
  JobsSummary,
  JobsView,
  PauseView,
  ScheduleTarget,
  ScheduleWhen,
} from "./jobs.ts";
export { JOB_DEFAULTS, OP_JOB_KIND, OP_JOB_MAX_ATTEMPTS } from "./jobs.ts";
// v0.1.23 (SDK-HV-1): dynamic hold view budget and the fallback line (SDK-API §4.6)
export { HOLD_VIEW_BUDGET_MS, HOLD_VIEW_UNREADABLE } from "./ops.ts";
export { CSRF_HEADER, SESSION_COOKIE } from "./person.ts";
export { TB_EXEC_CONTROL_PORT } from "./service-helper.ts";
