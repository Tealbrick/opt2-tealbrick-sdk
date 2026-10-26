// Vocabularies (MANIFEST §2, SDK-API §2). Manifest/credential/bridge literals are declared once in
// @opt2-tealbrick/spec and only re-exported here; RECEIPT_STATUSES and SDK_AUDIT_ACTIONS are owned by this package.
import type {
  RECEIPT_STATUSES as SPEC_RECEIPT_STATUSES,
  SDK_AUDIT_ACTIONS as SPEC_SDK_AUDIT_ACTIONS,
} from "@opt2-tealbrick/spec/sdk";

export { TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
export type { BridgeOp, Typ } from "@opt2-tealbrick/spec/credentials";
export {
  BRIDGE_OP_PATH,
  BRIDGE_OPS,
  CALLER_TYPES,
  CREDENTIAL_KINDS,
  OPAQUE_PREFIX,
  PROOF_HEADER,
  TYP,
} from "@opt2-tealbrick/spec/credentials";
export type {
  AgentMode,
  Artifact,
  Backups,
  Category,
  Companion,
  Condition,
  ConditionValue,
  ContractId,
  CrudAction,
  DefaultGrantKind,
  DynamicCallInput,
  DynamicCatalogEntry,
  DynamicMode,
  DynamicResolution,
  DynamicSearchInput,
  DynamicSpec,
  Effect,
  EnvEntry,
  HarnessHint,
  HarnessKind,
  HoldFamily,
  Hook,
  HookPhase,
  IdempotencyMode,
  KeyRequirement,
  KeySource,
  Manifest,
  ManifestIssue,
  ManifestValidation,
  Operation,
  OperationAudience,
  OperationListing,
  PublicRoute,
  PublicRoutePurpose,
  Scope,
  Service,
  SettingField,
  SettingStep,
  SettingType,
  Skill,
  StandardOperationId,
  Unlock,
  Volume,
} from "@opt2-tealbrick/spec/manifest";
export {
  AGENT_MODES,
  CATEGORIES,
  /** v0.1.77 (spec 0.1.77, C367 P3): `tb.hold_status`, the one other standard op a one-product companion entry may name (M-CP-3) */
  COMPANION_HOLD_STATUS_OP,
  /** v0.1.20 (spec 0.1.42): shared app-to-app contract ids */
  CONTRACT_IDS,
  CRUD_ACTIONS,
  DEFAULT_GRANT_KINDS,
  /** v0.1.20 (spec 0.1.41, C232): + public_link — held families of a new agent card and the default apps policy */
  DEFAULT_HELD_FAMILIES,
  DYNAMIC_MODES,
  EFFECTS,
  HARNESS_KINDS,
  HOLD_FAMILIES,
  HOOK_HOLD_FAMILIES,
  HOOK_PHASES,
  IDEMPOTENCY_MODES,
  KEY_SOURCES,
  /** v0.1.15 (C105): = HOLD_FAMILIES, the families an op may declare */
  KNOWN_HOLD_FAMILIES,
  MANIFEST_SCHEMA,
  OPERATION_AUDIENCES,
  /** v0.1.21 (spec 0.1.43, LR-1) */
  OPERATION_LISTINGS,
  /** v0.1.21 (spec 0.1.43, LA-1): + viewer */
  PUBLIC_ROUTE_PURPOSES,
  SETTING_TYPES,
  STANDARD_OPERATIONS,
  VOLUME_PURPOSES,
  WILDCARD_COMPANION_OPS,
} from "@opt2-tealbrick/spec/manifest";
export type { OperationView, SkillVars, StandardOpId } from "@opt2-tealbrick/spec/sdk";

/** Receipt row statuses (SDK-API §4; holds are receipt rows). Owned by this package. */
export const RECEIPT_STATUSES = [
  "run",
  "held",
  "approved",
  "denied",
  "refused",
  "failed",
  "after_failed",
] as const satisfies typeof SPEC_RECEIPT_STATUSES;
export type ReceiptStatus = (typeof RECEIPT_STATUSES)[number];

/** SDK audit actions (SDK-API §7.4), distinct from Core's AUDIT_ACTIONS. Owned by this package. */
export const SDK_AUDIT_ACTIONS = [
  "session.signin",
  "session.signout",
  "hold.decide",
  "scope.set",
  "key.set",
  "key.delete",
  "backup.create",
  "backup.restore",
  "migration.apply",
  "claim.complete",
  "scope.snapshot_backfill",
  "scope.offer_accepted",
] as const satisfies typeof SPEC_SDK_AUDIT_ACTIONS;
export type SdkAuditAction = (typeof SDK_AUDIT_ACTIONS)[number];
