// Internal runtime shared by the route modules of one running app (not exported from the package).
import type { Ed25519KeyPair, ReplayGuard } from "@opt2-tealbrick/manifest";
import type { ScopeRequest } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, BackupApi, CompanionResult, Db, HealthStatus, Json, Logger, OperationView, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";
import type { BackupHealth, RestoreOutcome } from "./backup.ts";
import type { BridgeClient } from "./bridge-client.ts";
import type { AttentionCode } from "./claim-guard.ts";
import type { ContextExtras, SdkAppDefinition, SdkEventContext } from "./context.ts";
import type { SdkConfig } from "./env.ts";
import type { JobRunner } from "./jobs.ts";
import type { KeysInternals } from "./keys.ts";
import type { SecretRegistry } from "./log.ts";
import type { PersonAuth } from "./person.ts";
import type { Receipts } from "./receipts.ts";
import type { ScopeStoreInternals } from "./scopes.ts";
import type { Sealer } from "./secrets.ts";
import type { RawDb, SchemaVersion } from "./store.ts";
import type { TrustState } from "./trust.ts";
import type { PreUpdateSnapshot } from "./upgrade.ts";

export interface Runtime {
  readonly def: SdkAppDefinition<string>;
  readonly manifest: Manifest;
  readonly product: string;
  readonly digest: `sha256:${string}`;
  readonly ops: ReadonlyMap<string, OperationView>;
  readonly sdkVersion: string;
  readonly cfg: SdkConfig;
  readonly env: Record<string, string | undefined>;
  readonly db: RawDb;
  readonly appDb: Db;
  readonly log: Logger;
  readonly secrets: SecretRegistry;
  readonly sealer: Sealer;
  readonly instanceId: InstanceId;
  readonly instanceKey: Ed25519KeyPair;
  readonly trust: TrustState;
  readonly receipts: Receipts;
  readonly scopes: ScopeStoreInternals;
  readonly keys: KeysInternals;
  readonly audit: AuditLog;
  readonly person: PersonAuth;
  readonly secretsStore: AppSecrets;
  readonly backups: BackupApi;
  readonly bridge: BridgeClient | null;
  /** v0.1.21 (R1): THE job runner of this process (tb_jobs) */
  readonly jobs: JobRunner;
  /** v0.1.21: a verified grant of `callerId` (newest wins for its pending scheduled ops) */
  noteGrant(callerId: string, token: string, iat: number): void;
  /** jti replay set for call proofs (CREDENTIALS §10: memory is enough) */
  readonly replay: ReplayGuard;
  /** `attention` (v0.1.12): why the instance needs the owner (health detail; wire readiness `degraded`) */
  readonly state: { claimed: boolean; failed: boolean; restoring: boolean; stopping: boolean; attention: AttentionCode | null };
  /** v0.1.25 (E2): what the data is at after the boot's data phase (health + status push; SPEC-GAP additive) */
  readonly upgrade: {
    schemaVersion: SchemaVersion;
    codeSchema: SchemaVersion;
    /** the oldest app version that can run this data (the version that applied its newest migration); null = unknown */
    minCompatibleCode: string | null;
    minCompatibleSdk: string | null;
    preUpdateSnapshot: PreUpdateSnapshot | null;
    lastRestore: RestoreOutcome | null;
  };
  /** test harness only (startApp `harness.mountinfoPath`): mountinfo file for the first-claim mount check */
  readonly mountinfoPath: string | undefined;
  health(): HealthStatus;
  /** C31 context members for agent/app calls (person calls override `workspace`) */
  extras(): ContextExtras;
  /** scopes changed: push a status report at once (C16 S2) */
  kickStatus(): void;
  /** v0.1.13 (C86): ctx.statusChanged() — push within 1 s, debounced, ≤ 1 push/s; the SDK calls it on hold create/decide/expire */
  statusChanged(): void;
  /** v0.1.13 (C86): AppStatus.pendingHolds = held receipts + the app's pendingCount() (clamped, 1 s timeout) */
  pendingHolds(): Promise<number>;
  /** v0.1.20 (spec 0.1.28, F89): the app's `attention()` (1 s timeout, validated; null when none) */
  attention(): Promise<{ code: string; reason: string } | null>;
  /** v0.1.22 (SDK-03): scheduled-backup state for health (`Health.backup`, spec 0.1.31) */
  backupHealth(): BackupHealth;
  /** v0.1.13 (C86): ctx.ownerLink(path); throws path_invalid; null until the slice carries portalUrl */
  ownerLink(path: string): string | null;
  /** v0.1.20: an owner link into ANOTHER app (e.g. Inbox opening a hold's decidePath in the owning app) */
  ownerLinkFor(product: string, path: string): string | null;
  /** v0.1.14 addition: product ids of the slice's companionTargets (sorted, unique) */
  companionTargets(): string[];
  /** v0.1.15 (C105a) */
  appsPolicy(): readonly string[] | null;
  /** v0.1.37 (C292): `ctx.bridgeCaps()` — a frozen copy of the CURRENT verified slice's `bridge.caps`; [] when absent, expired or none. Advisory only. */
  bridgeCaps(): readonly string[];
  /** v0.1.18 (C106a) */
  agentScopeRequest(agt: string): ScopeRequest | null;
  /** v0.1.13: the ctx every event handler gets */
  eventContext(): SdkEventContext;
  /** v0.1.13 (Fleet): events.agentsChanged when the slice's agents differ from the last notified list (and once after boot) */
  notifyAgents(): Promise<void>;
  /** claim completed (or already recorded): runs `onStart` once */
  onClaimed(): void;
  /** re-reads the slice from the bridge once (companion `grant_stale`) */
  refreshSlice(): Promise<void>;
  /** first sight of an agent edge (§7.2): agentAdded event, then manifest defaultGrants */
  ensureAgent(agent: SliceAgent): Promise<void>;
  /** `parentCall: null` = app-initiated (C85: StartContext / EventContext / timers) */
  callApp<O = Json>(product: string, op: string, input: Json, opts: { idempotencyKey?: string; parentCall: string | null }): Promise<CompanionResult<O>>;
  callServiceHelper<O = Json>(serviceId: string, path: string, body: Json): Promise<O>;
}
