// @opt2-tealbrick/conformance — CONFORMANCE.md: fakes generated from @opt2-tealbrick/spec + @opt2-tealbrick/manifest
// (S12: no other @opt2-tealbrick import), the app and manifest targets, the report shape, and the CLI entry.

export { AppClient, type CallOptions, type OpAnswer, type OpTamper, type PersonSession, tamperValue } from "./app-client.ts";
export { type AgentRole, type BridgeStart, type BridgeStartResult, BridgeWorld, deployedSettings, exampleManifests, peerManifest, SERVICE_KEY_OFF, SERVICE_KEY_ON, withServiceKeys } from "./bridge-world.ts";
export { type AppTargetContext, coverageOutcome, runAppChecks } from "./checks/app.ts";
export { BRIDGE_CRED_CASES, BRIDGE_GROUP_ORDER, BRIDGE_GROUPS } from "./checks/bridge-ids.ts";
export { APP_CHECK_IDS, BRIDGE_CHECKS, CHECK_IDS, CORE_CHECKS, isCheckId, MANIFEST_CHECK_IDS, PEER_CHECK_BASES, RELAY_CHECKS } from "./checks/catalog.ts";
export { type CoreStaticInput, runCoreStatic } from "./checks/core.ts";
export { authProbeRows, CORE_LIVE_CHECKS, CORE_STATIC_CHECKS } from "./checks/core-ids.ts";
export { API_BASE, envelopeOnly, isInternalDoc, LiveClient, type LiveClientOptions, type ProbeAnswer, ProbeBlocked, type ProbeRequest, runCoreLive, type Safety, secretInPublicAnswer } from "./checks/core-live.ts";
export { type FieldInfo, fieldsOf, loadSpecTypes, parseDeclarations, stringUnion, type TypeIndex } from "./checks/core-types.ts";
export { findProductLiterals, type ManifestCheckOptions, runManifestChecks } from "./checks/manifest.ts";
export { FakeApp, type FakeAppWorld } from "./fake-app.ts";
export {
  type CapturedPayload,
  createFakeBridge,
  type FakeAgent,
  FakeBridge,
  FakeBridgeControl,
  type FakeBridgeIds,
  type FakeBridgeOptions,
} from "./fake-bridge.ts";
export { createFakePortal, FAKE_PORTAL_ROUTES, FakePortal, FakePortalControl, type FakePortalOptions, type PersonOpResultSeen, type QueuedPersonOp } from "./fake-portal.ts";
export { FakeUpstream, type UpstreamRequest } from "./fake-upstream.ts";
export { checkStartModule, type ForkedStart, type ForkStartOptions, forkStart } from "./fork-start.ts";
export { SDK_EXPORTS, type SdkExport } from "./generated/sdk-exports.ts";
export { applyLevelCrud, LEVEL_CRUD_ENV, type LevelCrudChange, parseLevelCrud } from "./level-crud.ts";
export { KeyAgent, McpSession, OAuthAgent, parseForms, pkcePair } from "./mcp-agent.ts";
export { type AppDriver, DECOY_PRODUCT, type MultiAppDeps, PEER_SETTINGS_ENV, type PreparedPeer, preparePeers, runPeerChecks } from "./multi-app.ts";
export { defaultCacheRoot, extractArchive, fetchVerifiedIndex, githubSource, INDEX_BASES, type LoadedPeer, loadPeer, PeerError, type PeerSourceOptions, peerCacheDir, RELEASE_KEYS, type ReleaseRecord, removePeerCaches, selectRecord } from "./peer-source.ts";
export { bodyDigest, mintPersonOp, PERSON_OP_HEADER, PERSON_OP_ROUTE, PERSON_OP_SINCE, PERSON_OPS_CAP, type PersonOpMint } from "./person-op.ts";
export { loadSdk, REAL_ENTRIES, REAL_OPS, type RealApp, type RealCompanion, type RealRunningApp, type RealStartContext, realAppManifest, type SdkModule, startRealApp } from "./real-app.ts";
export {
  applyWaivers,
  buildReport,
  type CheckResult,
  type CheckStatus,
  compareVersions,
  exitCode,
  FAILING_STATUSES,
  type PayloadScan,
  type Report,
  renderMarkdown,
  specDigest,
  type Target,
  type Waiver,
  type WaiverOutcome,
} from "./report.ts";
export { type AppStartResult, appEnv, loadManifest, type RunAppOptions, runApp, TEST_ROOTS_ENV } from "./run-app.ts";
export { freePort, processHarness, type RunBridgeOptions, runBridgeTarget } from "./run-bridge.ts";
export { type CoreTargetOptions, gatewayOrigin, runCoreTarget } from "./run-core.ts";
export { type RunRelayOptions, runRelayTarget } from "./run-relay.ts";
export { sampleInput } from "./sample.ts";
export { scanPayloads } from "./scan.ts";
export { SDK_COVERAGE } from "./sdk-coverage.ts";
export { jsonPointer, type Resolved, resolvePlaceholders, runSetup, type SetupAnswer, type SetupResult } from "./setup.ts";
export { type Outcome, Suite } from "./suite.ts";
export { readTar, type TarEntry } from "./tar.ts";
export { defaultScanDirs, runManifestTarget, runPendingTarget } from "./targets.ts";
export { Mint, peek, rawSign } from "./tokens.ts";
export {
  BUILTIN_PLACEHOLDERS,
  CONFORMANCE_VERSION,
  ConfigError,
  type ConformanceConfig,
  type ContractOp,
  EMPTY_CONFIG,
  INPUT_CALLERS,
  type InputCaller,
  loadConformanceConfig,
  loadWaiverFile,
  MAX_PEERS,
  type NarrowingFixture,
  type PeerSpec,
  parseConformanceConfig,
  parseWaiveFlag,
  SETUP_CALLERS,
  type SetupCaller,
  type SetupStep,
  WAIVER_FILE,
  WaiverError,
} from "./waivers.ts";
