// Bridge target sensitivity: the checks pass against a minimal correct bridge and FAIL against variants that break
// one rule each (skips the pause gate, forwards without a call proof, lists person ops, sends payloads to Portal,
// accepts a person token at MCP, serves /keys on the main origin, opens the keys origin to other routes, serves the key
// page without CSP). Also: every reported id is catalogued, unselected groups report not_run, a bridge
// that never boots fails every check.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BridgeWorld } from "../../src/bridge-world.ts";
import { cspFormActionSelf } from "../../src/checks/bridge-flows.ts";
import { BRIDGE_CHECKS, CHECK_IDS, type Report, runBridgeTarget } from "../../src/index.ts";
import { type MiniFlags, type MiniState, startMiniBridge } from "./mini-bridge.ts";

const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
/** `keyset`: runBridgeTarget's key-set options (default: test roots, as the CLI) */
/** C91 group real_app: the workspace SDK source (no build needed: node strips the types outside node_modules) */
const SDK_MODULE = new URL("../../../miniapp-sdk/src/server/index.ts", import.meta.url).href;
const run = (flags: MiniFlags, groups: string[], state: MiniState = {}, keyset: { testRoots?: boolean; bootTimeoutMs?: number } = {}) =>
  runBridgeTarget({ start: (env) => startMiniBridge(env, flags, state), logs: () => (state.logs ?? []).join("\n"), groups, timeoutMs: 3000, bootTimeoutMs: 15_000, pauseLatencyMs: 4000, sdkModule: SDK_MODULE, ...keyset });
const ADDRESS_IDS = ["B21.own_infra_allowed", "B21.internal_url_external", "B21.own_infra_flag_required", "B21.neighbour_url_refused"];
const KEYSET_IDS = ["B20.kss_enrolled", "B20.portal_keys_ignored", "B20.kss_unknown_root", "B20.kss_rollback", "B20.kss_missing", "B20.kss_compromise", "B20.kss_reenrol_missing"];

const SPINE013_IDS = ["B22.hold_verdict", "B22.hold_retry_refused", "B22.hv_tamper", "B23.on_behalf_of", "B23.reserved_tb_namespace", "B24.app_initiated", "B24.no_grant"];
const B26_IDS = ["B26.app_initiated_real", "B26.app_initiated_rate", "B26.app_initiated_audit", "B26.parent_call_forged", "B26.parent_call_foreign", "B26.parent_call_expired"];
const REAL_APP_IDS = ["B25.real_catalog_search", "B25.real_dynamic_call", "B25.real_op_call", "B25.real_mark", "B25.real_hook_hold", "B25.real_hook_after_update", ...B26_IDS];
const C117_IDS = ["B27.hook_declared_absent", "B27.hook_disabled_skipped", "B27.hook_app_down"];
const HOOK_IDS = ["B6.order", "B6.hook_proof", "B6.no_hook_recursion", "B6.before_denied", "B6.before_failed", "B6.context_merged", "B6.after_failed"]; // B6.after_output: the mini bridge applies no redactions (not a C117 rule)
// the pause.instance checks C117 touches (hooks switched off by the owner while the hook app is paused); the mini bridge
// does not implement the rest of the instance pause (tools/list, companion, key fetch)
const PAUSE_INSTANCE_IDS = ["P1.instance.hook_app_paused", "P1.instance.other_app"];
const KEYS_ORIGIN_IDS = ["B11.main_origin_keys_404", "B11.keys_origin_only", "B11.keys_origin_csp", "B11.keys_origin_unset_503"];
const GOOD_IDS = ["B1.health", "B1.mcp_requires_auth", "B1.internal_not_public", "C1.K5", "cred.p1.bridge_rejects_clerk_jwt", "cred.p1.bridge_rejects_tbo", "B7.list_exact", "B7.no_person_ops", "B8.forward", "B8.grant_and_proof", "B5.bound_outside_wf", "P1.workspace.mcp", "B9.portal_paths", "B9.no_payload"];

const EVENT_IDS = Array.from({ length: 17 }, (_, i) => `B-EV-${i + 1}`);
const NO_CAP_ROW = "B-EV-18";
const asserted = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.asserted ?? "";

describe("bridge target", () => {
  it("spec 0.1.57 (B-EV): a bridge that DECLARES events and implements BRIDGE §14 passes every B-EV row", { timeout: 300_000 }, async () => {
    const r = await run({ events: true }, ["events"]);
    for (const id of EVENT_IDS) assert.equal(status(r, id), "pass", `${id}: ${asserted(r, id)}`);
    assert.equal(status(r, NO_CAP_ROW), "not_applicable");
  });

  it("spec 0.1.57 (B-EV): a bridge that declares no events cap is not_applicable on every §14.4 row, whatever version it reports; it answers the methods with -32601 (B-EV-18)", { timeout: 120_000 }, async () => {
    const r = await run({ version: "0.2.7" }, ["events"]);
    for (const id of EVENT_IDS) assert.equal(status(r, id), "not_applicable", `${id}: ${asserted(r, id)}`);
    assert.equal(status(r, NO_CAP_ROW), "pass", `${NO_CAP_ROW}: ${asserted(r, NO_CAP_ROW)}`);
    const empty = await run({ eventsMethodsAnswerEmpty: true }, ["events"]);
    assert.equal(status(empty, NO_CAP_ROW), "fail", `${NO_CAP_ROW} must fail a bridge that answers the events methods without the cap: ${asserted(empty, NO_CAP_ROW)}`);
    assert.match(asserted(r, "B-EV-1"), /does not declare the events capability.*never by version/);
  });

  it("fire-on-bad (B-EV): each broken §14 rule fails its row; a bridge that declares events without implementing it fails", { timeout: 900_000 }, async () => {
    const cases: [MiniFlags, string[]][] = [
      [{ events: true, eventFaults: { deliverToCause: true } }, ["B-EV-4", "B-EV-17"]],
      [{ events: true, eventFaults: { ignoreEligible: true } }, ["B-EV-3", "B-EV-14"]],
      [{ events: true, eventFaults: { noDeliveryRecheck: true } }, ["B-EV-6"]],
      [{ events: true, eventFaults: { keepSummaryWithHook: true } }, ["B-EV-9"]],
      [{ events: true, eventFaults: { noDedupe: true } }, ["B-EV-13"]],
      [{ events: true, eventFaults: { noReId: true } }, ["B-EV-7"]],
      [{ events: true, eventFaults: { noTruncated: true } }, ["B-EV-8", "B-EV-11"]],
      [{ events: true, eventFaults: { noReserved: true } }, ["B-EV-10", "B-EV-12"]],
      [{ events: true, eventFaults: { noPurge: true } }, ["B-EV-15", "B-EV-16"]],
      [{ declaredCaps: ["owner_rows", "events"] }, ["B-EV-1", "B-EV-17"]],
    ];
    // independent worlds and bridges (own ports): run them side by side
    const reports = await Promise.all(cases.map(([flags]) => run(flags, ["events"])));
    cases.forEach(([flags, ids], i) => {
      const r = reports[i] as Report;
      for (const id of ids) assert.equal(status(r, id), "fail", `${JSON.stringify(flags)} ${id}: ${status(r, id)} ${asserted(r, id)}`);
    });
  });


  it("reports every catalogued id; unselected groups are not_run; a correct bridge passes the selected rules", async () => {
    const r = await run({}, ["surface", "auth", "mcp", "call", "pause.workspace", "scan"]);
    assert.equal(r.target, "bridge");
    assert.deepEqual(new Set(r.checks.map((c) => c.id)), new Set(BRIDGE_CHECKS.map((c) => c.id)));
    for (const c of r.checks) assert.ok(CHECK_IDS.has(c.id), c.id);
    for (const id of GOOD_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B14.admin_pause"), "not_run");
    assert.equal(r.ok, false, "a partial run never passes");
  });

  it("C98a + C107 (conformance 0.1.11): a correct bridge derives keys for supported ops and refuses family-less outward / money resolutions", async () => {
    const r = await run({}, ["call", "dynamic"]);
    for (const id of ["B8.idempotency_derived", "B5.grant_held_unknown", "B5.free_wf_limits", "B5.free_wf_caps", "B5.restored", "B16.resolve_family", "B16.dynamic_call_resolved", "B16.dynamic_ceiling_exceeded", "B16.dynamic_entry_call", "B7.dynamic_list", "B7.dynamic_search"]) {
      assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    }
    assert.match(r.checks.find((c) => c.id === "B8.idempotency_derived")?.asserted ?? "", /supported \w+: .* key derived, retry .* key same/);
  });

  it("key page on its own origin (C59): a correct bridge passes every keys_origin check and is restored after the unset probe", async () => {
    const r = await run({}, ["keys_origin"]);
    for (const id of KEYS_ORIGIN_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B11.cookie_flags"), "not_run");
  });

  it("app addresses (BSD-07): a correct bridge passes every addresses check", async () => {
    const r = await run({}, ["addresses"]);
    for (const id of ADDRESS_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("key-set statements (spec 0.1.12): by default (test roots, strict) a correct bridge passes every keyset check", async () => {
    const r = await run({}, ["keyset"]);
    for (const id of [...KEYSET_IDS, "B20.kss_enrol_missing"]) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`); // gitleaks:allow (check id, not a secret)
  });

  it("one pass with test roots (conformance 0.1.8, Lead · Bridge): Portal key rotation re-signs the statement", async () => {
    // the mini bridge has no standalone mode; the B14 fixture fix is proven by the real bridge's one-pass run
    const r = await run({}, ["config"]);
    const failed = r.checks.filter((c) => c.id.startsWith("C5.") && c.status === "fail").map((c) => `${c.id}: ${c.asserted}`);
    assert.deepEqual(failed, []);
    assert.equal(status(r, "C5.portal_key_rotation"), "pass", r.checks.find((c) => c.id === "C5.portal_key_rotation")?.asserted);
  });

  it("--no-test-roots: a bridge that pins roots refuses the fake Portal's enrolment (boot fails with the pinned-roots hint)", async () => {
    const strict = await run({}, ["keyset"], {}, { testRoots: false, bootTimeoutMs: 3000 });
    assert.equal(strict.ok, false);
    assert.equal(status(strict, "B20.kss_enrolled"), "fail");
    assert.match(strict.notes.join(" "), /bridge build pins Portal Root Keys: run with test roots .*TBCONF_PORTAL_ROOT_KEYS.*--no-test-roots given/);
  });

  it("a bridge that accepts a first enrolment without a statement fails B20.kss_enrol_missing", async () => {
    const lax = await run({ ignoreKeySet: true }, ["keyset"]);
    assert.equal(status(lax, "B20.kss_enrol_missing"), "fail", lax.checks.find((c) => c.id === "B20.kss_enrol_missing")?.asserted);
  });

  it("fails a bridge that accepts a re-enrolment without a valid statement (C63a)", async () => {
    const r = await run({ acceptStrippedReenrol: true }, ["keyset"]);
    assert.equal(status(r, "B20.kss_reenrol_missing"), "fail", r.checks.find((c) => c.id === "B20.kss_reenrol_missing")?.asserted);
  });

  it("fails a bridge that ignores portalKeySet (pre-v0.1.11 rule)", async () => {
    const r = await run({ ignoreKeySet: true }, ["keyset"]);
    for (const id of ["B20.portal_keys_ignored", "B20.kss_unknown_root", "B20.kss_rollback", "B20.kss_missing", "B20.kss_compromise"]) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("spec 0.1.13 spine (spine013) + companion: a correct bridge passes every B22–B24 check and B16 re-entry / depth (valid parentCall)", async () => {
    const r = await run({}, ["spine013", "companion"]);
    for (const id of [...SPINE013_IDS, "B16.hook_reentry", "B16.call_depth", "C1.K10_companion"]) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B6.order"), "not_run", "an older bridge deselects spine013 the same way");
  });

  it("spec 0.1.45 (HOOK-CALLER-PRODUCT, B28): a bridge reporting 0.2.2 passes; one older than 0.2.2 is not_applicable by version, whatever it sends", async () => {
    const good = await run({ version: "0.2.2" }, ["spine013"]);
    assert.equal(status(good, "B28.hook_caller_product"), "pass", good.checks.find((c) => c.id === "B28.hook_caller_product")?.asserted);
    assert.match(good.checks.find((c) => c.id === "B28.hook_caller_product")?.asserted ?? "", /carry product/);
    for (const flags of [{}, { version: "0.2.1", noHookCallerProduct: true }, { version: "0.1.99" }]) {
      const r = await run(flags, ["spine013"]);
      const c = r.checks.find((x) => x.id === "B28.hook_caller_product");
      assert.equal(c?.status, "not_applicable", `${JSON.stringify(flags)}: ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /predates 0\.2\.2.*not applicable by version/);
    }
  });

  it("spec 0.1.54 (C292, B5.gate_scoped_above_grant): a bridge that DECLARES owner_rows and implements A1 passes, whatever version it reports", { timeout: 60_000 }, async () => {
    for (const version of ["0.0.0", "0.2.4", "0.2.5"]) {
      const good = await run({ version, ownerRows: true }, ["call"]);
      const c = good.checks.find((x) => x.id === "B5.gate_scoped_above_grant");
      assert.equal(c?.status, "pass", `${version}: ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /note_delete \(crud delete, beyond the free grant's .*\) reached the app/);
      // the example manifest has no UNSCOPED op beyond the Free grant's crud: a bridge with the A1 filter passes the scoped ones, so this row is n/a there
      assert.equal(status(good, "B5.crud_exceeds_grant"), "not_applicable", good.checks.find((x) => x.id === "B5.crud_exceeds_grant")?.asserted);
    }
  });

  it("spec 0.1.54 (C292a, B5.gate_scoped_above_grant): a bridge that declares no owner_rows is not_applicable, with the reason, also at version 0.2.4 or 0.2.5", { timeout: 60_000 }, async () => {
    // 0.2.4 = the real G2b-only bridge (no A1, no cap); a version >= 0.2.4 gate would have FAILED it
    for (const flags of [{}, { version: "0.2.3" }, { version: "0.2.4" }, { version: "0.2.5" }, { version: "0.2.5", declaredCaps: ["future_cap"] }]) {
      const r = await run(flags, ["call"]);
      const old = r.checks.find((x) => x.id === "B5.gate_scoped_above_grant");
      assert.equal(old?.status, "not_applicable", `${JSON.stringify(flags)}: ${old?.asserted}`);
      assert.match(old?.asserted ?? "", /does not declare the owner_rows capability in its StatusReport.*decides by capability, never by version/);
      assert.equal(status(r, "B5.crud_exceeds_grant"), "pass", `${JSON.stringify(flags)}: the CRUD ceiling check of a bridge without the A1 filter is unchanged`);
    }
  });

  it("fire-on-bad (B5.gate_scoped_above_grant): a bridge that declares owner_rows but never lists the app's admittedOps, or still refuses a scoped op above the grant, fails", { timeout: 60_000 }, async () => {
    const bad: MiniFlags[] = [{ ownerRows: true, ignoresAdmittedOps: true }, { ownerRows: true, oldGateCrud: true }, { version: "0.2.5", declaredCaps: ["owner_rows"] }];
    for (const flags of bad) {
      const r = await run(flags, ["call"]);
      const c = r.checks.find((x) => x.id === "B5.gate_scoped_above_grant");
      assert.equal(c?.status, "fail", `${JSON.stringify(flags)}: ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /named in the app's admittedOps never reached the app/);
    }
  });

  it("real SDK app behind the bridge (C91, group real_app): a correct bridge passes every B25 check against @opt2-tealbrick/miniapp-sdk", async () => {
    const r = await run({}, ["real_app"]);
    for (const id of REAL_APP_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("C117 (spec 0.1.24): the fake Portal lists every declared hook with enabled: true; hookState drops or switches one entry; hooksOn=false switches all off", async () => {
    const w = await BridgeWorld.create();
    try {
      const all = w.hookEntries();
      const declared = w.apps.reduce((n, a) => n + (a.manifest.hooks ?? []).length, 0);
      assert.ok(all.length > 0 && all.length === declared, `${all.length} entries for ${declared} declared hooks`);
      assert.ok(all.every((h) => h.enabled === true));
      const [one, two] = all as [(typeof all)[0], (typeof all)[0]];
      w.hookState.set(one.id, "absent");
      w.hookState.set(two.id, "disabled");
      const next = w.hookEntries();
      assert.equal(next.length, all.length - 1);
      assert.equal(next.find((h) => h.id === one.id), undefined);
      assert.equal(next.find((h) => h.id === two.id)?.enabled, false);
      w.hookState.clear();
      w.hooksOn = false;
      assert.ok(w.hookEntries().length === all.length && w.hookEntries().every((h) => h.enabled === false));
    } finally {
      await w.close();
    }
  });

  it("C117 (group c117): a correct bridge passes B27.hook_*; hooks and pause.instance (hooks switched off, not dropped) stay green", async () => {
    const r = await run({}, ["c117", "hooks", "pause.instance"]);
    for (const id of [...C117_IDS, ...HOOK_IDS, ...PAUSE_INSTANCE_IDS]) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B25.real_hook_after_update"), "not_run", "real_app not selected");
  });

  it("QA S1 regression (C91): a bridge that signs catalog proofs with `in` fails B25.real_catalog_search (real SDK) and B16.search_uses_catalog (fake app)", async () => {
    const r = await run({ catalogWithIn: true }, ["real_app", "dynamic"]);
    for (const id of ["B25.real_catalog_search", "B16.search_uses_catalog"]) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.match(r.checks.find((c) => c.id === "B25.real_catalog_search")?.asserted ?? "", /call_proof_invalid/);
    assert.equal(status(r, "B25.real_op_call"), "pass", "only the catalog binding is broken");
  });

  it("C85 audit without captured logs: B26.app_initiated_audit is not_run (the call checks still run)", async () => {
    const r = await runBridgeTarget({ start: (env) => startMiniBridge(env, {}, {}), groups: ["real_app"], timeoutMs: 3000, bootTimeoutMs: 15_000, pauseLatencyMs: 4000, sdkModule: SDK_MODULE });
    assert.equal(status(r, "B26.app_initiated_audit"), "not_run", r.checks.find((c) => c.id === "B26.app_initiated_audit")?.asserted);
    for (const id of ["B26.app_initiated_real", "B26.parent_call_forged", "B26.parent_call_foreign"]) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("cspFormActionSelf accepts exactly form-action 'self'", () => {
    assert.equal(cspFormActionSelf("default-src 'none'; form-action 'self'; frame-ancestors 'none'"), true);
    assert.equal(cspFormActionSelf("default-src 'self'"), false);
    assert.equal(cspFormActionSelf("form-action 'self' https://evil.example"), false);
    assert.equal(cspFormActionSelf("form-action *"), false);
    assert.equal(cspFormActionSelf(null), false);
  });

  const broken: [string, MiniFlags, string[], string[]][] = [
    ["skips the pause gate", { skipPause: true }, ["pause.workspace"], ["P1.workspace.mcp"]],
    ["forwards without a call proof", { noProof: true }, ["call"], ["B8.grant_and_proof", "B8.forward"]],
    ["refuses a required op without _meta (no derived key, pre-C98)", { noDerivedKey: true }, ["call"], ["B8.idempotency_derived"]],
    // spec 0.1.15 / 0.1.16 (conformance 0.1.11)
    ["derives the key for required ops only (supported forwarded keyless, pre-C98a)", { deriveRequiredOnly: true }, ["call"], ["B8.idempotency_derived"]],
    ["forwards an outward / money resolution without holdFamily (pre-C107)", { resolveNoFamilyCheck: true }, ["dynamic"], ["B16.resolve_family"]],
    ["drops a config grant whose held names an unknown family (strict reader, pre-C108)", { strictHeld: true }, ["call"], ["B5.grant_held_unknown"]],
    ["limits only Bound grants by wf (pre-C111a gate)", { wfOnlyBound: true }, ["call"], ["B5.free_wf_limits"]],
    ["lists person ops in tools/list", { listPerson: true }, ["mcp"], ["B7.no_person_ops", "B7.list_exact"]],
    ["sends tool payloads to Portal", { leakToPortal: true }, ["call", "scan"], ["B9.no_payload"]],
    ["accepts a person token at MCP", { acceptPerson: true }, ["auth"], ["cred.p1.bridge_rejects_clerk_jwt", "cred.p1.bridge_rejects_tbo"]],
    ["serves /keys on the main origin (C59)", { keysOnMain: true }, ["keys_origin"], ["B11.main_origin_keys_404"]],
    ["serves other routes on the keys origin (C59)", { keysOriginOpen: true }, ["keys_origin"], ["B11.keys_origin_only"]],
    ["serves the key page without CSP form-action (C59)", { noKeysCsp: true }, ["keys_origin"], ["B11.keys_origin_csp"]],
    ["answers 404 instead of 503 when the keys origin is unset (C59)", { noUnset503: true }, ["keys_origin"], ["B11.keys_origin_unset_503"]],
    ["routes to any internalUrl (BSD-07)", { noAddressCheck: true }, ["addresses"], ["B21.internal_url_external", "B21.own_infra_flag_required", "B21.neighbour_url_refused"]],
    // spec 0.1.13 (spine013)
    ["stops the before chain at a hold (a later refuse cannot win)", { holdStopsChain: true }, ["spine013"], ["B22.hold_verdict"]],
    ["sends the hold verdict outside the signed proof", { hvOutsideProof: true }, ["spine013"], ["B22.hold_verdict", "B22.hv_tamper"]],
    ["caches a hold verdict instead of re-running the chain on the retry", { cacheHoldVerdict: true }, ["spine013"], ["B22.hold_retry_refused"]],
    ["ignores _meta tealbrick/onBehalfOf", { noOnBehalfOf: true }, ["spine013"], ["B23.on_behalf_of"]],
    ["lets a context hook write tb.* keys", { allowTbContext: true }, ["spine013"], ["B23.reserved_tb_namespace"]],
    ["skips the hooks for app-initiated calls", { appCallsSkipHooks: true }, ["spine013"], ["B24.app_initiated"]],
    ["does not gate companion calls by the grant's workflow", { companionNoWfCheck: true }, ["spine013"], ["B24.no_grant"]],
    // spec 0.1.45 (HOOK-CALLER-PRODUCT, bridge 0.2.2): the version-gated check fires on a bridge that claims 0.2.2 and omits / forges it
    ["(0.2.2) omits call.caller.product from its hook requests", { version: "0.2.2", noHookCallerProduct: true }, ["spine013"], ["B28.hook_caller_product"]],
    ["(0.2.2) takes call.caller.product from the call input", { version: "0.2.2", hookCallerProductFromInput: true }, ["spine013"], ["B28.hook_caller_product"]],
    ["(0.2.2) gives agent callers a product", { version: "0.2.2", hookCallerProductForAgents: true }, ["spine013"], ["B28.hook_caller_product"]],
    // C85 + v0.1.14 A2A-10 (group real_app, B26)
    ["shows app-initiated calls to hooks as caller type system", { appInitiatedAsSystem: true }, ["real_app"], ["B26.app_initiated_real"]],
    ["does not rate-limit app-initiated calls", { noAppRateLimit: true }, ["real_app"], ["B26.app_initiated_rate"]],
    ["does not audit app-initiated calls", { noAppInitiatedAudit: true }, ["real_app"], ["B26.app_initiated_audit"]],
    ["trusts a forged parentCall (child call, not app-initiated)", { parentTrusted: true }, ["real_app"], ["B26.parent_call_forged"]],
    // L2: a REAL SDK before hook's hold verdict must reach the target app
    ["treats a before hook's hold verdict as hook_failed", { holdAsHookFailed: true }, ["real_app"], ["B25.real_hook_hold"]],
    ["accepts another instance's in-flight call as parentCall", { parentAnyInstance: true }, ["real_app"], ["B26.parent_call_foreign"]],
    ["keeps finished calls as valid parentCalls", { parentKeepsFinished: true }, ["real_app"], ["B26.parent_call_expired"]],
    // spec 0.1.24 (C117, S1 fail-open: hooks dropped after an update)
    ["builds the hook chain from config hooks[] only (a declared, absent hook is not enforced)", { trustConfigHooks: true }, ["c117"], ["B27.hook_declared_absent"]],
    ["forwards ungated while the real gate app updates and its hook is missing from config hooks[]", { trustConfigHooks: true }, ["real_app"], ["B25.real_hook_after_update"]],
    ["refuses a declared, unlisted hook without reporting rejected hook_not_listed (v0.1.25)", { noHookNotListedReport: true }, ["c117"], ["B27.hook_declared_absent"]],
    ["ignores the hook enabled switch", { ignoreHookEnabled: true }, ["c117"], ["B27.hook_disabled_skipped"]],
    ["skips a hook whose app is down", { skipDownHookApp: true }, ["c117"], ["B27.hook_app_down"]],
  ];
  for (const [name, flags, groups, ids] of broken) {
    it(`fails a bridge that ${name}`, async () => {
      const r = await run(flags, groups);
      for (const id of ids) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
      assert.equal(r.ok, false);
    });
  }

  it("a bridge that never enrols fails every check (boot failure)", async () => {
    const r = await runBridgeTarget({
      start: async (env) => ({ publicUrl: `http://127.0.0.1:${env.PORT}`, internalUrl: `http://127.0.0.1:${env.TB_INTERNAL_PORT}`, stop: async () => undefined }),
      bootTimeoutMs: 500,
    });
    assert.equal(r.counts.fail, BRIDGE_CHECKS.length);
    assert.match(r.notes.join(" "), /boot failed/);
  });
});
