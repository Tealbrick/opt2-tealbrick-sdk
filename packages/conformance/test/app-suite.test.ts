// App target: a correct mini app passes every check; each deliberately broken variant FAILS the matching checks
// (sensitivity). Ids reported by a run must all be catalogued.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { APP_CHECK_IDS, CHECK_IDS, type ConformanceConfig, exitCode, parseConformanceConfig, type Report, renderMarkdown, runApp } from "../src/index.ts";
import { freePort } from "./apps/free-port.ts";
import { type MiniAppFaults, RECALL_OP, RECALL_TAG, startMiniApp } from "./apps/mini-app.ts";

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(path, "utf8")) as Manifest;
const template = { services: [{ name: "app", domains: [] }, { name: "bridge", domains: ["bridge.example.org"] }] };

function run(faults: MiniAppFaults = {}, extra: Partial<Parameters<typeof runApp>[0]> = {}): Promise<Report> {
  return runApp({ manifest, manifestPath: path, start: (env) => startMiniApp(manifest, env, faults), deployTemplate: template, timeoutMs: 8000, ...extra });
}
const failing = (r: Report) => r.checks.filter((c) => c.status === "fail" || c.status === "not_run" || c.status === "not_implemented").map((c) => c.id);

describe("app target", () => {
  it("a correct app passes every check; report lists every catalogued app id", async () => {
    const r = await run();
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    assert.equal(r.ok, true);
    assert.equal(exitCode(r), 0);
    const ids = new Set(r.checks.map((c) => c.id));
    for (const id of APP_CHECK_IDS) assert.ok(ids.has(id), `missing ${id}`);
    for (const id of ids) assert.ok(CHECK_IDS.has(id), `uncatalogued ${id}`);
    assert.equal(r.payloadScan.findings.length, 0);
    assert.ok(r.payloadScan.payloads > 50);
    assert.match(r.specDigest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(r.sdk, { majors: [1, 0], reported: "1.0.0" });
    // the sample has no first_contact op and no dynamic op; its receipt op names app callers (C102)
    const st = (id: string) => r.checks.find((c) => c.id === id)?.status;
    assert.equal(st("A12.app_caller_held"), "not_applicable");
    assert.equal(st("A11.resolve_family"), "not_applicable");
    assert.equal(st("A11.narrowing_empty_anyof"), "not_applicable");
    assert.equal(st("A12.caller_name"), "pass");
    assert.equal(st("A12.caller_product_verified"), "pass");
    for (const id of ["A12.grant_prd_first", "A12.grant_prd_mismatch", "A12.grant_prd_absent"]) assert.equal(st(id), "pass", id);
    assert.match(r.checks.find((c) => c.id === "C3.grant_held_unknown")?.asserted ?? "", /item_delete \(destructive\): 202 held/);
  });

  it("GRANT-PRD checks are SDK >= 0.1.28 rules: an SDK that reports an older release gets not_applicable by version, whatever it does", async () => {
    const r = await run({ reportedSdkVersion: "0.1.27", callerProductIgnoresPrd: true });
    for (const id of ["A12.grant_prd_first", "A12.grant_prd_mismatch", "A12.grant_prd_absent"]) {
      const c = r.checks.find((x) => x.id === id);
      assert.equal(c?.status, "not_applicable", `${id}: ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /predates 0\.1\.28.*not applicable by version/);
    }
    const ok = await run({ reportedSdkVersion: "0.1.28" });
    assert.equal(ok.checks.find((x) => x.id === "A12.grant_prd_first")?.status, "pass");
  });

  const cases: [string, MiniAppFaults, string[], number?][] = [
    ["skips call-proof verification", { skipProofVerify: true }, ["A2.no_proof", "B8.tampered_input", "A2.proof_op", "C5.proof_unannounced_kid", "C2.proof_aud_foreign", "C3.grant_as_proof", "B13.bridge_op_proof_at_op"]],
    ["skips grant verification", { skipGrantVerify: true }, ["C5.grant_unannounced_kid", "C5.grant_expired", "C2.grant_aud_foreign", "C2.grant_aud_array", "A2.grant_revoked", "A2.grant_cnf"]],
    ["ignores the slice pause", { ignorePause: true }, ["P1.workspace", "P1.agent", "P1.instance", "P1.held_release_paused"]],
    ["accepts a launch ticket twice", { ticketReusable: true }, ["C6.ticket_replay"]],
    ["has no idempotency conflict", { noIdempotencyConflict: true }, ["A5"]],
    ["serves its own claim route", { servesClaimRoute: true }, ["A1.no_claim_route"]],
    ["keeps standing approvals", { standingApproval: true }, ["A10", "A3.no_standing_approval"]],
    ["skips CSRF", { noCsrf: true }, ["A6.csrf"]],
    ["stores raw input in receipts", { storesRawInput: true }, ["A4.receipt_digest"]],
    ["ignores personNbf", { ignorePersonNbf: true }, ["A6.person_nbf"]],
    ["has no proof replay set", { noProofReplayGuard: true }, ["C6.call_proof_replay"]],
    ["does not re-read its slice on a stale companion grant", { noCompanionRetry: true }, ["A12.companion_refresh_retry"]],
    ["answers a hook with a wrong shape", { badHookShape: true }, ["A2.hook_valid"]],
    ["ignores portalKeySet (pre-v0.1.11 trust rule)", { ignoreKeySet: true }, ["A13.portal_keys_ignored", "A13.kss_unknown_root", "A13.kss_rollback", "A13.kss_missing", "A13.kss_compromise"]],
    ["loses its instance key on restart", { newKeyOnRestart: true }, ["A1.key_persisted", "A7.restart"], 2000],
    ["keeps a refused identity although the enrolment code changed", { noReclaim: true }, ["A1.reclaim_on_new_code"]],
    // v0.1.13 (spec 0.1.13, conformance 0.1.9)
    ["ignores the proof's hook hold verdict (hv)", { ignoreHoldVerdict: true }, ["A14.hook_hold"]],
    ["never lets an approval satisfy a hook verdict", { hvIgnoresApproval: true }, ["A14.hold_retry_once"]],
    ["holds on a verdict before the scope checks", { hvBeforeScope: true }, ["A14.scope_wins"]],
    ["shows an agent every pending hold", { holdsPendingAll: true }, ["A15.holds_pending"]],
    ["makes an app-initiated call without its companion grant", { appInitiatedNoGrant: true }, ["A16.call_outside_handler"]],
    ["does not push its status when a hold changes", { noStatusChanged: true }, ["A17.status_changed"]],
    ["reports pendingHolds 0", { pendingHoldsZero: true }, ["A17.pending_count"]],
    // v0.1.15 (spec 0.1.15, conformance 0.1.11)
    ["names app callers by their instance id although companionCallers lists them", { callerNameIgnoresSlice: true }, ["A12.caller_name"]],
    // v0.1.19 (spec 0.1.44, SDK-CALLER-PRODUCT): the product comes from the verified instance, never from the name
    ["finds the caller's product by its NAME (an impostor named like another product is taken for it)", { callerProductFromName: true }, ["A12.caller_product_verified"]],
    ["never reports caller.product (pre-0.1.44)", { noCallerProduct: true }, ["A12.caller_product_verified", "A12.grant_prd_first", "A12.grant_prd_mismatch", "A12.grant_prd_absent"]],
    // v0.1.21 (spec 0.1.46, GRANT-PRD): the grant's prd first, the slice as fallback, a disagreement refused
    ["ignores the grant's prd (pre-0.1.46: slice only)", { callerProductIgnoresPrd: true }, ["A12.grant_prd_first", "A12.grant_prd_mismatch"]],
    ["prefers the slice entry over the grant's prd and never refuses a disagreement", { callerProductPrefersSlice: true }, ["A12.grant_prd_mismatch"]],
    ["picks the grant's prd over a disagreeing slice entry instead of refusing", { callerProductMismatchPicksGrant: true }, ["A12.grant_prd_mismatch"]],
    // v0.1.17 (C108)
    ["refuses a grant whose held names an unknown family (strict reader)", { strictHeld: true }, ["C3.grant_held_unknown"]],
    // v0.1.19 (C111a, conformance 0.1.12)
    ["ignores the caps of a Free grant with a workflow (pre-C111a)", { capsIgnoredWithWf: true }, ["A3.free_wf_caps"]],
    // v0.1.18 (spec 0.1.31, SDK-02/SDK-04): `max: 0` (A3.caps) cannot see a cap that never counts
    ["never counts Free cap usage", { capsUncounted: true }, ["A3.caps_count"]],
  ];
  // v0.1.15 / v0.1.16 (conformance 0.1.11): a manifest with an outward first_contact op and a search-mode dynamic op
  const c107 = structuredClone(manifest) as Manifest;
  c107.operations.push(
    {
      id: "item_send",
      title: "Send item",
      description: "Send an item to a new recipient.",
      input: { type: "object", required: ["space", "to"], properties: { space: { type: "string" }, to: { type: "string" } } },
      output: { type: "object" },
      crud: ["update"],
      effect: "outward",
      holdFamily: "first_contact",
      scopeType: "space",
      idempotency: "supported",
      receipt: true,
      audience: "agent",
    } as Manifest["operations"][number],
    {
      id: "item_lookup",
      title: "Look up items",
      description: "Search-mode dynamic operation.",
      crud: ["read"],
      effect: "read",
      idempotency: "supported",
      receipt: false,
      audience: "agent",
      dynamic: { mode: "search", crudCeiling: ["read", "create"], effectCeiling: "money" },
    } as Manifest["operations"][number],
  );
  const runC107 = (faults: MiniAppFaults = {}) => runApp({ manifest: c107, manifestPath: path, start: (env) => startMiniApp(c107, env, faults), deployTemplate: template, timeoutMs: 8000 });
  const statusOf = (r: Report, id: string) => r.checks.find((c) => c.id === id);

  it("app callers (C102, C105a) + resolve families (C107): a correct app with a first_contact op and a dynamic op passes", async () => {
    const r = await runC107();
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    for (const id of ["A12.caller_name", "A12.app_caller_held", "A11.resolve_family", "M2.hold_family_known", "M2.outward_family"]) assert.equal(statusOf(r, id)?.status, "pass", `${id}: ${statusOf(r, id)?.asserted}`);
    assert.match(statusOf(r, "A12.app_caller_held")?.asserted ?? "", /item_send .*first 202 held .*same input \+ key 200 ok; again \(new key\) 202 held/);
    assert.match(statusOf(r, "A11.resolve_family")?.asserted ?? "", /outward\/first_contact/);
  });

  // v0.1.18 (SDK-02): a receipt:false write op — the miniapp-sdk ≤ 0.1.21 bug (caps counted from receipts) shows only there
  const capsM = structuredClone(manifest) as Manifest;
  capsM.operations.push({
    id: "item_touch",
    title: "Touch item",
    description: "Mark an item as seen (no receipt).",
    input: { type: "object", required: ["space"], properties: { space: { type: "string" } } },
    output: { type: "object" },
    crud: ["update"],
    effect: "write",
    scopeType: "space",
    idempotency: "supported",
    receipt: false,
    audience: "agent",
  } as Manifest["operations"][number]);
  const runCaps = (faults: MiniAppFaults = {}) => runApp({ manifest: capsM, manifestPath: path, start: (env) => startMiniApp(capsM, env, faults), deployTemplate: template, timeoutMs: 8000 });
  it("A3.caps_count: a correct app holds the second call of a receipt:false AND a receipt:true op under max 1", async () => {
    const r = await runCaps();
    const c = statusOf(r, "A3.caps_count");
    assert.equal(c?.status, "pass", c?.asserted);
    assert.match(c?.asserted ?? "", /item_touch \(receipt false\): first 200 ok, second 202 held/);
    assert.match(c?.asserted ?? "", /item_create \(receipt true\): first 200 ok, second 202 held/);
  });
  it("A3.caps_count: an app that counts caps from receipts only (miniapp-sdk ≤ 0.1.21) fails", async () => {
    const r = await runCaps({ capsCountReceiptsOnly: true });
    const c = statusOf(r, "A3.caps_count");
    assert.equal(c?.status, "fail", c?.asserted);
    assert.match(c?.asserted ?? "", /item_touch \(receipt false\): first 200 ok, second 200 ok/);
  });

  // ── package 0.1.21 (Connect waiver): `as: "capsAgent"` setup steps run as the fresh caps agent of A3.caps_count ──
  // Connect-like: post_cancel acts on a post the CALLER owns, so the fresh caps agent needs a post of its own first.
  const pm = structuredClone(manifest) as Manifest;
  pm.operations.push(
    {
      id: "post_create",
      title: "Create post",
      description: "Create a post owned by the caller.",
      input: { type: "object", properties: { text: { type: "string" } } },
      output: { type: "object" },
      crud: ["create"],
      effect: "write",
      idempotency: "required",
      receipt: true,
      audience: "agent",
    } as Manifest["operations"][number],
    {
      id: "post_cancel",
      title: "Cancel post",
      description: "Cancel a post the caller owns.",
      input: { type: "object", required: ["id"], properties: { id: { type: "string" } } },
      output: { type: "object" },
      crud: ["update"],
      effect: "write",
      idempotency: "supported",
      receipt: false,
      audience: "agent",
    } as Manifest["operations"][number],
  );
  const capsCfg = (setup: unknown[]) => parseConformanceConfig({ setup, inputs: { post_cancel: { id: "${capsPost}" } } }, "test config");
  const capsStep = { id: "caps_post", as: "capsAgent", op: "post_create", input: { text: "caps probe" }, capture: { capsPost: "/id" } };
  const runPosts = (config: ConformanceConfig | null) =>
    runApp({ manifest: pm, config, start: (env) => startMiniApp(pm, env, { postsPerAgent: true }), deployTemplate: template, timeoutMs: 8000 });
  it("package 0.1.21: a capsAgent setup step gives the fresh caps agent its own post; A3.caps_count passes for the data-owning op", async () => {
    const r = await runPosts(capsCfg([capsStep]));
    const c = statusOf(r, "A3.caps_count");
    assert.equal(c?.status, "pass", c?.asserted);
    assert.match(c?.asserted ?? "", /post_cancel \(receipt false\): first 200 ok, second 202 held/);
    assert.match(c?.asserted ?? "", /post_create \(receipt true\): first 200 ok, second 202 held/);
    assert.equal(r.checks.filter((x) => x.status === "fail").length, 0, renderMarkdown(r));
    assert.ok(r.notes.some((n) => /setup: step caps_post \(capsAgent post_create\)/.test(n)), r.notes.join("\n"));
  });
  it("package 0.1.21: without the capsAgent step the generated input cannot cancel (the probe shows why the step is needed)", async () => {
    const r = await runPosts(null);
    assert.match(statusOf(r, "A3.caps_count")?.asserted ?? "", /post_cancel \(receipt false\): first 404 post_not_found/);
  });
  it("package 0.1.21: a failing capsAgent step blocks its capture: A3.caps_count is not_run naming the step and its answer", async () => {
    const r = await runPosts(capsCfg([{ ...capsStep, op: "post_cancel", input: { id: "nope" } }]));
    const c = statusOf(r, "A3.caps_count");
    assert.equal(c?.status, "not_run", c?.asserted);
    assert.match(c?.asserted ?? "", /setup step caps_post \(capsAgent post_cancel\) failed: .*404/);
  });

  for (const [name, faults, id] of [
    ["never holds an app caller (ignores the companion grant held)", { appCallerNoHold: true }, "A12.app_caller_held"],
    ["drops holdFamily from outward / money resolve answers", { resolveNoFamily: true }, "A11.resolve_family"],
  ] as const) {
    it(`an app that ${name} fails ${id}`, async () => {
      const r = await runC107(faults);
      assert.equal(statusOf(r, id)?.status, "fail", statusOf(r, id)?.asserted);
      assert.equal(r.ok, false);
    });
  }

  // ── v0.1.18 (conformance 0.1.12): setup fixtures, inputsAs, dynamic resolveTools ──
  // Knowledge-like app: app-caller data keyed by caller (areas), area-less app callers refused (areaPerAppCaller)
  const kn = structuredClone(manifest) as Manifest;
  kn.operations.push({
    id: "area_create",
    title: "Create area",
    description: "Create an area for the caller.",
    input: { type: "object", required: ["name"], properties: { name: { type: "string" } } },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
  } as Manifest["operations"][number]);
  const appArea = (input: unknown = { name: "conformance" }) =>
    parseConformanceConfig(
      {
        setup: [{ id: "app_area", as: "app", op: "area_create", input, capture: { appArea: "/id" } }],
        inputsAs: { app: { item_create: { space: "${appArea}", title: "Conformance item" }, item_delete: { space: "${appArea}", id: "conformance" } } },
      },
      "test config",
    );
  const runKn = (config: ConformanceConfig | null, extra: Partial<Parameters<typeof runApp>[0]> = {}) =>
    runApp({ manifest: kn, config, start: (env) => startMiniApp(kn, env, { areaPerAppCaller: true }), deployTemplate: template, timeoutMs: 8000, ...extra });

  it("v0.1.18: a Knowledge-like app (areas per app caller) without setup → A12.caller_name not_run (never a silent pass)", async () => {
    const r = await runKn(null);
    const cn = statusOf(r, "A12.caller_name");
    assert.equal(cn?.status, "not_run", cn?.asserted);
    assert.match(cn?.asserted ?? "", /area_required.*no receipt row to read/);
    assert.equal(statusOf(r, "A12.scope_request")?.status, "not_applicable");
  });

  it("v0.1.18: tealbrick-conformance.json setup (as app) + inputsAs.app → the Knowledge-like app passes every check", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tbconf-setup-"));
    try {
      const mPath = join(dir, "app.manifest.json");
      writeFileSync(mPath, JSON.stringify(kn));
      writeFileSync(
        join(dir, "tealbrick-conformance.json"),
        JSON.stringify({
          setup: [{ id: "app_area", as: "app", op: "area_create", input: { name: "conformance" }, capture: { appArea: "/id" } }],
          inputsAs: { app: { item_create: { space: "${appArea}", title: "Conformance item" } } },
        }),
      );
      // the file beside manifestPath is read by runApp itself (the CLI passes the same config)
      const r = await runApp({ manifestPath: mPath, start: (env) => startMiniApp(kn, env, { areaPerAppCaller: true }), deployTemplate: template, timeoutMs: 8000 });
      assert.deepEqual(failing(r), [], renderMarkdown(r));
      const cn = statusOf(r, "A12.caller_name");
      assert.equal(cn?.status, "pass", cn?.asserted);
      assert.match(cn?.asserted ?? "", /listed 200 ok \(inputsAs\.app fixture\); unlisted 200 ok \(inputsAs\.app fixture\)/);
      assert.ok(r.notes.some((n) => /^setup: step app_area \(app area_create\) 200 ok; captured appArea$/.test(n)), r.notes.join("\n"));
      assert.equal(statusOf(r, "A12.scope_request")?.status, "not_applicable");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("v0.1.18: a failing setup step → every check that needs its capture reports not_run naming the step and its answer", async () => {
    const r = await runKn(appArea({ name: 5 }));
    const cn = statusOf(r, "A12.caller_name");
    assert.equal(cn?.status, "not_run", cn?.asserted);
    assert.match(cn?.asserted ?? "", /^setup step app_area \(app area_create\) failed: 400 input_invalid — this check needs its captures/);
    assert.ok(r.notes.some((n) => n.includes("setup step app_area (app area_create) failed: 400 input_invalid")), r.notes.join("\n"));
    // the generic inputs of the hold chain may need a capture too: then the chain is not_run, not fail
    const held = await runKn(
      parseConformanceConfig({ setup: [{ id: "agent_space", as: "agentA", op: "area_create", input: { name: 7 }, capture: { space: "/id" } }], inputs: { item_delete: { space: "${space}", id: "x" }, item_create: { space: "${space}", title: "x" } } }, "test config"),
    );
    for (const id of ["A3.hold", "A4.hold_status", "A10", "P1.held_release_paused", "A3.no_standing_approval", "A7.restart"]) {
      const c = statusOf(held, id);
      assert.equal(c?.status, "not_run", `${id}: ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /setup step agent_space \(agentA area_create\) failed: 400 input_invalid/, id);
    }
  });

  it("v0.1.18: dynamic.<op>.resolveTools → A11.resolve_family resolves the configured tools of an empty catalog; a listed tool resolving to null fails", async () => {
    const runDyn = (config: ConformanceConfig | null) => runApp({ manifest: c107, config, start: (env) => startMiniApp(c107, env, { emptyCatalog: true }), deployTemplate: template, timeoutMs: 8000 });
    const none = await runDyn(null);
    assert.equal(statusOf(none, "A11.resolve_family")?.status, "not_run", statusOf(none, "A11.resolve_family")?.asserted);
    const listed = await runDyn(parseConformanceConfig({ dynamic: { item_lookup: { resolveTools: ["dyn_read", "dyn_send", "dyn_pay"] } } }, "test config"));
    const rf = statusOf(listed, "A11.resolve_family");
    assert.equal(rf?.status, "pass", rf?.asserted);
    assert.match(rf?.asserted ?? "", /^3 resolutions of 1 dynamic op\(s\) \(1 via configured resolveTools\).*outward\/first_contact/);
    const broken = await runDyn(parseConformanceConfig({ dynamic: { item_lookup: { resolveTools: ["dyn_send", "dyn_nope"] } } }, "test config"));
    const bf = statusOf(broken, "A11.resolve_family");
    assert.equal(bf?.status, "fail", bf?.asserted);
    assert.match(bf?.asserted ?? "", /item_lookup\/dyn_nope: listed in dynamic\.item_lookup\.resolveTools but resolve answered null/);
  });

  // ── v0.1.23 (C115, conformance 0.1.14): rules.narrowing — an empty anyOf passes NOTHING ──
  const nr = structuredClone(manifest) as Manifest;
  nr.operations.push({
    id: RECALL_OP,
    title: "Recall memories",
    description: "Tag-filtered memory read (rules.narrowing).",
    input: { type: "object", required: ["space"], properties: { space: { type: "string" } } },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    scopeType: "space",
    idempotency: "none",
    receipt: false,
    audience: "agent",
  } as Manifest["operations"][number]);
  const narrowingConfig = (n: Record<string, unknown> = { op: RECALL_OP, tag: RECALL_TAG.toUpperCase() }) => parseConformanceConfig({ narrowing: n }, "test config");
  const runNr = (faults: MiniAppFaults = {}, config: ConformanceConfig | null = narrowingConfig()) => runApp({ manifest: nr, manifestPath: path, config, start: (env) => startMiniApp(nr, env, faults), deployTemplate: template, timeoutMs: 8000 });

  it("v0.1.23 (C115): narrowing {op, tag} → a correct tag-filtered read passes A11.narrowing_empty_anyof (and every other check)", async () => {
    const r = await runNr();
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    const n = statusOf(r, "A11.narrowing_empty_anyof");
    assert.equal(n?.status, "pass", n?.asserted);
    assert.match(n?.asserted ?? "", /^memory_recall: unfiltered 3 item\(s\); anyOf \[\] → 200 ok, 0 item\(s\); anyOf \["CONFORMANCE"\] → 1 item\(s\)$/);
  });

  it("v0.1.23 (C115): an app whose filter reads anyOf: [] as \"no constraint\" fails A11.narrowing_empty_anyof", async () => {
    const r = await runNr({ emptyAnyOfNoFilter: true });
    const n = statusOf(r, "A11.narrowing_empty_anyof");
    assert.equal(n?.status, "fail", n?.asserted);
    assert.match(n?.asserted ?? "", /anyOf \[\] → 200 ok, 3 item\(s\) \(an empty anyOf must pass NOTHING\)/);
    assert.equal(r.ok, false);
  });

  it("conformance 0.1.15: a second array field (status list) is not counted; without itemsPath the check is not_run, with itemsPath it passes", async () => {
    const amb = statusOf(await runNr({ recallStatusArray: true }), "A11.narrowing_empty_anyof");
    assert.equal(amb?.status, "not_run", amb?.asserted);
    assert.match(amb?.asserted ?? "", /several array fields \(items, areas\): name the result items with narrowing\.itemsPath/);
    const named = statusOf(await runNr({ recallStatusArray: true }, narrowingConfig({ op: RECALL_OP, tag: RECALL_TAG, itemsPath: "/items" })), "A11.narrowing_empty_anyof");
    assert.equal(named?.status, "pass", named?.asserted);
    assert.throws(() => narrowingConfig({ op: RECALL_OP, itemsPath: "items" }), /itemsPath must be a JSON pointer/);
  });

  it("v0.1.23 (C115): narrowing config keys are checked (usage error); narrowing.op must be a static agent read op", async () => {
    for (const bad of [{ narrowing: [] }, { narrowing: {} }, { narrowing: { op: "" } }, { narrowing: { op: RECALL_OP, extra: 1 } }, { narrowing: { op: RECALL_OP, tag: "" } }, { narrowing: { op: RECALL_OP, tag: "x".repeat(65) } }, { narrowing: { op: RECALL_OP, input: { space: "${nope}" } } }]) {
      assert.throws(() => parseConformanceConfig(bad, "test config"), /narrowing/, JSON.stringify(bad));
    }
    assert.deepEqual(parseConformanceConfig({ narrowing: { op: RECALL_OP, input: { space: "${tb.instance}" }, tag: "x" } }, "t").narrowing, { op: RECALL_OP, input: { space: "${tb.instance}" }, tag: "x" });
    const r = await runNr({}, narrowingConfig({ op: "item_create" }));
    const n = statusOf(r, "A11.narrowing_empty_anyof");
    assert.equal(n?.status, "fail", n?.asserted);
    assert.match(n?.asserted ?? "", /narrowing\.op "item_create": not a static agent read op/);
  });

  it("--no-test-roots: a strict app refuses every fake-bridge slice, the run fails at boot with the pinned-roots note", async () => {
    const r = await run({}, { testRoots: false, bootTimeoutMs: 3000 });
    assert.equal(r.ok, false);
    assert.equal(exitCode(r), 1);
    assert.match(r.notes.join(" "), /boot failed/);
    assert.ok(
      r.notes.includes("app build pins Portal Root Keys: run with test roots (start module must pass env.TBCONF_PORTAL_ROOT_KEYS to startApp — see create-tealbrick-miniapp conformance.start.ts) (--no-test-roots given)"),
      r.notes.join("\n"),
    );
  });

  it("v0.1.21: two runs at the same time each get their own free port (TBCONF_PORT), no clash", async () => {
    const [a, b] = await Promise.all([run(), run()]);
    const portOf = (r: Report) => r.notes.find((n) => n.startsWith("app port: "))?.match(/^app port: (\d+) \(suite offered TBCONF_PORT=(\d+)\)$/);
    const pa = portOf(a);
    const pb = portOf(b);
    assert.ok(pa && pb, `${a.notes.join("\n")}\n${b.notes.join("\n")}`);
    assert.equal(pa[1], pa[2]);
    assert.notEqual(pa[1], pb[1]);
    assert.equal(a.ok && b.ok, true);
  });

  it("test roots offered but not pinned (a start module that drops TBCONF_PORTAL_ROOT_KEYS): boot fails with the same note", async () => {
    const r = await runApp({ manifest, manifestPath: path, start: (env) => startMiniApp(manifest, { ...env, TBCONF_PORTAL_ROOT_KEYS: "" }), timeoutMs: 8000, bootTimeoutMs: 3000 });
    assert.equal(r.ok, false);
    assert.match(r.notes.join(" "), /app build pins Portal Root Keys: run with test roots .*the app did not pin them/);
  });

  it("an app that skips the key-set rule (trusts the slice's portalKeys) fails A13.kss_first_missing", async () => {
    const lax = await run({ ignoreKeySet: true });
    const l = lax.checks.find((c) => c.id === "A13.kss_first_missing");
    assert.equal(l?.status, "fail", l?.asserted);
  });

  it("an app whose agent ops are ALL read-only passes: the hold chain and its dependants report not_applicable (Fleet)", async () => {
    const ro = structuredClone(manifest) as Manifest;
    ro.operations = ro.operations.map((o) => {
      if (o.audience !== "agent") return o;
      const { holdFamily: _h, ...rest } = o as typeof o & { holdFamily?: string };
      return { ...rest, effect: "read", crud: ["read"], idempotency: "none" } as typeof o;
    });
    const r = await runApp({ manifest: ro, manifestPath: path, start: (env) => startMiniApp(ro, env), deployTemplate: template, timeoutMs: 8000 });
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    for (const id of ["A3.hold", "A4.hold_status", "A4.decide_person_only", "A4.holds_list", "A4.receipt_digest", "A10", "P1.held_release_paused", "A3.no_standing_approval"]) {
      assert.equal(r.checks.find((c) => c.id === id)?.status, "not_applicable", id);
    }
    for (const id of ["P1.workspace", "P1.agent", "P1.instance", "A7.restart", "A1.key_persisted", "A7.backup_roundtrip"]) assert.equal(r.checks.find((c) => c.id === id)?.status, "pass", id);
  });

  it("A5 tampers a free-text field, never an enum first field (Inbox); no receipt op → A4.mark_after_failed not_applicable (Fleet)", async () => {
    const m = structuredClone(manifest) as Manifest;
    for (const o of m.operations) {
      if (o.id !== "item_create") continue;
      const inp = o.input as unknown as { required: string[]; properties: Record<string, unknown> };
      inp.properties = { kind: { type: "string", enum: ["task", "idea"] }, code: { type: "string", pattern: "^[A-Za-z0-9_-]+$" }, ...inp.properties };
      inp.required = ["kind", "code", ...inp.required];
    }
    const r = await runApp({ manifest: m, start: (env) => startMiniApp(m, env), timeoutMs: 8000 });
    const a5 = r.checks.find((c) => c.id === "A5");
    assert.equal(a5?.status, "pass", a5?.asserted);
    assert.match(a5?.asserted ?? "", /other input \(free-text field (title|space)\) 409 idempotency_conflict/);
    const noReceipt = structuredClone(manifest) as Manifest;
    noReceipt.operations = noReceipt.operations.map((o) => {
      if (o.audience !== "agent") return o;
      const { holdFamily: _h, ...rest } = o as typeof o & { holdFamily?: string };
      return { ...rest, effect: "read", crud: ["read"], idempotency: "none", receipt: false } as typeof o;
    });
    const n = await runApp({ manifest: noReceipt, start: (env) => startMiniApp(noReceipt, env), timeoutMs: 8000 });
    const mark = n.checks.find((c) => c.id === "A4.mark_after_failed");
    assert.equal(mark?.status, "not_applicable", mark?.asserted);
    assert.match(mark?.asserted ?? "", /no agent op has receipt: true/);
  });

  for (const [name, faults, expected, timeoutMs] of cases) {
    it(`an app that ${name} fails ${expected.join(", ")}`, async () => {
      const r = await run(faults, timeoutMs ? { timeoutMs } : {});
      const f = failing(r);
      for (const id of expected) assert.ok(f.includes(id), `${id} should fail; failing: ${f.join(", ")}`);
      assert.equal(r.ok, false);
      assert.equal(exitCode(r), 1);
    });
  }

  it("url mode (no restart) reports not_run for the restart / backup checks and fails", async () => {
    const port = await freePort();
    let app: Awaited<ReturnType<typeof startMiniApp>> | null = null;
    let booting: Promise<unknown> = Promise.resolve();
    try {
      const r = await runApp({
        manifest,
        manifestPath: path,
        url: `http://127.0.0.1:${port}`,
        onEnv: (env) => {
          booting = startMiniApp(manifest, env, {}, port).then((a) => {
            app = a;
          });
        },
        timeoutMs: 8000,
      });
      const notRun = r.checks.filter((c) => c.status === "not_run").map((c) => c.id);
      for (const id of ["A7.restart", "A7.backup_roundtrip", "A1.key_persisted"]) assert.ok(notRun.includes(id), `${id} not_run; got ${notRun.join(",")}`);
      assert.deepEqual(failing(r).filter((id) => !notRun.includes(id)), [], "everything else passes");
      assert.equal(r.ok, false);
    } finally {
      await booting;
      await (app as { stop(): Promise<void> } | null)?.stop();
    }
  });

  it("A9 without a deploy template asserts at manifest level; a public-binding env entry fails it", async () => {
    const plain = await run({}, { deployTemplate: undefined });
    const a9 = plain.checks.find((c) => c.id === "A9");
    assert.equal(a9?.status, "pass");
    assert.match(a9?.asserted ?? "", /manifest-level; the live project check is QA \(CONFORMANCE open Q1\)/);
    const exposed = { ...manifest, runtime: { ...manifest.runtime, env: [...(manifest.runtime.env ?? []), { name: "PUBLIC_URL", value: "https://app.example.org" }] } } as Manifest;
    const r = await runApp({ manifest: exposed, start: (env) => startMiniApp(exposed, env), timeoutMs: 8000 });
    assert.equal(r.checks.find((c) => c.id === "A9")?.status, "fail");
  });

  it("a URL that reaches another process (not the app under test) fails boot with that reason", async () => {
    const { createServer } = await import("node:http");
    const other = createServer((_req, res) => res.writeHead(302, { location: "/" }).end());
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", () => r()));
    const port = (other.address() as { port: number }).port;
    let app: Awaited<ReturnType<typeof startMiniApp>> | null = null;
    try {
      const r = await runApp({
        manifest,
        start: async (env) => {
          app = await startMiniApp(manifest, env);
          return { url: `http://127.0.0.1:${port}`, stop: async () => {} };
        },
      });
      const a1 = r.checks.find((c) => c.id === "A1");
      assert.equal(a1?.status, "fail");
      assert.match(a1?.asserted ?? "", /does not answer as the app under test.*302/);
    } finally {
      await (app as { stop(): Promise<void> } | null)?.stop();
      other.close();
    }
  });

  it("an app that never claims fails every app check with the boot reason", async () => {
    const r = await runApp({ manifest, start: async () => ({ url: "http://127.0.0.1:9", stop: async () => {} }), bootTimeoutMs: 300 });
    const app = r.checks.filter((c) => (APP_CHECK_IDS as readonly string[]).includes(c.id));
    assert.equal(app.length, APP_CHECK_IDS.length);
    assert.ok(app.every((c) => c.status === "fail" && c.asserted.startsWith("boot failed")));
    assert.equal(r.ok, false);
  });

  it("an invalid manifest fails M1 and every app check without booting", async () => {
    let started = false;
    const r = await runApp({
      manifest: { ...manifest, schema: "tealbrick.miniapp/1" },
      start: async () => {
        started = true;
        return { url: "http://127.0.0.1:9", stop: async () => {} };
      },
    });
    assert.equal(started, false);
    assert.equal(r.checks.find((c) => c.id === "M1")?.status, "fail");
    assert.equal(r.ok, false);
  });
});

// ── spec 0.1.47 (SDK-INSTANCE-GRANT, conformance 0.1.22): A18 ────────────────────────────────────────────────────────
describe("A18 SDK-INSTANCE-GRANT (conformance 0.1.22)", () => {
  const gm = structuredClone(manifest) as Manifest;
  const space = gm.scopes?.[0];
  if (!space) throw new Error("sample has no scope");
  // agents get read_write on their own space by default; `manage` is above that ceiling
  space.access.push({ id: "manage", label: "Manage", crud: ["read", "create", "update", "delete"] });
  gm.operations.push(
    {
      id: "scope_grant",
      title: "Start draft",
      description: "Person op that gives one agent access to one space.",
      input: { type: "object" },
      output: { type: "object" },
      crud: ["update"],
      effect: "write",
      idempotency: "supported",
      receipt: false,
      audience: "person",
    } as Manifest["operations"][number],
    {
      id: "scope_probe",
      title: "Probe grants",
      description: "Reports whether ctx.scopeGrants exists in this agent call.",
      input: { type: "object" },
      output: { type: "object" },
      crud: ["read"],
      effect: "read",
      idempotency: "none",
      receipt: false,
      audience: "agent",
    } as Manifest["operations"][number],
  );
  const cfg = (over: Record<string, unknown> = {}) =>
    parseConformanceConfig(
      { scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" }, agentProbe: { op: "scope_probe" }, ...over } },
      "test config",
    );
  const runG = (faults: MiniAppFaults = {}, config: ConformanceConfig | null = cfg()) => runApp({ manifest: gm, manifestPath: path, config, start: (env) => startMiniApp(gm, env, faults), deployTemplate: template, timeoutMs: 8000 });
  const ids = ["A18.scope_grant_within", "A18.scope_grant_ceiling", "A18.scope_grant_agent_absent"];
  const st = (r: Report, id: string) => r.checks.find((c) => c.id === id);

  it("a correct app passes the three checks (and every other check); the grant row is removed again", async () => {
    const r = await runG();
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    for (const id of ids) assert.equal(st(r, id)?.status, "pass", `${id}: ${st(r, id)?.asserted}`);
    assert.match(st(r, "A18.scope_grant_within")?.asserted ?? "", /source "app" grantedByOp "scope_grant"/);
    assert.match(st(r, "A18.scope_grant_ceiling")?.asserted ?? "", /400 scope_grant_invalid/);
    assert.match(st(r, "A18.scope_grant_agent_absent")?.asserted ?? "", /403 audience_not_agent.*output\/scopeGrants = false/);
  });

  it("without a scopeGrantOp fixture the checks are not_applicable (an app that does not use the API passes)", async () => {
    const r = await run();
    for (const id of ids) {
      assert.equal(st(r, id)?.status, "not_applicable", id);
      assert.match(st(r, id)?.asserted ?? "", /no scopeGrantOp/);
    }
  });

  it("an SDK older than 0.1.31 gets not_applicable by version, whatever it does", async () => {
    const r = await runG({ reportedSdkVersion: "0.1.30", scopeGrantNoCeiling: true, scopeGrantsOnAgent: true });
    for (const id of ids) {
      assert.equal(st(r, id)?.status, "not_applicable", `${id}: ${st(r, id)?.asserted}`);
      assert.match(st(r, id)?.asserted ?? "", /predates 0\.1\.31.*not applicable by version/);
    }
    const ok = await runG({ reportedSdkVersion: "0.1.31", scopeGrantNoCeiling: true });
    assert.equal(st(ok, "A18.scope_grant_ceiling")?.status, "fail");
  });

  it("fire-on-bad: an SDK that skips the ceiling fails A18.scope_grant_ceiling", async () => {
    const r = await runG({ scopeGrantNoCeiling: true });
    const c = st(r, "A18.scope_grant_ceiling");
    assert.equal(c?.status, "fail");
    assert.match(c?.asserted ?? "", /did not enforce the agent ceiling/);
    assert.match(c?.asserted ?? "", /scope rows changed: .*none -> manage\|app\|scope_grant/);
    assert.equal(st(r, "A18.scope_grant_within")?.status, "pass");
  });

  it("fire-on-bad: an SDK that exposes scopeGrants on an agent call fails A18.scope_grant_agent_absent", async () => {
    const r = await runG({ scopeGrantsOnAgent: true });
    const c = st(r, "A18.scope_grant_agent_absent");
    assert.equal(c?.status, "fail");
    assert.match(c?.asserted ?? "", /scope_probe output\/scopeGrants = true/);
    assert.equal(st(r, "A18.scope_grant_ceiling")?.status, "pass");
  });

  it("fire-on-bad: a grant row without source/grantedByOp fails A18.scope_grant_within", async () => {
    const r = await runG({ scopeGrantNoSource: true });
    assert.equal(st(r, "A18.scope_grant_within")?.status, "fail");
    assert.match(st(r, "A18.scope_grant_within")?.asserted ?? "", /gained no row with source "app" and grantedByOp "scope_grant"/);
  });

  it("fire-on-bad: an SDK that clamps an above-ceiling grant to the ceiling and answers 200 fails A18.scope_grant_ceiling (levels compared)", async () => {
    const r = await runG({ scopeGrantClamps: true });
    const c = st(r, "A18.scope_grant_ceiling");
    assert.equal(c?.status, "fail");
    assert.match(c?.asserted ?? "", /200 ok.*scope rows changed:.*-> read_write\|app\|scope_grant/);
  });

  it("fire-on-bad: an SDK that writes another level than the one granted fails A18.scope_grant_within", async () => {
    const r = await runG({ scopeGrantWrongLevel: true });
    const c = st(r, "A18.scope_grant_within");
    assert.equal(c?.status, "fail");
    assert.match(c?.asserted ?? "", /access "read" but the input granted "read_write"/);
  });

  it("a grant row that already existed identically is not mistaken for a NEW row (not_run); an owner row it overwrites is put back (pass)", async () => {
    const pre = parseConformanceConfig(
      {
        setup: [{ id: "pre", as: "owner", op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" } }],
        scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" } },
      },
      "test config",
    );
    const r = await runG({}, pre);
    assert.equal(st(r, "A18.scope_grant_within")?.status, "not_run", st(r, "A18.scope_grant_within")?.asserted);
    assert.match(st(r, "A18.scope_grant_within")?.asserted ?? "", /already existed.*cannot be told from it/);
    const owner = parseConformanceConfig(
      {
        setup: [{ id: "pre", as: "owner", op: "tb.scopes_set", input: { agent: "${tb.agentA}", type: "space", id: "space-draft", access: "read" } }],
        scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" } },
      },
      "test config",
    );
    const r2 = await runG({}, owner);
    assert.equal(st(r2, "A18.scope_grant_within")?.status, "pass", st(r2, "A18.scope_grant_within")?.asserted);
    assert.match(st(r2, "A18.scope_grant_within")?.asserted ?? "", /replaced read\|owner\|-/);
    assert.equal(st(r2, "A18.scope_grant_ceiling")?.status, "pass", st(r2, "A18.scope_grant_ceiling")?.asserted);
  });

  it("without an agentProbe the agent check still proves the agent route refuses the person op", async () => {
    const c = parseConformanceConfig({ scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" } } }, "test config");
    const r = await runG({ scopeGrantsOnAgent: true }, c);
    assert.equal(st(r, "A18.scope_grant_agent_absent")?.status, "pass");
    assert.match(st(r, "A18.scope_grant_agent_absent")?.asserted ?? "", /no agentProbe configured/);
  });

  it("a scopeGrantOp that names no person op of the manifest fails with the config key named", async () => {
    const r = await runG({}, cfg({ op: "item_get" }));
    assert.equal(st(r, "A18.scope_grant_within")?.status, "fail");
    assert.match(st(r, "A18.scope_grant_within")?.asserted ?? "", /scopeGrantOp\.op "item_get": not a person op/);
  });

  it("scopeGrantOp config keys are checked (usage error)", () => {
    const base = { op: "scope_grant", input: {}, aboveCeiling: {} };
    for (const bad of [[], {}, { op: "" }, { op: "x", input: {} }, { ...base, extra: 1 }, { ...base, agentProbe: [] }, { ...base, agentProbe: { op: "" } }, { ...base, agentProbe: { op: "p", path: "scopeGrants" } }, { ...base, input: { a: "${nope}" } }, { ...base, agentProbe: { op: "p", extra: 1 } }]) {
      assert.throws(() => parseConformanceConfig({ scopeGrantOp: bad }, "test config"), /scopeGrantOp/, JSON.stringify(bad));
    }
    assert.deepEqual(parseConformanceConfig({ scopeGrantOp: { ...base, agentProbe: { op: "p", path: "/x" } } }, "t").scopeGrantOp, { ...base, agentProbe: { op: "p", path: "/x" } });
  });
});
