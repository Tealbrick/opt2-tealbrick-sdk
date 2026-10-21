# @opt2-tealbrick/conformance

The Teal Brick opt2 conformance suite: checks, a fake bridge and a fake Portal, generated from `@opt2-tealbrick/spec`.
Targets: `app`, `manifest`, `bridge`, `relay`, `core` (`tb-conformance --help`).

## 0.1.28 (spec 0.1.57, C274c, C274d): app events

Release order (MANIFEST §16.3, C215): spec 0.1.57 → `@opt2-tealbrick/manifest` 0.1.30 → `@opt2-tealbrick/miniapp-sdk` 0.1.38 → this package → bridge 0.2.7. The pins of manifest, miniapp-sdk and conformance move to spec 0.1.57.

- **Manifest target: `M-EV-1`..`M-EV-4`** (MANIFEST §16.1). Each row re-asserts the rule on the manifest's own `events` (none declared → that part is empty) and proves that `validateManifest` refuses a mutated copy with the rule's code: a duplicate name, `tb.hold.decided` and events in a manifest `tb` (`event_name_invalid`); an array root, an unknown keyword (strict compile) and a `$id` (`event_schema_invalid`); an unknown op and a person op as `visibleWith` (`event_visible_with_invalid`); a top-level `summary` (`event_schema_invalid`, M-EV-4).
- **App target: `A-EV-1`..`A-EV-8`** (SDK >= 0.1.38, else not_applicable by version). A new optional fixture in `tealbrick-conformance.json`: `eventsProbe {op, event, scopedEvent?, instanceId?}` names a PERSON op the suite drives with `{case, key?, instanceId?, kind?}`: `emit` (one declared change that emits exactly one `event`, with the given key), `rollback` (an emit in a transaction that rolls back; the op answers 200), `commit_throw` (an emit in a committed transaction, then the op throws), `invalid` with `kind` payload | undeclared | reserved (the op returns the TbError code as `{code}`), `scoped` (one `scopedEvent` for `instanceId`, with the key), `purge` (`ctx.purgeEvents(instanceId)`), `grant {agent, access}` (`ctx.scopeGrants.grant(agent, <scope type>, instanceId, access)`). A manifest that declares `events` and has no `eventsProbe` FAILS every A-EV row (SDK-API §20, specs#33); a manifest without events and without the fixture is not_applicable. The fake bridge's slices carry the `events` cap only inside these rows.
  - `A-EV-1` exactly one emit item for one change, with the key, a declared name and a valid payload; `A-EV-2` a rolled-back emit is never sent, a committed one followed by a throw is; `A-EV-3` the three invalid emits throw their codes and nothing is sent; `A-EV-4` the fake answers 503 once, the batch comes again with the same key and is accepted once; `A-EV-5` no events cap → nothing sent, the cap appears → the backlog in order; `A-EV-6` `eligible` of a scoped emit = the agent rows of `tb.agents_list` on (scopeType, instanceId) whose crud ⊇ visibleWith.crud, with their authority; `A-EV-7` an owner row of agent B set, narrowed (when a narrower level exists) and removed (`tb.scopes_set`) → `purge {agent B}` after the earlier event (the scoped probe must answer 200 and its event must be sent); an owner row at the agent ceiling, a second scoped event, then `{case: grant}` of the same level (owner → bounded) → one more `purge {agent B}` after it; `{case: purge}` → a purge without agent (rows restored afterwards); `A-EV-8` `tb.hold.decided` to the agent caller on approve and deny (data, `to`, subject, no summary), none for an app caller's hold (expiry: miniapp-sdk tests only, the TTL is 15 min).
- **Bridge target: group `events`, `B-EV-1`..`B-EV-18`**: `B-EV-1`..`17` = one row per case of BRIDGE §14.4, in that order, decided by the `events` capability of the latest StatusReport (never by version): without it every row is not_applicable (`B-EV-17` fails a bridge that declared the cap in an earlier report and dropped it). With the cap the suite lists three extra fake apps for this group only (two that declare `conf.ping`, `conf.target` and, when the example manifest has a scoped read op, `conf.scoped`, plus one with product `tb`) and drives the agents on their `/mcp` session (`tealbrick/events/{list,poll,stream}`, GET /mcp frames). `B-EV-8`/`B-EV-11` send 10 100 events (101 batches, 429 honoured); "older than 7 days" is not observable in a run. `B-EV-17` (the row that certifies the cap) passes only when EVERY StatusReport of the run declares `events` and every one of `B-EV-1`..`16` PASSED (not_applicable or not_run counts as not passed). `B-EV-18`: a bridge WITHOUT the cap answers `tealbrick/events/list|poll|stream` with JSON-RPC -32601 (not_applicable for a bridge with the cap).
- **Fake bridge.** `POST /tb/v1/events` (instance assertion, 1..100 items, the §14.1 checks in order) into a per-agent log (`src/event-log.ts`, the reference EventLog: fan-out rules 1–4, re-check at delivery, instance-pause hold and re-id, retention 10 000 rows / 7 days with `truncated`, purge; purge keys deduped like emit keys, specs#33); `POST /mcp` serves the three methods and `GET /mcp` the frames for a runtime under test (fake authentication: `Authorization: Bearer <slice agent id>`). Control: `control.failNextEvents(n, status?, code?)`, `control.eventItems()`.
- **Test doubles.** The mini bridge implements §14 with the same EventLog when `events: true` (and declares the cap); faults `deliverToCause`, `ignoreEligible`, `noDeliveryRecheck`, `keepSummaryWithHook`, `noDedupe`, `noReId`, `noTruncated`, `noReserved`, `noPurge` and `declaredCaps: ["owner_rows", "events"]` without the implementation each fail their rows; `eventsMethodsAnswerEmpty` (no cap, but the methods answer) fails `B-EV-18`. `test/app-real-sdk.test.ts` runs `A-EV-1`..`8` against the real miniapp-sdk (pass), and against a broken probe plus an outbox without purges and `tb.hold.decided` (`A-EV-1`, `2`, `3`, `7`, `8` fail).

## 0.1.27 (spec 0.1.54, C292, C292a)

Release order (C215, each indexed and mirrored before the next tag): spec 0.1.54 → Portal Core with caps (portal-core#40) → `@opt2-tealbrick/manifest` 0.1.29 → `@opt2-tealbrick/miniapp-sdk` 0.1.37 → this package → bridge 0.2.5. The pins of manifest (0.1.29), miniapp-sdk and conformance move to spec 0.1.54.

- **Bridge target: the A1 rows are decided by the reported capability, not by version.** `B5.gate_scoped_above_grant` (and the unscoped-only rule of `B5.crud_exceeds_grant`) read `bridge.caps` of the latest StatusReport the fake Portal received. A bridge that does not declare `owner_rows` gets `not_applicable`, with the reason and the caps it did report; a bridge that declares it MUST pass: the scoped op named in `admittedOps` reaches the app. The earlier gate (bridge version >= 0.2.4) would have failed a real 0.2.4 bridge, which has no A1 filter (A1 and the cap first ship in bridge 0.2.5, C292a). A bridge that declares the cap without the filter fails the row. The version a bridge reports no longer matters for these rows.
- **App target: `ctx.bridgeCaps()` (group A22, SDK >= 0.1.37).** A new optional fixture in `tealbrick-conformance.json`: `bridgeCapsOp {op, path?, input?}` names a PERSON op whose output (JSON pointer `path`, default `/bridgeCaps`) is what `ctx.bridgeCaps()` gave the handler. Without it, or for an app that reports an SDK older than 0.1.37, the three rows are `not_applicable` with the reason (the value is not observable from outside; a later release may require the fixture of an app that reports SDK >= 0.1.37).
  - `A22.bridge_caps_equal`: the slice carries `bridge.caps` `["owner_rows", "tbconf_future_cap"]` → the op's value equals it (an unknown entry passes through); a new slice with `["owner_rows"]` → the next call shows exactly that (no snapshot).
  - `A22.bridge_caps_absent`: after a slice with `["owner_rows"]`, a slice WITHOUT `bridge.caps`, and one with `bridge.caps: []`, both give `[]` (an app that keeps caps it saw earlier fails).
  - `A22.bridge_caps_expired`: a slice with `["owner_rows"]` that stays valid for 4 more seconds is installed; after it has expired the op still runs (a person op does) and gives `[]`. The row takes about 6 seconds; it is `not_run` when the app does not install the short-lived slice in time. The next normal slice restores the caps (none) after every row.
  - Fake bridge: `control.setBridgeCaps(caps | undefined)`, `control.publishShortLivedSlice(secondsLeft)` (slice `iat` = now - 12 h + secondsLeft).
- **Test doubles.** Mini app: faults `bridgeCapsSnapshot` and `bridgeCapsDropsUnknown` (fail `A22.bridge_caps_equal`), `bridgeCapsSticky` (fails `A22.bridge_caps_absent`), `bridgeCapsIgnoresExpiry` (fails `A22.bridge_caps_expired`). Mini bridge: `ownerRows` (implements the A1 filter and declares the cap in every ack), `declaredCaps`. `test/app-real-sdk.test.ts` runs the three A22 rows against the real miniapp-sdk of this workspace (a person op returning `ctx.bridgeCaps()`). The new tests carry their own `{ timeout: 60_000 }` or more.

## 0.1.26 (spec 0.1.52)

Follow-up of the adversarial review of 0.1.25 (sdk#37, verdict safe). Release order (C215): this package is indexed and mirrored BEFORE `create-tealbrick-miniapp` 0.1.19 is tagged (the template pins it).

- **`A21.owner_row_widened_level` / `A21.owner_row_narrowed_level` fail when the start module ignores `TBCONF_LEVEL_CRUD`.** In 0.1.25 such an app got `not_applicable` and the two rows that guard the owner-row rule were silently skipped. Now an app that reports `sdkVersion` >= 0.1.36 in its claim, or that declares `proofClaims: ["bd"]`, must apply the variable: "the level change did not apply" is `fail`. Below 0.1.36 and without `bd` the rows stay `not_applicable` by version. `sdkVersion` is what the app says about itself (it is not verified), which is why the `proofClaims` declaration counts as a second signal. The rows say so in their text.
- **`A21.snapshot_backfill` stays `not_applicable`, and says why.** The one-time backfill of schema migration 10 (and a NULL or unparsable snapshot reading `[]`) is not observable from outside. It is covered ONLY by the miniapp-sdk tests (`packages/miniapp-sdk/test/owner-authority.test.ts`, the schema-10 tests). A conformance run says nothing about it.
- **Positive controls for the forged-`bd` rows.** `A2.hook_bd_malformed` and `A2.proof_bd_other_variants` build their refused tokens by re-signing a proof with one extra claim (`Mint.withExtraClaim`). Both rows now first send the SAME re-signing path with a VALID `bd` for a hook proof (and, in `A2.proof_bd_other_variants`, an identity re-sign of an op proof and a bridge-op proof): a correct app answers them, so a broken minting helper (every re-signed token refused) can no longer make the refusals pass.
- **New row `A2.hook_bd_raw_bytes`.** The same JSON body sent as other bytes (pretty-printed; every object's keys reversed) under the `bd` of the ORIGINAL bytes is refused 401 `call_proof_invalid`: `bd` hashes the bytes received, not a re-serialisation of the parsed body. Controls: the original bytes under their own `bd`, and each variant under ITS OWN `bd`, are answered.
- **Test doubles.** New mini-app fault `hookHashesReserialised`; `ignoresLevelCrud` now expects `fail`. The new tests carry their own `{ timeout: 60_000 }` or more; the schema-10 SDK tests carry `{ timeout: 60_000 }`.

## 0.1.25 (spec 0.1.52)

Release order (C215): spec 0.1.52 → `@opt2-tealbrick/manifest` 0.1.28 → `@opt2-tealbrick/miniapp-sdk` 0.1.36 → this package → bridge 0.2.5. All rows below are SDK >= 0.1.36 rules: an app that reports an older SDK in its claim gets `not_applicable` by version, whatever it does.

- **C283b/C283c, owner rows keep the CRUD they were set with (group A21).**
  - `A21.owner_row_widened_level`: a fresh agent; the owner sets level L on its rows; the app is "updated" so L gains the actions of a scoped op. The call needing them is refused 403 `scope_denied` (the Portal grant covers it, so the row is the only limiter), every owner row lists `crud` without them and `offer.adds` = them; a plain re-set of L accepts nothing; `acceptOffer` with other adds is 409 `offer_changed` and changes nothing; `acceptOffer` with the current adds (reversed, with a duplicate: compared as a set) is 200, the rows list the new crud and no offer, and the call runs.
  - `A21.owner_row_narrowed_level`: the owner row at the lowest level that covers a scoped op runs the call above the Portal grant; the app is updated so that level loses the op's actions: the call is refused 403 `scope_denied` at once, the rows list the narrower crud and NO offer.
  - `A21.accept_offer_rules` (no update needed): with no offer `acceptOffer {adds: []}` is 200 and any other adds is 409 `offer_changed`; `acceptOffer` with another level or with `access: null` is 400 `input_invalid` and the row is unchanged (not deleted); a malformed `acceptOffer` is 400; a plain re-set keeps the owner row.
  - `A21.snapshot_backfill`: always `not_applicable`: the one-time backfill of the schema migration, and a NULL or unparsable snapshot reading `[]`, need a data directory written by an older SDK and the app's database, which a black-box suite cannot reach. It is covered ONLY by the miniapp-sdk tests (`owner-authority.test.ts`, the schema-10 tests), not by this suite.
  - **"An app update" in a black-box suite.** The two update rows restart the app on the same data dir with the env name `TBCONF_LEVEL_CRUD` (JSON `[{type, level, crud}]`; exported as `LEVEL_CRUD_ENV`, with `parseLevelCrud` and `applyLevelCrud` for start modules). A start module applies it to its manifest before `defineApp`, like `TBCONF_PORT` and `TBCONF_PORTAL_ROOT_KEYS` (a harness name, not a `TB_*` name; the SDK never reads it). The suite checks that the app serves the digest of the updated manifest (`GET /tb/v1/health`); a start module that ignores the variable makes the two update rows `fail` for an app that reports SDK >= 0.1.36 or declares `proofClaims ["bd"]` (0.1.26; `not_applicable` in 0.1.25) and the report lists them. `--url` mode (no restart) reports `not_run`. The suite restarts the app back to the released manifest afterwards.
- **C268 B / C268c, hook proof `bd` (spec 0.1.52).**
  - `A2.proof_claims_declared`: the claim and every status push carry `proofClaims: ["bd"]`.
  - `A2.hook_bd_binds_body`: at every declared hook, for an agent and an app caller, a proof whose `bd` is the sha256 of the exact bytes sent is answered; the same proof with other bytes (`call.ws` changed: a field outside `ctx` and `in`, bound by no other claim since `call.id` and the caller are bound by `call` and `sub`) is refused 401 `call_proof_invalid`.
  - `A2.hook_bd_malformed`: `bd` = `""`, `sha256:abc`, upper-case hex, another algorithm, a number or `null` is refused 401 `call_proof_invalid`.
  - `A2.proof_bd_other_variants`: `bd` on an op proof (`tb.hold_status`) and on a bridge-op proof (`scope_summary`) is refused 401 `call_proof_invalid`; the same calls without `bd` are not.
  - A hook proof WITHOUT `bd` stays accepted: that is the baseline of every hook row.
- **Test doubles.** The mini app implements the rules and has one fault per row (`ownerRowFollowsLevel`, `ownerRowSnapshotOnly`, `plainResetAccepts`, `acceptNoCompare`, `acceptPhantomOk`, `acceptNullDeletes`, `acceptOtherLevelOk`, `noOffer`, `noEffectiveCrud`, `ignoresLevelCrud`, `hookIgnoresBd`, `bdProofsUnverified`, `noProofClaims`). The real miniapp-sdk of this workspace passes every row (`test/app-real-sdk.test.ts`).
- **Fix.** The CLI exits only after stdout and stderr are flushed. A report over 64 KiB (the pipe size) was cut off mid-string when a parent process read it; with these rows the report is larger than that.

## 0.1.24 (spec 0.1.50)

Release order (C215): `@opt2-tealbrick/manifest` 0.1.27 indexed and mirrored, then `@opt2-tealbrick/miniapp-sdk` 0.1.35, then this package. The workspace link pins the three together, so this package no longer carries the stale manifest 0.1.25 (ajv 8.17.1) of 0.1.23: it is built with manifest 0.1.27 (ajv 8.18.0).

All app-target rows below are SDK >= 0.1.35 rules: an app that reports an older SDK in its claim gets `not_applicable` by version, whatever it does.

- **C283 A1, owner-set access is primary (group A20, spec 0.1.50).** A row the owner wrote with `tb.scopes_set` carries `authority: "owner"` in `tb.agents_list` and is primary for a SCOPED op, also above the Portal grant's crud; every other row (manifest defaults, app rows) is `bounded` and keeps the grant as its ceiling. The rows use a FRESH agent each (no other check sees its rows), a Portal grant with crud `[read]` and a scoped op that needs more.
  - `A20.bounded_above_grant_refused`: the default (bounded) row covers the op, the grant does not → 403 `scope_denied`; the same input with the op's crud in the grant runs (so the refusal is the grant's, not a missing row). `not_applicable` when a fresh agent's default rows cover no scoped op.
  - `A20.owner_row_above_grant`: the owner saves a covering row with `tb.scopes_set` → the row shows `authority: "owner"`, the call above the grant runs (or is held), and its receipt row says `admittedBy: "app_owner_row"`.
  - `A20.agent_cannot_write_owner_row` / `A20.app_cannot_write_owner_row`: an agent call and a companion (app) call to `tb.scopes_set` are refused `audience_not_agent`; no row changes (level, source, authority); the agent's call above the grant is still refused.
  - `A20.scope_grants_bounded` (needs the `scopeGrantOp` fixture of 0.1.22): the app writes a row with `ctx.scopeGrants`, the owner makes it primary with `tb.scopes_set`, the app writes it again → source `app`, authority not `owner`. Every changed row is restored like A18.
  - `A20.unscoped_above_grant_refused`: an agent whose rows are all owner rows still gets 403 `scope_denied` for an op WITHOUT a scope type above the grant (`not_applicable` when the manifest has no such op).
  - `A20.paused_agent_owner_row`: an agent with an owner row above the grant runs; paused in the slice → 403 `paused`; released → runs again.
  - `A20.catalog_admitted` (needs a dynamic agent op with a `scopeType`): the bridge op `catalog` with `{op, agent}` marks `admitted: "owner"` on exactly the entries a fresh agent's owner rows admit; a fresh agent with default rows only and a body without `agent` get no mark.
  - `A20.admitted_ops`: the bridge op `scope_summary` names in `admittedOps` exactly the static scoped agent ops a fresh agent's owner rows admit; a fresh agent with default rows only has none.
- **C261, `A12.caller_unverified_refused` (spec 0.1.49 slice flag `appCallers: "verified"`).** With the flag the suite's app caller (not in `companionCallers`, grant without `prd`) is refused 403 `caller_unverified` and no run receipt appears; the same instance listed in `companionCallers`, and an unlisted one whose grant carries `prd`, are not refused as unverified; with the flag cleared the unverified caller is not refused `caller_unverified` (the earlier lenient rule). The flag is always cleared again. New control API: `control.setAppCallers("verified" | null)`.
- **C268 A, hook proof `sub` / `call` (spec 0.1.50).** `A2.hook_sub_mismatch` and `A2.hook_call_mismatch`: at every declared hook, for an agent caller and an app caller, the matching call is answered 200, and the same request whose proof names another caller (`sub`) or another call (`call`) is refused 401 `call_proof_invalid`. The existing hook probes now sign the proof with the `sub` of the request's caller and the request's call id (before: agent A and a fresh id), as the bridge does.
- **Bridge target, `B5.gate_scoped_above_grant` (decided by the reported `owner_rows` cap since 0.1.27; 0.1.25 used bridge >= 0.2.4, which a real 0.2.4 bridge fails).** The app's `scope_summary` names a scoped op beyond the Free grant's crud in `admittedOps` for the Free agent; the bridge lists the tool and its gate passes the call, so the app receives it. `B5.crud_exceeds_grant` keeps its rule for ops WITHOUT a `scopeType` (for a bridge that declares `owner_rows` it is `not_applicable` when every op beyond the grant is scoped; other bridges refuse both as before).
- Fake bridge: slice `appCallers` (`control.setAppCallers`), hook proofs bound to the request's caller and call id. Test doubles: the mini app and the mini bridge implement the 0.1.50 rules, each with faults the new rows must catch (`scopesSetBounded`, `allRowsPrimary`, `agentSetsOwner`, `appSetsOwner`, `scopeGrantKeepsOwner`, `ownerWidensUnscoped`, `ownerRevivesPaused`, `noAuthorityField`, `noAdmittedBy`, `catalogMarksAll`, `catalogNoMarks`, `admittedOpsAlways`, `noAdmittedOps`, `noCallerUnverified`, `hookIgnoresSub`, `hookIgnoresCall`; bridge: `ignoresAdmittedOps`, `oldGateCrud`).

## 0.1.23 (spec 0.1.49)

- App target, SDK-COMPANION-CALLERS (group A19, SDK >= 0.1.32; an older SDK is `not_applicable` by version): `ctx.companionCallers()` on owner pages. Opt-in fixture `companionCallersOp` in `tealbrick-conformance.json`: `{op: "<person op>", path?: "/companionCallers", input?, agentProbe?: {op: "<static agent op>", path?, input?}}`. The app's op returns what `ctx.companionCallers()` gave it, at `path` (JSON pointer into the op output). Without the fixture both checks are `not_applicable`.
  - `A19.companion_callers_person`: the suite lists three companion callers in the fake bridge slice (provider `railway`, `own_infra` and `null`), publishes it, runs the person op as the owner and requires the output at `path` to equal the WHOLE slice list `{product, ins, name, provider}` (`provider` null = unknown; any other member, for example grant material, fails; the listed callers are removed again afterwards). A list taken before the slice update, a dropped `provider` or an extra member fails.
  - `A19.companion_callers_agent_absent` (needs `agentProbe`; else `not_applicable`, since it is not observable black-box): agent A calls the probe agent op while the slice lists a caller; its output at `path` must be absent (undefined, null or false). Any list on an agent call fails.
  - `A19.caller_listed` (opt-in fixture `callerListedOp: {op: "<static agent op>", path?: "/listed", input?}`; extension `Caller.listed`, SPEC-GAP spec 0.1.49, SDK >= 0.1.32): the suite's `as: app` caller (companion grant with `prd` = `tbconf-listed`; `inputsAs.app` fixtures apply) runs the op while the slice lists its instance under that product, then again after the slice drops it. The output at `path` must be `true`, then `false`.
- App target, HOOK-CALLER-PRODUCT from the APP side (spec 0.1.45, bridge >= 0.2.2 sends `call.caller.product`): every declared BEFORE hook is now also called with `call.caller {type: "app", id: <an instance id>, product: <p>}` and with the same caller WITHOUT `product`, each with a proper hook proof. Both answers must be valid before answers (the `A2.hook_valid` shape rule): `A2.hook_app_caller_product`, `A2.hook_app_caller_no_product`. A manifest without before hooks is `not_applicable`.
  - Opt-in fixture `hookCallerProduct: {hook: "<before hook id>", product: "<product the hook's criteria key on>", op?: "<target op>", input?: <json>}` (placeholders allowed in `input`): with that product the hook answers per the app's rule (recorded in the report, must be valid). `A2.hook_app_caller_fail_closed`: the SAME caller without `product` must be answered `allow: false` (a hold verdict also has `allow: false`); `allow: true` fails. Without the fixture this check is `not_applicable`.
- Fake bridge world (bridge target): `companionCallers` entries now carry `provider` (`railway`, `own_infra` alternating).
- Test hygiene: the relay runner (`runRelayTarget`) kills every target process it started also when the runner exits by `process.exit`, SIGINT or SIGTERM (the processes run detached in their own group). The test relay ends by itself when its stdin closes, so the `--broken=listen` variant no longer outlives a killed runner. A new test fails if a run leaves a relay process behind.
- Config keys `companionCallersOp`, `hookCallerProduct` and `callerListedOp` are checked like the others (unknown key = usage error).

## 0.1.22 (spec 0.1.47)

- App target, SDK-INSTANCE-GRANT (group A18, SDK >= 0.1.31; an older SDK, read from its claim, is `not_applicable` by version): a person op that gives one agent one scope instance.
  - `A18.scope_grant_within`: the person op named by `scopeGrantOp` runs with `scopeGrantOp.input` (a grant within the agent ceiling) → 200, and `tb.agents_list` then lists a scope row with `source: "app"` and `grantedByOp` = that op id.
  - `A18.scope_grant_ceiling`: the same op with `scopeGrantOp.aboveCeiling` → 400 `scope_grant_invalid` and no new `source: "app"` row (a sabotaged SDK that skips the ceiling fails).
  - `A18.scope_grant_agent_absent`: an AGENT calling that person op is refused 403 `audience_not_agent` and writes no row; with the optional `scopeGrantOp.agentProbe` (an agent op whose output has a boolean at `path`, default `/scopeGrants`, equal to `ctx.scopeGrants !== undefined`) the boolean must be `false` (a sabotaged SDK that exposes `scopeGrants` on an agent call fails).
  - `scopeGrantOp` in `tealbrick-conformance.json` (placeholders such as `${tb.agentA}` allowed). Without it (an app that does not use the API) the three checks are `not_applicable`. Each check snapshots all scope rows first and puts every changed row back afterwards (a new row is removed, an owner row gets its level back with `tb.scopes_set`); a prior row with source `default` or `app` cannot be rewritten with its source through the public API, so a fixture that grants over one reports `not_run` (use a fresh instance). `A18.scope_grant_within` needs a NEW (or changed) row with source `app`, the op id in `grantedByOp`, the agent and the access level named in the input; an identical pre-existing row is `not_run`. `A18.scope_grant_ceiling` requires 400 AND that no scope row changed (level or source), so an SDK that clamps to the ceiling and answers 200 fails.

    ```json
    {
      "scopeGrantOp": {
        "op": "draft_start",
        "input": { "agent": "${tb.agentA}", "draft": "conformance-draft", "access": "read_write" },
        "aboveCeiling": { "agent": "${tb.agentA}", "draft": "conformance-draft", "access": "manage" },
        "agentProbe": { "op": "scope_probe", "path": "/scopeGrants" }
      }
    }
    ```

## 0.1.21 (spec 0.1.46)

- App target, GRANT-PRD: `A12.grant_prd_first` (a companion grant with `prd`, caller not yet in the slice: the receipt reports that product), `A12.grant_prd_mismatch` (grant `prd` differs from the slice product: refused 403 `grant_invalid`; a sabotaged SDK that prefers the slice fails), `A12.grant_prd_absent` (no `prd`: the slice product).
- Bridge target, HOOK-CALLER-PRODUCT (spec 0.1.45): `B28.hook_caller_product` in group `spine013`. Bridges older than 0.2.2 (version read from the EnrolRequest) report it `not_applicable` by version.
- Setup fixtures: `"as": "capsAgent"` and `${tb.capsAgent}` (see "Setup as the caps agent" below).

## Real peer apps behind the fake bridge (`--peers`, since 0.1.20)

By default the app under test talks to FAKE companion apps. With `--peers` the suite also starts REAL SDK apps at pinned
released versions and routes the companion calls of the app under test to them through the fake bridge (CONF-MULTIAPP,
L2 real-to-real). Off by default; `--no-peers` is the explicit form of the default.

### Enable it

1. Declare the peers in `tealbrick-conformance.json` next to the manifest (at most 3):

   ```json
   {
     "peers": [
       { "product": "kanban", "version": "0.1.13" },
       { "product": "knowledge", "version": "0.1.21", "channel": "stable", "settings": { "engine": "stub" } }
     ],
     "contractOps": { "messages/1": "knowledge.data_pull" }
   }
   ```

   - `product` + exact `version` (no ranges). `channel` is `stable` (default) or `dev` (a pre-release pair).
   - `settings` reach the peer's start module as JSON in `TBCONF_PEER_SETTINGS`. A peer that needs a companion service
     runs in its stub mode; a peer that cannot start without one is refused (X1 fails with the reason, never skipped).
   - Unknown keys are refused (usage error, exit 2).
   - `contractOps` (X4) names, per contract the app consumes and a peer produces, the peer op whose real output is the
     contract (`<peer product>.<op id>`). The manifests only declare WHICH contracts, not which op carries them.
   - A peer must be named in the app's `companions[]`, or name the app as a companion.
2. Run `tb-conformance app --start conformance.start.ts --manifest tealbrick.manifest.json --peers` (add `--clean-peers`
   to remove the checkouts afterwards). Needs test roots (the default), `pnpm` on `PATH` and network access to the
   release index host, `codeload.github.com` and the npm registry/dist hosts the peer's lockfile names.
3. The platform CI template opt-in (`tealbrick-ci.json` `conformancePeers`) is a platform change, not part of this package.

### Where a peer comes from (trust)

The peer is never a branch. The suite fetches the SIGNED release index (`index.json` + `index.jws`) from the pinned
registry hosts, verifies the JWS with the pinned release key (`verifyReleaseIndex` of `@opt2-tealbrick/manifest`, the code
Core and the CLI use), takes the record of `product@version` on the channel, and downloads `https://codeload.github.com/<repo>/tar.gz/<commit>`
of that record. Public repos only: a private repo (or an unpushed commit) answers 404 and the peer is refused with that
reason. The archive's top directory must end with the recorded commit; the checkout's manifest must be the released
version and, when the record has one, have the recorded digest. Then `pnpm install --frozen-lockfile --ignore-scripts`
and the repo's own `build` script. The peer starts through the same child-process path as `--start`
(`conformance.start.ts` of the checkout), with the conformance env (its own fake bridge, test roots, a temp data dir) and
without this process's environment (no CI secrets reach it). Checkouts are cached in `<tmp>/tbconf-peers/<product>@<version>@<commit>`.

### The checks (group X; one row per peer or per declared companion op)

| Row | Asserts |
|---|---|
| `X1.peer_boot.<peer>` | the peer boots, claims through its own fake bridge, installs its slice, answers `/tb/v1/health` with its manifest digest |
| `X2.companion_call.<peer>.<op>` | a REAL `callApp` of the app under test through the fake bridge reaches the peer with its companion grant and answers `ok` (or `held` when the apps policy holds the op); the PEER's receipt names the verified caller (`caller.type` app, `caller.id` this instance, `caller.product` the app under test, never a decoy of the same name that is listed first). `not_run` when no agent op of the app makes the call with the generated inputs: supply `inputs` fixtures in `tealbrick-conformance.json` |
| `X3.companion_refused.<peer>.<op>` | the real peer refuses a grant whose crud does not cover the op, a grant for another instance, a tampered proof and no proof (fire-on-bad: a peer that ignores the grant fails here). The grant's workflow list `wf` is the BRIDGE's rule (gate step 4, applied by the fake bridge in front of the peer); the SDK app does not re-check it on a live call |
| `X4.contract_schema.<peer>.<op>` | the peer's real output validates against the pinned schema in `@opt2-tealbrick/spec/schemas/contracts` (when the app `consumes` a contract the peer `produces`) |
| `X5.hold_round_trip.<peer>.<op>` | for an op the apps policy holds: held, listed by the peer, approved, the same call runs once, a call with a new key is held again |

Row ids are catalogued by `isCheckId` (waivers may name them).

### CI cost

Per peer: archive download (1 to 5 MB), frozen install (warm pnpm store about 20 to 40 s, cold 60 to 120 s), build (10 to 20 s),
boot (2 to 5 s), checks (seconds). Two peers add about 2 to 4 minutes to the pipeline. Run it on `pull_request` and `tag`
events only, not on every push to main. The peer cache is per pipeline workspace; there is no shared host cache.

### Self-tests

`test/multi-app.test.ts` runs group X against two tiny REAL SDK apps built inside the test (the loader's release index and
source are injected, no network): quiet on good; fires on a peer that ignores the grant, on a peer that finds the caller's
product by name, on an output that violates the contract; reports a peer that cannot start. `test/peer-source.test.ts`
covers the signed index, the archive, the loader and the CLI flags.

## Setup as the caps agent (`as: "capsAgent"`, since 0.1.21)

A3.caps_count creates a fresh agent for each capped op and calls the op twice with a cap of one more run. An op that acts
on data the caller owns (Connect: `buzz_schedule_cancel` on a post the caps agent created) cannot run with a generated
input, because the fresh agent owns nothing yet. A `setup` entry of `tealbrick-conformance.json` may therefore name
`"as": "capsAgent"`:

```json
{
  "setup": [
    { "id": "caps_post", "as": "capsAgent", "op": "buzz_post_create", "input": { "text": "caps probe" }, "capture": { "capsPost": "/id" } }
  ],
  "inputs": { "buzz_schedule_cancel": { "post": "${capsPost}" } }
}
```

- A `capsAgent` step is deferred: it does not run with the other setup steps. For each fresh caps agent the suite runs the
  `capsAgent` steps in order, AS that agent, after the agent exists in the slice and has seen its instance (first sight)
  and before the capped calls. They run again for the next fresh agent, so every capped op gets its own data.
- `${tb.capsAgent}` is the id of that agent, usable in `capsAgent` steps, `inputs` and `inputsAs`. An ordinary setup step
  that names it is a usage error. A capture of a `capsAgent` step holds the value of the agent of the latest pick, so use
  it in the inputs of the capped ops only.
- A step runs with `held: []` and takes a cap slot like any run of its effect. Every successful `capsAgent` step whose op
  has the same effect as the capped op raises the probe's cap by one, so the check still asserts "first call runs, second is held".
- A failing step blocks its captures: A3.caps_count reports `not_run` naming the step and its answer (never a silent pass).
