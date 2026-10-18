# @opt2-tealbrick/conformance

The Teal Brick opt2 conformance suite: checks, a fake bridge and a fake Portal, generated from `@opt2-tealbrick/spec`.
Targets: `app`, `manifest`, `bridge`, `relay`, `core` (`tb-conformance --help`).

## 0.1.23 (spec 0.1.48)

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
