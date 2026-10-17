# @opt2-tealbrick/conformance

The Teal Brick opt2 conformance suite: checks, a fake bridge and a fake Portal, generated from `@opt2-tealbrick/spec`.
Targets: `app`, `manifest`, `bridge`, `relay`, `core` (`tb-conformance --help`).

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
