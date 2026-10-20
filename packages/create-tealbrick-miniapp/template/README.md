# __APP_NAME__

A Teal Brick opt2 miniapp (product id `__APP_ID__`), built on `@opt2-tealbrick/miniapp-sdk`.

`tealbrick.manifest.json` is the only description of the app. The SDK derives the routes, input and output
validation, OpenAPI, receipts, holds, idempotency, scopes, backups and status from it. You write handlers by
operation id (`src/app.ts`) and plain migrations (`migrations/`).

## Layout

| Path | Content |
|---|---|
| `tealbrick.manifest.json` | identity, runtime (data + backup volumes), operations, scopes, skills, backups, UI paths |
| `src/app.ts` | `defineApp`: one typed handler per operation (op ids and I/O types from `#kit`), agent first-sight event |
| `src/items.ts` | the app's table access (plain functions over the SDK `Db`) |
| `src/main.ts` | `startApp(app, process.env)` |
| `src/ui/` | React UI (`<TbProvider>` + `<AppShell>` from `@opt2-tealbrick/ui`), built to `dist/ui` |
| `src/ui/standard.tsx` | the standard pages (Holds, Receipts, Agents & scopes, Backups & export) and the page router; pass your own words as props, do not edit (one source: the template) |
| `src/ui/pages.css` | page layout helpers of the approved mockups (`.page-head`, `.ruled`, `.item`, ...); tokens only. App-only layout goes in `src/ui/app.css` (linked after it when present) |
| `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES.md` | Apache-2.0 (C154), the copyright notice and the upstream licences the app ships (React, the UI kit, Nunito OFL); update the notices when you add a dependency |
| `migrations/0001_init.sql` | baseline; forward-only, never edit a released file |
| `skills/use-__APP_ID__/SKILL.md` | the agent skill (frontmatter `name`, `description`) |
| `scripts/build-ui.ts` | UI build without a bundler (tsc output + vendored modules + import map) |
| `gen/` (not committed) | `tb-gen` output; `node --run kit` generates the kit and compiles it to `dist/kit` (`#kit` import) |
| `Dockerfile` | `node:24-slim` pinned by digest, pnpm build to `dist/`, non-root, `CMD ["node", "dist/main.js"]` |
| `.woodpecker/ci.yaml` | the opt2 CI template, byte-identical copy (do not edit) |
| `tealbrick-ci.json` | CI settings: kind `miniapp`, one image |

## Develop

```sh
pnpm install          # commit pnpm-lock.yaml: CI installs with --frozen-lockfile
# typecheck, test, conformance, build and start first run `tb-gen kit` (op ids + I/O types from the manifest)
pnpm typecheck && pnpm lint && pnpm test      # lint = biome + check-system (the design-system guard)
pnpm build            # server to dist/, UI to dist/ui
pnpm conformance      # SDK conformance suite against this app
TB_STANDALONE=1 TB_DATA_DIR=.data pnpm start   # app-alone mode: person UI only, no agent calls
```

## Environment

The SDK reads only `TB_*` variables (SDK-API §13). The deploy recipe sets them: `TB_INSTANCE_ID`,
`TB_ENROL_CODE`, `TB_BRIDGE_URL`, `TB_PORTAL_KEYS`, `TB_KEK`, `TB_DATA_DIR` (the `data` volume mount, `/data`)
and `TB_BACKUP_DIR` (`/data/backup`: one volume per service). Optional: `TB_LOG_LEVEL`, `TB_RESTORE_FROM`,
`TB_STANDALONE`. The listen port is the manifest `runtime.port`.

Before its first claim the SDK checks that `TB_DATA_DIR` is a mounted volume (SDK 0.1.12); on a container's own
disk it waits and does not use the enrolment code. Tests and CI that run `startApp` or `tb-exec` in bridge mode on
Linux set `TB_DATA_EPHEMERAL=1` in that test or CI step (this template's own tests run app-alone and need none). Never set it in a deploy recipe.

## Release

1. Set the same version in `package.json` and `tealbrick.manifest.json`.
2. Tag `v<semver>` (for example `v0.1.0`) and push the tag.
3. CI builds and publishes the image, then writes the signed release record from the manifest.

Before the first push, check `publisher` and `source.repo` in the manifest. The repository name must match the
image name in `tealbrick-ci.json` (`opt2-tealbrick-__APP_ID__`).

## Dependency pins and caching
- `pnpm-lock.yaml` carries the sha512 integrity of every GitHub-release tarball (CI rule ci-v8). After changing an `@opt2-tealbrick/*` dependency run `pnpm install`, then `node <opt2-tealbrick-platform>/ci/tb-ci.ts pin-tarballs .`, then `pnpm install --frozen-lockfile`, and commit the lockfile. Image builds run `pnpm install --frozen-lockfile --ignore-scripts`.
- `pnpm build` writes the UI to `dist/ui/index.html` + `dist/ui/assets-<content hash>/`; the SDK serves index.html `no-cache` and the hashed directory immutable, so a deploy is visible at once (C61).

## Upgrading the SDK (0.1.36 and later)

- Go from `@opt2-tealbrick/miniapp-sdk` 0.1.34 straight to 0.1.36 (or later). Do not pin 0.1.35. Re-pin `@opt2-tealbrick/manifest` (0.1.28) and `@opt2-tealbrick/conformance` (0.1.26) with it, then run `pnpm install`, `node <opt2-tealbrick-platform>/ci/tb-ci.ts pin-tarballs .` and `pnpm install --frozen-lockfile` (see above).
- **Owner rows keep their CRUD (C283b/C283c).** An owner row stores the crud its level had when the owner set it. When an update widens a level, the row does not widen: it lists the new actions as `offer.adds`. If your owner UI shows scope rows (`useScopes().access`), it MUST show `offer.adds` and call `useScopes().acceptOffer(agent, type, instanceId, adds)` only on an explicit owner click. Never call it from an effect, on load or on another event. The default Agents page of this template lists agents and modes only, so it needs no offer control.
- **`conformance.start.ts` applies `TBCONF_LEVEL_CRUD`** (`parseLevelCrud` and `applyLevelCrud` from the conformance package). The A21 rows `owner_row_widened_level` and `owner_row_narrowed_level` restart the app with that variable to simulate an app update; since conformance 0.1.26 they FAIL for an app on SDK 0.1.36 or later if the start module ignores it. Keep the `leveled` line.
- **Keep a second level that covers each scoped op.** The narrowing row removes the op's actions from the lowest level that covers it. The updated manifest must still validate (M-OP-7), so a higher level (`manage` in this template) must cover the op too.
