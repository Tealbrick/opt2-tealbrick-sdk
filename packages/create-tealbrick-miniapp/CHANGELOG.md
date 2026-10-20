# Changelog: create-tealbrick-miniapp

Earlier releases are in the git history of this package.

## 0.1.19

- The template pins `@opt2-tealbrick/manifest` 0.1.28, `@opt2-tealbrick/miniapp-sdk` 0.1.36 and `@opt2-tealbrick/conformance` 0.1.26 (dist tarballs, sha512 integrity in `pnpm-lock.yaml`; the lock now resolves `@opt2-tealbrick/spec` 0.1.52 and one copy of each package). The SDK goes from 0.1.34 to 0.1.36; 0.1.35 is skipped.
- `conformance.start.ts` applies `TBCONF_LEVEL_CRUD` with `parseLevelCrud` and `applyLevelCrud` from the conformance package, as `packages/conformance/test/apps/mini-app.ts` does. A generated app now runs the A21 widen and narrow rows, which FAIL since conformance 0.1.26 for an SDK 0.1.36 app that ignores the variable.
- The starter manifest has a third access level, `manage` (read, create, update, delete). The narrowed manifest of `A21.owner_row_narrowed_level` must still cover `item_create` (M-OP-7); with two levels it did not validate.
- New test `test/conformance.test.ts` generates an app, installs it with `pnpm install --frozen-lockfile --ignore-scripts`, runs conformance 0.1.26 against it and checks that both A21 rows PASS, and FAIL when the `applyLevelCrud` line is removed from the generated start module.
- Template README: notes for SDK 0.1.36 (skip 0.1.35, the owner-click MUST for `acceptOffer`, `pin-tarballs` after a re-pin). The template has no scope-grid UI, so it adds no offer control.
- `THIRD_PARTY_NOTICES.md` follows the new pins.
