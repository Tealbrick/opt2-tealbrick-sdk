# Third-party notices

This app's own code is Apache-2.0 (see `LICENSE` and `NOTICE`). It includes the software and assets below under their own
licences. Update this file when you add a dependency, a vendored file or a companion image.

## Vendored into the built UI (`dist/ui`)

The UI build (`scripts/build-ui.ts`) copies these files into the app image.

| Name | Version | Licence | Source |
|---|---|---|---|
| React (`react`) | 19.3.0 | MIT | https://github.com/facebook/react |
| React DOM (`react-dom`) | 19.3.0 | MIT | https://github.com/facebook/react |
| `scheduler` | 0.28.0 | MIT | https://github.com/facebook/react |
| `@opt2-tealbrick/ui` (Tealbrick design system kit: tokens, components, CSS) | 0.3.0 | Tealbrick Software Licence 1.1 (incl. SDK Licence; https://tealbrick.com/software-licence) | https://github.com/Tealbrick/opt2-tealbrick-packages |
| `@opt2-tealbrick/miniapp-sdk/client` and `@opt2-tealbrick/spec/bridge` (browser modules only) | 0.1.36 / 0.1.52 | Tealbrick Software Licence 1.1 (incl. SDK Licence; https://tealbrick.com/software-licence) | see the next section |
| Nunito (variable font, `vendor/@opt2-tealbrick/ui/dist/fonts/*.woff2`) | 5.3.0 (`@fontsource-variable/nunito`) | SIL Open Font License 1.1 | https://github.com/googlefonts/nunito |

- Nunito is Copyright 2014 The Nunito Project Authors. Its licence text ships next to the font files as
  `vendor/@opt2-tealbrick/ui/dist/fonts/OFL.txt`.
- The Tealbrick brand mark and the app stills (`stills/*.webp`, from `@opt2-tealbrick/ui` `assets/`) are Tealbrick
  artwork. They are **not** covered by the Apache-2.0 licence of this app and are not licensed for reuse outside
  Tealbrick products.

## Runtime dependencies in the image (production `node_modules`)

| Name | Version | Licence | Source |
|---|---|---|---|
| `@opt2-tealbrick/miniapp-sdk` | 0.1.36 | Tealbrick Software Licence 1.1 (incl. SDK Licence; https://tealbrick.com/software-licence) | https://github.com/Tealbrick/opt2-tealbrick-sdk |
| `@opt2-tealbrick/manifest` | 0.1.28 | Tealbrick Software Licence 1.1 (incl. SDK Licence; https://tealbrick.com/software-licence) | https://github.com/Tealbrick/opt2-tealbrick-sdk |
| `@opt2-tealbrick/spec` (dependency of the SDK) | 0.1.52 | Tealbrick Software Licence 1.1 (incl. SDK Licence; https://tealbrick.com/software-licence) | https://github.com/Tealbrick/opt2-tealbrick-specs |
| `ajv` (dependency of the manifest package; 8.18.0 closes OSV GHSA-2g4f-4pwh-qvx6) | 8.18.0 | MIT | https://github.com/ajv-validator/ajv |
| `fast-deep-equal` (ajv) | 3.1.3 | MIT | https://github.com/epoberezkin/fast-deep-equal |
| `fast-uri` (ajv) | 3.1.8 | BSD-3-Clause | https://github.com/fastify/fast-uri |
| `json-schema-traverse` (ajv) | 1.0.0 | MIT | https://github.com/epoberezkin/json-schema-traverse |
| `require-from-string` (ajv) | 2.0.2 | MIT | https://github.com/floatdrop/require-from-string |
| `parse5` (dependency of `@opt2-tealbrick/miniapp-sdk` from 0.1.29, for `sanitizeAgentDocument`; only when the app depends on that SDK version) | 8.0.1 | MIT (Copyright (c) 2013-2019 Ivan Nikulin) | https://github.com/inikulin/parse5 |
| `entities` (parse5) | 8.1.0 | BSD-2-Clause (Copyright (c) Felix Boehm) | https://github.com/fb55/entities |

## Base image

`node:24-slim` (Dockerfile): Node.js (MIT, with bundled components under their own licences) on Debian (the licences of
its packages are in `/usr/share/doc/*/copyright` inside the image).

## Development only (not shipped)

TypeScript, Biome, `@types/*`, happy-dom and `@opt2-tealbrick/conformance` are used to build and test the app and are
not part of the image.
`@opt2-tealbrick/conformance` 0.1.26 shares the app's pins of `@opt2-tealbrick/manifest` 0.1.28, `@opt2-tealbrick/miniapp-sdk` 0.1.36
and `@opt2-tealbrick/spec` 0.1.52, so the lockfile holds one copy of each and `ajv` 8.18.0 only.
