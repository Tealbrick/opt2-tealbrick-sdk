# Third-party notices

The packages in this repository are under the Tealbrick Software Licence 1.1 (see `LICENSE`, `LICENSING.md` and `NOTICE`). They
depend at run time on the open-source packages below, under their own licences. Update this file when you add or change a
runtime dependency (the exact versions and integrity hashes are in `pnpm-lock.yaml`).

## Runtime dependencies

| Name | Version | Licence | Used by | Source |
|---|---|---|---|---|
| `parse5` | 8.0.1 | MIT (Copyright (c) 2013-2019 Ivan Nikulin) | `@opt2-tealbrick/miniapp-sdk` 0.1.29+ (`sanitizeAgentDocument`, server entry only) | https://github.com/inikulin/parse5 |
| `entities` (dependency of `parse5`) | 8.1.0 | BSD-2-Clause (Copyright (c) Felix Boehm) | `@opt2-tealbrick/miniapp-sdk` 0.1.29+ (through `parse5`) | https://github.com/fb55/entities |
| `ajv` | 8.18.0 | MIT | `@opt2-tealbrick/manifest` | https://github.com/ajv-validator/ajv |
| `fast-deep-equal` (ajv) | 3.1.3 | MIT | `@opt2-tealbrick/manifest` (through `ajv`) | https://github.com/epoberezkin/fast-deep-equal |
| `fast-uri` (ajv) | 3.1.8 | BSD-3-Clause | `@opt2-tealbrick/manifest` (through `ajv`) | https://github.com/fastify/fast-uri |
| `json-schema-traverse` (ajv) | 1.0.0 | MIT | `@opt2-tealbrick/manifest` (through `ajv`) | https://github.com/epoberezkin/json-schema-traverse |
| `require-from-string` (ajv) | 2.0.2 | MIT | `@opt2-tealbrick/manifest` (through `ajv`) | https://github.com/floatdrop/require-from-string |

`parse5` 8.0.1 has exactly one dependency, `entities` (which has none). Both were checked against the npm registry metadata and
the published tarballs (`package.json` licence field and `LICENSE` file); the lockfile pins the tarball integrity:
`parse5@8.0.1` `sha512-z1e/HMG90obSGeidlli3hj7cbocou0/wa5HacvI3ASx34PecNjNQeaHNo5WIZpWofN9kgkqV1q5YvXe3F0FoPw==`, `entities@8.1.0`
`sha512-kxL7msIffSuh9aaFAMD7rxAIuTRMAHMeBtgHW2yUdWw732ZNh4MehkF2gdjvtdmikkaIP9bFDDJOPlsvm7avrA==`.

## Peer and development only

`react` (optional peer of the `/client` entry; MIT), TypeScript, Biome and `@types/*` are not shipped in the packages.
