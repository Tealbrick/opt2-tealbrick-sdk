// SPEC-GAP: this package pins spec 0.1.94 (the Paddle webhook row, sdk#72) while @opt2-tealbrick/manifest still pins
// 0.1.78. The two `Manifest` types differ only in `contracts` (spec 0.1.83 adds "documents/1"), so a manifest typed by
// the newer spec is not assignable to the primitives (`manifestDigest`, `withStandardOps`, ...). The suite therefore
// types manifests the way the manifest package does. Delete this file, and import `Manifest` from
// `@opt2-tealbrick/spec/manifest` again, once the manifest package re-pins a spec >= this package's pin.
import type { manifestDigest } from "@opt2-tealbrick/manifest";

export type Manifest = Parameters<typeof manifestDigest>[0];
