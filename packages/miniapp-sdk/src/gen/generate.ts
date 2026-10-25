// `tb-gen` generators by kind, `all`, and the drift check (CONFORMANCE M4): generated output equals the manifest.
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { genDocs } from "./docs.ts";
import { genKit } from "./kit.ts";
import type { GenFiles, LoadedManifest } from "./load.ts";
import { genOpenApi } from "./openapi.ts";
import { genRailway, type RailwayOptions } from "./railway.ts";

export const GEN_KINDS = ["openapi", "kit", "docs", "railway"] as const;
export type GenKind = (typeof GEN_KINDS)[number];

/** `packageName` (C338): publish the kit under the app's own package name (e.g. `@tealbrick/knowledge`). */
export type GenOptions = RailwayOptions & { packageName?: string };

export function generate(kind: GenKind, lm: LoadedManifest, opts: GenOptions = {}): GenFiles {
  switch (kind) {
    case "openapi":
      return genOpenApi(lm);
    case "kit":
      return genKit(lm, opts.packageName !== undefined ? { packageName: opts.packageName } : {});
    case "docs":
      return genDocs(lm);
    case "railway":
      return genRailway(lm, opts);
  }
}

/** Every kind, paths prefixed with `<kind>/` (the layout of a `gen/` directory). */
export function generateAll(lm: LoadedManifest, opts: GenOptions = {}): GenFiles {
  const all: GenFiles = new Map();
  for (const kind of GEN_KINDS) for (const [rel, content] of generate(kind, lm, opts)) all.set(`${kind}/${rel}`, content);
  return all;
}

/** Build output and packed tarballs (`tb-gen kit --build`) are not generated sources and are not compared. */
const NOT_COMPARED_DIRS = new Set(["dist", "node_modules"]);

function listFiles(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, e.name);
    if (e.isDirectory()) {
      if (!NOT_COMPARED_DIRS.has(e.name)) out.push(...listFiles(path, base));
    } else if (!e.name.endsWith(".tgz")) out.push(path.slice(base.length + 1).split("\\").join("/"));
  }
  return out;
}

export interface DriftReport {
  /** False when `genDir` does not exist (nothing committed: nothing to drift). */
  present: boolean;
  /** Kinds whose directory exists under `genDir` and were compared. */
  compared: GenKind[];
  /** `missing <path>`, `extra <path>`, `differs <path>`; empty = no drift. */
  differences: string[];
}

/** Regenerates every kind in memory and compares it with the committed `genDir` (only kinds present there). */
export function checkDrift(lm: LoadedManifest, genDir: string, opts: GenOptions = {}): DriftReport {
  if (!existsSync(genDir) || !statSync(genDir).isDirectory()) return { present: false, compared: [], differences: [] };
  const compared: GenKind[] = [];
  const differences: string[] = [];
  for (const kind of GEN_KINDS) {
    const dir = join(genDir, kind);
    if (!existsSync(dir)) continue;
    compared.push(kind);
    const want = generate(kind, lm, opts);
    const have = new Set(listFiles(dir));
    for (const [rel, content] of [...want].sort(([a], [b]) => (a < b ? -1 : 1))) {
      if (!have.has(rel)) differences.push(`missing ${kind}/${rel}`);
      else if (readFileSync(join(dir, rel), "utf8") !== content) differences.push(`differs ${kind}/${rel}`);
      have.delete(rel);
    }
    for (const rel of [...have].sort()) differences.push(`extra ${kind}/${rel}`);
  }
  return { present: true, compared, differences };
}
