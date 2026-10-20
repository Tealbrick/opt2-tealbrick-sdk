// Conformance 0.1.25 (spec 0.1.52, C283c): the harness-only way to simulate "an app update changes the crud of an access level".
// A black-box suite cannot ship a new manifest, so a row that needs the update RESTARTS the app (same data dir) with the env name
// below; the start module applies the change to its manifest before `defineApp` (create-tealbrick-miniapp's conformance.start.ts
// does, from template 0.1.19; `applyLevelCrud` is the helper). A start module that ignores it is detected by the manifest digest the
// app serves (GET /tb/v1/health). From conformance 0.1.26 the rows FAIL for an app that reports SDK >= 0.1.36 or declares proofClaims ["bd"]
// (not_applicable only below that). Like TBCONF_PORT it is not a TB_* name and the SDK never reads it.

import type { CrudAction, Manifest } from "@opt2-tealbrick/spec/manifest";

export const LEVEL_CRUD_ENV = "TBCONF_LEVEL_CRUD";

/** One change: access level `level` of scope type `type` now has exactly `crud`. */
export interface LevelCrudChange {
  type: string;
  level: string;
  crud: CrudAction[];
}

const CRUD: readonly string[] = ["read", "create", "update", "delete"];

/** The changes in the env value (JSON array); [] when absent, not JSON or malformed (a start module must never throw on it). */
export function parseLevelCrud(value: string | undefined): LevelCrudChange[] {
  if (!value) return [];
  try {
    const v: unknown = JSON.parse(value);
    if (!Array.isArray(v)) return [];
    return v.filter(
      (c): c is LevelCrudChange =>
        !!c && typeof c === "object" && typeof c.type === "string" && typeof c.level === "string" && Array.isArray(c.crud) && c.crud.length > 0 && c.crud.every((x: unknown) => typeof x === "string" && CRUD.includes(x)),
    );
  } catch {
    return [];
  }
}

/** A deep copy of `manifest` with the changes applied (the input is not touched); changes naming no such level are ignored. */
export function applyLevelCrud<M extends Manifest>(manifest: M, changes: readonly LevelCrudChange[]): M {
  const out = structuredClone(manifest);
  for (const c of changes) {
    const level = out.scopes?.find((s) => s.type === c.type)?.access.find((a) => a.id === c.level);
    if (level) level.crud = [...c.crud];
  }
  return out;
}
