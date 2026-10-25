// Dynamic tool names, variants and hold-family sets (spec 0.1.74, C354a; MANIFEST §5.3, SDK-API v0.1.74).
// spec 0.1.74, copied until the spec pin moves: the regexes and helpers below are copies of `@opt2-tealbrick/spec/manifest`
// 0.1.74 (`DYNAMIC_CATALOG_NAME_RE`, `DYNAMIC_TOOL_NAME_RE`, `DYNAMIC_VARIANT_RE`, `dynamicVariantBase`, `holdFamilySet`,
// `variantNarrowerOrEqual`). The packages pin spec 0.1.57, which has none of them; when the pin moves, re-export the spec's.
import type { CrudAction, Effect, HoldFamily } from "@opt2-tealbrick/spec/manifest";
import { EFFECTS } from "./vocab.ts";

/** A catalog entry `name`: 2–48 chars, no `__`, no trailing `_` (`__` is reserved for variants such as `<name>__first_contact`). */
export const DYNAMIC_CATALOG_NAME_RE = /^(?!.*__)[a-z][a-z0-9_]{0,46}[a-z0-9]$/;
/** A requested or resolved dynamic tool: a catalog name, or a variant `<catalog name>__<suffix>` (≤ 63 chars). */
export const DYNAMIC_TOOL_NAME_RE = /^[a-z][a-z0-9_]{1,62}$/;
/** A variant name: base (a catalog name) + `__` + a suffix that starts with a letter or digit. Group 1 = base, group 2 = suffix. */
export const DYNAMIC_VARIANT_RE = /^([a-z](?:[a-z0-9]|_(?!_))*[a-z0-9])__([a-z0-9][a-z0-9_]*)$/;

/** The hold-family fields of a resolution, a catalog entry or an effective op (`holdFamilies` is spec 0.1.74). */
export interface HoldFamilyFields {
  holdFamily?: HoldFamily;
  holdFamilies?: HoldFamily[];
}

/**
 * The base catalog name of a variant `<base>__<suffix>`, or null when `name` is not a valid variant (bad shape, the base fails
 * `DYNAMIC_CATALOG_NAME_RE`, or the whole name fails `DYNAMIC_TOOL_NAME_RE`). Split names only here.
 */
export function dynamicVariantBase(name: string): string | null {
  if (!DYNAMIC_TOOL_NAME_RE.test(name)) return null;
  const m = DYNAMIC_VARIANT_RE.exec(name);
  return m?.[1] && DYNAMIC_CATALOG_NAME_RE.test(m[1]) ? m[1] : null;
}

/**
 * The hold families of a resolution or op as a set: `holdFamilies` ∪ {`holdFamily`}, in that order (the decision records the
 * first held member). An EMPTY `holdFamilies` never means "no holds": it falls back to `holdFamily` like an absent one.
 */
export function holdFamilySet(r: HoldFamilyFields): Set<HoldFamily> {
  const set = new Set<HoldFamily>(Array.isArray(r.holdFamilies) ? r.holdFamilies : []);
  if (r.holdFamily) set.add(r.holdFamily);
  return set;
}

/**
 * "Never broader" for a variant against its base: crud ⊆ the base's crud, effect at or below the base's in `EFFECTS` order
 * (an effect outside EFFECTS on either side → false, fail closed), and hold families ⊇ the base's (a variant may add a hold,
 * never drops one).
 */
export function variantNarrowerOrEqual(variant: { crud: CrudAction[]; effect: Effect } & HoldFamilyFields, base: { crud: CrudAction[]; effect: Effect } & HoldFamilyFields): boolean {
  if (!variant.crud.every((c) => base.crud.includes(c))) return false;
  const ve = EFFECTS.indexOf(variant.effect);
  const be = EFFECTS.indexOf(base.effect);
  if (ve < 0 || be < 0 || ve > be) return false;
  const v = holdFamilySet(variant);
  return [...holdFamilySet(base)].every((f) => v.has(f));
}
