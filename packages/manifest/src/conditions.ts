// ONE evaluation of manifest `when` conditions (MANIFEST §settings: `{ "<setting key>": value | [values] }`, all
// entries must match; array = one of). Used by Core (keyRequirements, deploy recipe, services, skills), the bridge
// (serviceKeys in the claim answer) and the SDK incl. tb-exec — Coordinator request after the live probe (keys whose
// `when` is false are not needed).
import type { Condition, ConditionValue, KeyRequirement, Manifest, SettingField } from "@opt2-tealbrick/spec/manifest";
import { declaredModelRoles, type ModelRoleRequirement } from "./model-roles.ts";

export type SettingValues = Record<string, ConditionValue | undefined>;

function fields(manifest: Manifest): SettingField[] {
  return (manifest.settings?.steps ?? []).flatMap((s) => s.fields);
}

/** Setting values with manifest defaults applied for keys the caller did not provide. Unknown keys are dropped. */
export function resolveSettings(manifest: Manifest, provided: SettingValues): SettingValues {
  const out: SettingValues = {};
  for (const f of fields(manifest)) {
    const v = provided[f.key];
    out[f.key] = v !== undefined ? v : f.default;
  }
  return out;
}

function coerce(f: SettingField, raw: string): ConditionValue | undefined {
  switch (f.type) {
    case "boolean":
      return raw === "true" ? true : raw === "false" ? false : undefined;
    case "integer":
    case "number": {
      const n = Number(raw);
      return raw.trim() !== "" && Number.isFinite(n) ? n : undefined;
    }
    default:
      return raw;
  }
}

/** Settings as an app or service sees them: from the env entries that carry a setting (`runtime.env[].setting`, C16 S6), then defaults. */
export function settingsFromEnv(manifest: Manifest, env: Record<string, string | undefined>): SettingValues {
  const byKey = new Map(fields(manifest).map((f) => [f.key, f]));
  const provided: SettingValues = {};
  for (const e of manifest.runtime.env ?? []) {
    if (!("setting" in e) || typeof e.setting !== "string") continue;
    const f = byKey.get(e.setting);
    const raw = env[e.name];
    if (f && raw !== undefined) provided[e.setting] = coerce(f, raw);
  }
  return resolveSettings(manifest, provided);
}

/** True when every entry of `when` matches the resolved settings (absent condition = true; an unset setting matches nothing). */
export function conditionHolds(when: Condition | undefined, settings: SettingValues): boolean {
  if (!when) return true;
  for (const [key, expected] of Object.entries(when)) {
    const actual = settings[key];
    if (actual === undefined) return false;
    const options = Array.isArray(expected) ? expected : [expected];
    if (!options.some((o) => o === actual)) return false;
  }
  return true;
}

/**
 * Key requirements in force for these settings, optionally only those a consumer (`"app"` or a service id) uses.
 * v0.1.30 (SPEC GAP, admin queue b, Knowledge lead): a key is in force when its own `when` holds AND, when it names a `step`,
 * that step's `when` holds too (MANIFEST §7: a step whose `when` is false is skipped, so the keys it shows do not apply).
 * Stored setting values (defaults included) are unchanged; only which keys count. One function for Core missingKeys, the
 * GUI and the bridge (L1). A key that must stay in force while its step is skipped belongs in no step (or in another step).
 */
export function activeKeyRequirements(manifest: Manifest, settings: SettingValues, usedBy?: string): KeyRequirement[] {
  const stepWhen = new Map((manifest.settings?.steps ?? []).map((s) => [s.id, s.when]));
  return (manifest.settings?.keys ?? []).filter(
    (k) => (usedBy === undefined || k.usedBy.includes(usedBy)) && conditionHolds(k.when, settings) && (k.step === undefined || conditionHolds(stepWhen.get(k.step), settings)),
  );
}

/**
 * Model roles in force for these settings (v0.1.63, MANIFEST §7.1), optionally only those a consumer (`"app"` or a service id)
 * uses. Same `when` evaluation as `activeKeyRequirements`; roles have no `step`. One function for Core's
 * `modelRoleRequirements`, the GUI, the bridge, the SDK readiness check and tb-exec.
 */
export function activeModelRoles(manifest: Manifest, settings: SettingValues, usedBy?: string): ModelRoleRequirement[] {
  return declaredModelRoles(manifest).filter((r) => (usedBy === undefined || r.usedBy.includes(usedBy)) && conditionHolds(r.when, settings));
}
