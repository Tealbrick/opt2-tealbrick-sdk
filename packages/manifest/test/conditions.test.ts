import assert from "node:assert/strict";
import { test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { activeKeyRequirements, conditionHolds, resolveSettings, settingsFromEnv } from "../src/index.ts";

const m = {
  runtime: { env: [{ name: "MODEL_PROVIDER", setting: "model_provider" }, { name: "RESEARCH", setting: "research" }, { name: "FIXED", value: "x" }] },
  settings: {
    steps: [
      {
        id: "engine",
        title: "Engine",
        fields: [
          { key: "model_provider", type: "enum", label: "Provider", default: "openai", choices: [] },
          { key: "research", type: "boolean", label: "Research", default: false },
          { key: "depth", type: "integer", label: "Depth" },
        ],
      },
    ],
    keys: [
      { name: "OPENAI_API_KEY", label: "OpenAI", provider: "OpenAI", required: true, source: "account_default", usedBy: ["engine"], when: { model_provider: "openai" } },
      { name: "ANTHROPIC_API_KEY", label: "Anthropic", provider: "Anthropic", required: true, source: "account_default", usedBy: ["engine"], when: { model_provider: "anthropic" } },
      { name: "GOOGLE_API_KEY", label: "Google", provider: "Google", required: true, source: "account_default", usedBy: ["engine", "app"], when: { model_provider: ["google", "anthropic"] } },
      { name: "NOTEBOOK_KEY", label: "Notebook", provider: "X", required: false, source: "app_own", usedBy: ["app"], when: { research: true } },
      { name: "ALWAYS", label: "Always", provider: "X", required: true, source: "account_default", usedBy: ["app"] },
    ],
  },
} as unknown as Manifest;

test("conditionHolds: AND over entries, array = one of, unset matches nothing, absent = true", () => {
  assert.equal(conditionHolds(undefined, {}), true);
  assert.equal(conditionHolds({ a: "x" }, { a: "x" }), true);
  assert.equal(conditionHolds({ a: ["x", "y"] }, { a: "y" }), true);
  assert.equal(conditionHolds({ a: "x", b: true }, { a: "x", b: false }), false);
  assert.equal(conditionHolds({ a: "x" }, {}), false);
  assert.equal(conditionHolds({ n: 2 }, { n: "2" }), false); // typed: no string/number coercion here
});

test("resolveSettings applies manifest defaults and drops unknown keys", () => {
  assert.deepEqual(resolveSettings(m, { research: true, other: "z" }), { model_provider: "openai", research: true, depth: undefined });
});

test("settingsFromEnv coerces by field type and falls back to defaults", () => {
  assert.deepEqual(settingsFromEnv(m, { MODEL_PROVIDER: "anthropic", RESEARCH: "true" }), { model_provider: "anthropic", research: true, depth: undefined });
  assert.deepEqual(settingsFromEnv(m, { RESEARCH: "yes" }), { model_provider: "openai", research: false, depth: undefined });
});

test("activeKeyRequirements: live-probe case — provider openai asks only for the OpenAI key (service) ", () => {
  const s = settingsFromEnv(m, { MODEL_PROVIDER: "openai" });
  assert.deepEqual(
    activeKeyRequirements(m, s, "engine").map((k) => k.name),
    ["OPENAI_API_KEY"],
  );
  assert.deepEqual(
    activeKeyRequirements(m, settingsFromEnv(m, { MODEL_PROVIDER: "anthropic", RESEARCH: "true" }), "app").map((k) => k.name),
    ["GOOGLE_API_KEY", "NOTEBOOK_KEY", "ALWAYS"],
  );
  assert.equal(activeKeyRequirements(m, resolveSettings(m, {})).length, 2);
});

test("activeKeyRequirements (v0.1.30, admin queue b): a key in a skipped step is not in force — Knowledge research case", () => {
  const k = {
    runtime: { env: [{ name: "MODE", setting: "mode" }] },
    settings: {
      steps: [
        { id: "basics", title: "Basics", fields: [{ key: "mode", type: "enum", label: "Mode", default: "notes", choices: [] }] },
        { id: "research", title: "Research", when: { mode: "research" }, fields: [] },
      ],
      keys: [
        { name: "RESEARCH_KEY", label: "Research", provider: "X", required: true, source: "account_default", usedBy: ["app"], step: "research" },
        { name: "OWN_WHEN", label: "Own when", provider: "X", required: true, source: "account_default", usedBy: ["app"], step: "research", when: { mode: ["research", "notes"] } },
        { name: "NO_STEP", label: "No step", provider: "X", required: true, source: "account_default", usedBy: ["app"] },
        { name: "BASIC_STEP", label: "Basic step", provider: "X", required: true, source: "account_default", usedBy: ["app"], step: "basics" },
      ],
    },
  } as unknown as Manifest;
  const names = (mode: string) => activeKeyRequirements(k, settingsFromEnv(k, { MODE: mode })).map((x) => x.name);
  assert.deepEqual(names("notes"), ["NO_STEP", "BASIC_STEP"], "mode ≠ research: the research step is skipped, its keys are not in force (also one whose own when holds)");
  assert.deepEqual(names("research"), ["RESEARCH_KEY", "OWN_WHEN", "NO_STEP", "BASIC_STEP"]);
  // stored defaults are unchanged: resolveSettings still returns every field
  assert.deepEqual(resolveSettings(k, {}), { mode: "notes" });
});
