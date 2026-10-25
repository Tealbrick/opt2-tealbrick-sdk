// RM-1 (CONFORMANCE v0.1.63): `settings.modelRoles` validates; M-MR-1..5 each refuse their bad case with their code.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import type { Manifest, ManifestValidation } from "@opt2-tealbrick/spec/manifest";
import {
  activeModelRoles,
  declaredModelRoles,
  MODEL_ID_PATTERN,
  MODEL_PROVIDERS,
  MODEL_ROLE_ATTENTION,
  MODEL_ROLE_HINTS_MAX,
  MODEL_ROLES,
  MODEL_ROLES_CAP,
  PROVIDER_ID_PATTERN,
  settingsFromEnv,
  validateManifest,
} from "../src/index.ts";

/** the notes example with its `search` service rebuilt as a tb-exec service (build, not image) and two roles */
const base = (): any => {
  const m = structuredClone(example) as any;
  const svc = m.runtime.services[0];
  delete svc.image;
  svc.build = { context: ".", dockerfile: "Dockerfile.search" };
  m.settings.modelRoles = [
    { role: "reasoning", required: true, minPolicy: "zdr", usedBy: ["app", "search"] },
    { role: "embeddings", required: false, usedBy: ["search"], env: { provider: "EMB_PROVIDER", model: "EMB_MODEL", baseUrl: "EMB_URL", key: "EMB_KEY", dims: "EMB_DIMS" }, help: "Vector index", when: { summaries: true } },
  ];
  return m;
};

function mutate(fn: (m: any) => void): ManifestValidation {
  const m = base();
  fn(m);
  return validateManifest(m);
}

function expectIssue(r: ManifestValidation, rule: string, code: string, path?: string): void {
  assert.equal(r.ok, false, `expected ${code}, got ok`);
  if (r.ok) return;
  const hit = r.errors.find((e) => e.rule === rule && e.code === code && (path === undefined || e.path === path));
  assert.ok(hit, `expected ${rule}/${code}${path ? ` at ${path}` : ""}; got ${JSON.stringify(r.errors)}`);
}

const refuses = (rule: string, code: string, fn: (m: any) => void, path?: string) => () => expectIssue(mutate(fn), rule, code, path);

describe("RM-1 settings.modelRoles (MANIFEST §7.1)", () => {
  test("a valid manifest with model roles passes", () => {
    const r = validateManifest(base());
    assert.equal(r.ok, true, JSON.stringify(r.ok ? [] : r.errors));
  });
  test("a manifest without model roles is unchanged", () => {
    assert.equal(validateManifest(structuredClone(example)).ok, true);
  });
  test("all eight roles and all three policies are accepted", () => {
    const r = mutate((m) => {
      const roles = ["embeddings", "rerank", "reasoning", "utility", "dreaming", "summarize", "vision", "transcribe"];
      m.settings.modelRoles = roles.map((role, i) => ({ role, required: false, minPolicy: ["local", "zdr", "standard"][i % 3], usedBy: ["app"] }));
    });
    assert.equal(r.ok, true, JSON.stringify(r.ok ? [] : r.errors));
  });
  test("a model role `when` counts as a use of its setting (M-ST-7)", () => {
    const r = mutate((m) => {
      delete m.skills;
      m.settings.steps[0].fields.push({ key: "use_vision", type: "boolean", label: "Vision" });
      m.settings.modelRoles.push({ role: "vision", required: false, usedBy: ["app"], when: { use_vision: true } });
    });
    assert.equal(r.ok, true, JSON.stringify(r.ok ? [] : r.errors));
  });

  test("M-MR-1 role not in MODEL_ROLES", refuses("M-MR-1", "model_role_invalid", (m) => (m.settings.modelRoles[0].role = "chat"), "/settings/modelRoles/0/role"));
  test("M-MR-1 role declared twice", refuses("M-MR-1", "model_role_invalid", (m) => m.settings.modelRoles.push({ role: "reasoning", required: false, usedBy: ["app"] }), "/settings/modelRoles/2/role"));
  test("M-MR-2 minPolicy not in DATA_POLICIES", refuses("M-MR-2", "model_role_invalid", (m) => (m.settings.modelRoles[0].minPolicy = "strict"), "/settings/modelRoles/0/minPolicy"));
  test("M-MR-3 usedBy names an undeclared service", refuses("M-MR-3", "model_role_invalid", (m) => (m.settings.modelRoles[0].usedBy = ["app", "ghost"]), "/settings/modelRoles/0/usedBy"));
  test("M-MR-3 usedBy item that is no id", refuses("M-MR-3", "model_role_invalid", (m) => (m.settings.modelRoles[0].usedBy = ["Not An Id"])));
  test("M-MR-3 usedBy empty", refuses("M-MR-3", "model_role_invalid", (m) => (m.settings.modelRoles[0].usedBy = [])));
  test(
    "M-MR-4 env with `app` in usedBy",
    refuses("M-MR-4", "model_role_invalid", (m) => (m.settings.modelRoles[1].usedBy = ["app", "search"]), "/settings/modelRoles/1/env"),
  );
  test(
    "M-MR-4 env on a service that has an image, not build",
    refuses(
      "M-MR-4",
      "model_role_invalid",
      (m) => {
        const svc = m.runtime.services[0];
        delete svc.build;
        svc.image = "getmeili/meilisearch:v1.10.3@sha256:0000000000000000000000000000000000000000000000000000000000000000";
      },
      "/settings/modelRoles/1/env",
    ),
  );
  test(
    "M-MR-4 env name equals one of the service's runtime env names",
    refuses("M-MR-4", "model_role_invalid", (m) => (m.settings.modelRoles[1].env.model = "MEILI_ENV"), "/settings/modelRoles/1/env/model"),
  );
  test(
    "M-MR-4 env name equals a key the service uses",
    refuses(
      "M-MR-4",
      "model_role_invalid",
      (m) => {
        m.settings.keys.push({ name: "SEARCH_KEY", label: "Search", provider: "X", required: false, source: "account_default", usedBy: ["search"] });
        m.settings.modelRoles[1].env.key = "SEARCH_KEY";
      },
      "/settings/modelRoles/1/env/key",
    ),
  );
  test(
    "M-MR-4 env name used twice across two roles of one service",
    refuses(
      "M-MR-4",
      "model_role_invalid",
      (m) => {
        m.settings.modelRoles[0] = { role: "reasoning", required: false, usedBy: ["search"], env: { model: "EMB_MODEL" } };
      },
      "/settings/modelRoles/1/env/model",
    ),
  );
  test(
    "M-MR-4 env name used twice inside one role",
    refuses("M-MR-4", "model_role_invalid", (m) => (m.settings.modelRoles[1].env.dims = "EMB_KEY"), "/settings/modelRoles/1/env/dims"),
  );
  for (const name of ["HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "GRPC_PROXY", "PIP_PROXY", "SOCKS_PROXY", "GLOBAL_AGENT_HTTP_PROXY", "NODE_USE_ENV_PROXY", "NPM_CONFIG_PROXY", "NPM_CONFIG_HTTPS_PROXY", "NODE_OPTIONS", "NODE_EXTRA_CA_CERTS", "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "DYLD_INSERT_LIBRARIES"]) {
    test(`M-MR-4 role env name ${name} (proxy, loader, search path) is refused`, refuses("M-MR-4", "model_role_invalid", (m) => (m.settings.modelRoles[1].env.provider = name), "/settings/modelRoles/1/env/provider"));
  }
  test("M-MR-4 ordinary role env names still pass (MODEL, KEY, URL, PROXYLESS_MODE)", () => {
    const r = mutate((m) => (m.settings.modelRoles[1].env = { provider: "KN_PROVIDER", model: "KN_MODEL", baseUrl: "KN_BASE_URL", key: "KN_API_KEY", dims: "PROXYLESS_DIMS" }));
    assert.equal(r.ok, true, JSON.stringify(r.ok ? [] : r.errors));
  });
  test("M-MR-4 the same env name on two different services is fine", () => {
    const r = mutate((m) => {
      const other = structuredClone(m.runtime.services[0]);
      other.id = "deep";
      other.volumes[0].id = "deep_data";
      delete other.when;
      m.runtime.services.push(other);
      m.settings.modelRoles[1].usedBy = ["search", "deep"];
    });
    assert.equal(r.ok, true, JSON.stringify(r.ok ? [] : r.errors));
  });
  test("M-MR-4 env name with a TB_ prefix is refused by the schema", () => {
    const r = mutate((m) => (m.settings.modelRoles[1].env.key = "TB_KEY"));
    assert.equal(r.ok, false);
  });
  test("M-MR-5 when names an undeclared setting", refuses("M-MR-5", "condition_invalid", (m) => (m.settings.modelRoles[0].when = { ghost: true }), "/settings/modelRoles/0/when/ghost"));
  test("M-MR-5 when value not valid for the setting", refuses("M-MR-5", "condition_invalid", (m) => (m.settings.modelRoles[1].when = { summaries: "yes" })));
  test("M-MR-5 when on a non-enum, non-boolean setting", refuses("M-MR-5", "condition_invalid", (m) => (m.settings.modelRoles[1].when = { summary_model: "x" })));
});

describe("mirror constants of spec 0.1.63", () => {
  test("provider catalog, id patterns, hints limit, cap", () => {
    const zdr = (id: string) => MODEL_PROVIDERS.find((p) => p.id === id)?.zdrOffered;
    assert.equal(zdr("litellm"), true);
    assert.equal(zdr("openai-compatible"), true);
    assert.equal(zdr("ollama"), false);
    assert.equal(MODEL_PROVIDERS.length, 14);
    assert.ok(MODEL_PROVIDERS.every((p) => new RegExp(PROVIDER_ID_PATTERN).test(p.id) && p.roles.every((r) => MODEL_ROLES.includes(r))));
    assert.ok(new RegExp(MODEL_ID_PATTERN).test("gpt-5.1") && new RegExp(MODEL_ID_PATTERN).test("nomic-embed-text:latest"));
    assert.ok(!new RegExp(MODEL_ID_PATTERN).test("two words") && !new RegExp(MODEL_ID_PATTERN).test("https://x"));
    assert.equal(MODEL_ROLE_HINTS_MAX, 8);
    assert.equal(MODEL_ROLES_CAP, "model_roles");
    assert.deepEqual(MODEL_ROLE_ATTENTION, ["model_role_missing", "model_role_optional", "embeddings_changed"]);
  });
});

describe("declaredModelRoles / activeModelRoles", () => {
  const m = base() as Manifest;
  test("declaredModelRoles lists the entries, or none", () => {
    assert.deepEqual(declaredModelRoles(m).map((r) => r.role), ["reasoning", "embeddings"]);
    assert.deepEqual(declaredModelRoles(example as unknown as Manifest), []);
  });
  test("activeModelRoles evaluates `when` like keys and filters by consumer", () => {
    const off = settingsFromEnv(m, {});
    assert.deepEqual(activeModelRoles(m, off).map((r) => r.role), ["reasoning"]);
    const withSummaries = { ...off, summaries: true };
    assert.deepEqual(activeModelRoles(m, withSummaries).map((r) => r.role), ["reasoning", "embeddings"]);
    assert.deepEqual(activeModelRoles(m, withSummaries, "app").map((r) => r.role), ["reasoning"]);
    assert.deepEqual(activeModelRoles(m, withSummaries, "search").map((r) => r.role), ["reasoning", "embeddings"]);
    assert.deepEqual(activeModelRoles(m, withSummaries, "nobody"), []);
  });
  test("an unset setting matches nothing, a manifest without roles gives none", () => {
    assert.deepEqual(activeModelRoles(m, {}).map((r) => r.role), ["reasoning"]);
    assert.deepEqual(activeModelRoles(example as unknown as Manifest, {}), []);
  });
});

// QA-SPEC42-3: the spec's own invalid cases (copied from specs#42 until the spec is released), every one must be refused.
interface InvalidCase {
  rule: string;
  code: string;
  what: string;
  services?: { id: string; build: boolean }[];
  modelRoles: unknown[];
}
const cases = (JSON.parse(readFileSync(new URL("./vectors/model-roles.invalid.json", import.meta.url), "utf8")) as { cases: InvalidCase[] }).cases;

describe("RM-1 spec fixture model-roles.invalid.json (specs#42)", () => {
  test("the fixture has a case for each of M-MR-1..5", () => {
    assert.deepEqual([...new Set(cases.map((c) => c.rule))].sort(), ["M-MR-1", "M-MR-2", "M-MR-3", "M-MR-4", "M-MR-5"]);
  });
  for (const c of cases) {
    test(`${c.rule} ${c.what} → ${c.code}`, () => {
      const m = structuredClone(example) as any;
      const template = m.runtime.services[0];
      for (const s of c.services ?? []) {
        // `build: true/false` = a service with / without a build (the tb-exec entrypoint): the real shapes
        const svc = structuredClone(template);
        svc.id = s.id;
        svc.volumes[0].id = `${s.id}_data`;
        delete svc.when;
        if (s.build) {
          delete svc.image;
          svc.build = { context: ".", dockerfile: `Dockerfile.${s.id}` };
        }
        m.runtime.services.push(svc);
      }
      m.settings = { ...m.settings, modelRoles: structuredClone(c.modelRoles) };
      expectIssue(validateManifest(m), c.rule, c.code);
    });
  }
});
