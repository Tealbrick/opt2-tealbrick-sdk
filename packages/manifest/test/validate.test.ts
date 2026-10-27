import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { after, describe, test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import type { Manifest, ManifestValidation } from "@opt2-tealbrick/spec/manifest";
import { digest } from "../src/jcs.ts";
import { withStandardOps } from "../src/ops.ts";
import {
  manifestDigest,
  validateAgainstSchema,
  validateAppFiles,
  validateCompanions,
  validateInput,
  validateManifest,
} from "../src/validate.ts";

const base = (): any => structuredClone(example);

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

describe("validateManifest: example and schema", () => {
  test("the spec example manifest validates and returns its digest", () => {
    const r = validateManifest(base());
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
    if (r.ok) {
      assert.equal(r.manifest.id, "notes");
      assert.equal(r.digest, digest(example as any));
      assert.match(r.digest, /^sha256:[a-f0-9]{64}$/);
    }
  });
  test("schema: unknown property → schema_invalid with pointer", refuses("schema", "schema_invalid", (m) => (m.extra = 1), "/extra"));
  test("schema: missing required → schema_invalid", refuses("schema", "schema_invalid", (m) => delete m.backups, "/backups"));
  test("schema: wrong schema version", refuses("schema", "schema_invalid", (m) => (m.schema = "tealbrick.miniapp/1")));
  test("schema: non-object input", () => expectIssue(validateManifest("nope"), "schema", "schema_invalid"));
  test(
    "size > 256 KiB JCS → manifest_too_large",
    refuses("M-DOC-0", "manifest_too_large", (m) => (m.operations[0].input.description = "x".repeat(270_000))),
  );
  test("a valid search-mode dynamic op passes", () => {
    const r = mutate((m) =>
      m.operations.push({
        id: "tools",
        title: "Third-party tools",
        description: "Search and call tools.",
        crud: ["read"],
        effect: "read",
        scopeType: "notebook",
        idempotency: "supported",
        receipt: false,
        audience: "agent",
        dynamic: { mode: "search", crudCeiling: ["read", "create", "update", "delete"], effectCeiling: "money" },
      }),
    );
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
});

describe("M-DOC", () => {
  test("M-DOC-1 PEM", refuses("M-DOC-1", "secret_material", (m) => (m.description = "-----BEGIN PRIVATE KEY----- abc"), "/description"));
  test("M-DOC-1 JWS", refuses("M-DOC-1", "secret_material", (m) => (m.description = "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ4In0.c2ln")));
  test("M-DOC-1 opaque token", refuses("M-DOC-1", "secret_material", (m) => (m.description = `tbr_${"A".repeat(43)}`)));
  test("M-DOC-2 URL in description", refuses("M-DOC-2", "url_not_allowed", (m) => (m.description = "see https://x.example"), "/description"));
  test("M-DOC-2 URL inside an operation schema is allowed", () => {
    const r = mutate((m) => (m.operations[0].input.description = "see https://x.example"));
    assert.equal(r.ok, true);
  });
  test("hostile strings are scanned in linear time", () => {
    const t0 = performance.now();
    const r = mutate((m) => {
      m.description = "eyJ".repeat(1300);
      m.operations[0].input.description = "a:".repeat(100_000);
    });
    assert.equal(r.ok, true);
    assert.ok(performance.now() - t0 < 2000);
  });
  test(
    "M-DOC-3 workspace id",
    refuses("M-DOC-3", "instance_id_in_manifest", (m) => (m.description = "for ws_01HZX5Y6Z7A8B9C0D1E2F3G4H5"), "/description"),
  );
});

describe("M-ID", () => {
  test("M-ID-1 NOASSERTION", refuses("M-ID-1", "license_invalid", (m) => (m.source.license = "NOASSERTION")));
  test("M-ID-1 unknown id", refuses("M-ID-1", "license_invalid", (m) => (m.source.license = "Foo-1.0")));
  test("M-ID-1 bad exception", refuses("M-ID-1", "license_invalid", (m) => (m.source.license = "GPL-2.0-only WITH MIT")));
  test("M-ID-1 compound expression accepted", () => {
    assert.equal(mutate((m) => (m.source.license = "MIT OR Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0")).ok, true);
  });
  test("M-ID-2 duplicate intent after trim/lower", refuses("M-ID-2", "intent_duplicate", (m) => m.discovery.intents.push(" Take Notes ")));
});

describe("M-RT", () => {
  test("M-RT-1 no backup volume", refuses("M-RT-1", "backup_volume", (m) => (m.runtime.volumes[1].purpose = "data")));
  test("M-RT-1 backup service volume", refuses("M-RT-1", "backup_volume", (m) => (m.runtime.services[0].volumes[0].purpose = "backup")));
  test("M-RT-2 volume id across containers", refuses("M-RT-2", "volume_conflict", (m) => (m.runtime.services[0].volumes[0].id = "data")));
  test("M-RT-2 nested mount", refuses("M-RT-2", "volume_conflict", (m) => (m.runtime.volumes[1].mountPath = "/data/backup")));
  test("M-RT-3 reserved id app", refuses("M-RT-3", "service_duplicate", (m) => (m.runtime.services[0].id = "app")));
  test("M-RT-3 duplicate id", refuses("M-RT-3", "service_duplicate", (m) => m.runtime.services.push(structuredClone(m.runtime.services[0]))));
  test("M-RT-4 undeclared setting", refuses("M-RT-4", "env_ref_invalid", (m) => (m.runtime.env[0].setting = "nope")));
  test("M-RT-4 undeclared service", refuses("M-RT-4", "env_ref_invalid", (m) => (m.runtime.env[2].value = "{{services.ghost.url}}")));
  test(
    "M-RT-4 env ref to a non-generate entry",
    refuses("M-RT-4", "env_ref_invalid", (m) => (m.runtime.env[3].value = "{{services.search.env.MEILI_ENV}}")),
  );
  test("M-RT-4 unknown template form", refuses("M-RT-4", "env_ref_invalid", (m) => (m.runtime.env[2].value = "{{workspace.name}}")));
  test("M-RT-4 duplicate env name", refuses("M-RT-4", "env_ref_invalid", (m) => (m.runtime.env[1].name = "NOTES_DEFAULT_FORMAT")));
  test("M-RT-5 secret-like literal", refuses("M-RT-5", "secret_env_literal", (m) => m.runtime.env.push({ name: "MY_API_KEY", value: "x" })));
  test(
    "M-RT-5 env equals a key name",
    refuses("M-RT-5", "secret_env_literal", (m) => m.runtime.env.push({ name: "OPENAI_API_KEY", generate: "secret" })),
  );
  test("M-RT-6 key consumer uses image", refuses("M-RT-6", "wrapper_required", (m) => (m.settings.keys[0].usedBy = ["app", "search"])));
  test(
    "M-RT-6 backup on image service",
    refuses("M-RT-6", "wrapper_required", (m) => (m.runtime.services[0].backup = { dump: ["d"], restore: ["r"], extension: "dump" })),
  );
  test(
    "M-RT-7 helper port equals service port",
    refuses("M-RT-7", "helper_port", (m) => {
      const s = m.runtime.services[0];
      delete s.image;
      s.build = { context: ".", dockerfile: "search/Dockerfile" };
      s.helper = { port: 7700, paths: ["/helper"] };
    }),
  );
  test("M-RT-8 service when on a string setting", refuses("M-RT-8", "condition_invalid", (m) => (m.runtime.services[0].when = { summary_model: "x" })));
});

describe("M-OP", () => {
  test("M-OP-1 duplicate id", refuses("M-OP-1", "operation_duplicate", (m) => m.operations.push(structuredClone(m.operations[1]))));
  test(
    "M-OP-1 tool name > 64",
    refuses("M-OP-1", "tool_name_too_long", (m) => {
      m.id = "abcdefghijklmnopqrstuvwxyzabcdef"; // 32 chars
      m.operations[1].id = `n${"a".repeat(38)}`; // 39 chars → 73
    }),
  );
  test(
    "M-OP-1 dynamic _search name > 64",
    refuses("M-OP-1", "tool_name_too_long", (m) => {
      m.id = "abcdefghijklmnopqrstuvwxyz"; // 26 + 2 + 30 = 58, + "_search" = 65
      m.operations.push({
        id: `t${"a".repeat(29)}`,
        title: "T",
        description: "D",
        crud: ["read"],
        effect: "read",
        idempotency: "supported",
        receipt: false,
        audience: "agent",
        dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" },
      });
    }),
  );
  test("M-OP-2 read crud with write effect", refuses("M-OP-2", "effect_crud_mismatch", (m) => (m.operations[1].effect = "write")));
  test("M-OP-3 delete without destructive", refuses("M-OP-3", "effect_crud_mismatch", (m) => (m.operations[3].crud = ["update", "delete"])));
  test(
    "M-OP-3 destructive without delete",
    refuses("M-OP-3", "effect_crud_mismatch", (m) => Object.assign(m.operations[3], { effect: "destructive", holdFamily: "destructive" })),
  );
  test("M-OP-4 holdFamily on write", refuses("M-OP-4", "hold_family_invalid", (m) => (m.operations[0].holdFamily = "money")));
  test("M-OP-4 outward with money family", refuses("M-OP-4", "hold_family_invalid", (m) => (m.operations[5].holdFamily = "money")));
  test("M-OP-4 destructive without family", refuses("M-OP-4", "hold_family_invalid", (m) => delete m.operations[4].holdFamily));
  test("M-OP-5 create not required", refuses("M-OP-5", "idempotency_invalid", (m) => (m.operations[0].idempotency = "supported")));
  test("M-OP-5 read with required", refuses("M-OP-5", "idempotency_invalid", (m) => (m.operations[1].idempotency = "required")));
  test("M-OP-6 outward without receipt", refuses("M-OP-6", "receipt_required", (m) => (m.operations[5].receipt = false)));
  test("M-OP-7 undeclared scope", refuses("M-OP-7", "scope_ref_invalid", (m) => (m.operations[0].scopeType = "ghost")));
  test(
    "M-OP-7 scope does not cover crud",
    refuses("M-OP-7", "scope_ref_invalid", (m) => (m.scopes[0].access[1].crud = ["read", "create", "update"]), "/operations/4/scopeType"),
  );
  test("M-OP-8 agent op without output", refuses("M-OP-8", "io_schema_invalid", (m) => delete m.operations[1].output));
  test("M-OP-8 $id", refuses("M-OP-8", "io_schema_invalid", (m) => (m.operations[1].input.$id = "x")));
  test(
    "M-OP-8 remote $ref",
    refuses("M-OP-8", "io_schema_invalid", (m) => (m.operations[1].input.properties.id = { $ref: "https://x.example/s.json" })),
  );
  test(
    "M-OP-8 contentMediaType",
    refuses("M-OP-8", "io_schema_invalid", (m) => (m.operations[1].input.properties.id.contentMediaType = "image/png")),
  );
  test("M-OP-8 uncompilable schema", refuses("M-OP-8", "io_schema_invalid", (m) => (m.operations[1].input.properties.id.type = 5)));
  test("M-OP-8 a property named $id is data, not a keyword", () => {
    assert.equal(mutate((m) => (m.operations[1].input.properties.$id = { type: "string" })).ok, true);
  });
  test(
    "M-OP-9 person dynamic",
    refuses("M-OP-9", "person_dynamic", (m) => (m.operations[7].dynamic = { mode: "list", crudCeiling: ["read"], effectCeiling: "read" })),
  );
  const dyn = (extra: object) => ({
    id: "engine",
    title: "Engine",
    description: "Engine ops.",
    crud: ["read"],
    effect: "read",
    idempotency: "supported",
    receipt: false,
    audience: "agent",
    dynamic: { mode: "list", crudCeiling: ["read", "create"], effectCeiling: "write" },
    ...extra,
  });
  test("M-OP-10 dynamic with receipt", refuses("M-OP-10", "dynamic_invalid", (m) => m.operations.push(dyn({ receipt: true }))));
  test(
    "M-OP-10 dynamic with input",
    refuses("M-OP-10", "dynamic_invalid", (m) => m.operations.push(dyn({ input: { type: "object" } }))),
  );
  test(
    "M-OP-10 read ceiling with write effect ceiling",
    refuses("M-OP-10", "dynamic_invalid", (m) =>
      m.operations.push(dyn({ dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "write" } })),
    ),
  );
});

describe("M-SC", () => {
  test("M-SC-1 duplicate type", refuses("M-SC-1", "scope_duplicate", (m) => m.scopes.push(structuredClone(m.scopes[0]))));
  test("M-SC-1 duplicate access id", refuses("M-SC-1", "scope_duplicate", (m) => (m.scopes[0].access[1].id = "read")));
  test("M-SC-2 undeclared access", refuses("M-SC-2", "default_grant_invalid", (m) => (m.scopes[0].defaultGrants[0].access = "ghost")));
  test("M-SC-2 duplicate kind", refuses("M-SC-2", "default_grant_invalid", (m) => (m.scopes[0].defaultGrants[1].kind = "own")));
  test("M-SC-3 unknown variable", refuses("M-SC-3", "template_invalid", (m) => (m.scopes[0].summaryTemplate = "{count} {foo}")));
  test("M-SC-3 undeclared access id", refuses("M-SC-3", "template_invalid", (m) => (m.scopes[0].summaryTemplate = "{access.ghost}")));
  test("M-SC-3 unbalanced", refuses("M-SC-3", "template_invalid", (m) => (m.scopes[0].summaryTemplate = "{count")));
  test("M-SC-4 scopes without configurePath", refuses("M-SC-4", "configure_ui_required", (m) => delete m.ui.configurePath));
});

describe("M-ST", () => {
  test("M-ST-1 duplicate step", refuses("M-ST-1", "setting_duplicate", (m) => (m.settings.steps[1].id = "basics")));
  test(
    "M-ST-1 duplicate field across steps",
    refuses("M-ST-1", "setting_duplicate", (m) => m.settings.steps[1].fields.push({ key: "summaries", type: "boolean", label: "X" })),
  );
  test("M-ST-1 duplicate key name", refuses("M-ST-1", "setting_duplicate", (m) => m.settings.keys.push(structuredClone(m.settings.keys[0]))));
  test("M-ST-2 enum without choices", refuses("M-ST-2", "setting_invalid", (m) => delete m.settings.steps[0].fields[0].choices));
  test("M-ST-2 default on disabled choice", refuses("M-ST-2", "setting_invalid", (m) => (m.settings.steps[0].fields[1].default = "semantic")));
  test("M-ST-2 maxLength on boolean", refuses("M-ST-2", "setting_invalid", (m) => (m.settings.steps[0].fields[2].maxLength = 5)));
  test("M-ST-2 min on string", refuses("M-ST-2", "setting_invalid", (m) => (m.settings.steps[1].fields[0].min = 1)));
  test("M-ST-2 default longer than maxLength", refuses("M-ST-2", "setting_invalid", (m) => (m.settings.steps[1].fields[0].maxLength = 3)));
  test(
    "M-ST-2 url with default",
    refuses("M-ST-2", "setting_invalid", (m) => Object.assign(m.settings.steps[1].fields[0], { type: "url", default: "x" })),
  );
  test("M-ST-3 step when on string field", refuses("M-ST-3", "condition_invalid", (m) => (m.settings.steps[1].when = { summary_model: "x" })));
  test("M-ST-3 forward reference", refuses("M-ST-3", "condition_invalid", (m) => (m.settings.steps[0].fields[0].when = { summaries: true })));
  test("M-ST-3 invalid value", refuses("M-ST-3", "condition_invalid", (m) => (m.settings.steps[1].when = { summaries: "yes" })));
  test("M-ST-3 key when on unknown setting", refuses("M-ST-3", "condition_invalid", (m) => (m.settings.keys[0].when = { ghost: true })));
  test(
    "M-ST-4 secret-like setting key",
    refuses("M-ST-4", "secret_setting", (m) => m.settings.steps[0].fields.push({ key: "api_token", type: "string", label: "Token" })),
  );
  test("M-ST-5 usedBy unknown", refuses("M-ST-5", "key_invalid", (m) => (m.settings.keys[0].usedBy = ["ghost"])));
  test(
    "M-ST-5 app_own without configurePath",
    refuses("M-ST-5", "key_invalid", (m) => {
      m.settings.keys[0].source = "app_own";
      delete m.ui.configurePath;
    }),
  );
  test("M-ST-5 undeclared step", refuses("M-ST-5", "key_invalid", (m) => (m.settings.keys[0].step = "ghost")));
  test("M-ST-6 service gate mutable", refuses("M-ST-6", "setting_must_be_immutable", (m) => (m.settings.steps[0].fields[1].mutable = true)));
  test(
    "M-ST-7 unused setting (no skills)",
    refuses("M-ST-7", "setting_unused", (m) => {
      delete m.skills;
      m.settings.steps[0].fields.push({ key: "orphan", type: "boolean", label: "Orphan" });
    }),
  );
  test("M-ST-7 with skills declared is deferred to validateAppFiles", () => {
    const r = mutate((m) => m.settings.steps[0].fields.push({ key: "orphan", type: "boolean", label: "Orphan" }));
    assert.equal(r.ok, true);
  });
});

describe("M-HK, M-CP, M-UL, M-SK, M-HH, M-BK, M-AR, M-PR", () => {
  test("M-HK-1 duplicate hook", refuses("M-HK-1", "hook_duplicate", (m) => m.hooks.push(structuredClone(m.hooks[0]))));
  test("M-HK-2 star not alone", refuses("M-HK-2", "hook_match_invalid", (m) => (m.hooks[0].match.products = ["*", "notes"])));
  test("M-HK-3 operations with star", refuses("M-HK-3", "hook_match_invalid", (m) => (m.hooks[0].match.products = ["*"])));
  test("M-HK-3 own person op", refuses("M-HK-3", "hook_match_invalid", (m) => (m.hooks[0].match.operations = ["notebook_rename"])));
  test("M-HK-3 other product ops are left to Core", () => {
    assert.equal(mutate((m) => (m.hooks[0].match = { products: ["calendar"], operations: ["anything"] })).ok, true);
  });
  test("M-CP-1 own product", refuses("M-CP-1", "companion_invalid", (m) => (m.companions[0].product = "notes")));
  test("M-CP-1 duplicate", refuses("M-CP-1", "companion_invalid", (m) => m.companions.push(structuredClone(m.companions[0]))));
  test("M-CP-3 wildcard companion: tb.holds_pending / read is valid", () => {
    assert.equal(mutate((m) => m.companions.push({ product: "*", operations: ["tb.holds_pending"], crud: ["read"], purpose: "Show pending approvals of all apps" })).ok, true);
  });
  test("M-CP-3 wildcard on another op", refuses("M-CP-3", "companion_invalid", (m) => m.companions.push({ product: "*", operations: ["event_get"], crud: ["read"], purpose: "x" })));
  test("M-CP-3 wildcard with write crud", refuses("M-CP-3", "companion_invalid", (m) => m.companions.push({ product: "*", operations: ["tb.holds_pending"], crud: ["read", "update"], purpose: "x" })));
  test("M-CP-3 other standard ops are never companion ops", () => {
    // the schema refuses tb.holds_list already (only tb.holds_pending is allowed as a standard companion op)
    assert.equal(mutate((m) => (m.companions[0].operations = ["tb.holds_list"])).ok, false);
  });
  // v0.1.77 (C367, P3): the one extra standard op, tb.hold_status, in an entry for ONE product next to an op of that product
  test("M-CP-3 v0.1.77: tb.hold_status next to an op of the same product is valid (no crud needed)", () => {
    const r = mutate((m) => m.companions[0].operations.push("tb.hold_status"));
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("M-CP-3 v0.1.77: tb.hold_status first in the list is valid too", () => {
    assert.equal(mutate((m) => m.companions[0].operations.unshift("tb.hold_status")).ok, true);
  });
  test("M-CP-3 v0.1.77: tb.hold_status as the only op of an entry", refuses("M-CP-3", "companion_invalid", (m) => (m.companions[0].operations = ["tb.hold_status"]), "/companions/0/operations"));
  test("M-CP-3 v0.1.77: tb.hold_status next to only standard ops", refuses("M-CP-3", "companion_invalid", (m) => (m.companions[0].operations = ["tb.holds_pending", "tb.hold_status"]), "/companions/0/operations"));
  test("M-CP-3 v0.1.77: tb.hold_status in a wildcard entry", refuses("M-CP-3", "companion_invalid", (m) => m.companions.push({ product: "*", operations: ["tb.holds_pending", "tb.hold_status"], crud: ["read"], purpose: "x" })));
  test("M-CP-3 v0.1.77: tb.hold_status alone in a wildcard entry", refuses("M-CP-3", "companion_invalid", (m) => m.companions.push({ product: "*", operations: ["tb.hold_status"], crud: ["read"], purpose: "x" })));
  test("M-CP-3 v0.1.77: any other standard op next to a product op is still refused", () => {
    for (const std of ["tb.holds_decide", "tb.export", "tb.receipts_list", "tb.key_set"]) {
      const r = mutate((m) => m.companions[0].operations.push(std));
      assert.equal(r.ok, false, std);
    }
  });
  test("M-CP-3 v0.1.77: tb.hold_status does not change the holds_pending wildcard rule", () => {
    assert.equal(mutate((m) => m.companions.push({ product: "*", operations: ["tb.holds_pending"], crud: ["read"], purpose: "x" })).ok, true);
    expectIssue(mutate((m) => m.companions.push({ product: "*", operations: ["tb.holds_pending", "event_get"], crud: ["read"], purpose: "x" })), "M-CP-3", "companion_invalid");
  });
  test("M-UL-1 requires non-companion", refuses("M-UL-1", "unlock_invalid", (m) => (m.unlocks[0].requires = "ghost")));
  test("M-UL-1 provides unknown op", refuses("M-UL-1", "unlock_invalid", (m) => (m.unlocks[0].provides.operations = ["ghost"])));
  test("M-UL-1 provides unknown skill", refuses("M-UL-1", "unlock_invalid", (m) => (m.unlocks[0].provides.skills = ["ghost"])));
  test("M-UL-1 duplicate id", refuses("M-UL-1", "unlock_invalid", (m) => m.unlocks.push(structuredClone(m.unlocks[0]))));
  test("M-SK-1 duplicate id", refuses("M-SK-1", "skill_invalid", (m) => (m.skills[1].id = "notes-basics")));
  test("M-SK-1 duplicate file", refuses("M-SK-1", "skill_invalid", (m) => (m.skills[1].file = m.skills[0].file)));
  test("M-SK-1 bad when", refuses("M-SK-1", "skill_invalid", (m) => (m.skills[1].when = { summaries: "x" })));
  test("M-HH-1 duplicate harness", refuses("M-HH-1", "hint_duplicate", (m) => (m.harnessHints[1].harness = "generic")));
  test("M-BK-1 backup volume in files", refuses("M-BK-1", "backup_invalid", (m) => (m.backups.files[0].volume = "backup")));
  test("M-BK-1 cron out of range", refuses("M-BK-1", "backup_invalid", (m) => (m.backups.schedule = "61 3 * * *")));
  test("M-BK-1 cron steps and ranges accepted", () => assert.equal(mutate((m) => (m.backups.schedule = "*/15 1-5 * 1,6 0-6")).ok, true));
  test(
    "M-AR-1 wrong url prefix",
    refuses("M-AR-1", "artifact_invalid", (m) => (m.artifacts[0].url = "https://github.com/other/repo/releases/download/v1/x.tgz")),
  );
  test("M-AR-1 duplicate id", refuses("M-AR-1", "artifact_invalid", (m) => m.artifacts.push(structuredClone(m.artifacts[0]))));
  test("M-PR-1 duplicate route", refuses("M-PR-1", "route_duplicate", (m) => m.publicRoutes.push(structuredClone(m.publicRoutes[0]))));
});

describe("manifestDigest", () => {
  test("is the JCS sha256 and ignores key order", () => {
    const m = base() as Manifest;
    const reordered = Object.fromEntries(Object.entries(m).reverse()) as unknown as Manifest;
    assert.equal(manifestDigest(m), digest(example as any));
    assert.equal(manifestDigest(reordered), manifestDigest(m));
    assert.notEqual(manifestDigest({ ...m, version: "1.2.1" }), manifestDigest(m));
  });
});

describe("validateCompanions (M-CP-2)", () => {
  const target = (ops: object[]): Manifest => ({ ...base(), id: "calendar", operations: ops });
  const op = (extra: object) => ({
    id: "event_get",
    title: "Get event",
    description: "Get one event.",
    input: { type: "object" },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
    ...extra,
  });
  test("matching target passes", () => {
    const r = validateCompanions(base(), [target([op({})])]);
    assert.equal(r.ok, true);
  });
  test("v0.1.13: tb.holds_pending on a named target needs read; a wildcard is not checked against targets", () => {
    const m = base();
    m.companions = [{ product: "calendar", operations: ["tb.holds_pending"], crud: ["read"], purpose: "x" }, { product: "*", operations: ["tb.holds_pending"], crud: ["read"], purpose: "y" }];
    assert.equal(validateCompanions(m, [target([op({})])]).ok, true);
  });
  test("missing target op", () => {
    expectIssue(validateCompanions(base(), [target([op({ id: "other" })])]), "M-CP-2", "companion_op_invalid");
  });
  test("person-audience target op", () => {
    expectIssue(validateCompanions(base(), [target([op({ audience: "person" })])]), "M-CP-2", "companion_op_invalid");
  });
  test("op.crud not within companion crud", () => {
    expectIssue(
      validateCompanions(base(), [target([op({ crud: ["create"], effect: "write", idempotency: "required" })])]),
      "M-CP-2",
      "companion_op_invalid",
    );
  });
  test("companion crud wider than the ops need", () => {
    const m = base();
    m.companions[0].crud = ["read", "update"];
    expectIssue(validateCompanions(m, [target([op({})])]), "M-CP-2", "companion_op_invalid");
  });
  test("v0.1.77 M-CP-2 ignores tb.hold_status: it needs no crud and adds nothing to the union", () => {
    const m = base();
    m.companions[0].operations = ["event_get", "tb.hold_status"];
    assert.equal(validateCompanions(m, [target([op({})])]).ok, true);
    // the op list the target must provide is still checked, and crud stays tied to the product ops only
    m.companions[0].crud = ["read", "update"];
    expectIssue(validateCompanions(m, [target([op({})])]), "M-CP-2", "companion_op_invalid");
    const missing = base();
    missing.companions[0].operations = ["other", "tb.hold_status"];
    expectIssue(validateCompanions(missing, [target([op({})])]), "M-CP-2", "companion_op_invalid", "/companions/0/operations");
  });
  test("targets not supplied are not checked", () => assert.equal(validateCompanions(base(), []).ok, true));

  describe("v0.1.79 (C370a): a listed dynamic op reaches its crudCeiling", () => {
    const dyn = (ceiling: string[], id = "tools") =>
      op({
        id,
        title: "Tools",
        description: "Search tools.",
        input: undefined,
        output: undefined,
        idempotency: "supported",
        dynamic: { mode: "search", crudCeiling: ceiling, effectCeiling: ceiling.length === 1 ? "read" : "money" },
      });
    const entry = (operations: string[], crud: string[]): Manifest => {
      const m = base();
      m.companions = [{ product: "calendar", operations, crud, purpose: "x" }];
      return m;
    };
    const all = ["read", "create", "update", "delete"];
    test("crud up to the ceiling is valid, including the whole ceiling", () => {
      const t = target([dyn(all)]);
      assert.equal(validateCompanions(entry(["tools"], ["read", "create", "update"]), [t]).ok, true);
      assert.equal(validateCompanions(entry(["tools"], all), [t]).ok, true);
    });
    test("crud beyond the ceiling is refused", () => {
      const t = target([dyn(["read", "create"])]);
      expectIssue(validateCompanions(entry(["tools"], ["read", "create", "update"]), [t]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
    });
    test("read-only ceiling gives no write crud", () => {
      expectIssue(validateCompanions(entry(["tools"], ["read", "create"]), [target([dyn(["read"])])]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
    });
    test("op.crud must still be within the entry crud", () => {
      expectIssue(validateCompanions(entry(["tools"], ["create"]), [target([dyn(all)])]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
    });
    test("a static op cannot widen the entry; a dynamic op listed next to it supplies the ceiling", () => {
      const statics = target([op({ id: "accounts_list" })]);
      expectIssue(validateCompanions(entry(["accounts_list"], ["read", "create"]), [statics]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
      const both = target([op({ id: "accounts_list" }), dyn(all)]);
      assert.equal(validateCompanions(entry(["accounts_list", "tools"], ["read", "create", "update"]), [both]).ok, true);
    });
    test("an unlisted dynamic op adds nothing", () => {
      const both = target([op({ id: "accounts_list" }), dyn(all)]);
      expectIssue(validateCompanions(entry(["accounts_list"], ["read", "create"]), [both]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
    });
    test("tb.hold_status and tb.holds_pending behave as before next to a dynamic op", () => {
      const t = target([dyn(all)]);
      assert.equal(validateCompanions(entry(["tools", "tb.hold_status"], ["read", "create"]), [t]).ok, true);
      // tb.hold_status adds nothing: with only a static read op it still cannot justify create
      expectIssue(validateCompanions(entry(["event_get", "tb.hold_status"], ["read", "create"]), [target([op({})])]), "M-CP-2", "companion_op_invalid");
      assert.equal(validateCompanions(entry(["tools", "tb.holds_pending"], ["read", "update"]), [t]).ok, true);
      expectIssue(validateCompanions(entry(["tb.holds_pending"], ["update"]), [t]), "M-CP-2", "companion_op_invalid", "/companions/0/crud");
    });
  });
});

describe("validateInput", () => {
  const ops = withStandardOps(base());
  const byId = (id: string) => {
    const o = ops.find((x) => x.id === id);
    assert.ok(o);
    return o;
  };
  test("valid manifest op input", () => {
    assert.deepEqual(validateInput(byId("note_create"), { notebook: "n", title: "t", body: "b" }), { ok: true });
  });
  test("missing required → input_invalid with pointer", () => {
    const r = validateInput(byId("note_create"), { notebook: "n", title: "t" });
    assert.equal(r.ok, false);
    if (!r.ok) {
      assert.equal(r.code, "input_invalid");
      assert.ok(r.errors.some((e) => e.path === "/body"));
    }
  });
  test("additional property refused by a closed schema", () => {
    assert.equal(validateInput(byId("note_create"), { notebook: "n", title: "t", body: "b", x: 1 }).ok, false);
  });
  test("format is an annotation (2020-12 default)", () => {
    assert.equal(validateInput(byId("note_send"), { id: "1", to: "not-an-email" }).ok, true);
  });
  test("standard op tb.hold_status", () => {
    assert.equal(validateInput(byId("tb.hold_status"), { holdId: "hld_1" }).ok, true);
    assert.equal(validateInput(byId("tb.hold_status"), {}).ok, false);
  });
  test("dynamic op takes DynamicCallInput", () => {
    const m = base();
    m.operations.push({
      id: "tools",
      title: "T",
      description: "D",
      crud: ["read"],
      effect: "read",
      idempotency: "supported",
      receipt: false,
      audience: "agent",
      dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" },
    });
    const dynOp = withStandardOps(m).find((o) => o.id === "tools");
    assert.ok(dynOp);
    assert.equal(validateInput(dynOp, { tool: "send_mail", arguments: { to: "x" } }).ok, true);
    assert.equal(validateInput(dynOp, { tool: "send_mail" }).ok, false);
  });
  test("op without input accepts only {}", () => {
    const m = base();
    delete m.operations[7].input;
    const person = withStandardOps(m).find((o) => o.id === "notebook_rename");
    assert.ok(person);
    assert.equal(validateInput(person, {}).ok, true);
    assert.equal(validateInput(person, { a: 1 }).ok, false);
  });
  test("validateAgainstSchema reports an uncompilable schema", () => {
    const r = validateAgainstSchema({ type: "object", properties: { a: { type: 5 } } } as any, {});
    assert.equal(r.ok, false);
  });
  test("structurally equal schemas from different objects validate the same", () => {
    const s1 = { type: "object" as const, required: ["a"] };
    const s2 = { type: "object" as const, required: ["a"] };
    assert.equal(validateAgainstSchema(s1, { a: 1 }).ok, true);
    assert.equal(validateAgainstSchema(s2, {}).ok, false);
  });
});

describe("validateAppFiles", async () => {
  const dirs: string[] = [];
  after(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  const basics = "---\nname: notes-basics\ndescription: How to use notes\n---\n# Notes\nHello {{agent.name}} in {{workspace.name}}.\n";
  const summaries =
    "---\nname: notes-summaries\ndescription: \"Summaries\"\n---\nUse {{settings.summary_model}} for {{scope.notebook.own}}.\n```html\n<div>example</div>\n```\n";
  async function repo(files: Record<string, string>): Promise<string> {
    const d = await mkdtemp(join(tmpdir(), "tb-manifest-"));
    dirs.push(d);
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(dirname(join(d, rel)), { recursive: true });
      await writeFile(join(d, rel), content);
    }
    return d;
  }
  const good = { Dockerfile: "FROM scratch\n", "skills/notes-basics/SKILL.md": basics, "skills/notes-summaries/SKILL.md": summaries };
  const files = async (over: Record<string, string>, m: any = base()) => validateAppFiles(m, await repo({ ...good, ...over }));
  const fileIssue = async (over: Record<string, string>) => expectIssue(await files(over), "M-SK-2", "skill_file_invalid");

  test("valid skill files pass", async () => {
    const r = await files({});
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("missing file", async () => {
    const d = await repo({ Dockerfile: "FROM scratch\n", "skills/notes-basics/SKILL.md": basics });
    expectIssue(await validateAppFiles(base(), d), "M-SK-2", "skill_file_invalid", "/skills/1/file");
  });
  test("frontmatter name mismatch", () => fileIssue({ "skills/notes-basics/SKILL.md": basics.replace("name: notes-basics", "name: other") }));
  test("missing frontmatter", () => fileIssue({ "skills/notes-basics/SKILL.md": "# no frontmatter\n" }));
  test("extra frontmatter key", () =>
    fileIssue({ "skills/notes-basics/SKILL.md": basics.replace("description:", "allowed-tools: all\ndescription:") }));
  test("unknown variable", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}{{agent.secret}}\n` }));
  test("undeclared setting variable", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}{{settings.ghost}}\n` }));
  test("undeclared default-grant kind", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}{{scope.notebook.all}}\n` }));
  test("raw HTML", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}<script>alert(1)</script>\n` }));
  test("javascript link", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}[x](javascript:alert(1))\n` }));
  test("tool-call markup, even in code", () =>
    fileIssue({ "skills/notes-basics/SKILL.md": `${basics}\`\`\`\n<invoke name="x">\n\`\`\`\n` }));
  test("MCP JSON-RPC directive", () =>
    fileIssue({ "skills/notes-basics/SKILL.md": `${basics}{"jsonrpc": "2.0", "method": "tools/call"}\n` }));
  test("larger than 64 KiB", () => fileIssue({ "skills/notes-basics/SKILL.md": `${basics}${"a".repeat(66_000)}\n` }));
  test("hostile skill text is sanitized in linear time", async () => {
    const t0 = performance.now();
    const r = await files({ "skills/notes-basics/SKILL.md": `${basics}${"<a ".repeat(15_000)}${"```\n".repeat(2000)}` });
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
    assert.ok(performance.now() - t0 < 2000);
  });
  test("autolinks are not HTML", async () => {
    const r = await files({ "skills/notes-basics/SKILL.md": `${basics}<https://example.org/docs>\n` });
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("hand-written openapi.json beside the manifest", async () => {
    expectIssue(await files({ "openapi.json": "{}" }), "§14", "hand_written_artifact");
  });
  test("M-ST-7 with skill bodies: a setting used only by a skill passes, an orphan fails", async () => {
    const m = base();
    m.settings.steps[0].fields.push({ key: "tone", type: "string", label: "Tone" });
    expectIssue(await files({}, m), "M-ST-7", "setting_unused");
    const r = await files({ "skills/notes-basics/SKILL.md": `${basics}Tone: {{settings.tone}}\n` }, m);
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("artifact sha256 format", async () => {
    const m = base();
    m.artifacts[0].sha256 = "ABC";
    expectIssue(await files({}, m), "M-AR-1", "artifact_invalid");
  });
});

describe("validateAppFiles: path bases (MANIFEST §3, v0.1.11 (C70))", async () => {
  const dirs: string[] = [];
  after(async () => {
    for (const d of dirs) await rm(d, { recursive: true, force: true });
  });
  const skill = (id: string) => `---\nname: ${id}\ndescription: Skill ${id}\n---\n# ${id}\n`;
  const SKILLS = { "skills/notes-basics/SKILL.md": skill("notes-basics"), "skills/notes-summaries/SKILL.md": skill("notes-summaries") };

  async function tree(files: Record<string, string>): Promise<string> {
    const d = await mkdtemp(join(tmpdir(), "tb-manifest-bases-"));
    dirs.push(d);
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(dirname(join(d, rel)), { recursive: true });
      await writeFile(join(d, rel), content);
    }
    return d;
  }
  /** Multi-app layout of opt2-tealbrick-samples: repo root with one directory per app (here `notes/`). */
  const multi = (): any => {
    const m = base();
    m.runtime.build = { context: "notes", dockerfile: "notes/Dockerfile" };
    const sv = m.runtime.services[0]; // the example's `search` service ships an upstream image; make it a thin layer built by the app CI
    delete sv.image;
    sv.build = { context: "notes", dockerfile: "notes/Dockerfile.search" };
    return m;
  };
  const inApp = (rel: string) => `notes/${rel}`;
  const appFiles = { "notes/Dockerfile": "FROM scratch\n", "notes/Dockerfile.search": "FROM scratch\n" };

  test("multi-app repo: build paths from the repo root, skills from the manifest dir", async () => {
    const root = await tree({ ...appFiles, ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    const r = await validateAppFiles(multi(), root, join(root, "notes"));
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });

  test("negative: skills resolved from the repo root fail when they only exist next to the manifest", async () => {
    const root = await tree({ ...appFiles, ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    const r = await validateAppFiles(multi(), root); // manifestDir defaults to repoDir
    expectIssue(r, "M-SK-2", "skill_file_invalid", "/skills/0/file");
  });

  test("negative: build paths resolved from the manifest dir fail", async () => {
    const root = await tree({ ...appFiles, ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    // repoDir wrongly set to the app dir: "notes/Dockerfile" would be looked up in notes/notes/
    const r = await validateAppFiles(multi(), join(root, "notes"), join(root, "notes"));
    expectIssue(r, "M-RT-9", "build_path_invalid", "/runtime/build/context");
    expectIssue(r, "M-RT-9", "build_path_invalid", "/runtime/build/dockerfile");
  });

  test("negative: a skill that exists only at the repo root is not found from the manifest dir", async () => {
    const root = await tree({ ...appFiles, ...SKILLS });
    expectIssue(await validateAppFiles(multi(), root, join(root, "notes")), "M-SK-2", "skill_file_invalid");
  });

  test("a service build is checked against the repo root too", async () => {
    const root = await tree({ "notes/Dockerfile": "FROM scratch\n", ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    const r = await validateAppFiles(multi(), root, join(root, "notes"));
    expectIssue(r, "M-RT-9", "build_path_invalid", "/runtime/services/0/build/dockerfile");
  });

  test("a build context that is a file, and a Dockerfile that is a directory, are refused", async () => {
    const root = await tree({ "notes/Dockerfile/x": "", "notes/Dockerfile.search": "FROM scratch\n", ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    expectIssue(await validateAppFiles(multi(), root, join(root, "notes")), "M-RT-9", "build_path_invalid", "/runtime/build/dockerfile");
  });

  test("paths escaping their base are refused", async () => {
    const root = await tree({ ...appFiles, "outside/SKILL.md": skill("notes-basics"), ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) });
    const m = multi();
    m.skills[0].file = "../outside/SKILL.md";
    expectIssue(await validateAppFiles(m, root, join(root, "notes")), "M-SK-2", "skill_file_invalid", "/skills/0/file");
    const b = multi();
    b.runtime.build.context = "../elsewhere";
    expectIssue(await validateAppFiles(b, root, join(root, "notes")), "M-RT-9", "build_path_invalid", "/runtime/build/context");
  });

  test("hand-written artifacts are looked for beside the manifest (manifestDir), not at the repo root", async () => {
    const files = { ...appFiles, ...Object.fromEntries(Object.entries(SKILLS).map(([k, v]) => [inApp(k), v])) };
    const atRoot = await tree({ ...files, "openapi.json": "{}" });
    assert.equal((await validateAppFiles(multi(), atRoot, join(atRoot, "notes"))).ok, true, "repo-root openapi.json is not beside the manifest");
    const beside = await tree({ ...files, "notes/openapi.json": "{}" });
    expectIssue(await validateAppFiles(multi(), beside, join(beside, "notes")), "§14", "hand_written_artifact");
  });

  test("manifestDir defaults to repoDir (single-app repo)", async () => {
    const root = await tree({ Dockerfile: "FROM scratch\n", ...SKILLS });
    const r = await validateAppFiles(base(), root);
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
    assert.deepEqual(await validateAppFiles(base(), root, root), r);
  });
});

describe("C107 (spec 0.1.16): outward ops and hold families", () => {
  test("outward op with family outward or identity is valid; absent is still accepted (one release of grace)", () => {
    for (const hf of ["outward", "identity", "first_contact", "public_link", undefined]) {
      const r = mutate((m) => {
        m.operations.push({ id: "post_send", title: "Send", description: "Send a post.", input: { type: "object" }, output: { type: "object" }, crud: ["create"], effect: "outward", idempotency: "required", receipt: true, audience: "agent", ...(hf ? { holdFamily: hf } : {}) });
      });
      assert.equal(r.ok, true, String(hf));
    }
  });
  test("C232: public_link is not valid for a write effect", refuses("M-OP-4", "hold_family_invalid", (m) => {
    m.operations.push({ id: "page_put", title: "Put", description: "Put.", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: true, audience: "agent", holdFamily: "public_link" });
  }));
  test("outward / identity are not valid for write or destructive effects", refuses("M-OP-4", "hold_family_invalid", (m) => {
    m.operations.push({ id: "note_put", title: "Put", description: "Put.", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: true, audience: "agent", holdFamily: "outward" });
  }));
});

describe("v0.1.21 (spec 0.1.43): viewer routes (M-PR-2) and listing (M-OP-11)", () => {
  test("one viewer route at /v validates", () => {
    const r = mutate((m) => (m.publicRoutes = [...(m.publicRoutes ?? []), { path: "/v", purpose: "viewer" }]));
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("a viewer route not at /v", refuses("M-PR-2", "viewer_route_invalid", (m) => (m.publicRoutes = [{ path: "/view", purpose: "viewer" }])));
  test("two viewer routes", refuses("M-PR-2", "viewer_route_invalid", (m) => (m.publicRoutes = [{ path: "/v", purpose: "viewer" }, { path: "/w", purpose: "viewer" }])));
  test("listing workflow on an agent op validates", () => {
    const r = mutate((m) => (m.operations.find((o: any) => o.audience === "agent").listing = "workflow"));
    assert.equal(r.ok, true, JSON.stringify(!r.ok && r.errors));
  });
  test("listing on a person op", refuses("M-OP-11", "listing_invalid", (m) => (m.operations.find((o: any) => o.audience === "person").listing = "workflow")));
  test("contracts field (spec 0.1.42) validates; an unknown contract id is refused by the schema", () => {
    assert.equal(mutate((m) => (m.contracts = { produces: ["messages/1"] })).ok, true);
    expectIssue(mutate((m) => (m.contracts = { produces: ["messages/9"] })), "schema", "schema_invalid");
  });
});
