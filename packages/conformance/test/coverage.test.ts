// A11: generated SDK export list is current, and every export maps to catalogued check ids.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { CHECK_IDS, coverageOutcome, SDK_COVERAGE, SDK_EXPORTS, SDK_UNCOVERED } from "../src/index.ts";

describe("A11 SDK coverage", () => {
  it("the committed export list equals the one generated from @opt2-tealbrick/spec/sdk", () => {
    const script = fileURLToPath(new URL("../scripts/gen-sdk-exports.ts", import.meta.url));
    const r = spawnSync(process.execPath, [script, "--check"], { encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.ok(SDK_EXPORTS.length >= 40);
    assert.ok(SDK_EXPORTS.some((e) => e.name === "authorize" && e.pkg === "@opt2-tealbrick/manifest"));
    assert.ok(SDK_EXPORTS.some((e) => e.name === "startApp" && e.pkg === "@opt2-tealbrick/miniapp-sdk"));
    assert.ok(SDK_EXPORTS.some((e) => e.name === "useHolds" && e.pkg === "@opt2-tealbrick/miniapp-sdk/client"));
  });

  it("every export maps to ≥ 1 catalogued check id", () => {
    for (const e of SDK_EXPORTS) {
      const ids = SDK_COVERAGE[e.name] ?? [];
      if (e.name in SDK_UNCOVERED) {
        assert.equal(ids.length, 0, `${e.name} is declared uncovered and must not be mapped`);
        continue;
      }
      assert.ok(ids.length > 0, `${e.name} unmapped`);
      for (const id of ids) assert.ok(CHECK_IDS.has(id), `${e.name} → ${id} not catalogued`);
    }
    assert.equal(coverageOutcome().pass, true);
  });

  it("modelRole maps to the real RM-17 row, and the uncovered exports are declared with a reason, not mapped to a row that does not call them", () => {
    assert.deepEqual(SDK_COVERAGE.modelRole, ["A23.model_role_no_route"]);
    assert.ok(!("familyAllowedFor" in SDK_COVERAGE));
    assert.match(SDK_UNCOVERED.familyAllowedFor ?? "", /person-op relay lane/);
    // v0.1.77: the modelFetch error codes have no row yet; the caller context summary limits map to B32.context_reaches_target
    assert.ok(!("SDK_MODEL_ERROR_CODES" in SDK_COVERAGE));
    assert.match(SDK_UNCOVERED.SDK_MODEL_ERROR_CODES ?? "", /modelFetch/);
    assert.deepEqual(SDK_COVERAGE.CALLER_CONTEXT_SUMMARY_MAX_CHARS, ["B32.context_reaches_target"]);
    assert.match(coverageOutcome().asserted, /not covered yet \(declared in SDK_UNCOVERED\): SDK_MODEL_ERROR_CODES, familyAllowedFor/);
  });
});
