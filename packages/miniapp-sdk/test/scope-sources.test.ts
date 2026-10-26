// spec 0.1.65 (C331 D5b/D8): the default scope summary names a type the agent can reach nothing of (`summaryEmpty`, e.g. Connect
// "no account yet") and lists the agent's scope instances as display `sources` (instance label cleaned, by type then label, ≤ 20).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import type { PersonPrincipal } from "@opt2-tealbrick/spec/sdk";
import { createAuditLog } from "../src/server/audit.ts";
import { boundScopeSummary, SCOPE_SUMMARY_MAX_BYTES } from "../src/server/bridge-routes.ts";
import { createScopeStore, SCOPE_SOURCES_MAX } from "../src/server/scopes.ts";
import { openStore } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { tempDir } from "./helpers.ts";

const person = { type: "person", id: "per_x", ws: "ws_x", instance: "ins_x" } as unknown as PersonPrincipal;
const AGT = "agt_01SOURCES00000000000000000" as never;
const c = (code: number) => String.fromCharCode(code);

function store(summaryEmpty?: string) {
  const t = tempDir();
  const db = openStore(t.dir);
  const m = fixtureManifest(0);
  const sc = m.scopes?.[0];
  if (!sc) throw new Error("no scope");
  sc.defaultGrants = [];
  if (summaryEmpty !== undefined) (sc as typeof sc & { summaryEmpty?: string }).summaryEmpty = summaryEmpty;
  const st = createScopeStore(db, m, createAuditLog(db, []), () => {});
  return { st, type: sc.type, level: sc.access[0]?.id ?? "read", cleanup: t.cleanup };
}

describe("C331 D5b summaryEmpty", () => {
  test("an agent with no row of the type gets the summaryEmpty text; with a row the template as before", async () => {
    const s = store("no notebook yet");
    try {
      assert.equal(await s.st.summary(AGT), "no notebook yet");
      await s.st.instances.create(s.type, "nb_1", "Team notes");
      await s.st.set(person, AGT, s.type, "nb_1", s.level);
      assert.doesNotMatch(await s.st.summary(AGT), /no notebook yet/u);
    } finally {
      s.cleanup();
    }
  });
  test("no summaryEmpty (or one with variables) adds nothing, as before spec 0.1.65", async () => {
    for (const v of [undefined, "{count} empty", ""]) {
      const s = store(v);
      try {
        assert.equal(await s.st.summary(AGT), "", String(v));
      } finally {
        s.cleanup();
      }
    }
  });
});

describe("C331 D8 sources", () => {
  test("[] without rows; the agent's instances with their app ids, cleaned labels and access, by label; at most 20", async () => {
    const s = store();
    try {
      assert.deepEqual(await s.st.sources(AGT), []);
      await s.st.instances.create(s.type, "nb_b", `Beta${c(0x200b)} notes${c(0x202e)}`);
      await s.st.instances.create(s.type, "nb_a", `Alpha${c(7)}${c(0x00ad)}`);
      await s.st.instances.create(s.type, "nb_x", "Not assigned");
      for (const id of ["nb_b", "nb_a"]) await s.st.set(person, AGT, s.type, id, s.level);
      assert.deepEqual(await s.st.sources(AGT), [
        { type: s.type, id: "nb_a", label: "Alpha", access: s.level },
        { type: s.type, id: "nb_b", label: "Beta notes", access: s.level },
      ]);
      for (let i = 0; i < 30; i++) {
        await s.st.instances.create(s.type, `nb_${String(i).padStart(2, "0")}`, `Book ${String(i).padStart(2, "0")}`);
        await s.st.set(person, AGT, s.type, `nb_${String(i).padStart(2, "0")}`, s.level);
      }
      assert.equal((await s.st.sources(AGT)).length, SCOPE_SOURCES_MAX);
    } finally {
      s.cleanup();
    }
  });
});

describe("QA sdk#50", () => {
  test("labels are cut at code points (no lone surrogate); provider-shaped ids and empty labels are not listed or counted", async () => {
    const s = store();
    try {
      const emoji = String.fromCodePoint(0x1f600);
      await s.st.instances.create(s.type, "nb_e", `${"a".repeat(59)}${emoji}${emoji}`);
      await s.st.instances.create(s.type, "cus_bYze8b07KDY7UK", "Stripe customer");
      await s.st.instances.create(s.type, "nb_empty", c(0x200b));
      for (const id of ["nb_e", "cus_bYze8b07KDY7UK", "nb_empty"]) await s.st.set(person, AGT, s.type, id, s.level);
      const out = await s.st.sources(AGT);
      assert.deepEqual(out.map((i) => i.id), ["nb_e"]);
      assert.equal(Array.from(out[0]?.label ?? "").length, 60);
      assert.equal(out[0]?.label.at(-1), emoji.at(-1), "the pair is whole");
      for (let i = 0; i < 25; i++) {
        await s.st.instances.create(s.type, `nb_${i}`, `Book ${String(i).padStart(2, "0")}`);
        await s.st.set(person, AGT, s.type, `nb_${i}`, s.level);
      }
      for (let i = 0; i < 5; i++) {
        await s.st.instances.create(s.type, `nb_z${i}`, "");
        await s.st.set(person, AGT, s.type, `nb_z${i}`, s.level);
      }
      assert.equal((await s.st.sources(AGT)).length, SCOPE_SOURCES_MAX, "empty labels never take a place of the 20");
      assert.ok((await s.st.sources(AGT)).every((i) => i.label.length > 0));
    } finally {
      s.cleanup();
    }
  });

  test("the scope_summary answer stays under the byte bound: sources go first (absent, not []), labels and admittedOps stay", () => {
    const sources = Array.from({ length: 20 }, (_, i) => ({ type: "account", id: `acc_${i}`, label: "L".repeat(60), access: "read" }));
    const rows = Array.from({ length: 200 }, (_, i) => ({ agent: `agt_${i}`, label: "1 account", admittedOps: ["op_a"], sources }));
    assert.ok(Buffer.byteLength(JSON.stringify(rows)) > SCOPE_SUMMARY_MAX_BYTES);
    const out = boundScopeSummary(rows);
    assert.ok(Buffer.byteLength(JSON.stringify(out)) <= SCOPE_SUMMARY_MAX_BYTES);
    assert.equal(out.length, 200);
    assert.ok(out.every((r) => r.label === "1 account" && r.admittedOps.length === 1));
    assert.ok(out.some((r) => "sources" in r), "the first agents keep theirs");
    assert.ok(out.filter((r) => !("sources" in r)).length > 0, "the last ones lose them");
    assert.ok(out.every((r) => !("sources" in r) || (r.sources?.length ?? 0) === 20), "never an empty list instead");
    const small = rows.slice(0, 3);
    assert.equal(boundScopeSummary(small), small, "a small answer is unchanged");
  });
});
