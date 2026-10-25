// spec 0.1.74 (C354a): catalog names, variant names, hold-family sets and the "never broader" variant rule (copied helpers).
import assert from "node:assert/strict";
import { test } from "node:test";
import { DYNAMIC_CATALOG_NAME_RE, DYNAMIC_TOOL_NAME_RE, dynamicVariantBase, holdFamilySet, variantNarrowerOrEqual } from "../src/index.ts";

test("DYNAMIC_CATALOG_NAME_RE: 2–48 chars, no `__`, no trailing `_`", () => {
  for (const ok of ["ab", "send", "gmail_send", "a1", `a${"b".repeat(47)}`]) assert.ok(DYNAMIC_CATALOG_NAME_RE.test(ok), ok);
  for (const bad of ["a", "a_", "a__b", "send__first_contact", "Send", "1send", "", `a${"b".repeat(48)}`, "a-b"]) assert.ok(!DYNAMIC_CATALOG_NAME_RE.test(bad), bad);
  assert.ok(DYNAMIC_TOOL_NAME_RE.test(`a${"b".repeat(62)}`));
  assert.ok(!DYNAMIC_TOOL_NAME_RE.test(`a${"b".repeat(63)}`));
});

test("dynamicVariantBase: the base of a valid variant, else null", () => {
  assert.equal(dynamicVariantBase("send__first_contact"), "send");
  assert.equal(dynamicVariantBase("gmail_send__first_contact"), "gmail_send");
  assert.equal(dynamicVariantBase("send__1a"), "send", "a suffix may start with a digit");
  // not variants: a suffix must start with a letter or digit, be non-empty and lower case; the base is a catalog name
  for (const bad of ["send___y", "send__", "send__Y", "send__1A", "send", "send_", "s__x", "x__1a", "send_x", "_send__x", "send_x___y"]) assert.equal(dynamicVariantBase(bad), null, bad);
  // ≤ 63 chars in all (a 48-char base + `__first_contact` = 63)
  const base48 = `g${"m".repeat(47)}`;
  assert.equal(dynamicVariantBase(`${base48}__first_contact`), base48);
  assert.equal(dynamicVariantBase(`${base48}__first_contacts`), null);
});

test("holdFamilySet: holdFamilies ∪ {holdFamily}, set order; empty or absent holdFamilies falls back to holdFamily", () => {
  assert.deepEqual([...holdFamilySet({ holdFamily: "first_contact", holdFamilies: ["first_contact", "outward"] })], ["first_contact", "outward"]);
  assert.deepEqual([...holdFamilySet({ holdFamily: "outward", holdFamilies: [] })], ["outward"]);
  assert.deepEqual([...holdFamilySet({ holdFamily: "outward" })], ["outward"]);
  assert.deepEqual([...holdFamilySet({ holdFamily: "outward", holdFamilies: ["first_contact"] })], ["first_contact", "outward"]);
  assert.deepEqual([...holdFamilySet({})], []);
});

test("variantNarrowerOrEqual: crud ⊆, effect ≤ (fail closed outside EFFECTS), hold families ⊇ the base's", () => {
  const base = { crud: ["create" as const], effect: "outward" as const, holdFamily: "outward" as const };
  assert.ok(variantNarrowerOrEqual({ crud: ["create"], effect: "outward", holdFamily: "first_contact", holdFamilies: ["first_contact", "outward"] }, base));
  assert.ok(variantNarrowerOrEqual({ crud: ["create"], effect: "write", holdFamily: "outward", holdFamilies: [] }, base), "empty holdFamilies = [holdFamily]");
  assert.ok(!variantNarrowerOrEqual({ crud: ["create"], effect: "outward", holdFamily: "first_contact" }, base), "drops the base family outward");
  assert.ok(!variantNarrowerOrEqual({ crud: ["create"], effect: "outward", holdFamily: "first_contact", holdFamilies: [] }, base));
  assert.ok(!variantNarrowerOrEqual({ crud: ["create", "delete"], effect: "outward", holdFamilies: ["outward"] }, base), "extra crud");
  assert.ok(!variantNarrowerOrEqual({ crud: ["create"], effect: "destructive", holdFamilies: ["outward"] }, base), "later effect");
  assert.ok(!variantNarrowerOrEqual({ crud: ["create"], effect: "teleport" as never, holdFamilies: ["outward"] }, base), "unknown variant effect");
  assert.ok(!variantNarrowerOrEqual({ crud: ["create"], effect: "read" }, { ...base, effect: "teleport" as never }), "unknown base effect");
});
