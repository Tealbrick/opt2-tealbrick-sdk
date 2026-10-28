import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { HANDLE_CHANNELS, handleChannel, isNpub, normalizeHandle, npubFromHex } from "../src/index.ts";

const V = JSON.parse(readFileSync(new URL("./vectors/handles.json", import.meta.url), "utf8")) as {
  npubFromHex: { hex: string; npub: string }[];
  npubFromHexThrows: string[];
  normalizeHandle: { in: string; out: string | null; note?: string }[];
};

test("G-4 npubFromHex: shared vectors (NIP-19), throws instead of truncating", () => {
  for (const v of V.npubFromHex) {
    assert.equal(npubFromHex(v.hex), v.npub);
    assert.equal(isNpub(v.npub), true);
  }
  for (const bad of V.npubFromHexThrows) assert.throws(() => npubFromHex(bad), /64 hex/);
});

test("G-4 isNpub: quiet on good, fires on bad (L34)", () => {
  const good = V.npubFromHex[0]?.npub as string;
  assert.equal(isNpub(good), true);
  assert.equal(isNpub(`${good.slice(0, -1)}7`), false); // checksum
  assert.equal(isNpub(good.toUpperCase()), false); // canonical form is lower case
  assert.equal(isNpub(`nsec1${good.slice(5)}`), false);
  assert.equal(isNpub(""), false);
});

test("G-4 normalizeHandle: shared vectors; never throws", () => {
  for (const v of V.normalizeHandle) assert.equal(normalizeHandle(v.in), v.out, `${v.in} (${v.note ?? ""})`);
  assert.equal(normalizeHandle(undefined as unknown as string), null);
  assert.equal(normalizeHandle(42 as unknown as string), null);
});

test("G-4 normalizeHandle is idempotent and handleChannel only accepts canonical handles", () => {
  for (const v of V.normalizeHandle) if (v.out) assert.equal(normalizeHandle(v.out), v.out);
  assert.deepEqual([...HANDLE_CHANNELS], ["buzz", "slack", "telegram", "email"]); // + email (C373)
  assert.equal(handleChannel("email:a@example.com"), "email");
  assert.equal(handleChannel("email:A@example.com"), null); // not canonical
  assert.equal(normalizeHandle(`email:${"a".repeat(65)}@example.com`), null); // local part > 64
  assert.equal(normalizeHandle(`email:a@${"b".repeat(60)}.${"c".repeat(60)}.${"d".repeat(60)}.${"e".repeat(60)}.${"f".repeat(9)}.example`), null); // > 254
  assert.equal(handleChannel("slack:U012ABCDEF"), "slack");
  assert.equal(handleChannel("slack:u012abcdef"), null); // not canonical
  assert.equal(handleChannel("telegram:-1001234567890"), "telegram");
  assert.equal(handleChannel("whatsapp:+421900000000"), null);
});
