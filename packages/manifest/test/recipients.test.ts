// spec next (unreleased; C373, G-6): recipients of an outward call — extractRecipients, recipientSpecsProblem and
// M-OP-14 in validateManifest. Each rule has a quiet case and a firing case (L34).
import assert from "node:assert/strict";
import { test } from "node:test";
import example from "@opt2-tealbrick/spec/examples/notes.manifest.json" with { type: "json" };
import { extractRecipients, isRecipientsOutward, RECIPIENT_KINDS, RECIPIENT_POINTER_MAX, RECIPIENT_SPECS_MAX, RECIPIENTS_MAX, recipientPointerProblem, recipientSpecsProblem } from "../src/index.ts";
import { validateManifest } from "../src/validate.ts";

const NPUB = "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6";
const HEX = "3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d";
const email = (pointer: string) => ({ pointer, kind: "email" as const });

test("C373: local mirrors equal the spec values (delete with the re-pin)", () => {
  assert.deepEqual([...RECIPIENT_KINDS], ["buzz", "slack", "telegram", "email"]);
  assert.equal(RECIPIENT_SPECS_MAX, 8);
  assert.equal(RECIPIENTS_MAX, 64);
  assert.equal(RECIPIENT_POINTER_MAX, 256);
});

test("C373 extractRecipients: bare values get the kind, prefixed values stay, result de-duplicated and sorted", () => {
  const input = {
    to: ["B@Example.com", "a@example.com", "email:a@example.com"],
    cc: null,
    people: [{ npub: NPUB }, { npub: `buzz:${HEX}` }],
    channel: "u012abcdef",
    chat: "-1001234567890",
    "a/b": { "~c": "U0SECOND1" },
  };
  const r = extractRecipients(input, [email("/to"), email("/cc"), email("/bcc"), { pointer: "/people/0/npub", kind: "buzz" }, { pointer: "/people/1/npub", kind: "buzz" }, { pointer: "/channel", kind: "slack" }, { pointer: "/chat", kind: "telegram" }, { pointer: "/a~1b/~0c", kind: "slack" }]);
  assert.deepEqual(r, {
    recipients: [`buzz:${NPUB}`, "email:a@example.com", "email:b@example.com", "slack:U012ABCDEF", "slack:U0SECOND1", "telegram:-1001234567890"],
    incomplete: false,
  });
});

test("C373 extractRecipients: known none is [] (missing member, null, empty array); never incomplete", () => {
  for (const input of [{}, { to: null }, { to: [] }, { to: [null, null] }, { other: "x@y.example" }]) {
    assert.deepEqual(extractRecipients(input, [email("/to")]), { recipients: [], incomplete: false }, JSON.stringify(input));
  }
  // a place under a scalar or a bad array index does not exist
  assert.deepEqual(extractRecipients({ to: "a@b.example" }, [email("/to/x")]), { recipients: [], incomplete: false });
  assert.deepEqual(extractRecipients({ to: ["a@b.example"] }, [email("/to/-")]), { recipients: [], incomplete: false });
  assert.deepEqual(extractRecipients({ to: ["a@b.example"] }, [email("/to/01")]), { recipients: [], incomplete: false });
  assert.deepEqual(extractRecipients({ to: ["a@b.example"] }, [email("/to/0")]), { recipients: ["email:a@b.example"], incomplete: false });
  // own members only: an inherited name is not a place
  assert.deepEqual(extractRecipients({}, [email("/constructor")]), { recipients: [], incomplete: false });
});

test("C373 extractRecipients: fires on bad values — the bad one is dropped, the good ones stay, incomplete is set", () => {
  const cases: [string, unknown][] = [
    ["display name", "Name <a@example.com>"],
    ["list in one string", "a@example.com, c@example.com"],
    ["number", 42],
    ["object", { address: "a@example.com" }],
    ["nested array", [["a@example.com"]]],
    ["empty string", ""],
    ["other kind prefix", "telegram:123"],
    ["own prefix, bad value", "email:not-an-address"],
    ["no domain dot", "a@localhost"],
  ];
  for (const [name, bad] of cases) {
    const r = extractRecipients({ to: bad, cc: "ok@example.com" }, [email("/to"), email("/cc")]);
    assert.deepEqual(r, { recipients: ["email:ok@example.com"], incomplete: true }, name);
  }
  // a mixed array: good members kept, nulls dropped quietly, a bad member marks incomplete
  assert.deepEqual(extractRecipients({ to: ["a@example.com", null, 7] }, [email("/to")]), { recipients: ["email:a@example.com"], incomplete: true });
  // C373: slack conversation ids (C/G/D) are recipient handles (conversations, not people); another prefix is not
  assert.deepEqual(extractRecipients({ c: ["C012ABCDEF", "g012abcdef", "D012ABCDEF"] }, [{ pointer: "/c", kind: "slack" }]), { recipients: ["slack:C012ABCDEF", "slack:D012ABCDEF", "slack:G012ABCDEF"], incomplete: false });
  assert.deepEqual(extractRecipients({ c: "X012ABCDEF" }, [{ pointer: "/c", kind: "slack" }]), { recipients: [], incomplete: true });
});

test("C373 extractRecipients: kind telegram takes JSON safe integers (negative group / channel ids) and digit strings; other numbers fail", () => {
  const tg = (v: unknown) => extractRecipients({ chat: v }, [{ pointer: "/chat", kind: "telegram" }]);
  assert.deepEqual(tg(123456789), { recipients: ["telegram:123456789"], incomplete: false });
  assert.deepEqual(tg(-1001234567890), { recipients: ["telegram:-1001234567890"], incomplete: false }, "negative group id");
  assert.deepEqual(tg("-1001234567890"), { recipients: ["telegram:-1001234567890"], incomplete: false }, "digit string");
  assert.deepEqual(tg([42, "42", "telegram:42"]), { recipients: ["telegram:42"], incomplete: false }, "one handle three ways");
  for (const bad of [1.5, 1e21, Number.MAX_SAFE_INTEGER + 2, 0, -0, Number.NaN, "1e5", "+123", "0123", "@someone"]) {
    assert.equal(tg(bad).incomplete, true, String(bad));
    assert.deepEqual(tg(bad).recipients, [], String(bad));
  }
  // a number is a value only for telegram
  assert.deepEqual(extractRecipients({ c: 123 }, [{ pointer: "/c", kind: "slack" }]), { recipients: [], incomplete: true });
  // the build-time walk lets an integer leaf through for telegram only
  const schema = { type: "object", properties: { chat: { type: "integer" }, chats: { type: "array", items: { type: "integer" } } } };
  assert.equal(recipientPointerProblem(schema, "/chat", "telegram"), null);
  assert.equal(recipientPointerProblem(schema, "/chats", "telegram"), null);
  assert.notEqual(recipientPointerProblem(schema, "/chat", "email"), null);
  assert.notEqual(recipientPointerProblem(schema, "/chats", "slack"), null);
});

test("C373 extractRecipients: more than 64 distinct → the first 64 in code-unit order and incomplete; exactly 64 is complete", () => {
  const addrs = (n: number) => Array.from({ length: n }, (_, i) => `u${String(i).padStart(3, "0")}@example.com`);
  const r64 = extractRecipients({ to: addrs(64) }, [email("/to")]);
  assert.equal(r64.recipients.length, 64);
  assert.equal(r64.incomplete, false);
  const r65 = extractRecipients({ to: [...addrs(65)].reverse() }, [email("/to")]);
  assert.equal(r65.incomplete, true);
  assert.deepEqual(r65.recipients, addrs(64).map((a) => `email:${a}`));
  // duplicates count once (70 values, 64 distinct)
  assert.deepEqual(extractRecipients({ to: [...addrs(64), ...addrs(6)] }, [email("/to")]).incomplete, false);
});

test("C373 extractRecipients: malformed specs → [] and incomplete (a policy fails closed); never throws", () => {
  for (const specs of [undefined, null, "x", [], Array.from({ length: 9 }, (_, i) => email(`/r${i}`)), [{ pointer: "", kind: "email" }], [{ pointer: "/to", kind: "fax" }], [email("/to"), email("/to")]]) {
    assert.deepEqual(extractRecipients({ to: "a@example.com" }, specs), { recipients: [], incomplete: true }, JSON.stringify(specs));
  }
  assert.doesNotThrow(() => extractRecipients(null, [email("/to")]));
  assert.deepEqual(extractRecipients("text", [email("/to")]), { recipients: [], incomplete: false });
});

test("C373 recipientSpecsProblem: quiet on good, fires on bad", () => {
  assert.equal(recipientSpecsProblem([email("/to"), { pointer: "/to", kind: "slack" }, { pointer: "/a~0b/~1", kind: "buzz" }]), null);
  assert.equal(recipientSpecsProblem(Array.from({ length: 8 }, (_, i) => email(`/r${i}`))), null);
  const bad: [string, unknown][] = [
    ["not an array", { pointer: "/to", kind: "email" }],
    ["empty", []],
    ["9 entries", Array.from({ length: 9 }, (_, i) => email(`/r${i}`))],
    ["root pointer", [email("")]],
    ["no slash", [email("to")]],
    ["bad escape", [email("/a~2")]],
    ["too long", [email(`/${"x".repeat(256)}`)]],
    ["unknown kind", [{ pointer: "/to", kind: "fax" }]],
    ["extra member", [{ pointer: "/to", kind: "email", label: "To" }]],
    ["bare string", ["/to"]],
    ["duplicate", [email("/to"), email("/to")]],
  ];
  for (const [name, specs] of bad) assert.notEqual(recipientSpecsProblem(specs), null, name);
  assert.equal(recipientSpecsProblem([email(`/${"x".repeat(255)}`)]), null, "256 chars is the limit");
  // QA-RCP-6: code points, like the schema's maxLength (255 astral chars = 510 UTF-16 units, still within the limit)
  const astral = String.fromCodePoint(0x1f600);
  assert.equal(recipientSpecsProblem([email(`/${astral.repeat(255)}`)]), null, "256 code points");
  assert.notEqual(recipientSpecsProblem([email(`/${astral.repeat(256)}`)]), null, "257 code points");
});

const base = (): any => structuredClone(example);
const outwardOp = (m: any) => m.operations.find((o: any) => o.effect === "outward");
function issues(fn: (m: any) => void) {
  const m = base();
  fn(m);
  const r = validateManifest(m);
  return r.ok ? [] : r.errors;
}

test("C373 M-OP-14: recipients on an outward agent op validate", () => {
  assert.deepEqual(issues((m) => (outwardOp(m).recipients = [email("/to"), { pointer: "/to", kind: "slack" }])), []);
});

test("C373 QA-RCP-7: isRecipientsOutward = effect or holdFamily outward", () => {
  assert.equal(isRecipientsOutward({ effect: "outward" }), true);
  assert.equal(isRecipientsOutward({ effect: "write", holdFamily: "outward" }), true);
  assert.equal(isRecipientsOutward({ effect: "outward", holdFamily: "first_contact" }), true);
  for (const r of [{ effect: "write" }, { effect: "money", holdFamily: "money" }, { effect: "write", holdFamily: "first_contact" }, {}]) assert.equal(isRecipientsOutward(r), false, JSON.stringify(r));
});

// QA-RCP-3: a static pointer must name a place the input schema can hold
const SCHEMA = {
  type: "object",
  properties: {
    to: { type: "string" },
    cc: { type: ["array", "null"], items: { type: "string" } },
    nums: { type: "array", items: { type: "integer" } },
    count: { type: "integer" },
    body: { type: "object", properties: { recipients: { type: "array", items: { type: "string" } } }, additionalProperties: false },
    pair: { type: "array", prefixItems: [{ type: "string" }, { type: "object", properties: { id: { type: "string" } } }] },
    meta: { type: "object" },
    byName: { type: "object", additionalProperties: { type: "string" } },
    ref: { $ref: "#/$defs/x" },
    any: {},
    open: true,
  },
};

test("C373 QA-RCP-3 recipientPointerProblem: quiet on places the schema can hold, and where it cannot be walked", () => {
  for (const p of ["/to", "/cc", "/cc/0", "/body/recipients", "/body/recipients/3", "/pair/0", "/pair/1/id", "/meta/anything", "/byName/x", "/ref/deep/er", "/any/x", "/open/x"]) {
    assert.equal(recipientPointerProblem(SCHEMA, p), null, p);
  }
  assert.equal(recipientPointerProblem({ type: "object" }, "/whatever"), null, "an open object without properties");
  assert.equal(recipientPointerProblem({ oneOf: [{ type: "object" }] }, "/x"), null, "a combinator");
  // RCPD-1: declared members plus an explicit `additionalProperties: true` admit any member
  assert.equal(recipientPointerProblem({ type: "object", properties: { a: { type: "string" } }, additionalProperties: true }, "/other"), null, "open by additionalProperties: true");
});

test("C373 QA-RCP-3 recipientPointerProblem: fires on a typo, a step through a scalar, a bad index, a leaf that holds no string", () => {
  for (const p of ["/does_not_exist", "/To", "/to/x", "/body/recipient", "/body/recipients/x", "/cc/-", "/cc/01", "/count", "/nums", "/pair/1/name"]) {
    assert.notEqual(recipientPointerProblem(SCHEMA, p), null, p);
  }
  assert.notEqual(recipientPointerProblem({ type: "object", properties: { a: { type: "string" } }, additionalProperties: false }, "/b"), null, "closed object");
  assert.notEqual(recipientPointerProblem({ type: "object", properties: {}, additionalProperties: false }, "/a"), null, "closed, no members");
  // RCPD-2: a `false` schema at the leaf, and an array leaf with `items: false`
  assert.notEqual(recipientPointerProblem({ type: "object", properties: { x: false } }, "/x"), null, "properties: {x: false}");
  assert.notEqual(recipientPointerProblem({ type: "object", properties: { x: { type: "array", items: false } } }, "/x"), null, "items: false");
  assert.notEqual(recipientPointerProblem({ type: "object", properties: { x: { items: false } } }, "/x"), null, "items: false, no type");
  assert.equal(recipientPointerProblem({ type: "object", properties: { x: { type: "array", items: { type: "string" } } } }, "/x"), null, "control: items of strings");
});

test("C373 QA-RCP-3 M-OP-14 in validateManifest: a static pointer the input cannot hold is refused at its path", () => {
  const errs = issues((m) => (outwardOp(m).recipients = [email("/to"), email("/does_not_exist")]));
  assert.equal(errs.length, 1, JSON.stringify(errs));
  assert.equal(errs[0]?.rule, "M-OP-14");
  assert.equal(errs[0]?.code, "recipients_invalid");
  assert.match(errs[0]?.path ?? "", /\/recipients\/1\/pointer$/);
  // the id field is a string: a valid place; quiet
  assert.deepEqual(issues((m) => (outwardOp(m).recipients = [email("/id")])), []);
});

test("C373 M-OP-14: fires on a non-outward op, bad pointer, > 8, unknown kind, duplicates — rule M-OP-14, code recipients_invalid", () => {
  const writeOp = (m: any) => m.operations.find((o: any) => o.effect === "write");
  const cases: [string, (m: any) => void][] = [
    ["write op", (m) => (writeOp(m).recipients = [email("/to")])],
    ["read op", (m) => (m.operations.find((o: any) => o.effect === "read").recipients = [email("/to")])],
    // QA-RCP-7: an outward op for people (never hooked)
    ["person op", (m) => Object.assign(outwardOp(m), { audience: "person", recipients: [email("/to")] })],
    ["bad pointer", (m) => (outwardOp(m).recipients = [email("to")])],
    ["9 places", (m) => (outwardOp(m).recipients = Array.from({ length: 9 }, (_, i) => email(`/r${i}`)))],
    ["unknown kind", (m) => (outwardOp(m).recipients = [{ pointer: "/to", kind: "fax" }])],
    ["empty", (m) => (outwardOp(m).recipients = [])],
    ["duplicate", (m) => (outwardOp(m).recipients = [email("/to"), email("/to")])],
  ];
  for (const [name, fn] of cases) {
    const errs = issues(fn);
    assert.ok(errs.length > 0, name);
    assert.ok(
      errs.every((e) => e.rule === "M-OP-14" && e.code === "recipients_invalid"),
      `${name}: ${JSON.stringify(errs)}`,
    );
  }
});
