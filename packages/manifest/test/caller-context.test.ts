// C367 P4 (spec 0.1.77): callerContextProblem (BRIDGE §8.5) and callerContextSummary (SDK-API §18.6 rule 6) against every row of the
// spec case file `examples/caller-context.cases.json` (shipped in @opt2-tealbrick/spec), plus edge tests the rows do not cover.
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import cases from "@opt2-tealbrick/spec/examples/caller-context.cases.json" with { type: "json" };
import { CALLER_CONTEXT_MAX_BYTES, CALLER_CONTEXT_MAX_DEPTH, callerContextProblem, callerContextSummary, canonicalize } from "../src/index.ts";

interface KeyCase {
  name: string;
  callerProduct: string | null;
  context: unknown;
  ok: boolean;
  pointer?: string;
}
interface SummaryCase {
  name: string;
  context: Record<string, unknown>;
  summary: string;
}
const keyCases = cases.cases as unknown as KeyCase[];
const summaryCases = cases.summaryCases as unknown as SummaryCase[];

describe("callerContextProblem: spec case file", () => {
  test("the case file has the rows and the limits this package implements", () => {
    assert.ok(keyCases.length >= 15);
    assert.ok(summaryCases.length >= 7);
    assert.equal(cases.limits.maxBytes, CALLER_CONTEXT_MAX_BYTES);
    assert.equal(cases.limits.maxDepth, CALLER_CONTEXT_MAX_DEPTH);
  });
  for (const c of keyCases) {
    test(`row ${c.name}`, () => {
      const p = callerContextProblem(c.callerProduct, c.context);
      if (c.ok) assert.equal(p, null, JSON.stringify(p));
      else {
        assert.ok(p, "expected a problem");
        assert.equal(p.pointer, c.pointer);
        assert.equal(typeof p.message, "string");
        assert.ok(p.message.length > 0);
      }
    });
  }
});

describe("callerContextProblem: order and edges", () => {
  const ctx = (o: Record<string, unknown>) => o;
  const at = (product: string | null, context: unknown) => callerContextProblem(product, context)?.pointer ?? null;

  test("rule 1: not a JSON object", () => {
    for (const v of [null, undefined, 1, "x", true, [], [{}], () => 1]) assert.equal(at("evolution", v), "/context", String(v));
  });
  test("rule 1 beats a missing product", () => assert.equal(at(null, []), "/context"));
  test("a non-plain object (Map, class instance, Date) is refused, not serialized", () => {
    // typeof "object", not an array; JCS refuses it (only plain objects), so it is not a valid context
    assert.equal(at("evolution", new Map()), "/context");
    assert.equal(at("evolution", { "evolution.a": new Date() }), "/context");
    class X {
      "evolution.a" = 1;
    }
    assert.equal(at("evolution", new X()), "/context");
  });
  test("a null-prototype object is a plain object", () => {
    const o = Object.assign(Object.create(null), { "evolution.run": "r" });
    assert.equal(callerContextProblem("evolution", o), null);
  });
  test("rule 2: undefined, NaN, Infinity, lone surrogates and functions in a value are refused at /context", () => {
    for (const v of [undefined, Number.NaN, Number.POSITIVE_INFINITY, "\ud800", () => 1, 1n]) assert.equal(at("evolution", ctx({ "evolution.a": v })), "/context", String(typeof v));
  });
  test("rule 2: a lone surrogate in a key is refused at /context", () => assert.equal(at("evolution", ctx({ "evolution.\ud800": 1 })), "/context"));
  test("rule 2: a very deep value is refused at /context, never throws", () => {
    let deep: unknown = 1;
    for (let i = 0; i < 200_000; i++) deep = [deep];
    assert.equal(at("evolution", ctx({ "evolution.a": deep })), "/context");
  });
  test("rule 2 beats rule 3 and 4", () => {
    const big = { "kanban.x": "y".repeat(CALLER_CONTEXT_MAX_BYTES) };
    assert.equal(at("evolution", big), "/context");
  });
  test("rule 2 counts the JCS form, not the input form: key order and spaces do not matter", () => {
    const o: Record<string, unknown> = {};
    o["evolution.b"] = "x".repeat(1000);
    o["evolution.a"] = "x".repeat(1000);
    const bytes = Buffer.byteLength(canonicalize(o as never));
    assert.ok(bytes > 2000 && bytes <= CALLER_CONTEXT_MAX_BYTES, String(bytes));
    assert.equal(callerContextProblem("evolution", o), null);
    o["evolution.c"] = "x".repeat(60); // one more key pushes the JCS form over the limit
    assert.equal(callerContextProblem("evolution", o)?.pointer, "/context");
  });
  test("no verified product: any key is refused at /context; {} passes", () => {
    for (const p of [null, "", "Evolution", "evo lution", "a", "-x", "evolution.", "a".repeat(40)]) {
      assert.equal(at(p, ctx({ "evolution.run": 1 })), "/context", String(p));
      assert.equal(callerContextProblem(p, {}), null, String(p));
    }
  });
  test("no verified product beats a bad key and a deep value", () => assert.equal(at(null, ctx({ "tb.x": 1, "evolution.a": [[[[1]]]] })), "/context"));
  test("a product with regexp characters is not trusted as a pattern", () => {
    assert.equal(at("ev.+", ctx({ "evolution.run": 1 })), "/context");
    assert.equal(at("(a|b)", ctx({ "a.run": 1 })), "/context");
  });
  test("rule 3: tb. wins over the pattern; the first failing key in sorted order names the pointer", () => {
    assert.equal(at("evolution", ctx({ "tb.x": 1 })), "/context/tb.x");
    assert.equal(at("evolution", ctx({ "evolution.z": 1, "evolution.A": 1, "evolution.b": 1 })), "/context/evolution.A"); // 'A' sorts before 'b' and 'z'
    assert.equal(at("evolution", ctx({ "zzz.a": 1, "kanban.a": 1 })), "/context/kanban.a");
    assert.equal(at("tb", ctx({ "tb.run": 1 })), "/context/tb.run"); // even a product literally named tb never gets the reserved namespace
  });
  test("rule 3 before rule 4: a pattern failure on a later key wins over a deep value on an earlier key", () => {
    // spec: "The first failing rule in the order above wins" (BRIDGE §8.5); the spec's reference checker runs rule 3 over all keys, then rule 4
    const p = callerContextProblem("evolution", ctx({ "evolution.a": [[[[1]]]], "evolution.b": 1, "kanban.z": 1 }));
    assert.equal(p?.pointer, "/context/kanban.z");
  });
  test("rule 4: with only depth failures the first key in sorted order is named", () => {
    const deep = { a: { b: { c: [1] } } }; // depth 4 under the key
    const p = callerContextProblem("evolution", ctx({ "evolution.z": deep, "evolution.b": deep, "evolution.a": 1 }));
    assert.equal(p?.pointer, "/context/evolution.b");
  });
  test("depth: scalars 0, [1] 1, {a:[1]} 2, depth 3 passes, depth 4 fails, empty containers add nothing", () => {
    const ok = (v: unknown) => callerContextProblem("evolution", ctx({ "evolution.a": v })) === null;
    assert.ok(ok(1) && ok(null) && ok("x") && ok([1]) && ok({ a: [1] }));
    assert.ok(ok({ a: { b: [1] } })); // 3
    assert.ok(!ok({ a: { b: { c: [1] } } })); // 4
    assert.ok(!ok([[[[1]]]])); // 4
    assert.ok(ok([[[[]]]])); // the innermost [] is empty: depth 3
    assert.ok(ok([[[]]]));
    assert.ok(!ok([[[[[]]]]])); // 4 non-empty levels
    assert.ok(ok({ a: {}, b: [], c: [[], {}] }));
  });
  test("depth agrees with the bottom-up definition on random values", () => {
    let seed = 7;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const gen = (budget: number): unknown => {
      if (budget <= 0 || rnd() < 0.2) return rnd() < 0.5 ? 1 : "s";
      const n = Math.floor(rnd() * 3);
      if (rnd() < 0.5) return Array.from({ length: n }, () => gen(budget - 1));
      const o: Record<string, unknown> = {};
      for (let i = 0; i < n; i++) o[`k${i}`] = gen(budget - 1);
      return o;
    };
    const height = (v: unknown): number => {
      if (v === null || typeof v !== "object") return 0;
      const ch = Array.isArray(v) ? v : Object.values(v);
      return 1 + Math.max(-1, ...ch.map(height));
    };
    for (let i = 0; i < 400; i++) {
      const v = gen(7);
      const expectOk = height(v) <= CALLER_CONTEXT_MAX_DEPTH;
      assert.equal(callerContextProblem("evolution", ctx({ "evolution.a": v })) === null, expectOk, JSON.stringify(v));
    }
  });
  test("RFC 6901 escaping of the pointer: ~ and /", () => {
    assert.equal(at("evolution", ctx({ "evolution/x": 1 })), "/context/evolution~1x");
    assert.equal(at("evolution", ctx({ "evolution~x": 1 })), "/context/evolution~0x");
    assert.equal(at("evolution", ctx({ "a~/b": 1 })), "/context/a~0~1b");
    assert.equal(at("evolution", ctx({ "~1": 1 })), "/context/~01"); // the escape does not re-escape its own output
  });
  test("messages never repeat a value or a key", () => {
    const secret = "S3CR3T-VALUE-xyz";
    const attempts: [string | null, unknown][] = [
      ["evolution", { "kanban.card": secret }],
      ["evolution", { "tb.onBehalfOf": secret }],
      ["evolution", { "evolution.a": { b: { c: { d: [secret] } } } }],
      ["evolution", { "evolution.big": secret.repeat(300) }],
      [null, { "evolution.run": secret }],
      ["evolution", [secret]],
      ["evolution", { "evolution.a": "\ud800" }],
    ];
    for (const [product, context] of attempts) {
      const p = callerContextProblem(product, context);
      assert.ok(p);
      assert.ok(!p.message.includes(secret), p.message);
      assert.ok(!p.message.includes("kanban.card") && !p.message.includes("tb.onBehalfOf"), p.message);
    }
  });
  test("size counts UTF-8 bytes of the JCS form (multi-byte, astral)", () => {
    // each 😀 is 4 bytes in UTF-8 (2 UTF-16 units, 1 code point)
    const wrap = (n: number) => ({ "evolution.n": "😀".repeat(n) });
    const bytesOf = (n: number) => Buffer.byteLength(canonicalize(wrap(n)));
    const fit = Math.floor((CALLER_CONTEXT_MAX_BYTES - bytesOf(0)) / 4);
    assert.ok(bytesOf(fit) <= CALLER_CONTEXT_MAX_BYTES && bytesOf(fit + 1) > CALLER_CONTEXT_MAX_BYTES);
    assert.equal(callerContextProblem("evolution", wrap(fit)), null);
    assert.equal(callerContextProblem("evolution", wrap(fit + 1))?.pointer, "/context");
  });
  test("accepted: Evolution's fixture, large-but-fitting nested values, numbers and null", () => {
    assert.equal(callerContextProblem("evolution", { "evolution.workflow": "w", "evolution.version": 3, "evolution.run": "r", "evolution.step": "s" }), null);
    assert.equal(callerContextProblem("evolution", { "evolution.a": null, "evolution.b": 1.5, "evolution.c": false, "evolution.d.e.f.g": { x: [1, 2, 3] } }), null);
  });
  test("does not mutate its input", () => {
    const o = { "evolution.b": { z: 1, a: 2 }, "evolution.a": [3, 1] };
    const copy = structuredClone(o);
    callerContextProblem("evolution", o);
    assert.deepEqual(o, copy);
    assert.deepEqual(Object.keys(o), Object.keys(copy));
  });
});

describe("callerContextSummary: spec case file", () => {
  for (const s of summaryCases) test(`row ${s.name}`, () => assert.equal(callerContextSummary(s.context), s.summary));
});

describe("callerContextSummary: edges", () => {
  test("no object or no key: undefined", () => {
    for (const v of [undefined, null, {}, [], "x", 1, true]) assert.equal(callerContextSummary(v), undefined, String(v));
  });
  test("an array of keys is not a context", () => assert.equal(callerContextSummary(["evolution.run"]), undefined));
  test("sorted keys, bare keys, join with '; '", () => {
    assert.equal(callerContextSummary({ "evolution.z": 1, "evolution.a": 2 }), "evolution.a; evolution.z");
  });
  test("plain code-unit order: uppercase before lowercase, '_' between", () => {
    assert.equal(callerContextSummary({ b: 1, B: 1, _: 1, a: 1, "~": 1 }), "B; _; a; b; ~");
  });
  test("only the LAST segment decides: run, version and workflow", () => {
    assert.equal(
      callerContextSummary({ "x.workflow": "w", "x.version": 2, "x.run": null, "x.workflow.step": "s", "x.step.run": true, "x.runs": 1, "x.run2": 1, run: 5 }),
      'run=5; x.run=null; x.run2; x.runs; x.step.run=true; x.version=2; x.workflow="w"; x.workflow.step',
    );
  });
  test("non-scalar values under those segments show the bare key", () => {
    assert.equal(callerContextSummary({ "x.run": { a: 1 }, "x.version": [1], "x.workflow": [] }), "x.run; x.version; x.workflow");
  });
  test("a value is its JSON text: strings quoted and escaped, numbers as ES prints them", () => {
    assert.equal(callerContextSummary({ "x.workflow": 'a"b\n' }), 'x.workflow="a\\"b\\n"');
    assert.equal(callerContextSummary({ "x.version": 1e21, "x.run": 0.1 }), "x.run=0.1; x.version=1e+21");
  });
  test("value cut: 64 code points of the JSON text, no marker; astral characters count once", () => {
    const v = callerContextSummary({ "x.run": "😀".repeat(100) }) as string;
    assert.equal(v, `x.run="${"😀".repeat(63)}`);
    assert.equal(Array.from(v.slice("x.run=".length)).length, 64);
    assert.ok(!v.endsWith("…"));
    // the cut can fall exactly on the closing quote or just before it
    const s63 = callerContextSummary({ "x.run": "a".repeat(62) }) as string; // 62 + 2 quotes = 64: whole
    assert.equal(s63, `x.run="${"a".repeat(62)}"`);
    const s64 = callerContextSummary({ "x.run": "a".repeat(63) }) as string; // 65 code points: the closing quote is cut
    assert.equal(s64, `x.run="${"a".repeat(63)}`);
  });
  test("whole cut: 256 code points kept, 257 becomes 255 + '…'; counts code points, not UTF-16 units", () => {
    const key = (n: number) => `x.${"a".repeat(n - 2)}`;
    const exact = callerContextSummary({ [key(256)]: 1 }) as string;
    assert.equal(Array.from(exact).length, 256);
    assert.ok(!exact.endsWith("…"));
    const cut = callerContextSummary({ [key(257)]: 1 }) as string;
    assert.equal(Array.from(cut).length, 256);
    assert.equal(cut, `${key(257).slice(0, 255)}…`);
    // 128 astral code points in the value-less key part would be 256 UTF-16 units but only 128 code points: never cut
    const astral = callerContextSummary({ [`x.${"😀".repeat(100)}`]: 1 }) as string;
    assert.equal(Array.from(astral).length, 102);
    assert.ok(astral.length > 102 && !astral.endsWith("…"));
    // a cut never splits a surrogate pair
    const split = callerContextSummary({ [`x.${"a".repeat(253)}😀😀`]: 1 }) as string; // 2 + 253 + 2 = 257 code points
    assert.equal(Array.from(split).length, 256);
    assert.ok(split.isWellFormed());
    assert.ok(split.endsWith("a…"));
  });
  test("many keys: cut at 256 with the ellipsis", () => {
    const o: Record<string, number> = {};
    for (let i = 0; i < 40; i++) o[`evolution.key_${String(i).padStart(2, "0")}`] = i;
    const s = callerContextSummary(o) as string;
    assert.equal(Array.from(s).length, 256);
    assert.ok(s.endsWith("…"));
    assert.ok(s.startsWith("evolution.key_00; evolution.key_01"));
  });
  test("inherited keys are not part of the context", () => {
    const o = Object.assign(Object.create({ inherited: 1 }), { "x.run": 1 });
    assert.equal(callerContextSummary(o), "x.run=1");
  });
});
