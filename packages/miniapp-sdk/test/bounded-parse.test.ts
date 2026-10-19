// The bounded parse5 parse (src/server/bounded-parse.ts), ported from live-artifacts src/bounded-parse.ts @1d9c462 together with
// that repository's tests for it (test/sanitize.test.ts, "parse work bounded while the tree is built"). Behaviour only here; the
// wall-clock checks of the same shapes run alone in agent-document.timing.ts (C259 (c)).
import assert from "node:assert/strict";
import { describe, test } from "node:test";
import { AGENT_DOCUMENT_UNAVAILABLE_HTML, boundedParse, maxOutputLength, PARSE_ATTRIBUTE_BUDGET, PARSE_MAX_ATTRIBUTES, ParseLimitExceeded, sanitizeAgentDocument } from "../src/server/index.ts";

const attrs = (n: number): string => Array.from({ length: n }, (_, i) => `a${i}`).join(" ");
const BOUNDS = { maxDepth: 600, maxElements: 200_000 };
const parse = (html: string) => boundedParse(html, BOUNDS, { scriptingEnabled: true });
const sanitize = (html: string) => sanitizeAgentDocument(html, { allowScripts: true, assetPrefix: "/v/x/" });

// shapes that cost seconds of one CPU in plain parse5 (unbounded cost measured on the dev Mac at write time)
const REFUSED: [string, string][] = [
  ["<html z0><html z1>... x30,000 (12.5 s)", Array.from({ length: 30_000 }, (_, i) => `<html z${i}>`).join("")],
  ["<body z0><body z1>... x30,000 (12 s)", Array.from({ length: 30_000 }, (_, i) => `<body z${i}>`).join("")],
  ["<p><b a0..a255> + <p>x x20,000 (4.6 s)", `<p><b ${attrs(256)}>${"<p>x".repeat(20_000)}`],
  ["<p> + 8 formatting elements + <p>x x45,000 (0.6 s, 4 MB out)", `<p><b><i><u><s><em><strong><code><small>${"<p>x".repeat(45_000)}`],
  ["adoption agency detaching 99,000 children (12 s)", `<b><div>${"<br>".repeat(99_000)}</b>`],
  ["60,000 nested <div> (10 s)", "<div>".repeat(60_000)],
];

describe("bounded parse: shapes that make parse5 do far more work than the source shows", () => {
  for (const [what, html] of REFUSED) {
    test(`refused: ${what}`, () => {
      assert.throws(() => parse(html), ParseLimitExceeded);
      // the SDK entry points fail closed on the same page (the sanitiser's own caps may refuse it even earlier)
      assert.equal(sanitize(html).ok, false);
      assert.equal(sanitize(html).html, AGENT_DOCUMENT_UNAVAILABLE_HTML);
    });
  }

  test("text before an open table after 60,000 siblings is kept (parse5 searches from the start: 5 s)", () => {
    assert.doesNotThrow(() => parse(`${"<br>".repeat(60_000)}<table>${"a ".repeat(250_000)}`));
  });

  test("99,990 elements foster-parented before an open table are kept (1 s unbounded)", () => {
    assert.doesNotThrow(() => parse(`<table>${"<br>".repeat(99_990)}`));
  });

  test("quiet on good: unclosed formatting in every list item or paragraph (refused by a cap of 2 elements per tag)", () => {
    assert.equal(sanitize(`<ul>${"<li><b>item".repeat(2000)}`).ok, true);
    assert.equal(sanitize(`<ul>${"<li><b><i>item".repeat(1000)}`).ok, true);
    assert.equal(sanitize(`<p><b><i>Title${"<p>text".repeat(2000)}`).ok, true);
  });

  test("quiet on good: a 3,000-row table with text between rows, mis-nested formatting around 2,000 children, <html lang> twice", () => {
    const rows = Array.from({ length: 3000 }, (_, r) => `<tr><td class="c">${r}</td><td>v</td></tr>x`).join("");
    assert.match(sanitize(`<table>${rows}</table>`).html, /<td class="c">2999<\/td>/);
    assert.match(sanitize(`<b><div>${"<p>p</p>".repeat(2000)}</b>after`).html, /after/);
    assert.match(sanitize('<html lang="en"><html data-x="1"><body class="k">t').html, /<html lang="en" data-x="1">/);
  });

  test("output cap: a re-opened <b> with a 1,000-character attribute in 20,000 paragraphs is refused (20 MB of output)", () => {
    const html = `<p><b a="${"X".repeat(1000)}">t${"<p>t".repeat(20_000)}`;
    assert.equal(sanitize(html).ok, false);
    assert.equal(maxOutputLength(100), 100 + 1024 * 1024);
    assert.equal(maxOutputLength(1024 * 1024), 4 * 1024 * 1024);
  });

  test("exported limits: attributes per element 2,048 and a budget of 2,048 squared, as the precheck", () => {
    assert.equal(PARSE_MAX_ATTRIBUTES, 2048);
    assert.equal(PARSE_ATTRIBUTE_BUDGET, 2048 * 2048);
  });
});

describe("bounded parse: depth", () => {
  // depth of ELEMENTS (the bound's unit): a text or comment node is not a level
  const realDepth = (n: { childNodes?: object[]; content?: object }, d = 0): number => {
    let m = d;
    for (const c of n.childNodes ?? []) if ("childNodes" in c) m = Math.max(m, realDepth(c as never, d + 1));
    return n.content ? Math.max(m, realDepth(n.content as never, d + 1)) : m;
  };

  test("a subtree moved by the parser is measured again, so nothing deeper than the bound is accepted (S6 verifier F3)", () => {
    // found by the verifier: accepted at real depth 9 under maxDepth 8 when moved subtrees were not measured again
    const html = "<tr><a><li>x</li><em><b></p><p></i><foreignObject><p></br><a><li><i><td><p><br></foreignObject>";
    try {
      const doc = boundedParse(html, { maxDepth: 8, maxElements: 1000 }, { scriptingEnabled: true });
      assert.ok(realDepth(doc as never) <= 8, `accepted at real depth ${realDepth(doc as never)}`);
    } catch (e) {
      assert.ok(e instanceof ParseLimitExceeded, String(e));
    }
  });

  test("seeded run over mis-nested pages at a small bound: accepted pages are never deeper than the bound", () => {
    const parts = ["<b>", "</b>", "<i>", "</i>", "<a>", "</a>", "<div>", "<p>", "</p>", "<table>", "<tr>", "<td>", "x", "<li>", "<em>", "<foreignObject>", "</br>"];
    let seed = 11;
    const rnd = (n: number): number => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed % n;
    };
    let accepted = 0;
    for (let i = 0; i < 3000; i++) {
      const page = Array.from({ length: 10 + rnd(40) }, () => parts[rnd(parts.length)]).join("");
      try {
        const doc = boundedParse(page, { maxDepth: 12, maxElements: 10_000 }, { scriptingEnabled: true });
        accepted++;
        assert.ok(realDepth(doc as never) <= 12, `${page}: accepted at real depth ${realDepth(doc as never)}`);
      } catch (e) {
        assert.ok(e instanceof ParseLimitExceeded, String(e));
      }
    }
    assert.ok(accepted > 1000, `only ${accepted} accepted`);
  });

  test("template content is one level deeper than its template", () => {
    const at = (n: number) => `${"<div>".repeat(n)}<template><i>x</i></template>`;
    // html 1, body 2: n divs end at depth n + 2, the template n + 3, its content n + 4, <i> n + 5
    assert.doesNotThrow(() => boundedParse(at(5), { maxDepth: 10, maxElements: 100 }));
    assert.throws(() => boundedParse(at(6), { maxDepth: 10, maxElements: 100 }), ParseLimitExceeded);
  });
});
