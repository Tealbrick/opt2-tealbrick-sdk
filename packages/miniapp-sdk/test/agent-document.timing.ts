// Wall-clock tests for sanitizeAgentDocument (C259, 0.1.34). They run ALONE, after the unit tests (see the package test script),
// so parallel test files do not skew the ceilings: (a) worst cases just under the limits, (b) every bypass shape refused fast,
// and the LA S2 shapes against the same page without the trick.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { AGENT_DOCUMENT_MAX_BYTES, AGENT_DOCUMENT_RULES as R } from "@opt2-tealbrick/manifest";
import { AGENT_DOCUMENT_UNAVAILABLE_HTML, agentDocumentPrecheck, agentDocumentStats, MAX_ATTRIBUTE_BUDGET, MAX_ATTRIBUTES_PER_TAG, type SanitizeAgentDocumentResult, sanitizeAgentDocument } from "../src/server/index.ts";
import { names, bodyPage as page, variants } from "./agent-document-shapes.ts";

const PREFIX = "/v/live-artifacts/_s/";
const o = { allowScripts: false, assetPrefix: PREFIX };
const on = { allowScripts: true, assetPrefix: PREFIX };
const cost = (h: string) => agentDocumentStats(h).attributeCost;
const nest = (n: number) => page(`${"<div>".repeat(n)}x${"</div>".repeat(n)}`);
const inputOf = (file: string): string => readFileSync(new URL(`./vectors/agent-documents/${file}`, import.meta.url), "utf8").replace(/\n$/, "");

/** Median of a few runs (CI machines are shared: one slow run must not fail a ceiling). */
const medianMs = (f: () => void, runs = 5): number => {
  const ts: number[] = [];
  for (let r = 0; r < runs; r++) {
    const t = performance.now();
    f();
    ts.push(performance.now() - t);
  }
  ts.sort((a, b) => a - b);
  return ts[Math.floor(runs / 2)] as number;
};

function expectInertResult(r: SanitizeAgentDocumentResult, why: string): void {
  assert.equal(r.ok, false, why);
  assert.equal(r.html, AGENT_DOCUMENT_UNAVAILABLE_HTML, why);
  assert.equal(r.runsScripts, false, why);
  assert.deepEqual(r.removed, [], why);
}

describe("C259 timing (runs alone)", () => {
  test("(a) worst cases just under the limits sanitise end to end within a measured ceiling", () => {
    // Ceiling 50 ms per sanitizeAgentDocument call (median of 5): every page below needs three parse5 passes, two linear scans
    // and the walk. Measured on the dev Mac under load (median): 2,048 attributes 15-26 ms, depth 600 3-6 ms, 256 KiB rich page
    // 34 ms. The 1,024 × 64 page (cost exactly at the budget, 254 KB of attributes) is parse5-bound: 3 × 11 ms of parse plus
    // 2 × 3 ms of scan, 55 ms median measured; its ceiling is 120 ms. Over a ceiling = the bounds no longer bound the work.
    const rich = inputOf("benign-rich-document.html");
    const richBody = rich.slice(rich.indexOf("<body>") + 6, rich.lastIndexOf("</body>"));
    const kib256 = page(richBody.repeat(Math.floor((256 * 1024 - page("").length) / richBody.length)));
    const one = page(`<p ${names(MAX_ATTRIBUTES_PER_TAG)}>x</p>`);
    const many = page(`<p ${names(64)}>x</p>`.repeat(1024));
    assert.equal(cost(one), MAX_ATTRIBUTE_BUDGET);
    assert.equal(1024 * 64 * 64, MAX_ATTRIBUTE_BUDGET);
    assert.equal(cost(many), MAX_ATTRIBUTE_BUDGET, "1,024 × 64² is AT the budget, and the rule is <=");
    assert.ok(Buffer.byteLength(kib256) <= 256 * 1024 && Buffer.byteLength(kib256) > 250 * 1024);
    const cases: [string, string, number][] = [
      ["one tag × 2,048 attributes", one, 50],
      ["1,024 tags × 64 attributes", many, 120],
      [`depth ${R.maxDepth} (the limit)`, nest(R.maxDepth - 2), 50],
      ["256 KiB rich document", kib256, 50],
    ];
    for (const [name, h, ceiling] of cases) {
      const r = sanitizeAgentDocument(h, on);
      assert.equal(r.ok, true, name);
      const ms = medianMs(() => sanitizeAgentDocument(h, on));
      console.log(`# C259 (a) ${name}: ${ms.toFixed(1)} ms (ceiling ${ceiling} ms)`);
      assert.ok(ms < ceiling, `${name}: ${ms.toFixed(1)} ms`);
    }
  });

  test("(b) every bypass shape is refused in < 100 ms", () => {
    // Live Artifacts S8 shapes (copied from the LA re-check, 2026-10-18) and the C259 shapes. A refusal is one linear scan
    // (≈10 ns per character) or a parse stopped by the bounded adapter; measured: 1-20 ms each (dev Mac, median of 3).
    const N = 40_000;
    const la = (n: number) => Array.from({ length: n }, (_, i) => `a${i}`).join(" ");
    const shapes: Record<string, string> = {
      "S8 div <a <b x40000": `<div ${"<a ".repeat(N)}>x</div>`,
      "S8 div <a <b x40000 closed": `<div ${"<a <b ".repeat(N / 2)}>x</div>`,
      'S8 a x0="<b" x40000': `<a ${Array.from({ length: N }, (_, i) => `x${i}="<b"`).join(" ")}>x</a>`,
      "S8 a x0='<b' x40000": `<a ${Array.from({ length: N }, (_, i) => `x${i}='<b'`).join(" ")}>x</a>`,
      "S8 comment closer <!-->": `<!--><a ${la(36000)}>x</a>`,
      "S8 <!--->": `<!---><a ${la(36000)}>x</a>`,
      "S8 --!>": `<!-- x --!><a ${la(36000)}>x</a>`,
      "S8 svg style": `<svg><style><a ${la(36000)}></a></style></svg>`,
      "S8 math script": `<math><script><a ${la(36000)}></a></script></math>`,
      "S8 svg title": `<svg><title><a ${la(36000)}></a></title></svg>`,
      "S8 plain 36000 attrs": `<a ${la(36000)}>x</a>`,
      "S8 unbalanced quote comment": `<!-- <p x=' --><a ${la(36000)}>'>`,
      "S8 quoted >": `<a ${Array.from({ length: 20000 }, (_, i) => `a${i}=">"`).join(" ")}>x</a>`,
      // context-free by design (C259): 5,000 whitespace-separated tokens after `i<n` read as one tag over the 2,048 cap
      "S8 script i<n long": `<script>for(i=0;i<n;i++){${"x ".repeat(5000)}}</script>`,
      "<div><a;b + 36,000 attributes": `<div><a;b ${names(36_000)}>`,
      "60,000 nested divs": "<div>".repeat(60_000),
      "60,000 nested divs, closed": `${"<div>".repeat(60_000)}${"</div>".repeat(60_000)}`,
      "64 tags × 2,048 attributes (each under the cap)": Array.from({ length: 64 }, (_, k) => `<p ${names(2048).replace(/a/g, `t${k}_`)}>x</p>`).join(""),
      "<html z0><html z1>... × 30,000": Array.from({ length: 30_000 }, (_, i) => `<html z${i}>`).join(""),
      "<body z0><body z1>... × 30,000": `<body>${Array.from({ length: 30_000 }, (_, i) => `<body z${i}>`).join("")}`,
      "re-opened <b> with 256 attributes × 20,000": `<p><b ${names(256)}>${"<p>x".repeat(20_000)}`,
      "re-opened formatting elements, no attributes × 20,000": `<p><b><i><u><s><em><strong><code><small><big><tt><font><nobr><strike>${"<p>x".repeat(20_000)}`,
    };
    for (const v of variants) shapes[`variant: ${v.name}`] = page(v.make(names(36_000)));
    assert.ok(Object.keys(shapes).length >= 21 + 14 + 8);
    for (const [name, h] of Object.entries(shapes)) {
      assert.ok(Buffer.byteLength(h) <= AGENT_DOCUMENT_MAX_BYTES, name);
      for (const allowScripts of [true, false]) expectInertResult(sanitizeAgentDocument(h, { ...o, allowScripts }), name);
      const ms = medianMs(() => sanitizeAgentDocument(h, on), 3);
      assert.ok(ms < 100, `${name}: ${ms.toFixed(1)} ms`);
    }
  });

  test("(b) LA S2 shapes cost no more than twice the same page without the trick (linear; the parse is bounded)", () => {
    // 1. foster parenting before an open table: parse5's own adapter searches the reference from the start of the child list
    //    (27 s in plain parse5). The bounded adapter (bounded-parse.ts) searches from the end: the page is kept, linear.
    // 2. the adoption agency detaching 99,000 children one by one (2.9 s in plain parse5): every detach is charged the whole
    //    list against MAX_CHILD_WORK, so the page is refused when the work bound is reached (the cost of the bound itself, not
    //    of the page). It passed in the first 0.1.34 draft, which detached the leading children lazily; the shared bounded
    //    parse (live-artifacts logic) refuses it. Fail closed, stricter.
    // The ceiling is relative (2 × the same page without the trick + 50 ms), so a loaded CI machine slows both sides alike.
    const pairs: [string, string, string, boolean][] = [
      ["<br> × 99,990 + <table> + 'a ' × 700,000", `${"<br>".repeat(99_990)}<table>${"a ".repeat(700_000)}`, `${"<br>".repeat(99_990)}${"a ".repeat(700_000)}<table>`, true],
      ["<b><div> + <br> × 99,000 + </b>", `<b><div>${"<br>".repeat(99_000)}</b>`, `<b><div>${"<br>".repeat(99_000)}</div></b>`, false],
    ];
    for (const [name, shape, reference, ok] of pairs) {
      assert.ok(Buffer.byteLength(shape) <= AGENT_DOCUMENT_MAX_BYTES && agentDocumentPrecheck(shape), `${name}: within the pre-parse caps`);
      assert.equal(sanitizeAgentDocument(shape, on).ok, ok, name);
      assert.equal(sanitizeAgentDocument(reference, on).ok, true, `${name}: reference`);
      const ms = medianMs(() => sanitizeAgentDocument(shape, on), 3);
      const ref = medianMs(() => sanitizeAgentDocument(reference, on), 3);
      console.log(`# C259 (b) ${name}: ${ms.toFixed(1)} ms (reference without the trick ${ref.toFixed(1)} ms)`);
      assert.ok(ms < 2 * ref + 50, `${name}: ${ms.toFixed(1)} ms vs ${ref.toFixed(1)} ms`);
    }
  });
});
