// DoS fuzz for sanitizeAgentDocument (C259, 0.1.34): a test, not a reviewer, should find the next slow shape.
//
// A seeded generator writes random documents (tag soup with html/body/svg/math/script/style/template/table/formatting elements
// and unknown names like `a;b`, attributes with duplicates, quotes, `<` and `>` in values, nesting and mis-nesting, comments,
// CDATA, doctypes) and repeats of the known DoS units (`<p>x`, `<html zN>`, `<div>`, `<a `, ...), up to the 2 MiB input cap.
// Every input must be prechecked and sanitised (or refused) within a per-input time cap, and sanitising twice must equal
// sanitising once.
//
// Time cap per input = 250 ms + 3 × (the slowest LINEAR rate measured on this machine at start) × input length. Why: the
// slowest benign paths are linear but not cheap (CSS text ≈ 0.4 µs per character, plain text and many small elements
// ≈ 0.1 µs per character on the dev Mac: a 2 MiB style sheet takes ~750 ms), so a flat cap would flag them at the size cap;
// 250 ms covers fixed costs and GC pauses on a shared CI machine, ×3 the noise. A super-linear shape (the quadratic attribute
// check, adoption, re-opened elements, deep nesting) misses this cap by orders of magnitude at a few hundred KB.
//
// It runs ALONE, after the unit tests (`npm test` = the unit tests, then `node --test test/agent-document.fuzz.ts`), because
// the cap is calibrated on this machine and parallel test files would skew it. The rate is the fastest of three runs per
// reference page; before an input fails, it is timed again and the rate is measured again, so a busy neighbour does not fail it.
//
// Env: TB_FUZZ_MS (run time; default 60 s when CI is set, 5 s otherwise), TB_FUZZ_SEED (base seed; input i uses seed + i,
// so a run is deterministic per seed). The seed is printed on every run; a failure prints the seed of the input, its length
// and the shortest failing prefix length.
import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENT_DOCUMENT_MAX_BYTES } from "@opt2-tealbrick/manifest";
import { agentDocumentPrecheck, agentDocumentStats, MAX_TAGS, sanitizeAgentDocument } from "../src/server/index.ts";

const RUN_MS = Number(process.env.TB_FUZZ_MS ?? (process.env.CI ? 60_000 : 5_000));
const BASE_SEED = Number(process.env.TB_FUZZ_SEED ?? 0x0c259);
const OPTS = [
  { allowScripts: true, assetPrefix: "/v/live-artifacts/_s/" },
  { allowScripts: false, assetPrefix: "/v/live-artifacts/_s/" },
];

const rngOf = (seed: number) => () => {
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};

const TAGS = ["html", "body", "head", "svg", "math", "mi", "script", "style", "template", "table", "tbody", "tr", "td", "caption", "colgroup", "col", "p", "div", "span", "b", "i", "a", "nobr", "font", "em", "s", "u", "strong", "code", "big", "small", "tt", "strike", "select", "option", "textarea", "title", "noscript", "xmp", "foreignObject", "desc", "annotation-xml", "li", "ul", "dl", "dt", "dd", "button", "img", "br", "frameset", "a;b", "x-y", "p<q", "set", "animate"];
const NAMES = ["a", "b", "id", "class", "style", "href", "src", "onclick", "x", "y", "data-tb-text", "z", "<", "=", "/", "encoding"];

function generate(seed: number): string {
  const r = rngOf(seed);
  const int = (n: number) => Math.floor(r() * n);
  const pick = <X>(a: readonly X[]): X => a[int(a.length)] as X;
  // target size: log-uniform from 64 bytes to the input cap
  const target = Math.min(AGENT_DOCUMENT_MAX_BYTES, Math.floor(64 * 2 ** (r() * 15)));
  let uniq = 0;
  const attrValue = (): string => {
    const v = pick(["", "1", "<b c d>", ">", "<", "a<b", "x y", "#f", "url(a)", "'", '"', "&lt;", "&#106;"]);
    const q = int(4);
    return q === 0 ? "" : q === 1 ? `=${v.replace(/[\s"'>]/g, "")}` : q === 2 ? `="${v.replace(/"/g, "")}"` : `='${v.replace(/'/g, "")}'`;
  };
  const attrs = (): string => {
    const big = r() < 0.03;
    const n = big ? int(3000) : int(6);
    let s = "";
    for (let k = 0; k < n; k++) s += `${pick([" ", " ", "/", "\n"])}${r() < 0.5 ? pick(NAMES) : `n${uniq++}`}${attrValue()}`;
    return s;
  };
  const piece = (): string => {
    switch (int(14)) {
      case 0:
      case 1:
      case 2:
        return `<${pick(TAGS)}${attrs()}${pick([">", ">", ">", "/>", " ", ""])}`;
      case 3:
      case 4:
        return `</${pick(TAGS)}${r() < 0.1 ? attrs() : ""}>`;
      case 5:
        return pick(["x", "text ", " ", "a<b ", "1 < 2 ", "i<n;", "&amp;", "\n"]);
      case 6:
        return pick(["<!--", "-->", "<!-->", "<!--->", "--!>", "<!-- c -->"]);
      case 7:
        return pick(["<![CDATA[", "]]>", "<!DOCTYPE html>", "<?x ?>", "<!x>"]);
      case 8:
        return pick(['"', "'", "=", ">", "<", "</", "/"]);
      case 9:
        return "<b><p>x</b>y</p>";
      case 10:
        return pick(["for(i=0;i<n;i++){", "}", "p{color:red}", "/* a<b */", "url(x)"]);
      default:
        return `<${pick(TAGS)}>`;
    }
  };
  // the repeat units of the known DoS shapes; {i} is a counter
  const UNITS = ["<p>x", "<div>", "</div>", "<html z{i}>", "<body z{i}>", "<a ", "<a <b ", 'x{i}="<b" ', "a{i} ", "<b>", "<i>", "<table>", "<td>", "<li>x", "<b><p>x</b>", "<template>", "<svg>", "<math><mi>", "<nobr>x", "<a>x<div>", "<p a{i} b{i}>x</p>", "<font><p>x", "x ", "<tr><td>", "<b a{i}>", "</b>", "<select><option>", "<br>", "a "];
  let out = "";
  const mode = int(4);
  if (mode !== 1) {
    // tag soup (all of the input when mode 0)
    const soupTarget = mode === 0 ? target : Math.min(target, 4096);
    while (out.length < soupTarget) out += piece();
  }
  if (mode !== 0) {
    // repeat body, possibly a mixed unit, possibly behind a prefix that opens formatting elements
    if (r() < 0.5) out += pick(["<p><b><i><u><s><em><strong><code>", "<p><b a0 a1 a2 a3>", "<table>", "<svg><style>", "<!-->", "<script>for(i=0;i<n;i++){", "<div><a;b ", "<b><div>", `${"<br>".repeat(int(5000))}<table>`]);
    const unit = r() < 0.7 ? pick(UNITS) : pick(UNITS) + pick(UNITS);
    let i = 0;
    while (out.length < target) out += unit.replaceAll("{i}", String(i++));
    if (r() < 0.3) out += pick(["</b>", "</a>", "</table>", "</p>", "</div>"]);
    if (mode === 3) for (let k = 0; k < 20; k++) out += piece();
  }
  while (Buffer.byteLength(out) > AGENT_DOCUMENT_MAX_BYTES) out = out.slice(0, Math.floor(out.length * 0.9));
  return out;
}

const timeOf = (html: string, opts: (typeof OPTS)[number]): number => {
  const t = performance.now();
  agentDocumentPrecheck(html);
  sanitizeAgentDocument(html, opts);
  return performance.now() - t;
};

/** The slowest linear rate (ms per character) of the known benign paths, on this machine. */
function calibrate(): number {
  const size = 256 * 1024;
  const pages = [`<style>${"p.a{color:red;margin:0 1px}".repeat(size / 27)}</style>`, `<p>${"a".repeat(size)}</p>`, `<ul>${"<li>x".repeat(size / 5)}`];
  let rate = 0;
  for (const p of pages) {
    const fastest = Math.min(...[0, 1, 2].map(() => timeOf(p, OPTS[0] as (typeof OPTS)[0])));
    rate = Math.max(rate, fastest / p.length);
  }
  return rate;
}

test(`DoS fuzz: every input is checked or refused within the time cap, and sanitising twice equals once (TB_FUZZ_MS, TB_FUZZ_SEED)`, () => {
  let rate = calibrate();
  const cap = (n: number) => 250 + 3 * rate * n;
  console.log(`# fuzz: seed ${BASE_SEED} (TB_FUZZ_SEED), run ${RUN_MS} ms (TB_FUZZ_MS), cap 250 ms + ${(3 * rate * 1e6).toFixed(0)} ns × chars (at 2 MiB: ${cap(AGENT_DOCUMENT_MAX_BYTES).toFixed(0)} ms)`);
  const start = performance.now();
  let tried = 0;
  let ok = 0;
  let worst = { ratio: 0, ms: 0, seed: 0, length: 0 };
  let maxMs = { ms: 0, seed: 0, length: 0 };
  for (let i = 0; performance.now() - start < RUN_MS; i++) {
    const seed = BASE_SEED + i;
    const html = generate(seed);
    const opts = OPTS[seed % 2] as (typeof OPTS)[number];
    let ms = timeOf(html, opts);
    // before failing: time it again and measure the machine again (a GC pause or a busy CI neighbour is not a DoS shape)
    if (ms > cap(html.length)) {
      ms = Math.min(ms, timeOf(html, opts));
      rate = Math.max(rate, calibrate());
    }
    if (ms > cap(html.length)) {
      // the shortest prefix that is still over the cap (binary search on the length)
      let lo = 0;
      let hi = html.length;
      while (hi - lo > Math.max(16, hi / 64)) {
        const mid = Math.floor((lo + hi) / 2);
        if (timeOf(html.slice(0, mid), opts) > cap(mid)) hi = mid;
        else lo = mid;
      }
      assert.fail(`fuzz input seed ${seed} (TB_FUZZ_SEED=${seed}, input #0) length ${html.length} took ${ms.toFixed(0)} ms > cap ${cap(html.length).toFixed(0)} ms; shortest failing prefix ≈ ${hi} chars: ${JSON.stringify(html.slice(0, 200))}`);
    }
    if (ms / cap(html.length) > worst.ratio) worst = { ratio: ms / cap(html.length), ms, seed, length: html.length };
    if (ms > maxMs.ms) maxMs = { ms, seed, length: html.length };
    const res = sanitizeAgentDocument(html, opts);
    if (res.ok) ok++;
    // idempotence holds for every output that is itself an acceptable input (at the size or tag cap the output may grow past it)
    const st = agentDocumentStats(res.html);
    if (Buffer.byteLength(res.html) <= AGENT_DOCUMENT_MAX_BYTES && st.tags <= MAX_TAGS) {
      const again = sanitizeAgentDocument(res.html, opts);
      assert.equal(again.html, res.html, `fuzz input seed ${seed}: sanitising twice differs from once`);
      assert.deepEqual(again.removed, [], `fuzz input seed ${seed}: the second pass removed something`);
    }
    tried++;
  }
  console.log(`# fuzz: ${tried} inputs (${ok} ok, ${tried - ok} refused); max ${maxMs.ms.toFixed(1)} ms (seed ${maxMs.seed}, ${maxMs.length} chars); closest to the cap ${(worst.ratio * 100).toFixed(0)}% (${worst.ms.toFixed(1)} ms, seed ${worst.seed}, ${worst.length} chars)`);
  assert.ok(tried > 0);
});
