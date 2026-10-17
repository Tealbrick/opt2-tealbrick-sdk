// sanitizeAgentDocument (C238, C230, C232). Corpus: test/vectors/agent-documents (one .html per case + cases.json).
//   fire on bad     every hostile case: the sanitised page has no construct the rule list matches
//   quiet on good   benign documents come back equal except the marker, with nothing removed
//   mutation guard  every hostile case RAW holds at least one such construct, and a sanitiser that removes nothing fails the
//                   very same checks. "0 removals" can therefore never pass by accident (A3).
//   property        sanitising twice equals sanitising once; a seeded fuzz of mixed corpus pieces always ends safe.
// The matcher below reads the shared rule list (AGENT_DOCUMENT_RULES) but is written separately from the sanitiser, with a
// plainer CSS reading (no comment handling, so it errs on the side of seeing a hit).
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { describe, test } from "node:test";
import { AGENT_DOCUMENT_MARKER, AGENT_DOCUMENT_MAX_BYTES, AGENT_DOCUMENT_UNAVAILABLE_TEXT, AGENT_DOCUMENT_RULES as R, viewerDocumentCspOk } from "@opt2-tealbrick/manifest";
import { parse, serialize, type DefaultTreeAdapterTypes as T } from "parse5";
import { AGENT_DOCUMENT_UNAVAILABLE_HTML, agentDocumentPrecheck, agentDocumentStats, fillTextSlots, MAX_ATTRIBUTES_PER_TAG, MAX_TAGS, NO_SCRIPT_CSP, type SanitizeAgentDocumentResult, sanitizeAgentDocument } from "../src/server/index.ts";

const DIR = new URL("./vectors/agent-documents/", import.meta.url);
interface Case {
  file: string;
  kind: "hostile" | "roundtrip" | "benign";
  allowScripts: boolean;
  absent: string[];
  present: string[];
  removed: string[];
  ok: boolean;
  note?: string;
}
const corpus = JSON.parse(readFileSync(new URL("cases.json", DIR), "utf8")) as { version: number; assetPrefix: string; cases: Case[] };
const PREFIX = corpus.assetPrefix;
const inputOf = (c: Case): string => readFileSync(new URL(c.file, DIR), "utf8").replace(/\n$/, "");
const optsOf = (c: Case) => ({ allowScripts: c.allowScripts, assetPrefix: PREFIX });

// ------------------------------------------------------------------------------------------- the independent matcher

function urlOk(value: string, tag: string, prefix: string): boolean {
  const stripped = value.replace(/[\t\n\r]/g, "");
  let a = 0;
  let b = stripped.length;
  while (a < b && stripped.charCodeAt(a) <= 0x20) a++;
  while (b > a && stripped.charCodeAt(b - 1) <= 0x20) b--;
  const v = stripped.slice(a, b);
  if (v.startsWith("#")) return true;
  if (/^data:image\/(?:png|gif|jpeg|webp|avif|bmp)[;,]/i.test(v) && !["a", "area", "script", "use"].includes(tag)) return true;
  return v.startsWith(prefix) && !/[\\\s]|\.\.|%2e|%5c/i.test(v.slice(prefix.length));
}

function cssHit(value: string): boolean {
  const decoded = value
    .replace(/\\([0-9a-f]{1,6})[ \t\r\n\f]?/gi, (_m, h: string) => String.fromCodePoint(Math.min(Number.parseInt(h, 16) || 0xfffd, 0x10ffff)))
    .replace(/\\(.)/gs, "$1")
    .toLowerCase()
    .replace(/url\(\s*(["']?)#[^)]*\)/g, "");
  // a function name is a whole identifier: `hurl(` is not `url(` (a vendor prefix, `-webkit-image-set(`, still is)
  return /(?<![a-z0-9_])(?:url|image|image-set|cross-fade|element|src)\(/.test(decoded) || decoded.includes("@import") || decoded.includes("expression(") || decoded.includes("-moz-binding");
}

function hits(html: string, allowScripts: boolean, prefix: string): string[] {
  const found = new Set<string>();
  const visit = (node: T.ParentNode): void => {
    for (const child of node.childNodes) {
      if (!("tagName" in child)) continue;
      const tag = child.tagName.toLowerCase();
      const attrs = child.attrs.map((a) => {
        const full = (a.prefix ? `${a.prefix}:${a.name}` : a.name).toLowerCase();
        return { full, local: full.slice(full.lastIndexOf(":") + 1), value: a.value };
      });
      const attr = (n: string) => attrs.find((a) => a.full === n)?.value;
      if (R.deniedElements.includes(tag)) found.add(`element:${tag}`);
      for (const d of R.deniedElementsWithAttribute) if (tag === d.element && attr(d.attribute) !== undefined) found.add(`element:${tag}-${d.attribute}`);
      if (!allowScripts && R.scriptElements.includes(tag)) found.add(`element:${tag}`);
      if (R.scriptElements.includes(tag) && R.deniedScriptTypes.includes((attr("type") ?? "").split(";")[0]?.replace(/^[\s\0-\x20]+|[\s\0-\x20]+$/g, "").toLowerCase() ?? "")) found.add(`element:${tag}-denied-type`);
      if (tag === "style") {
        if (child.childNodes.some((c) => c.nodeName !== "#text")) found.add("element:style-markup");
        if (cssHit(child.childNodes.map((c) => (c as T.TextNode).value ?? "").join(""))) found.add("css:style-element");
      }
      const smil = R.smilElements.includes(tag);
      if (smil) {
        const target = (attr(R.smilTargetAttribute) ?? "").replace(/\s+/g, "").toLowerCase();
        if (target.includes("href") || target.startsWith("on")) found.add(`element:${tag}-target`);
      }
      for (const a of attrs) {
        if (!allowScripts && a.full.startsWith("on")) found.add("attribute:event-handler");
        if (R.deniedAttributes.includes(a.full)) found.add(`attribute:${a.full}`);
        if (R.linkElements.includes(tag) && a.local === "target") found.add("attribute:target");
        if ((R.urlAttributes.includes(a.full) || R.urlAttributes.includes(a.local)) && !urlOk(a.value, tag, prefix)) found.add(`attribute:url:${a.local}`);
        if (R.srcsetAttributes.includes(a.local)) {
          for (const t of a.value.split(/\s+/)) {
            const u = t.replace(/^,+|,+$/g, "");
            if (u !== "" && !/^[0-9.]+[wxh]$/i.test(u) && !urlOk(u, tag, prefix)) found.add("attribute:url:srcset");
          }
        }
        if (R.styleAttributes.includes(a.full) && cssHit(a.value)) found.add("attribute:style");
        if ((R.cssValueAttributes.includes(a.full) || (smil && R.smilValueAttributes.includes(a.local))) && cssHit(a.value)) found.add(`attribute:css:${a.local}`);
      }
      visit(child);
      const content = (child as T.Template).content;
      if (tag === "template" && content) visit(content);
    }
  };
  for (const scripting of [true, false]) visit(parse(html, { scriptingEnabled: scripting }));
  return [...found].sort();
}

/** Independent reading of "can this page run script": a script element (any type, any namespace) or an on* attribute. */
function scriptsIn(html: string): boolean {
  let found = false;
  const visit = (node: T.ParentNode): void => {
    for (const child of node.childNodes) {
      if (!("tagName" in child)) continue;
      if (child.tagName.toLowerCase() === "script" || child.attrs.some((a) => a.name.toLowerCase().startsWith("on"))) found = true;
      visit(child);
      const content = (child as T.Template).content;
      if (content) visit(content);
    }
  };
  for (const scripting of [true, false]) visit(parse(html, { scriptingEnabled: scripting }));
  return found;
}

/** What a sanitiser that does nothing would return (parse, serialise, add the marker). */
function identity(html: string): SanitizeAgentDocumentResult {
  return { ok: true, html: AGENT_DOCUMENT_MARKER + serialize(parse(html, { scriptingEnabled: true })), runsScripts: false, removed: [] };
}

function verify(c: Case, input: string, res: SanitizeAgentDocumentResult, again: (html: string) => SanitizeAgentDocumentResult): void {
  if (c.kind === "roundtrip") {
    // a mutation trap: safe either way. Neutralised, or failed closed because the output would not survive a re-parse.
    if (!res.ok) assert.equal(res.html, AGENT_DOCUMENT_UNAVAILABLE_HTML, `${c.file}: inert page`);
  } else assert.equal(res.ok, c.ok, `${c.file}: ok`);
  assert.ok(res.html.startsWith(AGENT_DOCUMENT_MARKER), `${c.file}: marker first`);
  assert.equal(res.html.split(AGENT_DOCUMENT_MARKER).length, 2, `${c.file}: marker exactly once`);
  assert.deepEqual(hits(res.html, c.allowScripts, PREFIX), [], `${c.file}: constructs left in the output`);
  assert.equal(res.runsScripts, scriptsIn(res.html), `${c.file}: runsScripts matches the sanitised output`);
  if (!c.allowScripts) assert.equal(res.runsScripts, false, `${c.file}: no-scripts mode never runs scripts`);
  const low = res.html.toLowerCase();
  for (const a of c.absent) assert.ok(!low.includes(a.toLowerCase()), `${c.file}: output still has ${JSON.stringify(a)}`);
  for (const p of c.present) assert.ok(res.html.includes(p), `${c.file}: output lost ${JSON.stringify(p)}`);
  const kinds = res.removed.map((r) => r.kind);
  for (const k of c.removed) assert.ok(kinds.some((x) => x.startsWith(k)), `${c.file}: no removal of kind ${k} in ${JSON.stringify(kinds)}`);
  for (const r of res.removed) {
    assert.ok(Number.isInteger(r.count) && r.count > 0, `${c.file}: count`);
    assert.ok(!/canary|alert|prerender/i.test(r.kind) || r.kind.startsWith("element:"), `${c.file}: kind ${r.kind} must not carry content`);
  }
  if (c.kind === "benign") {
    assert.equal(res.html, AGENT_DOCUMENT_MARKER + input, `${c.file}: benign page must come back equal except the marker`);
    assert.deepEqual(res.removed, [], `${c.file}: nothing removed from a benign page`);
  }
  const second = again(res.html);
  assert.equal(second.html, res.html, `${c.file}: sanitising twice equals sanitising once`);
  assert.deepEqual(second.removed, [], `${c.file}: second pass removes nothing`);
}

describe("corpus", () => {
  test("cases.json lists exactly the .html files, each once", () => {
    const files = readdirSync(DIR).filter((f) => f.endsWith(".html")).sort();
    assert.deepEqual(corpus.cases.map((c) => c.file).sort(), files);
    assert.equal(corpus.version, 1);
    assert.ok(corpus.cases.filter((c) => c.kind === "hostile").length >= 80, "a broad hostile corpus");
    assert.ok(corpus.cases.filter((c) => c.kind === "benign").length >= 4);
    assert.ok(corpus.cases.filter((c) => c.kind === "roundtrip").length >= 5);
  });

  for (const c of corpus.cases) {
    test(`${c.kind}: ${c.file}${c.note ? ` (${c.note})` : ""}`, () => {
      const input = inputOf(c);
      const o = optsOf(c);
      const res = sanitizeAgentDocument(input, o);
      verify(c, input, res, (h) => sanitizeAgentDocument(h, o));
      if (c.kind === "benign") assert.deepEqual(hits(input, c.allowScripts, PREFIX), [], `${c.file}: a benign page must hold no construct`);
    });
  }
});

describe("mutation guard (A3): the corpus is hostile, and doing nothing fails it", () => {
  for (const c of corpus.cases.filter((x) => x.kind !== "benign")) {
    test(`raw page holds a matched construct, identity sanitiser fails: ${c.file}`, () => {
      const input = inputOf(c);
      let raw = hits(input, c.allowScripts, PREFIX);
      if (c.kind === "roundtrip") for (const a of [true, false]) for (const b of [true, false]) raw = raw.concat(hits(serialize(parse(input, { scriptingEnabled: a })), c.allowScripts, PREFIX), hits(serialize(parse(serialize(parse(input, { scriptingEnabled: a })), { scriptingEnabled: b })), c.allowScripts, PREFIX));
      assert.ok(raw.length > 0, `${c.file}: the raw page has no construct the rule list matches; the case proves nothing`);
      const id = identity(input);
      assert.throws(() => verify(c, input, id, () => id), `${c.file}: a sanitiser that removes nothing must fail this case`);
    });
  }

  test("kinds reported for the raw pages are the kinds the sanitiser removes (the rule list and the sanitiser agree)", () => {
    for (const c of corpus.cases.filter((x) => x.kind === "hostile")) {
      const res = sanitizeAgentDocument(inputOf(c), optsOf(c));
      assert.ok(res.removed.length > 0, `${c.file}: a hostile page must report at least one removal`);
    }
  });
});

describe("fail closed", () => {
  const o = { allowScripts: false, assetPrefix: PREFIX };
  const expectInert = (r: SanitizeAgentDocumentResult, why: string) => {
    assert.equal(r.ok, false, why);
    assert.equal(r.html, AGENT_DOCUMENT_UNAVAILABLE_HTML, why);
    assert.deepEqual(r.removed, [], why);
  };

  test("the inert document: marker, fixed sentence, no input, and a fixed point of the sanitiser", () => {
    assert.ok(AGENT_DOCUMENT_UNAVAILABLE_HTML.startsWith(AGENT_DOCUMENT_MARKER));
    assert.ok(AGENT_DOCUMENT_UNAVAILABLE_HTML.includes(AGENT_DOCUMENT_UNAVAILABLE_TEXT));
    assert.equal(AGENT_DOCUMENT_UNAVAILABLE_TEXT, "This file cannot be shown.");
    const r = sanitizeAgentDocument(AGENT_DOCUMENT_UNAVAILABLE_HTML, o);
    assert.equal(r.ok, true);
    assert.equal(r.html, AGENT_DOCUMENT_UNAVAILABLE_HTML);
    assert.deepEqual(hits(AGENT_DOCUMENT_UNAVAILABLE_HTML, false, PREFIX), []);
  });

  test("input over the cap (2 MiB of UTF-8 bytes) fails closed; at the cap it passes; bytes count, not characters", () => {
    assert.equal(AGENT_DOCUMENT_MAX_BYTES, 2 * 1024 * 1024);
    const head = "<!DOCTYPE html><html><head><title>t</title></head><body><p>";
    const tail = "</p></body></html>";
    const pad = (n: number, ch = "a") => head + ch.repeat(n) + tail;
    const atCap = pad(AGENT_DOCUMENT_MAX_BYTES - head.length - tail.length);
    assert.equal(Buffer.byteLength(atCap), AGENT_DOCUMENT_MAX_BYTES);
    const ok = sanitizeAgentDocument(atCap, o);
    assert.equal(ok.ok, true);
    assert.equal(ok.html, AGENT_DOCUMENT_MARKER + atCap);
    expectInert(sanitizeAgentDocument(`${atCap} `, o), "one byte over");
    // 1 MiB + 1 two-byte characters: under the cap by character count, over it by bytes
    expectInert(sanitizeAgentDocument(pad(1024 * 1024 + 1, "é"), o), "two-byte characters");
    expectInert(sanitizeAgentDocument(pad(700_000, "€"), o), "three-byte characters");
  });

  test("a tree deeper than the rule list allows fails closed; one inside the limit passes", () => {
    const nest = (n: number) => `<!DOCTYPE html><html><head><title>t</title></head><body>${"<div>".repeat(n)}x${"</div>".repeat(n)}</body></html>`;
    assert.equal(sanitizeAgentDocument(nest(100), o).ok, true);
    expectInert(sanitizeAgentDocument(nest(R.maxDepth + 50), o), "deep nesting");
    expectInert(sanitizeAgentDocument(nest(20_000), o), "very deep nesting (no stack overflow escapes)");
    expectInert(sanitizeAgentDocument(`<!DOCTYPE html><html><body>${"<span>".repeat(5000)}`, o), "very deep, never closed");
  });

  test("a tag with more attributes than the rule list allows fails closed at once (the parser is quadratic in them)", () => {
    const attrs = (n: number, quoted = false) => Array.from({ length: n }, (_, i) => (quoted ? `a${i}="1>"` : `a${i}=1`)).join(" ");
    const page = (inner: string) => `<!DOCTYPE html><html><head></head><body>${inner}</body></html>`;
    assert.equal(sanitizeAgentDocument(page(`<p ${attrs(R.maxAttributesPerTag)}>x</p>`), o).ok, true);
    expectInert(sanitizeAgentDocument(page(`<p ${attrs(R.maxAttributesPerTag + 1)}>x</p>`), o), "one over");
    expectInert(sanitizeAgentDocument(page(`<p ${attrs(60_000)}>x</p>`), o), "60 000 attributes");
    expectInert(sanitizeAgentDocument(page(`<p ${attrs(60_000, true)}>x</p>`), o), "a > inside quotes does not reset the count");
    expectInert(sanitizeAgentDocument(page(`</p ${attrs(60_000)}>`), o), "an end tag counts too");
    expectInert(sanitizeAgentDocument(page(`<p ${Array.from({ length: 60_000 }, (_, i) => `b${i}`).join("/")}>x</p>`), o), "slash separated, no values");
    // many tags with few attributes each are fine
    assert.equal(sanitizeAgentDocument(page("<i a=1 b=2 c=3>x</i>".repeat(5000)), o).ok, true);
  });

  test("bad options and non-string input fail closed, never throw", () => {
    const html = "<p>x</p>";
    for (const assetPrefix of ["", "/", "//", "v/x/_s/", "/v/x/_s", "/v//x/", "/../", "/v/../_s/", "/v/./x/", "/v/x y/", "/v/x\\y/", "https://h/", "/v/x/_s/?a=1", "/v/%2e%2e/", "/v/é/"]) {
      expectInert(sanitizeAgentDocument(html, { allowScripts: false, assetPrefix }), `prefix ${JSON.stringify(assetPrefix)}`);
    }
    for (const allowScripts of [undefined, null, 0, 1, "true", "false"]) expectInert(sanitizeAgentDocument(html, { allowScripts, assetPrefix: PREFIX } as never), `allowScripts ${String(allowScripts)}`);
    expectInert(sanitizeAgentDocument(html, undefined as never), "no options");
    expectInert(sanitizeAgentDocument(html, null as never), "null options");
    expectInert(sanitizeAgentDocument(html, { allowScripts: false } as never), "no prefix");
    for (const bad of [undefined, null, 12, {}, [], Buffer.from(html)]) expectInert(sanitizeAgentDocument(bad as never, o), `input ${typeof bad}`);
  });

  test("the inert page never echoes the input, whatever the input says", () => {
    const secret = `needle-${"x".repeat(8)}`;
    const r = sanitizeAgentDocument(`<p>${secret}</p>${"<div>".repeat(R.maxDepth + 10)}`, o);
    expectInert(r, "deep");
    assert.ok(!r.html.includes(secret));
  });

  test("an empty string and a fragment parse as a normal document", () => {
    const e = sanitizeAgentDocument("", o);
    assert.equal(e.ok, true);
    assert.equal(e.html, `${AGENT_DOCUMENT_MARKER}<html><head></head><body></body></html>`);
    assert.equal(sanitizeAgentDocument("<h1>Hi</h1>", o).html, `${AGENT_DOCUMENT_MARKER}<html><head></head><body><h1>Hi</h1></body></html>`);
  });
});

describe("rules and details", () => {
  const o = { allowScripts: false, assetPrefix: PREFIX };
  const body = (html: string, opts = o) => sanitizeAgentDocument(`<!DOCTYPE html><html><head></head><body>${html}</body></html>`, opts);

  test("the marker is not duplicated when the input already carries it, and is not trusted from the input", () => {
    const once = sanitizeAgentDocument(`${AGENT_DOCUMENT_MARKER}<!-- tb:sanitized v1 --><p>x</p>`, o);
    assert.equal(once.html.split(AGENT_DOCUMENT_MARKER).length, 2);
    const hostile = sanitizeAgentDocument(`${AGENT_DOCUMENT_MARKER}<link rel=prerender href=//x.invalid>`, o);
    assert.deepEqual(hits(hostile.html, false, PREFIX), []);
    assert.ok(hostile.removed.some((r) => r.kind === "element:link"));
  });

  test("removed counts are exact and sorted; they hold kinds, never content", () => {
    const r = body('<link rel=prefetch href="//a.invalid/1"><link rel=preload href="//a.invalid/2"><a href="//a.invalid/3" ping="//a.invalid/4">t</a>');
    assert.deepEqual(r.removed, [
      { kind: "attribute:ping", count: 1 },
      { kind: "attribute:url:href", count: 1 },
      { kind: "element:link", count: 2 },
    ]);
    assert.ok(!JSON.stringify(r.removed).includes("a.invalid"));
  });

  test("a link that loses href or target gets rel noreferrer noopener; a plain fragment link is left alone", () => {
    assert.ok(body('<a href="//x.invalid" rel="author">t</a>').html.includes('<a rel="noreferrer noopener">t</a>'));
    assert.ok(body('<a href="#x" target="_blank">t</a>').html.includes('<a href="#x" rel="noreferrer noopener">t</a>'));
    assert.ok(body('<a href="#x" rel="author">t</a>').html.includes('<a href="#x" rel="author">t</a>'));
  });

  test("allowed URL forms: fragment, raster data image, assetPrefix path; everything else goes", () => {
    const keep = ['href="#"', 'href="#a-b"', 'src="/v/live-artifacts/_s/a.png"', 'src="/v/live-artifacts/_s/d/e.png?v=2#f"', 'src="data:image/png;base64,iVBORw0KGgo="', 'src="data:image/webp,abc"'];
    for (const k of keep) {
      const tag = k.startsWith("href") ? "a" : "img";
      const r = body(`<${tag} ${k}>`);
      assert.ok(r.html.includes(k), `${k} -> ${r.html}`);
      assert.deepEqual(r.removed, [], k);
    }
    const drop = ['src="data:image/svg+xml,%3Csvg/%3E"', 'src="data:image/png"', 'src="data:text/html,x"', 'src="/other/a.png"', 'src="a.png"', 'src="//h.invalid/a.png"', 'src="https://h.invalid/a.png"', 'src="javascript:1"', 'src="blob:https://h.invalid/x"', 'src="file:///etc/passwd"', 'src="ftp://h.invalid/"', 'src=""'];
    for (const d of drop) {
      const r = body(`<img ${d}>`);
      assert.ok(!r.html.includes("src="), `${d} -> ${r.html}`);
      assert.deepEqual(r.removed, [{ kind: "attribute:url:src", count: 1 }], d);
    }
  });

  test("the written-back URL is the cleaned one the decision was made on", () => {
    const r = body('<a href=" \t#x\n">t</a><img src="/v/live-artifacts/_s/a\tb.png">');
    assert.ok(r.html.includes('href="#x"'));
    assert.ok(r.html.includes('src="/v/live-artifacts/_s/ab.png"'));
  });

  test("srcset: rebuilt from checked candidates only", () => {
    const good = body('<img srcset="/v/live-artifacts/_s/a.png 1x,   /v/live-artifacts/_s/b.png 2x ,data:image/gif;base64,R0lGODlhAQABAAAAACw= 3x">');
    assert.ok(good.html.includes('srcset="/v/live-artifacts/_s/a.png 1x, /v/live-artifacts/_s/b.png 2x, data:image/gif;base64,R0lGODlhAQABAAAAACw= 3x"'), good.html);
    assert.deepEqual(good.removed, []);
    for (const bad of ["", " ", ",", "//h.invalid/a.png", "/v/live-artifacts/_s/a.png 1x, //h.invalid/b.png 2x", "/v/live-artifacts/_s/a.png 1q", "/v/live-artifacts/_s/a.png 1x 2x 3y", "/v/live-artifacts/_s/a.png, //h.invalid/b.png"]) {
      const r = body(`<img srcset="${bad}">`);
      assert.ok(!r.html.includes("srcset"), `${JSON.stringify(bad)} -> ${r.html}`);
    }
  });

  test("allowScripts keeps scripts and handlers, drops network attributes; without it both go", () => {
    const html = '<script>go()</script><button onclick="go()">b</button><a href="javascript:go()">j</a>';
    const on = body(html, { allowScripts: true, assetPrefix: PREFIX });
    assert.ok(on.html.includes("<script>go()</script>") && on.html.includes('onclick="go()"'));
    assert.ok(!on.html.includes("javascript:"));
    const off = body(html);
    assert.ok(!off.html.includes("<script") && !off.html.includes("onclick") && !off.html.includes("javascript:"));
  });

  test("scripting is always parsed ON: noscript content cannot become a live link", () => {
    for (const allowScripts of [true, false]) {
      const r = body('<noscript><p title="</noscript><link rel=prerender href=\'http://x.invalid\'>"></p></noscript>', { allowScripts, assetPrefix: PREFIX });
      assert.equal(r.ok, true);
      assert.ok(!r.html.includes("noscript") && !r.html.includes("x.invalid"));
      for (const scripting of [true, false]) assert.deepEqual(hits(serialize(parse(r.html, { scriptingEnabled: scripting })), allowScripts, PREFIX), []);
    }
  });

  test("CSS: url(#fragment) stays, every other image function goes, quoting and spacing do not matter", () => {
    const keep = ["fill:url(#a)", "fill:url( #a )", 'fill:url("#a")', "fill:url('#a')", "fill:URL(#a-b_c.d)"];
    for (const k of keep) {
      const r = body(`<svg><rect style="${k.replace(/"/g, "&quot;")}"></rect></svg>`);
      assert.deepEqual(r.removed, [], k);
    }
    const drop = ["background:url(a.png)", "background:url(/v/live-artifacts/_s/a.png)", "background:url(#a), url(b)", "background:url(data:image/png;base64,AA)", "background:image-set(#a 1x)", "background:image(#a)", "background:cross-fade(red, blue)", "background:element(#a)", "background:src('#a')", "background:-webkit-image-set(#a 1x)", "background:-moz-element(#a)", "background:-x-cross-fade(red, blue)"];
    for (const d of drop) {
      const r = body(`<p style="color:red;${d};margin:0">t</p>`);
      assert.ok(r.html.includes('style="color:red;margin:0"'), `${d} -> ${r.html}`);
      assert.deepEqual(r.removed, [{ kind: "css:declaration", count: 1 }], d);
    }
  });

  test("CSS in <style>: a rule is kept without its bad declaration; @import and bad preludes go whole", () => {
    const r = body("<style>@import 'x.css';p{color:red;background:url(a)}@media screen{q{margin:0}}@media (a:url(b)){r{color:blue}}</style>");
    assert.ok(r.html.includes("<style>p{color:red;}@media screen{q{margin:0}}</style>"), r.html);
    assert.deepEqual(r.removed, [{ kind: "css:rule", count: 3 }]);
  });

  test("a style element with markup inside (svg namespace) is removed, an empty one is kept", () => {
    const r = body("<svg><style><a>x</a></style><style></style></svg>");
    assert.ok(r.html.includes("<style></style>") && !r.html.includes("<a>"));
    assert.deepEqual(r.removed, [{ kind: "element:style-markup", count: 1 }]);
  });

  test("attribute names that would not survive a re-parse are removed", () => {
    const r = body('<p "x=1 a<b=2 =3 ok="1">t</p>');
    assert.ok(r.html.includes('<p ok="1">t</p>'), r.html);
    assert.ok(r.removed.some((x) => x.kind === "attribute:invalid-name"));
  });

  test("the sanitiser is a pure function of its input", () => {
    const c = corpus.cases.find((x) => x.kind === "benign");
    assert.ok(c);
    const a = sanitizeAgentDocument(inputOf(c), optsOf(c));
    const b = sanitizeAgentDocument(inputOf(c), optsOf(c));
    assert.deepEqual(a, b);
    a.removed.push({ kind: "x", count: 1 });
    assert.deepEqual(sanitizeAgentDocument(inputOf(c), optsOf(c)).removed, []);
  });
});

describe("runsScripts, NO_SCRIPT_CSP, text slots (Live Artifacts S7)", () => {
  const page = (b: string) => `<!DOCTYPE html><html><head></head><body>${b}</body></html>`;
  const on = { allowScripts: true, assetPrefix: PREFIX };
  const off = { allowScripts: false, assetPrefix: PREFIX };

  test("runsScripts: false for a script-free page, true for any script element or inline handler", () => {
    const free = '<h1>t</h1><a href="#x">x</a><svg><rect fill="red"></rect></svg><style>p{color:red}</style><template><p>x</p></template>';
    for (const o of [on, off]) {
      const r = sanitizeAgentDocument(page(free), o);
      assert.equal(r.ok, true);
      assert.equal(r.runsScripts, false);
    }
    assert.equal(sanitizeAgentDocument(page('<script type="application/json">{"a":1}</script>'), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page('<script type="application/ld+json">{}</script>'), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page("<script>1</script>"), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page('<button onclick="go()">b</button>'), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page('<svg><script href="#x"></script></svg>'), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page('<template><p onclick="x()">t</p></template>'), on).runsScripts, true);
    // a script that the sanitiser removes does not count
    assert.equal(sanitizeAgentDocument(page('<noscript><script>1</script></noscript>'), on).runsScripts, false);
  });

  test("runsScripts is computed from the sanitised output: removed speculation rules and import maps never count (C238)", () => {
    const rules = '{"prerender":[{"source":"list","urls":["https://x.test/"]}]}';
    const only = [`<script type="speculationrules">${rules}</script>`, `<script type="importmap">{"imports":{}}</script>`, `<svg><script type="SpeculationRules">${rules}</script></svg>`, `<template><script type=" speculationrules ;a">${rules}</script></template>`, `<script type="speculation&#114;ules">${rules}</script>`];
    for (const o of [on, off]) {
      for (const s of only) {
        const r = sanitizeAgentDocument(page(s), o);
        assert.equal(r.ok, true, s);
        assert.equal(r.runsScripts, false, `${s}: the only script was removed`);
        assert.ok(!/<script|speculationrules|importmap/i.test(r.html), r.html);
        assert.ok(r.removed.some((x) => x.kind.startsWith("element:script-")), JSON.stringify(r.removed));
      }
      const all = sanitizeAgentDocument(page(only.join("")), o);
      assert.equal(all.runsScripts, false);
    }
    // a page that keeps another script still reports true; the denied one is gone
    const mixed = sanitizeAgentDocument(page(`<script type="speculationrules">${rules}</script><script>go()</script>`), on);
    assert.equal(mixed.runsScripts, true);
    assert.ok(mixed.html.includes("<script>go()</script>") && !mixed.html.includes("speculationrules"));
    // kinds: counted by name, never content
    assert.deepEqual(sanitizeAgentDocument(page(`<script type="speculationrules">${rules}</script><script type="importmap">{}</script><script type="importmap">{}</script>`), on).removed, [{ kind: "element:script-importmap", count: 2 }, { kind: "element:script-speculationrules", count: 1 }]);
    // a look-alike type is an ordinary script: it follows allowScripts
    assert.equal(sanitizeAgentDocument(page('<script type="text/speculationrules">1</script>'), on).runsScripts, true);
    assert.equal(sanitizeAgentDocument(page('<script type="text/speculationrules">1</script>'), off).runsScripts, false);
  });

  test("assetPrefix paths and raster data: images stay, other relative URLs go (Live Artifacts assets, C230)", () => {
    const o = { allowScripts: true, assetPrefix: PREFIX };
    const r = sanitizeAgentDocument(page(`<script src="${PREFIX}app.js"></script><a href="${PREFIX}style.css">css</a><img src="${PREFIX}logo.png"><img src="data:image/png;base64,iVBORw0KGgo=">`), o);
    for (const k of [`<script src="${PREFIX}app.js"></script>`, `<a href="${PREFIX}style.css">css</a>`, `<img src="${PREFIX}logo.png">`, '<img src="data:image/png;base64,iVBORw0KGgo=">']) assert.ok(r.html.includes(k), `${k} -> ${r.html}`);
    assert.deepEqual(r.removed, []);
    // never svg+xml, never on an anchor; other relative forms are refused
    for (const bad of ['<img src="data:image/svg+xml;base64,PHN2Zy8+">', '<a href="data:image/png;base64,iVBORw0KGgo=">x</a>', '<img src="logo.png">', '<img src="./logo.png">', '<img src="../logo.png">', '<img src="/_s/logo.png">', '<a href="style.css">x</a>', '<script src="app.js"></script>', '<img src="/v/other/_s/logo.png">']) {
      const x = sanitizeAgentDocument(page(bad), o);
      assert.ok(!/(?:src|href)=/.test(x.html.replace(/<!--.*?-->/, "")), `${bad} -> ${x.html}`);
      assert.ok(x.removed.some((y) => y.kind.startsWith("attribute:url:")), bad);
    }
    // a stylesheet <link> is removed whatever its href (design: link, every rel), so a stylesheet cannot be loaded that way
    const link = sanitizeAgentDocument(page(`<link rel="stylesheet" href="${PREFIX}style.css">`), o);
    assert.ok(!link.html.includes("<link") && link.removed.some((y) => y.kind === "element:link"));
  });

  test("no-scripts mode removes every script element (JSON too) and every on* attribute: runsScripts is always false", () => {
    const r = sanitizeAgentDocument(page('<script type="application/json">{"a":1}</script><script>1</script><p onclick="a()" ONMOUSEOVER="b()">t</p><svg onload="c()"><script>2</script></svg>'), off);
    assert.equal(r.ok, true);
    assert.equal(r.runsScripts, false);
    assert.ok(!/<script|onclick|onmouseover|onload/i.test(r.html), r.html);
    assert.equal(sanitizeAgentDocument("<p>x</p>".repeat(3) + "x".repeat(R.maxDepth * 1000), off).runsScripts, false);
    assert.equal(sanitizeAgentDocument(page("<div>".repeat(R.maxDepth + 5)), off).runsScripts, false, "the inert page runs nothing");
  });

  test("NO_SCRIPT_CSP: forbids script, passes the manifest _d gate, with or without frame-ancestors", () => {
    assert.equal(NO_SCRIPT_CSP, "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data: 'self'; sandbox");
    assert.equal(viewerDocumentCspOk([NO_SCRIPT_CSP]), true);
    assert.equal(viewerDocumentCspOk([`${NO_SCRIPT_CSP}; frame-ancestors https://v.example https://b.example`]), true);
    assert.ok(!/allow-/.test(NO_SCRIPT_CSP) && NO_SCRIPT_CSP.includes("script-src 'none'"));
    assert.ok(!NO_SCRIPT_CSP.includes("unsafe-eval") && !/script-src[^;]*unsafe-inline/.test(NO_SCRIPT_CSP));
  });

  test("data-tb-text: a valid key keeps attribute and element, an invalid one drops only the attribute", () => {
    for (const key of ["title", "a.b", "a_1.b_2.c3", "x9"]) {
      const r = sanitizeAgentDocument(page(`<h1 data-tb-text="${key}" class="k">placeholder</h1>`), off);
      assert.ok(r.html.includes(`<h1 data-tb-text="${key}" class="k">placeholder</h1>`), r.html);
      assert.deepEqual(r.removed, []);
    }
    for (const key of ["", "A", "a.B", "1a", "a..b", "a.", ".a", "a-b", "a b", "a.b\n", "a\nb", "k\u00e9y", "a.b/c", "<x>"]) {
      const r = sanitizeAgentDocument(page(`<h1 data-tb-text="${key.replace(/</g, "&lt;")}">placeholder</h1>`), off);
      assert.ok(r.html.includes("<h1>placeholder</h1>"), `${JSON.stringify(key)} -> ${r.html}`);
      assert.deepEqual(r.removed, [{ kind: "attribute:data-tb-text", count: 1 }], JSON.stringify(key));
    }
    assert.ok(sanitizeAgentDocument(page('<p DATA-TB-TEXT="a.b">x</p>'), off).html.includes('<p data-tb-text="a.b">x</p>'));
  });

  test("fillTextSlots: a hostile value is text, never markup; the page stays sanitised", () => {
    const sane = sanitizeAgentDocument(page('<h1 data-tb-text="t">x</h1><p data-tb-text="a.b"><b>old</b></p><span data-tb-text="missing">keep</span><img data-tb-text="t" src="#x">'), off);
    const hostile = `</p><img src=x onerror=alert(1)><script>alert(2)</script><link rel=prerender href=//h.invalid/> & "q" 'a' <!-- c --> </title></style>`;
    const out = fillTextSlots(sane.html, { t: hostile, "a.b": "<b>x</b>" });
    assert.ok(out.startsWith(AGENT_DOCUMENT_MARKER));
    assert.ok(out.includes("<h1 data-tb-text=\"t\">&lt;/p&gt;&lt;img src=x onerror=alert(1)&gt;&lt;script&gt;alert(2)&lt;/script&gt;"), out);
    assert.ok(out.includes('<p data-tb-text="a.b">&lt;b&gt;x&lt;/b&gt;</p>'));
    assert.ok(out.includes('<span data-tb-text="missing">keep</span>'), "a key without a value is left alone");
    assert.ok(out.includes('<img data-tb-text="t" src="#x">'), "a void element takes no text");
    // re-parse: still no construct, no script, and it equals what a second sanitiser pass gives
    assert.deepEqual(hits(out, false, PREFIX), []);
    assert.equal(scriptsIn(out), false);
    assert.equal(sanitizeAgentDocument(out, off).html, out);
    // the text comes back out of the DOM as the exact value
    const h1 = ((parse(out).childNodes.find((n) => "tagName" in n) as T.Element).childNodes[1] as T.Element).childNodes[0] as T.Element;
    assert.equal(h1.tagName, "h1");
    assert.equal(h1.childNodes.length, 1);
    assert.equal((h1.childNodes[0] as T.TextNode).value, hostile);
  });

  test("fillTextSlots: code and raw-text elements are never filled; values other than strings are written as text", () => {
    const sane = sanitizeAgentDocument(page('<style data-tb-text="s">p{color:red}</style><svg><style data-tb-text="s"></style><text data-tb-text="n">0</text></svg><template data-tb-text="s"><i data-tb-text="n">0</i></template><textarea data-tb-text="s"></textarea><title data-tb-text="s"></title>'), off);
    const out = fillTextSlots(sane.html, { s: "</textarea></title></style><img src=//h.invalid/x>", n: 42 });
    assert.ok(out.includes("<style data-tb-text=\"s\">p{color:red}</style>"), out);
    assert.ok(out.includes("<text data-tb-text=\"n\">42</text>"));
    assert.ok(out.includes("<i data-tb-text=\"n\">42</i>"), "template content is filled");
    assert.ok(out.includes('<textarea data-tb-text="s">&lt;/textarea&gt;&lt;/title&gt;&lt;/style&gt;&lt;img src=//h.invalid/x&gt;</textarea>'));
    assert.deepEqual(hits(out, false, PREFIX), []);
    assert.equal(sanitizeAgentDocument(out, off).html, out);
    // keys that are inherited object members or not valid keys are not looked up
    assert.equal(fillTextSlots(sanitizeAgentDocument(page('<p data-tb-text="constructor">x</p>'), off).html, {}).includes(">x</p>"), true);
  });
});

describe("pre-parse caps (L39): the HTML parser is quadratic in the attributes of one tag, so the caps run first", () => {
  const o = { allowScripts: false, assetPrefix: PREFIX };
  const names = (n: number) => Array.from({ length: n }, (_, i) => `a${i.toString(36)}`).join(" ");
  /** wraps `attrs` in a tag the parser really reads as a tag, behind each hiding trick */
  const variants: { name: string; real: boolean; make: (attrs: string) => string }[] = [
    { name: "plain", real: true, make: (a) => `<p ${a}>x</p>` },
    { name: "end tag", real: false, make: (a) => `</p ${a}>` },
    { name: "unterminated at the end of the file", real: true, make: (a) => `<p ${a}` },
    { name: "after <!-->", real: true, make: (a) => `<!--><p ${a}>x</p>` },
    { name: "after <!--->", real: true, make: (a) => `<!---><p ${a}>x</p>` },
    { name: "after a --!> closer", real: true, make: (a) => `<!-- c --!><p ${a}>x</p>` },
    { name: "after a --!> closer with a decoy tag", real: true, make: (a) => `<!-- <q z=" --!><p ${a}>x</p>` },
    { name: "svg style", real: true, make: (a) => `<svg><style><p ${a}>x</p></style></svg>` },
    { name: "svg title", real: true, make: (a) => `<svg><title><p ${a}>x</p></title></svg>` },
    { name: "svg desc", real: true, make: (a) => `<svg><desc><p ${a}>x</p></desc></svg>` },
    { name: "math title", real: true, make: (a) => `<math><title><p ${a}>x</p></title></math>` },
    { name: "math annotation-xml html", real: true, make: (a) => `<math><annotation-xml encoding="text/html"><p ${a}>x</p></annotation-xml></math>` },
    { name: "after a quoted >", real: true, make: (a) => `<p z=">" ${a}>x</p>` },
    { name: "after a quoted > behind a comment decoy", real: true, make: (a) => `<!-- <x z=" --><p y=">" ${a}>x</p>` },
    { name: "after a quoted < and >", real: true, make: (a) => `<p z='<>' ${a}>x</p>` },
    { name: "unquoted values", real: true, make: (a) => `<p ${a.replace(/ /g, "=1 ")}>x</p>` },
    { name: "slash separated", real: true, make: (a) => `<p ${a.replace(/ /g, "/")}>x</p>` },
    { name: "inside a comment", real: false, make: (a) => `<!-- <p ${a}> -->` },
    { name: "inside a textarea", real: false, make: (a) => `<textarea><p ${a}></textarea>` },
    { name: "inside a script", real: false, make: (a) => `<script><p ${a}></script>` },
    { name: "inside a CDATA section", real: false, make: (a) => `<svg><![CDATA[<p ${a}>]]></svg>` },
  ];
  const page = (inner: string) => `<!DOCTYPE html><html><head></head><body>${inner}</body></html>`;
  const counting = () => {
    const calls = { n: 0 };
    return { calls, deps: { parse: ((...a: Parameters<typeof parse>) => {
      calls.n++;
      return parse(...a);
    }) as typeof parse } };
  };
  const maxElementAttrs = (html: string): number => {
    let max = 0;
    const visit = (node: T.ParentNode): void => {
      for (const c of node.childNodes) {
        if (!("tagName" in c)) continue;
        max = Math.max(max, c.attrs.length);
        visit(c);
        if ((c as T.Template).content) visit((c as T.Template).content);
      }
    };
    for (const scripting of [true, false]) visit(parse(html, { scriptingEnabled: scripting }));
    return max;
  };

  test("a 36 000 attribute tag, in every hiding variant, fails closed and no parser call is made", () => {
    for (const v of variants) {
      const html = page(v.make(names(36_000)));
      assert.equal(agentDocumentPrecheck(html), false, v.name);
      const { calls, deps } = counting();
      for (const allowScripts of [false, true]) expectInertResult(sanitizeAgentDocument(html, { ...o, allowScripts }, deps), v.name);
      expectInertResult({ ok: false, html: fillTextSlots(html, { a: "b" }, deps), runsScripts: false, removed: [] }, `${v.name} (fillTextSlots)`);
      assert.equal(calls.n, 0, `${v.name}: parse5 must never see a page over the caps`);
    }
  });

  test("the variants are real: at 300 attributes the parser itself reads a tag over the cap (and the count is never below it)", () => {
    for (const v of variants.filter((x) => x.real)) {
      const html = page(v.make(names(300)));
      const real = maxElementAttrs(html);
      assert.ok(real > MAX_ATTRIBUTES_PER_TAG, `${v.name}: parse5 reads ${real} attributes; the variant does not hide a real tag`);
      assert.ok(agentDocumentStats(html).maxAttributes >= real, `${v.name}: the pre-parse count is below the parser's`);
      assert.equal(agentDocumentPrecheck(html), false, v.name);
    }
  });

  test("soundness: on random tag soup the pre-parse count is never below what the parser reads", () => {
    let seed = 12345;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) & 0x7fffffff;
      return seed / 0x7fffffff;
    };
    const bits = ["<", "<p ", "<q ", "</p ", "<svg>", "<math>", "<style>", "</style>", "<title>", "<textarea>", "<!--", "-->", "--!>", "<!-->", "<!--->", "<![CDATA[", "]]>", ">", '"', "'", "=", "/", " ", "\n", "x=", "y", "<script>", "<template>", "<noscript>", "<annotation-xml encoding=text/html>", "<foreignObject>", "<desc>"];
    let n = 0;
    for (let doc = 0; doc < 400; doc++) {
      let html = "";
      const parts = 5 + Math.floor(rnd() * 80);
      for (let i = 0; i < parts; i++) {
        const b = bits[Math.floor(rnd() * bits.length)] as string;
        html += rnd() < 0.3 ? `${b}n${n++}=${n++} n${n++} ` : b;
        if (rnd() < 0.5) html += `m${n++} `;
      }
      const real = maxElementAttrs(html);
      const counted = agentDocumentStats(html).maxAttributes;
      assert.ok(counted >= real, `doc #${doc}: counted ${counted} < parser ${real}: ${JSON.stringify(html).slice(0, 300)}`);
    }
  });

  test("agentDocumentStats: attribute and tag counts", () => {
    const m = (h: string) => agentDocumentStats(h).maxAttributes;
    assert.equal(m('<p a b=1 c="x y" d=\'z\'>'), 4);
    assert.equal(m('<p a=">" b>'), 2);
    assert.equal(m("</p a b>"), 2);
    assert.equal(m("<p/a/b>"), 2);
    assert.equal(m("<p a = 1 b>"), 2);
    assert.equal(m('<p a="1"b="2"c=3>'), 3);
    assert.equal(m("<p =a b>"), 2);
    assert.equal(m("<!-- <p a b c> -->"), 3);
    assert.equal(m("text only, no tags"), 0);
    assert.equal(m("<p><q a></q></p>"), 1);
    assert.deepEqual(agentDocumentStats("<!DOCTYPE html><p></p><!-- x --><? y ?> 1 < 2 <3"), { maxAttributes: 0, tags: 4 });
    // attributes after a long quoted value still count
    assert.equal(m(`<p z="${"q ".repeat(5000)}" ${names(20)}>`), 21);
  });

  test("benign large pages just under the caps pass untouched (quiet on good)", () => {
    const attrs = Array.from({ length: MAX_ATTRIBUTES_PER_TAG }, (_, i) => `a${i}="1"`).join(" ");
    const base = page(`<p ${attrs}>x</p>`);
    assert.equal(agentDocumentStats(base).maxAttributes, MAX_ATTRIBUTES_PER_TAG);
    const r = sanitizeAgentDocument(base, o);
    assert.equal(r.ok, true);
    assert.equal(r.html, AGENT_DOCUMENT_MARKER + base);
    assert.deepEqual(r.removed, []);
    // exactly MAX_TAGS tags
    const baseTags = agentDocumentStats(page("")).tags;
    const pairs = Math.floor((MAX_TAGS - baseTags) / 2);
    const odd = (MAX_TAGS - baseTags) % 2 === 1;
    const big = page(`${"<i>x</i>".repeat(pairs)}${odd ? "<br>" : ""}`);
    assert.equal(agentDocumentStats(big).tags, MAX_TAGS);
    assert.ok(Buffer.byteLength(big) < AGENT_DOCUMENT_MAX_BYTES);
    const rb = sanitizeAgentDocument(big, o);
    assert.equal(rb.ok, true);
    assert.equal(rb.html, AGENT_DOCUMENT_MARKER + big);
    // one over each cap
    expectInertResult(sanitizeAgentDocument(page(`<p ${attrs} extra="1">x</p>`), o), "257 attributes");
    expectInertResult(sanitizeAgentDocument(`${big}<b>`, o), "MAX_TAGS + 1");
    // the real parser is reached for a page under the caps: three passes
    const { calls, deps } = counting();
    assert.equal(sanitizeAgentDocument(base, o, deps).ok, true);
    assert.equal(calls.n, 3);
    const filled = fillTextSlots(r.html, {}, deps);
    assert.equal(calls.n, 4);
    assert.equal(filled, r.html);
  });

  test("fillTextSlots applies the same caps and size limit", () => {
    expectInertResult({ ok: false, html: fillTextSlots(page(`<p ${names(MAX_ATTRIBUTES_PER_TAG + 1)}>`), {}), runsScripts: false, removed: [] }, "attributes");
    assert.equal(fillTextSlots("<p>".repeat(MAX_TAGS + 1), {}), AGENT_DOCUMENT_UNAVAILABLE_HTML);
    assert.equal(fillTextSlots("a".repeat(AGENT_DOCUMENT_MAX_BYTES + 1), {}), AGENT_DOCUMENT_UNAVAILABLE_HTML);
    assert.equal(fillTextSlots(5 as never, {}), AGENT_DOCUMENT_UNAVAILABLE_HTML);
  });

  test("no wall-clock race: a refused page costs one linear pass and zero parses, whatever its size", () => {
    const { calls, deps } = counting();
    const worst = `<!DOCTYPE html>${"<p<p<p<p ".repeat(200_000)}`; // 1.8 MB of nested candidate starts
    assert.ok(Buffer.byteLength(worst) < AGENT_DOCUMENT_MAX_BYTES);
    expectInertResult(sanitizeAgentDocument(worst, o, deps), "nested candidate starts");
    assert.equal(calls.n, 0);
  });
});

function expectInertResult(r: SanitizeAgentDocumentResult, why: string): void {
  assert.equal(r.ok, false, why);
  assert.equal(r.html, AGENT_DOCUMENT_UNAVAILABLE_HTML, why);
  assert.equal(r.runsScripts, false, why);
  assert.deepEqual(r.removed, [], why);
}

describe("package boundary", () => {
  test("server entry exports it; the browser client entry never touches the sanitiser or parse5", () => {
    const walk = (dir: URL): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(new URL(`${e.name}/`, dir)) : [new URL(e.name, dir).pathname]));
    for (const f of walk(new URL("../src/client/", import.meta.url))) {
      const text = readFileSync(f, "utf8");
      assert.ok(!/parse5|agent-document|sanitizeAgentDocument/.test(text), `${f} must not reference the sanitiser`);
    }
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { dependencies: Record<string, string> };
    assert.match(pkg.dependencies.parse5 ?? "", /^\d+\.\d+\.\d+$/, "parse5 is pinned to an exact version");
  });
});

describe("property: sanitising twice equals sanitising once; the output is always safe", () => {
  // small seeded generator (mulberry32)
  const rng = (seed: number) => () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pieces = corpus.cases.flatMap((c) => inputOf(c).split(/(?=<)/).filter((p) => p.length < 400));
  const noise = ["<", ">", '"', "'", "&#x3c;", "&#106;", "&lt;", "</", "<!--", "-->", "<![CDATA[", "]]>", "\t", "\n", "\u0000", "\\", "/*", "*/", "url(", "(", ")", ";", "{", "}", "=", "<svg>", "<math>", "<template>", "</template>", "<noscript>", "</noscript>", "<style>", "</style>", "<table>", "<select>", "<textarea>", "</textarea>", "<xmp>", "<title>"];

  for (const allowScripts of [false, true]) {
    test(`seeded fuzz of mixed corpus pieces (allowScripts ${allowScripts}): 600 inputs`, () => {
      const r = rng(allowScripts ? 7 : 11);
      const pick = <X>(a: X[]): X => a[Math.floor(r() * a.length)] as X;
      let ok = 0;
      for (let n = 0; n < 600; n++) {
        let html = "";
        const parts = 1 + Math.floor(r() * 9);
        for (let i = 0; i < parts; i++) {
          let p = pick(pieces);
          const m = r();
          if (m < 0.15) p = p.toUpperCase();
          else if (m < 0.3) p = p.slice(0, Math.floor(r() * p.length));
          else if (m < 0.45) {
            const at = Math.floor(r() * p.length);
            p = p.slice(0, at) + pick(noise) + p.slice(at);
          }
          html += p;
          if (r() < 0.3) html += pick(noise);
        }
        const o = { allowScripts, assetPrefix: PREFIX };
        const res = sanitizeAgentDocument(html, o);
        assert.ok(res.html.startsWith(AGENT_DOCUMENT_MARKER));
        const second = sanitizeAgentDocument(res.html, o);
        assert.equal(second.html, res.html, `not idempotent for input #${n}`);
        assert.equal(second.ok, true);
        assert.deepEqual(second.removed, []);
        assert.deepEqual(hits(res.html, allowScripts, PREFIX), [], `input #${n} left a construct: ${res.html.slice(0, 300)}`);
        assert.equal(res.runsScripts, scriptsIn(res.html), `input #${n}: runsScripts`);
        if (!allowScripts) assert.equal(res.runsScripts, false);
        if (res.ok) ok++;
      }
      assert.ok(ok >= 540, `fail-closed must stay rare on realistic input (ok ${ok} of 600)`);
    });
  }
});
