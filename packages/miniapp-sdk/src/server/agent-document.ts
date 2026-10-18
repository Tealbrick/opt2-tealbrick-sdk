// sanitizeAgentDocument (C238, C230, C232; SANITIZE-AGENT-DOCUMENT). SERVER ENTRY ONLY, never the browser `client` entry.
//
// Agent HTML is served as a sandboxed `/_d/` document. CSP cannot stop `<link rel=prerender>`, `<a ping>` or a navigation, so
// this removes them first. Method: parse with a real HTML5 parser (parse5, scripting ON, the conservative reading), walk the
// tree, apply the rule list (AGENT_DOCUMENT_RULES, @opt2-tealbrick/manifest), serialise. Never a regex on HTML.
//
// Fail closed: any parse or internal error, an input over the size cap, a tree too deep, a bad option, or an output that a
// second pass would still change -> `{ ok: false, html: AGENT_DOCUMENT_UNAVAILABLE_HTML }`. The fixed page never echoes input.
//
// The `removed` counts name a rule kind and how many times it fired. They never hold removed content.
import { AGENT_DOCUMENT_MARKER, AGENT_DOCUMENT_RULES, AGENT_DOCUMENT_UNAVAILABLE_TEXT } from "@opt2-tealbrick/manifest";
import { defaultTreeAdapter, parse, html as parse5Html, serialize, type DefaultTreeAdapterTypes as T } from "parse5";

const R = AGENT_DOCUMENT_RULES;

export interface SanitizeAgentDocumentOptions {
  /** True when the app serves the page in a sandbox that allows scripts (Live Artifacts): `<script>` and `on*` stay. Every
   *  network attribute still goes through the URL rules. */
  allowScripts: boolean;
  /** The path under which the app serves its own assets, e.g. `/v/live-artifacts/_s/`. Letters, digits, `._~-` per segment;
   *  starts and ends with `/`. A URL under it is an allowed URL form. */
  assetPrefix: string;
}

type ParseFn = typeof parse;

/** Test seam: replaces the HTML parser, so a test can count parse calls (a refused page must reach none). Not for apps. */
export interface AgentDocumentDeps {
  parse?: ParseFn;
}

export interface SanitizeAgentDocumentResult {
  /** True: `html` is the sanitised document. False: the sanitiser failed closed and `html` is AGENT_DOCUMENT_UNAVAILABLE_HTML. */
  ok: boolean;
  html: string;
  /** True when the sanitised page can run script: a `<script>` element of any type (JSON types too) or an inline `on*` handler
   *  is left in it. Always false with `allowScripts: false`, and false for the inert page. Read from the sanitised tree, so an
   *  app can choose the CSP from it (`NO_SCRIPT_CSP` when false). */
  runsScripts: boolean;
  /** What the rules removed: kind and count, sorted by kind. Never the removed content. */
  removed: { kind: string; count: number }[];
}

/** The inert document returned (with `ok: false`) on every failure. It carries the marker, no input, and is a fixed point of
 *  the sanitiser. */
export const AGENT_DOCUMENT_UNAVAILABLE_HTML = `${AGENT_DOCUMENT_MARKER}<!DOCTYPE html><html><head><meta charset="utf-8"><title>${AGENT_DOCUMENT_UNAVAILABLE_TEXT}</title></head><body><p>${AGENT_DOCUMENT_UNAVAILABLE_TEXT}</p></body></html>`;

const failed = (): SanitizeAgentDocumentResult => ({ ok: false, html: AGENT_DOCUMENT_UNAVAILABLE_HTML, runsScripts: false, removed: [] });

/**
 * The Content-Security-Policy for a page that came back with `runsScripts: false`: no script at all (not even a JSON one
 * can be read by a script, there is none), inline style allowed (`style` attributes and `<style>` are sanitised), images only
 * from `data:` and the page's own origin (the app's `assetPrefix` paths; CSP cannot name a path without a host), nothing
 * else (`default-src 'none'`: no fonts, media, frames, connections), and a sandbox WITHOUT any allow-* token. The app adds
 * its own `frame-ancestors <viewUrl> <publicUrl>` to it. It passes `viewerDocumentCspOk` (@opt2-tealbrick/manifest).
 */
export const NO_SCRIPT_CSP = "default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; img-src data: 'self'; sandbox";

const TEXT_SLOT_ATTRIBUTE = R.textSlotAttribute;
const TEXT_SLOT_RE = new RegExp(R.textSlotPattern);
/** Elements whose text is not text for the parser (or is code): a slot there is never filled. */
const NO_FILL_ELEMENTS = new Set(["area", "base", "br", "col", "embed", "hr", "iframe", "img", "input", "link", "meta", "noembed", "noframes", "noscript", "param", "plaintext", "script", "source", "style", "template", "track", "wbr", "xmp"]);

const MARKER_COMMENT = AGENT_DOCUMENT_MARKER.slice("<!--".length, -"-->".length);

const DENIED_ELEMENTS = new Set(R.deniedElements);
const SCRIPT_ELEMENTS = new Set(R.scriptElements);
const DENIED_SCRIPT_TYPES = new Set(R.deniedScriptTypes);
const DENIED_ATTRIBUTES = new Set(R.deniedAttributes);
const LINK_ELEMENTS = new Set(R.linkElements);
const URL_ATTRIBUTES = new Set(R.urlAttributes);
const SRCSET_ATTRIBUTES = new Set(R.srcsetAttributes);
const STYLE_ATTRIBUTES = new Set(R.styleAttributes);
const CSS_VALUE_ATTRIBUTES = new Set(R.cssValueAttributes);
const SMIL_ELEMENTS = new Set(R.smilElements);
const SMIL_VALUE_ATTRIBUTES = new Set(R.smilValueAttributes);
const CSS_FORBIDDEN_FUNCTIONS = new Set(R.cssForbiddenFunctions);
const DATA_IMAGE = R.allowedUrlForms.find((f) => f.kind === "data-image");
const DATA_IMAGE_DENIED_ON = new Set(DATA_IMAGE?.deniedOn ?? []);
const DATA_IMAGE_RE = new RegExp(`^data:(?:${(DATA_IMAGE?.mimeTypes ?? []).map((m) => m.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&")).join("|")})(?:;[a-z0-9._+=-]+)*,`, "i");
const ASSET_PREFIX_RE = /^\/(?:[A-Za-z0-9._~-]+\/)+$/;
const ATTRIBUTE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_.:-]*$/;
const MARK = "\ue000"; // stands for a CSS comment: a comment separates tokens

class Counts {
  private readonly m = new Map<string, number>();
  add(kind: string): void {
    this.m.set(kind, (this.m.get(kind) ?? 0) + 1);
  }
  list(): { kind: string; count: number }[] {
    return [...this.m.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([kind, count]) => ({ kind, count }));
  }
}

// ---------------------------------------------------------------------------------------------------------------- URLs

/** The URL parser's own clean-up: strip leading and trailing C0 controls and spaces, remove tab and newline everywhere. */
function cleanUrl(v: string): string {
  const s = v.replace(/[\t\n\r]/g, "");
  let a = 0;
  let b = s.length;
  while (a < b && s.charCodeAt(a) <= 0x20) a++;
  while (b > a && s.charCodeAt(b - 1) <= 0x20) b--;
  return s.slice(a, b);
}

/** True when the text has a control character, a space or DEL, or a backslash. */
function hasControlSpaceOrBackslash(t: string): boolean {
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c <= 0x20 || c === 0x7f || c === 0x5c) return true;
  }
  return false;
}

/** Takes out white space and control characters (used on a short attribute value, to read its name). */
function stripSpaceAndControls(t: string): string {
  let out = "";
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c > 0x20 && c !== 0x7f && !/\s/.test(t[i] as string)) out += t[i];
  }
  return out;
}

function underAssetPrefix(url: string, prefix: string): boolean {
  if (!url.startsWith(prefix)) return false;
  const rest = url.slice(prefix.length);
  if (hasControlSpaceOrBackslash(rest) || /%(?:2e|5c)/i.test(rest)) return false;
  for (const seg of rest.split(/[?#]/, 1)[0]?.split("/") ?? []) if (seg === "." || seg === "..") return false;
  return true;
}

/** The ONE URL decision. Returns the cleaned URL to write back, or null when the form is not allowed. */
function allowedUrl(raw: string, tag: string, assetPrefix: string): string | null {
  const url = cleanUrl(raw);
  if (url.startsWith("#")) return url;
  if (!DATA_IMAGE_DENIED_ON.has(tag) && DATA_IMAGE_RE.test(url)) return url;
  if (underAssetPrefix(url, assetPrefix)) return url;
  return null;
}

/** `srcset` / `imagesrcset`: the HTML "parse a srcset attribute" tokenising. Rebuilt from validated parts only, so a browser
 *  cannot read a candidate this function did not see. Null when any candidate is not allowed or not understood. */
function allowedSrcset(raw: string, tag: string, assetPrefix: string): string | null {
  const ws = (c: string | undefined) => c === " " || c === "\t" || c === "\n" || c === "\f" || c === "\r";
  const out: string[] = [];
  let i = 0;
  for (;;) {
    while (i < raw.length && (ws(raw[i]) || raw[i] === ",")) i++;
    if (i >= raw.length) break;
    let start = i;
    while (i < raw.length && !ws(raw[i])) i++;
    let url = raw.slice(start, i);
    let descriptor = "";
    if (url.endsWith(",")) {
      url = url.replace(/,+$/, "");
    } else {
      while (i < raw.length && ws(raw[i])) i++;
      start = i;
      let depth = 0;
      while (i < raw.length && !(raw[i] === "," && depth === 0)) {
        if (raw[i] === "(") depth++;
        else if (raw[i] === ")" && depth > 0) depth--;
        i++;
      }
      descriptor = raw.slice(start, i).trim();
      if (descriptor !== "" && !/^[0-9]+(?:\.[0-9]+)?[wxh](?: +[0-9]+(?:\.[0-9]+)?[wxh])*$/i.test(descriptor)) return null;
    }
    if (url === "") return null;
    const ok = allowedUrl(url, tag, assetPrefix);
    if (ok === null || /\s/.test(ok) || (ok.includes(",") && !ok.startsWith("data:"))) return null;
    out.push(descriptor === "" ? ok : `${ok} ${descriptor}`);
  }
  return out.length === 0 ? null : out.join(", ");
}

// ------------------------------------------------------------------------------------------------------------------ CSS

function decodeCssEscapes(t: string): string {
  return t.replace(/\\(?:([0-9a-fA-F]{1,6})(?:\r\n|[ \t\r\n\f])?|(\r\n|[\n\r\f])|([\s\S]))/g, (_m, hex: string | undefined, nl: string | undefined, ch: string | undefined) => {
    if (hex !== undefined) {
      const cp = Number.parseInt(hex, 16);
      return cp === 0 || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? "\ufffd" : String.fromCodePoint(cp);
    }
    return nl !== undefined ? "" : (ch ?? "");
  });
}

const ALLOWED_URL_FRAGMENT = /url\([ \t\n\r\f]*(?:"#[^"\\\s()]*"|'#[^'\\\s()]*'|#[^"'\\\s()]*)[ \t\n\r\f]*\)/g;

/** True when this CSS text (comments already turned into MARK) uses a forbidden function, at-rule or legacy hook. `url(#frag)`
 *  is the one allowed `url(`. Case-insensitive (ASCII), CSS escapes decoded first. */
function cssBad(marked: string): boolean {
  // two readings: a comment as a token separator (what a browser does) and a comment taken out (A4: be conservative, so
  // `u/**/rl(` and `url/**/(` count as `url(`); the allowed `url(#fragment)` must be clean in BOTH
  return cssBadReading(marked) || cssBadReading(marked.replaceAll(MARK, ""));
}

function cssBadReading(marked: string): boolean {
  const d = decodeCssEscapes(marked.replaceAll(String.fromCharCode(0), "\ufffd")).replace(/[A-Z]/g, (c) => c.toLowerCase());
  const rest = d.replace(ALLOWED_URL_FRAGMENT, "");
  for (const at of R.cssForbiddenAtRules) if (rest.includes(`@${at}`)) return true;
  for (const legacy of R.cssForbiddenLegacy) if (rest.includes(legacy)) return true;
  // one linear scan for "<identifier>(" (a regex over an identifier run is quadratic on a long run with no "(")
  let run = -1;
  for (let i = 0; i < rest.length; i++) {
    const c = rest.charCodeAt(i);
    if ((c >= 0x61 && c <= 0x7a) || (c >= 0x30 && c <= 0x39) || c === 0x5f || c === 0x2d || c > 0x7f) {
      if (run < 0) run = i;
    } else {
      if (c === 0x28 && run >= 0) {
        const name = rest.slice(run, i);
        if (CSS_FORBIDDEN_FUNCTIONS.has(name) || CSS_FORBIDDEN_FUNCTIONS.has(name.replace(/^-[a-z]+-/, ""))) return true;
      }
      run = -1;
    }
  }
  return false;
}

interface CssState {
  removed: number;
}

/** Walks CSS text (a declaration list or a style sheet). Items end at `;`, `{` (then a block) or `}` outside strings, comments,
 *  escapes and parentheses. An item that is bad is dropped; a block whose prelude is bad is dropped whole. */
function filterCssList(s: string, start: number, nested: boolean, st: CssState): { out: string; pos: number } {
  let out = "";
  let i = start;
  while (i < s.length) {
    let raw = "";
    let marked = "";
    let depth = 0;
    let delim = "";
    while (i < s.length) {
      const c = s[i] as string;
      if (c === "\\") {
        const piece = s.slice(i, i + 2);
        raw += piece;
        marked += piece;
        i += 2;
        continue;
      }
      if (c === "/" && s[i + 1] === "*") {
        const e = s.indexOf("*/", i + 2);
        const end = e < 0 ? s.length : e + 2;
        raw += s.slice(i, end);
        marked += MARK;
        i = end;
        continue;
      }
      if (c === '"' || c === "'") {
        let j = i + 1;
        while (j < s.length) {
          const d = s[j] as string;
          if (d === "\\") {
            j += 2;
            continue;
          }
          if (d === c) {
            j++;
            break;
          }
          if (d === "\n" || d === "\r" || d === "\f") break;
          j++;
        }
        j = Math.min(j, s.length);
        const piece = s.slice(i, j);
        raw += piece;
        marked += piece;
        i = j;
        continue;
      }
      if (c === "(") depth++;
      else if (c === ")") {
        if (depth > 0) depth--;
      } else if (depth === 0 && (c === ";" || c === "{" || (c === "}" && nested))) {
        delim = c;
        break;
      }
      raw += c;
      marked += c;
      i++;
    }
    const bad = cssBad(marked);
    if (delim === "{") {
      const inner = filterCssList(s, i + 1, true, bad ? { removed: 0 } : st);
      i = inner.pos;
      if (bad) st.removed++;
      else out += `${raw}{${inner.out}}`;
    } else if (delim === ";") {
      i++;
      if (bad) st.removed++;
      else out += `${raw};`;
    } else if (delim === "}") {
      if (bad) st.removed++;
      else out += raw;
      return { out, pos: i + 1 };
    } else if (raw !== "") {
      if (bad) st.removed++;
      else out += raw;
    }
  }
  return { out, pos: i };
}

function sanitizeCss(css: string, counts: Counts, kind: string): string {
  const st: CssState = { removed: 0 };
  let out = filterCssList(css, 0, false, st).out;
  // belt and braces: what is left must itself be clean, else nothing is kept
  const again: CssState = { removed: 0 };
  if (filterCssList(out, 0, false, again).out !== out || again.removed > 0) {
    st.removed++;
    out = "";
  }
  for (let n = 0; n < st.removed; n++) counts.add(kind);
  return out;
}

/** A whole attribute value that is CSS (an SVG presentation attribute): bad -> the attribute goes. */
function cssValueBad(value: string): boolean {
  const st: CssState = { removed: 0 };
  filterCssList(value, 0, false, st);
  return st.removed > 0;
}

// ------------------------------------------------------------------------------------------------------------ input guard

/** Caps counted before parse5 runs. Exported so a later re-parse applies the same caps (C259, 0.1.34).
 *  parse5 checks each new attribute of a tag against the ones before it (quadratic per tag: 2,048 attributes in one tag cost
 *  ~10 ms, 4,000 cost 34 ms, 36,000 cost 1.8 s), so the cost of a page is the SUM over its tags of attrs². The precheck bounds
 *  that sum (MAX_ATTRIBUTE_BUDGET = 2,048²: the whole page may cost what one tag at the hard cap costs) and caps one tag at
 *  MAX_ATTRIBUTES_PER_TAG. These replace AGENT_DOCUMENT_RULES.maxAttributesPerTag (256) for the SDK. */
export const MAX_ATTRIBUTES_PER_TAG = 2048;
export const MAX_ATTRIBUTE_BUDGET = 4_194_304;
export const MAX_TAGS = R.maxTags;
/** Most elements one parse may create (parsed AND copied by the parser: formatting elements it re-opens, adoption agency
 *  clones). A page within MAX_TAGS creates at most ~1 element per tag plus a few implied ones (html, head, body, tbody, a `p`
 *  for a stray `</p>`); measured on the corpus and the at-cap test pages: at most 1.01 elements per counted tag. The factor 2
 *  leaves room for normal mis-nested formatting; above it the parser is multiplying elements (`<p><b><i><u><s>` + `<p>x` × N). */
export const MAX_ELEMENTS = 2 * R.maxTags;

// HTML tokenizer states of a tag, the ones that decide where an attribute starts.
const TAG_NAME = 0;
const BEFORE_NAME = 1;
const IN_NAME = 2;
const AFTER_NAME = 3;
const BEFORE_VALUE = 4;
const VALUE_DQ = 5;
const VALUE_SQ = 6;
const VALUE_UNQ = 7;
const AFTER_QUOTED = 8;
const SELF_CLOSING = 9;
const END_OPEN = 10; // after "</", before the tag name
const STATES = 11;
// character classes inside a tag: 0 other, 1 white space, 2 "/", 3 ">", 4 "=", 5 '"', 6 "'"
const CLASSES = 7;
const CHAR_CLASS = new Uint8Array(0x80);
for (const ws of [0x20, 0x09, 0x0a, 0x0c, 0x0d]) CHAR_CLASS[ws] = 1;
CHAR_CLASS[0x2f] = 2;
CHAR_CLASS[0x3e] = 3;
CHAR_CLASS[0x3d] = 4;
CHAR_CLASS[0x22] = 5;
CHAR_CLASS[0x27] = 6;
const isLetter = (x: number): boolean => (x >= 0x41 && x <= 0x5a) || (x >= 0x61 && x <= 0x7a);
/** The tokenizer's tag states as a table: NEXT_STATE[state * CLASSES + class] (-1: the tag ends at this ">"), and
 *  STARTS_ATTRIBUTE: 1 when that character starts a new attribute name. */
const NEXT_STATE = new Int8Array(STATES * CLASSES);
const STARTS_ATTRIBUTE = new Int8Array(STATES * CLASSES);
{
  const E = -1;
  const A = 100; // marks "IN_NAME, and an attribute starts here"
  //                 other         ws           /             >  =             "             '
  const rows: number[][] = [];
  rows[TAG_NAME] = [TAG_NAME, BEFORE_NAME, SELF_CLOSING, E, TAG_NAME, TAG_NAME, TAG_NAME];
  rows[BEFORE_NAME] = [A, BEFORE_NAME, SELF_CLOSING, E, A, A, A];
  rows[SELF_CLOSING] = rows[BEFORE_NAME];
  rows[IN_NAME] = [IN_NAME, AFTER_NAME, SELF_CLOSING, E, BEFORE_VALUE, IN_NAME, IN_NAME];
  rows[AFTER_NAME] = [A, AFTER_NAME, SELF_CLOSING, E, BEFORE_VALUE, A, A];
  rows[BEFORE_VALUE] = [VALUE_UNQ, BEFORE_VALUE, VALUE_UNQ, E, VALUE_UNQ, VALUE_DQ, VALUE_SQ];
  rows[VALUE_DQ] = [VALUE_DQ, VALUE_DQ, VALUE_DQ, VALUE_DQ, VALUE_DQ, AFTER_QUOTED, VALUE_DQ];
  rows[VALUE_SQ] = [VALUE_SQ, VALUE_SQ, VALUE_SQ, VALUE_SQ, VALUE_SQ, VALUE_SQ, AFTER_QUOTED];
  rows[VALUE_UNQ] = [VALUE_UNQ, BEFORE_NAME, VALUE_UNQ, E, VALUE_UNQ, VALUE_UNQ, VALUE_UNQ];
  rows[END_OPEN] = [TAG_NAME, TAG_NAME, TAG_NAME, TAG_NAME, TAG_NAME, TAG_NAME, TAG_NAME];
  rows[AFTER_QUOTED] = [A, BEFORE_NAME, SELF_CLOSING, E, A, A, A];
  for (let st = 0; st < STATES; st++) {
    for (let cl = 0; cl < CLASSES; cl++) {
      const to = (rows[st] as number[])[cl] as number;
      NEXT_STATE[st * CLASSES + cl] = to === A ? IN_NAME : to;
      STARTS_ATTRIBUTE[st * CLASSES + cl] = to === A ? 1 : 0;
    }
  }
}

export interface AgentDocumentStats {
  /** The most attributes any candidate tag carries before it ends (or the source ends). */
  maxAttributes: number;
  /** Sum over the candidate tags of (attributes)²: each `>` that ends one or more candidates charges the largest of their counts,
   *  squared, and the source end charges the largest count still open, squared. Never below what parse5's tags cost. */
  attributeCost: number;
  /** Count of `<` followed by a letter, `/` or `!`. */
  tags: number;
}

/**
 * ONE linear pass over the WHOLE source, with no notion of comments, raw text, CDATA or `<script>`: every `<` that could start
 * a tag (`<` + letter, or `</` + letter) starts a tag-reading automaton there, whatever the page "really" is at that point
 * (inside `<!-->`, `<!--->`, `--!>`, an SVG `<style>`, a MathML `<title>`: all counted). Each automaton follows the HTML
 * tokenizer's own tag states (names, quoted and unquoted values), so a `>` in a quoted value does not hide attributes. The
 * automata are merged by state, keeping the highest attribute count per state, so the pass stays linear however many start.
 * The real tokenizer's count for any real tag is one of the candidates', so this never counts less than parse5 will see.
 *
 * Cost (C259): real tags never overlap, so at most one real tag ends at a given `>` and at most one is open at the end of the
 * source. Charging, per `>`, the square of the LARGEST count among the candidates that end there, plus the square of the
 * largest count still open at the end, is therefore never below the sum of squares of the real tags (a candidate merged into
 * another one in the same state is covered by the survivor: same future, higher or equal count). A candidate cannot escape the
 * charge by never closing: the end of the source closes it.
 */
export function agentDocumentStats(s: string): AgentDocumentStats {
  // the live candidates: `list[0..len)` holds their states, `cnt[state]` their counts (-1: no candidate in that state)
  let cnt = new Int32Array(STATES).fill(-1);
  let nxt = new Int32Array(STATES).fill(-1);
  let list = new Int8Array(STATES);
  let nlist = new Int8Array(STATES);
  let len = 0;
  let max = 0;
  let cost = 0;
  let tags = 0;
  const n = s.length;
  for (let i = 0; i < n; i++) {
    const c = s.charCodeAt(i);
    if (len > 0) {
      const cls = c < 0x80 ? (CHAR_CLASS[c] as number) : 0;
      let nlen = 0;
      let ended = -1; // the largest count among the candidates that end at this character
      for (let j = 0; j < len; j++) {
        const st = list[j] as number;
        const k = cnt[st] as number;
        cnt[st] = -1;
        const e = st * CLASSES + cls;
        const to = NEXT_STATE[e] as number;
        const v = k + (STARTS_ATTRIBUTE[e] as number);
        if (to < 0) {
          if (v > ended) ended = v;
          continue;
        }
        const p = nxt[to] as number;
        if (p < 0) {
          nlist[nlen++] = to;
          nxt[to] = v;
        } else if (v > p) nxt[to] = v;
        if (v > max) max = v;
      }
      if (ended > 0) cost += ended * ended;
      const sc = cnt;
      cnt = nxt;
      nxt = sc;
      const sl = list;
      list = nlist;
      nlist = sl;
      len = nlen;
    }
    if (c === 0x3c) {
      const d = s.charCodeAt(i + 1);
      if (isLetter(d) || d === 0x2f || d === 0x21) tags++;
      const spawn = isLetter(d) ? TAG_NAME : d === 0x2f && isLetter(s.charCodeAt(i + 2)) ? END_OPEN : -1;
      if (spawn >= 0 && (cnt[spawn] as number) < 0) {
        cnt[spawn] = 0;
        list[len++] = spawn;
      }
    }
  }
  // the end of the source closes every candidate still open (parse5 has already paid for its attributes)
  let open = 0;
  for (let j = 0; j < len; j++) open = Math.max(open, cnt[list[j] as number] as number);
  cost += open * open;
  return { maxAttributes: max, attributeCost: cost, tags };
}

/** True when the attribute caps hold: no tag-like token over MAX_ATTRIBUTES_PER_TAG, the cost within MAX_ATTRIBUTE_BUDGET. */
const attributesWithin = (st: AgentDocumentStats): boolean => st.maxAttributes <= MAX_ATTRIBUTES_PER_TAG && st.attributeCost <= MAX_ATTRIBUTE_BUDGET;

/** True when the source is within the caps (MAX_ATTRIBUTES_PER_TAG attributes in any tag-like token, the sum of attrs² within
 *  MAX_ATTRIBUTE_BUDGET, MAX_TAGS tags). Cheap, linear, runs before any parse. Apply it before every re-parse of agent HTML
 *  (`fillTextSlots` does). */
export function agentDocumentPrecheck(html: string): boolean {
  const st = agentDocumentStats(html);
  return attributesWithin(st) && st.tags <= MAX_TAGS;
}

// ------------------------------------------------------------------------------------------------------ bounded parse

/** Thrown by the bounded tree adapter; private, so only the sanitiser's own catch sees it. */
class ParseLimitExceeded extends Error {}

/** Most elements the parser may COPY in one parse (formatting elements it re-opens, adoption agency clones): 20,000 plus twice
 *  the elements parsed so far. Benign mis-nesting copies about one element per tag that crosses an open formatting element
 *  (corpus: at most 1 copy per page; `<p><b><i><u>t` + 1,000 × `<p>x`: 3,000 copies for 1,004 tags). Formatting elements with
 *  distinct attributes escape the parser's own limit of 3 (Noah's Ark), so `<font><p>x<b aN>` × N re-opens N elements per
 *  unit: N²/2 copies, 300 ms at N = 400 (4.6 KB, found by the fuzz test) before this cap. */
const MAX_COPIES_BASE = 20_000;
const MAX_COPIES_PER_PARSED = 2;

/** Most tree work one parse may spend beyond plain appends: child visits re-measuring the depth of subtrees the parser moves
 *  (adoption agency, foster parenting) and 2 × the sibling entries read and shifted to insert before or detach (2 per
 *  foster-parented node next to an open table). A benign page moves small subtrees a few times and foster-parents a few stray
 *  texts; 4 × MAX_TAGS (200,000 foster-parented nodes) refuses `<br>` × 99,990 + `<table>` + `a ` × 700,000 in ~60 ms. */
const MAX_TREE_WORK = 4 * R.maxTags;
/** A child list longer than this has its leading children removed lazily (see detachNode). */
const LAZY_HEAD_MIN = 64;

/**
 * A parse5 tree adapter that bounds the parse WHILE parse5 builds the tree (C259): parse5's tree builder is quadratic in the
 * number of open elements (60,000 nested `<div>` cost 10 s before the post-parse depth check could refuse them).
 *
 * - Depth. Each element (and template content) gets a recorded depth on insertion: the parent's + 1, with the walk's numbering
 *   (document 0, `html` 1; template content at its template's depth). Past R.maxDepth it throws at once. A node that is
 *   inserted again (adoption agency, foster parenting) or that already has children when it is inserted (a clone that received
 *   the furthest block's children) has its subtree measured again when it lands deeper than recorded; a node that lands at the
 *   same depth or shallower keeps its larger recorded depth. Recorded depths therefore never fall below the real ones. The
 *   re-measuring is bounded by MAX_TREE_WORK. The post-parse walk checks the final tree again.
 * - Sibling lists. parse5's default adapter finds a foster-parenting reference with indexOf from the FRONT of a growing
 *   child list (`<table>x<b></b>` × 32,000: 0.6 s per parse) and detaches leading children with splice(0, 1). Here the
 *   reference is found from the END (it is the table, next to the end), leading children of a long list are removed lazily,
 *   and the steps are charged to MAX_TREE_WORK.
 * - Copied attributes. An element whose attribute list was already used by an earlier element is a copy made by the parser
 *   (a formatting element re-opened, an adoption agency clone): parse5 did not tokenize it, but every re-parse will. It is
 *   charged attrs² against what is left of MAX_ATTRIBUTE_BUDGET after the precheck's own charge.
 * - `<html>` / `<body>` attribute merging (adoptAttributes): done with an incremental name set (parse5 rebuilds a set per call:
 *   quadratic), the element capped at MAX_ATTRIBUTES_PER_TAG and its growth charged against the same budget.
 * - Element count: at most MAX_ELEMENTS created per parse, of which at most MAX_COPIES_BASE + 2 × (parsed elements) copies.
 *
 * Provenance: reconciled with Live Artifacts `src/bounded-parse.ts` (opt2-tealbrick-live-artifacts, branch
 * feat/C167-s6-hardening, commit c044698, 2026-10-18), which LA deletes after 0.1.34. Same bounds; taken from it: the 2 ×
 * (entries read + shifted) charge for a search from the end. Kept here instead: leading children of a long list are removed
 * lazily, so the adoption agency moving a block's 99,000 children is linear and the page passes (LA charges every detach the
 * whole list and refuses it); template content at its template's depth (the walk's numbering; LA: one below); the attribute
 * budget left after the precheck (LA: a fresh budget per parse); plain Map/Set (LA: WeakMap/WeakSet, slower at 10^5 nodes).
 */
/** Compacts every child list left with lazily removed leading children, once the parse is done. */
const FINISH = new WeakMap<object, () => void>();
function finishTree(adapter: object): void {
  FINISH.get(adapter)?.();
}

function boundedTreeAdapter(budgetLeft: number): typeof defaultTreeAdapter {
  // plain Map/Set, not Weak*: the adapter lives for one parse, and V8's ephemeron tables made the weak versions the most
  // expensive part of a parse with 10^5 elements
  const depthOf = new Map<object, number>();
  const usedAttrs = new Set<object>();
  const names = new Map<object, Set<string>>();
  let left = budgetLeft;
  let elements = 0;
  let copies = 0;
  let work = 0;
  const step = (n: number): void => {
    work += n;
    if (work > MAX_TREE_WORK) over();
  };
  // parse5 moves every child of an adoption agency's furthest block with getFirstChild + detachNode: splice(0, 1) on a long
  // child list is O(length), so 64,000 children cost 6 s. On a long list the leading children are removed lazily: `head`
  // holds how many leading entries are already detached; every other access to that list compacts it first.
  const head = new Map<ParentNode, number>();
  const compact = (p: ParentNode): void => {
    const k = head.get(p);
    if (k !== undefined) {
      head.delete(p);
      p.childNodes.splice(0, k);
    }
  };
  const over = (): never => {
    throw new ParseLimitExceeded();
  };
  const charge = (cost: number): void => {
    left -= cost;
    if (left < 0) over();
  };
  const hasChildren = (n: object): n is ParentNode => "childNodes" in n;
  /** Re-measures the subtree under `node` (recorded at depth d). */
  const remeasure = (node: ParentNode, d: number): void => {
    const content = (node as T.Template).content;
    if (content) {
      if (d > (depthOf.get(content) ?? -1)) depthOf.set(content, d);
      remeasure(content, d);
    }
    for (const child of node.childNodes) {
      step(1);
      if (!hasChildren(child)) continue;
      const cd = d + 1;
      if (cd > R.maxDepth) over();
      if (cd > (depthOf.get(child) ?? -1)) depthOf.set(child, cd);
      remeasure(child, depthOf.get(child) as number);
    }
  };
  const place = (parent: ParentNode, child: ChildNode): void => {
    if (!hasChildren(child)) return; // text, comment, doctype: leaves
    const d = (depthOf.get(parent) ?? 0) + 1;
    if (d > R.maxDepth) over();
    const old = depthOf.get(child);
    if (old !== undefined && d <= old) return; // same depth or shallower: the recorded depth stays an upper bound
    depthOf.set(child, d);
    const content = (child as T.Template).content;
    if (child.childNodes.length > 0 || (content && content.childNodes.length > 0)) remeasure(child, d);
    else if (content) depthOf.set(content, d);
  };
  const adapter: typeof defaultTreeAdapter = {
    ...defaultTreeAdapter,
    createElement(tagName, namespaceURI, attrs) {
      if (++elements > MAX_ELEMENTS) over();
      if (usedAttrs.has(attrs)) {
        if (++copies > MAX_COPIES_BASE + MAX_COPIES_PER_PARSED * (elements - copies)) over();
        if (attrs.length > MAX_ATTRIBUTES_PER_TAG) over();
        charge(attrs.length * attrs.length);
      } else usedAttrs.add(attrs);
      return defaultTreeAdapter.createElement(tagName, namespaceURI, attrs);
    },
    appendChild(parent, child) {
      compact(parent);
      place(parent, child);
      defaultTreeAdapter.appendChild(parent, child);
    },
    insertBefore(parent, child, reference) {
      compact(parent);
      place(parent, child);
      const list = parent.childNodes;
      const at = list.lastIndexOf(reference);
      step(2 * (list.length - at)); // the entries read from the end, and the entries the insert shifts
      list.splice(at, 0, child);
      child.parentNode = parent;
    },
    insertText(parent, text) {
      compact(parent);
      defaultTreeAdapter.insertText(parent, text);
    },
    insertTextBefore(parent, text, reference) {
      compact(parent);
      const list = parent.childNodes;
      const at = list.lastIndexOf(reference);
      step(2 * (list.length - at)); // the entries read from the end, and the entries the insert shifts
      const prev = list[at - 1];
      if (prev && defaultTreeAdapter.isTextNode(prev)) prev.value += text;
      else {
        const node = defaultTreeAdapter.createTextNode(text);
        list.splice(at, 0, node);
        node.parentNode = parent;
      }
    },
    detachNode(node) {
      const p = node.parentNode;
      if (!p) return;
      const list = p.childNodes;
      const k = head.get(p) ?? 0;
      if (list[k] === node && list.length >= LAZY_HEAD_MIN) {
        node.parentNode = null;
        if (k + 1 === list.length) {
          head.delete(p);
          list.length = 0;
        } else head.set(p, k + 1);
        return;
      }
      compact(p);
      const at = list.lastIndexOf(node);
      step(2 * (list.length - at));
      list.splice(at, 1);
      node.parentNode = null;
    },
    getFirstChild(node) {
      return node.childNodes[head.get(node) ?? 0];
    },
    getChildNodes(node) {
      compact(node);
      return node.childNodes;
    },
    setDocumentType(document, name, publicId, systemId) {
      compact(document);
      defaultTreeAdapter.setDocumentType(document, name, publicId, systemId);
    },
    setTemplateContent(template, content) {
      depthOf.set(content, depthOf.get(template) ?? 0);
      defaultTreeAdapter.setTemplateContent(template, content);
    },
    adoptAttributes(recipient, attrs) {
      let set = names.get(recipient);
      if (!set) {
        set = new Set(recipient.attrs.map((a) => a.name));
        names.set(recipient, set);
      }
      const before = recipient.attrs.length;
      for (const a of attrs) {
        if (set.has(a.name)) continue;
        set.add(a.name);
        recipient.attrs.push(a);
      }
      const after = recipient.attrs.length;
      if (after > MAX_ATTRIBUTES_PER_TAG) over();
      charge(after * after - before * before);
    },
  };
  FINISH.set(adapter, () => {
    for (const p of [...head.keys()]) compact(p);
  });
  return adapter;
}

/** One parse through the bounded adapter. `parseFn` is parse5's `parse` (or the test seam); it must pass `treeAdapter` on. */
function boundedParse(parseFn: ParseFn, html: string, scripting: boolean, budgetLeft: number): T.Document {
  const treeAdapter = boundedTreeAdapter(budgetLeft);
  const doc = parseFn(html, { scriptingEnabled: scripting, treeAdapter });
  finishTree(treeAdapter);
  return doc;
}

// ----------------------------------------------------------------------------------------------------------------- walk

type ParentNode = T.ParentNode;
type ChildNode = T.ChildNode;
type Element = T.Element;

const isElement = (n: ChildNode): n is Element => "tagName" in n;
const isText = (n: ChildNode): n is T.TextNode => n.nodeName === "#text";
/** Where a script element takes its code from, besides its text (`src`; `href` / `xlink:href` on an SVG script). */
const SCRIPT_SOURCE_ATTRIBUTES = new Set(["src", "href", "xlink:href"]);

interface Ctx {
  allowScripts: boolean;
  assetPrefix: string;
  counts: Counts;
  runsScripts: boolean;
}

function fullName(a: { name: string; prefix?: string | undefined }): string {
  return (a.prefix ? `${a.prefix}:${a.name}` : a.name).toLowerCase();
}

function attrValue(el: Element, name: string): string | undefined {
  return el.attrs.find((a) => fullName(a) === name)?.value;
}

/** The script type as a browser reads it for these two kinds: parameters after `;` ignored, ASCII white space, C0 controls and
 *  spaces trimmed, ASCII lower-cased. Character references are already decoded by the parser. */
function scriptKind(el: Element): string {
  const raw = attrValue(el, "type") ?? "";
  const semi = raw.indexOf(";");
  return cleanUrl(semi < 0 ? raw : raw.slice(0, semi)).replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function removeElementReason(el: Element, tag: string, ctx: Ctx): string | null {
  if (DENIED_ELEMENTS.has(tag)) return `element:${tag}`;
  // speculation rules and import maps go in EVERY mode (C238), before the allowScripts decision
  if (SCRIPT_ELEMENTS.has(tag)) {
    const kind = scriptKind(el);
    if (DENIED_SCRIPT_TYPES.has(kind)) return `element:${tag}-${kind}`;
  }
  for (const d of R.deniedElementsWithAttribute) if (tag === d.element && el.attrs.some((a) => fullName(a) === d.attribute)) return `element:${tag}-${d.attribute}`;
  if (!ctx.allowScripts && SCRIPT_ELEMENTS.has(tag)) return `element:${tag}`;
  if (SMIL_ELEMENTS.has(tag)) {
    const target = stripSpaceAndControls(attrValue(el, R.smilTargetAttribute) ?? "").toLowerCase().replace(/^xlink:/, "");
    if (R.smilDeniedTargets.some((t) => target === t || target.endsWith(`:${t}`)) || target.includes("href") || target.startsWith(R.eventHandlerPrefix)) return `element:${tag}-href-target`;
  }
  if (tag === "style" && el.childNodes.some((c) => !isText(c))) return "element:style-markup";
  return null;
}

/** Attribute names that no rule is about, on any element (most names on a page): kept as they are. A bounded cache of the
 *  decision, so a page with many attributes pays the rule lookups once per name, not once per attribute and pass. */
const PLAIN_NAMES = new Map<string, boolean>();
const PLAIN_NAMES_MAX = 4096;
function plainName(a: { name: string; prefix?: string | undefined }): boolean {
  const key = a.prefix ? `${a.prefix}:${a.name}` : a.name;
  let plain = PLAIN_NAMES.get(key);
  if (plain === undefined) {
    const full = key.toLowerCase();
    const local = full.slice(full.lastIndexOf(":") + 1);
    plain =
      ATTRIBUTE_NAME_RE.test(full) &&
      !full.startsWith(R.eventHandlerPrefix) &&
      !local.startsWith(R.eventHandlerPrefix) &&
      full !== TEXT_SLOT_ATTRIBUTE &&
      local !== "target" &&
      ![DENIED_ATTRIBUTES, URL_ATTRIBUTES, SRCSET_ATTRIBUTES, CSS_VALUE_ATTRIBUTES].some((set) => set.has(full) || set.has(local)) &&
      !STYLE_ATTRIBUTES.has(full) &&
      !SMIL_VALUE_ATTRIBUTES.has(local);
    if (PLAIN_NAMES.size >= PLAIN_NAMES_MAX) PLAIN_NAMES.clear();
    PLAIN_NAMES.set(key, plain);
  }
  return plain;
}

function sanitizeAttributes(el: Element, tag: string, ctx: Ctx): void {
  const kept: typeof el.attrs = [];
  let lostLink = false;
  for (const a of el.attrs) {
    if (plainName(a)) {
      kept.push(a);
      continue;
    }
    const full = fullName(a);
    const local = full.slice(full.lastIndexOf(":") + 1);
    const drop = (kind: string) => {
      ctx.counts.add(kind);
      if (local === "href" || local === "target") lostLink = true;
    };
    if (!ATTRIBUTE_NAME_RE.test(full)) {
      drop("attribute:invalid-name");
      continue;
    }
    if (full.startsWith(R.eventHandlerPrefix) || local.startsWith(R.eventHandlerPrefix)) {
      if (ctx.allowScripts) {
        ctx.runsScripts = true;
        kept.push(a);
      } else drop("attribute:event-handler");
      continue;
    }
    if (full === TEXT_SLOT_ATTRIBUTE) {
      if (TEXT_SLOT_RE.test(a.value)) kept.push(a);
      else drop("attribute:data-tb-text");
      continue;
    }
    if (DENIED_ATTRIBUTES.has(full) || DENIED_ATTRIBUTES.has(local)) {
      drop(`attribute:${local}`);
      continue;
    }
    if (LINK_ELEMENTS.has(tag) && local === "target") {
      drop("attribute:target");
      continue;
    }
    if (URL_ATTRIBUTES.has(full) || URL_ATTRIBUTES.has(local)) {
      const ok = allowedUrl(a.value, tag, ctx.assetPrefix);
      if (ok === null) drop(`attribute:url:${local}`);
      else kept.push({ ...a, value: ok });
      continue;
    }
    if (SRCSET_ATTRIBUTES.has(full) || SRCSET_ATTRIBUTES.has(local)) {
      const ok = allowedSrcset(a.value, tag, ctx.assetPrefix);
      if (ok === null) drop(`attribute:url:${local}`);
      else kept.push({ ...a, value: ok });
      continue;
    }
    if (STYLE_ATTRIBUTES.has(full)) {
      const css = sanitizeCss(a.value, ctx.counts, "css:declaration");
      if (css.trim() === "" && a.value.trim() !== "") ctx.counts.add("attribute:style");
      else kept.push({ ...a, value: css });
      continue;
    }
    if (CSS_VALUE_ATTRIBUTES.has(full) || CSS_VALUE_ATTRIBUTES.has(local) || (SMIL_ELEMENTS.has(tag) && SMIL_VALUE_ATTRIBUTES.has(local))) {
      if (cssValueBad(a.value)) drop(`attribute:css:${local}`);
      else kept.push(a);
      continue;
    }
    kept.push(a);
  }
  el.attrs = kept;
  if (LINK_ELEMENTS.has(tag) && lostLink) {
    const rel = el.attrs.find((a) => fullName(a) === "rel");
    if (rel) rel.value = "noreferrer noopener";
    else el.attrs.push({ name: "rel", value: "noreferrer noopener" });
  }
}

function walk(parent: ParentNode, ctx: Ctx, depth: number): void {
  if (depth > R.maxDepth) throw new Error("too deep");
  const kept: ChildNode[] = [];
  for (const child of parent.childNodes) {
    if (!isElement(child)) {
      kept.push(child);
      continue;
    }
    const tag = child.tagName.toLowerCase();
    const reason = removeElementReason(child, tag, ctx);
    if (reason !== null) {
      ctx.counts.add(reason);
      continue;
    }
    const scriptsBefore = ctx.runsScripts;
    sanitizeAttributes(child, tag, ctx);
    if (SCRIPT_ELEMENTS.has(tag)) {
      // S4 (0.1.34): a script with no source left (its src or href removed, or none) and no code runs nothing; it goes, and it
      // does not make the page "run scripts" (an inline handler on it never fires either)
      if (!child.attrs.some((a) => SCRIPT_SOURCE_ATTRIBUTES.has(fullName(a))) && child.childNodes.every((c) => isText(c) && c.value.trim() === "")) {
        ctx.runsScripts = scriptsBefore;
        ctx.counts.add(`element:${tag}-empty`);
        continue;
      }
      ctx.runsScripts = true;
    }
    if (tag === "style") {
      const text = child.childNodes.filter(isText);
      const first = text[0];
      if (first) {
        first.value = sanitizeCss(text.map((t) => t.value).join(""), ctx.counts, "css:rule");
        child.childNodes = [first];
      }
    } else {
      walk(child, ctx, depth + 1);
      const content = (child as T.Template).content;
      if (tag === "template" && content) walk(content, ctx, depth + 1);
    }
    kept.push(child);
  }
  parent.childNodes = kept;
}

function runPass(input: string, opts: SanitizeAgentDocumentOptions, scripting: boolean, parseFn: ParseFn, budgetLeft: number): { html: string; runsScripts: boolean; removed: { kind: string; count: number }[] } {
  const doc = boundedParse(parseFn, input, scripting, budgetLeft);
  const counts = new Counts();
  const ctx: Ctx = { allowScripts: opts.allowScripts, assetPrefix: opts.assetPrefix, counts, runsScripts: false };
  walk(doc, ctx, 0);
  // a frameset document loses its frameset above; a document always has a body when it is parsed again, so add it now
  const root = doc.childNodes.find((n): n is Element => isElement(n) && n.tagName === "html");
  if (root && !root.childNodes.some((n) => isElement(n) && n.tagName === "body")) {
    const body = defaultTreeAdapter.createElement("body", parse5Html.NS.HTML, []);
    body.parentNode = root;
    root.childNodes.push(body);
  }
  doc.childNodes = doc.childNodes.filter((n) => !(n.nodeName === "#comment" && (n as T.CommentNode).data === MARKER_COMMENT));
  const marker = defaultTreeAdapter.createCommentNode(MARKER_COMMENT);
  marker.parentNode = doc;
  doc.childNodes.unshift(marker);
  const html = serialize(doc);
  if (!html.startsWith(AGENT_DOCUMENT_MARKER)) throw new Error("marker lost");
  return { html, runsScripts: ctx.runsScripts, removed: counts.list() };
}

/** The longest output accepted for an input of `n` characters (C259): max(4 × n, n + 1 MiB). Benign pages grow by the
 *  marker, implied end tags and quoted attribute values (measured: at most 1.4× on the corpus); more is the parser multiplying
 *  re-opened formatting elements. */
const maxOutputLength = (n: number): number => Math.max(4 * n, n + 1024 * 1024);

/**
 * Removes from agent-written HTML everything that can reach the network or the top window outside the CSP: `link`, `base`,
 * `meta[http-equiv]`, forms, frames, `object`/`embed`/`portal`, `noscript`, `<a ping>`, URL attributes that are not a
 * fragment, a raster `data:` image or a path under `assetPrefix`, `srcset`, CSS `url()`/`image-set()`/`@import`, SMIL that
 * writes a URL. See AGENT_DOCUMENT_RULES. The output starts with `<!-- tb:sanitized v1 -->`. Fail closed (`ok: false`).
 */
export function sanitizeAgentDocument(html: string, opts: SanitizeAgentDocumentOptions, deps?: AgentDocumentDeps): SanitizeAgentDocumentResult {
  try {
    if (typeof html !== "string" || !opts || typeof opts.allowScripts !== "boolean" || typeof opts.assetPrefix !== "string" || !ASSET_PREFIX_RE.test(opts.assetPrefix)) return failed();
    if (opts.assetPrefix.split("/").some((s) => s === "." || s === "..")) return failed();
    if (html.length > R.maxInputBytes || Buffer.byteLength(html, "utf8") > R.maxInputBytes) return failed();
    const st = agentDocumentStats(html);
    if (!attributesWithin(st) || st.tags > MAX_TAGS) return failed();
    const o: SanitizeAgentDocumentOptions = { allowScripts: opts.allowScripts, assetPrefix: opts.assetPrefix };
    const parseFn = deps?.parse ?? parse;
    const first = runPass(html, o, true, parseFn, MAX_ATTRIBUTE_BUDGET - st.attributeCost);
    // the output is served, stored and parsed twice more: it may not grow past max(4 × input, input + 1 MiB) (the parser can
    // multiply elements it re-opens), and its own attributes must be within the same budget (copies made by the parser count)
    if (first.html.length > maxOutputLength(html.length)) return failed();
    const out = agentDocumentStats(first.html);
    if (!attributesWithin(out)) return failed();
    // a second pass, parsed with scripting on AND off, must find nothing to remove and change nothing
    for (const scripting of [true, false]) {
      const again = runPass(first.html, o, scripting, parseFn, MAX_ATTRIBUTE_BUDGET - out.attributeCost);
      if (again.removed.length > 0 || again.html !== first.html || again.runsScripts !== first.runsScripts) return failed();
    }
    return { ok: true, html: first.html, runsScripts: first.runsScripts, removed: first.removed };
  } catch {
    return failed();
  }
}

/**
 * Fills the text slots (`data-tb-text="key.path"`) of a SANITISED page: each slot element whose key is in `values` gets that
 * value as its only child, as a text node. The value is text, never markup: the serialiser escapes it (`<`, `&`, ...), so
 * `<img src=x onerror=...>` comes out as visible text. A slot on a raw-text or code element (`script`, `style`, `template`,
 * `noscript`, `iframe`, `xmp`, ...) or on a void element (`img`, `br`, ...) is left alone; so is a slot whose key is not in `values` or is not a
 * valid key. Values that are not strings are written with `String()`. Over the caps (size, attributes per tag, attribute
 * budget, tags) it returns AGENT_DOCUMENT_UNAVAILABLE_HTML without parsing; past a parse-time bound (depth, elements copied by
 * the parser) it returns the same page. Run it AFTER `sanitizeAgentDocument`, on its `html`.
 */
export function fillTextSlots(html: string, values: Readonly<Record<string, string | number | boolean>>, deps?: AgentDocumentDeps): string {
  // the same caps as the sanitiser, before any parse: over them, the inert page
  if (typeof html !== "string" || html.length > R.maxInputBytes || Buffer.byteLength(html, "utf8") > R.maxInputBytes) return AGENT_DOCUMENT_UNAVAILABLE_HTML;
  const st = agentDocumentStats(html);
  if (!attributesWithin(st) || st.tags > MAX_TAGS) return AGENT_DOCUMENT_UNAVAILABLE_HTML;
  let doc: T.Document;
  try {
    // the same bounded parse as the sanitiser (depth, copied attributes, element count): past a bound, the inert page
    doc = boundedParse(deps?.parse ?? parse, html, true, MAX_ATTRIBUTE_BUDGET - st.attributeCost);
  } catch (e) {
    if (e instanceof ParseLimitExceeded) return AGENT_DOCUMENT_UNAVAILABLE_HTML;
    throw e;
  }
  const fill = (parent: ParentNode): void => {
    for (const child of parent.childNodes) {
      if (!isElement(child)) continue;
      const tag = child.tagName.toLowerCase();
      const key = child.attrs.find((a) => fullName(a) === TEXT_SLOT_ATTRIBUTE)?.value;
      if (key !== undefined && TEXT_SLOT_RE.test(key) && Object.hasOwn(values, key) && !NO_FILL_ELEMENTS.has(tag)) {
        child.childNodes = [];
        defaultTreeAdapter.insertText(child, String(values[key]));
        continue;
      }
      fill(child);
      const content = (child as T.Template).content;
      if (tag === "template" && content) fill(content);
    }
  };
  fill(doc);
  return serialize(doc);
}
