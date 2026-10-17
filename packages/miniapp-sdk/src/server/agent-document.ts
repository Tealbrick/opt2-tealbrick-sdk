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

export interface SanitizeAgentDocumentResult {
  /** True: `html` is the sanitised document. False: the sanitiser failed closed and `html` is AGENT_DOCUMENT_UNAVAILABLE_HTML. */
  ok: boolean;
  html: string;
  /** What the rules removed: kind and count, sorted by kind. Never the removed content. */
  removed: { kind: string; count: number }[];
}

/** The inert document returned (with `ok: false`) on every failure. It carries the marker, no input, and is a fixed point of
 *  the sanitiser. */
export const AGENT_DOCUMENT_UNAVAILABLE_HTML = `${AGENT_DOCUMENT_MARKER}<!DOCTYPE html><html><head><meta charset="utf-8"><title>${AGENT_DOCUMENT_UNAVAILABLE_TEXT}</title></head><body><p>${AGENT_DOCUMENT_UNAVAILABLE_TEXT}</p></body></html>`;

const failed = (): SanitizeAgentDocumentResult => ({ ok: false, html: AGENT_DOCUMENT_UNAVAILABLE_HTML, removed: [] });

const MARKER_COMMENT = AGENT_DOCUMENT_MARKER.slice("<!--".length, -"-->".length);

const DENIED_ELEMENTS = new Set(R.deniedElements);
const SCRIPT_ELEMENTS = new Set(R.scriptElements);
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

const isSpace = (c: string | undefined) => c === " " || c === "\t" || c === "\n" || c === "\f" || c === "\r";
const isAlpha = (c: string | undefined) => c !== undefined && ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z"));

/** One linear pass that follows the HTML tokenizer's tag rules (name, attribute names, quoted and unquoted values) and returns
 *  the largest attribute count of any one tag. It may count tags the tokenizer would read as text (inside `<style>`): that can
 *  only fail closed, never let a page through. */
function maxAttributesInOneTag(s: string, limit: number): number {
  let max = 0;
  let i = 0;
  const n = s.length;
  while (i < n) {
    if (s[i] !== "<") {
      i++;
      continue;
    }
    i++;
    if (s[i] === "/") i++;
    if (!isAlpha(s[i])) continue;
    while (i < n && !isSpace(s[i]) && s[i] !== "/" && s[i] !== ">") i++;
    let count = 0;
    for (;;) {
      while (i < n && (isSpace(s[i]) || s[i] === "/")) i++;
      if (i >= n) break;
      if (s[i] === ">") {
        i++;
        break;
      }
      count++;
      if (count > limit) return count;
      i++;
      while (i < n && !isSpace(s[i]) && s[i] !== "/" && s[i] !== ">" && s[i] !== "=") i++;
      while (i < n && isSpace(s[i])) i++;
      if (s[i] === "=") {
        i++;
        while (i < n && isSpace(s[i])) i++;
        const q = s[i];
        if (q === '"' || q === "'") {
          const e = s.indexOf(q, i + 1);
          i = e < 0 ? n : e + 1;
        } else {
          while (i < n && !isSpace(s[i]) && s[i] !== ">") i++;
        }
      }
    }
    if (count > max) max = count;
  }
  return max;
}

// ----------------------------------------------------------------------------------------------------------------- walk

type ParentNode = T.ParentNode;
type ChildNode = T.ChildNode;
type Element = T.Element;

const isElement = (n: ChildNode): n is Element => "tagName" in n;
const isText = (n: ChildNode): n is T.TextNode => n.nodeName === "#text";

interface Ctx {
  allowScripts: boolean;
  assetPrefix: string;
  counts: Counts;
}

function fullName(a: { name: string; prefix?: string | undefined }): string {
  return (a.prefix ? `${a.prefix}:${a.name}` : a.name).toLowerCase();
}

function attrValue(el: Element, name: string): string | undefined {
  return el.attrs.find((a) => fullName(a) === name)?.value;
}

function removeElementReason(el: Element, tag: string, ctx: Ctx): string | null {
  if (DENIED_ELEMENTS.has(tag)) return `element:${tag}`;
  for (const d of R.deniedElementsWithAttribute) if (tag === d.element && el.attrs.some((a) => fullName(a) === d.attribute)) return `element:${tag}-${d.attribute}`;
  if (!ctx.allowScripts && SCRIPT_ELEMENTS.has(tag)) return `element:${tag}`;
  if (SMIL_ELEMENTS.has(tag)) {
    const target = stripSpaceAndControls(attrValue(el, R.smilTargetAttribute) ?? "").toLowerCase().replace(/^xlink:/, "");
    if (R.smilDeniedTargets.some((t) => target === t || target.endsWith(`:${t}`)) || target.includes("href") || target.startsWith(R.eventHandlerPrefix)) return `element:${tag}-href-target`;
  }
  if (tag === "style" && el.childNodes.some((c) => !isText(c))) return "element:style-markup";
  return null;
}

function sanitizeAttributes(el: Element, tag: string, ctx: Ctx): void {
  const kept: typeof el.attrs = [];
  let lostLink = false;
  for (const a of el.attrs) {
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
      if (ctx.allowScripts) kept.push(a);
      else drop("attribute:event-handler");
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
    sanitizeAttributes(child, tag, ctx);
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

function runPass(input: string, opts: SanitizeAgentDocumentOptions, scripting: boolean): { html: string; removed: { kind: string; count: number }[] } {
  const doc = parse(input, { scriptingEnabled: scripting });
  const counts = new Counts();
  walk(doc, { allowScripts: opts.allowScripts, assetPrefix: opts.assetPrefix, counts }, 0);
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
  return { html, removed: counts.list() };
}

/**
 * Removes from agent-written HTML everything that can reach the network or the top window outside the CSP: `link`, `base`,
 * `meta[http-equiv]`, forms, frames, `object`/`embed`/`portal`, `noscript`, `<a ping>`, URL attributes that are not a
 * fragment, a raster `data:` image or a path under `assetPrefix`, `srcset`, CSS `url()`/`image-set()`/`@import`, SMIL that
 * writes a URL. See AGENT_DOCUMENT_RULES. The output starts with `<!-- tb:sanitized v1 -->`. Fail closed (`ok: false`).
 */
export function sanitizeAgentDocument(html: string, opts: SanitizeAgentDocumentOptions): SanitizeAgentDocumentResult {
  try {
    if (typeof html !== "string" || !opts || typeof opts.allowScripts !== "boolean" || typeof opts.assetPrefix !== "string" || !ASSET_PREFIX_RE.test(opts.assetPrefix)) return failed();
    if (opts.assetPrefix.split("/").some((s) => s === "." || s === "..")) return failed();
    if (html.length > R.maxInputBytes || Buffer.byteLength(html, "utf8") > R.maxInputBytes) return failed();
    if (maxAttributesInOneTag(html, R.maxAttributesPerTag) > R.maxAttributesPerTag) return failed();
    const o: SanitizeAgentDocumentOptions = { allowScripts: opts.allowScripts, assetPrefix: opts.assetPrefix };
    const first = runPass(html, o, true);
    // a second pass, parsed with scripting on AND off, must find nothing to remove and change nothing
    for (const scripting of [true, false]) {
      const again = runPass(first.html, o, scripting);
      if (again.removed.length > 0 || again.html !== first.html) return failed();
    }
    return { ok: true, html: first.html, removed: first.removed };
  } catch {
    return failed();
  }
}
