// v0.1.42 (C369 D1/D4, SDK-API §4.8–§4.9, spec 0.1.84 reservation): the SDK default hold view, its summary, and the input kept
// with a hold for `tb.hold_details`. Pure functions, no I/O: the same input, schema and title give the same bytes on every
// SDK (the approval is bound to sha256 of the view, D2). Every rule here is in SDK-API §4.8 and is checked row by row against
// the spec fixture `examples/hold-view.cases.json` (test/fixtures/hold-view.cases.json is a copy until spec 0.1.84 ships).
import type { Json } from "@opt2-tealbrick/spec/sdk";

// ── Local mirror of the spec 0.1.84 constants and types (reservation). Replace with imports from @opt2-tealbrick/spec/sdk
// when the spec pin moves to 0.1.84; the values are the spec's.
/** The cap of every hold view (unchanged, SDK-API §4.1): at most 16 000 UTF-16 code units. */
export const HOLD_VIEW_MAX_CHARS = 16_000;
/** D1 limits; counts are in code points except `summaryMaxChars` (UTF-16 code units, like every receipt summary). */
export const HOLD_VIEW_LIMITS = {
  titleMaxChars: 200,
  labelMaxChars: 80,
  valueMaxChars: 200,
  blockMaxChars: 1000,
  listMaxItems: 10,
  depthMax: 3,
  summaryMaxChars: 280,
  summaryFields: 2,
} as const;
/** QA-C369-6 (lead decision): a key is secret when its folded form (humanized, ASCII lower case, separators removed) CONTAINS one of
 *  these parts, or one of its words EQUALS one of HOLD_SECRET_KEY_WORDS. One rule for the kept input, the view and the summary. */
export const HOLD_SECRET_KEY_PARTS = ["token", "secret", "password", "passwd", "passphrase", "apikey", "authorization", "cookie", "credential", "bearer", "jwt", "privatekey", "clientsecret"] as const;
export const HOLD_SECRET_KEY_WORDS = ["auth", "pwd", "otp", "pin", "sig", "signature"] as const;
/** QA-C369-2 (lead decision): the default view shows `<label>: (hidden)` for a value under a secret key. */
export const HOLD_VIEW_HIDDEN = "(hidden)";
/** The value that replaces a secret member in the kept input. */
export const HOLD_INPUT_REDACTED = "[redacted]";
/** D4: the kept input is the JCS text of the redacted input; more than this many UTF-8 bytes → not kept (`too_large`). */
export const HOLD_INPUT_MAX_BYTES = 60_000;
/** D4 + Coordinator 2026-10-27: the sealed input is wiped this long after the hold reaches a terminal status. */
export const HOLD_INPUT_KEEP_MS = 7 * 86_400_000;
/** D4: the standard person op (owner only). */
export const HOLD_DETAILS_OP = "tb.hold_details" as const;

/** D4: what `tb.hold_details` can say about the kept input (spec HOLD_INPUT_STATES). */
export type HoldInputState = "kept" | "too_large" | "wiped" | "unreadable" | "none";

/** D4: output of `tb.hold_details` (spec 0.1.84 `HoldDetails`). Times are UTC ISO 8601 (D6). */
export interface HoldDetails {
  holdId: `hld_${string}`;
  /** the same row: a hold's id stays its receipt id (SDK-API §4.1) */
  receiptId: `hld_${string}`;
  status: "run" | "held" | "approved" | "denied" | "refused" | "failed" | "after_failed";
  op: string;
  opTitle: string;
  /** dynamic ops: the tool name of the call */
  tool?: string;
  family: string;
  reason?: string;
  heldBy?: string;
  caller: { type: "agent" | "app"; id: string; name: string; product?: string };
  callId: string | null;
  inputDigest: string;
  /** the redacted input (JSON), or null when not kept, wiped or unreadable (`inputState`) */
  input: Json | null;
  inputState: HoldInputState;
  /** when the kept input is wiped (terminal status + 7 days); null while the hold is not terminal or nothing is kept */
  inputWipeAt: string | null;
  createdAt: string;
  expiresAt: string | null;
  decidedAt: string | null;
  /** `sha256:` hex of the view the owner saw; null for a hold made by an SDK before 0.1.42 */
  viewSha256: string | null;
}

// ── text rules ──────────────────────────────────────────────────────────────
const isRemoved = (cp: number): boolean =>
  (cp <= 0x1f && cp !== 0x0a) ||
  (cp >= 0x7f && cp <= 0x9f) ||
  cp === 0x061c || // Arabic letter mark (a bidi control; QA-C369-7)
  (cp >= 0x200b && cp <= 0x200f) ||
  cp === 0x2028 || // line separator (QA-C369-7)
  cp === 0x2029 || // paragraph separator (QA-C369-7)
  (cp >= 0x202a && cp <= 0x202e) ||
  (cp >= 0x2060 && cp <= 0x2064) ||
  (cp >= 0x2066 && cp <= 0x2069) ||
  cp === 0xfeff ||
  (cp >= 0xe0000 && cp <= 0xe007f) || // tag characters (invisible ASCII; QA-C369-7)
  (cp >= 0xd800 && cp <= 0xdfff); // a lone surrogate (a valid pair is one code point above 0xFFFF)

/** §4.8 clean(): CR LF and CR → LF, TAB → space, then control, bidi, zero-width, separator, tag, BOM and lone surrogates removed. */
export function clean(s: string): string {
  const t = s.replace(/\r\n?/g, "\n").replace(/\t/g, " ");
  let out = "";
  for (const ch of t) if (!isRemoved(ch.codePointAt(0) ?? 0)) out += ch;
  return out;
}

const cps = (s: string): string[] => Array.from(s);

/** First n−1 code points + "…" when longer than n code points. */
function clip(s: string, n: number): string {
  const a = cps(s);
  return a.length <= n ? s : `${a.slice(0, n - 1).join("")}…`;
}

/** §4.8 oneLine(): clean, LF → space, clip. */
export function oneLine(s: string, n: number): string {
  return clip(clean(s).replace(/\n/g, " "), n);
}

/** §4.8 humanize(): `to_address` / `toAddress` → "To address" (ASCII case rules only). */
export function humanize(key: string): string {
  const w = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_\-. ]+/g, " ")
    .replace(/^ +| +$/g, "")
    .replace(/[A-Z]/g, (c) => c.toLowerCase());
  if (w === "") return "(unnamed)";
  return /^[a-z]/.test(w) ? (w[0] as string).toUpperCase() + w.slice(1) : w;
}

/** §4.8 group(): 12345 → "12,345". */
export function group(n: number): string {
  return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** §4.8 count(): "1 field", "2 fields" (the noun gets an "s" unless n = 1). */
const count = (n: number, noun: string): string => `${group(n)} ${noun}${n === 1 ? "" : "s"}`;

/** §4.8 line 2 of a view that does not show every field (QA-C369-1, lead decision). */
export function holdViewElidedLine(n: number): string {
  return `Not every field is shown (${group(n)} more). Open More details before you approve.`;
}

/**
 * §4.9 secret keys (QA-C369-6, lead decision): humanize the cleaned key, lower-case ASCII, split into words; the folded key is the
 * words joined without separators. Secret when the folded key CONTAINS a HOLD_SECRET_KEY_PARTS entry or a word EQUALS a
 * HOLD_SECRET_KEY_WORDS entry. `api_key`, `ACCESSTOKEN`, `secrets`, `privateKey`, `x-auth` are secret; `keyword`, `author` are not.
 */
export function isSecretKey(key: string): boolean {
  const words = humanize(clean(key).replace(/\n/g, " "))
    .replace(/[A-Z]/g, (c) => c.toLowerCase())
    .split(" ");
  const folded = words.join("");
  return (HOLD_SECRET_KEY_PARTS as readonly string[]).some((p) => folded.includes(p)) || words.some((w) => (HOLD_SECRET_KEY_WORDS as readonly string[]).includes(w));
}

const isObj = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isScalar = (v: unknown): boolean => v === null || typeof v === "boolean" || typeof v === "number" || typeof v === "string";
/** JCS member order: keys sorted by UTF-16 code units. */
const jcsKeys = (o: Record<string, unknown>): string[] => Object.keys(o).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
/** An own member only (QA-C369-3: `__proto__` is data, never the prototype). */
const own = (o: Record<string, unknown>, k: string): unknown => (Object.hasOwn(o, k) ? o[k] : undefined);

function subSchema(schema: unknown, key: string): Record<string, unknown> | null {
  if (!isObj(schema) || !isObj(schema.properties) || !Object.hasOwn(schema.properties, key)) return null;
  const s = schema.properties[key];
  return isObj(s) ? s : null;
}
const itemsSchema = (schema: unknown): Record<string, unknown> | null => (isObj(schema) && isObj(schema.items) ? schema.items : null);

/** Label of one path segment: the schema `title` (cleaned, one line, ≤ 80), else the humanized key. */
function segment(key: string, schema: Record<string, unknown> | null): string {
  if (schema && typeof schema.title === "string") {
    const t = oneLine(schema.title, HOLD_VIEW_LIMITS.labelMaxChars);
    if (!/^ *$/.test(t)) return t; // blank = empty or only spaces (U+0020)
  }
  return clip(humanize(clean(key).replace(/\n/g, " ")), HOLD_VIEW_LIMITS.labelMaxChars);
}

const isBlock = (t: string): boolean => t.includes("\n") || cps(t).length > HOLD_VIEW_LIMITS.valueMaxChars;

/** Scalar value text (a string here is never a block). */
function scalarText(v: unknown): string {
  if (v === null) return "(empty)";
  if (typeof v === "boolean") return v ? "yes" : "no";
  if (typeof v === "number") return JSON.stringify(v);
  const t = clean(String(v));
  return t === "" ? "(empty)" : t;
}

interface Line {
  text: string;
  /** a `label: value` line that may go into the summary */
  summary: boolean;
}
interface RenderState {
  lines: Line[];
  /** items, members and fields not shown (list limit, depth limit); the cap adds its dropped lines (§4.8 "Elision") */
  elided: number;
  /** raw paths (JSON of the token list) already rendered as a `recipients` place: skipped where the walk meets them again */
  shown: Set<string>;
}
const pathKey = (raw: readonly string[]): string => JSON.stringify(raw);

/**
 * The lines of one field (§4.8 rules 1–7). `labels` = the label segments, `raw` = the member keys / item indexes of the path, `hidden`
 * = a key on the path is secret: the field is one `<label>: (hidden)` line (QA-C369-2), never in the summary.
 */
function field(value: unknown, labels: string[], raw: string[], hidden: boolean, schema: Record<string, unknown> | null, st: RenderState): void {
  const label = labels.join(" › ");
  const depth = labels.length;
  // `more` lines ("and N more", "not shown") never go into the summary
  const line = (v: string, summary = true): void => {
    st.lines.push({ text: `${label}: ${v}`, summary });
  };
  if (hidden) line(HOLD_VIEW_HIDDEN, false);
  else if (typeof value === "string") {
    const t = clean(value);
    if (!isBlock(t)) {
      line(scalarText(value));
      return;
    }
    const a = cps(t);
    const max = HOLD_VIEW_LIMITS.blockMaxChars;
    st.lines.push({ text: a.length <= max ? `${label} (plain text):` : `${label} (plain text, first ${group(max)} characters; ${group(a.length - max)} more not shown):`, summary: false });
    for (const l of a.slice(0, max).join("").split("\n")) st.lines.push({ text: `  ${l}`, summary: false });
  } else if (Array.isArray(value)) {
    const max = HOLD_VIEW_LIMITS.listMaxItems;
    if (value.length === 0) line("(none)");
    else if (value.every((v) => isScalar(v) && !(typeof v === "string" && isBlock(clean(v))))) {
      const shown = value.slice(0, max).map(scalarText).join(", ");
      if (value.length > max) st.elided += value.length - max;
      line(value.length > max ? `${shown} and ${group(value.length - max)} more` : shown);
    } else if (depth >= HOLD_VIEW_LIMITS.depthMax) {
      st.elided += value.length;
      line(`(list of ${count(value.length, "item")}, not shown)`, false);
    } else {
      const items = itemsSchema(schema);
      value.slice(0, max).forEach((v, i) => {
        const r = [...raw, String(i)];
        if (!st.shown.has(pathKey(r))) field(v, [...labels, `#${i + 1}`], r, false, items, st);
      });
      if (value.length > max) {
        st.elided += value.length - max;
        line(`and ${group(value.length - max)} more`, false);
      }
    }
  } else if (isObj(value)) {
    const keys = jcsKeys(value);
    if (keys.length === 0) line("(none)");
    else if (depth >= HOLD_VIEW_LIMITS.depthMax) {
      st.elided += keys.length;
      line(`(${count(keys.length, "field")}, not shown)`, false);
    } else
      for (const k of keys) {
        const r = [...raw, k];
        if (st.shown.has(pathKey(r))) continue;
        const sub = subSchema(schema, k);
        field(own(value, k), [...labels, segment(k, sub)], r, isSecretKey(k), sub, st);
      }
  } else line(scalarText(value ?? null)); // null, boolean, number (undefined never occurs in parsed JSON)
}

/** RFC 6901 tokens of a pointer ("/a/b~1c" → ["a", "b/c"]); null for "" or a pointer that does not start with "/". */
function pointerTokens(p: string): string[] | null {
  if (!p.startsWith("/")) return null;
  return p
    .slice(1)
    .split("/")
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
}

/**
 * §4.8 "Recipients first": the op's `recipients` places (MANIFEST M-OP-14 `{pointer, kind}`; a dynamic tool's resolution places),
 * read structurally: anything that is not an array of objects with a string `pointer` is ignored. Each place that resolves (own
 * members, list indexes `0|[1-9][0-9]*` in range) renders as a field before the JCS walk, in declaration order, once.
 */
function renderPlaces(input: Record<string, unknown>, schema: unknown, recipients: unknown, st: RenderState): void {
  if (!Array.isArray(recipients)) return;
  for (const spec of recipients) {
    if (!isObj(spec) || typeof spec.pointer !== "string") continue;
    const tokens = pointerTokens(spec.pointer);
    if (!tokens || tokens.length === 0) continue;
    let cur: unknown = input;
    let sch: Record<string, unknown> | null = isObj(schema) ? schema : null;
    const labels: string[] = [];
    let hidden = false;
    let found = true;
    let covered = false;
    for (let i = 0; i < tokens.length; i++) {
      const t = tokens[i] as string;
      if (st.shown.has(pathKey(tokens.slice(0, i + 1)))) covered = true;
      if (Array.isArray(cur)) {
        if (!/^(0|[1-9][0-9]*)$/.test(t) || Number(t) >= cur.length) {
          found = false;
          break;
        }
        labels.push(`#${Number(t) + 1}`);
        sch = itemsSchema(sch);
        cur = cur[Number(t)];
      } else if (isObj(cur) && Object.hasOwn(cur, t)) {
        const sub = subSchema(sch, t);
        labels.push(segment(t, sub));
        hidden = hidden || isSecretKey(t);
        sch = sub;
        cur = cur[t];
      } else {
        found = false;
        break;
      }
    }
    if (!found || covered) continue;
    st.shown.add(pathKey(tokens));
    field(cur, labels, tokens, hidden, sch, st);
  }
}

/** D1 line 1 of a dynamic op (QA-C369-5, lead decision): `<op title>: <tool>` — no catalog lookup, so the hash never depends on it. */
export function dynamicHoldTitle(opTitle: string, tool: string): string {
  return `${opTitle}: ${tool}`;
}

const utf16 = (s: string) => s.length;

/** §4.8 summary clamp: ≤ 280 UTF-16 code units, cut at a code point boundary, "…" added. */
export function clampSummaryCp(s: string, max: number = HOLD_VIEW_LIMITS.summaryMaxChars): string {
  if (utf16(s) <= max) return s;
  let out = "";
  for (const ch of s) {
    if (utf16(out) + utf16(ch) > max - 1) break;
    out += ch;
  }
  return `${out}…`;
}

/**
 * D1 (SDK-API §4.8): the default hold view and its summary. `title` = line 1 (op title, or `dynamicHoldTitle(...)`), `input` = the
 * op input (or a dynamic call's tool arguments), `schema` = the op's input schema, or null. `recipients` = the op's (or the dynamic
 * resolution's) `recipients` places, read structurally; their fields come first. When anything is not shown (list limit, depth
 * limit, the 16 000 cap), line 2 is `holdViewElidedLine(n)`.
 */
export function renderHoldView(title: string, input: Json, schema: unknown, recipients?: unknown): { view: string; summary: string } {
  const head = oneLine(title, HOLD_VIEW_LIMITS.titleMaxChars);
  const st: RenderState = { lines: [], elided: 0, shown: new Set() };
  if (isObj(input)) {
    const keys = jcsKeys(input);
    if (keys.length === 0) st.lines.push({ text: "No input.", summary: false });
    renderPlaces(input, schema, recipients, st);
    for (const k of keys) {
      if (st.shown.has(pathKey([k]))) continue;
      const sub = subSchema(schema, k);
      field(own(input, k), [segment(k, sub)], [k], isSecretKey(k), sub, st);
    }
  } else field(input, ["Input"], [], false, null, st);

  const body = st.lines.map((l) => l.text);
  const fits = (lines: string[]) => utf16(lines.join("\n")) <= HOLD_VIEW_MAX_CHARS;
  let view = [head, ...body].join("\n");
  if (st.elided > 0 || !fits([head, ...body])) {
    // keep the most body lines k such that head + line 2 + k lines fit; n = elided + dropped lines
    for (let k = st.elided > 0 ? body.length : body.length - 1; k >= 0; k--) {
      const lines = [head, holdViewElidedLine(st.elided + body.length - k), ...body.slice(0, k)];
      if (fits(lines)) {
        view = lines.join("\n");
        break;
      }
    }
  }
  const picked = st.lines
    .filter((l) => l.summary)
    .slice(0, HOLD_VIEW_LIMITS.summaryFields)
    .map((l) => l.text);
  const summary = clampSummaryCp([head, ...picked].join(" · "));
  return { view, summary };
}

/** D4: the input with every member under a secret key replaced by "[redacted]" (all depths). Null-prototype objects (QA-C369-3). */
export function redactHoldInput(v: Json): Json {
  if (Array.isArray(v)) return v.map(redactHoldInput);
  if (isObj(v)) {
    const out = Object.create(null) as Record<string, Json>;
    for (const k of Object.keys(v)) out[k] = isSecretKey(k) ? HOLD_INPUT_REDACTED : redactHoldInput(own(v, k) as Json);
    return out;
  }
  return v;
}

/** D4: the JCS text of the redacted input when it fits HOLD_INPUT_MAX_BYTES, else null (`too_large`). `jcs` is the SDK's canonicalize(). */
export function keptHoldInput(input: Json, jcs: (v: Json) => string): string | null {
  const text = jcs(redactHoldInput(input));
  return Buffer.byteLength(text, "utf8") <= HOLD_INPUT_MAX_BYTES ? text : null;
}
