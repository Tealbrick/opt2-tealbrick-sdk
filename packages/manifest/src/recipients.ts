// Recipients of an outward call (spec next, unreleased; C373, G-6; MANIFEST M-OP-14, BRIDGE "hook recipients").
// An op (`operations[].recipients`) or a dynamic resolution (`DynamicResolution.recipients`) names PLACES in the call input;
// the bridge reads the values of each call with `extractRecipients` and puts the canonical handles into the hook target.
// The one implementation (L1): the validator (M-OP-14), the SDK (resolution pass-through) and the bridge import it.
// No Node APIs: browser bundles may import it.
import { HANDLE_CHANNELS, normalizeHandle } from "./handles.ts";

// spec next (unreleased): local mirrors until the spec pin carries `RecipientSpec`, `RECIPIENT_KINDS`,
// `RECIPIENT_SPECS_MAX`, `RECIPIENTS_MAX` and `RECIPIENT_POINTER_MAX` (types/manifest.ts). TODO(C373 re-pin): import them from
// `@opt2-tealbrick/spec/manifest` and delete these lines; test/recipients.test.ts pins the values meanwhile.
export const RECIPIENT_KINDS = ["buzz", "slack", "telegram", "email"] as const;
export type RecipientKind = (typeof RECIPIENT_KINDS)[number];
export interface RecipientSpec {
  pointer: string;
  kind: RecipientKind;
}
export const RECIPIENT_SPECS_MAX = 8;
export const RECIPIENTS_MAX = 64;
/** In Unicode code points, the JSON Schema `maxLength` unit (QA-RCP-6): the schema and this check count the same way. */
export const RECIPIENT_POINTER_MAX = 256;

/** RFC 6901, non-empty (the whole input is never a recipient): `/`-separated tokens, `~` only as `~0` or `~1`. */
const POINTER_RE = /^(?:\/(?:[^~/]|~[01])*)+$/;

/** One `RecipientSpec`'s problem, or null. `kind` must be a recipient kind; nothing else may be in the object. */
function specProblem(s: unknown): string | null {
  if (s === null || typeof s !== "object" || Array.isArray(s)) return "an entry is not an object";
  const o = s as Record<string, unknown>;
  if (Object.keys(o).some((k) => k !== "pointer" && k !== "kind")) return "an entry has a member other than pointer and kind";
  if (typeof o.pointer !== "string" || [...o.pointer].length > RECIPIENT_POINTER_MAX || !POINTER_RE.test(o.pointer)) return "pointer is not a non-empty JSON pointer of at most 256 code points";
  if (!(RECIPIENT_KINDS as readonly unknown[]).includes(o.kind)) return `kind must be one of ${RECIPIENT_KINDS.join(", ")}`;
  return null;
}

/**
 * M-OP-14 shape of a `recipients` list (op or resolution): an array of 1..RECIPIENT_SPECS_MAX `{pointer, kind}` entries, no two
 * with the same pointer and kind. The problem as a short message (never a value from a call), or null. The outward rule
 * (`isRecipientsOutward`) is the caller's: the validator checks it on the op, the SDK and the bridge on the resolution.
 */
export function recipientSpecsProblem(specs: unknown): string | null {
  if (!Array.isArray(specs)) return "recipients is not an array";
  if (specs.length < 1 || specs.length > RECIPIENT_SPECS_MAX) return `recipients needs 1..${RECIPIENT_SPECS_MAX} entries`;
  const seen = new Set<string>();
  for (const s of specs) {
    const p = specProblem(s);
    if (p) return p;
    const key = `${(s as RecipientSpec).kind} ${(s as RecipientSpec).pointer}`;
    if (seen.has(key)) return "two entries name the same pointer and kind";
    seen.add(key);
  }
  return null;
}

/**
 * QA-RCP-7 (MANIFEST M-OP-14): an op or a resolution may name recipient places when it is outward = `effect` or `holdFamily` is
 * `outward`. (The validator also requires `audience: "agent"` on an op: person ops are never hooked.)
 */
export function isRecipientsOutward(r: { effect?: unknown; holdFamily?: unknown }): boolean {
  return r.effect === "outward" || r.holdFamily === "outward";
}

type SchemaNode = Record<string, unknown>;
/** keywords where a walk cannot know the shape: the place is accepted without a check */
const OPAQUE = ["$ref", "$dynamicRef", "allOf", "anyOf", "oneOf", "not", "if", "patternProperties", "dependentSchemas", "unevaluatedProperties", "unevaluatedItems"];
const INDEX_RE = /^(?:0|[1-9][0-9]*)$/;

function typesOf(node: SchemaNode): string[] | null {
  const t = node.type;
  if (typeof t === "string") return [t];
  return Array.isArray(t) && t.every((x) => typeof x === "string") ? (t as string[]) : null;
}

/**
 * QA-RCP-3 (MANIFEST M-OP-14, STATIC ops only): can `pointer` name a place in values of the op's `input` schema? Walks
 * `properties` (or a schema-valued `additionalProperties`) for object steps and `prefixItems` / `items` for array index steps.
 * A token the schema cannot hold → a problem (a typo would read as "known: nobody" at run time). Stops quietly (null) where the
 * schema cannot be walked (`$ref`, combinators, `patternProperties`, an object or array schema without `properties` / `items`,
 * a boolean schema `true`). The leaf, when it states `type`, must allow `string`, `null` or `array` (kind `telegram`: also
 * `integer` / `number`); an array leaf whose `items.type` is stated must allow one of those. Dynamic places have no schema at build time: never checked here.
 */
export function recipientPointerProblem(inputSchema: unknown, pointer: string, kind?: RecipientKind): string | null {
  // the leaf types a value of this kind may have (telegram chat ids may be JSON integers)
  const leafOk = (t: string) => t === "string" || t === "null" || (kind === "telegram" && (t === "integer" || t === "number"));
  if (!POINTER_RE.test(pointer)) return "pointer is not a non-empty JSON pointer";
  let node: unknown = inputSchema;
  const tokens = pointer.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  for (const token of tokens) {
    if (node === true || node === undefined) return null;
    if (node === false || node === null || typeof node !== "object" || Array.isArray(node)) return `pointer ${pointer} names no place in the input schema`;
    const n = node as SchemaNode;
    if (OPAQUE.some((k) => k in n)) return null;
    const types = typesOf(n);
    const objectish = types === null ? "properties" in n || "additionalProperties" in n : types.includes("object");
    const arrayish = types === null ? "items" in n || "prefixItems" in n : types.includes("array");
    if (objectish && n.properties !== null && typeof n.properties === "object" && Object.hasOwn(n.properties as object, token)) {
      node = (n.properties as SchemaNode)[token];
      continue;
    }
    if (arrayish && INDEX_RE.test(token)) {
      const prefix = Array.isArray(n.prefixItems) ? (n.prefixItems as unknown[]) : [];
      const i = Number(token);
      if (i < prefix.length) node = prefix[i];
      else if ("items" in n) node = n.items;
      else return null;
      continue;
    }
    if (objectish && n.additionalProperties !== undefined && n.additionalProperties !== false) {
      if (!("properties" in n) && n.additionalProperties === true) return null;
      if (typeof n.additionalProperties === "object") {
        node = n.additionalProperties;
        continue;
      }
    }
    // a schema with no shape keywords (`{}`), or an open object without declared members, cannot be walked; anything else
    // cannot hold the token
    if (types === null && !objectish && !arrayish) return null;
    if (objectish && !("properties" in n) && n.additionalProperties === undefined) return null;
    if (arrayish && !objectish && !("items" in n) && !("prefixItems" in n)) return null;
    return `pointer ${pointer} names no place in the input schema`;
  }
  if (node === true || node === undefined || node === null || typeof node !== "object") return null;
  const leaf = node as SchemaNode;
  if (OPAQUE.some((k) => k in leaf)) return null;
  const types = typesOf(leaf);
  if (types !== null && !types.some((t) => leafOk(t) || t === "array")) return `pointer ${pointer} names a place that holds no string`;
  if (types?.includes("array") && !types.some(leafOk) && leaf.items !== null && typeof leaf.items === "object") {
    const it = typesOf(leaf.items as SchemaNode);
    if (it !== null && !it.some(leafOk)) return `pointer ${pointer} names an array that holds no string`;
  }
  return null;
}

/** RFC 6901 evaluation. `undefined` = no such member (own members only; an array index is `0` or `[1-9][0-9]*`, never `-`). */
function at(root: unknown, pointer: string): unknown {
  let cur = root;
  for (const raw of pointer.slice(1).split("/")) {
    const token = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(cur)) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(token)) return undefined;
      cur = cur[Number(token)];
    } else if (cur !== null && typeof cur === "object") {
      if (!Object.hasOwn(cur, token)) return undefined;
      cur = (cur as Record<string, unknown>)[token];
    } else {
      return undefined;
    }
  }
  return cur;
}

/** One string at a place, read with its kind → the canonical handle, or null. A value with another kind's prefix is null. */
function handleOf(value: string, kind: RecipientKind): string | null {
  const v = value.trim();
  if (v.startsWith(`${kind}:`)) return normalizeHandle(v);
  const colon = v.indexOf(":");
  if (colon > 0 && (HANDLE_CHANNELS as readonly string[]).includes(v.slice(0, colon))) return null;
  return v === "" ? null : normalizeHandle(`${kind}:${v}`);
}

export interface ExtractedRecipients {
  /** canonical handles (`normalizeHandle`), de-duplicated, sorted by UTF-16 code unit, at most RECIPIENTS_MAX */
  recipients: string[];
  /** true when a value was not a handle of its kind, a place held another shape, the specs were malformed, or more than
   *  RECIPIENTS_MAX distinct handles were found (BRIDGE `target.recipientsIncomplete`) */
  incomplete: boolean;
}

/**
 * BRIDGE "hook recipients" (spec next, unreleased, C373): the recipients of ONE call. `root` = the op input (static op)
 * or `input.arguments` (dynamic op); `specs` = `Operation.recipients` or `DynamicResolution.recipients`. Per place: a missing
 * member or `null` adds nothing; a string, or an array of strings and nulls, adds each string read with the place's `kind`
 * (kind `telegram` also takes a JSON safe integer)
 * (a bare value gets the `<kind>:` prefix; a value already prefixed with `<kind>:` is read as is; another kind's prefix, an
 * empty string or a value `normalizeHandle` refuses is dropped and marks the result incomplete); any other shape marks it
 * incomplete. Malformed `specs` → `{recipients: [], incomplete: true}`. Never throws; never logs (the values are personal data).
 */
export function extractRecipients(root: unknown, specs: unknown): ExtractedRecipients {
  if (recipientSpecsProblem(specs) !== null) return { recipients: [], incomplete: true };
  const found = new Set<string>();
  let incomplete = false;
  const add = (v: unknown, kind: RecipientKind): void => {
    if (v === null || v === undefined) return;
    // C373 (packages lead): a JSON integer is a value only for kind telegram (chat ids; groups and channels are negative);
    // a float, an exponent form outside the safe range, or a number for any other kind is a failure
    const h = typeof v === "string" ? handleOf(v, kind) : typeof v === "number" && kind === "telegram" && Number.isSafeInteger(v) ? normalizeHandle(`telegram:${v}`) : null;
    if (h === null) incomplete = true;
    else found.add(h);
  };
  for (const s of specs as RecipientSpec[]) {
    const v = at(root, s.pointer);
    if (Array.isArray(v)) for (const item of v) add(item, s.kind);
    else add(v, s.kind);
  }
  // code-unit order (never localeCompare), so every reader sorts the same way
  const sorted = [...found].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (sorted.length > RECIPIENTS_MAX) return { recipients: sorted.slice(0, RECIPIENTS_MAX), incomplete: true };
  return { recipients: sorted, incomplete };
}
