// Recipients of an outward call (spec 0.1.81 unreleased label; C373, G-6; MANIFEST M-OP-14, BRIDGE "hook recipients").
// An op (`operations[].recipients`) or a dynamic resolution (`DynamicResolution.recipients`) names PLACES in the call input;
// the bridge reads the values of each call with `extractRecipients` and puts the canonical handles into the hook target.
// The one implementation (L1): the validator (M-OP-14), the SDK (resolution pass-through) and the bridge import it.
// No Node APIs: browser bundles may import it.
import { HANDLE_CHANNELS, normalizeHandle } from "./handles.ts";

// spec 0.1.81 (unreleased label): local mirrors until the spec pin carries `RecipientSpec`, `RECIPIENT_KINDS`,
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
export const RECIPIENT_POINTER_MAX = 256;

/** RFC 6901, non-empty (the whole input is never a recipient): `/`-separated tokens, `~` only as `~0` or `~1`. */
const POINTER_RE = /^(?:\/(?:[^~/]|~[01])*)+$/;

/** One `RecipientSpec`'s problem, or null. `kind` must be a recipient kind; nothing else may be in the object. */
function specProblem(s: unknown): string | null {
  if (s === null || typeof s !== "object" || Array.isArray(s)) return "an entry is not an object";
  const o = s as Record<string, unknown>;
  if (Object.keys(o).some((k) => k !== "pointer" && k !== "kind")) return "an entry has a member other than pointer and kind";
  if (typeof o.pointer !== "string" || o.pointer.length > RECIPIENT_POINTER_MAX || !POINTER_RE.test(o.pointer)) return "pointer is not a non-empty JSON pointer of at most 256 chars";
  if (!(RECIPIENT_KINDS as readonly unknown[]).includes(o.kind)) return `kind must be one of ${RECIPIENT_KINDS.join(", ")}`;
  return null;
}

/**
 * M-OP-14 shape of a `recipients` list (op or resolution): an array of 1..RECIPIENT_SPECS_MAX `{pointer, kind}` entries, no two
 * with the same pointer and kind. The problem as a short message (never a value from a call), or null. The effect rule
 * (outward only) is the caller's: the validator checks it on the op, the SDK and the bridge on the resolution.
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
 * BRIDGE "hook recipients" (spec 0.1.81 unreleased label, C373): the recipients of ONE call. `root` = the op input (static op)
 * or `input.arguments` (dynamic op); `specs` = `Operation.recipients` or `DynamicResolution.recipients`. Per place: a missing
 * member or `null` adds nothing; a string, or an array of strings and nulls, adds each string read with the place's `kind`
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
    const h = typeof v === "string" ? handleOf(v, kind) : null;
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
