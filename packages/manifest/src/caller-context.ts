// Caller context on app-initiated calls (BRIDGE §8.5, SDK-API §18.6; spec 0.1.77, C367 P4). The ONE implementation (L1):
// the bridge validates `CallEnvelope.context` with `callerContextProblem`, the SDK pre-checks with the same function, conformance runs
// the spec case file against it; the SDK builds the `tb.holds_pending` summary with `callerContextSummary`.
import { CALLER_CONTEXT_MAX_BYTES, CALLER_CONTEXT_MAX_DEPTH, callerContextKeyPattern, RESERVED_CONTEXT_PREFIX } from "@opt2-tealbrick/spec/bridge";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { CALLER_CONTEXT_SUMMARY_MAX_CHARS, CALLER_CONTEXT_SUMMARY_VALUE_MAX_CHARS, CALLER_CONTEXT_SUMMARY_VALUE_SEGMENTS } from "@opt2-tealbrick/spec/sdk";
import { canonicalize } from "./jcs.ts";

export {
  CALLER_CONTEXT_KEY_TAIL,
  CALLER_CONTEXT_MAX_BYTES,
  CALLER_CONTEXT_MAX_DEPTH,
  callerContextKeyPattern,
} from "@opt2-tealbrick/spec/bridge";
export { CALLER_CONTEXT_SUMMARY_MAX_CHARS, CALLER_CONTEXT_SUMMARY_VALUE_MAX_CHARS, CALLER_CONTEXT_SUMMARY_VALUE_SEGMENTS } from "@opt2-tealbrick/spec/sdk";

/** Bridge capability (`BRIDGE_CAPS`): the bridge accepts `CallEnvelope.context` on the companion path (BRIDGE §8.5). Without it `callApp({ context })` throws `bridge_cap_missing`. */
export const APP_CALL_CONTEXT_CAP = "app_call_context" as const;
/** Bridge capability (`BRIDGE_CAPS`): the bridge routes the standard op `tb.hold_status` to an app caller whose companion grant lists it (BRIDGE §8.3, SDK-API §4.7). */
export const APP_HOLD_STATUS_CAP = "app_hold_status" as const;

/** A refused context: `pointer` is an RFC 6901 JSON pointer into the request (`/context` or `/context/<key>`). The message never repeats a value. */
export interface CallerContextProblem {
  pointer: string;
  message: string;
}

/** `^[a-z][a-z0-9-]{1,31}$` (CORE §1, GRANT-PRD): the only shape a verified product id has. Anything else counts as "no verified product". */
const PRODUCT_RE = /^[a-z][a-z0-9-]{1,31}$/;

const isPlainObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** RFC 6901 token escape: `~` first, then `/`. */
const pointerToken = (k: string) => k.replaceAll("~", "~0").replaceAll("/", "~1");

/** Depth of a value: a scalar is 0, `[1]` is 1, `{"a":[1]}` is 2; an empty array or object is 0. Stops counting past `limit` (no deep recursion). */
function depthOver(v: unknown, limit: number, at = 0): boolean {
  if (v === null || typeof v !== "object") return false;
  // `at` = the depth of the container's own level; a container with any child sits at least one level above its children
  const children = Array.isArray(v) ? v : Object.values(v);
  if (children.length === 0) return false;
  if (at + 1 > limit) return true;
  for (const c of children) if (depthOver(c, limit, at + 1)) return true;
  return false;
}

/**
 * BRIDGE §8.5 rules, in the spec's order; the first failing rule wins:
 * 1. `context` is a JSON object; 2. its JCS serialization is at most `CALLER_CONTEXT_MAX_BYTES` UTF-8 bytes; (no verified product and a
 * non-empty object is refused here, pointer `/context`); 3. over all keys in sorted order: a `tb.` key or a key that fails
 * `callerContextKeyPattern(callerProduct)`; 4. over all keys in sorted order: depth under the key above `CALLER_CONTEXT_MAX_DEPTH`.
 * `callerProduct` is the caller's VERIFIED product (the `prd` of the presented companion grant), `null` when there is none: then only
 * `{}` passes. Returns null when the context is acceptable.
 */
export function callerContextProblem(callerProduct: string | null, context: unknown): CallerContextProblem | null {
  if (!isPlainObject(context)) return { pointer: "/context", message: "context must be a JSON object" };
  let bytes: number;
  try {
    bytes = Buffer.byteLength(canonicalize(context as Json), "utf8");
  } catch {
    // not I-JSON (undefined, non-finite number, lone surrogate, non-plain object) or too deeply nested to serialize
    return { pointer: "/context", message: "context is not a valid JSON object" };
  }
  if (bytes > CALLER_CONTEXT_MAX_BYTES) return { pointer: "/context", message: `context is larger than ${CALLER_CONTEXT_MAX_BYTES} bytes` };
  const keys = Object.keys(context).sort(); // UTF-16 code unit order
  const product = callerProduct !== null && PRODUCT_RE.test(callerProduct) ? callerProduct : null;
  if (keys.length > 0 && product === null) return { pointer: "/context", message: "context needs a verified caller product" };
  if (product === null) return null;
  const pattern = callerContextKeyPattern(product);
  for (const k of keys) {
    if (k.startsWith(RESERVED_CONTEXT_PREFIX)) return { pointer: `/context/${pointerToken(k)}`, message: `a context key in the ${RESERVED_CONTEXT_PREFIX} namespace is reserved` };
    if (!pattern.test(k)) return { pointer: `/context/${pointerToken(k)}`, message: `a context key must be ${product}.<name> (1 to 4 segments of a-z, 0-9, _; at most 40 characters each)` };
  }
  for (const k of keys) {
    if (depthOver(context[k], CALLER_CONTEXT_MAX_DEPTH)) return { pointer: `/context/${pointerToken(k)}`, message: `a context value is nested deeper than ${CALLER_CONTEXT_MAX_DEPTH}` };
  }
  return null;
}

/** The first `n` code points of `s` (never splits a surrogate pair). */
const cutCodePoints = (s: string, n: number) => Array.from(s).slice(0, n).join("");

/**
 * SDK-API §18.6 rule 6: the one-line `HoldsPendingItem.callerContext` summary of a receipt's `meta.callerContext`. Sorted keys (code-unit
 * order); a key shows bare, except when its LAST segment is `workflow`, `version` or `run` and its value is a scalar: then `key=<JSON value>`
 * with the JSON text cut to 64 code points (no marker). Entries join with "; "; a whole text over 256 code points keeps the first 255 plus
 * "…". All counts are code points, not UTF-16 units. `undefined` when there is no object or it has no key.
 */
export function callerContextSummary(callerContext: unknown): string | undefined {
  if (!isPlainObject(callerContext)) return undefined;
  const keys = Object.keys(callerContext).sort();
  if (keys.length === 0) return undefined;
  const parts = keys.map((k) => {
    const v = callerContext[k];
    const last = k.split(".").at(-1) as string;
    const scalar = v === null || typeof v !== "object";
    if (!scalar || !(CALLER_CONTEXT_SUMMARY_VALUE_SEGMENTS as readonly string[]).includes(last)) return k;
    const text = JSON.stringify(v); // undefined (not JSON) or a function cannot come from stored meta; shown bare then
    return text === undefined ? k : `${k}=${cutCodePoints(text, CALLER_CONTEXT_SUMMARY_VALUE_MAX_CHARS)}`;
  });
  const all = parts.join("; ");
  const cps = Array.from(all);
  return cps.length > CALLER_CONTEXT_SUMMARY_MAX_CHARS ? `${cps.slice(0, CALLER_CONTEXT_SUMMARY_MAX_CHARS - 1).join("")}…` : all;
}
