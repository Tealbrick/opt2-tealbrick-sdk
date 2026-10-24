// Hook answers, the before-chain reducer, the reserved `tb.onBehalfOf` carrier and the launch path rule
// (spec 0.1.13: BRIDGE §8.1 step 6 / §8.5, PORTAL-API v0.1.13, SDK-API §18). ONE implementation for bridge, SDK,
// Core and conformance.

import type { HookHoldVerdict, OnBehalfOfClaim, OnBehalfOfContext } from "@opt2-tealbrick/spec/bridge";
import { RESERVED_CONTEXT_PREFIX } from "@opt2-tealbrick/spec/bridge";
import { HOOK_HOLD_FAMILIES, type HookPhase } from "@opt2-tealbrick/spec/manifest";
import { canonicalize, digest } from "./jcs.ts";

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const POINTER_RE = /^(\/([^~/]|~[01])*)*$/;

/**
 * Phase shape of a hook answer (BRIDGE §8.1 steps 6, 7, 12; v0.1.13 hold verdict and reserved `tb.` namespace).
 * `product` = the answering hook's product (context keys must start with `<product>.`). Returns the problem or null.
 */
export function hookResponseProblem(phase: HookPhase, body: unknown, product: string): string | null {
  if (!isObj(body)) return "answer is not an object";
  const keys = Object.keys(body);
  if (phase === "before") {
    const extra = keys.filter((k) => k !== "allow" && k !== "reason" && k !== "hold");
    if (extra.length) return `unknown keys ${extra.join(",")}`;
    if (typeof body.allow !== "boolean") return "allow not boolean";
    if (body.reason !== undefined && typeof body.reason !== "string") return "reason not a string";
    if (body.hold !== undefined) {
      if (body.allow) return "hold with allow true";
      const h = body.hold;
      if (!isObj(h) || Object.keys(h).some((k) => k !== "family" && k !== "reason")) return "hold shape";
      if (typeof h.family !== "string" || !(HOOK_HOLD_FAMILIES as readonly string[]).includes(h.family)) return "hold family";
      if (typeof h.reason !== "string" || h.reason.length < 1 || h.reason.length > 280) return "hold reason (1..280)";
    }
    return null;
  }
  if (phase === "context") {
    if (keys.some((k) => k !== "add")) return "unknown keys";
    if (!isObj(body.add)) return "add not an object";
    for (const k of Object.keys(body.add)) {
      if (k.startsWith(RESERVED_CONTEXT_PREFIX)) return `reserved key ${k}`;
      if (!k.startsWith(`${product}.`) || k.length === product.length + 1) return `key ${k} outside ${product}.`;
    }
    return null;
  }
  if (keys.some((k) => k !== "output" && k !== "redactions")) return "unknown keys";
  if (body.redactions !== undefined && (!Array.isArray(body.redactions) || !body.redactions.every((p) => typeof p === "string" && POINTER_RE.test(p)))) return "redactions not JSON pointers";
  return null;
}

export type BeforeChainResult =
  | { kind: "allow" }
  | { kind: "refuse"; by: string; reason: string | null }
  | { kind: "hold"; by: string; verdict: HookHoldVerdict };

/**
 * The before-chain precedence (BRIDGE v0.1.13): answers in chain order (`by` = `<product>/<hookId>`, `answer` already
 * shape-checked). The first refuse wins at once; else the FIRST hold is kept; else allow. Callers may stop calling
 * hooks after a refuse; a kept hold never stops the chain.
 */
export function reduceBeforeChain(answers: readonly { by: string; answer: { allow: boolean; reason?: string; hold?: HookHoldVerdict } }[]): BeforeChainResult {
  let hold: BeforeChainResult | null = null;
  for (const { by, answer } of answers) {
    if (!answer.allow && !answer.hold) return { kind: "refuse", by, reason: answer.reason ?? null };
    if (!answer.allow && answer.hold && !hold) hold = { kind: "hold", by, verdict: { family: answer.hold.family, reason: answer.hold.reason } };
  }
  return hold ?? { kind: "allow" };
}

/** `hv` proof claim for a kept hold (CREDENTIALS v0.1.13). */
export function holdVerdictClaim(r: Extract<BeforeChainResult, { kind: "hold" }>): { f: HookHoldVerdict["family"]; r: string; by: string } {
  return { f: r.verdict.family, r: r.verdict.reason, by: r.by };
}

/** channel_sender id `"<channel>:<value>"` (SDK-API §18). */
export const CHANNEL_SENDER_RE = /^[a-z0-9_-]{1,32}:.+$/;

/** `channel_sender` id from Connect's channel and sender value. */
export function channelSenderId(channel: string, value: string): string {
  const id = `${channel}:${value}`;
  if (!CHANNEL_SENDER_RE.test(id) || value.length === 0) throw new Error("channel_sender: channel must match [a-z0-9_-]{1,32} and value be non-empty");
  return id;
}

/** Parses a `channel_sender` id; a bare `npub1…` reads as `buzz:` (compatibility). Null when not parseable. */
export function parseChannelSender(id: string): { channel: string; value: string } | null {
  if (id.startsWith("npub1")) return { channel: "buzz", value: id };
  if (!CHANNEL_SENDER_RE.test(id)) return null;
  const i = id.indexOf(":");
  return { channel: id.slice(0, i), value: id.slice(i + 1) };
}

/**
 * Bridge §8.5: `_meta["tealbrick/onBehalfOf"]` → context `tb.onBehalfOf` (unverified), or null when absent or invalid
 * (kind unknown, id 1..256, display ≤ 128, no other keys, JCS ≤ 1024 bytes, channel_sender id `<channel>:<value>`).
 */
export function onBehalfOfFromMeta(value: unknown): OnBehalfOfContext | null {
  if (!isObj(value)) return null;
  if (Object.keys(value).some((k) => k !== "kind" && k !== "id" && k !== "display")) return null;
  const { kind, id, display } = value;
  if (kind !== "person" && kind !== "agent" && kind !== "channel_sender") return null;
  if (typeof id !== "string" || id.length < 1 || id.length > 256) return null;
  if (display !== undefined && (typeof display !== "string" || display.length > 128)) return null;
  if (kind === "channel_sender" && !CHANNEL_SENDER_RE.test(id)) return null;
  const claim: OnBehalfOfClaim = { kind, id, ...(display !== undefined ? { display } : {}) };
  if (new TextEncoder().encode(canonicalize(claim as unknown as Parameters<typeof canonicalize>[0])).length > 1024) return null;
  return { claim, verified: false, via: "mcp_meta" };
}

/**
 * Launch path rule (PORTAL-API v0.1.13, C86): app-relative, starts with `/`, ≤ 512 chars, no scheme, host, `//`, `\`,
 * control characters or `..` segment — checked on the raw string and after percent-decoding. A leading `/` without
 * `//` already rules out a scheme or host.
 */
export function isValidLaunchPath(path: string): boolean {
  if (typeof path !== "string" || path.length < 1 || path.length > 512) return false;
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false;
  }
  for (const p of [path, decoded]) {
    if (!p.startsWith("/") || p.startsWith("//")) return false;
    if (p.includes("\\") || p.includes("//")) return false;
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the rule rejects control characters
    if (/[\u0000-\u001f\u007f]/.test(p)) return false;
    if (p.split(/[/?#]/).some((seg) => seg === "..")) return false;
  }
  return true;
}

/** C98 (BRIDGE §7.2, spec 0.1.14): window of a derived idempotency key. */
export const DERIVED_IDEMPOTENCY_WINDOW_MS = 10 * 60_000;

/**
 * C98: the idempotency key the bridge derives when a `tools/call` carries no `_meta["tealbrick/idempotencyKey"]`
 * (model-driven clients cannot set `_meta`): `drv_` + hex sha256 of JCS {c: connection id, s: MCP session id, op,
 * in: canonical input, b: 10-min bucket}. Same call in the same session and window → same key (deduplicated by the
 * app); clients that send a key keep exact semantics. ONE implementation for the bridge and its conformance fakes.
 */
export function deriveIdempotencyKey(i: { connection: string; session: string; op: string; input: unknown; now: number }): string {
  const bucket = Math.floor(i.now / DERIVED_IDEMPOTENCY_WINDOW_MS);
  const d = digest({ c: i.connection, s: i.session, op: i.op, in: i.input as Parameters<typeof digest>[0], b: bucket });
  return `drv_${d.slice("sha256:".length)}`;
}

/** v0.1.22 (G5, SDK-API §18): THE memory tag normalisation — trim + lower case, on write and on compare. */
export function normalizeTag(tag: string): string {
  return tag.trim().toLowerCase();
}

/**
 * v0.1.23 (G5, C115): THE `rules.narrowing` tag comparison. `memoryTags.anyOf` PRESENT (even empty) → at least one
 * normalised item tag is in it, so an empty `anyOf` passes NOTHING (Rules emits it for a disjoint merge; treating it as "no
 * constraint" would widen access, L13); `noneOf` → no normalised item tag is in it; absent `memoryTags` / absent `anyOf` →
 * no anyOf constraint. Callers handle items whose
 * tags are UNKNOWN themselves (dropped under any narrowing, §18 point 4) — an empty `tags` array means "no tags".
 */
export function tagsMatch(memoryTags: { anyOf?: readonly string[]; noneOf?: readonly string[] } | undefined, tags: readonly string[]): boolean {
  if (!memoryTags) return true;
  const have = new Set(tags.map(normalizeTag));
  if (memoryTags.anyOf !== undefined && !memoryTags.anyOf.map(normalizeTag).some((t) => have.has(t))) return false;
  return !(memoryTags.noneOf ?? []).map(normalizeTag).some((t) => have.has(t));
}

/** spec 0.1.68 (C336 RQ-2, SDK-API §18.5 rule 1): limits of a `deepDatasets` narrowing — each list ≤ 64 ids of 1–128 chars. */
export const DEEP_DATASETS_MAX_IDS = 64;
export const DEEP_DATASET_ID_MAX_CHARS = 128;

/** spec 0.1.68 (C336 RQ-2): `RulesNarrowingV2.deepDatasets` (local until the spec pin carries `RulesNarrowingV2`). */
export interface DeepDatasets {
  anyOf?: readonly string[];
  noneOf?: readonly string[];
}

/**
 * spec 0.1.68 (C336 RQ-2, SDK-API §18.5 rule 1): is `value` a well-formed `deepDatasets`? An object with at least one of
 * `anyOf` / `noneOf` (no other keys), each an array of 0–64 strings of 1–128 characters. A reader refuses anything else
 * (`{}`, `null`, a non-array, a non-string item, an over-long list or id) with `narrowing_unsupported`.
 */
export function deepDatasetsValid(value: unknown): value is DeepDatasets {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  if (keys.length === 0 || keys.some((k) => k !== "anyOf" && k !== "noneOf")) return false;
  return keys.every((k) => {
    const list = (value as Record<string, unknown>)[k];
    return (
      Array.isArray(list) &&
      list.length <= DEEP_DATASETS_MAX_IDS &&
      list.every((id) => typeof id === "string" && id.length >= 1 && id.length <= DEEP_DATASET_ID_MAX_CHARS)
    );
  });
}

/**
 * spec 0.1.68 (C336 RQ-2, SDK-API §18.5 rule 3): THE `rules.narrowing.deepDatasets` comparison. `ids` = the CANONICAL
 * dataset ids a data read names or would read (the app resolves names first, rule 2). Exact, case-sensitive: no trimming,
 * no case folding, no Unicode normalisation. Absent narrowing → pass. Otherwise `ids` must be non-empty (an empty list means
 * "every dataset", rule 4: the op restricts itself or refuses `narrowing_unsupported`), then `anyOf` present → every id is in
 * it (`anyOf: []` passes nothing) and `noneOf` present → no id is in it. A malformed narrowing (see `deepDatasetsValid`) never
 * passes (fail closed; the reader answers `narrowing_unsupported`).
 */
export function datasetsMatch(deepDatasets: DeepDatasets | undefined, ids: readonly string[]): boolean {
  if (deepDatasets === undefined) return true;
  if (!deepDatasetsValid(deepDatasets) || ids.length === 0) return false;
  if (deepDatasets.anyOf !== undefined) {
    const allow = new Set(deepDatasets.anyOf);
    if (!ids.every((id) => allow.has(id))) return false;
  }
  const deny = new Set(deepDatasets.noneOf ?? []);
  return !ids.some((id) => deny.has(id));
}
