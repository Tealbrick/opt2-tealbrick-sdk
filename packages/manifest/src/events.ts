// App events (MANIFEST §16, BRIDGE §14, SDK-API §20; spec 0.1.57, C274c/C274d): the ONE implementation of the declaration
// lookup, the scope type of an event, the payload check and the grant rule. The SDK (ctx.emit, the outbox sender) and the
// bridge (ingest, fan-out, delivery) both call these (L1); neither keeps its own copy.
import { PLATFORM_EVENTS, type PlatformEventType } from "@opt2-tealbrick/spec/bridge";
import type { CrudAction, EventDecl, JsonSchemaObject, Manifest } from "@opt2-tealbrick/spec/manifest";
import { RESERVED_EVENT_PREFIX } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { opInGrantWorkflow, opVisibleToGrant } from "./decision.ts";
import { canonicalize } from "./jcs.ts";
import { withStandardOps } from "./ops.ts";
import { validateAgainstSchema } from "./validate.ts";

/** MANIFEST §16.1: an app event name (without the product). The `tb.` namespace is the platform's. */
export const EVENT_NAME_RE = /^(?!tb\.)[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
export const EVENT_NAME_MAX = 64;
/** BRIDGE §14.1 / SDK-API §20: the idempotency key of one emit (default: a ULID made at emit). */
export const EVENT_KEY_RE = /^[A-Za-z0-9._:-]{8,128}$/;
export const EVENT_SUBJECT_KIND_RE = /^[a-z][a-z0-9_]{0,31}$/;
export const EVENT_SUBJECT_ID_MAX = 256;
export const EVENT_INSTANCE_ID_MAX = 256;
/** `data` ≤ 2 KiB (JCS bytes) per event (C274d ruling 2). */
export const EVENT_DATA_MAX_BYTES = 2048;
/** BRIDGE §14.1 / SDK-API §20: one wire item WITHOUT `eligible` ≤ 4 KiB (UTF-8 bytes of its JSON); `eligible` has its own limit. */
export const EVENT_ITEM_MAX_BYTES = 4096;
/** `payloadSchema` ≤ 8 KiB (JCS bytes) (M-EV-2). */
export const EVENT_SCHEMA_MAX_BYTES = 8192;
export const EVENT_SUMMARY_MAX = 280;
/** `to` of a target event: 1..100 agents. */
export const EVENT_TO_MAX = 100;
/** `eligible` of a scoped event: ≤ 500 entries (a slice has at most 500 agents). */
export const EVENT_ELIGIBLE_MAX = 500;
/** One ingest batch: 1..100 items. */
export const EVENT_BATCH_MAX = 100;
/** Bridge dedupe window and SDK outbox prune age (7 days). */
export const EVENT_WINDOW_MS = 7 * 86_400_000;

/** A declaration the SDK and the bridge can emit / check: a manifest `events[]` entry or a `PLATFORM_EVENTS` type. */
export type ResolvedEventDecl = EventDecl & { platform: boolean; subjectKind?: string };

/** True for a name in the platform's `tb.` event namespace. */
export function isReservedEventName(name: string): boolean {
  return name.startsWith(RESERVED_EVENT_PREFIX);
}

/**
 * The declaration of `name` for `manifest`: a `tb.*` name is a PLATFORM_EVENTS type (null when unknown), any other name is the
 * manifest's own `events[]` entry (null when undeclared). The platform declaration names its standard op in `visibleWith`
 * (`tb.hold_status`: any valid grant, CORE I4).
 */
export function eventDecl(manifest: Pick<Manifest, "events">, name: string): ResolvedEventDecl | null {
  if (isReservedEventName(name)) {
    if (!Object.hasOwn(PLATFORM_EVENTS, name)) return null;
    const p = PLATFORM_EVENTS[name as PlatformEventType];
    return {
      name,
      title: p.title,
      payloadSchema: p.payloadSchema as unknown as JsonSchemaObject,
      visibleWith: p.visibleWith as EventDecl["visibleWith"],
      audience: p.audience,
      platform: true,
      subjectKind: p.subjectKind,
    };
  }
  const d = (manifest.events ?? []).find((e) => e.name === name);
  return d ? { ...d, platform: false } : null;
}

/**
 * The scope type of an event = the `scopeType` of its `visibleWith` op, or null (an UNSCOPED event). There is no declared
 * `scoped` flag: a derived one cannot disagree with the op (MANIFEST §16.1). Platform events are unscoped.
 */
export function eventScopeType(manifest: Pick<Manifest, "operations">, decl: Pick<EventDecl, "visibleWith"> & { platform?: boolean }): string | null {
  if (decl.platform) return null;
  return manifest.operations.find((o) => o.id === decl.visibleWith)?.scopeType ?? null;
}

/** The crud of the `visibleWith` op (what a scope row must admit for a scoped event); [] when the op is missing. */
export function eventVisibleCrud(manifest: Manifest, decl: Pick<EventDecl, "visibleWith">): CrudAction[] {
  return [...(withStandardOps(manifest).find((o) => o.id === decl.visibleWith)?.crud ?? [])];
}

export type EventPayloadCheck =
  | { ok: true; bytes: number }
  | { ok: false; code: "event_payload_invalid" | "event_too_large"; errors: { path: string; message: string }[] };

/**
 * `data` against the declaration: a JSON object, ≤ 2 KiB (JCS) → else `event_too_large`; validates against `payloadSchema`
 * (compiled once and cached) → else `event_payload_invalid`. The size check comes first (a 1 MB payload is not walked).
 */
export function validateEventPayload(decl: Pick<EventDecl, "payloadSchema">, data: unknown): EventPayloadCheck {
  if (!data || typeof data !== "object" || Array.isArray(data)) return { ok: false, code: "event_payload_invalid", errors: [{ path: "", message: "data must be a JSON object" }] };
  let bytes: number;
  try {
    bytes = Buffer.byteLength(canonicalize(data as Json));
  } catch (e) {
    return { ok: false, code: "event_payload_invalid", errors: [{ path: "", message: `not a JSON value: ${(e as Error).message}` }] };
  }
  if (bytes > EVENT_DATA_MAX_BYTES) return { ok: false, code: "event_too_large", errors: [{ path: "", message: `data is ${bytes} JCS bytes (max ${EVENT_DATA_MAX_BYTES})` }] };
  const v = validateAgainstSchema(decl.payloadSchema, data as Json);
  return v.ok ? { ok: true, bytes } : { ok: false, code: "event_payload_invalid", errors: v.errors };
}

/**
 * MANIFEST §16.2 rule 1 for one agent: the tools/list rule (`opVisibleToGrant`) for the event's `visibleWith` op, with the
 * per-entry authority of a SCOPED event: `authority: "owner"` (the agent's `eligible` entry; the C283 A1 rule, as `gate()` does
 * for scoped ops) skips `op.crud ⊆ grant.crud` and keeps every other step (agent audience, declared scope type, the `wf` rule);
 * `"bounded"` or absent keeps it. A missing op is never visible. Pause and grant validity are the caller's (as for tools/list).
 */
export function eventVisibleToGrant(
  manifest: Manifest,
  decl: Pick<EventDecl, "visibleWith">,
  claims: { mode: string; wf: readonly string[]; crud: readonly CrudAction[] },
  authority: "owner" | "bounded" | null = null,
): boolean {
  const op = withStandardOps(manifest).find((o) => o.id === decl.visibleWith);
  if (!op) return false;
  const declared = (manifest.scopes ?? []).map((s) => s.type);
  const scopeType = op.standard ? undefined : op.scopeType;
  if (authority === "owner" && scopeType !== undefined) {
    if (op.audience !== "agent" || !declared.includes(scopeType)) return false;
    return opInGrantWorkflow(claims, op.id, op.standard ? undefined : op.listing);
  }
  return opVisibleToGrant(op, claims, declared);
}
