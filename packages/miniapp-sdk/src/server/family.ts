// The family rule of relayed decisions (SDK-API §21, C332a(4), spec 0.1.64 sdk.ts `familyAllowedFor`).
import type { PersonOpClient } from "@opt2-tealbrick/spec/credentials";
import { type HoldFamily, KNOWN_HOLD_FAMILIES } from "@opt2-tealbrick/spec/manifest";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import { TbError } from "./errors.ts";

/**
 * v0.1.39 (C332a(4), SDK-API §21, spec 0.1.64 sdk.ts): may a decision made through the relay (`via` set) decide a hold of
 * `family`? Browser sessions (`via` undefined) → true. Relayed (`via` set) → false when the family is null, not a known
 * HoldFamily (e.g. `caps`, `policy`, a newer family) or listed in `PERSON_OP_RELAY.refuseFamiliesFor[via]`, and false for a
 * `via` without an entry there (deny by default, spec e62bbad). The SDK enforces it in `tb.holds_decide`; an app decide op (Inbox
 * `item_decide` for an item carrying a hold, C277 A3) calls it with `ctx.caller.via` and answers 403 `family_needs_portal`.
 */
export function familyAllowedFor(via: PersonOpClient | undefined, family: HoldFamily | null): boolean {
  if (via === undefined) return true;
  if (typeof family !== "string" || !(KNOWN_HOLD_FAMILIES as readonly string[]).includes(family)) return false;
  const refused = (PERSON_OP_RELAY.refuseFamiliesFor as Record<string, readonly string[] | undefined>)[via];
  if (!Array.isArray(refused)) return false;
  return !refused.includes(family);
}

/** 403 `family_needs_portal`: the decision has to be made in the app opened from Portal (SDK-API §21 family rule). */
export function familyNeedsPortal(): TbError {
  return new TbError("family_needs_portal", "this decision can only be made in the app opened from Portal", 403);
}
