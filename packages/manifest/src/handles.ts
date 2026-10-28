// Channel handles (G-4, RUL-06, INB-03): ONE canonical form "<channel>:<value>", equal to the `tb.onBehalfOf`
// channel_sender id (SDK-API §18). Governance (fleet), Rules and Inbox import these instead of keeping own copies (L1).
// Canonical value per channel, as Connect reports a sender: Buzz = npub (bech32 of the 32-byte Nostr public key; a
// 64-hex key becomes its npub), Slack = upper-case user id (C373: or conversation id C/G/D), Telegram = numeric user or chat id.
// Spec next (unreleased; C373, G-6): + Email = a bare addr-spec, lower-cased (recipients of outward calls,
// `extractRecipients`). No display name, comment, quoted local part or list is parsed: the resolving app extracts addresses.
// No Buffer and no Node APIs: browser bundles (Portal GUI, app UIs) may import it.
import { parseChannelSender } from "./hooks.ts";

export const HANDLE_CHANNELS = ["buzz", "slack", "telegram", "email"] as const;
export type HandleChannel = (typeof HANDLE_CHANNELS)[number];

const BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3] as const;
const HEX64 = /^[0-9a-f]{64}$/;
const NPUB_SHAPE = /^npub1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$/;
/** C373: dot-atom local part (RFC 5322 atext, lower case), `@`, two or more LDH labels; ASCII only (an IDN arrives as `xn--`). */
const EMAIL_SHAPE = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function polymod(values: readonly number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i] as number;
  }
  return chk >>> 0;
}

const hrpExpand = (hrp: string): number[] => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

function convertBits(data: readonly number[], from: number, to: number, pad: boolean): number[] | null {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  const max = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = ((acc << from) | v) & 0xffffff;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & max);
    }
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & max);
  } else if (bits >= from || (acc << (to - bits)) & max) return null;
  return out;
}

/** 32-byte public key as 64 hex characters (either case) → npub. Throws on any other input (never truncates). */
export function npubFromHex(hex: string): string {
  const h = hex.toLowerCase();
  if (!HEX64.test(h)) throw new Error("npubFromHex: expected 64 hex characters");
  const bytes: number[] = [];
  for (let i = 0; i < 64; i += 2) bytes.push(Number.parseInt(h.slice(i, i + 2), 16));
  const data = convertBits(bytes, 8, 5, true) as number[];
  const mod = polymod([...hrpExpand("npub"), ...data, 0, 0, 0, 0, 0, 0]) ^ 1;
  const checksum = [0, 1, 2, 3, 4, 5].map((i) => (mod >>> (5 * (5 - i))) & 31);
  return `npub1${[...data, ...checksum].map((d) => BECH32[d]).join("")}`;
}

/** True only for a lower-case npub with a valid bech32 checksum and a 32-byte payload. */
export function isNpub(s: string): boolean {
  if (!NPUB_SHAPE.test(s)) return false;
  const data = [...s.slice(5)].map((c) => BECH32.indexOf(c));
  if (polymod([...hrpExpand("npub"), ...data]) !== 1) return false;
  return convertBits(data.slice(0, -6), 5, 8, false)?.length === 32;
}

/** QA-RCP-4 (C373): printable ASCII only, checked BEFORE any case folding: `toLowerCase` / `toUpperCase` map some non-ASCII
 *  code points onto ASCII (U+212A Kelvin sign → `k`, `ß` → `SS`, `ı` → `I`, `ſ` → `S`), so a folded value would differ from the
 *  bytes the app sends. */
const PRINTABLE_ASCII = /^[ -~]*$/;

function canonicalValue(channel: HandleChannel, raw: string): string | null {
  const v = raw.trim();
  if (!PRINTABLE_ASCII.test(v)) return null;
  switch (channel) {
    case "buzz": {
      const s = v.toLowerCase();
      if (HEX64.test(s)) return npubFromHex(s);
      return isNpub(s) ? s : null;
    }
    case "slack": {
      // U/W = a person (user id); C/G/D = a conversation (channel, private group, DM; C373) — a recipient handle, never a person
      const s = v.toUpperCase();
      return /^[UWCGD][A-Z0-9]{2,30}$/.test(s) ? s : null;
    }
    case "telegram":
      return /^-?[1-9][0-9]{0,19}$/.test(v) ? v : null;
    case "email": {
      const s = v.toLowerCase();
      // QA-RCP-5: the last domain label holds a letter (no `a@1.2.3.4`, no all-numeric top-level label)
      return s.length <= 254 && s.indexOf("@") <= 64 && EMAIL_SHAPE.test(s) && /[a-z]/.test(s.slice(s.lastIndexOf(".") + 1)) ? s : null;
    }
  }
}

/**
 * A channel_sender id (`buzz:npub1…`, `slack:U…`, `telegram:123`, `email:a@b.example`) or a bare npub → the canonical handle, or null when the
 * channel is not one of HANDLE_CHANNELS or the value is not valid for it. Never throws. Callers treat null as "no match",
 * never as the raw input (a fallback to the raw string would let two spellings of one sender differ).
 */
export function normalizeHandle(input: string): string | null {
  if (typeof input !== "string") return null;
  const id = parseChannelSender(input.trim());
  if (!id || !(HANDLE_CHANNELS as readonly string[]).includes(id.channel)) return null;
  const value = canonicalValue(id.channel as HandleChannel, id.value);
  return value ? `${id.channel}:${value}` : null;
}

/** The channel of a canonical handle (from normalizeHandle), or null for anything else. */
export function handleChannel(handle: string): HandleChannel | null {
  const n = normalizeHandle(handle);
  return n === handle ? (n.slice(0, n.indexOf(":")) as HandleChannel) : null;
}
