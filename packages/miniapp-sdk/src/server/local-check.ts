// The local check of BRIDGE §15.3 (spec follow-up #49, QA-SPEC49): one text classifier for a model base URL, and the address rules
// the connect-time guard applies after it resolved the host. `modelFetch` (model-fetch.ts) and `tb-exec` (exec/roles.ts) use them.
// Data: spec `examples/local-check.cases.json`, copied to test/vectors with its source (every `kind: "base"` row is tested).
import { BlockList, isIP } from "node:net";
import { NEVER_LOCAL, NEVER_LOCAL_HOSTNAMES, type PolicyBasis } from "@opt2-tealbrick/manifest";

export type LocalCheckResult = "verified" | "owner_listed" | "not_local" | "refused";
export interface Classified {
  result: LocalCheckResult;
  /** `url.href` (WHATWG) when the input parsed: the form the bridge stores and serves */
  canonical?: string;
  /** the host as the rules read it: lower case, one trailing dot and the IPv6 brackets removed, an IPv4-mapped IPv6 as dotted IPv4 */
  host?: string;
}

function listOf(cidrs: readonly string[]): BlockList {
  const l = new BlockList();
  for (const c of cidrs) {
    const [net, bits] = c.split("/") as [string, string];
    l.addSubnet(net, Number(bits), isIP(net) === 6 ? "ipv6" : "ipv4");
  }
  return l;
}
const NEVER = listOf(NEVER_LOCAL);
/** BRIDGE §15.3 step 4 (verified by text, and the ranges a resolved address of a `local` binding must be in) */
const VERIFIED = listOf(["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"]);
const CGNAT = listOf(["100.64.0.0/10"]);
/** Addresses that are private to a network (verified ranges and CGNAT): a name must not mix them with public ones. */
export function isPrivateAddress(address: string): boolean {
  const c = canonicalIp(address);
  return c !== null && (inList(VERIFIED, c) || inList(CGNAT, c));
}
/** Transport rule: `http:` to an Own hosts IP literal only in these ranges */
const OWN_HTTP_IP = listOf(["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"]);
const NEVER_NAMES: ReadonlySet<string> = new Set(NEVER_LOCAL_HOSTNAMES);

/** Canonical IP text of an address string (zone id dropped; IPv4-mapped IPv6 decoded to dotted IPv4), or null when it is no IP. */
export function canonicalIp(address: string): { ip: string; family: 4 | 6 } | null {
  const a = address.replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  const fam = isIP(a);
  if (fam === 4) return { ip: a, family: 4 };
  if (fam !== 6) return null;
  let v6: string;
  try {
    v6 = new URL(`http://[${a}]/`).hostname.slice(1, -1);
  } catch {
    return null;
  }
  const m = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(v6);
  if (m) {
    const hi = Number.parseInt(m[1] as string, 16);
    const lo = Number.parseInt(m[2] as string, 16);
    return { ip: `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, family: 4 };
  }
  return { ip: v6, family: 6 };
}
const inList = (list: BlockList, c: { ip: string; family: 4 | 6 }): boolean => list.check(c.ip, c.family === 4 ? "ipv4" : "ipv6");

/** Input hygiene (step 0): WHATWG and other parsers disagree on these characters (`\`, `@`, their look-alikes U+FF20, U+FE6B, U+FF3C and their percent forms), so the input is refused. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: the control characters are exactly what step 0 refuses
const HYGIENE = /[\\@\uFF20\uFE6B\uFF3C\s?#\u0000-\u001f\u007f]|%40|%5c/iu;

/** Steps 0-2: the parsed URL and its rule host, or null (refused). */
export function parseBase(input: string): { url: URL; host: string } | null {
  if (HYGIENE.test(input)) return null;
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  let host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (host.endsWith(".")) host = host.slice(0, -1);
  const ip = canonicalIp(host);
  return { url, host: ip ? ip.ip : host };
}

/** Step 3: the host is an address in NEVER_LOCAL or a name in NEVER_LOCAL_HOSTNAMES. */
export function isNeverLocalHost(host: string): boolean {
  const ip = canonicalIp(host);
  return ip ? inList(NEVER, ip) : NEVER_NAMES.has(host.toLowerCase());
}

/**
 * BRIDGE §15.3 steps 0-6 + the transport rule. `ownInfraOrigins` = `TB_OWN_INFRA_ORIGINS`, `ownHosts` = the owner's "Own hosts"
 * origins (the bridge's data; a caller without them gets `not_local` / `refused` for what only they could vouch for).
 */
export function classifyBaseUrl(input: string, opts: { ownInfraOrigins?: readonly string[]; ownHosts?: readonly string[] } = {}): Classified {
  const parsed = parseBase(input);
  if (!parsed) return { result: "refused" };
  const { url, host } = parsed;
  const canonical = url.href;
  const never = isNeverLocalHost(host);
  const ip = canonicalIp(host);
  const sameOrigin = (o: string): boolean => {
    try {
      return new URL(o).origin === url.origin;
    } catch {
      return false;
    }
  };
  const verified = !never && (host === "localhost" || host.endsWith(".railway.internal") || (opts.ownInfraOrigins ?? []).some(sameOrigin) || (ip !== null && inList(VERIFIED, ip)));
  const owned = !never && (opts.ownHosts ?? []).some(sameOrigin);
  if (url.protocol === "http:") {
    // a key never crosses a network in clear text to a name: http only for a verified host or an Own hosts IP literal in the private ranges
    const ownedIpHttp = owned && ip !== null && inList(OWN_HTTP_IP, ip);
    if (!verified && !ownedIpHttp) return { result: "refused", canonical, host };
  }
  return { result: verified ? "verified" : owned ? "owner_listed" : "not_local", canonical, host };
}

/**
 * Connect-time address rules (BRIDGE §15.3, Connect-time guard): why a RESOLVED address must not be used, or null. NEVER_LOCAL applies to
 * every binding; a `local` binding also needs 127/8, 10/8, 172.16/12, 192.168/16, ::1 or fc00::/7, plus 100.64/10 when owner-attested.
 */
export function addressRefusal(address: string, opts: { local: boolean; policyBasis: PolicyBasis }): string | null {
  const c = canonicalIp(address);
  if (!c) return "not an IP address";
  if (inList(NEVER, c)) return "address in NEVER_LOCAL";
  if (!opts.local) return null;
  if (inList(VERIFIED, c) || (opts.policyBasis === "owner_attested" && inList(CGNAT, c))) return null;
  return "address outside the local ranges";
}
