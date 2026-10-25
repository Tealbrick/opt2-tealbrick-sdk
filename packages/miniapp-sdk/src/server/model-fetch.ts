// `modelFetch(role)` (SDK-API, spec follow-up #49, QA-SPEC49-2c) and the connect-time guard of BRIDGE §15.3. The bridge classifies a
// base URL by text and never resolves names; this resolves the host when the request is made, refuses any address the binding must not
// reach, and pins the checked address for that request (no second lookup). Values (the key) are never logged: the app adds its own
// auth header.
import { lookup as dnsLookup } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isIP } from "node:net";
import { Readable } from "node:stream";
import type { ModelFetchHandle, PolicyBasis, ResolvedModelRole } from "@opt2-tealbrick/manifest";
import { TbError } from "./errors.ts";
import { addressRefusal, classifyBaseUrl, isNeverLocalHost, isPrivateAddress, parseBase } from "./local-check.ts";

export type LookupAll = (host: string) => Promise<{ address: string; family: number }[]>;
export interface GuardDeps {
  /** default: `dns.lookup(host, {all: true, verbatim: true})`; tests inject a stub */
  lookup?: LookupAll;
  /** `TB_OWN_INFRA_ORIGINS` (machine-managed own-infrastructure origins), when the caller has them */
  ownInfraOrigins?: readonly string[];
}
export interface GuardedEndpoint {
  url: URL;
  host: string;
  /** the checked address every connection of this request uses */
  address: string;
  family: 4 | 6;
}

const refused = (why: string): TbError => new TbError("model_endpoint_refused", `model endpoint refused: ${why}`, 502);
const defaultLookup: LookupAll = (host) => dnsLookup(host, { all: true, verbatim: true });
const MAX_REDIRECTS = 5;

/**
 * Why of the basis: a `local` binding whose base URL is not verified by text can only be local because the owner listed the host
 * (BRIDGE §15.3 step 5): `owner_attested`. A `policyBasis` the bridge sends wins.
 */
export function policyBasisOf(binding: Pick<ResolvedModelRole, "baseUrl" | "dataPolicy"> & { policyBasis?: PolicyBasis }, deps: GuardDeps = {}): PolicyBasis {
  if (binding.policyBasis === "verified" || binding.policyBasis === "owner_attested") return binding.policyBasis;
  if (binding.dataPolicy === "zdr") return "owner_attested";
  return binding.baseUrl !== null && classifyBaseUrl(binding.baseUrl, { ownInfraOrigins: deps.ownInfraOrigins }).result === "verified" ? "verified" : "owner_attested";
}

/** Text-only part of the guard (no DNS): hygiene, parse, scheme, never-local host. Returns the parsed base. */
export function checkBaseText(base: string | null): { url: URL; host: string } {
  if (base === null) throw refused("the binding has no base URL");
  const parsed = parseBase(base);
  if (!parsed) throw refused("the base URL is not a plain http(s) origin and path");
  if (isNeverLocalHost(parsed.host)) throw refused("the host is never a model endpoint (link-local or cloud metadata)");
  return parsed;
}

/**
 * The connect-time guard: resolves the host (a literal needs no lookup) and refuses when ANY address is in NEVER_LOCAL or, for a
 * `local` binding, outside the local ranges. Returns the first address, which the caller pins for the request.
 */
export async function guardEndpoint(binding: Pick<ResolvedModelRole, "baseUrl" | "dataPolicy"> & { policyBasis?: PolicyBasis }, deps: GuardDeps = {}): Promise<GuardedEndpoint> {
  const { url, host } = checkBaseText(binding.baseUrl);
  const local = binding.dataPolicy === "local";
  const policyBasis = policyBasisOf(binding, deps);
  let addrs: { address: string; family: number }[];
  if (isIP(host)) addrs = [{ address: host, family: isIP(host) }];
  else {
    try {
      addrs = await (deps.lookup ?? defaultLookup)(host);
    } catch {
      throw refused("the host does not resolve");
    }
  }
  if (addrs.length === 0) throw refused("the host does not resolve");
  for (const a of addrs) {
    const why = addressRefusal(a.address, { local, policyBasis });
    if (why) throw refused(`${why} (a name resolves to it)`);
  }
  // rebinding: a name that mixes private and public records is refused, whatever the binding says
  if (new Set(addrs.map((a) => isPrivateAddress(a.address))).size > 1) throw refused("the host resolves to a mix of private and public addresses");
  const first = addrs[0] as { address: string; family: number };
  return { url, host, address: first.address.replace(/%.*$/, ""), family: isIP(first.address.replace(/%.*$/, "")) === 6 ? 6 : 4 };
}

/** `path` joined to the base URL path; refuses anything that would leave the origin or the base path. */
// biome-ignore lint/suspicious/noControlCharactersInRegex: the control characters are exactly what the path check refuses
const PATH_BAD = /[\\@\uFF20\uFE6B\uFF3C\u0000-\u001f\u007f]|%40|%5c/iu;
function target(base: URL, path: string): URL {
  if (typeof path !== "string" || /^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith("//") || PATH_BAD.test(path) || path.split(/[/?#]/).some((s) => s === ".." || s === "%2e%2e")) {
    throw refused("the path is not a path under the base URL");
  }
  const t = new URL(`${base.pathname.replace(/\/$/, "")}/${path.replace(/^\/+/, "")}`, base.origin);
  if (t.origin !== base.origin) throw refused("the path leaves the base URL origin");
  return t;
}

function bodyBytes(body: RequestInit["body"]): Uint8Array | undefined {
  if (body === undefined || body === null) return undefined;
  if (typeof body === "string") return new TextEncoder().encode(body);
  if (body instanceof Uint8Array) return body;
  if (body instanceof ArrayBuffer) return new Uint8Array(body);
  if (body instanceof URLSearchParams) return new TextEncoder().encode(body.toString());
  throw new TbError("model_fetch_body_unsupported", "modelFetch sends a string, bytes or URLSearchParams body", 500);
}

const NULL_BODY = new Set([101, 204, 205, 304]);

/** One request to `url` over the pinned address; the response is handed back as it came (redirects are the caller's business). */
function once(g: GuardedEndpoint, url: URL, method: string, headers: Headers, body: Uint8Array | undefined, signal: AbortSignal | undefined): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    const h: Record<string, string> = {};
    headers.forEach((v, k) => {
      h[k] = v;
    });
    h.host = url.host;
    if (body) h["content-length"] = String(body.byteLength);
    if (!("accept-encoding" in h)) h["accept-encoding"] = "identity";
    const https = url.protocol === "https:";
    const req = (https ? httpsRequest : httpRequest)({
      host: g.address,
      port: url.port === "" ? (https ? 443 : 80) : Number(url.port),
      path: url.pathname + url.search,
      method,
      headers: h,
      ...(https && !isIP(g.host) ? { servername: g.host } : {}),
    });
    const onAbort = () => req.destroy(signal?.reason instanceof Error ? signal.reason : new DOMException("aborted", "AbortError"));
    if (signal) {
      if (signal.aborted) return void onAbort();
      signal.addEventListener("abort", onAbort, { once: true });
    }
    req.once("error", (e) => {
      signal?.removeEventListener("abort", onAbort);
      reject(signal?.aborted ? e : new TbError("model_endpoint_unreachable", "the model endpoint cannot be reached", 502));
    });
    req.once("response", (res) => {
      const out = new Headers();
      for (const [k, v] of Object.entries(res.headers)) for (const x of Array.isArray(v) ? v : v === undefined ? [] : [v]) out.append(k, x);
      const status = res.statusCode ?? 502;
      res.once("close", () => signal?.removeEventListener("abort", onAbort));
      resolve(new Response(NULL_BODY.has(status) ? null : (Readable.toWeb(res) as ReadableStream), { status, statusText: res.statusMessage ?? "", headers: out }));
      if (NULL_BODY.has(status)) res.resume();
    });
    req.end(body ? Buffer.from(body) : undefined);
  });
}

/**
 * The `fetch` of a `modelFetch` handle: only the binding's canonical base URL origin; per request one lookup, the guard, and the
 * checked address pinned for the connection (TLS keeps the original host name for SNI and certificate checks). A redirect to the same
 * origin is followed (guarded again, every hop); a redirect to another origin is NEVER followed, whatever headers the app set:
 * `model_endpoint_refused`, nothing further is sent.
 */
export function guardedFetch(binding: ResolvedModelRole & { policyBasis?: PolicyBasis }, deps: GuardDeps = {}): ModelFetchHandle["fetch"] {
  const snapshot = { ...binding };
  return async (path, init = {}) => {
    let method = (init.method ?? "GET").toUpperCase();
    const headers = new Headers(init.headers);
    headers.delete("host");
    let body = bodyBytes(init.body);
    let url = target(checkBaseText(snapshot.baseUrl).url, path);
    for (let hop = 0; ; hop++) {
      const g = await guardEndpoint(snapshot, deps);
      const res = await once(g, url, method, headers, body, init.signal ?? undefined);
      const loc = res.headers.get("location");
      if (![301, 302, 303, 307, 308].includes(res.status) || !loc) return res;
      let next: URL;
      try {
        next = new URL(loc, url);
      } catch {
        return res;
      }
      void res.body?.cancel();
      if (next.origin !== url.origin) throw refused("the endpoint redirects to another origin");
      if (hop >= MAX_REDIRECTS) throw refused("too many redirects");
      if (res.status !== 307 && res.status !== 308) {
        method = method === "HEAD" ? "HEAD" : "GET";
        body = undefined;
      }
      url = next;
    }
  };
}
