// Person UI served by a companion service (SDK-API §23, spec 0.1.95). The SDK stays the only door: it checks the
// session (and the same-Origin rule for writes and upgrades), strips its own credentials and forwards the request with
// a short-lived HMAC person assertion. The companion never sees `tb_session` and keeps no login of its own.
import { createHmac } from "node:crypto";
import { request as httpRequest, type IncomingHttpHeaders, type IncomingMessage, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import type { Socket } from "node:net";
import { ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId, PersonId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { SessionInfo } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { escapeHtml, header, requestId, sendError, sendHtml } from "./http.ts";
import { SESSION_COOKIE, sameOrigin } from "./person.ts";
import type { Runtime } from "./runtime.ts";

/** spec 0.1.95: `PERSON_ASSERTION_HEADER` (SPEC-GAP until the SDK pins spec ≥ 0.1.95) */
export const PERSON_ASSERTION_HEADER = "TB-Person" as const;
/** spec 0.1.95: `PERSON_ASSERTION_TTL_S` */
export const PERSON_ASSERTION_TTL_S = 60 as const;
/** the bridge's body cap on `/a/<product>/` (BRIDGE §9) */
export const UI_PROXY_MAX_BODY = 10 * 1024 * 1024;
const HTTP_TIMEOUT_MS = 60_000;
const UPGRADE_IDLE_MS = 10 * 60_000;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host"]);

/** spec 0.1.95 `UiProxy` (SPEC-GAP until the SDK pins spec ≥ 0.1.95) */
export interface UiProxy {
  /** the companion's private base URL (`{{services.<id>.url}}`) */
  target: string;
  /** shared with that companion only; ≥ 32 characters, never logged */
  secret: string;
}

/** spec 0.1.95 `PersonAssertion` */
export interface PersonAssertion {
  v: 1;
  per: PersonId;
  ws: WorkspaceId;
  ins: InstanceId;
  iat: number;
  exp: number;
  base: string;
  jti: string;
}

/** Boot checks (SDK-API §23 item 1); problems use the boot-error list of `defineApp` / `startApp`. */
export function uiProxyProblems(p: UiProxy | undefined, m: Manifest): string[] {
  if (p === undefined) return [];
  const out: string[] = [];
  if (!m.ui) out.push("ui_proxy_without_ui: uiProxy needs manifest ui");
  let url: URL | null = null;
  try {
    url = new URL(p?.target ?? "");
  } catch {
    url = null;
  }
  if (!url || (url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    out.push("ui_proxy_invalid: uiProxy.target must be an http(s) URL without path, query or credentials");
  }
  if (typeof p?.secret !== "string" || p.secret.length < 32) out.push("ui_proxy_invalid: uiProxy.secret must have at least 32 characters");
  return out;
}

/** `TB-Person` value: base64url(JSON) "." base64url(HMAC-SHA256(secret, first part)) */
export function signPersonAssertion(a: PersonAssertion, secret: string): string {
  const body = Buffer.from(JSON.stringify(a), "utf8").toString("base64url");
  return `${body}.${createHmac("sha256", secret).update(body, "ascii").digest("base64url")}`;
}

function assertionFor(s: SessionInfo, base: string, nowMs: number): PersonAssertion {
  const iat = Math.floor(nowMs / 1000);
  return { v: 1, per: s.principal.id, ws: s.principal.ws, ins: s.principal.instance, iat, exp: iat + PERSON_ASSERTION_TTL_S, base, jti: ulid() };
}

/** `tb_session` removed; other cookies stay (item 5) */
function stripSessionCookie(cookie: string | string[] | undefined): string | undefined {
  const parts = (Array.isArray(cookie) ? cookie.join("; ") : (cookie ?? ""))
    .split(";")
    .map((c) => c.trim())
    .filter((c) => c !== "" && c.split("=")[0]?.trim() !== SESSION_COOKIE);
  return parts.length ? parts.join("; ") : undefined;
}

/** Request headers for the companion (item 5). */
export function forwardHeaders(req: IncomingMessage, assertion: string, base: string, keepUpgrade: boolean): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(req.headers as IncomingHttpHeaders)) {
    if (v === undefined) continue;
    const lk = k.toLowerCase();
    if (lk === "cookie" || lk === "authorization" || lk === "forwarded" || lk.startsWith("tb-") || lk.startsWith("x-forwarded-")) continue;
    if (HOP_BY_HOP.has(lk) && !(keepUpgrade && (lk === "connection" || lk === "upgrade"))) continue;
    out[lk] = v;
  }
  const cookie = stripSessionCookie(req.headers.cookie);
  if (cookie) out.cookie = cookie;
  out[PERSON_ASSERTION_HEADER.toLowerCase()] = assertion;
  out["x-forwarded-prefix"] = base;
  out["x-forwarded-host"] = header(req, "x-forwarded-host") ?? header(req, "host") ?? "";
  out["x-forwarded-proto"] = header(req, "x-forwarded-proto") ?? "http";
  return out;
}

/** Answer headers for the browser (item 6). */
export function answerHeaders(h: IncomingHttpHeaders): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(h)) {
    if (v === undefined) continue;
    const lk = k.toLowerCase();
    if (lk === "set-cookie" || lk === "connection" || lk === "keep-alive" || lk === "transfer-encoding") continue;
    out[lk] = v;
  }
  out["x-content-type-options"] ??= "nosniff";
  const csp = [out["content-security-policy"]].flat().join(" ");
  if (out["x-frame-options"] === undefined && !/frame-ancestors/i.test(csp)) out["x-frame-options"] = "DENY";
  return out;
}

function wantsHtml(req: IncomingMessage): boolean {
  return req.method === "GET" && /text\/html/i.test(header(req, "accept") ?? "");
}

function refuse(req: IncomingMessage, res: ServerResponse, e: TbError): void {
  if (wantsHtml(req) && e.code === "session_required") {
    sendHtml(res, 401, "Sign in", `<h1>Sign in required</h1><p>Open this app from Portal.</p><p><code>${escapeHtml(e.code)}</code></p>`);
  } else if (wantsHtml(req) && e.code === "ui_unavailable") {
    sendHtml(res, 502, "Not available", `<h1>This app is starting or not available</h1><p>Try again in a minute.</p><p><code>${escapeHtml(e.code)}</code></p>`);
  } else sendError(res, requestId(), e);
}

function check(rt: Runtime, req: IncomingMessage, upgrade: boolean): SessionInfo {
  const s = rt.person.requireSession(req);
  if ((upgrade || !SAFE_METHODS.has(req.method ?? "GET")) && !sameOrigin(req)) throw new TbError("csrf_invalid", "Origin missing or not this host", 403);
  return s;
}

function upstreamPath(req: IncomingMessage, base: string): string {
  const raw = req.url ?? "/";
  const q = raw.indexOf("?");
  const path = (q < 0 ? raw : raw.slice(0, q)).slice(base.length) || "/";
  return path + (q < 0 ? "" : raw.slice(q));
}

/** HTTP: any method on `/a/<product>/<path>` that is not an SDK route (items 2–6). */
export function proxyUiRequest(rt: Runtime, p: UiProxy, req: IncomingMessage, res: ServerResponse): void {
  const base = `/a/${rt.product}`;
  let session: SessionInfo;
  try {
    session = check(rt, req, false);
  } catch (e) {
    refuse(req, res, e instanceof TbError ? e : new TbError("session_required", "sign in through Portal", 401));
    return;
  }
  const declared = Number(req.headers["content-length"] ?? "0");
  if (declared > UI_PROXY_MAX_BODY) {
    refuse(req, res, new TbError("payload_too_large", "request body too large", 413));
    return;
  }
  const target = new URL(p.target);
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const assertion = signPersonAssertion(assertionFor(session, base, Date.now()), p.secret);
  const up = send(
    { protocol: target.protocol, hostname: target.hostname, port: target.port, method: req.method, path: upstreamPath(req, base), headers: forwardHeaders(req, assertion, base, false), timeout: HTTP_TIMEOUT_MS },
    (ur) => {
      res.writeHead(ur.statusCode ?? 502, answerHeaders(ur.headers));
      ur.pipe(res);
    },
  );
  let done = false;
  const fail = () => {
    up.destroy();
    if (done) return;
    done = true;
    if (res.headersSent) res.destroy();
    else refuse(req, res, new TbError("ui_unavailable", "the app UI service is not reachable", 502));
  };
  up.on("timeout", fail);
  up.on("error", fail);
  let seen = 0;
  req.on("data", (chunk: Buffer) => {
    seen += chunk.length;
    if (seen > UI_PROXY_MAX_BODY && !done) {
      done = true;
      req.unpipe(up);
      up.destroy();
      if (res.headersSent) res.destroy();
      else refuse(req, res, new TbError("payload_too_large", "request body too large", 413));
    }
  });
  req.pipe(up);
}

/** open proxied WebSockets per runtime: they leave the HTTP server's connection list, so `stop()` closes them here */
const openUpgrades = new WeakMap<Runtime, Set<Socket>>();

/** Called by `stop()`: ends every proxied WebSocket at once (the browser reconnects to the next app process). */
export function closeUiUpgrades(rt: Runtime): void {
  for (const s of openUpgrades.get(rt) ?? []) s.destroy();
  openUpgrades.delete(rt);
}

function track(rt: Runtime, ...sockets: Socket[]): void {
  const set = openUpgrades.get(rt) ?? new Set<Socket>();
  openUpgrades.set(rt, set);
  for (const s of sockets) {
    set.add(s);
    s.once("close", () => set.delete(s));
  }
}

function closeSocket(socket: Socket, status: number, reason: string): void {
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nconnection: close\r\ncontent-length: 0\r\n\r\n`);
}

/** WebSocket upgrade on `/a/<product>/<path>` (items 2–5): raw pass-through after the session and Origin check. */
export function proxyUiUpgrade(rt: Runtime, p: UiProxy, req: IncomingMessage, socket: Socket, head: Buffer): void {
  const base = `/a/${rt.product}`;
  let session: SessionInfo;
  try {
    session = check(rt, req, true);
  } catch (e) {
    const code = e instanceof TbError ? e.httpStatus : 401;
    closeSocket(socket, code, code === 403 ? "Forbidden" : "Unauthorized");
    return;
  }
  const target = new URL(p.target);
  const send = target.protocol === "https:" ? httpsRequest : httpRequest;
  const assertion = signPersonAssertion(assertionFor(session, base, Date.now()), p.secret);
  const up = send({ protocol: target.protocol, hostname: target.hostname, port: target.port, method: req.method, path: upstreamPath(req, base), headers: forwardHeaders(req, assertion, base, true), timeout: HTTP_TIMEOUT_MS });
  let upgraded = false;
  up.on("upgrade", (ur, upSocket, upHead) => {
    upgraded = true;
    upSocket.removeAllListeners("timeout");
    track(rt, socket, upSocket);
    const lines = [`HTTP/1.1 101 ${ur.statusMessage ?? "Switching Protocols"}`];
    for (const [k, v] of Object.entries(ur.headers)) {
      if (v === undefined || k.toLowerCase() === "set-cookie") continue;
      for (const one of [v].flat()) lines.push(`${k}: ${one}`);
    }
    socket.write(`${lines.join("\r\n")}\r\n\r\n`);
    if (upHead.length) socket.write(upHead);
    if (head.length) upSocket.write(head);
    for (const s of [socket, upSocket]) {
      s.setTimeout(UPGRADE_IDLE_MS, () => {
        socket.destroy();
        upSocket.destroy();
      });
    }
    socket.on("error", () => upSocket.destroy());
    upSocket.on("error", () => socket.destroy());
    socket.on("close", () => upSocket.destroy());
    upSocket.on("close", () => socket.destroy());
    upSocket.pipe(socket);
    socket.pipe(upSocket);
  });
  up.on("response", (ur) => {
    // the companion refused the upgrade: pass its status on, no body
    closeSocket(socket, ur.statusCode ?? 502, ur.statusMessage ?? "Bad Gateway");
    ur.resume();
  });
  const fail = () => {
    if (upgraded) return;
    up.destroy();
    if (!socket.destroyed) closeSocket(socket, 502, "Bad Gateway");
  };
  up.on("timeout", fail);
  up.on("error", fail);
  socket.on("error", () => up.destroy());
  up.end();
}
