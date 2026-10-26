// HTTP surface (SDK-API §3.2): every route is derived from the manifest; apps add none under /tb.
import { createReadStream, statSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { extname, join, normalize, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import type { BridgeOp } from "@opt2-tealbrick/spec/credentials";
import type { Health } from "@opt2-tealbrick/spec/sdk";
import { handleBridgeOp, handleHook } from "./bridge-routes.ts";
import type { AttentionCode } from "./claim-guard.ts";
import type { SdkPublicContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { HOLD_PAGE_RE, handleHoldPage } from "./holds-page.ts";
import { escapeHtml, readRaw, requestId, sendError, sendHtml, sendJson } from "./http.ts";
import { buildOpenApi } from "./openapi.ts";
import { handleAgentOp, handlePersonOp } from "./ops.ts";
import { handleRelayedPersonOp } from "./person-op.ts";
import type { Runtime } from "./runtime.ts";
import { handleViewer, isViewerPath } from "./viewer.ts";

const BRIDGE_OP_ROUTES: Record<string, BridgeOp> = { catalog: "catalog", resolve: "resolve", mark: "mark", "scope-summary": "scope_summary" };
const PUBLIC_BODY_MAX = 1024 * 1024;
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
  ".txt": "text/plain; charset=utf-8",
  ".map": "application/json",
};

/**
 * SPEC-GAP: types/sdk.ts `HealthStatus` and `AppStatus.readiness` are closed unions without a needs_attention state.
 * v0.1.12 keeps `status` in the union (`needs_claim`), the wire readiness `degraded`, and adds the detail `attention`
 * (`data_dir_not_mounted` | `identity_refused`) only while one applies.
 */
export async function health(rt: Runtime): Promise<Health & { attention?: AttentionCode }> {
  const h: Health = { status: rt.health(), sdk: rt.sdkVersion, version: rt.manifest.version, manifestDigest: rt.digest, keys: await rt.keys.status() };
  // v0.1.22 (SDK-03, spec 0.1.31 Health.backup): the scheduled-backup state (schedule, last good / failed run, failures, overdue)
  const out = { ...h, backup: rt.backupHealth(), ...upgradeHealth(rt) };
  return rt.state.attention ? { ...out, attention: rt.state.attention } : out;
}

/**
 * v0.1.25 (E2, SPEC-GAP additive Health/AppStatus members): the data's schema, the oldest code that can run it and the
 * newest pre-update snapshot, so Core's health gate and rollback can decide (UPGRADE-SAFETY M4/M5).
 */
export function upgradeHealth(rt: Runtime): {
  schemaVersion: { app: number; sdk: number };
  minCompatibleCode: string | null;
  minCompatibleSdk: string | null;
  preUpdateSnapshot: { file: string; sha256: string; createdAt: string; from: string | null; to: string } | null;
} {
  const u = rt.upgrade;
  const s = u.preUpdateSnapshot;
  return {
    schemaVersion: u.schemaVersion,
    minCompatibleCode: u.minCompatibleCode,
    minCompatibleSdk: u.minCompatibleSdk,
    preUpdateSnapshot: s ? { file: s.file, sha256: s.sha256, createdAt: s.createdAt, from: s.from, to: s.to } : null,
  };
}

/** Content-hashed asset directory written by the template's build-ui (`assets-<hex>/…`): immutable for a year. */
export const HASHED_ASSET_DIR = /^assets-[0-9a-f]{12,64}\//;

/**
 * C61: the HTML entry (and any un-hashed file) revalidates on every load (`no-cache`), so owners see a deploy at once;
 * files under a content-hashed `assets-<hex>/` directory are immutable (a new build gets a new directory name).
 */
export function uiCacheControl(rel: string): string {
  const path = rel.replace(/^\/+/, "");
  return HASHED_ASSET_DIR.test(path) ? "private, max-age=31536000, immutable" : "no-cache";
}

/** Static UI from `dist/ui` beside the migrations directory's parent (template layout, SDK-API §15). */
function serveUi(uiRoot: string, rel: string, res: ServerResponse): void {
  const notFound = () => sendError(res, requestId(), new TbError("not_found", "not found", 404));
  let decoded: string;
  try {
    decoded = decodeURIComponent(rel);
  } catch {
    notFound();
    return;
  }
  const target = normalize(join(uiRoot, decoded));
  if (target !== uiRoot && !target.startsWith(uiRoot + sep)) {
    notFound();
    return;
  }
  const pick = (p: string): string | null => {
    try {
      const st = statSync(p);
      return st.isFile() ? p : st.isDirectory() ? pick(join(p, "index.html")) : null;
    } catch {
      return null;
    }
  };
  // SPA fallback: extension-less paths render index.html
  const file = pick(target) ?? (extname(target) === "" ? pick(join(uiRoot, "index.html")) : null);
  if (!file) {
    notFound();
    return;
  }
  res.writeHead(200, {
    "content-type": MIME[extname(file)] ?? "application/octet-stream",
    "cache-control": uiCacheControl(rel),
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
  });
  createReadStream(file).pipe(res);
}

async function publicRoute(rt: Runtime, req: IncomingMessage, res: ServerResponse, path: string): Promise<boolean> {
  const route = rt.manifest.publicRoutes?.find((r) => r.path === path);
  const handler = route ? rt.def.publicRoutes?.[route.path] : undefined;
  // v0.1.26 (LA-3c): a viewer route is a PREFIX route served by handleViewer on /v/<product>/…, never by exact path
  if (!route || !handler || route.purpose === "viewer") return false;
  const method = route.purpose === "oauth_callback" ? "GET" : "POST";
  if (req.method !== method) {
    sendError(res, requestId(), new TbError("method_not_allowed", `${route.path} accepts ${method}`, 405), { allow: method });
    return true;
  }
  const body = method === "POST" ? await readRaw(req, PUBLIC_BODY_MAX) : undefined;
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && !/^tb-/i.test(k)) headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  const request = new Request(`http://${req.headers.host ?? "localhost"}${req.url ?? "/"}`, { method, headers, body: body ? new Uint8Array(body) : undefined });
  const ctx: SdkPublicContext = { ...rt.extras(), log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n) };
  const response = await handler(request, ctx);
  const out: Record<string, string> = {};
  response.headers.forEach((v, k) => {
    out[k] = v;
  });
  res.writeHead(response.status, out);
  if (response.body) Readable.fromWeb(response.body as import("node:stream/web").ReadableStream).pipe(res);
  else res.end();
  return true;
}

export function createHttpServer(rt: Runtime): Server {
  const base = `/a/${rt.product}`;
  const uiRoot = resolve(rt.def.migrations, "..", "dist", "ui");
  let openapi: string | null = null;

  const route = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const url = new URL(req.url ?? "/", "http://app.internal");
    const path = url.pathname;
    const m = req.method ?? "GET";

    if (path.startsWith("/tb/v1/")) {
      const rest = path.slice("/tb/v1/".length);
      if (m === "GET" && rest === "health") return sendJson(res, 200, await health(rt));
      if (m === "GET" && rest === "manifest") return sendJson(res, 200, rt.manifest);
      if (m === "GET" && rest === "openapi.json") {
        openapi ??= JSON.stringify(buildOpenApi(rt.manifest, [...rt.ops.values()], rt.sdkVersion));
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        return void res.end(openapi);
      }
      if (m === "POST" && rest.startsWith("ops/")) return handleAgentOp(rt, req, res, decodeURIComponent(rest.slice(4)));
      // v0.1.39 (SDK-API §21, spec 0.1.64): a person op relayed by the workspace bridge for a native owner session (K14; no cookie, no CSRF)
      if (m === "POST" && rest === "person-op") return handleRelayedPersonOp(rt, req, res);
      if (m === "POST" && rest.startsWith("hooks/")) return handleHook(rt, req, res, decodeURIComponent(rest.slice(6)));
      if (m === "POST" && rest.startsWith("bridge/") && BRIDGE_OP_ROUTES[rest.slice(7)]) return handleBridgeOp(rt, req, res, BRIDGE_OP_ROUTES[rest.slice(7)] as BridgeOp);
      return sendError(res, requestId(), new TbError("not_found", "not found", 404));
    }

    if (path === base || path.startsWith(`${base}/`)) {
      const rest = path.slice(base.length);
      if (rest === "/tb/launch" && m === "POST") return rt.person.handleLaunch(req, res);
      if (rest === "/tb/v1/session" && m === "GET") return rt.person.handleSession(req, res);
      if (rest === "/tb/v1/logout" && m === "POST") return rt.person.handleLogout(req, res);
      if (rest.startsWith("/tb/v1/ops/") && m === "POST") return handlePersonOp(rt, req, res, decodeURIComponent(rest.slice("/tb/v1/ops/".length)));
      if (rest === "/tb/standalone" && (m === "GET" || m === "POST")) return rt.person.handleStandalone(req, res);
      // v0.1.13 (G4): apps without a person UI get the SDK's minimal decision page at /holds/<id> (apps with a UI route it)
      const hold = rt.manifest.ui ? null : HOLD_PAGE_RE.exec(rest);
      if (hold?.[1] && (m === "GET" || m === "POST")) return handleHoldPage(rt, req, res, hold[1]);
      if (rest.startsWith("/tb/") || m !== "GET") return sendError(res, requestId(), new TbError("not_found", "not found", 404));
      if (!rt.manifest.ui) return sendError(res, requestId(), new TbError("not_found", "this app has no person UI", 404));
      try {
        rt.person.requireSession(req);
      } catch (e) {
        const code = e instanceof TbError ? e.code : "session_required";
        return sendHtml(res, 401, "Sign in", `<h1>Sign in required</h1><p>Open this app from Portal.</p><p><code>${escapeHtml(code)}</code></p>`);
      }
      return serveUi(uiRoot, rest === "" ? "/" : rest, res);
    }

    // v0.1.26 (LA-1 / LA-3c): the viewer prefix route; the bridge private views route forwards GET /v/<product>/<rest> unchanged
    if (isViewerPath(rt, path) && (await handleViewer(rt, req, res, url))) return;

    // manifest public routes: BRIDGE §9.2 forwards /p/<product>/<path> unchanged; SDK-API §3.2 names <path> (SPEC-GAP: both served)
    const pub = path.startsWith(`/p/${rt.product}/`) ? path.slice(`/p/${rt.product}`.length) : path;
    if (await publicRoute(rt, req, res, pub)) return;
    sendError(res, requestId(), new TbError("not_found", "not found", 404));
  };

  return createServer((req, res) => {
    route(req, res).catch((e) => {
      rt.log.error("request failed", { error: e instanceof Error ? e.message : "unknown" });
      sendError(res, requestId(), e);
    });
  });
}
