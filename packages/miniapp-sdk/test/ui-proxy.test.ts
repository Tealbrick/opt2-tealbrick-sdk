// spec 0.1.95 (SDK-API §23): person UI served by a companion — session, same-Origin rule, header hygiene, the signed
// TB-Person assertion, a companion that is down, and WebSocket upgrades. Real HTTP on ephemeral ports.
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { createServer, type IncomingHttpHeaders, request, type Server } from "node:http";
import type { Socket } from "node:net";
import { after, before, describe, test } from "node:test";
import type { RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp, TbError } from "../src/server/index.ts";
import { uiProxyProblems } from "../src/server/ui-proxy.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const SECRET = "s".repeat(48);

interface Seen {
  method: string;
  url: string;
  headers: IncomingHttpHeaders;
  body: string;
}

/** The companion: records each request, answers with a cookie it must not leak, echoes WebSocket bytes. */
async function companion(): Promise<{ url: string; seen: Seen[]; server: Server }> {
  const seen: Seen[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c: Buffer) => {
      body += c.toString();
    });
    req.on("end", () => {
      seen.push({ method: req.method ?? "", url: req.url ?? "", headers: req.headers, body });
      res.writeHead(200, { "content-type": "text/plain", "set-cookie": "engine=1; Path=/" });
      res.end(`ok ${req.method} ${req.url}`);
    });
  });
  server.on("upgrade", (req, socket: Socket) => {
    seen.push({ method: "UPGRADE", url: req.url ?? "", headers: req.headers, body: "" });
    socket.write("HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\n\r\n");
    socket.on("data", (d) => socket.write(d));
  });
  const port = await freePort();
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${port}`, seen, server };
}

const handlers = { note_create: { scope: () => "x", run: async () => ({ id: "n" }) }, note_get: async () => ({}), note_delete: async () => ({}), notebook_rename: async () => ({}) };

function verify(value: string): Record<string, unknown> {
  const [body, mac] = value.split(".");
  assert.ok(body && mac);
  assert.equal(createHmac("sha256", SECRET).update(body, "ascii").digest("base64url"), mac, "MAC with the shared secret");
  return JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as Record<string, unknown>;
}

describe("uiProxy boot checks", () => {
  test("refused without manifest ui", () => {
    const m = fixtureManifest(8080);
    delete m.ui;
    assert.match(uiProxyProblems({ target: "http://engine:3000", secret: SECRET }, m).join(), /ui_proxy_without_ui/);
    assert.deepEqual(uiProxyProblems({ target: "http://engine:3000", secret: SECRET }, fixtureManifest(8080)), []);
  });

  test("startApp refuses a bad target or a short secret", async () => {
    const t = tempDir();
    const cases: [ReturnType<typeof fixtureManifest>, { target: string; secret: string }, RegExp][] = [
      [fixtureManifest(8080), { target: "http://engine:3000/app", secret: SECRET }, /ui_proxy_invalid/],
      [fixtureManifest(8080), { target: "ftp://engine", secret: SECRET }, /ui_proxy_invalid/],
      [fixtureManifest(8080), { target: "http://u:p@engine:3000", secret: SECRET }, /ui_proxy_invalid/],
      [fixtureManifest(8080), { target: "http://engine:3000", secret: "short" }, /ui_proxy_invalid/],
    ];
    for (const [manifest, uiProxy, re] of cases) {
      const app = defineApp({ manifest, migrations: migrationsDir(t.dir), handlers, uiProxy });
      const started = await startApp(app, { TB_STANDALONE: "1", TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" }).then(
        async (r) => {
          await r.stop();
          return null;
        },
        (e: unknown) => e,
      );
      assert.ok(started instanceof TbError && started.code === "handlers_invalid" && re.test(started.message), String(started));
    }
    t.cleanup();
  });
});

describe("uiProxy routes", () => {
  let w: World;
  let bridge: FakeBridge;
  let running: RunningApp;
  let base: string;
  let host: string;
  let comp: Awaited<ReturnType<typeof companion>>;
  let cookie: string;
  const t = tempDir();

  before(async () => {
    w = await world();
    comp = await companion();
    const port = await freePort();
    bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    const app = defineApp({ manifest: fixtureManifest(port), migrations: migrationsDir(t.dir), handlers, uiProxy: { target: comp.url, secret: SECRET } });
    running = await startApp(
      app,
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    await until(async () => running.status() === "ok");
    host = `127.0.0.1:${port}`;
    base = `http://${host}`;
    const res = await fetch(`${base}/a/${PRODUCT}/tb/launch`, { method: "POST", redirect: "manual", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ ticket: await ticket(w, "/") }) });
    assert.equal(res.status, 303);
    cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  });

  after(async () => {
    await running?.stop();
    await bridge?.stop();
    comp?.server.close();
    comp?.server.closeAllConnections();
    t.cleanup();
  });

  test("no session: sign-in page for HTML, 401 JSON otherwise; the companion is not called", async () => {
    const before = comp.seen.length;
    const html = await fetch(`${base}/a/${PRODUCT}/board`, { headers: { accept: "text/html" } });
    assert.equal(html.status, 401);
    assert.match(await html.text(), /Sign in required/);
    const json = await fetch(`${base}/a/${PRODUCT}/api/v1/me`);
    assert.equal(json.status, 401);
    assert.equal(((await json.json()) as { error: { code: string } }).error.code, "session_required");
    assert.equal(comp.seen.length, before);
  });

  test("GET is forwarded without the prefix, with a valid TB-Person and without SDK credentials", async () => {
    const res = await fetch(`${base}/a/${PRODUCT}/board/7?tab=chat`, {
      headers: { cookie: `${cookie}; theme=dark`, authorization: "Bearer agent", "tb-call": "x", "x-forwarded-for": "1.2.3.4", "x-forwarded-host": host, "x-forwarded-proto": "https", forwarded: "for=1.2.3.4" },
    });
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "ok GET /board/7?tab=chat");
    assert.equal(res.headers.get("set-cookie"), null, "the companion's cookie never reaches the browser");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(res.headers.get("x-frame-options"), "DENY");
    const s = comp.seen.at(-1) as Seen;
    assert.equal(s.url, "/board/7?tab=chat");
    assert.equal(s.headers.cookie, "theme=dark", "tb_session removed, other cookies kept");
    assert.equal(s.headers.authorization, undefined);
    assert.equal(s.headers["tb-call"], undefined);
    assert.equal(s.headers.forwarded, undefined);
    assert.equal(s.headers["x-forwarded-for"], undefined);
    assert.equal(s.headers["x-forwarded-prefix"], `/a/${PRODUCT}`);
    assert.equal(s.headers["x-forwarded-host"], host);
    assert.equal(s.headers["x-forwarded-proto"], "https");
    const a = verify(String(s.headers["tb-person"]));
    assert.equal(a.v, 1);
    assert.equal(a.per, w.per);
    assert.equal(a.ws, w.ws);
    assert.equal(a.ins, w.ins);
    assert.equal(a.base, `/a/${PRODUCT}`);
    assert.equal(Number(a.exp) - Number(a.iat), 60);
    assert.equal(typeof a.jti, "string");
  });

  test("a forged TB-Person from the browser is replaced", async () => {
    await fetch(`${base}/a/${PRODUCT}/x`, { headers: { cookie, "tb-person": "forged.mac" } });
    verify(String((comp.seen.at(-1) as Seen).headers["tb-person"]));
  });

  test("writes need the same Origin; then method and body pass", async () => {
    const no = await fetch(`${base}/a/${PRODUCT}/api/v1/tasks`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}" });
    assert.equal(no.status, 403);
    assert.equal(((await no.json()) as { error: { code: string } }).error.code, "csrf_invalid");
    const other = await fetch(`${base}/a/${PRODUCT}/api/v1/tasks`, { method: "DELETE", headers: { cookie, origin: "https://evil.example" } });
    assert.equal(other.status, 403);
    const ok = await fetch(`${base}/a/${PRODUCT}/api/v1/tasks`, { method: "PATCH", headers: { cookie, origin: base, "content-type": "application/json" }, body: '{"title":"a"}' });
    assert.equal(ok.status, 200);
    const s = comp.seen.at(-1) as Seen;
    assert.equal(s.method, "PATCH");
    assert.equal(s.body, '{"title":"a"}');
  });

  test("SDK routes stay the SDK's; other /tb/ paths are 404", async () => {
    const before = comp.seen.length;
    const s = await fetch(`${base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } });
    assert.equal(s.status, 200);
    assert.equal(((await s.json()) as { principal: { id: string } }).principal.id, w.per);
    assert.equal((await fetch(`${base}/a/${PRODUCT}/tb/other`, { headers: { cookie } })).status, 404);
    assert.equal(comp.seen.length, before);
  });

  test("WebSocket: refused without session or Origin; with both, bytes pass both ways", async () => {
    const upgrade = (headers: Record<string, string>) =>
      new Promise<{ status: number; socket?: Socket }>((resolve, reject) => {
        const r = request({ host: "127.0.0.1", port: Number(host.split(":")[1]), path: `/a/${PRODUCT}/api/v1/live`, headers: { connection: "Upgrade", upgrade: "websocket", ...headers } });
        r.on("upgrade", (res, socket) => resolve({ status: res.statusCode ?? 0, socket }));
        r.on("response", (res) => {
          res.resume();
          resolve({ status: res.statusCode ?? 0 });
        });
        r.on("error", reject);
        r.end();
      });
    assert.equal((await upgrade({ origin: base })).status, 401);
    assert.equal((await upgrade({ cookie })).status, 403);
    const ok = await upgrade({ cookie, origin: base });
    assert.equal(ok.status, 101);
    const s = comp.seen.at(-1) as Seen;
    assert.equal(s.method, "UPGRADE");
    assert.equal(s.url, "/api/v1/live");
    assert.equal(s.headers.cookie, undefined);
    verify(String(s.headers["tb-person"]));
    const socket = ok.socket as Socket;
    const echo = new Promise<string>((r) => socket.once("data", (d) => r(d.toString())));
    socket.write("ping");
    assert.equal(await echo, "ping");
    // left open on purpose: `after` proves that stop() ends proxied sockets (they leave the HTTP server's list)
    socket.on("error", () => {});
  });

  test("companion down: 502 ui_unavailable", async () => {
    comp.server.close();
    comp.server.closeAllConnections();
    const json = await fetch(`${base}/a/${PRODUCT}/api/v1/me`, { headers: { cookie } });
    assert.equal(json.status, 502);
    assert.equal(((await json.json()) as { error: { code: string } }).error.code, "ui_unavailable");
    const html = await fetch(`${base}/a/${PRODUCT}/`, { headers: { cookie, accept: "text/html" } });
    assert.equal(html.status, 502);
    assert.match(await html.text(), /not available/);
  });
});
