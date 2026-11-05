// C390 (knowledge#38): tb-exec's private-network listeners bind `::` (IPv4 and IPv6) and every network failure of a
// helper call carries a cause label (refused, timeout, DNS), in the error details and in the proxy's own log.
import assert from "node:assert/strict";
import { createServer, request, type Server } from "node:http";
import { after, describe, test } from "node:test";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { DEFAULT_LISTEN_HOST, startHelperProxy } from "../../src/exec/servers.ts";
import { errorFrom } from "../../src/server/bridge-client.ts";
import { netCause } from "../../src/server/net-cause.ts";
import { freePort } from "../helpers.ts";

type Line = { level: string; msg: string; fields: Record<string, unknown> };
function sink(): { log: Logger; lines: Line[] } {
  const lines: Line[] = [];
  const add = (level: string) => (msg: string, fields: Record<string, unknown> = {}) => void lines.push({ level, msg, fields });
  return { log: { info: add("info"), warn: add("warn"), error: add("error"), debug: add("debug") } as unknown as Logger, lines };
}

function post(host: string, port: number, path: string): Promise<{ status: number; body: { error?: { code?: string; details?: Record<string, unknown> } } & Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const r = request({ host, port, path, method: "POST", headers: { "content-type": "application/json" } }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (c) => (text += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: text ? JSON.parse(text) : {} }));
    });
    r.once("error", reject);
    r.end("{}");
  });
}

const servers: Server[] = [];
after(() => {
  for (const s of servers) s.close();
});

describe("tb-exec listeners (C390)", () => {
  test("the default host is :: and the helper proxy answers on IPv4 and IPv6; it logs where it listens", async () => {
    assert.equal(DEFAULT_LISTEN_HOST, "::");
    const targetPort = await freePort();
    const target = createServer((req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ path: req.url }));
    });
    servers.push(target);
    await new Promise<void>((ok) => target.listen(targetPort, "127.0.0.1", ok));
    const port = await freePort();
    const s = sink();
    servers.push(await startHelperProxy({ port, host: DEFAULT_LISTEN_HOST, paths: ["/sources"], target: { host: "127.0.0.1", port: targetPort }, verify: () => undefined, log: s.log }));
    assert.equal((await post("127.0.0.1", port, "/sources")).status, 200, "IPv4");
    assert.equal((await post("::1", port, "/sources")).status, 200, "IPv6");
    assert.ok(s.lines.some((l) => l.level === "info" && l.msg === "helper proxy listening" && l.fields.port === port));
  });

  test("a helper process that does not answer: 502 helper_unavailable with the cause in details, and a proxy log line", async () => {
    const port = await freePort();
    const dead = await freePort(); // nothing listens here
    const s = sink();
    servers.push(await startHelperProxy({ port, host: "127.0.0.1", paths: ["/sources"], target: { host: "127.0.0.1", port: dead }, verify: () => undefined, log: s.log }));
    const r = await post("127.0.0.1", port, "/sources");
    assert.equal(r.status, 502);
    assert.equal(r.body.error?.code, "helper_unavailable");
    assert.equal(r.body.error?.details?.cause, "ECONNREFUSED");
    assert.ok(s.lines.some((l) => l.level === "warn" && l.msg === "helper proxy error" && l.fields.cause === "ECONNREFUSED"));
    // the caller side keeps the envelope details (errorFrom), so the app can log the cause too
    const e = errorFrom({ status: r.status, body: r.body } as never, "helper_failed");
    assert.equal(e.code, "helper_unavailable");
    assert.equal(e.details?.cause, "ECONNREFUSED");
  });
});

describe("netCause (C390)", () => {
  test("a refused fetch, a timeout, an abort, DNS, both address families, and an unknown failure", async () => {
    const port = await freePort();
    const refused = await fetch(`http://127.0.0.1:${port}/`).catch((e: unknown) => e);
    assert.equal(netCause(refused), "ECONNREFUSED");
    assert.equal(netCause(Object.assign(new Error("t"), { name: "TimeoutError" })), "timeout");
    assert.equal(netCause(Object.assign(new Error("a"), { name: "AbortError" })), "aborted");
    assert.equal(netCause(new TypeError("fetch failed", { cause: Object.assign(new Error("x"), { code: "ENOTFOUND" }) })), "ENOTFOUND");
    const both = new AggregateError([Object.assign(new Error("6"), { code: "EHOSTUNREACH" }), Object.assign(new Error("4"), { code: "ECONNREFUSED" })]);
    assert.equal(netCause(new TypeError("fetch failed", { cause: both })), "EHOSTUNREACH");
    assert.equal(netCause(new TypeError("fetch failed")), "fetch_failed");
    assert.equal(netCause(new TypeError("fetch failed", { cause: { code: "not a code; has spaces" } })), "fetch_failed", "only label-shaped codes");
  });
});
