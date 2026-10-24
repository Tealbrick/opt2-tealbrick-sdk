// Spec follow-up #49 (QA-SPEC49, RM-19 / RM-20): the local check of BRIDGE §15.3 (every `kind: "base"` row of the spec's fixture) and the
// connect-time guard of `modelFetch`: addresses, path rules, pinned address, redirects, TLS server name.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { after, describe, test } from "node:test";
import { createServer as createTlsServer } from "node:tls";
import type { ResolvedModelRole } from "@opt2-tealbrick/manifest";
import { TbError } from "../src/server/errors.ts";
import { addressRefusal, canonicalIp, classifyBaseUrl } from "../src/server/local-check.ts";
import { guardEndpoint, guardedFetch, type LookupAll } from "../src/server/model-fetch.ts";
import { freePort } from "./helpers.ts";

interface Row {
  kind: "base" | "own_host";
  input: string;
  expect: string;
  canonical?: string;
  ownHosts?: string[];
  ownInfra?: string[];
}
const cases = (JSON.parse(readFileSync(new URL("./vectors/local-check.cases.json", import.meta.url), "utf8")) as { cases: Row[] }).cases;
const baseRows = cases.filter((c) => c.kind === "base");

describe("RM-19 classifier: every kind=base row of the spec fixture", () => {
  test("the fixture has the rows of specs#49", () => {
    assert.ok(cases.length >= 106);
    assert.ok(baseRows.length >= 80);
  });
  for (const [i, row] of baseRows.entries()) {
    test(`#${i} ${JSON.stringify(row.input)} → ${row.expect}`, () => {
      const r = classifyBaseUrl(row.input, { ownHosts: row.ownHosts, ownInfraOrigins: row.ownInfra });
      assert.equal(r.result, row.expect);
      if (row.canonical !== undefined) assert.equal(r.canonical, row.canonical, "canonical form");
    });
  }
});

const ok = (address: string, family = address.includes(":") ? 6 : 4) => ({ address, family });
const stub =
  (...addrs: { address: string; family: number }[]): LookupAll =>
  async () =>
    addrs;
const binding = (over: Partial<ResolvedModelRole> = {}): ResolvedModelRole => ({
  role: "embeddings",
  provider: "ollama",
  model: "nomic-embed-text",
  baseUrl: "http://ollama.railway.internal:11434/v1",
  key: null,
  dataPolicy: "local",
  dims: null,
  ...over,
});
const code = (e: unknown) => (e instanceof TbError ? e.code : "other");

describe("RM-20 address rules and the connect-time guard", () => {
  test("canonicalIp decodes IPv4-mapped IPv6 (both spellings) and drops the zone id", () => {
    assert.deepEqual(canonicalIp("::ffff:169.254.169.254"), { ip: "169.254.169.254", family: 4 });
    assert.deepEqual(canonicalIp("::ffff:a9fe:a9fe"), { ip: "169.254.169.254", family: 4 });
    assert.deepEqual(canonicalIp("fe80::1%en0"), { ip: "fe80::1", family: 6 });
    assert.equal(canonicalIp("example.com"), null);
  });

  test("a local binding whose name resolves to a refused address → model_endpoint_refused (public, metadata, mapped metadata, AWS IPv6, mixed, CGNAT when verified)", async () => {
    const bad: [string, { address: string; family: number }[]][] = [
      ["a public address", [ok("93.184.216.34")]],
      ["169.254.169.254", [ok("169.254.169.254")]],
      ["::ffff:169.254.169.254", [ok("::ffff:169.254.169.254")]],
      ["fd00:ec2::254", [ok("fd00:ec2::254")]],
      ["fe80::1", [ok("fe80::1")]],
      ["100.100.100.200", [ok("100.100.100.200")]],
      ["a private and a public record", [ok("10.0.0.5"), ok("93.184.216.34")]],
      ["a private record and the metadata address", [ok("10.0.0.5"), ok("169.254.169.254")]],
      ["100.64.1.2 for a verified binding", [ok("100.64.1.2")]],
      ["no record", []],
    ];
    for (const [name, addrs] of bad) {
      await assert.rejects(guardEndpoint(binding(), { lookup: stub(...addrs) }), (e: unknown) => code(e) === "model_endpoint_refused", name);
    }
    await assert.rejects(guardEndpoint(binding(), { lookup: async () => Promise.reject(new Error("ENOTFOUND")) }), (e: unknown) => code(e) === "model_endpoint_refused");
  });

  test("private records pass for a verified local binding; the first checked address is the one to pin; 100.64/10 only for an owner-listed name", async () => {
    const g = await guardEndpoint(binding(), { lookup: stub(ok("10.1.2.3"), ok("fd12::1")) });
    assert.deepEqual([g.address, g.family, g.host], ["10.1.2.3", 4, "ollama.railway.internal"]);
    const tail = binding({ baseUrl: "https://gpu.taild2144d.ts.net/v1" }); // not verified by text: only an owner can have listed it
    assert.equal((await guardEndpoint(tail, { lookup: stub(ok("100.101.102.103")) })).address, "100.101.102.103");
    await assert.rejects(guardEndpoint(tail, { lookup: stub(ok("93.184.216.34")) }), (e: unknown) => code(e) === "model_endpoint_refused");
    await assert.rejects(guardEndpoint(tail, { lookup: stub(ok("169.254.169.254")) }), (e: unknown) => code(e) === "model_endpoint_refused");
    // a `policyBasis` the bridge sends wins
    await assert.rejects(guardEndpoint({ ...tail, policyBasis: "verified" } as never, { lookup: stub(ok("100.101.102.103")) }), (e: unknown) => code(e) === "model_endpoint_refused");
  });

  test("a non-local binding: public addresses pass, NEVER_LOCAL and a private/public mix do not; an IP literal needs no lookup", async () => {
    const std = binding({ dataPolicy: "standard", baseUrl: "https://api.example.com/v1" });
    assert.equal((await guardEndpoint(std, { lookup: stub(ok("93.184.216.34")) })).address, "93.184.216.34");
    await assert.rejects(guardEndpoint(std, { lookup: stub(ok("169.254.169.254")) }), (e: unknown) => code(e) === "model_endpoint_refused");
    await assert.rejects(guardEndpoint(std, { lookup: stub(ok("93.184.216.34"), ok("10.0.0.5")) }), (e: unknown) => code(e) === "model_endpoint_refused");
    const lit = binding({ baseUrl: "http://10.0.0.5:11434/v1" });
    assert.equal((await guardEndpoint(lit, { lookup: async () => Promise.reject(new Error("no lookup for a literal")) })).address, "10.0.0.5");
    await assert.rejects(guardEndpoint(binding({ dataPolicy: "standard", baseUrl: "https://169.254.169.254/" }), {}), (e: unknown) => code(e) === "model_endpoint_refused");
    await assert.rejects(guardEndpoint(binding({ dataPolicy: "standard", baseUrl: "https://metadata.google.internal/" }), {}), (e: unknown) => code(e) === "model_endpoint_refused");
    await assert.rejects(guardEndpoint(binding({ baseUrl: null }), {}), (e: unknown) => code(e) === "model_endpoint_refused");
    await assert.rejects(guardEndpoint(binding({ baseUrl: "http://10.0.0.1\\@evil.example/v1" }), {}), (e: unknown) => code(e) === "model_endpoint_refused");
  });

  test("addressRefusal: the ranges", () => {
    for (const a of ["127.0.0.1", "10.0.0.1", "172.31.255.255", "192.168.0.1", "::1", "fc00::1", "fd12:3456::1"]) assert.equal(addressRefusal(a, { local: true, policyBasis: "verified" }), null, a);
    for (const a of ["172.32.0.1", "192.169.0.1", "100.64.0.1", "8.8.8.8", "2001:db8::1", "::"]) assert.notEqual(addressRefusal(a, { local: true, policyBasis: "verified" }), null, a);
    assert.equal(addressRefusal("100.127.255.255", { local: true, policyBasis: "owner_attested" }), null);
    assert.notEqual(addressRefusal("100.100.100.200", { local: true, policyBasis: "owner_attested" }), null, "metadata inside CGNAT");
  });
});

describe("RM-20 guardedFetch against real sockets", () => {
  const servers: Server[] = [];
  after(async () => {
    for (const s of servers) {
      s.closeAllConnections();
      await new Promise<void>((r) => s.close(() => r()));
    }
  });
  async function listen(handler: (req: IncomingMessage, res: import("node:http").ServerResponse) => void): Promise<{ port: number; hits: IncomingMessage[] }> {
    const port = await freePort();
    const hits: IncomingMessage[] = [];
    const s = createServer((req, res) => {
      hits.push(req);
      handler(req, res);
    });
    servers.push(s);
    await new Promise<void>((r) => s.listen(port, "127.0.0.1", r));
    return { port, hits };
  }
  const b = (port: number, name = "ollama.railway.internal") => binding({ baseUrl: `http://${name}:${port}/v1` });

  test("one lookup per request, the checked address is the one connected to; Host keeps the name; path joins under the base path; the app's header goes through", async () => {
    const srv = await listen((req, res) => {
      let body = "";
      req.on("data", (c) => {
        body += c;
      });
      req.on("end", () => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ path: req.url, host: req.headers.host, auth: req.headers.authorization, body })));
    });
    let lookups = 0;
    // the name does not exist: only the pinned address can reach the server
    const f = guardedFetch(b(srv.port), {
      lookup: async () => {
        lookups++;
        return [ok("127.0.0.1")];
      },
    });
    const r = await f("/embeddings", { method: "POST", headers: { authorization: "Bearer app-adds-this", host: "evil.example" }, body: JSON.stringify({ input: "x" }) });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { path: "/v1/embeddings", host: `ollama.railway.internal:${srv.port}`, auth: "Bearer app-adds-this", body: '{"input":"x"}' });
    assert.equal(lookups, 1, "no second lookup for the request");
    await (await f("models")).text();
    assert.equal(lookups, 2, "one lookup per request");
  });

  test("a refused address sends nothing: the server sees no request", async () => {
    const srv = await listen((_req, res) => res.end("hit"));
    for (const addrs of [[ok("169.254.169.254")], [ok("127.0.0.1"), ok("93.184.216.34")], [ok("100.64.1.2")], [ok("::ffff:169.254.169.254")]]) {
      await assert.rejects(guardedFetch(b(srv.port), { lookup: stub(...addrs) })("/x"), (e: unknown) => code(e) === "model_endpoint_refused");
    }
    assert.equal(srv.hits.length, 0);
  });

  test("a path that leaves the origin is refused before any lookup or request", async () => {
    const srv = await listen((_req, res) => res.end("hit"));
    let lookups = 0;
    const f = guardedFetch(b(srv.port), {
      lookup: async () => {
        lookups++;
        return [ok("127.0.0.1")];
      },
    });
    for (const p of ["//evil.example/x", "https://evil.example/x", "http://127.0.0.1/x", "\\@evil/x", "/a@evil/x", "/../admin", "/v1/%2e%2e/admin", "/x\u0000", "javascript:x"]) {
      await assert.rejects(f(p), (e: unknown) => code(e) === "model_endpoint_refused", p);
    }
    assert.equal(lookups, 0);
    assert.equal(srv.hits.length, 0);
  });

  test("a cross-origin redirect is never followed (model_endpoint_refused), whatever headers the app set; the other origin sees nothing", async () => {
    const other = await listen((_req, res) => res.end("stolen"));
    const srv = await listen((_req, res) => res.writeHead(302, { location: `http://127.0.0.1:${other.port}/steal` }).end());
    const f = guardedFetch(b(srv.port), { lookup: stub(ok("127.0.0.1")) });
    await assert.rejects(f("/x", { headers: { authorization: "Bearer k", "x-api-key": "k" } }), (e: unknown) => code(e) === "model_endpoint_refused");
    // another port on the same host is another origin too
    const srv2 = await listen((_req, res) => res.writeHead(307, { location: `http://ollama.railway.internal:${other.port}/steal` }).end());
    await assert.rejects(guardedFetch(b(srv2.port), { lookup: stub(ok("127.0.0.1")) })("/x"), (e: unknown) => code(e) === "model_endpoint_refused");
    assert.equal(other.hits.length, 0);
  });

  test("a same-origin redirect is followed and re-runs the guard on every hop", async () => {
    const srv = await listen((req, res) => (req.url === "/v1/old" ? res.writeHead(302, { location: "/v1/new" }).end() : res.writeHead(200).end(`at ${req.url}`)));
    let lookups = 0;
    const f = guardedFetch(b(srv.port), {
      lookup: async () => {
        lookups++;
        return [ok("127.0.0.1")];
      },
    });
    const r = await f("/old");
    assert.equal(await r.text(), "at /v1/new");
    assert.equal(lookups, 2, "the guard ran on both hops");
    // the second hop's name now resolves to metadata: refused, the redirect target is not requested
    let n = 0;
    const g = guardedFetch(b(srv.port), { lookup: async () => (++n === 1 ? [ok("127.0.0.1")] : [ok("169.254.169.254")]) });
    const before = srv.hits.length;
    await assert.rejects(g("/old"), (e: unknown) => code(e) === "model_endpoint_refused");
    assert.equal(srv.hits.length, before + 1, "only the first hop was sent");
  });

  test("TLS keeps the ORIGINAL host name for SNI while the address is pinned", async () => {
    const seen: string[] = [];
    const port = await freePort();
    const tls = createTlsServer({ SNICallback: (name, cb) => {
        seen.push(name);
        cb(new Error("no certificate in this test"), undefined);
      },
    });
    await new Promise<void>((r) => tls.listen(port, "127.0.0.1", r));
    try {
      const f = guardedFetch(binding({ baseUrl: `https://ollama.railway.internal:${port}/v1` }), { lookup: stub(ok("127.0.0.1")) });
      await assert.rejects(f("/x"), (e: unknown) => code(e) === "model_endpoint_unreachable");
      assert.deepEqual(seen, ["ollama.railway.internal"]);
    } finally {
      tls.close();
    }
  });
});
