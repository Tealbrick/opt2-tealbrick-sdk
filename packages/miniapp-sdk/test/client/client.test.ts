// Client (SDK-API §14) with a mocked fetch: base path, credentials, the one CSRF header, error envelope → TbError,
// person ops, session store, the standard-op helpers behind the hooks, and an initial server render of the hooks.
import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, test } from "node:test";
import React from "react";
import { renderToString } from "react-dom/server";
import { basePath, setProduct } from "../../src/client/fetch.ts";
import { callOp, TbError, TbProvider, tbFetch, useAgents, useHolds, useScopes, useSession } from "../../src/client/index.ts";
import { acceptOffer, decideHold, getSessionSnapshot, listAgents, listHolds, loadSession, resetClientState, scopeRows, setScope, signOut } from "../../src/client/store.ts";

interface Call {
  url: string;
  method: string;
  headers: Headers;
  credentials: RequestCredentials | undefined;
  body: string | null;
}

type Handler = (c: Call) => Response;
const realFetch = globalThis.fetch;
let calls: Call[] = [];
let handler: Handler = () => new Response("{}");

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

const principal = { type: "person", id: "per_01JA2Q3R4S5T6V7W8X9YZABCDE", ws: "ws_01JA2Q3R4S5T6V7W8X9YZABCDE", instance: "ins_01JA2Q3R4S5T6V7W8X9YZABCDE", iss: "tb:portal", sessionExpiresAt: 1 };

beforeEach(() => {
  calls = [];
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const c: Call = { url: String(input), method: init?.method ?? "GET", headers: new Headers(init?.headers), credentials: init?.credentials, body: typeof init?.body === "string" ? init.body : null };
    calls.push(c);
    return handler(c);
  }) as typeof fetch;
});
afterEach(() => {
  globalThis.fetch = realFetch;
  resetClientState();
});

describe("base path", () => {
  test("without a provider the product comes from the page path; refused outside /a/<product>/", async () => {
    (globalThis as { location?: { pathname: string } }).location = { pathname: "/a/notes/holds" };
    assert.equal(basePath(), "/a/notes/");
    (globalThis as { location?: { pathname: string } }).location = { pathname: "/elsewhere" };
    assert.throws(() => basePath(), TypeError);
    delete (globalThis as { location?: unknown }).location;
    setProduct("jotter");
    assert.equal(basePath(), "/a/jotter/");
    assert.throws(() => setProduct("Bad Id"), TypeError);
  });
});

describe("tbFetch", () => {
  test("GET: same-origin path under the base, credentials include, no CSRF header", async () => {
    setProduct("jotter");
    handler = () => json(200, { ok: true });
    const res = await tbFetch("/tb/v1/things?x=1");
    assert.equal(res.status, 200);
    assert.equal(calls[0]?.url, "/a/jotter/tb/v1/things?x=1");
    assert.equal(calls[0]?.credentials, "include");
    assert.equal(calls[0]?.headers.get("TB-CSRF"), null);
  });

  test("non-GET loads the session once for the CSRF token and sends it as TB-CSRF", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/tb/v1/session") ? json(200, { principal, csrf: "csrf-token-1" }) : json(200, { done: true }));
    await tbFetch("custom/write", { method: "POST", body: "{}" });
    await tbFetch("custom/write", { method: "DELETE" });
    assert.deepEqual(
      calls.map((c) => [c.method, c.url, c.headers.get("TB-CSRF")]),
      [
        ["GET", "/a/jotter/tb/v1/session", null],
        ["POST", "/a/jotter/custom/write", "csrf-token-1"],
        ["DELETE", "/a/jotter/custom/write", "csrf-token-1"],
      ],
    );
  });

  test("non-GET without a session → session_required, no write request sent", async () => {
    setProduct("jotter");
    handler = () => json(401, { error: { code: "session_required", message: "sign in", requestId: "req_1" } });
    await assert.rejects(tbFetch("x", { method: "POST" }), (e: unknown) => e instanceof TbError && e.code === "session_required" && e.httpStatus === 401);
    assert.equal(calls.length, 1);
  });

  test("error envelope → TbError with code, message, status and details; other failures → http_error", async () => {
    setProduct("jotter");
    handler = () => json(409, { error: { code: "idempotency_conflict", message: "different input", requestId: "req_2", details: { op: "x" } } });
    await assert.rejects(tbFetch("y"), (e: unknown) => e instanceof TbError && e.code === "idempotency_conflict" && e.message === "different input" && e.httpStatus === 409 && e.details?.op === "x");
    handler = () => new Response("oops", { status: 502 });
    await assert.rejects(tbFetch("y"), (e: unknown) => e instanceof TbError && e.code === "http_error" && e.httpStatus === 502);
  });

  test("paths that leave the base path are refused before any request", async () => {
    setProduct("jotter");
    for (const p of ["https://evil.example/x", "//evil.example/x", "../other/x", "a/../../x", "..", "a\\b"]) await assert.rejects(tbFetch(p), TypeError, p);
    assert.equal(calls.length, 0);
  });
});

describe("callOp", () => {
  test("POSTs { input } to the person op route and returns the output", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(200, { status: "ok", output: { renamed: true } }));
    const out = await callOp<{ renamed: boolean }>("notebook_rename", { notebook: "n1", label: "Work" });
    assert.deepEqual(out, { renamed: true });
    const post = calls.at(-1);
    assert.equal(post?.url, "/a/jotter/tb/v1/ops/notebook_rename");
    assert.equal(post?.headers.get("content-type"), "application/json");
    assert.deepEqual(JSON.parse(post?.body ?? ""), { input: { notebook: "n1", label: "Work" } });
  });

  test("C41: idempotencyKey option is sent as body field; invalid key refused before any request", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(200, { status: "ok", output: { ok: true } }));
    await callOp("item_create", { title: "a" }, { idempotencyKey: "k-1:abc" });
    assert.deepEqual(JSON.parse(calls.at(-1)?.body ?? ""), { input: { title: "a" }, idempotencyKey: "k-1:abc" });
    const before = calls.length;
    await assert.rejects(callOp("item_create", {}, { idempotencyKey: "bad key!" }), (e: unknown) => e instanceof TbError && e.code === "idempotency_key_invalid");
    assert.equal(calls.length, before);
  });

  test("C53: ops listed in idempotencyRequired get a fresh UUID key per call; other ops none; caller key wins", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t", idempotencyRequired: ["item_create"] }) : json(200, { status: "ok", output: {} }));
    const bodies = async (op: string, opts?: { idempotencyKey?: string }) => {
      await callOp(op, { title: "a" }, opts);
      return JSON.parse(calls.at(-1)?.body ?? "") as { input: unknown; idempotencyKey?: string };
    };
    const first = await bodies("item_create");
    const second = await bodies("item_create");
    assert.match(first.idempotencyKey ?? "", /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    assert.notEqual(first.idempotencyKey, second.idempotencyKey, "a new call is a new logical call");
    assert.equal(calls.filter((c) => c.url.endsWith("/session")).length, 1, "the session answer is loaded once");
    assert.equal("idempotencyKey" in (await bodies("item_rename")), false);
    assert.equal((await bodies("item_create", { idempotencyKey: "caller-key-1" })).idempotencyKey, "caller-key-1");
  });

  test("C53: older server without idempotencyRequired → no auto key; signed out → session_required after one GET", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(200, { status: "ok", output: {} }));
    await callOp("item_create", {});
    assert.deepEqual(JSON.parse(calls.at(-1)?.body ?? ""), { input: {} });
    resetClientState();
    calls = [];
    handler = () => json(401, { error: { code: "session_required", message: "sign in", requestId: "r" } });
    await assert.rejects(callOp("item_create", {}), (e: unknown) => e instanceof TbError && e.code === "session_required");
    assert.deepEqual(
      calls.map((c) => c.method),
      ["GET"],
    );
  });

  test("a refusal envelope throws its code; a non-ok result throws op_not_completed", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(403, { error: { code: "csrf_invalid", message: "bad", requestId: "r" } }));
    await assert.rejects(callOp("x", {}), (e: unknown) => e instanceof TbError && e.code === "csrf_invalid");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(200, { status: "held", holdId: "hld_1", expiresAt: "z" }));
    await assert.rejects(callOp("x", {}), (e: unknown) => e instanceof TbError && e.code === "op_not_completed");
  });
});

describe("session store", () => {
  test("loadSession → signed_in with principal; signOut POSTs logout with CSRF → signed_out", async () => {
    setProduct("jotter");
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "csrf-2" }) : json(200, { ok: true }));
    assert.equal(getSessionSnapshot().status, "loading");
    await loadSession();
    assert.equal(getSessionSnapshot().status, "signed_in");
    assert.deepEqual(getSessionSnapshot().principal, principal);
    await signOut();
    assert.equal(getSessionSnapshot().status, "signed_out");
    const logout = calls.at(-1);
    assert.equal(logout?.method, "POST");
    assert.equal(logout?.url, "/a/jotter/tb/v1/logout");
    assert.equal(logout?.headers.get("TB-CSRF"), "csrf-2");
  });

  test("session_required → signed_out; other failures throw", async () => {
    setProduct("jotter");
    handler = () => json(401, { error: { code: "session_required", message: "no", requestId: "r" } });
    assert.equal((await loadSession()).status, "signed_out");
    handler = () => json(500, { error: { code: "internal_error", message: "boom", requestId: "r" } });
    await assert.rejects(loadSession(), (e: unknown) => e instanceof TbError && e.code === "internal_error");
  });
});

describe("standard person ops behind the hooks", () => {
  const ops = (c: Call) => JSON.parse(c.body ?? "{}").input as Record<string, unknown>;
  const agentA = "agt_01JA2Q3R4S5T6V7W8X9YZABCDE";
  const agentB = "agt_01JA2Q3R4S5T6V7W8X9YZABCDF";

  test("listHolds follows cursors; decideHold sends holdId, decision, note", async () => {
    setProduct("jotter");
    handler = (c) => {
      if (c.url.endsWith("/session")) return json(200, { principal, csrf: "t" });
      if (c.url.endsWith("tb.holds_list")) return json(200, { status: "ok", output: ops(c).cursor ? { items: [{ id: "hld_2" }], nextCursor: null } : { items: [{ id: "hld_1" }], nextCursor: "c1" } });
      return json(200, { status: "ok", output: { id: "hld_1", status: "approved" } });
    };
    const holds = await listHolds({ status: "held" });
    assert.deepEqual(
      holds.map((h) => h.id),
      ["hld_1", "hld_2"],
    );
    const lists = calls.filter((c) => c.url.endsWith("tb.holds_list")).map(ops);
    assert.deepEqual(lists, [{ status: "held" }, { status: "held", cursor: "c1" }]);
    await decideHold("hld_01JA2Q3R4S5T6V7W8X9YZABCDE", "approve", "ok by me");
    assert.deepEqual(ops(calls.at(-1) as Call), { holdId: "hld_01JA2Q3R4S5T6V7W8X9YZABCDE", decision: "approve", note: "ok by me" });
  });

  test("listAgents / scopeRows / setScope", async () => {
    setProduct("jotter");
    const agents = [
      { id: agentA, name: "A", mode: "free", status: "active", access: [{ agent: agentA, type: "notebook", instanceId: "n1", access: "read" }] },
      { id: agentB, name: "B", mode: "free", status: "active", access: [{ agent: agentB, type: "notebook", instanceId: "n2", access: "read_write" }] },
    ];
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : c.url.endsWith("tb.agents_list") ? json(200, { status: "ok", output: { agents } }) : json(200, { status: "ok", output: { access: null } }));
    const got = await listAgents();
    assert.equal(got.length, 2);
    assert.deepEqual(
      scopeRows(got, agentB).map((r) => r.instanceId),
      ["n2"],
    );
    assert.equal(scopeRows(got).length, 2);
    await setScope(agentA, "notebook", "n1", null);
    assert.deepEqual(ops(calls.at(-1) as Call), { agent: agentA, type: "notebook", id: "n1", access: null });
  });

  test("acceptOffer sends the row's OWN level with acceptOffer {adds}; no row → input_invalid and nothing is sent (v0.1.36)", { timeout: 60_000 }, async () => {
    setProduct("jotter");
    const agents = [{ id: agentA, name: "A", mode: "free", status: "active", access: [{ agent: agentA, type: "notebook", instanceId: "n1", access: "write", authority: "owner", crud: ["read"], offer: { adds: ["update", "delete"] } }] }];
    handler = (c) => (c.url.endsWith("/session") ? json(200, { principal, csrf: "t" }) : json(200, { status: "ok", output: { access: null } }));
    await loadSession();
    const before = calls.length;
    await acceptOffer(agents as never, agentA, "notebook", "n1", ["update", "delete"]);
    assert.deepEqual(ops(calls.at(-1) as Call), { agent: agentA, type: "notebook", id: "n1", access: "write", acceptOffer: { adds: ["update", "delete"] } });
    assert.equal(calls.length, before + 1);
    await assert.rejects(acceptOffer(agents as never, agentA, "notebook", "nope", ["delete"]), (e: unknown) => (e as { code?: string }).code === "input_invalid");
    await assert.rejects(acceptOffer(agents as never, agentB, "notebook", "n1", ["delete"]), (e: unknown) => (e as { code?: string }).code === "input_invalid");
    assert.equal(calls.length, before + 1, "nothing was sent for a row that does not exist");
  });
});

describe("React bindings (initial render)", () => {
  test("TbProvider + hooks render their initial state", () => {
    let seen: Record<string, unknown> = {};
    function Probe() {
      const s = useSession();
      const h = useHolds({ status: "held" });
      const a = useAgents();
      const sc = useScopes();
      seen = { status: s.status, holds: h.holds.length, holdsLoading: h.loading, agents: a.agents.length, access: sc.access.length, signOut: typeof s.signOut, decide: typeof h.decide, set: typeof sc.set, acceptOffer: typeof sc.acceptOffer };
      return React.createElement("p", null, s.status);
    }
    const html = renderToString(React.createElement(TbProvider, { product: "jotter" }, React.createElement(Probe)));
    assert.equal(html, "<p>loading</p>");
    assert.deepEqual(seen, { status: "loading", holds: 0, holdsLoading: true, agents: 0, access: 0, signOut: "function", decide: "function", set: "function", acceptOffer: "function" });
    assert.equal(basePath(), "/a/jotter/");
  });

  test("hooks outside TbProvider throw", () => {
    function Bare() {
      useSession();
      return null;
    }
    assert.throws(() => renderToString(React.createElement(Bare)), /TbProvider/);
  });
});
