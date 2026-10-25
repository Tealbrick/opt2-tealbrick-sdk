// Core target, live layer against the fake gateway: a correct gateway passes every probe it can run (sign-in checks
// stay not_run), --live-readonly never writes, and each broken variant fails exactly the check that guards it.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { OPAQUE_PREFIX } from "@opt2-tealbrick/spec/credentials";
import { ROUTES } from "@opt2-tealbrick/spec/routes";
import { authProbeRows, CORE_LIVE_CHECKS, envelopeOnly, gatewayOrigin, LiveClient, loadSpecTypes, ProbeBlocked, runCoreLive, runCoreTarget, secretInPublicAnswer, stringUnion } from "../../src/index.ts";
import type { CheckResult } from "../../src/report.ts";
import { type Break, type FakeGateway, startFakeGateway } from "./fake-gateway.ts";

/** a live-key-shaped fixture assembled at run time (no key-like literal in source for the secret scanner) */
const FAKE_LIVE_KEY = ["sk", "live", "0123456789abcdef"].join("_");

const errorCodes = stringUnion(loadSpecTypes(), "ErrorCode");
const byStatus = (rs: CheckResult[], s: string) => rs.filter((r) => r.status === s).map((r) => r.id);
async function live(breaks: Break[] = [], readonly = true): Promise<{ results: CheckResult[]; gw: FakeGateway; client: LiveClient }> {
  const gw = await startFakeGateway(breaks);
  try {
    const client = new LiveClient({ origin: gw.url, readonly, minIntervalMs: 0, timeoutMs: 3000 });
    const results = await runCoreLive({ client, errorCodes });
    return { results, gw, client };
  } finally {
    await gw.close();
  }
}
const SIGNED_IN = ["R2.live_owner_cli_refused", "R3", "cred.dev.approve_requires_user_code", "cred.dev.one_time", "cred.dev.expiry", "R9.idle_24h", "R10.live_replay", "R11.flow", "R12", "C7", "P2"];

describe("core live checks", () => {
  let ok: Awaited<ReturnType<typeof live>>;
  before(async () => {
    ok = await live();
  });

  it("correct gateway, --live-readonly: no fail; sign-in and write checks not_run; one result per catalogued id", () => {
    assert.deepEqual(
      ok.results.map((r) => r.id).sort(),
      CORE_LIVE_CHECKS.map((c) => c.id).sort(),
    );
    assert.deepEqual(
      ok.results.filter((r) => r.status === "fail").map((r) => `${r.id}: ${r.asserted}`),
      [],
    );
    const notRun = byStatus(ok.results, "not_run");
    for (const id of [...SIGNED_IN, "R7.start_shape", "R7.poll_pending", "R8.agent_batch_limit", "cred.p1.kit_cannot_get_owner", "R8.owner_no_key"]) assert.ok(notRun.includes(id), id);
    for (const id of SIGNED_IN) assert.match(ok.results.find((r) => r.id === id)?.asserted ?? "", /QA/);
    for (const r of authProbeRows()) assert.equal(ok.results.find((x) => x.id === `R1.auth.${r.opId}`)?.status, "pass", r.opId);
    for (const id of ["R1.unknown_path", "R1.internal_unreachable", "R1.cors", "R1.no_internals", "R7.unknown_device_code", "C6.enrol_unknown_code", "R11.webhook_bad_signature", "R1.public_rows", "R1.status_mapping"]) {
      assert.equal(ok.results.find((r) => r.id === id)?.status, "pass", id);
    }
  });

  it("--live-readonly never writes: no device.start, no credential sent to a person mutation, no non-GET to a credentialed row except bridge/no-credential", () => {
    const start = ROUTES.find((r) => r.opId === "device.start");
    assert.ok(!ok.gw.seen.some((s) => s.method === "POST" && s.path === `/api/v1${start?.path}`), "device.start not called");
    assert.ok(!ok.gw.seen.some((s) => s.headers.cookie !== undefined), "no cookie ever sent");
    const personMutations = ok.gw.seen.filter((s) => s.method !== "GET" && s.method !== "OPTIONS" && typeof s.headers.authorization === "string");
    assert.deepEqual(
      personMutations.map((s) => `${s.method} ${s.path}`),
      [],
    );
    assert.ok(ok.client.sent < 600 && ok.client.sent === ok.gw.seen.length, `${ok.client.sent} requests`);
  });

  it("full live mode (no --live-readonly) runs the device.start refusal and shape probes", async () => {
    const r = await live([], false);
    for (const id of ["cred.p1.kit_cannot_get_owner", "R8.owner_no_key", "R8.agent_batch_limit", "R7.start_shape", "R1.public_rows"]) assert.equal(r.results.find((x) => x.id === id)?.status, "pass", id);
    assert.doesNotMatch(r.results.find((x) => x.id === "R1.public_rows")?.asserted ?? "", /SECRET IN ANSWER/);
    assert.equal(r.results.find((x) => x.id === "R7.poll_pending")?.status, "fail", "the fake never answers authorization_pending");
  });

  it("device.start leaking a field that is not in DeviceStart fails R1.public_rows (R7.start_shape still passes)", async () => {
    const r = await live(["device_start_extra_secret"], false);
    const pr = r.results.find((x) => x.id === "R1.public_rows");
    assert.equal(pr?.status, "fail");
    assert.match(pr?.asserted ?? "", /device\.start → 200.*SECRET IN ANSWER/);
    assert.equal(r.results.find((x) => x.id === "R7.start_shape")?.status, "pass");
  });

  it("secretInPublicAnswer exempts exactly the spec-defined device-flow outputs", () => {
    const ans = (status: number, body: Record<string, unknown>) => ({ status, body, text: JSON.stringify(body) });
    const deviceCode = `${OPAQUE_PREFIX.deviceCode}${"B".repeat(43)}`;
    const start = { device_code: deviceCode, user_code: "BCDF-GHJK", verification_uri: "https://p.test/device", verification_uri_complete: "https://p.test/device?user_code=BCDF-GHJK", expires_in: 600, interval: 5 };
    const owner = { scope: "owner", access_token: `${OPAQUE_PREFIX.ownerCliSession}${"A".repeat(43)}`, token_type: "Bearer", expires_in: 86400, session_id: "ses_x" };
    const agent = { scope: "agent", workspace_id: "ws_x", bridge_id: "brg_x", mcp_url: "https://b.test/mcp", token_endpoint: "https://b.test/oauth/token", connections: [] };
    assert.equal(secretInPublicAnswer("device.start", ans(200, start)), false);
    assert.equal(secretInPublicAnswer("device.token", ans(200, owner)), false);
    assert.equal(secretInPublicAnswer("device.token", ans(200, agent)), false);
    // not the spec op, not a 200, not the owner shape, not the spec value shape → scanned as usual
    assert.equal(secretInPublicAnswer("bridge_api.enrol", ans(200, start)), true);
    assert.equal(secretInPublicAnswer("device.start", ans(400, start)), true);
    assert.equal(secretInPublicAnswer("device.token", ans(200, { ...owner, scope: undefined })), true);
    assert.equal(secretInPublicAnswer("device.token", ans(200, { access_token: owner.access_token, token_type: "Bearer" })), true);
    assert.equal(secretInPublicAnswer("device.start", ans(200, { ...start, device_code: FAKE_LIVE_KEY })), true);
    assert.equal(secretInPublicAnswer("device.token", ans(200, { ...agent, access_token: owner.access_token })), true);
    // anything beyond the exempt fields still fails
    assert.equal(secretInPublicAnswer("device.start", ans(200, { ...start, client_secret: "x" })), true);
    assert.equal(secretInPublicAnswer("device.start", ans(200, { ...start, note: deviceCode })), true);
    assert.equal(secretInPublicAnswer("device.token", ans(200, { ...owner, refresh_token: "r" })), true);
    assert.equal(secretInPublicAnswer("device.token", ans(200, { ...owner, key: { kty: "OKP", d: "E".repeat(43) } })), true);
    const dupText = `{"device_code":"${FAKE_LIVE_KEY}","device_code":"${deviceCode}","user_code":"BCDF-GHJK"}`;
    assert.equal(secretInPublicAnswer("device.start", { status: 200, body: JSON.parse(dupText) as unknown, text: dupText }), true);
  });

  const cases: [Break, string[]][] = [
    ["data_without_auth", ["R1.auth.account.me", "R1.auth.workspaces.list"]],
    ["wildcard_cors", ["R1.cors"]],
    ["internal_reachable", ["R1.internal_unreachable"]],
    ["unknown_path_200", ["R1.unknown_path", "R1.unknown_method"]],
    ["stack_trace", ["R1.no_internals"]],
    ["device_token_leak", ["R7.unknown_device_code", "R7.malformed_poll", "R1.public_rows"]],
    ["status_mismatch", ["R1.unknown_path", "R1.status_mapping", "R11.webhook_bad_signature"]],
    ["public_key_leak", ["R1.public_rows"]],
  ];
  for (const [b, ids] of cases) {
    it(`broken gateway (${b}) fails ${ids.join(", ")}`, async () => {
      const r = await live([b]);
      const failed = byStatus(r.results, "fail");
      for (const id of ids) assert.ok(failed.includes(id), `${id} should fail; failed: ${failed.join(", ")}`);
    });
  }

  it("unreachable gateway: every live probe fails, deferred ones stay not_run", async () => {
    const client = new LiveClient({ origin: "http://127.0.0.1:1", readonly: true, minIntervalMs: 0, timeoutMs: 1000 });
    const rs = await runCoreLive({ client });
    assert.ok(byStatus(rs, "fail").includes("R1.unknown_path"));
    assert.ok(byStatus(rs, "not_run").includes("R3"));
    assert.equal(byStatus(rs, "pass").length, 0);
  });
});

describe("LiveClient guard rails", () => {
  let gw: FakeGateway;
  before(async () => {
    gw = await startFakeGateway();
  });
  after(() => gw.close());

  it("refuses write probes in readonly mode and non-GET 'read' probes", async () => {
    const c = new LiveClient({ origin: gw.url, readonly: true, minIntervalMs: 0 });
    await assert.rejects(c.probe({ method: "POST", path: "/api/v1/device/authorize", body: "{}", safety: "write", label: "w" }), ProbeBlocked);
    await assert.rejects(c.probe({ method: "POST", path: "/api/v1/x", safety: "read", label: "r" }), ProbeBlocked);
    assert.equal(c.sent, 0);
  });

  it("keeps the request budget and the minimum interval", async () => {
    const c = new LiveClient({ origin: gw.url, readonly: true, minIntervalMs: 60, maxRequests: 3 });
    const before = gw.seen.length;
    for (let i = 0; i < 3; i++) await c.probe({ method: "GET", path: "/api/v1/me", safety: "read", label: "p" });
    await assert.rejects(c.probe({ method: "GET", path: "/api/v1/me", safety: "read", label: "p" }), /budget/);
    const at = gw.seen.slice(before).map((s) => s.at);
    assert.equal(at.length, 3);
    for (let i = 1; i < at.length; i++) assert.ok(at[i] - at[i - 1] >= 55, `gap ${at[i] - at[i - 1]} ms`);
  });

  it("a budget too small for the run reports the rest not_run, never pass", async () => {
    const client = new LiveClient({ origin: gw.url, readonly: true, minIntervalMs: 0, maxRequests: 5 });
    const rs = await runCoreLive({ client });
    assert.equal(client.sent, 5);
    assert.ok(byStatus(rs, "not_run").includes("R1.no_internals") || byStatus(rs, "not_run").includes("R1.cors"));
    assert.match(rs.find((r) => r.id === "R1.auth.account.me")?.asserted ?? "", /budget/);
  });

  it("envelopeOnly accepts exactly the one error envelope", () => {
    assert.deepEqual(envelopeOnly({ error: { code: "not_found", message: "m", requestId: "r" } }), { code: "not_found", message: "m", requestId: "r" });
    assert.equal(envelopeOnly({ error: { code: "x", message: "m" } }), null);
    assert.equal(envelopeOnly({ error: { code: "x", message: "m", requestId: "r" }, data: [] }), null);
    assert.equal(envelopeOnly({ error: { code: "x", message: "m", requestId: "r", stack: "at …" } }), null);
    assert.equal(envelopeOnly("text"), null);
  });
});

describe("runCoreTarget", () => {
  it("gatewayOrigin accepts an origin or origin + /api/v1, refuses other paths", () => {
    assert.equal(gatewayOrigin("https://p.example/"), "https://p.example");
    assert.equal(gatewayOrigin("https://p.example/api/v1/"), "https://p.example");
    assert.throws(() => gatewayOrigin("https://p.example/other"), /gateway origin/);
  });

  it("static only (no url): static checks pass, live ids not_run, the run fails (CONFORMANCE §6)", async () => {
    const r = await runCoreTarget();
    assert.equal(r.target, "core");
    assert.equal(r.ok, false);
    assert.equal(r.counts.fail, 0);
    assert.equal(r.counts.pass, r.checks.filter((c) => !CORE_LIVE_CHECKS.some((l) => l.id === c.id)).length);
  });

  it("with --url and --live-readonly: notes record the mode and request count; no fail on a correct gateway", async () => {
    const gw = await startFakeGateway();
    try {
      const r = await runCoreTarget({ url: `${gw.url}/api/v1`, liveReadonly: true, minIntervalMs: 0 });
      assert.equal(r.counts.fail, 0, r.notes.join("\n"));
      assert.ok(r.notes.some((n) => n.includes("--live-readonly")));
      assert.ok(r.notes.some((n) => /requests sent: \d+/.test(n)));
    } finally {
      await gw.close();
    }
  });
});

describe("PORTAL-API §1.4 status table (spec 0.1.68)", () => {
  it("bridge_cap_missing (C336, BRIDGE v0.1.68: a release needs a bridge cap the workspace bridge lacks) maps to 409", async () => {
    const { coreErrorStatus } = await import("../../src/checks/core-live.ts");
    assert.deepEqual(coreErrorStatus("bridge_cap_missing"), [409]);
    assert.deepEqual(coreErrorStatus("conflict"), [409], "control: an existing 409 code");
    assert.equal(coreErrorStatus("no_such_code"), undefined);
  });
});
