// Tiny Portal gateway for the Core target's sensitivity tests, built from the spec route table: default deny, every
// credentialed row refused without the one test credential, the explicit public rows, /internal/* not served. It serves
// exactly the rows of the table it is given: pass a table without `paddle.webhook` for a Core on Stripe, without
// `stripe.webhook` for a Core on Paddle only. `breaks` switches on one defect each, so a test can prove the matching
// live check fails.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { DEVICE_FLOW, OPAQUE_PREFIX } from "@opt2-tealbrick/spec/credentials";
import { ROUTES, type RouteOp } from "@opt2-tealbrick/spec/routes";

export type Break =
  /** browser/owner-cli GET rows answer 200 with data without a credential */
  | "data_without_auth"
  /** every answer carries ACAO * and ACAC true */
  | "wildcard_cors"
  /** /api/v1/internal/routes and /internal/routes serve the route document */
  | "internal_reachable"
  /** unknown paths answer 200 {} */
  | "unknown_path_200"
  /** error bodies carry a stack trace */
  | "stack_trace"
  /** device.token answers an unknown code with an access token */
  | "device_token_leak"
  /** unknown paths answer 400 not_found; the webhook answers an off-spec code */
  | "status_mismatch"
  /** the enrol refusal carries a private JWK (`d`) of a key */
  | "public_key_leak"
  /** device.start answers the spec body plus a field that is not in DeviceStart (a refresh token) */
  | "device_start_extra_secret"
  /** the payment webhooks acknowledge an event with a forged or missing signature (200 {received: true}) */
  | "webhook_accepts_unsigned";

export interface Seen {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  at: number;
}

export interface FakeGateway {
  url: string;
  seen: Seen[];
  close(): Promise<void>;
}

/** The only credential this gateway accepts; the suite never has it. */
export const GOOD_TOKEN = "Bearer tb-conformance-test-only";
const ALLOWED_ORIGIN = "https://portal.conformance.test";
const API = "/api/v1";

const match = (row: RouteOp, path: string): boolean => new RegExp(`^${API}${row.path.replace(/\{[^}]+\}/g, "[^/]+")}$`).test(path);

export async function startFakeGateway(breaks: readonly Break[] = [], routes: readonly RouteOp[] = ROUTES): Promise<FakeGateway> {
  const has = (b: Break) => breaks.includes(b);
  const seen: Seen[] = [];
  let n = 0;
  const send = (res: ServerResponse, req: IncomingMessage, status: number, body: unknown) => {
    const headers: Record<string, string> = { "content-type": "application/json" };
    const origin = req.headers.origin;
    if (has("wildcard_cors")) Object.assign(headers, { "access-control-allow-origin": "*", "access-control-allow-credentials": "true" });
    else if (origin === ALLOWED_ORIGIN) Object.assign(headers, { "access-control-allow-origin": origin, "access-control-allow-credentials": "true", vary: "Origin" });
    res.writeHead(status, headers).end(JSON.stringify(body));
  };
  const fail = (res: ServerResponse, req: IncomingMessage, status: number, code: string, message: string) => {
    const error: Record<string, unknown> = { code, message, requestId: `req_${++n}` };
    if (has("stack_trace") && status >= 400) error.message = `${message}\n    at handle (/srv/core/src/router.ts:42:7)`;
    send(res, req, status, { error });
  };

  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const url = req.url ?? "/";
      const path = url.split("?")[0];
      const method = req.method ?? "GET";
      seen.push({ method, path: url, headers: req.headers, body: raw, at: Date.now() });

      if (has("internal_reachable") && (path === `${API}/internal/routes` || path === "/internal/routes")) return send(res, req, 200, { digest: "sha256:x", routes });
      if (!path.startsWith(`${API}/`) || path.slice(API.length).startsWith("/internal")) return fail(res, req, 404, "not_found", "no such route");
      if (method === "OPTIONS") {
        res.writeHead(204, req.headers.origin === ALLOWED_ORIGIN ? { "access-control-allow-origin": ALLOWED_ORIGIN, "access-control-allow-credentials": "true", vary: "Origin" } : {}).end();
        return;
      }
      const row = routes.find((r) => r.exposure === "gateway" && r.method === method && match(r, path));
      if (!row) {
        if (has("unknown_path_200")) return send(res, req, 200, {});
        if (has("status_mismatch")) return fail(res, req, 400, "not_found", "no such route");
        return fail(res, req, 404, "not_found", "no such route");
      }
      const auth = req.headers.authorization;
      const needsPerson = row.auth.some((a) => a === "browser" || a === "owner-cli");
      if (needsPerson) {
        if (has("data_without_auth") && method === "GET") return send(res, req, 200, { items: [{ id: "ws_leak" }] });
        if (auth !== GOOD_TOKEN) return fail(res, req, 401, "unauthenticated", "sign in required");
        return send(res, req, 200, {});
      }
      if (row.auth.includes("bridge")) return fail(res, req, 401, "unauthenticated", "bridge assertion required");

      let body: Record<string, unknown> = {};
      try {
        body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      } catch {
        return fail(res, req, 400, "bad_request", "invalid JSON");
      }
      switch (row.opId) {
        case "device.token": {
          if (has("device_token_leak")) return send(res, req, 200, { access_token: `${OPAQUE_PREFIX.ownerCliSession}${"A".repeat(43)}`, token_type: "Bearer" });
          if (body.grant_type !== "urn:ietf:params:oauth:grant-type:device_code") return fail(res, req, 400, "bad_request", "unsupported grant_type");
          return fail(res, req, 400, "expired_token", "unknown or expired device code");
        }
        case "device.start": {
          const agents = Array.isArray(body.agents) ? body.agents : [];
          if (body.scope === "owner" && (body.client_id !== "tealbrick-cli" || agents.length > 0)) return fail(res, req, 400, "validation_failed", "owner scope: tealbrick-cli, no keys");
          if (agents.length > DEVICE_FLOW.maxAgentPairs) return fail(res, req, 400, "validation_failed", "too many keys");
          const start: Record<string, unknown> = {
            device_code: `${OPAQUE_PREFIX.deviceCode}${"B".repeat(43)}`,
            user_code: "BCDF-GHJK",
            verification_uri: `${ALLOWED_ORIGIN}/device`,
            verification_uri_complete: `${ALLOWED_ORIGIN}/device?user_code=BCDF-GHJK`,
            expires_in: DEVICE_FLOW.expiresIn,
            interval: DEVICE_FLOW.interval,
          };
          if (has("device_start_extra_secret")) start.refresh = `${OPAQUE_PREFIX.agentRefresh}${"C".repeat(43)}`;
          return send(res, req, 200, start);
        }
        case "bridge_api.enrol":
          if (has("public_key_leak")) return send(res, req, 401, { error: { code: "enrolment_code_invalid", message: "unknown enrolment code", requestId: `req_${++n}` }, key: { kty: "OKP", crv: "Ed25519", x: "D".repeat(43), d: "E".repeat(43) } });
          return fail(res, req, 401, "enrolment_code_invalid", "unknown enrolment code");
        case "stripe.webhook":
          if (has("webhook_accepts_unsigned")) return send(res, req, 200, { received: true });
          if (has("status_mismatch")) return fail(res, req, 401, "webhook_bad", "signature mismatch");
          return fail(res, req, 401, "stripe_signature_invalid", "signature mismatch");
        case "paddle.webhook":
          if (has("webhook_accepts_unsigned")) return send(res, req, 200, { received: true });
          if (has("status_mismatch")) return fail(res, req, 401, "stripe_signature_invalid", "signature mismatch");
          return fail(res, req, 401, "webhook_signature_invalid", "signature mismatch");
        case "clerk.webhook":
          return fail(res, req, 401, "clerk_signature_invalid", "signature mismatch");
        default:
          return fail(res, req, 404, "not_found", "no such route");
      }
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    seen,
    close: () =>
      new Promise<void>((r) => {
        server.closeAllConnections();
        server.close(() => r());
      }),
  };
}
