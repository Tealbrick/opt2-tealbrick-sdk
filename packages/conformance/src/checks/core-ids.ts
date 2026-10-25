// Portal Core target check ids (CONFORMANCE §4.6 R1–R12 + the Core cells of §4.2/§4.3). Ids are stable; per-row
// auth probes (`R1.auth.<opId>`) are generated from the spec route table, so a new row gets a probe automatically.
import { ROUTES, type RouteOp } from "@opt2-tealbrick/spec/routes";
import type { PendingCheck } from "./catalog.ts";

/** Static checks: the route table (ROUTES) and the spec declaration files. */
export const CORE_STATIC_CHECKS: readonly PendingCheck[] = [
  { id: "R1.table.unique_ops", title: "op ids are unique" },
  { id: "R1.table.unique_paths", title: "method + path are unique (parameter names ignored)" },
  { id: "R1.table.row_fields", title: "every row: non-empty auth from the six classes, exposure gateway|internal, known transport/rate/registry/audit, input/output in SchemaMap" },
  { id: "R1.table.internal_paths", title: "exposure internal exactly on /internal/ paths (RT4, RT5)" },
  { id: "R1.table.bindings", title: "path params and query keys bind to input fields; query keys on GET rows only" },
  { id: "R1.table.explicit_public", title: "rows reachable without a person or bridge credential are exactly the four explicit public rows" },
  { id: "R1.table.p1_disjoint", title: "no row accepts a person credential and a non-person credential (P1)" },
  { id: "R1.table.rt9", title: "auth host only on host.* rows, and host.* rows only host (RT9)" },
  { id: "R2.owner_cli_rows", title: "owner-cli rows are reads, drafts.* or owner_sessions.logout (RT1)" },
  { id: "R2.owner_cli_no_confirm", title: "no owner-cli row is a confirm row (RT3)" },
  { id: "R2.apply_browser_only", title: "drafts.apply / drafts.reject are browser-only; apply is confirm + idempotent" },
  { id: "R2.draftable_rows", title: "draftable rows are browser mutations, never GET / public / bridge / device / webhook (RT2)" },
  { id: "R4.no_key_input", title: "no route input field can hold an app key value (type scan)" },
  { id: "R4.secret_inputs_unlogged", title: "inputs carrying a code, token or user code only on bodyLog: none rows" },
  { id: "R4.key_status_booleans", title: "key status outputs carry presence booleans only, never values" },
  { id: "R5.forbidden_ops", title: "no op for tool execution, connectors, channels, relay, Fleet, rooms, app data, key values, grant checks, JWKS" },
  { id: "R5.no_product_routes", title: "no product-named route (product ids from the spec example manifests)" },
  { id: "R5.no_passthrough", title: "no passthrough prefix, catch-all segment, legacy alias or version segment" },
  { id: "R7.device_rows", title: "device.start public / device.token device-auth, bodyLog none, never idempotent; RFC 8628 codes in ErrorCode" },
  { id: "R8.user_code_required", title: "device.lookup / approve / deny are browser-only and require userCode" },
  { id: "cred.dev.no_unbound_list", title: "no op lists pending device requests (only device.lookup returns one)" },
  { id: "cred.dev.no_clear_user_code", title: "no output other than the device start response carries a user code" },
  { id: "R9.owner_cli_outputs", title: "no owner-cli output is secret-bearing or carries a code / ticket / token field (RT7, S1, B4)" },
  { id: "R9.secret_outputs", title: "secret-bearing outputs: bodyLog none, never idempotent, never owner-cli (RT8)" },
  { id: "R9.secret_list_complete", title: "every output with a top-level code / ticket / token field is a declared SecretBearingSchema" },
  { id: "R10.no_idempotent_secret_rows", title: "bodyLog: none rows are never idempotent, so their responses are never stored (RT6, B8)" },
];

/** Gateway rows that require a credential (browser, owner-cli or bridge): each gets one unauthenticated probe. */
export function authProbeRows(routes: readonly RouteOp[] = ROUTES): RouteOp[] {
  return routes.filter((r) => r.exposure === "gateway" && r.auth.some((a) => a === "browser" || a === "owner-cli" || a === "bridge"));
}

/** Live checks against a running gateway (`tb-conformance core --url`). */
export const CORE_LIVE_CHECKS: readonly PendingCheck[] = [
  { id: "R1.unknown_path", title: "unknown paths under /api/v1 → 404 with the one error envelope and no data" },
  { id: "R1.unknown_method", title: "unknown method on a known path → 404/405 with the error envelope" },
  { id: "R1.traversal", title: "dot-segment / encoded paths never reach an internal document" },
  { id: "R1.internal_unreachable", title: "/internal/* not reachable through the gateway" },
  ...authProbeRows().map((r) => ({ id: `R1.auth.${r.opId}`, title: `${r.method} ${r.path} without a valid credential → 401/403 envelope, no data` })),
  { id: "R1.public_rows", title: "explicit public rows answer without a credential and never carry a secret" },
  { id: "R1.status_mapping", title: "every error envelope carries an ErrorCode with the status PORTAL-API §1.4 maps it to" },
  { id: "R1.no_internals", title: "no response header or error body carries a stack trace, framework banner or internal host" },
  { id: "R1.cors", title: "no CORS wildcard or reflected foreign origin with credentials" },
  { id: "R7.unknown_device_code", title: "device.token with an unknown device code → 400 envelope, RFC 8628 code, no token" },
  { id: "R7.malformed_poll", title: "device.token with a wrong grant_type → 400 envelope" },
  { id: "R7.start_shape", title: "device.start: device code, user code, 600 s lifetime, 5 s interval" },
  { id: "R7.poll_pending", title: "polling a pending request → authorization_pending, then slow_down when polled too fast" },
  { id: "cred.p1.kit_cannot_get_owner", title: "device.start scope=owner with client_id=kit → refused" },
  { id: "R8.owner_no_key", title: "device.start scope=owner with a public key → refused" },
  { id: "R8.agent_batch_limit", title: "device.start scope=agent with 65 keys → refused" },
  { id: "C6.enrol_unknown_code", title: "bridge enrolment with an unknown code → 401 enrolment_code_invalid" },
  { id: "R11.webhook_bad_signature", title: "Stripe webhook with an invalid signature → refused (stripe_signature_invalid)" },
  { id: "R11.webhook_no_signature", title: "Stripe webhook without a signature → refused" },
  { id: "R11.clerk_webhook_bad_signature", title: "Clerk webhook with a bad svix signature → 401 clerk_signature_invalid (C49)" },
  { id: "R1.route_doc", title: "route table served at /internal/routes equals types/routes.ts" },
  { id: "R1.core_private", title: "Core has no public domain (deploy check)" },
  { id: "R2.live_owner_cli_refused", title: "owner-cli session: any non-draft mutation refused; drafts.apply needs a browser session" },
  { id: "R3", title: "licence gate: unlicensed app → no grants, no edges in config, no launch ticket" },
  { id: "R6", title: "signing keys and Railway token sealed (DB inspection)" },
  { id: "cred.dev.approve_requires_user_code", title: "lookup / approve need the user code; 6th wrong try locked" },
  { id: "cred.dev.one_time", title: "device codes one-time, digest-stored" },
  { id: "cred.dev.expiry", title: "device codes expire after 600 s" },
  { id: "R9.idle_24h", title: "K3 idle > 24 h → refused" },
  { id: "R10.live_replay", title: "replay of a bodyLog: none request → 409 idempotency_conflict, nothing stored" },
  { id: "R11.flow", title: "onboarding order: bridge enrolled, agent authorised before any app; licence-last; webhook → grants" },
  { id: "R12", title: "pairing approval: principal check, redirect host, unverified client name" },
  { id: "C7", title: "no issued token exceeds its kind's lifetime" },
  { id: "P2", title: "owner CLI session revoked → next CLI call refused; agents keep working" },
];

export const CORE_CHECKS: readonly PendingCheck[] = [...CORE_STATIC_CHECKS, ...CORE_LIVE_CHECKS];
