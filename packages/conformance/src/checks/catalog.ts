// Check catalogue: every id the suite reports, per target (CONFORMANCE §4). Ids are stable. App and manifest ids are
// implemented in checks/app.ts and checks/manifest.ts, bridge and relay ids in checks/bridge*.ts and checks/relay.ts
// (listed in checks/bridge-ids.ts), core ids in checks/core*.ts. A test asserts that every id a run
// reports is in this catalogue, and A11 asserts that every SDK export maps to catalogued ids.

import { BRIDGE_CHECKS, RELAY_CHECKS } from "./bridge-ids.ts";
import { CORE_CHECKS } from "./core-ids.ts";

export const MANIFEST_CHECK_IDS = [
  "M1",
  "M1.strict_unknown_key",
  "M1.reserved_prefix",
  "M2.create_idempotency",
  "M2.create_idempotency.enforced",
  "M2.scope_types",
  "M2.scope_types.enforced",
  "M2.money_held",
  "M2.hold_family_known",
  "M2.hold_family_known.enforced",
  "M2.outward_family",
  "M2.tool_names",
  "M2.key_names_unique",
  "M2.hook_ops",
  "M2.companion_wildcard",
  "M2.companion_wildcard.enforced",
  "M2.when_settings",
  "M3",
  "M4.no_copies",
  "M5",
  "M6.paths",
] as const;

export const APP_CHECK_IDS = [
  "A1",
  "A1.no_claim_route",
  "A1.manifest_served",
  "A1.health",
  "A1.key_persisted",
  "A1.reclaim_on_new_code",
  "M4.openapi",
  "A6",
  "A6.principal",
  "A6.csrf",
  "A6.session_required",
  "A6.person_nbf",
  "A6.logout",
  "C6.ticket_replay",
  "C2.ticket_aud_foreign",
  "C2.ticket_ws_foreign",
  "C5.ticket_expired",
  "C5.ticket_unannounced_kid",
  "C3.grant_as_ticket",
  "A8",
  "A8.applied_once",
  "A8.scope_summary",
  "A2",
  "A2.no_proof",
  "B8.tampered_input",
  "A2.tampered_context",
  "A2.proof_op",
  "A2.proof_gjti",
  "A2.proof_sub",
  "A2.no_grant",
  "A2.grant_ws",
  "A2.grant_cnf",
  "A2.grant_revoked",
  "A2.hook_valid",
  "A2.hook_no_proof",
  "A2.hook_wrong_phase",
  "A2.hook_op_proof",
  "A2.hook_tampered_context",
  "A2.hook_tampered_input",
  "A2.hook_unknown",
  "C5.hook_proof_unannounced_kid",
  "C6.hook_proof_replay",
  "C2.proof_aud_foreign",
  "C2.proof_aud_missing",
  "C2.grant_aud_foreign",
  "C2.grant_aud_missing",
  "C2.grant_aud_array",
  "C3.ticket_as_grant",
  "C3.session_as_grant",
  "C3.grant_as_proof",
  "C3.hook_proof_at_op",
  "C3.grant_held_unknown",
  "C4.owner_cli_session_at_op",
  "C4.session_cookie_at_op",
  "cred.p1.app_op_rejects_person",
  "cred.p1.payload_scan_no_person_cred",
  "C5.proof_unannounced_kid",
  "C5.proof_expired",
  "C5.grant_unannounced_kid",
  "C5.grant_expired",
  "C5.grant_not_yet_valid",
  "C5.grant_wrong_issuer",
  "C5.portal_key_rotation",
  "C5.bridge_key_rotation",
  "C6.call_proof_replay",
  "C7.assertion_lifetime",
  "C8.no_shared_secret",
  "C8.env",
  "C8.keys_via_bridge",
  "B13.bridge_op_proof_at_op",
  "B13.op_proof_at_bridge_route",
  "B13.hook_proof_at_bridge_route",
  "B13.no_proof_at_bridge_route",
  "B13.bop_mismatch",
  "A3.audience",
  "A3.crud_ceiling",
  "A3.run",
  "A3.hold",
  "A3.held_family",
  "A3.money",
  "A3.caps",
  "A3.free_wf_caps",
  "A3.caps_count",
  "A3.no_standing_approval",
  "A4.hold_status",
  "A4.decide_person_only",
  "A4.holds_list",
  "A4.receipt_digest",
  "A4.mark_after_failed",
  "A5",
  "A5.required",
  "A12.companion_inbound",
  "A12.companion_call",
  "A12.companion_refresh_retry",
  "A12.caller_name",
  "A12.caller_product_verified",
  "A12.grant_prd_first",
  "A12.grant_prd_mismatch",
  "A12.grant_prd_absent",
  "A12.app_caller_held",
  "A12.scope_request",
  "A11.resolve_family",
  "A11.narrowing_empty_anyof",
  "A13.kss_pinned",
  "A13.portal_keys_ignored",
  "A13.kss_unknown_root",
  "A13.kss_rollback",
  "A13.kss_missing",
  "A13.kss_rotation",
  "A13.kss_compromise",
  "A13.kss_first_missing",
  "A14.hook_hold",
  "A14.hold_retry_once",
  "A14.scope_wins",
  "A15.holds_pending",
  "A16.call_outside_handler",
  "A17.pending_count",
  "A17.status_changed",
  "A18.scope_grant_within",
  "A18.scope_grant_ceiling",
  "A18.scope_grant_agent_absent",
  "A10",
  "P1.held_release_paused",
  "P1.workspace",
  "P1.agent",
  "P1.instance",
  "A7.export",
  "A7.restart",
  "A7.backup_roundtrip",
  "A9",
  "A11",
] as const;

/**
 * CONF-MULTIAPP (conformance 0.1.20): group X, real peer apps behind the fake bridge (`--peers`). A run reports ONE ROW
 * per peer (X1) or per declared companion op of a peer (X2..X5), so the row ids carry the peer product and the op:
 * `X1.peer_boot.<peer>`, `X2.companion_call.<peer>.<op>`, `X3.companion_refused.<peer>.<op>`,
 * `X4.contract_schema.<peer>.<op>`, `X5.hold_round_trip.<peer>.<op>`. They are not in CHECK_IDS (no peers, no X rows);
 * `isCheckId` accepts them (waivers name them, the id tests use it).
 */
export const PEER_CHECK_BASES = {
  "X1.peer_boot": "each peer boots under the conformance env and claims through its own fake bridge",
  "X2.companion_call": "a real callApp of the app under test through the fake bridge reaches the real peer; the peer's receipt names the verified caller",
  "X3.companion_refused": "the real peer refuses a crud beyond the grant, a grant for another instance, a tampered proof and no proof",
  "X4.contract_schema": "the peer's real output validates against the pinned contract schema",
  "X5.hold_round_trip": "a held companion op: hold listed in the peer, approved, the retried call runs once",
} as const;

const PEER_ROW = /^(X[1-5]\.[a-z_]+)\.([a-z][a-z0-9-]{1,31})(?:\.([a-z][a-z0-9_]{1,39}))?$/;
/** True for a catalogued id, or a group X row id (`<base>.<peer>[.<op>]`; X1 has no op). */
export function isCheckId(id: string): boolean {
  if (CHECK_IDS.has(id)) return true;
  const m = PEER_ROW.exec(id);
  if (!m) return false;
  const base = m[1] as string;
  if (!(base in PEER_CHECK_BASES)) return false;
  return base === "X1.peer_boot" ? m[3] === undefined : m[3] !== undefined;
}

export interface PendingCheck {
  id: string;
  title: string;
}

/** Bridge and relay targets (CONFORMANCE §4.4 + bridge / relay cells of §4.2, §4.3, §5): ids live beside the checks (checks/bridge-ids.ts). */
/** Portal Core target (CONFORMANCE §4.6 + Core cells of §4.2/§4.3): ids live beside the checks (checks/core-ids.ts). */
export { BRIDGE_CHECKS, CORE_CHECKS, RELAY_CHECKS };

export const CHECK_IDS: ReadonlySet<string> = new Set<string>([
  ...MANIFEST_CHECK_IDS,
  ...APP_CHECK_IDS,
  ...BRIDGE_CHECKS.map((c) => c.id),
  ...RELAY_CHECKS.map((c) => c.id),
  ...CORE_CHECKS.map((c) => c.id),
]);
