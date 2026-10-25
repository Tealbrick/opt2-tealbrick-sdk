// CONFORMANCE A11 coverage map: every runtime export of types/sdk.ts (src/generated/sdk-exports.ts) → the check ids
// that exercise it. Manifest primitives are exercised through the app behaviour that depends on them (the app's
// verifiers must refuse what the checks forge) and through the manifest checks; client hooks through the person API
// routes they wrap. Ids pointing at bridge/core checks are listed in the catalogue and run as `not_implemented` there.

export const SDK_COVERAGE: Readonly<Record<string, readonly string[]>> = {
  // @opt2-tealbrick/manifest
  authorize: ["A3.run", "A3.crud_ceiling", "A3.hold", "A3.held_family", "A3.money", "A3.caps", "A3.caps_count", "A3.no_standing_approval", "A14.hook_hold", "A14.hold_retry_once", "A14.scope_wins", "P1.workspace", "P1.agent", "P1.instance"],
  canonicalize: ["M3", "B8.tampered_input", "A4.receipt_digest"],
  digest: ["M3", "A4.receipt_digest", "A2.tampered_context"],
  gate: ["B5.paused_first", "B5.bound_outside_wf", "B5.grant_revoked"],
  generateKeyPair: ["A1", "A1.key_persisted"],
  keySetFrom: ["C5.grant_unannounced_kid", "C5.proof_unannounced_kid", "C5.bridge_key_rotation"],
  manifestDigest: ["M3", "A1", "A1.manifest_served", "A1.health"],
  RECEIPT_STATUSES: ["A4.holds_list", "A10", "A4.mark_after_failed"],
  // spec 0.1.70 (follow-up of specs#49): the TbError codes of the model-role helpers; same family as modelRole (sdk#52 adds its rows)
  SDK_MODEL_ERROR_CODES: ["C8.keys_via_bridge"],
  renderSkill: ["B17.served_as_rendered", "B7.skills_resources"],
  isPrivateInternalUrl: ["B21.internal_url_external", "B21.own_infra_flag_required", "B21.own_infra_allowed", "B21.neighbour_url_refused"],
  portalRootKeys: ["A13.kss_pinned", "B20.kss_enrolled"],
  signKeySetStatement: ["A13.kss_pinned", "A13.kss_rotation", "B20.kss_enrolled"],
  trustedPortalKeys: ["A13.kss_missing", "A13.kss_rollback", "B20.kss_missing", "B20.kss_reenrol_missing", "A13.portal_keys_ignored"],
  verifyKeySetStatement: ["A13.kss_unknown_root", "A13.kss_compromise", "B20.kss_unknown_root", "B20.kss_compromise"],
  SDK_AUDIT_ACTIONS: ["A7.export"],
  signInstanceAssertion: ["A1", "C7.assertion_lifetime", "C8.no_shared_secret", "A12.companion_call"],
  signJws: ["A1", "C7.assertion_lifetime"],
  signJwsWithSigner: ["C1"],
  thumbprint: ["A1.key_persisted", "C5.proof_unannounced_kid"], // gitleaks:allow (check ids, not secrets)
  validateAppFiles: ["M4.no_copies", "M2.when_settings", "M6.paths"],
  validateCompanions: ["M2.hook_ops"],
  validateManifest: ["M1", "M1.strict_unknown_key", "M1.reserved_prefix", "M2.create_idempotency.enforced", "M2.scope_types.enforced"],
  verifyBridgeOpProof: ["A8.scope_summary", "B13.op_proof_at_bridge_route", "B13.hook_proof_at_bridge_route", "B13.no_proof_at_bridge_route", "B13.bop_mismatch", "A4.mark_after_failed"],
  verifyCallProof: ["A2", "A2.no_proof", "B8.tampered_input", "A2.tampered_context", "A2.proof_op", "A2.proof_gjti", "A2.proof_sub", "C5.proof_expired", "C2.proof_aud_foreign", "C6.call_proof_replay"],
  verifyConfig: ["B3.applied", "B3.bad_signature"],
  verifyGrant: ["A2.grant_ws", "A2.grant_cnf", "A2.grant_revoked", "C2.grant_aud_foreign", "C2.grant_aud_missing", "C2.grant_aud_array", "C5.grant_expired", "C5.grant_not_yet_valid", "C5.grant_wrong_issuer", "C3.ticket_as_grant"],
  verifyHookProof: ["A2.hook_valid", "A2.hook_no_proof", "A2.hook_wrong_phase", "A2.hook_op_proof", "A2.hook_tampered_context", "A2.hook_tampered_input", "C5.hook_proof_unannounced_kid", "C6.hook_proof_replay", "C3.hook_proof_at_op"],
  verifyJws: ["C3.grant_as_proof", "C3.session_as_grant"],
  verifySlice: ["P1.workspace", "C5.portal_key_rotation", "A6.person_nbf"], // gitleaks:allow (check ids, not secrets)
  verifyTicket: ["A6", "C2.ticket_aud_foreign", "C2.ticket_ws_foreign", "C5.ticket_expired", "C5.ticket_unannounced_kid", "C3.grant_as_ticket"],
  withStandardOps: ["A3.audience", "A4.hold_status", "M4.openapi"],
  // @opt2-tealbrick/miniapp-sdk (server)
  CSRF_HEADER: ["A6.csrf"],
  decideHold: ["A4.decide_person_only", "A10"],
  // conformance 0.1.31 (spec 0.1.64, SDK-API §21, C332a(4)): the family rule of relayed hold decisions (S-PO-8; not observable in the
  // generic suite, covered by the miniapp-sdk tests)
  familyAllowedFor: ["S-PO-8"],
  defineApp: ["A1.manifest_served", "M4.openapi", "A1.no_claim_route", "A17.pending_count"], // gitleaks:allow (check ids, not secrets)
  getKey: ["C8.keys_via_bridge"],
  // v0.1.63: `modelRole` (the bridge route and its declared-role rule are exercised by the same check as keys; the model-roles
  // release, sdk#52, adds its own rows)
  modelRole: ["C8.keys_via_bridge"],
  onKeysChanged: ["C8.keys_via_bridge"],
  SESSION_COOKIE: ["A6"],
  startApp: ["A1", "A1.health", "A7.restart", "A16.call_outside_handler", "A17.status_changed"],
  TB_EXEC_CONTROL_PORT: ["B11.set_and_fetch"],
  TbError: ["A5", "A5.required", "A6.session_required"],
  // @opt2-tealbrick/miniapp-sdk/client (thin wrappers over the person API routes)
  callOp: ["A6.csrf", "A4.holds_list"],
  tbFetch: ["A6.csrf", "A6.session_required"],
  TbProvider: ["A6", "A6.principal"],
  useAgents: ["A8"],
  useHolds: ["A4.holds_list", "A10"],
  useScopes: ["A8.applied_once"],
  useSession: ["A6.principal", "A6.logout"],
};
