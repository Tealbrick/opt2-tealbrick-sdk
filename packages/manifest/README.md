# @opt2-tealbrick/manifest

The one owner of opt2 contract primitives (SDK-API §2, CORE §3): manifest validator (schema + every MANIFEST cross-field rule), `validateInput`, `withStandardOps`, MCP tool names, `renderSkill`, RFC 8785 JCS + sha256 digests, Ed25519 keys and JWS (`signJws`, `signJwsWithSigner`, `verifyJws`), key sets and the announcement trust rule, assertions, AES-256-GCM sealing, opaque values, ULIDs, every token verifier and issuer-side signer (grant, call/hook/bridge-op proofs, tickets, config, slice, pairing code, agent session, release index), and the decision functions `gate()` (bridge) and `authorize()` (app).

Runtime deps: `@opt2-tealbrick/spec`, `ajv`. Node 24+. Copying any of these primitives elsewhere is a CI failure.

0.1.23 (spec 0.1.46, GRANT-PRD): the grant claim set accepts an optional `prd` (a product id, `^[a-z][a-z0-9-]{1,31}$`) for companion grants; `signGrant` and `verifyGrant` shape-check it. A verifier older than 0.1.23 refuses a grant that carries `prd` (closed claim set), so deploy readers before Core mints it.
