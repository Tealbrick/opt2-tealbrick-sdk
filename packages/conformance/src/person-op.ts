// Person-op relay helpers (conformance 0.1.31, spec 0.1.64, C326): the K14 the fake Portal mints (CREDENTIALS K14, PersonOpClaims)
// and the names the bridge rows (BRIDGE §16, R-PO-1..6) and the app rows (SDK-API §21, S-PO-1..12) share. The K14 is signed with
// a Portal key of the fake (the fake Portal in the bridge target, the fake bridge's Portal key in the app target). The manifest
// package has no K14 signer yet (it pins a spec before 0.1.64), so the token is built with `rawSign` over the CLOSED claim set.
import { type Ed25519KeyPair, sha256Bytes, ulid } from "@opt2-tealbrick/manifest";
import { APP_CAPS_LIMITS, type AppCap, PERSON_OP_BRIDGE_REFUSALS } from "@opt2-tealbrick/spec/bridge";
import { type InstanceId, LIFETIME_S, type PersonId, type PersonOpClaims, type Sha256Digest, TYP, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { PersonOpId } from "@opt2-tealbrick/spec/routes";
import { newId, nowS, rawSign } from "./tokens.ts";

/** BRIDGE_CAPS entry of a bridge that runs the relay (spec 0.1.64). */
export const PERSON_OPS_CAP = "person_ops";
/** The app's private route (SDK-API §21). */
export const PERSON_OP_ROUTE = "/tb/v1/person-op";
/** SPEC-GAP (spec 0.1.70): the spec names the header in SDK-API §21 / BRIDGE §16 only (no constant in BRIDGE_HEADERS). */
export const PERSON_OP_HEADER = "TB-Person-Op";
/** spec 0.1.70 (C354): the app capability for `POST /tb/v1/person-op` (APP_CAPS), declared in ClaimRequest.caps and every
 *  AppStatus.caps. Gates read it, never a version number. */
export const PERSON_OP_APP_CAP: AppCap = "person_op";
export { APP_CAPS_LIMITS, PERSON_OP_BRIDGE_REFUSALS };

/** The caps an app declares (spec 0.1.70; unknown entries pass through, readers ignore them): a value that is not an array of strings within APP_CAPS_LIMITS = none (fail closed). */
export function declaredAppCaps(v: unknown): string[] {
  if (!Array.isArray(v) || v.length > APP_CAPS_LIMITS.maxEntries) return [];
  if (!v.every((x) => typeof x === "string" && x.length <= APP_CAPS_LIMITS.maxLength)) return [];
  return v as string[];
}
/** Core → bridge pull and bridge → Core result paths (routes.ts bridge_api.person_ops / bridge_api.person_op_result). */
export const PERSON_OPS_PATH = "/api/v1/bridge/person-ops";
export const PERSON_OP_RESULT_PATH_RE = /^\/api\/v1\/bridge\/person-ops\/(pop_[0-9A-Za-z]{1,64})\/result$/;

/** K14 `bd`: "sha256:" + lowercase hex of SHA-256 over the UTF-8 bytes of the exact body string (NOT the JCS digest). */
export function bodyDigest(body: string | Uint8Array): Sha256Digest {
  return sha256Bytes(typeof body === "string" ? new TextEncoder().encode(body) : body) as Sha256Digest;
}

export interface PersonOpMint {
  key: Ed25519KeyPair;
  ws: WorkspaceId;
  ins: InstanceId;
  person: PersonId;
  op: string;
  /** the exact body string; `bd` is its digest unless `bd` is given */
  body: string;
  pop?: PersonOpId;
  idk?: string;
  /** default "tbm" (PERSON_OP_RELAY.clients); negative cases set "tbd" / "cli" */
  cli?: string;
  iat?: number;
  /** default iat + LIFETIME_S.personOp */
  exp?: number;
  jti?: string;
  bd?: string;
  /** overrides of the closed claim set (negative cases only: foreign aud / ws) */
  aud?: string;
  wsClaim?: string;
}

/** A new idempotency key in the PersonOpCallInput shape (16..64 chars [A-Za-z0-9_-]). */
export const newIdk = (): string => `tbconf_${ulid()}`;

/** Signs one K14 (typ tb-person-op+jwt) over the closed PersonOpClaims set; returns the token and its claims. */
export async function mintPersonOp(p: PersonOpMint): Promise<{ jws: string; claims: PersonOpClaims }> {
  const iat = p.iat ?? nowS();
  const claims = {
    iss: "tb:portal",
    sub: `tb:per:${p.person}`,
    aud: p.aud ?? `tb:ins:${p.ins}`,
    iat,
    exp: p.exp ?? iat + LIFETIME_S.personOp,
    jti: p.jti ?? ulid(),
    ws: p.wsClaim ?? p.ws,
    op: p.op,
    bd: p.bd ?? bodyDigest(p.body),
    idk: p.idk ?? newIdk(),
    cli: p.cli ?? "tbm",
    pop: p.pop ?? newId("pop"),
  } as unknown as PersonOpClaims;
  const jws = await rawSign({ alg: "EdDSA", typ: TYP.personOp, kid: p.key.kid }, claims, p.key);
  return { jws, claims };
}
