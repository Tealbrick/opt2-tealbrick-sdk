// Accepts only instance assertions signed by this service's OWN app instance key (C6, SDK-API §11): the key from
// `ClaimResponse.app.publicKey`, `iss = sub = tb:ins:<ins>`, no `svc` (a sibling service cannot call), `aud` =
// `tb:brg:<bridge>` (the audience every instance assertion carries, CREDENTIALS §10), htm/htu/bd bound, one-time `jti`.
import type { IncomingMessage } from "node:http";
import { keySetFrom, memoryReplayGuard, type ReplayGuard, verifyAssertion, verifyV0 } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import { type InstanceAssertionClaims, LEEWAY_S, LIFETIME_S, type Sha256Digest, TYP } from "@opt2-tealbrick/spec/credentials";
import { TbError } from "../server/errors.ts";
import { header } from "../server/http.ts";
import type { ClaimRecord } from "./identity.ts";

export type AppAssertionVerifier = (req: IncomingMessage, body: Uint8Array) => void;

/**
 * C373a, streamed bodies (restore): every check of {@link AppAssertionVerifier} BEFORE the body is read — V0 (key, typ,
 * iss = sub, aud, lifetime), `htm`/`htu`, no `svc`, one-time `jti` — and returns the asserted body digest `bd` (null = the
 * assertion binds no body, so the body must be empty). The caller MUST compare `bd` with the sha256 of the received bytes
 * before it acts on them (CREDENTIALS §10 step 9, split in time; the same claims and order as `verifyAssertion`).
 */
export type AppAssertionHeadVerifier = (req: IncomingMessage) => Sha256Digest | null;

export interface AppAssertionVerifiers {
  body: AppAssertionVerifier;
  head: AppAssertionHeadVerifier;
}

const invalid = () => new TbError("unauthenticated", "instance assertion invalid", 401);

function token(req: IncomingMessage): string {
  const t = header(req, BRIDGE_HEADERS.assertion);
  if (!t) throw new TbError("unauthenticated", "instance assertion required", 401);
  return t;
}

/** Both verifiers share ONE replay set: a `jti` accepted by one is refused by the other. */
export function appAssertionVerifiers(rec: ClaimRecord, replay: ReplayGuard = memoryReplayGuard(), now: () => number = () => Math.floor(Date.now() / 1000)): AppAssertionVerifiers {
  const ref = `tb:ins:${rec.ins}` as const;
  const keys = keySetFrom({ keys: [rec.app.publicKey] }, ref);
  const aud = `tb:brg:${rec.bridge.id}`;
  return {
    body: (req, body) => {
      const r = verifyAssertion(token(req), keys, { typ: TYP.instanceAssertion, aud, now: now(), method: req.method ?? "", pathAndQuery: req.url ?? "", body, replay });
      if (!r.ok || r.claims.svc !== undefined) throw invalid();
    },
    head: (req) => {
      const at = now();
      const r = verifyV0<InstanceAssertionClaims>(token(req), keys, { typ: TYP.instanceAssertion, aud, iss: [ref], now: at, maxLifetimeS: LIFETIME_S.proof });
      if (!r.ok) throw invalid();
      const c = r.claims;
      if (c.htm !== (req.method ?? "").toUpperCase() || c.htu !== (req.url ?? "") || c.svc !== undefined) throw invalid();
      if (!replay(c.jti, c.exp + LEEWAY_S, at)) throw invalid();
      return c.bd ?? null;
    },
  };
}

/** Throws TbError 401 `unauthenticated` unless the request carries a valid assertion from the own app instance. */
export function appAssertionVerifier(rec: ClaimRecord, replay: ReplayGuard = memoryReplayGuard(), now: () => number = () => Math.floor(Date.now() / 1000)): AppAssertionVerifier {
  return appAssertionVerifiers(rec, replay, now).body;
}
