// Token mint for the fakes: grants, call / hook / bridge-op proofs, tickets, agent sessions, slices — all signed with
// the @opt2-tealbrick/manifest signers (no hand-rolled claims). `rawSign` exists only to forge MALFORMED tokens for
// negative cases (array `aud`, missing `aud`, foreign `typ`); it never verifies anything.
import { webcrypto } from "node:crypto";
import {
  digest,
  type Ed25519KeyPair,
  generateKeyPair,
  signAgentSession,
  signBridgeOpProof,
  signCallProof,
  signGrant,
  signHookProof,
  signTicket,
  ulid,
} from "@opt2-tealbrick/manifest";
import type {
  AgentId,
  BridgeId,
  BridgeOp,
  CallId,
  ConnectionId,
  FreeCaps,
  GrantClaims,
  HoldVerdictClaim,
  InstanceId,
  PersonId,
  Sha256Digest,
  WorkspaceId,
} from "@opt2-tealbrick/spec/credentials";
import type { AgentMode, CrudAction, HoldFamily, HookPhase } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

export const nowS = (): number => Math.floor(Date.now() / 1000);
export const newId = <P extends string>(prefix: P): `${P}_${string}` => `${prefix}_${ulid()}`;

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

/** Signs an arbitrary header + payload, bypassing the closed claim checks — ONLY for forged negative-case tokens. */
export async function rawSign(header: unknown, payload: unknown, key: Ed25519KeyPair): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = await webcrypto.subtle.sign({ name: "Ed25519" }, key.privateKey as webcrypto.CryptoKey, Buffer.from(input, "ascii"));
  return `${input}.${Buffer.from(sig).toString("base64url")}`;
}

/** Unverified payload read (binding values and test assertions only; never a trust decision). */
export function peek(token: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8"));
    return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export interface MintWorld {
  ws: WorkspaceId;
  bridge: BridgeId;
  /** current Portal signing key (the active one) */
  portalKey(): Ed25519KeyPair;
  /** current bridge key (call proofs) */
  bridgeKey(): Ed25519KeyPair;
  /** a key nobody trusts (unannounced `kid`) */
  stranger: Ed25519KeyPair;
}

export interface GrantSpec {
  sub: `tb:agt:${AgentId}` | `tb:ins:${InstanceId}`;
  aud: `tb:ins:${InstanceId}`;
  crud: CrudAction[];
  mode: AgentMode;
  /** v0.1.17 (C108): may name families this build does not know (a newer Core); signGrant checks the shape only */
  held?: readonly (HoldFamily | (string & {}))[];
  caps?: FreeCaps;
  wf?: string[];
  iat?: number;
  exp?: number;
  ws?: WorkspaceId;
  brg?: BridgeId;
  key?: Ed25519KeyPair;
  iss?: GrantClaims["iss"];
  /** spec 0.1.46 (GRANT-PRD): a companion grant's `prd` = the product of the calling instance (`sub`); never for an agent grant */
  prd?: string;
}

export class Mint {
  readonly #w: MintWorld;
  constructor(world: MintWorld) {
    this.#w = world;
  }

  static async stranger(): Promise<Ed25519KeyPair> {
    return generateKeyPair();
  }

  grant(s: GrantSpec): Promise<string> {
    const iat = s.iat ?? nowS() - 5;
    return signGrant(
      {
        iss: s.iss ?? "tb:portal",
        sub: s.sub,
        aud: s.aud,
        ws: s.ws ?? this.#w.ws,
        cnf: { brg: s.brg ?? this.#w.bridge },
        crud: [...new Set(s.crud)],
        mode: s.mode,
        held: [...new Set(s.held ?? [])] as HoldFamily[],
        caps: s.caps ?? {},
        wf: s.wf ?? [],
        polrev: 1,
        iat,
        ...(s.prd !== undefined ? { prd: s.prd } : {}),
        ...(s.exp !== undefined ? { exp: s.exp } : {}),
      },
      s.key ?? this.#w.portalKey(),
    );
  }

  callProof(p: {
    sub: string;
    aud: `tb:ins:${InstanceId}`;
    gjti: string;
    op: string;
    input: Json;
    context: Json;
    call?: CallId;
    iat?: number;
    exp?: number;
    key?: Ed25519KeyPair;
    /** v0.1.13 (G1): attested before-hook hold verdict `{f, r, by}` */
    hv?: HoldVerdictClaim;
  }): Promise<string> {
    return signCallProof(
      {
        iss: `tb:brg:${this.#w.bridge}`,
        sub: p.sub as `tb:agt:${AgentId}`,
        aud: p.aud,
        call: p.call ?? newId("call"),
        gjti: p.gjti,
        op: p.op,
        in: digest(p.input),
        ctx: digest(p.context),
        iat: p.iat ?? nowS(),
        ...(p.exp !== undefined ? { exp: p.exp } : {}),
        ...(p.hv !== undefined ? { hv: p.hv } : {}),
      },
      p.key ?? this.#w.bridgeKey(),
    );
  }

  hookProof(p: { sub: string; aud: `tb:ins:${InstanceId}`; hook: string; phase: HookPhase; context: Json; input?: Json; call?: CallId; key?: Ed25519KeyPair }): Promise<string> {
    return signHookProof(
      {
        iss: `tb:brg:${this.#w.bridge}`,
        sub: p.sub as `tb:agt:${AgentId}`,
        aud: p.aud,
        call: p.call ?? newId("call"),
        hook: p.hook,
        phase: p.phase,
        ctx: digest(p.context),
        ...(p.input !== undefined ? { in: digest(p.input) } : {}),
        iat: nowS(),
      },
      p.key ?? this.#w.bridgeKey(),
    );
  }

  /** `body`: binds `in` = digest(body); `in`: a precomputed digest (bridgeOpProofClaims) */
  bridgeOpProof(p: { aud: `tb:ins:${InstanceId}`; bop: BridgeOp; op?: string; body?: Json; in?: Sha256Digest; key?: Ed25519KeyPair }): Promise<string> {
    const brg = `tb:brg:${this.#w.bridge}` as const;
    return signBridgeOpProof(
      {
        iss: brg,
        sub: brg,
        aud: p.aud,
        call: newId("call"),
        bop: p.bop,
        ...(p.op !== undefined ? { op: p.op } : {}),
        ...(p.body !== undefined ? { in: digest(p.body) } : p.in !== undefined ? { in: p.in } : {}),
        iat: nowS(),
      },
      p.key ?? this.#w.bridgeKey(),
    );
  }

  launchTicket(p: { person: PersonId; aud: `tb:ins:${InstanceId}`; path?: string; iat?: number; exp?: number; key?: Ed25519KeyPair; ws?: WorkspaceId }): Promise<string> {
    return signTicket(
      {
        iss: "tb:portal",
        sub: `tb:per:${p.person}`,
        aud: p.aud,
        ws: p.ws ?? this.#w.ws,
        pur: "launch",
        ...(p.path !== undefined ? { path: p.path } : {}),
        iat: p.iat ?? nowS(),
        ...(p.exp !== undefined ? { exp: p.exp } : {}),
      },
      p.key ?? this.#w.portalKey(),
    );
  }

  /** K5 access token (bridge key) — used only to present the wrong kind at app routes (C3). */
  agentSession(agent: AgentId): Promise<string> {
    const brg = `tb:brg:${this.#w.bridge}` as const;
    return signAgentSession({ iss: brg, sub: `tb:agt:${agent}`, aud: brg, ws: this.#w.ws, con: newId("con") as ConnectionId, gen: 1, iat: nowS() }, this.#w.bridgeKey());
  }

  /** An RS256-shaped, Clerk-like person JWT (never valid anywhere but Core; used for C4 negative cases). */
  static clerkLikeJwt(): string {
    const h = b64({ alg: "RS256", typ: "JWT", kid: "ins_clerk_test" });
    const p = b64({ iss: "https://clerk.example.test", sub: "user_conformance", azp: "https://portal.example.test", iat: nowS(), exp: nowS() + 60, sid: "sess_conformance" });
    return `${h}.${p}.${Buffer.from("not-a-signature-but-shaped-like-one").toString("base64url")}`;
  }

  /** An opaque owner-CLI-session-shaped value (`tbo_` + 43 chars). */
  static ownerCliLike(): string {
    return `tbo_${Buffer.from(webcrypto.getRandomValues(new Uint8Array(32))).toString("base64url")}`;
  }
}
