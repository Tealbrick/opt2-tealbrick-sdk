// Test harness: Portal + bridge key pairs, a fake bridge internal API (claim, status long-poll), and token helpers
// built ONLY from the manifest package's signers (no hand-rolled JWS).
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digest, type Ed25519KeyPair, generateKeyPair, signCallProof, signGrant, signKeySetStatement, signSlice, signTicket, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, BridgeId, Ed25519PublicJwk, FreeCaps, InstanceId, PersonId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, HoldFamily, HookHoldFamily } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

export const nowS = () => Math.floor(Date.now() / 1000);

export async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createNetServer();
    s.once("error", reject);
    s.listen(0, () => {
      const a = s.address();
      const port = typeof a === "object" && a ? a.port : 0;
      s.close(() => resolve(port));
    });
  });
}

export function tempDir(prefix = "tb-sdk-test-"): { dir: string; cleanup(): void } {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

export function migrationsDir(root: string, files: Record<string, string> = { "0001_init.sql": "CREATE TABLE notes (id TEXT PRIMARY KEY, notebook TEXT NOT NULL, title TEXT NOT NULL);" }): string {
  const dir = join(root, "migrations");
  mkdirSync(dir, { recursive: true });
  for (const [f, body] of Object.entries(files)) writeFileSync(join(dir, f), body);
  return dir;
}

export interface World {
  /** TEST Portal Root Key pair (spec 0.1.12: the SDK refuses a first slice without a root-signed key-set statement) */
  root: Ed25519KeyPair;
  /** key-set statement (seq 1) signed by `root`, listing `portal` as the active key; carried by every helper slice */
  portalKeySet: string;
  portal: Ed25519KeyPair;
  bridgeKey: Ed25519KeyPair;
  ws: WorkspaceId;
  brg: BridgeId;
  ins: InstanceId;
  per: PersonId;
  agents: { a: AgentId; b: AgentId };
  rev: number;
}

export async function world(): Promise<World> {
  const [root, portal] = await Promise.all([generateKeyPair(), generateKeyPair()]);
  const portalKeySet = await signKeySetStatement({ iss: "tb:portal-root", aud: "tb:portal-keys", seq: 1, iat: nowS(), keys: [{ jwk: portal.publicJwk, status: "active" }] }, root);
  return {
    root,
    portalKeySet,
    portal,
    bridgeKey: await generateKeyPair(),
    ws: `ws_${ulid()}`,
    brg: `brg_${ulid()}`,
    ins: `ins_${ulid()}`,
    per: `per_${ulid()}`,
    agents: { a: `agt_${ulid()}`, b: `agt_${ulid()}` },
    rev: 0,
  };
}

/** startApp harness that pins the world's TEST root instead of the build's Portal Root Keys (StartHooks.portalRootKeys). */
export function testRoots(w: World): { portalRootKeys: Ed25519PublicJwk[] } {
  return { portalRootKeys: [w.root.publicJwk] };
}

/** `portalKeySet: null` omits the statement (negative tests: a strict SDK refuses it with `keyset_missing`). */
export async function slice(
  w: World,
  product: string,
  over: Partial<Pick<InstanceSlice, "pause" | "agents" | "grants" | "personNbf" | "portalUrl" | "revoked">> & {
    portalKeySet?: string | null;
    /** spec 0.1.14 addition (not in the 0.1.13 types): companion grant targets */
    companionTargets?: { product: string; ins: string }[];
    /** spec 0.1.48: `provider` (where that instance runs); `unknown` so a test can push an invalid value */
    companionCallers?: { product: string; ins: string; name: string; provider?: unknown }[];
    appsPolicy?: { held: string[] };
    /** spec 0.1.49 (C261): `"verified"` = an app caller without a verified product is refused `caller_unverified`; `unknown` so a test can push another value */
    appCallers?: unknown;
    /** spec 0.1.43 (LA-1): bridge.viewUrl (string = tb-views origin, null = Core has none yet, absent = member omitted) */
    viewUrl?: string | null;
  } = {},
): Promise<string> {
  w.rev += 1;
  const self = `tb:ins:${w.ins}` as const;
  return signSlice(
    {
      iss: "tb:portal",
      sub: self,
      aud: self,
      iat: nowS(),
      ws: w.ws,
      v: 1,
      rev: w.rev,
      ins: w.ins,
      product,
      portalKeys: [{ jwk: w.portal.publicJwk, status: "active" }],
      bridge: { id: w.brg, keys: [w.bridgeKey.publicJwk], ...(over.viewUrl !== undefined ? { viewUrl: over.viewUrl } : {}) },
      pause: over.pause ?? { workspace: false, agents: [], instances: [] },
      revoked: over.revoked ?? { jtis: [] },
      personNbf: over.personNbf ?? 0,
      grants: over.grants ?? [],
      agents: over.agents ?? [
        { id: w.agents.a, name: "Agent A", mode: "free", status: "active" },
        { id: w.agents.b, name: "Agent B", mode: "free", status: "active" },
      ],
      ...(over.portalKeySet === null ? {} : { portalKeySet: over.portalKeySet ?? w.portalKeySet }),
      ...(over.portalUrl ? { portalUrl: over.portalUrl } : {}),
      ...(over.companionTargets ? { companionTargets: over.companionTargets } : {}),
      ...(over.companionCallers ? { companionCallers: over.companionCallers } : {}),
      ...(over.appsPolicy ? { appsPolicy: over.appsPolicy } : {}),
      ...(over.appCallers !== undefined ? { appCallers: over.appCallers } : {}),
    } as Parameters<typeof signSlice>[0],
    w.portal,
  );
}

export async function grant(
  w: World,
  agent: AgentId,
  opts: { crud?: CrudAction[]; held?: HoldFamily[]; aud?: InstanceId; wf?: string[]; mode?: "free" | "bound"; caps?: FreeCaps } = {},
): Promise<string> {
  return signGrant(
    {
      iss: "tb:portal",
      sub: `tb:agt:${agent}`,
      aud: `tb:ins:${opts.aud ?? w.ins}`,
      iat: nowS(),
      ws: w.ws,
      cnf: { brg: w.brg },
      crud: opts.crud ?? ["create", "read", "update", "delete"],
      mode: opts.mode ?? "free",
      held: opts.held ?? [],
      caps: opts.caps ?? {},
      wf: opts.wf ?? [],
      polrev: 1,
    },
    w.portal,
  );
}

/** `over.hv` (v0.1.13 G1): the bridge-attested before-hook hold verdict claim. */
export async function callProof(
  w: World,
  grantToken: string,
  op: string,
  input: Json,
  context: Record<string, Json> = {},
  over: { aud?: InstanceId; inputFor?: Json; hv?: { f: HookHoldFamily; r: string; by: string } } = {},
): Promise<string> {
  const g = JSON.parse(Buffer.from(grantToken.split(".")[1] as string, "base64url").toString("utf8")) as { jti: string; sub: `tb:agt:${string}` };
  return signCallProof(
    {
      iss: `tb:brg:${w.brg}`,
      sub: g.sub as `tb:agt:${AgentId}`,
      aud: `tb:ins:${over.aud ?? w.ins}`,
      iat: nowS(),
      call: `call_${ulid()}`,
      gjti: g.jti,
      op,
      in: digest(over.inputFor ?? input),
      ctx: digest(context),
      ...(over.hv ? { hv: over.hv } : {}),
    },
    w.bridgeKey,
  );
}

export async function ticket(w: World, path = "/"): Promise<string> {
  return signTicket({ iss: "tb:portal", sub: `tb:per:${w.per}`, aud: `tb:ins:${w.ins}`, iat: nowS(), ws: w.ws, pur: "launch", path }, w.portal);
}

/** Fake bridge internal listener: claim + status long-poll (answers at once when a new slice is pushed). */
export class FakeBridge {
  readonly w: World;
  server: Server | null = null;
  port = 0;
  claims = 0;
  /** enrolment codes of every claim, in order */
  claimCodes: string[] = [];
  /** v0.1.12 tests: true → a reused code is refused 403 code_invalid (one-time codes) */
  oneTimeCodes = false;
  /** v0.1.12 tests: true → instance-assertion routes answer 401 unauthenticated (stored identity unknown); a claim clears it */
  refuseIdentity = false;
  instanceKey: import("@opt2-tealbrick/spec/credentials").Ed25519PublicJwk | null = null;
  statuses: Record<string, unknown>[] = [];
  /** companion calls seen at POST /tb/v1/call */
  calls: { body: Record<string, unknown>; grant: string; assert: string }[] = [];
  /** answer of POST /tb/v1/call (default: ok) */
  onCall: (body: Record<string, unknown>) => { status: number; body: unknown } = () => ({ status: 200, body: { status: "ok", output: { done: true } } });
  #slice: string | null = null;
  #rev = 0;
  #waiting: ServerResponse[] = [];

  constructor(w: World) {
    this.w = w;
  }

  async start(initialSlice: string): Promise<string> {
    this.#slice = initialSlice;
    this.#rev = this.w.rev;
    this.server = createServer((req, res) => void this.#handle(req, res));
    this.port = await freePort();
    await new Promise<void>((r) => this.server?.listen(this.port, "127.0.0.1", r));
    return `http://127.0.0.1:${this.port}`;
  }

  push(token: string): void {
    this.#slice = token;
    this.#rev = this.w.rev;
    for (const res of this.#waiting.splice(0)) this.#answer(res);
  }

  #answer(res: ServerResponse): void {
    if (res.writableEnded) return;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ slice: this.#slice, sliceRevision: this.#rev, keysRev: 0 }));
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : null;
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/tb/v1/claim") {
      const code = String(body?.code ?? "");
      if (this.oneTimeCodes && this.claimCodes.includes(code)) {
        res.writeHead(403, { "content-type": "application/json" });
        return void res.end(JSON.stringify({ error: { code: "code_invalid", message: "enrolment code used", requestId: "req_test" } }));
      }
      this.claimCodes.push(code);
      this.refuseIdentity = false;
      this.claims += 1;
      this.instanceKey = body?.instancePublicKey ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ ins: this.w.ins, bridge: { id: this.w.brg, publicKey: this.w.bridgeKey.publicJwk, internalUrl: `http://127.0.0.1:${this.port}` }, slice: this.#slice, _code: body?.code ? "seen" : "none" }));
    }
    if (url.pathname === "/tb/v1/call") {
      const assertion = String(req.headers["tb-assert"] ?? "");
      if (!assertion) {
        res.writeHead(401);
        return void res.end();
      }
      this.calls.push({ body, grant: String(req.headers["tb-grant"] ?? ""), assert: assertion });
      const a = this.onCall(body);
      res.writeHead(a.status, { "content-type": "application/json" });
      return void res.end(JSON.stringify(a.body));
    }
    if (url.pathname === "/tb/v1/status") {
      if (!req.headers["tb-assert"]) {
        res.writeHead(401);
        return void res.end();
      }
      if (this.refuseIdentity) {
        res.writeHead(401, { "content-type": "application/json" });
        return void res.end(JSON.stringify({ error: { code: "unauthenticated", message: "instance assertion missing or key unknown", requestId: "req_test" } }));
      }
      this.statuses.push(body);
      if (body?.sliceRevision !== this.#rev) return this.#answer(res);
      const wait = Number(url.searchParams.get("wait") ?? "0");
      if (wait === 0) {
        res.writeHead(204);
        return void res.end();
      }
      this.#waiting.push(res);
      const t = setTimeout(() => {
        this.#waiting = this.#waiting.filter((r) => r !== res);
        if (!res.writableEnded) {
          res.writeHead(204);
          res.end();
        }
      }, 1500);
      t.unref();
      return;
    }
    res.writeHead(404);
    res.end();
  }

  async stop(): Promise<void> {
    for (const r of this.#waiting.splice(0)) r.end();
    this.server?.closeAllConnections();
    await new Promise<void>((r) => (this.server ? this.server.close(() => r()) : r()));
  }
}

export async function until<T>(fn: () => Promise<T | undefined | null | false>, ms = 5000): Promise<T> {
  const end = Date.now() + ms;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > end) throw new Error("until: timed out");
    await new Promise((r) => setTimeout(r, 25));
  }
}
