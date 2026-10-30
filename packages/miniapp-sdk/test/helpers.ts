// Test harness: Portal + bridge key pairs, a fake bridge internal API (claim, status long-poll), and token helpers
// built ONLY from the manifest package's signers (no hand-rolled JWS).
import { webcrypto } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { digest, type Ed25519KeyPair, generateKeyPair, keySetFrom, signCallProof, signGrant, signKeySetStatement, signSlice, signTicket, ulid, verifyAssertion } from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type BridgeId, type Ed25519PublicJwk, type FreeCaps, type InstanceId, type PersonId, TYP, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
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
    /** spec 0.1.54 (C292): bridge.caps as the bridge reported them (`unknown` so a test can push a malformed value; absent = member omitted) */
    bridgeCaps?: unknown;
    /** spec 0.1.80 (C373): slice `topology` (`unknown` so a test can push a malformed value; absent = member omitted) */
    topology?: unknown;
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
      bridge: { id: w.brg, keys: [w.bridgeKey.publicJwk], ...(over.viewUrl !== undefined ? { viewUrl: over.viewUrl } : {}), ...(over.bridgeCaps !== undefined ? { caps: over.bridgeCaps } : {}) },
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
      ...(over.topology !== undefined ? { topology: over.topology } : {}),
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

const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

/**
 * Signs ANY header + payload with `key`, bypassing the claim checks of the manifest signers. The ONLY use: a token the signers refuse
 * to build (a malformed `bd`, `bd` on an op proof) so a test can show the SDK refuses it too. Never for a valid token.
 */
export async function rawSign(header: unknown, payload: unknown, key: Ed25519KeyPair): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = await webcrypto.subtle.sign({ name: "Ed25519" }, key.privateKey as webcrypto.CryptoKey, Buffer.from(input));
  return `${input}.${Buffer.from(sig).toString("base64url")}`;
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
  /** v0.1.36: the whole body of every claim, in order (proofClaims) */
  claimBodies: Record<string, unknown>[] = [];
  /** v0.1.12 tests: true → a reused code is refused 403 code_invalid (one-time codes) */
  oneTimeCodes = false;
  /** v0.1.12 tests: true → instance-assertion routes answer 401 unauthenticated (stored identity unknown); a claim clears it */
  refuseIdentity = false;
  instanceKey: import("@opt2-tealbrick/spec/credentials").Ed25519PublicJwk | null = null;
  statuses: Record<string, unknown>[] = [];
  /** spec 0.1.88: bodies of POST /tb/v1/policy-recheck, and its answer (default: allow) */
  rechecks: Record<string, unknown>[] = [];
  onRecheck: (body: Record<string, unknown>) => { status: number; body: unknown } = () => ({ status: 200, body: { decision: "allow" } });
  /** spec 0.1.88: bodies of POST /tb/v1/acting-tickets; the answer is one fake ticket per call */
  ticketAsks: Record<string, unknown>[] = [];
  /** spec 0.1.89: bodies of POST /tb/v1/owner-drafts{,/get,/withdraw} and whether the instance assertion verified (htm, htu, bd); and the answer */
  ownerDraftAsks: { path: string; body: Record<string, unknown>; assertOk: boolean }[] = [];
  onOwnerDraft: (path: string, body: Record<string, unknown>) => { status: number; body: unknown; headers?: Record<string, string> } = () => ({ status: 200, body: { draftId: "drf_test", state: "submitted", reviewUrl: "https://portal.test/review" } });
  /** companion calls seen at POST /tb/v1/call */
  calls: { body: Record<string, unknown>; grant: string; assert: string }[] = [];
  /** answer of POST /tb/v1/call (default: ok) */
  onCall: (body: Record<string, unknown>) => { status: number; body: unknown } = () => ({ status: 200, body: { status: "ok", output: { done: true } } });
  /** v0.1.38 (C274c): every POST /tb/v1/events attempt: items, and whether the instance assertion verified (htm, htu, bd) */
  eventPosts: { items: Record<string, unknown>[]; assertOk: boolean }[] = [];
  /** answer of POST /tb/v1/events (default: 200, stored for each item; an emit key seen before → duplicate) */
  onEvents: ((items: Record<string, unknown>[]) => { status: number; body: unknown } | null) | null = null;
  /** emit items stored once each (dedupe by key, as the bridge does per app instance) */
  storedEvents: Record<string, unknown>[] = [];
  /** v0.1.63 (BRIDGE §15.4): the keys + role-binding revision the status answers carry (`bumpKeys`) */
  keysRev = 0;
  /** v0.1.63: role → answer of GET /tb/v1/model-roles/<role> (absent = 404 role_not_set); `keysRev` is added when sent */
  modelRoles = new Map<string, { status: number; body: Record<string, unknown> }>();
  /** v0.1.63: false = a bridge without cap `model_roles`: the route does not exist (404 not_found, no refuse code) */
  modelRoutes = true;
  /** v0.1.63: every model-role fetch: the role and whether the instance assertion verified (htm, htu) */
  modelRoleFetches: { role: string; assertOk: boolean }[] = [];
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

  /** v0.1.63: a key or binding changed: one new revision, every waiting status answers at once */
  bumpKeys(): void {
    this.keysRev += 1;
    for (const res of this.#waiting.splice(0)) this.#answer(res);
  }

  push(token: string): void {
    this.#slice = token;
    this.#rev = this.w.rev;
    for (const res of this.#waiting.splice(0)) this.#answer(res);
  }

  #answer(res: ServerResponse): void {
    if (res.writableEnded) return;
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ slice: this.#slice, sliceRevision: this.#rev, keysRev: this.keysRev }));
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const raw = Buffer.concat(chunks);
    const body = chunks.length ? JSON.parse(raw.toString("utf8")) : null;
    const url = new URL(req.url ?? "/", "http://x");
    if (url.pathname === "/tb/v1/events" && req.method === "POST") {
      const token = String(req.headers["tb-assert"] ?? "");
      const keys = this.instanceKey ? keySetFrom({ keys: [this.instanceKey] }, `tb:ins:${this.w.ins}`) : null;
      const v = keys ? verifyAssertion(token, keys, { typ: TYP.instanceAssertion, aud: `tb:brg:${this.w.brg}`, now: nowS(), method: "POST", pathAndQuery: url.pathname + url.search, body: new Uint8Array(raw) }) : { ok: false };
      const items = Array.isArray(body?.items) ? (body.items as Record<string, unknown>[]) : [];
      this.eventPosts.push({ items, assertOk: v.ok });
      if (!v.ok) {
        res.writeHead(401, { "content-type": "application/json" });
        return void res.end(JSON.stringify({ error: { code: "unauthenticated", message: "assertion", requestId: "req_test" } }));
      }
      const a = this.onEvents?.(items) ?? null;
      if (a) {
        res.writeHead(a.status, { "content-type": "application/json" });
        return void res.end(JSON.stringify(a.body));
      }
      const results = items.map((it) => {
        if (it.kind === "emit" && this.storedEvents.some((x) => x.key === it.key)) return { key: it.key, status: "duplicate" };
        this.storedEvents.push(it);
        return { key: it.key, status: "stored", recipients: 0 };
      });
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ results }));
    }
    if (url.pathname.startsWith("/tb/v1/model-roles/") && req.method === "GET") {
      const role = decodeURIComponent(url.pathname.slice("/tb/v1/model-roles/".length));
      const token = String(req.headers["tb-assert"] ?? "");
      const keys = this.instanceKey ? keySetFrom({ keys: [this.instanceKey] }, `tb:ins:${this.w.ins}`) : null;
      const v = keys ? verifyAssertion(token, keys, { typ: TYP.instanceAssertion, aud: `tb:brg:${this.w.brg}`, now: nowS(), method: "GET", pathAndQuery: url.pathname + url.search }) : { ok: false };
      const send = (status: number, payload: unknown) => {
        res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
        res.end(JSON.stringify(payload));
      };
      if (!this.modelRoutes) return send(404, { error: { code: "not_found", message: "no such route", requestId: "req_test" } });
      this.modelRoleFetches.push({ role, assertOk: v.ok });
      if (!v.ok) return send(401, { error: { code: "unauthenticated", message: "assertion", requestId: "req_test" } });
      const a = this.modelRoles.get(role);
      if (!a) return send(404, { error: { code: "role_not_set", message: "role_not_set", requestId: "req_test" } });
      return send(a.status, a.status === 200 ? { ...a.body, keysRev: this.keysRev } : a.body);
    }
    if (url.pathname === "/tb/v1/claim") {
      const code = String(body?.code ?? "");
      if (this.oneTimeCodes && this.claimCodes.includes(code)) {
        res.writeHead(403, { "content-type": "application/json" });
        return void res.end(JSON.stringify({ error: { code: "code_invalid", message: "enrolment code used", requestId: "req_test" } }));
      }
      this.claimCodes.push(code);
      this.claimBodies.push(body ?? {});
      this.refuseIdentity = false;
      this.claims += 1;
      this.instanceKey = body?.instancePublicKey ?? null;
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ ins: this.w.ins, bridge: { id: this.w.brg, publicKey: this.w.bridgeKey.publicJwk, internalUrl: `http://127.0.0.1:${this.port}` }, slice: this.#slice, _code: body?.code ? "seen" : "none" }));
    }
    if (url.pathname.startsWith("/tb/v1/owner-drafts") && req.method === "POST") {
      const token = String(req.headers["tb-assert"] ?? "");
      const keys = this.instanceKey ? keySetFrom({ keys: [this.instanceKey] }, `tb:ins:${this.w.ins}`) : null;
      const v = keys ? verifyAssertion(token, keys, { typ: TYP.instanceAssertion, aud: `tb:brg:${this.w.brg}`, now: nowS(), method: "POST", pathAndQuery: url.pathname + url.search, body: new Uint8Array(raw) }) : { ok: false };
      this.ownerDraftAsks.push({ path: url.pathname, body, assertOk: v.ok });
      const a = this.onOwnerDraft(url.pathname, body);
      res.writeHead(a.status, { "content-type": "application/json", ...(a.headers ?? {}) });
      return void res.end(typeof a.body === "string" ? a.body : JSON.stringify(a.body));
    }
    if (url.pathname === "/tb/v1/policy-recheck") {
      this.rechecks.push(body);
      const a = this.onRecheck(body);
      res.writeHead(a.status, { "content-type": "application/json" });
      return void res.end(JSON.stringify(a.body));
    }
    if (url.pathname === "/tb/v1/acting-tickets") {
      this.ticketAsks.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      return void res.end(JSON.stringify({ tickets: ["a.b.c"] }));
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
      if (body?.sliceRevision !== this.#rev || (typeof body?.keysRev === "number" && body.keysRev !== this.keysRev)) return this.#answer(res);
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
