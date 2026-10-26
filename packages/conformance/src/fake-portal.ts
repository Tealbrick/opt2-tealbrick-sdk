// Fake Portal (CONFORMANCE §3): exactly the `bridge`-auth and `device`-auth rows of the route table (`ROUTES`, plus
// the public rows those flows start with: `bridge_api.enrol`, `device.start`), mounted under /api/v1; every other path
// → 404 (default deny). It issues enrolment codes, signs workspace configs with a fake Portal key, verifies bridge
// assertions, records acks, and runs the RFC 8628 device flow; a control API mints revisions, pauses, rotates keys,
// revokes connections, approves device requests and takes the Portal offline. Used by the (pending) bridge target.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import {
  assertPublicJwk,
  digest,
  digestEqual,
  type Ed25519KeyPair,
  generateKeyPair,
  keySetFrom,
  memoryReplayGuard,
  opaqueDigest,
  opaqueValue,
  signConfig,
  TYP,
  thumbprint,
  verifyAssertion,
} from "@opt2-tealbrick/manifest";
import type { EnrolRequest, EnrolResponse, StatusReport, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, BridgeId, ConnectionEntry, Ed25519PublicJwk, InstanceId, PersonId, PersonOpClaims, PortalKeyEntry, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import { DEVICE_FLOW } from "@opt2-tealbrick/spec/credentials";
import type { AgentMode } from "@opt2-tealbrick/spec/manifest";
import { type BridgePersonOp, type BridgePersonOpResultInput, type DeviceAgentTokenResult, type DeviceOwnerTokenResult, type DeviceStart, PERSON_OP_RELAY, type PersonOpId, ROUTES } from "@opt2-tealbrick/spec/routes";
import { closeServer, HttpError, header, listen, parseJson, readRaw, sendError, sendJson } from "./http.ts";
import { mintPersonOp, PERSON_OP_RESULT_PATH_RE, type PersonOpMint } from "./person-op.ts";
import { newId, nowS } from "./tokens.ts";

const API = "/api/v1";
/** The rows the fake serves: every `bridge`/`device` auth row plus the public rows that start those flows. */
export const FAKE_PORTAL_ROUTES = ROUTES.filter(
  (r) => r.exposure === "gateway" && ((r.auth as readonly string[]).some((a) => a === "bridge" || a === "device") || r.opId === "bridge_api.enrol" || r.opId === "device.start"),
);

interface DeviceReq {
  deviceDigest: string;
  userDigest: string;
  scope: "owner" | "agent";
  clientId: string;
  agents: { agt?: AgentId; public_key: Ed25519PublicJwk }[];
  state: "pending" | "approved" | "denied" | "redeemed";
  exp: number;
  lastPoll: number;
  interval: number;
  connections: { connection_id: `con_${string}`; agent_id: AgentId; public_key_thumbprint: string }[];
}

/** conformance 0.1.31 (spec 0.1.64, BRIDGE §16): one relay row as the fake Core keeps it. */
export interface QueuedPersonOp {
  item: BridgePersonOp;
  claims: PersonOpClaims;
  queuedAt: number;
  /** when a bridge poll took it (handed out once), null while queued */
  takenAt: number | null;
  /** not taken within the queue TTL: never handed out (PERSON_OP_RELAY.queueTtlS) */
  expired: boolean;
}
/** One `POST /bridge/person-ops/{pop}/result` that passed the bridge assertion (body = the raw request text). */
export interface PersonOpResultSeen {
  pop: string;
  status: number;
  body: string;
  raw: string;
  at: number;
}

export interface FakePortalOptions {
  workspaceName?: string;
  /** device polling interval in seconds (default DEVICE_FLOW.interval); tests use 0 */
  pollIntervalS?: number;
  maxWaitS?: number;
}

export class FakePortal {
  url = "";
  readonly ws: WorkspaceId = newId("ws") as WorkspaceId;
  readonly bridgeId: BridgeId = newId("brg") as BridgeId;
  readonly acks: StatusReport[] = [];
  readonly requests: { method: string; path: string; at: number }[] = [];
  readonly control: FakePortalControl;
  keys: { key: Ed25519KeyPair; status: PortalKeyEntry["status"] }[];
  bridgeKey: Ed25519PublicJwk | null = null;
  readonly enrolCodes = new Map<string, { used: boolean; exp: number }>();
  rev = 0;
  config: string | null = null;
  pause = { workspace: false, agents: new Set<AgentId>(), instances: new Set<InstanceId>() };
  agents: { agt: AgentId; name: string; mode: AgentMode }[] = [];
  connections: ConnectionEntry[] = [];
  revoked: { jti: string; exp: number }[] = [];
  offline = false;
  readonly devices: DeviceReq[] = [];
  /** extra config fields merged into every minted revision (bridge target: apps, grants, hooks, skills, …) */
  // SPEC-GAP: @opt2-tealbrick/spec 0.1.10 types lack v0.1.11 `portalKeySet` (CREDENTIALS §9.5); typed here until 0.1.11.
  configExtra: Partial<Omit<WorkspaceConfig, "iat" | "exp" | "jti">> & { portalKeySet?: string } = {};
  /** v0.1.11: key-set statement returned in the enrolment response (`portalKeySet`); null = omitted */
  enrolKeySet: string | null = null;
  /** v0.1.12 (conformance 0.1.8): the world's current statement after a key change (test roots on), else null */
  keySetSource: (() => Promise<string>) | null = null;
  /** public origin of the bridge under test (config `bridge.publicUrl`, device-flow `mcp_url` / `token_endpoint`) */
  bridgePublicUrl = "https://bridge.conformance.test";
  /** conformance 0.1.31 (BRIDGE §16): the workspace owner K14 `sub` names, the relay queue, the result posts and the person-op polls */
  readonly owner: PersonId = newId("per") as PersonId;
  readonly personOps: QueuedPersonOp[] = [];
  readonly personOpResults: PersonOpResultSeen[] = [];
  readonly personOpPolls: { at: number; wait: number | null; end: number | null; items: number }[] = [];
  /** most person-op polls open at the same time (BRIDGE §16: ONE long-poll) */
  personOpPollsMaxOpen = 0;
  #personOpPollsOpen = 0;
  /** a queued row not taken within this many ms expires (default PERSON_OP_RELAY.queueTtlS) */
  personOpTtlMs: number = PERSON_OP_RELAY.queueTtlS * 1000;
  readonly #poWaiters = new Set<() => void>();
  /** every request with headers and raw body, recorded after it was read (bridge target B9 scan) */
  readonly captured: { method: string; path: string; headers: Record<string, string>; body: string; at: number }[] = [];
  readonly #sockets = new Set<Socket>();
  readonly #opts: FakePortalOptions;
  readonly #replay = memoryReplayGuard();
  readonly #waiters = new Set<() => void>();
  readonly #server = createServer((req, res) => void this.#handle(req, res));

  private constructor(opts: FakePortalOptions, key: Ed25519KeyPair) {
    this.#opts = opts;
    this.keys = [{ key, status: "active" }];
    this.control = new FakePortalControl(this);
    this.#server.on("connection", (sock: Socket) => {
      this.#sockets.add(sock);
      sock.once("close", () => this.#sockets.delete(sock));
    });
  }

  static async create(opts: FakePortalOptions = {}): Promise<FakePortal> {
    const p = new FakePortal(opts, await generateKeyPair());
    p.url = await listen(p.#server);
    await p.mintRevision();
    return p;
  }

  activeKey(): Ed25519KeyPair {
    const a = this.keys.find((k) => k.status === "active");
    if (!a) throw new Error("fake portal: no active key");
    return a.key;
  }

  issueEnrolCode(): string {
    const code = opaqueValue("tbe_");
    this.enrolCodes.set(opaqueDigest(code), { used: false, exp: nowS() + 86400 });
    return code;
  }

  /** Config body for revision `rev` from the current state (unsigned; `configExtra` merged last). */
  configBody(rev: number, iat: number = nowS()): Omit<WorkspaceConfig, "exp" | "jti"> {
    const brg = `tb:brg:${this.bridgeId}` as const;
    return {
      v: 1 as const,
      iss: "tb:portal" as const,
      sub: brg,
      aud: brg,
      iat,
      ws: this.ws,
      rev,
      workspace: { id: this.ws, name: this.#opts.workspaceName ?? "Conformance workspace" },
      bridge: { id: this.bridgeId, publicUrl: this.bridgePublicUrl },
      portalKeys: this.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })),
      pause: { workspace: this.pause.workspace, agents: [...this.pause.agents], instances: [...this.pause.instances] },
      revoked: { jtis: this.revoked.map((r) => ({ jti: r.jti, exp: r.exp })) },
      connections: this.connections,
      instanceKeys: [],
      grants: [],
      apps: [],
      agents: this.agents,
      hooks: [],
      skills: { digest: digest({ files: [] }), files: [] },
      keyRequirements: [],
      enrolCodes: [],
      ...this.configExtra,
    } satisfies Omit<WorkspaceConfig, "exp" | "jti">;
  }

  /** Signs config revision `rev + 1` from the current state and wakes the config long-polls (`iat` override: B4 config age). */
  async mintRevision(opts: { iat?: number } = {}): Promise<number> {
    this.rev++;
    const now = nowS();
    this.revoked = this.revoked.filter((r) => r.exp > now);
    this.config = await signConfig(this.configBody(this.rev, opts.iat ?? now), this.activeKey());
    for (const w of [...this.#waiters]) w();
    return this.rev;
  }

  /** Serves `jws` verbatim as the next revision (bridge target B3: bad signature, lower rev, foreign workspace). */
  serveRaw(jws: string): void {
    this.rev++;
    this.config = jws;
    for (const w of [...this.#waiters]) w();
  }

  /** Destroys every open connection, including held config long-polls (bridge target B4: Portal down). */
  dropConnections(): void {
    for (const s of this.#sockets) s.destroy();
  }

  async close(): Promise<void> {
    for (const w of [...this.#waiters]) w();
    for (const w of [...this.#poWaiters]) w();
    await closeServer(this.#server);
  }

  #verifyBridge(req: IncomingMessage, raw: Buffer): void {
    if (!this.bridgeKey) throw new HttpError(401, "unauthenticated", "bridge not enrolled");
    const r = verifyAssertion(header(req, "TB-Assert") ?? "", keySetFrom({ keys: [this.bridgeKey] }, `tb:brg:${this.bridgeId}`), {
      typ: TYP.bridgeAssertion,
      aud: "tb:portal",
      now: nowS(),
      method: req.method ?? "GET",
      pathAndQuery: req.url ?? "/",
      body: raw.length > 0 ? new Uint8Array(raw) : undefined,
      replay: this.#replay,
    });
    if (!r.ok) throw new HttpError(401, "bridge_key_revoked", `bridge assertion refused (${r.reason})`);
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    this.requests.push({ method: req.method ?? "GET", path, at: Date.now() });
    try {
      if (this.offline) {
        req.socket.destroy();
        return;
      }
      const raw = await readRaw(req);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
      this.captured.push({ method: req.method ?? "GET", path: req.url ?? "/", headers, body: raw.toString("utf8"), at: Date.now() });
      const pop = req.method === "POST" ? PERSON_OP_RESULT_PATH_RE.exec(path)?.[1] : undefined;
      if (pop) return this.#personOpResult(req, raw, pop, res);
      const row = FAKE_PORTAL_ROUTES.find((r) => r.method === req.method && API + r.path === path);
      if (!row) throw new HttpError(404, "not_found", "no such route");
      switch (row.opId) {
        case "bridge_api.enrol":
          return this.#enrol(raw, res);
        case "bridge_api.config":
          return await this.#config(req, raw, url, res);
        case "bridge_api.ack":
          return this.#ack(req, raw, res);
        case "bridge_api.person_ops":
          return await this.#personOpsPoll(req, raw, url, res);
        case "device.start":
          return this.#deviceStart(raw, res);
        case "device.token":
          return this.#deviceToken(raw, res);
        default:
          throw new HttpError(404, "not_found", "no such route");
      }
    } catch (e) {
      const err = e instanceof HttpError ? e : new HttpError(500, "internal", "fake portal error");
      sendError(res, err.status, err.code, err.message);
    }
  }

  #enrol(raw: Buffer, res: ServerResponse): void {
    const b = parseJson(raw) as Partial<EnrolRequest> | undefined;
    if (!b || typeof b.code !== "string") throw new HttpError(400, "validation_failed", "EnrolRequest shape");
    const d = opaqueDigest(b.code);
    let entry: { used: boolean; exp: number } | undefined;
    for (const [k, v] of this.enrolCodes) if (digestEqual(k, d)) entry = v;
    if (!entry || entry.used || entry.exp < nowS()) throw new HttpError(400, "enrolment_code_invalid", "enrolment code unknown, used or expired");
    try {
      assertPublicJwk(b.publicKey);
    } catch {
      throw new HttpError(400, "validation_failed", "publicKey is not an Ed25519 public JWK");
    }
    entry.used = true;
    this.bridgeKey = b.publicKey as Ed25519PublicJwk;
    const body: EnrolResponse = {
      bridgeId: this.bridgeId,
      workspaceId: this.ws,
      portalKeys: this.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })),
      ...(this.enrolKeySet ? { portalKeySet: this.enrolKeySet } : {}),
      configPath: `${API}/bridge/config`,
      ackPath: `${API}/bridge/ack`,
      waitMaxS: 60,
    };
    sendJson(res, 200, body);
  }

  async #config(req: IncomingMessage, raw: Buffer, url: URL, res: ServerResponse): Promise<void> {
    this.#verifyBridge(req, raw);
    const after = Number(url.searchParams.get("after") ?? "0");
    const wait = Math.max(0, Math.min(this.#opts.maxWaitS ?? 60, Number(url.searchParams.get("wait") ?? "0") || 0));
    if (after >= this.rev && wait > 0) {
      await new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(t);
          this.#waiters.delete(done);
          resolve();
        };
        const t = setTimeout(done, wait * 1000);
        this.#waiters.add(done);
        req.once("close", done);
      });
    }
    if (res.destroyed) return;
    if (after >= this.rev || !this.config) return void res.writeHead(304).end();
    res.writeHead(200, { "content-type": "application/jose", "cache-control": "no-store" });
    res.end(this.config);
  }

  #ack(req: IncomingMessage, raw: Buffer, res: ServerResponse): void {
    this.#verifyBridge(req, raw);
    const b = parseJson(raw) as Partial<StatusReport> | undefined;
    if (!b || !Number.isInteger(b.rev) || typeof b.bridge !== "object") throw new HttpError(400, "validation_failed", "StatusReport shape");
    this.acks.push(b as StatusReport);
    sendJson(res, 200, { accepted: true, configRevision: this.rev });
  }

  /**
   * conformance 0.1.31 (BRIDGE §16, PORTAL-API v0.1.64 B–C): queues one relay row for the bridge, with a K14 signed by the active
   * Portal key over the exact `body` string. `mint` overrides parts of the claim set (negative cases); `jws` replaces the token.
   */
  async queuePersonOp(p: { ins: InstanceId; op: string; body: string; mint?: Partial<PersonOpMint>; jws?: string }): Promise<QueuedPersonOp> {
    const pop = newId("pop") as PersonOpId;
    const m = await mintPersonOp({ key: this.activeKey(), ws: this.ws, ins: p.ins, person: this.owner, op: p.op, body: p.body, pop, ...p.mint });
    const now = Date.now();
    const row: QueuedPersonOp = { item: { id: pop, ins: p.ins, op: p.op, jws: p.jws ?? m.jws, body: p.body, expiresAt: new Date(now + this.personOpTtlMs).toISOString() }, claims: m.claims, queuedAt: now, takenAt: null, expired: false };
    this.personOps.push(row);
    for (const w of [...this.#poWaiters]) w();
    return row;
  }

  /** Resolves with the first result post for `pop` (null after `ms`). */
  async waitPersonOpResult(pop: string, ms: number): Promise<PersonOpResultSeen | null> {
    const end = Date.now() + ms;
    for (;;) {
      const r = this.personOpResults.find((x) => x.pop === pop);
      if (r) return r;
      if (Date.now() >= end) return null;
      await new Promise((res) => setTimeout(res, 50));
    }
  }

  #takePersonOps(): BridgePersonOp[] {
    const now = Date.now();
    const out: BridgePersonOp[] = [];
    for (const r of this.personOps) {
      if (r.takenAt !== null || r.expired) continue;
      if (now - r.queuedAt > this.personOpTtlMs) {
        r.expired = true;
        continue;
      }
      r.takenAt = now;
      out.push(r.item);
    }
    return out;
  }

  /** `GET /bridge/person-ops?wait=N` (bridge assertion): every untaken row once; an empty batch after `wait` seconds. */
  async #personOpsPoll(req: IncomingMessage, raw: Buffer, url: URL, res: ServerResponse): Promise<void> {
    this.#verifyBridge(req, raw);
    const w = url.searchParams.get("wait");
    const wait = Math.max(0, Math.min(this.#opts.maxWaitS ?? 60, PERSON_OP_RELAY.pollWaitS, Number(w ?? "0") || 0));
    const rec = { at: Date.now(), wait: w === null ? null : Number(w), end: null as number | null, items: 0 };
    this.personOpPolls.push(rec);
    this.#personOpPollsOpen++;
    this.personOpPollsMaxOpen = Math.max(this.personOpPollsMaxOpen, this.#personOpPollsOpen);
    try {
      const gone = () => res.destroyed || req.socket.destroyed;
      let items = this.#takePersonOps();
      const end = Date.now() + wait * 1000;
      while (items.length === 0 && Date.now() < end && !gone() && !this.offline) {
        await new Promise<void>((resolve) => {
          const done = () => {
            clearTimeout(t);
            this.#poWaiters.delete(done);
            req.off("close", done);
            resolve();
          };
          const t = setTimeout(done, Math.max(0, end - Date.now()));
          this.#poWaiters.add(done);
          req.once("close", done);
        });
        // a closed portal or a dropped poll never takes a row
        if (gone() || !this.#server.listening) return;
        items = this.#takePersonOps();
      }
      if (gone()) return;
      rec.items = items.length;
      sendJson(res, 200, { items });
    } finally {
      this.#personOpPollsOpen--;
      rec.end = Date.now();
    }
  }

  /** `POST /bridge/person-ops/{pop}/result` (bridge assertion): recorded; an unknown or untaken pop → 404 (C-PO-7). */
  #personOpResult(req: IncomingMessage, raw: Buffer, pop: string, res: ServerResponse): void {
    this.#verifyBridge(req, raw);
    const row = this.personOps.find((r) => r.item.id === pop);
    if (!row || row.takenAt === null) throw new HttpError(404, "not_found", "no such relay row");
    const b = parseJson(raw) as Partial<BridgePersonOpResultInput> | undefined;
    if (!b || b.pop !== pop || !Number.isInteger(b.status) || typeof b.body !== "string") throw new HttpError(400, "validation_failed", "BridgePersonOpResultInput shape");
    this.personOpResults.push({ pop, status: b.status as number, body: b.body, raw: raw.toString("utf8"), at: Date.now() });
    sendJson(res, 200, { ok: true });
  }

  #deviceStart(raw: Buffer, res: ServerResponse): void {
    const b = parseJson(raw) as Record<string, unknown> | undefined;
    const label = typeof b?.machine_label === "string" && b.machine_label.length > 0 && b.machine_label.length <= DEVICE_FLOW.machineLabelMax;
    let agents: DeviceReq["agents"] = [];
    if (b?.scope === "owner") {
      if (!(DEVICE_FLOW.ownerClientIds as readonly unknown[]).includes(b.client_id) || !label || "agents" in b) throw new HttpError(400, "bad_request", "scope owner only for tealbrick-cli|tbd, no keys");
    } else if (b?.scope === "agent") {
      if (!(DEVICE_FLOW.agentClientIds as readonly unknown[]).includes(b.client_id) || !label || typeof b.harness !== "string") throw new HttpError(400, "bad_request", "agent start shape");
      if (!Array.isArray(b.agents) || b.agents.length < 1 || b.agents.length > DEVICE_FLOW.maxAgentPairs) throw new HttpError(400, "bad_request", "1..64 agent key pairs");
      try {
        for (const a of b.agents as { public_key: unknown }[]) assertPublicJwk(a.public_key);
      } catch {
        throw new HttpError(400, "bad_request", "agent public_key must be an Ed25519 public JWK");
      }
      agents = b.agents as DeviceReq["agents"];
    } else throw new HttpError(400, "bad_request", "scope must be owner or agent");
    const device = opaqueValue("tbdv_");
    const alpha = DEVICE_FLOW.userCodeAlphabet;
    const bytes = crypto.getRandomValues(new Uint8Array(DEVICE_FLOW.userCodeLength));
    const plain = [...bytes].map((x) => alpha[x % alpha.length]).join("");
    this.devices.push({
      deviceDigest: opaqueDigest(device),
      userDigest: opaqueDigest(plain),
      scope: b.scope,
      clientId: String(b.client_id),
      agents,
      state: "pending",
      exp: nowS() + DEVICE_FLOW.expiresIn,
      lastPoll: 0,
      interval: this.#opts.pollIntervalS ?? DEVICE_FLOW.interval,
      connections: [],
    });
    const user = `${plain.slice(0, 4)}-${plain.slice(4)}`;
    const body: DeviceStart = {
      device_code: device,
      user_code: user,
      verification_uri: `${this.url}/device`,
      verification_uri_complete: `${this.url}/device?code=${user}`,
      expires_in: DEVICE_FLOW.expiresIn,
      interval: DEVICE_FLOW.interval,
    };
    sendJson(res, 200, body);
  }

  #deviceToken(raw: Buffer, res: ServerResponse): void {
    const b = parseJson(raw) as Record<string, unknown> | undefined;
    if (b?.grant_type !== "urn:ietf:params:oauth:grant-type:device_code" || typeof b.device_code !== "string") throw new HttpError(400, "bad_request", "DeviceTokenInput shape");
    const d = opaqueDigest(b.device_code);
    const r = this.devices.find((x) => digestEqual(x.deviceDigest, d));
    if (!r || r.clientId !== b.client_id) throw new HttpError(400, "expired_token", "unknown device code");
    const now = nowS();
    if (r.exp < now || r.state === "redeemed") throw new HttpError(400, "expired_token", "device code expired or used");
    if (r.state === "denied") throw new HttpError(400, "access_denied", "the owner denied the request");
    if (r.state === "pending") {
      const fast = now - r.lastPoll < r.interval;
      r.lastPoll = now;
      if (fast) {
        r.interval += DEVICE_FLOW.slowDownIncrement;
        throw new HttpError(400, "slow_down", "poll slower");
      }
      throw new HttpError(400, "authorization_pending", "waiting for the owner");
    }
    r.state = "redeemed";
    if (r.scope === "owner") {
      const body: DeviceOwnerTokenResult = { scope: "owner", access_token: opaqueValue("tbo_"), token_type: "Bearer", expires_in: 86400, session_id: newId("osn") as DeviceOwnerTokenResult["session_id"] };
      sendJson(res, 200, body);
      return;
    }
    const body: DeviceAgentTokenResult = { scope: "agent", workspace_id: this.ws, bridge_id: this.bridgeId, mcp_url: `${this.bridgePublicUrl}/mcp`, token_endpoint: `${this.bridgePublicUrl}/oauth/token`, connections: r.connections };
    sendJson(res, 200, body);
  }
}

/** Test control API for the fake Portal. */
export class FakePortalControl {
  readonly #p: FakePortal;
  constructor(p: FakePortal) {
    this.#p = p;
  }
  issueEnrolCode(): string {
    return this.#p.issueEnrolCode();
  }
  mintRevision(): Promise<number> {
    return this.#p.mintRevision();
  }
  addAgent(name: string, mode: AgentMode = "free"): Promise<AgentId> {
    const agt = newId("agt") as AgentId;
    this.#p.agents.push({ agt, name, mode });
    return this.#p.mintRevision().then(() => agt);
  }
  pauseWorkspace(on: boolean): Promise<number> {
    this.#p.pause.workspace = on;
    return this.#p.mintRevision();
  }
  pauseAgent(agt: AgentId, on: boolean): Promise<number> {
    if (on) this.#p.pause.agents.add(agt);
    else this.#p.pause.agents.delete(agt);
    return this.#p.mintRevision();
  }
  revokeConnection(con: string): Promise<number> {
    for (const c of this.#p.connections) if (c.con === con) c.status = "revoked";
    return this.#p.mintRevision();
  }
  async rotateKey(phase: "announce" | "activate" | "retire"): Promise<number> {
    const p = this.#p;
    if (phase === "announce") p.keys.push({ key: await generateKeyPair(), status: "pending" });
    if (phase === "activate") {
      const next = p.keys.find((k) => k.status === "pending");
      if (!next) throw new Error("no pending key");
      for (const k of p.keys) if (k.status === "active") k.status = "retired";
      next.status = "active";
    }
    if (phase === "retire") p.keys = p.keys.filter((k) => k.status !== "retired");
    // A world may have frozen `portalKeys` into configExtra (merged last); refresh it from the key list so the
    // announce / activate / retire revisions actually carry the rotation (Lead · Bridge finding on C5.portal_key_rotation).
    // A standalone world (portalKeys: []) keeps its empty list.
    if (p.configExtra.portalKeys && p.configExtra.portalKeys.length > 0) {
      p.configExtra = { ...p.configExtra, portalKeys: p.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })) };
    }
    // With test roots the trusted keys come ONLY from the statement (CREDENTIALS §9.5): re-sign it (seq + 1) over the
    // rotated list, or the activate revision is signed by a kid the pinned statement does not list (Lead · Bridge, 0.1.8).
    if (p.keySetSource && p.configExtra.portalKeySet) p.configExtra = { ...p.configExtra, portalKeySet: await p.keySetSource() };
    return p.mintRevision();
  }
  /** Portal down (B4): connections are dropped without an answer. */
  goOffline(on: boolean): void {
    this.#p.offline = on;
  }
  /** Owner approval in the browser (K1 + user code); agent scope creates one key connection per pair. */
  async approveDevice(userCode: string, agents: AgentId[] = []): Promise<void> {
    const norm = userCode.toUpperCase().replace(/-/g, "");
    const r = this.#p.devices.find((x) => digestEqual(x.userDigest, opaqueDigest(norm)));
    if (r?.state !== "pending") throw new Error("no pending device request for that user code");
    await this.#approve(r, agents);
  }
  /** Approves the newest pending device request (the suite plays the owner for a CLI it started; relay target). */
  async approvePending(agents: AgentId[] = []): Promise<boolean> {
    const r = [...this.#p.devices].reverse().find((x) => x.state === "pending" && x.exp > nowS());
    if (!r) return false;
    await this.#approve(r, agents);
    return true;
  }
  async #approve(r: DeviceReq, agents: AgentId[]): Promise<void> {
    r.state = "approved";
    if (r.scope === "agent") {
      r.agents.forEach((a, i) => {
        const agt = agents[i] ?? a.agt ?? (newId("agt") as AgentId);
        const con = newId("con") as `con_${string}`;
        this.#p.connections.push({ con: con as ConnectionEntry["con"], agt, method: "key", gen: 1, publicKey: a.public_key, status: "active" });
        r.connections.push({ connection_id: con, agent_id: agt, public_key_thumbprint: thumbprint(a.public_key) });
      });
      await this.#p.mintRevision();
    }
  }
  denyDevice(userCode: string): void {
    const norm = userCode.toUpperCase().replace(/-/g, "");
    const r = this.#p.devices.find((x) => digestEqual(x.userDigest, opaqueDigest(norm)));
    if (r) r.state = "denied";
  }
}

export function createFakePortal(opts: FakePortalOptions = {}): Promise<FakePortal> {
  return FakePortal.create(opts);
}
