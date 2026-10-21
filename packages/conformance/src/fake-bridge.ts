// Fake bridge (CONFORMANCE §3): the bridge internal surface an app talks to — `/tb/v1/claim`, `/tb/v1/status`
// (long-poll), `/tb/v1/keys/<name>`, `/tb/v1/call` — exactly per BRIDGE §8.3, §9.4, §10, plus a programmatic control
// API and a client that drives an app the way the bridge does (CORE §8). It holds a fake Portal key set and a bridge
// key, issues enrolment codes and signs slices / grants / proofs / tickets with the @opt2-tealbrick/manifest signers.
// Unknown routes → 404 (default deny). Every request and answer is captured for the payload scans (C4, C8).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  assertPublicJwk,
  DEFAULT_HELD_FAMILIES,
  digestEqual,
  type Ed25519KeyPair,
  gate,
  generateKeyPair,
  keySetFrom,
  keySetFromPortalKeys,
  manifestDigest,
  memoryReplayGuard,
  opaqueDigest,
  opaqueValue,
  sdkMajorOf,
  signKeySetStatement,
  signSlice,
  TYP,
  verifyAssertion,
} from "@opt2-tealbrick/manifest";
import {
  type AppStatus,
  type AppStatusResponse,
  BRIDGE_HEADERS,
  BRIDGE_INTERNAL_PATHS,
  type CallEnvelope,
  type ClaimRequest,
  type ClaimResponse,
  type InstanceSlice,
  type KeyFetchResponse,
  type OpResult,
} from "@opt2-tealbrick/spec/bridge";
import {
  type AgentId,
  type BridgeId,
  type Ed25519PublicJwk,
  type InstanceId,
  LIFETIME_S,
  type PersonId,
  type PortalKeyEntry,
  type Sha256Digest,
  type WorkspaceId,
} from "@opt2-tealbrick/spec/credentials";
import type { AgentMode, CrudAction, HoldFamily, Manifest } from "@opt2-tealbrick/spec/manifest";
import { CRUD_ACTIONS } from "@opt2-tealbrick/spec/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { AppClient } from "./app-client.ts";
import { EventLog } from "./event-log.ts";
import { closeServer, HttpError, header, listen, parseJson, readRaw, sendError, sendJson } from "./http.ts";
import { Mint, newId, nowS, peek } from "./tokens.ts";

export interface FakeAgent {
  id: AgentId;
  name: string;
  mode: AgentMode;
}

export interface FakeBridgeOptions {
  /** manifest of the app under test (key declarations, companions, expected digest) */
  manifest: Manifest;
  instanceId?: InstanceId;
  /** agents with an edge to the app (default: two free agents and one bound agent) */
  agents?: FakeAgent[];
  /** SDK majors served (default: manifest.sdkMajor and the one before, CONFORMANCE §5) */
  sdkMajors?: number[];
  /** claims are accepted but the key is listed (and the slice returned) only after `control.bind()` */
  deferBinding?: boolean;
  /** cap for status long-polls in seconds (default 60, BRIDGE §10.3) */
  maxWaitS?: number;
  port?: number;
  /**
   * CONF-MULTIAPP (conformance 0.1.20): join the world of another fake bridge: the SAME workspace, bridge id, Portal keys,
   * bridge keys and test root, so the grants and call proofs of one fake bridge verify at the app behind this one (a REAL
   * peer app of the app under test has its own claim, slice and status long-poll, hence its own fake bridge).
   */
  joinWorld?: FakeBridge;
  /** CONF-MULTIAPP: instance ids for companion products that are other (real) apps of this world; others get a fresh fake id */
  peerInstances?: Record<string, InstanceId>;
}

/** One forwarded companion call (CONF-MULTIAPP): what the fake bridge hands to the real peer app and relays back. */
export interface PeerCall {
  envelope: CallEnvelope;
  /** the verified calling instance (TB-Assert) */
  caller: InstanceId;
  /** the companion grant the caller presented (already checked by gate()) */
  grant: string;
}
export interface PeerAnswer {
  status: number;
  body: unknown;
}
/** Routes a companion call to a REAL app instead of the `companionResponder` fake (CONF-MULTIAPP). */
export type PeerRoute = (call: PeerCall) => Promise<PeerAnswer>;
/** A real peer target as the fake bridge's gate() needs it: the target manifest's operations and scope types. */
export interface PeerTarget {
  ops: readonly OperationView[];
  scopeTypes: readonly string[];
  route: PeerRoute;
}

export interface CapturedPayload {
  /** `bridge-in`: request the app sent to the fake; `app-out`: request the fake sent to the app; `app-in`: the app's answer */
  dir: "bridge-in" | "app-out" | "app-in";
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  at: number;
}

export interface ClaimSeen {
  request: ClaimRequest;
  codeDigest: Sha256Digest;
  at: number;
}
export interface StatusSeen {
  status: AppStatus;
  ins: InstanceId;
  assertion: { iat: number; exp: number; kid: string };
  at: number;
}
export interface Violation {
  route: string;
  code: string;
  detail: string;
  at: number;
}

type HookBehaviour = "deny" | "error" | "timeout";
type CompanionResponder = (env: CallEnvelope, caller: InstanceId) => OpResult | Promise<OpResult>;

interface PortalKeyState {
  key: Ed25519KeyPair;
  status: PortalKeyEntry["status"];
}

export interface FakeBridgeIds {
  ws: WorkspaceId;
  bridge: BridgeId;
  ins: InstanceId;
  person: PersonId;
  agents: FakeAgent[];
  /** a fake target instance per companion product */
  peers: Record<string, InstanceId>;
}

export class FakeBridge {
  readonly ids: FakeBridgeIds;
  readonly manifest: Manifest;
  readonly mint: Mint;
  readonly control: FakeBridgeControl;
  readonly captured: CapturedPayload[] = [];
  readonly claims: ClaimSeen[] = [];
  readonly statuses: StatusSeen[] = [];
  readonly keyFetches: { name: string; ins: InstanceId; at: number }[] = [];
  readonly violations: Violation[] = [];
  readonly companionCalls: { envelope: CallEnvelope; caller: InstanceId; answer: number; at: number; grant: string }[] = [];
  /** CONF-MULTIAPP: companion targets that are REAL apps (product → target); every other target keeps the `companionResponder` fake */
  readonly peerTargets = new Map<string, PeerTarget>();
  /** companion calls refused on purpose by `control.refuseNextCompanionCalls` (the SDK's refresh-and-retry path) */
  readonly companionRefusals: { envelope: CallEnvelope; caller: InstanceId; code: string; at: number }[] = [];
  companionRefuseQueue: { status: number; code: string }[] = [];
  /**
   * v0.1.13 (C85, A16): EVERY `/tb/v1/call` attempt, refused ones included: the envelope (best-effort parse), the
   * asserting instance (null when the instance assertion was refused), the presented TB-Grant and the refusal code.
   */
  readonly callAttempts: { envelope: Partial<CallEnvelope> | null; caller: InstanceId | null; grant: string; code: string | null; status: number; at: number }[] = [];
  /** windows in which `control.forgetInstanceKey` had dropped the instance key (A16 ignores calls refused then) */
  readonly forgotten: { from: number; to: number | null }[] = [];
  /** every companion grant a slice of this run carried (A16: an app-initiated call must present one of them) */
  readonly sliceGrants = new Set<string>();
  /**
   * conformance 0.1.28 (C274c, BRIDGE §14): every `POST /tb/v1/events` attempt that passed the instance assertion: the items and the
   * HTTP status answered (a 503 from `control.failNextEvents` included), in arrival order.
   */
  readonly eventPosts: { items: Record<string, unknown>[]; status: number; at: number }[] = [];
  /** the next `n` ingest requests are answered with this status (A-EV-4: retry with the same key) */
  eventFailQueue: { status: number; code: string }[] = [];
  /** the per-agent event log (BRIDGE §14.1–§14.3) the `tealbrick/events/*` methods read */
  readonly events: EventLog;
  /** the first K6 for the app instance (`TB_ENROL_CODE`) */
  readonly enrolCode: string;
  url = "";

  // state (internal)
  portalKeys: PortalKeyState[];
  /**
   * v0.1.11 (C62/C63): TEST Portal Root Key pair for key-set statements. An app pins it only when its start module
   * passes `env.TBCONF_PORTAL_ROOT_KEYS` to startApp's harness `portalRootKeys` (CONFORMANCE §7); production builds pin
   * their channel's roots and never read that name.
   */
  readonly testRoot: Ed25519KeyPair;
  /** key-set statement state: slices carry `portalKeySet` once `on` (runApp turns it on before the first slice unless --no-test-roots) */
  keySet = { on: false, seq: 0, kss: null as string | null };
  /** one-shot override of the next slice (A13 negatives): `portalKeySet` (null = omitted), signer, extra portalKeys */
  sliceOverride: { portalKeySet?: string | null; signer?: Ed25519KeyPair; extraPortalKeys?: PortalKeyEntry[]; iat?: number } | null = null;
  /**
   * spec 0.1.54 (C292): `bridge.caps` of the slices this fake signs. undefined = the member is omitted (a bridge that declares nothing);
   * any array is carried as given (the A22 rows publish known and unknown entries; `unknown[]` so a test can publish a malformed list).
   */
  bridgeCaps: unknown[] | undefined = undefined;
  bridgeKeys: Ed25519KeyPair[];
  stranger: Ed25519KeyPair;
  readonly sdkMajors: number[];
  readonly expectedDigest: Sha256Digest;
  readonly enrolCodes = new Map<string, { ins: InstanceId; svc?: string; exp: number; used: boolean }>();
  readonly instanceKeys = new Map<string, Ed25519PublicJwk>();
  readonly pending = new Map<string, Ed25519PublicJwk>();
  pause = { workspace: false, agents: new Set<AgentId>(), instances: new Set<InstanceId>() };
  revoked: { jti: string; exp: number }[] = [];
  personNbf = 0;
  sliceRev = 0;
  slice: string | null = null;
  keysRev = 0;
  readonly keyValues = new Map<string, string>();
  configExpired = false;
  hooks: { phase: "before" | "context"; behaviour: HookBehaviour }[] = [];
  companionResponder: CompanionResponder = () => ({ status: "ok", output: {} });
  /**
   * v0.1.15 (C105a, CORE I8): the workspace apps policy. Its `held` is the `held` claim of every companion grant (the
   * slice's own grants and the inbound app-caller grants the client mints) and the slice field `appsPolicy`.
   * Default: the spec's DEFAULT_HELD_FAMILIES (imported, L1).
   */
  appsPolicy: { held: HoldFamily[] } = { held: [...DEFAULT_HELD_FAMILIES] };
  /** v0.1.14 (C102): instances listed in slice `companionCallers` (Core: the apps holding a companion grant to this one) */
  companionCallers: NonNullable<InstanceSlice["companionCallers"]> = [];
  /** spec 0.1.49 (C261): slice `appCallers`; `"verified"` = the SDK refuses an app caller without a verified product (`control.setAppCallers`) */
  appCallers: "verified" | null = null;
  readonly #replay = memoryReplayGuard();
  readonly #waiters = new Set<() => void>();
  readonly #statusWaiters = new Set<() => void>();
  readonly #server = createServer((req, res) => void this.#handle(req, res));
  readonly #opts: FakeBridgeOptions;
  #closed = false;

  private constructor(opts: FakeBridgeOptions, keys: { portal: Ed25519KeyPair; bridge: Ed25519KeyPair; stranger: Ed25519KeyPair; root: Ed25519KeyPair }) {
    this.#opts = opts;
    this.testRoot = keys.root;
    this.manifest = opts.manifest;
    const agents = opts.agents ?? [
      { id: newId("agt") as AgentId, name: "Conformance agent A", mode: "free" },
      { id: newId("agt") as AgentId, name: "Conformance agent B", mode: "free" },
      { id: newId("agt") as AgentId, name: "Conformance agent C", mode: "bound" },
    ];
    const peers: Record<string, InstanceId> = {};
    for (const c of opts.manifest.companions ?? []) peers[c.product] = opts.peerInstances?.[c.product] ?? (newId("ins") as InstanceId);
    this.ids = {
      ws: opts.joinWorld?.ids.ws ?? (newId("ws") as WorkspaceId),
      bridge: opts.joinWorld?.ids.bridge ?? (newId("brg") as BridgeId),
      ins: opts.instanceId ?? (newId("ins") as InstanceId),
      person: newId("per") as PersonId,
      agents,
      peers,
    };
    this.portalKeys = [{ key: keys.portal, status: "active" }];
    this.bridgeKeys = [keys.bridge];
    this.stranger = keys.stranger;
    this.sdkMajors = opts.sdkMajors ?? [opts.manifest.sdkMajor, opts.manifest.sdkMajor - 1].filter((m) => m >= 0);
    this.expectedDigest = manifestDigest(opts.manifest);
    this.mint = new Mint({
      ws: this.ids.ws,
      bridge: this.ids.bridge,
      portalKey: () => this.activePortalKey(),
      bridgeKey: () => this.bridgeKeys[0],
      stranger: keys.stranger,
    });
    this.enrolCode = this.issueEnrolCode(this.ids.ins);
    this.control = new FakeBridgeControl(this);
    // the fake's grant rule for events: every slice agent holds a valid grant with every crud; a bound agent's wf = every agent op
    const agentOps = opts.manifest.operations.filter((o) => o.audience === "agent").map((o) => o.id);
    this.events = new EventLog({
      manifest: (ins) => (ins === this.ids.ins ? this.manifest : null),
      grantees: (ins) => (ins === this.ids.ins ? this.ids.agents.map((a) => a.id) : []),
      claims: (agent, ins) => {
        const a = ins === this.ids.ins ? this.ids.agents.find((x) => x.id === agent) : undefined;
        return a ? { mode: a.mode, wf: a.mode === "bound" ? agentOps : [], crud: [...CRUD_ACTIONS] } : null;
      },
      agentPaused: (agent) => this.pause.workspace || this.pause.agents.has(agent),
      instancePaused: (ins) => this.pause.instances.has(ins),
      hookMatches: () => false,
    });
  }

  static async create(opts: FakeBridgeOptions): Promise<FakeBridge> {
    const w = opts.joinWorld;
    const [portal, bridge, stranger, root] = w
      ? [w.activePortalKey(), w.bridgeKeys[0], w.stranger, w.testRoot]
      : await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair(), generateKeyPair()]);
    const fb = new FakeBridge(opts, { portal, bridge, stranger, root });
    if (w) {
      // the whole key state of the joined world (rotated / retired keys included), so its grants and proofs verify here
      fb.portalKeys = w.portalKeys.map((k) => ({ key: k.key, status: k.status }));
      fb.bridgeKeys = [...w.bridgeKeys];
    }
    fb.url = await listen(fb.#server, opts.port ?? 0);
    await fb.rebuildSlice();
    return fb;
  }

  /** `TB_PORTAL_KEYS` value (public JWKS, bootstrap trust). */
  portalJwks(): { keys: Ed25519PublicJwk[] } {
    return { keys: this.portalKeys.filter((k) => k.status !== "pending").map((k) => k.key.publicJwk) };
  }

  /** Public JWKs of the TEST root pair (value of `TBCONF_PORTAL_ROOT_KEYS`, JSON array). */
  testRootJwks(): Ed25519PublicJwk[] {
    return [this.testRoot.publicJwk];
  }

  /** A key-set statement over `keys` (default: the current Portal keys) with `seq`, signed by `root` (default: the test root). */
  signKeySet(seq: number, keys: PortalKeyEntry[] = this.portalKeys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })), root: Ed25519KeyPair = this.testRoot): Promise<string> {
    return signKeySetStatement({ iss: "tb:portal-root", aud: "tb:portal-keys", seq, iat: nowS(), keys }, root);
  }

  /** Signs the next statement (`seq` + 1) over the current Portal keys and turns `portalKeySet` on. */
  async nextKeySet(): Promise<void> {
    this.keySet.seq++;
    this.keySet.kss = await this.signKeySet(this.keySet.seq);
    this.keySet.on = true;
  }

  activePortalKey(): Ed25519KeyPair {
    const a = this.portalKeys.find((k) => k.status === "active");
    if (!a) throw new Error("fake bridge: no active Portal key");
    return a.key;
  }

  issueEnrolCode(ins: InstanceId, svc?: string): string {
    const code = opaqueValue("tbe_");
    this.enrolCodes.set(opaqueDigest(code), { ins, ...(svc ? { svc } : {}), exp: nowS() + 86400, used: false });
    return code;
  }

  /** Client that drives the app at `appUrl` like the bridge does (op calls, hooks, bridge ops, person launch). */
  client(appUrl: string): AppClient {
    return new AppClient(this, appUrl.replace(/\/$/, ""));
  }

  capture(p: Omit<CapturedPayload, "at">): void {
    if (this.captured.length < 20_000) this.captured.push({ ...p, at: Date.now() });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const w of this.#waiters) w();
    for (const w of this.#statusWaiters) w();
    await closeServer(this.#server);
  }

  // ── slice ─────────────────────────────────────────────────────────────────
  agentEntries(): InstanceSlice["agents"] {
    // v0.1.18 (C106a, Connect F21; L1): agent A carries the channel the owner chose at adopt for THIS product
    return this.ids.agents.map((a, i) => ({
      id: a.id,
      name: a.name,
      mode: a.mode,
      status: this.pause.agents.has(a.id) ? "paused" : "active",
      ...(i === 0 ? { scopeRequest: { product: this.manifest.id, kind: "connect_inbox" as const, createName: "conformance" } } : {}),
    }));
  }

  async companionGrants(): Promise<string[]> {
    const out: string[] = [];
    for (const c of this.manifest.companions ?? []) {
      out.push(
        await this.mint.grant({
          sub: `tb:ins:${this.ids.ins}`,
          aud: `tb:ins:${this.ids.peers[c.product]}`,
          crud: c.crud,
          mode: "bound",
          held: [...this.appsPolicy.held],
          caps: {},
          wf: c.operations,
        }),
      );
    }
    return out;
  }

  /**
   * CONF-MULTIAPP: a companion grant of this app for the companion `product`, minted exactly as the slice's own (sub self,
   * aud the target instance, mode bound, held = the workspace apps policy, wf = the declared ops); `over` changes `wf` /
   * `crud` / `aud` for the negative cases (a crud beyond the grant, another instance); `op` picks the companion entry that lists it.
   */
  companionGrantFor(product: string, over: { op?: string; wf?: string[]; crud?: CrudAction[]; aud?: InstanceId; prd?: string } = {}): Promise<string> {
    const c = (this.manifest.companions ?? []).find((x) => x.product === product && (over.op === undefined || x.operations.includes(over.op)));
    const aud = over.aud ?? this.ids.peers[product];
    if (!c || !aud) throw new Error(`fake bridge: ${this.manifest.id} declares no companion ${product}`);
    return this.mint.grant({ sub: `tb:ins:${this.ids.ins}`, aud: `tb:ins:${aud}`, crud: over.crud ?? c.crud, mode: "bound", held: [...this.appsPolicy.held], caps: {}, wf: over.wf ?? c.operations, ...(over.prd !== undefined ? { prd: over.prd } : {}) });
  }

  /** Signs a new slice (`rev` + 1) with the active Portal key and wakes the status long-polls. */
  async rebuildSlice(): Promise<number> {
    // the revision and the signed slice change together (after the async sign): a long-poll that wakes or times out
    // meanwhile must never answer the old slice under the new revision (race seen in slower CI runners)
    const rev = this.sliceRev + 1;
    const now = nowS();
    const over = this.sliceOverride;
    this.sliceOverride = null;
    const portalKeySet = over && "portalKeySet" in over ? over.portalKeySet : this.keySet.on ? this.keySet.kss : null;
    this.revoked = this.revoked.filter((r) => r.exp > now);
    const body = {
      v: 1 as const,
      iss: "tb:portal" as const,
      sub: `tb:ins:${this.ids.ins}` as const,
      aud: `tb:ins:${this.ids.ins}` as const,
      iat: over?.iat ?? now,
      ws: this.ids.ws,
      rev,
      ins: this.ids.ins,
      product: this.manifest.id,
      portalKeys: [...this.portalKeys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })), ...(over?.extraPortalKeys ?? [])],
      ...(portalKeySet ? { portalKeySet } : {}),
      bridge: { id: this.ids.bridge, keys: this.bridgeKeys.slice(0, 4).map((k) => k.publicJwk), ...(this.bridgeCaps !== undefined ? { caps: [...this.bridgeCaps] as string[] } : {}) },
      pause: { workspace: this.pause.workspace, agents: [...this.pause.agents], instances: [...this.pause.instances] },
      revoked: { jtis: this.revoked.map((r) => ({ jti: r.jti, exp: r.exp })) },
      personNbf: this.personNbf,
      grants: await this.companionGrants(),
      agents: this.agentEntries(),
      // the shared slice shape (spec 0.1.15 InstanceSlice): one companionTargets entry per companion grant (C90), the
      // listed inbound callers (C102) and the workspace apps policy (C105a)
      companionTargets: (this.manifest.companions ?? []).filter((c) => this.ids.peers[c.product]).map((c) => ({ product: c.product, ins: this.ids.peers[c.product] })),
      companionCallers: this.companionCallers.map((x) => ({ ...x })),
      appsPolicy: { held: [...this.appsPolicy.held] },
      ...(this.appCallers ? { appCallers: this.appCallers } : {}),
    };
    for (const g of body.grants) this.sliceGrants.add(g);
    const signedSlice = await signSlice(body, over?.signer ?? this.activePortalKey());
    this.slice = signedSlice;
    this.sliceRev = rev;
    this.wake();
    return rev;
  }

  wake(): void {
    for (const w of [...this.#waiters]) w();
  }

  /** Resolves when `pred` holds for a recorded status push (checked on every push) or rejects after `timeoutMs`. */
  waitForStatus(pred: (s: StatusSeen) => boolean, timeoutMs: number): Promise<StatusSeen> {
    const hit = this.statuses.findLast(pred);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      const done = () => {
        const s = this.statuses.findLast(pred);
        if (s) {
          clearTimeout(t);
          this.#statusWaiters.delete(done);
          resolve(s);
        } else if (this.#closed) {
          clearTimeout(t);
          this.#statusWaiters.delete(done);
          reject(new Error("fake bridge closed"));
        }
      };
      const t = setTimeout(() => {
        this.#statusWaiters.delete(done);
        reject(new Error(`timeout after ${timeoutMs} ms waiting for an app status push`));
      }, timeoutMs);
      this.#statusWaiters.add(done);
    });
  }

  /** Resolves with the latest claim (at once if one was seen) or rejects after `timeoutMs`. */
  waitForClaim(timeoutMs: number): Promise<ClaimSeen> {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve, reject) => {
      const tick = () => {
        const c = this.claims.at(-1);
        if (c) return resolve(c);
        if (this.#closed || Date.now() > deadline) return reject(new Error(`no claim within ${timeoutMs} ms`));
        setTimeout(tick, 50).unref();
      };
      tick();
    });
  }

  // ── HTTP ──────────────────────────────────────────────────────────────────
  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const pathAndQuery = req.url ?? "/";
    const path = pathAndQuery.split("?")[0];
    let raw: Buffer = Buffer.alloc(0);
    try {
      raw = await readRaw(req);
      this.capture({ dir: "bridge-in", method: req.method ?? "GET", path: pathAndQuery, headers: flatHeaders(req), body: raw.toString("utf8") });
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.claim) return await this.#claim(raw, res);
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.status) return await this.#status(req, pathAndQuery, raw, res);
      if (req.method === "GET" && path.startsWith("/tb/v1/keys/")) return this.#keys(req, pathAndQuery, path, res);
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.call) return await this.#call(req, pathAndQuery, raw, res);
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.events) return this.#ingest(req, pathAndQuery, raw, res);
      if (path === "/mcp") return this.#mcp(req, raw, res);
      if (req.method === "GET" && path === BRIDGE_INTERNAL_PATHS.metrics) {
        res.writeHead(200, { "content-type": "text/plain" });
        return void res.end(`tb_fake_bridge_requests_total ${this.captured.filter((c) => c.dir === "bridge-in").length}\n`);
      }
      throw new HttpError(404, "not_found", "no such route");
    } catch (e) {
      const err = e instanceof HttpError ? e : new HttpError(500, "internal", "fake bridge error");
      if (err.status !== 404 && path !== BRIDGE_INTERNAL_PATHS.status) this.violations.push({ route: path, code: err.code, detail: err.message, at: Date.now() });
      sendError(res, err.status, err.code, err.message);
    }
  }

  /** TB-Assert check (CREDENTIALS §10): `kid` ∈ claimed keys for (ins, svc), htm/htu/bd bound, ≤ 60 s, replay set. */
  #verifyInstance(req: IncomingMessage, pathAndQuery: string, raw: Buffer): { ins: InstanceId; svc?: string; iat: number; exp: number; kid: string } {
    const token = header(req, BRIDGE_HEADERS.assertion) ?? "";
    const c = peek(token);
    const iss = typeof c?.iss === "string" ? c.iss : "";
    const ins = iss.startsWith("tb:ins:") ? (iss.slice(7) as InstanceId) : null;
    const svc = typeof c?.svc === "string" ? c.svc : undefined;
    const jwk = ins ? this.instanceKeys.get(svc ? `${ins}/${svc}` : ins) : undefined;
    if (!ins || !jwk) throw new HttpError(401, "unauthenticated", "instance assertion missing or key unknown");
    const r = verifyAssertion(token, keySetFrom({ keys: [jwk] }, `tb:ins:${ins}`), {
      typ: TYP.instanceAssertion,
      aud: `tb:brg:${this.ids.bridge}`,
      now: nowS(),
      method: req.method ?? "GET",
      pathAndQuery,
      body: raw.length > 0 ? new Uint8Array(raw) : undefined,
      replay: this.#replay,
    });
    if (!r.ok) throw new HttpError(401, "unauthenticated", `instance assertion refused (${r.reason})`);
    return { ins, ...(svc ? { svc } : {}), iat: r.claims.iat, exp: r.claims.exp, kid: r.header.kid };
  }

  /** conformance 0.1.28 (BRIDGE §14.1): `POST /tb/v1/events` from the claimed APP instance (a companion service → 403). */
  #ingest(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse): void {
    const who = this.#verifyInstance(req, pathAndQuery, raw);
    if (who.svc) throw new HttpError(403, "forbidden", "a companion service sends no events");
    if (raw.length > 512 * 1024) throw new HttpError(413, "payload_too_large", "ingest body over 512 KiB");
    const b = parseJson(raw) as { items?: unknown } | undefined;
    const items = Array.isArray(b?.items) ? (b.items as Record<string, unknown>[]) : null;
    if (!items || items.length < 1 || items.length > 100) throw new HttpError(400, "input_invalid", "EventIngestBody {items: 1..100}");
    const fail = this.eventFailQueue.shift();
    this.eventPosts.push({ items, status: fail?.status ?? 200, at: Date.now() });
    if (fail) throw new HttpError(fail.status, fail.code, "event ingest refused by the control API");
    sendJson(res, 200, this.events.ingest(who.ins, this.manifest.id, items));
  }

  /**
   * conformance 0.1.28 (BRIDGE §14.3, fake only): the three `tealbrick/events/*` JSON-RPC methods on `POST /mcp`, and `GET /mcp` as
   * the SSE stream of `notifications/tealbrick/event` frames. FAKE authentication: `Authorization: Bearer <agent id>` of a slice
   * agent (a runtime under test talks to this fake with an agent id, never a real token).
   */
  #mcp(req: IncomingMessage, raw: Buffer, res: ServerResponse): void {
    const auth = header(req, "authorization") ?? "";
    const agent = auth.startsWith("Bearer ") ? (auth.slice(7).trim() as AgentId) : null;
    if (!agent || !this.ids.agents.some((a) => a.id === agent)) throw new HttpError(401, "unauthenticated", "fake /mcp: Bearer <slice agent id>");
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
      const frame = (e: unknown) => {
        const ev = e as { id: string };
        res.write(`id: ${ev.id}\ndata: ${JSON.stringify({ jsonrpc: "2.0", method: "notifications/tealbrick/event", params: { event: e } })}\n\n`);
      };
      const last = header(req, "last-event-id");
      const backlog = this.events.poll(agent, last, 100);
      if (!("error" in backlog)) for (const e of backlog.events) frame(e);
      const off = this.events.subscribe(agent, frame);
      req.once("close", off);
      return;
    }
    const msg = parseJson(raw) as { id?: unknown; method?: unknown; params?: unknown } | undefined;
    const id = msg?.id ?? null;
    const r = typeof msg?.method === "string" ? this.events.rpc(agent, [this.ids.ins], msg.method, msg.params) : null;
    sendJson(res, 200, r === null ? { jsonrpc: "2.0", id, error: { code: -32601, message: "method not found" } } : { jsonrpc: "2.0", id, ...r });
  }

  async #claim(raw: Buffer, res: ServerResponse): Promise<void> {
    const b = parseJson(raw) as Partial<ClaimRequest> | undefined;
    if (!b || typeof b.code !== "string" || typeof b.manifestDigest !== "string" || typeof b.sdkVersion !== "string" || typeof b.version !== "string") {
      throw new HttpError(400, "input_invalid", "ClaimRequest shape");
    }
    const d = opaqueDigest(b.code);
    let entry: { ins: InstanceId; svc?: string; exp: number; used: boolean } | undefined;
    for (const [k, v] of this.enrolCodes) if (digestEqual(k, d)) entry = v;
    if (!entry || entry.used || entry.exp < nowS()) throw new HttpError(403, "code_invalid", "enrolment code unknown, used or expired");
    if ((b.service ?? undefined) !== entry.svc) throw new HttpError(403, "code_invalid", "code bound to another target");
    let major = Number.NaN;
    try {
      major = sdkMajorOf(b.sdkVersion);
    } catch {
      throw new HttpError(400, "sdk_major_unsupported", "sdkVersion is not semver");
    }
    if (!this.sdkMajors.includes(major)) throw new HttpError(400, "sdk_major_unsupported", `SDK major ${major} not served`);
    if (b.manifestDigest !== this.expectedDigest) throw new HttpError(409, "manifest_mismatch", "manifestDigest differs from the deployed manifest");
    try {
      assertPublicJwk(b.instancePublicKey);
    } catch {
      throw new HttpError(400, "input_invalid", "instancePublicKey is not an Ed25519 public JWK");
    }
    entry.used = true;
    const slot = entry.svc ? `${entry.ins}/${entry.svc}` : entry.ins;
    this.claims.push({ request: b as ClaimRequest, codeDigest: d, at: Date.now() });
    if (this.#opts.deferBinding) this.pending.set(slot, b.instancePublicKey as Ed25519PublicJwk);
    else this.instanceKeys.set(slot, b.instancePublicKey as Ed25519PublicJwk);
    const body: ClaimResponse = {
      ins: entry.ins,
      bridge: { id: this.ids.bridge, publicKey: this.bridgeKeys[0].publicJwk, internalUrl: this.url },
      ...(this.#opts.deferBinding || !this.slice ? {} : { slice: this.slice }),
    };
    sendJson(res, 200, body);
  }

  async #status(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse): Promise<void> {
    const who = this.#verifyInstance(req, pathAndQuery, raw);
    const s = parseJson(raw) as Partial<AppStatus> | undefined;
    const nums = ["scopesRev", "sliceRevision", "keysRev", "pendingHolds"] as const;
    if (!s || !["ready", "needs_keys", "degraded"].includes(String(s.readiness)) || nums.some((k) => !Number.isInteger(s[k]))) {
      throw new HttpError(400, "input_invalid", "AppStatus shape");
    }
    this.statuses.push({ status: s as AppStatus, ins: who.ins, assertion: { iat: who.iat, exp: who.exp, kid: who.kid }, at: Date.now() });
    for (const w of [...this.#statusWaiters]) w();
    const wait = Math.max(0, Math.min(this.#opts.maxWaitS ?? 60, Number(new URL(pathAndQuery, "http://x").searchParams.get("wait") ?? "0") || 0));
    const changed = () => this.slice !== null && (s.sliceRevision !== this.sliceRev || s.keysRev !== this.keysRev);
    if (!changed() && wait > 0 && !this.#closed) {
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
    if (changed() && this.slice) {
      const body: AppStatusResponse = { slice: this.slice, sliceRevision: this.sliceRev, keysRev: this.keysRev };
      return sendJson(res, 200, body);
    }
    res.writeHead(204).end();
  }

  #keys(req: IncomingMessage, pathAndQuery: string, path: string, res: ServerResponse): void {
    const who = this.#verifyInstance(req, pathAndQuery, Buffer.alloc(0));
    const name = decodeURIComponent(path.slice("/tb/v1/keys/".length));
    if (this.pause.workspace || this.pause.instances.has(who.ins)) throw new HttpError(403, "paused", "workspace or instance paused");
    const declared = (this.manifest.settings?.keys ?? []).find((k) => k.name === name && k.source === "account_default" && k.usedBy.includes(who.svc ?? "app"));
    if (!declared) throw new HttpError(403, "key_not_declared", "key not declared for this caller");
    this.keyFetches.push({ name, ins: who.ins, at: Date.now() });
    const value = this.keyValues.get(name);
    if (value === undefined) throw new HttpError(404, "key_not_set", "key not set on the key page");
    const body: KeyFetchResponse = { name, value, keysRev: this.keysRev };
    sendJson(res, 200, body, { "cache-control": "no-store" });
  }

  async #call(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse): Promise<void> {
    let parsed: unknown = null;
    try {
      parsed = parseJson(raw);
    } catch {
      // recorded with a null envelope; #callInner refuses it
    }
    const attempt = {
      envelope: parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Partial<CallEnvelope>) : null,
      caller: null as InstanceId | null,
      grant: header(req, BRIDGE_HEADERS.companionGrant) ?? "",
      code: null as string | null,
      status: 200,
      at: Date.now(),
    };
    this.callAttempts.push(attempt);
    try {
      await this.#callInner(req, pathAndQuery, raw, res, (ins) => {
        attempt.caller = ins;
      });
    } catch (e) {
      attempt.code = e instanceof HttpError ? e.code : "internal";
      attempt.status = e instanceof HttpError ? e.status : 500;
      throw e;
    }
  }

  async #callInner(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse, asserted: (ins: InstanceId) => void): Promise<void> {
    const who = this.#verifyInstance(req, pathAndQuery, raw);
    asserted(who.ins);
    const env = parseJson(raw) as Partial<CallEnvelope> | undefined;
    if (!env || typeof env.target !== "string" || typeof env.op !== "string" || !("input" in env)) throw new HttpError(400, "input_invalid", "CallEnvelope shape");
    const target = this.ids.peers[env.target];
    const declared = (this.manifest.companions ?? []).find((c) => c.product === env.target);
    if (!target || !declared) throw new HttpError(404, "unknown_tool", "no such companion target");
    if (this.configExpired) throw new HttpError(503, "config_expired", "signed config older than 12 h");
    const grant = header(req, BRIDGE_HEADERS.companionGrant) ?? "";
    if (peek(grant)?.sub !== `tb:ins:${who.ins}`) throw new HttpError(403, "grant_invalid", "companion grant subject is not the asserting instance");
    const refuse = this.companionRefuseQueue.shift();
    if (refuse) {
      this.companionRefusals.push({ envelope: env as CallEnvelope, caller: who.ins, code: refuse.code, at: Date.now() });
      throw new HttpError(refuse.status, refuse.code, "companion call refused by the control API");
    }
    // CONF-MULTIAPP: a REAL peer app answers from its own manifest (the op's crud / audience / scope type decide gate())
    const real = this.peerTargets.get(env.target);
    const realOp = real?.ops.find((o) => o.id === env.op);
    if (real && !realOp) throw new HttpError(404, "unknown_tool", `the target app has no operation ${env.op}`);
    const op: OperationView = realOp ?? {
      standard: false,
      id: env.op,
      title: env.op,
      description: "companion target operation (fake)",
      crud: declared.crud,
      effect: "read",
      idempotency: "none",
      receipt: false,
      audience: "agent",
    };
    const g = gate({
      paused: { workspace: this.pause.workspace, agent: false, connection: false, instance: this.pause.instances.has(who.ins) || this.pause.instances.has(target) },
      grant,
      trust: {
        now: nowS(),
        self: `tb:ins:${target}`,
        ws: this.ids.ws,
        bridge: this.ids.bridge,
        issuers: keySetFromPortalKeys(this.portalKeys.map((k) => ({ jwk: k.key.publicJwk, status: k.status }))),
        bridgeKeys: keySetFrom({ keys: this.bridgeKeys.map((k) => k.publicJwk) }, `tb:brg:${this.ids.bridge}`),
        revokedJtis: new Set(this.revoked.map((r) => r.jti)),
      },
      op,
      declaredScopeTypes: real ? [...real.scopeTypes] : [],
    });
    if (g.decision === "refuse") throw new HttpError(403, g.reason, "refused by gate()");
    for (const h of this.hooks) {
      if (h.behaviour === "deny") throw new HttpError(403, "hook_denied", `${h.phase} hook denied the call`);
      if (h.behaviour === "timeout") await new Promise((r) => setTimeout(r, 2100));
      throw new HttpError(502, "hook_failed", `${h.phase} hook failed (fail closed)`);
    }
    if (real) {
      const r = await real.route({ envelope: env as CallEnvelope, caller: who.ins, grant });
      if (r.status !== 200 && r.status !== 202) {
        // the peer's refusal is relayed with its status and error code (the caller's callApp sees what the peer said)
        const e = (r.body as { error?: { code?: unknown; message?: unknown } } | null)?.error;
        throw new HttpError(r.status, typeof e?.code === "string" ? e.code : "peer_error", typeof e?.message === "string" ? e.message : `the target app answered ${r.status}`);
      }
      this.companionCalls.push({ envelope: env as CallEnvelope, caller: who.ins, answer: r.status, at: Date.now(), grant });
      return sendJson(res, r.status, r.body);
    }
    const answer = await this.companionResponder(env as CallEnvelope, who.ins);
    this.companionCalls.push({ envelope: env as CallEnvelope, caller: who.ins, answer: answer.status === "held" ? 202 : 200, at: Date.now(), grant });
    sendJson(res, answer.status === "held" ? 202 : 200, answer);
  }
}

function flatHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) out[k] = Array.isArray(v) ? v.join(", ") : v;
  return out;
}

/** Test control API (CONFORMANCE §3): pause, rotate, revoke, expire, set keys, inject hooks, wait for the app. */
export class FakeBridgeControl {
  readonly #b: FakeBridge;
  constructor(b: FakeBridge) {
    this.#b = b;
  }

  get sliceRevision(): number {
    return this.#b.sliceRev;
  }
  get keysRev(): number {
    return this.#b.keysRev;
  }

  /** Lists a deferred claim's key (Core binding) and publishes a new slice. */
  async bind(): Promise<number> {
    for (const [slot, jwk] of this.#b.pending) this.#b.instanceKeys.set(slot, jwk);
    this.#b.pending.clear();
    return this.#b.rebuildSlice();
  }
  issueEnrolCode(svc?: string): string {
    return this.#b.issueEnrolCode(this.#b.ids.ins, svc);
  }
  /**
   * v0.1.12 (A1.reclaim_on_new_code): Core dropped the instance key from config — every instance assertion of that
   * identity is refused 401 `unauthenticated` until a new claim binds a key. Returns a restore function.
   */
  forgetInstanceKey(svc?: string): () => void {
    const slot = svc ? `${this.#b.ids.ins}/${svc}` : this.#b.ids.ins;
    const jwk = this.#b.instanceKeys.get(slot);
    this.#b.instanceKeys.delete(slot);
    const window = { from: Date.now(), to: null as number | null };
    this.#b.forgotten.push(window);
    return () => {
      window.to = Date.now();
      if (jwk && !this.#b.instanceKeys.has(slot)) this.#b.instanceKeys.set(slot, jwk);
    };
  }
  pauseWorkspace(on: boolean): Promise<number> {
    this.#b.pause.workspace = on;
    return this.#b.rebuildSlice();
  }
  pauseAgent(agent: AgentId, on: boolean): Promise<number> {
    if (on) this.#b.pause.agents.add(agent);
    else this.#b.pause.agents.delete(agent);
    return this.#b.rebuildSlice();
  }
  pauseInstance(on: boolean, ins: InstanceId = this.#b.ids.ins): Promise<number> {
    if (on) this.#b.pause.instances.add(ins);
    else this.#b.pause.instances.delete(ins);
    return this.#b.rebuildSlice();
  }
  /** Withdraws a grant (or other jti) before its `exp` via slice `revoked.jtis`. */
  revokeJti(jti: string, exp: number): Promise<number> {
    this.#b.revoked.push({ jti, exp });
    return this.#b.rebuildSlice();
  }
  /** "Sign out everywhere": app UI sessions created before `at` become invalid. */
  setPersonNbf(at: number): Promise<number> {
    this.#b.personNbf = at;
    return this.#b.rebuildSlice();
  }
  republish(): Promise<number> {
    return this.#b.rebuildSlice();
  }
  /** v0.1.18 (A3.caps_count, SDK-02/SDK-04): a fresh agent (no usage yet) joins the slice; returns it and the new revision. */
  async addAgent(name: string, mode: AgentMode = "free"): Promise<{ agent: FakeAgent; rev: number }> {
    const agent: FakeAgent = { id: newId("agt") as AgentId, name, mode };
    this.#b.ids.agents.push(agent);
    return { agent, rev: await this.#b.rebuildSlice() };
  }
  /** Portal key rotation (CREDENTIALS §9.2): `announce` adds a pending key; `activate` makes it sign (old → retired); `retire` drops retired keys. */
  async rotatePortalKey(phase: "announce" | "activate" | "retire"): Promise<number> {
    const b = this.#b;
    if (phase === "announce") b.portalKeys.push({ key: await generateKeyPair(), status: "pending" });
    if (phase === "activate") {
      const next = b.portalKeys.find((k) => k.status === "pending");
      if (!next) throw new Error("no pending Portal key to activate");
      for (const k of b.portalKeys) if (k.status === "active") k.status = "retired";
      next.status = "active";
    }
    if (phase === "retire") b.portalKeys = b.portalKeys.filter((k) => k.status !== "retired");
    // v0.1.11: once statements are on, every rotation step is one statement (CREDENTIALS §9.5)
    if (b.keySet.on) await b.nextKeySet();
    return b.rebuildSlice();
  }
  /** v0.1.11: publishes the next key-set statement (`seq` + 1, current keys) in a new slice; turns statements on. */
  async publishKeySet(): Promise<number> {
    await this.#b.nextKeySet();
    return this.#b.rebuildSlice();
  }
  /** v0.1.11 compromise rotation: a fresh key replaces every Portal key in statement `seq` + 1; the slice carrying it is signed by `signWith` (default: the new key). */
  async compromisePortalKey(opts: { signWith?: Ed25519KeyPair } = {}): Promise<number> {
    const b = this.#b;
    b.portalKeys = [{ key: await generateKeyPair(), status: "active" }];
    await b.nextKeySet();
    if (opts.signWith) b.sliceOverride = { signer: opts.signWith };
    return b.rebuildSlice();
  }
  /** One slice with an override (A13 negatives); the next slice is normal again. */
  serveSlice(over: NonNullable<FakeBridge["sliceOverride"]>): Promise<number> {
    this.#b.sliceOverride = over;
    return this.#b.rebuildSlice();
  }
  /** Re-enrolment of the bridge: new bridge key signs proofs; `keepOld` keeps the old key in slice `bridge.keys`. */
  async rotateBridgeKey(opts: { keepOld?: boolean } = {}): Promise<number> {
    const b = this.#b;
    const next = await generateKeyPair();
    b.bridgeKeys = opts.keepOld ? [next, ...b.bridgeKeys].slice(0, 4) : [next];
    return b.rebuildSlice();
  }
  /** Key page write (BRIDGE §9.3): value stored, `keysRev` bumped, long-polls woken. */
  setKey(name: string, value: string): void {
    this.#b.keyValues.set(name, value);
    this.#b.keysRev++;
    this.#b.wake();
  }
  deleteKey(name: string): void {
    this.#b.keyValues.delete(name);
    this.#b.keysRev++;
    this.#b.wake();
  }
  setConfigExpired(on: boolean): void {
    this.#b.configExpired = on;
  }
  injectHook(phase: "before" | "context", behaviour: HookBehaviour): void {
    this.#b.hooks.push({ phase, behaviour });
  }
  clearHooks(): void {
    this.#b.hooks = [];
  }
  /** v0.1.14 (C102): lists an app caller in slice `companionCallers` and publishes the slice. */
  listCompanionCaller(caller: NonNullable<InstanceSlice["companionCallers"]>[number]): Promise<number> {
    this.#b.companionCallers = [...this.#b.companionCallers.filter((x) => x.ins !== caller.ins), caller];
    return this.#b.rebuildSlice();
  }
  /** spec 0.1.46 (GRANT-PRD): removes an app caller from slice `companionCallers` (the slice lags behind a new edge) and publishes the slice. */
  unlistCompanionCaller(ins: InstanceId): Promise<number> {
    this.#b.companionCallers = this.#b.companionCallers.filter((x) => x.ins !== ins);
    return this.#b.rebuildSlice();
  }
  /** conformance 0.1.28 (A-EV-4): the next `n` event ingest requests are refused with `status` (default 503 app_not_claimed). */
  failNextEvents(n: number, status = 503, code = "app_not_claimed"): void {
    for (let i = 0; i < n; i++) this.#b.eventFailQueue.push({ status, code });
  }
  /** conformance 0.1.28: every emit / purge item the fake answered 200 for, in arrival order (with the batch status). */
  eventItems(): { item: Record<string, unknown>; status: number; at: number }[] {
    return this.#b.eventPosts.flatMap((p) => p.items.map((item) => ({ item, status: p.status, at: p.at })));
  }
  /** spec 0.1.54 (C292): sets `bridge.caps` of the slice (`undefined` = the member is omitted) and publishes the slice. */
  setBridgeCaps(caps: readonly unknown[] | undefined): Promise<number> {
    this.#b.bridgeCaps = caps === undefined ? undefined : [...caps];
    return this.#b.rebuildSlice();
  }
  /**
   * spec 0.1.54 (C292, A22.bridge_caps_expired): publishes ONE slice that stays valid for only `secondsLeft` more seconds (its `iat` is
   * 12 h minus `secondsLeft` in the past, its `exp` is `iat` + 12 h, the slice lifetime), so a black-box suite can watch what an app
   * does once the slice it holds has expired. The next slice is normal again. Returns the revision and the `exp` (epoch seconds).
   */
  async publishShortLivedSlice(secondsLeft: number): Promise<{ rev: number; exp: number }> {
    const iat = nowS() - LIFETIME_S.configOrSlice + secondsLeft;
    this.#b.sliceOverride = { ...(this.#b.sliceOverride ?? {}), iat };
    return { rev: await this.#b.rebuildSlice(), exp: iat + LIFETIME_S.configOrSlice };
  }
  /** spec 0.1.49 (C261): sets (or clears, `null`) the slice flag `appCallers: "verified"` and publishes the slice. */
  setAppCallers(mode: "verified" | null): Promise<number> {
    this.#b.appCallers = mode;
    return this.#b.rebuildSlice();
  }
  /** v0.1.15 (C105a): sets the workspace apps policy (companion grant `held` + slice `appsPolicy`) and publishes the slice. */
  setAppsPolicy(held: readonly HoldFamily[]): Promise<number> {
    this.#b.appsPolicy = { held: [...held] };
    return this.#b.rebuildSlice();
  }
  setCompanionResponder(fn: CompanionResponder): void {
    this.#b.companionResponder = fn;
  }
  /** The next `refusals.length` companion calls (after the instance assertion and grant subject check) are refused in order. */
  refuseNextCompanionCalls(refusals: { status: number; code: string }[]): void {
    this.#b.companionRefuseQueue.push(...refusals);
  }
  waitForClaim(timeoutMs = 20_000): Promise<ClaimSeen> {
    return this.#b.waitForClaim(timeoutMs);
  }
  waitForStatus(pred: (s: StatusSeen) => boolean = () => true, timeoutMs = 20_000): Promise<StatusSeen> {
    return this.#b.waitForStatus(pred, timeoutMs);
  }
  /** Resolves once the app reports `sliceRevision ≥ rev` (i.e. it installed that slice). */
  waitForSliceRevision(rev: number, timeoutMs = 20_000): Promise<StatusSeen> {
    return this.#b.waitForStatus((s) => s.status.sliceRevision >= rev, timeoutMs);
  }
}

export async function createFakeBridge(opts: FakeBridgeOptions): Promise<FakeBridge> {
  return FakeBridge.create(opts);
}

export { Mint };
