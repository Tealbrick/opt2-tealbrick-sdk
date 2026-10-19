// Bridge target world (CONFORMANCE §2 "Bridge (deployed form)"): the fake Portal, fake apps generated from the
// example manifests (one per manifest plus a peer derived from its first companion declaration, so the companion,
// hook-order and dynamic-tool paths exist), the agents with key connections, the grants and the signed config /
// slices built from that state. Everything is derived from manifest data — no product id appears in this source.
import { randomBytes } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  activeKeyRequirements,
  DEFAULT_HELD_FAMILIES,
  digest,
  type Ed25519KeyPair,
  generateKeyPair,
  keySetFrom,
  keySetFromPortalKeys,
  opaqueDigest,
  opaqueValue,
  resolveSettings,
  type SettingValues,
  signKeySetStatement,
  signPairingCode,
  signSlice,
  signTicket,
  thumbprint,
  ulid,
  validateManifest,
} from "@opt2-tealbrick/manifest";
import type { AppEntry, EnrolCodeEntry, HookEntry, KeyRequirementEntry, SkillFile, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type BridgeId, type ConnectionId, type Ed25519PublicJwk, type FreeCaps, type InstanceId, type PersonId, type StandaloneState, TYP } from "@opt2-tealbrick/spec/credentials";
import type { AgentMode, CrudAction, HoldFamily, Manifest, Operation } from "@opt2-tealbrick/spec/manifest";
import type { KeySet } from "@opt2-tealbrick/spec/sdk";
import { FakeApp, type FakeAppWorld } from "./fake-app.ts";
import { FakePortal } from "./fake-portal.ts";
import { type AgentCapture, KeyAgent, OAuthAgent } from "./mcp-agent.ts";
import { Mint, newId, nowS, peek, rawSign } from "./tokens.ts";

export interface BridgeStartResult {
  /** public listener origin (MCP, OAuth, /a, /p, /keys, health) */
  publicUrl: string;
  /** internal listener origin (claim, status, keys, call) */
  internalUrl: string;
  stop(): Promise<void>;
}
export type BridgeStart = (env: Record<string, string>) => Promise<BridgeStartResult>;

export type AgentRole = "free" | "bound" | "none" | "revoked" | "pairing";
export interface WorldAgent {
  agt: AgentId;
  name: string;
  mode: AgentMode;
}

const ALL_CRUD: CrudAction[] = ["create", "read", "update", "delete"];
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Example manifests shipped with @opt2-tealbrick/spec (the bridge target's app fixtures). */
export function exampleManifests(): Manifest[] {
  const dir = dirname(fileURLToPath(import.meta.resolve("@opt2-tealbrick/spec/examples/notes.manifest.json".replace(/[^/]+$/, "x.json"))));
  return readdirSync(dir)
    .filter((f) => f.endsWith(".manifest.json"))
    .sort()
    .map((f) => JSON.parse(readFileSync(join(dir, f), "utf8")) as Manifest);
}

const peerOp = (id: string, crud: CrudAction[], audience: "agent" | "person"): Operation => ({
  id,
  title: `Generated ${id}`,
  description: "Generated conformance operation.",
  input: { type: "object", properties: { id: { type: "string" } } },
  output: { type: "object" },
  crud,
  effect: crud.includes("read") && crud.length === 1 ? "read" : "write",
  idempotency: crud.includes("create") ? "required" : crud.includes("read") && crud.length === 1 ? "none" : "supported",
  receipt: !(crud.includes("read") && crud.length === 1),
  audience,
});

/**
 * Peer app derived from `base.companions[0]`: id = the companion product, one agent op per companion op, a plain read
 * op outside the companion workflow, two person ops, a list-mode and a search-mode dynamic op, hooks in all three
 * phases (matching every product) and a companion edge back to a read op of `base`. Null when `base` has no companion.
 */
export function peerManifest(base: Manifest): Manifest | null {
  const comp = base.companions?.[0];
  const backOp = base.operations.find((o) => o.audience === "agent" && !o.dynamic && o.crud.length === 1 && o.crud[0] === "read");
  if (!comp || !backOp) return null;
  const m = structuredClone(base) as Manifest & Record<string, unknown>;
  m.id = comp.product;
  m.name = `${base.name} peer`;
  // C107 (B16.resolve_family): the search op admits outward / money resolutions (effectCeiling money), so the refusal
  // of a family-less one is the bridge's family rule, not its ceiling rule
  const dyn = (id: string, mode: "list" | "search"): Operation => ({
    id,
    title: `Generated ${id}`,
    description: "Generated dynamic operation.",
    crud: ["read"],
    effect: "read",
    idempotency: "supported",
    receipt: false,
    audience: "agent",
    dynamic: { mode, crudCeiling: ["read", "create"], effectCeiling: mode === "search" ? "money" : "write" },
  });
  m.operations = [
    ...comp.operations.map((id) => peerOp(id, comp.crud, "agent")),
    peerOp("peer_read", ["read"], "agent"),
    peerOp("peer_view", ["read"], "person"),
    peerOp("peer_admin", ["update"], "person"),
    dyn("catalog", "list"),
    dyn("lookup", "search"),
  ];
  m.hooks = [
    { id: "peer_before", title: "Generated before hook", phase: "before", order: base.hooks?.[0]?.order ?? 100, match: { products: ["*"] }, timeoutMs: 500 },
    { id: "peer_context", title: "Generated context hook", phase: "context", order: 10, match: { products: ["*"] }, timeoutMs: 500 },
    { id: "peer_after", title: "Generated after hook", phase: "after", order: 10, match: { products: ["*"] }, timeoutMs: 500 },
  ];
  m.companions = [{ product: base.id, operations: [backOp.id], crud: ["read"], purpose: "Generated companion edge back to the base app" }];
  delete m.unlocks;
  if (m.settings) m.settings = { ...m.settings, keys: [] };
  const v = validateManifest(m);
  return v.ok ? v.manifest : null;
}

/** Key names added by `withServiceKeys` (B19): one whose `when` holds for the deployed settings, one whose `when` is false. */
export const SERVICE_KEY_ON = "CONF_SERVICE_KEY_ON";
export const SERVICE_KEY_OFF = "CONF_SERVICE_KEY_OFF";

/**
 * Settings the world "deploys" for `m`: manifest defaults, every boolean on, and the first runtime service's own
 * `when` (so the service exists). Core resolves key `when`s against these (config keyRequirements); the bridge must
 * honour the same evaluation for a service's claim answer `serviceKeys` (B19).
 */
export function deployedSettings(m: Manifest): SettingValues {
  const provided: SettingValues = {};
  for (const f of (m.settings?.steps ?? []).flatMap((x) => x.fields)) if (f.type === "boolean") provided[f.key] = true;
  for (const [k, v] of Object.entries(m.runtime.services?.[0]?.when ?? {})) provided[k] = Array.isArray(v) ? v[0] : v;
  return resolveSettings(m, provided);
}

/**
 * `m` with two account_default keys used by its first runtime service (built, M-RT-6): SERVICE_KEY_ON (`when` = the
 * service's own condition, in force) and SERVICE_KEY_OFF (`when` = another choice of an enum setting, not in force).
 * Returns `m` unchanged when it has no service or no free enum setting.
 */
export function withServiceKeys(m: Manifest): Manifest {
  const svc = m.runtime.services?.[0];
  if (!svc) return m;
  const settings = deployedSettings(m);
  const used = new Set(Object.keys(svc.when ?? {}));
  const field = (m.settings?.steps ?? []).flatMap((x) => x.fields).find((f) => f.type === "enum" && !used.has(f.key) && (f.choices ?? []).some((ch) => ch.value !== settings[f.key]));
  const other = field?.choices?.find((ch) => ch.value !== settings[field.key])?.value;
  if (!field || other === undefined || !m.settings) return m;
  const out = structuredClone(m) as Manifest;
  const service = out.runtime.services?.[0] as unknown as { image?: string; build?: unknown };
  if (service.image !== undefined) {
    delete service.image;
    service.build = { context: ".", dockerfile: "Dockerfile" };
  }
  const key = (name: string, when: Record<string, unknown> | undefined) => ({
    name,
    label: `Generated ${name.toLowerCase()}`,
    provider: "Generated",
    required: true,
    source: "account_default" as const,
    usedBy: [svc.id],
    ...(when ? { when } : {}),
  });
  (out.settings as NonNullable<Manifest["settings"]>).keys = [...(m.settings.keys ?? []), key(SERVICE_KEY_ON, svc.when as Record<string, unknown> | undefined), key(SERVICE_KEY_OFF, { [field.key]: other })] as NonNullable<Manifest["settings"]>["keys"];
  const v = validateManifest(out);
  return v.ok ? v.manifest : m;
}

export interface WorldOptions {
  manifests?: Manifest[];
  /** v0.1.11: the bridge under test pins the world's TEST root pair (start module honours TBCONF_PORTAL_ROOT_KEYS); enrolment, configs and slices then carry `portalKeySet` */
  testRoots?: boolean;
}

/** The fake counterparts of one bridge run and the state the signed config is built from. */
export class BridgeWorld {
  readonly portal: FakePortal;
  readonly apps: FakeApp[] = [];
  /** primary app (first example manifest) and its generated peer */
  primary!: FakeApp;
  peer: FakeApp | null = null;
  readonly agents = {} as Record<AgentRole, WorldAgent>;
  readonly keyAgents = {} as Record<"free" | "free2" | "bound" | "none" | "revoked", KeyAgent>;
  readonly log: AgentCapture[] = [];
  readonly oauth: OAuthAgent;
  readonly person: PersonId = newId("per") as PersonId;
  readonly canary = `cnry${randomBytes(9).toString("hex")}`;
  readonly mint: Mint;
  readonly stranger: Ed25519KeyPair;
  /** agent grants by `${role}|${ins}` (compact JWS) */
  readonly grants = new Map<string, string>();
  /** companion grants by caller ins */
  readonly companionGrants = new Map<InstanceId, string>();
  /** v0.1.15 (C105a, CORE I8): workspace apps policy = `held` of every companion grant and slice `appsPolicy` (default imported) */
  appsPolicy: { held: HoldFamily[] } = { held: [...DEFAULT_HELD_FAMILIES] };
  /** live K4 grant specs, rebuilt into JWS by `publish()` */
  /** `held` overrides the agent card default (DEFAULT_HELD_FAMILIES); v0.1.17 (C108) it may name unknown families */
  /** agent grants the fake Portal mints into the config; `caps` (v0.1.19 C111a: applies in any mode) default {} */
  grantSpecs: { role: AgentRole; app: FakeApp; crud: CrudAction[]; mode: AgentMode; wf: string[]; held?: readonly string[]; caps?: FreeCaps }[] = [];
  /**
   * Owner switch for every hook (v0.1.24, C117): false → every config `hooks[]` entry carries `enabled: false` (the
   * owner switched them off; the bridge skips them). Core still LISTS every declared hook: a hook missing from the
   * config is refused (hook_failed), so "no hooks" is never modelled by dropping entries.
   */
  hooksOn = true;
  /**
   * v0.1.24 (C117, B27.hook_*): per config hook entry id (`<product>.<hookId>`): `absent` = left out of config
   * `hooks[]` (the S1 fault: Core dropped a declared hook), `disabled` = listed with `enabled: false`.
   */
  readonly hookState = new Map<string, "absent" | "disabled">();
  enrolCodes: EnrolCodeEntry[] = [];
  claimCode = "";
  standalone: (StandaloneState & { ownerKey: Ed25519KeyPair; owner: PersonId }) | null = null;
  bridge: BridgeStartResult | null = null;
  env: Record<string, string> = {};
  #seq = 0;
  #sliceRev = 0;
  /** v0.1.11 (C62/C63): TEST Portal Root Key pair; statements are emitted only when `testRoots` */
  readonly root!: Ed25519KeyPair;
  testRoots = false;
  /** current statement: `seq`, the JWS and the key list it signs (re-signed by publish() when the Portal keys change) */
  keySet: { seq: number; jws: string; keys: string } | null = null;
  /** per-instance overrides of the config `apps[]` entry (BSD-07 checks: foreign internalUrl, missing ownInfra) */
  readonly appOverrides = new Map<InstanceId, Record<string, unknown>>();
  /** C91 (group real_app): port reserved for the real SDK app at boot, so its origin is on TB_OWN_INFRA_ORIGINS */
  realAppPort: number | null = null;
  /**
   * C91: the real SDK app slot. `listed`: in config apps[] with a slice and a free-agent grant; `jwk`: its instance key,
   * bound (config instanceKeys) once the bridge reported its claim — as Core binds a claimed key.
   */
  realApp: { ins: InstanceId; manifest: Manifest; digest: string; url: string; jwk: Ed25519PublicJwk | null; listed: boolean } | null = null;

  private constructor(portal: FakePortal, stranger: Ed25519KeyPair) {
    this.portal = portal;
    this.stranger = stranger;
    this.oauth = new OAuthAgent(() => this.publicUrl, this.log, () => this.advertisedUrl);
    this.mint = new Mint({ ws: portal.ws, bridge: portal.bridgeId, portalKey: () => portal.activeKey(), bridgeKey: () => stranger, stranger });
  }

  static async create(o: WorldOptions = {}): Promise<BridgeWorld> {
    const w = new BridgeWorld(await FakePortal.create({ maxWaitS: 60 }), await generateKeyPair());
    (w as { root: Ed25519KeyPair }).root = await generateKeyPair();
    w.testRoots = o.testRoots === true;
    if (w.testRoots) {
      await w.ensureKeySet();
      w.portal.keySetSource = () => w.ensureKeySet();
    }
    const manifests = o.manifests ?? exampleManifests();
    if (manifests.length === 0) throw new Error("bridge target: no example manifests");
    const adapter = w.#adapter();
    for (const [i, m] of manifests.entries()) {
      const app = await FakeApp.create(i === 0 ? withServiceKeys(m) : m, adapter);
      app.marker = w.canary;
      w.apps.push(app);
    }
    w.primary = w.apps[0] as FakeApp;
    const peer = peerManifest(w.primary.manifest);
    if (peer && !w.apps.some((a) => a.product === peer.id)) {
      w.peer = await FakeApp.create(peer, adapter);
      w.peer.marker = w.canary;
      w.apps.push(w.peer);
    }
    await w.#agents();
    return w;
  }

  get ws() {
    return this.portal.ws;
  }
  get bridgeId(): BridgeId {
    return this.portal.bridgeId;
  }
  /** origin the suite connects to (the public listener) */
  get publicUrl(): string {
    return this.bridge?.publicUrl ?? this.env.TB_PUBLIC_URL ?? "";
  }
  /** the bridge's advertised public origin (TB_PUBLIC_URL: https, TLS terminated in front of the listener) */
  get advertisedUrl(): string {
    return this.env.TB_PUBLIC_URL ?? this.publicUrl;
  }
  /** advertised keys origin (TB_KEYS_PUBLIC_URL, BRIDGE §3.1 v0.1.10 / C59); "" when unset */
  get keysAdvertisedUrl(): string {
    return this.env.TB_KEYS_PUBLIC_URL ?? "";
  }
  /** origin the suite connects to for the key page: the public listener reached under the keys host name, so the
   * request `Host` is the keys origin's host name (fetch derives `Host` from the URL and never lets a caller set it) */
  get keysUrl(): string {
    const adv = this.keysAdvertisedUrl;
    if (!adv || !this.publicUrl) return "";
    const u = new URL(this.publicUrl);
    u.hostname = new URL(adv).hostname;
    return u.origin;
  }
  get internalUrl(): string {
    return this.bridge?.internalUrl ?? "";
  }
  seqNow(): number {
    return this.#seq;
  }

  /** The enrolled bridge public key (latest enrolment). */
  bridgeJwk(): Ed25519PublicJwk | null {
    return this.portal.bridgeKey;
  }

  #adapter(): FakeAppWorld {
    return {
      ws: this.portal.ws,
      bridge: this.portal.bridgeId,
      issuers: (): KeySet => {
        const jwk = this.portal.bridgeKey;
        if (this.standalone && jwk) return keySetFrom({ keys: [jwk] }, `tb:brg:${this.portal.bridgeId}`);
        return keySetFromPortalKeys(this.portal.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })));
      },
      bridgeKeys: (): KeySet => {
        const jwk = this.portal.bridgeKey;
        return jwk ? keySetFrom({ keys: [jwk] }, `tb:brg:${this.portal.bridgeId}`) : { keys: [] };
      },
      revokedJtis: () => new Set(this.portal.revoked.map((r) => r.jti)),
      seq: () => ++this.#seq,
      bridgeInternalUrl: () => this.internalUrl,
    };
  }

  async #agents(): Promise<void> {
    const add = (role: AgentRole, name: string, mode: AgentMode) => {
      const a: WorldAgent = { agt: newId("agt") as AgentId, name, mode };
      this.agents[role] = a;
      this.portal.agents.push(a);
    };
    add("free", "Conformance free agent", "free");
    add("bound", "Conformance bound agent", "bound");
    add("none", "Conformance agent without grants", "free");
    add("revoked", "Conformance agent to revoke", "free");
    add("pairing", "Conformance pairing agent", "free");
    const conn = async (slot: keyof BridgeWorld["keyAgents"], role: AgentRole) => {
      const key = await generateKeyPair();
      const con = newId("con") as ConnectionId;
      this.portal.connections.push({ con, agt: this.agents[role].agt, method: "key", gen: 1, publicKey: key.publicJwk, status: "active" });
      this.keyAgents[slot] = new KeyAgent({ agt: this.agents[role].agt, con, key, bridge: this.portal.bridgeId, publicUrl: () => this.publicUrl, log: this.log });
    };
    await conn("free", "free");
    await conn("free2", "free");
    await conn("bound", "bound");
    await conn("none", "none");
    await conn("revoked", "revoked");
    const p = this.primary;
    const firstRead = p.manifest.operations.find((o) => o.audience === "agent" && !o.dynamic && o.crud.length === 1 && o.crud[0] === "read");
    this.grantSpecs = [
      { role: "free", app: p, crud: ["read", "create", "update"], mode: "free", wf: [] },
      { role: "bound", app: p, crud: [...ALL_CRUD], mode: "bound", wf: firstRead ? [firstRead.id] : [] },
      { role: "revoked", app: p, crud: ["read"], mode: "free", wf: [] },
      { role: "pairing", app: p, crud: ["read"], mode: "free", wf: [] },
    ];
    if (this.peer) this.grantSpecs.push({ role: "free", app: this.peer, crud: [...ALL_CRUD], mode: "free", wf: [] });
  }

  /** Public JWKs of the TEST root pair (value of TBCONF_PORTAL_ROOT_KEYS). */
  testRootJwks(): Ed25519PublicJwk[] {
    return [this.root.publicJwk];
  }

  /** Statement `seq` over `keys` (default: the fake Portal's keys) signed by `root` (default: the test root). */
  signKeySet(seq: number, keys = this.portal.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })), root: Ed25519KeyPair = this.root): Promise<string> {
    return signKeySetStatement({ iss: "tb:portal-root", aud: "tb:portal-keys", seq, iat: nowS(), keys }, root);
  }

  /** The current statement; a new one (`seq` + 1) whenever the fake Portal's key list changed since the last one. */
  async ensureKeySet(): Promise<string> {
    const keys = JSON.stringify(this.portal.keys.map((k) => [k.key.kid, k.status]));
    if (!this.keySet || this.keySet.keys !== keys) {
      const seq = (this.keySet?.seq ?? 0) + 1;
      this.keySet = { seq, jws: await this.signKeySet(seq), keys };
      // Core embeds the CURRENT statement in every enrolment response too (re-enrolment of a pinned bridge)
      if (this.testRoots) this.portal.enrolKeySet = this.keySet.jws;
    }
    return this.keySet.jws;
  }

  /** Origins of the fake apps (they run on the suite's own host: own infrastructure, BRIDGE §5.7). */
  ownInfraOrigins(): string[] {
    return [...this.apps.map((a) => new URL(a.url).origin), ...(this.realAppPort ? [`http://127.0.0.1:${this.realAppPort}`] : [])];
  }

  /** The current config grant JWS for (role, app). */
  grantFor(role: AgentRole, app: FakeApp): string | undefined {
    return this.grants.get(`${role}|${app.ins}`);
  }

  /**
   * Config `hooks[]` (BRIDGE v0.1.24, C117): EVERY declared hook of every deployed app (the fake apps and the listed real
   * SDK app) with `enabled` (the owner switch, true unless `hooksOn` is false or `hookState` says `disabled`); an entry
   * whose `hookState` is `absent` is left out.
   */
  hookEntries(): HookEntry[] {
    const out: HookEntry[] = [];
    const add = (ins: InstanceId, product: string, h: NonNullable<Manifest["hooks"]>[number]) => {
      const id = `${product}.${h.id}` as HookEntry["id"];
      const state = this.hookState.get(id);
      if (state === "absent") return;
      out.push({ id, ins, product: product as HookEntry["product"], hookId: h.id, phase: h.phase, order: h.order, timeoutMs: h.timeoutMs ?? 2000, match: h.match, enabled: this.hooksOn && state !== "disabled" });
    };
    for (const a of this.apps) for (const h of a.manifest.hooks ?? []) add(a.ins, a.product, h);
    // the listed real SDK app's hooks (B25.real_hook_hold: a REAL before hook answering a hold verdict)
    const real = this.realApp?.listed ? this.realApp : null;
    if (real) for (const h of real.manifest.hooks ?? []) add(real.ins, real.manifest.id, h);
    return out;
  }

  skillFiles(): SkillFile[] {
    const out: SkillFile[] = [];
    for (const a of this.apps)
      for (const s of a.manifest.skills ?? [])
        out.push({ product: a.product, id: s.id, title: s.title, content: `# ${s.title}\n\nAgent {{agent.name}} ({{agent.id}}) uses ${a.manifest.name}. Ref ${this.canary}.\n` });
    return out;
  }

  /** Core's view (BRIDGE §5.5): requirements whose `when` holds for the deployed settings. */
  keyRequirements(): KeyRequirementEntry[] {
    const out: KeyRequirementEntry[] = [];
    for (const a of this.apps)
      for (const k of activeKeyRequirements(a.manifest, deployedSettings(a.manifest)))
        out.push({ name: k.name, label: k.label, ...(k.provider ? { provider: k.provider } : {}), ins: a.ins, product: a.product, required: k.required, source: k.source, usedBy: [...k.usedBy] });
    return out;
  }

  /** A fresh one-time instance enrolment code (K6) for the primary app, listed in the next config. */
  newClaimCode(): string {
    this.claimCode = opaqueValue("tbe_");
    this.enrolCodes.push({ digest: opaqueDigest(this.claimCode), kind: "instance", ins: this.primary.ins, product: this.primary.product, exp: nowS() + 3600 });
    return this.claimCode;
  }

  /** A fresh one-time service enrolment code (K6, kind service) for the primary app's first runtime service. */
  newServiceCode(): { code: string; service: string } | null {
    const svc = this.primary.manifest.runtime.services?.[0];
    if (!svc) return null;
    const code = opaqueValue("tbe_");
    this.enrolCodes.push({ digest: opaqueDigest(code), kind: "service", ins: this.primary.ins, product: this.primary.product, service: svc.id, exp: nowS() + 3600 } as EnrolCodeEntry);
    return { code, service: svc.id };
  }

  /** Builds grants, slices and the config body from the current state and mints the next revision. */
  async publish(o: { iat?: number; standalone?: boolean } = {}): Promise<number> {
    const p = this.portal;
    const jwk = p.bridgeKey;
    if (!jwk) throw new Error("bridge not enrolled");
    const brg = `tb:brg:${p.bridgeId}` as const;
    const iat = o.iat ?? nowS();
    p.bridgePublicUrl = this.advertisedUrl || p.bridgePublicUrl;
    this.grants.clear();
    for (const g of this.grantSpecs) {
      // v0.1.15 (C105, L1): agent grants carry the agent card default held families (Core mints a new card's policy so)
      this.grants.set(`${g.role}|${g.app.ins}`, await this.mint.grant({ sub: `tb:agt:${this.agents[g.role].agt}`, aud: `tb:ins:${g.app.ins}`, crud: g.crud, mode: g.mode, held: [...(g.held ?? DEFAULT_HELD_FAMILIES)], ...(g.caps ? { caps: g.caps } : {}), wf: g.wf, iat: nowS() - 5 }));
    }
    const real = this.realApp?.listed ? this.realApp : null;
    if (real) this.grants.set(`free|${real.ins}`, await this.mint.grant({ sub: `tb:agt:${this.agents.free.agt}`, aud: `tb:ins:${real.ins}`, crud: [...ALL_CRUD], mode: "free", held: [...DEFAULT_HELD_FAMILIES], wf: [], iat: nowS() - 5 }));
    this.companionGrants.clear();
    // C85 (B26): the listed real SDK app gets the companion grant of its manifest edge too (app-initiated callApp)
    const callers: { ins: InstanceId; manifest: Manifest }[] = [...this.apps, ...(real ? [real] : [])];
    /** v0.1.14 (C90 / C102): per instance, the targets it holds a companion grant for and the callers that hold one to it */
    const targetsOf = new Map<string, { product: string; ins: InstanceId }[]>();
    const callersOf = new Map<string, { product: string; ins: InstanceId; name: string; provider: string }[]>();
    for (const caller of callers)
      for (const comp of caller.manifest.companions ?? []) {
        const target = this.apps.find((a) => a.product === comp.product);
        if (!target) continue;
        // CORE I8 (C105a): companion grants hold the workspace apps policy (default DEFAULT_HELD_FAMILIES, imported)
        this.companionGrants.set(caller.ins, await this.mint.grant({ sub: `tb:ins:${caller.ins}`, aud: `tb:ins:${target.ins}`, crud: comp.crud, mode: "bound", wf: comp.operations, held: [...this.appsPolicy.held] }));
        // one companionTargets entry per grant: the world keeps one companion grant per caller (its last edge)
        targetsOf.set(caller.ins, [{ product: target.product, ins: target.ins }]);
      }
    for (const caller of callers)
      for (const t of targetsOf.get(caller.ins) ?? []) {
        const list = callersOf.get(t.ins) ?? [];
        // spec 0.1.48 (SDK-COMPANION-CALLERS): `provider` = where the caller runs; the world alternates "railway" and "own_infra"
        callersOf.set(t.ins, [...list, { product: caller.manifest.id, ins: caller.ins, name: caller.manifest.name.slice(0, 80), provider: list.length % 2 === 0 ? "railway" : "own_infra" }]);
      }
    const portalKeys = o.standalone ? [] : p.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status }));
    // §9.5 Standalone: the FINAL Portal-signed document (the one that carries `standalone`) is verified under the KSS rule,
    // so it carries the current statement; only the later bridge-issued documents drop it (Lead · Bridge request, 0.1.8)
    const portalKeySet = this.testRoots && !this.standalone ? await this.ensureKeySet() : undefined;
    if (o.standalone && !this.standalone) {
      const ownerKey = await generateKeyPair();
      this.standalone = { issuer: brg, kid: thumbprint(jwk), ownerKeys: [ownerKey.publicJwk], ownerKey, owner: this.person };
    }
    const standalone = this.standalone ? { issuer: this.standalone.issuer, kid: this.standalone.kid, ownerKeys: this.standalone.ownerKeys } : undefined;
    const rev = ++this.#sliceRev;
    const pause = { workspace: p.pause.workspace, agents: [...p.pause.agents], instances: [...p.pause.instances] };
    const revoked = { jtis: p.revoked.map((r) => ({ jti: r.jti, exp: r.exp })) };
    const apps: AppEntry[] = [];
    const entries: { ins: InstanceId; product: string; manifest: Manifest; digest: string; url: string }[] = [...this.apps, ...(real ? [{ ...real, product: real.manifest.id }] : [])];
    for (const a of entries) {
      const slice = await signSlice(
        {
          v: 1,
          iss: "tb:portal",
          sub: `tb:ins:${a.ins}`,
          aud: `tb:ins:${a.ins}`,
          iat: nowS(),
          ws: p.ws,
          rev,
          ins: a.ins,
          product: a.product,
          portalKeys,
          ...(portalKeySet ? { portalKeySet } : {}),
          bridge: { id: p.bridgeId, keys: [jwk] },
          pause,
          revoked,
          personNbf: 0,
          grants: this.companionGrants.has(a.ins) ? [this.companionGrants.get(a.ins) as string] : [],
          agents: p.agents.map((x) => ({ id: x.agt, name: x.name, mode: x.mode, status: p.pause.agents.has(x.agt) ? ("paused" as const) : ("active" as const) })),
          ...(standalone ? { standalone } : {}),
          // the shared slice shape (spec 0.1.15 InstanceSlice): companionTargets (C90), companionCallers (C102), appsPolicy (C105a)
          companionTargets: targetsOf.get(a.ins) ?? [],
          companionCallers: callersOf.get(a.ins) ?? [],
          appsPolicy: { held: [...this.appsPolicy.held] },
        },
        p.activeKey(),
      );
      // BSD-07: the fake apps listen on the suite's host, so they are own-infrastructure entries the bridge accepts only
      // through its local TB_OWN_INFRA_ORIGINS allow-list (set by the runner)
      apps.push({
        ins: a.ins,
        product: a.product,
        version: a.manifest.version,
        sdkMajor: a.manifest.sdkMajor,
        manifestDigest: a.digest as AppEntry["manifestDigest"],
        internalUrl: new URL(a.url).origin,
        ownInfra: true,
        entitled: true,
        slice,
        ...(this.appOverrides.get(a.ins) ?? {}),
      } as AppEntry);
    }
    const files = this.skillFiles();
    const extra: Partial<Omit<WorkspaceConfig, "iat" | "exp" | "jti">> = {
      bridge: { id: p.bridgeId, publicUrl: this.advertisedUrl },
      portalKeys,
      ...(portalKeySet ? { portalKeySet } : {}),
      instanceKeys: [...this.apps.map((a) => ({ ins: a.ins, jwk: a.key.publicJwk })), ...(this.realApp?.jwk ? [{ ins: this.realApp.ins, jwk: this.realApp.jwk }] : [])],
      grants: [...this.grants.values()],
      apps,
      hooks: this.hookEntries(),
      skills: { digest: digest(files.map((f) => ({ ...f })) as never), files },
      keyRequirements: this.keyRequirements(),
      enrolCodes: this.enrolCodes,
      ...(standalone ? { standalone } : {}),
    };
    p.configExtra = extra;
    return p.mintRevision({ iat });
  }

  /** Revokes an agent the way Core does (CREDENTIALS §14): card, connections and grants gone, grant jtis revoked. */
  revokeAgent(role: AgentRole): void {
    const agt = this.agents[role].agt;
    const p = this.portal;
    for (const [k, jws] of this.grants) if (k.startsWith(`${role}|`)) p.revoked.push({ jti: String(peek(jws)?.jti ?? ""), exp: Number(peek(jws)?.exp ?? nowS() + 3600) });
    p.agents = p.agents.filter((a) => a.agt !== agt);
    p.connections = p.connections.filter((c) => c.agt !== agt);
    this.grantSpecs = this.grantSpecs.filter((g) => g.role !== role);
  }

  /**
   * Serves a config signed with `key` (default: the active Portal key) whose body is the current state with
   * `over` applied (B3 negatives: lower `rev`, foreign workspace / audience, expired, bad signature). Not acked.
   */
  async serveForged(over: { key?: Ed25519KeyPair; rev?: number; iat?: number; body?: Partial<WorkspaceConfig> }): Promise<number> {
    const p = this.portal;
    const iat = over.iat ?? nowS();
    const rev = over.rev ?? p.rev + 1;
    const key = over.key ?? p.activeKey();
    const body = { ...p.configBody(rev, iat), ...(over.body ?? {}), exp: iat + 43200, jti: ulid() };
    // raw signing on purpose: forged documents may break the claim rules signConfig enforces (sub ≠ aud)
    p.serveRaw(await rawSign({ alg: "EdDSA", typ: TYP.config, kid: thumbprint(key.publicJwk) }, body, key));
    return rev;
  }

  /** Waits until the fake Portal received an ack (status report) with `rev` ≥ the given revision. */
  async waitAck(rev: number, ms: number): Promise<boolean> {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (this.portal.acks.some((a) => a.rev >= rev)) return true;
      await sleep(100);
    }
    return false;
  }

  /** publish() and wait for the bridge's ack of that revision. */
  async apply(ms: number, o: Parameters<BridgeWorld["publish"]>[0] = {}): Promise<number> {
    const rev = await this.publish(o);
    await this.waitAck(rev, ms);
    return rev;
  }

  keysTicket(over: { iat?: number; aud?: string; key?: Ed25519KeyPair; pur?: "launch" | "keys" } = {}): Promise<string> {
    const aud = (over.aud ?? `tb:brg:${this.bridgeId}`) as `tb:brg:${BridgeId}`;
    return signTicket({ iss: "tb:portal", sub: `tb:per:${this.person}`, aud, ws: this.ws, pur: "keys", iat: over.iat ?? nowS() }, over.key ?? this.portal.activeKey());
  }

  launchTicket(app: FakeApp, over: { key?: Ed25519KeyPair } = {}): Promise<string> {
    return this.mint.launchTicket({ person: this.person, aud: `tb:ins:${app.ins}`, ...(over.key ? { key: over.key } : {}) });
  }

  pairingCode(role: AgentRole, over: { rid?: string; iat?: number; key?: Ed25519KeyPair; aud?: string } = {}): Promise<string> {
    return signPairingCode(
      {
        iss: "tb:portal",
        sub: `tb:agt:${this.agents[role].agt}`,
        aud: (over.aud ?? `tb:brg:${this.bridgeId}`) as `tb:brg:${BridgeId}`,
        ws: this.ws,
        ...(over.rid !== undefined ? { rid: over.rid } : {}),
        iat: over.iat ?? nowS(),
      },
      over.key ?? this.portal.activeKey(),
    );
  }

  async close(): Promise<void> {
    await Promise.all(this.apps.map((a) => a.close()));
    await this.portal.close();
  }
}

export type { InstanceId };
