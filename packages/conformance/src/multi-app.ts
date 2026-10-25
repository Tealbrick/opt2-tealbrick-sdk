// CONF-MULTIAPP (conformance 0.1.20, group X): the app under test runs next to REAL peer apps (released SDK apps from the
// signed release index, see peer-source.ts). Every real app has its own fake bridge (own claim, slice and status long-poll)
// but they all JOIN ONE WORLD: the same workspace, bridge id, Portal keys, bridge keys and test root, so a companion grant
// minted for app A verifies at peer P, and the proof the bridge signs for P verifies there. The fake bridge of the caller
// routes `POST /tb/v1/call` to the real callee (FakeBridge.peerTargets) exactly as Core's bridge would: it checks the caller's
// assertion and the companion grant with gate(), then calls the callee's `/tb/v1/ops/<op>` with that grant and a fresh call
// proof (AppClient.callOp) and relays the callee's answer (ok, held, or the refusal and its code).
// The checks are rows per peer (X1) and per declared companion op (X2..X5), see checks/catalog.ts PEER_CHECK_BASES.
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { ulid, validateAgainstSchema, withStandardOps } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Manifest, Operation, ProductId } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import type { AppClient, OpAnswer, OpTamper, PersonSession } from "./app-client.ts";
import { createFakeBridge, type FakeBridge, type PeerRoute } from "./fake-bridge.ts";
import { forkStart } from "./fork-start.ts";
import { errorCode, request } from "./http.ts";
import { listPersonPages } from "./list-pages.ts";
import { fetchVerifiedIndex, type LoadedPeer, loadPeer, type PeerSourceOptions } from "./peer-source.ts";
import { sampleInput } from "./sample.ts";
import { bad, notRun, ok, type Suite, verdict } from "./suite.ts";
import { newId } from "./tokens.ts";
import type { ConformanceConfig, PeerSpec } from "./waivers.ts";

/** Harness-only env name: the peer's `settings` from tealbrick-conformance.json as JSON (read only by the peer's start module). */
export const PEER_SETTINGS_ENV = "TBCONF_PEER_SETTINGS";
/** A decoy app caller listed first in every peer's `companionCallers` under the SAME name as the app under test (X2). */
export const DECOY_PRODUCT = "tbconf-decoy";

/** What runApp hands the X group (run-app.ts passes its own helpers: no import cycle). */
export interface MultiAppDeps {
  appEnv(bridge: FakeBridge, dataDir: string, extra?: Record<string, string>): Record<string, string>;
  freeTcpPort(): Promise<number>;
  testRootsEnv: string;
  portEnv: string;
}

/** The app-under-test side of the X group (provided by the app checks, which own the input generation). */
export interface AppDriver {
  /** the app under test's current client */
  client(): AppClient;
  /** Runs the app's agent ops (generated or fixture inputs, nothing held) until `done()`; returns what it called. */
  drive(done: () => boolean): Promise<string[]>;
}

/** Loaded-or-failed peer, the result of the preparation phase (downloads and builds happen BEFORE the app checks). */
export type PreparedPeer = { spec: PeerSpec; peer: LoadedPeer } | { spec: PeerSpec; error: string };

/** Downloads / reuses / builds every peer (sequentially: one CI worker); a failure becomes that peer's X1 row, never an abort. */
export async function preparePeers(specs: readonly PeerSpec[], source: PeerSourceOptions, notes: string[]): Promise<PreparedPeer[]> {
  const out: PreparedPeer[] = [];
  // the index is fetched once for all peers
  let shared: readonly unknown[] | null = null;
  for (const spec of specs) {
    try {
      const index = source.index ?? (async () => (shared ??= await fetchVerifiedIndex()));
      const peer = await loadPeer(spec, { ...source, index });
      notes.push(`peer ${spec.product}@${spec.version} (${spec.channel}) ← ${peer.record.repo}@${peer.record.commit} (signed release index record)`);
      out.push({ spec, peer });
    } catch (e) {
      out.push({ spec, error: e instanceof Error ? e.message : String(e) });
    }
  }
  return out;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const rowId = (base: string, peer: string, op?: string) => (op ? `${base}.${peer}.${op}` : `${base}.${peer}`);
const answerOf = (a: { status: number; body: unknown }): string => {
  const code = errorCode(a.body);
  if (code) return `${a.status} ${code}`;
  if (isObj(a.body) && typeof a.body.status === "string") return `${a.status} ${a.body.status}${typeof a.body.holdId === "string" ? ` ${a.body.holdId}` : ""}`;
  return String(a.status);
};
const isOkBody = (a: { status: number; body: unknown }) => a.status === 200 && isObj(a.body) && a.body.status === "ok";
const isHeldBody = (a: { status: number; body: unknown }) => a.status === 202 && isObj(a.body) && a.body.status === "held" && typeof a.body.holdId === "string";
const sanitize = (s: string) => s.replace(/\s+/g, " ").slice(0, 300);

/** A real app of the world: the app under test or a booted peer. */
interface Member {
  manifest: Manifest;
  bridge: FakeBridge;
  ins: InstanceId;
  url(): string;
}
interface Peer extends Member {
  loaded: LoadedPeer;
  app: { url: string; stop(): Promise<void> } | null;
  dataDir: string;
}
/** One companion call that crossed the fake bridge between two real apps. */
interface RouteRecord {
  from: string;
  to: string;
  op: string;
  idempotencyKey: string | undefined;
  status: number;
  body: unknown;
  at: number;
}

/** True when `op` is held by the companion grant (CORE I8): effect money always, else its holdFamily is in the apps policy. */
function expectHeld(op: OperationView, held: readonly string[]): boolean {
  const family = (op as { holdFamily?: string }).holdFamily;
  return op.effect === "money" || (family !== undefined && held.includes(family));
}

export interface PeerChecksInput {
  suite: Suite;
  deps: MultiAppDeps;
  /** the app under test */
  app: { manifest: Manifest; bridge: FakeBridge; driver: AppDriver; timeoutMs: number };
  prepared: readonly PreparedPeer[];
  config: Pick<ConformanceConfig, "contractOps">;
  testRoots: boolean;
  notes: string[];
}

/** Runs the whole X group; stops the peers it started. Never throws. */
export async function runPeerChecks(inp: PeerChecksInput): Promise<void> {
  const world = new World(inp);
  try {
    await world.run();
  } finally {
    await world.stop();
  }
}

class World {
  readonly #i: PeerChecksInput;
  readonly #a: Member;
  readonly #peers: Peer[] = [];
  readonly #calls: RouteRecord[] = [];
  readonly #sessions = new Map<string, PersonSession | null>();
  readonly #T: number;

  constructor(inp: PeerChecksInput) {
    this.#i = inp;
    this.#T = inp.app.timeoutMs;
    this.#a = { manifest: inp.app.manifest, bridge: inp.app.bridge, ins: inp.app.bridge.ids.ins, url: () => inp.app.driver.client().url };
  }

  get #s(): Suite {
    return this.#i.suite;
  }

  async stop(): Promise<void> {
    for (const p of this.#peers) {
      await p.app?.stop().catch(() => undefined);
      await p.bridge.close().catch(() => undefined);
      rmSync(p.dataDir, { recursive: true, force: true });
    }
  }

  /** Companion ops the app under test declares on `product` (wildcard entries excluded), with the entry's crud. */
  #declared(product: string): { op: string; crud: CrudAction[] }[] {
    const out: { op: string; crud: CrudAction[] }[] = [];
    for (const c of this.#a.manifest.companions ?? []) if (c.product === product) for (const op of c.operations) if (!out.some((x) => x.op === op)) out.push({ op, crud: c.crud });
    return out;
  }

  async run(): Promise<void> {
    const { prepared } = this.#i;
    if (prepared.length === 0) return;
    if (!this.#i.testRoots) {
      for (const p of prepared) this.#s.record(rowId("X1.peer_boot", p.spec.product), "peer boots under the conformance env", "the peer claims through its own fake bridge", notRun("--no-test-roots: a released peer pins its build's Portal Root Keys and cannot boot against the fakes; run with test roots (the default)"));
      return;
    }
    if (await this.#wire()) await this.#boot();
    await this.#rows();
  }

  // ── wiring ────────────────────────────────────────────────────────────────

  async #wire(): Promise<boolean> {
    const a = this.#a;
    const members: Member[] = [a];
    const ins = new Map<string, InstanceId>([[a.manifest.id, a.ins]]);
    const loaded = this.#i.prepared.filter((p): p is { spec: PeerSpec; peer: LoadedPeer } => "peer" in p);
    for (const p of loaded) ins.set(p.spec.product, newId("ins") as InstanceId);
    const peerInstances = Object.fromEntries(ins);
    for (const p of loaded) {
      try {
        const bridge = await createFakeBridge({ manifest: p.peer.manifest, instanceId: ins.get(p.spec.product) as InstanceId, joinWorld: a.bridge, peerInstances });
        const peer: Peer = { loaded: p.peer, manifest: p.peer.manifest, bridge, ins: bridge.ids.ins, url: () => peer.app?.url ?? "", app: null, dataDir: mkdtempSync(join(tmpdir(), "tbconf-peer-")) };
        this.#peers.push(peer);
        members.push(peer);
      } catch (e) {
        this.#s.record(rowId("X1.peer_boot", p.spec.product), "peer boots under the conformance env", "the peer claims through its own fake bridge", bad(`could not create the peer's fake bridge: ${sanitize(String(e))}`));
      }
    }
    // a peer must be a companion of the app under test, or name it (CONF-MULTIAPP §2)
    for (const peer of [...this.#peers]) {
      const names = (m: Manifest, product: string) => (m.companions ?? []).some((c) => c.product === product);
      if (!names(a.manifest, peer.manifest.id) && !names(peer.manifest, a.manifest.id)) {
        this.#s.record(rowId("X1.peer_boot", peer.manifest.id), "peer boots under the conformance env", "the peer claims through its own fake bridge", bad(`peer ${peer.manifest.id} is neither named in ${a.manifest.id}'s companions[] nor names ${a.manifest.id} as a companion (CONF-MULTIAPP §2)`));
        await peer.bridge.close();
        rmSync(peer.dataDir, { recursive: true, force: true });
        this.#peers.splice(this.#peers.indexOf(peer), 1);
        members.splice(members.indexOf(peer), 1);
      }
    }
    // every ordered pair (X, Y): X names Y in companions[] → X's fake bridge routes to Y's real app and Y lists X as a caller
    for (const x of members) {
      for (const y of members) {
        if (x === y || !(x.manifest.companions ?? []).some((c) => c.product === y.manifest.id)) continue;
        x.bridge.ids.peers[y.manifest.id] = y.ins;
        const route: PeerRoute = async ({ envelope, caller, grant }) => {
          const answer = await y.bridge.client(y.url()).callOp(envelope.op, envelope.input as Json, { caller, grant, context: {}, ...(envelope.idempotencyKey ? { idempotencyKey: envelope.idempotencyKey } : {}) });
          this.#calls.push({ from: x.manifest.id, to: y.manifest.id, op: envelope.op, idempotencyKey: envelope.idempotencyKey, status: answer.status, body: answer.body, at: Date.now() });
          return { status: answer.status, body: answer.body };
        };
        x.bridge.peerTargets.set(y.manifest.id, { ops: withStandardOps(y.manifest), scopeTypes: (y.manifest.scopes ?? []).map((sc) => sc.type), route });
        y.bridge.companionCallers = [...y.bridge.companionCallers.filter((c) => c.ins !== x.ins), { product: x.manifest.id as ProductId, ins: x.ins, name: x.manifest.name }];
      }
    }
    // the decoy shares the app under test's NAME and is listed FIRST: a callee that finds the caller's product by name reports the decoy
    for (const peer of this.#peers) {
      if ((a.manifest.companions ?? []).some((c) => c.product === peer.manifest.id)) {
        peer.bridge.companionCallers = [{ product: DECOY_PRODUCT as ProductId, ins: newId("ins") as InstanceId, name: a.manifest.name }, ...peer.bridge.companionCallers];
      }
    }
    for (const peer of this.#peers) await peer.bridge.rebuildSlice();
    try {
      // the app under test gets the grants (aud = the real peer instances) and the callers listed by the peers that name it
      await a.bridge.control.waitForSliceRevision(await a.bridge.rebuildSlice(), this.#T);
    } catch (e) {
      const last = a.bridge.statuses.at(-1);
      for (const peer of this.#peers) this.#s.record(rowId("X1.peer_boot", peer.manifest.id), "peer boots under the conformance env", "the peer claims through its own fake bridge", bad(`the app under test did not install the slice that names its peers (${sanitize(String(e))}; slice revision served ${a.bridge.control.sliceRevision}, last status push reports ${last?.status.sliceRevision ?? "none"} ${last ? `${Date.now() - last.at} ms ago` : ""}, refusals ${a.bridge.violations.slice(-3).map((v) => v.code).join(",") || "none"})`));
      return false;
    }
    return true;
  }

  async #boot(): Promise<void> {
    const { deps } = this.#i;
    const settingsOf = (product: string) => this.#i.prepared.find((p) => p.spec.product === product)?.spec.settings;
    for (const peer of this.#peers) {
      const id = rowId("X1.peer_boot", peer.manifest.id);
      const title = "peer boots under the conformance env";
      const expected = "the real peer app starts with the suite env (fake bridge of its own, test roots, temp data dir), claims, installs its first slice and answers /tb/v1/health with its manifest digest";
      const bootMs = 90_000;
      await this.#s.run(id, title, expected, async () => {
        await peer.bridge.control.publishKeySet();
        const port = await deps.freeTcpPort();
        const settings = settingsOf(peer.manifest.id);
        const env = deps.appEnv(peer.bridge, peer.dataDir, {
          [deps.testRootsEnv]: JSON.stringify(peer.bridge.testRootJwks()),
          [deps.portEnv]: String(port),
          ...(settings ? { [PEER_SETTINGS_ENV]: JSON.stringify(settings) } : {}),
        });
        const start = forkStart<{ url: string; stop(): Promise<void> }>(peer.loaded.startModule, { cwd: peer.loaded.dir, inheritEnv: false, bootTimeoutMs: bootMs });
        let app: { url: string; stop(): Promise<void> };
        try {
          app = await start(env);
        } catch (e) {
          return bad(`${peer.manifest.id}@${peer.manifest.version} did not start: ${sanitize(String(e instanceof Error ? e.message : e))}${peer.loaded.spec.settings ? "" : " (a peer that needs a companion service must run in its stub mode: declare settings in tealbrick-conformance.json peers)"}`);
        }
        peer.app = app;
        try {
          await peer.bridge.control.waitForClaim(bootMs);
          await peer.bridge.control.waitForSliceRevision(1, bootMs);
        } catch (e) {
          return bad(`${peer.manifest.id}@${peer.manifest.version} started but did not claim and install its slice: ${sanitize(String(e))} (claims ${peer.bridge.claims.length}, refusals ${peer.bridge.violations.map((v) => v.code).join(",") || "none"})`);
        }
        const h = await request(`${app.url}/tb/v1/health`, { timeoutMs: 5000 }).catch((e: unknown) => ({ status: 0, body: String(e) as unknown }));
        const served = (h.body as { manifestDigest?: unknown } | null)?.manifestDigest;
        if (h.status !== 200 || served !== peer.bridge.expectedDigest) return bad(`${app.url} does not answer as ${peer.manifest.id} (GET /tb/v1/health → ${h.status}${served ? `, manifestDigest ${String(served)}` : ""})`);
        return ok(`${peer.manifest.id}@${peer.manifest.version} (${peer.loaded.record.repo}@${peer.loaded.record.commit.slice(0, 12)}) booted at ${app.url}; claimed through its own fake bridge, slice installed`);
      });
    }
  }

  // ── rows ─────────────────────────────────────────────────────────────────

  async #rows(): Promise<void> {
    const a = this.#a;
    const booted = (p: Peer) => this.#s.results.some((r) => r.id === rowId("X1.peer_boot", p.manifest.id) && r.status === "pass");
    // failed preparations → X1 rows
    for (const p of this.#i.prepared) {
      if ("error" in p) this.#s.record(rowId("X1.peer_boot", p.spec.product), "peer boots under the conformance env", "the peer is resolved from the signed release index, installed from its lockfile and started", bad(sanitize(p.error)));
    }
    const live = this.#peers.filter(booted);
    // drive the app under test: its agent ops make the real callApp calls
    const wanted = live.flatMap((p) => this.#declared(p.manifest.id).map((d) => `${p.manifest.id}.${d.op}`));
    let tried: string[] = [];
    if (wanted.length > 0) {
      const seen = () => wanted.every((w) => this.#calls.some((c) => c.from === a.manifest.id && `${c.to}.${c.op}` === w));
      tried = await this.#i.app.driver.drive(seen);
    }
    for (const p of this.#i.prepared) {
      const id = p.spec.product;
      const peer = this.#peers.find((x) => x.manifest.id === id);
      if (peer && booted(peer)) continue;
      // a peer that did not load or boot: its declared companion ops cannot be checked
      const ops = peer ? this.#declared(id) : [];
      for (const d of ops) {
        for (const base of ["X2.companion_call", "X3.companion_refused"] as const) this.#s.record(rowId(base, id, d.op), "companion op of a peer", "the peer boots first (X1)", bad(`peer ${id} is not running (${rowId("X1.peer_boot", id)})`));
      }
    }
    for (const peer of live) {
      for (const d of this.#declared(peer.manifest.id)) {
        await this.#x2(peer, d.op, tried);
        await this.#x3(peer, d.op);
      }
    }
    await this.#x4(live, tried);
    for (const peer of live) {
      for (const d of this.#declared(peer.manifest.id)) await this.#x5(peer, d.op);
    }
  }

  #viewOf(peer: Peer, op: string): OperationView | undefined {
    return withStandardOps(peer.manifest).find((o) => o.id === op);
  }

  async #session(peer: Peer): Promise<PersonSession | null> {
    const k = peer.manifest.id;
    if (!this.#sessions.has(k)) this.#sessions.set(k, await peer.bridge.client(peer.url()).signIn());
    return this.#sessions.get(k) ?? null;
  }

  /** The receipt row `rowId` of the peer (receipt or hold), or null. */
  async #receiptRow(peer: Peer, rowIdValue: string): Promise<Record<string, unknown> | null> {
    const sess = await this.#session(peer);
    if (!sess) return null;
    const r = await listPersonPages(peer.bridge.client(peer.url()), sess, "tb.receipts_list", (xs) => xs.some((x) => x.id === rowIdValue));
    return r.items.find((x) => x.id === rowIdValue) ?? null;
  }

  /** X2: the real callApp of the app under test crossed the fake bridge to the real peer. */
  async #x2(peer: Peer, op: string, tried: readonly string[]): Promise<void> {
    const a = this.#a;
    const id = rowId("X2.companion_call", peer.manifest.id, op);
    const view = this.#viewOf(peer, op);
    await this.#s.run(
      id,
      `real callApp ${a.manifest.id} → ${peer.manifest.id}.${op}`,
      `a real callApp of the app under test through the fake bridge reaches the real peer with its companion grant: the peer answers ok (or held when the op is held by the apps policy), and the peer's receipt names the VERIFIED caller app (caller.type app, caller.id = this instance, caller.product = ${a.manifest.id} from the signed companionCallers entry, never the decoy of the same name listed first)`,
      async () => {
        if (!view) return bad(`${peer.manifest.id}@${peer.manifest.version} has no operation ${op} (declared in ${a.manifest.id}'s companions[])`);
        const rec = this.#calls.find((c) => c.from === a.manifest.id && c.to === peer.manifest.id && c.op === op);
        if (!rec) {
          return notRun(`no operation of ${a.manifest.id} made this call with the generated inputs (tried ${tried.length}: ${tried.slice(0, 4).join("; ") || "no agent op"}); supply inputs for the op that calls ${peer.manifest.id}.${op} in tealbrick-conformance.json (a companion call from a person op or a job is not observable here)`);
        }
        const wantHeld = expectHeld(view, a.bridge.appsPolicy.held);
        const got = answerOf(rec);
        if (wantHeld ? !isHeldBody(rec) : !isOkBody(rec)) {
          const scoped = errorCode(rec.body) === "scope_denied" ? `; ${op} is a scoped op and the app caller holds no scope instance on the peer` : "";
          return bad(`${peer.manifest.id}.${op} answered ${got}, expected ${wantHeld ? "202 held (the op's hold family is in the workspace apps policy)" : "200 ok"}${scoped}`);
        }
        const body = rec.body as Record<string, unknown>;
        const row = wantHeld ? String(body.holdId) : typeof body.receiptId === "string" ? body.receiptId : null;
        if (row === null) return ok(`${peer.manifest.id}.${op} answered ${got}; the op writes no receipt, so the verified caller is not observable (read ops: nothing to check)`);
        const found = await this.#receiptRow(peer, row);
        if (!found) return bad(`${peer.manifest.id}.${op} answered ${got} but tb.receipts_list of the peer has no row ${row}`);
        const caller = isObj(found.caller) ? found.caller : {};
        const shown = `caller ${JSON.stringify({ type: caller.type, id: caller.id, product: caller.product })}`;
        if (caller.product === DECOY_PRODUCT) return bad(`${got}; ${shown}: the peer took the caller's product from its NAME (the decoy "${DECOY_PRODUCT}" has the same name and is listed first), not from the entry of the grant's caller instance`);
        const good = caller.type === "app" && caller.id === a.ins && caller.product === a.manifest.id;
        return verdict(good, `${peer.manifest.id}.${op} answered ${got} (idempotencyKey ${rec.idempotencyKey ? "sent" : "none"}); peer receipt ${row}: ${shown} (expected app, ${a.ins}, ${a.manifest.id})`);
      },
    );
  }

  /** The suite as the bridge: a call to the peer from the app under test's instance with `over` changed (negative cases). */
  async #asApp(peer: Peer, op: string, input: Json, opts: { grantOver?: { wf?: string[]; crud?: CrudAction[]; aud?: InstanceId }; tamper?: OpTamper; idempotencyKey?: string } = {}): Promise<OpAnswer> {
    const a = this.#a;
    const grant = await a.bridge.companionGrantFor(peer.manifest.id, { op, ...(opts.grantOver ?? {}) });
    return peer.bridge.client(peer.url()).callOp(op, input, { caller: a.ins, grant, context: {}, ...(opts.tamper ? { tamper: opts.tamper } : {}), ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}) });
  }

  #inputFor(view: OperationView): Json {
    return sampleInput((view as Operation).input, "conformance");
  }

  /**
   * X3 (fire-on-bad, L34): the real peer refuses what the grant and the proof do not allow. The workflow list (`wf`) is
   * the BRIDGE's rule (gate() step 4, the fake bridge applies it in front of the peer): the SDK app never re-checks it on
   * a live call, so X3 asserts what the peer itself enforces: the grant's crud, its audience, the proof binding.
   */
  async #x3(peer: Peer, op: string): Promise<void> {
    const view = this.#viewOf(peer, op);
    await this.#s.run(
      rowId("X3.companion_refused", peer.manifest.id, op),
      `real peer refuses outside the grant: ${peer.manifest.id}.${op}`,
      "with the companion grant of the app under test: a grant whose crud does not cover the op → refused (scope_denied / crud_exceeds_grant); a grant for another instance → grant_invalid; a proof that binds another input → call_proof_invalid; no proof → call_proof_invalid",
      async () => {
        if (!view) return bad(`${peer.manifest.id} has no operation ${op}`);
        const input = this.#inputFor(view);
        // a new key per probe: a replayed key would answer the first probe's stored result
        const fresh = () => (view.idempotency === "none" ? {} : { idempotencyKey: `conf-x3-${ulid()}` });
        const otherCrud = (["delete", "update", "create", "read"] as CrudAction[]).find((c) => !view.crud.includes(c)) ?? "delete";
        const cases: [string, () => Promise<OpAnswer>, string[]][] = [
          [`grant crud ${otherCrud} only`, () => this.#asApp(peer, op, input, { grantOver: { crud: [otherCrud] }, ...fresh() }), ["crud_exceeds_grant", "scope_denied"]],
          ["grant for another instance", () => this.#asApp(peer, op, input, { grantOver: { aud: newId("ins") as InstanceId }, ...fresh() }), ["grant_invalid"]],
          ["tampered input", () => this.#asApp(peer, op, input, { tamper: "input", ...fresh() }), ["call_proof_invalid"]],
          ["no proof", () => this.#asApp(peer, op, input, { tamper: "no_proof", ...fresh() }), ["call_proof_invalid"]],
        ];
        const problems: string[] = [];
        const shown: string[] = [];
        for (const [what, send, codes] of cases) {
          const r = await send();
          shown.push(`${what}: ${answerOf(r)}`);
          if (!(r.status >= 400 && r.status < 500 && r.code !== null && codes.includes(r.code))) problems.push(`${what} → ${answerOf(r)} (expected ${codes.join(" or ")})`);
        }
        return problems.length === 0 ? ok(shown.join("; ")) : bad(problems.join("; "));
      },
    );
  }

  /** X4: the peer's real output validates against the pinned contract schema (tealbrick-conformance.json contractOps names the op). */
  async #x4(live: readonly Peer[], tried: readonly string[]): Promise<void> {
    const a = this.#a;
    const consumes = a.manifest.contracts?.consumes ?? [];
    const ops = this.#i.config.contractOps;
    for (const peer of live) {
      for (const contract of consumes.filter((c) => (peer.manifest.contracts?.produces ?? []).includes(c))) {
        const bound = ops[contract];
        const title = `${peer.manifest.id} output is ${contract}`;
        const expected = `the real output of ${peer.manifest.id}'s companion op bound to ${contract} (contractOps) validates against schemas/contracts/${contract.replace("/", ".")}.schema.json of @opt2-tealbrick/spec`;
        if (!bound || bound.peer !== peer.manifest.id) {
          this.#s.record(rowId("X4.contract_schema", peer.manifest.id, "unmapped"), title, expected, notRun(`${a.manifest.id} consumes ${contract} and ${peer.manifest.id} produces it, but tealbrick-conformance.json contractOps does not name the op: add {"contractOps": {"${contract}": "${peer.manifest.id}.<op>"}}`));
          continue;
        }
        await this.#s.run(rowId("X4.contract_schema", peer.manifest.id, bound.op), title, expected, async () => {
          const view = this.#viewOf(peer, bound.op);
          if (!view) return bad(`${peer.manifest.id} has no operation ${bound.op}`);
          if (!this.#declared(peer.manifest.id).some((d) => d.op === bound.op)) return bad(`${a.manifest.id}'s companions[] does not list ${peer.manifest.id}.${bound.op}`);
          // the app's own call when it made one, else the suite's call with the same grant
          const rec = this.#calls.find((c) => c.from === a.manifest.id && c.to === peer.manifest.id && c.op === bound.op && isOkBody(c));
          let output: unknown;
          let how: string;
          if (rec) {
            output = (rec.body as { output?: unknown }).output;
            how = `the real call of ${a.manifest.id}`;
          } else {
            const key = view.idempotency === "none" ? undefined : `conf-x4-${ulid()}`;
            const r = await this.#asApp(peer, bound.op, this.#inputFor(view), key ? { idempotencyKey: key } : {});
            if (!isOkBody(r)) return bad(`no call of ${a.manifest.id} reached ${bound.op} (tried ${tried.length}), and the suite's call answered ${answerOf(r)}`);
            output = (r.body as { output?: unknown }).output;
            how = "the suite's call with the app's grant (no op of the app made it)";
          }
          const schemaPath = fileURLToPath(import.meta.resolve(`@opt2-tealbrick/spec/schemas/contracts/${contract.replace("/", ".")}.schema.json`));
          const v = validateAgainstSchema(JSON.parse(readFileSync(schemaPath, "utf8")) as never, output as Json);
          if (v.ok) return ok(`${peer.manifest.id}.${bound.op} (${how}) validates against ${contract}`);
          return bad(`${peer.manifest.id}.${bound.op} (${how}) violates ${contract}: ${v.errors.slice(0, 3).map((e) => `${e.path || "/"} ${e.message}`).join("; ")}`);
        });
      }
    }
  }

  /** X5 (only for an op the apps policy holds): hold listed in the peer → approved → the retried call runs once. */
  async #x5(peer: Peer, op: string): Promise<void> {
    const view = this.#viewOf(peer, op);
    if (!view || !expectHeld(view, this.#a.bridge.appsPolicy.held)) return;
    await this.#s.run(
      rowId("X5.hold_round_trip", peer.manifest.id, op),
      `held companion op: hold round trip ${peer.manifest.id}.${op}`,
      "the app caller's first call is held (202 held + holdId); the hold is listed by the peer (tb.holds_list); the owner approves it (tb.holds_decide); the same call with the same idempotency key runs (200 ok); the same call with a new key is held again with a new holdId",
      async () => {
        const sess = await this.#session(peer);
        if (!sess) return bad("owner sign-in at the peer failed");
        const input = this.#inputFor(view);
        const key = view.idempotency === "none" ? undefined : `conf-x5-${ulid()}`;
        const first = await this.#asApp(peer, op, input, key ? { idempotencyKey: key } : {});
        if (!isHeldBody(first)) return bad(`first call answered ${answerOf(first)}, expected 202 held${errorCode(first.body) === "scope_denied" ? " (the op is scoped and the app caller holds no scope instance on the peer)" : ""}`);
        const holdId = String((first.body as { holdId: string }).holdId);
        const client = peer.bridge.client(peer.url());
        const listed = await listPersonPages(client, sess, "tb.holds_list", (xs) => xs.some((x) => x.id === holdId));
        if (!listed.items.some((x) => x.id === holdId)) return bad(`hold ${holdId} is not listed by the peer's tb.holds_list (${listed.failed ?? `${listed.pages} page(s)${listed.truncated ? ", page limit reached" : ""}`})`);
        const d = await client.personOp(sess, "tb.holds_decide", { holdId, decision: "approve" });
        if (d.status !== 200) return bad(`approve ${holdId} → ${d.status}${d.code ? ` ${d.code}` : ""}`);
        const same = await this.#asApp(peer, op, input, key ? { idempotencyKey: key } : {});
        const again = await this.#asApp(peer, op, input, view.idempotency === "none" ? {} : { idempotencyKey: `conf-x5-${ulid()}` });
        const good = isOkBody(same) && isHeldBody(again) && (again.body as { holdId: string }).holdId !== holdId;
        return verdict(good, `held ${holdId}; listed; approved; same call${key ? " + key" : ""} ${answerOf(same)}; again${key ? " (new key)" : ""} ${answerOf(again)}`);
      },
    );
  }
}
