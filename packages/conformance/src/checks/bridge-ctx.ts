// Shared context of the bridge target checks (CONFORMANCE §4.4): the world (fake Portal, fake apps, agents), the
// running bridge, MCP sessions per agent slot, generic tool / input derivation from the manifests, config
// publication and the evidence other checks reuse (C1 positive paths, C7 lifetimes, scans). No product id appears
// here: every op, tool and key is picked from manifest data by shape.
import { dynamicToolNames, type Ed25519KeyPair, keySetFrom, mcpToolName, standardOpInputSchema, toolNameFits, ulid } from "@opt2-tealbrick/manifest";
import type { AgentMode, DynamicCatalogEntry, Manifest, Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, KeySet } from "@opt2-tealbrick/spec/sdk";
import type { AgentRole, BridgeWorld } from "../bridge-world.ts";
import type { FakeApp, Received } from "../fake-app.ts";
import { type HttpAnswer, request } from "../http.ts";
import { McpSession, type ToolCallResult } from "../mcp-agent.ts";
import { sampleInput } from "../sample.ts";
import { bad, type Outcome, ok, type Suite } from "../suite.ts";
import { nowS, peek } from "../tokens.ts";

export type KeySlot = "free" | "free2" | "bound" | "none" | "revoked";

/** What the runner hands the checks. */
export interface BridgeHarness {
  world: BridgeWorld;
  /** env the bridge under test was started with (names checked by C8; values never reported) */
  env: Record<string, string>;
  /** stops and restarts the bridge on the same data dir with `extra` env merged (B2 re-enrolment); a `null` value
   * removes that name from the env (B11.keys_origin_unset_503) */
  restart?: (extra?: Record<string, string | null>) => Promise<void>;
  /** captured stdout/stderr of the bridge process; null when the harness cannot capture logs */
  logs: () => string | null;
  dataDir: string;
  /** per-wait timeout (acks, notifications), ms */
  timeoutMs: number;
  /** pause / revocation latency bound (CREDENTIALS §13: ≤ 60 s online) */
  pauseLatencyMs: number;
  /** check groups to run; null = all (tests select groups; the CLI runs all) */
  groups: ReadonlySet<string> | null;
  /** C91 group real_app: SDK module to start the real app with (default: the installed @opt2-tealbrick/miniapp-sdk) */
  sdkModule?: string;
  /** conformance 0.1.28 (B-EV-8/11): time budget of the volume rows (the 10 100-event flood); default 300 000 ms */
  eventVolumeBudgetMs?: number;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
export const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const subset = (a: readonly string[], b: readonly string[]) => a.every((x) => b.includes(x));
const EFFECT_RANK: Record<string, number> = { read: 0, write: 1, outward: 2, destructive: 2, money: 3 };

/** Refusal of a tool call: an `isError` result whose envelope code is one of `codes`. */
export function toolRefused(r: ToolCallResult, codes: readonly string[]): Outcome {
  const pass = r.isError && r.code !== null && codes.includes(r.code);
  return { pass, asserted: describeCall(r) };
}

export function describeCall(r: ToolCallResult): string {
  if (r.rpcError) return `HTTP ${r.status} JSON-RPC error ${r.rpcError.code} ${r.rpcError.message.slice(0, 80)}`;
  if (r.isError) return `HTTP ${r.status} isError ${r.code ?? "(no error envelope)"}`;
  if (r.structured) return `HTTP ${r.status} ok ${JSON.stringify(r.structured).slice(0, 120)}`;
  return `HTTP ${r.status} ${JSON.stringify(r.raw ?? null).slice(0, 120)}`;
}

/** 4xx answer, optionally with one of the OAuth `error` values or envelope codes. */
export function httpRefused(a: HttpAnswer, codes: readonly string[] = []): Outcome {
  const b = isObj(a.body) ? a.body : {};
  const env = isObj(b.error) && typeof b.error.code === "string" ? b.error.code : null;
  const oauth = typeof b.error === "string" ? b.error : null;
  const code = env ?? oauth;
  const pass = a.status >= 400 && a.status < 500 && (codes.length === 0 || (code !== null && codes.includes(code)));
  return { pass, asserted: `${a.status}${code ? ` ${code}` : ""}` };
}

export class BridgeCtx {
  readonly h: BridgeHarness;
  readonly w: BridgeWorld;
  readonly s: Suite;
  readonly #sessions = new Map<KeySlot, McpSession>();
  /** positive-path evidence (C1 per kind) */
  readonly evidence = new Map<string, string>();
  /** every K5 access token issued to the suite (C7 lifetimes, log / disk scans) */
  readonly accessTokens = new Set<string>();
  readonly refreshTokens = new Set<string>();
  /** secrets the suite handed the bridge (log / disk / Portal scans; never reported) */
  readonly secrets = { tickets: new Set<string>(), pairing: new Set<string>(), keyValues: new Set<string>(), idempotency: new Set<string>() };

  constructor(h: BridgeHarness, s: Suite) {
    this.h = h;
    this.w = h.world;
    this.s = s;
  }

  get primary(): FakeApp {
    return this.w.primary;
  }
  get peer(): FakeApp | null {
    return this.w.peer;
  }
  /** origin the suite connects to */
  get pub(): string {
    return this.w.publicUrl;
  }
  /** advertised public origin (TB_PUBLIC_URL): issuer, resource, callback URLs */
  get adv(): string {
    return this.w.advertisedUrl;
  }
  /** maps a URL on the advertised origin to the listener the suite connects to */
  local(url: string): string {
    const u = new URL(url);
    return u.origin === new URL(this.adv).origin ? `${this.pub}${u.pathname}${u.search}` : url;
  }
  /** origin the suite connects to for the key page (keys origin host name, TB_KEYS_PUBLIC_URL; C59) */
  get keysPub(): string {
    return this.w.keysUrl;
  }
  get int(): string {
    return this.w.internalUrl;
  }
  get brg(): `tb:brg:${string}` {
    return `tb:brg:${this.w.bridgeId}`;
  }

  on(group: string): boolean {
    return this.h.groups === null || this.h.groups.has(group);
  }

  /** The enrolled bridge key as a key set (K5, call proofs, pair state, standalone tokens). */
  bridgeKeys(): KeySet {
    const jwk = this.w.bridgeJwk();
    return jwk ? keySetFrom({ keys: [jwk] }, this.brg as `tb:brg:brg_${string}`) : { keys: [] };
  }

  // ── tools and inputs (derived from manifests) ──
  tool(app: FakeApp, opId: string): string {
    return mcpToolName(app.product, opId);
  }
  op(app: FakeApp, id: string): Operation | undefined {
    return app.manifest.operations.find((o) => o.id === id);
  }
  agentOps(app: FakeApp): Operation[] {
    return app.manifest.operations.filter((o) => o.audience === "agent" && !o.dynamic);
  }
  /** first agent op of `app` matching `pred` */
  pick(app: FakeApp, pred: (o: Operation) => boolean): Operation | undefined {
    return this.agentOps(app).find(pred);
  }
  readOp(app: FakeApp): Operation | undefined {
    return this.pick(app, (o) => o.crud.length === 1 && o.crud[0] === "read");
  }
  input(app: FakeApp, opId: string): Json {
    const op = this.op(app, opId);
    const schema = op?.input ?? (opId.startsWith("tb.") ? standardOpInputSchema(opId as never) : { type: "object" });
    return sampleInput(schema, `${this.w.canary}in`);
  }
  idemKey(): string {
    const k = `idem${ulid()}`;
    this.secrets.idempotency.add(k);
    return k;
  }

  /** Expected tools/list for `role` from the current grant specs (BRIDGE §7.2); dynamic names separately. */
  expectedTools(role: AgentRole, catalog: (app: FakeApp, op: Operation) => DynamicCatalogEntry[] = () => []): { fixed: Set<string>; dynamic: Set<string> } {
    const fixed = new Set<string>();
    const dynamic = new Set<string>();
    const paused = this.w.portal.pause;
    if (paused.workspace || paused.agents.has(this.w.agents[role].agt)) return { fixed, dynamic };
    for (const g of this.w.grantSpecs) {
      if (g.role !== role || paused.instances.has(g.app.ins)) continue;
      const m: Manifest = g.app.manifest;
      const scopeTypes = (m.scopes ?? []).map((x) => x.type);
      let visible = 0;
      for (const o of m.operations) {
        if (o.audience !== "agent" || !subset(o.crud, g.crud)) continue;
        if (o.scopeType !== undefined && !scopeTypes.includes(o.scopeType)) continue;
        if (g.mode === ("bound" satisfies AgentMode) && !g.wf.includes(o.id)) continue;
        if (!o.dynamic) {
          if (toolNameFits(mcpToolName(m.id, o.id))) {
            fixed.add(mcpToolName(m.id, o.id));
            visible++;
          }
          continue;
        }
        if (o.dynamic.mode === "search") {
          const d = dynamicToolNames(m.id, o.id);
          dynamic.add(d.search);
          dynamic.add(d.call);
          visible++;
          continue;
        }
        for (const e of catalog(g.app, o)) {
          const name = mcpToolName(m.id, e.name);
          const inCeiling = subset(e.crud, o.dynamic.crudCeiling) && (EFFECT_RANK[e.effect] ?? 9) <= (EFFECT_RANK[o.dynamic.effectCeiling] ?? 0);
          if (inCeiling && subset(e.crud, g.crud) && toolNameFits(name)) {
            dynamic.add(name);
            visible++;
          }
        }
      }
      if (visible > 0) {
        fixed.add(mcpToolName(m.id, "tb_hold_status"));
        fixed.add(mcpToolName(m.id, "tb_skills"));
      }
    }
    return { fixed, dynamic };
  }

  // ── sessions and calls ──
  async session(slot: KeySlot, fresh = false): Promise<McpSession> {
    const have = this.#sessions.get(slot);
    if (have && !fresh) return have;
    const a = await this.w.keyAgents[slot].tokenAnswer();
    const token = isObj(a.body) && typeof a.body.access_token === "string" ? a.body.access_token : null;
    if (a.status !== 200 || !token) throw new Error(`no K5 for ${slot}: /oauth/token → ${a.status} ${JSON.stringify(a.body).slice(0, 120)}`);
    this.accessTokens.add(token);
    const s = new McpSession(this.pub, token, this.w.log);
    const init = await s.initialize();
    if (init.status !== 200) throw new Error(`MCP initialize for ${slot} → ${init.status}`);
    this.#sessions.set(slot, s);
    return s;
  }
  dropSessions(): void {
    this.#sessions.clear();
  }

  /** tools/call of `opId` at `app` as `slot` (idempotency key added for ops that require one unless `idem` is null). */
  async call(slot: KeySlot, app: FakeApp, opId: string, input?: Json, idem?: string | null, meta?: Record<string, unknown>): Promise<ToolCallResult> {
    const op = this.op(app, opId);
    const key = idem === null ? undefined : (idem ?? (op?.idempotency === "required" ? this.idemKey() : undefined));
    const s = await this.session(slot);
    return s.callTool(this.tool(app, opId), (input ?? this.input(app, opId)) as Record<string, unknown>, key, meta);
  }
  async callTool(slot: KeySlot, name: string, args: Record<string, unknown>, idem?: string): Promise<ToolCallResult> {
    return (await this.session(slot)).callTool(name, args, idem);
  }
  isOk(r: ToolCallResult): boolean {
    return !r.isError && r.rpcError === null && r.status === 200;
  }

  /** ops / hooks / bridge ops an app received after event counter `seq` */
  since(app: FakeApp, seq: number, kind?: Received["kind"]): Received[] {
    return app.received.filter((r) => r.seq > seq && (kind === undefined || r.kind === kind));
  }
  everyApp(seq: number, kind?: Received["kind"]): Received[] {
    return this.w.apps.flatMap((a) => this.since(a, seq, kind));
  }

  /** publish the current world state and wait for the bridge's ack of that revision */
  async apply(o: Parameters<BridgeWorld["publish"]>[0] = {}): Promise<{ rev: number; acked: boolean }> {
    const rev = await this.w.publish(o);
    const acked = await this.w.waitAck(rev, this.h.timeoutMs);
    return { rev, acked };
  }

  /** polls `fn` until it returns a value or `ms` passes */
  async until<T>(fn: () => Promise<T | null | undefined | false>, ms: number, stepMs = 250): Promise<{ value: T | null; ms: number }> {
    const t0 = Date.now();
    for (;;) {
      try {
        const v = await fn();
        if (v) return { value: v as T, ms: Date.now() - t0 };
      } catch {
        // retry until the deadline
      }
      if (Date.now() - t0 > ms) return { value: null, ms: Date.now() - t0 };
      await sleep(stepMs);
    }
  }

  get(path: string, headers: Record<string, string> = {}, base = this.pub): Promise<HttpAnswer> {
    return request(`${base}${path}`, { headers });
  }
  post(path: string, body: string, headers: Record<string, string> = {}, base = this.pub): Promise<HttpAnswer> {
    return request(`${base}${path}`, { method: "POST", headers, body });
  }
  form(path: string, fields: Record<string, string>, headers: Record<string, string> = {}, base = this.pub): Promise<HttpAnswer> {
    return request(`${base}${path}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams(fields).toString() });
  }
  /** keys-ticket form POST to the key page on the keys origin (BRIDGE §9.3, C59) */
  keysForm(ticket: string): Promise<HttpAnswer> {
    return this.form("/keys", { ticket }, {}, this.keysPub);
  }
  mcpWith(bearer: string): Promise<HttpAnswer> {
    const body = { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "tb-conformance", version: "0.1.0" } } };
    return request(`${this.pub}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${bearer}` }, body: JSON.stringify(body) });
  }

  /** Records `id` as not_run when its group is not selected; otherwise runs it. */
  run(id: string, title: string, expected: string, fn: () => Promise<Outcome> | Outcome): Promise<Outcome> {
    return this.s.run(id, title, expected, fn);
  }

  /** `exp − iat` of a compact JWS (unverified read; lifetime evidence only) */
  static lifetime(token: string): number | null {
    const c = peek(token);
    return c && typeof c.exp === "number" && typeof c.iat === "number" ? c.exp - c.iat : null;
  }
}

export { bad, type Ed25519KeyPair, nowS, ok };
