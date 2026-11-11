// B31 / B32 (conformance 0.1.31, spec 0.1.78, CONFORMANCE B31 + B32, BRIDGE §8.3 / §8.5, SDK-API §4.7 / §18.6): `tb.hold_status` for an
// app caller (cap `app_hold_status`) and the caller context of a companion call (cap `app_call_context`). Gated by the cap the bridge
// reports in its StatusReport (`bridge.caps`), never by version: a bridge without a cap skips that group (not_applicable, noted).
//
// Fixture. The TARGET is a REAL SDK app (its ownership and context rules are the ones under test), reached through a proxy that counts
// what the bridge forwards and can tamper with it. The CALLERS are fake apps listed in the config with companion grants the world
// mints like Core: `a` and `b` are two instances of ONE product (`evolution`) with the same grant shape (a rule keyed on the product
// instead of the instance fails), `g` / `f` carry the other caller products of examples/caller-context.cases.json (a hyphen product, a
// grant without `prd`), `e` / `d` call an old fake target with / without `tb.hold_status` in their grant. A REAL SDK caller (`r`) runs
// the SDK-side row; its slice carries no `bridge.caps` until the row adds them (the Portal, i.e. this suite, signs the slice).
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { canonicalize, manifestDigest, mcpToolName, opaqueDigest, opaqueValue, ulid } from "@opt2-tealbrick/manifest";
import type { CallEnvelope } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { RealSlot } from "../bridge-world.ts";
import { CAP_CALLER, CAP_TARGET, type CapRole, type CapTarget, capTargetManifest, OwnerSession, startCapTarget, TargetProxy } from "../cap-fixture.ts";
import type { FakeApp } from "../fake-app.ts";
import type { HttpAnswer } from "../http.ts";
import { loadSdk, type RealApp, type RealRunningApp, realAppManifest, type SdkModule, startRealApp } from "../real-app.ts";
import { bad, na, notRun, type Outcome, verdict } from "../suite.ts";
import { newId, nowS } from "../tokens.ts";
import { reportedBridgeCaps } from "./bridge.ts";
import type { BridgeCtx } from "./bridge-ctx.ts";
import { isObj, sleep } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

export const APP_HOLD_STATUS_CAP = "app_hold_status";
export const APP_CALL_CONTEXT_CAP = "app_call_context";
/** a version every release satisfies, and one every release exceeds (BRIDGE §8.3: the bridge's minimum is its own constant) */
const SDK_NEW = "99.0.0";
const SDK_OLD = "0.0.1";
/** the spec fixture (CONFORMANCE B32) */
const EVO: Record<string, Json> = { "evolution.workflow": "wf_1", "evolution.version": 3, "evolution.run": "run_1", "evolution.step": "step_1" };
/** spec 0.1.78 erratum: the SDK's existing fixed message for an unknown or not-owned hold */
const HOLD_NOT_FOUND = "no such hold for this caller";
const EVO_SUMMARY = 'evolution.run="run_1"; evolution.step; evolution.version=3; evolution.workflow="wf_1"';

interface Fx {
  apps: Record<CapRole, FakeApp>;
  x: { ins: InstanceId; product: string };
  target: CapTarget;
  proxy: TargetProxy;
  owner: OwnerSession;
  caller: { ins: InstanceId; app: RealApp };
  teardown(): Promise<void>;
}

const code = (a: HttpAnswer): string | null => (isObj(a.body) && isObj(a.body.error) && typeof a.body.error.code === "string" ? a.body.error.code : null);
const message = (a: HttpAnswer): string | null => (isObj(a.body) && isObj(a.body.error) && typeof a.body.error.message === "string" ? a.body.error.message : null);
const pointer = (a: HttpAnswer): string | null => (isObj(a.body) && isObj(a.body.error) && isObj(a.body.error.details) && typeof a.body.error.details.pointer === "string" ? a.body.error.details.pointer : null);
const shown = (a: HttpAnswer): string => `${a.status} ${code(a) ?? (isObj(a.body) && typeof a.body.status === "string" ? a.body.status : "(no envelope)")}`;
/** the error envelope without its requestId, as bytes */
const envelope = (a: HttpAnswer): string => (isObj(a.body) && isObj(a.body.error) ? JSON.stringify({ ...a.body, error: Object.fromEntries(Object.entries(a.body.error).filter(([k]) => k !== "requestId")) }) : JSON.stringify(a.body));
const out = (a: HttpAnswer): Record<string, unknown> => (isObj(a.body) && isObj(a.body.output) ? a.body.output : {});
const same = (x: unknown, y: unknown): boolean => canonicalize(x as Json) === canonicalize(y as Json);

export async function p3p4Checks(c: BridgeCtx): Promise<void> {
  const caps = reportedBridgeCaps(c);
  const active: { group: string; cap: string }[] = [];
  for (const [group, cap] of [["b31", APP_HOLD_STATUS_CAP], ["b32", APP_CALL_CONTEXT_CAP]] as const) {
    if (!c.on(group)) continue;
    if (caps.includes(cap)) active.push({ group, cap });
    else {
      const why = `the bridge does not declare the ${cap} capability in its StatusReport (bridge.caps = ${JSON.stringify(caps)}): this group is skipped, decided by capability, never by version (CONFORMANCE B31 / B32)`;
      for (const r of BRIDGE_GROUPS[group] ?? []) await c.run(r.id, r.title, `cap ${cap} declared`, () => na(why));
    }
  }
  if (active.length === 0) return;
  const every = (o: Outcome) => {
    for (const x of active) for (const r of BRIDGE_GROUPS[x.group] ?? []) if (!c.s.has(r.id)) c.s.record(r.id, r.title, "the real target and its callers are deployed behind the bridge", o);
  };
  if (!c.w.testRoots) return every(notRun("needs test roots (the real SDK apps pin the run's TEST root through startApp's portalRootKeys)"));
  const loaded = await loadSdk(c.h.sdkModule);
  if ("error" in loaded) return every(notRun(loaded.error));
  const fx = await setup(c, loaded.sdk);
  if (typeof fx === "string") return every(bad(fx));
  try {
    if (active.some((x) => x.group === "b31")) await hold(c, fx);
    if (active.some((x) => x.group === "b32")) await context(c, fx);
  } finally {
    await fx.teardown();
  }
}

// ── fixture ──
async function deploy<T extends RealRunningApp>(c: BridgeCtx, manifest: Manifest, url: string, start: (env: Record<string, string>, dataDir: string) => Promise<T>): Promise<{ slot: RealSlot; app: T } | string> {
  const ins = newId("ins") as InstanceId;
  const dataDir = mkdtempSync(join(tmpdir(), "tb-conformance-cap-"));
  mkdirSync(join(dataDir, "backup"), { recursive: true });
  const enrol = opaqueValue("tbe_");
  c.w.enrolCodes.push({ digest: opaqueDigest(enrol), kind: "instance", ins, product: manifest.id, exp: nowS() + 3600 });
  const slot: RealSlot = { ins, manifest, digest: manifestDigest(manifest), url, jwk: null, listed: true };
  c.w.extraReals.push(slot);
  await c.apply();
  const env: Record<string, string> = {
    TB_INSTANCE_ID: ins,
    TB_ENROL_CODE: enrol,
    TB_BRIDGE_URL: c.int,
    TB_PORTAL_KEYS: JSON.stringify({ keys: c.w.portal.keys.filter((k) => k.status !== "pending").map((k) => k.key.publicJwk) }),
    TB_KEK: randomBytes(32).toString("base64url"),
    TB_DATA_DIR: dataDir,
    TB_BACKUP_DIR: join(dataDir, "backup"),
    TB_LOG_LEVEL: "error",
    TB_DATA_EPHEMERAL: "1",
  };
  const app = await start(env, dataDir);
  const fail = async (why: string): Promise<string> => {
    await app.stop().catch(() => undefined);
    return why;
  };
  const d = opaqueDigest(enrol);
  const claim = (await c.until(async () => c.w.portal.acks.flatMap((a) => a.claims ?? []).find((x) => x.ins === ins && x.codeDigest === d), c.h.timeoutMs)).value;
  if (!claim) return fail(`the claim of ${manifest.id} was not reported by the bridge within ${c.h.timeoutMs} ms (app status ${app.status()})`);
  slot.jwk = claim.publicKey;
  await c.apply();
  const ready = (await c.until(async () => app.status() === "ok", c.h.timeoutMs)).value;
  if (!ready) return fail(`${manifest.id} did not install its slice through the bridge (status ${app.status()})`);
  await c.apply();
  return { slot, app };
}

async function setup(c: BridgeCtx, sdk: SdkModule): Promise<Fx | string> {
  const [proxyPort, callerPort, xPort] = c.w.capPorts;
  if (!proxyPort || !callerPort || !xPort) return "no ports reserved for the real target and caller (runBridgeTarget sets world.capPorts)";
  if (c.w.capApps.size === 0) return "the suite could not derive the caller apps from the example manifest (capAppManifests)";
  const apps = Object.fromEntries(c.w.capApps) as Record<CapRole, FakeApp>;
  const stops: (() => Promise<unknown>)[] = [];
  const teardown = async () => {
    for (const stop of stops.reverse()) await stop().catch(() => undefined);
    c.w.extraReals.length = 0;
    c.w.capAppsListed = false;
    c.w.grantPrd.clear();
    c.w.grantWfExtra.clear();
    c.w.sliceCaps.clear();
    await c.apply().catch(() => undefined);
  };
  try {
    // grant shapes first: every later publish carries them (a and b: the same product, instance ids differ)
    for (const r of ["a", "b"] as const) {
      c.w.grantPrd.set(apps[r].ins, apps[r].product);
      c.w.grantWfExtra.set(apps[r].ins, ["tb.holds_pending"]);
    }
    c.w.grantPrd.set(apps.g.ins, apps.g.product);
    c.w.capAppsListed = true;
    const proxy = await TargetProxy.start(proxyPort, xPort);
    stops.push(() => proxy.stop());
    const x = await deploy(c, capTargetManifest(c.primary.manifest, xPort), `http://127.0.0.1:${proxyPort}`, (env, dir) => startCapTarget(sdk, capTargetManifest(c.primary.manifest, xPort), env, dir, [c.w.root.publicJwk]));
    if (typeof x === "string") {
      await teardown();
      return x;
    }
    stops.push(() => x.app.stop());
    const callerManifest = realAppManifest(c.primary.manifest, CAP_CALLER.product, callerPort, { product: CAP_TARGET.product, operations: [CAP_TARGET.note], crud: ["create"] });
    const r = await deploy(c, callerManifest, `http://127.0.0.1:${callerPort}`, (env, dir) => startRealApp(sdk, callerManifest, env, dir, [c.w.root.publicJwk]));
    if (typeof r === "string") {
      await teardown();
      return r;
    }
    stops.push(() => r.app.stop());
    c.w.grantPrd.set(r.slot.ins, CAP_CALLER.product);
    await c.apply();
    const owner = new OwnerSession(`http://127.0.0.1:${xPort}`, CAP_TARGET.product);
    const err = await owner.signIn(await c.w.mint.launchTicket({ person: c.w.person, aud: `tb:ins:${x.slot.ins}` }));
    if (err) {
      await teardown();
      return `owner session of the target: ${err}`;
    }
    const started = (await c.until(async () => r.app.startContext(), c.h.timeoutMs)).value;
    if (!started) {
      await teardown();
      return "the real caller did not run onStart";
    }
    return { apps, x: { ins: x.slot.ins, product: CAP_TARGET.product }, target: x.app, proxy, owner, caller: { ins: r.slot.ins, app: r.app }, teardown };
  } catch (e) {
    await teardown();
    return `fixture setup failed: ${e instanceof Error ? e.message : String(e)}`;
  }
}

// ── calls ──
const envelopeOf = (target: string, op: string, input: Json, o: { key?: string; context?: unknown } = {}): CallEnvelope =>
  ({ target, op, input, ...(o.key ? { idempotencyKey: o.key } : {}), ...(o.context !== undefined ? { context: o.context } : {}) }) as unknown as CallEnvelope;

class Caller {
  readonly c: BridgeCtx;
  readonly fx: Fx;
  constructor(c: BridgeCtx, fx: Fx) {
    this.c = c;
    this.fx = fx;
  }
  /** an app-initiated companion call as `app` (a rate-limited answer waits and retries: the group makes many calls) */
  async call(app: FakeApp, target: string, op: string, input: Json, o: { key?: string; context?: unknown } = {}): Promise<HttpAnswer> {
    const grant = this.c.w.companionGrants.get(app.ins) ?? null;
    // the generated write requires an idempotency key (a create op, MANIFEST M-OP-6): one unless the row set it
    const key = o.key ?? (op === CAP_TARGET.note ? this.c.idemKey() : undefined);
    for (let i = 0; ; i++) {
      const a = await app.companion(envelopeOf(target, op, input, { ...o, ...(key ? { key } : {}) }), grant);
      if (code(a) !== "rate_limited" || i >= 6) return a;
      await sleep(1200);
    }
  }
  toX(app: FakeApp, op: string, input: Json, o: { key?: string; context?: unknown } = {}): Promise<HttpAnswer> {
    return this.call(app, CAP_TARGET.product, op, input, o);
  }
  /** a call of the destructive op: held under the default apps policy */
  async hold(app: FakeApp, context?: unknown): Promise<{ a: HttpAnswer; holdId: string | null; key: string; input: Json }> {
    const key = this.c.idemKey();
    const input = { id: `cap-${ulid()}` };
    const a = await this.toX(app, CAP_TARGET.del, input, { key, ...(context !== undefined ? { context } : {}) });
    const id = isObj(a.body) && a.body.status === "held" && typeof a.body.holdId === "string" ? a.body.holdId : null;
    return { a, holdId: a.status === 202 ? id : null, key, input };
  }
  status(app: FakeApp, holdId: string): Promise<HttpAnswer> {
    return this.toX(app, "tb.hold_status", { holdId });
  }
  async decide(holdId: string, decision: "approve" | "deny"): Promise<string | null> {
    const r = await this.fx.owner.op("tb.holds_decide", { holdId, decision });
    return r.status === 200 ? null : `owner decision ${decision} answered ${r.status} ${code(r) ?? ""}`;
  }
}

// ── B31 ──
async function hold(c: BridgeCtx, fx: Fx): Promise<void> {
  const k = new Caller(c, fx);
  const { a: A, b: B, d: D, e: E, t: T } = fx.apps;
  const ref = (id: string) => BRIDGE_GROUPS.b31?.find((x) => x.id === id)?.title ?? id;
  const run = (id: string, expected: string, fn: () => Promise<Outcome>) => c.run(id, ref(id), expected, fn);

  await run("B31.hold_status_own", "A's call is held; A calls tb.hold_status with the holdId → held (the receipt status; CONFORMANCE says pending), then approved after the owner decides", async () => {
    const h = await k.hold(A);
    if (!h.holdId) return bad(`the destructive op was not held: ${shown(h.a)}`);
    const s1 = await k.status(A, h.holdId);
    const declined = await k.decide(h.holdId, "approve");
    if (declined) return bad(declined);
    const s2 = await k.status(A, h.holdId);
    const pass = s1.status === 200 && out(s1).status === "held" && s2.status === 200 && out(s2).status === "approved" && out(s2).decidedAt !== null && out(s2).decidedAt !== undefined;
    return verdict(pass, `before the decision ${shown(s1)} status ${String(out(s1).status)}; after ${shown(s2)} status ${String(out(s2).status)} decidedAt ${String(out(s2).decidedAt)}`);
  });

  await run("B31.hold_status_other_not_found", "B asks for A's hold, A asks for an agent's hold, A asks for an unknown id → the same 404 hold_not_found envelope (requestId aside) as an agent's unknown id; never the id", async () => {
    const mine = await k.hold(A);
    if (!mine.holdId) return bad(`A's call was not held: ${shown(mine.a)}`);
    const agentCall = await c.callTool("free", mcpToolName(CAP_TARGET.product, CAP_TARGET.del), { id: `cap-${ulid()}` }, c.idemKey());
    const agentHold = agentCall.structured?.status === "held" && typeof agentCall.structured.holdId === "string" ? agentCall.structured.holdId : null;
    if (!agentHold) return bad(`the agent's call was not held: ${JSON.stringify(agentCall.structured ?? agentCall.raw).slice(0, 160)}`);
    const unknown = `hld_${ulid()}`;
    const other = await k.status(B, mine.holdId);
    const agents = await k.status(A, agentHold);
    const nope = await k.status(A, unknown);
    // the reference: what an AGENT gets for an unknown id, through its MCP tool
    const ref = await c.callTool("free", mcpToolName(CAP_TARGET.product, "tb_hold_status"), { holdId: `hld_${ulid()}` });
    const refEnv = agentEnvelope(ref);
    const answers = [other, agents, nope];
    const equal = answers.every((x) => envelope(x) === envelope(nope));
    const all404 = answers.every((x) => x.status === 404 && code(x) === "hold_not_found");
    const noIds = answers.every((x) => ![mine.holdId, agentHold, unknown].some((id) => JSON.stringify(x.body).includes(id as string)));
    // the fixed text of spec 0.1.78 (the SDK's existing message for an agent's unknown id): the agent's own answer (through the bridge's MCP wrapping) must carry it too, so an SDK that words it differently for apps OR for agents fails
    const likeAgent = refEnv !== null && refEnv.code === "hold_not_found" && refEnv.message === HOLD_NOT_FOUND && answers.every((x) => message(x) === HOLD_NOT_FOUND);
    return verdict(equal && all404 && noIds && likeAgent, `B→A's hold ${shown(other)}; A→agent's hold ${shown(agents)}; A→unknown ${shown(nope)}; envelopes equal ${equal}; message "${message(nope) ?? ""}" (spec: "${HOLD_NOT_FOUND}"); the agent's unknown id: ${refEnv?.code ?? "no envelope"} "${refEnv?.message ?? ""}"; the id never appears ${noIds}`);
  });

  await run("B31.hold_status_undeclared", "a companion entry without tb.hold_status → callApp throws companion_undeclared; a direct bridge call with that grant → refused not_in_workflow; the app never sees it", async () => {
    // SDK side: the real caller's edge lists only real_note
    const ctx = fx.caller.app.startContext();
    const thrown = await caught(() => (ctx ? ctx.callApp(CAP_TARGET.product, "tb.hold_status", { holdId: `hld_${ulid()}` }) : Promise.reject(new Error("no start context"))));
    // bridge side: the old fake target reports a version that passes the gate, so the grant is the only reason
    await T.status({ sdkVersion: SDK_NEW });
    const op = "conf_event_read";
    const s0 = c.w.seqNow();
    const ctl = await k.call(E, T.product, "tb.hold_status", { holdId: `hld_${ulid()}` });
    const controlSeen = c.since(T, s0, "op").filter((r) => r.name === "tb.hold_status").length;
    const s1 = c.w.seqNow();
    const refused = await k.call(D, T.product, "tb.hold_status", { holdId: `hld_${ulid()}` });
    const seen = c.since(T, s1, "op").length;
    const direct = refused.status >= 400 && refused.status < 500 && code(refused) === "not_in_workflow" && seen === 0;
    const control = ctl.status === 200 && controlSeen === 1;
    return verdict(thrown?.code === "companion_undeclared" && direct && control, `callApp: ${thrown ? thrown.code : "did not throw"}; direct without tb.hold_status in wf: ${shown(refused)}, target saw ${seen} op call(s); control (grant lists it, ${op} edge): ${shown(ctl)}, target saw ${controlSeen}`);
  });

  await run("B31.hold_approved_repeat_once", "after approved the same call (op, input, idempotency key) runs exactly once; a second repeat (same key) and a third call (fresh key, same input) are not run again; hold_status answers run", async () => {
    const ran = fx.target.runs.del;
    // B31 sends NO caller context: a bridge that declares only app_hold_status need not accept the field (BRIDGE §8.5)
    const h = await k.hold(A);
    if (!h.holdId) return bad(`the destructive op was not held: ${shown(h.a)}`);
    const declined = await k.decide(h.holdId, "approve");
    if (declined) return bad(declined);
    const one = await k.toX(A, CAP_TARGET.del, h.input, { key: h.key });
    const afterOne = fx.target.runs.del;
    const two = await k.toX(A, CAP_TARGET.del, h.input, { key: h.key });
    const afterTwo = fx.target.runs.del;
    const st = await k.status(A, h.holdId);
    // the approval matches (caller, op, input digest), not the idempotency key (SDK-API §4.2 / §4.7): the SDK's idempotency replay alone
    // keeps the same-key repeat at +1, so a third call with a FRESH key and the same input is what proves the approval was consumed
    const fresh = await k.toX(A, CAP_TARGET.del, h.input, { key: c.idemKey() });
    const afterFresh = fx.target.runs.del;
    const freshRan = afterFresh !== afterTwo || (fresh.status === 200 && isObj(fresh.body) && fresh.body.status === "ok");
    const pass = one.status === 200 && afterOne === ran + 1 && afterTwo === ran + 1 && two.status < 500 && out(st).status === "run" && !freshRan;
    return verdict(pass, `repeat ${shown(one)} (handler runs +${afterOne - ran}); second repeat, same key ${shown(two)} (handler runs +${afterTwo - ran} in total); status after ${String(out(st).status)} (erratum v0.1.78: run, not consumed); third call, fresh key, same input ${shown(fresh)} (handler runs +${afterFresh - ran} in total; +1 expected, the approval is used up by the first run)`);
  });

  await run("B31.hold_status_old_target", "a target that reports an sdkVersion below the minimum, none at all, or a malformed one (banana, 0.1.41-rc.1) → not_in_workflow and the target is not called (a version at or above it is routed: control)", async () => {
    try {
      await T.status({ sdkVersion: SDK_NEW });
      const sNew = c.w.seqNow();
      const control = await k.call(E, T.product, "tb.hold_status", { holdId: `hld_${ulid()}` });
      const routed = c.since(T, sNew, "op").filter((r) => r.name === "tb.hold_status").length;
      // fail closed (PK-D6): below the minimum, no sdkVersion in the report, and a value that is not a version; the minimum's own prerelease is below it
      const variants: { label: string; version: string | undefined }[] = [
        { label: SDK_OLD, version: SDK_OLD },
        { label: "(none)", version: undefined },
        { label: "banana", version: "banana" },
        { label: "0.1.41-rc.1", version: "0.1.41-rc.1" },
      ];
      const lines: string[] = [];
      let pass = control.status === 200 && routed === 1;
      for (const v of variants) {
        const pushed = await T.status(v.version === undefined ? ({ sdkVersion: undefined } as never) : { sdkVersion: v.version });
        if (pushed.status >= 300) {
          // the bridge refused this report itself (a status shape check): there is no such state to gate on, the variant is not exercised
          lines.push(`${v.label}: report refused ${pushed.status} (not exercised)`);
          continue;
        }
        const s0 = c.w.seqNow();
        const refused = await k.call(E, T.product, "tb.hold_status", { holdId: `hld_${ulid()}` });
        const seen = c.since(T, s0, "op").length;
        const ok = refused.status >= 400 && refused.status < 500 && code(refused) === "not_in_workflow" && seen === 0;
        pass &&= ok;
        lines.push(`${v.label}: ${shown(refused)}, target saw ${seen}`);
      }
      return verdict(pass, `target at ${SDK_NEW}: ${shown(control)}, target saw ${routed}; ${lines.join("; ")}`);
    } finally {
      await T.status({ sdkVersion: SDK_NEW }).catch(() => undefined);
    }
  });

  await run("B31.hold_denied_repeat_blocked", "after denied (and after expired) the same repeat does not run; the handler is not called", async () => {
    const ran = fx.target.runs.del;
    const d = await k.hold(A);
    if (!d.holdId) return bad(`the destructive op was not held: ${shown(d.a)}`);
    const declined = await k.decide(d.holdId, "deny");
    if (declined) return bad(declined);
    const st = await k.status(A, d.holdId);
    const rep = await k.toX(A, CAP_TARGET.del, d.input, { key: d.key });
    const deniedOk = out(st).status === "denied" && rep.status >= 400 && rep.status < 500 && fx.target.runs.del === ran;
    const deniedText = `denied: status ${String(out(st).status)}, repeat ${shown(rep)}, handler runs +${fx.target.runs.del - ran}`;
    if (!deniedOk) return bad(deniedText);
    // expired: the hold's time ran out (white-box: the hold's expiry is moved into the past, as 15 minutes cannot be waited for)
    const e = await k.hold(A);
    if (!e.holdId) return bad(`${deniedText}; the second hold was not held: ${shown(e.a)}`);
    try {
      const db = new DatabaseSync(join(fx.target.dataDir, "app.db"));
      try {
        const r = db.prepare("UPDATE tb_receipts SET expires_at = ? WHERE id = ? AND status = 'held'").run(Date.now() - 1000, e.holdId);
        if (Number(r.changes) !== 1) throw new Error(`${String(r.changes)} rows changed`);
      } finally {
        db.close();
      }
    } catch (err) {
      return notRun(`${deniedText}; the expired half was not exercised: the SDK's receipt table could not be aged (${err instanceof Error ? err.message : String(err)})`);
    }
    const before = fx.target.runs.del;
    const rep2 = await k.toX(A, CAP_TARGET.del, e.input, { key: e.key });
    const expiredOk = !(rep2.status === 200 && isObj(rep2.body) && rep2.body.status === "ok") && fx.target.runs.del === before;
    return verdict(expiredOk, `${deniedText}; expired: repeat ${shown(rep2)}, handler runs +${fx.target.runs.del - before}`);
  });
}

/** the envelope an agent's tool error carries: `{code, message}` from structuredContent or the JSON text content */
function agentEnvelope(r: { structured: Record<string, unknown> | null; raw: unknown }): { code: string; message: string } | null {
  const pick = (v: unknown) => (isObj(v) && isObj(v.error) && typeof v.error.code === "string" && typeof v.error.message === "string" ? { code: v.error.code, message: v.error.message } : null);
  const s = pick(r.structured);
  if (s) return s;
  const res = isObj(r.raw) && isObj(r.raw.result) ? r.raw.result : null;
  for (const part of Array.isArray(res?.content) ? (res.content as { text?: unknown }[]) : []) {
    try {
      const e = pick(JSON.parse(String(part.text)));
      if (e) return e;
    } catch {
      // plain text content
    }
  }
  return null;
}

/** What a rejected promise carried: the TbError fields the rows read. */
async function caught(fn: () => Promise<unknown>): Promise<{ code: string; status: number | null; details: unknown } | null> {
  try {
    await fn();
    return null;
  } catch (e) {
    const x = e as { code?: unknown; httpStatus?: unknown; details?: unknown };
    return { code: typeof x.code === "string" ? x.code : `(${e instanceof Error ? e.message : String(e)})`, status: typeof x.httpStatus === "number" ? x.httpStatus : null, details: x.details };
  }
}

// ── B32 ──
interface CaseFile {
  cases: { name: string; callerProduct: string | null; context: unknown; ok: boolean; pointer?: string }[];
  summaryCases: { name: string; context: Record<string, Json>; summary: string }[];
}
const caseFile = (): CaseFile => JSON.parse(readFileSync(fileURLToPath(import.meta.resolve("@opt2-tealbrick/spec/examples/caller-context.cases.json")), "utf8")) as CaseFile;

async function context(c: BridgeCtx, fx: Fx): Promise<void> {
  const k = new Caller(c, fx);
  const { a: A, b: B, g: G, f: F } = fx.apps;
  const ref = (id: string) => BRIDGE_GROUPS.b32?.find((x) => x.id === id)?.title ?? id;
  const run = (id: string, expected: string, fn: () => Promise<Outcome>) => c.run(id, ref(id), expected, fn);
  const noteRuns = () => fx.target.runs.note;
  const noteHits = () => fx.proxy.opHits(0, CAP_TARGET.note).length;

  await run("B32.context_reaches_target", "ctx.context has the four keys; the receipt has meta.callerContext; tb.receipts_list and (held call) tb.holds_list return it; tb.holds_pending has the summary (and every summaryCases row of the case file)", async () => {
    const t0 = Date.now() - 1000;
    const note = await k.toX(A, CAP_TARGET.note, { id: `cap-${ulid()}` }, { key: c.idemKey(), context: EVO });
    const reached = isObj(out(note).context) && Object.entries(EVO).every(([key, v]) => same((out(note).context as Record<string, unknown>)[key], v));
    const rc = (await fx.target.receipts.list({ op: CAP_TARGET.note })).items.find((x) => x.createdAt >= t0 && x.caller.id === A.ins);
    const receiptOk = !!rc && isObj(rc.meta) && same(rc.meta.callerContext, EVO);
    const rl = await fx.owner.op("tb.receipts_list", { op: CAP_TARGET.note });
    const listed = (isObj(rl.body) && isObj(rl.body.output) && Array.isArray(rl.body.output.items) ? (rl.body.output.items as { id?: unknown; meta?: unknown }[]) : []).find((x) => x.id === rc?.id);
    const listOk = !!listed && isObj(listed.meta) && same(listed.meta.callerContext, EVO);
    const h = await k.hold(B, EVO);
    if (!h.holdId) return bad(`the destructive op was not held: ${shown(h.a)}`);
    const hl = await fx.owner.op("tb.holds_list", {});
    const held = (isObj(hl.body) && isObj(hl.body.output) && Array.isArray(hl.body.output.items) ? (hl.body.output.items as { id?: unknown; meta?: unknown }[]) : []).find((x) => x.id === h.holdId);
    const holdsOk = !!held && isObj(held.meta) && same(held.meta.callerContext, EVO);
    // the summary rule of SDK-API §18.6 item 7: every summaryCases row of the case file is one held call
    const summaryHolds: { name: string; holdId: string | null; summary: string }[] = [];
    for (const cs of caseFile().summaryCases) summaryHolds.push({ name: cs.name, holdId: (await k.hold(B, cs.context)).holdId, summary: cs.summary });
    const pend = await k.toX(B, "tb.holds_pending", { limit: 100 });
    const items = Array.isArray(out(pend).items) ? (out(pend).items as { id?: unknown; callerContext?: unknown }[]) : [];
    const item = items.find((x) => x.id === h.holdId);
    const summaryOk = item?.callerContext === EVO_SUMMARY;
    const summaryMisses = summaryHolds.filter((x) => !x.holdId || items.find((i) => i.id === x.holdId)?.callerContext !== x.summary).map((x) => x.name);
    return verdict(
      reached && receiptOk && listOk && holdsOk && summaryOk && summaryMisses.length === 0,
      `op → ctx.context ${shown(note)} four keys ${reached}; receipt meta.callerContext ${receiptOk}; tb.receipts_list ${listOk}; tb.holds_list ${holdsOk}; tb.holds_pending ${shown(pend)} summary ${JSON.stringify(item?.callerContext ?? null)}; ${summaryHolds.length - summaryMisses.length} of ${summaryHolds.length} summaryCases rows agree${summaryMisses.length ? ` (differ: ${summaryMisses.join(", ")})` : ""}`,
    );
  });

  const refused = async (key: string, want: string): Promise<{ pass: boolean; text: string }> => {
    const runs = noteRuns();
    const hits = noteHits();
    const r = await k.toX(B, CAP_TARGET.note, { id: `cap-${ulid()}` }, { context: { [key]: "x" } });
    const callsNow = noteRuns() - runs + (noteHits() - hits);
    return { pass: r.status === 400 && code(r) === "input_invalid" && pointer(r) === want && callsNow === 0, text: `${shown(r)} pointer ${pointer(r) ?? "(none)"}, target calls +${callsNow}` };
  };
  await run("B32.context_foreign_key", "a key of another product (kanban.card) → 400 input_invalid, details.pointer /context/kanban.card; the target is not called", async () => {
    const r = await refused("kanban.card", "/context/kanban.card");
    return verdict(r.pass, r.text);
  });
  await run("B32.context_tb_key", "a tb. key from an app (tb.onBehalfOf) → 400 input_invalid, pointer /context/tb.onBehalfOf; the target is not called", async () => {
    const r = await refused("tb.onBehalfOf", "/context/tb.onBehalfOf");
    return verdict(r.pass, r.text);
  });

  await run("B32.context_too_large", "JCS of 2049 bytes → 400 input_invalid /context; exactly 2048 accepted; every row of caller-context.cases.json through the bridge", async () => {
    const sized = (bytes: number): Record<string, Json> => {
      const base = Buffer.byteLength(canonicalize({ "evolution.note": "" }));
      return { "evolution.note": "x".repeat(bytes - base) };
    };
    const edge: string[] = [];
    const at = await k.toX(B, CAP_TARGET.note, { id: `cap-${ulid()}` }, { context: sized(2048) });
    if (at.status !== 200) edge.push(`2048 bytes: ${shown(at)}`);
    const runs = noteRuns();
    const over = await k.toX(B, CAP_TARGET.note, { id: `cap-${ulid()}` }, { context: sized(2049) });
    if (!(over.status === 400 && code(over) === "input_invalid" && pointer(over) === "/context" && noteRuns() === runs)) edge.push(`2049 bytes: ${shown(over)} pointer ${pointer(over) ?? "(none)"}`);
    const file = caseFile();
    const fails: string[] = [];
    let n = 0;
    for (const [i, cs] of file.cases.entries()) {
      const caller = cs.callerProduct === "evolution" ? (i % 2 === 0 ? A : B) : cs.callerProduct === "my-app" ? G : cs.callerProduct === null ? F : null;
      if (!caller) {
        fails.push(`${cs.name}: no fixture caller for product ${String(cs.callerProduct)}`);
        continue;
      }
      n++;
      const before = noteRuns();
      const r = await k.toX(caller, CAP_TARGET.note, { id: `cap-${ulid()}` }, { context: cs.context });
      const ran = noteRuns() - before;
      if (cs.ok) {
        if (!(r.status === 200 && ran === 1)) fails.push(`${cs.name}: expected accepted, got ${shown(r)} (target runs +${ran})`);
      } else if (!(r.status === 400 && code(r) === "input_invalid" && pointer(r) === cs.pointer && ran === 0)) fails.push(`${cs.name}: expected 400 input_invalid at ${String(cs.pointer)}, got ${shown(r)} at ${pointer(r) ?? "(none)"} (target runs +${ran})`);
    }
    const all = [...edge, ...fails];
    return verdict(all.length === 0, all.length === 0 ? `2048 bytes accepted, 2049 refused at /context; ${n} case rows agree` : all.slice(0, 5).join("; ") + (all.length > 5 ? `; … ${all.length} in all` : ""));
  });

  await run("B32.context_informational", "A's call with run_1 is held and approved; the identical repeat that reports run_2 runs once; the receipt keeps run_1 as callerContext and stores run_2 as callerContextRun", async () => {
    const ran = fx.target.runs.del;
    const h = await k.hold(A, EVO);
    if (!h.holdId) return bad(`the destructive op was not held: ${shown(h.a)}`);
    const declined = await k.decide(h.holdId, "approve");
    if (declined) return bad(declined);
    const run2 = { ...EVO, "evolution.run": "run_2" };
    const rep = await k.toX(A, CAP_TARGET.del, h.input, { key: h.key, context: run2 });
    const rc = await fx.target.receipts.get(h.holdId);
    const meta = rc && isObj(rc.meta) ? rc.meta : {};
    const pass = rep.status === 200 && fx.target.runs.del === ran + 1 && same(meta.callerContext, EVO) && same(meta.callerContextRun, run2);
    return verdict(pass, `repeat with run_2 ${shown(rep)}, handler runs +${fx.target.runs.del - ran}; receipt status ${rc?.status ?? "(none)"}, callerContext run ${JSON.stringify((meta.callerContext as Record<string, unknown> | undefined)?.["evolution.run"] ?? null)}, callerContextRun run ${JSON.stringify((meta.callerContextRun as Record<string, unknown> | undefined)?.["evolution.run"] ?? null)}`);
  });

  await run("B32.sdk_local_refusal", "a real SDK caller whose slice has no app_call_context: callApp with a context → bridge_cap_missing (409, details.cap) and the target is not called; with {} the call goes through and the target sees no caller key; an op outside wf → companion_undeclared first; with the cap a bad key → local input_invalid with details.pointer", async () => {
    const ctx = fx.caller.app.startContext();
    if (!ctx) return bad("the real caller has no start context");
    const mine = (run: string): Record<string, Json> => ({ [`${CAP_CALLER.product}.run`]: run });
    const caps = () => (ctx.bridgeCaps ? [...ctx.bridgeCaps()] : null);
    if (caps() === null) return notRun("the SDK under test has no ctx.bridgeCaps() (before miniapp-sdk 0.1.41): the SDK-side rules of SDK-API §18.6 are not implemented");
    const problems: string[] = [];
    const hits0 = noteHits();
    const noCap = await caught(() => ctx.callApp(CAP_TARGET.product, CAP_TARGET.note, { id: "a" }, { idempotencyKey: c.idemKey(), context: mine("r1") }));
    if (!(noCap?.code === "bridge_cap_missing" && noCap.status === 409 && isObj(noCap.details) && noCap.details.cap === APP_CALL_CONTEXT_CAP && noteHits() === hits0)) problems.push(`no cap: ${noCap ? `${noCap.code} ${String(noCap.status)} ${JSON.stringify(noCap.details)}` : "did not throw"}, target hits +${noteHits() - hits0}`);
    const hits1 = noteHits();
    const empty = await caught(() => ctx.callApp(CAP_TARGET.product, CAP_TARGET.note, { id: "b" }, { idempotencyKey: c.idemKey(), context: {} }));
    // observable here: the body the target receives (after the bridge merged its own tb.* keys), not the envelope the caller sent to the bridge
    const sent = fx.proxy.opHits(0, CAP_TARGET.note).at(-1);
    const sentContext = sent ? (JSON.parse(sent.body) as { context?: Record<string, unknown> }).context ?? {} : null;
    if (!(empty === null && noteHits() === hits1 + 1 && sentContext !== null && Object.keys(sentContext).every((key) => !key.startsWith(`${CAP_CALLER.product}.`)))) problems.push(`{} (no cap): ${empty ? `threw ${empty.code}` : "no throw"}, target hits +${noteHits() - hits1}, caller keys in the body the target got ${sentContext ? JSON.stringify(Object.keys(sentContext)) : "(none seen)"}`);
    const outside = await caught(() => ctx.callApp(CAP_TARGET.product, CAP_TARGET.del, { id: "c" }, { idempotencyKey: c.idemKey(), context: mine("r1") }));
    if (outside?.code !== "companion_undeclared") problems.push(`op outside wf with a context: ${outside ? outside.code : "did not throw"} (expected companion_undeclared)`);
    // the slice now carries the cap (the Portal signs it)
    c.w.sliceCaps.set(fx.caller.ins, [APP_CALL_CONTEXT_CAP]);
    await c.apply();
    const have = (await c.until(async () => caps()?.includes(APP_CALL_CONTEXT_CAP), c.h.timeoutMs)).value;
    if (!have) return bad(`${problems.join("; ")}${problems.length ? "; " : ""}the real caller's slice with the cap was not served within ${c.h.timeoutMs} ms`);
    const hits2 = noteHits();
    const badKey = await caught(() => ctx.callApp(CAP_TARGET.product, CAP_TARGET.note, { id: "d" }, { idempotencyKey: c.idemKey(), context: { "kanban.card": 1 } }));
    if (!(badKey?.code === "input_invalid" && badKey.status === 400 && isObj(badKey.details) && badKey.details.pointer === "/context/kanban.card" && noteHits() === hits2)) problems.push(`bad key with the cap: ${badKey ? `${badKey.code} ${String(badKey.status)} ${JSON.stringify(badKey.details)}` : "did not throw"}, target hits +${noteHits() - hits2}`);
    const good = await caught(() => ctx.callApp(CAP_TARGET.product, CAP_TARGET.note, { id: "e" }, { idempotencyKey: c.idemKey(), context: mine("r2") }));
    const reached = isObj(fx.target.runs.lastContext) && same((fx.target.runs.lastContext as Record<string, unknown>)[`${CAP_CALLER.product}.run`], "r2");
    if (!(good === null && reached)) problems.push(`good key with the cap: ${good ? good.code : "no throw"}, reached the target ${reached}`);
    c.w.sliceCaps.delete(fx.caller.ins);
    return verdict(problems.length === 0, problems.length === 0 ? "no cap: bridge_cap_missing and the target not called; {} accepted and the target got no caller key; undeclared op first; with the cap a bad key is refused locally and a good key reaches the target" : problems.join("; "));
  });

  await run("B32.context_tampered", "the context in the op body is changed after the bridge signed the proof → the app refuses call_proof_invalid and does not run", async () => {
    const path = `/tb/v1/ops/${CAP_TARGET.note}`;
    fx.proxy.tamper = (p, body) => {
      if (p !== path) return body;
      const j = JSON.parse(body) as { context?: Record<string, unknown> };
      return JSON.stringify({ ...j, context: { ...(j.context ?? {}), "evolution.run": "run_TAMPERED" } });
    };
    let tampered: HttpAnswer;
    const runs = noteRuns();
    try {
      tampered = await k.toX(B, CAP_TARGET.note, { id: `cap-${ulid()}` }, { key: c.idemKey(), context: EVO });
    } finally {
      fx.proxy.tamper = null;
    }
    const ranTampered = noteRuns() - runs;
    const control = await k.toX(B, CAP_TARGET.note, { id: `cap-${ulid()}` }, { key: c.idemKey(), context: EVO });
    const pass = tampered.status >= 400 && code(tampered) === "call_proof_invalid" && ranTampered === 0 && control.status === 200;
    return verdict(pass, `tampered: ${shown(tampered)} (handler runs +${ranTampered}); the same call untampered: ${shown(control)}`);
  });
}
