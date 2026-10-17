// Bridge target, spec 0.1.13 spine additions (CONFORMANCE v0.1.13, conformance 0.1.9; bridge 0.1.14+), group
// `spine013`: B22 hook hold verdict (BRIDGE §8.1 step 6, CREDENTIALS `hv`), B23 reserved context (§8.5 tb.onBehalfOf,
// the bridge-only `tb.` namespace), B24 app-initiated companion calls (§8.3 C85). The fake apps' hooks answer as each
// case needs; ops and hooks are picked from manifest data by shape (no product id in this source).
import { digest, onBehalfOfFromMeta, ulid, verifyCallProof } from "@opt2-tealbrick/manifest";
import type { HookEntry } from "@opt2-tealbrick/spec/bridge";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { FakeApp, Received } from "../fake-app.ts";
import { errorCode, type HttpAnswer } from "../http.ts";
import type { ToolCallResult } from "../mcp-agent.ts";
import { bad, na, verdict } from "../suite.ts";
import { versionBelow } from "../version.ts";
import { enrolRequests } from "./bridge.ts";
import { type BridgeCtx, describeCall, isObj, toolRefused } from "./bridge-ctx.ts";

type Chain = (HookEntry & { by: string })[];
const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const unb64 = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8")) as Record<string, unknown>;
const ON_BEHALF_OF_META = "tealbrick/onBehalfOf";

/** First bridge release whose hook requests carry `call.caller.product` (spec 0.1.45, HOOK-CALLER-PRODUCT). */
export const HOOK_CALLER_PRODUCT_SINCE = "0.2.2";

/** Enabled hook entries of `phase` that match a call of `op` at `app`, in chain order (order, then product). */
export function chainFor(c: BridgeCtx, app: FakeApp, op: Operation, phase: "before" | "context" | "after"): Chain {
  return c.w
    .hookEntries()
    .filter((h) => {
      const m = h.match;
      return h.enabled !== false && h.phase === phase && (m.products.includes("*") || m.products.includes(app.product)) && (!m.operations || m.operations.includes(op.id)) && (!m.effects || m.effects.includes(op.effect));
    })
    .sort((a, b) => a.order - b.order || (a.product < b.product ? -1 : a.product > b.product ? 1 : 0))
    .map((h) => ({ ...h, by: `${h.product}/${h.hookId}` }));
}

export async function spine013Checks(c: BridgeCtx): Promise<void> {
  if (!c.on("spine013")) return;
  const p = c.primary;
  const peer = c.peer;
  const apps = c.w.apps;
  const appOf = (product: string) => apps.find((a) => a.product === product);
  const reset = () => {
    for (const a of apps) {
      a.onHook = null;
      a.onOp = null;
    }
  };
  /** every fake app answers its hooks: before by `<product>/<hookId>` from `before` (default allow), context from `context` (default nothing) */
  const answer = (before: Record<string, unknown> = {}, context: Record<string, unknown> = {}) => {
    for (const a of apps)
      a.onHook = (hookId, phase) => {
        const by = `${a.product}/${hookId}`;
        if (phase === "before") return { status: 200, body: before[by] ?? { allow: true } };
        if (phase === "context") return { status: 200, body: context[by] ?? { add: {} } };
        return { status: 200, body: {} };
      };
  };
  const hookCalls = (seq: number, h: { product: string; hookId: string }): Received[] => {
    const a = appOf(h.product);
    return a ? c.since(a, seq, "hook").filter((r) => r.name === h.hookId) : [];
  };
  const opCalls = (app: FakeApp, seq: number, op?: string) => c.since(app, seq, "op").filter((r) => op === undefined || r.name === op);
  const held = () => ({ status: 202, body: { status: "held", holdId: `hld_${ulid()}`, expiresAt: new Date(Date.now() + 900_000).toISOString() } });
  const isHeldResult = (r: ToolCallResult) => c.isOk(r) && r.structured?.status === "held";
  const brief = (r: ToolCallResult) => (isHeldResult(r) ? `HTTP ${r.status} held` : describeCall(r));
  const hv = (rec: Received | undefined) => (rec?.proof && isObj(rec.proof.hv) ? rec.proof.hv : null);
  const hvShow = (rec: Received | undefined) => {
    const v = hv(rec);
    return rec ? (v ? `hv {f ${String(v.f)}, by ${String(v.by)}}` : "no hv") : "op not called";
  };
  const hold = (family: string, reason: string) => ({ allow: false, hold: { family, reason } });

  // ── B22 hold verdict: the primary op with the longest before chain (≥ 2 hooks for the precedence cases) ──
  const candidates = c.agentOps(p).map((op) => ({ op, chain: chainFor(c, p, op, "before") }));
  const pick = candidates.sort((x, y) => y.chain.length - x.chain.length || Number(x.op.effect !== "read") - Number(y.op.effect !== "read"))[0];
  let withHv: Received | undefined;
  await c.run("B22.hold_verdict", "before hook hold verdict → forwarded with hv; refuse > hold > allow; first hold kept; a later refuse wins", "all allow → no hv; first hook holds → op proof hv {f, r, by: <product>/<hookId>} and the held answer returned; two holds → the first kept, the chain still runs; hold then refuse → hook_denied, op not called", async () => {
    if (!pick || pick.chain.length < 2) return bad(`no op of the primary app with ≥ 2 matching before hooks (longest chain ${pick?.chain.length ?? 0})`);
    const { op, chain } = pick;
    const [h1, h2] = chain as [Chain[number], Chain[number]];
    const r1 = `conformance policy hold ${ulid()}`;
    const r2 = `conformance second hold ${ulid()}`;
    const out: string[] = [];
    let pass = true;
    try {
      p.onOp = () => held();
      answer();
      let s0 = c.w.seqNow();
      const allow = await c.call("free", p, op.id);
      const recAllow = opCalls(p, s0, op.id)[0];
      pass &&= c.isOk(allow) && !!recAllow?.verified && hv(recAllow) === null;
      out.push(`allow: ${brief(allow)}, ${hvShow(recAllow)}`);

      answer({ [h1.by]: hold("policy", r1) });
      s0 = c.w.seqNow();
      const one = await c.call("free", p, op.id);
      const rec1 = opCalls(p, s0, op.id)[0];
      const v1 = hv(rec1);
      const good1 = isHeldResult(one) && !!rec1?.verified && v1?.f === "policy" && v1.r === r1 && v1.by === h1.by;
      if (good1) withHv = rec1;
      pass &&= good1;
      out.push(`${h1.by} holds: ${brief(one)}, ${hvShow(rec1)}${v1 && v1.r !== r1 ? " (r differs)" : ""}`);

      answer({ [h1.by]: hold("policy", r1), [h2.by]: hold("first_contact", r2) });
      s0 = c.w.seqNow();
      const two = await c.call("free", p, op.id);
      const rec2 = opCalls(p, s0, op.id)[0];
      const v2 = hv(rec2);
      const ran2 = hookCalls(s0, h2).length;
      pass &&= isHeldResult(two) && v2?.f === "policy" && v2.r === r1 && v2.by === h1.by && ran2 === 1;
      out.push(`both hold: ${hvShow(rec2)}, ${h2.by} called ${ran2}×`);

      answer({ [h1.by]: hold("policy", r1), [h2.by]: { allow: false, reason: "conformance refusal after a hold" } });
      s0 = c.w.seqNow();
      const refused = await c.call("free", p, op.id);
      const ops3 = opCalls(p, s0).length;
      const o = toolRefused(refused, ["hook_denied"]);
      pass &&= o.pass === true && ops3 === 0 && hookCalls(s0, h2).length === 1;
      out.push(`hold then refuse: ${o.asserted}, op calls ${ops3}`);
    } finally {
      reset();
    }
    return verdict(pass, `${op.id} chain [${chain.map((h) => h.by).join(", ")}]: ${out.join("; ")}`);
  });

  await c.run("B22.hold_retry_refused", "the retry re-runs the before chain (C82)", "same call (same input and idempotency key): hold → held with hv; retry while the hook refuses → hook_denied, op not called; retry while it holds again → op called with hv again", async () => {
    if (!pick || pick.chain.length < 1) return bad("no op of the primary app with a matching before hook");
    const { op, chain } = pick;
    const h1 = chain[0] as Chain[number];
    const input = c.input(p, op.id);
    const key = op.idempotency === "none" ? null : c.idemKey();
    const reason = `conformance retry hold ${ulid()}`;
    let n = 0;
    try {
      p.onOp = () => (n++ === 0 ? held() : { status: 200, body: { status: "ok", output: { approved: true } } });
      answer({ [h1.by]: hold("policy", reason) });
      let s0 = c.w.seqNow();
      const first = await c.call("free", p, op.id, input, key);
      const rec1 = opCalls(p, s0, op.id)[0];
      answer({ [h1.by]: { allow: false, reason: "conformance: the hook refuses the retry" } });
      s0 = c.w.seqNow();
      const retryRefused = await c.call("free", p, op.id, input, key);
      const opsRefused = opCalls(p, s0).length;
      answer({ [h1.by]: hold("policy", reason) });
      s0 = c.w.seqNow();
      const retryHeld = await c.call("free", p, op.id, input, key);
      const rec3 = opCalls(p, s0, op.id)[0];
      const o = toolRefused(retryRefused, ["hook_denied"]);
      const pass = isHeldResult(first) && hv(rec1)?.by === h1.by && o.pass === true && opsRefused === 0 && c.isOk(retryHeld) && hv(rec3)?.by === h1.by && hv(rec3)?.r === reason;
      return verdict(pass, `${op.id}: hold ${brief(first)} (${hvShow(rec1)}); retry, hook refuses: ${o.asserted}, op calls ${opsRefused}; retry, hook holds: ${brief(retryHeld)} (${hvShow(rec3)})`);
    } finally {
      reset();
    }
  });

  await c.run("B22.hv_tamper", "hv is signed inside the op proof", "the captured op proof with hv verifies at the app; the same proof with hv.r edited, hv.by edited or hv removed (signature kept) is refused", () => {
    const rec = withHv;
    const token = rec?.headers["tb-call"];
    if (!rec || !token || !rec.grant || !rec.proof) return bad("no op proof with hv captured (B22.hold_verdict)");
    const body = JSON.parse(rec.body) as { input: Json; context: Json };
    const bind = { op: rec.name, inputDigest: digest(body.input), contextDigest: digest(body.context), grantJti: String(rec.grant.jti), grantSub: String(rec.grant.sub) };
    const [h, pl, sig] = token.split(".") as [string, string, string];
    const edit = (f: (claims: Record<string, unknown>) => void) => {
      const claims = unb64(pl);
      f(claims);
      return `${h}.${b64(claims)}.${sig}`;
    };
    const trust = p.trust();
    const orig = verifyCallProof(token, trust, bind);
    const results = {
      reason: verifyCallProof(edit((x) => ((x.hv as Record<string, unknown>).r = `${String((x.hv as Record<string, unknown>).r)} (edited)`)), trust, bind),
      by: verifyCallProof(edit((x) => ((x.hv as Record<string, unknown>).by = "tbconf-forged/forged_hook")), trust, bind),
      removed: verifyCallProof(edit((x) => delete x.hv), trust, bind),
    };
    const shown = Object.entries(results).map(([k, r]) => `${k} ${r.ok ? "ACCEPTED" : "refused"}`);
    // the original was signed seconds ago: an expiry here would hide nothing (the edited copies carry the same exp)
    return verdict(orig.ok && Object.values(results).every((r) => !r.ok), `original ${orig.ok ? "verifies" : `refused (${orig.ok ? "" : orig.reason})`}; edited: ${shown.join(", ")}`);
  });

  // ── B23 reserved context ──
  const read = c.readOp(p);
  await c.run("B23.on_behalf_of", "_meta tealbrick/onBehalfOf → context tb.onBehalfOf (unverified)", "valid claim: the before hooks and the app get context tb.onBehalfOf = {claim, verified: false, via: mcp_meta} (covered by the proof ctx); an invalid claim (id > 256 chars) is dropped, the call proceeds, and a status report lists rejected {kind: claim, code: on_behalf_of_invalid}", async () => {
    if (!read) return bad("no read op on the primary app");
    const claim = { kind: "channel_sender", id: "slack:UCONFORMANCE", display: "Conformance sender" };
    const want = onBehalfOfFromMeta(claim);
    if (!want) return bad("onBehalfOfFromMeta refused the probe claim");
    try {
      answer();
      let s0 = c.w.seqNow();
      const a = await c.call("free", p, read.id, undefined, undefined, { [ON_BEHALF_OF_META]: claim });
      const rec = opCalls(p, s0, read.id)[0];
      const ctxOf = (r: Received) => (JSON.parse(r.body) as { context?: Record<string, unknown> }).context ?? {};
      const atApp = rec ? ctxOf(rec)["tb.onBehalfOf"] : undefined;
      const appOk = !!rec?.verified && atApp !== undefined && digest(atApp as Json) === digest(want as unknown as Json);
      const befores = chainFor(c, p, read, "before").flatMap((h) => hookCalls(s0, h));
      const hooksOk = befores.length > 0 && befores.every((r) => digest((ctxOf(r)["tb.onBehalfOf"] ?? null) as Json) === digest(want as unknown as Json));
      const acks0 = c.w.portal.acks.length;
      s0 = c.w.seqNow();
      const big = await c.call("free", p, read.id, undefined, undefined, { [ON_BEHALF_OF_META]: { kind: "person", id: "p".repeat(300) } });
      const recBig = opCalls(p, s0, read.id)[0];
      const dropped = c.isOk(big) && !!recBig && !("tb.onBehalfOf" in ctxOf(recBig));
      await c.apply();
      const reported = await c.until(async () => c.w.portal.acks.slice(acks0).some((x) => (x.rejected ?? []).some((r) => r.kind === "claim" && r.code === "on_behalf_of_invalid")), c.h.timeoutMs);
      return verdict(
        c.isOk(a) && appOk && hooksOk && dropped && !!reported.value,
        `valid: ${describeCall(a)}, app context ${atApp === undefined ? "missing" : appOk ? "= {claim, verified: false, via: mcp_meta}" : JSON.stringify(atApp).slice(0, 120)}, ${befores.length} before hook calls ${hooksOk ? "see it" : "MISS it"}; invalid: ${describeCall(big)}, ${dropped ? "dropped" : "NOT dropped"}; status report ${reported.value ? "lists claim/on_behalf_of_invalid" : "does not list claim/on_behalf_of_invalid"}`,
      );
    } finally {
      reset();
    }
  });

  await c.run("B23.reserved_tb_namespace", "a context hook writing tb.* → hook_failed (fail closed)", "context hook answers {add: {\"tb.onBehalfOf\": …}} → isError hook_failed; op not called", async () => {
    if (!read) return bad("no read op on the primary app");
    const ctxHook = chainFor(c, p, read, "context")[0];
    if (!ctxHook) return bad("no context hook matches a primary read op");
    try {
      answer({}, { [ctxHook.by]: { add: { "tb.onBehalfOf": { claim: { kind: "person", id: "per_forged" }, verified: true, via: "mcp_meta" } } } });
      const s0 = c.w.seqNow();
      const a = await c.call("free", p, read.id);
      const o = toolRefused(a, ["hook_failed"]);
      const ops = opCalls(p, s0).length;
      return verdict(o.pass === true && ops === 0 && hookCalls(s0, ctxHook).length === 1, `${ctxHook.by} adds tb.onBehalfOf: ${o.asserted}; op calls ${ops}`);
    } finally {
      reset();
    }
  });

  // ── B24 app-initiated companion calls (no parentCall) ──
  const edge = p.manifest.companions?.[0];
  const pg = c.w.companionGrants.get(p.ins) ?? null;
  const status = (a: HttpAnswer) => (isObj(a.body) && typeof a.body.status === "string" ? `${a.status} ${a.body.status}` : `${a.status} ${errorCode(a.body) ?? ""}`);
  await c.run("B24.app_initiated", "companion call without parentCall passes the whole pipeline", "200; every matching hook (before, context, after) sees call.caller {type: app, id: <caller instance>}; the target receives a verified grant + proof with sub tb:ins:<caller>", async () => {
    if (!peer || !edge || !pg) return bad("no companion edge between the primary and the peer app");
    const opId = edge.operations[0] as string;
    const op = c.op(peer, opId);
    if (!op) return bad(`peer has no op ${opId}`);
    try {
      answer();
      const s0 = c.w.seqNow();
      const a = await p.companion({ target: peer.product, op: opId, input: c.input(peer, opId) as Json }, pg);
      const rec = opCalls(peer, s0, opId)[0];
      const phases = (["before", "context", "after"] as const).map((ph) => ({ ph, hooks: chainFor(c, peer, op, ph) })).filter((x) => x.hooks.length > 0);
      const seen = phases.map(({ ph, hooks }) => {
        const calls = hooks.flatMap((h) => hookCalls(s0, h));
        const asApp = calls.filter((r) => {
          const caller = (JSON.parse(r.body) as { call?: { caller?: { type?: unknown; id?: unknown } } }).call?.caller;
          return caller?.type === "app" && caller.id === p.ins;
        });
        return { ph, n: hooks.length, calls: calls.length, asApp: asApp.length };
      });
      const hooksOk = seen.length > 0 && seen.every((x) => x.calls === x.n && x.asApp === x.n);
      const opOk = !!rec?.verified && rec.grant?.sub === `tb:ins:${p.ins}` && rec.proof?.sub === `tb:ins:${p.ins}`;
      return verdict(a.status === 200 && opOk && hooksOk, `${status(a)}; target op ${rec ? `verified ${rec.verified}, sub ${String(rec.proof?.sub)}` : "not called"}; hooks ${seen.map((x) => `${x.ph} ${x.asApp}/${x.n} as app`).join(", ") || "none match"}`);
    } finally {
      reset();
    }
  });

  await c.run("B24.no_grant", "app-initiated call without its grant or for an undeclared op is refused", "no TB-Grant → 4xx; an op outside the companion edge → 4xx; the target is called in neither case", async () => {
    if (!peer || !edge || !pg) return bad("no companion edge between the primary and the peer app");
    const opId = edge.operations[0] as string;
    const outside = c.pick(peer, (o) => !edge.operations.includes(o.id) && !o.dynamic);
    if (!outside) return bad("no peer op outside the companion edge");
    const s0 = c.w.seqNow();
    const none = await p.companion({ target: peer.product, op: opId, input: c.input(peer, opId) as Json }, null);
    const undeclared = await p.companion({ target: peer.product, op: outside.id, input: c.input(peer, outside.id) as Json }, pg);
    const calls = opCalls(peer, s0).length;
    const refused = (x: HttpAnswer) => x.status >= 400 && x.status < 500;
    return verdict(refused(none) && refused(undeclared) && calls === 0, `no grant: ${status(none)}; undeclared ${outside.id}: ${status(undeclared)}; target op calls ${calls}`);
  });

  // ── B28 hook caller product (spec 0.1.45, BRIDGE v0.1.45; bridge 0.2.2+): version-gated, older bridges are not_applicable ──
  await c.run(
    "B28.hook_caller_product",
    "hook requests of an app-initiated call carry call.caller.product = the caller instance's product; an agent call carries none",
    "app-initiated companion call (no parentCall) → every matching hook (before, context, after) sees call.caller {type: app, id: <caller instance>, product: <the caller's product from the signed config>}, also when the input names another product; an agent call's hooks see call.caller {type: agent} with no product key; bridges older than 0.2.2 are not_applicable by version",
    async () => {
      const version = enrolRequests(c)[0]?.version;
      if (versionBelow(version, HOOK_CALLER_PRODUCT_SINCE)) return na(`bridge ${version} predates ${HOOK_CALLER_PRODUCT_SINCE} (HOOK-CALLER-PRODUCT, spec 0.1.45): not applicable by version`);
      if (!peer || !edge || !pg) return bad("no companion edge between the primary and the peer app");
      const opId = edge.operations[0] as string;
      const op = c.op(peer, opId);
      if (!op) return bad(`peer has no op ${opId}`);
      const callerOf = (r: Received) => (JSON.parse(r.body) as { call?: { caller?: Record<string, unknown> } }).call?.caller;
      const phases = (["before", "context", "after"] as const).map((ph) => ({ ph, hooks: chainFor(c, peer, op, ph) })).filter((x) => x.hooks.length > 0);
      if (phases.length === 0) return bad(`no hook matches the companion op ${opId} of the peer`);
      // a decoy: the input names another product (when the op's input admits extra properties); the bridge must not read it
      const base = c.input(peer, opId) as Json;
      const decoy = isObj(base) && (op.input as { additionalProperties?: unknown } | undefined)?.additionalProperties !== false && !("product" in base);
      const input = decoy ? ({ ...(base as Record<string, Json>), product: "tbconf-forged-product" } as Json) : base;
      try {
        answer();
        let s0 = c.w.seqNow();
        const a = await p.companion({ target: peer.product, op: opId, input }, pg);
        const seen = phases.map(({ ph, hooks }) => {
          const calls = hooks.flatMap((h) => hookCalls(s0, h));
          const withProduct = calls.filter((r) => {
            const caller = callerOf(r);
            return caller?.type === "app" && caller.id === p.ins && caller.product === p.product;
          });
          const products = [...new Set(calls.map((r) => JSON.stringify(callerOf(r)?.product ?? null)))].join("|");
          return { ph, n: hooks.length, calls: calls.length, good: withProduct.length, products };
        });
        const appOk = a.status === 200 && seen.every((x) => x.calls === x.n && x.good === x.n);
        // an agent call: the hooks see the agent and NO product key
        const agentOp = c.readOp(peer) ?? c.agentOps(peer)[0];
        let agentShown = "no agent op on the peer";
        let agentOk = false;
        if (agentOp) {
          s0 = c.w.seqNow();
          const r = await c.call("free", peer, agentOp.id);
          const hooks = (["before", "context", "after"] as const).flatMap((ph) => chainFor(c, peer, agentOp, ph));
          const calls = hooks.flatMap((h) => hookCalls(s0, h));
          const clean = calls.filter((x) => callerOf(x)?.type === "agent" && !("product" in (callerOf(x) ?? {})));
          agentOk = c.isOk(r) && calls.length > 0 && clean.length === calls.length;
          agentShown = `${describeCall(r)}; ${clean.length}/${calls.length} hook calls see an agent without product`;
        }
        return verdict(
          appOk && agentOk,
          `app-initiated${decoy ? " (input names product tbconf-forged-product)" : ""}: ${status(a)}; hooks ${seen.map((x) => `${x.ph} ${x.good}/${x.n} carry product ${p.product}${x.good < x.n ? ` (saw ${x.products || "no calls"})` : ""}`).join(", ")}; agent call: ${agentShown}`,
        );
      } finally {
        reset();
      }
    },
  );
}
