// R-PO (conformance 0.1.31, spec 0.1.64, BRIDGE §16, C326): the person-op relay of a bridge that DECLARES the `person_ops`
// capability. Gated by the capability the bridge reports in its StatusReport (`bridge.caps`), never by version (C292): without it
// every row is not_applicable, except that R-PO-1 fails a bridge that polls without declaring the cap. The suite plays Core (the
// fake Portal queues rows with a K14 signed by its key and records the result posts) and the app (the primary fake app answers
// `POST /tb/v1/person-op` as each row plans it and records the exact bytes it received).
import { ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import type { OpAnswerSpec, Received } from "../fake-app.ts";
import type { PersonOpResultSeen, QueuedPersonOp } from "../fake-portal.ts";
import { bodyDigest, PERSON_OP_ROUTE, PERSON_OPS_CAP } from "../person-op.ts";
import { bad, na, notRun, type Outcome, ok, verdict } from "../suite.ts";
import { newId, peek } from "../tokens.ts";
import { reportedBridgeCaps } from "./bridge.ts";
import { type BridgeCtx, sleep } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

const TITLES: Record<string, string> = Object.fromEntries((BRIDGE_GROUPS.person_ops ?? []).map((x) => [x.id, x.title]));
const title = (id: string): string => TITLES[id] ?? id;
/** the bridge's forward timeout (BRIDGE §16) */
const FORWARD_MS = PERSON_OP_RELAY.bridgeForwardS * 1000;

type Plan = OpAnswerSpec & { holdMs?: number };

export async function personOpChecks(c: BridgeCtx): Promise<void> {
  const portal = c.w.portal;
  const T = c.h.timeoutMs;
  const caps = reportedBridgeCaps(c);
  if (!caps.includes(PERSON_OPS_CAP)) {
    const why = `the bridge does not declare the ${PERSON_OPS_CAP} capability in its StatusReport (bridge.caps = ${JSON.stringify(caps)}): BRIDGE §16 is not announced, so this row does not apply (decided by capability, never by version, C292)`;
    await c.run("R-PO-1", title("R-PO-1"), "no person_ops cap → no GET /bridge/person-ops at the fake Portal during the run (≥ 2 s observed)", async () => {
      await sleep(Math.min(T, 2000));
      const polls = c.w.portal.captured.filter((r) => r.method === "GET" && r.path.split("?")[0] === "/api/v1/bridge/person-ops").length;
      return polls === 0 ? na(why) : bad(`${polls} GET /api/v1/bridge/person-ops from a bridge that does not declare ${PERSON_OPS_CAP} (caps ${JSON.stringify(caps)}): cap declared ⇔ relay implemented`);
    });
    for (const id of ["R-PO-2", "R-PO-3", "R-PO-4", "R-PO-5", "R-PO-6"]) await c.run(id, title(id), "BRIDGE §16", () => na(why));
    return;
  }

  const app = c.primary;
  const plans = new Map<string, Plan>();
  const relayed: QueuedPersonOp[] = [];
  const answerMarkers: string[] = [];
  /** wait for a row's result: the bridge's long-poll takes it at once, the forward may take up to the forward timeout */
  const resultWait = T + FORWARD_MS + 2000;
  const forwardsOf = (row: QueuedPersonOp): Received[] => c.w.apps.flatMap((a) => a.received.filter((r) => r.kind === "person_op" && r.headers["tb-person-op"] === row.item.jws));
  const queue = async (ins: InstanceId, op: string, body: string, plan?: Plan): Promise<QueuedPersonOp> => {
    const row = await portal.queuePersonOp({ ins, op, body });
    if (plan) plans.set(row.item.id, plan);
    relayed.push(row);
    return row;
  };
  const describeRow = (row: QueuedPersonOp, r: PersonOpResultSeen | null): string =>
    r ? `result status ${r.status}` : `no result post within ${resultWait} ms (${row.expired ? `row expired untaken after ${portal.personOpTtlMs} ms` : row.takenAt === null ? "row never taken" : "row taken"})`;
  const sameJson = (text: string, want: unknown): boolean => {
    try {
      return JSON.stringify(JSON.parse(text)) === JSON.stringify(want);
    } catch {
      return false;
    }
  };
  const answer = (code: string | null, extra: Record<string, unknown> = {}): unknown => {
    const m = `tbconf-poans-${ulid()}`;
    answerMarkers.push(m);
    return code ? { error: { code, message: `conformance ${m}`, requestId: "req_tbconf" } } : { status: "ok", output: { marker: m, ...extra } };
  };
  app.onPersonOp = (rec) => {
    const pop = String(peek(rec.headers["tb-person-op"] ?? "")?.pop ?? "");
    return plans.get(pop) ?? { status: 200, body: { status: "ok", output: {} } };
  };

  try {
    await c.run("R-PO-1", title("R-PO-1"), `the bridge declares ${PERSON_OPS_CAP} → GET /api/v1/bridge/person-ops with a valid bridge assertion and wait in 1..${PERSON_OP_RELAY.pollWaitS}; never more than one poll open at a time`, async () => {
      const seen = await c.until(async () => portal.personOpPolls.length > 0, T);
      const polls = portal.personOpPolls;
      if (!seen.value) return bad(`caps ${JSON.stringify(caps)}, but no accepted GET /api/v1/bridge/person-ops within ${T} ms (captured: ${portal.captured.filter((r) => r.path.startsWith("/api/v1/bridge/person-ops")).length} incl. refused)`);
      const waits = [...new Set(polls.map((p) => p.wait))];
      const waitOk = polls.every((p) => p.wait !== null && Number.isInteger(p.wait) && p.wait >= 1 && p.wait <= PERSON_OP_RELAY.pollWaitS);
      return verdict(waitOk && portal.personOpPollsMaxOpen <= 1, `${polls.length} accepted polls; wait ${JSON.stringify(waits)}; at most ${portal.personOpPollsMaxOpen} open at once`);
    });

    await c.run("R-PO-2", title("R-PO-2"), "a row for an instance id no config lists → the result post has status 409 and body {error: {code: instance_unknown}}; no fake app receives a person op for it", async () => {
      const row = await queue(newId("ins") as InstanceId, "items_list", "{}");
      const r = await portal.waitPersonOpResult(row.item.id, resultWait);
      await sleep(300);
      const fwd = forwardsOf(row).length;
      if (!r) return bad(describeRow(row, r));
      // BRIDGE §16 names the body {error: {code: "instance_unknown"}}: only error.code is read (message / requestId optional)
      const code = (() => {
        try {
          const e = (JSON.parse(r.body) as { error?: { code?: unknown } } | null)?.error;
          return typeof e?.code === "string" ? e.code : null;
        } catch {
          return null;
        }
      })();
      return verdict(r.status === 409 && code === "instance_unknown" && fwd === 0, `${describeRow(row, r)}, code ${code ?? "(none)"}; forwards ${fwd}`);
    });

    await c.run("R-PO-3", title("R-PO-3"), "a body with non-ASCII text and non-canonical spacing → the app receives exactly one POST /tb/v1/person-op whose bytes hash to K14 bd, TB-Person-Op = the K14, content-type application/json; the result is the app's status and body", async () => {
      const marker = `tbconf-pobody-${ulid()}`;
      const body = `{"note":"Grüße, 日本語 — ✓ ${marker}",  "n" : 1,\n "z":[ ] }`;
      const want = answer(null, { echo: "unchanged ✓" });
      const row = await queue(app.ins, "items_list", body, { status: 200, body: want });
      const r = await portal.waitPersonOpResult(row.item.id, resultWait);
      const fwd = forwardsOf(row);
      const f = fwd[0];
      if (!r || !f) return bad(`${describeRow(row, r)}; forwards ${fwd.length}`);
      const bytesOk = bodyDigest(f.raw ?? Buffer.alloc(0)) === row.claims.bd;
      const headerOk = f.headers["tb-person-op"] === row.item.jws;
      const typeOk = (f.headers["content-type"] ?? "").startsWith("application/json");
      const pathOk = f.path === PERSON_OP_ROUTE && f.method === "POST";
      const resultOk = r.status === 200 && sameJson(r.body, want);
      return verdict(
        fwd.length === 1 && bytesOk && headerOk && typeOk && pathOk && resultOk,
        `forwards ${fwd.length} to ${f.method} ${f.path}; body ${f.raw?.length ?? 0} bytes, sha256 ${bytesOk ? "= bd" : `≠ bd (${bodyDigest(f.raw ?? Buffer.alloc(0)).slice(0, 20)}… vs ${row.claims.bd.slice(0, 20)}…)`}; TB-Person-Op ${headerOk ? "= K14" : "≠ K14"}; content-type ${f.headers["content-type"] ?? "(none)"}; ${describeRow(row, r)}, body ${resultOk ? "= the app's answer" : "≠ the app's answer"}`,
      );
    });

    // R-PO-5 / R-PO-6 share their observations: a 500, an answer held past the forward timeout, the app down, a refusal
    const r500 = await (async () => {
      const row = await queue(app.ins, "item_ack", `{"id":"tbconf-poid-${ulid()}"}`, { status: 500, body: answer("internal") });
      const r = await portal.waitPersonOpResult(row.item.id, resultWait);
      await sleep(1500);
      return { row, r, fwd: forwardsOf(row).length };
    })();
    const hung = await (async () => {
      const row = await queue(app.ins, "item_ack", `{"id":"tbconf-poid-${ulid()}"}`, { status: 200, body: answer(null), holdMs: FORWARD_MS + 3000 });
      const r = await portal.waitPersonOpResult(row.item.id, resultWait);
      await sleep(2000);
      return { row, r, fwd: forwardsOf(row).length };
    })();
    await c.run("R-PO-5", title("R-PO-5"), `the app answers 500 → exactly one request and result 500; the app holds its answer ${FORWARD_MS + 3000} ms (past the ${FORWARD_MS} ms forward timeout) → exactly one request, also 2 s after the result`, () =>
      verdict(
        r500.fwd === 1 && r500.r?.status === 500 && hung.fwd === 1 && hung.r !== null,
        `500: forwards ${r500.fwd}, ${describeRow(r500.row, r500.r)}; held answer: forwards ${hung.fwd}, ${describeRow(hung.row, hung.r)}`,
      ),
    );

    await c.run("R-PO-6", title("R-PO-6"), "the app's listener closed (connection refused) → status -1 and no forward; the answer held past the forward timeout → status 0; a 403 envelope and a 500 come back with the app's status and body", async () => {
      await app.stop();
      let down: { row: QueuedPersonOp; r: PersonOpResultSeen | null };
      try {
        const row = await queue(app.ins, "item_get", `{"id":"tbconf-poid-${ulid()}"}`);
        down = { row, r: await portal.waitPersonOpResult(row.item.id, resultWait) };
      } finally {
        await app.start();
      }
      const refusal = answer("person_op_not_allowed");
      const row403 = await queue(app.ins, "item_get", `{"id":"tbconf-poid-${ulid()}"}`, { status: 403, body: refusal });
      const r403 = await portal.waitPersonOpResult(row403.item.id, resultWait);
      const passed = r403?.status === 403 && sameJson(r403.body, refusal) && r500.r?.status === 500 && sameJson(r500.r.body, plans.get(r500.row.item.id)?.body);
      return verdict(
        down.r?.status === -1 && hung.r?.status === 0 && passed,
        `app down: ${describeRow(down.row, down.r)}; held past timeout: ${describeRow(hung.row, hung.r)}; 403: ${describeRow(row403, r403)}${r403 && !sameJson(r403.body, refusal) ? " (body changed)" : ""}; 500: ${describeRow(r500.row, r500.r)}${passed ? "; bodies passed through" : ""}`,
      );
    });

    await c.run("R-PO-4", title("R-PO-4"), "the bridge's captured stdout/stderr contain none of the relayed bodies (their markers), the app answers (their markers) or the K14s (whole token, payload or signature segment)", (): Outcome => {
      const logs = c.h.logs();
      if (logs === null) return notRun("this harness cannot capture the bridge's logs (run the bridge with --cmd or --start): R-PO-4 is not observable, so it is not run");
      const bodyMarkers = relayed.flatMap((r) => [...r.item.body.matchAll(/tbconf-[a-z]+-[0-9A-Z]{26}/g)].map((m) => m[0]));
      const tokens = relayed.flatMap((r) => [r.item.jws, ...r.item.jws.split(".").slice(1)]);
      const needles = [...bodyMarkers, ...answerMarkers, ...tokens].filter((x) => x.length >= 16);
      const hits = needles.filter((n) => logs.includes(n));
      if (relayed.length === 0) return bad("no row was relayed");
      return hits.length === 0
        ? ok(`${logs.length} log bytes; ${relayed.length} relayed rows, ${needles.length} needles: none found`)
        : bad(`${hits.length} of ${needles.length} needles in the bridge's logs (e.g. ${hits[0]?.slice(0, 24)}…)`);
    });
  } finally {
    app.onPersonOp = null;
    if (!app.up) await app.start().catch(() => undefined);
  }
}
