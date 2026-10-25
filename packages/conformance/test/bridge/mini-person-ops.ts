// The mini bridge's person-op relay (BRIDGE §16, spec 0.1.64; NOT a product bridge): one long-poll of GET /api/v1/bridge/person-ops,
// one forward per row to `<internalUrl>/tb/v1/person-op` with the K14 in TB-Person-Op and the body bytes unchanged, the result
// posted to /api/v1/bridge/person-ops/{pop}/result. Each fault breaks exactly one rule so a test can prove the matching R-PO row fails.
import type { WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import { type BridgePersonOp, PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";

export interface MiniPersonOpFaults {
  /** forwards a re-serialisation of the body instead of its bytes (fails R-PO-3) */
  rewritesBody?: boolean;
  /** forwards once more after a 5xx answer or a timeout (fails R-PO-5) */
  retries?: boolean;
  /** logs the body and the K14 of every row (fails R-PO-4) */
  logsBody?: boolean;
  /** answers a row of an unknown instance -1 instead of 409 instance_unknown (fails R-PO-2) */
  unknownInsNotDelivered?: boolean;
  /** maps a refused connection to 0 instead of -1 (fails R-PO-6) */
  zeroForUnreachable?: boolean;
}

export interface MiniPersonOpDeps {
  portalCall(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<Response>;
  config(): WorkspaceConfig | null;
  stopped(): boolean;
  log(line: string): void;
  faults: MiniPersonOpFaults;
}

const POLL = "/api/v1/bridge/person-ops";
/** short long-poll: the mini bridge's portal client gives up after a few seconds */
const WAIT_S = 3;

export function runMiniPersonOps(d: MiniPersonOpDeps): void {
  const f = d.faults;
  const forward = async (url: string, item: BridgePersonOp): Promise<{ status: number; body: string }> => {
    try {
      const res = await fetch(new URL("/tb/v1/person-op", url), {
        method: "POST",
        headers: { "TB-Person-Op": item.jws, "content-type": "application/json" },
        body: f.rewritesBody ? JSON.stringify(JSON.parse(item.body)) : Buffer.from(item.body, "utf8"),
        signal: AbortSignal.timeout(PERSON_OP_RELAY.bridgeForwardS * 1000),
      });
      return { status: res.status, body: await res.text() };
    } catch (e) {
      const refused = (e as { cause?: { code?: unknown } }).cause?.code === "ECONNREFUSED";
      return { status: refused && !f.zeroForUnreachable ? -1 : 0, body: "" };
    }
  };
  const handle = async (item: BridgePersonOp): Promise<void> => {
    const app = d.config()?.apps.find((a) => a.ins === item.ins);
    let result: { status: number; body: string };
    if (!app) result = { status: f.unknownInsNotDelivered ? -1 : 409, body: JSON.stringify({ error: { code: "instance_unknown", message: "the app instance is not in this bridge's config", requestId: "req_mini" } }) };
    else {
      result = await forward(app.internalUrl, item);
      if (f.retries && (result.status >= 500 || result.status === 0)) result = await forward(app.internalUrl, item);
    }
    await d.portalCall("POST", `${POLL}/${item.id}/result`, { pop: item.id, ...result }).catch(() => undefined);
    d.log(JSON.stringify({ ts: new Date().toISOString(), level: "info", evt: "bridge.person_op.relayed", pop: item.id, ins: item.ins, op: item.op, status: result.status, ...(f.logsBody ? { body: item.body, jws: item.jws } : {}) }));
  };
  void (async () => {
    while (!d.stopped()) {
      try {
        const r = await d.portalCall("GET", `${POLL}?wait=${WAIT_S}`, undefined, (WAIT_S + 5) * 1000);
        if (r.status !== 200) {
          await r.body?.cancel();
          await new Promise((res) => setTimeout(res, 500));
          continue;
        }
        const batch = (await r.json()) as { items?: BridgePersonOp[] };
        for (const item of batch.items ?? []) void handle(item);
      } catch {
        if (!d.stopped()) await new Promise((res) => setTimeout(res, 300));
      }
    }
  })();
}
