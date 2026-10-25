// The mini app's relayed person op (SDK-API §21, CREDENTIALS K14, spec 0.1.64; a test double, NOT the SDK): POST /tb/v1/person-op
// with the checks in the SDK-API §21 order, and an app-alone (TB_STANDALONE=1) server whose route answers 503. Each fault breaks
// exactly one rule so a test can prove the matching S-PO row fails.
import { randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { manifestDigest, sha256Bytes, validateInput, verifySignedCompact } from "@opt2-tealbrick/manifest";
import { LIFETIME_S, MAX_JWS_BYTES, TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import type { Json, OperationView, TrustContext } from "@opt2-tealbrick/spec/sdk";

export interface MiniPersonOpFaults {
  /** declares no `person_op` capability in its claim and status pushes (spec 0.1.69, C354): the S-PO rows are not_applicable */
  noCap?: boolean;
  /** never compares bd with the body (fails S-PO-4) */
  noBodyDigest?: boolean;
  /** spends the jti only after the body digest matched (fails S-PO-4: the same K14 with the right body then runs) */
  jtiAfterBody?: boolean;
  /** no one-time jti (fails S-PO-5 and S-PO-4) */
  noReplay?: boolean;
  /** the general 30 s leeway on exp instead of PERSON_OP_RELAY.expLeewayS (fails S-PO-9) */
  generalLeeway?: boolean;
  /** accepts any cli (fails S-PO-7) */
  anyCli?: boolean;
  /** skips the allow-list (fails S-PO-6) */
  allowAll?: boolean;
  /** runs the op again for an idk it has seen (fails S-PO-11) */
  ignoresIdk?: boolean;
  /** skips the aud check (fails S-PO-2) */
  ignoresAud?: boolean;
  /** skips the ws check (fails S-PO-3) */
  ignoresWs?: boolean;
  /** typ confusion: any token its Portal keys sign (e.g. a launch ticket) is taken as checked (fails S-PO-1) */
  anyTyp?: boolean;
  /** in app-alone mode the route is served instead of 503 (fails S-PO-10) */
  servedStandalone?: boolean;
}

type Answer = { status: number; body: unknown };
const env = (status: number, code: string): Answer => ({ status, body: { error: { code, message: code, requestId: `req_${randomBytes(6).toString("hex")}` } } });
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const nowS = () => Math.floor(Date.now() / 1000);

export interface MiniPersonOpDeps {
  trust(): TrustContext | null;
  personNbf(): number;
  product: string;
  ops: readonly OperationView[];
  faults: MiniPersonOpFaults;
}

/** One handler per app process (jti set and idempotency store in memory). `run` counts handler runs (S-PO-11 sensitivity). */
export function miniPersonOp(d: MiniPersonOpDeps): (token: string | undefined, raw: string) => Answer {
  const f = d.faults;
  const used = new Set<string>();
  const idem = new Map<string, Json>();
  let runs = 0;
  const entry = PERSON_OP_RELAY.allow.find((a) => a.product === d.product);
  const isListed = (op: string) => ((entry?.read ?? []) as readonly string[]).includes(op) || ((entry?.write ?? []) as readonly string[]).includes(op);
  const listedOrRefused = (op: string): Answer => (isListed(op) ? { status: 200, body: { status: "ok", output: {} } } : env(403, "person_op_not_allowed"));
  return (token, raw) => {
    const t = d.trust();
    if (!t) return env(503, "person_op_unavailable");
    const portal = { keys: t.issuers.keys.filter((k) => k.issuer === "tb:portal") };
    const typ = f.anyTyp ? String((JSON.parse(Buffer.from((token ?? "").split(".")[0] ?? "", "base64url").toString() || "{}") as { typ?: unknown }).typ) : TYP.personOp;
    const sv = verifySignedCompact(token ?? "", portal, typ, MAX_JWS_BYTES);
    if (!sv.ok || !isObj(sv.payload)) return env(401, "person_op_invalid");
    const c = sv.payload as Record<string, unknown>;
    if (f.anyTyp && typ !== TYP.personOp) return listedOrRefused(String(c.op));
    const n = nowS();
    const iat = Number(c.iat);
    const exp = Number(c.exp);
    const leeway = f.generalLeeway ? 30 : PERSON_OP_RELAY.expLeewayS;
    if (c.iss !== "tb:portal") return env(401, "person_op_invalid");
    if (!f.ignoresAud && c.aud !== t.self) return env(401, "person_op_invalid");
    if (!f.ignoresWs && c.ws !== t.ws) return env(401, "person_op_invalid");
    if (!(exp - iat > 0 && exp - iat <= LIFETIME_S.personOp) || iat > n + leeway || n > exp + leeway) return env(401, "person_op_invalid");
    if (!f.anyCli && !(PERSON_OP_RELAY.clients as readonly unknown[]).includes(c.cli)) return env(401, "person_op_invalid");
    const jti = String(c.jti);
    const spend = (): boolean => {
      if (f.noReplay) return true;
      if (used.has(jti)) return false;
      used.add(jti);
      return true;
    };
    if (!f.jtiAfterBody && !spend()) return env(401, "person_op_invalid");
    if (iat < d.personNbf()) return env(401, "person_op_invalid");
    if (!f.noBodyDigest && sha256Bytes(new TextEncoder().encode(raw)) !== c.bd) return env(401, "person_op_invalid");
    if (f.jtiAfterBody && !spend()) return env(401, "person_op_invalid");
    const op = String(c.op);
    if (!isListed(op) && !f.allowAll) return env(403, "person_op_not_allowed");
    const view = d.ops.find((o) => o.id === op);
    if (view?.audience !== "person") return env(404, "op_not_found");
    let input: unknown;
    try {
      input = JSON.parse(raw);
    } catch {
      return env(400, "validation_failed");
    }
    if (!isObj(input) || !validateInput(view, input as Json).ok) return env(400, "validation_failed");
    const key = `${String(c.sub)}:${op}:${String(c.idk)}`;
    const stored = f.ignoresIdk ? undefined : idem.get(key);
    if (stored !== undefined) return { status: 200, body: { status: "ok", output: stored } };
    runs++;
    const output: Json = { op, run: runs, via: String(c.cli) };
    idem.set(key, output);
    return { status: 200, body: { status: "ok", output } };
  };
}

/** App-alone mode (SDK-API §13 TB_STANDALONE=1): no bridge, no K14 issuer → the route answers 503 person_op_unavailable. */
export async function startMiniStandalone(manifest: Manifest, environment: Record<string, string>, f: MiniPersonOpFaults, port = 0) {
  const digest = manifestDigest(manifest);
  const server = createServer((req, res) => {
    const send = (a: Answer) => {
      res.writeHead(a.status, { "content-type": "application/json" });
      res.end(JSON.stringify(a.body));
    };
    req.resume();
    const path = new URL(req.url ?? "/", "http://x").pathname;
    if (req.method === "GET" && path === "/tb/v1/health") return send({ status: 200, body: { status: "ok", sdk: "0.0.0-test", version: manifest.version, manifestDigest: digest, keys: [] } });
    if (req.method === "POST" && path === "/tb/v1/person-op") return send(f.servedStandalone ? env(403, "person_op_not_allowed") : env(503, "person_op_unavailable"));
    send(env(404, "not_found"));
  });
  await new Promise<void>((r) => server.listen(port || Number(environment.TBCONF_PORT ?? 0), "127.0.0.1", () => r()));
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    async stop() {
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
    async backupNow() {},
  };
}
