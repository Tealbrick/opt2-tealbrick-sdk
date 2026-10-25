// Fake bridge internal API for tb-exec tests (BRIDGE §9.4, §10): claim (one-time code), key fetch and status long-poll,
// each later request verified as a service instance assertion with the manifest package's verifier.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, memoryReplayGuard, ulid, verifyAssertion } from "@opt2-tealbrick/manifest";
import type { AppStatus, ClaimRequest, ClaimResponse } from "@opt2-tealbrick/spec/bridge";
import { type BridgeId, type Ed25519PublicJwk, type InstanceId, TYP } from "@opt2-tealbrick/spec/credentials";

export interface FakeBridge {
  url: string;
  brg: BridgeId;
  ins: InstanceId;
  appKey: Ed25519KeyPair;
  claims: ClaimRequest[];
  keyFetches: string[];
  statusBodies: AppStatus[];
  refused: string[];
  keysRev: number;
  setKey(name: string, value: string | null): void;
  /** v0.1.63 (BRIDGE §15.4): role → the answer of GET /tb/v1/model-roles/<role> (absent = 404 role_not_set); `keysRev` is added when sent. A change bumps keysRev. */
  setRole(role: string, answer: { status: number; body: Record<string, unknown> } | null): void;
  roleFetches: string[];
  /** test switch: names answered 403 key_not_declared (Core declaration bug, Knowledge S2); changes do NOT bump keysRev */
  undeclared: Set<string>;
  /** v0.1.12 tests: Core dropped the service key (assertions → 401 unauthenticated until a new claim) */
  forget(): void;
  /** v0.1.12 tests: Core re-issued the one-time code (the old one is gone) */
  newCode(code: string): void;
  close(): Promise<void>;
}

function send(res: ServerResponse, status: number, body?: unknown): void {
  if (body === undefined) {
    res.writeHead(status);
    res.end();
    return;
  }
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(body));
}

const refuse = (res: ServerResponse, status: number, code: string) => send(res, status, { error: { code, message: code, requestId: "req_test" } });

async function body(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

export async function startFakeBridge(o: { ins: InstanceId; code: string; service: string; serviceKeys: { name: string; env: string }[]; keys: Record<string, string> }): Promise<FakeBridge> {
  const appKey = await generateKeyPair();
  const bridgeKey = await generateKeyPair();
  const brg: BridgeId = `brg_${ulid()}`;
  const keys = new Map(Object.entries(o.keys));
  const roles = new Map<string, { status: number; body: Record<string, unknown> }>();
  const replay = memoryReplayGuard();
  let usedCode = false;
  let code = o.code;
  let servicePub: Ed25519PublicJwk | null = null;
  const sliceRevision = 1;
  const waiters = new Set<() => void>();

  const fb: FakeBridge = {
    url: "",
    brg,
    ins: o.ins,
    appKey,
    claims: [],
    keyFetches: [],
    statusBodies: [],
    refused: [],
    roleFetches: [],
    keysRev: 7,
    undeclared: new Set<string>(),
    forget() {
      servicePub = null;
    },
    newCode(c) {
      code = c;
      usedCode = false;
    },
    setKey(name, value) {
      if (value === null) keys.delete(name);
      else keys.set(name, value);
      fb.keysRev++;
      for (const w of [...waiters]) w();
    },
    setRole(role, answer) {
      if (answer === null) roles.delete(role);
      else roles.set(role, answer);
      fb.keysRev++;
      for (const w of [...waiters]) w();
    },
    close: async () => {
      for (const w of [...waiters]) w();
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    },
  };

  const assertOk = (req: IncomingMessage, raw: Buffer): boolean => {
    const token = req.headers["tb-assert"];
    if (typeof token !== "string" || !servicePub) return false;
    const r = verifyAssertion(token, keySetFrom({ keys: [servicePub] }, `tb:ins:${o.ins}`), {
      typ: TYP.instanceAssertion,
      aud: `tb:brg:${brg}`,
      now: Math.floor(Date.now() / 1000),
      method: req.method ?? "",
      pathAndQuery: req.url ?? "",
      body: raw,
      replay,
    });
    return r.ok && r.claims.svc === o.service;
  };

  const server = createServer(async (req, res) => {
    const raw = await body(req);
    const url = req.url ?? "";
    if (req.method === "POST" && url === "/tb/v1/claim") {
      const c = JSON.parse(raw.toString("utf8")) as ClaimRequest;
      fb.claims.push(c);
      if (c.code !== code || usedCode) return refuse(res, 403, "code_invalid");
      usedCode = true;
      servicePub = c.instancePublicKey;
      const answer: ClaimResponse = {
        ins: o.ins,
        bridge: { id: brg, publicKey: bridgeKey.publicJwk, internalUrl: fb.url },
        app: { publicKey: appKey.publicJwk },
        serviceKeys: o.serviceKeys,
      };
      return send(res, 200, answer);
    }
    if (!assertOk(req, raw)) {
      fb.refused.push(url);
      return refuse(res, 401, "unauthenticated");
    }
    if (req.method === "GET" && url.startsWith("/tb/v1/keys/")) {
      const name = decodeURIComponent(url.slice("/tb/v1/keys/".length));
      fb.keyFetches.push(name);
      if (fb.undeclared.has(name)) return refuse(res, 403, "key_not_declared");
      const value = keys.get(name);
      if (value === undefined) return refuse(res, 404, "key_not_set");
      return send(res, 200, { name, value, keysRev: fb.keysRev });
    }
    if (req.method === "GET" && url.startsWith("/tb/v1/model-roles/")) {
      const role = decodeURIComponent(url.slice("/tb/v1/model-roles/".length));
      fb.roleFetches.push(role);
      const a = roles.get(role);
      if (!a) return refuse(res, 404, "role_not_set");
      return send(res, a.status, a.status === 200 ? { ...a.body, keysRev: fb.keysRev } : a.body);
    }
    if (req.method === "POST" && url === "/tb/v1/status?wait=60") {
      const b = JSON.parse(raw.toString("utf8")) as AppStatus;
      fb.statusBodies.push(b);
      const answer = () => send(res, 200, { slice: "test.slice.jws", sliceRevision, keysRev: fb.keysRev });
      if (b.keysRev !== fb.keysRev || b.sliceRevision !== sliceRevision) return answer();
      const t = setTimeout(done, 60_000);
      function done() {
        clearTimeout(t);
        waiters.delete(done);
        if (!res.writableEnded) answer();
      }
      waiters.add(done);
      res.once("close", () => {
        clearTimeout(t);
        waiters.delete(done);
      });
      return;
    }
    refuse(res, 404, "not_found");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const a = server.address();
  fb.url = `http://127.0.0.1:${typeof a === "object" && a ? a.port : 0}`;
  return fb;
}
