// Fake deployed bridge for the relay target (CONFORMANCE §2 "Bridge (relay form, CLI)"): the upstream a stdio relay
// talks to. It serves exactly `/oauth/token` (RFC 7523 jwt-bearer: agent assertion verified with the connection key
// the fake Portal registered in the device flow → K5 signed by its own key) and `/mcp` (Streamable HTTP: POST
// JSON-RPC, GET notification stream, DELETE), answers with canned results the checks compare verbatim, and records
// every request. Everything else → 404.
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, memoryReplayGuard, signAgentSession, verifyAgentSession, verifyAssertion } from "@opt2-tealbrick/manifest";
import { type AgentId, type BridgeId, type ConnectionEntry, type ConnectionId, OAUTH_GRANT_TYPES, TYP, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import { closeServer, header, listen, readRaw, sendJson } from "./http.ts";
import { nowS, peek } from "./tokens.ts";

export interface UpstreamRequest {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  at: number;
  /** JSON-RPC method of a POST /mcp body */
  rpc?: string;
  rpcId?: unknown;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export class FakeUpstream {
  url = "";
  readonly bridgeId: BridgeId;
  readonly ws: WorkspaceId;
  readonly requests: UpstreamRequest[] = [];
  readonly issued = new Set<string>();
  /** results per JSON-RPC method (tools/call: per tool name via `toolResults`) */
  initializeResult: Record<string, unknown> = {};
  toolsList: Record<string, unknown> = { tools: [] };
  readonly toolResults = new Map<string, Record<string, unknown>>();
  /** answer for tools/call of a name without a canned result (an upstream refusal the relay must pass through) */
  unknownToolResult: Record<string, unknown> = {};
  /** connection revoked / unknown: jwt-bearer refused and every K5 rejected */
  refuseAll = false;
  /** conformance 0.1.29 (BRIDGE §14.3): this upstream offers `tealbrick/events/*` (the relay B10.events_* rows run only then) */
  events = true;
  /** a forgotten session answers 404 on GET and POST (a bridge restart); `forgetSessions()` sets it */
  readonly #forgotten = new Set<string>();
  #key!: Ed25519KeyPair;
  readonly #connections: () => readonly ConnectionEntry[];
  readonly #replay = memoryReplayGuard();
  readonly #streams = new Set<ServerResponse>();
  readonly #sessions = new Set<string>();
  readonly #server = createServer((req, res) => void this.#handle(req, res));

  private constructor(o: { bridgeId: BridgeId; ws: WorkspaceId; connections: () => readonly ConnectionEntry[] }) {
    this.bridgeId = o.bridgeId;
    this.ws = o.ws;
    this.#connections = o.connections;
  }

  static async create(o: { bridgeId: BridgeId; ws: WorkspaceId; connections: () => readonly ConnectionEntry[] }): Promise<FakeUpstream> {
    const u = new FakeUpstream(o);
    u.#key = await generateKeyPair();
    u.url = await listen(u.#server);
    return u;
  }

  get streams(): number {
    return this.#streams.size;
  }

  /** Sends one app event frame (`id:` = the event id, BRIDGE §14.3) on every open GET stream. */
  notifyEvent(event: Record<string, unknown> & { id: string }): void {
    const frame = { jsonrpc: "2.0", method: "notifications/tealbrick/event", params: { event } };
    for (const s of this.#streams) s.write(`id: ${event.id}\nevent: message\ndata: ${JSON.stringify(frame)}\n\n`);
  }

  /** Ends every open GET stream (a proxy idle cut): the relay reconnects. */
  endStreams(): void {
    for (const s of this.#streams) s.end();
    this.#streams.clear();
  }

  /** The bridge restarted: every current session is unknown from now on (404), new ones work. */
  forgetSessions(): void {
    for (const sid of this.#sessions) this.#forgotten.add(sid);
    this.#sessions.clear();
    this.endStreams();
  }

  /** Sends a JSON-RPC notification on every open GET stream. */
  notify(message: Record<string, unknown>): void {
    for (const s of this.#streams) s.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
  }

  async close(): Promise<void> {
    for (const s of this.#streams) s.end();
    await closeServer(this.#server);
  }

  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const raw = await readRaw(req).catch(() => Buffer.alloc(0));
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) headers[k] = Array.isArray(v) ? v.join(", ") : v;
    const rec: UpstreamRequest = { method: req.method ?? "GET", path: req.url ?? "/", headers, body: raw.toString("utf8"), at: Date.now() };
    this.requests.push(rec);
    if (url.pathname === "/oauth/token" && req.method === "POST") return this.#token(raw, res);
    if (url.pathname !== "/mcp") return sendJson(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_fake" } });
    const bearer = /^Bearer (\S+)$/.exec(header(req, "authorization") ?? "")?.[1] ?? "";
    const v = bearer ? verifyAgentSession(bearer, { now: nowS(), self: `tb:brg:${this.bridgeId}`, ws: this.ws, keys: this.#keys() }) : null;
    if (!v?.ok || this.refuseAll || !this.issued.has(bearer)) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": `Bearer resource_metadata="${this.url}/.well-known/oauth-protected-resource"` });
      res.end(JSON.stringify({ error: { code: "unauthenticated", message: "agent session required", requestId: "req_fake" } }));
      return;
    }
    if (this.#forgotten.has(header(req, "mcp-session-id") ?? "")) return sendJson(res, 404, { jsonrpc: "2.0", id: null, error: { code: -32001, message: "unknown session" } });
    if (req.method === "GET") {
      res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-store" });
      res.write(": open\n\n");
      this.#streams.add(res);
      req.once("close", () => this.#streams.delete(res));
      return;
    }
    if (req.method === "DELETE") {
      this.#sessions.delete(header(req, "mcp-session-id") ?? "");
      return void res.writeHead(200).end();
    }
    let msg: Record<string, unknown> = {};
    try {
      msg = JSON.parse(rec.body) as Record<string, unknown>;
    } catch {
      return sendJson(res, 400, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } });
    }
    rec.rpc = typeof msg.method === "string" ? msg.method : undefined;
    rec.rpcId = msg.id;
    if (msg.id === undefined) return void res.writeHead(202).end();
    const extra: Record<string, string> = {};
    let result: Record<string, unknown>;
    if (msg.method === "initialize") {
      const sid = `sess_${Math.random().toString(36).slice(2)}`;
      this.#sessions.add(sid);
      extra["mcp-session-id"] = sid;
      result = this.initializeResult;
    } else if (msg.method === "tools/list") result = this.toolsList;
    else if (this.events && msg.method === "tealbrick/events/stream") result = { cursor: isObj(msg.params) && typeof msg.params.cursor === "string" ? msg.params.cursor : null, truncated: false };
    else if (!this.events && typeof msg.method === "string" && msg.method.startsWith("tealbrick/events/")) return sendJson(res, 200, { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `method not found: ${msg.method}` } }, extra);
    else if (msg.method === "tools/call") {
      const name = isObj(msg.params) ? String(msg.params.name) : "";
      result = this.toolResults.get(name) ?? this.unknownToolResult;
    } else result = {};
    sendJson(res, 200, { jsonrpc: "2.0", id: msg.id, result }, extra);
  }

  #keys() {
    return keySetFrom({ keys: [this.#key.publicJwk] }, `tb:brg:${this.bridgeId}`);
  }

  async #token(raw: Buffer, res: ServerResponse): Promise<void> {
    const form = new URLSearchParams(raw.toString("utf8"));
    const refuse = (error: string, description: string) => sendJson(res, 400, { error, error_description: description });
    if (form.get("grant_type") !== OAUTH_GRANT_TYPES.jwtBearer) return refuse("unsupported_grant_type", "jwt-bearer only");
    const assertion = form.get("assertion") ?? "";
    const claimed = peek(assertion);
    const conn = this.#connections().find((c) => c.con === claimed?.con && c.status === "active" && c.method === "key" && c.publicKey);
    if (!conn?.publicKey || this.refuseAll) return refuse("invalid_grant", "connection_unknown");
    const v = verifyAssertion(assertion, keySetFrom({ keys: [conn.publicKey] }, `tb:agt:${conn.agt}`), { typ: TYP.agentAssertion, aud: `tb:brg:${this.bridgeId}`, now: nowS(), replay: this.#replay });
    if (!v.ok || v.claims.con !== conn.con) return refuse("invalid_grant", "assertion refused");
    const token = await signAgentSession({ iss: `tb:brg:${this.bridgeId}`, sub: `tb:agt:${conn.agt as AgentId}`, aud: `tb:brg:${this.bridgeId}`, ws: this.ws, con: conn.con as ConnectionId, gen: conn.gen, iat: nowS() }, this.#key);
    this.issued.add(token);
    sendJson(res, 200, { access_token: token, token_type: "Bearer", expires_in: 900 });
  }
}
