// Minimal stdio relay for the relay target's sensitivity tests (NOT the product relay): `login` runs the RFC 8628
// device flow (scope agent) and stores the agent item in $XDG_CONFIG_HOME/tealbrick (file store); `serve` relays
// JSON-RPC lines to the deployed bridge with a K5 from a jwt-bearer exchange, keeps an app event subscription alive
// (BRIDGE §14.3: Last-Event-ID on a GET reconnect; a lost session → re-initialize + stream from the last event).
// `--broken=<rule>` breaks one rule.
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { exportPrivateKey, generateKeyPair, importKeyPair, signAssertion, ulid } from "@opt2-tealbrick/manifest";

const [mode, flag] = process.argv.slice(2);
const broken = flag?.startsWith("--broken=") ? flag.slice(9) : "";
const dir = join(process.env.XDG_CONFIG_HOME ?? ".", "tealbrick");
const nowS = () => Math.floor(Date.now() / 1000);

interface Item {
  con: string;
  agt: string;
  bridgeId: string;
  bridgeUrl: string;
  tokenEndpoint: string;
  privateKey: string;
}

async function login(): Promise<void> {
  const portal = process.env.TB_PORTAL_URL as string;
  const key = await generateKeyPair({ extractable: true });
  const post = (path: string, body: unknown) => fetch(`${portal}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json() as Promise<Record<string, unknown>>);
  const start = await post("/api/v1/device/authorize", { scope: "agent", client_id: "kit", machine_label: "conformance", harness: "generic", agents: [{ public_key: key.publicJwk }] });
  for (let i = 0; i < 200; i++) {
    await new Promise((r) => setTimeout(r, 300));
    const t = await post("/api/v1/device/token", { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.device_code, client_id: "kit" });
    const cons = t.connections as { connection_id: string; agent_id: string }[] | undefined;
    if (!cons?.[0]) continue;
    const mcp = new URL(String(t.mcp_url));
    const item: Item = { con: cons[0].connection_id, agt: cons[0].agent_id, bridgeId: String(t.bridge_id), bridgeUrl: mcp.origin, tokenEndpoint: String(t.token_endpoint), privateKey: Buffer.from(await exportPrivateKey(key)).toString("base64url") };
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, `agent-${item.con}.json`), JSON.stringify(item), { mode: 0o600 });
    return;
  }
  process.exit(10);
}

async function serve(): Promise<void> {
  const file = readdirSync(dir).find((f) => f.startsWith("agent-"));
  if (!file) process.exit(3);
  const item = JSON.parse(readFileSync(join(dir, file as string), "utf8")) as Item;
  const key = await importKeyPair(new Uint8Array(Buffer.from(item.privateKey, "base64url")));
  if (broken === "listen") createServer().listen(0, "127.0.0.1");
  let token = "";
  let session = "";
  const extra: Record<string, string> = broken === "person" ? { "x-owner-session": process.env.TB_OWNER_SESSION ?? "" } : {};
  const getToken = async () => {
    const ref = `tb:agt:${item.agt}` as `tb:agt:agt_${string}`;
    const assertion = await signAssertion("tb-agent-assert+jwt", { iss: ref as never, sub: ref as never, aud: `tb:brg:${item.bridgeId}` as never, iat: nowS(), con: item.con as never }, key);
    const r = (await (await fetch(item.tokenEndpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...extra }, body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }).toString() })).json()) as { access_token?: string };
    token = r.access_token ?? "";
    if (broken === "disk") writeFileSync(join(process.env.TMPDIR ?? ".", "relay-cache.json"), JSON.stringify({ token, at: ulid() }));
  };
  const write = (m: unknown) => process.stdout.write(`${JSON.stringify(m)}\n`);
  let initLine = "";
  let subscribed = false;
  let lastEvent = "";
  let gen = 0;
  const post = (body: string) =>
    fetch(`${item.bridgeUrl}/mcp`, { method: "POST", headers: { "content-type": "application/json", accept: "application/json, text/event-stream", authorization: `Bearer ${token}`, ...(session ? { "mcp-session-id": session } : {}), ...extra }, body });
  /** the session is gone (404): a new one, and the event subscription again from the last event (unless broken) */
  const renew = async () => {
    session = "";
    const r = await post(initLine);
    session = r.headers.get("mcp-session-id") ?? "";
    await r.body?.cancel();
    await (await post(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }))).body?.cancel();
    if (subscribed && broken !== "no-resubscribe") {
      const a = await post(JSON.stringify({ jsonrpc: "2.0", id: "relay-resub", method: "tealbrick/events/stream", params: lastEvent ? { cursor: lastEvent } : {} }));
      const answer = await a.json();
      if (broken === "leak-resub") write(answer);
    }
  };
  const listenSse = async (mine: number) => {
    while (mine === gen) {
      const r = await fetch(`${item.bridgeUrl}/mcp`, { headers: { accept: "text/event-stream", authorization: `Bearer ${token}`, "mcp-session-id": session, ...(lastEvent && broken !== "no-last-event-id" ? { "last-event-id": lastEvent } : {}) } });
      if (r.status === 404) {
        await r.body?.cancel();
        await renew();
        continue;
      }
      let buf = "";
      for await (const chunk of r.body as unknown as AsyncIterable<Uint8Array>) {
        buf += Buffer.from(chunk).toString("utf8");
        for (let i = buf.indexOf("\n\n"); i >= 0; i = buf.indexOf("\n\n")) {
          const lines = buf.slice(0, i).split("\n");
          buf = buf.slice(i + 2);
          const id = lines.find((l) => l.startsWith("id:"))?.slice(3).trim();
          if (id) lastEvent = id;
          const data = lines.filter((l) => l.startsWith("data:")).map((l) => l.slice(5).trim()).join("");
          if (data) write(JSON.parse(data));
        }
      }
      await new Promise((res) => setTimeout(res, 200));
    }
  };
  const listed = new Set<string>();
  // A stdio relay ends when its stdin closes (the runner ended or died). Without this the `--broken=listen` variant, whose open
  // listener keeps the event loop alive, outlived a runner that was killed: an orphan under launchd.
  process.stdin.once("close", () => setTimeout(() => process.exit(0), 500));
  createInterface({ input: process.stdin }).on("line", async (line) => {
    const m = JSON.parse(line) as { id?: unknown; method?: string; params?: { name?: string } };
    try {
      if (broken === "local" && m.method === "tools/call" && !listed.has(String(m.params?.name))) return write({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "unknown tool" } });
      if (!token) await getToken();
      if (m.method === "initialize") initLine = line;
      if (m.method === "tealbrick/events/stream") subscribed = true;
      let r = await post(line);
      if (r.status === 404 && m.method !== "initialize" && initLine) {
        await r.body?.cancel();
        await renew();
        r = await post(line);
      }
      if (m.method === "initialize") {
        session = r.headers.get("mcp-session-id") ?? "";
        gen += 1;
        void listenSse(gen).catch(() => undefined);
      }
      if (r.status === 202) return;
      if (r.status === 401) return write({ jsonrpc: "2.0", id: m.id, error: { code: -32001, message: "agent connection refused" } });
      const body = (await r.json()) as { result?: { tools?: { name: string }[] } };
      if (m.method === "tools/list") for (const t of body.result?.tools ?? []) listed.add(t.name);
      if (broken === "filter" && body.result?.tools) body.result.tools = body.result.tools.filter((t) => !t.name.includes("owner"));
      write(body);
    } catch (e) {
      if (m.id !== undefined) write({ jsonrpc: "2.0", id: m.id, error: { code: -32603, message: String(e) } });
    }
  });
}

if (mode === "login") await login();
else await serve();
