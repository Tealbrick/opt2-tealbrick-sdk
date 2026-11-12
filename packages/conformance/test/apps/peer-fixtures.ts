// CONF-MULTIAPP self-test fixtures: tiny REAL miniapp-sdk apps (workspace source, no build needed) written into a temp
// directory as a checkout the peer loader accepts: tealbrick.manifest.json + conformance.start.ts. The caller app
// ("conf-caller") calls its peer ("conf-peer") with ctx.callApp; the peer has a read op with a receipt, an outward op that
// the workspace apps policy holds (first_contact) and a directory-feed op (contract fleet.directory_feed/1).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateManifest } from "@opt2-tealbrick/manifest";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Manifest } from "../../src/manifest-type.ts";

const sample = JSON.parse(readFileSync(new URL("../fixtures/sample.manifest.json", import.meta.url), "utf8")) as Record<string, unknown>;
const sdkUrl = new URL("../../../miniapp-sdk/src/server/index.ts", import.meta.url).href;
const miniAppUrl = new URL("./mini-app.ts", import.meta.url).href;

export const CALLER = "conf-caller";
export const PEER = "conf-peer";
export const FEED = "fleet.directory_feed/1";

const op = (id: string, over: Partial<Operation>): Operation =>
  ({
    id,
    title: id,
    description: `Fixture operation ${id}.`,
    input: { type: "object", properties: { id: { type: "string" } } },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
    ...over,
  }) as Operation;

/** The peer's operations: a read op with a receipt, an outward op held by the default apps policy, the feed op. */
export const PEER_OPS: Operation[] = [
  op("peer_get", { receipt: true }),
  op("peer_send", { crud: ["create"], effect: "outward", holdFamily: "first_contact", idempotency: "required", receipt: true, input: { type: "object", properties: { to: { type: "string" } } } }),
  op("peer_feed", {}),
];

function manifestOf(id: string, name: string, operations: Operation[], extra: Record<string, unknown>): Manifest {
  const m: Record<string, unknown> = { ...structuredClone(sample), id, name, summary: `${name}: conformance peer fixture.`, version: "1.0.0", operations, ...extra };
  for (const k of ["scopes", "settings", "hooks", "ui", "companions"]) delete m[k];
  Object.assign(m, extra);
  delete (m.runtime as Record<string, unknown>).env;
  (m.source as Record<string, unknown>).repo = `https://github.com/example-org/${id}`;
  const v = validateManifest(m);
  if (!v.ok) throw new Error(`fixture manifest ${id} invalid: ${v.errors.map((e) => `${e.path} ${e.code} ${e.message}`).join("; ")}`);
  return v.manifest;
}

/** The app under test: one read op that calls every peer op (a real callApp). */
export function callerManifest(): Manifest {
  return manifestOf(CALLER, "Conformance Caller", [op("caller_run", { title: "Run the caller" })], {
    companions: [{ product: PEER, operations: ["peer_get", "peer_send", "peer_feed"], crud: ["read", "create"], purpose: "Fixture companion calls" }],
    contracts: { consumes: [FEED] },
  });
}
export function peerManifest(over: { contracts?: boolean } = {}): Manifest {
  return manifestOf(PEER, "Conformance Peer", PEER_OPS, over.contracts === false ? {} : { contracts: { produces: [FEED] } });
}

const callerHandlers = `{
  caller_run: async (_input, ctx) => {
    const get = await ctx.callApp("${PEER}", "peer_get", { id: "x" });
    const send = await ctx.callApp("${PEER}", "peer_send", { to: "someone" }, { idempotencyKey: "caller-" + ctx.callId });
    const feed = await ctx.callApp("${PEER}", "peer_feed", {});
    return { get, send, feed };
  },
}`;

/** A valid fleet.directory_feed/1 answer (the spec example). */
export function validFeed(): unknown {
  return JSON.parse(readFileSync(new URL(import.meta.resolve("@opt2-tealbrick/spec/examples/contracts/fleet.directory_feed.1.json")), "utf8")).valid[0];
}

const realStart = (handlers: string) => `
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
const sdk: any = await import(${JSON.stringify(sdkUrl)});
const manifest = JSON.parse(readFileSync(new URL("./tealbrick.manifest.json", import.meta.url), "utf8"));
const handlers = ${handlers};
export default async function start(env: Record<string, string>) {
  const migrations = join(env.TB_DATA_DIR, "migrations");
  mkdirSync(migrations, { recursive: true });
  writeFileSync(join(migrations, "0001_init.sql"), "CREATE TABLE fixture_rows (id TEXT PRIMARY KEY);\\n");
  const app = sdk.defineApp({ manifest, handlers, migrations });
  const running = await sdk.startApp(app, env, { portalRootKeys: JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS), port: Number(env.TBCONF_PORT), privilegeProc: { getuid: () => 1000 } });
  return { url: "http://127.0.0.1:" + running.port, stop: () => running.stop() };
}
`;

const miniStart = (faults: Record<string, unknown>) => `
import { readFileSync } from "node:fs";
import { startMiniApp } from ${JSON.stringify(miniAppUrl)};
const manifest = JSON.parse(readFileSync(new URL("./tealbrick.manifest.json", import.meta.url), "utf8"));
export default function start(env: Record<string, string>) {
  return startMiniApp(manifest, env, ${JSON.stringify(faults)}, Number(env.TBCONF_PORT));
}
`;

function write(dir: string, manifest: Manifest, startSource: string): string {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "tealbrick.manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  writeFileSync(join(dir, "conformance.start.ts"), startSource);
  return dir;
}

/** The app under test (REAL SDK app); `calls: false` makes its op call nobody (X2 cannot observe a call). */
export function writeCaller(dir: string, opts: { calls?: boolean } = {}): { dir: string; manifest: Manifest; startModule: string } {
  const manifest = callerManifest();
  write(dir, manifest, realStart(opts.calls === false ? "{ caller_run: async () => ({}) }" : callerHandlers));
  return { dir, manifest, startModule: join(dir, "conformance.start.ts") };
}

/** A peer checkout: a REAL SDK app (default), `feed` changes the feed op's answer, or a mini app with `miniFaults`, or a start that throws. */
export function writePeer(dir: string, opts: { feed?: unknown; miniFaults?: Record<string, unknown>; throws?: boolean; contracts?: boolean } = {}): string {
  const manifest = peerManifest(opts.contracts === undefined ? {} : { contracts: opts.contracts });
  if (opts.throws) return write(dir, manifest, `export default async function start(): Promise<never> { throw new Error("fixture peer refuses to start"); }\n`);
  if (opts.miniFaults) return write(dir, manifest, miniStart(opts.miniFaults));
  const feed = opts.feed ?? validFeed();
  return write(
    dir,
    manifest,
    realStart(`{
  peer_get: async (input: any) => ({ got: input.id ?? null }),
  peer_send: async () => ({ sent: true }),
  peer_feed: async () => (${JSON.stringify(feed)}),
}`),
  );
}
