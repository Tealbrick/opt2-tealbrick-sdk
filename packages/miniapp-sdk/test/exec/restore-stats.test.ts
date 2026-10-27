// C373a: configurable + streamed restore (TBEXEC_RESTORE_MAX_BYTES, temp file on the data volume, sha-256 before apply)
// and the stats route (GET /tb/v1/exec/stats). Quiet on good, fires on bad.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { request, type Server } from "node:http";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { type Ed25519KeyPair, generateKeyPair, memoryReplayGuard, signInstanceAssertion, signJws, ulid } from "@opt2-tealbrick/manifest";
import type { BridgeId, InstanceId } from "@opt2-tealbrick/spec/credentials";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { EXEC_ENV, mainDataFileFrom, RESTORE_DEFAULT_MAX_BYTES, RESTORE_HARD_MAX_BYTES, restoreMaxBytesFrom } from "../../src/exec/config.ts";
import type { ClaimRecord } from "../../src/exec/identity.ts";
import { startTbExec, type TbExecHandle } from "../../src/exec/run.ts";
import { CONTROL_PATHS, type ControlOptions, startControlServer } from "../../src/exec/servers.ts";
import { appAssertionVerifiers } from "../../src/exec/verify.ts";
import { freePort, nowS, tempDir } from "../helpers.ts";
import { execWorld, UPSTREAM, until } from "./world.ts";

const MiB = 1024 * 1024;
const quiet: Logger = { debug() {}, info() {}, warn() {}, error() {} };
const sha = (b: Uint8Array) => `sha256:${createHash("sha256").update(b).digest("hex")}`;
/** restore command: writes {size, sha} of its stdin to `out` (never holds the body) */
const hashingRestore = (out: string) => [process.execPath, "-e", `const h=require('crypto').createHash('sha256');let n=0;process.stdin.on('data',d=>{n+=d.length;h.update(d)}).on('end',()=>require('fs').writeFileSync(${JSON.stringify(out)},JSON.stringify({size:n,sha:'sha256:'+h.digest('hex')})))`];

interface Ids {
  key: Ed25519KeyPair;
  ins: InstanceId;
  brg: BridgeId;
}

/** an instance assertion that names `bd` directly (what a streaming sender signs; it never holds the body) */
async function signDigest(ids: Ids, method: string, path: string, bd: string | null, key: Ed25519KeyPair = ids.key): Promise<string> {
  const ref = `tb:ins:${ids.ins}`;
  const iat = nowS();
  return signJws(TYP.instanceAssertion, { iss: ref, sub: ref, aud: `tb:brg:${ids.brg}`, iat, exp: iat + 60, jti: ulid(), htm: method, htu: path, ...(bd ? { bd } : {}) }, key);
}

interface Reply {
  status: number | null;
  body: Record<string, unknown> | null;
}

/** POST with a streamed body; `length` = content-length header (omit → chunked); `abortAfter` → the client goes away */
function post(port: number, path: string, headers: Record<string, string>, chunks: Iterable<Uint8Array>, o: { length?: number; abortAfter?: number } = {}): Promise<Reply> {
  return new Promise((resolve) => {
    const req = request({ host: "127.0.0.1", port, method: "POST", path, headers: { ...headers, ...(o.length !== undefined ? { "content-length": String(o.length) } : {}) } }, (res) => {
      const parts: Buffer[] = [];
      res.on("data", (c: Buffer) => parts.push(c));
      res.on("end", () => {
        let body: Record<string, unknown> | null = null;
        try {
          body = JSON.parse(Buffer.concat(parts).toString("utf8"));
        } catch {}
        resolve({ status: res.statusCode ?? null, body });
      });
      res.on("error", () => resolve({ status: res.statusCode ?? null, body: null }));
    });
    req.on("error", () => resolve({ status: null, body: null }));
    let sent = 0;
    (async () => {
      for (const c of chunks) {
        if (req.destroyed) return;
        if (o.abortAfter !== undefined && sent >= o.abortAfter) {
          req.destroy();
          return resolve({ status: null, body: null });
        }
        sent += c.length;
        if (!req.write(c)) await new Promise((r) => req.once("drain", r));
      }
      req.end();
    })();
  });
}

function* zeros(total: number, chunk = MiB): Generator<Uint8Array> {
  const buf = new Uint8Array(chunk);
  for (let left = total; left > 0; left -= chunk) yield left >= chunk ? buf : buf.subarray(0, left);
}

const code = (r: Reply) => (r.body?.error as { code?: string } | undefined)?.code;

describe("TBEXEC_RESTORE_MAX_BYTES and TBEXEC_MAIN_DATA_FILE", () => {
  test("unset / empty / invalid = 512 MiB; a valid value is used; above 16 GiB clamps to 16 GiB", () => {
    const at = (v?: string) => restoreMaxBytesFrom(v === undefined ? {} : { [EXEC_ENV.restoreMaxBytes]: v });
    assert.equal(RESTORE_DEFAULT_MAX_BYTES, 512 * MiB);
    assert.equal(RESTORE_HARD_MAX_BYTES, 16 * 1024 * MiB);
    for (const v of [undefined, "", "  ", "abc", "-1", "0", "1.5", "1e9", "512MB"]) assert.equal(at(v), 512 * MiB, String(v));
    assert.equal(at("1073741824"), 1024 * MiB);
    assert.equal(at(String(16 * 1024 * MiB)), 16 * 1024 * MiB);
    assert.equal(at(String(16 * 1024 * MiB + 1)), 16 * 1024 * MiB);
    assert.equal(at("999999999999999999999999"), 16 * 1024 * MiB);
  });
  test("main data file: relative names inside the data dir only", () => {
    const at = (v: string) => mainDataFileFrom({ [EXEC_ENV.mainDataFile]: v });
    assert.equal(at("db/main.sqlite"), join("db", "main.sqlite"));
    for (const v of ["", "/etc/passwd", "../x", "a/../../x", ".", "a/.."]) assert.equal(at(v), null, v);
  });
});

describe("control port: streamed restore and stats (startControlServer)", () => {
  let ids: Ids;
  let rec: ClaimRecord;
  let dir: { dir: string; cleanup(): void };
  let dataDir: string;
  let out: string;
  const servers: Server[] = [];

  before(async () => {
    const key = await generateKeyPair();
    ids = { key, ins: `ins_${ulid()}`, brg: `brg_${ulid()}` };
    rec = { ins: ids.ins, svc: "engine", bridge: { id: ids.brg, publicKey: key.publicJwk }, app: { publicKey: key.publicJwk }, serviceKeys: [] };
    dir = tempDir("tb-exec-restore-");
    dataDir = join(dir.dir, "data");
    out = join(dir.dir, "restored.json");
  });
  after(async () => {
    for (const s of servers) await new Promise((r) => s.close(r));
    dir.cleanup();
  });

  async function control(extra: Partial<ControlOptions> = {}): Promise<number> {
    const v = appAssertionVerifiers(rec, memoryReplayGuard());
    const port = await freePort();
    servers.push(
      await startControlServer({
        port,
        host: "127.0.0.1",
        backup: { dump: [process.execPath, "-e", "process.stdout.write('D')"], restore: hashingRestore(out), extension: "dump" },
        verify: v.body,
        verifyHead: v.head,
        env: () => ({ PATH: process.env.PATH ?? "" }),
        log: quiet,
        dataDir,
        restoreMaxBytes: 64 * 1024,
        ...extra,
      }),
    );
    return port;
  }
  const temps = () => (existsSync(join(dataDir, "tb")) ? readdirSync(join(dataDir, "tb")).filter((n) => n.endsWith(".part")) : []);
  const original = () => writeFileSync(out, "ORIGINAL");
  const unchanged = () => assert.equal(readFileSync(out, "utf8"), "ORIGINAL", "the restore must not have run");
  const restorePath = CONTROL_PATHS.restore;

  test("good: the body streams to disk, restore sees the exact bytes, the temp file is gone", async () => {
    const port = await control();
    const body = new Uint8Array(50_000).map((_, i) => i % 251);
    for (const length of [body.length, undefined]) {
      original();
      const r = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, [body.subarray(0, 20_000), body.subarray(20_000)], { ...(length !== undefined ? { length } : {}) });
      assert.equal(r.status, 200);
      assert.deepEqual(r.body, { ok: true });
      assert.deepEqual(JSON.parse(readFileSync(out, "utf8")), { size: body.length, sha: sha(body) });
      assert.deepEqual(temps(), []);
    }
  });

  test("the classic whole-body assertion (signInstanceAssertion) is still accepted", async () => {
    const port = await control();
    const body = new TextEncoder().encode("restore-me-\u0000-bytes");
    const r = await post(port, restorePath, { "tb-assert": await signInstanceAssertion({ key: ids.key, ins: ids.ins, bridge: ids.brg, method: "POST", pathAndQuery: restorePath, body, now: nowS() }) }, [body], { length: body.length });
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(readFileSync(out, "utf8")), { size: body.length, sha: sha(body) });
  });

  test("over the cap: refused by content-length (413) and mid-stream (chunked); temp file gone, data unchanged", async () => {
    const port = await control({ restoreMaxBytes: 10_000 });
    const body = new Uint8Array(30_000);
    original();
    const a = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, [body], { length: body.length });
    assert.equal(a.status, 413);
    assert.equal(code(a), "payload_too_large");
    const b = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, zeros(30_000, 1000));
    assert.ok(b.status === 413 || b.status === null, `mid-stream: 413 or a closed connection, got ${b.status}`);
    await until(() => temps().length === 0, 5000);
    unchanged();
  });

  test("sha mismatch: 401, restore never runs, temp file gone", async () => {
    const port = await control();
    const signed = new Uint8Array(20_000).fill(1);
    const sent = new Uint8Array(20_000).fill(2);
    original();
    const r = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(signed)) }, [sent], { length: sent.length });
    assert.equal(r.status, 401);
    assert.equal(code(r), "unauthenticated");
    assert.deepEqual(temps(), []);
    unchanged();
    // an assertion without `bd` binds an EMPTY body: bytes are a mismatch too
    const n = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, null) }, [sent], { length: sent.length });
    assert.equal(n.status, 401);
    assert.deepEqual(temps(), []);
    unchanged();
  });

  test("low disk: refused before (507, nothing written) and during the stream (507, temp file gone)", async () => {
    original();
    const before = await control({ freeBytes: async () => 100 });
    const body = new Uint8Array(20_000);
    const a = await post(before, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, [body], { length: body.length });
    assert.equal(a.status, 507);
    assert.equal(code(a), "insufficient_storage");
    let calls = 0;
    const during = await control({ freeBytes: async () => (++calls === 1 ? 1e12 : 100), checkEveryBytes: 4096 });
    const b = await post(during, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, zeros(20_000, 2048), { length: body.length });
    assert.ok(b.status === 507 || b.status === null, `during: 507 or a closed connection, got ${b.status}`);
    assert.ok(calls >= 2, "free space is checked during the stream");
    await until(() => temps().length === 0, 5000);
    unchanged();
  });

  test("client abort mid-stream: temp file gone, restore never runs, the port is free again", async () => {
    const port = await control();
    const body = new Uint8Array(40_000);
    original();
    await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, zeros(40_000, 4096), { length: body.length, abortAfter: 12_000 });
    await until(() => temps().length === 0, 5000);
    unchanged();
    const ok = await post(port, restorePath, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body)) }, [body], { length: body.length });
    assert.equal(ok.status, 200, "busy is released after an abort");
  });

  test("auth before any byte: no assertion, a foreign key, a wrong path binding, a sibling svc and a replay are 401", async () => {
    const port = await control();
    const body = new Uint8Array(1000);
    original();
    const other = await generateKeyPair();
    const ref = `tb:ins:${ids.ins}`;
    const iat = nowS();
    const sibling = await signJws(TYP.instanceAssertion, { iss: ref, sub: ref, aud: `tb:brg:${ids.brg}`, iat, exp: iat + 60, jti: ulid(), htm: "POST", htu: restorePath, bd: sha(body), svc: "other" }, ids.key);
    for (const h of [{}, { "tb-assert": await signDigest(ids, "POST", restorePath, sha(body), other) }, { "tb-assert": await signDigest(ids, "POST", CONTROL_PATHS.backup, sha(body)) }, { "tb-assert": sibling }]) {
      const r = await post(port, restorePath, h, [body], { length: body.length });
      assert.equal(r.status, 401);
    }
    const once = await signDigest(ids, "POST", restorePath, sha(body));
    assert.equal((await post(port, restorePath, { "tb-assert": once }, [body], { length: body.length })).status, 200);
    assert.equal((await post(port, restorePath, { "tb-assert": once }, [body], { length: body.length })).status, 401, "replay");
    assert.deepEqual(temps(), []);
  });

  test("head and body verifiers agree on the same assertions (one replay set)", async () => {
    const v = appAssertionVerifiers(rec, memoryReplayGuard());
    const body = new TextEncoder().encode("x");
    const fake = (url: string, method: string, token: string) => ({ url, method, headers: { "tb-assert": token } }) as unknown as import("node:http").IncomingMessage;
    const t1 = await signDigest(ids, "POST", restorePath, sha(body));
    assert.equal(v.head(fake(restorePath, "POST", t1)), sha(body));
    assert.throws(() => v.body(fake(restorePath, "POST", t1), body), "a jti seen by head is a replay for body");
    const t2 = await signDigest(ids, "POST", restorePath, sha(body));
    v.body(fake(restorePath, "POST", t2), body);
    assert.throws(() => v.head(fake(restorePath, "POST", t2)), "and the other way round");
    const t3 = await signDigest(ids, "POST", restorePath, sha(body));
    assert.throws(() => v.head(fake(restorePath, "GET", t3)));
    assert.throws(() => v.head(fake(`${restorePath}?x=1`, "POST", t3)));
  });

  test("stale temp files from a crash are removed at start; other files stay", async () => {
    mkdirSync(join(dataDir, "tb"), { recursive: true });
    writeFileSync(join(dataDir, "tb", `restore-${"a".repeat(24)}.part`), "left over");
    writeFileSync(join(dataDir, "tb", "keep.part"), "not ours");
    await control();
    assert.deepEqual(temps(), ["keep.part"]);
  });

  test("stats: same auth (401 without / with a foreign assertion, 404 for POST); numbers only, no path", async () => {
    const cg = join(dir.dir, "cgroup");
    mkdirSync(cg, { recursive: true });
    writeFileSync(join(cg, "memory.current"), "123456\n");
    writeFileSync(join(cg, "memory.max"), "max\n");
    writeFileSync(join(cg, "memory.stat"), "anon 4096\nfile 8192\n");
    writeFileSync(join(cg, "cpu.stat"), "usage_usec 1000\nuser_usec 600\nsystem_usec 400\n");
    writeFileSync(join(cg, "cpu.max"), "50000 100000\n");
    mkdirSync(join(dataDir, "db"), { recursive: true });
    writeFileSync(join(dataDir, "db", "main.sqlite"), new Uint8Array(3000));
    const port = await control({ cgroupDir: cg, mainDataFile: join("db", "main.sqlite") });
    const url = `http://127.0.0.1:${port}${CONTROL_PATHS.stats}`;
    assert.equal((await fetch(url)).status, 401);
    assert.equal((await fetch(url, { headers: { "tb-assert": await signDigest(ids, "GET", CONTROL_PATHS.stats, null, await generateKeyPair()) } })).status, 401);
    assert.equal((await fetch(url, { method: "POST", headers: { "tb-assert": await signDigest(ids, "POST", CONTROL_PATHS.stats, null) } })).status, 404);
    const res = await fetch(url, { headers: { "tb-assert": await signDigest(ids, "GET", CONTROL_PATHS.stats, null) } });
    assert.equal(res.status, 200);
    const text = await res.text();
    const s = JSON.parse(text);
    const leaves = (v: unknown): unknown[] => (v !== null && typeof v === "object" ? Object.values(v).flatMap(leaves) : [v]);
    for (const leaf of leaves(s)) assert.ok(leaf === null || typeof leaf === "number" || typeof leaf === "boolean", `leaf ${String(leaf)}`);
    assert.ok(!text.includes(dir.dir) && !text.includes("main.sqlite") && !text.includes("/"), "no path or file name");
    assert.deepEqual(s.memory.currentBytes, 123456);
    assert.equal(s.memory.maxBytes, null);
    assert.equal(s.memory.anonBytes, 4096);
    assert.ok(s.memory.processRssBytes > 0);
    assert.deepEqual([s.cpu.usageUsec, s.cpu.userUsec, s.cpu.systemUsec, s.cpu.limitCores], [1000, 600, 400, 0.5]);
    assert.ok(s.volume.totalBytes > 0 && s.volume.availableBytes > 0);
    assert.ok(s.dataDir.sizeBytes >= 3000 && s.dataDir.files >= 1);
    assert.equal(s.mainDataFile.sizeBytes, 3000);
    assert.equal(s.restoreMaxBytes, 64 * 1024);
  });
});

describe("tb-exec end to end: the env sets the cap (a real > 512 MiB streamed restore)", () => {
  const live: TbExecHandle[] = [];
  after(async () => {
    for (const h of live) {
      h.signal("SIGTERM");
      await h.exited;
    }
  });

  async function boot(env: Record<string, string>) {
    const w = await execWorld({ helper: false, restore: hashingRestore });
    const controlPort = await freePort();
    const h = startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], env: { ...w.env, ...env }, host: "127.0.0.1", controlPort, logSink: w.sink });
    live.push(h);
    await until(() => w.starts().length === 1);
    const ids: Ids = { key: w.bridge.appKey, ins: w.bridge.ins, brg: w.bridge.brg };
    return { w, controlPort, ids };
  }

  test("TBEXEC_RESTORE_MAX_BYTES = 1 GiB: a 600 MiB body streams through, the restore sees every byte, stats reports the cap", async (t) => {
    const { w, controlPort, ids } = await boot({ [EXEC_ENV.restoreMaxBytes]: String(1024 * MiB) });
    t.after(() => w.cleanup());
    const size = 600 * MiB;
    const h = createHash("sha256");
    for (const c of zeros(size)) h.update(c);
    const digest = `sha256:${h.digest("hex")}`;
    const r = await post(controlPort, CONTROL_PATHS.restore, { "tb-assert": await signDigest(ids, "POST", CONTROL_PATHS.restore, digest) }, zeros(size), { length: size });
    assert.equal(r.status, 200);
    assert.deepEqual(JSON.parse(readFileSync(w.restoreFile, "utf8")), { size, sha: digest });
    assert.deepEqual(readdirSync(join(w.env.TB_DATA_DIR as string, "tb")).filter((n) => n.endsWith(".part")), []);
    assert.ok(!w.logs.some((l) => l.includes(w.dir)), "no data path in the logs");
    const s = await fetch(`http://127.0.0.1:${controlPort}${CONTROL_PATHS.stats}`, { headers: { "tb-assert": await signDigest(ids, "GET", CONTROL_PATHS.stats, null) } });
    assert.equal((await s.json()).restoreMaxBytes, 1024 * MiB);
  });

  test("env unset: the cap is 512 MiB (512 MiB + 1 refused with 413 before any byte); above 16 GiB clamps", async (t) => {
    const a = await boot({});
    t.after(() => a.w.cleanup());
    const r = await post(a.controlPort, CONTROL_PATHS.restore, { "tb-assert": await signDigest(a.ids, "POST", CONTROL_PATHS.restore, sha(new Uint8Array(1))) }, [], { length: 512 * MiB + 1 });
    assert.equal(r.status, 413);
    const stats = async (b: typeof a) => (await (await fetch(`http://127.0.0.1:${b.controlPort}${CONTROL_PATHS.stats}`, { headers: { "tb-assert": await signDigest(b.ids, "GET", CONTROL_PATHS.stats, null) } })).json()).restoreMaxBytes;
    assert.equal(await stats(a), 512 * MiB);
    const b = await boot({ [EXEC_ENV.restoreMaxBytes]: String(64 * 1024 * MiB) });
    t.after(() => b.w.cleanup());
    assert.equal(await stats(b), 16 * 1024 * MiB);
    assert.ok(b.w.logs.some((l) => l.includes("clamped")));
  });
});
