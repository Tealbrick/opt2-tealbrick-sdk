// tb-exec end-to-end against a fake bridge: claim, keys → env, restart on keysRev, helper auth, control port, signals.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { connect } from "node:net";
import { join } from "node:path";
import { after, before, describe, test } from "node:test";
import { type Ed25519KeyPair, generateKeyPair, manifestDigest, signInstanceAssertion, validateManifest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { DEFAULT_MANIFEST_PATH, parseArgs } from "../../src/exec/args.ts";
import { childEnv } from "../../src/exec/config.ts";
import { startTbExec, type TbExecHandle } from "../../src/exec/run.ts";
import { enrolCodeDigest } from "../../src/server/claim-guard.ts";
import { freePort, nowS } from "../helpers.ts";
import { type ExecWorld, execWorld, HELPER, KEY_VALUE, SERVICE, UPSTREAM, until } from "./world.ts";

describe("parseArgs", () => {
  test("upstream only, default manifest path", () => {
    assert.deepEqual(parseArgs(["--", "postgres", "-c", "x=1"]), { helperCmd: null, helperTarget: null, manifestPath: DEFAULT_MANIFEST_PATH, command: ["postgres", "-c", "x=1"] });
  });
  test("helper flags and manifest override", () => {
    const a = parseArgs(["--helper-cmd", "node helper.ts", "--helper-target", "127.0.0.1:3141", "--manifest", "/m.json", "--", "run"]);
    assert.equal(a.helperCmd, "node helper.ts");
    assert.deepEqual(a.helperTarget, { host: "127.0.0.1", port: 3141 });
    assert.equal(a.manifestPath, "/m.json");
  });
  test("refusals: missing --, empty command, lone helper flag, non-loopback target, unknown flag", () => {
    for (const argv of [["postgres"], ["--"], ["--helper-cmd", "x", "--", "a"], ["--helper-cmd", "x", "--helper-target", "10.0.0.1:80", "--", "a"], ["--helper-target", "127.0.0.1:0", "--helper-cmd", "x", "--", "a"], ["--bogus", "--", "a"]]) {
      assert.throws(() => parseArgs(argv), (e: Error & { code?: string }) => e.code === "usage", JSON.stringify(argv));
    }
  });
});

test("childEnv strips every TB_* name and adds the keys", () => {
  const env = childEnv({ PATH: "/bin", TB_KEK: "k", TB_ENROL_CODE: "c", HOME: "/h" }, new Map([["ENGINE_KEY", "v"]]));
  assert.deepEqual(env, { PATH: "/bin", HOME: "/h", ENGINE_KEY: "v" });
});

function run(w: ExecWorld, extra: string[] = [], controlPort?: number): TbExecHandle {
  return startTbExec({ argv: [...extra, "--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], env: w.env, host: "127.0.0.1", controlPort, logSink: w.sink });
}

describe("tb-exec with helper and backup", () => {
  let w: ExecWorld;
  let h: TbExecHandle;
  let controlPort: number;
  before(async () => {
    w = await execWorld();
    controlPort = await freePort();
    h = run(w, ["--helper-cmd", `${JSON.stringify(process.execPath)} ${JSON.stringify(HELPER)} ${w.helperTarget}`, "--helper-target", `127.0.0.1:${w.helperTarget}`], controlPort);
    await until(() => w.starts().length === 1);
  });
  after(async () => {
    h.signal("SIGTERM");
    await h.exited;
    await w.cleanup();
  });

  test("claims as the service with the manifest digest, version and own key", async () => {
    assert.equal(w.bridge.claims.length, 1);
    const c = w.bridge.claims[0];
    assert.ok(c);
    const m = validateManifest(JSON.parse(readFileSync(w.manifestPath, "utf8")));
    assert.ok(m.ok);
    assert.equal(c.service, SERVICE);
    assert.equal(c.code, w.env.TB_ENROL_CODE);
    assert.equal(c.manifestDigest, manifestDigest(m.manifest as Manifest));
    assert.equal(c.version, "1.0.0");
    assert.equal(c.instancePublicKey.kty, "OKP");
    assert.ok(!("d" in c.instancePublicKey));
    assert.ok(existsSync(join(w.env.TB_DATA_DIR as string, "tb", "instance-key")));
    const rec = JSON.parse(readFileSync(join(w.env.TB_DATA_DIR as string, "tb", "claim.json"), "utf8"));
    assert.equal(rec.ins, w.bridge.ins);
    assert.deepEqual(rec.app.publicKey, w.bridge.appKey.publicJwk);
  });

  test("fetches each declared key with a valid service assertion and passes it as env, never TB_* names", () => {
    assert.deepEqual(w.bridge.keyFetches.slice(0, 1), ["ENGINE_KEY"]);
    assert.deepEqual(w.bridge.refused, []);
    const s = w.starts()[0];
    assert.equal(s?.key, KEY_VALUE);
    assert.deepEqual(s?.tbNames, []);
    assert.ok(!w.logs.some((l) => l.includes(KEY_VALUE)), "key value must never be logged");
  });

  async function helperCall(path: string, opts: { key?: Ed25519KeyPair; svc?: string; body?: string; token?: string; signedBody?: string } = {}) {
    const body = opts.body ?? JSON.stringify({ id: "ka-1", name: "area" });
    const token =
      opts.token ??
      (await signInstanceAssertion({
        key: opts.key ?? w.bridge.appKey,
        ins: w.bridge.ins,
        bridge: w.bridge.brg,
        ...(opts.svc ? { svc: opts.svc } : {}),
        method: "POST",
        pathAndQuery: path,
        body: new TextEncoder().encode(opts.signedBody ?? body),
        now: nowS(),
      }));
    const res = await fetch(`http://127.0.0.1:${w.helperPort}${path}`, { method: "POST", headers: { "content-type": "application/json", "tb-assert": token }, body });
    return { status: res.status, body: (await res.json()) as Record<string, unknown>, token };
  }

  test("helper proxy forwards a declared path signed by the own app instance key", async () => {
    let r = await helperCall("/sources");
    for (let i = 0; r.status === 502 && i < 50; i++) {
      await new Promise((ok) => setTimeout(ok, 50)); // helper process still starting
      r = await helperCall("/sources");
    }
    assert.equal(r.status, 200);
    assert.equal(r.body.path, "/sources");
    assert.equal(r.body.body, JSON.stringify({ id: "ka-1", name: "area" }));
    assert.equal(r.body.assert, null, "the assertion is not forwarded to the helper");
  });

  test("helper proxy refuses a wrong key, a sibling service, a tampered body, a missing header and a replay", async () => {
    const other = await generateKeyPair();
    assert.equal((await helperCall("/sources", { key: other })).status, 401);
    const sib = await helperCall("/sources", { svc: "other-service" });
    assert.equal(sib.status, 401);
    assert.equal((sib.body.error as { code: string }).code, "unauthenticated");
    assert.equal((await helperCall("/sources", { signedBody: "{}" })).status, 401);
    const missing = await fetch(`http://127.0.0.1:${w.helperPort}/sources`, { method: "POST", body: "{}" });
    assert.equal(missing.status, 401);
    const first = await helperCall("/sources");
    assert.equal(first.status, 200);
    const replay = await helperCall("/sources", { token: first.token });
    assert.equal(replay.status, 401);
  });

  test("helper proxy refuses an undeclared path even with a valid assertion", async () => {
    const r = await helperCall("/admin");
    assert.equal(r.status, 404);
    assert.equal((r.body.error as { code: string }).code, "helper_path_undeclared");
  });

  test("control port: backup streams backup.dump stdout (with keys in env), restore pipes the body; foreign key refused", async () => {
    const sign = async (path: string, body: Uint8Array | undefined, key: Ed25519KeyPair = w.bridge.appKey) =>
      signInstanceAssertion({ key, ins: w.bridge.ins, bridge: w.bridge.brg, method: "POST", pathAndQuery: path, body, now: nowS() });
    const empty = new TextEncoder().encode("{}");
    const b = await fetch(`http://127.0.0.1:${controlPort}/tb/v1/exec/backup`, { method: "POST", headers: { "tb-assert": await sign("/tb/v1/exec/backup", empty) }, body: empty });
    assert.equal(b.status, 200);
    assert.equal(b.headers.get("content-type"), "application/octet-stream");
    assert.equal(await b.text(), "DUMP:with-key");
    const dump = new TextEncoder().encode("restore-me-\u0000-bytes");
    const r = await fetch(`http://127.0.0.1:${controlPort}/tb/v1/exec/restore`, { method: "POST", headers: { "tb-assert": await sign("/tb/v1/exec/restore", dump) }, body: dump });
    assert.equal(r.status, 200);
    assert.deepEqual(await r.json(), { ok: true });
    assert.deepEqual(new Uint8Array(readFileSync(w.restoreFile)), dump);
    const foreign = await fetch(`http://127.0.0.1:${controlPort}/tb/v1/exec/backup`, { method: "POST", headers: { "tb-assert": await sign("/tb/v1/exec/backup", empty, await generateKeyPair()) }, body: empty });
    assert.equal(foreign.status, 401);
    const unknown = await fetch(`http://127.0.0.1:${controlPort}/tb/v1/exec/other`, { method: "POST", body: "{}" });
    assert.equal(unknown.status, 404);
  });

  test("control port: an unparseable target (POST //) is a 404 and tb-exec keeps serving", async () => {
    const text = await new Promise<string>((resolve) => {
      const s = connect(controlPort, "127.0.0.1");
      let out = "";
      s.on("data", (c: Buffer) => {
        out += c.toString("utf8");
      });
      s.on("close", () => resolve(out));
      s.on("error", () => resolve(out));
      s.write("POST // HTTP/1.1\r\nhost: 127.0.0.1\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
    });
    assert.match(text, /^HTTP\/1\.1 404 /);
    const unknown = await fetch(`http://127.0.0.1:${controlPort}/tb/v1/exec/other`, { method: "POST", body: "{}" });
    assert.equal(unknown.status, 404);
  });

  test("status long-poll reports readiness and the keysRev it holds", async () => {
    await until(() => w.bridge.statusBodies.length > 0);
    const s = w.bridge.statusBodies.at(-1);
    assert.equal(s?.readiness, "ready");
    assert.equal(s?.version, "1.0.0");
    assert.equal(s?.pendingHolds, 0);
  });

  test("a new keysRev with a changed value restarts the child with the new value; SIGHUP is forwarded", async () => {
    const firstPid = w.starts()[0]?.pid;
    h.signal("SIGHUP");
    await until(() => w.events().some((e) => e.event === "SIGHUP" && e.pid === firstPid));
    w.bridge.setKey("ENGINE_KEY", "sk-test-rotated-value-xyz");
    await until(() => w.starts().length === 2, 8000);
    const second = w.starts()[1];
    assert.equal(second?.key, "sk-test-rotated-value-xyz");
    assert.notEqual(second?.pid, firstPid);
    assert.ok(w.events().some((e) => e.event === "SIGTERM" && e.pid === firstPid), "old child got SIGTERM");
    assert.ok(!w.logs.some((l) => l.includes("sk-test-rotated-value-xyz")));
  });

  test("a new keysRev with unchanged values does not restart the child", async () => {
    w.bridge.setKey("ENGINE_KEY", "sk-test-rotated-value-xyz");
    const rev = w.bridge.keysRev;
    await until(() => w.bridge.statusBodies.some((b) => b.keysRev === rev));
    assert.equal(w.starts().length, 2);
  });
});

describe("tb-exec lifecycle", () => {
  test("SIGTERM is forwarded and tb-exec exits with the child's code; a restart reuses the stored claim", async () => {
    const w = await execWorld({ helper: false, backup: false });
    try {
      const h = run(w);
      await until(() => w.starts().length === 1);
      h.signal("SIGTERM");
      assert.equal(await h.exited, 42);
      assert.ok(w.events().some((e) => e.event === "SIGTERM"));
      // second boot: the one-time code would be refused, so no new claim may be sent
      const h2 = run(w);
      await until(() => w.starts().length === 2);
      assert.equal(w.bridge.claims.length, 1);
      h2.signal("SIGTERM");
      assert.equal(await h2.exited, 42);
    } finally {
      await w.cleanup();
    }
  });

  test("C54: started as root, tb-exec drops privileges only for a service with dropPrivileges: true", async () => {
    for (const flag of [undefined, false, true] as const) {
      const w = await execWorld({ helper: false, backup: false, dropPrivileges: flag });
      const calls: string[] = [];
      let uid = 0;
      let gid = 0;
      const proc = {
        getuid: () => uid,
        getgid: () => gid,
        setuid: (id: number) => {
          calls.push(`setuid:${id}`);
          uid = id;
        },
        setgid: (id: number) => {
          calls.push(`setgid:${id}`);
          gid = id;
        },
        setgroups: () => {},
        chown: () => {},
      };
      try {
        const h = startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile, "exit3"], env: w.env, host: "127.0.0.1", logSink: w.sink, privilegeProc: proc });
        assert.equal(await h.exited, 3);
        if (flag === true) assert.deepEqual(calls, ["setgid:1000", "setuid:1000"]);
        else assert.deepEqual(calls, [], `dropPrivileges=${String(flag)} must not drop`);
      } finally {
        await w.cleanup();
      }
    }
  });

  test("the child's own exit code becomes tb-exec's exit code", async () => {
    const w = await execWorld({ helper: false, backup: false });
    try {
      const h = startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile, "exit3"], env: w.env, host: "127.0.0.1", logSink: w.sink });
      assert.equal(await h.exited, 3);
    } finally {
      await w.cleanup();
    }
  });

  test("a refused claim (code_invalid) ends tb-exec with 1; a declared helper without flags is refused", async () => {
    const w = await execWorld({ backup: false });
    try {
      const bad = startTbExec({ argv: ["--manifest", w.manifestPath, "--", "true"], env: { ...w.env, TB_ENROL_CODE: "tbe_wrong" }, host: "127.0.0.1", logSink: w.sink });
      assert.equal(await bad.exited, 1);
      assert.ok(w.logs.some((l) => l.includes("helper_flags_required")));
      const noHelper = await execWorld({ helper: false, backup: false });
      try {
        const r = startTbExec({ argv: ["--manifest", noHelper.manifestPath, "--", "true"], env: { ...noHelper.env, TB_ENROL_CODE: "tbe_wrong" }, host: "127.0.0.1", logSink: noHelper.sink });
        assert.equal(await r.exited, 1);
        assert.ok(noHelper.logs.some((l) => l.includes("code_invalid")));
      } finally {
        await noHelper.cleanup();
      }
      assert.equal(await startTbExec({ argv: ["nope"], env: w.env, logSink: w.sink }).exited, 2);
    } finally {
      await w.cleanup();
    }
  });

  test("cli binary: a real SIGTERM reaches the child and the process exits with its code", async () => {
    const w = await execWorld({ helper: false, backup: false });
    try {
      const cli = new URL("../../src/exec/cli.ts", import.meta.url).pathname;
      const p = spawn(process.execPath, [cli, "--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], { env: w.env, stdio: ["ignore", "ignore", "pipe"] });
      let stderr = "";
      p.stderr.on("data", (d) => {
        stderr += d;
      });
      await until(() => w.starts().length === 1, 10_000);
      p.kill("SIGTERM");
      const code = await new Promise<number | null>((r) => p.once("exit", (c) => r(c)));
      assert.equal(code, 42, stderr);
      assert.ok(!stderr.includes(KEY_VALUE));
    } finally {
      await w.cleanup();
    }
  });
});

test("keysInForce: drops a listed key whose manifest `when` is false for the settings this service carries (live-probe gap)", async () => {
  const { keysInForce } = await import("../../src/exec/run.ts");
  const manifest = {
    runtime: { env: [{ name: "MODEL_PROVIDER", setting: "model_provider" }] },
    settings: {
      steps: [{ id: "s", title: "S", fields: [{ key: "model_provider", type: "enum", label: "P", default: "openai", choices: [] }, { key: "other", type: "enum", label: "O", choices: [] }] }],
      keys: [
        { name: "OPENAI_API_KEY", label: "o", provider: "o", required: true, source: "account_default", usedBy: ["engine"], when: { model_provider: "openai" } },
        { name: "ANTHROPIC_API_KEY", label: "a", provider: "a", required: true, source: "account_default", usedBy: ["engine"], when: { model_provider: "anthropic" } },
        { name: "UNJUDGED_KEY", label: "u", provider: "u", required: true, source: "account_default", usedBy: ["engine"], when: { other: "x" } },
      ],
    },
  } as never;
  const listed = [
    { name: "OPENAI_API_KEY", env: "OPENAI_API_KEY" },
    { name: "ANTHROPIC_API_KEY", env: "ANTHROPIC_API_KEY" },
    { name: "UNJUDGED_KEY", env: "UNJUDGED_KEY" },
  ];
  assert.deepEqual(
    keysInForce(manifest, "engine", listed, { MODEL_PROVIDER: "openai" }).map((k) => k.name),
    ["OPENAI_API_KEY", "UNJUDGED_KEY"],
  );
  // setting not carried in the service env → trust the bridge list
  assert.equal(keysInForce(manifest, "engine", listed, {}).length, 3);
});

describe("tb-exec waits for required keys (Knowledge S2)", () => {
  test("a required key answered key_not_declared: upstream not started, status needs_keys; re-pulled with backoff; starts with the key once it is delivered", { timeout: 30_000 }, async () => {
    const w = await execWorld({ helper: false, backup: false });
    w.bridge.undeclared.add("ENGINE_KEY");
    try {
      const h = startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], env: w.env, host: "127.0.0.1", logSink: w.sink });
      await until(() => w.bridge.statusBodies.length > 0, 10_000);
      assert.equal(w.starts().length, 0, "upstream must not start without the required key");
      assert.equal(w.bridge.statusBodies.at(-1)?.readiness, "needs_keys");
      w.bridge.undeclared.delete("ENGINE_KEY"); // declaration fixed; keysRev unchanged → only the backoff re-pull finds it
      await until(() => w.starts().length === 1, 15_000);
      assert.equal(w.starts()[0].key, KEY_VALUE, "upstream got the key in its env");
      assert.ok(w.bridge.keyFetches.filter((n) => n === "ENGINE_KEY").length >= 2, "re-pulled");
      h.signal("SIGTERM");
      await h.exited;
    } finally {
      await w.cleanup();
    }
  });

  test("stop while waiting for keys ends tb-exec", { timeout: 15_000 }, async () => {
    const w = await execWorld({ helper: false, backup: false });
    w.bridge.undeclared.add("ENGINE_KEY");
    try {
      const h = startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], env: w.env, host: "127.0.0.1", logSink: w.sink });
      await until(() => w.bridge.statusBodies.length > 0, 10_000);
      h.signal("SIGTERM");
      const code = await h.exited;
      assert.equal(code, 143);
      assert.equal(w.starts().length, 0);
    } finally {
      await w.cleanup();
    }
  });
});

describe("tb-exec claim guard (v0.1.12, spine S1)", () => {
  const start = (w: ExecWorld, env: Record<string, string>, mountinfoPath?: string) =>
    startTbExec({ argv: ["--manifest", w.manifestPath, "--", process.execPath, UPSTREAM, w.outFile], env, host: "127.0.0.1", logSink: w.sink, ...(mountinfoPath ? { mountinfoPath } : {}) });

  test("TB_DATA_DIR on the container root: the code is not redeemed, the upstream does not start; stop ends tb-exec", { timeout: 15_000 }, async () => {
    const w = await execWorld({ helper: false, backup: false });
    try {
      const file = join(w.dir, "mountinfo");
      writeFileSync(file, "611 540 0:63 / / rw,relatime - overlay overlay rw\n");
      const { TB_DATA_EPHEMERAL: _skip, ...env } = w.env;
      const h = start(w, env, file);
      await until(() => w.logs.some((l) => l.includes('"msg":"data_dir_not_mounted"')), 5000);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(w.bridge.claims.length, 0);
      assert.equal(w.starts().length, 0);
      const boot = w.logs.map((l) => JSON.parse(l)).find((l) => l.msg === "data_dir_mount");
      assert.equal(boot?.mounted, false);
      assert.equal(boot?.mountPoint, "/");
      assert.equal(boot?.fsType, "overlay");
      h.signal("SIGTERM");
      assert.equal(await h.exited, 143);
    } finally {
      await w.cleanup();
    }
  });

  test("refused identity: a NEW code → one fresh claim and the upstream starts; the same code → no claim", { timeout: 30_000 }, async () => {
    const w = await execWorld({ helper: false, backup: false });
    try {
      let h = start(w, w.env);
      await until(() => w.starts().length === 1, 10_000);
      h.signal("SIGTERM");
      await h.exited;

      w.bridge.forget();
      w.bridge.newCode("tbe_reissued");
      h = start(w, { ...w.env, TB_ENROL_CODE: "tbe_reissued" });
      await until(() => w.starts().length === 2, 15_000);
      assert.deepEqual(w.bridge.claims.map((c) => c.code), [w.env.TB_ENROL_CODE, "tbe_reissued"]);
      const rec = JSON.parse(readFileSync(join(w.env.TB_DATA_DIR as string, "tb", "claim.json"), "utf8"));
      assert.equal(rec.codeDigest, enrolCodeDigest("tbe_reissued"));
      assert.ok(!JSON.stringify(rec).includes("tbe_reissued"), "only the digest is stored");
      h.signal("SIGTERM");
      await h.exited;

      w.bridge.forget();
      const from = w.logs.length;
      h = start(w, { ...w.env, TB_ENROL_CODE: "tbe_reissued" });
      await until(() => w.logs.slice(from).some((l) => l.includes('"msg":"identity_refused"')), 10_000);
      await new Promise((r) => setTimeout(r, 2500));
      assert.equal(w.bridge.claims.length, 2, "an unchanged code never claims again");
      assert.equal(w.logs.slice(from).filter((l) => l.includes('"msg":"identity_refused"')).length, 1, "logged once, no storm");
      assert.equal(w.starts().length, 2, "upstream waits for its required key");
      h.signal("SIGTERM");
      await h.exited;
    } finally {
      await w.cleanup();
    }
  });
});
