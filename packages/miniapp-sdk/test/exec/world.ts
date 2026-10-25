// tb-exec test world: a manifest with one wrapped service (key, helper, backup), a fake bridge and a temp data dir.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type ModelRoleRequirement, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest, Service } from "@opt2-tealbrick/spec/manifest";
import type { LogSink } from "../../src/server/log.ts";
import { fixtureManifest } from "../fixtures/manifest.ts";
import { freePort, tempDir } from "../helpers.ts";
import { type FakeBridge, startFakeBridge } from "./fake-bridge.ts";

export const SERVICE = "engine";
export const KEY_VALUE = "fixture-value-not-a-secret";
export const UPSTREAM = new URL("./upstream.ts", import.meta.url).pathname;
export const HELPER = new URL("./helper.ts", import.meta.url).pathname;

export interface ExecWorld {
  dir: string;
  manifestPath: string;
  outFile: string;
  restoreFile: string;
  helperPort: number;
  helperTarget: number;
  bridge: FakeBridge;
  env: Record<string, string>;
  logs: string[];
  sink: LogSink;
  starts(): { event: string; pid: number; key: string | null; tbNames: string[]; roleEnv: Record<string, string>; proxyEnv: string[] }[];
  events(): { event: string; pid: number }[];
  cleanup(): Promise<void>;
}

export async function execWorld(opts: { helper?: boolean; backup?: boolean; dropPrivileges?: boolean; modelRoles?: ModelRoleRequirement[]; settings?: Manifest["settings"]; runtimeEnv?: Manifest["runtime"]["env"] } = {}): Promise<ExecWorld> {
  const t = tempDir("tb-exec-test-");
  const helperPort = await freePort();
  const helperTarget = await freePort();
  const outFile = join(t.dir, "upstream.jsonl");
  const restoreFile = join(t.dir, "restored.bin");
  const m: Manifest = fixtureManifest(8080);
  const service: Service = {
    id: SERVICE,
    build: { context: "services/engine", dockerfile: "services/engine/Dockerfile" },
    port: 9100,
    resources: { cpu: 0.5, memoryMb: 256 },
    health: { kind: "tcp" },
    startOrder: 0,
    ...(opts.dropPrivileges === undefined ? {} : { dropPrivileges: opts.dropPrivileges }),
    ...(opts.helper === false ? {} : { helper: { port: helperPort, paths: ["/sources"] } }),
    ...(opts.backup === false
      ? {}
      : {
          backup: {
            dump: [process.execPath, "-e", "process.stdout.write('DUMP:' + (process.env.ENGINE_KEY ? 'with-key' : 'no-key'))"],
            restore: [process.execPath, "-e", `const c=[];process.stdin.on('data',d=>c.push(d)).on('end',()=>require('fs').writeFileSync(${JSON.stringify(restoreFile)},Buffer.concat(c)))`],
            extension: "dump",
          },
        }),
  };
  m.runtime.services = [service];
  const settings = m.settings ?? { steps: [] };
  settings.keys = [...(settings.keys ?? []), { name: "ENGINE_KEY", label: "Engine key", provider: "Demo", required: true, source: "account_default", usedBy: [SERVICE] }];
  m.settings = settings;
  // v0.1.63: `settings.modelRoles` (spec 0.1.57 types do not know the key; the validator does)
  if (opts.modelRoles) (settings as { modelRoles?: ModelRoleRequirement[] }).modelRoles = opts.modelRoles;
  if (opts.settings) settings.steps = opts.settings.steps;
  if (opts.runtimeEnv) m.runtime.env = opts.runtimeEnv;
  const manifestPath = join(t.dir, "manifest.json");
  writeFileSync(manifestPath, JSON.stringify(m));
  const ins: InstanceId = `ins_${ulid()}`;
  const code = "tbe_test_enrol_code";
  const bridge = await startFakeBridge({ ins, code, service: SERVICE, serviceKeys: [{ name: "ENGINE_KEY", env: "ENGINE_KEY" }], keys: { ENGINE_KEY: KEY_VALUE } });
  const logs: string[] = [];
  const lines = () => {
    try {
      return readFileSync(outFile, "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
    } catch {
      return [];
    }
  };
  return {
    dir: t.dir,
    manifestPath,
    outFile,
    restoreFile,
    helperPort,
    helperTarget,
    bridge,
    env: {
      PATH: process.env.PATH ?? "",
      TB_INSTANCE_ID: ins,
      TB_SERVICE: SERVICE,
      TB_ENROL_CODE: code,
      TB_BRIDGE_URL: bridge.url,
      TB_KEK: "a".repeat(64),
      TB_DATA_DIR: join(t.dir, "data"),
      // temp dirs are not volumes: skip the first-claim mount check (tests only; Linux CI has /proc/self/mountinfo)
      TB_DATA_EPHEMERAL: "1",
      TB_LOG_LEVEL: "debug",
    },
    logs,
    sink: { write: (_l, line) => logs.push(line) },
    starts: () => lines().filter((l) => l.event === "start"),
    events: () => lines(),
    cleanup: async () => {
      await bridge.close();
      t.cleanup();
    },
  };
}

// 20 s default: these waits cover child process starts, which take > 5 s when the workspace runs package tests in parallel
// (the flaky "tb-exec with helper and backup" before-hook timeout, 2026-10-12); a passing run returns as soon as cond holds.
export async function until(cond: () => boolean, ms = 20_000): Promise<void> {
  const end = Date.now() + ms;
  while (!cond()) {
    if (Date.now() > end) throw new Error("timeout waiting for condition");
    await new Promise((r) => setTimeout(r, 20));
  }
}
