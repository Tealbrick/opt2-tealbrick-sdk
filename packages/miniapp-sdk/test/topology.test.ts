// spec 0.1.80 (C373, G-2; number set at merge): ctx.topology() = a frozen deep copy of the CURRENT verified slice's `topology`;
// null when the slice is absent, expired or has none, and when the topology is malformed (never throws); read again on every
// call; DISPLAY ONLY (nothing in the SDK authorizes with it).
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { after, before, describe, mock, test } from "node:test";
import { fileURLToPath } from "node:url";
import { ulid } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, type SdkOpContext, type SliceTopology, startApp, TOPOLOGY_MAX } from "../src/server/index.ts";
import { readTopology } from "../src/server/topology.ts";
import { TrustState } from "../src/server/trust.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const T = { timeout: 60_000 };

const id = (p: string) => `${p}_${ulid()}`;
const INS_A = id("ins");
const INS_B = id("ins");
const CON_1 = id("con");
const CON_2 = id("con");
/** the slice helper's default agents[] has 2 entries (Agent A, Agent B) */
const AGENTS = 2;

function sample(): SliceTopology {
  return {
    v: 1,
    instances: [
      [INS_A, "fleet", "Fleet", "0.3.1"],
      [INS_B, "connect", "Connect", "1.2.0"],
    ],
    edges: [
      [0, 1, "cr", "b", 0b11_0000, 2, 0],
      [1, 0, "r", "f", 0, 0, 1],
    ],
    companions: [[0, 1, "r", 1]],
    connections: [
      [CON_1, 0, "p", "a"],
      [CON_2, 1, "k", "r"],
    ],
  };
}

const deepFrozen = (v: unknown): boolean => {
  if (v === null || typeof v !== "object") return true;
  if (!Object.isFrozen(v)) return false;
  return Object.values(v as object).every(deepFrozen);
};

// ───────────────────────────── unit: readTopology ─────────────────────────────

describe("readTopology: shape check, index check, frozen deep copy (unit)", T, () => {
  test("a valid topology → an equal, deeply frozen copy (not the same arrays)", T, () => {
    const raw = sample();
    const t = readTopology(raw, AGENTS);
    assert.deepEqual(t, raw);
    assert.ok(deepFrozen(t), "every level is frozen");
    assert.notEqual(t, raw);
    assert.notEqual(t?.edges, raw.edges);
    assert.notEqual(t?.edges[0], raw.edges[0]);
  });

  test("empty lists and truncated: true are kept", T, () => {
    const empty = { v: 1, instances: [], edges: [], companions: [], connections: [] };
    assert.deepEqual(readTopology(empty, 0), empty);
    assert.equal(readTopology({ ...sample(), truncated: true }, AGENTS)?.truncated, true);
  });

  test("absent → null", T, () => {
    assert.equal(readTopology(undefined, AGENTS), null);
    assert.equal(readTopology(null, AGENTS), null);
  });

  test("changing the source after the read does not change the copy", T, () => {
    const raw = sample() as any;
    const t = readTopology(raw, AGENTS);
    raw.edges[0][2] = "crud";
    raw.instances[0][2] = "Changed";
    raw.connections.pop();
    assert.deepEqual(t, sample());
  });

  test("out-of-range indexes: the row is dropped and the copy says truncated (never null, never a throw)", T, () => {
    const cases: [string, (t: any) => void, keyof SliceTopology][] = [
      ["edge agentIdx = agents.length", (t) => (t.edges[0][0] = AGENTS), "edges"],
      ["edge agentIdx negative", (t) => (t.edges[0][0] = -1), "edges"],
      ["edge instIdx = instances.length", (t) => (t.edges[1][1] = 2), "edges"],
      ["companion fromIdx out of range", (t) => (t.companions[0][0] = 7), "companions"],
      ["companion toIdx out of range", (t) => (t.companions[0][1] = 2), "companions"],
      ["connection agentIdx out of range", (t) => (t.connections[1][1] = 99), "connections"],
    ];
    for (const [why, mut, listName] of cases) {
      const raw = structuredClone(sample()) as any;
      mut(raw);
      const t = readTopology(raw, AGENTS);
      assert.ok(t, why);
      assert.equal(t.truncated, true, why);
      assert.equal((t[listName] as unknown[]).length, (sample()[listName] as unknown[]).length - 1, `${why}: exactly one row dropped`);
      for (const other of ["instances", "edges", "companions", "connections"] as const) {
        if (other !== listName) assert.deepEqual(t[other], sample()[other], `${why}: ${other} kept`);
      }
    }
  });

  test("agentIdx is checked against the slice's agents length", T, () => {
    const t = readTopology(sample(), 1);
    assert.equal(t?.truncated, true);
    assert.deepEqual(t?.edges, [sample().edges[0]], "the edge of agent 1 is dropped");
    assert.deepEqual(t?.connections, [sample().connections[0]]);
    assert.deepEqual(readTopology(sample(), 0)?.edges, []);
  });

  /** each case changes a fresh sample in place, or returns a replacement value */
  const malformed: [string, (t: any) => unknown][] = [
    ["not an object", () => "topology"],
    ["an array", () => []],
    ["v missing", (t) => {
      delete t.v;
    }],
    ["v 2", (t) => {
      t.v = 2;
    }],
    ["a missing list", (t) => {
      delete t.connections;
    }],
    ["a list that is not an array", (t) => {
      t.edges = {};
    }],
    ["a row that is an object", (t) => {
      t.instances[0] = { ins: INS_A };
    }],
    ["instance arity 5", (t) => {
      t.instances[0].push("persona");
    }],
    ["edge arity 6", (t) => {
      t.edges[0].pop();
    }],
    ["edge arity 8", (t) => {
      t.edges[0].push(0);
    }],
    ["connection arity 5", (t) => {
      t.connections[0].push({ kty: "OKP" });
    }],
    ["an empty id", (t) => {
      t.instances[0][0] = "";
    }],
    ["a number for a string", (t) => {
      t.instances[0][3] = 1;
    }],
    ["an index that is not an integer", (t) => {
      t.edges[0][0] = 0.5;
    }],
    ["an index that is a string", (t) => {
      t.edges[0][1] = "0";
    }],
    ["crud letters out of order", (t) => {
      t.edges[0][2] = "rc";
    }],
    ["crud as a word", (t) => {
      t.companions[0][2] = "read";
    }],
    ["mode free", (t) => {
      t.edges[0][3] = "free";
    }],
    ["held negative", (t) => {
      t.edges[0][4] = -1;
    }],
    ["held over 31 bits", (t) => {
      t.edges[0][4] = 2 ** 31;
    }],
    ["wfCount over 128", (t) => {
      t.edges[0][5] = 129;
    }],
    ["paused true", (t) => {
      t.edges[1][6] = true;
    }],
    ["paused 2", (t) => {
      t.edges[1][6] = 2;
    }],
    ["opsCount negative", (t) => {
      t.companions[0][3] = -1;
    }],
    ["method key", (t) => {
      t.connections[0][2] = "key";
    }],
    ["status active", (t) => {
      t.connections[0][3] = "active";
    }],
    ["truncated false", (t) => {
      t.truncated = false;
    }],
    ["edges over the bound", (t) => {
      t.edges = Array.from({ length: TOPOLOGY_MAX.edges + 1 }, () => t.edges[1]);
    }],
    ["instances over the bound", (t) => {
      t.instances = Array.from({ length: TOPOLOGY_MAX.instances + 1 }, () => t.instances[0]);
    }],
    ["a throwing getter", (t) => {
      Object.defineProperty(t.edges[0], 2, {
        enumerable: true,
        get: () => {
          throw new Error("boom");
        },
      });
    }],
  ];
  for (const [why, mut] of malformed) {
    test(`malformed (${why}) → null, never throws`, T, () => {
      const t = structuredClone(sample());
      const replaced = mut(t);
      assert.equal(readTopology(replaced === undefined ? t : replaced, AGENTS), null);
    });
  }

  test("bounds mirror the spec (TOPOLOGY_MAX)", T, () => {
    assert.deepEqual(TOPOLOGY_MAX, { instances: 40, edges: 600, companions: 100, connections: 300 });
    const full = { v: 1, instances: sample().instances, edges: Array.from({ length: TOPOLOGY_MAX.edges }, () => sample().edges[1]), companions: [], connections: [] };
    const t = readTopology(full, AGENTS);
    assert.equal(t?.edges.length, TOPOLOGY_MAX.edges, "exactly at the bound is fine");
    assert.equal(t?.truncated, undefined);
  });
});

describe("TrustState.topology (unit)", T, () => {
  const run = (self: unknown) => TrustState.prototype.topology.call(self as never, Date.now());
  const agents = [{ id: "a" }, { id: "b" }];
  test("no slice → null; stale slice → null; no member → null; fresh → copy; indexes use the slice's agents", T, () => {
    assert.equal(run({ slice: null, stale: () => false }), null);
    assert.equal(run({ slice: { agents, topology: sample() }, stale: () => true }), null);
    assert.equal(run({ slice: { agents }, stale: () => false }), null);
    assert.deepEqual(run({ slice: { agents, topology: sample() }, stale: () => false }), sample());
    assert.equal(run({ slice: { agents: [agents[0]], topology: sample() }, stale: () => false })?.truncated, true);
  });
});

// ───────────────────────────── through the running app ─────────────────────────────

function manifestWithProbes(port: number): Manifest {
  const m = fixtureManifest(port) as Manifest & { needsTopology?: boolean };
  m.needsTopology = true; // validated by the manifest package (boolean only; M-TP-1 needs the directory)
  m.needsAgentDirectory = true;
  const op = (opId: string, audience: "person" | "agent") => ({
    id: opId,
    title: opId,
    description: opId,
    input: { type: "object" as const },
    output: { type: "object" as const },
    crud: ["read" as const],
    effect: "read" as const,
    idempotency: "none" as const,
    receipt: false,
    audience,
  });
  m.operations.push(op("topo_person", "person"), op("topo_stash", "person"), op("topo_agent", "agent"));
  return m;
}

const stash: { fn?: () => SliceTopology | null } = {};
const seenJob: unknown[] = [];

function testApp(port: number, migrations: string) {
  return defineApp({
    manifest: manifestWithProbes(port),
    migrations,
    handlers: {
      note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n" }) },
      note_get: async () => ({}),
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
      topo_person: async (input, c) => {
        const ctx = c as SdkOpContext;
        const t = ctx.topology();
        const out: Record<string, Json> = { topology: t as unknown as Json, frozen: deepFrozen(t) };
        if ((input as { mutate?: boolean }).mutate && t) {
          const threw: string[] = [];
          const tries: [string, () => void][] = [
            ["push edge", () => (t.edges as unknown[]).push([0, 0, "crud", "f", 0, 0, 0])],
            ["set name", () => ((t.instances[0] as string[])[2] = "Evil")],
            ["set crud", () => ((t.edges[0] as unknown[])[2] = "crud")],
            ["set truncated", () => ((t as { truncated?: true }).truncated = true)],
          ];
          for (const [k, f] of tries) {
            try {
              f();
            } catch {
              threw.push(k);
            }
          }
          out.threw = threw;
          out.after = ctx.topology() as unknown as Json;
          out.fresh = ctx.topology() !== t;
        }
        return out;
      },
      topo_stash: async (_input, c) => {
        stash.fn = (c as SdkOpContext).topology;
        return { ok: true };
      },
      topo_agent: async (input, c) => {
        const ctx = c as SdkOpContext;
        if ((input as { job?: boolean }).job) ctx.jobs.enqueue("topo_job", {});
        return { topology: ctx.topology() as unknown as Json, caller: ctx.caller.type };
      },
    },
    jobs: {
      topo_job: async (_input, ctx) => {
        seenJob.push(ctx.topology());
      },
    },
  });
}

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  push(over?: Parameters<typeof slice>[2]): Promise<void>;
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  let running: RunningApp | undefined;
  try {
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { topology: sample() }));
    running = await startApp(
      testApp(port, migrationsDir(t.dir)),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      { ...testRoots(w), port, jobs: { pollMs: 40, drainMs: 300 } },
    );
    const app = running;
    await until(async () => app.status() === "ok");
  } catch (e) {
    await running?.stop().catch(() => {});
    await bridge.stop();
    t.cleanup();
    throw e;
  }
  const app = running;
  return {
    w,
    bridge,
    running: app,
    base: `http://127.0.0.1:${port}`,
    async push(over = {}) {
      const before = bridge.statuses.length;
      bridge.push(await slice(w, PRODUCT, over));
      await until(async () => bridge.statuses.length > before && (bridge.statuses.at(-1) as { sliceRevision?: number }).sliceRevision === w.rev);
    },
    async cleanup() {
      await app.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function signIn(b: Booted): Promise<{ cookie: string; csrf: string }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, "/configure") }),
  });
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  return { cookie, csrf: s.csrf };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json = {}) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

async function agentOp(b: Booted, op: string, input: Json) {
  const g = await grant(b.w, b.w.agents.a);
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, idempotencyKey: `k_${ulid()}` }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

describe("ctx.topology (C373, spec 0.1.80)", T, () => {
  let b: Booted;
  let s: { cookie: string; csrf: string };
  before(async () => {
    b = await boot();
    s = await signIn(b);
  });
  after(async () => b.cleanup());
  const topo = async () => (await personOp(b, s, "topo_person")).body.output.topology;

  test("a manifest with needsTopology: true boots (the validator accepts the boolean)", T, () => {
    assert.equal(b.running.status(), "ok");
  });

  test("present → a frozen copy equal to the slice's topology", T, async () => {
    await b.push({ topology: sample() });
    const r = await personOp(b, s, "topo_person");
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.topology, sample());
    assert.equal(r.body.output.frozen, true);
  });

  test("mutation of the returned object throws and cannot change SDK state; each call is a new copy", T, async () => {
    await b.push({ topology: sample() });
    const r = await personOp(b, s, "topo_person", { mutate: true });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body.output.threw, ["push edge", "set name", "set crud", "set truncated"]);
    assert.deepEqual(r.body.output.after, sample(), "the next read is unchanged");
    assert.equal(r.body.output.fresh, true);
  });

  test("absent → null", T, async () => {
    await b.push({});
    assert.equal(await topo(), null);
  });

  test("malformed → null (and the op still runs)", T, async () => {
    await b.push({ topology: { ...sample(), connections: "all" } });
    assert.equal(await topo(), null);
    await b.push({ topology: { ...sample(), edges: [[0, 1, "cr", "loose", 0, 0, 0]] } });
    assert.equal(await topo(), null);
    await b.push({ topology: 42 });
    assert.equal(await topo(), null);
  });

  test("a slice update changes what a later call sees", T, async () => {
    await b.push({ topology: sample() });
    assert.deepEqual(await topo(), sample());
    const next = { ...sample(), edges: [], truncated: true as const };
    await b.push({ topology: next });
    assert.deepEqual(await topo(), next);
    // an index beyond the slice's agents (2 by default) drops the row and marks the copy truncated
    await b.push({ topology: { ...sample(), edges: [...sample().edges, [5, 0, "r", "f", 0, 0, 0]] } });
    assert.deepEqual(await topo(), { ...sample(), truncated: true });
  });

  test("an expired slice (older than 12 h) → null; a stashed function reads the current slice", T, async () => {
    await b.push({ topology: sample() });
    assert.equal((await personOp(b, s, "topo_stash")).status, 200);
    const fn = stash.fn;
    assert.ok(fn);
    assert.deepEqual(fn(), sample());
    const real = Date.now();
    const m = mock.method(Date, "now", () => real + 12 * 3600_000 + 60_000);
    try {
      assert.equal(fn(), null);
    } finally {
      m.mock.restore();
    }
    assert.deepEqual(fn(), sample(), "fresh again when the clock is back");
  });

  test("an agent op and a handler job (event-context family) see it too", T, async () => {
    await b.push({ topology: sample() });
    seenJob.length = 0;
    const a = await agentOp(b, "topo_agent", { job: true });
    assert.equal(a.status, 200, JSON.stringify(a.body));
    assert.deepEqual(a.body.output, { topology: sample(), caller: "agent" });
    await until(async () => seenJob.length > 0);
    assert.deepEqual(seenJob[0], sample());
  });
});

describe("topology is display only: nothing in the SDK reads it for authorization", T, () => {
  const src = join(dirname(fileURLToPath(import.meta.url)), "..", "src");
  const files = (dir: string): string[] => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".ts") ? [join(dir, e.name)] : []));

  test("the name appears only in the reader, the slice accessor, the context builders, their types and the index", T, () => {
    const allowed = new Set(["server/topology.ts", "server/trust.ts", "server/ops.ts", "server/app.ts", "server/context.ts", "server/runtime.ts", "server/index.ts"]);
    const hits = files(src)
      .filter((f) => /topology|Topology/.test(readFileSync(f, "utf8")))
      .map((f) => relative(src, f));
    for (const h of hits) assert.ok(allowed.has(h), `${h} references topology: authorization code must not read it (C373)`);
    assert.ok(hits.includes("server/trust.ts") && hits.includes("server/ops.ts") && hits.includes("server/app.ts"), "the scan finds the accessor and the context builders");
  });
});
