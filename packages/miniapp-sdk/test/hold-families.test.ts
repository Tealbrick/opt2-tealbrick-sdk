// spec 0.1.74 (C354a, INC-20261025-01): dynamic resolutions carry a hold-family SET (`holdFamilies`); the call is held when ANY
// member is held for the caller. A variant `<base>__<suffix>` is checked against the app's own `resolve(base)` and is never
// broader (crud ⊆, effect ≤, hold families ⊇). Catalog answers drop names that fail DYNAMIC_CATALOG_NAME_RE. Real HTTP, fake bridge.
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { bridgeOpProofClaims, DEFAULT_HELD_FAMILIES, signBridgeOpProof, ulid } from "@opt2-tealbrick/manifest";
import { BRIDGE_OP_PATH, type BridgeOp } from "@opt2-tealbrick/spec/credentials";
import type { DynamicCatalogEntry, HoldFamily, Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { type DynamicResolutionV074, defineApp, startApp } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const toolsOp = {
  id: "tools",
  title: "Connected tools",
  description: "Search and call connected tools (test op).",
  crud: ["read"],
  effect: "read",
  idempotency: "supported",
  receipt: false,
  audience: "agent",
  dynamic: { mode: "list", crudCeiling: ["read", "create", "update", "delete"], effectCeiling: "money" },
} as unknown as Operation;

/** what the app's `resolve` answers per tool name (the requested name is echoed as `tool`) */
const RESOLVE: Record<string, Omit<DynamicResolutionV074, "tool">> = {
  send: { crud: ["create"], effect: "outward", holdFamily: "outward" },
  // Connect after step 3: the first-contact variant keeps its base family
  send__first_contact: { crud: ["create"], effect: "outward", holdFamily: "first_contact", holdFamilies: ["first_contact", "outward"] },
  // Connect today (INC-20261025-01): the variant drops its base's `outward`
  send__fc_only: { crud: ["create"], effect: "outward", holdFamily: "first_contact" },
  send__later: { crud: ["create"], effect: "destructive", holdFamily: "outward", holdFamilies: ["outward", "destructive"] },
  send__crud: { crud: ["create", "delete"], effect: "outward", holdFamily: "outward" },
  send__empty: { crud: ["create"], effect: "outward", holdFamily: "outward", holdFamilies: [] },
  send__1a: { crud: ["create"], effect: "write", holdFamily: "outward" },
  plain_empty: { crud: ["create"], effect: "outward", holdFamily: "outward", holdFamilies: [] },
  odd: { crud: ["create"], effect: "teleport" as never },
  oddbase: { crud: ["create"], effect: "teleport" as never },
  oddbase__x: { crud: ["create"], effect: "write" },
  nobase__x: { crud: ["create"], effect: "write" },
};
const CATALOG = ["ok_tool", "a__b", "a_", "send__first_contact", "also_ok"].map(
  (name): DynamicCatalogEntry => ({ name, title: name, description: name, inputSchema: { type: "object" }, crud: ["read"], effect: "read" }),
);

describe("spec 0.1.74: hold-family sets and variants of dynamic tools (C354a)", () => {
  let w: World;
  let base = "";
  let running: RunningApp;
  const resolved: string[] = [];
  const called: string[] = [];
  let cleanup: () => Promise<void> = async () => {};
  before(async () => {
    w = await world();
    const t = tempDir();
    const port = await freePort();
    const bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    const manifest = fixtureManifest(port);
    manifest.operations.push(toolsOp);
    const noop = async () => ({});
    running = await startApp(
      defineApp({
        manifest,
        migrations: migrationsDir(t.dir),
        handlers: { note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: noop }, note_get: noop, note_delete: noop, notebook_rename: noop },
        dynamic: {
          tools: {
            catalog: async () => CATALOG.map((e) => ({ ...e })),
            resolve: async (tool) => {
              resolved.push(tool);
              const r = RESOLVE[tool];
              if (!r) return null;
              const out: DynamicResolutionV074 = { tool, ...r };
              return out;
            },
            call: async (tool) => {
              called.push(tool);
              return { tool };
            },
          },
        },
      }),
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "warn" },
      testRoots(w),
    ).catch(async (e) => {
      await bridge.stop();
      t.cleanup();
      throw e;
    });
    await until(async () => running.status() === "ok");
    base = `http://127.0.0.1:${port}`;
    cleanup = async () => {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    };
  });
  after(async () => cleanup());

  const call = async (tool: string, held: HoldFamily[]) => {
    const g = await grant(w, w.agents.a, { held });
    const input: Json = { tool, arguments: { n: ulid() } };
    const proof = await callProof(w, g, "tools", input);
    const res = await fetch(`${base}/tb/v1/ops/tools`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof }, body: JSON.stringify({ input, context: {} }) });
    return { status: res.status, body: (await res.json()) as Record<string, any> };
  };
  const bridgeOp = async (bop: BridgeOp, body: Record<string, Json>) => {
    const c = bridgeOpProofClaims(bop, body);
    const proof = await signBridgeOpProof(
      { iss: `tb:brg:${w.brg}`, sub: `tb:brg:${w.brg}`, aud: `tb:ins:${w.ins}`, iat: nowS(), call: `call_${ulid()}`, bop, ...(c.op !== undefined ? { op: c.op } : {}), ...(c.in !== undefined ? { in: c.in } : {}) } as never,
      w.bridgeKey,
    );
    const res = await fetch(`${base}/tb/v1/bridge/${BRIDGE_OP_PATH[bop]}`, { method: "POST", headers: { "content-type": "application/json", "tb-call": proof }, body: JSON.stringify(body) });
    return { status: res.status, body: (await res.json()) as any };
  };
  const holdFamilyOf = async (holdId: string) => (await running.receipts.get(holdId as never))?.holdFamily;
  const refusedVariant = (r: { status: number; body: Record<string, any> }, reason: string, msg: string) => {
    assert.equal(r.body.error?.code, "dynamic_resolve_failed", `${msg}: ${JSON.stringify(r.body)}`);
    assert.equal(r.body.error?.details?.reason, reason, msg);
  };

  test("held [outward]: a variant resolving holdFamilies [first_contact, outward] is held (202) and the hold records the first HELD member, outward", async () => {
    const r = await call("send__first_contact", ["outward"]);
    assert.equal(r.status, 202, `fires on bad (decision reads holdFamily only): ${JSON.stringify(r.body)}`);
    assert.equal(r.body.status, "held");
    assert.equal(await holdFamilyOf(r.body.holdId), "outward");
    assert.equal(called.includes("send__first_contact"), false);
  });

  test("held [outward]: a variant resolving holdFamily first_contact only (base outward) is refused dynamic_resolve_failed — it drops a base family", async () => {
    const n = called.length;
    const r = await call("send__fc_only", ["outward"]);
    assert.equal(r.status, 403, JSON.stringify(r.body));
    refusedVariant(r, "variant_broader", "fires on bad (no variant check)");
    assert.equal(called.length, n, "the op is never called");
    assert.ok(resolved.includes("send"), "the SDK resolved the base with the app's own resolve");
  });

  test("a variant with a later effect or extra crud is refused; a variant whose base does not resolve is refused", async () => {
    refusedVariant(await call("send__later", ["outward"]), "variant_broader", "later effect");
    refusedVariant(await call("send__crud", ["outward"]), "variant_broader", "extra crud");
    refusedVariant(await call("nobase__x", []), "variant_base_unknown", "base unknown");
  });

  test("malformed variants are refused: `send___y` and `send__` (dynamic_resolve_failed, never resolved), `send__Y` (input_invalid); `send__1a` is a valid variant", async () => {
    for (const tool of ["send___y", "send__"]) {
      const r = await call(tool, []);
      assert.equal(r.status, 404, `${tool}: ${JSON.stringify(r.body)}`);
      refusedVariant(r, "variant_invalid", tool);
      assert.equal(resolved.includes(tool), false, `${tool} never reaches resolve`);
    }
    const upper = await call("send__Y", []);
    assert.equal(upper.status, 400, JSON.stringify(upper.body));
    assert.equal(upper.body.error.code, "input_invalid");
    const ok = await call("send__1a", []);
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    assert.deepEqual(ok.body.output, { tool: "send__1a" });
    // still held through its holdFamily (outward) when held
    assert.equal((await call("send__1a", ["outward"])).status, 202);
  });

  test("an EMPTY holdFamilies behaves as [holdFamily]: held, and a variant with it passes the base check", async () => {
    const plain = await call("plain_empty", ["outward"]);
    assert.equal(plain.status, 202, `fires on bad (empty set = no holds): ${JSON.stringify(plain.body)}`);
    assert.equal(await holdFamilyOf(plain.body.holdId), "outward");
    const variant = await call("send__empty", ["outward"]);
    assert.equal(variant.status, 202, `fires on bad (empty set drops the base family): ${JSON.stringify(variant.body)}`);
  });

  test("an effect outside EFFECTS is refused: on the tool (ceiling, fail closed) and on a variant's base (variant check)", async () => {
    const odd = await call("odd", []);
    assert.equal(odd.status, 403, JSON.stringify(odd.body));
    assert.equal(odd.body.error.code, "dynamic_ceiling_exceeded");
    refusedVariant(await call("oddbase__x", []), "variant_broader", "unknown base effect");
  });

  test("default held families (first_contact held): the variant is still held; held [] → it runs (unchanged)", async () => {
    const d = await call("send__first_contact", [...DEFAULT_HELD_FAMILIES]);
    assert.equal(d.status, 202, JSON.stringify(d.body));
    assert.equal(await holdFamilyOf(d.body.holdId), "first_contact");
    const open = await call("send__first_contact", []);
    assert.equal(open.status, 200, JSON.stringify(open.body));
    assert.equal(called.at(-1), "send__first_contact");
    // the base itself is unchanged: held on outward, runs with nothing held
    assert.equal((await call("send", ["outward"])).status, 202);
    assert.equal((await call("send", [])).status, 200);
  });

  test("bridge op resolve: holdFamilies passes through unchanged; a broader variant is refused there too", async () => {
    const r = await bridgeOp("resolve", { op: "tools", tool: "send__first_contact" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.deepEqual(r.body, { tool: "send__first_contact", crud: ["create"], effect: "outward", holdFamily: "first_contact", holdFamilies: ["first_contact", "outward"] });
    const e = await bridgeOp("resolve", { op: "tools", tool: "plain_empty" });
    assert.deepEqual(e.body.holdFamilies, [], "passed through as given");
    const plain = await bridgeOp("resolve", { op: "tools", tool: "send" });
    assert.equal("holdFamilies" in plain.body, false);
    const broad = await bridgeOp("resolve", { op: "tools", tool: "send__fc_only" });
    assert.equal(broad.status, 403, JSON.stringify(broad.body));
    assert.equal(broad.body.error.code, "dynamic_resolve_failed");
  });

  test("catalog answer: entries named `a__b`, `a_` (and a variant name) are dropped, logged once per name; the valid entries return", async () => {
    const lines: string[] = [];
    const orig = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array, ...rest: unknown[]) => {
      lines.push(String(chunk));
      return orig(chunk, ...(rest as []));
    }) as typeof process.stderr.write;
    let first: { status: number; body: any };
    try {
      first = await bridgeOp("catalog", { op: "tools" });
      await bridgeOp("catalog", { op: "tools" });
    } finally {
      process.stderr.write = orig;
    }
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.deepEqual(
      (first.body as DynamicCatalogEntry[]).map((e) => e.name),
      ["ok_tool", "also_ok"],
      "fires on bad (no catalog name filter)",
    );
    const dropped = lines.filter((l) => l.includes("dynamic catalog entry dropped"));
    for (const name of ["a__b", "a_", "send__first_contact"]) assert.equal(dropped.filter((l) => l.includes(`"name":"${name}"`)).length, 1, `${name} logged once over two answers`);
  });
});
