// conformance 0.1.31 (spec 0.1.64, SDK-API §21): the S-PO rows pass against the mini app and the REAL miniapp-sdk, are
// not_applicable for an app that does not declare the `person_op` capability (spec 0.1.69, C354; never by version), and FAIL against
// mini-app variants that break one rule each. The relayed write of S-PO-11 needs a product on PERSON_OP_RELAY.allow: the `inbox`
// variant of the sample manifest declares the allow-listed person ops. The real-SDK case runs the workspace miniapp-sdk, or the
// checkout named by TBCONF_SDK_DIR; it is skipped (with the reason) when that checkout has no person-op route at all.
import assert from "node:assert/strict";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { type Report, runApp } from "../src/index.ts";
import { type MiniAppFaults, startMiniApp } from "./apps/mini-app.ts";

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const sample = JSON.parse(readFileSync(path, "utf8")) as Manifest;
const template = { services: [{ name: "app", domains: [] }, { name: "bridge", domains: ["bridge.example.org"] }] };
/** the sample as product `inbox` with the allow-listed person ops items_list (read) and item_ack (write) */
const inbox = structuredClone(sample) as Manifest;
(inbox as { id: string }).id = "inbox";
inbox.operations.push(
  { id: "items_list", title: "List items", description: "Person op: list the open items.", input: { type: "object" }, output: { type: "object" }, crud: ["read"], effect: "read", idempotency: "none", receipt: false, audience: "person" } as Manifest["operations"][number],
  { id: "item_ack", title: "Acknowledge item", description: "Person op: acknowledge one item.", input: { type: "object", properties: { id: { type: "string" } } }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: false, audience: "person" } as Manifest["operations"][number],
);

const SPO = Array.from({ length: 12 }, (_, i) => `S-PO-${i + 1}`);
const NA_GENERIC = ["S-PO-8", "S-PO-12"];
const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
const asserted = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.asserted ?? "";
const failing = (r: Report) => r.checks.filter((c) => c.status === "fail" || c.status === "not_run" || c.status === "not_implemented").map((c) => `${c.id}: ${c.asserted.slice(0, 160)}`);
const mini = (m: Manifest, faults: MiniAppFaults = {}) => runApp({ manifest: m, manifestPath: path, start: (env) => startMiniApp(m, env, faults), deployTemplate: template, timeoutMs: 8000 });

describe("app target: relayed person ops (S-PO, spec 0.1.64)", { timeout: 600_000 }, () => {
  it("a correct app of product inbox passes every row, S-PO-11 included; S-PO-8 / S-PO-12 are not_applicable with their reason", { timeout: 120_000 }, async () => {
    const r = await mini(inbox);
    assert.deepEqual(failing(r), []);
    for (const id of SPO.filter((x) => !NA_GENERIC.includes(x))) assert.equal(status(r, id), "pass", `${id}: ${asserted(r, id)}`);
    for (const id of NA_GENERIC) assert.equal(status(r, id), "not_applicable", `${id}: ${asserted(r, id)}`);
    assert.match(asserted(r, "S-PO-11"), /item_ack: first 200 ok; same idk again 200 ok, answer = the first/);
    assert.match(asserted(r, "S-PO-12"), /Inbox suite/);
  });

  it("the sample product (no allow-list entry): S-PO-11 is not_applicable, every op is 403 person_op_not_allowed", { timeout: 120_000 }, async () => {
    const r = await mini(sample);
    assert.equal(status(r, "S-PO-11"), "not_applicable", asserted(r, "S-PO-11"));
    assert.equal(status(r, "S-PO-6"), "pass", asserted(r, "S-PO-6"));
    assert.match(asserted(r, "S-PO-6"), /items_list → 403 person_op_not_allowed/);
  });

  it("S-PO rows are decided by the person_op capability, never by version: no cap → not_applicable whatever the app does; cap + an old reported version → the rows run", { timeout: 120_000 }, async () => {
    const [none, old] = await Promise.all([mini(inbox, { personOp: { noCap: true, noBodyDigest: true, anyCli: true } }), mini(inbox, { reportedSdkVersion: "0.1.30" })]);
    for (const id of SPO) {
      assert.equal(status(none, id), "not_applicable", `${id}: ${asserted(none, id)}`);
      assert.match(asserted(none, id), /does not declare the person_op capability.*never by version/);
    }
    for (const id of SPO.filter((x) => !NA_GENERIC.includes(x))) assert.equal(status(old, id), "pass", `reported 0.1.30 ${id}: ${asserted(old, id)}`);
  });

  it("fire-on-bad: each broken §21 rule fails its row", { timeout: 300_000 }, async () => {
    const cases: [MiniAppFaults["personOp"], string[]][] = [
      [{ noBodyDigest: true }, ["S-PO-4"]],
      [{ jtiAfterBody: true }, ["S-PO-4"]],
      [{ noReplay: true }, ["S-PO-5", "S-PO-4"]],
      [{ generalLeeway: true }, ["S-PO-9"]],
      [{ anyCli: true }, ["S-PO-7"]],
      [{ allowAll: true }, ["S-PO-6"]],
      [{ ignoresAud: true }, ["S-PO-2"]],
      [{ ignoresWs: true }, ["S-PO-3"]],
      [{ anyTyp: true }, ["S-PO-1"]],
      [{ servedStandalone: true }, ["S-PO-10"]],
      [{ ignoresIdk: true }, ["S-PO-11"]],
    ];
    const reports = await Promise.all(cases.map(([f]) => mini(inbox, { personOp: f })));
    cases.forEach(([f, ids], i) => {
      const r = reports[i] as Report;
      for (const id of ids) assert.equal(status(r, id), "fail", `${JSON.stringify(f)} ${id}: ${status(r, id)} ${asserted(r, id)}`);
    });
    // the body-digest fault fails S-PO-4 only: the other token rows still pass
    for (const id of ["S-PO-1", "S-PO-2", "S-PO-3", "S-PO-5", "S-PO-9"]) assert.equal(status(reports[0] as Report, id), "pass", `noBodyDigest ${id}: ${asserted(reports[0] as Report, id)}`);
  });

  // ── the REAL miniapp-sdk (L2) ──
  const sdkDir = process.env.TBCONF_SDK_DIR ?? fileURLToPath(new URL("../../miniapp-sdk", import.meta.url));
  const skip = existsSync(join(sdkDir, "src/server/person-op.ts")) ? false : `the miniapp-sdk checkout at ${sdkDir} has no POST /tb/v1/person-op (src/server/person-op.ts): set TBCONF_SDK_DIR to a checkout with the route`;
  it("the real miniapp-sdk passes every S-PO row it can be driven on (or, without the person_op declaration, gets not_applicable by capability)", { timeout: 240_000, skip }, async (t) => {
    const sdk = (await import(pathToFileURL(join(sdkDir, "src/server/index.ts")).href)) as {
      defineApp(def: unknown): unknown;
      startApp(app: unknown, env: Record<string, string>, harness?: unknown): Promise<{ stop(): Promise<void>; backups: { runNow(): Promise<unknown> } }>;
    };
    let runs = 0;
    const handlers: Record<string, unknown> = {};
    for (const o of inbox.operations) handlers[o.id] = o.id === "item_ack" ? async (_input: unknown, ctx: { caller?: { via?: string } }) => ({ run: ctx.caller?.via === "tbm" ? ++runs : 0 }) : { scope: () => null, run: async () => ({ ok: true, op: o.id }) };
    const start = async (env: Record<string, string>) => {
      const migrations = join(env.TB_DATA_DIR as string, "migrations");
      mkdirSync(migrations, { recursive: true });
      writeFileSync(join(migrations, "0001_init.sql"), "CREATE TABLE conformance_po (id TEXT PRIMARY KEY);\n");
      const app = sdk.defineApp({ manifest: inbox, handlers, hooks: { guard: async () => ({ allow: true }) }, migrations });
      const port = Number(env.TBCONF_PORT);
      const running = await sdk.startApp(app, env, { portalRootKeys: JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS as string), privilegeProc: { getuid: () => 4242 }, port });
      return { url: `http://127.0.0.1:${port}`, stop: () => running.stop(), backupNow: async () => void (await running.backups.runNow()) };
    };
    const r = await runApp({ manifest: inbox, manifestPath: path, config: null, start: start as never, deployTemplate: template, timeoutMs: 8000 });
    if (status(r, "S-PO-1") === "not_applicable" && /does not declare the person_op capability/.test(asserted(r, "S-PO-1"))) {
      for (const id of SPO) assert.equal(status(r, id), "not_applicable", `${id}: ${asserted(r, id)}`);
      t.diagnostic("this miniapp-sdk serves the route but does not declare caps [person_op] (C354): every S-PO row is not_applicable");
      return;
    }
    for (const id of SPO.filter((x) => !NA_GENERIC.includes(x))) assert.equal(status(r, id), "pass", `${id}: ${asserted(r, id)}`);
    for (const id of NA_GENERIC) assert.equal(status(r, id), "not_applicable", `${id}: ${asserted(r, id)}`);
    assert.equal(runs, 1, "the relayed item_ack ran exactly once for the two calls with one idk");
  });
});
