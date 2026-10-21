// The new 0.1.24 to 0.1.28 app rows (A20, A12.caller_unverified_refused, A2 hook sub / call / bd, A21) against the REAL miniapp-sdk of this workspace,
// not against the mini app test double: a correct SDK passes every row. (The double is where the rows are proven to FAIL on bad.)
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, it } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { applyLevelCrud, LEVEL_CRUD_ENV, parseConformanceConfig, parseLevelCrud, runApp } from "../src/index.ts";

const sdk = (await import(new URL("../../miniapp-sdk/src/server/index.ts", import.meta.url).href)) as {
  defineApp(def: unknown): unknown;
  startApp(app: unknown, env: Record<string, string>, harness?: unknown): Promise<{ stop(): Promise<void>; backups: { runNow(): Promise<unknown> } }>;
};

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const template = { services: [{ name: "app", domains: [] }, { name: "bridge", domains: ["bridge.example.org"] }] };

const am = JSON.parse(readFileSync(path, "utf8")) as Manifest;
am.scopes?.[0]?.access.push({ id: "manage", label: "Manage", crud: ["read", "create", "update", "delete"] });
am.operations.push(
  { id: "scope_grant", title: "Start draft", description: "Person op that gives one agent access to one space.", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: false, audience: "person" } as Manifest["operations"][number],
  { id: "bridge_caps", title: "Bridge caps", description: "Person op that returns ctx.bridgeCaps().", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: false, audience: "person" } as Manifest["operations"][number],
  { id: "purge_all", title: "Purge", description: "Delete everything (no scope type).", input: { type: "object" }, output: { type: "object" }, crud: ["delete"], effect: "destructive", holdFamily: "destructive", idempotency: "supported", receipt: true, audience: "agent" } as Manifest["operations"][number],
  { id: "item_lookup", title: "Look up items", description: "Search-mode dynamic operation.", crud: ["read"], effect: "read", scopeType: "space", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read", "create"], effectCeiling: "money" } } as Manifest["operations"][number],
);
// conformance 0.1.28 (C274c, spec 0.1.57): one unscoped and one scoped event, and the probe op of the A-EV rows
am.operations.push({ id: "events_probe", title: "Events probe", description: "Person op that drives ctx.emit for the A-EV rows.", input: { type: "object" }, output: { type: "object" }, crud: ["update"], effect: "write", idempotency: "supported", receipt: false, audience: "person" } as Manifest["operations"][number]);
am.events = [
  { name: "item.ping", title: "Ping", payloadSchema: { type: "object", additionalProperties: false, required: ["n"], properties: { n: { type: "integer" } } }, visibleWith: "purge_all", audience: "granted" },
  { name: "item.created", title: "An item was created", payloadSchema: { type: "object", additionalProperties: false, required: ["itemId"], properties: { itemId: { type: "string" } } }, visibleWith: "item_get", audience: "granted" },
];
type Emit = (name: string, data: unknown, opts: Record<string, unknown>) => void;
type EvCtx = { emit: Emit; purgeEvents(id: string): void; db: { exec(sql: string): void; transaction<T>(fn: () => T): T }; scopeGrants: { grant(a: string, t: string, id: string, access: string): Promise<unknown> } };
/** sensitivity run only: a probe (and an SDK) that break the A-EV rules */
const broken = { on: false };
async function eventsProbe(input: { case: string; key?: string; instanceId?: string; kind?: string; agent?: string; access?: string }, ctx: EvCtx): Promise<unknown> {
  const subject = { kind: "item", id: "i1" };
  if (broken.on) {
    // emits twice for one change; "rollback" commits; invalid emits are swallowed
    if (input.case === "emit") {
      ctx.emit("item.ping", { n: 1 }, { subject, ...(input.key ? { key: input.key } : {}) });
      ctx.emit("item.ping", { n: 1 }, { subject });
      return {};
    }
    if (input.case === "rollback") {
      ctx.emit("item.ping", { n: 2 }, { subject, ...(input.key ? { key: input.key } : {}) });
      return {};
    }
    if (input.case === "invalid") return { code: null };
  }
  const key = input.key ? { key: input.key } : {};
  const change = () => ctx.db.exec(`INSERT INTO conformance_real (id) VALUES ('${Math.random().toString(36).slice(2)}')`);
  switch (input.case) {
    case "emit":
      ctx.db.transaction(() => {
        change();
        ctx.emit("item.ping", { n: 1 }, { subject, ...key });
      });
      return {};
    case "rollback":
      try {
        ctx.db.transaction(() => {
          change();
          ctx.emit("item.ping", { n: 2 }, { subject, ...key });
          throw new Error("roll back");
        });
      } catch {
        // rolled back on purpose
      }
      return {};
    case "commit_throw":
      ctx.db.transaction(() => ctx.emit("item.ping", { n: 3 }, { subject, ...key }));
      throw new Error("the handler fails after its transaction committed");
    case "invalid": {
      try {
        if (input.kind === "payload") ctx.emit("item.ping", { n: "not an integer" }, { subject });
        else if (input.kind === "undeclared") ctx.emit("item.unknown", {}, { subject });
        else ctx.emit("tb.hold.decided", {}, { subject });
      } catch (e) {
        return { code: (e as { code?: string }).code };
      }
      return { code: null };
    }
    case "scoped":
      ctx.emit("item.created", { itemId: "i1" }, { subject, instanceId: input.instanceId, ...key });
      return {};
    case "purge":
      ctx.purgeEvents(String(input.instanceId));
      return {};
    case "grant":
      await ctx.scopeGrants.grant(String(input.agent), "space", String(input.instanceId), String(input.access));
      return {};
    default:
      return {};
  }
}
const DYN = [
  { name: "dyn_read", title: "Read entry", description: "Generated read entry.", inputSchema: { type: "object", properties: {} }, crud: ["read"], effect: "read" },
  { name: "dyn_send", title: "Send entry", description: "Generated outward entry.", inputSchema: { type: "object", properties: {} }, crud: ["create"], effect: "outward", holdFamily: "first_contact" },
] as const;

type Ctx = { bridgeCaps(): readonly string[]; scopes: { instances: { create(t: string, id: string, label: string): Promise<unknown> } }; scopeGrants: { grant(a: string, t: string, id: string, access: string): Promise<unknown> } };
const handlers: Record<string, unknown> = {};
for (const o of am.operations) {
  if (o.dynamic) continue;
  if (o.id === "bridge_caps") handlers[o.id] = async (_input: unknown, ctx: Ctx) => ({ bridgeCaps: ctx.bridgeCaps() });
  else if (o.id === "events_probe") handlers[o.id] = eventsProbe;
  else if (o.id === "scope_grant") {
    handlers[o.id] = async (input: { agent: string; id: string; access: string }, ctx: Ctx) => {
      await ctx.scopes.instances.create("space", input.id, `Draft ${input.id}`);
      return { row: await ctx.scopeGrants.grant(input.agent, "space", input.id, input.access) };
    };
  } else handlers[o.id] = { scope: (input: { space?: unknown }) => (typeof input?.space === "string" ? input.space : null), run: async () => ({ ok: true, op: o.id }) };
}

async function startReal(env: Record<string, string>) {
  const migrations = join(env.TB_DATA_DIR as string, "migrations");
  mkdirSync(migrations, { recursive: true });
  writeFileSync(join(migrations, "0001_init.sql"), "CREATE TABLE conformance_real (id TEXT PRIMARY KEY);\n");
  const app = sdk.defineApp({
    // conformance 0.1.25: the A21 rows simulate an app update by restarting with TBCONF_LEVEL_CRUD; this start module applies it
    manifest: applyLevelCrud(am, parseLevelCrud(env[LEVEL_CRUD_ENV])),
    handlers,
    hooks: { guard: async () => ({ allow: true }) },
    dynamic: {
      item_lookup: {
        catalog: async () => DYN,
        resolve: async (tool: string) => {
          const e = DYN.find((x) => x.name === tool);
          return e ? { tool, crud: e.crud, effect: e.effect, ...("holdFamily" in e ? { holdFamily: e.holdFamily } : {}) } : null;
        },
        call: async () => ({ done: true }),
      },
    },
    migrations,
  });
  const port = Number(env.TBCONF_PORT);
  const running = await sdk.startApp(app, env, { portalRootKeys: JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS as string), privilegeProc: { getuid: () => 4242 }, port });
  return { url: `http://127.0.0.1:${port}`, stop: () => running.stop(), backupNow: async () => void (await running.backups.runNow()) };
}

const outbox = (await import(new URL("../../miniapp-sdk/src/server/events.ts", import.meta.url).href)) as { EventOutbox: { prototype: Record<string, unknown> } };
const eventsConfig = { eventsProbe: { op: "events_probe", event: "item.ping", scopedEvent: "item.created", instanceId: "${tb.agentA}" } };

describe("conformance 0.1.24 to 0.1.28 rows against the real miniapp-sdk", { timeout: 300_000 }, () => {
  it("a manifest that declares events with no eventsProbe FAILS every A-EV row (never not_applicable; specs#33)", { timeout: 240_000 }, async () => {
    const r = await runApp({ manifest: am, manifestPath: path, config: parseConformanceConfig({}, "test config"), start: startReal as never, deployTemplate: template, timeoutMs: 8000 });
    for (let i = 1; i <= 8; i++) {
      const c = r.checks.find((x) => x.id === `A-EV-${i}`);
      assert.equal(c?.status, "fail", `A-EV-${i}: ${c?.status} ${c?.asserted}`);
      assert.match(c?.asserted ?? "", /no eventsProbe/);
    }
  });

  it("A-EV rows FAIL on a broken probe and an outbox that drops purges and tb.hold.decided (sensitivity)", { timeout: 240_000 }, async () => {
    const proto = outbox.EventOutbox.prototype;
    const saved = { holdDecided: proto.holdDecided, rowNarrowed: proto.rowNarrowed };
    broken.on = true;
    proto.holdDecided = () => {};
    proto.rowNarrowed = () => {};
    try {
      const config = parseConformanceConfig(eventsConfig, "test config");
      const r = await runApp({ manifest: am, manifestPath: path, config, start: startReal as never, deployTemplate: template, timeoutMs: 8000 });
      const st = (id: string) => r.checks.find((c) => c.id === id);
      for (const id of ["A-EV-1", "A-EV-2", "A-EV-3", "A-EV-7", "A-EV-8"]) assert.equal(st(id)?.status, "fail", `${id}: ${st(id)?.status} ${st(id)?.asserted}`);
      // the SDK paths the faults do not touch still pass
      for (const id of ["A-EV-4", "A-EV-5", "A-EV-6"]) assert.equal(st(id)?.status, "pass", `${id}: ${st(id)?.asserted}`);
    } finally {
      broken.on = false;
      proto.holdDecided = saved.holdDecided;
      proto.rowNarrowed = saved.rowNarrowed;
    }
  });

  it("a correct SDK passes every new row", { timeout: 240_000 }, async () => {
    const config = parseConformanceConfig({ scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" } }, bridgeCapsOp: { op: "bridge_caps" }, ...eventsConfig }, "test config");
    const r = await runApp({ manifest: am, manifestPath: path, config, start: startReal as never, deployTemplate: template, timeoutMs: 8000 });
    const st = (id: string) => r.checks.find((c) => c.id === id);
    for (const id of [
      "A12.caller_unverified_refused",
      "A2.hook_sub_mismatch",
      "A2.hook_call_mismatch",
      "A20.bounded_above_grant_refused",
      "A20.owner_row_above_grant",
      "A20.agent_cannot_write_owner_row",
      "A20.app_cannot_write_owner_row",
      "A20.scope_grants_bounded",
      "A20.unscoped_above_grant_refused",
      "A20.paused_agent_owner_row",
      "A20.catalog_admitted",
      "A20.admitted_ops",
      // 0.1.25 (spec 0.1.52): owner rows keep their CRUD (the update rows restart the REAL SDK with the widened / narrowed level), hook proof bd, proofClaims
      "A21.owner_row_widened_level",
      "A21.owner_row_narrowed_level",
      "A21.accept_offer_rules",
      "A2.proof_claims_declared",
      "A2.hook_bd_binds_body",
      "A2.hook_bd_malformed",
      "A2.hook_bd_raw_bytes", // 0.1.26
      "A2.proof_bd_other_variants",
      // 0.1.27 (spec 0.1.54): ctx.bridgeCaps of the REAL SDK follows the slice: equal, absent, expired (a person op still runs on an expired slice)
      "A22.bridge_caps_equal",
      "A22.bridge_caps_absent",
      "A22.bridge_caps_expired",
      // 0.1.28 (spec 0.1.57): app events of the REAL SDK (outbox, sender, eligible, purges, tb.hold.decided)
      "A-EV-1",
      "A-EV-2",
      "A-EV-3",
      "A-EV-4",
      "A-EV-5",
      "A-EV-6",
      "A-EV-7",
      "A-EV-8",
    ]) {
      assert.equal(st(id)?.status, "pass", `${id}: ${st(id)?.asserted}`);
    }
  });
});
