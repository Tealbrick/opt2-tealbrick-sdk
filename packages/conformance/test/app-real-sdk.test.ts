// The new 0.1.24 and 0.1.25 app rows (A20, A12.caller_unverified_refused, A2 hook sub / call / bd, A21) against the REAL miniapp-sdk of this workspace,
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
  { id: "purge_all", title: "Purge", description: "Delete everything (no scope type).", input: { type: "object" }, output: { type: "object" }, crud: ["delete"], effect: "destructive", holdFamily: "destructive", idempotency: "supported", receipt: true, audience: "agent" } as Manifest["operations"][number],
  { id: "item_lookup", title: "Look up items", description: "Search-mode dynamic operation.", crud: ["read"], effect: "read", scopeType: "space", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read", "create"], effectCeiling: "money" } } as Manifest["operations"][number],
);
const DYN = [
  { name: "dyn_read", title: "Read entry", description: "Generated read entry.", inputSchema: { type: "object", properties: {} }, crud: ["read"], effect: "read" },
  { name: "dyn_send", title: "Send entry", description: "Generated outward entry.", inputSchema: { type: "object", properties: {} }, crud: ["create"], effect: "outward", holdFamily: "first_contact" },
] as const;

type Ctx = { scopes: { instances: { create(t: string, id: string, label: string): Promise<unknown> } }; scopeGrants: { grant(a: string, t: string, id: string, access: string): Promise<unknown> } };
const handlers: Record<string, unknown> = {};
for (const o of am.operations) {
  if (o.dynamic) continue;
  if (o.id === "scope_grant") {
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

describe("conformance 0.1.24 and 0.1.25 rows against the real miniapp-sdk", { timeout: 300_000 }, () => {
  it("a correct SDK passes every new row", { timeout: 240_000 }, async () => {
    const config = parseConformanceConfig({ scopeGrantOp: { op: "scope_grant", input: { agent: "${tb.agentA}", id: "space-draft", access: "read_write" }, aboveCeiling: { agent: "${tb.agentA}", id: "space-draft", access: "manage" } } }, "test config");
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
      "A2.proof_bd_other_variants",
    ]) {
      assert.equal(st(id)?.status, "pass", `${id}: ${st(id)?.asserted}`);
    }
  });
});
