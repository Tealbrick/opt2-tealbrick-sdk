// A REAL @opt2-tealbrick/miniapp-sdk app behind the bridge under test (bridge target group `real_app`, C91): the
// fake apps re-implement the SDK's verification rules, so a bridge and a fake app can agree on a binding the SDK
// refuses (QA S1: catalog proofs signed with `in` → 401 on every dynamic search). This app is started IN-PROCESS with
// startApp (test roots via the harness option, TB_DATA_EPHEMERAL=1) and claims through the bridge like any instance.
// Its manifest is derived from an example manifest: one plain agent op with a receipt, one search-mode and one
// list-mode dynamic op. The SDK is loaded at run time (default: the installed package; `sdkModule` overrides it, e.g.
// the SDK source in a workspace), so the rest of the suite never needs it.
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { validateManifest } from "@opt2-tealbrick/manifest";
import type { DynamicCatalogEntry, Manifest, Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

/** Op ids of the real app (generated; no product id). */
export const REAL_OPS = { plain: "real_write", search: "real_lookup", list: "real_listing" } as const;
/**
 * The real app's before hook (L2, B25.real_hook_hold): it matches one agent op of a fake app and answers a hold verdict
 * {family policy, reason} when the call input carries `marker`, otherwise allow. miniapp-sdk ≤ 0.1.15 checked hook
 * answers with its own key list and turned every hold answer into 500 hook_failed.
 */
export const REAL_HOOK = { id: "conformance_hold", marker: "tbconf-hold-marker", family: "policy", reason: "conformance hold" } as const;
/** The fake app op the real app's before hook matches (`realAppManifest` option). */
export interface RealHookTarget {
  product: string;
  operation: string;
}
/** Catalog entries the real app answers: one per dynamic op. */
export const REAL_ENTRIES = { search: "real_found_entry", list: "real_listed_entry" } as const;

/** The subset of the SDK this suite uses (typed locally: the SDK is an optional run-time load). */
export interface SdkModule {
  defineApp(def: Record<string, unknown>): unknown;
  startApp(app: unknown, env: Record<string, string>, harness?: { portalRootKeys?: unknown[]; privilegeProc?: { getuid?: () => number } }): Promise<RealRunningApp>;
}
/** The subset of a receipt this suite reads (SDK-API §4.1; `meta` carries the caller context since spec 0.1.77). */
export interface RealReceipt {
  id: string;
  op: string;
  status: string;
  callId: string | null;
  createdAt: number;
  caller: { type: string; id: string };
  meta: Json;
}
export interface RealRunningApp {
  status(): string;
  receipts: {
    list(q: { op?: string; limit?: number }): Promise<{ items: RealReceipt[] }>;
    /** conformance 0.1.31 (B32): one receipt by id (a hold's id is its receipt's) */
    get(id: string): Promise<RealReceipt | null>;
  };
  stop(): Promise<void>;
}
/** The subset of the SDK's StartContext the suite uses (C85: app-initiated companion calls, no parentCall). */
export interface RealStartContext {
  /** conformance 0.1.31 (C367 P4, SDK-API §18.6): `context` = the caller context of the call */
  callApp(product: string, op: string, input: Json, opts?: { idempotencyKey?: string; context?: Record<string, Json> }): Promise<unknown>;
  /** conformance 0.1.31 (spec 0.1.77): the caps of the slice (`bridge.caps`; [] when absent); an SDK before 0.1.41 has no such member */
  bridgeCaps?(): readonly string[];
}
/** A started real app plus the StartContext its `onStart` received (null until the claim succeeded and onStart ran). */
export interface RealApp extends RealRunningApp {
  startContext(): RealStartContext | null;
}
/** A companion edge of the real app (manifest `companions[]`): the world mints its grant like any app's (B26). */
export interface RealCompanion {
  product: string;
  operations: string[];
  crud: Operation["crud"];
}

/** Loads the SDK (`spec` default: the installed `@opt2-tealbrick/miniapp-sdk`); null with the reason when it cannot. */
export async function loadSdk(spec = "@opt2-tealbrick/miniapp-sdk"): Promise<{ sdk: SdkModule } | { error: string }> {
  try {
    const m = (await import(spec)) as Partial<SdkModule>;
    if (typeof m.defineApp !== "function" || typeof m.startApp !== "function") return { error: `${spec} exports no defineApp / startApp` };
    return { sdk: m as SdkModule };
  } catch (e) {
    return { error: `cannot load ${spec} (${e instanceof Error ? e.message.split("\n")[0] : String(e)}); build it (pnpm --filter @opt2-tealbrick/miniapp-sdk build) or pass sdkModule` };
  }
}

const entry = (name: string, title: string): DynamicCatalogEntry => ({
  name,
  title,
  description: "Generated conformance catalog entry.",
  inputSchema: { type: "object", properties: { q: { type: "string" } } },
  crud: ["read"],
  effect: "read",
});

/**
 * The real app's manifest: `base` (an example manifest) reduced to three generated ops, listening on `port`; with
 * `companion`, one companion edge (C85 app-initiated calls through StartContext.callApp, B26).
 */
export function realAppManifest(base: Manifest, id: string, port: number, companion?: RealCompanion, hook?: RealHookTarget): Manifest {
  const b = structuredClone(base) as Manifest & Record<string, unknown>;
  const m: Record<string, unknown> = {
    ...(b.$schema !== undefined ? { $schema: b.$schema } : {}),
    schema: b.schema,
    id,
    name: "Conformance real app",
    summary: "Generated SDK app for the bridge target.",
    description: "Generated by the conformance suite: a real SDK app with plain and dynamic operations.",
    version: "1.0.0",
    sdkMajor: b.sdkMajor,
    publisher: b.publisher,
    source: b.source,
    icon: b.icon,
    discovery: b.discovery,
    backups: b.backups,
    runtime: { build: b.runtime.build, port, healthPath: b.runtime.healthPath, resources: b.runtime.resources, volumes: b.runtime.volumes },
    operations: [
      {
        id: REAL_OPS.plain,
        title: "Generated write",
        description: "Generated conformance operation with a receipt.",
        input: { type: "object", properties: { id: { type: "string" } } },
        output: { type: "object" },
        crud: ["create"],
        effect: "write",
        idempotency: "required",
        receipt: true,
        audience: "agent",
      },
      { id: REAL_OPS.search, title: "Generated search", description: "Generated search-mode dynamic operation.", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read"], effectCeiling: "read" } },
      { id: REAL_OPS.list, title: "Generated listing", description: "Generated list-mode dynamic operation.", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } },
    ],
    ...(companion ? { companions: [{ product: companion.product, operations: companion.operations, crud: companion.crud, purpose: "Generated companion edge for app-initiated calls" }] } : {}),
    ...(hook ? { hooks: [{ id: REAL_HOOK.id, title: "Conformance hold verdict", phase: "before", order: 500, match: { products: [hook.product], operations: [hook.operation] }, timeoutMs: 2000 }] } : {}),
    ...(b.ui ? { ui: b.ui } : {}),
  };
  const v = validateManifest(m);
  if (!v.ok) throw new Error(`real app manifest invalid: ${v.errors.slice(0, 4).map((e) => `${e.path} ${e.code} ${e.message}`).join("; ")}`);
  return v.manifest;
}

/**
 * defineApp + startApp with the given env (TB_* names) and test roots; `dataDir` gets a migrations folder. `onStart`
 * keeps its StartContext (C85: callApp outside a handler) for the harness: `startContext()`.
 */
export async function startRealApp(sdk: SdkModule, manifest: Manifest, env: Record<string, string>, dataDir: string, portalRootKeys: unknown[] | null): Promise<RealApp> {
  const migrations = join(dataDir, "migrations");
  mkdirSync(migrations, { recursive: true });
  writeFileSync(join(migrations, "0001_init.sql"), "CREATE TABLE conformance_real (id TEXT PRIMARY KEY);\n");
  let started: RealStartContext | null = null;
  const dyn = (name: string) => ({
    catalog: async () => [entry(name, `Generated ${name}`)],
    resolve: async (tool: string) => (tool === name ? { tool, crud: ["read"], effect: "read" } : null),
    call: async (tool: string, args: Json) => ({ tool, real: true, args }),
  });
  const hasMarker = (r: unknown) => JSON.stringify((r as { call?: { input?: unknown } } | null)?.call?.input ?? null).includes(REAL_HOOK.marker);
  const app = sdk.defineApp({
    manifest,
    handlers: { [REAL_OPS.plain]: async () => ({ written: true, real: true }) },
    ...((manifest.hooks ?? []).some((h) => h.id === REAL_HOOK.id)
      ? { hooks: { [REAL_HOOK.id]: async (r: unknown) => (hasMarker(r) ? { allow: false, hold: { family: REAL_HOOK.family, reason: REAL_HOOK.reason } } : { allow: true }) } }
      : {}),
    dynamic: { [REAL_OPS.search]: dyn(REAL_ENTRIES.search), [REAL_OPS.list]: dyn(REAL_ENTRIES.list) },
    migrations,
    onStart: async (ctx: RealStartContext) => {
      started = ctx;
    },
  });
  // in-process app: a root CI runner must not be dropped to uid 1000 by it (harness-only privilege facade, C53/C54)
  const privilegeProc = { getuid: () => 1000 };
  const running = await sdk.startApp(app, env, portalRootKeys ? { portalRootKeys, privilegeProc } : { privilegeProc });
  return { status: () => running.status(), receipts: running.receipts, stop: () => running.stop(), startContext: () => started };
}
