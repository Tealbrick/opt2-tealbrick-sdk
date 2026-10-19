// Operation views and MCP tool names (SDK-API §2 + §6, MANIFEST §5.4, BRIDGE §7.3, CORE I9).
import { TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
import type { JsonSchemaObject, Manifest, StandardOperationId } from "@opt2-tealbrick/spec/manifest";
import { CRUD_ACTIONS, STANDARD_OPERATIONS } from "@opt2-tealbrick/spec/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";

type StandardView = Extract<OperationView, { standard: true }>;
type StandardDef = Omit<StandardView, "id" | "standard"> & { input: JsonSchemaObject };

const str = { type: "string", minLength: 1, maxLength: 256 } as const;
const cursor = { type: "string", maxLength: 512 } as const;
const empty: JsonSchemaObject = { type: "object", additionalProperties: false };
function closed(properties: Record<string, unknown>, required: string[] = []): JsonSchemaObject {
  return { type: "object", additionalProperties: false, required, properties };
}

/** The 11 standard operations with audience / crud / effect per SDK-API §6 and their input shapes. */
const STANDARD_DEFS: Record<StandardOperationId, StandardDef> = {
  "tb.hold_status": {
    title: "Hold status",
    crud: ["read"],
    effect: "read",
    audience: "agent",
    idempotency: "none",
    receipt: false,
    input: closed({ holdId: str }, ["holdId"]),
  },
  "tb.holds_list": {
    title: "List holds",
    crud: ["read"],
    effect: "read",
    audience: "person",
    idempotency: "none",
    receipt: false,
    input: closed({ status: str, cursor }),
  },
  "tb.holds_decide": {
    title: "Decide hold",
    crud: ["update"],
    effect: "write",
    audience: "person",
    idempotency: "supported",
    receipt: false,
    input: closed({ holdId: str, decision: { enum: ["approve", "deny"] }, note: { type: "string", maxLength: 1000 } }, [
      "holdId",
      "decision",
    ]),
  },
  "tb.receipts_list": {
    title: "List receipts",
    crud: ["read"],
    effect: "read",
    audience: "person",
    idempotency: "none",
    receipt: false,
    input: closed({ caller: str, op: str, status: str, cursor }),
  },
  "tb.agents_list": {
    title: "List agents",
    crud: ["read"],
    effect: "read",
    audience: "person",
    idempotency: "none",
    receipt: false,
    input: empty,
  },
  "tb.scopes_set": {
    title: "Set scope access",
    crud: ["update"],
    effect: "write",
    audience: "person",
    idempotency: "supported",
    receipt: false,
    // v0.1.52 (C283b/C283c, manifest 0.1.28): `acceptOffer {adds}` accepts a row's offer (SDK-API §7.2); the SDK compares it as a set
    input: closed(
      {
        agent: str,
        type: str,
        id: str,
        access: { anyOf: [str, { type: "null" }] },
        acceptOffer: closed({ adds: { type: "array", maxItems: 8, items: { enum: [...CRUD_ACTIONS] } } }, ["adds"]),
      },
      ["agent", "type", "id", "access"],
    ),
  },
  "tb.keys_status": {
    title: "Key status",
    crud: ["read"],
    effect: "read",
    audience: "person",
    idempotency: "none",
    receipt: false,
    input: empty,
  },
  "tb.key_set": {
    title: "Set key",
    crud: ["update"],
    effect: "write",
    audience: "person",
    idempotency: "supported",
    receipt: false,
    input: closed({ name: str, value: { type: "string", minLength: 1, maxLength: 16384 } }, ["name", "value"]),
  },
  "tb.key_delete": {
    title: "Delete key",
    crud: ["delete"],
    effect: "write",
    audience: "person",
    idempotency: "supported",
    receipt: false,
    input: closed({ name: str }, ["name"]),
  },
  "tb.export": {
    title: "Export data",
    crud: ["read"],
    effect: "read",
    audience: "person",
    idempotency: "none",
    receipt: false,
    input: empty,
  },
  // v0.1.13 (G4): pending holds as summaries; agent → own, companion app → all
  "tb.holds_pending": {
    title: "Pending approvals",
    crud: ["read"],
    effect: "read",
    audience: "agent",
    idempotency: "none",
    receipt: false,
    input: closed({ limit: { type: "integer", minimum: 1, maximum: 100 }, cursor }),
  },
};

/** Input of every dynamic operation call and of the `<product>__<op>_call` tool (`DynamicCallInput`, MANIFEST §5.3). */
export const DYNAMIC_CALL_INPUT_SCHEMA: JsonSchemaObject = Object.freeze(
  closed({ tool: { type: "string", pattern: "^[a-z][a-z0-9_]{1,47}$" }, arguments: { type: "object" } }, ["tool", "arguments"]),
);

/** Input of the `<product>__<op>_search` tool (`DynamicSearchInput`, MANIFEST §5.3). */
export const DYNAMIC_SEARCH_INPUT_SCHEMA: JsonSchemaObject = Object.freeze(
  closed({ query: { type: "string" }, limit: { type: "integer", minimum: 1 } }, ["query"]),
);

/** Standard operation views in STANDARD_OPERATIONS order (frozen; callers must not mutate). */
export const STANDARD_OPERATION_VIEWS: readonly StandardView[] = Object.freeze(
  STANDARD_OPERATIONS.map((id): StandardView => {
    const { input: _input, ...view } = STANDARD_DEFS[id];
    return Object.freeze({ standard: true, id, ...view, crud: [...view.crud] });
  }),
);

/** Input JSON Schema of a standard operation (SDK-API §6 shapes). */
export function standardOpInputSchema(id: StandardOperationId): JsonSchemaObject {
  return STANDARD_DEFS[id].input;
}

/** True when `id` names a standard operation. */
export function isStandardOpId(id: string): id is StandardOperationId {
  return (STANDARD_OPERATIONS as readonly string[]).includes(id);
}

/** Manifest operations (in manifest order) followed by the 11 standard operations: the one list bridge and SDK use. */
export function withStandardOps(manifest: Manifest): OperationView[] {
  const own: OperationView[] = manifest.operations.map((op) => ({ ...op, standard: false as const }));
  return [...own, ...STANDARD_OPERATION_VIEWS.map((v) => ({ ...v, crud: [...v.crud] }))];
}

/** Agent-audience operations (manifest + `tb.hold_status` + `tb.holds_pending`): the candidates for MCP tools. */
export function agentOperations(manifest: Manifest): OperationView[] {
  return withStandardOps(manifest).filter((op) => op.audience === "agent");
}

/** Operation id as it appears in a tool name: standard `tb.x` → `tb_x`; manifest ids unchanged. */
function toolOpPart(opId: string): string {
  return opId.startsWith("tb.") ? `tb_${opId.slice(3)}` : opId;
}

/** MCP tool name `<product>__<op>` (BRIDGE §7.3). Does not check the length; see `toolNameFits`. */
export function mcpToolName(product: string, opId: string): string {
  return `${product}${TOOL_NAME_RULE.separator}${toolOpPart(opId)}`;
}

/** Search-mode dynamic tool names `<product>__<op>_search` / `<product>__<op>_call` (MANIFEST §5.3). */
export function dynamicToolNames(product: string, opId: string): { search: string; call: string } {
  const base = mcpToolName(product, opId);
  return { search: `${base}${TOOL_NAME_RULE.searchSuffix}`, call: `${base}${TOOL_NAME_RULE.callSuffix}` };
}

const TOOL_NAME_RE = new RegExp(TOOL_NAME_RULE.pattern);

/** CORE I9 / BRIDGE §7.3: charset `^[a-z0-9_-]+$` and length ≤ 64. */
export function toolNameFits(name: string): boolean {
  return name.length <= TOOL_NAME_RULE.maxLength && TOOL_NAME_RE.test(name);
}

/** Every MCP tool name a manifest operation derives (M-OP-1): `<product>__<op>`, plus `_search`/`_call` in search mode. Person ops derive none. */
export function derivedToolNames(product: string, op: Manifest["operations"][number]): string[] {
  if (op.audience !== "agent") return [];
  const names = [mcpToolName(product, op.id)];
  if (op.dynamic?.mode === "search") {
    const d = dynamicToolNames(product, op.id);
    names.push(d.search, d.call);
  }
  return names;
}
