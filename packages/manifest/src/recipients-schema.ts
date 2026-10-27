// spec 0.1.81 (unreleased label; C373, M-OP-14): the manifest schema of the pinned spec (0.1.78) has no `operations[].recipients`
// and refuses unknown op members. Until the spec pin carries it, the validator compiles the pinned schema with the SAME
// addition the spec PR makes (specs `manifest.schema.json`: `$defs.recipientSpec`, `operation.properties.recipients`,
// `operation.dependentSchemas.recipients`). TODO(C373 re-pin): delete this file and compile the pinned schema as it is; when the
// pinned schema already has the member this is the identity. Not exported from the package index.
import { RECIPIENT_KINDS, RECIPIENT_POINTER_MAX, RECIPIENT_SPECS_MAX } from "./recipients.ts";

type Obj = Record<string, unknown>;

export function withRecipientsSchema<S extends object>(schema: S): S {
  const defs = (schema as { $defs?: Obj }).$defs;
  const op = defs?.operation as { properties?: Obj; dependentSchemas?: Obj } | undefined;
  if (!defs || !op?.properties || "recipients" in op.properties) return schema;
  return {
    ...schema,
    $defs: {
      ...defs,
      recipientSpec: {
        type: "object",
        additionalProperties: false,
        required: ["pointer", "kind"],
        properties: { pointer: { type: "string", maxLength: RECIPIENT_POINTER_MAX, pattern: "^(/([^~/]|~[01])*)+$" }, kind: { enum: [...RECIPIENT_KINDS] } },
      },
      operation: {
        ...op,
        dependentSchemas: { ...(op.dependentSchemas ?? {}), recipients: { properties: { effect: { const: "outward" } } } },
        properties: { ...op.properties, recipients: { type: "array", minItems: 1, maxItems: RECIPIENT_SPECS_MAX, items: { $ref: "#/$defs/recipientSpec" } } },
      },
    },
  } as S;
}
