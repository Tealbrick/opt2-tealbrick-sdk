// spec 0.1.80 (C373, G-2; number set at merge): `ctx.topology()` — the workspace grant picture from the verified slice
// (`slice.topology`), DISPLAY ONLY. Nothing in the SDK reads it for authorization; apps MUST NOT authorize with it.
//
// SPEC-GAP until the spec pin carries 0.1.80: `SliceTopology` and `TOPOLOGY_MAX` mirror `@opt2-tealbrick/spec/bridge`
// (same names, same shape). When the pin moves, replace this mirror with the spec import (L1: one copy).

/** Mirror of spec `TOPOLOGY_MAX` (instance-slice.schema.json `maxItems`). */
export const TOPOLOGY_MAX = { instances: 200, edges: 2000, companions: 500, connections: 500 } as const;

const CRUD = new Set(["create", "read", "update", "delete"]);
const MODES = new Set(["free", "bound"]);
const METHODS = new Set(["key", "pairing"]);
const CON_STATUS = new Set(["active", "revoked"]);

/** Mirror of spec `SliceTopology` (CORE "v0.1.80"). */
export interface SliceTopology {
  instances: { ins: string; product: string; name: string; version: string }[];
  edges: { agt: string; ins: string; product: string; crud: string[]; mode: "free" | "bound"; held: string[]; wf?: string[]; paused?: true }[];
  companions: { from: string; to: string; product: string; crud: string[]; ops?: string[] }[];
  connections: { con: string; agt: string; method: "key" | "pairing"; status: "active" | "revoked" }[];
  truncated?: true;
}

/** Thrown inside {@link readTopology} only; never leaves it. */
class Malformed extends Error {}
const fail = (): never => {
  throw new Malformed();
};

type Obj = Record<string, unknown>;
const obj = (v: unknown): Obj => (v !== null && typeof v === "object" && !Array.isArray(v) ? (v as Obj) : fail());
const str = (o: Obj, k: string): string => {
  const v = o[k];
  return typeof v === "string" && v !== "" ? v : fail();
};
const list = (v: unknown, max: number): unknown[] => (Array.isArray(v) && v.length <= max ? v : fail());
const strings = (v: unknown, allowed?: Set<string>): string[] => {
  const a = list(v, 256);
  for (const x of a) if (typeof x !== "string" || x === "" || (allowed && !allowed.has(x))) fail();
  return Object.freeze([...(a as string[])]) as string[];
};
const oneOf = <T extends string>(o: Obj, k: string, allowed: Set<string>): T => {
  const v = str(o, k);
  return allowed.has(v) ? (v as T) : fail();
};
/** an optional `true`-only flag: absent → not set, `true` → set, anything else → malformed */
const flag = (o: Obj, k: string): boolean => (o[k] === undefined ? false : o[k] === true ? true : fail());
const optStrings = (o: Obj, k: string): { [key: string]: string[] } => (o[k] === undefined ? {} : { [k]: strings(o[k]) });

/**
 * Validates `raw` (the slice's `topology` member) and returns a frozen deep copy that carries ONLY the spec members (unknown
 * members are dropped, so nothing else from the slice can reach the app through it). null when `raw` is absent or any part is
 * malformed (wrong type, unknown vocabulary value, a list over its bound). Never throws.
 */
export function readTopology(raw: unknown): SliceTopology | null {
  if (raw === undefined || raw === null) return null;
  try {
    const t = obj(raw);
    const freeze = <T extends object>(x: T): T => Object.freeze(x);
    const instances = list(t.instances, TOPOLOGY_MAX.instances).map((e) => {
      const o = obj(e);
      return freeze({ ins: str(o, "ins"), product: str(o, "product"), name: str(o, "name"), version: str(o, "version") });
    });
    const edges = list(t.edges, TOPOLOGY_MAX.edges).map((e) => {
      const o = obj(e);
      return freeze({
        agt: str(o, "agt"),
        ins: str(o, "ins"),
        product: str(o, "product"),
        crud: strings(o.crud, CRUD),
        mode: oneOf<"free" | "bound">(o, "mode", MODES),
        held: strings(o.held),
        ...optStrings(o, "wf"),
        ...(flag(o, "paused") ? { paused: true as const } : {}),
      });
    });
    const companions = list(t.companions, TOPOLOGY_MAX.companions).map((e) => {
      const o = obj(e);
      return freeze({ from: str(o, "from"), to: str(o, "to"), product: str(o, "product"), crud: strings(o.crud, CRUD), ...optStrings(o, "ops") });
    });
    const connections = list(t.connections, TOPOLOGY_MAX.connections).map((e) => {
      const o = obj(e);
      return freeze({ con: str(o, "con"), agt: str(o, "agt"), method: oneOf<"key" | "pairing">(o, "method", METHODS), status: oneOf<"active" | "revoked">(o, "status", CON_STATUS) });
    });
    return freeze({
      instances: freeze(instances),
      edges: freeze(edges),
      companions: freeze(companions),
      connections: freeze(connections),
      ...(flag(t, "truncated") ? { truncated: true as const } : {}),
    }) as SliceTopology;
  } catch {
    // Malformed, or (defensive) anything else a crafted value could raise: ctx.topology() never throws
    return null;
  }
}
