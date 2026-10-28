// spec 0.1.87 (C373, G-2): `ctx.topology()` — the workspace grant picture from the verified slice
// (`slice.topology`, compact tuple form), DISPLAY ONLY. Nothing in the SDK reads it for authorization; apps MUST NOT
// authorize with it.
//
// SPEC-GAP until the spec pin carries 0.1.87: `SliceTopology`, the tuple aliases and `TOPOLOGY_MAX` mirror
// `@opt2-tealbrick/spec/bridge` (same names, same shape). When the pin moves, replace this mirror with the spec import (L1:
// one copy); the decode helpers (`topologyCrudActions`, `topologyHeldFamilies`) come from the spec then.

/** Mirror of spec `TOPOLOGY_MAX` (instance-slice.schema.json `maxItems`). */
export const TOPOLOGY_MAX = { instances: 40, edges: 600, companions: 100, connections: 300 } as const;
const OPS_COUNT_MAX = 128;
const HELD_MASK_MAX = 0x7fff_ffff;
const CRUD_RE = /^c?r?u?d?$/;

/** Mirrors of the spec tuple aliases (CORE "v0.1.87"). */
export type TopologyInstance = [ins: string, product: string, name: string, version: string];
export type TopologyEdge = [agentIdx: number, instIdx: number, crud: string, mode: "f" | "b", held: number, wfCount: number, paused: 0 | 1];
export type TopologyCompanion = [fromIdx: number, toIdx: number, crud: string, opsCount: number];
export type TopologyConnection = [con: string, agentIdx: number, method: "k" | "p", status: "a" | "r"];
/** Mirror of spec `SliceTopology`. */
export interface SliceTopology {
  v: 1;
  instances: TopologyInstance[];
  edges: TopologyEdge[];
  companions: TopologyCompanion[];
  connections: TopologyConnection[];
  truncated?: true;
}

class Malformed extends Error {}
const fail = (): never => {
  throw new Malformed();
};

const list = (v: unknown, max: number): unknown[] => (Array.isArray(v) && v.length <= max ? v : fail());
const tuple = (v: unknown, arity: number): unknown[] => (Array.isArray(v) && v.length === arity ? v : fail());
const str = (v: unknown): string => (typeof v === "string" && v !== "" ? v : fail());
const int = (v: unknown, max: number): number => (Number.isInteger(v) && (v as number) >= 0 && (v as number) <= max ? (v as number) : fail());
/** an index: any integer is well-formed; whether it is IN RANGE is checked by the caller (out of range = drop the row) */
const index = (v: unknown): number => (Number.isInteger(v) ? (v as number) : fail());
const crud = (v: unknown): string => (typeof v === "string" && CRUD_RE.test(v) ? v : fail());
const oneOf = <T extends string | number>(v: unknown, allowed: readonly T[]): T => (allowed.includes(v as T) ? (v as T) : fail());
const inRange = (i: number, length: number): boolean => i >= 0 && i < length;

/**
 * Validates `raw` (the slice's `topology` member) and returns a deeply frozen copy. `agentsLength` = the length of the SAME
 * slice's `agents[]` (what `agentIdx` indexes). A row whose index is out of range (0 ≤ idx < length fails) is DROPPED and the
 * copy carries `truncated: true` (CORE "v0.1.87" rule 2). null when `raw` is absent or malformed: `v` is not 1, a list is
 * missing, not an array or over its bound, a row has the wrong arity or a value outside its type. Never throws.
 */
export function readTopology(raw: unknown, agentsLength: number): SliceTopology | null {
  if (raw === undefined || raw === null) return null;
  try {
    if (typeof raw !== "object" || Array.isArray(raw)) fail();
    const t = raw as Record<string, unknown>;
    if (t.v !== 1) fail();
    if (t.truncated !== undefined && t.truncated !== true) fail();
    let dropped = false;
    const keep = <R>(row: R, ok: boolean): R[] => {
      if (ok) return [Object.freeze(row) as R];
      dropped = true;
      return [];
    };
    const instances = list(t.instances, TOPOLOGY_MAX.instances).map((r) => {
      const [ins, product, name, version] = tuple(r, 4);
      return Object.freeze([str(ins), str(product), str(name), str(version)]) as TopologyInstance;
    });
    const n = instances.length;
    const edges = list(t.edges, TOPOLOGY_MAX.edges).flatMap((r) => {
      const [a, i, c, m, h, w, p] = tuple(r, 7);
      const row: TopologyEdge = [index(a), index(i), crud(c), oneOf(m, ["f", "b"] as const), int(h, HELD_MASK_MAX), int(w, OPS_COUNT_MAX), oneOf(p, [0, 1] as const)];
      return keep(row, inRange(row[0], agentsLength) && inRange(row[1], n));
    });
    const companions = list(t.companions, TOPOLOGY_MAX.companions).flatMap((r) => {
      const [f, to, c, o] = tuple(r, 4);
      const row: TopologyCompanion = [index(f), index(to), crud(c), int(o, OPS_COUNT_MAX)];
      return keep(row, inRange(row[0], n) && inRange(row[1], n));
    });
    const connections = list(t.connections, TOPOLOGY_MAX.connections).flatMap((r) => {
      const [con, a, m, s] = tuple(r, 4);
      const row: TopologyConnection = [str(con), index(a), oneOf(m, ["k", "p"] as const), oneOf(s, ["a", "r"] as const)];
      return keep(row, inRange(row[1], agentsLength));
    });
    return Object.freeze({
      v: 1 as const,
      instances: Object.freeze(instances) as TopologyInstance[],
      edges: Object.freeze(edges) as TopologyEdge[],
      companions: Object.freeze(companions) as TopologyCompanion[],
      connections: Object.freeze(connections) as TopologyConnection[],
      ...(t.truncated === true || dropped ? { truncated: true as const } : {}),
    });
  } catch {
    // Malformed, or (defensive) anything else a crafted value could raise: ctx.topology() never throws
    return null;
  }
}

/** What `ctx.topology()` returns: the topology AND the agent ids of the SAME verified slice, in slice order (`agentIds[i]` =
 *  `slice.agents[i].id`), so `agentIdx` resolves without a second read that a newer slice could change in between. */
export type SliceTopologyView = SliceTopology & { agentIds: readonly string[] };

/**
 * Builds the view from ONE slice object (`slice.topology` + `slice.agents`, read together). null when the topology is absent or
 * malformed (readTopology) or when `agents` is not an array of entries with a non-empty string `id`. Deeply frozen. Never throws.
 */
export function topologyView(slice: { topology?: unknown; agents?: unknown }): SliceTopologyView | null {
  try {
    const agents = slice.agents;
    if (!Array.isArray(agents)) return null;
    const agentIds: string[] = [];
    for (const a of agents) {
      const id = a !== null && typeof a === "object" ? (a as { id?: unknown }).id : undefined;
      if (typeof id !== "string" || id === "") return null;
      agentIds.push(id);
    }
    const t = readTopology(slice.topology, agentIds.length);
    return t ? Object.freeze({ ...t, agentIds: Object.freeze(agentIds) }) : null;
  } catch {
    return null;
  }
}

