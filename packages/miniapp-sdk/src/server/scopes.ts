// Scope store (SDK-API §7.2): the app is the authority for scope assignments (CORE §6). Types and access levels
// come from manifest `scopes[]`; `defaultGrants` (C1) are applied once per (caller, type) on first sight, and (v0.1.13)
// the `shared` default also when an instance becomes shared later, for every caller seen before.
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import { CRUD_ACTIONS, type CrudAction, type Manifest, type Scope } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, PersonPrincipal, ScopeAccessView, ScopeAuthority, ScopeGrantRow, ScopeInstance, ScopeStore, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { metaGet, metaSet, type RawDb, type Row, tx } from "./store.ts";

const SUMMARY_MAX = 80;
/** v0.1.14 (Connect Q-C2): caller type of a scope caller id (companion app callers are instances). */
const callerKind = (id: string): "agent" | "app" => (id.startsWith("ins_") ? "app" : "agent");
const appliesTo = (g: { callers?: readonly ("agent" | "app")[] }, id: string): boolean => !g.callers || g.callers.includes(callerKind(id));

const isCrud = (c: unknown): c is CrudAction => typeof c === "string" && (CRUD_ACTIONS as readonly string[]).includes(c);

/**
 * v0.1.36 (C283b/C283c): the crud snapshot of an OWNER row. NULL, not JSON, not an array: null (the caller reads it as []);
 * an array keeps only valid crud actions. Never throws.
 */
function parseSnapshot(raw: unknown): CrudAction[] | null {
  if (typeof raw !== "string") return null;
  try {
    const v: unknown = JSON.parse(raw);
    return Array.isArray(v) ? v.filter(isCrud) : null;
  } catch {
    return null;
  }
}

/** Same members, any order, duplicates ignored (`acceptOffer.adds` is compared as a SET). */
const sameSet = (a: readonly string[], b: readonly string[]): boolean => {
  const x = new Set(a);
  const y = new Set(b);
  return x.size === y.size && [...x].every((c) => y.has(c));
};

/** v0.1.36: the shape of `acceptOffer` (the standard op's input schema checks it too); 400 input_invalid. */
function acceptOfferAdds(v: unknown): CrudAction[] {
  const adds = v && typeof v === "object" && !Array.isArray(v) && Object.keys(v).every((k) => k === "adds") ? (v as { adds?: unknown }).adds : undefined;
  if (!Array.isArray(adds) || !adds.every(isCrud)) throw new TbError("input_invalid", "acceptOffer must be { adds: crud actions }", 400);
  return adds;
}

function toInstance(r: Row): ScopeInstance {
  return { type: String(r.type), id: String(r.id), label: String(r.label), shared: Number(r.shared) === 1 };
}

export interface ScopeStoreInternals extends ScopeStore {
  /** CRUD set of an access level (manifest `access[].crud`); [] for unknown levels. */
  crudOf(type: string, level: string): CrudAction[];
  /** Monotonic counter reported as `AppStatus.scopesRev`. */
  rev(): number;
  /**
   * Resolved access for a call: the targeted instance, or the best access when the op spans instances.
   * v0.1.35 (C283 A1): `authority` is the stored authority of the targeted row; for an op that spans instances (id null) it is
   * "owner" ONLY when EVERY row of the caller for this type is an owner row, else "bounded" (fail closed).
   */
  resolve(caller: string, type: string, instanceId: string | null): { level: string; crud: CrudAction[]; id: string | null; authority: ScopeAuthority } | null;
  /**
   * v0.1.35 (C283 A1): do the caller's OWNER rows admit `crud` for `type` across instances (the display marks `admitted` and
   * `admittedOps`)? True only when the caller has rows, EVERY row is an owner row and the best row's crud contains `crud`.
   */
  ownerAdmits(caller: string, type: string, crud: readonly CrudAction[]): boolean;
  /** ScopeAccessView for an agent/app caller (person callers see everything). */
  view(caller: string | null, access: ScopeAccessView["access"]): ScopeAccessView;
  /** Applies defaults for a caller that has no slice entry (companion app callers). */
  applyDefaultsFor(caller: string, name: string): void;
  /** v0.1.31: the highest access level the manifest gives AGENTS by default for `type` (see ScopeGrantOps); null = none. */
  agentCeiling(type: string): string | null;
  /** v0.1.38 (C274c, SDK-API §20): every row on one instance (any caller), with its EFFECTIVE crud and authority (event `eligible`). */
  rowsOn(type: string, instanceId: string): ScopeGrantRow[];
}

/**
 * v0.1.38 (C274c/C274d, SDK-API §20): called INSIDE the transaction of a row change when a row of `agent` on (`type`, `instanceId`)
 * was removed, its effective crud narrowed, or its authority went from owner to bounded (the outbox writes a purge row).
 */
export type RowNarrowed = (agent: string, type: string, instanceId: string) => void;

/**
 * v0.1.31 (SDK-INSTANCE-GRANT): the write paths behind `ctx.scopeGrants` / `ctx.scopeSelfRevoke`. Deliberately NOT members
 * of the store object (Start/Event contexts hand the store itself to app code): they are reached only through
 * `scopeGrantOps(store)`, called by the person-op / agent-op context builders in ops.ts.
 */
export interface ScopeGrantOps {
  /**
   * `tb.scopes_set` of a verified owner SESSION (ops.ts `runStandardPersonOp`): the ONE path that writes `authority = 'owner'`
   * (v0.1.35, C283 A1), also when the access level is unchanged ("make primary"). Not a member of the store object, so app code
   * (an op handler, a hook, a job) that holds the store can never reach it.
   */
  ownerSet(principal: PersonPrincipal, agent: string, type: string, instanceId: string, access: string | null, acceptOffer?: { adds: CrudAction[] }): Promise<void>;
  /** `ctx.scopeGrants.grant`: person op only (the caller builds `by` from the verified session). */
  appGrant(by: GrantBy, agent: string, type: string, instanceId: string, access: string): Promise<ScopeGrantRow>;
  /** `ctx.scopeGrants.revoke`: removes the agent's row for the instance, whatever its source; audited. */
  appRevoke(by: GrantBy, agent: string, type: string, instanceId: string): Promise<void>;
  /** `ctx.scopeSelfRevoke`: an agent call drops its OWN row (narrowing is always allowed); audited as `system`. */
  selfRevoke(agent: string, op: string, callId: string | null, type: string, instanceId: string): Promise<void>;
}
const grantOps = new WeakMap<object, ScopeGrantOps>();
export function scopeGrantOps(store: ScopeStoreInternals): ScopeGrantOps {
  const ops = grantOps.get(store);
  if (!ops) throw new TbError("scope_store_unknown", "not a scope store of this SDK", 500);
  return ops;
}

/** Who performs an app grant: the verified person of the live person op, the op, and a check against the verified slice. */
export interface GrantBy {
  principal: PersonPrincipal;
  op: string;
  callId: string | null;
  /** the request id of the person op call (a person op has no call id) */
  requestId: string | null;
  /**
   * Why this agent may not be granted right now, from the CURRENT verified slice (null = may): not in the slice (no edge),
   * or paused / not active (agent status or the workspace, instance or agent pause lists). Throws when the slice is expired.
   */
  refusal(agent: string): { reason: string; message: string } | null;
}

export function createScopeStore(db: RawDb, manifest: Manifest, audit: AuditLog, onChange: () => void, onNarrowed: RowNarrowed = () => {}): ScopeStoreInternals {
  const scopes = new Map<string, Scope>((manifest.scopes ?? []).map((s) => [s.type, s]));
  const scopeOf = (type: string): Scope => {
    const s = scopes.get(type);
    if (!s) throw new TbError("scope_type_unknown", `scope type not declared: ${type}`, 400);
    return s;
  };
  const crudOf = (type: string, level: string): CrudAction[] => [...(scopes.get(type)?.access.find((a) => a.id === level)?.crud ?? [])];
  /**
   * v0.1.36 (C283b/C283c): THE one helper for the crud a stored row gives. A bounded row: the level's crud now (the Portal grant still
   * caps it at call time). An OWNER row: its snapshot ∩ the level's crud now; a narrowed level applies at once, a widened level does
   * not; a NULL, unparsable or non-array snapshot, or a level the manifest no longer has, gives []. EVERY reader goes through
   * `toRow(...).crud` (= this): resolve, best/rank, ownerAdmits, view (readable/writable/can), list/access, the catalog and
   * scope_summary marks.
   */
  const rowCrud = (r: Row): CrudAction[] => {
    const level = crudOf(String(r.type), String(r.access));
    if (r.authority !== "owner") return level;
    const snap = new Set(parseSnapshot(r.crud_snapshot) ?? []);
    return level.filter((c) => snap.has(c));
  };
  /** The actions the level grants now that the owner row's snapshot does not (the OFFER). [] = no offer; bounded rows never offer. */
  const rowOffer = (r: Row): CrudAction[] => {
    if (r.authority !== "owner") return [];
    const snap = new Set(parseSnapshot(r.crud_snapshot) ?? []);
    return crudOf(String(r.type), String(r.access)).filter((c) => !snap.has(c));
  };
  const toRow = (r: Row): ScopeGrantRow => {
    const source = r.source === "default" || r.source === "owner" || r.source === "app" ? r.source : undefined;
    const adds = rowOffer(r);
    return {
      agent: String(r.agent) as AgentId,
      type: String(r.type),
      instanceId: String(r.instance_id),
      access: String(r.access),
      // v0.1.35 (C283 A1): ONLY the exact stored value 'owner' is primary; anything else (the column default, a NULL from a
      // database that skipped the migration, a corrupted value) reads as bounded, the Portal-ceiling rule
      authority: r.authority === "owner" ? "owner" : "bounded",
      // v0.1.31 (SDK-INSTANCE-GRANT): absent on rows written before 0.1.31 (the writer was not stored)
      ...(source ? { source } : {}),
      ...(source === "app" && typeof r.granted_by_op === "string" ? { grantedByOp: r.granted_by_op } : {}),
      // v0.1.36 (C283b/C283c): the EFFECTIVE crud, and the offer on an owner row whose level now grants more than it was set with
      crud: rowCrud(r),
      ...(adds.length > 0 ? { offer: { adds } } : {}),
    };
  };
  const bump = () => {
    metaSet(db, "scopes_rev", (metaGet<number>(db, "scopes_rev") ?? 0) + 1);
    onChange();
  };
  /** order of a LEVEL in the manifest (agent ceiling, app grants): by its crud, then its place in `access[]` */
  const rank = (type: string, level: string): number => {
    const s = scopes.get(type);
    const i = s?.access.findIndex((a) => a.id === level) ?? -1;
    return crudOf(type, level).length * 1000 + i;
  };
  /** order of a ROW: by its EFFECTIVE crud (rowCrud), then its level's place in `access[]` */
  const rowRank = (row: ScopeGrantRow): number => {
    const i = scopes.get(row.type)?.access.findIndex((a) => a.id === row.access) ?? -1;
    return (row.crud ?? []).length * 1000 + i;
  };
  const rowsOf = (caller: string, type: string): ScopeGrantRow[] =>
    (db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ?").all(caller, type) as Row[]).map(toRow);
  const bestOf = (caller: string, type: string): ScopeGrantRow | null =>
    rowsOf(caller, type).reduce<ScopeGrantRow | null>((b, r) => (b === null || rowRank(r) > rowRank(b) ? r : b), null);
  /** v0.1.31 (SDK-INSTANCE-GRANT): the agent ceiling of a type = the highest level any agent-applicable default grant gives. */
  const agentCeiling = (type: string): string | null => {
    const s = scopes.get(type);
    if (!s) return null;
    let best: string | null = null;
    for (const g of s.defaultGrants) {
      if (g.callers && !g.callers.includes("agent")) continue;
      if (best === null || rank(type, g.access) > rank(type, best)) best = g.access;
    }
    return best;
  };
  const accessOf = (caller: string, type: string, id: string): ScopeGrantRow | null => {
    const r = db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").get(caller, type, id) as Row | undefined;
    return r ? toRow(r) : null;
  };
  /**
   * v0.1.38 (C274c/C274d): compares a row before and after a change (call INSIDE its transaction). Removed, effective crud
   * narrowed (an action it gave is gone) or owner → bounded → `onNarrowed` (a purge row of the event outbox).
   */
  const noteChange = (before: ScopeGrantRow | null, agent: string, type: string, instanceId: string): void => {
    if (!before) return;
    const after = accessOf(agent, type, instanceId);
    const lost = after === null || !(before.crud ?? []).every((c) => (after.crud ?? []).includes(c)) || (before.authority === "owner" && after.authority !== "owner");
    if (lost) onNarrowed(agent, type, instanceId);
  };

  /**
   * v0.1.13 (Kanban QA S2): an instance that BECOMES shared (created shared, or switched from not shared) gets the
   * `shared` default grant for every caller whose defaults were already applied (the directory seen so far); callers
   * seen later get it on first sight as before. INSERT OR IGNORE: an existing row (an owner edit) always wins.
   */
  const shareWithSeen = (s: Scope, id: string): boolean => {
    const shared = s.defaultGrants.filter((x) => x.kind === "shared");
    if (shared.length === 0) return false;
    const seen = (db.prepare("SELECT agent FROM tb_scope_defaults WHERE type = ?").all(s.type) as Row[]).map((r) => String(r.agent));
    let n = 0;
    const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES (?, ?, ?, ?, 'default', 'bounded')");
    for (const agent of seen) {
      const g = shared.find((x) => appliesTo(x, agent));
      if (g) n += Number(grant.run(agent, s.type, id, g.access).changes ?? 0);
    }
    return n > 0;
  };

  const createInstance = (type: string, id: string, label: string, opts: { shared?: boolean; ownerAgent?: string } = {}): ScopeInstance => {
    const s = scopeOf(type);
    if (!id || id.length > 128) throw new TbError("scope_instance_invalid", "scope instance id must be 1..128 chars", 400);
    const before = db.prepare("SELECT shared FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, id) as Row | undefined;
    const becomesShared = opts.shared === true && (before === undefined || Number(before.shared) !== 1);
    db.prepare(
      `INSERT INTO tb_scope_instances (type, id, label, shared, owner_agent, created_at) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (type, id) DO UPDATE SET label = excluded.label, shared = excluded.shared, owner_agent = COALESCE(excluded.owner_agent, owner_agent)`,
    ).run(type, id, label, opts.shared ? 1 : 0, opts.ownerAgent ?? null, Date.now());
    if (becomesShared && shareWithSeen(s, id)) bump();
    return toInstance(db.prepare("SELECT * FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, id) as Row);
  };

  const applyDefaultsFor = (caller: string, name: string): void => {
    let changed = false;
    tx(db, () => {
      for (const s of scopes.values()) {
        if (db.prepare("SELECT 1 FROM tb_scope_defaults WHERE agent = ? AND type = ?").get(caller, s.type)) continue;
        const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access, source, authority) VALUES (?, ?, ?, ?, 'default', 'bounded')");
        for (const g of s.defaultGrants) {
          if (!appliesTo(g, caller)) continue;
          let ids: string[];
          if (g.kind === "own") {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ? AND owner_agent = ?").all(s.type, caller) as Row[]).map((r) => String(r.id));
            // MANIFEST §6: `own` = the caller's own instance, created if the app has not created one.
            if (ids.length === 0) ids = [createInstance(s.type, caller, name, { ownerAgent: caller }).id];
          } else if (g.kind === "shared") {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ? AND shared = 1").all(s.type) as Row[]).map((r) => String(r.id));
          } else {
            ids = (db.prepare("SELECT id FROM tb_scope_instances WHERE type = ?").all(s.type) as Row[]).map((r) => String(r.id));
          }
          for (const id of ids) grant.run(caller, s.type, id, g.access);
        }
        db.prepare("INSERT INTO tb_scope_defaults (agent, type, applied_at) VALUES (?, ?, ?)").run(caller, s.type, Date.now());
        changed = true;
      }
    });
    if (changed) bump();
  };

  /**
   * The one writer of a person-set row (`tb.scopes_set`): `authority` says whether it is primary (see ScopeGrantOps.ownerSet).
   * v0.1.36 (C283b/C283c): an owner row stores a crud SNAPSHOT (the level's crud now) when it is created, when its level changes,
   * when a bounded row is made primary, and when an offer is accepted; a plain re-set of the same level on an owner row KEEPS it.
   * `acceptOffer` (owner path only): see ScopeGrantOps.ownerSet. A bounded row has no snapshot (NULL).
   */
  const setRow = async (
    principal: PersonPrincipal,
    agent: string,
    type: string,
    instanceId: string,
    access: string | null,
    authority: ScopeAuthority,
    acceptOffer?: unknown,
  ): Promise<void> => {
    if (principal?.type !== "person") throw new TbError("session_required", "only the owner can set scope access", 403);
    const s = scopeOf(type);
    const accepting = acceptOffer !== undefined;
    const accepted = accepting ? acceptOfferAdds(acceptOffer) : [];
    if (accepting && (access === null || authority !== "owner")) throw new TbError("input_invalid", "acceptOffer needs a level (access) and the owner path", 400);
    if (access !== null && !s.access.some((a) => a.id === access)) throw new TbError("access_level_unknown", `access level not declared: ${access}`, 400);
    if (!db.prepare("SELECT 1 FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, instanceId))
      throw new TbError("scope_instance_unknown", "scope instance does not exist", 404);
    let acceptedAdds: CrudAction[] = [];
    tx(db, () => {
      const before = accessOf(agent, type, instanceId);
      if (access === null) {
        db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
        noteChange(before, agent, type, instanceId);
        return;
      }
      const cur = db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").get(agent, type, instanceId) as Row | undefined;
      let snapshot: string | null = null;
      if (authority === "owner") {
        const ownerCur = cur !== undefined && cur.authority === "owner";
        if (accepting && cur !== undefined && String(cur.access) !== access) throw new TbError("input_invalid", "acceptOffer is for the row's current level: another level is a new choice, not an accept", 400);
        const offer = ownerCur ? rowOffer(cur) : [];
        if (accepting && !sameSet(accepted, offer)) throw new TbError("offer_changed", "the offer is not the one that was shown: read the row again", 409, { adds: offer });
        acceptedAdds = accepting ? offer : [];
        // keep: a plain re-set (or an accept of NOTHING) of an owner row at its own level does not change what the owner accepted
        const keep = ownerCur && String(cur.access) === access && acceptedAdds.length === 0;
        snapshot = keep ? (typeof cur.crud_snapshot === "string" ? cur.crud_snapshot : null) : JSON.stringify(crudOf(type, access));
      }
      db.prepare(
        `INSERT INTO tb_scopes (agent, type, instance_id, access, source, granted_by_op, authority, crud_snapshot) VALUES (?, ?, ?, ?, 'owner', NULL, ?, ?)
         ON CONFLICT (agent, type, instance_id) DO UPDATE SET access = excluded.access, source = 'owner', granted_by_op = NULL, authority = excluded.authority, crud_snapshot = excluded.crud_snapshot`,
      ).run(agent, type, instanceId, access, authority === "owner" ? "owner" : "bounded", snapshot);
      noteChange(before, agent, type, instanceId);
    });
    await audit.record({ actor: principal.id, action: "scope.set", target: agent, detail: { type, instance: instanceId, access, ...(access !== null ? { authority } : {}) } });
    if (acceptedAdds.length > 0) await audit.record({ actor: principal.id, action: "scope.offer_accepted", target: agent, detail: { type, instance: instanceId, access, adds: acceptedAdds } });
    bump();
  };

  /** Deletes one row and notes the removal (purge row) in the same transaction; false when there was none. */
  const removeRow = (agent: string, type: string, instanceId: string): boolean =>
    tx(db, () => {
      const before = accessOf(agent, type, instanceId);
      const r = db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
      if (Number(r.changes ?? 0) === 0) return false;
      noteChange(before, agent, type, instanceId);
      return true;
    });

  const store: ScopeStoreInternals = {
    instances: {
      async create(type, id, label, opts) {
        return createInstance(type, id, label, opts);
      },
      async list(type) {
        scopeOf(type);
        return (db.prepare("SELECT * FROM tb_scope_instances WHERE type = ? ORDER BY created_at, id").all(type) as Row[]).map(toInstance);
      },
    },
    async access(agent, type, instanceId) {
      return accessOf(agent, type, instanceId);
    },
    async best(agent, type) {
      return bestOf(agent, type);
    },
    async list(agent) {
      return (db.prepare("SELECT * FROM tb_scopes WHERE agent = ? ORDER BY type, instance_id").all(agent) as Row[]).map(toRow);
    },
    // v0.1.35 (C283 A1): the public store method NEVER writes an owner row: it is reachable from app code (the `StartedApp` handle),
    // and the principal it takes is a plain object an agent op or a companion-call handler could forge. It still writes source
    // 'owner' (audited) but authority 'bounded'. The one owner path is `ScopeGrantOps.ownerSet`, called with the verified session.
    async set(principal: PersonPrincipal, agent, type, instanceId, access) {
      await setRow(principal, agent, type, instanceId, access, "bounded");
    },
    async applyDefaults(agent: SliceAgent) {
      applyDefaultsFor(agent.id, agent.name);
    },
    async summary(agent) {
      const parts: string[] = [];
      for (const s of scopes.values()) {
        const rows = rowsOf(agent, s.type);
        if (rows.length === 0) continue;
        const text = s.summaryTemplate.replace(/\{(count|label|labelPlural|access\.([a-z0-9_]+))\}/g, (_m, v: string, level?: string) => {
          if (v === "count") return String(rows.length);
          if (v === "label") return s.label;
          if (v === "labelPlural") return s.labelPlural;
          return String(rows.filter((r) => r.access === level).length);
        });
        parts.push(text);
      }
      const out = parts.join(" · ");
      return out.length <= SUMMARY_MAX ? out : `${out.slice(0, SUMMARY_MAX - 1)}…`;
    },
    crudOf,
    agentCeiling,
    rowsOn(type, instanceId) {
      return (db.prepare("SELECT * FROM tb_scopes WHERE type = ? AND instance_id = ? ORDER BY agent").all(type, instanceId) as Row[]).map(toRow);
    },
    rev: () => metaGet<number>(db, "scopes_rev") ?? 0,
    resolve(caller, type, instanceId) {
      if (instanceId !== null) {
        const row = accessOf(caller, type, instanceId);
        return row ? { level: row.access, crud: row.crud ?? [], id: instanceId, authority: row.authority === "owner" ? "owner" : "bounded" } : null;
      }
      // an op that spans instances: the best access; owner only when EVERY row involved is an owner row
      const rows = rowsOf(caller, type);
      const row = bestOf(caller, type);
      if (!row) return null;
      return { level: row.access, crud: row.crud ?? [], id: null, authority: rows.every((r) => r.authority === "owner") ? "owner" : "bounded" };
    },
    ownerAdmits(caller, type, crud) {
      if (!scopes.has(type)) return false;
      const r = store.resolve(caller, type, null);
      return r !== null && r.authority === "owner" && crud.every((c) => r.crud.includes(c));
    },
    view(caller, access) {
      const ids = async (type: string, want: (c: CrudAction[]) => boolean): Promise<string[]> => {
        scopeOf(type);
        if (caller === null) return (await store.instances.list(type)).map((i) => i.id);
        return rowsOf(caller, type)
          .filter((r) => want(r.crud ?? []))
          .map((r) => r.instanceId);
      };
      return {
        access,
        readable: (type) => ids(type, (c) => c.includes("read")),
        writable: (type) => ids(type, (c) => c.some((a) => a !== "read")),
        async can(type, id, crud) {
          scopeOf(type);
          if (caller === null) return true;
          const row = accessOf(caller, type, id);
          return row !== null && (row.crud ?? []).includes(crud);
        },
      };
    },
    applyDefaultsFor,
  };
  const ops: ScopeGrantOps = {
    async ownerSet(principal, agent, type, instanceId, access, acceptOffer) {
      await setRow(principal, agent, type, instanceId, access, "owner", acceptOffer);
    },
    async appGrant(by, agent, type, instanceId, access) {
      const bad = (reason: string, message: string): TbError => new TbError("scope_grant_invalid", message, 400, { reason });
      if (by?.principal?.type !== "person") throw new TbError("session_required", "only a person op can grant scope access", 403);
      if (typeof agent !== "string" || !agent.startsWith("agt_")) throw bad("agent_invalid", "not an agent id");
      const s = scopes.get(type);
      if (!s) throw bad("type_unknown", `scope type not declared: ${type}`);
      if (typeof instanceId !== "string" || !db.prepare("SELECT 1 FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, instanceId))
        throw bad("instance_unknown", "scope instance does not exist");
      if (typeof access !== "string" || !s.access.some((a) => a.id === access)) throw bad("level_unknown", `access level not declared: ${String(access)}`);
      const ceiling = agentCeiling(type);
      if (ceiling === null) throw bad("no_agent_ceiling", `the manifest gives agents no default access to ${type}: an app cannot grant it`);
      // level <= ceiling: not above it in the manifest order AND no CRUD action the ceiling lacks
      const cc = crudOf(type, ceiling);
      if (rank(type, access) > rank(type, ceiling) || !crudOf(type, access).every((c) => cc.includes(c)))
        throw bad("above_ceiling", `access level ${access} is above the agent ceiling ${ceiling}`);
      const refused = by.refusal(agent);
      if (refused) throw bad(refused.reason, refused.message);
      tx(db, () => {
        const before = accessOf(agent, type, instanceId);
        db.prepare(
          // v0.1.35 (C283 A1): authority 'bounded' also when this overwrites an owner row (an app never makes a row primary)
          `INSERT INTO tb_scopes (agent, type, instance_id, access, source, granted_by_op, authority) VALUES (?, ?, ?, ?, 'app', ?, 'bounded')
           ON CONFLICT (agent, type, instance_id) DO UPDATE SET access = excluded.access, source = 'app', granted_by_op = excluded.granted_by_op, authority = 'bounded', crud_snapshot = NULL`,
        ).run(agent, type, instanceId, access, by.op);
        noteChange(before, agent, type, instanceId);
      });
      await audit.record({
        actor: by.principal.id,
        action: "scope.set",
        target: agent,
        detail: { type, instance: instanceId, access, source: "app", op: by.op, callId: by.callId, requestId: by.requestId },
      });
      bump();
      return toRow(db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").get(agent, type, instanceId) as Row);
    },
    async appRevoke(by, agent, type, instanceId) {
      if (by?.principal?.type !== "person") throw new TbError("session_required", "only a person op can revoke scope access", 403);
      if (!scopes.has(type)) throw new TbError("scope_grant_invalid", `scope type not declared: ${type}`, 400, { reason: "type_unknown" });
      const removed = removeRow(agent, type, instanceId);
      if (!removed) return;
      await audit.record({
        actor: by.principal.id,
        action: "scope.set",
        target: agent,
        detail: { type, instance: instanceId, access: null, source: "app", op: by.op, callId: by.callId, requestId: by.requestId },
      });
      bump();
    },
    async selfRevoke(agent, op, callId, type, instanceId) {
      if (!scopes.has(type)) throw new TbError("scope_grant_invalid", `scope type not declared: ${type}`, 400, { reason: "type_unknown" });
      const removed = removeRow(agent, type, instanceId);
      if (!removed) return;
      await audit.record({
        // the agent narrowed its own access: it is the actor (AuditEntry.actor is typed for people, but the column is text)
        actor: agent as never,
        action: "scope.set",
        target: agent,
        detail: { type, instance: instanceId, access: null, source: "agent_self", op, callId },
      });
      bump();
    },
  };
  grantOps.set(store, ops);
  return store;
}
