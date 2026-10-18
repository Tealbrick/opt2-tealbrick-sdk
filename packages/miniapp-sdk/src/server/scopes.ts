// Scope store (SDK-API §7.2): the app is the authority for scope assignments (CORE §6). Types and access levels
// come from manifest `scopes[]`; `defaultGrants` (C1) are applied once per (caller, type) on first sight, and (v0.1.13)
// the `shared` default also when an instance becomes shared later, for every caller seen before.
import type { AgentId } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, Manifest, Scope } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, PersonPrincipal, ScopeAccessView, ScopeGrantRow, ScopeInstance, ScopeStore, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { metaGet, metaSet, type RawDb, type Row, tx } from "./store.ts";

const SUMMARY_MAX = 80;
/** v0.1.14 (Connect Q-C2): caller type of a scope caller id (companion app callers are instances). */
const callerKind = (id: string): "agent" | "app" => (id.startsWith("ins_") ? "app" : "agent");
const appliesTo = (g: { callers?: readonly ("agent" | "app")[] }, id: string): boolean => !g.callers || g.callers.includes(callerKind(id));

function toRow(r: Row): ScopeGrantRow {
  const source = r.source === "default" || r.source === "owner" || r.source === "app" ? r.source : undefined;
  return {
    agent: String(r.agent) as AgentId,
    type: String(r.type),
    instanceId: String(r.instance_id),
    access: String(r.access),
    // v0.1.31 (SDK-INSTANCE-GRANT): absent on rows written before 0.1.31 (the writer was not stored)
    ...(source ? { source } : {}),
    ...(source === "app" && typeof r.granted_by_op === "string" ? { grantedByOp: r.granted_by_op } : {}),
  };
}
function toInstance(r: Row): ScopeInstance {
  return { type: String(r.type), id: String(r.id), label: String(r.label), shared: Number(r.shared) === 1 };
}

export interface ScopeStoreInternals extends ScopeStore {
  /** CRUD set of an access level (manifest `access[].crud`); [] for unknown levels. */
  crudOf(type: string, level: string): CrudAction[];
  /** Monotonic counter reported as `AppStatus.scopesRev`. */
  rev(): number;
  /** Resolved access for a call: the targeted instance, or the best access when the op spans instances. */
  resolve(caller: string, type: string, instanceId: string | null): { level: string; crud: CrudAction[]; id: string | null } | null;
  /** ScopeAccessView for an agent/app caller (person callers see everything). */
  view(caller: string | null, access: ScopeAccessView["access"]): ScopeAccessView;
  /** Applies defaults for a caller that has no slice entry (companion app callers). */
  applyDefaultsFor(caller: string, name: string): void;
  /** v0.1.31: the highest access level the manifest gives AGENTS by default for `type` (see ScopeGrantOps); null = none. */
  agentCeiling(type: string): string | null;
}

/**
 * v0.1.31 (SDK-INSTANCE-GRANT): the write paths behind `ctx.scopeGrants` / `ctx.scopeSelfRevoke`. Deliberately NOT members
 * of the store object (Start/Event contexts hand the store itself to app code): they are reached only through
 * `scopeGrantOps(store)`, called by the person-op / agent-op context builders in ops.ts.
 */
export interface ScopeGrantOps {
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

export function createScopeStore(db: RawDb, manifest: Manifest, audit: AuditLog, onChange: () => void): ScopeStoreInternals {
  const scopes = new Map<string, Scope>((manifest.scopes ?? []).map((s) => [s.type, s]));
  const scopeOf = (type: string): Scope => {
    const s = scopes.get(type);
    if (!s) throw new TbError("scope_type_unknown", `scope type not declared: ${type}`, 400);
    return s;
  };
  const crudOf = (type: string, level: string): CrudAction[] => [...(scopes.get(type)?.access.find((a) => a.id === level)?.crud ?? [])];
  const bump = () => {
    metaSet(db, "scopes_rev", (metaGet<number>(db, "scopes_rev") ?? 0) + 1);
    onChange();
  };
  const rank = (type: string, level: string): number => {
    const s = scopes.get(type);
    const i = s?.access.findIndex((a) => a.id === level) ?? -1;
    return crudOf(type, level).length * 1000 + i;
  };
  const rowsOf = (caller: string, type: string): ScopeGrantRow[] =>
    (db.prepare("SELECT * FROM tb_scopes WHERE agent = ? AND type = ?").all(caller, type) as Row[]).map(toRow);
  const bestOf = (caller: string, type: string): ScopeGrantRow | null =>
    rowsOf(caller, type).reduce<ScopeGrantRow | null>((b, r) => (b === null || rank(type, r.access) > rank(type, b.access) ? r : b), null);
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
   * v0.1.13 (Kanban QA S2): an instance that BECOMES shared (created shared, or switched from not shared) gets the
   * `shared` default grant for every caller whose defaults were already applied (the directory seen so far); callers
   * seen later get it on first sight as before. INSERT OR IGNORE: an existing row (an owner edit) always wins.
   */
  const shareWithSeen = (s: Scope, id: string): boolean => {
    const shared = s.defaultGrants.filter((x) => x.kind === "shared");
    if (shared.length === 0) return false;
    const seen = (db.prepare("SELECT agent FROM tb_scope_defaults WHERE type = ?").all(s.type) as Row[]).map((r) => String(r.agent));
    let n = 0;
    const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access, source) VALUES (?, ?, ?, ?, 'default')");
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
        const grant = db.prepare("INSERT OR IGNORE INTO tb_scopes (agent, type, instance_id, access, source) VALUES (?, ?, ?, ?, 'default')");
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
    async set(principal: PersonPrincipal, agent, type, instanceId, access) {
      if (principal?.type !== "person") throw new TbError("session_required", "only the owner can set scope access", 403);
      const s = scopeOf(type);
      if (access !== null && !s.access.some((a) => a.id === access)) throw new TbError("access_level_unknown", `access level not declared: ${access}`, 400);
      if (!db.prepare("SELECT 1 FROM tb_scope_instances WHERE type = ? AND id = ?").get(type, instanceId))
        throw new TbError("scope_instance_unknown", "scope instance does not exist", 404);
      if (access === null) db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
      else
        db.prepare(
          `INSERT INTO tb_scopes (agent, type, instance_id, access, source, granted_by_op) VALUES (?, ?, ?, ?, 'owner', NULL)
           ON CONFLICT (agent, type, instance_id) DO UPDATE SET access = excluded.access, source = 'owner', granted_by_op = NULL`,
        ).run(agent, type, instanceId, access);
      await audit.record({ actor: principal.id, action: "scope.set", target: agent, detail: { type, instance: instanceId, access } });
      bump();
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
    rev: () => metaGet<number>(db, "scopes_rev") ?? 0,
    resolve(caller, type, instanceId) {
      const row = instanceId === null ? bestOf(caller, type) : accessOf(caller, type, instanceId);
      return row ? { level: row.access, crud: crudOf(type, row.access), id: instanceId } : null;
    },
    view(caller, access) {
      const ids = async (type: string, want: (c: CrudAction[]) => boolean): Promise<string[]> => {
        scopeOf(type);
        if (caller === null) return (await store.instances.list(type)).map((i) => i.id);
        return rowsOf(caller, type)
          .filter((r) => want(crudOf(type, r.access)))
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
          return row !== null && crudOf(type, row.access).includes(crud);
        },
      };
    },
    applyDefaultsFor,
  };
  const ops: ScopeGrantOps = {
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
      db.prepare(
        `INSERT INTO tb_scopes (agent, type, instance_id, access, source, granted_by_op) VALUES (?, ?, ?, ?, 'app', ?)
         ON CONFLICT (agent, type, instance_id) DO UPDATE SET access = excluded.access, source = 'app', granted_by_op = excluded.granted_by_op`,
      ).run(agent, type, instanceId, access, by.op);
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
      const r = db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
      if (Number(r.changes ?? 0) === 0) return;
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
      const r = db.prepare("DELETE FROM tb_scopes WHERE agent = ? AND type = ? AND instance_id = ?").run(agent, type, instanceId);
      if (Number(r.changes ?? 0) === 0) return;
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
