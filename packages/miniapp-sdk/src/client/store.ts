// Client state without React: the session store (GET …/tb/v1/session → principal + CSRF; POST …/tb/v1/logout) and
// the standard person ops behind useHolds / useScopes / useAgents (SDK-API §6, §14).
import type { AgentId, Ulid } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction } from "@opt2-tealbrick/spec/manifest";
import type { Json, PersonPrincipal, Receipt, ScopeGrantRow, SessionInfo, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";
import { callOp, setCsrf, setCsrfLoader, setIdempotencyRequired, tbFetch } from "./fetch.ts";

export interface SessionSnapshot {
  principal: PersonPrincipal | null;
  status: "loading" | "signed_in" | "signed_out";
}

type Listener = () => void;

let snapshot: SessionSnapshot = { principal: null, status: "loading" };
let inflight: Promise<SessionSnapshot> | null = null;
const listeners = new Set<Listener>();

function publish(next: SessionSnapshot): void {
  snapshot = next;
  for (const l of [...listeners]) l();
}

export function getSessionSnapshot(): SessionSnapshot {
  return snapshot;
}

export function subscribeSession(l: Listener): () => void {
  listeners.add(l);
  return () => listeners.delete(l);
}

/** Loads the session once at a time; `session_required` → signed_out; other failures throw and keep the state. */
export function loadSession(): Promise<SessionSnapshot> {
  inflight ??= (async () => {
    try {
      const res = await tbFetch("tb/v1/session");
      const s = (await res.json()) as SessionInfo & { idempotencyRequired?: unknown };
      setCsrf(s.csrf);
      setIdempotencyRequired(Array.isArray(s.idempotencyRequired) ? s.idempotencyRequired.filter((o): o is string => typeof o === "string") : []);
      publish({ principal: s.principal, status: "signed_in" });
    } catch (e) {
      if (!(e instanceof TbError) || (e.code !== "session_required" && e.httpStatus !== 401)) throw e;
      setCsrf(null);
      publish({ principal: null, status: "signed_out" });
    } finally {
      inflight = null;
    }
    return snapshot;
  })();
  return inflight;
}

setCsrfLoader(loadSession);

export async function signOut(): Promise<void> {
  try {
    await tbFetch("tb/v1/logout", { method: "POST" });
  } catch (e) {
    if (!(e instanceof TbError) || e.code !== "session_required") throw e;
  }
  setCsrf(null);
  publish({ principal: null, status: "signed_out" });
}

/** Test hook: back to the initial state. */
export function resetClientState(): void {
  setCsrf(null);
  setIdempotencyRequired(null);
  inflight = null;
  snapshot = { principal: null, status: "loading" };
}

// ── standard person ops ─────────────────────────────────────────────────────
const MAX_PAGES = 20;

export type HoldFilter = { status?: "held" | "approved" | "denied" };

/** `tb.holds_list`, all pages (bounded). */
export async function listHolds(filter: HoldFilter = {}): Promise<Receipt[]> {
  const out: Receipt[] = [];
  let cursor: string | null = null;
  for (let i = 0; i < MAX_PAGES; i++) {
    const input: Record<string, Json> = {};
    if (filter.status) input.status = filter.status;
    if (cursor) input.cursor = cursor;
    const page: { items: Receipt[]; nextCursor: string | null } = await callOp("tb.holds_list", input);
    out.push(...page.items);
    cursor = page.nextCursor;
    if (!cursor) break;
  }
  return out;
}

export async function decideHold(holdId: `hld_${Ulid}`, decision: "approve" | "deny", note?: string): Promise<void> {
  await callOp("tb.holds_decide", note === undefined ? { holdId, decision } : { holdId, decision, note });
}

export type AgentWithAccess = SliceAgent & { access: ScopeGrantRow[] };

/** `tb.agents_list`: slice agents with their scope access rows. */
export async function listAgents(): Promise<AgentWithAccess[]> {
  const r: { agents: AgentWithAccess[] } = await callOp("tb.agents_list", {});
  return r.agents;
}

/** Scope access rows of one agent, or of every agent. */
export function scopeRows(agents: readonly AgentWithAccess[], agent?: AgentId): ScopeGrantRow[] {
  return agents.filter((a) => agent === undefined || a.id === agent).flatMap((a) => a.access ?? []);
}

/** `tb.scopes_set` (`access: null` removes the row). */
export async function setScope(agent: AgentId, type: string, instanceId: string, access: string | null): Promise<void> {
  await callOp("tb.scopes_set", { agent, type, id: instanceId, access });
}

/** `tb.scopes_set` with `acceptOffer` (v0.1.52): accept a row's `offer.adds` at the SAME level. Call it only on the owner's click. */
export async function acceptScopeOffer(agent: AgentId, type: string, instanceId: string, level: string, adds: CrudAction[]): Promise<void> {
  await callOp("tb.scopes_set", { agent, type, id: instanceId, access: level, acceptOffer: { adds } });
}
