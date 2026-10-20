// React bindings (SDK-API §14, types/sdk.ts §C): <TbProvider product> + hooks over the client store. React is an
// optional peer dependency; plain createElement, no JSX build step. No UI components (AppShell is @opt2-tealbrick/ui).
import type { AgentId, Ulid } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction } from "@opt2-tealbrick/spec/manifest";
import type { Receipt, ScopeGrantRow, SliceAgent, TbProviderProps, UseAgents, UseHolds, UseScopes, UseSession } from "@opt2-tealbrick/spec/sdk";
import React from "react";
import { setProduct } from "./fetch.ts";
import { type AgentWithAccess, acceptOffer as acceptScopeOffer, decideHold, getSessionSnapshot, type HoldFilter, listAgents, listHolds, loadSession, scopeRows, setScope, signOut, subscribeSession } from "./store.ts";

const ProductContext = React.createContext<string | null>(null);

function useProduct(): string {
  const p = React.useContext(ProductContext);
  if (p === null) throw new Error("tealbrick client hooks need <TbProvider product>");
  return p;
}

/** Context for session, CSRF and the base path `/a/<product>/`; loads the session once mounted. */
export function TbProvider(props: TbProviderProps): React.ReactElement {
  setProduct(props.product); // idempotent; must hold before any child effect calls tbFetch
  React.useEffect(() => {
    loadSession().catch(() => {});
  }, []);
  return React.createElement(ProductContext.Provider, { value: props.product }, props.children as React.ReactNode);
}

export function useSession(): UseSession {
  useProduct();
  const s = React.useSyncExternalStore(subscribeSession, getSessionSnapshot, getSessionSnapshot);
  return { principal: s.principal, status: s.status, signOut };
}

/** Loads with `load` on mount and whenever `key` changes; `reload` re-runs it. Load errors keep the last data. */
function useLoaded<T>(load: () => Promise<T>, initial: T, key: string): { data: T; loading: boolean; reload: () => Promise<void> } {
  const [data, setData] = React.useState<T>(initial);
  const [loading, setLoading] = React.useState(true);
  const loadRef = React.useRef(load);
  loadRef.current = load;
  const reload = React.useCallback(async () => {
    setLoading(true);
    try {
      setData(await loadRef.current());
    } finally {
      setLoading(false);
    }
  }, []);
  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` is the reload trigger
  React.useEffect(() => {
    reload().catch(() => {});
  }, [key, reload]);
  return { data, loading, reload };
}

const NO_HOLDS: Receipt[] = [];
const NO_AGENTS: AgentWithAccess[] = [];

export function useHolds(filter?: HoldFilter): UseHolds {
  useProduct();
  const status = filter?.status;
  const { data, loading, reload } = useLoaded(() => listHolds(status ? { status } : {}), NO_HOLDS, status ?? "");
  const decide = React.useCallback(
    async (holdId: `hld_${Ulid}`, decision: "approve" | "deny", note?: string) => {
      await decideHold(holdId, decision, note);
      await reload();
    },
    [reload],
  );
  return { holds: data, loading, decide };
}

export function useScopes(agent?: AgentId): UseScopes {
  useProduct();
  const { data, loading, reload } = useLoaded(listAgents, NO_AGENTS, "");
  const access: ScopeGrantRow[] = React.useMemo(() => scopeRows(data, agent), [data, agent]);
  const set = React.useCallback(
    async (a: AgentId, type: string, instanceId: string, level: string | null) => {
      await setScope(a, type, instanceId, level);
      await reload();
    },
    [reload],
  );
  const acceptOffer = React.useCallback(
    async (a: AgentId, type: string, instanceId: string, adds: CrudAction[]) => {
      await acceptScopeOffer(data, a, type, instanceId, adds);
      await reload();
    },
    [data, reload],
  );
  return { access, loading, set, acceptOffer };
}

export function useAgents(): UseAgents {
  useProduct();
  const { data, loading } = useLoaded(listAgents, NO_AGENTS, "");
  const agents: SliceAgent[] = React.useMemo(() => data.map(({ access: _a, ...agent }) => agent), [data]);
  return { agents, loading };
}
