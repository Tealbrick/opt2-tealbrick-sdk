// Model roles (MANIFEST §7.1, M-MR-1..5; BRIDGE §15; SDK-API "v0.1.63 additions"). The released shapes come from
// @opt2-tealbrick/spec 0.1.63 and are re-exported here for the other packages. What is declared below is a MIRROR of the
// spec follow-up #49 (Tealbrick/opt2-tealbrick-specs#49, not released): replace each marked block with the import after that
// spec release.
import type { ModelRoleFetchResponse } from "@opt2-tealbrick/spec/bridge";
import { BRIDGE_INTERNAL_PATHS } from "@opt2-tealbrick/spec/bridge";
import type { Manifest, ModelRoleRequirement } from "@opt2-tealbrick/spec/manifest";
import type { ModelRole } from "@opt2-tealbrick/spec/models";
import type { ResolvedModelRole } from "@opt2-tealbrick/spec/sdk";

export type { ModelProvider, ModelRole } from "@opt2-tealbrick/spec/models";
export {
  DATA_POLICIES,
  DATA_POLICY_RANK,
  type DataPolicy,
  MODEL_ID_PATTERN,
  MODEL_PROVIDERS,
  MODEL_ROLE_ATTENTION,
  MODEL_ROLE_HINTS_MAX,
  MODEL_ROLES,
  PROVIDER_ID_PATTERN,
} from "@opt2-tealbrick/spec/models";
export type { ModelRoleFetchResponse, ModelRoleRequirement, ResolvedModelRole };

/** `BRIDGE_INTERNAL_PATHS.modelRoles` (BRIDGE §15.4). */
export const MODEL_ROLES_PATH = BRIDGE_INTERNAL_PATHS.modelRoles;
/** Bridge capability (`BRIDGE_CAPS` = owner_rows, events, model_roles): the bridge implements BRIDGE §15 in full. A bridge without it has no model-roles route: 404 without a refuse code. */
export const MODEL_ROLES_CAP = "model_roles" as const;

/** Env names `tb-exec` fills for a service from a resolved binding (M-MR-4). */
export type ModelRoleEnv = NonNullable<ModelRoleRequirement["env"]>;
/** The env fields in the order tb-exec sets them. */
export const MODEL_ROLE_ENV_FIELDS = ["provider", "model", "baseUrl", "key", "dims"] as const satisfies readonly (keyof ModelRoleEnv)[];

/** The model roles a manifest declares (`settings.modelRoles`). */
export function declaredModelRoles(manifest: Manifest): readonly ModelRoleRequirement[] {
  return manifest.settings?.modelRoles ?? [];
}

// ── spec follow-up #49 (not released): mirror ────────────────────────────────

/** spec follow-up #49 (QA-SPEC49): providers that route to other upstreams (OpenRouter, LiteLLM, a custom address): a `zdr` attestation names the host. */
export const MODEL_GATEWAYS = ["openrouter", "litellm", "openai-compatible"] as const;
/** spec follow-up #49: max origins in the owner's "Own hosts" list. */
export const OWN_HOSTS_MAX = 32;
/**
 * spec follow-up #49 (BRIDGE §15.3 step 3): never local, even when the owner lists them: link-local, cloud metadata (AWS IPv6,
 * Alibaba, Oracle, Azure wireserver), "this network", unspecified.
 */
export const NEVER_LOCAL = ["169.254.0.0/16", "fe80::/10", "fd00:ec2::254/128", "100.100.100.200/32", "192.0.0.192/32", "168.63.129.16/32", "0.0.0.0/8", "::/128"] as const;
/** spec follow-up #49: metadata host names that are never local, even when listed. */
export const NEVER_LOCAL_HOSTNAMES = ["metadata.google.internal", "metadata.goog", "metadata"] as const;
/** spec follow-up #49 (BRIDGE §15.3/§15.5): why a binding has its data policy: `verified` = the bridge checked the URL; `owner_attested` = the owner said so. */
export const POLICY_BASES = ["verified", "owner_attested"] as const;
export type PolicyBasis = (typeof POLICY_BASES)[number];

/** spec follow-up #49 (SDK-API "modelFetch"): `TbError.code` values the model-role helpers throw. */
export const SDK_MODEL_ERROR_CODES = ["role_undeclared", "model_endpoint_refused"] as const;
export type SdkModelErrorCode = (typeof SDK_MODEL_ERROR_CODES)[number];

/** What `modelFetch(role)` returns: the binding and a `fetch` bound to its canonical base URL origin (spec follow-up #49, SDK-API). */
export interface ModelFetchHandle {
  binding: ResolvedModelRole;
  fetch: (path: string, init?: RequestInit) => Promise<Response>;
}

/**
 * spec follow-up #49 (QA-SPEC49-2c): `modelFetch(role)` on the contexts spec 0.1.63 gives `modelRole` (`OpContext`, `StartContext`,
 * `HookContext`, `KeyApi`). Declared here because the pinned spec lacks it; the declaration merges away when the spec has it.
 */
declare module "@opt2-tealbrick/spec/sdk" {
  interface OpContext {
    modelFetch(role: ModelRole): Promise<ModelFetchHandle | null>;
  }
  interface StartContext {
    modelFetch(role: ModelRole): Promise<ModelFetchHandle | null>;
  }
  interface HookContext {
    modelFetch(role: ModelRole): Promise<ModelFetchHandle | null>;
  }
  interface KeyApi {
    modelFetch(role: ModelRole): Promise<ModelFetchHandle | null>;
  }
}
