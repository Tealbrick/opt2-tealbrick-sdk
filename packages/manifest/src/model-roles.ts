// Model roles (MANIFEST §7.1, M-MR-1..5; BRIDGE §15; SDK-API "v0.1.63 additions"). The shapes come from @opt2-tealbrick/spec
// (0.1.63, in 0.1.64) and are re-exported here for the other packages.
import type { ModelRoleFetchResponse } from "@opt2-tealbrick/spec/bridge";
import { BRIDGE_INTERNAL_PATHS } from "@opt2-tealbrick/spec/bridge";
import type { Manifest, ModelRoleRequirement } from "@opt2-tealbrick/spec/manifest";
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

/**
 * M-MR-4 (QA S4-3): env names a model role must not set, because they change how the service connects or loads code: any `*_PROXY`
 * (a proxy resolves the endpoint itself), `npm_config_*proxy`, `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`,
 * `PATH`, `DYLD_*`. `tb-exec` also strips proxy names from the env of a role-bound service.
 */
export const MODEL_ROLE_ENV_REFUSED = /_proxy$|^proxy$|^npm_config_.*proxy$|^(NODE_OPTIONS|NODE_EXTRA_CA_CERTS|LD_PRELOAD|LD_LIBRARY_PATH|PATH)$|^DYLD_/i;
