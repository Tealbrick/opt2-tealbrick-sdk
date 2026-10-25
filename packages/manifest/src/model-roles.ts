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

// ── spec follow-up #54 (UNRELEASED, Tealbrick/opt2-tealbrick-specs#54 head dfdbef2): M-MR-4 deny list ──────────────────────────────

/** spec follow-up #54: `HOST_DENIED_ENV` of spec host.ts (code loading, library injection, egress redirection); a trailing `*` is a prefix. */
export const HOST_DENIED_ENV = [
  "NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "LD_*", "DYLD_*", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME",
  "PYTHONUSERBASE", "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",
  "JDK_JAVA_OPTIONS", "CLASSPATH", "BASH_ENV", "ENV", "PATH", "HOME", "SHELL", "IFS", "GCONV_PATH", "OPENSSL_CONF",
  "SSL_CERT_FILE", "SSL_CERT_DIR", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "DOCKER_*", "BUN_*", "DENO_*",
] as const;
/** spec follow-up #54: env names no model role may set (M-MR-4): the host deny list plus TLS trust, CA bundles, package-manager and git config. A trailing `*` is a prefix; any name ending in `_PROXY` is refused too. */
export const MODEL_ROLE_DENIED_ENV = [...HOST_DENIED_ENV, "NODE_TLS_REJECT_UNAUTHORIZED", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "NPM_CONFIG_*", "PYTHON*", "GIT_*"] as const;

/** M-MR-4: true when a role env name is in `MODEL_ROLE_DENIED_ENV` (exact, or by prefix for an entry ending in `*`) or ends in `_PROXY`. */
export function modelRoleEnvDenied(name: string): boolean {
  if (name.endsWith("_PROXY")) return true;
  return MODEL_ROLE_DENIED_ENV.some((d) => (d.endsWith("*") ? name.startsWith(d.slice(0, -1)) : name === d));
}
