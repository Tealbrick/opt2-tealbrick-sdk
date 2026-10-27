// SDK major rule (CORE §11, C35 item 6, C44): the SDK ships as 0.x during opt2; 0.x counts as major 1 until SDK 1.0.

/** Major of an SDK semver string; `0.x.y` → 1. Throws on a non-semver input. */
export function sdkMajorOf(version: string): number {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:[-+][0-9A-Za-z.+-]*)?$/.exec(version);
  if (!m) throw new TypeError(`sdkMajorOf: not a semver version: ${JSON.stringify(version)}`);
  const major = Number(m[1]);
  return major === 0 ? 1 : major;
}

/** Bridge/Core rule: the current major and the one before are served (CORE §11). */
export function sdkMajorServed(version: string, currentMajor: number): boolean {
  const major = sdkMajorOf(version);
  return major === currentMajor || major === currentMajor - 1;
}

/** Semver core compare (pre-release tags sort before the release); throws on a non-semver input. */
export function compareSemver(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$/.exec(v);
    if (!m) throw new TypeError(`compareSemver: not a semver version: ${JSON.stringify(v)}`);
    return { n: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null };
  };
  const x = parse(a);
  const y = parse(b);
  for (let i = 0; i < 3; i++) if ((x.n[i] as number) !== (y.n[i] as number)) return (x.n[i] as number) < (y.n[i] as number) ? -1 : 1;
  if (x.pre === y.pre) return 0;
  if (x.pre === null) return 1;
  if (y.pre === null) return -1;
  return x.pre < y.pre ? -1 : 1;
}

/**
 * C104 (spec 0.1.15): THE feature table of minimum bridge versions. Extend it with every bridge feature an app can depend on;
 * the release signer and Core read only `requiredBridgeVersion`, never their own copy (L1).
 */
export const BRIDGE_FEATURES = [
  { feature: "dynamic_ops", minBridge: "0.1.15", why: "dynamic tool search needs the C91 catalog proof binding" },
  { feature: "wildcard_companion", minBridge: "0.1.16", why: "companion product \"*\" (tb.holds_pending, C82)" },
  { feature: "holds_pending_companion", minBridge: "0.1.16", why: "tb.holds_pending as a companion op (G4)" },
  // v0.1.30 (spec 0.1.57, MANIFEST §16.3): a manifest with `events` (also an empty list: an older validator refuses the key) needs
  // a bridge that pins manifest >= 0.1.30 and declares the `events` cap; bridge 0.2.7 is the first
  { feature: "events", minBridge: "0.2.7", why: "app events (C274)" },
  // v0.1.33 (spec 0.1.82, C373 P1): a manifest with `companions[].perWorkflow` asks for per-workflow grants: the bridge must relay
  // workflow_grant_* and gate CallEnvelope.workflow (cap app_workflow_grants). TEMP until spec 0.1.82 pin: the bridge release that
  // contains BRIDGE §8.6 (bridge P1 follows 0.2.11 = P3/P4); re-check against the spec's number at the pin.
  { feature: "per_workflow_grants", minBridge: "0.2.12", why: "per-workflow companion grants (companions[].perWorkflow, C373)" },
  // C111a: op-limited Free grants (wf + caps) need the Free-wf gate (bridge 0.1.19 = manifest 0.1.12). A grant property, not a
  // manifest feature: Core checks it per workspace bridge before minting such grants (MIN_BRIDGE_FREE_WF).
] as const;

type ManifestLike = {
  operations?: readonly { dynamic?: unknown }[];
  companions?: readonly { product: string; operations: readonly string[]; perWorkflow?: unknown }[];
  requires?: { bridge?: string };
  events?: readonly unknown[];
};

/**
 * C104: minimum workspace bridge version for a manifest = max(declared `requires.bridge`, every BRIDGE_FEATURES row the
 * manifest uses), with the reasons; `bridge: null` when nothing is required.
 */
export function requiredBridgeVersion(m: ManifestLike): { bridge: string | null; reasons: string[] } {
  const used = new Set<string>();
  if ((m.operations ?? []).some((o) => o.dynamic !== undefined)) used.add("dynamic_ops");
  for (const c of m.companions ?? []) {
    if (c.product === "*") used.add("wildcard_companion");
    if (c.operations.includes("tb.holds_pending")) used.add("holds_pending_companion");
    if (c.perWorkflow !== undefined) used.add("per_workflow_grants");
  }
  if (m.events !== undefined) used.add("events");
  let bridge: string | null = null;
  const reasons: string[] = [];
  const bump = (v: string, why: string) => {
    reasons.push(`${v}: ${why}`);
    if (bridge === null || compareSemver(v, bridge) > 0) bridge = v;
  };
  for (const f of BRIDGE_FEATURES) if (used.has(f.feature)) bump(f.minBridge, f.why);
  const declared = m.requires?.bridge;
  if (typeof declared === "string") bump(declared, "declared by the manifest (requires.bridge)");
  return { bridge, reasons };
}

/** C111a (spec 0.1.20 cutover rule): the first bridge that enforces a non-empty `wf` on Free grants. */
export const MIN_BRIDGE_FREE_WF = "0.1.19";
/** C111a: the first miniapp-sdk whose authorize() pairs with op-limited Free grants (caps in any mode, C108 tolerant held). */
export const MIN_SDK_FREE_WF = "0.1.16";
