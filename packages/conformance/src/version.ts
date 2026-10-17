// Version gates of the version-dependent checks (the target reports its release in the claim / enrolment).

/**
 * True when the release `v` (as the target reported it) is below `min` (both `x.y.z`; a pre-release suffix is ignored).
 * An unreadable or missing version is NOT below: the check then runs and fails visibly instead of hiding.
 */
export function versionBelow(v: string | null | undefined, min: string): boolean {
  const num = (x: string) => /^(\d+)\.(\d+)\.(\d+)/.exec(x)?.slice(1, 4).map(Number);
  const a = v == null ? undefined : num(v);
  const b = num(min);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) if ((a[i] as number) !== (b[i] as number)) return (a[i] as number) < (b[i] as number);
  return false;
}
