// Manifest checks M1–M6 (CONFORMANCE §4.1). M1/M2 run the ONE validator (`validateManifest`) and re-assert the key
// cross-field rules independently, then prove the validator enforces them with mutated copies (sensitivity). M3
// recomputes the digest several ways. M4 scans for hand-written generator outputs beside the manifest. M5 looks for
// product ids taken from manifests as literals in source trees: in JS/TS files only code literals count (comments are
// stripped by `codeLiterals`); other files are matched on their raw text. This package's own tree is never scanned.
// M6 (v0.1.11 (C70)): path bases (MANIFEST §3): build paths resolve from the repo root, skill files from the manifest dir.
import { readdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname, extname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { digest, HOLDS_PENDING_OP, KNOWN_HOLD_FAMILIES, manifestDigest, mcpToolName, toolNameFits, validateAppFiles, validateManifest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { codeLiterals, literalNamesId } from "../code-literals.ts";
import type { CheckResult } from "../report.ts";
import { bad, na, notRun, ok, Suite, verdict } from "../suite.ts";

export interface ManifestCheckOptions {
  /** path of the manifest file (M4 scans its directory) */
  manifestPath?: string;
  /** source trees for M5 (default: none → M5 not_run) */
  scanDirs?: string[];
  /** extra product ids for M5 (e.g. ids from the spec examples) */
  extraProductIds?: string[];
  /** expected digest (e.g. the one in a release record) */
  expectDigest?: string;
  /**
   * repository root for M6 (build paths are repo-relative, MANIFEST §3). Skill files resolve from the directory of
   * `manifestPath` (default: `repoDir`). Without it M6 is not_applicable.
   */
  repoDir?: string;
  /** when set and no scanDirs are given, M5 reports not_applicable with this reason (app target) */
  m5NotApplicable?: string;
}

function isKind(path: string, dir: boolean): boolean {
  try {
    const st = statSync(path);
    return dir ? st.isDirectory() : st.isFile();
  } catch {
    return false;
  }
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const codes = (r: ReturnType<typeof validateManifest>) => (r.ok ? [] : r.errors.map((e) => e.code));

function shuffleKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>).reverse();
    return Object.fromEntries(entries.map(([k, x]) => [k, shuffleKeys(x)]));
  }
  return v;
}

/** Synthetic agent op appended to a copy of the manifest for the sensitivity probes. */
function probeOp(over: Record<string, unknown>): Record<string, unknown> {
  return {
    id: "conformance_probe",
    title: "Probe",
    description: "Conformance probe operation.",
    input: { type: "object", properties: {} },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
    ...over,
  };
}

const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".go", ".py", ".rs"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "test", "tests", "fixtures", "examples", "__tests__", "coverage"]);
/** JS/TS files: M5 matches code literals only (no comments). */
const CODE_EXT = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"]);
/** This package's root (src/checks/ or dist/checks/ → ../../): the checker's own source and install tree. */
const OWN_ROOT = realpathSync(fileURLToPath(new URL("../../", import.meta.url))).replace(/[\\/]+$/, "");

/** True for this package's own tree (source, dist or an install of it): the checker never scans itself. */
export function isOwnTree(dir: string): boolean {
  let real: string;
  try {
    real = realpathSync(dir);
  } catch {
    return false;
  }
  return real === OWN_ROOT || real.startsWith(OWN_ROOT + sep);
}

function* sourceFiles(dir: string): Generator<string> {
  if (isOwnTree(dir)) return;
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const n of names) {
    const p = join(dir, n);
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(n)) yield* sourceFiles(p);
    } else if (SOURCE_EXT.has(extname(n)) && !n.includes(".test.") && st.size < 4 * 1024 * 1024) yield p;
  }
}

/**
 * M5: product ids appearing as literals (the whole literal, or a `/`-delimited path segment of it) in source trees.
 * JS/TS files: string, template and regex literals of the code only — a comment naming a product is not a hit.
 * Other files (.json, .go, .py, .rs): quote- or slash-delimited on the raw text. This package's tree is skipped.
 */
export function findProductLiterals(dirs: readonly string[], productIds: readonly string[]): string[] {
  const hits: string[] = [];
  const res = productIds.map((id) => ({ id, re: new RegExp(`["'\`/]${id.replace(/[-]/g, "\\-")}["'\`/]`) }));
  for (const d of dirs) {
    for (const f of sourceFiles(d)) {
      const text = readFileSync(f, "utf8");
      const literals = CODE_EXT.has(extname(f)) ? codeLiterals(text) : null;
      for (const { id, re } of res) if (literals ? literals.some((l) => literalNamesId(l, id)) : re.test(text)) hits.push(`${f}: "${id}"`);
    }
  }
  return hits;
}

export async function runManifestChecks(json: unknown, opts: ManifestCheckOptions = {}): Promise<{ results: CheckResult[]; manifest: Manifest | null; notes: string[] }> {
  const s = new Suite();
  /** report notes (none since 0.1.12: M2.outward_family fails instead of warning) */
  const notes: string[] = [];
  const v = validateManifest(json);
  const m = v.ok ? v.manifest : null;

  // ── M1 schema ──
  await s.run("M1", "manifest schema valid (tealbrick.miniapp/2, strict)", "validateManifest ok, schema tealbrick.miniapp/2", () =>
    v.ok ? ok(`valid; schema ${v.manifest.schema}`) : bad(`${v.errors.length} errors: ${v.errors.slice(0, 5).map((e) => `${e.path} ${e.code}`).join("; ")}`),
  );
  await s.run("M1.strict_unknown_key", "unknown top-level key rejected", "validateManifest refuses an extra key", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), conformanceUnknownKey: true });
    return verdict(!r.ok, r.ok ? "accepted" : `refused: ${codes(r).join(",")}`);
  });
  await s.run("M1.reserved_prefix", "tb_ operation ids reserved", "an op id starting tb_ is refused", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ id: "tb_conformance" })] });
    return verdict(!r.ok, r.ok ? "accepted" : `refused: ${codes(r).join(",")}`);
  });

  // ── M2 cross-field rules: independent re-assertion + validator sensitivity ──
  await s.run("M2.create_idempotency", "create ⇒ idempotency required (M-OP-5)", "every op with create in crud has idempotency required", () => {
    if (!m) return bad("manifest invalid");
    const off = m.operations.filter((o) => o.crud.includes("create") && o.idempotency !== "required").map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : `${m.operations.filter((o) => o.crud.includes("create")).length} create ops, all required`);
  });
  await s.run("M2.create_idempotency.enforced", "validator enforces M-OP-5", "validateManifest refuses create + idempotency supported (idempotency_invalid)", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ crud: ["create"], effect: "write", idempotency: "supported", receipt: true })] });
    return verdict(codes(r).includes("idempotency_invalid"), r.ok ? "accepted" : codes(r).join(","));
  });
  await s.run("M2.scope_types", "scopeType declared (M-OP-7)", "every op scopeType names a declared scope whose access covers op.crud", () => {
    if (!m) return bad("manifest invalid");
    const off = m.operations
      .filter((o) => o.scopeType !== undefined)
      .filter((o) => {
        const sc = m.scopes?.find((x) => x.type === o.scopeType);
        const union = new Set(sc?.access.flatMap((a) => a.crud) ?? []);
        return !sc || !o.crud.every((c) => union.has(c));
      })
      .map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : "all scoped ops reference declared scopes");
  });
  await s.run("M2.scope_types.enforced", "validator enforces M-OP-7", "validateManifest refuses an undeclared scopeType (scope_ref_invalid)", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ scopeType: "conformance_undeclared" })] });
    return verdict(codes(r).includes("scope_ref_invalid"), r.ok ? "accepted" : codes(r).join(","));
  });
  await s.run("M2.money_held", "money effect ⇒ holdFamily money + receipt (M-OP-4/6)", "money ops declare holdFamily money and receipt true", () => {
    if (!m) return bad("manifest invalid");
    const money = m.operations.filter((o) => o.effect === "money");
    if (money.length === 0) return na("no money op declared");
    const off = money.filter((o) => o.holdFamily !== "money" || !o.receipt).map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : `${money.length} money ops ok`);
  });
  // C105 (spec 0.1.15): the families an op may declare are the spec vocabulary KNOWN_HOLD_FAMILIES (imported, L1);
  // `policy` (hook verdicts only) and `caps` (Free-card caps) are never op families. Asserted on the raw JSON so an
  // invalid manifest still names the offending ops.
  const rawOps = (): Record<string, unknown>[] => {
    const ops = (json as { operations?: unknown } | null)?.operations;
    return Array.isArray(ops) ? ops.filter((o): o is Record<string, unknown> => !!o && typeof o === "object" && !Array.isArray(o)) : [];
  };
  const known = new Set<string>(KNOWN_HOLD_FAMILIES);
  await s.run("M2.hold_family_known", "op holdFamily ∈ KNOWN_HOLD_FAMILIES (C105)", `every op holdFamily is one of ${KNOWN_HOLD_FAMILIES.join("|")} (never policy or caps)`, () => {
    const ops = rawOps();
    if (ops.length === 0) return bad("no operations array");
    const declared = ops.filter((o) => o.holdFamily !== undefined);
    const off = declared.filter((o) => typeof o.holdFamily !== "string" || !known.has(o.holdFamily)).map((o) => `${String(o.id)}: ${String(o.holdFamily)}`);
    if (declared.length === 0) return na("no op declares a holdFamily");
    return verdict(off.length === 0, off.length ? `unknown families: ${off.join(", ")}` : `${declared.length} declared families, all known`);
  });
  await s.run("M2.hold_family_known.enforced", "validator enforces the known hold families (C105)", "validateManifest refuses an op with holdFamily policy and one with caps; accepts every known family the op's effect admits", () => {
    if (!m) return bad("manifest invalid");
    const probe = (hf: string, effect = "outward") => validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ crud: [effect === "destructive" ? "delete" : "update"], effect, idempotency: "supported", receipt: true, holdFamily: hf })] });
    const refusedAt = (r: ReturnType<typeof validateManifest>) => !r.ok && r.errors.some((e) => e.path.endsWith("/holdFamily"));
    const policy = probe("policy");
    const caps = probe("caps");
    // M-OP-4: destructive/money have their own family; every other known family is an outward family
    const effectFor = (hf: string) => (hf === "destructive" ? "destructive" : hf === "money" ? "money" : "outward");
    const knownOk = KNOWN_HOLD_FAMILIES.filter((hf) => !probe(hf, effectFor(hf)).ok);
    const show = (r: ReturnType<typeof validateManifest>) => (r.ok ? "accepted" : codes(r).join(","));
    return verdict(refusedAt(policy) && refusedAt(caps) && knownOk.length === 0, `policy: ${show(policy)}; caps: ${show(caps)}; known families refused: ${knownOk.join(",") || "none"}`);
  });
  // C107 (spec 0.1.16): every outward op declares a family. Warn-only in conformance 0.1.11; FAILS from 0.1.12 (spec
  // 0.1.18 SDK sweep). The manifest validator keeps its grace (older releases stay deployable by Core).
  await s.run("M2.outward_family", "outward ops declare a holdFamily (C107)", "every op with effect outward declares a holdFamily (fails since conformance 0.1.12; the manifest validator still accepts a missing one)", () => {
    const outward = rawOps().filter((o) => o.effect === "outward");
    if (outward.length === 0) return na("no outward op declared");
    const off = outward.filter((o) => o.holdFamily === undefined).map((o) => `${String(o.id)} (${String(o.audience)})`);
    if (off.length === 0) return ok(`${outward.length} outward ops, all declare a family`);
    return bad(`${off.length} of ${outward.length} outward ops declare no holdFamily: ${off.join(", ")}`);
  });
  await s.run("M2.tool_names", "MCP tool names ≤ 64 chars (M-OP-1, CORE I9)", "every <product>__<op> fits ^[a-z0-9_-]+$ and ≤ 64", () => {
    if (!m) return bad("manifest invalid");
    const names = m.operations.filter((o) => o.audience === "agent").map((o) => mcpToolName(m.id, o.id));
    const off = names.filter((n) => !toolNameFits(n));
    return verdict(off.length === 0, off.length ? `too long/invalid: ${off.join(",")}` : `${names.length} names fit (longest ${Math.max(0, ...names.map((n) => n.length))})`);
  });
  await s.run("M2.key_names_unique", "settings/key names unique (M-ST-1)", "no duplicate step id, field key or key name", () => {
    if (!m) return bad("manifest invalid");
    const keys = [...(m.settings?.steps.flatMap((st) => st.fields.map((f) => `field:${f.key}`)) ?? []), ...(m.settings?.keys?.map((k) => `key:${k.name}`) ?? [])];
    const dup = keys.filter((k, i) => keys.indexOf(k) !== i);
    return verdict(dup.length === 0, dup.length ? `duplicates: ${dup.join(",")}` : `${keys.length} names unique`);
  });
  await s.run("M2.hook_ops", "hooks reference real ops (M-HK-3)", "own-product hook match.operations exist with audience agent; foreign hooks are checked by Core", () => {
    if (!m) return bad("manifest invalid");
    const hooks = m.hooks ?? [];
    const own = hooks.filter((h) => h.match.products.length === 1 && h.match.products[0] === m.id);
    const foreign = hooks.length - own.length;
    if (own.length === 0) return na(`no own-product hook declared (own 0, foreign ${foreign}: checked by Core at chain resolution (M-HK-3))`);
    const agentOps = new Set(m.operations.filter((o) => o.audience === "agent").map((o) => o.id));
    const off = own.filter((h) => (h.match.operations ?? []).some((o) => !agentOps.has(o))).map((h) => h.id);
    const counts = `own ${own.length} (ops checked), foreign ${foreign}: checked by Core at chain resolution (M-HK-3)`;
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}; ${counts}` : counts);
  });
  // M-CP-3 (v0.1.13, G4/C82): the wildcard companion ("*") names exactly tb.holds_pending with crud [read]; no other
  // standard op may be a companion op (the schema refuses the others' names; the validator owns the wildcard shape)
  await s.run("M2.companion_wildcard", "wildcard companion is only tb.holds_pending / read (M-CP-3)", "a companion with product \"*\" has operations [tb.holds_pending] and crud [read]; tb.holds_pending is the only tb.* companion op", () => {
    if (!m) return bad("manifest invalid");
    const comps = m.companions ?? [];
    if (comps.length === 0) return na("no companions declared");
    const off: string[] = [];
    for (const c of comps) {
      const std = c.operations.filter((o) => o.startsWith("tb."));
      if (std.some((o) => o !== HOLDS_PENDING_OP)) off.push(`${c.product}: standard op ${std.join(",")}`);
      if (c.product === "*" && (c.operations.length !== 1 || c.operations[0] !== HOLDS_PENDING_OP || c.crud.length !== 1 || c.crud[0] !== "read")) off.push(`*: operations ${c.operations.join(",")} crud ${c.crud.join(",")}`);
    }
    const wild = comps.filter((c) => c.product === "*").length;
    return verdict(off.length === 0, off.length ? `violations: ${off.join("; ")}` : `${comps.length} companions (${wild} wildcard) ok`);
  });
  await s.run("M2.companion_wildcard.enforced", "validator enforces M-CP-3", "validateManifest refuses a wildcard companion naming another op, or with crud beyond read (companion_invalid, rule M-CP-3); accepts the valid wildcard", () => {
    if (!m) return bad("manifest invalid");
    const withComp = (c: Record<string, unknown>) => validateManifest({ ...clone(m), companions: [...clone(m.companions ?? []).filter((x) => x.product !== "*"), c] });
    const purpose = "Conformance probe of the wildcard companion rule";
    const own = m.operations.find((o) => o.audience === "agent")?.id ?? "conformance_probe";
    const cpRule = (r: ReturnType<typeof validateManifest>) => !r.ok && r.errors.some((e) => e.rule === "M-CP-3" && e.code === "companion_invalid");
    const otherOp = withComp({ product: "*", operations: [own], crud: ["read"], purpose });
    const wideCrud = withComp({ product: "*", operations: [HOLDS_PENDING_OP], crud: ["read", "update"], purpose });
    const valid = withComp({ product: "*", operations: [HOLDS_PENDING_OP], crud: ["read"], purpose });
    const show = (r: ReturnType<typeof validateManifest>) => (r.ok ? "accepted" : codes(r).join(","));
    return verdict(cpRule(otherOp) && cpRule(wideCrud) && valid.ok, `other op: ${show(otherOp)}; crud read+update: ${show(wideCrud)}; valid wildcard: ${show(valid)}`);
  });
  await s.run("M2.when_settings", "`when` references declared settings (M-ST-3)", "every when key names an enum/boolean field", () => {
    if (!m) return bad("manifest invalid");
    const fields = new Map((m.settings?.steps ?? []).flatMap((st) => st.fields.map((f) => [f.key, f.type] as const)));
    const whens = [
      ...(m.settings?.steps ?? []).flatMap((st) => [st.when, ...st.fields.map((f) => f.when)]),
      ...(m.settings?.keys ?? []).map((k) => k.when),
      ...(m.runtime.services ?? []).map((x) => x.when),
      ...(m.skills ?? []).map((x) => x.when),
    ].filter((w) => w !== undefined);
    if (whens.length === 0) return na("no when conditions declared");
    const off = whens.flatMap((w) => Object.keys(w)).filter((k) => fields.get(k) !== "enum" && fields.get(k) !== "boolean");
    return verdict(off.length === 0, off.length ? `unknown/invalid: ${off.join(",")}` : `${whens.length} conditions ok`);
  });

  // ── M-EV app events (conformance 0.1.28, spec 0.1.57, MANIFEST §16): the manifest's own events re-asserted, then the ONE
  // validator must refuse a mutated copy with the rule's code (a probe agent op + a probe event are added to the copy) ──
  const events = (): Record<string, unknown>[] => {
    const e = (json as { events?: unknown } | null)?.events;
    return Array.isArray(e) ? e.filter((x): x is Record<string, unknown> => !!x && typeof x === "object" && !Array.isArray(x)) : [];
  };
  const probeEvent = (over: Record<string, unknown> = {}) => ({
    name: "conformance.probe",
    title: "Conformance probe event",
    payloadSchema: { type: "object", additionalProperties: false, properties: { id: { type: "string" } } },
    visibleWith: "conformance_probe",
    audience: "granted",
    ...over,
  });
  const withProbeEvents = (evs: Record<string, unknown>[], over: Record<string, unknown> = {}) =>
    validateManifest({ ...clone(m), ...over, operations: [...clone((m as Manifest).operations), probeOp({})], events: evs });
  const evRefused = (r: ReturnType<typeof validateManifest>, rule: string, code: string) => !r.ok && r.errors.some((e) => e.rule === rule && e.code === code);
  const evShow = (r: ReturnType<typeof validateManifest>) => (r.ok ? "accepted" : [...new Set(r.errors.map((e) => `${e.rule}/${e.code}`))].join(","));
  const evOwn = (check: (e: Record<string, unknown>, i: number) => string | null): string[] =>
    events()
      .map((e, i) => check(e, i))
      .filter((x): x is string => x !== null);
  const evRow = async (id: string, title: string, asserted: string, own: () => string[], probes: () => { label: string; r: ReturnType<typeof validateManifest>; rule: string; code: string }[]) => {
    await s.run(id, title, asserted, () => {
      if (!m) return bad("manifest invalid");
      const off = own();
      if (off.length) return bad(`the manifest's events: ${off.join("; ")}`);
      const valid = withProbeEvents([probeEvent()]);
      if (!valid.ok) return bad(`the validator refuses a VALID probe event: ${evShow(valid)}`);
      const p = probes();
      const missed = p.filter((x) => !evRefused(x.r, x.rule, x.code));
      const n = events().length;
      return verdict(missed.length === 0, missed.length ? `validator did not refuse: ${missed.map((x) => `${x.label} (${evShow(x.r)})`).join("; ")}` : `${n ? `${n} declared event(s) ok` : "no events declared"}; validator refuses ${p.map((x) => x.label).join(", ")}`);
    });
  };
  const EV_NAME = /^(?!tb\.)[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;
  await evRow(
    "M-EV-1",
    "event names unique, pattern, never tb.; a manifest tb declares none (M-EV-1)",
    "every events[].name matches ^(?!tb\\.)[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$ (≤ 64), names unique, no events when id is tb; validateManifest refuses a duplicate name, a tb.* name and events in a manifest tb (event_name_invalid)",
    () => {
      const names = events().map((e) => String(e.name));
      const off = evOwn((e) => (typeof e.name !== "string" || e.name.length > 64 || !EV_NAME.test(e.name) ? `name ${String(e.name)}` : null));
      const dup = names.filter((x, i) => names.indexOf(x) !== i);
      if (dup.length) off.push(`duplicate ${dup.join(",")}`);
      if (m?.id === "tb" && names.length) off.push("a manifest tb declares events");
      return off;
    },
    () => [
      { label: "a duplicate name", r: withProbeEvents([probeEvent(), probeEvent()]), rule: "M-EV-1", code: "event_name_invalid" },
      { label: "tb.hold.decided", r: withProbeEvents([probeEvent({ name: "tb.hold.decided" })]), rule: "M-EV-1", code: "event_name_invalid" },
      { label: "events in a manifest tb", r: withProbeEvents([probeEvent()], { id: "tb" }), rule: "M-EV-1", code: "event_name_invalid" },
    ],
  );
  await evRow(
    "M-EV-2",
    "payloadSchema: object root, strict compile, ≤ 8 KiB, M-OP-8 limits (M-EV-2)",
    "every events[].payloadSchema has type object, is ≤ 8 KiB (JCS) and has no $id / remote $ref / contentEncoding / contentMediaType; validateManifest refuses an array root, an unknown keyword (strict) and a $id (event_schema_invalid)",
    () =>
      evOwn((e) => {
        const ps = e.payloadSchema as Record<string, unknown> | undefined;
        if (ps?.type !== "object") return `${String(e.name)}: root type ${String(ps?.type)}`;
        if (Buffer.byteLength(JSON.stringify(ps)) > 8192) return `${String(e.name)}: over 8 KiB`;
        const text = JSON.stringify(ps);
        if (/"\$id"|"contentEncoding"|"contentMediaType"/.test(text) || /"\$ref":"(?!#)/.test(text)) return `${String(e.name)}: a keyword M-OP-8 forbids`;
        return null;
      }),
    () => [
      { label: "an array root", r: withProbeEvents([probeEvent({ payloadSchema: { type: "array" } })]), rule: "M-EV-2", code: "event_schema_invalid" },
      { label: "an unknown keyword", r: withProbeEvents([probeEvent({ payloadSchema: { type: "object", properties: { id: { type: "string", conformanceUnknown: 1 } } } })]), rule: "M-EV-2", code: "event_schema_invalid" },
      { label: "a $id", r: withProbeEvents([probeEvent({ payloadSchema: { type: "object", $id: "urn:conformance" } })]), rule: "M-EV-2", code: "event_schema_invalid" },
    ],
  );
  await evRow(
    "M-EV-3",
    "visibleWith = an agent op of the manifest, not dynamic (M-EV-3)",
    "every events[].visibleWith names an operation of the manifest with audience agent and no dynamic; validateManifest refuses an unknown op and a person op (event_visible_with_invalid)",
    () =>
      evOwn((e) => {
        const op = m?.operations.find((o) => o.id === e.visibleWith);
        return op?.audience !== "agent" || op.dynamic ? `${String(e.name)}: visibleWith ${String(e.visibleWith)}` : null;
      }),
    () => {
      const person = m?.operations.find((o) => o.audience === "person")?.id;
      return [
        { label: "an unknown op", r: withProbeEvents([probeEvent({ visibleWith: "conformance_missing" })]), rule: "M-EV-3", code: "event_visible_with_invalid" },
        ...(person ? [{ label: `the person op ${person}`, r: withProbeEvents([probeEvent({ visibleWith: person })]), rule: "M-EV-3", code: "event_visible_with_invalid" }] : []),
      ];
    },
  );
  await evRow(
    "M-EV-4",
    "no top-level summary in a payloadSchema (M-EV-4)",
    "no events[].payloadSchema.properties.summary (the summary travels in the envelope); validateManifest refuses one (event_schema_invalid, rule M-EV-4)",
    () => evOwn((e) => (Object.hasOwn((e.payloadSchema as { properties?: object } | undefined)?.properties ?? {}, "summary") ? `${String(e.name)}: properties.summary` : null)),
    () => [{ label: "properties.summary", r: withProbeEvents([probeEvent({ payloadSchema: { type: "object", properties: { summary: { type: "string" } } } })]), rule: "M-EV-4", code: "event_schema_invalid" }],
  );

  // ── M3 digest ──
  await s.run("M3", "digest = sha256(JCS) reproducible", "manifestDigest stable across runs, key order and JSON round-trip", () => {
    if (!m) return bad("manifest invalid");
    const d1 = manifestDigest(m);
    const d2 = manifestDigest(clone(m));
    const d3 = digest(shuffleKeys(json) as Json);
    const d4 = v.ok ? v.digest : "";
    const same = d1 === d2 && d2 === d3 && d3 === d4 && /^sha256:[0-9a-f]{64}$/.test(d1);
    if (opts.expectDigest && opts.expectDigest !== d1) return bad(`${d1} ≠ expected ${opts.expectDigest}`);
    return verdict(same, same ? d1 : `mismatch: ${[d1, d2, d3, d4].join(" / ")}`);
  });

  // ── M4 no hand-written generator outputs ──
  await s.run("M4.no_copies", "no hand-written generator outputs beside the manifest", "no openapi.*, manifest.json or recipe.json next to the manifest", () => {
    if (!opts.manifestPath) return notRun("manifest path unknown (pass --manifest <file>)");
    const dir = dirname(opts.manifestPath);
    const own = basename(opts.manifestPath);
    const found = readdirSync(dir).filter((n) => n !== own && (/^openapi\./i.test(n) || n === "manifest.json" || n === "recipe.json"));
    return verdict(found.length === 0, found.length ? `found: ${found.join(",")}` : `clean: ${dir}`);
  });

  // ── M5 no product literal ──
  await s.run("M5", "no product literal in platform source trees", "no product id from any manifest appears as a literal in the scanned trees", () => {
    if (!m) return bad("manifest invalid");
    if (!opts.scanDirs?.length) return opts.m5NotApplicable ? na(opts.m5NotApplicable) : notRun("no source trees given (pass --scan <dir>)");
    const ids = [...new Set([m.id, ...(opts.extraProductIds ?? [])])];
    const hits = findProductLiterals(opts.scanDirs, ids);
    return verdict(hits.length === 0, hits.length ? `${hits.length} hits: ${hits.slice(0, 5).join("; ")}` : `${opts.scanDirs.length} trees clean of ${ids.join(",")}`);
  });

  // ── M6 path bases (MANIFEST §3) ──
  await s.run("M6.paths", "path bases: build paths repo-relative, skill files manifest-relative (MANIFEST §3)", "build contexts/Dockerfiles exist under the repo root, skill files under the manifest directory, none escaping its base", async () => {
    if (!m) return bad("manifest invalid");
    if (!opts.repoDir) return na("no repo dir given (pass --repo <dir>: the repository root that build paths are relative to)");
    const repoRoot = resolve(opts.repoDir);
    const manifestDir = opts.manifestPath ? resolve(dirname(opts.manifestPath)) : repoRoot;
    const builds = [{ at: "runtime.build", ...m.runtime.build }, ...(m.runtime.services ?? []).flatMap((x) => (x.build ? [{ at: `runtime.services[${x.id}].build`, ...x.build }] : []))];
    const off: string[] = [];
    for (const b of builds) {
      for (const [field, dir] of [["context", true], ["dockerfile", false]] as const) {
        const p = resolve(repoRoot, b[field]);
        if (p !== repoRoot && !p.startsWith(repoRoot + sep)) off.push(`${b.at}.${field} ${b[field]} escapes the repo root`);
        else if (!isKind(p, dir)) off.push(`${b.at}.${field} ${b[field]}: no ${dir ? "directory" : "file"} under the repo root ${repoRoot}`);
      }
    }
    for (const sk of m.skills ?? []) {
      const p = resolve(manifestDir, sk.file);
      if (!p.startsWith(manifestDir + sep)) off.push(`skill ${sk.id}: ${sk.file} escapes the manifest directory`);
      else if (!isKind(p, false)) off.push(`skill ${sk.id}: ${sk.file}: no file under the manifest directory ${manifestDir}`);
    }
    // the one validator must agree with the independent check above
    const vr = await validateAppFiles(m, repoRoot, manifestDir);
    const vPaths = vr.ok ? [] : vr.errors.filter((e) => e.code === "build_path_invalid" || (e.code === "skill_file_invalid" && /not found|escapes/.test(e.message)));
    if (vPaths.length !== off.length) off.push(`validateAppFiles disagrees: ${vPaths.length} path issue(s) against ${off.length} found here`);
    const nSkills = m.skills?.length ?? 0;
    return verdict(off.length === 0, off.length ? `violations: ${off.join("; ")}` : `${builds.length} build(s) under repo ${repoRoot}; ${nSkills} skill file(s) under manifest dir ${manifestDir}`);
  });

  return { results: s.results, manifest: m, notes };
}
