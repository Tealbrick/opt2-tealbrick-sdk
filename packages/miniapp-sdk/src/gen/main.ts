// `tb-gen` command line (SDK-API §15, §17): openapi | kit | docs | railway | all | check.
import { join, relative, resolve } from "node:path";
import { checkDrift, GEN_KINDS, type GenKind, generate } from "./generate.ts";
import { buildKit, kitDirName } from "./kit.ts";
import { DEFAULT_MANIFEST, GenError, loadManifest, writeFiles } from "./load.ts";
import type { SettingValue } from "./railway.ts";

export const USAGE = `usage: tb-gen <openapi|kit|docs|railway|all|check> [--manifest <path>] [--repo <dir>] [--out <dir>] [--build] [--set <setting>=<value>]... [--package-name <@scope/name>]
  --repo    repository root: build paths (runtime.build) are repo-relative and railway checks they exist there; skill files are
            manifest-relative (the directory of --manifest). Default: the directory of --manifest. (MANIFEST §3)
  openapi   gen/openapi/openapi.json (the document the app serves at /tb/v1/openapi.json)
  kit       gen/kit/<product>-kit/ (package @opt2-tealbrick/<product>-kit, or --package-name); --build compiles it and packs a tarball into --out.
            The kit exports TOOLS (agent tool definitions as the bridge lists them) for harness packages (C338).
  docs      gen/docs/<product>.md
  railway   gen/railway/{railway.json,template.json}; --set renders with setting values other than the defaults
  all       every kind under --out (default gen/)
  check     regenerates every kind and fails if a committed gen/ (if present) differs`;

const COMMANDS = [...GEN_KINDS, "all", "check"] as const;
type Command = (typeof COMMANDS)[number];

export interface TbGenArgs {
  command: Command;
  manifest: string;
  /** repo root (build paths); null = the manifest's directory */
  repo: string | null;
  out: string | null;
  build: boolean;
  settings: Record<string, SettingValue>;
  /** C338: kit package name override */
  packageName: string | null;
}

export class UsageError extends Error {}

export function parseTbGenArgs(argv: readonly string[]): TbGenArgs {
  const [command, ...rest] = argv;
  if (!command || !(COMMANDS as readonly string[]).includes(command)) throw new UsageError(command ? `unknown command ${command}` : "missing command");
  const args: TbGenArgs = { command: command as Command, manifest: DEFAULT_MANIFEST, repo: null, out: null, build: false, settings: {}, packageName: null };
  for (let i = 0; i < rest.length; i++) {
    const flag = rest[i];
    const value = () => {
      const v = rest[++i];
      if (v === undefined || v.startsWith("--")) throw new UsageError(`${flag} needs a value`);
      return v;
    };
    if (flag === "--manifest") args.manifest = value();
    else if (flag === "--repo") args.repo = value();
    else if (flag === "--out") args.out = value();
    else if (flag === "--build" && (args.command === "kit" || args.command === "all")) args.build = true;
    else if (flag === "--package-name" && (args.command === "kit" || args.command === "all" || args.command === "check")) args.packageName = value();
    else if (flag === "--set" && (args.command === "railway" || args.command === "all" || args.command === "check")) {
      const kv = value();
      const eq = kv.indexOf("=");
      if (eq < 1) throw new UsageError(`--set expects <setting>=<value>, got ${kv}`);
      args.settings[kv.slice(0, eq)] = kv.slice(eq + 1);
    } else throw new UsageError(`unknown flag ${flag} for ${args.command}`);
  }
  return args;
}

export interface TbGenIo {
  cwd: string;
  out: (line: string) => void;
  err: (line: string) => void;
}

/** Runs one `tb-gen` invocation; returns the exit code (0 ok, 1 refused/drift, 2 usage). */
export function runTbGen(argv: readonly string[], io: TbGenIo): number {
  let args: TbGenArgs;
  try {
    args = parseTbGenArgs(argv);
  } catch (e) {
    io.err(`tb-gen: ${(e as Error).message}`);
    io.err(USAGE);
    return 2;
  }
  try {
    const lm = loadManifest(resolve(io.cwd, args.manifest), args.repo === null ? undefined : resolve(io.cwd, args.repo));
    const show = (p: string) => relative(io.cwd, p) || ".";
    if (args.command === "check") {
      const genDir = resolve(io.cwd, args.out ?? "gen");
      const r = checkDrift(lm, genDir, { settings: args.settings, ...(args.packageName !== null ? { packageName: args.packageName } : {}) });
      if (!r.present) {
        io.out(`tb-gen check: no ${show(genDir)} directory; nothing committed, nothing to drift`);
        return 0;
      }
      if (r.differences.length > 0) {
        io.err(`tb-gen check: ${show(genDir)} differs from the manifest (run tb-gen all):`);
        for (const d of r.differences) io.err(`  ${d}`);
        return 1;
      }
      io.out(`tb-gen check: ok (${r.compared.join(", ") || "no generated kinds present"})`);
      return 0;
    }
    const kinds: readonly GenKind[] = args.command === "all" ? GEN_KINDS : [args.command];
    for (const kind of kinds) {
      const outDir = resolve(io.cwd, args.command === "all" ? join(args.out ?? "gen", kind) : (args.out ?? join("gen", kind)));
      for (const p of writeFiles(outDir, generate(kind, lm, { settings: args.settings, ...(args.packageName !== null ? { packageName: args.packageName } : {}) }))) io.out(show(p));
      if (kind === "kit" && args.build) io.out(show(buildKit(join(outDir, kitDirName(lm.manifest.id)), outDir, io.cwd)));
    }
    return 0;
  } catch (e) {
    if (e instanceof GenError) {
      io.err(`tb-gen: ${e.code}: ${e.message}`);
      for (const i of e.issues) io.err(`  ${i.path || "/"} ${i.rule} ${i.code}: ${i.message}`);
    } else io.err(`tb-gen: ${(e as Error).message}`);
    return 1;
  }
}
