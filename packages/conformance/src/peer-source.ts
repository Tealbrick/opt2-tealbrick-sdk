// CONF-MULTIAPP (conformance 0.1.20): where a REAL peer app comes from. A peer is named by product + exact released
// version; its source is the commit that the SIGNED release index records for it, never a branch:
//   1. the signed release index (`index.json` + `index.jws`) is fetched from the pinned registry bases and verified with
//      the pinned release key through `verifyReleaseIndex` of @opt2-tealbrick/manifest (the code Core and the CLI use, L1);
//   2. the record for product@version (channel stable unless the peer says "dev") gives `repo` + `commit`;
//   3. the source archive of that commit is downloaded from codeload.github.com (public repos only: a private repo, or a
//      commit that is not pushed, answers 404 and the peer is refused with that reason), extracted with this package's own
//      tar reader, and its top directory name must end with the recorded commit;
//   4. `pnpm install --frozen-lockfile --ignore-scripts`, then the repo's own build script;
//   5. the checkout lives in `<tmp>/tbconf-peers/<product>@<version>@<commit>` and is reused while its ready marker holds.
// The index lookup and the source step are injectable, so the suite's own tests never touch the network.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { gunzipSync } from "node:zlib";
import { keySetFrom, manifestDigest, validateManifest, verifyReleaseIndex } from "@opt2-tealbrick/manifest";
import type { Manifest } from "./manifest-type.ts";
import { readTar } from "./tar.ts";
import type { PeerSpec } from "./waivers.ts";

/**
 * The release signing public keys (Ed25519 JWK `x`, issuer `tb:releases`): the platform `registry/keys.json`, the same
 * list `tealbrick self-update` and install.sh pin. Rotation: add the new key here when the platform signs with it.
 */
export const RELEASE_KEYS: readonly string[] = ["H7nxFrNugQLVOqEXVIB4aOg83Jn19UCosd27fqnoPPI"];
/** The signed release index hosts (`<base>/index.json` + `<base>/index.jws`), tried in order; the CLI pins the same two. */
export const INDEX_BASES: readonly string[] = [
  "https://github.com/Tealbrick/opt2-tealbrick-dist/releases/download/registry",
  "https://github.com/Tealbrick/opt2-tealbrick-platform/releases/download/registry",
];
/** Repo owners an index record may name (the org, and the user account the records signed before the C206 move name). */
const REPO_OWNERS = new Set(["Tealbrick", "Martin-Atrin"]);
const REPO_RE = /^([A-Za-z0-9-]+)\/(opt2-tealbrick-[a-z0-9-]+)$/;
const COMMIT_RE = /^[0-9a-f]{40}$/;
const MAX_INDEX_BYTES = 4_000_000;
const MAX_ARCHIVE_BYTES = 100 * 1024 * 1024;
const MAX_TAR_BYTES = 600 * 1024 * 1024;
const MAX_FILES = 60_000;
const READY = ".tbconf-ready";

/** A peer could not be loaded; the message is shown as is in the X1 row. */
export class PeerError extends Error {}

/** The fields of a signed `kind: "app"` release record the loader uses. */
export interface ReleaseRecord {
  product: string;
  version: string;
  channel: string;
  /** `<owner>/<repo>` of the public app repo */
  repo: string;
  /** 40 hex: the source commit of the release */
  commit: string;
  /** `sha256:<hex>` of the manifest at that commit, or null */
  manifestDigest: string | null;
}

export interface PeerSourceOptions {
  /** the VERIFIED `releases[]` of the index (default: fetched from INDEX_BASES and verified with RELEASE_KEYS) */
  index?: () => Promise<readonly unknown[]>;
  /** puts the checkout of `rec` into the empty directory `dir`, ready to start (default: GitHub archive, frozen install, build) */
  source?: (rec: ReleaseRecord, dir: string) => Promise<void>;
  /** where checkouts are cached (default `<tmp>/tbconf-peers`) */
  cacheRoot?: string;
  /** progress lines (default: stderr) */
  log?: (line: string) => void;
}

/** A peer ready to boot: its record, checkout, manifest and start module. */
export interface LoadedPeer {
  spec: PeerSpec;
  record: ReleaseRecord;
  dir: string;
  manifest: Manifest;
  /** absolute path of the module that default-exports `start(env)` (the app's conformance.start.ts) */
  startModule: string;
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const say = (o: PeerSourceOptions) => o.log ?? ((l: string) => void process.stderr.write(`tb-conformance peers: ${l}\n`));
const why = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** Where the peer cache lives (`<tmp>/tbconf-peers`). */
export const defaultCacheRoot = (): string => join(tmpdir(), "tbconf-peers");
/** `<cacheRoot>/<product>@<version>@<commit>` */
export const peerCacheDir = (root: string, rec: Pick<ReleaseRecord, "product" | "version" | "commit">): string => join(root, `${rec.product}@${rec.version}@${rec.commit}`);

// ── the signed index ────────────────────────────────────────────────────────

async function fetchCapped(url: string, max: number, hosts: readonly string[], what: string): Promise<Buffer> {
  let u = url;
  for (let hop = 0; hop < 4; hop++) {
    const host = new URL(u).hostname;
    if (new URL(u).protocol !== "https:" || !hosts.includes(host)) throw new PeerError(`${what}: refusing ${u} (host ${host} is not one of ${hosts.join(", ")})`);
    let res: Response;
    try {
      res = await fetch(u, { redirect: "manual", signal: AbortSignal.timeout(120_000) });
    } catch (e) {
      throw new PeerError(`${what}: download failed (${why(e)}): ${u}`);
    }
    if (res.status >= 300 && res.status < 400 && res.headers.get("location")) {
      u = new URL(res.headers.get("location") as string, u).href;
      continue;
    }
    if (res.status === 404) throw new PeerError(`${what}: HTTP 404 for ${u}`);
    if (!res.ok) throw new PeerError(`${what}: HTTP ${res.status} for ${u}`);
    const len = Number(res.headers.get("content-length") ?? "0");
    if (len > max) throw new PeerError(`${what}: ${u} is larger than ${max} bytes`);
    const bytes = Buffer.from(await res.arrayBuffer());
    if (bytes.length > max) throw new PeerError(`${what}: ${u} is larger than ${max} bytes`);
    return bytes;
  }
  throw new PeerError(`${what}: too many redirects from ${url}`);
}

/** Hosts a release asset download may redirect through (GitHub serves release assets from its object store). */
const ASSET_HOSTS = ["github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"] as const;

/**
 * Fetches and VERIFIES the signed release index: the JWS with the pinned release keys (`verifyReleaseIndex`, which also
 * checks `claims.indexDigest` against the JCS digest of the body and the counts), the body schema, the bases in order.
 * Returns `releases[]`; throws a PeerError naming every base and its reason when none verifies.
 */
export async function fetchVerifiedIndex(opts: { bases?: readonly string[]; keys?: readonly string[]; now?: () => number; get?: (url: string, max: number) => Promise<Buffer> } = {}): Promise<unknown[]> {
  const bases = opts.bases ?? INDEX_BASES;
  const keys = keySetFrom({ keys: (opts.keys ?? RELEASE_KEYS).map((x) => ({ kty: "OKP", crv: "Ed25519", x }) as never) }, "tb:releases");
  const get = opts.get ?? ((url: string, max: number) => fetchCapped(url, max, ASSET_HOSTS, "release index"));
  const failures: string[] = [];
  for (const base of bases) {
    try {
      const body = JSON.parse((await get(`${base}/index.json`, MAX_INDEX_BYTES)).toString("utf8")) as unknown;
      const jws = (await get(`${base}/index.jws`, 32_768)).toString("utf8").trim();
      if (!isRecord(body) || body.schema !== "opt2.release-index/v2" || !Array.isArray(body.releases)) throw new PeerError("unexpected release index schema");
      const v = verifyReleaseIndex(jws, body as never, { now: Math.floor((opts.now?.() ?? Date.now()) / 1000), keys });
      if (!v.ok) throw new PeerError(`release index signature refused (${(v as { reason?: string }).reason ?? "invalid"})`);
      return body.releases as unknown[];
    } catch (e) {
      failures.push(`${base}: ${why(e)}`);
    }
  }
  throw new PeerError(`no release index host gave a verified index:\n  ${failures.join("\n  ")}`);
}

/** The one `kind: "app"` record for product@version on `channel`; refuses a missing, duplicate or malformed record. */
export function selectRecord(releases: readonly unknown[], spec: Pick<PeerSpec, "product" | "version" | "channel">): ReleaseRecord {
  const id = `${spec.product}@${spec.version} (${spec.channel})`;
  const same = releases.filter((r): r is Record<string, unknown> => isRecord(r) && r.kind === "app" && r.product === spec.product);
  const hit = same.filter((r) => r.version === spec.version && r.channel === spec.channel);
  if (hit.length === 0) {
    const other = same.filter((r) => r.version === spec.version).map((r) => String(r.channel));
    const have = same.filter((r) => r.channel === spec.channel).map((r) => String(r.version));
    throw new PeerError(
      `peer ${id} is not in the signed release index${other.length ? ` (that version exists on channel ${other.join(", ")}: set "channel" in tealbrick-conformance.json peers)` : have.length ? `; released on ${spec.channel}: ${have.slice(-6).join(", ")}` : `; the index has no ${spec.channel} release of ${spec.product}`}`,
    );
  }
  if (hit.length > 1) throw new PeerError(`peer ${id} is listed more than once in the release index`);
  const r = hit[0] as Record<string, unknown>;
  if (typeof r.repo !== "string" || !REPO_RE.test(r.repo) || !REPO_OWNERS.has((REPO_RE.exec(r.repo) as RegExpExecArray)[1] as string)) {
    throw new PeerError(`peer ${id}: the index record names a repo that is not a Teal Brick app repo (${JSON.stringify(r.repo)})`);
  }
  if (typeof r.commit !== "string" || !COMMIT_RE.test(r.commit)) throw new PeerError(`peer ${id}: the index record has no source commit (${JSON.stringify(r.commit)})`);
  const md = typeof r.manifestDigest === "string" && /^sha256:[0-9a-f]{64}$/.test(r.manifestDigest) ? r.manifestDigest : null;
  return { product: spec.product, version: spec.version, channel: spec.channel, repo: r.repo, commit: r.commit, manifestDigest: md };
}

// ── the source archive ────────────────────────────────────────────────────

/** Extracts a GitHub source archive (tar.gz) of `commit` into `dir`; refuses a tree whose top directory does not end with the commit. Returns the file count. */
export function extractArchive(bytes: Uint8Array, commit: string, dir: string): number {
  let tar: Uint8Array;
  try {
    tar = new Uint8Array(gunzipSync(bytes, { maxOutputLength: MAX_TAR_BYTES }));
  } catch (e) {
    throw new PeerError(`the source archive is not a gzip tar (${why(e)})`);
  }
  const entries = readTar(tar);
  if (entries.length === 0) throw new PeerError("the source archive is empty");
  if (entries.length > MAX_FILES) throw new PeerError(`the source archive has more than ${MAX_FILES} files`);
  const tops = new Set(entries.map((e) => e.name.split("/")[0]));
  const top = [...tops][0] as string;
  if (tops.size !== 1 || !top.endsWith(`-${commit}`)) {
    throw new PeerError(`the source archive is not the commit of the signed index record (top directory ${JSON.stringify([...tops].join(","))}, expected …-${commit})`);
  }
  const root = resolve(dir);
  let n = 0;
  for (const e of entries) {
    const rel = e.name.slice(top.length + 1);
    if (rel === "") continue;
    if (rel.includes("\0") || rel.includes("\\") || isAbsolute(rel) || rel.split("/").some((s) => s === ".." || s === "")) throw new PeerError(`the source archive has an unsafe path ${JSON.stringify(e.name)}`);
    const target = resolve(root, rel);
    if (!target.startsWith(root + sep)) throw new PeerError(`the source archive has an unsafe path ${JSON.stringify(e.name)}`);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, e.data, { mode: 0o644 });
    n++;
  }
  return n;
}

/** The environment of the install / build commands: no secrets (names with TOKEN, SECRET, PASSWORD, KEY, AUTH or CREDENTIAL are dropped). */
function toolEnv(): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || /TOKEN|SECRET|PASSWORD|KEY|AUTH|CREDENTIAL/i.test(k)) continue;
    if (/^(PATH|HOME|TMPDIR|LANG|LC_.*|TZ|CI|SHELL|USER|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|SSL_CERT_.*|(HTTPS?|NO|ALL)_PROXY|(https?|no|all)_proxy|(npm|NPM|pnpm|PNPM|COREPACK)_.*)$/.test(k)) out[k] = v;
  }
  return out;
}

function runTool(cmd: string, args: string[], cwd: string, timeoutMs: number): Promise<void> {
  return new Promise((done, fail) => {
    let tail = "";
    const child = spawn(cmd, args, { cwd, env: toolEnv(), stdio: ["ignore", "pipe", "pipe"] });
    const keep = (d: Buffer) => {
      tail = (tail + d.toString("utf8")).slice(-1200);
    };
    child.stdout.on("data", keep);
    child.stderr.on("data", keep);
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("error", (e) => {
      clearTimeout(timer);
      fail(
        (e as NodeJS.ErrnoException).code === "ENOENT"
          ? new PeerError(`${cmd} is not installed or not on PATH: --peers installs each peer app from its lockfile with pnpm (install pnpm, or run without --peers)`)
          : new PeerError(`${cmd} could not start (${e.message})`),
      );
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) return done();
      fail(new PeerError(`\`${cmd} ${args.join(" ")}\` ${signal ? `was killed (${signal}; ${timeoutMs} ms limit)` : `failed with code ${code}`}${tail.trim() ? `; last output: ${tail.trim()}` : ""}`));
    });
  });
}

/** The default source step: the archive of the signed commit from codeload.github.com, a frozen install without scripts, the repo's build. */
export async function githubSource(rec: ReleaseRecord, dir: string, log: (l: string) => void = () => undefined): Promise<void> {
  const url = `https://codeload.github.com/${rec.repo}/tar.gz/${rec.commit}`;
  log(`${rec.product}@${rec.version}: downloading ${rec.repo}@${rec.commit.slice(0, 12)}`);
  let bytes: Buffer;
  try {
    bytes = await fetchCapped(url, MAX_ARCHIVE_BYTES, ["codeload.github.com"], "source archive");
  } catch (e) {
    if (e instanceof PeerError && /HTTP 404/.test(e.message)) {
      throw new PeerError(
        `peer ${rec.product}@${rec.version}: ${rec.repo} at ${rec.commit.slice(0, 12)} cannot be downloaded (HTTP 404): the repo is private or the commit is not pushed. Peers come from PUBLIC app repos only (private-first apps are peers after their public flip, CONF-MULTIAPP)`,
      );
    }
    throw e;
  }
  const files = extractArchive(bytes, rec.commit, dir);
  log(`${rec.product}@${rec.version}: extracted ${files} files; installing from the lockfile`);
  if (!existsSync(join(dir, "pnpm-lock.yaml"))) throw new PeerError(`peer ${rec.product}@${rec.version}: the repo has no pnpm-lock.yaml, so a frozen install is not possible`);
  await runTool("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts"], dir, 10 * 60_000);
  const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { scripts?: Record<string, string> };
  if (pkg.scripts?.build) {
    log(`${rec.product}@${rec.version}: building`);
    await runTool("pnpm", ["run", "build"], dir, 10 * 60_000);
  }
}

// ── the loader ──────────────────────────────────────────────────────────────

/** Manifest path of `product` in the checkout: `tealbrick-ci.json` images[] (kind app) when present, else `tealbrick.manifest.json`. */
function manifestPathOf(dir: string, product: string): string {
  let rel = "tealbrick.manifest.json";
  const ci = join(dir, "tealbrick-ci.json");
  if (existsSync(ci)) {
    try {
      const images = (JSON.parse(readFileSync(ci, "utf8")) as { images?: { product?: string; kind?: string; manifest?: string }[] }).images ?? [];
      const hit = images.find((i) => i.product === product && (i.kind === undefined || i.kind === "app") && typeof i.manifest === "string");
      if (hit?.manifest) rel = hit.manifest;
    } catch {
      // an unreadable tealbrick-ci.json falls back to the conventional name
    }
  }
  const path = resolve(dir, rel);
  if (isAbsolute(rel) || !path.startsWith(resolve(dir) + sep)) throw new PeerError(`peer ${product}: manifest path ${JSON.stringify(rel)} leaves the checkout`);
  return path;
}

/** Start module of the checkout: `conformance.start.ts`, else the `--start <module>` of its package.json `conformance` script. */
function startModuleOf(dir: string, product: string): string {
  const fixed = join(dir, "conformance.start.ts");
  if (existsSync(fixed)) return fixed;
  try {
    const script = (JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { scripts?: Record<string, string> }).scripts?.conformance ?? "";
    const m = /--start\s+(\S+)/.exec(script);
    if (m) {
      const path = resolve(dir, m[1] as string);
      if (path.startsWith(resolve(dir) + sep) && existsSync(path)) return path;
    }
  } catch {
    // no package.json: refused below
  }
  throw new PeerError(`peer ${product}: no conformance.start.ts (and no \`--start <module>\` in its package.json conformance script); the peer must export start(env) like create-tealbrick-miniapp's conformance.start.ts`);
}

/** Resolves, fetches (or reuses the cache of), checks and reads one peer. Throws a PeerError with a clear reason. */
export async function loadPeer(spec: PeerSpec, opts: PeerSourceOptions = {}): Promise<LoadedPeer> {
  const log = say(opts);
  const releases = await (opts.index ?? (() => fetchVerifiedIndex()))();
  const record = selectRecord(releases, spec);
  const root = opts.cacheRoot ?? defaultCacheRoot();
  const dir = peerCacheDir(root, record);
  const marker = join(dir, READY);
  if (existsSync(marker) && readFileSync(marker, "utf8").trim() === record.commit) {
    log(`${spec.product}@${spec.version}: cached checkout ${dir}`);
  } else {
    rmSync(dir, { recursive: true, force: true });
    mkdirSync(dir, { recursive: true });
    try {
      await (opts.source ?? ((r, d) => githubSource(r, d, log)))(record, dir);
    } catch (e) {
      rmSync(dir, { recursive: true, force: true });
      throw e instanceof PeerError ? e : new PeerError(`peer ${spec.product}@${spec.version}: ${why(e)}`);
    }
    writeFileSync(marker, `${record.commit}\n`);
  }
  const mpath = manifestPathOf(dir, spec.product);
  if (!existsSync(mpath)) throw new PeerError(`peer ${spec.product}@${spec.version}: no manifest at ${mpath.slice(dir.length + 1)} in the checkout`);
  const v = validateManifest(JSON.parse(readFileSync(mpath, "utf8")));
  if (!v.ok) throw new PeerError(`peer ${spec.product}@${spec.version}: its manifest is invalid (${v.errors.slice(0, 3).map((e) => `${e.path} ${e.code}`).join("; ")})`);
  const manifest = v.manifest;
  if (manifest.id !== spec.product) throw new PeerError(`peer ${spec.product}@${spec.version}: the checkout's manifest is for ${manifest.id}`);
  if (manifest.version !== spec.version) throw new PeerError(`peer ${spec.product}@${spec.version}: the checkout's manifest is version ${manifest.version}, not the released ${spec.version}`);
  if (record.manifestDigest && manifestDigest(manifest) !== record.manifestDigest) {
    throw new PeerError(`peer ${spec.product}@${spec.version}: the checkout's manifest digest ${manifestDigest(manifest)} differs from the signed record's ${record.manifestDigest}`);
  }
  return { spec, record, dir, manifest, startModule: startModuleOf(dir, spec.product) };
}

/** Removes the cache directories of `peers` that this run created (never anything else under the cache root). */
export function removePeerCaches(peers: readonly LoadedPeer[]): void {
  for (const p of peers) rmSync(p.dir, { recursive: true, force: true });
}
