// C373a: the numbers behind `GET /tb/v1/exec/stats` (control port, own app instance assertion). Numbers, booleans and
// null only: no path, no file name, no body bytes. cgroup v2 values when readable (the container), else null.
import { lstat, opendir, readFile, statfs } from "node:fs/promises";
import { join } from "node:path";

export const CGROUP_DIR = "/sys/fs/cgroup";
/** the data dir walk stops after this many entries (`dataDir.truncated` then says the sizes are lower bounds) */
export const DATA_DIR_WALK_LIMIT = 1_000_000;
/** a walk result is reused for this long (several callers in a row do not walk again) */
export const DATA_DIR_CACHE_MS = 10_000;

export interface ExecStats {
  /** epoch milliseconds */
  at: number;
  memory: {
    /** cgroup `memory.current` */
    currentBytes: number | null;
    /** cgroup `memory.max`; null = no limit or not readable */
    maxBytes: number | null;
    /** `anon` of cgroup `memory.stat` */
    anonBytes: number | null;
    /** resident set of the tb-exec process itself (always present; the fallback when no cgroup is readable) */
    processRssBytes: number;
  };
  cpu: {
    /** cgroup `cpu.stat` (microseconds since the cgroup started) */
    usageUsec: number | null;
    userUsec: number | null;
    systemUsec: number | null;
    /** cgroup `cpu.max` quota / period; null = no limit or not readable */
    limitCores: number | null;
    /** CPU time of the tb-exec process itself */
    processUserUsec: number;
    processSystemUsec: number;
  };
  /** the filesystem that holds TB_DATA_DIR */
  volume: { totalBytes: number; freeBytes: number; availableBytes: number };
  /** everything under TB_DATA_DIR (symlinks not followed) */
  dataDir: { sizeBytes: number; allocatedBytes: number; files: number; unreadableDirs: number; truncated: boolean };
  /** the file named by TBEXEC_MAIN_DATA_FILE; null = not configured, missing or not a regular file */
  mainDataFile: { sizeBytes: number; allocatedBytes: number } | null;
  /** the restore cap in force (TBEXEC_RESTORE_MAX_BYTES after bounds) */
  restoreMaxBytes: number;
}

export interface StatsOptions {
  dataDir: string;
  /** relative to dataDir (already validated by `mainDataFileFrom`) */
  mainDataFile: string | null;
  restoreMaxBytes: number;
  /** tests only */
  cgroupDir?: string;
}

async function text(file: string): Promise<string | null> {
  try {
    return (await readFile(file, "utf8")).trim();
  } catch {
    return null;
  }
}

const num = (s: string | null | undefined): number | null => (s && /^[0-9]+$/.test(s) ? Number(s) : null);

function keyed(body: string | null): Map<string, string> {
  const m = new Map<string, string>();
  for (const line of (body ?? "").split("\n")) {
    const [k, v] = line.trim().split(/\s+/);
    if (k && v !== undefined) m.set(k, v);
  }
  return m;
}

interface Walk {
  sizeBytes: number;
  allocatedBytes: number;
  files: number;
  unreadableDirs: number;
  truncated: boolean;
}

async function walk(root: string): Promise<Walk> {
  const w: Walk = { sizeBytes: 0, allocatedBytes: 0, files: 0, unreadableDirs: 0, truncated: false };
  const stack = [root];
  let seen = 0;
  while (stack.length > 0) {
    const dir = stack.pop() as string;
    let handle: Awaited<ReturnType<typeof opendir>>;
    try {
      handle = await opendir(dir);
    } catch {
      w.unreadableDirs++;
      continue;
    }
    try {
      for await (const ent of handle) {
        if (++seen > DATA_DIR_WALK_LIMIT) {
          w.truncated = true;
          break;
        }
        const p = join(dir, ent.name);
        if (ent.isDirectory()) {
          stack.push(p);
          continue;
        }
        try {
          const s = await lstat(p);
          w.sizeBytes += s.size;
          w.allocatedBytes += s.blocks * 512;
          w.files++;
        } catch {
          // removed while walking
        }
      }
    } catch {
      w.unreadableDirs++;
    }
    if (w.truncated) break;
  }
  return w;
}

export function statsCollector(o: StatsOptions): () => Promise<ExecStats> {
  const cg = o.cgroupDir ?? CGROUP_DIR;
  let cached: { at: number; walk: Promise<Walk> } | null = null;
  const dataWalk = (): Promise<Walk> => {
    if (!cached || Date.now() - cached.at > DATA_DIR_CACHE_MS) cached = { at: Date.now(), walk: walk(o.dataDir) };
    return cached.walk;
  };
  return async () => {
    const [current, max, memStat, cpuStat, cpuMax, fs, dir, main] = await Promise.all([
      text(join(cg, "memory.current")),
      text(join(cg, "memory.max")),
      text(join(cg, "memory.stat")),
      text(join(cg, "cpu.stat")),
      text(join(cg, "cpu.max")),
      statfs(o.dataDir).catch(() => null),
      dataWalk(),
      o.mainDataFile === null ? Promise.resolve(null) : lstat(join(o.dataDir, o.mainDataFile)).catch(() => null),
    ]);
    const cpu = keyed(cpuStat);
    const [quota, period] = (cpuMax ?? "").split(/\s+/);
    const q = num(quota);
    const per = num(period);
    const own = process.cpuUsage();
    return {
      at: Date.now(),
      memory: { currentBytes: num(current), maxBytes: num(max), anonBytes: num(keyed(memStat).get("anon")), processRssBytes: process.memoryUsage.rss() },
      cpu: {
        usageUsec: num(cpu.get("usage_usec")),
        userUsec: num(cpu.get("user_usec")),
        systemUsec: num(cpu.get("system_usec")),
        limitCores: q !== null && per ? q / per : null,
        processUserUsec: own.user,
        processSystemUsec: own.system,
      },
      volume: fs
        ? { totalBytes: Number(fs.blocks) * Number(fs.bsize), freeBytes: Number(fs.bfree) * Number(fs.bsize), availableBytes: Number(fs.bavail) * Number(fs.bsize) }
        : { totalBytes: 0, freeBytes: 0, availableBytes: 0 },
      dataDir: { ...dir },
      mainDataFile: main?.isFile() ? { sizeBytes: main.size, allocatedBytes: main.blocks * 512 } : null,
      restoreMaxBytes: o.restoreMaxBytes,
    };
  };
}
