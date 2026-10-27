// C373a: streamed restore. The body goes to a temp file on the companion's OWN data volume (`<TB_DATA_DIR>/tb/`, the
// same filesystem as the data), sha-256 computed on the way; free space is checked before and during. The restore
// command runs ONLY after the digest equals the assertion's `bd`; on any refusal the temp file is deleted.
// Never logs a path or body bytes.
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createReadStream, createWriteStream } from "node:fs";
import { mkdir, readdir, statfs, unlink } from "node:fs/promises";
import type { IncomingHttpHeaders } from "node:http";
import { join } from "node:path";
import { finished } from "node:stream/promises";
import type { Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";

/** temp files live in tb-exec's own folder of the data dir (next to `claim.json`) */
export const RESTORE_TEMP_SUBDIR = "tb";
const TEMP_NAME = /^restore-[0-9a-f]{24}\.part$/;
/** free space is re-checked after every this many received bytes */
export const DISK_CHECK_EVERY_BYTES = 64 * 1024 * 1024;

/** free bytes for an unprivileged writer on the filesystem of `dir` */
export type FreeBytes = (dir: string) => Promise<number>;
export const volumeFreeBytes: FreeBytes = async (dir) => {
  const s = await statfs(dir);
  return Number(s.bavail) * Number(s.bsize);
};

export const tooLarge = () => new TbError("payload_too_large", "request body too large", 413);
export const noSpace = () => new TbError("insufficient_storage", "not enough free space on the data volume for the restore body", 507);
const digestMismatch = () => new TbError("unauthenticated", "instance assertion invalid", 401);

export interface RestoreBodySource extends AsyncIterable<Buffer> {
  headers: IncomingHttpHeaders;
}

export interface ReceiveOptions {
  dataDir: string;
  maxBytes: number;
  /** the assertion's `bd`; null = it binds no body, so the body must be empty */
  digest: Sha256Digest | null;
  freeBytes?: FreeBytes;
  checkEveryBytes?: number;
}

export interface ReceivedBody {
  /** temp file holding the verified body (empty body: none) */
  file: string | null;
  size: number;
  /** deletes the temp file (idempotent) */
  dispose(): Promise<void>;
}

const unlinkQuiet = (file: string) => unlink(file).catch(() => {});

/**
 * Receives the body into a temp file and verifies it against `digest`. Throws TbError 413 (over `maxBytes`), 507 (free
 * space), 401 (digest mismatch) or `aborted` (the client went away); the temp file is gone whenever it throws. The
 * iterator of `src` is not closed on a refusal, so the caller can still answer before it drops the connection.
 */
export async function receiveRestoreBody(src: RestoreBodySource, o: ReceiveOptions): Promise<ReceivedBody> {
  const free = o.freeBytes ?? volumeFreeBytes;
  const every = o.checkEveryBytes ?? DISK_CHECK_EVERY_BYTES;
  const cl = src.headers["content-length"];
  const declared = cl === undefined ? null : Number(cl);
  if (declared !== null && !(declared <= o.maxBytes)) throw tooLarge();
  if (o.digest === null) {
    if (declared !== null && declared > 0) throw digestMismatch();
  } else if (declared === 0) throw digestMismatch();
  const need = declared ?? o.maxBytes;
  const dir = join(o.dataDir, RESTORE_TEMP_SUBDIR);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  if ((await free(dir)) < need) throw noSpace();

  const file = join(dir, `restore-${randomBytes(12).toString("hex")}.part`);
  const out = createWriteStream(file, { flags: "wx", mode: 0o600 });
  let writeError: Error | null = null;
  out.on("error", (e) => {
    writeError ??= e;
  });
  const hash = createHash("sha256");
  let size = 0;
  let nextCheck = every;
  const it = src[Symbol.asyncIterator]();
  try {
    for (;;) {
      let step: IteratorResult<Buffer>;
      try {
        step = await it.next();
      } catch {
        throw new TbError("aborted", "the restore body ended early", 400);
      }
      if (step.done) break;
      const chunk = step.value;
      size += chunk.length;
      if (size > o.maxBytes) throw tooLarge();
      if (o.digest === null) throw digestMismatch();
      hash.update(chunk);
      if (writeError) throw writeError;
      if (!out.write(chunk)) await drained(out);
      if (size >= nextCheck) {
        nextCheck = size + every;
        if ((await free(dir)) < need - size) throw noSpace();
      }
    }
    out.end();
    await finished(out);
    if (writeError) throw writeError;
    if (o.digest !== null && (size === 0 || `sha256:${hash.digest("hex")}` !== o.digest)) throw digestMismatch();
  } catch (e) {
    out.destroy();
    await finished(out).catch(() => {});
    await unlinkQuiet(file);
    if (e instanceof TbError) throw e;
    if ((e as NodeJS.ErrnoException).code === "ENOSPC" || (e as NodeJS.ErrnoException).code === "EDQUOT") throw noSpace();
    throw new TbError("restore_failed", "the restore body could not be stored", 500);
  }
  if (size === 0) {
    await unlinkQuiet(file);
    return { file: null, size: 0, dispose: async () => {} };
  }
  return { file, size, dispose: () => unlinkQuiet(file) };
}

function drained(out: NodeJS.WritableStream): Promise<void> {
  return new Promise((resolve, reject) => {
    const done = () => {
      out.off("drain", done);
      out.off("error", fail);
      out.off("close", done);
      resolve();
    };
    const fail = (e: Error) => {
      out.off("drain", done);
      out.off("close", done);
      reject(e);
    };
    out.once("drain", done);
    out.once("close", done);
    out.once("error", fail);
  });
}

/** Deletes temp files a crash left behind (`<dataDir>/tb/restore-*.part`); returns how many. */
export async function sweepRestoreTemp(dataDir: string): Promise<number> {
  const dir = join(dataDir, RESTORE_TEMP_SUBDIR);
  let names: string[];
  try {
    names = await readdir(dir);
  } catch {
    return 0;
  }
  let n = 0;
  for (const name of names) {
    if (!TEMP_NAME.test(name)) continue;
    await unlinkQuiet(join(dir, name));
    n++;
  }
  return n;
}

/** Runs `backup.restore` with the verified temp file (or nothing) on stdin; the exit code decides. */
export function runRestoreFrom(argv: string[], env: Record<string, string>, file: string | null, log: Logger): Promise<void> {
  return new Promise((resolve, reject) => {
    const [cmd, ...args] = argv as [string, ...string[]];
    const p = spawn(cmd, args, { env, stdio: ["pipe", "inherit", "inherit"] });
    let readFailed = false;
    p.stdin.once("error", () => {}); // an early exit closes stdin; the exit code decides
    p.once("error", () => reject(new TbError("restore_failed", "backup.restore could not start", 500)));
    p.once("close", (code) => {
      log.info("backup restore finished", { exitCode: code });
      if (code === 0 && !readFailed) resolve();
      else reject(new TbError("restore_failed", "backup.restore failed", 500));
    });
    if (file === null) {
      p.stdin.end();
      return;
    }
    const body = createReadStream(file);
    body.once("error", () => {
      readFailed = true;
      p.stdin.destroy();
    });
    body.pipe(p.stdin);
  });
}
