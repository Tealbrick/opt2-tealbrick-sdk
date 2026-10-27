// The two private-network listeners of tb-exec, both callable only by the own app instance (instance assertion):
// - helper proxy on manifest `helper.port` (C6): declared paths only, forwarded to `--helper-target` (loopback);
// - control port 7077 (SDK-API §11): `POST /tb/v1/exec/backup` streams `backup.dump` stdout,
//   `POST /tb/v1/exec/restore` runs `backup.restore` with the body on stdin (C373a: streamed to a temp file on the data
//   volume and verified against the assertion's `bd` first), `GET /tb/v1/exec/stats` answers resource numbers (C373a).
import { spawn } from "node:child_process";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, request, type Server, type ServerResponse } from "node:http";
import type { ServiceBackup } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";
import { MAX_BODY_BYTES, pathOf, readRaw, requestId, sendError, sendJson } from "../server/http.ts";
import { RESTORE_DEFAULT_MAX_BYTES } from "./config.ts";
import { type FreeBytes, receiveRestoreBody, runRestoreFrom, sweepRestoreTemp } from "./restore.ts";
import { statsCollector } from "./stats.ts";
import type { AppAssertionHeadVerifier, AppAssertionVerifier } from "./verify.ts";

export const HELPER_TIMEOUT_MS = 30_000;
/** @deprecated C373a: the restore cap is `ControlOptions.restoreMaxBytes` (env TBEXEC_RESTORE_MAX_BYTES); this is its default */
export const RESTORE_MAX_BYTES = RESTORE_DEFAULT_MAX_BYTES;
export const CONTROL_PATHS = { backup: "/tb/v1/exec/backup", restore: "/tb/v1/exec/restore", stats: "/tb/v1/exec/stats" } as const;
const CONTROL_METHODS = { backup: "POST", restore: "POST", stats: "GET" } as const;

const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length", "tb-assert"]);

function forwardHeaders(h: IncomingHttpHeaders): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(h)) if (v !== undefined && !HOP_BY_HOP.has(k)) out[k] = v;
  return out;
}

function listen(server: Server, port: number, host: string): Promise<Server> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      server.off("error", reject);
      resolve(server);
    });
  });
}

export interface HelperProxyOptions {
  port: number;
  host: string;
  paths: readonly string[];
  target: { host: string; port: number };
  verify: AppAssertionVerifier;
  log: Logger;
}

export function startHelperProxy(o: HelperProxyOptions): Promise<Server> {
  const declared = new Set(o.paths);
  const server = createServer(async (req, res) => {
    const rid = requestId();
    try {
      const body = await readRaw(req, MAX_BODY_BYTES);
      o.verify(req, body);
      const path = new URL(req.url ?? "/", "http://helper").pathname;
      if (!declared.has(path)) throw new TbError("helper_path_undeclared", "path is not a declared helper path", 404);
      await forward(req, res, body, o.target);
    } catch (e) {
      if (!(e instanceof TbError)) o.log.warn("helper proxy error", { code: "internal_error" });
      sendError(res, rid, e);
    }
  });
  return listen(server, o.port, o.host);
}

function forward(req: IncomingMessage, res: ServerResponse, body: Buffer, target: { host: string; port: number }): Promise<void> {
  return new Promise((resolve, reject) => {
    const up = request(
      { host: target.host, port: target.port, method: req.method, path: req.url, headers: { ...forwardHeaders(req.headers), "content-length": String(body.length) }, timeout: HELPER_TIMEOUT_MS },
      (upRes) => {
        res.writeHead(upRes.statusCode ?? 502, forwardHeaders(upRes.headers));
        upRes.pipe(res);
        upRes.once("end", resolve);
        upRes.once("error", () => {
          res.destroy();
          resolve();
        });
      },
    );
    up.once("timeout", () => up.destroy(new Error("timeout")));
    up.once("error", () => reject(new TbError("helper_unavailable", "the service helper is not reachable", 502)));
    up.end(body);
  });
}

export interface ControlOptions {
  port: number;
  host: string;
  backup: ServiceBackup | undefined;
  verify: AppAssertionVerifier;
  /** C373a: the restore route verifies everything but `bd` before it reads the body (shares the replay set with `verify`) */
  verifyHead: AppAssertionHeadVerifier;
  /** current child env (the dump/restore commands run with the same env as the upstream) */
  env: () => Record<string, string>;
  log: Logger;
  /** TB_DATA_DIR: restore temp files live in `<dataDir>/tb/`; the stats route measures it */
  dataDir: string;
  /** cap of one restore body (default 512 MiB; run.ts reads TBEXEC_RESTORE_MAX_BYTES) */
  restoreMaxBytes?: number;
  /** TBEXEC_MAIN_DATA_FILE, relative to dataDir (validated) */
  mainDataFile?: string | null;
  /** tests only */
  freeBytes?: FreeBytes;
  checkEveryBytes?: number;
  cgroupDir?: string;
}

type ControlKind = keyof typeof CONTROL_PATHS;

function controlKind(path: string): ControlKind | null {
  for (const k of Object.keys(CONTROL_PATHS) as ControlKind[]) if (CONTROL_PATHS[k] === path) return k;
  return null;
}

export async function startControlServer(o: ControlOptions): Promise<Server> {
  const restoreMaxBytes = o.restoreMaxBytes ?? RESTORE_DEFAULT_MAX_BYTES;
  const stats = statsCollector({ dataDir: o.dataDir, mainDataFile: o.mainDataFile ?? null, restoreMaxBytes, ...(o.cgroupDir ? { cgroupDir: o.cgroupDir } : {}) });
  const swept = await sweepRestoreTemp(o.dataDir);
  if (swept > 0) o.log.info("stale restore temp files removed", { count: swept });
  let busy = false;
  const server = createServer(async (req, res) => {
    const rid = requestId();
    // an unparseable target (e.g. `//`) is an unknown route: `new URL` throwing here was an unhandled rejection that stopped the process
    const path = pathOf(req.url, "http://control");
    const kind = controlKind(path);
    try {
      if (!kind || req.method !== CONTROL_METHODS[kind]) throw new TbError("not_found", "unknown control route", 404);
      if (kind === "restore") return await restore(req, res);
      const body = await readRaw(req, 64 * 1024);
      o.verify(req, body);
      if (kind === "stats") return sendJson(res, 200, await stats());
      if (!o.backup) throw new TbError("backup_undeclared", "this service declares no backup", 404);
      if (busy) throw new TbError("busy", "a backup or restore is already running", 409);
      busy = true;
      try {
        await runDump(o.backup.dump, o.env(), req, res, o.log);
      } finally {
        busy = false;
      }
    } catch (e) {
      sendError(res, rid, e);
    }
  });

  /** auth before any byte is read; then the body streams to disk; `restore` runs only on a matching digest */
  async function restore(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const rid = requestId();
    let mine = false;
    try {
      const digest = o.verifyHead(req);
      if (!o.backup) throw new TbError("backup_undeclared", "this service declares no backup", 404);
      if (busy) throw new TbError("busy", "a backup or restore is already running", 409);
      busy = mine = true;
      const got = await receiveRestoreBody(req, {
        dataDir: o.dataDir,
        maxBytes: restoreMaxBytes,
        digest,
        ...(o.freeBytes ? { freeBytes: o.freeBytes } : {}),
        ...(o.checkEveryBytes ? { checkEveryBytes: o.checkEveryBytes } : {}),
      });
      try {
        o.log.info("restore body verified", { bytes: got.size });
        await runRestoreFrom(o.backup.restore, o.env(), got.file, o.log);
      } finally {
        await got.dispose();
      }
      sendJson(res, 200, { ok: true });
    } catch (e) {
      if (e instanceof TbError) o.log.warn("restore refused", { code: e.code });
      // the rest of a refused body is never read: answer, then close the connection
      if (!req.complete) {
        res.once("finish", () => req.destroy());
      }
      sendError(res, rid, e, req.complete ? {} : { connection: "close" });
    } finally {
      if (mine) busy = false;
    }
  }
  return listen(server, o.port, o.host);
}

/** Streams the dump's stdout; a failure before the first byte → 500 `backup_failed`, after it → connection reset. */
function runDump(argv: string[], env: Record<string, string>, req: IncomingMessage, res: ServerResponse, log: Logger): Promise<void> {
  return new Promise((resolve, reject) => {
    const [file, ...args] = argv as [string, ...string[]];
    const p = spawn(file, args, { env, stdio: ["ignore", "pipe", "inherit"] });
    const head = () => {
      if (!res.headersSent) res.writeHead(200, { "content-type": "application/octet-stream", "cache-control": "no-store" });
    };
    res.once("close", () => {
      if (!res.writableFinished && p.exitCode === null) p.kill("SIGTERM");
    });
    req.resume();
    p.stdout.on("data", (chunk: Buffer) => {
      head();
      if (!res.write(chunk)) {
        p.stdout.pause();
        res.once("drain", () => p.stdout.resume());
      }
    });
    p.once("error", () => reject(new TbError("backup_failed", "backup.dump could not start", 500)));
    p.once("close", (code) => {
      log.info("backup dump finished", { exitCode: code });
      if (code === 0) {
        head();
        res.end();
        return resolve();
      }
      if (res.headersSent) {
        res.destroy();
        return resolve();
      }
      reject(new TbError("backup_failed", "backup.dump failed", 500));
    });
  });
}
