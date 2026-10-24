// The two private-network listeners of tb-exec, both callable only by the own app instance (instance assertion):
// - helper proxy on manifest `helper.port` (C6): declared paths only, forwarded to `--helper-target` (loopback);
// - control port 7077 (SDK-API §11): `POST /tb/v1/exec/backup` streams `backup.dump` stdout,
//   `POST /tb/v1/exec/restore` runs `backup.restore` with the body on stdin.
import { spawn } from "node:child_process";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, request, type Server, type ServerResponse } from "node:http";
import type { ServiceBackup } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";
import { MAX_BODY_BYTES, pathOf, readRaw, requestId, sendError, sendJson } from "../server/http.ts";
import type { AppAssertionVerifier } from "./verify.ts";

export const HELPER_TIMEOUT_MS = 30_000;
/**
 * SPEC-GAP: the assertion's `bd` binds the whole restore body, so tb-exec must hold it before it may run `restore`;
 * streaming restores of any size need a digest-based verify input in the manifest package. Until then: bounded.
 */
export const RESTORE_MAX_BYTES = 512 * 1024 * 1024;
export const CONTROL_PATHS = { backup: "/tb/v1/exec/backup", restore: "/tb/v1/exec/restore" } as const;

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
  /** current child env (the dump/restore commands run with the same env as the upstream) */
  env: () => Record<string, string>;
  log: Logger;
}

export function startControlServer(o: ControlOptions): Promise<Server> {
  let busy = false;
  const server = createServer(async (req, res) => {
    const rid = requestId();
    // an unparseable target (e.g. `//`) is an unknown route: `new URL` throwing here was an unhandled rejection that stopped the process
    const path = pathOf(req.url, "http://control");
    const kind = path === CONTROL_PATHS.backup ? "backup" : path === CONTROL_PATHS.restore ? "restore" : null;
    try {
      if (!kind || req.method !== "POST") throw new TbError("not_found", "unknown control route", 404);
      const body = await readRaw(req, kind === "restore" ? RESTORE_MAX_BYTES : 64 * 1024);
      o.verify(req, body);
      if (!o.backup) throw new TbError("backup_undeclared", "this service declares no backup", 404);
      if (busy) throw new TbError("busy", "a backup or restore is already running", 409);
      busy = true;
      try {
        if (kind === "backup") await runDump(o.backup.dump, o.env(), req, res, o.log);
        else {
          await runRestore(o.backup.restore, o.env(), body, o.log);
          sendJson(res, 200, { ok: true });
        }
      } finally {
        busy = false;
      }
    } catch (e) {
      sendError(res, rid, e);
    }
  });
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

function runRestore(argv: string[], env: Record<string, string>, body: Buffer, log: Logger): Promise<void> {
  return new Promise((resolve, reject) => {
    const [file, ...args] = argv as [string, ...string[]];
    const p = spawn(file, args, { env, stdio: ["pipe", "inherit", "inherit"] });
    p.stdin.once("error", () => {}); // an early exit closes stdin; the exit code decides
    p.once("error", () => reject(new TbError("restore_failed", "backup.restore could not start", 500)));
    p.once("close", (code) => {
      log.info("backup restore finished", { exitCode: code });
      if (code === 0) resolve();
      else reject(new TbError("restore_failed", "backup.restore failed", 500));
    });
    p.stdin.end(body);
  });
}
