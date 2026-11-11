// Small node:http + fetch helpers shared by the fakes and the checks: bounded bodies, the CORE §8 error envelope,
// and an HTTP client that never follows redirects and always returns the raw answer for assertions.
import { randomBytes } from "node:crypto";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import type { ErrorEnvelope } from "@opt2-tealbrick/spec/bridge";

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

export function requestId(): string {
  return `req_${randomBytes(12).toString("base64url")}`;
}

/** Thrown inside a fake's handler; mapped to the CORE §8 envelope. */
export class HttpError extends Error {
  readonly code: string;
  readonly status: number;
  /** conformance 0.1.31: `error.details` of the envelope (e.g. `{ pointer }` of an `input_invalid`) */
  readonly details: Record<string, unknown> | undefined;
  constructor(status: number, code: string, message: string, details?: Record<string, unknown>) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

export async function readRaw(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, "payload_too_large", "request body too large");
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export function parseJson(raw: Buffer): unknown {
  if (raw.length === 0) return undefined;
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new HttpError(400, "input_invalid", "body is not JSON");
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  if (res.headersSent) return;
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  res.end(text);
}

export function sendError(res: ServerResponse, status: number, code: string, message: string, details?: Record<string, unknown>): void {
  const body = { error: { code, message, requestId: requestId(), ...(details ? { details } : {}) } } as ErrorEnvelope<string>;
  sendJson(res, status, body);
}

export function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/** Listens on 127.0.0.1 with an OS-assigned port; resolves the origin. */
export function listen(server: Server, port = 0): Promise<string> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const a = server.address();
      if (!a || typeof a === "string") return reject(new Error("no address"));
      resolve(`http://127.0.0.1:${a.port}`);
    });
  });
}

export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.closeAllConnections();
    server.close(() => resolve());
  });
}

// ── client ───────────────────────────────────────────────────────────────────
export interface HttpAnswer {
  status: number;
  headers: Headers;
  /** parsed JSON when the body is JSON, else the text ("" when empty) */
  body: unknown;
  text: string;
  bytes: Uint8Array;
}

export async function request(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string | Uint8Array; timeoutMs?: number } = {},
): Promise<HttpAnswer> {
  const res = await fetch(url, {
    method: init.method ?? "GET",
    headers: init.headers,
    body: init.body as BodyInit | undefined,
    redirect: "manual",
    signal: AbortSignal.timeout(init.timeoutMs ?? 15_000),
  });
  const bytes = new Uint8Array(await res.arrayBuffer());
  const text = new TextDecoder().decode(bytes);
  let body: unknown = text;
  if ((res.headers.get("content-type") ?? "").includes("json") && text !== "") {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  return { status: res.status, headers: res.headers, body, text, bytes };
}

/** `error.code` of a CORE §8 envelope, or null when the body is not one. */
export function errorCode(body: unknown): string | null {
  const e = (body as { error?: { code?: unknown; message?: unknown; requestId?: unknown } } | null)?.error;
  return e && typeof e.code === "string" && typeof e.message === "string" && typeof e.requestId === "string" ? e.code : null;
}
