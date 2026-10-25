// node:http helpers: bounded bodies, JSON answers, the CORE §8 error envelope, cookies.
import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { envelope, TbError } from "./errors.ts";

export const MAX_BODY_BYTES = 4 * 1024 * 1024;

export function requestId(): string {
  return `req_${randomBytes(12).toString("base64url")}`;
}

/** The pathname of a request target, or "" when it does not parse (e.g. `//`); never throws (a throw in a listener stops the process). */
export function pathOf(target: string | undefined, base: string): string {
  return URL.canParse(target ?? "/", base) ? new URL(target ?? "/", base).pathname : "";
}

export async function readRaw(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<Buffer> {
  const declared = Number(req.headers["content-length"] ?? "0");
  if (declared > limit) throw new TbError("payload_too_large", "request body too large", 413);
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new TbError("payload_too_large", "request body too large", 413);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks);
}

export async function readJson(req: IncomingMessage, limit = MAX_BODY_BYTES): Promise<unknown> {
  const raw = await readRaw(req, limit);
  if (raw.length === 0) return {};
  try {
    return JSON.parse(raw.toString("utf8"));
  } catch {
    throw new TbError("input_invalid", "body is not JSON", 400);
  }
}

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string | string[]> = {}): void {
  if (res.headersSent) return;
  const text = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "content-length": Buffer.byteLength(text), ...headers });
  res.end(text);
}

export function sendError(res: ServerResponse, rid: string, e: unknown, headers: Record<string, string | string[]> = {}): void {
  const err = e instanceof TbError ? e : new TbError("internal_error", "internal error", 500);
  sendJson(res, err.httpStatus, envelope(err.code, err.message, rid, err.details), headers);
}

const HTML_ESCAPE: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => HTML_ESCAPE[c] ?? c);
}

/** Minimal HTML page (launch / standalone errors show the same codes as the JSON envelope, SDK-API §5). */
export function sendHtml(res: ServerResponse, status: number, title: string, body: string, headers: Record<string, string | string[]> = {}): void {
  if (res.headersSent) return;
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(title)}</title></head><body style="font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem">${body}</body></html>`;
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    ...headers,
  });
  res.end(html);
}

export function parseCookies(header: string | undefined): Map<string, string> {
  const out = new Map<string, string>();
  for (const part of (header ?? "").split(";")) {
    const i = part.indexOf("=");
    if (i < 1) continue;
    out.set(part.slice(0, i).trim(), part.slice(i + 1).trim());
  }
  return out;
}

export function header(req: IncomingMessage, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}
