// TbError and the ONE error envelope (CORE §8). Handlers throw TbError; the SDK maps it to the envelope.

export class TbError extends Error {
  readonly code: string;
  readonly httpStatus: number;
  readonly details: Record<string, unknown> | undefined;
  constructor(code: string, message: string, httpStatus = 400, details?: Record<string, unknown>) {
    super(message);
    this.name = "TbError";
    this.code = code;
    this.httpStatus = httpStatus;
    this.details = details;
  }
}

export function isTbError(e: unknown): e is TbError {
  return e instanceof TbError;
}

/** CORE §8 envelope; `details` only when the caller passed some. */
export function envelope(code: string, message: string, requestId: string, details?: Record<string, unknown>): { error: { code: string; message: string; requestId: string; details?: Record<string, unknown> } } {
  return { error: details ? { code, message, requestId, details } : { code, message, requestId } };
}

/** v0.1.26 (LA-1, MANIFEST v0.1.43): the code an app answers while `ctx.viewUrl` is null (Core has not created tb-views yet). */
export const VIEW_ORIGIN_MISSING = "view_origin_missing";

/** 409 `view_origin_missing`. */
export function viewOriginMissing(): TbError {
  return new TbError(VIEW_ORIGIN_MISSING, "the viewer address is not ready yet (no views service for this workspace)", 409);
}

/**
 * v0.1.26 (LA-1): the views origin of `ctx`, or throws 409 `view_origin_missing` while it is null. Use it before building
 * a viewer link: `const base = requireViewUrl(ctx)`.
 */
export function requireViewUrl(ctx: { viewUrl?: string | null }): string {
  if (typeof ctx.viewUrl !== "string" || ctx.viewUrl === "") throw viewOriginMissing();
  return ctx.viewUrl;
}
