// C390 (knowledge#38): why a private-network call failed, as a short label for logs and error details. A fetch failure
// hides the reason in `cause` (undici: `cause.code`, or an AggregateError of both address families). Labels only:
// never a message, a URL or a body (they can carry the address or the upstream answer).

const CODE = /^[A-Z][A-Z0-9_]{1,47}$/u;

function codeOf(e: unknown): string | null {
  if (!e || typeof e !== "object") return null;
  const code = (e as { code?: unknown }).code;
  if (typeof code === "string" && CODE.test(code)) return code;
  const errors = (e as { errors?: unknown }).errors;
  if (Array.isArray(errors)) for (const inner of errors) {
    const c = codeOf(inner);
    if (c) return c;
  }
  return null;
}

/** `timeout`, `aborted`, a system/undici code (`ECONNREFUSED`, `ENOTFOUND`, `UND_ERR_CONNECT_TIMEOUT`, …) or `fetch_failed`. */
export function netCause(e: unknown): string {
  const name = e && typeof e === "object" ? (e as { name?: unknown }).name : undefined;
  if (name === "TimeoutError") return "timeout";
  if (name === "AbortError") return "aborted";
  return codeOf((e as { cause?: unknown } | null)?.cause) ?? codeOf(e) ?? "fetch_failed";
}
