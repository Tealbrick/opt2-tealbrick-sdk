// spec 0.1.68 (C336 RQ-3, S-8; MANIFEST M-OP-12, SDK-API v0.1.68): ops whose output carries a secret (e.g. a short-lived
// credential). One place for the flag and the fixed refusal/error texts; ops.ts and jobs.ts apply them.
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";

/** Reads `Operation.secretOutput` structurally (`// spec 0.1.68`) until the spec pin carries the field. */
export const isSecretOutput = (op: object | undefined): boolean => !!op && (op as { secretOutput?: unknown }).secretOutput === true;

/** The only receipt meta of a secretOutput op (plus an error code on a failed run): never output, never a message. */
export const SECRET_OUTPUT_META: Json = { secretOutput: true };

/** SDK-API v0.1.68 rule 4: the fixed message every handler error of a secretOutput op carries. */
export const SECRET_OUTPUT_ERROR_MESSAGE = "operation failed";

/** SDK-API v0.1.68 rule 1: agent callers are refused before the handler runs. */
export const secretOutputAppOnly = (): TbError => new TbError("secret_output_app_only", "this operation answers app callers only", 403);

/** SDK-API v0.1.68 rule 2. */
export const secretOutputNotSchedulable = (): TbError => new TbError("secret_output_not_schedulable", "this operation cannot be scheduled", 403);

/** SDK-API v0.1.68 rule 4: keep the code (and status), drop the message and every detail. */
export const secretOutputError = (e: TbError): TbError => new TbError(e.code, SECRET_OUTPUT_ERROR_MESSAGE, e.httpStatus);
