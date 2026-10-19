// v0.1.25 (E2/M2, L3): failed-mode boot. A failure in the data phase (restore, schema check, migration lock, pre-update
// snapshot, SDK or app migrations) does NOT exit the process (Railway would restart it up to 10 times, Core would wait
// 6 minutes for a timeout). The SDK serves a minimal HTTP surface instead:
// - GET /tb/v1/health → 200 with `status: "failed"` and the machine-readable `failure` (same 200 contract as every other
//   health status: the body carries the state; Railway's healthcheck only proves the process is up),
// - GET /tb/v1/manifest → the manifest (the bridge may re-read it),
// - everything else → 503 `app_failed`.
// It pushes a status report to the bridge (when the instance has claimed): readiness `degraded` + attention
// (`failureAttention`) + the additive `failure` / `schemaVersion` fields, so Core's health gate fails the update at once.
import { createServer, type Server } from "node:http";
import { DatabaseSync } from "node:sqlite";
import { BRIDGE_INTERNAL_PATHS } from "@opt2-tealbrick/spec/bridge";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { BridgeClient, SDK_PROOF_CLAIMS } from "./bridge-client.ts";
import type { SdkConfig } from "./env.ts";
import { TbError } from "./errors.ts";
import { requestId, sendError, sendJson } from "./http.ts";
import { loadInstanceKey, type Sealer } from "./secrets.ts";
import { metaGet, type SchemaVersion } from "./store.ts";
import { type BootFailure, failureAttention, type PreUpdateSnapshot } from "./upgrade.ts";

/** Status push interval in failed mode (the bridge emits a Portal report when readiness/attention change). */
export const FAILED_PUSH_MS = 15_000;

export interface FailedBoot {
  manifest: Manifest;
  digest: `sha256:${string}`;
  sdkVersion: string;
  cfg: SdkConfig;
  log: Logger;
  sealer: Sealer;
  failure: BootFailure;
  /** what the data is at, when it could be read */
  schemaVersion: SchemaVersion | null;
  codeSchema: SchemaVersion;
  minCompatibleCode: string | null;
  preUpdateSnapshot: PreUpdateSnapshot | null;
  port: number;
}

export interface FailedHealth {
  status: "failed";
  sdk: string;
  version: string;
  manifestDigest: `sha256:${string}`;
  failure: BootFailure;
  attention: { code: string; reason: string };
  schemaVersion: SchemaVersion | null;
  codeSchema: SchemaVersion;
  minCompatibleCode: string | null;
  preUpdateSnapshot: Pick<PreUpdateSnapshot, "file" | "sha256" | "createdAt" | "from" | "to"> | null;
}

export function failedHealth(f: FailedBoot): FailedHealth {
  const s = f.preUpdateSnapshot;
  return {
    status: "failed",
    sdk: f.sdkVersion,
    version: f.manifest.version,
    manifestDigest: f.digest,
    failure: f.failure,
    attention: failureAttention(f.failure),
    schemaVersion: f.schemaVersion,
    codeSchema: f.codeSchema,
    minCompatibleCode: f.minCompatibleCode,
    preUpdateSnapshot: s ? { file: s.file, sha256: s.sha256, createdAt: s.createdAt, from: s.from, to: s.to } : null,
  };
}

/** The stored claim record, read only (the database may be half-migrated; nothing is written). */
function storedClaim(dataDir: string): { ins?: string; bridge?: { id?: string } } | null {
  let db: DatabaseSync | null = null;
  try {
    db = new DatabaseSync(`${dataDir}/app.db`, { readOnly: true });
    return metaGet(db, "claim");
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

export async function startFailedMode(f: FailedBoot): Promise<{ port: number; stop(): Promise<void> }> {
  const health = failedHealth(f);
  f.log.error("app failed to boot; serving failed mode (no ops, no UI)", { phase: f.failure.phase, code: f.failure.code, ...(f.failure.file ? { file: f.failure.file } : {}) });
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://app.internal").pathname;
    if (req.method === "GET" && path === "/tb/v1/health") return sendJson(res, 200, health);
    if (req.method === "GET" && path === "/tb/v1/manifest") return sendJson(res, 200, f.manifest);
    sendError(res, requestId(), new TbError("app_failed", `the app failed to boot (${f.failure.code}); only /tb/v1/health answers`, 503, { failure: f.failure }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(f.port, () => {
      server.off("error", reject);
      resolve();
    });
  });
  const addr = server.address();
  const port = addr && typeof addr === "object" ? addr.port : f.port;

  // status push: only for a claimed instance with a bridge (app-alone and unclaimed instances have health only)
  const stopper = new AbortController();
  let loop: Promise<void> = Promise.resolve();
  const claim = f.cfg.standalone || !f.cfg.bridgeUrl || !f.cfg.instanceId ? null : storedClaim(f.cfg.dataDir);
  if (claim?.bridge?.id && f.cfg.bridgeUrl && f.cfg.instanceId) {
    let client: BridgeClient | null = null;
    try {
      const key = await loadInstanceKey(f.cfg.dataDir, f.sealer);
      const bridgeId = claim.bridge.id as import("@opt2-tealbrick/spec/credentials").BridgeId;
      client = new BridgeClient({ baseUrl: f.cfg.bridgeUrl, instanceId: f.cfg.instanceId as InstanceId, key, bridgeId: () => bridgeId });
    } catch (e) {
      f.log.warn("failed mode: no status push (instance key unreadable)", { error: e instanceof Error ? e.message : "unknown" });
    }
    if (client) {
      const c = client;
      const body = {
        readiness: "degraded" as const,
        version: f.manifest.version,
        sdkVersion: f.sdkVersion,
        proofClaims: [...SDK_PROOF_CLAIMS],
        scopesRev: 0,
        sliceRevision: 0,
        keysRev: 0,
        pendingHolds: 0,
        attention: health.attention,
        // SPEC-GAP (E2, additive; bridge 0.1.29 forwards only `attention` to Portal): the machine-readable detail
        failure: f.failure,
        schemaVersion: f.schemaVersion,
        minCompatibleCode: f.minCompatibleCode,
        ...(health.preUpdateSnapshot ? { preUpdateSnapshot: health.preUpdateSnapshot } : {}),
      };
      loop = (async () => {
        while (!stopper.signal.aborted) {
          try {
            await c.request("POST", `${BRIDGE_INTERNAL_PATHS.status}?wait=0`, body, {}, stopper.signal);
          } catch (e) {
            if (stopper.signal.aborted) break;
            f.log.warn("failed mode: status push failed", { code: e instanceof TbError ? e.code : "error" });
          }
          await new Promise<void>((r) => {
            const t = setTimeout(r, FAILED_PUSH_MS);
            t.unref();
            stopper.signal.addEventListener(
              "abort",
              () => {
                clearTimeout(t);
                r();
              },
              { once: true },
            );
          });
        }
      })();
    }
  }
  return {
    port,
    async stop() {
      stopper.abort();
      await loop.catch(() => undefined);
      await new Promise<void>((r) => {
        server.close(() => r());
        server.closeAllConnections();
      });
    },
  };
}
