// Person sign-in — ONE module `personAuth` (SDK-API §5, §12, CREDENTIALS §12): launch ticket redeemer, one session
// cookie, one CSRF header, one principal shape. App-alone mode mints a K11-shaped ticket and uses the same redeemer.
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { promisify } from "node:util";
import { digestEqual, type Ed25519KeyPair, opaqueDigest, signTicket, ulid, verifyTicket } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import { LIFETIME_S, type PersonId } from "@opt2-tealbrick/spec/credentials";
import type { AuditLog, Logger, PersonPrincipal, SessionInfo } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import { escapeHtml, header, parseCookies, readRaw, requestId, sendError, sendHtml, sendJson } from "./http.ts";
import { metaGet, metaSet, type RawDb, type Row } from "./store.ts";
import type { TrustState } from "./trust.ts";

export const SESSION_COOKIE = "tb_session" as const;
export const CSRF_HEADER = BRIDGE_HEADERS.csrf;

const scrypt = promisify(scryptCb) as (pw: string, salt: Buffer, len: number, opts: { N: number; r: number; p: number; maxmem: number }) => Promise<Buffer>;
const SCRYPT = { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SETUP_CODE_TTL_MS = 24 * 3600_000;
const PASSPHRASE_MIN = 12;
const TRIES_PER_MIN = 5;
const SAFE_PATH = /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*$/;

/**
 * `GET /a/<product>/tb/v1/session` answer: SessionInfo plus `idempotencyRequired`, the person-audience operation ids
 * whose manifest says `idempotency: "required"` — the client `callOp` adds a key itself for them (C53 / BSA-12).
 * SPEC-GAP: additive field, not yet in types/sdk.ts `SessionInfo` (SDK-API §14).
 */
/** spec 0.1.7: SessionInfo carries `idempotencyRequired` itself. */
export type SessionAnswer = SessionInfo;

interface StandaloneState {
  per: PersonId;
  setupDigest: string | null;
  setupExp: number | null;
  passHash: string | null;
}

export interface PersonAuth {
  readonly base: string;
  handleLaunch(req: IncomingMessage, res: ServerResponse): Promise<void>;
  handleSession(req: IncomingMessage, res: ServerResponse): Promise<void>;
  handleLogout(req: IncomingMessage, res: ServerResponse): Promise<void>;
  handleStandalone(req: IncomingMessage, res: ServerResponse): Promise<void>;
  /** session cookie → principal + CSRF token; throws `session_required` */
  requireSession(req: IncomingMessage): SessionInfo;
  /** non-GET under /a/<product>/: `TB-CSRF` equals the session token and `Origin` = request host; throws `csrf_invalid` */
  requireCsrf(req: IncomingMessage, s: SessionInfo): void;
  /** v0.1.13: the same check for a form POST (no script, CSP): the session CSRF token in a form field + same Origin */
  requireCsrfToken(req: IncomingMessage, s: SessionInfo, token: string | undefined): void;
  /** app-alone mode: prints a setup code at first boot or with TB_STANDALONE_RESET=1 */
  standaloneBoot(reset: boolean): void;
  sweep(nowMs: number): void;
}

function sha256(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

/** `Origin` must name the host the request was made to (the bridge sets X-Forwarded-Host when it proxies). */
export function sameOrigin(req: IncomingMessage): boolean {
  const origin = header(req, "origin");
  if (!origin) return false;
  const host = header(req, "x-forwarded-host") ?? header(req, "host");
  try {
    return host !== undefined && new URL(origin).host === host;
  } catch {
    return false;
  }
}

export function createPersonAuth(opts: {
  db: RawDb;
  product: string;
  launchPath: string;
  trust: TrustState;
  audit: AuditLog;
  log: Logger;
  instanceKey: Ed25519KeyPair;
  standalone: boolean;
  /** person-audience op ids with `idempotency: "required"` (sent in the session answer) */
  idempotencyRequired: readonly string[];
}): PersonAuth {
  const { db, trust, audit } = opts;
  const base = `/a/${opts.product}`;
  const cookieAttrs = `Path=${base}/; HttpOnly; Secure; SameSite=Lax`;
  let tries: number[] = [];

  const location = (path: string | undefined): string => {
    if (path && SAFE_PATH.test(path) && !path.startsWith("//") && !path.split(/[/?]/).includes("..")) return `${base}${path}`;
    return `${base}${opts.launchPath.startsWith("/") ? opts.launchPath : `/${opts.launchPath}`}`;
  };

  /** The ONE redeemer: verifyTicket, one-time jti, session row, cookie. */
  const redeem = async (ticket: string, nowMs: number): Promise<{ cookie: string; location: string }> => {
    const ctx = trust.context(nowMs);
    if (!ctx) throw new TbError("ticket_invalid", "no trusted issuer yet (instance not claimed)", 401);
    const v = verifyTicket(ticket, ctx);
    if (!v.ok) throw new TbError("ticket_invalid", "launch ticket is not valid", 401);
    const c = v.claims;
    const per = c.sub.slice("tb:per:".length) as PersonId;
    if (!/^per_[0-7][0-9A-HJKMNP-TV-Z]{25}$/.test(per)) throw new TbError("ticket_invalid", "launch ticket subject is not a person", 401);
    const used = db.prepare("INSERT OR IGNORE INTO tb_used_jti (jti, exp) VALUES (?, ?)").run(c.jti, c.exp + 30);
    if (Number(used.changes) !== 1) throw new TbError("ticket_used", "launch ticket was already used", 401);
    const value = randomBytes(32).toString("base64url");
    const csrf = randomBytes(32).toString("base64url");
    const expiresAt = nowMs + LIFETIME_S.appUiSession * 1000;
    db.prepare("INSERT INTO tb_sessions (digest, person, ws, instance, iss, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(
      sha256(value),
      per,
      c.ws,
      trust.instanceId,
      c.iss,
      csrf,
      nowMs,
      expiresAt,
    );
    await audit.record({ actor: per, action: "session.signin", target: trust.instanceId, detail: { iss: c.iss } });
    return { cookie: `${SESSION_COOKIE}=${value}; ${cookieAttrs}; Max-Age=${LIFETIME_S.appUiSession}`, location: location(c.path) };
  };

  const lookup = (req: IncomingMessage, nowMs: number): (SessionInfo & { digest: string }) | null => {
    const value = parseCookies(header(req, "cookie")).get(SESSION_COOKIE);
    if (!value || value.length > 128) return null;
    const digest = sha256(value);
    const r = db.prepare("SELECT * FROM tb_sessions WHERE digest = ?").get(digest) as Row | undefined;
    if (!r || Number(r.expires_at) <= nowMs || r.instance !== trust.instanceId) return null;
    const nbf = trust.slice?.personNbf ?? 0;
    if (Math.floor(Number(r.created_at) / 1000) < nbf) return null;
    const principal: PersonPrincipal = {
      type: "person",
      id: String(r.person) as PersonId,
      ws: String(r.ws) as PersonPrincipal["ws"],
      instance: trust.instanceId,
      iss: String(r.iss) as PersonPrincipal["iss"],
      sessionExpiresAt: Number(r.expires_at),
    };
    return { principal, csrf: String(r.csrf), idempotencyRequired: [...opts.idempotencyRequired], digest };
  };

  const formField = async (req: IncomingMessage, names: string[]): Promise<Record<string, string>> => {
    const raw = (await readRaw(req, 64 * 1024)).toString("utf8");
    const type = header(req, "content-type") ?? "";
    const params = type.startsWith("application/json") ? new URLSearchParams(Object.entries(JSON.parse(raw || "{}") as Record<string, string>)) : new URLSearchParams(raw);
    const out: Record<string, string> = {};
    for (const n of names) {
      const v = params.get(n);
      if (v !== null) out[n] = v;
    }
    return out;
  };

  const failPage = (res: ServerResponse, e: unknown) => {
    const err = e instanceof TbError ? e : new TbError("internal_error", "internal error", 500);
    sendHtml(res, err.httpStatus, "Sign-in failed", `<h1>Sign-in failed</h1><p>${escapeHtml(err.message)}</p><p><code>${escapeHtml(err.code)}</code></p>`);
  };

  const standaloneState = (): StandaloneState | null => metaGet<StandaloneState>(db, "standalone");

  const standalonePage = (res: ServerResponse, status: number, note?: string) => {
    const st = standaloneState();
    const setup = !st?.passHash || st.setupDigest !== null;
    const codeField = setup ? `<p><label>Setup code<br><input name="code" autocomplete="one-time-code" required></label></p>` : "";
    sendHtml(
      res,
      status,
      "Sign in",
      `<h1>${setup ? "Set up" : "Sign in"}</h1>${note ? `<p><code>${escapeHtml(note)}</code></p>` : ""}<form method="post">${codeField}<p><label>Passphrase (at least ${PASSPHRASE_MIN} characters)<br><input name="passphrase" type="password" minlength="${PASSPHRASE_MIN}" required autocomplete="${setup ? "new-password" : "current-password"}"></label></p><p><button type="submit">Continue</button></p></form>`,
    );
  };

  const hashPassphrase = async (pw: string): Promise<string> => {
    const salt = randomBytes(16);
    const h = await scrypt(pw, salt, 32, SCRYPT);
    return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64url")}$${h.toString("base64url")}`;
  };
  const checkPassphrase = async (pw: string, stored: string): Promise<boolean> => {
    const [alg, n, r, p, salt, hash] = stored.split("$");
    if (alg !== "scrypt" || !salt || !hash) return false;
    const want = Buffer.from(hash, "base64url");
    const got = await scrypt(pw, Buffer.from(salt, "base64url"), want.length, { N: Number(n), r: Number(r), p: Number(p), maxmem: SCRYPT.maxmem });
    return got.length === want.length && timingSafeEqual(got, want);
  };

  return {
    base,
    async handleLaunch(req, res) {
      try {
        const { ticket } = await formField(req, ["ticket"]);
        if (!ticket) throw new TbError("ticket_invalid", "form field ticket is missing", 400);
        const r = await redeem(ticket, Date.now());
        res.writeHead(303, { location: r.location, "set-cookie": r.cookie, "cache-control": "no-store" });
        res.end();
      } catch (e) {
        failPage(res, e);
      }
    },
    async handleSession(req, res) {
      const rid = requestId();
      const s = lookup(req, Date.now());
      if (!s) return sendError(res, rid, new TbError("session_required", "sign in through Portal", 401));
      sendJson(res, 200, { principal: s.principal, csrf: s.csrf, idempotencyRequired: [...opts.idempotencyRequired] } satisfies SessionAnswer);
    },
    async handleLogout(req, res) {
      const rid = requestId();
      try {
        const s = lookup(req, Date.now());
        if (!s) throw new TbError("session_required", "no session", 401);
        this.requireCsrf(req, s);
        db.prepare("DELETE FROM tb_sessions WHERE digest = ?").run(s.digest);
        await audit.record({ actor: s.principal.id, action: "session.signout", target: trust.instanceId, detail: null });
        sendJson(res, 200, { ok: true }, { "set-cookie": `${SESSION_COOKIE}=; ${cookieAttrs}; Max-Age=0` });
      } catch (e) {
        sendError(res, rid, e);
      }
    },
    async handleStandalone(req, res) {
      if (!opts.standalone) return sendError(res, requestId(), new TbError("not_found", "not found", 404));
      if (req.method === "GET") return standalonePage(res, 200);
      try {
        if (!sameOrigin(req)) throw new TbError("csrf_invalid", "Origin does not match the host", 403);
        const st = standaloneState();
        if (!st) throw new TbError("standalone_not_ready", "standalone sign-in is not set up", 503);
        const f = await formField(req, ["code", "passphrase"]);
        const pw = f.passphrase ?? "";
        const now = Date.now();
        if (st.setupDigest !== null || !st.passHash) {
          const code = (f.code ?? "").replace(/[^0-9a-f]/gi, "").toUpperCase();
          const valid = st.setupDigest !== null && st.setupExp !== null && st.setupExp > now && digestEqual(opaqueDigest(code), st.setupDigest);
          if (!valid) throw new TbError("ticket_invalid", "setup code is not valid", 401);
          if (pw.length < PASSPHRASE_MIN) throw new TbError("passphrase_too_short", `passphrase needs at least ${PASSPHRASE_MIN} characters`, 400);
          metaSet(db, "standalone", { ...st, setupDigest: null, setupExp: null, passHash: await hashPassphrase(pw) } satisfies StandaloneState);
        } else {
          tries = tries.filter((t) => t > now - 60_000);
          if (tries.length >= TRIES_PER_MIN) throw new TbError("rate_limited", "too many tries, wait a minute", 429);
          tries.push(now);
          if (!(await checkPassphrase(pw, st.passHash))) throw new TbError("ticket_invalid", "passphrase is not valid", 401);
        }
        const ws = trust.ws;
        if (!ws) throw new TbError("standalone_not_ready", "standalone identity missing", 503);
        const iat = Math.floor(now / 1000);
        // SPEC-GAP: SDK-API §12 mints iss = tb:ins:<id>, but PersonTicketLaunchClaims types iss as Portal | bridge only.
        const ticket = await signTicket({ iss: trust.self as unknown as "tb:portal", sub: `tb:per:${st.per}`, aud: trust.self, iat, exp: iat + LIFETIME_S.ticketLaunch, ws, pur: "launch" }, opts.instanceKey);
        const r = await redeem(ticket, now);
        res.writeHead(303, { location: r.location, "set-cookie": r.cookie, "cache-control": "no-store" });
        res.end();
      } catch (e) {
        if (e instanceof TbError && e.httpStatus < 500) return standalonePage(res, e.httpStatus, e.code);
        failPage(res, e);
      }
    },
    requireSession(req) {
      const s = lookup(req, Date.now());
      if (!s) throw new TbError("session_required", "sign in through Portal", 401);
      return { principal: s.principal, csrf: s.csrf, idempotencyRequired: s.idempotencyRequired };
    },
    requireCsrf(req, s) {
      this.requireCsrfToken(req, s, header(req, CSRF_HEADER));
    },
    requireCsrfToken(req, s, token) {
      if (!token || !digestEqual(token, s.csrf) || !sameOrigin(req)) throw new TbError("csrf_invalid", "TB-CSRF header or Origin missing or wrong", 403);
    },
    standaloneBoot(reset) {
      const st = standaloneState();
      if (st?.passHash && !reset) return;
      const raw = randomBytes(10).toString("hex").toUpperCase();
      const code = raw.match(/.{5}/g)?.join("-") ?? raw;
      metaSet(db, "standalone", {
        per: st?.per ?? (`per_${ulid()}` as PersonId),
        setupDigest: opaqueDigest(raw),
        setupExp: Date.now() + SETUP_CODE_TTL_MS,
        passHash: st?.passHash ?? null,
      } satisfies StandaloneState);
      // Deliberate one-time print to stdout (SDK-API §12); stored only as SHA-256.
      process.stdout.write(`tealbrick standalone setup code (valid 24 h, open ${base}/tb/standalone): ${code}\n`);
    },
    sweep(nowMs) {
      db.prepare("DELETE FROM tb_used_jti WHERE exp < ?").run(Math.floor(nowMs / 1000));
      db.prepare("DELETE FROM tb_sessions WHERE expires_at <= ?").run(nowMs);
    },
  };
}
