// S-PO (conformance 0.1.31, spec 0.1.64, SDK-API §21, CREDENTIALS K14, C326): the app's private `POST /tb/v1/person-op`, driven
// the way the workspace bridge forwards a relayed person op. The suite plays Core: every K14 is signed with the fake bridge's Portal
// key (the key the app trusts for `iss tb:portal`). The rows apply to an app that DECLARES the `person_op` capability (spec 0.1.69,
// C354) in its claim or its latest status push; any other app gets not_applicable (by capability, never by version). The probe op of the token rows is `tb.export`: it is on no product's
// PERSON_OP_RELAY.allow entry, so a K14 that passes every token and digest check is answered 403 person_op_not_allowed (the
// positive control), and a refusal at an earlier step is 401 person_op_invalid (CHECK ORDER of SDK-API §21).
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { ulid, withStandardOps } from "@opt2-tealbrick/manifest";
import { PERSON_OP_RELAY } from "@opt2-tealbrick/spec/routes";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { errorCode, type HttpAnswer } from "../http.ts";
import { declaredAppCaps, mintPersonOp, newIdk, PERSON_OP_APP_CAP, PERSON_OP_HEADER, PERSON_OP_ROUTE, type PersonOpMint } from "../person-op.ts";
import { sampleInput } from "../sample.ts";
import { bad, na, notRun, type Outcome, type Suite, verdict } from "../suite.ts";
import { newId, nowS } from "../tokens.ts";
import type { AppTargetContext } from "./app.ts";

export const PERSON_OP_APP_TITLES = {
  "S-PO-1": "a K11 launch ticket in TB-Person-Op → 401 person_op_invalid",
  "S-PO-2": "a K14 for another instance (aud) → 401 person_op_invalid",
  "S-PO-3": "a K14 of a foreign workspace (ws) → 401 person_op_invalid",
  "S-PO-4": "bd ≠ sha256 of the body → 401, and the jti is spent (the same K14 with the right body → 401)",
  "S-PO-5": "the same K14 twice → the replay is 401 person_op_invalid",
  "S-PO-6": "an op outside PERSON_OP_RELAY.allow (tb.key_set, tb.export, another product's op, an unlisted own op) → 403 person_op_not_allowed",
  "S-PO-7": "cli tbd or cli, on a read and a write op → 401 person_op_invalid, no handler run, the jti not spent",
  "S-PO-8": "family rule: a hold decision relayed with via tbm and family money / destructive / unknown → 403 family_needs_portal",
  "S-PO-9": "a K14 whose exp is 5 s in the past → 401 (the general 30 s leeway does not apply)",
  "S-PO-10": "app-alone mode (TB_STANDALONE=1) → 503 person_op_unavailable",
  "S-PO-11": "the same idk twice (two K14s) → one effect: the second answer is the stored first one",
  "S-PO-12": "an answered Inbox ask never releases an SDK hold (Inbox-specific)",
} as const;
type Row = keyof typeof PERSON_OP_APP_TITLES;

export interface PersonOpAppDeps {
  /** the op's fixture input (tealbrick-conformance.json `inputs.<op>`, placeholders resolved), else undefined */
  fixture(opId: string): Json | undefined;
}

/** token rows probe this op: never on an allow-list entry (SDK-API §21: key, export and scope ops never travel the relay) */
const PROBE_OP = "tb.export";

export async function personOpAppChecks(s: Suite, ctx: AppTargetContext, deps: PersonOpAppDeps): Promise<void> {
  const b = ctx.bridge;
  const m = ctx.manifest;
  const c = () => ctx.client();
  const T = ctx.timeoutMs;
  // the raw `caps` member (spec 0.1.69 ClaimRequest.caps / AppStatus.caps; the pinned 0.1.64 types do not name it)
  const rawCaps = (v: unknown): unknown => (v && typeof v === "object" ? (v as { caps?: unknown }).caps : undefined);
  const gate = (): Outcome | null => {
    const claim = rawCaps(b.claims.at(-1)?.request);
    const status = rawCaps(b.statuses.filter((x) => x.ins === b.ids.ins).at(-1)?.status);
    if (declaredAppCaps(claim).includes(PERSON_OP_APP_CAP) || declaredAppCaps(status).includes(PERSON_OP_APP_CAP)) return null;
    return na(
      `the app does not declare the ${PERSON_OP_APP_CAP} capability (claim caps ${JSON.stringify(claim ?? null)}, latest status caps ${JSON.stringify(status ?? null)}): POST ${PERSON_OP_ROUTE} is not announced, so this row does not apply (decided by capability, never by version, C354)`,
    );
  };
  const row = (id: Row, expected: string, fn: () => Promise<Outcome> | Outcome) => s.run(id, PERSON_OP_APP_TITLES[id], expected, async () => gate() ?? fn());

  const mint = (o: Partial<PersonOpMint> & { op: string; body: string }) => mintPersonOp({ key: b.activePortalKey(), ws: b.ids.ws, ins: b.ids.ins, person: b.ids.person, ...o });
  const send = (jws: string, body: string): Promise<HttpAnswer> => c().post(PERSON_OP_ROUTE, body, { [PERSON_OP_HEADER]: jws });
  const show = (a: HttpAnswer) => {
    const code = errorCode(a.body);
    if (code) return `${a.status} ${code}`;
    const st = (a.body as { status?: unknown } | null)?.status;
    return typeof st === "string" ? `${a.status} ${st}` : `${a.status} ${typeof a.body === "string" ? a.body.slice(0, 40) : "(no error envelope)"}`;
  };
  const is = (a: HttpAnswer, status: number, code: string) => a.status === status && errorCode(a.body) === code;
  const invalid = (a: HttpAnswer) => is(a, 401, "person_op_invalid");
  const notAllowed = (a: HttpAnswer) => is(a, 403, "person_op_not_allowed");
  /** positive control: a K14 that passes every token and digest check (optionally with a given jti) reaches the allow-list → 403 */
  const control = async (jti?: string): Promise<{ ok: boolean; shown: string }> => {
    const t = await mint({ op: PROBE_OP, body: "{}", ...(jti ? { jti } : {}) });
    const a = await send(t.jws, "{}");
    return { ok: notAllowed(a), shown: show(a) };
  };

  const personOps = withStandardOps(m).filter((o) => o.audience === "person");
  const own = PERSON_OP_RELAY.allow.find((a) => a.product === m.id);
  const isRead = (o: { crud: readonly string[] }) => o.crud.length > 0 && o.crud.every((x) => x === "read");
  const readOp = (own?.read as readonly string[] | undefined)?.[0] ?? personOps.find((o) => !o.standard && isRead(o))?.id ?? "items_list";
  const writeOp = (own?.write as readonly string[] | undefined)?.[0] ?? personOps.find((o) => !o.standard && !isRead(o))?.id ?? "item_ack";

  await row("S-PO-1", "a launch ticket (K11, typ tb-person-ticket) for this instance in TB-Person-Op → 401 person_op_invalid; control: a valid K14 → 403 person_op_not_allowed", async () => {
    const ticket = await b.mint.launchTicket({ person: b.ids.person, aud: `tb:ins:${b.ids.ins}` });
    const a = await send(ticket, "{}");
    const k = await control();
    return verdict(invalid(a) && k.ok, `launch ticket: ${show(a)}; control K14: ${k.shown}`);
  });
  await row("S-PO-2", "a K14 with aud = another instance id → 401 person_op_invalid; control → 403", async () => {
    const t = await mint({ op: PROBE_OP, body: "{}", aud: `tb:ins:${newId("ins")}` });
    const a = await send(t.jws, "{}");
    const k = await control();
    return verdict(invalid(a) && k.ok, `aud of another instance: ${show(a)}; control: ${k.shown}`);
  });
  await row("S-PO-3", "a K14 whose ws is another workspace → 401 person_op_invalid; control → 403", async () => {
    const t = await mint({ op: PROBE_OP, body: "{}", wsClaim: newId("ws") });
    const a = await send(t.jws, "{}");
    const k = await control();
    return verdict(invalid(a) && k.ok, `foreign ws: ${show(a)}; control: ${k.shown}`);
  });
  await row("S-PO-4", "a K14 bound to body A sent with body B → 401 person_op_invalid; the same K14 with body A → 401 (jti spent before the body check); a fresh K14 with body A → 403", async () => {
    const body = `{"tbconf":"bd-${ulid()}"}`;
    const t = await mint({ op: PROBE_OP, body });
    const wrong = await send(t.jws, `{"tbconf":"other-${ulid()}"}`);
    const again = await send(t.jws, body);
    const fresh = await send((await mint({ op: PROBE_OP, body })).jws, body);
    return verdict(invalid(wrong) && invalid(again) && notAllowed(fresh), `other body: ${show(wrong)}; same K14, right body: ${show(again)}; fresh K14: ${show(fresh)}`);
  });
  await row("S-PO-5", "a valid K14 → 403 person_op_not_allowed (past the token checks); the same K14 again → 401 person_op_invalid", async () => {
    const t = await mint({ op: PROBE_OP, body: "{}" });
    const first = await send(t.jws, "{}");
    const replay = await send(t.jws, "{}");
    return verdict(notAllowed(first) && invalid(replay), `first: ${show(first)}; replay: ${show(replay)}`);
  });
  await row("S-PO-6", "valid K14s (cli tbm, right bd) for tb.key_set, tb.export, an op of another product's allow entry and an own person op not on the list → each 403 person_op_not_allowed", async () => {
    const otherProduct = PERSON_OP_RELAY.allow.find((a) => a.product !== m.id);
    const listed = new Set<string>([...((own?.read as readonly string[] | undefined) ?? []), ...((own?.write as readonly string[] | undefined) ?? [])]);
    const unlisted = personOps.find((o) => !o.standard && !listed.has(o.id))?.id;
    const ops = ["tb.key_set", "tb.export", ...(otherProduct ? [otherProduct.read[0] as string] : []), ...(unlisted ? [unlisted] : [])].filter((x, i, all) => all.indexOf(x) === i && !listed.has(x));
    const seen: string[] = [];
    let pass = true;
    for (const op of ops) {
      const t = await mint({ op, body: "{}" });
      const a = await send(t.jws, "{}");
      seen.push(`${op} → ${show(a)}`);
      pass &&= notAllowed(a);
    }
    return verdict(pass && ops.length >= 2, seen.join("; "));
  });
  await row("S-PO-7", `cli tbd and cli on the read op ${readOp} and the write op ${writeOp} → each 401 person_op_invalid; then a cli tbm K14 with the SAME jti → 403 (the refused jti was not spent)`, async () => {
    const seen: string[] = [];
    let pass = true;
    for (const cli of ["tbd", "cli"]) {
      for (const op of [readOp, writeOp]) {
        const jti = ulid();
        const body = JSON.stringify(deps.fixture(op) ?? {});
        const a = await send((await mint({ op, body, cli, jti })).jws, body);
        const k = await control(jti);
        seen.push(`${cli} ${op} → ${show(a)}, same jti as tbm → ${k.shown}`);
        pass &&= invalid(a) && k.ok;
      }
    }
    return verdict(pass, seen.join("; "));
  });
  await row("S-PO-8", "not observable in the generic suite", () => {
    const decide = PERSON_OP_RELAY.allow.filter((a) => (a.write as readonly string[]).includes("tb.holds_decide")).map((a) => a.product);
    return na(
      `no held decision reaches this app through the relay: tb.holds_decide is on the PERSON_OP_RELAY.allow entry of ${decide.length ? decide.join(", ") : "no product"} (spec 0.1.64), and an app op that decides an item carrying a hold (Inbox item_decide, C277 A3) is product-specific; the family rule is covered by the miniapp-sdk tests (familyAllowedFor) and the Inbox suite`,
    );
  });
  await row("S-PO-9", `two K14s with iat = now − 6: exp = now − 5 → 401 person_op_invalid (only PERSON_OP_RELAY.expLeewayS = ${PERSON_OP_RELAY.expLeewayS} s applies, not the general 30 s); exp = now − 1 (inside the ${PERSON_OP_RELAY.expLeewayS} s) → 403 person_op_not_allowed, so the refusal is the expiry's`, async () => {
    // both K14s share iat, so only exp differs; iat must not fall before the slice personNbf (A6.person_nbf set it a moment ago)
    const wait = (b.personNbf - (nowS() - 7)) * 1000;
    if (wait > 0) await new Promise((r) => setTimeout(r, Math.min(wait, 10_000)));
    const now = nowS();
    const expired = await send((await mint({ op: PROBE_OP, body: "{}", iat: now - 6, exp: now - 5 })).jws, "{}");
    const inLeeway = await send((await mint({ op: PROBE_OP, body: "{}", iat: now - 6, exp: now - 1 })).jws, "{}");
    return verdict(invalid(expired) && notAllowed(inLeeway), `exp 5 s ago: ${show(expired)}; exp 1 s ago (inside the leeway): ${show(inLeeway)}`);
  });
  await row("S-PO-10", "the app restarted with TB_STANDALONE=1 on a fresh data dir: a valid K14 → 503 person_op_unavailable; restarted back, it pushes its status again", async () => {
    if (!ctx.restart) return notRun("needs a restartable app (runApp start()/--cmd) to start it in app-alone mode");
    const fresh = join(ctx.env.TB_DATA_DIR as string, "person-op-standalone");
    mkdirSync(join(fresh, "backup"), { recursive: true });
    let a: HttpAnswer | null = null;
    let why = "";
    try {
      await ctx.restart({ TB_STANDALONE: "1", TB_DATA_DIR: fresh, TB_BACKUP_DIR: join(fresh, "backup") });
      const t = await mint({ op: PROBE_OP, body: "{}" });
      a = await send(t.jws, "{}");
    } catch (e) {
      why = e instanceof Error ? e.message : String(e);
    }
    const n = b.statuses.length;
    await ctx.restart();
    const back = await b.control.waitForStatus((x) => b.statuses.indexOf(x) >= n && x.status.sliceRevision >= b.sliceRev, T).then(
      () => true,
      () => false,
    );
    if (!a) return bad(`app-alone start failed: ${why}`);
    return verdict(is(a, 503, "person_op_unavailable") && back, `app-alone: ${show(a)}; back in bridge mode: ${back ? "status pushed with the current slice" : "NO status push"}`);
  });
  await row("S-PO-11", "the same idk in two K14s (same body) for an allow-listed write op → both 200, the second answer equals the first (the stored result, not a second run)", async () => {
    const op = ((own?.write as readonly string[] | undefined) ?? []).map((id) => personOps.find((o) => o.id === id)).find((o) => o !== undefined);
    if (!op)
      return na(
        `product ${m.id} has no write op on PERSON_OP_RELAY.allow that its manifest declares as a person op (spec 0.1.64 lists ${PERSON_OP_RELAY.allow.map((a) => `${a.product}: ${a.write.join(", ")}`).join("; ")}): no relayed write to repeat`,
      );
    const fx = deps.fixture(op.id);
    const input = fx ?? sampleInput(m.operations.find((o) => o.id === op.id)?.input ?? { type: "object" }, "tbconf");
    const body = JSON.stringify(input);
    const idk = newIdk();
    const a1 = await send((await mint({ op: op.id, body, idk })).jws, body);
    if (a1.status !== 200) return notRun(`the relayed ${op.id} with the ${fx ? "fixture" : "generated"} input answered ${show(a1)}: this row needs an input the op accepts (tealbrick-conformance.json inputs.${op.id})`);
    const a2 = await send((await mint({ op: op.id, body, idk })).jws, body);
    const same = JSON.stringify(a1.body) === JSON.stringify(a2.body);
    return verdict(a2.status === 200 && same, `${op.id}: first ${show(a1)}; same idk again ${show(a2)}, answer ${same ? "= the first" : `≠ the first (${JSON.stringify(a1.body).slice(0, 60)} vs ${JSON.stringify(a2.body).slice(0, 60)})`}`);
  });
  await row("S-PO-12", "Inbox-specific", () =>
    na("an Inbox ask and its link to an SDK hold (C277 A3) exist only in the Inbox app: checked by the Inbox suite, not the generic app suite"),
  );
}
