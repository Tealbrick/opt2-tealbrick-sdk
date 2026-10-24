// tb-gen: determinism, OpenAPI = server output, kit (compiles, typed client calls the right tools), docs, Railway
// template, drift check, refusals.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import { pathToFileURL } from "node:url";
import { STANDARD_OPERATIONS } from "@opt2-tealbrick/spec/manifest";
import { checkDrift, GEN_KINDS, generate, generateAll } from "../../src/gen/generate.ts";
import { buildKit, kitDirName, lazyPairDefs } from "../../src/gen/kit.ts";
import { fromManifest, GenError, loadManifest, stableJson, writeFiles } from "../../src/gen/load.ts";
import { parseTbGenArgs, runTbGen } from "../../src/gen/main.ts";
import { genRailway, KEK_SECRET, resolveSettings } from "../../src/gen/railway.ts";
import { defineApp, SDK_VERSION, startApp } from "../../src/server/index.ts";
import { fixtureManifest } from "../fixtures/manifest.ts";
import { freePort, migrationsDir } from "../helpers.ts";
import { notesJson, TB_GEN_CLI, TEMPLATE_ID, temp, templateJson, tree, writeRepo, writeTemplateRepo } from "./repos.ts";

const isGen = (code: string) => (e: unknown) => e instanceof GenError && e.code === code;
const cli = (args: string[], cwd: string) => spawnSync(process.execPath, [TB_GEN_CLI, ...args], { cwd, encoding: "utf8" });

function capture(argv: string[], cwd: string) {
  const out: string[] = [];
  const err: string[] = [];
  const code = runTbGen(argv, { cwd, out: (l) => out.push(l), err: (l) => err.push(l) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

describe("determinism", () => {
  test("two CLI runs of `all` are byte-identical (spec example and template)", (t) => {
    for (const write of [(d: string) => writeRepo(d, notesJson()), writeTemplateRepo]) {
      const dir = temp(t);
      write(dir);
      for (const out of ["a", "b"]) {
        const r = cli(["all", "--out", out], dir);
        assert.equal(r.status, 0, r.stderr);
      }
      const a = tree(join(dir, "a"));
      const b = tree(join(dir, "b"));
      assert.deepEqual([...a.keys()], [...b.keys()]);
      for (const [k, v] of a) assert.ok(v.equals(b.get(k) as Buffer), k);
      assert.ok(a.size >= 7);
      // JSON outputs have sorted keys and no timestamps
      for (const [k, v] of a) {
        if (k.endsWith(".json")) assert.equal(v.toString(), stableJson(JSON.parse(v.toString())), k);
        assert.doesNotMatch(v.toString(), /\b20\d\d-\d\d-\d\dT\d\d:/, k);
      }
    }
  });
});

describe("openapi", () => {
  test("equals what the running server serves at /tb/v1/openapi.json", async (t) => {
    const dir = temp(t);
    const port = await freePort();
    const manifest = fixtureManifest(port);
    const app = defineApp({
      manifest,
      migrations: migrationsDir(dir),
      handlers: {
        note_create: { scope: () => "nb", run: async () => ({ id: "x" }) },
        note_get: async () => ({}),
        note_delete: async () => ({}),
        notebook_rename: async () => ({}),
      },
    });
    // harness proc: never drop the (possibly root, in CI) test runner to uid 1000
    const running = await startApp(app, { TB_DATA_DIR: dir, TB_STANDALONE: "1", TB_LOG_LEVEL: "error" }, { privilegeProc: { getuid: () => 1000 } });
    try {
      const served = await (await fetch(`http://127.0.0.1:${port}/tb/v1/openapi.json`)).json();
      const [[name, text]] = [...generate("openapi", fromManifest(manifest))] as [[string, string]];
      assert.equal(name, "openapi.json");
      assert.deepEqual(JSON.parse(text), served);
    } finally {
      await running.stop();
    }
  });

  test("spec example: every op path, the SDK version, OpenAPI 3.1", () => {
    const doc = JSON.parse(generate("openapi", fromManifest(notesJson())).get("openapi.json") as string);
    assert.equal(doc.openapi, "3.1.0");
    assert.equal(doc.info["x-tealbrick-sdk"], SDK_VERSION);
    assert.ok(doc.paths["/tb/v1/ops/note_create"]);
    assert.ok(doc.paths["/a/notes/tb/v1/ops/notebook_rename"]);
    assert.ok(doc.paths["/tb/v1/ops/tb.hold_status"]);
    assert.equal(Object.keys(doc.paths).length, notesJson().operations.length + STANDARD_OPERATIONS.length);
  });
});

describe("kit", () => {
  test("package shape: name, private, manifest version, files", (t) => {
    const dir = temp(t);
    writeTemplateRepo(dir);
    const files = generate("kit", loadManifest(join(dir, "tealbrick.manifest.json")));
    const k = kitDirName(TEMPLATE_ID);
    assert.deepEqual([...files.keys()].sort(), [`${k}/README.md`, `${k}/package.json`, `${k}/src/index.ts`, `${k}/tsconfig.json`]);
    const pkg = JSON.parse(files.get(`${k}/package.json`) as string);
    assert.equal(pkg.name, `@opt2-tealbrick/${TEMPLATE_ID}-kit`);
    assert.equal(pkg.private, true);
    assert.equal(pkg.version, templateJson().version);
    assert.equal(pkg.dependencies, undefined);
    const src = files.get(`${k}/src/index.ts`) as string;
    assert.match(src, /itemsList: "demo-items__items_list"/);
    assert.match(src, /Call `demo-items__items_list` to see/, "skill text embedded raw (placeholders of the template substituted)");
    assert.match(src, /\{\{agent\.name\}\}/, "skill variables left unrendered");
    assert.match(files.get(`${k}/README.md`) as string, /`itemCreate` \| `demo-items__item_create` \| write \| required/);
  });

  test("C338 / QA-SDK48: TOOLS names = the bridge's tools/list rule; order, text, flags, annotations; --package-name in package.json, README and the CLI", (t) => {
    const dir = temp(t);
    const manifest = notesJson();
    // a workflow-listed op (QA-SDK48 mutant: listing flag)
    const firstAgent = manifest.operations.find((o: { audience: string; dynamic?: unknown }) => o.audience === "agent" && !o.dynamic) as { id: string };
    manifest.operations = manifest.operations.map((o) => (o.id === firstAgent.id ? { ...o, listing: "workflow" as const } : o));
    writeRepo(dir, manifest);
    const m = loadManifest(join(dir, "tealbrick.manifest.json"));
    const files = generate("kit", m, { packageName: "@tealbrick/notes" });
    const k = kitDirName(m.manifest.id);
    assert.equal(JSON.parse(files.get(`${k}/package.json`) as string).name, "@tealbrick/notes");
    assert.match(files.get(`${k}/README.md`) as string, /^# @tealbrick\/notes$/mu, "README names the package");
    const src = files.get(`${k}/src/index.ts`) as string;
    const marker = "export const TOOLS: readonly KitToolDef[] = ";
    const json = src.slice(src.indexOf(marker) + marker.length, src.indexOf("];", src.indexOf(marker)) + 1);
    const tools = JSON.parse(json) as { name: string; title: string; description: string; inputSchema: unknown; effect: string; listing?: string }[];
    // the bridge rule (bridge tools.ts buildToolIndex): agent static ops in manifest order, search-mode pairs, then per app
    // hold status (when the app has tb.hold_status) and skills; standard ops are never listed otherwise
    const p = m.manifest.id;
    const want: string[] = [];
    for (const o of m.manifest.operations) {
      if (o.audience !== "agent") continue;
      if (o.dynamic?.mode === "search") want.push(`${p}__${o.id}_search`, `${p}__${o.id}_call`);
      else if (!o.dynamic) want.push(`${p}__${o.id}`);
    }
    const names = tools.map((x) => x.name);
    assert.deepEqual(names.filter((n) => !n.endsWith("__tb_hold_status") && !n.endsWith("__tb_skills")), want, "static and search tools in manifest order");
    assert.ok(names.includes(`${p}__tb_hold_status`) && names.includes(`${p}__tb_skills`));
    assert.deepEqual(names.filter((n) => n.includes("__tb_")).sort(), [`${p}__tb_hold_status`, `${p}__tb_skills`], "no other tb_ tool (tb_holds_pending is never listed)");
    for (const o of m.manifest.operations.filter((x) => x.audience === "agent" && !x.dynamic)) {
      const def = tools.find((x) => x.name === `${p}__${o.id}`);
      assert.ok(def, o.id);
      assert.equal(def.description, o.description);
      assert.equal(def.title, o.title);
      assert.deepEqual(def.inputSchema, o.input ?? { type: "object" });
      assert.equal(def.effect, o.effect);
      assert.equal(def.listing, o.id === firstAgent.id ? "workflow" : undefined, o.id);
    }
    // annotations exactly as the bridge: three booleans for every effect
    assert.match(src, /readOnlyHint: effect === "read", destructiveHint: effect === "destructive", openWorldHint: effect === "outward" \|\| effect === "money"/u);
    // package name edges
    for (const bad of ["", "Not A Name", "@a.b/c", "@a/b.c", `@${"a".repeat(212)}/bb`, "@a/b/c", "notes"]) assert.throws(() => generate("kit", m, { packageName: bad }), isGen("package_name_invalid"), JSON.stringify(bad));
    assert.equal(JSON.parse(generate("kit", m).get(`${k}/package.json`) as string).name, `@opt2-tealbrick/${p}-kit`, "default name unchanged");
    // the CLI forwards the flag (and refuses an empty one)
    const out = join(dir, "gen-cli");
    const ok = capture(["kit", "--manifest", join(dir, "tealbrick.manifest.json"), "--out", out, "--package-name", "@tealbrick/notes"], dir);
    assert.equal(ok.code, 0, ok.err);
    assert.equal(JSON.parse(readFileSync(join(out, k, "package.json"), "utf8")).name, "@tealbrick/notes");
    assert.notEqual(capture(["kit", "--manifest", join(dir, "tealbrick.manifest.json"), "--out", out, "--package-name", ""], dir).code, 0);
  });

  test("QA-SDK48-5/-7/-8: lazy pair as the bridge lists it; tb-gen check honours --package-name; the skills tool schema", (t) => {
    assert.deepEqual(lazyPairDefs("knowledge", "Knowledge", []), []);
    const pair = lazyPairDefs("knowledge", "Knowledge", [
      { id: "a1", effect: "read" },
      { id: "a2", effect: "write" },
      { id: "a3", effect: "destructive" },
      { id: "a4", effect: "read" },
      { id: "a5", effect: "read" },
      { id: "a6", effect: "outward" },
    ]);
    assert.deepEqual(pair.map((d) => d.name), ["knowledge__tb_more_search", "knowledge__tb_more_call"]);
    assert.equal(pair[0]?.effect, "read");
    assert.match(pair[0]?.description ?? "", /6 not listed here \(e\.g\. a1, a2, a3, a4, a5, …\)/u);
    assert.equal(pair[1]?.effect, "destructive", "widest effect of the lazy ops");
    assert.deepEqual(pair[1]?.annotations, { readOnlyHint: false, destructiveHint: true, openWorldHint: true });
    assert.deepEqual(lazyPairDefs("k", "K", [{ id: "r", effect: "read" }])[1]?.annotations, { readOnlyHint: true, destructiveHint: false, openWorldHint: false });
    // -7: `check` with and without the flag
    const dir = temp(t);
    writeRepo(dir, notesJson());
    const manifest = join(dir, "tealbrick.manifest.json");
    const out = join(dir, "gen");
    assert.equal(capture(["all", "--manifest", manifest, "--out", out, "--package-name", "@tealbrick/notes"], dir).code, 0);
    assert.equal(capture(["check", "--manifest", manifest, "--package-name", "@tealbrick/notes"], dir).code, 0, "same name: no drift");
    assert.notEqual(capture(["check", "--manifest", manifest], dir).code, 0, "without the flag the committed kit drifts");
    // -8: the skills tool and its schema
    const m = loadManifest(manifest);
    const src = generate("kit", m).get(`${kitDirName(m.manifest.id)}/src/index.ts`) as string;
    const marker = "export const TOOLS: readonly KitToolDef[] = ";
    const tools = JSON.parse(src.slice(src.indexOf(marker) + marker.length, src.indexOf("];", src.indexOf(marker)) + 1)) as { name: string; inputSchema: unknown; effect: string }[];
    const skills = tools.find((x) => x.name === `${m.manifest.id}__tb_skills`);
    assert.deepEqual(skills?.inputSchema, { type: "object", additionalProperties: false, properties: { skillId: { type: "string", maxLength: 64 } } });
    assert.equal(skills?.effect, "read");
  });

  test("person-audience ops: PERSON_OPS, IDEMPOTENCY facts and the PersonOps io map (Connect request, BSA-08/12)", (t) => {
    const dir = temp(t);
    writeRepo(dir, notesJson());
    const m = loadManifest(join(dir, "tealbrick.manifest.json"));
    const src = generate("kit", m).get(`${kitDirName(m.manifest.id)}/src/index.ts`) as string;
    const person = m.manifest.operations.filter((o) => o.audience === "person");
    assert.ok(person.length > 0, "fixture has a person op");
    assert.ok(src.includes(`export const PERSON_OPS = ${JSON.stringify(person.map((o) => o.id))} as const;`));
    for (const o of m.manifest.operations) assert.match(src, new RegExp(`  ${o.id}: "${o.idempotency}",`));
    for (const o of person) assert.ok(src.includes(`"${o.id}": { input: `), o.id);
    assert.ok(!src.includes(`"${m.manifest.operations.find((o) => o.audience === "agent")?.id}": { input: `), "agent ops are not in PersonOps");
  });

  test("refuses a missing skill file", (t) => {
    const dir = temp(t);
    writeFileSync(join(dir, "tealbrick.manifest.json"), JSON.stringify(notesJson()));
    assert.throws(() => generate("kit", loadManifest(join(dir, "tealbrick.manifest.json"))), isGen("skill_file_missing"));
  });

  test("--build compiles with tsc and packs; the typed client calls the right tools with a fake MCP", async (t) => {
    const dir = temp(t);
    writeRepo(dir, notesJson());
    const r = capture(["kit", "--build"], dir);
    assert.equal(r.code, 0, r.err);
    const out = join(dir, "gen", "kit");
    const kitDir = join(out, kitDirName("notes"));
    assert.ok(existsSync(join(kitDir, "dist", "index.js")));
    assert.ok(existsSync(join(kitDir, "dist", "index.d.ts")));
    assert.ok(existsSync(join(out, "opt2-tealbrick-notes-kit-1.2.0.tgz")), r.out);

    // type-level: derived input types are enforced
    writeFileSync(
      join(kitDir, "check.ts"),
      `import { createKitClient, OP, type NoteCreateInput } from "./src/index.ts";
const kit = createKitClient({ callTool: async () => ({}) });
const ok: NoteCreateInput = { notebook: "n", title: "t", body: "b", tags: ["x"] };
void kit.noteCreate(ok, { idempotencyKey: "k-12345678" });
// @ts-expect-error idempotency is required for note_create
void kit.noteCreate(ok);
// @ts-expect-error title must be a string
void kit.noteCreate({ notebook: "n", title: 1, body: "b" }, { idempotencyKey: "k-12345678" });
// @ts-expect-error input is closed (additionalProperties: false)
void kit.noteCreate({ notebook: "n", title: "t", body: "b", extra: 1 }, { idempotencyKey: "k-12345678" });
void kit.noteGet({ id: "1" });
const op: "note_get" = OP.noteGet;
void op;
`,
    );
    writeFileSync(join(kitDir, "tsconfig.check.json"), JSON.stringify({ extends: "./tsconfig.json", compilerOptions: { noEmit: true, rootDir: ".", allowImportingTsExtensions: true }, include: ["src/**/*.ts", "check.ts"] }));
    const tsc = join(import.meta.dirname, "../../node_modules/typescript/bin/tsc");
    const typed = spawnSync(process.execPath, [tsc, "-p", join(kitDir, "tsconfig.check.json")], { encoding: "utf8" });
    assert.equal(typed.status, 0, typed.stdout + typed.stderr);

    // runtime: tool names, idempotency _meta, held results, errors
    const kit = await import(pathToFileURL(join(kitDir, "dist", "index.js")).href);
    const calls: { name: string; args: unknown; meta: unknown }[] = [];
    let next: unknown = { structuredContent: { id: "n1" } };
    const client = kit.createKitClient({
      callTool: async (name: string, args: unknown, meta?: unknown) => {
        calls.push({ name, args, meta });
        return next;
      },
    });
    assert.deepEqual(await client.noteCreate({ notebook: "a", title: "t", body: "b" }, { idempotencyKey: "idem-1" }), { status: "ok", output: { id: "n1" } });
    assert.deepEqual(calls[0], { name: "notes__note_create", args: { notebook: "a", title: "t", body: "b" }, meta: { "tealbrick/idempotencyKey": "idem-1" } });
    next = { content: [{ type: "text", text: '{"hits":[]}' }] };
    assert.deepEqual(await client.noteSearch({ query: "q" }), { status: "ok", output: { hits: [] } });
    assert.deepEqual(calls[1], { name: "notes__note_search", args: { query: "q" }, meta: undefined });
    const held = { status: "held", holdId: "hld_1", expiresAt: "x", checkWith: "notes__tb_hold_status" };
    next = { structuredContent: held };
    assert.deepEqual(await client.noteDelete({ id: "1" }), held);
    next = { structuredContent: { status: "pending", expiresAt: "x" } };
    await client.tbHoldStatus({ holdId: "hld_1" });
    assert.equal(calls.at(-1)?.name, "notes__tb_hold_status");
    next = { isError: true, structuredContent: { error: { code: "scope_denied", message: "no", requestId: "req_1" } } };
    await assert.rejects(client.noteGet({ id: "1" }), (e: { name: string; code: string; requestId: string }) => e.name === "KitError" && e.code === "scope_denied" && e.requestId === "req_1");
    assert.equal(client.notebookRename, undefined, "person ops are not MCP tools");
    assert.equal(kit.TOOL.noteFromEvent, "notes__note_from_event");
    assert.equal(kit.SKILLS.length, 2);
    assert.match(kit.SKILLS[0].text, /\{\{agent\.name\}\}/);
  });

  test("dynamic ops: search → _search/_call methods, list → entry method", async (t) => {
    const m = notesJson();
    m.skills = [];
    m.unlocks = [];
    m.operations.push(
      { id: "tools", title: "Tools", description: "Search and call tools.", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "search", crudCeiling: ["read", "create"], effectCeiling: "write" } },
      { id: "engine", title: "Engine", description: "Engine ops.", crud: ["read"], effect: "read", idempotency: "supported", receipt: false, audience: "agent", dynamic: { mode: "list", crudCeiling: ["read"], effectCeiling: "read" } },
    );
    const dir = temp(t);
    const files = generate("kit", fromManifest(m, dir));
    writeFiles(dir, files);
    const kitDir = join(dir, kitDirName("notes"));
    buildKit(kitDir, dir, import.meta.dirname);
    const kit = await import(pathToFileURL(join(kitDir, "dist", "index.js")).href);
    const names: [string, unknown][] = [];
    const client = kit.createKitClient({
      callTool: async (name: string, args: unknown) => {
        names.push([name, args]);
        return { structuredContent: [] };
      },
    });
    await client.toolsSearch({ query: "mail" });
    await client.toolsCall({ tool: "send_mail", arguments: { to: "x" } });
    await client.engineTool("vacuum", { full: true });
    assert.deepEqual(names, [
      ["notes__tools_search", { query: "mail" }],
      ["notes__tools_call", { tool: "send_mail", arguments: { to: "x" } }],
      ["notes__vacuum", { full: true }],
    ]);
    assert.equal(kit.TOOL.tools, undefined);
    assert.equal(kit.toolName("x"), "notes__x");
  });
});

describe("docs", () => {
  test("mention every operation, scopes, settings, keys, hooks, skills, backups and runtime", () => {
    const m = notesJson();
    const md = generate("docs", fromManifest(m)).get("notes.md") as string;
    for (const op of m.operations) assert.match(md, new RegExp(`\`${op.id}\``), op.id);
    for (const id of STANDARD_OPERATIONS) assert.ok(md.includes(`\`${id}\``), id);
    for (const s of ["notes__note_create", "first_contact", "`read_write`", "own → `read_write`", "`search_index`", "app: NOTES_DEFAULT_FORMAT", "`OPENAI_API_KEY`", "account_default", "`secret_guard`", "`notes-summaries`", "17 3 * * *", "attachments", "`search`", "8080", "/tb/v1/health", "Companion `calendar`", "/p/notes/inbound/email"])
      assert.ok(md.includes(s), s);
    assert.match(md, /\| `note_delete` \| Delete note \| agent \| `notes__note_delete` \| delete \| destructive \| destructive \| supported \| yes \| notebook \|/);
  });

  test("template manifest docs", () => {
    const md = generate("docs", fromManifest(templateJson())).get(`${TEMPLATE_ID}.md`) as string;
    assert.match(md, /`items_list`/);
    assert.match(md, /`item_create`/);
    assert.match(md, /`use-demo-items`/);
  });
});

describe("railway", () => {
  const template = (files: Map<string, string>) => JSON.parse(files.get("template.json") as string);
  const allValues = (svc: { variables: Record<string, string> }[]) => svc.flatMap((s) => Object.values(s.variables));

  test("one volume per service, no public domain, TB_KEK generated, private-network references", () => {
    const files = genRailway(fromManifest(notesJson()), { settings: { search_index: "fulltext" } });
    const tpl = template(files);
    assert.deepEqual(
      tpl.services.map((s: { name: string; role: string; startOrder: number }) => [s.name, s.role, s.startOrder]),
      [
        ["notes-search", "service", 0],
        ["notes", "app", 1],
      ],
    );
    for (const s of tpl.services) {
      assert.equal(s.publicDomain, false, s.name);
      assert.equal(Object.hasOwn(s, "domains"), false);
      assert.ok(s.volume === null || (typeof s.volume.mountPath === "string" && !Array.isArray(s.volume)), s.name);
    }
    const [search, app] = tpl.services;
    assert.deepEqual(app.volume, { mountPath: "/data", sizeGb: 15 });
    assert.equal(app.variables.TB_DATA_DIR, "/data");
    assert.equal(app.variables.TB_BACKUP_DIR, "/data/backup");
    assert.equal(app.variables.TB_KEK, KEK_SECRET);
    assert.equal(app.variables.NOTES_SEARCH_URL, "http://${{notes-search.RAILWAY_PRIVATE_DOMAIN}}:7700");
    assert.equal(app.variables.NOTES_SEARCH_MASTER_KEY, "${{notes-search.MEILI_MASTER_KEY}}");
    assert.equal(app.variables.NOTES_DEFAULT_FORMAT, "markdown");
    assert.equal(app.healthcheck.path, "/tb/v1/health");
    assert.equal(app.internalPort, 8080);
    assert.deepEqual(search.volume, { mountPath: "/meili_data", sizeGb: 2 });
    assert.equal(search.source.image, notesJson().runtime.services?.[0]?.image);
    assert.equal(search.variables.MEILI_MASTER_KEY, "${{secret(48)}}");
    assert.equal(search.variables.TB_KEK, undefined, "upstream images get no TB_* env");
    assert.deepEqual(search.healthcheck, { type: "http", path: "/health" });
    assert.ok(tpl.notes.some((n: string) => /bridge/.test(n)), "notes say a bridge is needed for agents");
    for (const v of allValues(tpl.services)) assert.doesNotMatch(v, /\{\{services\./);
    assert.doesNotMatch(files.get("template.json") as string, /OPENAI_API_KEY/, "keys never travel as env");
    const cfg = JSON.parse(files.get("railway.json") as string);
    assert.equal(cfg.$schema, "https://railway.com/railway.schema.json");
    assert.deepEqual(cfg.build, { builder: "DOCKERFILE", dockerfilePath: "Dockerfile" });
    assert.equal(cfg.deploy.healthcheckPath, "/tb/v1/health");
  });

  test("defaults omit a service whose `when` is false and every env entry referencing it", () => {
    const tpl = template(genRailway(fromManifest(notesJson())));
    assert.deepEqual(
      tpl.services.map((s: { name: string }) => s.name),
      ["notes"],
    );
    assert.equal(tpl.services[0].variables.NOTES_SEARCH_URL, undefined);
    assert.equal(tpl.settings.search_index, "builtin");
    assert.ok(tpl.notes.some((n: string) => n.includes("search")));
  });

  test("a tb-exec (build) service gets TB_KEK, TB_SERVICE and a 1 GB data volume", () => {
    const m = notesJson();
    const svc = m.runtime.services?.[0] as unknown as Record<string, unknown>;
    delete svc.image;
    delete svc.volumes;
    svc.build = { context: ".", dockerfile: "services/search.Dockerfile" };
    const tpl = template(genRailway(fromManifest(m), { settings: { search_index: "fulltext" } }));
    const search = tpl.services[0];
    assert.deepEqual(search.volume, { mountPath: "/data", sizeGb: 1 });
    assert.equal(search.variables.TB_SERVICE, "search");
    assert.equal(search.variables.TB_KEK, KEK_SECRET);
    assert.equal(search.variables.TB_DATA_DIR, "/data");
    assert.deepEqual(search.source, { repo: m.source.repo, rootDirectory: ".", dockerfilePath: "services/search.Dockerfile" });
  });

  test("template manifest: app only, data + backup merged into one volume", () => {
    const tpl = template(genRailway(fromManifest(templateJson())));
    assert.equal(tpl.services.length, 1);
    assert.deepEqual(tpl.services[0].volume, { mountPath: "/data", sizeGb: 3 });
    assert.equal(tpl.services[0].name, TEMPLATE_ID);
  });

  test("setting overrides are checked against the field", () => {
    const m = fromManifest(notesJson()).manifest;
    assert.deepEqual(resolveSettings(m, { summaries: "true" }).summaries, true);
    assert.throws(() => resolveSettings(m, { nope: "1" }), isGen("setting_unknown"));
    assert.throws(() => resolveSettings(m, { search_index: "semantic" }), isGen("setting_invalid"), "disabled choice");
    assert.throws(() => resolveSettings(m, { summaries: "yes" }), isGen("setting_invalid"));
  });
});

describe("check (drift, CONFORMANCE M4)", () => {
  test("no gen/ passes; regenerated gen/ passes; edited, extra and missing files fail", (t) => {
    const dir = temp(t);
    writeRepo(dir, notesJson());
    const lm = loadManifest(join(dir, "tealbrick.manifest.json"));
    assert.deepEqual(checkDrift(lm, join(dir, "gen")), { present: false, compared: [], differences: [] });
    assert.equal(capture(["check"], dir).code, 0);

    assert.equal(capture(["all"], dir).code, 0);
    let r = capture(["check"], dir);
    assert.equal(r.code, 0, r.err);
    assert.match(r.out, /ok \(openapi, kit, docs, railway\)/);

    writeFileSync(join(dir, "gen/docs/notes.md"), "hand edited\n");
    writeFileSync(join(dir, "gen/openapi/extra.json"), "{}\n");
    rmSync(join(dir, "gen/railway/railway.json"));
    mkdirSync(join(dir, "gen/kit/notes-kit/dist"), { recursive: true });
    writeFileSync(join(dir, "gen/kit/notes-kit/dist/index.js"), "build output is not compared");
    r = capture(["check"], dir);
    assert.equal(r.code, 1);
    assert.deepEqual(checkDrift(lm, join(dir, "gen")).differences, ["extra openapi/extra.json", "differs docs/notes.md", "missing railway/railway.json"]);
    assert.match(r.err, /differs docs\/notes\.md/);

    // a manifest change is drift too
    const changed = notesJson();
    changed.version = "1.2.1";
    writeRepo(dir, changed);
    rmSync(join(dir, "gen"), { recursive: true });
    assert.equal(capture(["all"], dir).code, 0);
    writeRepo(dir, notesJson());
    assert.ok(checkDrift(loadManifest(join(dir, "tealbrick.manifest.json")), join(dir, "gen")).differences.length >= GEN_KINDS.length);
  });

  test("generateAll lays out <kind>/<file>", (t) => {
    const dir = temp(t);
    writeTemplateRepo(dir);
    const all = generateAll(loadManifest(join(dir, "tealbrick.manifest.json")));
    assert.ok(all.has("openapi/openapi.json"));
    assert.ok(all.has(`kit/${TEMPLATE_ID}-kit/src/index.ts`));
    assert.ok(all.has(`docs/${TEMPLATE_ID}.md`));
    assert.ok(all.has("railway/template.json"));
  });
});

describe("refusals and CLI", () => {
  test("an invalid manifest is refused with the validator errors and nothing is written", (t) => {
    const dir = temp(t);
    const bad = notesJson();
    (bad.operations[0] as { effect: string }).effect = "read";
    writeRepo(dir, bad);
    for (const cmd of ["openapi", "kit", "docs", "railway", "all", "check"]) {
      const r = cli([cmd], dir);
      assert.equal(r.status, 1, cmd);
      assert.match(r.stderr, /manifest_invalid/, cmd);
      assert.match(r.stderr, /\/operations\/0.*effect_crud_mismatch/, cmd);
    }
    assert.equal(existsSync(join(dir, "gen")), false);
    assert.throws(() => fromManifest({ schema: "nope" }), (e: unknown) => isGen("manifest_invalid")(e) && (e as GenError).issues.length > 0);
  });

  test("unreadable or non-JSON manifest; usage errors exit 2", (t) => {
    const dir = temp(t);
    assert.throws(() => loadManifest(join(dir, "missing.json")), isGen("manifest_unreadable"));
    writeFileSync(join(dir, "x.json"), "{");
    assert.throws(() => loadManifest(join(dir, "x.json")), isGen("manifest_invalid"));
    assert.equal(capture(["docs", "--manifest", "missing.json"], dir).code, 1);
    for (const argv of [[], ["bogus"], ["docs", "--build"], ["openapi", "--set", "a=b"], ["railway", "--set", "novalue"], ["docs", "--out"], ["docs", "--wat"]]) {
      const r = capture(argv, dir);
      assert.equal(r.code, 2, JSON.stringify(argv));
      assert.match(r.err, /usage: tb-gen/);
    }
  });

  test("parseTbGenArgs and per-kind output dirs", (t) => {
    assert.deepEqual(parseTbGenArgs(["railway", "--manifest", "m.json", "--out", "o", "--set", "a=b=c"]), { command: "railway", manifest: "m.json", repo: null, out: "o", build: false, settings: { a: "b=c" }, packageName: null });
    assert.equal(parseTbGenArgs(["kit", "--package-name", "@tealbrick/notes"]).packageName, "@tealbrick/notes");
    assert.throws(() => parseTbGenArgs(["openapi", "--package-name", "@tealbrick/notes"]), /unknown flag --package-name/u);
    assert.equal(parseTbGenArgs(["kit", "--build"]).build, true);
    assert.equal(parseTbGenArgs(["all", "--repo", "../.."]).repo, "../..");
    const dir = temp(t);
    writeTemplateRepo(dir);
    const r = cli(["docs"], dir);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stdout.trim(), `gen/docs/${TEMPLATE_ID}.md`);
    assert.equal(cli(["openapi", "--out", "custom"], dir).stdout.trim(), "custom/openapi.json");
    assert.ok(readFileSync(join(dir, "custom/openapi.json"), "utf8").startsWith("{\n"));
  });
});
