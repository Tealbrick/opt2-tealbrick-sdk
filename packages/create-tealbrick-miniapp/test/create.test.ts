import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { validateAppFiles, validateManifest } from "@opt2-tealbrick/manifest";
import { CreateError, createMiniapp, defaultName, PLACEHOLDER, renderTemplate, TEMPLATE_DIR } from "../src/create.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const PLATFORM_CI = fileURLToPath(new URL("../../../../opt2-tealbrick-platform/ci/woodpecker/ci.yaml", import.meta.url));
const PLATFORM_GH = fileURLToPath(new URL("../../../../opt2-tealbrick-platform/ci/github/opt2-release.yml", import.meta.url));
// same rule as the platform CI setup step (ci/tb-ci.ts RELEASE_URL_RE)
const RELEASE_URL_RE =
  /^https:\/\/github\.com\/(?:Martin-Atrin|Tealbrick)\/opt2-tealbrick-[a-z0-9-]+\/releases\/download\/[a-z0-9-]+-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\/[a-z0-9-]+-\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.tgz$/;

function temp(t: TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), "create-tb-miniapp-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function walk(dir: string, base = dir): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name), base) : [join(dir, e.name).slice(base.length + 1)]));
}

const read = (dir: string, rel: string) => readFileSync(join(dir, rel), "utf8");
const readJson = <T = Record<string, any>>(dir: string, rel: string) => JSON.parse(read(dir, rel)) as T;

function rejectsWith(code: string) {
  return (e: unknown) => e instanceof CreateError && e.code === code;
}

describe("createMiniapp", () => {
  it("writes a scaffold whose manifest and app files validate", async (t) => {
    const dir = join(temp(t), "my-notes");
    const r = createMiniapp({ dir, id: "my-notes", name: "My Notes" });
    assert.equal(r.dir, dir);
    assert.equal(r.name, "My Notes");
    for (const f of [
      "tealbrick.manifest.json",
      "src/app.ts",
      "src/main.ts",
      "src/items.ts",
      "src/ui/main.tsx",
      "src/ui/App.tsx",
      "src/ui/index.html",
      "src/ui/standard.tsx",
      "src/ui/pages.css",
      "migrations/0001_init.sql",
      "skills/use-my-notes/SKILL.md",
      "Dockerfile",
      ".woodpecker/ci.yaml",
      ".github/workflows/opt2-release.yml",
      "tealbrick-ci.json",
      "biome.json",
      "tsconfig.json",
      "package.json",
      "test/app.test.ts",
      "test/ui-holds.test.ts",
      ".gitignore",
      ".dockerignore",
      "README.md",
      "LICENSE",
      "NOTICE",
      "THIRD_PARTY_NOTICES.md",
    ])
      assert.ok(r.files.includes(f), `scaffold has ${f}`);
    assert.deepEqual(walk(dir).sort(), r.files);

    const manifest = readJson(dir, "tealbrick.manifest.json");
    const v = validateManifest(manifest);
    assert.equal(v.ok, true, v.ok ? "" : JSON.stringify(v.errors));
    if (!v.ok) return;
    assert.equal(v.manifest.id, "my-notes");
    assert.equal(v.manifest.name, "My Notes");
    const files = await validateAppFiles(v.manifest, dir);
    assert.equal(files.ok, true, files.ok ? "" : JSON.stringify(files.errors));

    // starter content the template promises (SDK-API §15, C28)
    const ops = v.manifest.operations;
    assert.deepEqual(
      ops.map((o) => [o.id, o.crud.join(","), o.idempotency]),
      [
        ["items_list", "read", "none"],
        ["item_create", "create", "required"],
      ],
    );
    assert.deepEqual(
      v.manifest.runtime.volumes.map((x) => x.purpose),
      ["data", "backup"],
    );
    assert.equal(v.manifest.scopes?.length, 1);
    assert.ok((v.manifest.scopes?.[0]?.defaultGrants.length ?? 0) > 0);
    assert.ok(v.manifest.backups.schedule && v.manifest.backups.retain > 0);
    assert.equal(v.manifest.ui?.launchPath, "/");
  });

  it("leaves no placeholder in any path or file", (t) => {
    const dir = join(temp(t), "app");
    const r = createMiniapp({ dir, id: "zz-top", name: "ZZ Top" });
    for (const f of r.files) {
      assert.doesNotMatch(f, PLACEHOLDER, f);
      assert.doesNotMatch(read(dir, f), PLACEHOLDER, f);
    }
    assert.match(read(dir, "src/ui/main.tsx"), /product="zz-top"/);
    assert.match(read(dir, "src/ui/index.html"), /<base href="\/a\/zz-top\/" \/>/);
  });

  it("ships pnpm-lock.yaml with sha512 integrity for every release-URL tarball (ci-v8; no tealbrick-integrity.json)", (t) => {
    const dir = join(temp(t), "app");
    const r = createMiniapp({ dir, id: "pin-check" });
    assert.ok(r.files.includes("pnpm-lock.yaml"));
    assert.ok(!r.files.includes("tealbrick-integrity.json"), "retired in ci-v8");
    const lock = readFileSync(join(dir, "pnpm-lock.yaml"), "utf8");
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
    for (const url of Object.values({ ...pkg.dependencies, ...pkg.devDependencies }).filter((u) => u.startsWith("https://github.com/"))) {
      const at = lock.indexOf(`tarball: ${url}`);
      assert.ok(at >= 0, `lockfile resolves ${url}`);
      assert.match(lock.slice(Math.max(0, at - 200), at + url.length + 200), /integrity: sha512-/, `integrity for ${url}`);
    }
  });

  it("follows the platform CI standard and the release-URL dependency rule", (t) => {
    const dir = join(temp(t), "app");
    createMiniapp({ dir, id: "tasks", name: "Tasks" });
    const pkg = readJson(dir, "package.json");
    assert.equal(pkg.name, "opt2-tealbrick-tasks");
    assert.equal(pkg.private, true);
    assert.equal(pkg.publishConfig, undefined);
    assert.match(pkg.packageManager, /^pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}$/, "ci-v8: packageManager pinned by hash");
    assert.match(readFileSync(join(dir, "Dockerfile"), "utf8"), /RUN pnpm install --frozen-lockfile --ignore-scripts/, "ci-v8: image installs never run scripts");
    for (const s of ["typecheck", "lint", "test", "conformance", "build", "gen"]) assert.equal(typeof pkg.scripts[s], "string", `script ${s}`);
    assert.equal(pkg.scripts.conformance, "node --run kit && tb-conformance app --start conformance.start.ts --manifest tealbrick.manifest.json --test-roots");
    // BSA-12: op ids and I/O types come from the generated kit, generated before every step that compiles or runs src
    assert.equal(pkg.scripts.kit, "tb-gen kit && tsc -p gen/kit/tasks-kit --outDir dist/kit");
    assert.deepEqual(pkg.imports, { "#kit": "./dist/kit/index.js" });
    for (const s of ["start", "typecheck", "test", "conformance", "build"]) assert.match(pkg.scripts[s], /^node --run kit && /, `script ${s}`);
    const app = read(dir, "src/app.ts");
    assert.match(app, /^import \{[^}]*\bOP\b[^}]*\} from "#kit";$/m);
    assert.match(app, /\[OP\.itemsList\]/);
    assert.match(app, /satisfies Record<OpId, HandlerSpec>/);
    assert.doesNotMatch(app, /\binterface \w+(Input|Output)\b/, "no hand-written I/O types");
    // generated artifacts (SDK-API §15): produced by tb-gen, never committed
    assert.equal(pkg.scripts.gen, "tb-gen all");
    assert.ok(read(dir, ".gitignore").split("\n").includes("gen/"), "gen/ is gitignored");
    // the conformance harness the script names: default-exports start(env) with backupNow (A7 round-trip)
    const harness = read(dir, "conformance.start.ts");
    assert.match(harness, /export default async function start\(env/);
    assert.match(harness, /startApp\(app, env, harness\)/);
    assert.match(harness, /backupNow/);
    const tb = Object.entries<string>({ ...pkg.dependencies, ...pkg.devDependencies }).filter(([n]) => n.startsWith("@opt2-tealbrick/"));
    assert.deepEqual(tb.map(([n]) => n).sort(), ["@opt2-tealbrick/conformance", "@opt2-tealbrick/manifest", "@opt2-tealbrick/miniapp-sdk", "@opt2-tealbrick/ui"]);
    for (const [n, url] of tb) assert.match(url, RELEASE_URL_RE, n);
    assert.match(pkg.devDependencies["@opt2-tealbrick/ui"], /[/-]ui-v0\.3\.0\//);
    assert.match(pkg.dependencies["@opt2-tealbrick/manifest"], /[/-]manifest-v0\.1\.26\//);
    assert.match(pkg.dependencies["@opt2-tealbrick/miniapp-sdk"], /[/-]miniapp-sdk-v0\.1\.34\//);
    assert.match(pkg.devDependencies["@opt2-tealbrick/conformance"], /[/-]conformance-v0\.1\.23\//);
    // BSA-07: the ONE app shell from ui, no local frame
    const ui = read(dir, "src/ui/App.tsx");
    assert.match(ui, /import \{[^}]*\bAppShell\b[^}]*\} from "@opt2-tealbrick\/ui";/);
    assert.match(ui, /<AppShell\b/);
    assert.doesNotMatch(ui, /SPEC-GAP|function Frame\b/);
    // C150: the header is in the app's colour with its art; the standard pages are the template's single copy
    assert.match(ui, /colour=\{appColour\("tasks"\)\}/);
    assert.match(ui, /art=\{appArt\("tasks", STILLS\)\}/);
    assert.match(ui, /from "\.\/standard\.tsx"/);
    assert.equal(pkg.scripts.lint, "biome check . && check-system src", "the kit guard runs in CI through lint");

    const ci = readJson(dir, "tealbrick-ci.json");
    assert.equal(ci.kind, "miniapp");
    assert.deepEqual(ci.images, [{ name: "opt2-tealbrick-tasks", product: "tasks", kind: "app", manifest: "tealbrick.manifest.json" }]);
    const pipeline = read(dir, ".woodpecker/ci.yaml");
    assert.match(pipeline, /GENERATED from (?:Martin-Atrin|Tealbrick)\/opt2-tealbrick-platform: ci\/woodpecker\/ci\.yaml/);
    if (existsSync(PLATFORM_CI)) assert.equal(pipeline, readFileSync(PLATFORM_CI, "utf8"), "byte-identical copy of the platform template");
    // ci-v9 (C72): releases publish through GitHub Actions with the built-in token
    if (existsSync(PLATFORM_GH)) assert.equal(read(dir, ".github/workflows/opt2-release.yml"), readFileSync(PLATFORM_GH, "utf8"), "byte-identical copy of the platform release workflow");

    const docker = read(dir, "Dockerfile");
    const froms = [...docker.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
    assert.ok(froms.length > 0);
    for (const f of froms) assert.match(f as string, /^node:24-slim@sha256:[0-9a-f]{64}$/);
    assert.match(docker, /^USER node$/m);
    assert.match(docker, /^CMD \["node", "dist\/main\.js"\]$/m);
    assert.match(docker, /^COPY tealbrick\.manifest\.json \/opt\/tb\/tealbrick\.manifest\.json$/m);
    // BSA-06: the ONE Dockerfile pattern (pnpm frozen lockfile, kit + tsc + UI build to dist, data under /data)
    const [build = "", runtime = ""] = docker.split(/^FROM .*$/m).slice(1);
    assert.match(build, /^RUN corepack enable$/m);
    assert.match(build, /^RUN pnpm install --frozen-lockfile --ignore-scripts$/m);
    assert.match(build, /^COPY tealbrick\.manifest\.json .*\n(?:.*\n)*RUN pnpm run build && pnpm prune --prod$/m, "manifest is in the build stage before tb-gen runs");
    assert.match(build, /^COPY skills \.\/skills$/m, "the kit embeds the skill texts");
    assert.match(runtime, /^ENV .*\bTB_DATA_DIR=\/data TB_BACKUP_DIR=\/data\/backup$/m);
    assert.match(runtime, /^COPY --from=build \/app\/dist \.\/dist$/m);
    assert.match(read(dir, ".dockerignore"), /^gen$/m);

    const skill = read(dir, "skills/use-tasks/SKILL.md");
    const front = /^---\n([\s\S]*?)\n---\n/.exec(skill)?.[1] ?? "";
    assert.deepEqual(
      front.split("\n").map((l) => l.split(":")[0]),
      ["name", "description"],
    );
    assert.match(front, /^name: use-tasks$/m);
  });

  it("design system 0.2.0: the standard pages and pages.css are identical for every app, and no 0.1.x name is left", (t) => {
    const a = join(temp(t), "a");
    const b = join(temp(t), "b");
    createMiniapp({ dir: a, id: "alpha", name: "Alpha" });
    createMiniapp({ dir: b, id: "beta-two", name: "Beta Two" });
    for (const f of ["src/ui/standard.tsx", "src/ui/pages.css", "test/ui-holds.test.ts"]) assert.equal(read(a, f), read(b, f), `${f} is one source for all apps`);
    const standard = read(a, "src/ui/standard.tsx");
    assert.doesNotMatch(standard, /alpha|Alpha/, "no app id or name inside standard.tsx");
    // RUL-01 / RUL-14 / C8 are in the shared module, not left to each app
    assert.match(standard, /role="alert"/);
    assert.match(standard, /Try again/);
    assert.match(standard, /inflight/);
    assert.doesNotMatch(standard, /void list\.decide\(/, "no fire-and-forget decide (RUL-01): the page goes through decideOrError");
    assert.match(standard, /decideOrError\(/);
    const gone =
      /--tb-(?:radius|surface|canvas|accent|border|text-(?:xs|sm|md|lg|xl|2xl))(?![\w-])|--tb-(?:burgundy|teal-\d)|tone="(?:ok|action|progress|blocked)"|variant="(?:accent|ghost)"|\bEyebrow\b|\bSetupSteps\b|\bSetupOverlay\b/;
    for (const f of ["src/ui/App.tsx", "src/ui/standard.tsx", "src/ui/pages.css"]) assert.doesNotMatch(read(a, f), gone, `${f} has no 0.1.x name`);
    // page header: title + lede are ONE flex item under the title (a lede beside the title left a wide gap at 1280px)
    assert.match(standard, /<div className="page-title">\s*<h1>\{title\}<\/h1>\s*\{lede \? <p className="tb-lede">\{lede\}<\/p> : null\}\s*<\/div>/, "Head wraps the title and the lede in .page-title");
    assert.doesNotMatch(standard, /<div className="page-head">\s*(?:\{\/\*[\s\S]*?\*\/\}\s*)?<h1>/, "the h1 is not a direct item of .page-head with a lede beside it");
    assert.match(read(a, "src/ui/pages.css"), /\.page-title \{[^}]*display: grid;/);
    // the app CSS is page layout only and uses tokens, never a raw colour, radius or font
    assert.doesNotMatch(read(a, "src/ui/pages.css"), /#[0-9a-f]{3,8}\b|rgb\(|border-radius:\s*\d|font-family:(?!\s*var)/i);
    // build-ui: kit sheets first, then pages.css/app.css; Nunito files and the still travel with the build
    const build = read(a, "scripts/build-ui.ts");
    assert.match(build, /APP_STYLES = \["pages\.css", "app\.css"\]/);
    assert.match(build, /copyCssAssets/);
    assert.match(build, /appArt\(productId, "stills\/"\)/);
    assert.match(read(a, "src/ui/index.html"), /<body class="tb-root">/);
    const pkg = readJson(a, "package.json");
    assert.equal(pkg.devDependencies["happy-dom"], "21.0.1", "the Holds UI test renders in happy-dom");
  });

  it("C154: Apache-2.0 LICENSE (verbatim text), NOTICE with the app's name, third-party notices, package licence", (t) => {
    const dir = join(temp(t), "a");
    createMiniapp({ dir, id: "alpha", name: "Alpha App" });
    const licence = read(dir, "LICENSE");
    assert.match(licence, /^\s+Apache License\n\s+Version 2\.0, January 2004/);
    assert.match(licence, /END OF TERMS AND CONDITIONS/);
    assert.match(licence, /^ {3}Copyright 2026 Tealbrick$/m);
    // the standard text unchanged apart from the appendix line: the canonical file is 11358 bytes with the 33-char placeholder
    assert.equal(Buffer.byteLength(licence), 11358 - "Copyright [yyyy] [name of copyright owner]".length + "Copyright 2026 Tealbrick".length);
    assert.equal(
      read(dir, "NOTICE"),
      "Alpha App (opt2-tealbrick-alpha)\nCopyright 2026 Polygonface s.r.o. Tealbrick is a trademark of Polygonface s.r.o.; the Apache License 2.0 grants no right to it.\n\nThis product includes software and assets developed by third parties; see THIRD_PARTY_NOTICES.md.\n",
    );
    const third = read(dir, "THIRD_PARTY_NOTICES.md");
    for (const name of ["react-dom", "scheduler", "@opt2-tealbrick/ui", "Nunito", "SIL Open Font License 1.1", "OFL.txt", "not** covered by the Apache-2.0", "@opt2-tealbrick/miniapp-sdk"])
      assert.ok(third.includes(name), `THIRD_PARTY_NOTICES.md mentions ${name}`);
    assert.equal(readJson(dir, "package.json").license, "Apache-2.0");
    assert.equal(readJson(dir, "tealbrick.manifest.json").source.license, "Apache-2.0", "the manifest names the same licence");
    assert.equal(readJson(dir, "tealbrick.manifest.json").source.repo, "https://github.com/Tealbrick/opt2-tealbrick-alpha", "C206: source repo is under the Tealbrick org");
    assert.ok(!third.includes("github.com/Martin-Atrin/"), "C206: source links point at the Tealbrick org");
  });

  it("derives the name from the id when --name is omitted", (t) => {
    const r = createMiniapp({ dir: join(temp(t), "a"), id: "field-notes" });
    assert.equal(r.name, "Field Notes");
    assert.equal(defaultName("a1-b--c"), "A1 B C");
  });

  it("accepts an existing empty directory", (t) => {
    const dir = temp(t);
    assert.equal(createMiniapp({ dir, id: "empty-ok" }).dir, dir);
  });

  it("refuses a non-empty directory and writes nothing", (t) => {
    const dir = temp(t);
    writeFileSync(join(dir, "keep.txt"), "mine");
    assert.throws(() => createMiniapp({ dir, id: "taken" }), rejectsWith("dir_not_empty"));
    assert.deepEqual(readdirSync(dir), ["keep.txt"]);
    const file = join(dir, "keep.txt");
    assert.throws(() => createMiniapp({ dir: file, id: "taken" }), rejectsWith("dir_not_empty"));
  });

  it("refuses invalid slugs and names", (t) => {
    const dir = join(temp(t), "x");
    for (const id of ["", "a", "A-app", "1app", "my_app", "my.app", "x".repeat(33), "app/../evil"])
      assert.throws(() => createMiniapp({ dir, id }), rejectsWith("id_invalid"), JSON.stringify(id));
    for (const name of ["", "  ", 'Quote"s', "<b>Bold</b>", "x".repeat(41), "Two  spaces", "Colon: no", "-dash"])
      assert.throws(() => createMiniapp({ dir, id: "ok-app", name }), rejectsWith("name_invalid"), JSON.stringify(name));
    assert.equal(existsSync(dir), false);
  });
});

describe("renderTemplate", () => {
  it("refuses a template with an unknown placeholder or an invalid manifest", (t) => {
    const tpl = join(temp(t), "tpl");
    cpSync(TEMPLATE_DIR, tpl, { recursive: true });
    writeFileSync(join(tpl, "extra.txt"), "__APP_VERSION__");
    assert.throws(() => renderTemplate("abc", "Abc", tpl), rejectsWith("template_invalid"));
    rmSync(join(tpl, "extra.txt"));
    const m = JSON.parse(readFileSync(join(tpl, "tealbrick.manifest.json"), "utf8"));
    m.runtime.volumes = m.runtime.volumes.filter((v: { purpose: string }) => v.purpose !== "backup");
    writeFileSync(join(tpl, "tealbrick.manifest.json"), JSON.stringify(m));
    assert.throws(() => renderTemplate("abc", "Abc", tpl), rejectsWith("manifest_invalid"));
  });
});

describe("cli", () => {
  const run = (args: string[], cwd: string) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });

  it("scaffolds and prints next steps", (t) => {
    const cwd = temp(t);
    const r = run(["hello", "--id", "hello", "--name", "Hello World"], cwd);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Created Hello World \(hello\) in hello/);
    assert.match(r.stdout, /pnpm install/);
    assert.match(r.stdout, /Push to github\.com\/Tealbrick\/opt2-tealbrick-hello;/);
    assert.equal(readJson(join(cwd, "hello"), "tealbrick.manifest.json").name, "Hello World");
  });

  it("exits non-zero on a non-empty dir, a bad slug, or missing arguments", (t) => {
    const cwd = temp(t);
    mkdirSync(join(cwd, "full"));
    writeFileSync(join(cwd, "full", "x"), "");
    const full = run(["full", "--id", "full"], cwd);
    assert.equal(full.status, 1);
    assert.match(full.stderr, /dir_not_empty/);
    const bad = run(["bad", "--id", "Bad"], cwd);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /id_invalid/);
    assert.equal(run(["only-dir"], cwd).status, 2);
    assert.equal(run(["a", "--id", "aa", "--bogus"], cwd).status, 2);
  });
});
