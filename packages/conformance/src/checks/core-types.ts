// Type scan for the Core target's static checks (CONFORMANCE R4, R8, R9): reads the declaration files that
// @opt2-tealbrick/spec ships (dist/*.d.ts — the frozen route input/output interfaces) and answers "which field
// names can this schema carry, at any depth". No JSON Schema exists for route inputs in the spec package, so the
// declarations are the machine-readable source. Over-approximates on purpose (a generic argument's fields count as
// nested fields): a forbidden-name scan must never miss a field.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** name → declaration: `interface` (body + extends) or `alias` (right-hand side). */
export interface TypeDecl {
  kind: "interface" | "alias";
  text: string;
  extends: string;
}
export type TypeIndex = ReadonlyMap<string, TypeDecl>;

export interface FieldInfo {
  /** dotted path from the schema root, `[]` marks array items, `<>` generic arguments */
  path: string;
  name: string;
  optional: boolean;
  type: string;
  /** 0 = top-level field of the schema */
  depth: number;
}

/** spec 0.1.58: + host (server / host-agent route types, HOST.md) */
const SPEC_DTS = ["routes", "bridge", "credentials", "manifest", "host"] as const;

/** Index of every declaration in the installed @opt2-tealbrick/spec declaration files (routes first on clashes). */
export function loadSpecTypes(): TypeIndex {
  const dir = dirname(fileURLToPath(import.meta.resolve("@opt2-tealbrick/spec/routes")));
  return parseDeclarations(...SPEC_DTS.map((f) => readFileSync(join(dir, `${f}.d.ts`), "utf8")));
}

function stripComments(src: string): string {
  let out = "";
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (c === '"' || c === "'" || c === "`") {
      const end = skipString(src, i);
      out += src.slice(i, end);
      i = end - 1;
    } else if (c === "/" && src[i + 1] === "*") {
      const end = src.indexOf("*/", i + 2);
      i = end < 0 ? src.length : end + 1;
    } else if (c === "/" && src[i + 1] === "/") {
      const end = src.indexOf("\n", i);
      i = end < 0 ? src.length : end - 1;
    } else out += c;
  }
  return out;
}

/** index just past the string literal starting at `i` (template literals: `${…}` may nest braces). */
function skipString(s: string, i: number): number {
  const q = s[i];
  let j = i + 1;
  while (j < s.length && s[j] !== q) j += s[j] === "\\" ? 2 : 1;
  return j + 1;
}

/** index of the closing bracket matching the opener at `i`, tracking (), [], {}, <> (ignoring `=>`) and strings. */
function matchClose(s: string, i: number): number {
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (c === '"' || c === "'" || c === "`") {
      j = skipString(s, j) - 1;
      continue;
    }
    if (c === "=" && s[j + 1] === ">") {
      j++;
      continue;
    }
    if ("([{<".includes(c)) depth++;
    else if (")]}>".includes(c)) {
      depth--;
      if (depth === 0) return j;
    }
  }
  return s.length - 1;
}

/** end (exclusive) of a type alias right-hand side: the `;` at bracket depth 0. */
function aliasEnd(s: string, i: number): number {
  let depth = 0;
  for (let j = i; j < s.length; j++) {
    const c = s[j];
    if (c === '"' || c === "'" || c === "`") {
      j = skipString(s, j) - 1;
      continue;
    }
    if (c === "=" && s[j + 1] === ">") {
      j++;
      continue;
    }
    if ("([{<".includes(c)) depth++;
    else if (")]}>".includes(c)) depth--;
    else if (c === ";" && depth === 0) return j;
  }
  return s.length;
}

const DECL_RE = /(?:^|\n)\s*(?:export\s+)?(?:declare\s+)?(interface|type)\s+([A-Za-z_]\w*)\s*/g;

/** Parses `interface` and `type` declarations from declaration-file sources (first declaration of a name wins). */
export function parseDeclarations(...sources: string[]): TypeIndex {
  const index = new Map<string, TypeDecl>();
  for (const raw of sources) {
    const src = stripComments(raw);
    for (const m of src.matchAll(DECL_RE)) {
      const [whole, kind, name] = m;
      let i = (m.index ?? 0) + whole.length;
      if (src[i] === "<") i = matchClose(src, i) + 1;
      if (kind === "interface") {
        const open = src.indexOf("{", i);
        if (open < 0) continue;
        const ext = src.slice(i, open).replace(/^\s*extends\s+/, "").trim();
        const close = matchClose(src, open);
        if (!index.has(name)) index.set(name, { kind: "interface", text: src.slice(open + 1, close), extends: ext });
      } else {
        const eq = src.indexOf("=", i);
        if (eq < 0) continue;
        const end = aliasEnd(src, eq + 1);
        if (!index.has(name)) index.set(name, { kind: "alias", text: src.slice(eq + 1, end).trim(), extends: "" });
      }
    }
  }
  return index;
}

/** Members of an object-type body: `name?: type` pairs at depth 0 (index signatures and methods skipped). */
export function members(body: string): { name: string; optional: boolean; type: string }[] {
  const out: { name: string; optional: boolean; type: string }[] = [];
  let start = 0;
  const parts: string[] = [];
  for (let j = 0; j < body.length; j++) {
    const c = body[j];
    if (c === '"' || c === "'" || c === "`") {
      j = skipString(body, j) - 1;
      continue;
    }
    if ("([{<".includes(c)) {
      j = matchClose(body, j);
      continue;
    }
    if (c === ";" || c === "\n" || c === ",") {
      parts.push(body.slice(start, j));
      start = j + 1;
    }
  }
  parts.push(body.slice(start));
  for (const p of parts) {
    const m = /^\s*(?:readonly\s+)?(?:"([^"]+)"|'([^']+)'|([A-Za-z_$][\w$]*))\s*(\?)?\s*:\s*([\s\S]+)$/.exec(p);
    if (m) out.push({ name: m[1] ?? m[2] ?? m[3], optional: m[4] === "?", type: m[5].trim() });
  }
  return out;
}

/**
 * Every field reachable from `typeText` (deep). Identifiers declared in the index are resolved (interfaces incl.
 * `extends`, aliases); inline object literals are entered; generic arguments are entered one level deeper.
 */
export function fieldsOfType(index: TypeIndex, typeText: string, prefix = "", depth = 0, seen: ReadonlySet<string> = new Set()): FieldInfo[] {
  const out: FieldInfo[] = [];
  const s = typeText;
  for (let j = 0; j < s.length; j++) {
    const c = s[j];
    if (c === '"' || c === "'" || c === "`") {
      j = skipString(s, j) - 1;
      continue;
    }
    if (c === "{") {
      const close = matchClose(s, j);
      for (const m of members(s.slice(j + 1, close))) {
        const path = prefix ? `${prefix}.${m.name}` : m.name;
        out.push({ path, name: m.name, optional: m.optional, type: m.type, depth });
        out.push(...fieldsOfType(index, m.type, path, depth + 1, seen));
      }
      j = close;
      continue;
    }
    if (c === "<") {
      const close = matchClose(s, j);
      out.push(...fieldsOfType(index, s.slice(j + 1, close), `${prefix}<>`, depth + 1, seen));
      j = close;
      continue;
    }
    const id = /^[A-Za-z_]\w*/.exec(s.slice(j));
    if (id && (j === 0 || !/[\w$.]/.test(s[j - 1]))) {
      const name = id[0];
      const decl = index.get(name);
      // `keyof X` / `typeof x` yield key names or value types, not X's fields
      const operand = /\b(keyof|typeof)\s+$/.test(s.slice(Math.max(0, j - 8), j));
      if (decl && !operand && !seen.has(name)) {
        const next = new Set(seen).add(name);
        if (decl.extends) out.push(...fieldsOfType(index, decl.extends, prefix, depth, next));
        out.push(...fieldsOfType(index, decl.kind === "interface" ? `{${decl.text}}` : decl.text, prefix, depth, next));
      }
      j += name.length - 1;
    }
  }
  return arraySuffix(out);
}

/** `x: T[]` children read as `x[].child` for clarity (paths only; names unchanged). */
function arraySuffix(fields: FieldInfo[]): FieldInfo[] {
  const arrays = new Set(fields.filter((f) => /\[\]\s*$/.test(f.type) || /^(readonly\s+)?\(?\{[\s\S]*\}\)?\[\]$/.test(f.type)).map((f) => f.path));
  return fields.map((f) => {
    let p = f.path;
    for (const a of arrays) if (p.startsWith(`${a}.`)) p = `${a}[]${p.slice(a.length)}`;
    return p === f.path ? f : { ...f, path: p };
  });
}

/** Deep fields of a declared schema name (empty when the name is unknown). */
export function fieldsOf(index: TypeIndex, name: string): FieldInfo[] {
  return index.has(name) ? fieldsOfType(index, name) : [];
}

/** String members of a union of string literals, e.g. `type X = "a" | "b"` → ["a", "b"] (empty when not one). */
export function stringUnion(index: TypeIndex, name: string): string[] {
  const d = index.get(name);
  if (d?.kind !== "alias") return [];
  const parts = d.text.split("|").map((p) => p.trim());
  const lit = parts.map((p) => /^"([^"]*)"$/.exec(p)?.[1]);
  return lit.every((x) => x !== undefined) ? (lit as string[]) : [];
}

/** Lower case without `_` / `-`: `user_code`, `userCode` and `user-code` compare equal. */
export const normName = (n: string): string => n.toLowerCase().replace(/[_-]/g, "");
