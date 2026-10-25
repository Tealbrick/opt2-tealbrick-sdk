// Manifest validator (MANIFEST.md §13): manifest.schema.json (ajv, draft 2020-12) + every cross-field rule M-*.
// The one implementation; Core, SDK, bridge, CLI and conformance call it. Warnings do not exist.
import { readdir, readFile, stat } from "node:fs/promises";
import { resolve, sep } from "node:path";
import type {
  Condition,
  JsonSchemaObject,
  Manifest,
  ManifestIssue,
  ManifestValidation,
  Operation,
  SettingField,
} from "@opt2-tealbrick/spec/manifest";
import { RESERVED_EVENT_PREFIX } from "@opt2-tealbrick/spec/manifest";
import manifestSchema from "@opt2-tealbrick/spec/schemas/manifest.schema.json" with { type: "json" };
import type { Json, OperationView } from "@opt2-tealbrick/spec/sdk";
import type { ErrorObject, ValidateFunction } from "ajv/dist/2020.js";
import { Ajv2020 } from "ajv/dist/2020.js";
import { HOLDS_PENDING_OP } from "./decision.ts";
import { canonicalize, digest } from "./jcs.ts";
import { DYNAMIC_CALL_INPUT_SCHEMA, derivedToolNames, standardOpInputSchema, toolNameFits } from "./ops.ts";
import { parseSkillFile, parseVariable, skillTextViolation, VARIABLE_RE } from "./skill-text.ts";
import { compareSemver, LAZY_LISTING_MIN_BRIDGE } from "./version.ts";

type Add = (rule: string, code: string, path: string, message: string) => void;

const MAX_MANIFEST_BYTES = 256 * 1024;
const MAX_SKILL_BYTES = 64 * 1024;

// ───────────────────────────── helpers ─────────────────────────────

function ptr(...parts: (string | number)[]): string {
  return parts.map((p) => `/${String(p).replace(/~/g, "~0").replace(/\//g, "~1")}`).join("");
}

function collector(): { errors: ManifestIssue[]; add: Add } {
  const errors: ManifestIssue[] = [];
  return { errors, add: (rule, code, path, message) => errors.push({ path, rule, code, message }) };
}

/** Reports every later occurrence of an already-seen key. */
function uniq<T>(items: readonly T[] | undefined, key: (t: T) => string, onDup: (t: T, i: number, k: string) => void): void {
  const seen = new Set<string>();
  items?.forEach((t, i) => {
    const k = key(t);
    if (seen.has(k)) onDup(t, i, k);
    seen.add(k);
  });
}

const isSubset = (a: readonly string[], b: readonly string[]): boolean => a.every((x) => b.includes(x));
const isReadOnly = (crud: readonly string[]): boolean => crud.length === 1 && crud[0] === "read";

// ───────────────────────────── schema ─────────────────────────────

// SPEC-GAP: no code is named for structural (schema) failures; they are reported as rule `schema`, code `schema_invalid`.
let schemaCheck: ValidateFunction | undefined;
function checkSchema(json: unknown): ManifestIssue[] {
  schemaCheck ??= new Ajv2020({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true }).compile(manifestSchema);
  if (schemaCheck(json)) return [];
  const out: ManifestIssue[] = [];
  const seen = new Set<string>();
  for (const e of schemaCheck.errors as ErrorObject[]) {
    let path = e.instancePath;
    if (e.keyword === "additionalProperties") path += ptr(String(e.params.additionalProperty));
    if (e.keyword === "required") path += ptr(String(e.params.missingProperty));
    const message = `${e.message ?? "invalid"} (${e.schemaPath})`;
    if (seen.has(path + message)) continue;
    seen.add(path + message);
    out.push({ path, rule: "schema", code: "schema_invalid", message });
  }
  return out;
}

// ───────────────────────────── JSON Schema compile cache (operation input/output) ─────────────────────────────

const ioAjv = new Ajv2020({ allErrors: true, strict: false, validateFormats: false, logger: false });
const byObject = new WeakMap<object, ValidateFunction>();
const byContent = new Map<string, ValidateFunction>();
const MAX_CONTENT_CACHE = 1024;

/** Compiles (cached by identity, then by JCS content, bounded) a JSON Schema 2020-12 object. Throws on an invalid schema. */
function compileIo(schema: JsonSchemaObject): ValidateFunction {
  const hit = byObject.get(schema);
  if (hit) return hit;
  const key = canonicalize(schema as Json);
  let fn = byContent.get(key);
  if (!fn) {
    try {
      fn = ioAjv.compile(schema);
    } finally {
      ioAjv.removeSchema(schema); // ajv's own cache holds schema objects strongly; keep only ours
    }
    if (byContent.size >= MAX_CONTENT_CACHE) byContent.delete(byContent.keys().next().value as string);
    byContent.set(key, fn);
  }
  byObject.set(schema, fn);
  return fn;
}

export type InputValidation = { ok: true } | { ok: false; code: "input_invalid"; errors: { path: string; message: string }[] };

/** Validates a JSON value against a JSON Schema 2020-12 object (compiled once and cached). Formats are annotations only. */
export function validateAgainstSchema(schema: JsonSchemaObject, value: Json): InputValidation {
  let fn: ValidateFunction;
  try {
    fn = compileIo(schema);
  } catch (e) {
    return { ok: false, code: "input_invalid", errors: [{ path: "", message: `schema not compilable: ${(e as Error).message}` }] };
  }
  if (fn(value)) return { ok: true };
  const errors = (fn.errors ?? []).map((e) => ({
    path: e.instancePath + (e.keyword === "required" ? ptr(String(e.params.missingProperty)) : ""),
    message: e.message ?? "invalid",
  }));
  return { ok: false, code: "input_invalid", errors };
}

const NO_INPUT: JsonSchemaObject = { type: "object", additionalProperties: false };
/** M-OP-4: the families an `outward` op may declare (every hold family except the effect-bound destructive and money). */
const OUTWARD_FAMILIES = ["first_contact", "profile_change", "live_call", "outward", "identity", "public_link"] as const;

/** Validates a call input against the op's input schema (C21; BRIDGE §8.1 step 4). Standard ops use the SDK-API §6 shapes,
 * dynamic ops `DynamicCallInput`, an op without `input` accepts only `{}`. */
export function validateInput(op: OperationView, input: Json): InputValidation {
  const schema = op.standard
    ? standardOpInputSchema(op.id)
    : op.dynamic
      ? DYNAMIC_CALL_INPUT_SCHEMA
      : (op.input ?? NO_INPUT);
  return validateAgainstSchema(schema, input);
}

// ───────────────────────────── M-DOC ─────────────────────────────

// All scans are linear in the string length: Core validates untrusted manifests (no backtracking blow-up).
const PEM_RE = /-----BEGIN [A-Z0-9 ]{1,64}-----/;
const OPAQUE_RE = /(?<![A-Za-z0-9])tb[a-z]{0,4}_[A-Za-z0-9_-]{40}/;
const JWS_HEAD_RE = /eyJ[A-Za-z0-9_-]*/g;
const JWS_SEGMENT_RE = /[A-Za-z0-9_-]{4,}\./y;

/** JWS-shaped `eyJ<b64url>.<b64url>.`; the global scan resumes after each run, so the work stays linear. */
function hasJws(value: string): boolean {
  JWS_HEAD_RE.lastIndex = 0;
  for (let m = JWS_HEAD_RE.exec(value); m; m = JWS_HEAD_RE.exec(value)) {
    const end = m.index + m[0].length;
    if (m[0].length < 7 || value[end] !== ".") continue;
    JWS_SEGMENT_RE.lastIndex = end + 1;
    if (JWS_SEGMENT_RE.test(value)) return true;
  }
  return false;
}
const URL_ALLOWED_RE = /^(\/\$schema|\/publisher\/url|\/source\/repo|\/artifacts\/\d+\/url|\/operations\/\d+\/(input|output)(\/.*)?)$/;
const INSTANCE_ID_RE =
  /(?<![A-Za-z0-9])(acc|per|ws|agt|con|ins|brg|rel|lic|off|ord|edg|drf|dev|aud|hld|rcp|call|osn|lnk)_[0-9A-HJKMNP-TV-Z]{26}(?![0-9A-Za-z])/;

function docRules(value: unknown, path: string, add: Add): void {
  if (typeof value === "string") {
    if (PEM_RE.test(value) || OPAQUE_RE.test(value) || hasJws(value)) add("M-DOC-1", "secret_material", path, "key material, token or credential in a string");
    if (value.includes("://") && !URL_ALLOWED_RE.test(path)) add("M-DOC-2", "url_not_allowed", path, "literal URL outside the allowed fields");
    if (INSTANCE_ID_RE.test(value)) add("M-DOC-3", "instance_id_in_manifest", path, "customer, workspace or instance identifier in the manifest");
  } else if (Array.isArray(value)) {
    for (const [i, v] of value.entries()) docRules(v, `${path}${ptr(i)}`, add);
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) docRules(v, `${path}${ptr(k)}`, add);
  }
}

// ───────────────────────────── M-ID ─────────────────────────────

// SPEC-GAP: the spec ships no SPDX list; M-ID-1 checks against this embedded set of OSI-approved / common SPDX ids.
const SPDX_LICENSES = new Set(
  (
    "0BSD AAL AFL-1.1 AFL-1.2 AFL-2.0 AFL-2.1 AFL-3.0 AGPL-3.0 AGPL-3.0-only AGPL-3.0-or-later Apache-1.1 Apache-2.0 APL-1.0 " +
    "APSL-2.0 Artistic-1.0 Artistic-1.0-Perl Artistic-2.0 BlueOak-1.0.0 BSD-1-Clause BSD-2-Clause BSD-2-Clause-Patent " +
    "BSD-3-Clause BSD-3-Clause-Clear BSD-3-Clause-LBNL BSD-4-Clause BSL-1.0 CAL-1.0 CATOSL-1.1 CC0-1.0 CC-BY-4.0 CC-BY-SA-4.0 " +
    "CDDL-1.0 CDDL-1.1 CECILL-2.1 CECILL-B CECILL-C CNRI-Python CPAL-1.0 CPL-1.0 CUA-OPL-1.0 ECL-1.0 ECL-2.0 EFL-1.0 EFL-2.0 " +
    "Entessa EPL-1.0 EPL-2.0 EUDatagrid EUPL-1.1 EUPL-1.2 Fair Frameworx-1.0 GPL-2.0 GPL-2.0-only GPL-2.0-or-later GPL-3.0 " +
    "GPL-3.0-only GPL-3.0-or-later HPND Intel IPA IPL-1.0 ISC Jam LGPL-2.0 LGPL-2.0-only LGPL-2.0-or-later LGPL-2.1 " +
    "LGPL-2.1-only LGPL-2.1-or-later LGPL-3.0 LGPL-3.0-only LGPL-3.0-or-later LiLiQ-P-1.1 LiLiQ-R-1.1 LiLiQ-Rplus-1.1 " +
    "LPL-1.0 LPL-1.02 LPPL-1.3c MirOS MIT MIT-0 MIT-Modern-Variant Motosoto MPL-1.0 MPL-1.1 MPL-2.0 " +
    "MPL-2.0-no-copyleft-exception MS-PL MS-RL MulanPSL-2.0 Multics NASA-1.3 Naumen NCSA NGPL Nokia NPOSL-3.0 NTP OCLC-2.0 " +
    "OFL-1.1 OGTSL OLDAP-2.8 OSET-PL-2.1 OSL-1.0 OSL-2.0 OSL-2.1 OSL-3.0 PHP-3.0 PHP-3.01 PostgreSQL PSF-2.0 Python-2.0 " +
    "QPL-1.0 RPL-1.1 RPL-1.5 RPSL-1.0 RSCPL SimPL-2.0 SISSL Sleepycat SPL-1.0 Unicode-3.0 Unicode-DFS-2016 Unlicense UPL-1.0 " +
    "Vim VSL-1.0 W3C Watcom-1.0 WTFPL X11 Xnet Zlib ZPL-2.0 ZPL-2.1"
  )
    .toLowerCase()
    .split(" "),
);
const SPDX_EXCEPTIONS = new Set(
  (
    "389-exception Autoconf-exception-2.0 Autoconf-exception-3.0 Bison-exception-2.2 Classpath-exception-2.0 " +
    "eCos-exception-2.0 Font-exception-2.0 freertos-exception-2.0 GCC-exception-2.0 GCC-exception-3.1 GPL-CC-1.0 " +
    "Libtool-exception Linux-syscall-note LLVM-exception mif-exception OCaml-LGPL-linking-exception " +
    "OpenJDK-assembly-exception-1.0 openvpn-openssl-exception Qt-GPL-exception-1.0 Qt-LGPL-exception-1.1 Swift-exception " +
    "u-boot-exception-2.0 Universal-FOSS-exception-1.0 WxWindows-exception-3.1"
  )
    .toLowerCase()
    .split(" "),
);

function licenseProblem(expr: string): string | null {
  const parts = expr.split(" "); // the schema guarantees `id (OP id)*`
  for (let i = 0; i < parts.length; i += 2) {
    const id = parts[i].toLowerCase();
    if (id === "none" || id === "noassertion") return `${parts[i]} is not a licence`;
    if (parts[i - 1] === "WITH") {
      if (!SPDX_EXCEPTIONS.has(id)) return `unknown SPDX exception ${parts[i]}`;
      if (parts[i + 1] === "WITH") return "WITH applies once";
    } else if (!SPDX_LICENSES.has(id.replace(/\+$/, ""))) {
      return `unknown or non open-source SPDX licence ${parts[i]}`;
    }
  }
  return null;
}

// ───────────────────────────── conditions (M-ST-3) ─────────────────────────────

function checkCondition(
  when: Condition | undefined,
  path: string,
  allFields: ReadonlyMap<string, SettingField>,
  available: ReadonlySet<string> | null, // null = every field may be referenced
  rule: string,
  code: string,
  add: Add,
): void {
  if (!when) return;
  for (const [key, raw] of Object.entries(when)) {
    const p = `${path}${ptr(key)}`;
    const f = allFields.get(key);
    if (!f) {
      add(rule, code, p, `condition names undeclared setting ${key}`);
      continue;
    }
    if (f.type !== "enum" && f.type !== "boolean") {
      add(rule, code, p, `condition setting ${key} must be enum or boolean`);
      continue;
    }
    if (available && !available.has(key)) {
      add(rule, code, p, `condition may only reference settings declared earlier (${key})`);
      continue;
    }
    const values = Array.isArray(raw) ? raw : [raw];
    const ok =
      f.type === "boolean"
        ? values.every((v) => typeof v === "boolean")
        : values.every((v) => typeof v === "string" && (f.choices ?? []).some((c) => c.value === v));
    if (!ok) add(rule, code, p, `condition value not valid for ${f.type} setting ${key}`);
  }
}

// ───────────────────────────── settings index ─────────────────────────────

interface SettingsIndex {
  fields: Map<string, SettingField>;
  fieldPath: Map<string, string>;
}

function indexSettings(m: Manifest): SettingsIndex {
  const fields = new Map<string, SettingField>();
  const fieldPath = new Map<string, string>();
  for (const [si, s] of (m.settings?.steps ?? []).entries()) {
    for (const [fi, f] of s.fields.entries()) {
      if (!fields.has(f.key)) {
        fields.set(f.key, f);
        fieldPath.set(f.key, ptr("settings", "steps", si, "fields", fi));
      }
    }
  }
  return { fields, fieldPath };
}

/** M-ST-7: setting keys referenced by env, any `when`, plus `extraRefs` (skill `{{settings.<key>}}`). */
function unusedSettings(m: Manifest, idx: SettingsIndex, extraRefs: ReadonlySet<string>, add: Add): void {
  const refs = new Set(extraRefs);
  const conds: (Condition | undefined)[] = [];
  for (const e of m.runtime.env ?? []) if (e.setting) refs.add(e.setting);
  for (const s of m.runtime.services ?? []) {
    for (const e of s.env ?? []) if (e.setting) refs.add(e.setting);
    conds.push(s.when);
  }
  for (const st of m.settings?.steps ?? []) {
    conds.push(st.when);
    for (const f of st.fields) conds.push(f.when);
  }
  for (const k of m.settings?.keys ?? []) conds.push(k.when);
  for (const sk of m.skills ?? []) conds.push(sk.when);
  for (const c of conds) for (const k of Object.keys(c ?? {})) refs.add(k);
  for (const [key, path] of idx.fieldPath) {
    if (!refs.has(key)) add("M-ST-7", "setting_unused", path, `setting ${key} reaches no env, condition or skill`);
  }
}

// ───────────────────────────── rule groups ─────────────────────────────

const SECRET_ENV_RE = /SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE|API_?KEY|CREDENTIAL/;
const SECRET_SETTING_RE = /secret|token|password|passwd|private|api_?key|credential/i;
const SERVICE_ENV_REF_RE = /^\{\{services\.[^{}]+\.env\.[^{}]+\}\}$/;
const TEMPLATE_RE = /\{\{([^{}]*)\}\}/g;
const TEMPLATE_FORM_RE = /^services\.([a-z][a-z0-9-]{1,31})\.(url|host|port|env\.([A-Z][A-Z0-9_]{1,63}))$/;

function runtimeRules(m: Manifest, idx: SettingsIndex, add: Add): void {
  const rt = m.runtime;
  const services = rt.services ?? [];
  const serviceById = new Map(services.map((s) => [s.id, s]));
  const keyNames = new Set((m.settings?.keys ?? []).map((k) => k.name));
  const keyConsumers = new Set((m.settings?.keys ?? []).flatMap((k) => k.usedBy));

  // M-RT-1
  if (rt.volumes.filter((v) => v.purpose === "backup").length !== 1) {
    add("M-RT-1", "backup_volume", "/runtime/volumes", "runtime.volumes needs exactly one purpose: backup");
  }
  for (const [si, s] of services.entries()) {
    for (const [vi, v] of (s.volumes ?? []).entries()) {
      if (v.purpose !== "data") add("M-RT-1", "backup_volume", ptr("runtime", "services", si, "volumes", vi), "service volumes are data only");
    }
  }

  // M-RT-2 + M-RT-4 + M-RT-5 per container
  const volumeIds = new Set<string>();
  const containers = [
    { path: "/runtime", volumes: rt.volumes, env: rt.env ?? [] },
    ...services.map((s, si) => ({ path: ptr("runtime", "services", si), volumes: s.volumes ?? [], env: s.env ?? [] })),
  ];
  for (const c of containers) {
    const mounts: string[] = [];
    c.volumes.forEach((v, vi) => {
      const p = `${c.path}${ptr("volumes", vi)}`;
      if (volumeIds.has(v.id)) add("M-RT-2", "volume_conflict", `${p}/id`, `volume id ${v.id} not unique`);
      volumeIds.add(v.id);
      const mp = v.mountPath.replace(/\/+$/, "") || "/";
      const clash = mounts.find((o) => o === mp || o === "/" || mp === "/" || mp.startsWith(`${o}/`) || o.startsWith(`${mp}/`));
      if (clash !== undefined) add("M-RT-2", "volume_conflict", `${p}/mountPath`, `mount path ${v.mountPath} duplicates or nests ${clash}`);
      mounts.push(mp);
    });

    uniq(
      c.env,
      (e) => e.name,
      (e, i) => add("M-RT-4", "env_ref_invalid", `${c.path}${ptr("env", i, "name")}`, `env name ${e.name} not unique`),
    );
    c.env.forEach((e, i) => {
      const p = `${c.path}${ptr("env", i)}`;
      if (e.setting !== undefined && !idx.fields.has(e.setting)) {
        add("M-RT-4", "env_ref_invalid", `${p}/setting`, `setting ${e.setting} is not declared`);
      }
      if (e.value !== undefined) {
        const rest = e.value.replace(TEMPLATE_RE, "");
        if (rest.includes("{{") || rest.includes("}}")) add("M-RT-4", "env_ref_invalid", `${p}/value`, "malformed template");
        for (const [, inner] of e.value.matchAll(TEMPLATE_RE)) {
          const t = TEMPLATE_FORM_RE.exec(inner);
          const target = t ? serviceById.get(t[1]) : undefined;
          if (!t) add("M-RT-4", "env_ref_invalid", `${p}/value`, `template {{${inner}}} is not an allowed form`);
          else if (!target) add("M-RT-4", "env_ref_invalid", `${p}/value`, `template names undeclared service ${t[1]}`);
          else if (t[3] !== undefined && !(target.env ?? []).some((x) => x.name === t[3] && x.generate === "secret")) {
            add("M-RT-4", "env_ref_invalid", `${p}/value`, `${t[3]} is not a generate entry of service ${t[1]}`);
          }
        }
      }
      if (SECRET_ENV_RE.test(e.name) && e.generate !== "secret" && !(e.value !== undefined && SERVICE_ENV_REF_RE.test(e.value))) {
        add("M-RT-5", "secret_env_literal", `${p}/name`, `secret-like env ${e.name} must use generate or a {{services.*.env.*}} reference`);
      }
      if (keyNames.has(e.name)) add("M-RT-5", "secret_env_literal", `${p}/name`, `env ${e.name} equals a key name; keys never travel as env`);
    });
  }

  // M-RT-3, M-RT-6, M-RT-7, M-RT-8
  uniq(
    services,
    (s) => s.id,
    (s, i) => add("M-RT-3", "service_duplicate", ptr("runtime", "services", i, "id"), `service id ${s.id} not unique`),
  );
  services.forEach((s, si) => {
    const p = ptr("runtime", "services", si);
    if (s.id === "app") add("M-RT-3", "service_duplicate", `${p}/id`, "service id app is reserved");
    if (s.image !== undefined && (s.backup || s.helper || keyConsumers.has(s.id))) {
      add("M-RT-6", "wrapper_required", p, `service ${s.id} needs the tb-exec wrapper: use build, not image`);
    }
    if (s.helper && s.helper.port === s.port) add("M-RT-7", "helper_port", `${p}/helper/port`, "helper port equals the service port");
    checkCondition(s.when, `${p}/when`, idx.fields, null, "M-RT-8", "condition_invalid", add);
  });
}

function operationRules(m: Manifest, add: Add): void {
  const scopes = new Map((m.scopes ?? []).map((s) => [s.type, s]));
  uniq(
    m.operations,
    (o) => o.id,
    // SPEC-GAP: M-OP-1 names only `tool_name_too_long`; duplicate ids get `operation_duplicate`.
    (o, i) => add("M-OP-1", "operation_duplicate", ptr("operations", i, "id"), `operation id ${o.id} not unique`),
  );
  m.operations.forEach((op, i) => {
    const p = ptr("operations", i);
    for (const name of derivedToolNames(m.id, op)) {
      if (!toolNameFits(name)) add("M-OP-1", "tool_name_too_long", `${p}/id`, `MCP tool name ${name} exceeds 64 characters`);
    }
    const ro = isReadOnly(op.crud);
    if ((op.effect === "read") !== ro) add("M-OP-2", "effect_crud_mismatch", p, 'effect "read" iff crud is ["read"]');
    const del = op.crud.includes("delete");
    if (del && op.effect !== "destructive" && op.effect !== "money") {
      add("M-OP-3", "effect_crud_mismatch", p, "delete in crud requires effect destructive or money");
    }
    if (op.effect === "destructive" && !del) add("M-OP-3", "effect_crud_mismatch", p, "effect destructive requires delete in crud");

    const hf = op.holdFamily;
    const hfOk =
      op.effect === "read" || op.effect === "write"
        ? hf === undefined
        : op.effect === "destructive"
          ? hf === "destructive"
          : op.effect === "money"
            ? hf === "money"
            : // outward (v0.1.16 C107: + outward, identity; spec 0.1.41 C232: + public_link). An ABSENT family is still accepted
              // for one release (Core keeps deploying current manifests); conformance 0.1.11 warns (M2.outward_family).
              hf === undefined || (OUTWARD_FAMILIES as readonly string[]).includes(hf);
    if (!hfOk) add("M-OP-4", "hold_family_invalid", `${p}/holdFamily`, `holdFamily ${hf ?? "(absent)"} invalid for effect ${op.effect}`);

    if (op.crud.includes("create") && op.idempotency !== "required") {
      add("M-OP-5", "idempotency_invalid", `${p}/idempotency`, "create requires idempotency required");
    }
    if (ro && op.idempotency === "required") add("M-OP-5", "idempotency_invalid", `${p}/idempotency`, "read-only ops cannot require idempotency");

    if ((op.effect === "outward" || op.effect === "destructive" || op.effect === "money" || hf !== undefined) && !op.receipt) {
      add("M-OP-6", "receipt_required", `${p}/receipt`, `effect ${op.effect} requires receipt: true`);
    }

    if (op.scopeType !== undefined) {
      const sc = scopes.get(op.scopeType);
      if (!sc) add("M-OP-7", "scope_ref_invalid", `${p}/scopeType`, `scope ${op.scopeType} is not declared`);
      else if (!isSubset(op.crud, [...new Set(sc.access.flatMap((a) => a.crud))])) {
        add("M-OP-7", "scope_ref_invalid", `${p}/scopeType`, `scope ${op.scopeType} access levels do not cover crud ${op.crud.join(",")}`);
      }
    }

    if (!op.dynamic && op.audience === "agent") {
      for (const k of ["input", "output"] as const) {
        if (!op[k]) add("M-OP-8", "io_schema_invalid", `${p}/${k}`, `agent operation needs ${k}`);
      }
    }
    for (const k of ["input", "output"] as const) {
      const schema = op[k];
      if (schema) ioSchemaRules(schema, `${p}/${k}`, add);
    }

    if (op.audience === "person" && op.dynamic) add("M-OP-9", "person_dynamic", `${p}/dynamic`, "person operations cannot be dynamic");

    if (op.dynamic) {
      const d = op.dynamic;
      const ok =
        ro &&
        op.effect === "read" &&
        hf === undefined &&
        op.idempotency === "supported" &&
        op.receipt === false &&
        op.audience === "agent" &&
        !op.input &&
        !op.output;
      if (!ok) {
        add("M-OP-10", "dynamic_invalid", p, 'dynamic ops: crud ["read"], effect read, no holdFamily, idempotency supported, receipt false, audience agent, no input/output');
      }
      if (isReadOnly(d.crudCeiling) && d.effectCeiling !== "read") {
        add("M-OP-10", "dynamic_invalid", `${p}/dynamic/effectCeiling`, 'crudCeiling ["read"] requires effectCeiling read');
      }
    }
  });
}

// Keywords whose object value maps names → subschemas (names are data, not keywords).
const NAME_MAP_KEYWORDS = new Set(["properties", "patternProperties", "$defs", "definitions", "dependentSchemas"]);

/** M-OP-8 for one embedded schema: no remote `$ref`, no `$id`, no contentEncoding/contentMediaType; must compile. */
function ioSchemaRules(schema: JsonSchemaObject, path: string, add: Add, rule = "M-OP-8", code = "io_schema_invalid", compile: (s: JsonSchemaObject) => unknown = compileIo): void {
  let bad = false;
  const walk = (node: unknown, p: string, namesOnly: boolean): void => {
    if (Array.isArray(node)) {
      for (const [i, n] of node.entries()) walk(n, `${p}${ptr(i)}`, false);
      return;
    }
    if (!node || typeof node !== "object") return;
    for (const [k, v] of Object.entries(node)) {
      const kp = `${p}${ptr(k)}`;
      if (namesOnly) {
        walk(v, kp, false);
        continue;
      }
      if (k === "$id" || k === "contentEncoding" || k === "contentMediaType") {
        bad = true;
        add(rule, code, kp, `${k} is not allowed in ${rule === "M-OP-8" ? "operation" : "event payload"} schemas`);
      } else if ((k === "$ref" || k === "$dynamicRef") && (typeof v !== "string" || !v.startsWith("#"))) {
        bad = true;
        add(rule, code, kp, "only local $ref is allowed");
      } else if (k === "enum" || k === "const" || k === "examples" || k === "default") {
        // values, not subschemas
      } else {
        walk(v, kp, NAME_MAP_KEYWORDS.has(k));
      }
    }
  };
  walk(schema, path, false);
  if (bad) return;
  try {
    compile(schema);
  } catch (e) {
    add(rule, code, path, `not a valid JSON Schema 2020-12: ${(e as Error).message}`);
  }
}

// ───────────────────────────── M-EV (v0.1.57, MANIFEST §16; manifest 0.1.30) ─────────────────────────────

/** M-EV-2: payload schemas compile in Ajv 2020 STRICT mode (formats are annotations; unknown keywords refused). */
const eventAjv = new Ajv2020({ strict: true, allErrors: true, validateFormats: false, logger: false });
function compileStrict(schema: JsonSchemaObject): void {
  try {
    eventAjv.compile(schema);
  } finally {
    eventAjv.removeSchema(schema);
  }
}
const EVENT_SCHEMA_MAX_BYTES = 8192;

function eventRules(m: Manifest, add: Add): void {
  const events = m.events ?? [];
  if (events.length === 0) return;
  // M-EV-1: a manifest `tb` declares no events (its wire types `tb.<name>` would read as platform types)
  if (m.id === "tb") add("M-EV-1", "event_name_invalid", "/events", "a manifest with id tb declares no events (the tb. event namespace is the platform's)");
  uniq(
    events,
    (e) => e.name,
    (e, i) => add("M-EV-1", "event_name_invalid", ptr("events", i, "name"), `event name ${e.name} not unique`),
  );
  const ops = new Map(m.operations.map((o) => [o.id, o]));
  events.forEach((e, i) => {
    const p = ptr("events", i);
    // the schema pattern already refuses these; kept so a hand-built manifest object that skipped the schema is still refused
    if (e.name.startsWith(RESERVED_EVENT_PREFIX)) add("M-EV-1", "event_name_invalid", `${p}/name`, `event names starting with ${RESERVED_EVENT_PREFIX} are the platform's`);
    const ps = e.payloadSchema;
    if (ps.type !== "object") add("M-EV-2", "event_schema_invalid", `${p}/payloadSchema/type`, "payloadSchema must have an object root");
    let bytes = 0;
    try {
      bytes = Buffer.byteLength(canonicalize(ps as unknown as Json));
    } catch {
      bytes = Number.POSITIVE_INFINITY;
    }
    if (bytes > EVENT_SCHEMA_MAX_BYTES) add("M-EV-2", "event_schema_invalid", `${p}/payloadSchema`, `payloadSchema is ${bytes} JCS bytes (max ${EVENT_SCHEMA_MAX_BYTES})`);
    else ioSchemaRules(ps, `${p}/payloadSchema`, add, "M-EV-2", "event_schema_invalid", compileStrict);
    // M-EV-4: the summary travels in the envelope (ctx.emit), never in the payload
    const props = (ps as { properties?: unknown }).properties;
    if (props && typeof props === "object" && Object.hasOwn(props, "summary"))
      add("M-EV-4", "event_schema_invalid", `${p}/payloadSchema/properties/summary`, "payloadSchema declares no top-level summary (the summary travels in the envelope)");
    // M-EV-3: an agent op of this manifest, not dynamic
    const op = ops.get(e.visibleWith);
    if (!op) add("M-EV-3", "event_visible_with_invalid", `${p}/visibleWith`, `visibleWith ${e.visibleWith} is not an operation of this manifest`);
    else if (op.audience !== "agent" || op.dynamic) add("M-EV-3", "event_visible_with_invalid", `${p}/visibleWith`, `visibleWith ${e.visibleWith} must be an agent operation that is not dynamic`);
  });
}

/** Schema failures inside `events[]` carry the M-EV rule and code (the schema owns the name pattern and the object root). */
function eventSchemaIssue(issue: ManifestIssue): ManifestIssue {
  const m = /^\/events\/\d+\/(name|payloadSchema|visibleWith)(\/|$)/.exec(issue.path);
  if (!m) return issue;
  const [rule, code] = m[1] === "name" ? ["M-EV-1", "event_name_invalid"] : m[1] === "payloadSchema" ? ["M-EV-2", "event_schema_invalid"] : ["M-EV-3", "event_visible_with_invalid"];
  return { ...issue, rule: rule as string, code: code as string };
}

const TEMPLATE_VAR_RE = /\{([^{}]*)\}/g;

function scopeRules(m: Manifest, add: Add): void {
  const scopes = m.scopes ?? [];
  uniq(
    scopes,
    (s) => s.type,
    (s, i) => add("M-SC-1", "scope_duplicate", ptr("scopes", i, "type"), `scope type ${s.type} not unique`),
  );
  scopes.forEach((s, si) => {
    const p = ptr("scopes", si);
    uniq(
      s.access,
      (a) => a.id,
      (a, i) => add("M-SC-1", "scope_duplicate", `${p}${ptr("access", i, "id")}`, `access id ${a.id} not unique`),
    );
    const accessIds = new Set(s.access.map((a) => a.id));
    s.defaultGrants.forEach((g, gi) => {
      if (!accessIds.has(g.access)) add("M-SC-2", "default_grant_invalid", `${p}${ptr("defaultGrants", gi, "access")}`, `access ${g.access} not declared`);
    });
    uniq(
      s.defaultGrants,
      (g) => g.kind,
      (g, i) => add("M-SC-2", "default_grant_invalid", `${p}${ptr("defaultGrants", i, "kind")}`, `default grant kind ${g.kind} repeated`),
    );
    const rest = s.summaryTemplate.replace(TEMPLATE_VAR_RE, "");
    if (rest.includes("{") || rest.includes("}")) add("M-SC-3", "template_invalid", `${p}/summaryTemplate`, "unbalanced braces");
    for (const [, v] of s.summaryTemplate.matchAll(TEMPLATE_VAR_RE)) {
      const ok = v === "count" || v === "label" || v === "labelPlural" || (v.startsWith("access.") && accessIds.has(v.slice(7)));
      if (!ok) add("M-SC-3", "template_invalid", `${p}/summaryTemplate`, `unknown variable {${v}}`);
    }
  });
  if (scopes.length > 0 && !m.ui?.configurePath) {
    add("M-SC-4", "configure_ui_required", "/ui", "scopes require ui.configurePath");
  }
}

function fieldDefaultProblem(f: SettingField): string | null {
  const d = f.default;
  if (d === undefined) return null;
  switch (f.type) {
    case "url":
      return "url settings have no default";
    case "boolean":
      return typeof d === "boolean" ? null : "default must be boolean";
    case "integer":
    case "number":
      if (typeof d !== "number" || (f.type === "integer" && !Number.isInteger(d))) return `default must be ${f.type}`;
      if ((f.min !== undefined && d < f.min) || (f.max !== undefined && d > f.max)) return "default outside min/max";
      return null;
    case "enum": {
      const c = (f.choices ?? []).find((x) => x.value === d);
      return c && !c.disabled ? null : "enum default must be a non-disabled choice";
    }
    default: {
      if (typeof d !== "string") return "default must be a string";
      if (f.maxLength !== undefined && d.length > f.maxLength) return "default longer than maxLength";
      // SPEC-GAP: the default is not matched against the app-supplied `pattern` (an untrusted regex could hang Core);
      // the pattern itself must compile (checked in settingsRules).
      return null;
    }
  }
}

function settingsRules(m: Manifest, idx: SettingsIndex, add: Add): void {
  const steps = m.settings?.steps ?? [];
  const keys = m.settings?.keys ?? [];
  const stepIds = new Set(steps.map((s) => s.id));
  const serviceIds = new Set((m.runtime.services ?? []).map((s) => s.id));

  uniq(
    steps,
    (s) => s.id,
    (s, i) => add("M-ST-1", "setting_duplicate", ptr("settings", "steps", i, "id"), `step id ${s.id} not unique`),
  );
  uniq(
    keys,
    (k) => k.name,
    (k, i) => add("M-ST-1", "setting_duplicate", ptr("settings", "keys", i, "name"), `key name ${k.name} not unique`),
  );

  const seen = new Set<string>();
  steps.forEach((s, si) => {
    const sp = ptr("settings", "steps", si);
    checkCondition(s.when, `${sp}/when`, idx.fields, new Set(seen), "M-ST-3", "condition_invalid", add);
    s.fields.forEach((f, fi) => {
      const p = `${sp}${ptr("fields", fi)}`;
      if (seen.has(f.key)) add("M-ST-1", "setting_duplicate", `${p}/key`, `setting key ${f.key} not unique`);
      checkCondition(f.when, `${p}/when`, idx.fields, seen, "M-ST-3", "condition_invalid", add);
      seen.add(f.key);

      const isText = f.type === "string" || f.type === "text" || f.type === "url";
      const isNum = f.type === "integer" || f.type === "number";
      const problems: string[] = [];
      if ((f.type === "enum") !== (f.choices !== undefined)) problems.push("choices iff type enum");
      if (!isText && (f.maxLength !== undefined || f.pattern !== undefined)) problems.push("maxLength/pattern only on string, text or url");
      if (!isNum && (f.min !== undefined || f.max !== undefined)) problems.push("min/max only on number or integer");
      if (f.min !== undefined && f.max !== undefined && f.min > f.max) problems.push("min greater than max");
      if (f.pattern !== undefined) {
        try {
          new RegExp(f.pattern, "u");
        } catch {
          problems.push("pattern is not a valid regular expression");
        }
      }
      if (f.choices && new Set(f.choices.map((c) => c.value)).size !== f.choices.length) problems.push("choice values not unique");
      const dp = fieldDefaultProblem(f);
      if (dp) problems.push(dp);
      for (const msg of problems) add("M-ST-2", "setting_invalid", p, msg);

      if (SECRET_SETTING_RE.test(f.key)) add("M-ST-4", "secret_setting", `${p}/key`, `setting ${f.key} looks secret; declare it in settings.keys`);
    });
  });

  keys.forEach((k, ki) => {
    const p = ptr("settings", "keys", ki);
    checkCondition(k.when, `${p}/when`, idx.fields, null, "M-ST-3", "condition_invalid", add);
    for (const u of k.usedBy) {
      if (u !== "app" && !serviceIds.has(u)) add("M-ST-5", "key_invalid", `${p}/usedBy`, `usedBy ${u} is neither app nor a declared service`);
    }
    if (k.source === "app_own" && (k.usedBy.length !== 1 || k.usedBy[0] !== "app")) {
      add("M-ST-5", "key_invalid", `${p}/usedBy`, 'app_own keys are used by ["app"] only');
    }
    if (k.source === "app_own" && !m.ui?.configurePath) add("M-ST-5", "key_invalid", `${p}/source`, "app_own keys require ui.configurePath");
    if (k.step !== undefined && !stepIds.has(k.step)) add("M-ST-5", "key_invalid", `${p}/step`, `step ${k.step} is not declared`);
  });

  // M-ST-6
  const reported = new Set<string>();
  for (const s of m.runtime.services ?? []) {
    for (const key of Object.keys(s.when ?? {})) {
      const f = idx.fields.get(key);
      if (f && f.mutable !== false && !reported.has(key)) {
        reported.add(key);
        add("M-ST-6", "setting_must_be_immutable", `${idx.fieldPath.get(key)}/mutable`, `setting ${key} gates a service and must be mutable: false`);
      }
    }
  }

  // SPEC-GAP: M-ST-7 counts skill `{{settings.<key>}}` references, but skill bodies are not visible to this pure
  // function; with skills declared the check is deferred to validateAppFiles (CI), which has the bodies.
  if (!m.skills?.length) unusedSettings(m, idx, new Set(), add);
}

function hookRules(m: Manifest, add: Add): void {
  const hooks = m.hooks ?? [];
  uniq(
    hooks,
    (h) => h.id,
    (h, i) => add("M-HK-1", "hook_duplicate", ptr("hooks", i, "id"), `hook id ${h.id} not unique`),
  );
  const ops = new Map(m.operations.map((o) => [o.id, o]));
  hooks.forEach((h, hi) => {
    const p = ptr("hooks", hi, "match");
    const products = h.match.products;
    if (products.includes("*") && products.length > 1) add("M-HK-2", "hook_match_invalid", `${p}/products`, '"*" must appear alone');
    if (!h.match.operations) return;
    if (products.length !== 1 || products[0] === "*") {
      add("M-HK-3", "hook_match_invalid", `${p}/operations`, "operations need exactly one product id");
    } else if (products[0] === m.id) {
      for (const id of h.match.operations) {
        if (ops.get(id)?.audience !== "agent") add("M-HK-3", "hook_match_invalid", `${p}/operations`, `own operation ${id} missing or not agent audience`);
      }
    }
  });
}

function companionRules(m: Manifest, add: Add): void {
  const companions = m.companions ?? [];
  uniq(
    companions,
    (c) => c.product,
    (c, i) => add("M-CP-1", "companion_invalid", ptr("companions", i, "product"), `companion ${c.product} repeated`),
  );
  companions.forEach((c, i) => {
    if (c.product === m.id) add("M-CP-1", "companion_invalid", ptr("companions", i, "product"), "an app is not its own companion");
    // M-CP-3 (v0.1.13, G4/C82): the wildcard companion is ONLY tb.holds_pending / read; tb.holds_pending is the only
    // standard op a companion may name
    const std = c.operations.filter((o) => o.startsWith("tb."));
    if (std.some((o) => o !== HOLDS_PENDING_OP)) add("M-CP-3", "companion_invalid", ptr("companions", i, "operations"), `standard op ${std.join(",")} cannot be a companion op (only ${HOLDS_PENDING_OP})`);
    if (c.product === "*" && (c.operations.length !== 1 || c.operations[0] !== HOLDS_PENDING_OP || c.crud.length !== 1 || c.crud[0] !== "read")) {
      add("M-CP-3", "companion_invalid", ptr("companions", i), `a wildcard companion ("*") needs exactly operations ["${HOLDS_PENDING_OP}"] and crud ["read"]`);
    }
  });

  const unlocks = m.unlocks ?? [];
  const opIds = new Set(m.operations.map((o) => o.id));
  const skillIds = new Set((m.skills ?? []).map((s) => s.id));
  const products = new Set(companions.map((c) => c.product));
  uniq(
    unlocks,
    (u) => u.id,
    (u, i) => add("M-UL-1", "unlock_invalid", ptr("unlocks", i, "id"), `unlock id ${u.id} not unique`),
  );
  unlocks.forEach((u, i) => {
    const p = ptr("unlocks", i);
    if (!products.has(u.requires)) add("M-UL-1", "unlock_invalid", `${p}/requires`, `${u.requires} is not a declared companion`);
    for (const o of u.provides.operations ?? []) if (!opIds.has(o)) add("M-UL-1", "unlock_invalid", `${p}/provides/operations`, `operation ${o} not declared`);
    for (const s of u.provides.skills ?? []) if (!skillIds.has(s)) add("M-UL-1", "unlock_invalid", `${p}/provides/skills`, `skill ${s} not declared`);
  });
}

function skillHintRules(m: Manifest, idx: SettingsIndex, add: Add): void {
  const skills = m.skills ?? [];
  uniq(
    skills,
    (s) => s.id,
    (s, i) => add("M-SK-1", "skill_invalid", ptr("skills", i, "id"), `skill id ${s.id} not unique`),
  );
  uniq(
    skills,
    (s) => s.file,
    (s, i) => add("M-SK-1", "skill_invalid", ptr("skills", i, "file"), `skill file ${s.file} not unique`),
  );
  for (const [i, s] of skills.entries()) checkCondition(s.when, ptr("skills", i, "when"), idx.fields, null, "M-SK-1", "skill_invalid", add);
  uniq(
    m.harnessHints,
    (h) => h.harness,
    (h, i) => add("M-HH-1", "hint_duplicate", ptr("harnessHints", i, "harness"), `second hint for ${h.harness}`),
  );
}

const CRON_RANGES: [number, number][] = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 7],
];

function cronFieldOk(field: string, [lo, hi]: [number, number]): boolean {
  return field.split(",").every((part) => {
    const m = /^(\*|(\d+)(?:-(\d+))?)(?:\/(\d+))?$/.exec(part);
    if (!m) return false;
    if (m[4] !== undefined && Number(m[4]) < 1) return false;
    if (m[1] === "*") return true;
    const a = Number(m[2]);
    const b = m[3] === undefined ? a : Number(m[3]);
    return a >= lo && b <= hi && a <= b;
  });
}

function backupArtifactRouteRules(m: Manifest, add: Add): void {
  const dataVolumes = new Set(m.runtime.volumes.filter((v) => v.purpose === "data").map((v) => v.id));
  m.backups.files?.forEach((f, i) => {
    if (!dataVolumes.has(f.volume)) add("M-BK-1", "backup_invalid", ptr("backups", "files", i, "volume"), `${f.volume} is not an app data volume`);
  });
  const fields = m.backups.schedule.split(" ");
  if (!fields.every((f, i) => cronFieldOk(f, CRON_RANGES[i]))) add("M-BK-1", "backup_invalid", "/backups/schedule", "cron field out of range");

  const prefix = `${m.source.repo.replace(/\/+$/, "")}/releases/download/`;
  uniq(
    m.artifacts,
    (a) => a.id,
    (a, i) => add("M-AR-1", "artifact_invalid", ptr("artifacts", i, "id"), `artifact id ${a.id} not unique`),
  );
  m.artifacts?.forEach((a, i) => {
    if (!a.url.startsWith(prefix)) add("M-AR-1", "artifact_invalid", ptr("artifacts", i, "url"), `url must start with ${prefix}`);
  });
  uniq(
    m.publicRoutes,
    (r) => r.path,
    (r, i) => add("M-PR-1", "route_duplicate", ptr("publicRoutes", i, "path"), `public route ${r.path} repeated`),
  );
  // v0.1.21 (spec 0.1.43, LA-1 C232): at most one viewer route, path exactly /v (served only by the views service)
  const viewers = (m.publicRoutes ?? []).map((r, i) => ({ r, i })).filter((x) => x.r.purpose === "viewer");
  viewers.forEach(({ r, i }, k) => {
    if (k > 0) add("M-PR-2", "viewer_route_invalid", ptr("publicRoutes", i, "purpose"), "at most one viewer route");
    if (r.path !== "/v") add("M-PR-2", "viewer_route_invalid", ptr("publicRoutes", i, "path"), "a viewer route has path /v");
  });
  // v0.1.21 (spec 0.1.43, LR-1 C234): `listing` only on agent ops
  m.operations.forEach((op, i) => {
    if (op.listing !== undefined && op.audience !== "agent") add("M-OP-11", "listing_invalid", ptr("operations", i, "listing"), "listing applies to agent ops only");
  });
  // v0.1.31 (spec 0.1.73, M4b; QA-SPEC48-2): `listing: "lazy"` only on STATIC agent ops, and the manifest states
  // requires.bridge >= the first bridge with `lazy_tools` (an older bridge has no fallback: the app would lose every tool)
  let lazy = false;
  m.operations.forEach((op, i) => {
    if ((op.listing as string | undefined) !== "lazy") return;
    lazy = true;
    if (op.dynamic !== undefined) add("M-OP-13", "listing_invalid", ptr("operations", i, "listing"), "lazy applies to static agent ops only (a dynamic family is already one search away)");
  });
  if (lazy) {
    const rb = m.requires?.bridge;
    if (typeof rb !== "string" || !/^\d+\.\d+\.\d+/.test(rb) || compareSemver(rb, LAZY_LISTING_MIN_BRIDGE) < 0) {
      add("M-OP-13", "listing_invalid", ptr("requires", "bridge"), `a manifest with lazy ops states requires.bridge >= ${LAZY_LISTING_MIN_BRIDGE} (the first bridge with lazy_tools)`);
    }
  }
}

// ───────────────────────────── public surface ─────────────────────────────

/** `"sha256:" + hex(sha256(JCS(manifest)))` (MANIFEST §1). */
export function manifestDigest(manifest: Manifest): `sha256:${string}` {
  return digest(manifest as unknown as Json);
}

/** Schema + every M-* rule. Returns the manifest (same object) and its digest, or every issue found. */
export function validateManifest(json: unknown): ManifestValidation {
  const schemaErrors = checkSchema(json);
  if (schemaErrors.length) return { ok: false, errors: schemaErrors.map(eventSchemaIssue) };
  const m = json as Manifest;
  let bytes: number;
  try {
    bytes = Buffer.byteLength(canonicalize(m as unknown as Json));
  } catch (e) {
    return { ok: false, errors: [{ path: "", rule: "schema", code: "schema_invalid", message: `not a JSON value: ${(e as Error).message}` }] };
  }
  const { errors, add } = collector();
  // SPEC-GAP: MANIFEST §1 states the 256 KiB limit without a code; `manifest_too_large` is used.
  if (bytes > MAX_MANIFEST_BYTES) {
    add("M-DOC-0", "manifest_too_large", "", `manifest is ${bytes} JCS bytes (max ${MAX_MANIFEST_BYTES})`);
    return { ok: false, errors };
  }
  docRules(m, "", add);
  const licence = licenseProblem(m.source.license);
  if (licence) add("M-ID-1", "license_invalid", "/source/license", licence);
  uniq(
    m.discovery.intents,
    (s) => s.trim().toLowerCase(),
    (s, i) => add("M-ID-2", "intent_duplicate", ptr("discovery", "intents", i), `intent "${s}" repeated`),
  );
  const idx = indexSettings(m);
  runtimeRules(m, idx, add);
  operationRules(m, add);
  scopeRules(m, add);
  settingsRules(m, idx, add);
  hookRules(m, add);
  companionRules(m, add);
  skillHintRules(m, idx, add);
  backupArtifactRouteRules(m, add);
  eventRules(m, add);
  return errors.length ? { ok: false, errors } : { ok: true, manifest: m, digest: manifestDigest(m) };
}

/**
 * M-CP-2 (Core at deploy, conformance): each companion's target ops exist with audience agent, every op.crud ⊆ crud and
 * crud ⊆ ∪ op.crud. Companions whose target manifest is not in `targets` are not checked: the companion grant is minted
 * only once both apps are deployed (MANIFEST §9), and the caller passes the deployed targets.
 */
export function validateCompanions(manifest: Manifest, targets: readonly Manifest[]): ManifestValidation {
  const { errors, add } = collector();
  const byId = new Map(targets.map((t) => [t.id, t]));
  manifest.companions?.forEach((c, ci) => {
    if (c.product === "*") return; // M-CP-3: every app serves tb.holds_pending (standard op)
    const target = byId.get(c.product);
    if (!target) return;
    const p = ptr("companions", ci);
    const ops = new Map<string, Operation>(target.operations.map((o) => [o.id, o]));
    const union = new Set<string>();
    for (const id of c.operations) {
      if (id === HOLDS_PENDING_OP) {
        union.add("read");
        if (!c.crud.includes("read")) add("M-CP-2", "companion_op_invalid", `${p}/crud`, `${c.product}.${id} needs crud read`);
        continue;
      }
      const op = ops.get(id);
      if (op?.audience !== "agent") {
        add("M-CP-2", "companion_op_invalid", `${p}/operations`, `${c.product} has no agent operation ${id}`);
        continue;
      }
      for (const x of op.crud) union.add(x);
      if (!isSubset(op.crud, c.crud)) add("M-CP-2", "companion_op_invalid", `${p}/crud`, `${c.product}.${id} needs crud ${op.crud.join(",")}`);
    }
    const extra = c.crud.filter((x) => !union.has(x));
    if (extra.length) add("M-CP-2", "companion_op_invalid", `${p}/crud`, `crud ${extra.join(",")} not needed by the listed operations`);
  });
  return errors.length ? { ok: false, errors } : { ok: true, manifest, digest: manifestDigest(manifest) };
}

// SPEC-GAP: MANIFEST §14 forbids hand-written copies without naming a code; `hand_written_artifact` is used.
const HAND_WRITTEN = new Set(["openapi.json", "openapi.yaml", "openapi.yml", "manifest.json", "recipe.json"]);
const FRONTMATTER_KEYS = new Set(["name", "description"]);

/**
 * CI / CLI only, the one export that reads files (M-SK-2, M-RT-9, M-ST-7 with skill bodies, M-AR-1 digest format, §14).
 * Path bases (MANIFEST §3, v0.1.11 (C70)):
 * - `repoDir` is the repository root. Build paths are REPO-relative: `runtime.build.context` and `runtime.services[].build.context`
 *   must be directories, the matching `dockerfile` files, all under `repoDir` (`build_path_invalid`).
 * - `manifestDir` is the directory that contains the manifest file (default `repoDir`: a single-app repo keeps the manifest
 *   at its root). Skill files and every other app file are MANIFEST-relative and resolve from it; so does the hand-written
 *   artifact scan ("beside the manifest").
 * Skill checks: each skill file exists under `manifestDir`, frontmatter is exactly `{name = id, description}`, only allowed
 * variables, `{{settings.<key>}}` names a declared field, `{{scope.<type>.<kind>}}` a declared default grant, text
 * sanitized, ≤ 64 KiB; no hand-written OpenAPI / manifest.json / recipe.json beside the manifest.
 */
export async function validateAppFiles(manifest: Manifest, repoDir: string, manifestDir: string = repoDir): Promise<ManifestValidation> {
  const { errors, add } = collector();
  const repoRoot = resolve(repoDir);
  const root = resolve(manifestDir);
  const idx = indexSettings(manifest);
  const scopeKinds = new Map((manifest.scopes ?? []).map((s) => [s.type, new Set<string>(s.defaultGrants.map((g) => g.kind))]));
  const settingRefs = new Set<string>();

  const builds: { p: string; context: string; dockerfile: string }[] = [
    { p: ptr("runtime", "build"), ...manifest.runtime.build },
    ...(manifest.runtime.services ?? []).flatMap((svc, i) => (svc.build ? [{ p: ptr("runtime", "services", i, "build"), ...svc.build }] : [])),
  ];
  for (const b of builds) {
    const bad = (field: "context" | "dockerfile", msg: string): void => add("M-RT-9", "build_path_invalid", `${b.p}/${field}`, `${b[field]}: ${msg}`);
    for (const [field, kind] of [["context", "directory"], ["dockerfile", "file"]] as const) {
      const target = resolve(repoRoot, b[field]);
      if (target !== repoRoot && !target.startsWith(repoRoot + sep)) {
        bad(field, "path escapes the repository (build paths are repo-relative)");
        continue;
      }
      const st = await stat(target).catch(() => null);
      if (!st) bad(field, `not found under the repository root ${repoDir} (build paths are repo-relative)`);
      else if (kind === "directory" ? !st.isDirectory() : !st.isFile()) bad(field, `not a ${kind}`);
    }
  }

  for (const [i, skill] of (manifest.skills ?? []).entries()) {
    const p = ptr("skills", i, "file");
    const bad = (msg: string): void => add("M-SK-2", "skill_file_invalid", p, `${skill.file}: ${msg}`);
    const file = resolve(root, skill.file);
    if (!file.startsWith(root + sep)) {
      bad("path escapes the manifest directory (skill files are manifest-relative)");
      continue;
    }
    let bytes: Buffer;
    try {
      bytes = await readFile(file);
    } catch {
      bad("file not found (skill files are manifest-relative)");
      continue;
    }
    if (bytes.length > MAX_SKILL_BYTES) {
      bad(`larger than ${MAX_SKILL_BYTES} bytes`);
      continue;
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      bad("not valid UTF-8");
      continue;
    }
    const parsed = parseSkillFile(text);
    if ("error" in parsed) {
      bad(parsed.error);
      continue;
    }
    for (const k of Object.keys(parsed.frontmatter)) if (!FRONTMATTER_KEYS.has(k)) bad(`frontmatter key ${k} not allowed`);
    if (parsed.frontmatter.name !== skill.id) bad(`frontmatter name must be ${skill.id}`);
    if (!parsed.frontmatter.description) bad("frontmatter description missing");
    for (const [, raw] of text.matchAll(VARIABLE_RE)) {
      const v = parseVariable(raw);
      if (!v) bad(`variable {{${raw}}} not allowed`);
      else if (v.kind === "settings") {
        settingRefs.add(v.key);
        if (!idx.fields.has(v.key)) bad(`{{settings.${v.key}}} names no declared setting`);
      } else if (v.kind === "scope" && !scopeKinds.get(v.type)?.has(v.grantKind)) {
        bad(`{{scope.${v.type}.${v.grantKind}}} names no declared default grant`);
      }
    }
    const violation = skillTextViolation(text);
    if (violation) bad(`content not allowed: ${violation}`);
  }

  if (manifest.skills?.length) unusedSettings(manifest, idx, settingRefs, add);

  manifest.artifacts?.forEach((a, i) => {
    if (!/^[a-f0-9]{64}$/.test(a.sha256)) add("M-AR-1", "artifact_invalid", ptr("artifacts", i, "sha256"), "sha256 must be 64 lower-case hex");
  });

  let entries: string[] = [];
  try {
    entries = await readdir(root);
  } catch {
    add("§14", "hand_written_artifact", "", `manifest directory ${manifestDir} not readable`);
  }
  for (const name of entries) {
    if (HAND_WRITTEN.has(name.toLowerCase())) add("§14", "hand_written_artifact", "", `hand-written ${name} beside the manifest is forbidden`);
  }
  return errors.length ? { ok: false, errors } : { ok: true, manifest, digest: manifestDigest(manifest) };
}
