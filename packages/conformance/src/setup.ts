// Setup fixtures (CONFORMANCE v0.1.18, package 0.1.12): the `setup` steps of `tealbrick-conformance.json` run once after
// the first status push, before the checks, in order. Each step calls one op as the owner (person session), agent A / B
// or the suite's companion app caller, and captures values from its `output` by JSON pointer. `${name}` placeholders
// (whole-string values only) in later step inputs and in `inputs` / `inputsAs` are replaced by the captured values. A
// failed step blocks its captures: every check that resolves an input through one reports not_run naming the step and
// its answer (never a silent pass).
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { PLACEHOLDER_RE, type SetupCaller, type SetupStep } from "./waivers.ts";

/** One setup call's answer: `ok` with the op `output`, or the answer shown in reports (e.g. `403 area_required`). */
export interface SetupAnswer {
  ok: boolean;
  output: unknown;
  shown: string;
}

export interface SetupResult {
  /** placeholder name → value (built-ins + captures of passed steps) */
  values: Map<string, Json>;
  /** placeholder name → why it has no value ("setup step <id> failed: <answer>") */
  blocked: Map<string, string>;
  /** one line per step for the report notes */
  notes: string[];
}

export interface Resolved {
  value: Json;
  /** reasons of the blocked placeholders `value` still holds (empty: fully resolved) */
  blocked: string[];
}

/** RFC 6901 JSON pointer into `doc`; `undefined` when the path does not exist. */
export function jsonPointer(doc: unknown, pointer: string): unknown {
  if (pointer === "") return doc;
  let cur: unknown = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(key)) return undefined;
      cur = cur[Number(key)];
    } else if (cur && typeof cur === "object" && Object.hasOwn(cur, key)) cur = (cur as Record<string, unknown>)[key];
    else return undefined;
    if (cur === undefined) return undefined;
  }
  return cur;
}

/** Replaces whole-string `${name}` placeholders in `v`; blocked or unknown names stay in place and are reported. */
export function resolvePlaceholders(v: Json, r: Pick<SetupResult, "values" | "blocked">): Resolved {
  const blocked: string[] = [];
  const walk = (x: Json): Json => {
    if (typeof x === "string") {
      const m = PLACEHOLDER_RE.exec(x);
      if (!m) return x;
      const name = m[1] as string;
      if (r.values.has(name)) return r.values.get(name) as Json;
      blocked.push(r.blocked.get(name) ?? `placeholder \${${name}} has no value`);
      return x;
    }
    if (Array.isArray(x)) return x.map(walk);
    if (x && typeof x === "object") return Object.fromEntries(Object.entries(x).map(([k, y]) => [k, walk(y as Json)]));
    return x;
  };
  const value = walk(v);
  return { value, blocked: [...new Set(blocked)] };
}

/** Runs `steps` in order through `call`; `builtins` seed the placeholder values (`tb.agentA`, …). */
export async function runSetup(
  steps: readonly SetupStep[],
  builtins: Record<string, Json>,
  call: (as: SetupCaller, op: string, input: Json) => Promise<SetupAnswer>,
  /** continue an earlier result (the deferred `capsAgent` steps): the captures of `steps` are cleared first, `builtins` are added */
  into?: SetupResult,
): Promise<SetupResult> {
  const r: SetupResult = into ?? { values: new Map(), blocked: new Map(), notes: [] };
  for (const [k, v] of Object.entries(builtins)) r.values.set(k, v);
  if (into)
    for (const step of steps)
      for (const name of Object.keys(step.capture)) {
        r.values.delete(name);
        r.blocked.delete(name);
      }
  const block = (step: SetupStep, why: string) => {
    for (const name of Object.keys(step.capture)) r.blocked.set(name, why);
    r.notes.push(`setup: ${why}`);
  };
  for (const step of steps) {
    const input = resolvePlaceholders(step.input, r);
    if (input.blocked.length) {
      block(step, `setup step ${step.id} not run: its input needs ${input.blocked.join("; ")}`);
      continue;
    }
    let a: SetupAnswer;
    try {
      a = await call(step.as, step.op, input.value);
    } catch (e) {
      a = { ok: false, output: undefined, shown: `error: ${e instanceof Error ? e.message : String(e)}` };
    }
    if (!a.ok) {
      block(step, `setup step ${step.id} (${step.as} ${step.op}) failed: ${a.shown}`);
      continue;
    }
    const missing = Object.entries(step.capture).filter(([, ptr]) => jsonPointer(a.output, ptr) === undefined);
    if (missing.length) {
      block(step, `setup step ${step.id} (${step.as} ${step.op}) answered ${a.shown} but its output has no ${missing.map(([n, p]) => `${n} (${p || "(whole output)"})`).join(", ")}`);
      continue;
    }
    for (const [name, ptr] of Object.entries(step.capture)) r.values.set(name, jsonPointer(a.output, ptr) as Json);
    const caps = Object.keys(step.capture);
    r.notes.push(`setup: step ${step.id} (${step.as} ${step.op}) ${a.shown}${caps.length ? `; captured ${caps.join(", ")}` : ""}`);
  }
  return r;
}
