// The filter of the standard Holds and Receipts pages (C382 batch 4): a filter never hides that it is on, held approvals
// that a filter hides are counted, and a paged list says that the text filter reads only the loaded rows. The page is
// compiled with the build tsconfig and rendered in happy-dom against a stub server.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { rmSync } from "node:fs";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";
import { Window } from "happy-dom";
import type { ReactElement } from "react";

type Standard = typeof import("../src/ui/standard.tsx");

const root = fileURLToPath(new URL("..", import.meta.url));
const outDir = join(root, "dist", "ui-test-filter");

const win = new Window({ url: "http://localhost/a/kanban/", width: 1280, height: 860 });
const g = globalThis as Record<string, unknown>;
for (const k of ["window", "document", "navigator", "location", "history", "sessionStorage", "localStorage", "HTMLElement", "HTMLInputElement", "HTMLButtonElement", "HTMLDialogElement", "Element", "Node", "Event", "MouseEvent", "KeyboardEvent", "MutationObserver"]) {
  const v = (win as unknown as Record<string, unknown>)[k];
  if (v === undefined) continue;
  try {
    g[k] = v;
  } catch {
    Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  }
}
g.IS_REACT_ACT_ENVIRONMENT = true;

const ULID = "01HZX3K8Q2V4N6P8R0S2T4V6W8";
const AGENTS = [
  { id: "agt_1", name: "Front desk" },
  { id: "agt_2", name: "Research partner" },
  { id: "agt_3", name: "Scout" },
];
type StubHold = { id: string; caller: { type: "agent"; id: string; name: string }; op: string; holdFamily: string | null; heldBy: string | null; summary: string; status: "held" };
const hold = (n: number): StubHold => {
  const a = AGENTS[n % 3] as (typeof AGENTS)[number];
  return { id: `hld_${ULID.slice(0, 24)}${String(n).padStart(2, "0")}`, caller: { type: "agent", ...a }, op: n % 2 ? "issue_move" : "issue_delete", holdFamily: null, heldBy: null, summary: `Change number ${n}`, status: "held" };
};
type StubReceipt = { id: string; caller: { type: "agent"; id: string; name: string }; op: string; status: string; summary: string; createdAt: number };
const receipt = (n: number): StubReceipt => {
  const a = AGENTS[n % 3] as (typeof AGENTS)[number];
  return { id: `rcp_${n}`, caller: { type: "agent", ...a }, op: "issue_move", status: "run", summary: `Moved card ${n}`, createdAt: Date.now() - n * 60_000 };
};

const PAGE = 12;
interface Stub {
  holds: StubHold[];
  receipts: StubReceipt[];
  calls: { op: string; input: Record<string, unknown> }[];
}
const stub: Stub = { holds: [], receipts: [], calls: [] };
const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url, "http://localhost");
  const path = url.pathname.replace("/a/kanban/tb/v1/", "");
  if (path === "session") return json(200, { principal: { type: "person", id: "per_1", instance: "ins_1" }, csrf: "csrf-token", idempotencyRequired: [] });
  const op = /^ops\/(.+)$/.exec(path)?.[1];
  if (!op) return json(404, { error: { code: "not_found", message: "not found" } });
  const body = JSON.parse(String(init?.body ?? "{}")) as { input?: Record<string, unknown> };
  const inp = body.input ?? {};
  stub.calls.push({ op, input: inp });
  if (op === "tb.holds_list") return json(200, { status: "ok", output: { items: stub.holds, nextCursor: null } });
  if (op === "tb.agents_list") return json(200, { status: "ok", output: { agents: AGENTS.map((a) => ({ ...a, mode: "read", status: "active" })) } });
  if (op === "tb.receipts_list") {
    const all = inp.caller ? stub.receipts.filter((r) => r.caller.id === inp.caller) : stub.receipts;
    const from = inp.cursor ? Number(inp.cursor) : 0;
    const items = all.slice(from, from + PAGE);
    return json(200, { status: "ok", output: { items, nextCursor: from + PAGE < all.length ? String(from + PAGE) : null } });
  }
  return json(404, { error: { code: "not_found", message: op } });
}) as typeof fetch;

const { act, createElement: h } = await import("react");
const { createRoot } = await import("react-dom/client");
const { TbProvider } = await import("@opt2-tealbrick/miniapp-sdk/client");

async function flush() {
  for (let i = 0; i < 4; i++) await act(async () => new Promise((r) => setTimeout(r, 0)));
}
async function mount(el: ReactElement) {
  const host = document.createElement("div");
  document.body.appendChild(host);
  const r = createRoot(host);
  await act(async () => r.render(h(TbProvider, { product: "kanban" }, el)));
  await flush();
  return {
    host,
    unmount: async () => {
      await act(async () => r.unmount());
      host.remove();
    },
  };
}
const click = async (el: Element) => {
  await act(async () => (el as HTMLElement).click());
  await flush();
};
const type = async (input: HTMLInputElement, value: string) => {
  await act(async () => {
    Object.getOwnPropertyDescriptor(win.HTMLInputElement.prototype, "value")?.set?.call(input, value);
    input.dispatchEvent(new win.Event("input", { bubbles: true }) as unknown as Event);
  });
};
const buttons = (host: Element, text: string) => [...host.querySelectorAll("button")].filter((b) => b.textContent?.trim() === text);
const text = (host: Element) => host.textContent ?? "";
const KEY = "tb-filter:/a/kanban/:";
const remember = (k: string, v: string) => localStorage.setItem(`${KEY}${k}`, v);

let std: Standard;
before(() => {
  const tsc = spawnSync(join(root, "node_modules", ".bin", "tsc"), ["-p", "tsconfig.build.json", "--outDir", outDir], { cwd: root, encoding: "utf8" });
  assert.equal(tsc.status, 0, `${tsc.stdout}${tsc.stderr}`);
});
before(async () => {
  std = (await import(pathToFileURL(join(outDir, "ui", "standard.js")).href)) as Standard;
});
after(() => rmSync(outDir, { recursive: true, force: true }));

const reset = () => {
  localStorage.clear();
  stub.holds = [];
  stub.receipts = [];
  stub.calls = [];
};

describe("Holds filter", () => {
  it("a short list shows no filter bar", async () => {
    reset();
    stub.holds = Array.from({ length: 3 }, (_, i) => hold(i));
    const m = await mount(h(std.HoldsPage, { empty: "Nothing waits." }));
    assert.equal(m.host.querySelector("input"), null);
    assert.equal(m.host.querySelectorAll(".item").length, 3);
    await m.unmount();
  });

  it("a long list: text filter shows N of M, counts what it hides as an alert, keeps Approve and Deny per row, Clear brings all back", async () => {
    reset();
    stub.holds = Array.from({ length: 10 }, (_, i) => hold(i));
    const m = await mount(h(std.HoldsPage, { empty: "Nothing waits." }));
    assert.equal(m.host.querySelectorAll(".item").length, 10);
    assert.doesNotMatch(text(m.host), /hidden by the filter/);
    await type(m.host.querySelector("input") as HTMLInputElement, "Change number 7");
    assert.equal(m.host.querySelectorAll(".item").length, 1);
    assert.match(text(m.host), /Showing 1 of 10 held approvals\./);
    const alert = [...m.host.querySelectorAll('[role="alert"]')].map((a) => a.textContent).join(" ");
    assert.match(alert, /9 held approvals are hidden by the filter\./);
    const row = m.host.querySelector(".item") as Element;
    assert.equal(buttons(row, "Approve").length + buttons(row, "Deny").length, 2, "Approve and Deny stay per row");
    await click(buttons(m.host, "Clear filter")[0] as Element);
    assert.equal(m.host.querySelectorAll(".item").length, 10);
    assert.doesNotMatch(text(m.host), /hidden by the filter/);
    await m.unmount();
  });

  it("a remembered filter is visible after reload: the bar shows the text, N of M and the hidden count", async () => {
    reset();
    stub.holds = Array.from({ length: 3 }, (_, i) => hold(i));
    remember("holds", "Change number 1");
    const m = await mount(h(std.HoldsPage, { empty: "Nothing waits." }));
    assert.equal((m.host.querySelector("input") as HTMLInputElement).value, "Change number 1");
    assert.match(text(m.host), /Showing 1 of 3 held approvals\./);
    assert.match(text(m.host), /2 held approvals are hidden by the filter\./);
    await m.unmount();
  });

  it("a remembered agent is a filter too, and a filter that hides everything does not show the empty sentence", async () => {
    reset();
    stub.holds = Array.from({ length: 4 }, (_, i) => hold(i * 3)); // all by agt_1
    remember("holds:agent", "agt_2");
    const m = await mount(h(std.HoldsPage, { empty: "Nothing waits for your approval." }));
    assert.equal(m.host.querySelectorAll(".item").length, 0);
    assert.doesNotMatch(text(m.host), /Nothing waits for your approval/, "four approvals wait: the empty sentence would be false");
    assert.match(text(m.host), /4 held approvals are hidden by the filter\./);
    assert.match(text(m.host), /No held approval matches\./);
    await m.unmount();
  });

  it("the deep link ignores the filter", async () => {
    reset();
    stub.holds = Array.from({ length: 10 }, (_, i) => hold(i));
    remember("holds", "no such text");
    const m = await mount(h(std.HoldsPage, { empty: "Nothing waits.", only: (stub.holds[4] as StubHold).id }));
    assert.equal(m.host.querySelectorAll(".item").length, 1);
    assert.equal(m.host.querySelector("input"), null);
    await m.unmount();
  });
});

describe("Receipts filter", () => {
  it("a paged list: a text with no match says the filter read only the loaded rows and keeps Show older in reach; Show older then reads more", async () => {
    reset();
    stub.receipts = Array.from({ length: PAGE + 2 }, (_, i) => receipt(i));
    remember("receipts", "Moved card 13");
    const m = await mount(h(std.ReceiptsPage, {}));
    assert.equal(m.host.querySelectorAll("tbody tr").length, 0);
    assert.match(text(m.host), /No loaded receipt matches\./);
    assert.match(text(m.host), new RegExp(`The filter searches only the ${PAGE} receipts loaded so far\\.`));
    assert.doesNotMatch(text(m.host), /The filter searched all/);
    assert.match(text(m.host), new RegExp(`Showing 0 of ${PAGE} loaded receipts\\.`));
    const older = buttons(m.host, "Show older");
    assert.ok(older.length >= 1, "Show older is in reach");
    await click(older[0] as Element);
    assert.equal(m.host.querySelectorAll("tbody tr").length, 1);
    assert.match(text(m.host), /Showing 1 of 14 receipts\./);
    assert.doesNotMatch(text(m.host), /loaded so far/, "everything is loaded now");
    assert.equal(buttons(m.host, "Show older").length, 0);
    await m.unmount();
  });

  it("a complete list with no match says all rows were searched", async () => {
    reset();
    stub.receipts = Array.from({ length: 5 }, (_, i) => receipt(i));
    remember("receipts", "zzz");
    const m = await mount(h(std.ReceiptsPage, {}));
    assert.match(text(m.host), /No receipt matches\. The filter searched all 5 receipts\./);
    assert.match(text(m.host), /Showing 0 of 5 receipts\./);
    await m.unmount();
  });

  it("the agent filter is the server's: the call carries caller, and the count says it is not a search of loaded rows", async () => {
    reset();
    stub.receipts = Array.from({ length: 60 }, (_, i) => receipt(i));
    remember("receipts:agent", "agt_2");
    const m = await mount(h(std.ReceiptsPage, {}));
    const first = stub.calls.find((c) => c.op === "tb.receipts_list");
    assert.equal(first?.input.caller, "agt_2");
    assert.equal(m.host.querySelectorAll("tbody tr").length, PAGE);
    assert.ok([...m.host.querySelectorAll("tbody tr")].every((tr) => /Research partner/.test(tr.textContent ?? "")));
    assert.match(text(m.host), new RegExp(`Showing ${PAGE} of ${PAGE} loaded receipts\\.`));
    assert.doesNotMatch(text(m.host), /searches only/, "no text typed: the server did the filtering");
    await click(buttons(m.host, "Show older")[0] as Element);
    const second = stub.calls.filter((c) => c.op === "tb.receipts_list")[1];
    assert.deepEqual(second?.input, { caller: "agt_2", cursor: String(PAGE) });
    assert.equal(m.host.querySelectorAll("tbody tr").length, 20, "all 20 receipts of the agent come in two pages, none of another agent");
    await m.unmount();
  });

  it("Clear filter removes the text and the agent and loads the whole list again", async () => {
    reset();
    stub.receipts = Array.from({ length: 30 }, (_, i) => receipt(i));
    remember("receipts:agent", "agt_1");
    remember("receipts", "card");
    const m = await mount(h(std.ReceiptsPage, {}));
    await click(buttons(m.host, "Clear filter")[0] as Element);
    assert.equal((m.host.querySelector("input") as HTMLInputElement).value, "");
    assert.equal(localStorage.getItem(`${KEY}receipts`), "");
    assert.equal(localStorage.getItem(`${KEY}receipts:agent`), "");
    assert.equal(m.host.querySelectorAll("tbody tr").length, PAGE);
    assert.equal(buttons(m.host, "Clear filter").length, 0, "no filter is on");
    await m.unmount();
  });

  it("no receipts and no filter: the app's empty sentence, no filter bar", async () => {
    reset();
    const m = await mount(h(std.ReceiptsPage, { empty: "No agent changes recorded yet." }));
    assert.equal(m.host.querySelector(".tb-empty h3")?.textContent, "No agent changes recorded yet.");
    assert.equal(m.host.querySelector("input"), null);
    await m.unmount();
  });
});
