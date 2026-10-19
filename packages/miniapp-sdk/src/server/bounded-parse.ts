// Ported from live-artifacts src/bounded-parse.ts @1d9c462 (opt2-tealbrick-live-artifacts, main). One implementation of the bounded
// parse5 parse for both products: the logic below is that file's, unchanged; Live Artifacts can import it from
// @opt2-tealbrick/miniapp-sdk instead of keeping a copy. If a bound changes, change it in ONE place and keep both in step.
// One parse5 parse with its WORK bounded while the tree is built (C238, C269). A source within the whole-source caps (size, tags,
// attributes per tag) can still make parse5's tree builder do far more work than the source shows; each bound below is a shape
// that cost seconds of one CPU at write time (S6/S7/S8 re-checks; the miniapp-sdk 0.1.33 draft has the first four):
// - depth: each insert records the parent's depth + 1; past `maxDepth` it throws (60,000 unclosed <div>: ~10 s). A node that is
//   inserted again or arrives with children (adoption agency, foster parenting move children onto a new element before it is
//   attached) has its subtree measured again when it lands deeper than recorded, and a recorded depth is never lowered, so it is
//   never below the real one. The re-measuring is bounded by MAX_MOVE_VISITS.
// - copied attributes: an element whose attribute list an earlier element already used is a copy made by the parser (a
//   formatting element re-opened, an adoption agency clone), charged attrs² against ATTRIBUTE_BUDGET (`<p><b a0..a255>` +
//   `<p>x` × 20,000 = 79 KB: 39 MB of output in 15 s).
// - <html>/<body> attribute merging (adoptAttributes): an incremental name set (parse5 rebuilds one per call: quadratic), the
//   element capped at MAX_ATTRIBUTES, its growth charged against the same budget (`<html z0><html z1>…` × 30,000: 12–26 s).
// - element count: at most `maxElements` created per parse.
// - child-list work: parse5 finds a reference node with indexOf from the START of the child list and shifts the list on every
//   insert before and every detach. Text or elements foster-parented before an open <table> after 60,000 siblings cost 5–30 s
//   (`<br>` × N + `<table>` + `a ` × M); the adoption agency detaching 99,000 children one by one cost 12 s. Here the reference
//   node is searched from the END (an open table is the last child), and every search and shift is charged against
//   MAX_CHILD_WORK.
// The bounds are the same for every caller; `maxDepth` and `maxElements` come from the caller's rules.
import { type DefaultTreeAdapterMap, defaultTreeAdapter, parse } from "parse5";

export const PARSE_MAX_ATTRIBUTES = 2048;
export const PARSE_ATTRIBUTE_BUDGET = 4_194_304;
/** Child-list entries read or shifted per parse (~3 ns each). A benign page spends a few per insert; 2^24 refuses a hostile page
 *  in ~50 ms and still allows one mis-nested formatting element around a block of ~5,800 direct children. */
export const PARSE_MAX_CHILD_WORK = 1 << 24;
const MAX_MOVE_VISITS_PER_ELEMENT = 10;

/** Thrown when a bound is passed; callers fail closed. */
export class ParseLimitExceeded extends Error {}

export interface ParseBounds {
  /** deepest node depth (document 0, html 1; template content one below its template) */
  maxDepth: number;
  /** most elements created by one parse (parsed and copied by the parser) */
  maxElements: number;
}

/** The longest output accepted for an input of `n` characters: max(4 × n, n + 1 MiB). Benign pages grow by implied end tags and
 *  quoted values (at most 1.4× on the corpus); more is the parser multiplying re-opened formatting elements. */
export const maxOutputLength = (n: number): number => Math.max(4 * n, n + 1024 * 1024);

type Adapter = typeof defaultTreeAdapter;
type ParentNode = DefaultTreeAdapterMap["parentNode"];
type ChildNode = DefaultTreeAdapterMap["childNode"];
type Element = DefaultTreeAdapterMap["element"];
type Parent = { childNodes: object[]; content?: Parent };

export function boundedTreeAdapter(bounds: ParseBounds): Adapter {
  const depthOf = new WeakMap<object, number>();
  const usedAttrs = new WeakSet<object>();
  const names = new WeakMap<object, Set<string>>();
  let attributeBudget = PARSE_ATTRIBUTE_BUDGET;
  let childWork = PARSE_MAX_CHILD_WORK;
  let elements = 0;
  let moveVisits = 0;
  const over = (what: string): never => {
    throw new ParseLimitExceeded(`document over a parse bound: ${what}`);
  };
  const chargeAttributes = (cost: number): void => {
    attributeBudget -= cost;
    if (attributeBudget < 0) over("attributes copied by the parser");
  };
  const chargeWork = (cost: number): void => {
    childWork -= cost;
    if (childWork < 0) over("child-list work");
  };
  const isParent = (n: object): n is Parent => "childNodes" in n;
  /** Measures again the subtree under `node`, recorded at depth d. */
  const remeasure = (node: Parent, d: number): void => {
    if (node.content) {
      if (d + 1 > (depthOf.get(node.content) ?? -1)) depthOf.set(node.content, d + 1);
      remeasure(node.content, depthOf.get(node.content) as number);
    }
    for (const child of node.childNodes) {
      if (++moveVisits > MAX_MOVE_VISITS_PER_ELEMENT * bounds.maxElements) over("too many moved nodes");
      if (!isParent(child)) continue;
      if (d + 1 > bounds.maxDepth) over("nests too deeply");
      if (d + 1 > (depthOf.get(child) ?? -1)) depthOf.set(child, d + 1);
      remeasure(child, depthOf.get(child) as number);
    }
  };
  const place = (parent: object, child: object): void => {
    if (!isParent(child)) return; // text, comment, doctype: leaves
    const d = (depthOf.get(parent) ?? 0) + 1;
    if (d > bounds.maxDepth) over("nests too deeply");
    const old = depthOf.get(child);
    if (old !== undefined && d <= old) return; // same depth or shallower: the recorded depth stays an upper bound
    depthOf.set(child, d);
    if (child.childNodes.length > 0 || (child.content && child.content.childNodes.length > 0)) remeasure(child, d);
    else if (child.content) depthOf.set(child.content, d + 1);
  };
  /** Index of `ref` in `list`, searched from the end; the entries read and the entries an insert there shifts are charged. */
  const indexFromEnd = (list: ChildNode[], ref: ChildNode): number => {
    let i = list.length - 1;
    while (i >= 0 && list[i] !== ref) i--;
    chargeWork(2 * (list.length - i));
    return i;
  };
  return {
    ...defaultTreeAdapter,
    createElement(tagName, namespaceURI, attrs) {
      if (++elements > bounds.maxElements) over("too many elements");
      if (usedAttrs.has(attrs)) {
        if (attrs.length > PARSE_MAX_ATTRIBUTES) over("too many attributes");
        chargeAttributes(attrs.length * attrs.length);
      } else usedAttrs.add(attrs);
      return defaultTreeAdapter.createElement(tagName, namespaceURI, attrs);
    },
    appendChild(parent, child) {
      place(parent, child);
      defaultTreeAdapter.appendChild(parent, child);
    },
    insertBefore(parent: ParentNode, child: ChildNode, reference: ChildNode) {
      place(parent, child);
      const i = indexFromEnd(parent.childNodes, reference);
      parent.childNodes.splice(i, 0, child);
      child.parentNode = parent;
    },
    insertTextBefore(parent: ParentNode, text: string, reference: ChildNode) {
      const i = indexFromEnd(parent.childNodes, reference);
      const prev = parent.childNodes[i - 1];
      if (prev && defaultTreeAdapter.isTextNode(prev)) prev.value += text;
      else {
        const node = defaultTreeAdapter.createTextNode(text);
        parent.childNodes.splice(i, 0, node);
        node.parentNode = parent;
      }
    },
    detachNode(node: ChildNode) {
      const parent = node.parentNode;
      if (!parent) return;
      // indexOf from the start plus the shift after it: the whole list. The adoption agency moves a block's children one by one
      // from the front, so a block with n children costs n²/2 (shift() is O(n) too): 99,000 children took 12 s
      chargeWork(parent.childNodes.length);
      parent.childNodes.splice(parent.childNodes.indexOf(node), 1);
      node.parentNode = null;
    },
    setTemplateContent(template, content) {
      depthOf.set(content, (depthOf.get(template) ?? 0) + 1);
      defaultTreeAdapter.setTemplateContent(template, content);
    },
    adoptAttributes(recipient: Element, attrs) {
      let set = names.get(recipient);
      if (!set) {
        set = new Set(recipient.attrs.map((a) => a.name));
        names.set(recipient, set);
      }
      const before = recipient.attrs.length;
      for (const a of attrs) {
        if (set.has(a.name)) continue;
        set.add(a.name);
        recipient.attrs.push(a);
      }
      const after = recipient.attrs.length;
      if (after > PARSE_MAX_ATTRIBUTES) over("too many attributes");
      chargeAttributes(after * after - before * before);
    },
  };
}

/** One bounded parse (a fresh adapter: the budgets are per parse). Throws ParseLimitExceeded past a bound. */
export function boundedParse(html: string, bounds: ParseBounds, options: { scriptingEnabled?: boolean } = {}): DefaultTreeAdapterMap["document"] {
  return parse(html, { ...options, treeAdapter: boundedTreeAdapter(bounds) });
}
