import assert from "node:assert/strict";
import { test } from "node:test";
import { AGENT_DOCUMENT_MARKER, AGENT_DOCUMENT_MAX_BYTES, AGENT_DOCUMENT_UNAVAILABLE_TEXT, AGENT_DOCUMENT_RULES as R } from "../src/index.ts";

test("AGENT_DOCUMENT_RULES (0.1.25): frozen data, one marker, the 2 MiB viewer body cap", () => {
  assert.equal(R.version, 1);
  assert.equal(R.marker, AGENT_DOCUMENT_MARKER);
  assert.equal(AGENT_DOCUMENT_MARKER, "<!-- tb:sanitized v1 -->");
  assert.equal(R.maxInputBytes, AGENT_DOCUMENT_MAX_BYTES);
  assert.equal(AGENT_DOCUMENT_MAX_BYTES, 2 * 1024 * 1024);
  assert.equal(AGENT_DOCUMENT_UNAVAILABLE_TEXT, "This file cannot be shown.");
  assert.ok(Object.isFrozen(R) && Object.isFrozen(R.deniedElements) && Object.isFrozen(R.allowedUrlForms) && Object.isFrozen(R.allowedUrlForms[1]));
  assert.throws(() => (R.deniedElements as string[]).push("x"));
  assert.ok(R.maxDepth > 100);
  assert.equal(R.maxAttributesPerTag, 256);
  assert.equal(R.maxTags, 100000);
});

test("AGENT_DOCUMENT_RULES: every name list is lower case, sorted, without duplicates", () => {
  const lists: Record<string, readonly string[]> = {
    deniedElements: R.deniedElements,
    scriptElements: R.scriptElements,
    deniedScriptTypes: R.deniedScriptTypes,
    deniedAttributes: R.deniedAttributes,
    linkElements: R.linkElements,
    urlAttributes: R.urlAttributes,
    srcsetAttributes: R.srcsetAttributes,
    styleAttributes: R.styleAttributes,
    cssValueAttributes: R.cssValueAttributes,
    smilElements: R.smilElements,
    smilValueAttributes: R.smilValueAttributes,
    smilDeniedTargets: R.smilDeniedTargets,
    cssForbiddenFunctions: R.cssForbiddenFunctions,
    cssForbiddenAtRules: R.cssForbiddenAtRules,
    cssForbiddenLegacy: R.cssForbiddenLegacy,
  };
  for (const [name, list] of Object.entries(lists)) {
    assert.ok(list.length > 0, name);
    assert.deepEqual([...list], [...new Set(list)], `${name}: duplicates`);
    assert.deepEqual([...list], [...list].sort(), `${name}: sorted`);
    for (const v of list) assert.equal(v, v.toLowerCase(), `${name}: ${v}`);
  }
});

test("AGENT_DOCUMENT_RULES: the agreed removals are in the list (Creative S3 / Live Artifacts S2, C238)", () => {
  for (const el of ["link", "base", "form", "iframe", "frame", "frameset", "object", "embed", "applet", "portal", "noscript"]) assert.ok(R.deniedElements.includes(el), el);
  assert.ok(!R.deniedElements.includes("template"), "template content is walked, not removed");
  assert.deepEqual(R.deniedElementsWithAttribute, [{ element: "meta", attribute: "http-equiv" }]);
  assert.deepEqual(R.scriptElements, ["script"]);
  // 0.1.25 (C238): speculation rules and import maps go in every mode
  assert.deepEqual([...R.deniedScriptTypes], ["importmap", "speculationrules"]);
  assert.ok(Object.isFrozen(R.deniedScriptTypes));
  assert.equal(R.eventHandlerPrefix, "on");
  for (const a of ["ping", "srcdoc"]) assert.ok(R.deniedAttributes.includes(a), a);
  for (const a of ["action", "formaction", "href", "src", "poster", "data", "background", "xlink:href"]) assert.ok(R.urlAttributes.includes(a), a);
  assert.deepEqual([...R.srcsetAttributes], ["imagesrcset", "srcset"]);
  assert.deepEqual(R.allowedUrlForms.map((f) => f.kind), ["fragment", "data-image", "asset-prefix"]);
  assert.ok(!R.allowedUrlForms[1]?.mimeTypes?.some((m) => m.includes("svg") || m.includes("html")));
  // A2: presentation attributes and SMIL
  for (const a of ["fill", "filter", "mask", "clip-path", "marker-start", "marker-mid", "marker-end", "stroke", "cursor"]) assert.ok(R.cssValueAttributes.includes(a), a);
  for (const e of ["set", "animate", "animatetransform", "animatemotion"]) assert.ok(R.smilElements.includes(e), e);
  for (const a of ["to", "from", "values", "by"]) assert.ok(R.smilValueAttributes.includes(a), a);
  assert.ok(R.smilDeniedTargets.includes("href"));
  // A4: CSS image functions and at-rules
  for (const f of ["url", "image", "image-set", "cross-fade", "element", "src"]) assert.ok(R.cssForbiddenFunctions.includes(f), f);
  assert.deepEqual([...R.cssForbiddenAtRules], ["import"]);
  // text slots (Live Artifacts S7)
  assert.equal(R.textSlotAttribute, "data-tb-text");
  const slot = new RegExp(R.textSlotPattern);
  for (const ok of ["a", "a.b", "a_1.b2"]) assert.ok(slot.test(ok), ok);
  for (const bad of ["", "A", "1a", "a..b", "a.", "a-b", "a\n"]) assert.ok(!slot.test(bad), JSON.stringify(bad));
});
