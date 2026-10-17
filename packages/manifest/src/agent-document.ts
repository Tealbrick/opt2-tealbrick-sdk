// Agent documents (C238, C230, C232; SANITIZE-AGENT-DOCUMENT design). Agent-written HTML is served as a sandboxed `/_d/`
// document. CSP cannot stop every browser network reach (`<link rel=prerender>`, `<a ping>`, a navigation by `.click()`),
// so the server removes the constructs before it serves the page. The SANITISER lives in @opt2-tealbrick/miniapp-sdk
// (`sanitizeAgentDocument`, it needs a real HTML5 parser). The RULE LIST is data and lives here (L1, next to
// VIEWER_HEADER_FLOOR): the SDK sanitiser, its tests and conformance read the same lists. Pure data, no Node APIs.

/** First thing in every sanitised document (an HTML comment, so it cannot change how the page renders). */
export const AGENT_DOCUMENT_MARKER = "<!-- tb:sanitized v1 -->";

/** Largest input the sanitiser accepts, in UTF-8 bytes: the viewer body cap (BRIDGE views role, 2 MiB). Larger: fail closed. */
export const AGENT_DOCUMENT_MAX_BYTES = 2 * 1024 * 1024;

/** The one sentence of the inert document the sanitiser returns when it fails closed. No input is ever echoed into it. */
export const AGENT_DOCUMENT_UNAVAILABLE_TEXT = "This file cannot be shown.";

export interface AgentDocumentRules {
  /** Rule list version; moves with the marker (`tb:sanitized v<version>`). */
  readonly version: 1;
  readonly marker: string;
  readonly maxInputBytes: number;
  /** Elements removed with all their content, in any namespace and any letter case. `noscript` is removed because its
   *  content parses differently with scripting on and off (a re-parse risk); `template` is NOT here: its content is walked. */
  readonly deniedElements: readonly string[];
  /** Elements removed only when they carry the attribute (`<meta http-equiv=refresh>`). */
  readonly deniedElementsWithAttribute: readonly { readonly element: string; readonly attribute: string }[];
  /** Removed when the app does not opt into scripts (`allowScripts: false`). */
  readonly scriptElements: readonly string[];
  /** Attribute names that start with this are event handlers: removed when `allowScripts` is false. */
  readonly eventHandlerPrefix: string;
  /** Attributes removed on every element, always (full name with prefix, lower case). */
  readonly deniedAttributes: readonly string[];
  /** Elements whose `target` is removed (and that get `rel="noreferrer noopener"` when they lose `href` or `target`). */
  readonly linkElements: readonly string[];
  /** Attributes (lower case, full name or local name after the last `:`) that hold ONE URL. Value must be an allowed URL form. */
  readonly urlAttributes: readonly string[];
  /** Attributes that hold a `srcset` candidate list: every candidate URL must be an allowed URL form. */
  readonly srcsetAttributes: readonly string[];
  /** The allowed URL forms, in the order they are tried. Everything else (absolute, `//host`, `javascript:`, a relative path,
   *  `data:text/html`, …) is removed. The value is judged after the URL parser's own clean-up (strip leading and trailing C0
   *  controls and spaces, remove tab and newline), so `java\tscript:` is no different from `javascript:`. */
  readonly allowedUrlForms: readonly {
    readonly kind: "fragment" | "data-image" | "asset-prefix";
    readonly description: string;
    /** `data-image`: allowed MIME types (no SVG: an SVG image is a document). */
    readonly mimeTypes?: readonly string[];
    /** `data-image`: elements where a `data:` URL is never allowed (it would be a navigation or a document reference). */
    readonly deniedOn?: readonly string[];
  }[];
  /** Attributes holding a CSS declaration list: declarations that use a forbidden CSS function or at-rule are removed. */
  readonly styleAttributes: readonly string[];
  /** Presentation attributes (SVG and others) whose whole value is CSS: removed when it uses a forbidden CSS function. */
  readonly cssValueAttributes: readonly string[];
  /** SMIL animation elements (lower case). Their value attributes get the same CSS check as `cssValueAttributes`. */
  readonly smilElements: readonly string[];
  readonly smilValueAttributes: readonly string[];
  /** SMIL element is removed when its `attributeName` (spaces removed, lower case, `xlink:` prefix dropped) names one of
   *  these, or starts with `on`: it would write a URL or a handler into the page after the sanitiser ran. */
  readonly smilTargetAttribute: string;
  readonly smilDeniedTargets: readonly string[];
  /** CSS functions that load or reference a resource. Matched case-insensitively after comments are taken out and CSS
   *  escapes are decoded (`\75 rl(`), with or without a vendor prefix (`-webkit-image-set(`). `url(#fragment)` is the only
   *  allowed use of `url(`. */
  readonly cssForbiddenFunctions: readonly string[];
  /** CSS at-rules that load a resource (written without `@`). */
  readonly cssForbiddenAtRules: readonly string[];
  /** Old browser-only code hooks in CSS: forbidden too. */
  readonly cssForbiddenLegacy: readonly string[];
  /** Text slots: an element with this attribute is kept, and the attribute is kept when its value matches `textSlotPattern`
   *  (else the attribute is removed). The app fills the slot with ESCAPED text AFTER sanitising (`fillTextSlots`). */
  readonly textSlotAttribute: string;
  readonly textSlotPattern: string;
  /** Largest tree depth the sanitiser walks; deeper: fail closed. */
  readonly maxDepth: number;
  /** Most attributes one tag may carry in the input; more: fail closed. (An HTML5 parser takes time quadratic in the
   *  attribute count of one tag, so a 2 MiB page of attributes would hold the server for minutes.) */
  readonly maxAttributesPerTag: number;
}

function deepFreeze<T>(o: T): T {
  if (o && typeof o === "object") {
    for (const v of Object.values(o as object)) deepFreeze(v);
    Object.freeze(o);
  }
  return o;
}

export const AGENT_DOCUMENT_RULES: AgentDocumentRules = deepFreeze({
  version: 1,
  marker: AGENT_DOCUMENT_MARKER,
  maxInputBytes: AGENT_DOCUMENT_MAX_BYTES,
  deniedElements: ["applet", "base", "bgsound", "embed", "fencedframe", "form", "frame", "frameset", "iframe", "keygen", "link", "noembed", "noframes", "noscript", "object", "portal"],
  deniedElementsWithAttribute: [{ element: "meta", attribute: "http-equiv" }],
  scriptElements: ["script"],
  eventHandlerPrefix: "on",
  deniedAttributes: ["ping", "srcdoc", "xml:base"],
  linkElements: ["a", "area"],
  urlAttributes: ["action", "archive", "attributionsrc", "background", "cite", "classid", "codebase", "data", "dynsrc", "formaction", "href", "icon", "longdesc", "lowsrc", "manifest", "poster", "profile", "src", "usemap", "xlink:href"],
  srcsetAttributes: ["imagesrcset", "srcset"],
  allowedUrlForms: [
    { kind: "fragment", description: "a same-document fragment: `#` and anything after it" },
    {
      kind: "data-image",
      description: "a `data:image/<type>` URL of a raster type",
      mimeTypes: ["image/png", "image/gif", "image/jpeg", "image/webp", "image/avif", "image/bmp"],
      deniedOn: ["a", "area", "script", "use"],
    },
    { kind: "asset-prefix", description: "a path that starts with the `assetPrefix` the app passes (its own `/_s/` assets), without dot segments or backslashes" },
  ],
  styleAttributes: ["style"],
  cssValueAttributes: ["background-image", "border-image", "border-image-source", "clip", "clip-path", "cursor", "fill", "filter", "list-style-image", "marker", "marker-end", "marker-mid", "marker-start", "mask", "mask-border", "mask-border-source", "mask-image", "shape-outside", "stroke"],
  smilElements: ["animate", "animatemotion", "animatetransform", "set"],
  smilValueAttributes: ["by", "from", "to", "values"],
  smilTargetAttribute: "attributename",
  smilDeniedTargets: ["href"],
  cssForbiddenFunctions: ["cross-fade", "element", "image", "image-set", "src", "url"],
  cssForbiddenAtRules: ["import"],
  cssForbiddenLegacy: ["-moz-binding", "expression"],
  textSlotAttribute: "data-tb-text",
  textSlotPattern: "^[a-z][a-z0-9_]*(\\.[a-z0-9_]+)*$",
  maxDepth: 600,
  maxAttributesPerTag: 1000,
});
