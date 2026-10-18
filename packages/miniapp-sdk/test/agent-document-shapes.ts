// Shared shapes for the sanitizeAgentDocument tests (unit and timing files). Not a test file.

/** n distinct attribute names, space separated. */
export const names = (n: number): string => Array.from({ length: n }, (_, i) => `a${i.toString(36)}`).join(" ");

/** A full document around a body fragment. */
export const bodyPage = (inner: string): string => `<!DOCTYPE html><html><head></head><body>${inner}</body></html>`;

/** Wraps `attrs` in a tag the parser really reads as a tag, behind each hiding trick (21 variants). */
export const variants: { name: string; real: boolean; make: (attrs: string) => string }[] = [
  { name: "plain", real: true, make: (a) => `<p ${a}>x</p>` },
  { name: "end tag", real: false, make: (a) => `</p ${a}>` },
  { name: "unterminated at the end of the file", real: true, make: (a) => `<p ${a}` },
  { name: "after <!-->", real: true, make: (a) => `<!--><p ${a}>x</p>` },
  { name: "after <!--->", real: true, make: (a) => `<!---><p ${a}>x</p>` },
  { name: "after a --!> closer", real: true, make: (a) => `<!-- c --!><p ${a}>x</p>` },
  { name: "after a --!> closer with a decoy tag", real: true, make: (a) => `<!-- <q z=" --!><p ${a}>x</p>` },
  { name: "svg style", real: true, make: (a) => `<svg><style><p ${a}>x</p></style></svg>` },
  { name: "svg title", real: true, make: (a) => `<svg><title><p ${a}>x</p></title></svg>` },
  { name: "svg desc", real: true, make: (a) => `<svg><desc><p ${a}>x</p></desc></svg>` },
  { name: "math title", real: true, make: (a) => `<math><title><p ${a}>x</p></title></math>` },
  { name: "math annotation-xml html", real: true, make: (a) => `<math><annotation-xml encoding="text/html"><p ${a}>x</p></annotation-xml></math>` },
  { name: "after a quoted >", real: true, make: (a) => `<p z=">" ${a}>x</p>` },
  { name: "after a quoted > behind a comment decoy", real: true, make: (a) => `<!-- <x z=" --><p y=">" ${a}>x</p>` },
  { name: "after a quoted < and >", real: true, make: (a) => `<p z='<>' ${a}>x</p>` },
  { name: "unquoted values", real: true, make: (a) => `<p ${a.replace(/ /g, "=1 ")}>x</p>` },
  { name: "slash separated", real: true, make: (a) => `<p ${a.replace(/ /g, "/")}>x</p>` },
  { name: "inside a comment", real: false, make: (a) => `<!-- <p ${a}> -->` },
  { name: "inside a textarea", real: false, make: (a) => `<textarea><p ${a}></textarea>` },
  { name: "inside a script", real: false, make: (a) => `<script><p ${a}></script>` },
  { name: "inside a CDATA section", real: false, make: (a) => `<svg><![CDATA[<p ${a}>]]></svg>` },
];
