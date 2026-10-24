// Person list ops (`tb.receipts_list`, `tb.holds_list`) answer newest first, 50 rows a page, with `nextCursor`.
// A check that reads page 1 only loses its row as soon as more than a page of rows is written after it (for example
// when A12 has called every agent op). Follow `nextCursor`, bounded, until the wanted row is found or the list ends.
import type { AppClient, PersonSession } from "./app-client.ts";

/** Pages followed at most (50 rows each by default): a bound, not a promise that the list ended. */
export const MAX_LIST_PAGES = 20;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

export interface ListedPages {
  /** rows of every page read, in the order the app returned them */
  items: Record<string, unknown>[];
  pages: number;
  /** the last answer was not ok / not a list (rows read so far are kept) */
  failed: string | null;
  /** MAX_LIST_PAGES pages were read and the app still offered a `nextCursor` */
  truncated: boolean;
  /** the raw answer text of every page read, joined (for leak scans and report lines) */
  text: string;
}

/**
 * Read the person list op page by page. Stops when `until(items)` is true (after the page that made it true), when
 * `nextCursor` is absent, on a non-ok answer, or after `maxPages`.
 */
export async function listPersonPages(
  client: Pick<AppClient, "personOp">,
  sess: PersonSession,
  op: string,
  until?: (items: Record<string, unknown>[]) => boolean,
  maxPages: number = MAX_LIST_PAGES,
): Promise<ListedPages> {
  const items: Record<string, unknown>[] = [];
  let cursor: string | null = null;
  let text = "";
  for (let pages = 1; pages <= maxPages; pages++) {
    const r = await client.personOp(sess, op, cursor ? { cursor } : {});
    text += r.text;
    if (!isObj(r.output) || !Array.isArray(r.output.items)) return { items, pages, failed: `${r.status}${r.code ? ` ${r.code}` : ""}`, truncated: false, text };
    items.push(...r.output.items.filter(isObj));
    cursor = typeof r.output.nextCursor === "string" && r.output.nextCursor !== "" ? r.output.nextCursor : null;
    if (until?.(items) || !cursor) return { items, pages, failed: null, truncated: false, text };
  }
  return { items, pages: maxPages, failed: null, truncated: true, text };
}
