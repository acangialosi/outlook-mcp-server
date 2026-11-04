const GRAPH_BASE = "https://graph.microsoft.com/v1.0";
const GRAPH_BETA = "https://graph.microsoft.com/beta";

export class GraphError extends Error {
  constructor(public readonly status: number, public readonly code: string, public readonly requestId: string | null) {
    super(`Microsoft Graph request failed (${status} ${code}).`);
    this.name = "GraphError";
  }
}

export interface BatchRequest {
  method: "GET" | "POST" | "PATCH";
  /** Relative to /v1.0, e.g. /me/messages/{encoded id}/move. */
  url: string;
  body?: object;
}

export interface BatchResponse {
  status: number;
  body?: Record<string, unknown>;
  /** Graph error code, for failed items. */
  code?: string;
}

interface RawBatchItem { id?: unknown; status?: unknown; headers?: Record<string, string>; body?: unknown }
const BATCH_LIMIT = 20;
const RETRYABLE = new Set([429, 503, 504]);

export interface Page {
  items: unknown[];
  /** Pass back unchanged to fetch the next page. */
  nextLink?: string;
  /** Total matching items across all pages, when the request asked for $count. */
  count?: number;
}

/**
 * Canonical form of a Graph path for comparing a nextLink with the collection it should continue.
 * Graph writes keys in OData form in its nextLinks: a request for /me/mailFolders/inbox/messages pages on as
 * /me/mailFolders('inbox')/messages. Both forms address the same collection, so ('key') segments become /key
 * (with '' unescaped to '). Route names are case-insensitive, but IDs are not.
 */
function collectionKey(pathname: string): string {
  const collections = new Set(["users", "mailfolders", "childfolders", "messages", "contacts", "calendars", "events"]);
  const routes = new Set(["v1.0", "me", "calendarview", "attachments", ...collections]);
  const parts: string[] = [];
  let expectsId = false;
  for (const segment of pathname.split("/")) {
    const decoded = decodeURIComponent(segment);
    if (expectsId) {
      parts.push(decoded);
      expectsId = false;
      continue;
    }
    const keyed = /^([a-z]+)\('((?:[^']|'')*)'\)$/i.exec(decoded);
    if (keyed && collections.has(keyed[1]!.toLowerCase())) {
      parts.push(keyed[1]!.toLowerCase(), keyed[2]!.replaceAll("''", "'"));
      continue;
    }
    const lower = decoded.toLowerCase();
    parts.push(routes.has(lower) ? lower : decoded);
    expectsId = collections.has(lower);
  }
  // Keep encoded slashes inside an identifier distinct from actual path boundaries.
  return JSON.stringify(parts);
}

function withoutEtag(item: unknown): unknown {
  if (!item || typeof item !== "object" || !("@odata.etag" in item)) return item;
  const { "@odata.etag": _etag, ...rest } = item as Record<string, unknown>;
  return rest;
}

/** Minimal Microsoft Graph client for one user's delegated token. */
export class GraphClient {
  constructor(
    private readonly accessToken: () => Promise<string>,
    private readonly fetchRequest: typeof fetch = fetch,
  ) {}

  async get(path: string, query: Record<string, string> = {}): Promise<Record<string, unknown>> {
    const url = new URL(GRAPH_BASE + path);
    for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
    return this.request(url);
  }

  /** POSTs a JSON action (e.g. /me/messages/{id}/move). `beta` targets the /beta endpoint. */
  async post(path: string, body: object, options: { beta?: boolean } = {}): Promise<Record<string, unknown>> {
    return this.request(new URL((options.beta ? GRAPH_BETA : GRAPH_BASE) + path), body);
  }

  /** Fetches a collection page, or continues one from a nextLink returned for the same path. */
  async page(path: string, query: Record<string, string>, nextLink?: string): Promise<Page> {
    let body: Record<string, unknown>;
    if (nextLink) {
      const url = new URL(nextLink);
      // Only follow links back to the same Graph collection, so a crafted nextLink can't
      // send this user's token elsewhere or read a different resource.
      const expected = new URL(GRAPH_BASE + path);
      if (url.origin !== expected.origin || collectionKey(url.pathname) !== collectionKey(expected.pathname)) {
        throw new Error("nextLink does not belong to this tool's collection.");
      }
      body = await this.request(url);
    } else {
      body = await this.get(path, query);
    }
    const link = body["@odata.nextLink"];
    return {
      // Drop per-item @odata.etag: callers never need it and it adds ~60 bytes per message.
      items: Array.isArray(body.value) ? body.value.map(withoutEtag) : [],
      ...(typeof link === "string" ? { nextLink: link } : {}),
      ...(typeof body["@odata.count"] === "number" ? { count: body["@odata.count"] } : {}),
    };
  }

  /**
   * Runs many requests through Graph's JSON $batch endpoint, 20 per round trip, and returns one response per
   * request in the same order. Items Graph throttles (429/503/504) are retried up to twice, honouring
   * Retry-After (capped at 10s). A failed item does not fail the others.
   * If a round trip itself fails, results already received are kept: that round trip's items get status 0 with
   * code "Indeterminate" (they may have run), and later items get code "NotAttempted".
   * `url` is relative to /v1.0 and must be built from validated, URL-encoded IDs.
   */
  async batch(requests: BatchRequest[]): Promise<BatchResponse[]> {
    const results: (BatchResponse | undefined)[] = new Array(requests.length);
    await this.accessToken(); // surface sign-in problems as errors, before anything runs
    chunks: for (let start = 0; start < requests.length; start += BATCH_LIMIT) {
      let pending = [...Array(Math.min(BATCH_LIMIT, requests.length - start)).keys()].map((i) => start + i);
      for (let attempt = 0; pending.length; attempt++) {
        let response: Record<string, unknown>;
        try {
          response = await this.request(new URL(`${GRAPH_BASE}/$batch`), {
          requests: pending.map((i) => {
            const { method, url, body } = requests[i]!;
            return { id: String(i), method, url, ...(body ? { body, headers: { "Content-Type": "application/json" } } : {}) };
          }),
          }, 60_000);
        } catch (error) {
          console.warn("Batch round trip failed:", error instanceof Error ? error.message : error);
          for (const i of pending) results[i] = { status: 0, code: "Indeterminate" };
          for (let i = start + BATCH_LIMIT; i < requests.length; i++) results[i] = { status: 0, code: "NotAttempted" };
          break chunks;
        }
        const retry: number[] = [];
        let waitSeconds = 1;
        for (const item of Array.isArray(response.responses) ? response.responses as RawBatchItem[] : []) {
          const i = Number(item.id);
          if (!pending.includes(i)) continue;
          const status = typeof item.status === "number" ? item.status : 500;
          if (RETRYABLE.has(status) && attempt < 2) {
            retry.push(i);
            const after = Number(item.headers?.["Retry-After"] ?? item.headers?.["retry-after"]);
            if (Number.isFinite(after)) waitSeconds = Math.max(waitSeconds, after);
            continue;
          }
          const code = (item.body as { error?: { code?: unknown } } | undefined)?.error?.code;
          results[i] = { status, body: item.body as Record<string, unknown> | undefined, ...(typeof code === "string" ? { code: code.slice(0, 100) } : {}) };
        }
        pending = retry;
        if (pending.length) await new Promise((resolve) => setTimeout(resolve, Math.min(waitSeconds, 10) * 1000));
      }
    }
    // Array.from visits every index; map would skip the holes left by items Graph never answered. A missing
    // response does not mean the request did not run, so it is indeterminate.
    return Array.from({ length: requests.length }, (_, i) => results[i] ?? { status: 0, code: "Indeterminate" });
  }

  private async request(url: URL, body?: object, timeoutMs = 20_000): Promise<Record<string, unknown>> {
    const response = await this.fetchRequest(url, {
      method: body ? "POST" : "GET",
      headers: {
        Authorization: `Bearer ${await this.accessToken()}`,
        Accept: "application/json",
        Prefer: 'outlook.body-content-type="text", outlook.timezone="UTC"',
        ...(body ? { "Content-Type": "application/json" } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => undefined) as { error?: { code?: unknown } } | undefined;
      const code = typeof body?.error?.code === "string" ? body.error.code.slice(0, 100) : "UnknownError";
      throw new GraphError(response.status, code, response.headers.get("request-id"));
    }
    const text = await response.text();
    return text ? JSON.parse(text) as Record<string, unknown> : {};
  }
}
