import { isIP } from "node:net";
import {
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  oauthMetadataResponse,
  requireBearerAuth,
} from "@modelcontextprotocol/server";
import { MCP_SCOPE, type Config } from "./config.js";
import { GraphClient } from "./graph.js";
import type { OAuthServer } from "./oauth.js";
import { createOutlookServer } from "./tools.js";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, Content-Type, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID",
  "Access-Control-Expose-Headers": "WWW-Authenticate, Mcp-Session-Id, Mcp-Protocol-Version",
  "Access-Control-Max-Age": "86400",
};

/** Fixed-window per-IP limiter for the unauthenticated OAuth endpoints. */
class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly limit: number, private readonly windowMs: number) {}

  allow(key: string): boolean {
    const now = Date.now();
    if (this.hits.size > 10_000) {
      for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
    }
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    return ++entry.count <= this.limit;
  }
}

function withHeaders(response: Response, headers: Record<string, string>): Response {
  const result = new Response(response.body, response);
  for (const [key, value] of Object.entries(headers)) result.headers.set(key, value);
  return result;
}

function clientIp(request: Request, remoteAddress: string | undefined, trustProxy: boolean): string {
  const forwarded = trustProxy ? request.headers.get("x-forwarded-for")?.split(",").at(-1)?.trim() : undefined;
  return forwarded && isIP(forwarded) ? forwarded : remoteAddress || "local";
}

export function createApp(config: Config, oauth: OAuthServer): (request: Request, remoteAddress?: string) => Promise<Response> {
  const mcpUrl = new URL(config.mcpUrl);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(mcpUrl);
  const metadataOptions = {
    oauthMetadata: oauth.metadata,
    resourceServerUrl: mcpUrl,
    scopesSupported: [MCP_SCOPE],
    resourceName: "Outlook.com (personal)",
    dangerouslyAllowInsecureIssuerUrl: !config.publicUrl.startsWith("https:"),
  };
  const gate = requireBearerAuth({ verifier: oauth, expectedResource: mcpUrl, resourceMetadataUrl });
  const mcp = createMcpHandler(({ authInfo }) => {
    const grantId = authInfo?.extra?.grantId;
    if (typeof grantId !== "string") throw new Error("Request reached the MCP handler without a verified grant.");
    return createOutlookServer(new GraphClient(() => oauth.graphAccessToken(grantId)));
  }, { onerror: (error) => console.error("MCP error:", error.message) });

  const strict = new RateLimiter(30, 60 * 60 * 1000); // registrations and consent pages
  const tokens = new RateLimiter(120, 60 * 1000);

  return async (request: Request, remoteAddress?: string): Promise<Response> => {
    const { pathname } = new URL(request.url);
    const method = request.method;
    const tooMany = () => new Response("Too many requests", { status: 429, headers: { "Retry-After": "60" } });

    try {
      if (pathname === "/" && method === "GET") {
        return new Response(`Outlook.com MCP server. Add ${config.mcpUrl} as a remote MCP server / custom connector.\n`,
          { headers: { "Content-Type": "text/plain; charset=utf-8" } });
      }
      if (pathname === "/healthz") return new Response("ok");

      const metadata = oauthMetadataResponse(request, metadataOptions);
      if (metadata) return metadata;

      if (pathname === "/register") {
        if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
        if (method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST" } });
        if (!strict.allow(clientIp(request, remoteAddress, config.trustProxy))) return tooMany();
        return withHeaders(await oauth.register(request), CORS);
      }
      if (pathname === "/token") {
        if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
        if (method !== "POST") return new Response(null, { status: 405, headers: { Allow: "POST" } });
        if (!tokens.allow(clientIp(request, remoteAddress, config.trustProxy))) return tooMany();
        return withHeaders(await oauth.token(request), CORS);
      }
      if (pathname === "/authorize" && method === "GET") {
        if (!strict.allow(clientIp(request, remoteAddress, config.trustProxy))) return tooMany();
        return await oauth.authorize(request);
      }
      if (pathname === "/authorize/consent" && method === "POST") return await oauth.consent(request);
      if (pathname === "/oauth/callback" && method === "GET") return await oauth.callback(request);

      if (pathname === "/mcp") {
        if (method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
        const auth = await gate(request);
        if (auth instanceof Response) return withHeaders(auth, CORS);
        return withHeaders(await mcp.fetch(request, { authInfo: auth }), CORS);
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error("Unhandled error on %s %s:", method, JSON.stringify(pathname), error);
      return new Response(JSON.stringify({ error: "server_error" }), {
        status: 500, headers: { "Content-Type": "application/json" },
      });
    }
  };
}
