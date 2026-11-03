import { z } from "zod";
import { GRAPH_SCOPES, MSA_TENANT_ID } from "./config.js";

const AUTHORITY = "https://login.microsoftonline.com/consumers/oauth2/v2.0";
const UPSTREAM_SCOPES = ["openid", "profile", "email", "offline_access", ...GRAPH_SCOPES].join(" ");

const tokenResponse = z.object({
  access_token: z.string().min(1),
  refresh_token: z.string().min(1).optional(),
  id_token: z.string().optional(),
  expires_in: z.coerce.number().int().positive(),
});

const idTokenClaims = z.object({
  tid: z.string(),
  oid: z.string().optional(),
  sub: z.string(),
  name: z.string().optional(),
  preferred_username: z.string().optional(),
  email: z.string().optional(),
});

export interface UpstreamTokens {
  accessToken: string;
  accessTokenExpiresAt: number;
  refreshToken?: string;
}

export interface UpstreamUser {
  /** Stable per-user identifier for this app registration. */
  id: string;
  name?: string;
  username?: string;
}

export class UpstreamError extends Error {
  constructor(public readonly status: number, public readonly code: string) {
    super(`Microsoft sign-in failed (${status}, ${code}).`);
    this.name = "UpstreamError";
  }
}

/** OAuth 2.0 client for Microsoft identity platform, restricted to personal Microsoft accounts. */
export class EntraClient {
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly redirectUri: string,
    private readonly fetchRequest: typeof fetch = fetch,
  ) {}

  authorizeUrl(state: string, codeChallenge: string): string {
    const url = new URL(`${AUTHORITY}/authorize`);
    url.search = new URLSearchParams({
      client_id: this.clientId,
      response_type: "code",
      redirect_uri: this.redirectUri,
      response_mode: "query",
      scope: UPSTREAM_SCOPES,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      prompt: "select_account",
    }).toString();
    return url.href;
  }

  async redeemCode(code: string, codeVerifier: string): Promise<{ tokens: UpstreamTokens; user: UpstreamUser }> {
    const body = await this.token({
      grant_type: "authorization_code",
      code,
      code_verifier: codeVerifier,
      redirect_uri: this.redirectUri,
      scope: UPSTREAM_SCOPES,
    });
    if (!body.id_token || !body.refresh_token) {
      throw new UpstreamError(502, "missing_tokens");
    }
    // The ID token came directly from Entra's token endpoint over TLS, so its signature
    // need not be re-verified (OIDC Core 3.1.3.7); its claims are still validated.
    const claims = idTokenClaims.safeParse(JSON.parse(
      Buffer.from(body.id_token.split(".")[1] ?? "", "base64url").toString("utf8") || "null"));
    if (!claims.success) throw new UpstreamError(502, "invalid_id_token");
    if (claims.data.tid !== MSA_TENANT_ID) throw new UpstreamError(403, "not_personal_account");
    return {
      tokens: tokensFrom(body),
      user: {
        id: claims.data.oid ?? claims.data.sub,
        ...(claims.data.name ? { name: claims.data.name } : {}),
        ...((claims.data.preferred_username ?? claims.data.email) ?
          { username: claims.data.preferred_username ?? claims.data.email } : {}),
      },
    };
  }

  async refresh(refreshToken: string): Promise<UpstreamTokens> {
    return tokensFrom(await this.token({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      scope: UPSTREAM_SCOPES,
    }));
  }

  private async token(params: Record<string, string>): Promise<z.infer<typeof tokenResponse>> {
    let response: Response;
    try {
      response = await this.fetchRequest(`${AUTHORITY}/token`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: new URLSearchParams({ client_id: this.clientId, client_secret: this.clientSecret, ...params }),
        redirect: "error",
        signal: AbortSignal.timeout(15_000),
      });
    } catch {
      throw new UpstreamError(504, "network_error");
    }
    const json: unknown = await response.json().catch(() => undefined);
    if (!response.ok) {
      const code = z.object({ error: z.string().regex(/^[\w.-]{1,100}$/) }).safeParse(json);
      throw new UpstreamError(response.status, code.success ? code.data.error : "unknown_error");
    }
    const parsed = tokenResponse.safeParse(json);
    if (!parsed.success) throw new UpstreamError(502, "invalid_token_response");
    return parsed.data;
  }
}

function tokensFrom(body: z.infer<typeof tokenResponse>): UpstreamTokens {
  return {
    accessToken: body.access_token,
    accessTokenExpiresAt: Date.now() + body.expires_in * 1000,
    ...(body.refresh_token ? { refreshToken: body.refresh_token } : {}),
  };
}
