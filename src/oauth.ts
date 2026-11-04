import { OAuthError, OAuthErrorCode, type AuthInfo, type OAuthMetadata, type OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { z } from "zod";
import { GRANT_VERSION, MCP_SCOPE, type Config } from "./config.js";
import { hashToken, pkceChallenge, randomToken, safeEqual, verifyPkce } from "./crypto.js";
import type { Store } from "./store.js";
import { EntraClient, UpstreamError } from "./upstream.js";

const DAY = 24 * 60 * 60;
const TTL = {
  client: 180 * DAY,
  txn: 10 * 60,
  code: 5 * 60,
  access: 60 * 60,
  refresh: 30 * DAY,
  grant: 90 * DAY,
};

type AuthMethod = "none" | "client_secret_post" | "client_secret_basic";

interface ClientRecord {
  clientId: string;
  clientName?: string;
  redirectUris: string[];
  authMethod: AuthMethod;
  secretHash?: string;
  issuedAt: number;
}

interface TxnRecord {
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  bindingHash: string;
  upstreamVerifier: string;
  consented: boolean;
}

interface GrantRecord {
  /** GRANT_VERSION the user consented under; older grants are discarded. */
  version?: number;
  /** Bounds delayed writes so they cannot outlive a revocation marker. */
  expiresAt?: number;
  userId: string;
  username?: string;
  clientId: string;
  upstreamRefreshToken: string;
  upstreamAccessToken?: string;
  upstreamAccessTokenExpiresAt?: number;
}

interface CodeRecord {
  grantId: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
}

interface AccessRecord {
  grantId: string;
  clientId: string;
  expiresAt: number;
}

interface RefreshRecord {
  grantId: string;
  clientId: string;
}

/** Thrown when a user's Microsoft sign-in can no longer be renewed; the client must reconnect. */
export class ReconnectRequiredError extends Error {
  constructor() {
    super("Your Outlook.com sign-in has expired or was revoked. Reconnect this server in your MCP client.");
    this.name = "ReconnectRequiredError";
  }
}

const BLOCKED_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:", "about:", "blob:", "http:", "https:"]);

function isLoopback(url: URL): boolean {
  return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

/** Accept https, http loopback (RFC 8252 §7.3), and private-use URI schemes for native apps (§7.1). */
function validRedirectUri(value: string): boolean {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  if (url.hash || url.username || url.password) return false;
  if (url.protocol === "https:") return true;
  if (isLoopback(url)) return true;
  return /^[a-z][a-z0-9+.-]*:$/.test(url.protocol) && !BLOCKED_SCHEMES.has(url.protocol);
}

/** Exact match, except loopback redirects may use any port (RFC 8252 §7.3). */
function redirectMatches(registered: string, requested: string): boolean {
  if (registered === requested) return true;
  try {
    const a = new URL(registered);
    const b = new URL(requested);
    return isLoopback(a) && isLoopback(b) && a.hostname === b.hostname &&
      a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

function sameResource(value: string, mcpUrl: string): boolean {
  const strip = (s: string) => s.replace(/#.*$/, "").replace(/\/$/, "");
  return strip(value) === strip(mcpUrl);
}

const registration = z.object({
  redirect_uris: z.array(z.string().max(2048)).min(1).max(10),
  client_name: z.string().trim().min(1).max(100).optional(),
  token_endpoint_auth_method: z.enum(["none", "client_secret_post", "client_secret_basic"]).default("client_secret_basic"),
  grant_types: z.array(z.string()).default(["authorization_code", "refresh_token"]),
  response_types: z.array(z.string()).default(["code"]),
}).loose();

function json(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
  });
}

function oauthError(code: string, description: string, status = 400): Response {
  return json({ error: code, error_description: description }, status);
}

function redirect(location: string, headers: Record<string, string> = {}): Response {
  return new Response(null, { status: 302, headers: { Location: location, "Cache-Control": "no-store", ...headers } });
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

// `body` is HTML built by this file's callers with every dynamic value passed through escapeHtml.
function htmlPage(title: string, body: string, status = 200, headers: Record<string, string> = {}): Response {
  // nosemgrep: javascript.lang.security.html-in-template-string
  return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>
<style>
body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;background:#f5f5f7;color:#1d1d1f;margin:0;padding:24px 16px}
main{max-width:440px;margin:40px auto;background:#fff;border-radius:12px;padding:28px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1{font-size:20px;margin:0 0 16px}p{line-height:1.5}ul{padding-left:20px;line-height:1.6}code{background:#f0f0f2;padding:1px 5px;border-radius:4px;word-break:break-all}
.actions{display:flex;gap:12px;margin-top:24px}button{flex:1;font-size:16px;padding:12px;border-radius:8px;border:1px solid #c7c7cc;background:#fff;cursor:pointer}
button.primary{background:#0067b8;border-color:#0067b8;color:#fff}.muted{color:#6e6e73;font-size:14px}
@media (prefers-color-scheme:dark){body{background:#1c1c1e;color:#f5f5f7}main{background:#2c2c2e}code{background:#3a3a3c}button{background:#3a3a3c;color:#f5f5f7;border-color:#48484a}.muted{color:#a1a1a6}}
</style></head><body><main>${body}</main></body></html>`, {
    status,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
      // No form-action: browsers apply it to the redirect after submit, which goes to Microsoft
      // sign-in or the client's own redirect URI.
      "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      "X-Frame-Options": "DENY",
      // same-origin (not no-referrer) so the consent POST carries a real Origin header, not "null".
      "Referrer-Policy": "same-origin",
      ...headers,
    },
  });
}

function cookies(request: Request): Map<string, string> {
  const result = new Map<string, string>();
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return result;
}

async function readBody(request: Request, limit = 16_384): Promise<string | undefined> {
  if (!request.body) return "";
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      bytes += value.byteLength;
      if (bytes > limit) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

/**
 * OAuth 2.1 authorization server for MCP clients that federates sign-in to Microsoft.
 *
 * MCP clients register dynamically (RFC 7591) and receive this server's own opaque tokens.
 * Each user's Microsoft refresh token stays server-side, encrypted, and is used only to call
 * Microsoft Graph on that user's behalf. Because one Entra app serves every dynamically
 * registered client, the user approves each client on a consent screen before Microsoft
 * sign-in (MCP authorization spec, "confused deputy" mitigation).
 */
export class OAuthServer implements OAuthTokenVerifier {
  readonly metadata: OAuthMetadata;
  private readonly cookiePrefix: string;
  private readonly secureCookie: string;
  private readonly refreshing = new Map<string, Promise<string>>();

  constructor(
    private readonly config: Config,
    private readonly store: Store,
    private readonly entra: EntraClient,
  ) {
    const base = config.publicUrl;
    this.metadata = {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
      scopes_supported: [MCP_SCOPE],
      authorization_response_iss_parameter_supported: true,
    } as OAuthMetadata;
    const https = base.startsWith("https:");
    this.cookiePrefix = https ? "__Host-omcp_" : "omcp_";
    this.secureCookie = https ? "; Secure" : "";
  }

  // ---- Dynamic client registration (RFC 7591) -------------------------------------------

  async register(request: Request): Promise<Response> {
    const text = await readBody(request);
    let body: unknown;
    try {
      body = text === undefined ? undefined : JSON.parse(text);
    } catch {
      body = undefined;
    }
    const parsed = registration.safeParse(body);
    if (!parsed.success) return oauthError("invalid_client_metadata", "Invalid client registration request.");
    const meta = parsed.data;
    if (!meta.redirect_uris.every(validRedirectUri)) {
      return oauthError("invalid_redirect_uri", "Redirect URIs must be https, http loopback, or a private-use scheme.");
    }
    if (!meta.grant_types.every((g) => g === "authorization_code" || g === "refresh_token") ||
        !meta.response_types.every((r) => r === "code")) {
      return oauthError("invalid_client_metadata", "Only the authorization_code and refresh_token grants are supported.");
    }
    const clientId = randomToken();
    const secret = meta.token_endpoint_auth_method === "none" ? undefined : randomToken();
    const record: ClientRecord = {
      clientId,
      redirectUris: meta.redirect_uris,
      authMethod: meta.token_endpoint_auth_method,
      issuedAt: Math.floor(Date.now() / 1000),
      ...(meta.client_name ? { clientName: meta.client_name } : {}),
      ...(secret ? { secretHash: hashToken(secret) } : {}),
    };
    await this.store.put("client", clientId, record, TTL.client);
    return json({
      client_id: clientId,
      client_id_issued_at: record.issuedAt,
      ...(secret ? { client_secret: secret, client_secret_expires_at: 0 } : {}),
      redirect_uris: record.redirectUris,
      token_endpoint_auth_method: record.authMethod,
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      ...(record.clientName ? { client_name: record.clientName } : {}),
      scope: MCP_SCOPE,
    }, 201);
  }

  // ---- Authorization endpoint + consent ------------------------------------------------

  async authorize(request: Request): Promise<Response> {
    const params = new URL(request.url).searchParams;
    const clientId = params.get("client_id") ?? "";
    const redirectUri = params.get("redirect_uri") ?? "";
    const client = clientId ? await this.store.get<ClientRecord>("client", clientId) : undefined;
    // Never redirect to an unverified URI: show the error to the user instead.
    if (!client) return htmlPage("Unknown application", "<h1>Unknown application</h1><p>This application is not registered with this server. Remove and re-add the connector in your MCP client.</p>", 400);
    const registered = client.redirectUris.find((uri) => redirectMatches(uri, redirectUri)) ??
      (!redirectUri && client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
    if (!registered) return htmlPage("Invalid redirect", "<h1>Invalid redirect</h1><p>The application's redirect address does not match its registration.</p>", 400);
    const target = redirectUri || registered;

    const state = params.get("state") ?? undefined;
    const fail = (code: string, description: string) => this.clientRedirect(target, { error: code, error_description: description, state });
    if (params.get("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code.");
    const challenge = params.get("code_challenge") ?? "";
    if (params.get("code_challenge_method") !== "S256" || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
      return fail("invalid_request", "PKCE with code_challenge_method=S256 is required.");
    }
    const resource = params.get("resource");
    if (resource && !sameResource(resource, this.config.mcpUrl)) {
      return fail("invalid_target", "Unknown resource.");
    }

    const txnId = randomToken();
    const binding = randomToken();
    await this.store.put("txn", txnId, {
      clientId,
      redirectUri: target,
      codeChallenge: challenge,
      bindingHash: hashToken(binding),
      upstreamVerifier: randomToken(),
      consented: false,
      ...(state !== undefined ? { state } : {}),
    } satisfies TxnRecord, TTL.txn);

    const name = client.clientName ?? "An unnamed application";
    const host = (() => {
      const url = new URL(target);
      return url.protocol === "https:" || url.protocol === "http:" ? url.host : url.protocol;
    })();
    return htmlPage("Connect Outlook.com", `
<h1>Connect your Outlook.com account</h1>
<p><strong>${escapeHtml(name)}</strong> wants access to your personal Outlook.com:</p>
<ul><li>Profile</li><li>Mail: read, search, move between folders, mark read or unread, flag, categorize, and report as not junk</li><li>Mail folders: create</li><li>Calendar events (read)</li><li>Contacts (read)</li></ul>
<p class="muted">It cannot send or permanently delete mail, rename or delete folders, or change calendar events or contacts. Moving mail to Deleted Items is reversible.</p>
<p class="muted">After approval you will return to <code>${escapeHtml(host)}</code>. Only continue if you started this connection from that app.</p>
<form method="post" action="/authorize/consent">
<input type="hidden" name="txn" value="${escapeHtml(txnId)}">
<div class="actions"><button name="decision" value="deny">Cancel</button>
<button class="primary" name="decision" value="allow" autofocus>Continue to Microsoft</button></div>
</form>`, 200, { "Set-Cookie": this.bindingCookie(txnId, binding, TTL.txn) });
  }

  async consent(request: Request): Promise<Response> {
    const origin = request.headers.get("origin");
    if (origin && origin !== this.config.publicUrl) return htmlPage("Request blocked", "<h1>Request blocked</h1>", 403);
    const form = new URLSearchParams(await readBody(request) ?? "");
    const txnId = form.get("txn") ?? "";
    const txn = txnId ? await this.store.get<TxnRecord>("txn", txnId) : undefined;
    if (!txn || !this.boundToBrowser(request, txnId, txn)) return this.expired();
    if (form.get("decision") !== "allow") {
      await this.store.delete("txn", txnId);
      return this.clientRedirect(txn.redirectUri, { error: "access_denied", error_description: "The user declined.", state: txn.state },
        { "Set-Cookie": this.bindingCookie(txnId, "", 0) });
    }
    await this.store.put("txn", txnId, { ...txn, consented: true }, TTL.txn);
    return redirect(this.entra.authorizeUrl(txnId, pkceChallenge(txn.upstreamVerifier)));
  }

  /** Microsoft redirects here after sign-in. */
  async callback(request: Request): Promise<Response> {
    const params = new URL(request.url).searchParams;
    const txnId = params.get("state") ?? "";
    const txn = txnId ? await this.store.take<TxnRecord>("txn", txnId) : undefined;
    if (!txn || !txn.consented || !this.boundToBrowser(request, txnId, txn)) return this.expired();
    const clear = { "Set-Cookie": this.bindingCookie(txnId, "", 0) };
    const fail = (code: string, description: string) =>
      this.clientRedirect(txn.redirectUri, { error: code, error_description: description, state: txn.state }, clear);

    const upstreamError = params.get("error");
    if (upstreamError) return fail(upstreamError === "access_denied" ? "access_denied" : "server_error", "Microsoft sign-in was not completed.");
    const code = params.get("code");
    if (!code) return fail("server_error", "Microsoft did not return an authorization code.");

    let signIn: Awaited<ReturnType<EntraClient["redeemCode"]>>;
    try {
      signIn = await this.entra.redeemCode(code, txn.upstreamVerifier);
    } catch (error) {
      if (error instanceof UpstreamError && error.code === "not_personal_account") {
        return htmlPage("Personal account required", "<h1>Personal account required</h1><p>Sign in with a personal Microsoft account (Outlook.com, Hotmail, or Live), not a work or school account.</p>", 403, clear);
      }
      console.error("Upstream code redemption failed:", error instanceof Error ? error.message : error);
      return fail("server_error", "Microsoft sign-in failed.");
    }
    const username = signIn.user.username?.toLowerCase();
    if (this.config.allowedUsers && !(username && this.config.allowedUsers.has(username))) {
      // nosemgrep: javascript.lang.security.html-in-template-string -- username is escaped
      return htmlPage("Account not allowed", `<h1>Account not allowed</h1><p>${escapeHtml(username ?? "This account")} is not authorized to use this server. Ask the server owner to add it.</p>`, 403, clear);
    }

    const grantId = randomToken();
    await this.store.put("grant", grantId, {
      version: GRANT_VERSION,
      expiresAt: Date.now() + TTL.grant * 1000,
      userId: signIn.user.id,
      clientId: txn.clientId,
      upstreamRefreshToken: signIn.tokens.refreshToken!,
      upstreamAccessToken: signIn.tokens.accessToken,
      upstreamAccessTokenExpiresAt: signIn.tokens.accessTokenExpiresAt,
      ...(username ? { username } : {}),
    } satisfies GrantRecord, TTL.grant);
    const authCode = randomToken();
    await this.store.put("code", hashToken(authCode), {
      grantId, clientId: txn.clientId, redirectUri: txn.redirectUri, codeChallenge: txn.codeChallenge,
    } satisfies CodeRecord, TTL.code);
    console.log(`Authorized grant for ${username ?? signIn.user.id}`);
    return this.clientRedirect(txn.redirectUri, { code: authCode, state: txn.state }, clear);
  }

  // ---- Token endpoint ------------------------------------------------------------------

  async token(request: Request): Promise<Response> {
    const form = new URLSearchParams(await readBody(request) ?? "");
    const client = await this.authenticateClient(request, form);
    if (client instanceof Response) return client;

    const resource = form.get("resource");
    if (resource && !sameResource(resource, this.config.mcpUrl)) return oauthError("invalid_target", "Unknown resource.");

    const grantType = form.get("grant_type");
    if (grantType === "authorization_code") {
      const code = form.get("code") ?? "";
      const record = code ? await this.store.take<CodeRecord>("code", hashToken(code)) : undefined;
      if (!record || record.clientId !== client.clientId) return oauthError("invalid_grant", "Invalid or expired authorization code.");
      const requestedRedirect = form.get("redirect_uri");
      if (requestedRedirect !== null && requestedRedirect !== record.redirectUri) {
        return oauthError("invalid_grant", "redirect_uri does not match the authorization request.");
      }
      if (!verifyPkce(form.get("code_verifier") ?? "", record.codeChallenge)) {
        return oauthError("invalid_grant", "PKCE verification failed.");
      }
      return this.issueTokens(record.grantId, client.clientId);
    }
    if (grantType === "refresh_token") {
      const expiresAt = Date.now() + TTL.grant * 1000;
      const token = form.get("refresh_token") ?? "";
      const key = hashToken(token);
      let family = token ? await this.store.get<RefreshRecord>("refreshFamily", key) : undefined;
      if (!family && token) {
        // Upgrade still-live tokens issued before persistent reuse tracking.
        family = await this.store.get<RefreshRecord>("refresh", key);
        if (!family) {
          family = await this.store.get<RefreshRecord>("refreshFamily", key);
        } else if (family.clientId === client.clientId) {
          await this.store.put("refreshFamily", key, family, TTL.refresh);
        }
      }
      if (!family || family.clientId !== client.clientId) return oauthError("invalid_grant", "Invalid or expired refresh token.");
      const record = await this.store.take<RefreshRecord>("refresh", key);
      if (!record) {
        await this.revokeGrant(family.grantId);
        return oauthError("invalid_grant", "Invalid or expired refresh token.");
      }
      if (record.clientId !== client.clientId) return oauthError("invalid_grant", "Invalid or expired refresh token.");
      const grant = await this.currentGrant(record.grantId);
      if (!grant) return oauthError("invalid_grant", "The authorization was revoked. Sign in again.");
      if (!await this.store.update<GrantRecord>("grant", record.grantId,
        (latest) => ({ ...latest, expiresAt: Math.max(latest.expiresAt ?? 0, expiresAt) }), TTL.grant)) {
        return oauthError("invalid_grant", "The authorization was revoked. Sign in again.");
      }
      return this.issueTokens(record.grantId, client.clientId);
    }
    return oauthError("unsupported_grant_type", "Use authorization_code or refresh_token.");
  }

  private async issueTokens(grantId: string, clientId: string): Promise<Response> {
    if (!await this.currentGrant(grantId)) return oauthError("invalid_grant", "The authorization was revoked. Sign in again.");
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const expiresAt = Math.floor(Date.now() / 1000) + TTL.access;
    // Family expiry triggers a storage lifecycle review, retaining hashes for the entire live session.
    await this.store.put("refreshFamily", hashToken(refreshToken), { grantId, clientId } satisfies RefreshRecord, TTL.refresh);
    await this.store.put("access", hashToken(accessToken), { grantId, clientId, expiresAt } satisfies AccessRecord, TTL.access);
    await this.store.put("refresh", hashToken(refreshToken), { grantId, clientId } satisfies RefreshRecord, TTL.refresh);
    if (!await this.currentGrant(grantId)) return oauthError("invalid_grant", "The authorization was revoked. Sign in again.");
    return json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: TTL.access,
      refresh_token: refreshToken,
      scope: MCP_SCOPE,
    });
  }

  private async authenticateClient(request: Request, form: URLSearchParams): Promise<ClientRecord | Response> {
    let clientId = form.get("client_id");
    let secret = form.get("client_secret");
    const header = request.headers.get("authorization");
    if (header?.toLowerCase().startsWith("basic ")) {
      const decoded = Buffer.from(header.slice(6).trim(), "base64").toString("utf8");
      const index = decoded.indexOf(":");
      if (index < 0) return oauthError("invalid_client", "Malformed client credentials.", 401);
      try {
        clientId = decodeURIComponent(decoded.slice(0, index));
        secret = decodeURIComponent(decoded.slice(index + 1));
      } catch (error) {
        if (!(error instanceof URIError)) throw error;
        return oauthError("invalid_client", "Malformed client credentials.", 401);
      }
    }
    const client = clientId ? await this.store.get<ClientRecord>("client", clientId) : undefined;
    if (!client) return oauthError("invalid_client", "Unknown client.", 401);
    if (client.secretHash && !(secret && safeEqual(hashToken(secret), client.secretHash))) {
      return oauthError("invalid_client", "Client authentication failed.", 401);
    }
    return client;
  }

  // ---- Resource server side ------------------------------------------------------------

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = await this.store.get<AccessRecord>("access", hashToken(token));
    if (!record || !(await this.currentGrant(record.grantId))) {
      throw new OAuthError(OAuthErrorCode.InvalidToken, "Invalid or expired access token.");
    }
    return {
      token,
      clientId: record.clientId,
      scopes: [MCP_SCOPE],
      expiresAt: record.expiresAt,
      resource: new URL(this.config.mcpUrl),
      extra: { grantId: record.grantId },
    };
  }

  /** Returns a Microsoft Graph access token for the grant, refreshing it with Microsoft when needed. */
  async graphAccessToken(grantId: string): Promise<string> {
    const grant = await this.currentGrant(grantId);
    if (!grant) throw new ReconnectRequiredError();
    let pending = this.refreshing.get(grantId);
    if (!pending) {
      pending = this.loadGraphToken(grantId, grant).finally(() => this.refreshing.delete(grantId));
      this.refreshing.set(grantId, pending);
    }
    return pending;
  }

  private async loadGraphToken(grantId: string, grant: GrantRecord): Promise<string> {
    const expiresAt = Date.now() + TTL.grant * 1000;
    if (grant.upstreamAccessToken && (grant.upstreamAccessTokenExpiresAt ?? 0) - Date.now() > 120_000) {
      return grant.upstreamAccessToken;
    }
    let tokens;
    try {
      tokens = await this.entra.refresh(grant.upstreamRefreshToken);
    } catch (error) {
      if (error instanceof UpstreamError && (error.code === "invalid_grant" || error.code === "interaction_required")) {
        await this.revokeGrant(grantId);
        throw new ReconnectRequiredError();
      }
      throw error;
    }
    const updated = await this.store.update<GrantRecord>("grant", grantId, (latest) => ({
      ...latest,
      expiresAt: Math.max(latest.expiresAt ?? 0, expiresAt),
      upstreamRefreshToken: tokens.refreshToken ?? latest.upstreamRefreshToken,
      upstreamAccessToken: tokens.accessToken,
      upstreamAccessTokenExpiresAt: tokens.accessTokenExpiresAt,
    }), TTL.grant);
    if (!updated || !await this.currentGrant(grantId)) throw new ReconnectRequiredError();
    return tokens.accessToken;
  }

  // ---- Helpers -------------------------------------------------------------------------

  private async revokeGrant(grantId: string): Promise<void> {
    // Never delete this marker while stale requests can still write a usable grant.
    await this.store.put("revoked", grantId, {}, TTL.grant + TTL.refresh);
    await this.store.delete("grant", grantId);
  }

  /** Persistent revocation is authoritative even if an in-flight writer restores the grant row. */
  private async currentGrant(grantId: string): Promise<GrantRecord | undefined> {
    const grant = await this.store.get<GrantRecord>("grant", grantId);
    if (grant && ((grant.version ?? 1) < GRANT_VERSION || (grant.expiresAt ?? Infinity) <= Date.now())) {
      await this.revokeGrant(grantId);
      return undefined;
    }
    if (await this.store.get("revoked", grantId)) return undefined;
    return grant;
  }

  private clientRedirect(target: string, params: Record<string, string | undefined>, headers: Record<string, string> = {}): Response {
    const url = new URL(target);
    for (const [key, value] of Object.entries({ ...params, iss: this.config.publicUrl })) {
      if (value !== undefined) url.searchParams.set(key, value);
    }
    return redirect(url.href, headers);
  }

  private bindingCookie(txnId: string, value: string, maxAge: number): string {
    return `${this.cookiePrefix}${txnId.slice(0, 16)}=${value}; Max-Age=${maxAge}; Path=/; HttpOnly; SameSite=Lax${this.secureCookie}`;
  }

  private boundToBrowser(request: Request, txnId: string, txn: TxnRecord): boolean {
    const value = cookies(request).get(`${this.cookiePrefix}${txnId.slice(0, 16)}`);
    return !!value && safeEqual(hashToken(value), txn.bindingHash);
  }

  private expired(): Response {
    return htmlPage("Sign-in expired", "<h1>Sign-in expired</h1><p>This sign-in link expired or was opened in a different browser. Start the connection again from your MCP client.</p>", 400);
  }
}
