import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { RestError } from "@azure/data-tables";
import { MSA_TENANT_ID, loadConfig } from "../dist/config.js";
import { hashToken, pkceChallenge, Sealer } from "../dist/crypto.js";
import { OAuthServer, ReconnectRequiredError } from "../dist/oauth.js";
import { MemoryStore, TableStore } from "../dist/store.js";
import { EntraClient, UpstreamError } from "../dist/upstream.js";

const BASE = "https://oauth.example";
const CLIENT_ID = "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13";
const OTHER_ID = "00000000-0000-4000-8000-000000000001";
const REDIRECT = "https://client.example/callback";
const LIMIT = 16_384;
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const jwt = (claims) => `${encode({ alg: "none" })}.${encode(claims)}.synthetic`;
const validClaims = () => ({
  tid: MSA_TENANT_ID,
  iss: `https://login.microsoftonline.com/${MSA_TENANT_ID}/v2.0`,
  aud: CLIENT_ID,
  exp: Math.floor(Date.now() / 1000) + 3600,
  sub: "synthetic-user",
  preferred_username: "user@example.com",
});

function fakeEntra(claims = validClaims()) {
  return new EntraClient(CLIENT_ID, "synthetic-test-secret", `${BASE}/oauth/callback`, async () =>
    Response.json({
      access_token: "synthetic-graph-access",
      refresh_token: "synthetic-graph-refresh",
      expires_in: 3600,
      id_token: typeof claims === "string" ? claims : jwt(claims),
    }));
}

function setup(entra = fakeEntra(), store) {
  const config = loadConfig({
    PUBLIC_URL: BASE,
    ENTRA_CLIENT_ID: CLIENT_ID,
    ENTRA_CLIENT_SECRET: "synthetic-test-secret",
    TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
  });
  store ??= new MemoryStore(new Sealer(config.encryptionKey));
  return { oauth: new OAuthServer(config, store, entra), store, config };
}

function form(path, fields) {
  return new Request(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields),
  });
}

async function signIn(oauth, username = "user@example.com") {
  const registration = await oauth.register(new Request(`${BASE}/register`, {
    method: "POST",
    body: JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none" }),
  }));
  assert.equal(registration.status, 201);
  const { client_id: clientId } = await registration.json();
  const verifier = randomBytes(32).toString("base64url");
  const page = await oauth.authorize(new Request(`${BASE}/authorize?${new URLSearchParams({
    response_type: "code", client_id: clientId, redirect_uri: REDIRECT,
    code_challenge: pkceChallenge(verifier), code_challenge_method: "S256",
  })}`));
  const txn = /name="txn" value="([^"]+)"/.exec(await page.text())[1];
  const cookie = page.headers.get("set-cookie").split(";")[0];
  const consent = form("/authorize/consent", { txn, decision: "allow" });
  consent.headers.set("cookie", cookie);
  consent.headers.set("origin", BASE);
  assert.equal((await oauth.consent(consent)).status, 302);
  const callback = await oauth.callback(new Request(`${BASE}/oauth/callback?${new URLSearchParams({
    state: txn, code: username,
  })}`, { headers: { cookie } }));
  const code = new URL(callback.headers.get("location")).searchParams.get("code");
  assert.ok(code);
  const response = await oauth.token(form("/token", {
    grant_type: "authorization_code", client_id: clientId, code, code_verifier: verifier, redirect_uri: REDIRECT,
  }));
  assert.equal(response.status, 200);
  return { clientId, tokens: await response.json() };
}

async function refresh(oauth, session, token = session.tokens.refresh_token) {
  return oauth.token(form("/token", {
    grant_type: "refresh_token", client_id: session.clientId, refresh_token: token,
  }));
}

function tableFixture() {
  const rows = new Map();
  let version = 0;
  const failure = (statusCode) => new RestError("Synthetic storage conflict", { statusCode });
  return {
    async createTable() {},
    async upsertEntity(entity) {
      rows.set(`${entity.partitionKey}/${entity.rowKey}`, { ...entity, etag: `${++version}` });
    },
    async getEntity(kind, key) {
      const row = rows.get(`${kind}/${key}`);
      if (!row) throw failure(404);
      return { ...row };
    },
    async updateEntity(entity, mode, options) {
      const id = `${entity.partitionKey}/${entity.rowKey}`;
      const row = rows.get(id);
      if (!row) throw failure(404);
      assert.equal(mode, "Replace");
      if (row.etag !== options.etag) throw failure(412);
      rows.set(id, { ...entity, etag: `${++version}` });
    },
    async deleteEntity(kind, key, options) {
      const id = `${kind}/${key}`;
      const row = rows.get(id);
      if (!row) throw failure(404);
      if (options.etag && row.etag !== options.etag) throw failure(412);
      rows.delete(id);
    },
  };
}

describe("OAuth Basic client credentials", () => {
  it("returns invalid_client for malformed percent escapes in either field", async () => {
    const { oauth } = setup();
    for (const credentials of ["bad%:synthetic-secret", `${CLIENT_ID}:bad%E0%A4%A`]) {
      const request = form("/token", { grant_type: "refresh_token" });
      request.headers.set("authorization", `Basic ${Buffer.from(credentials).toString("base64")}`);
      const response = await oauth.token(request);
      assert.equal(response.status, 401);
      assert.equal((await response.json()).error, "invalid_client");
    }
  });

  it("accepts correctly percent-encoded confidential client IDs and secrets", async () => {
    const { oauth, store } = setup();
    const clientId = "synthetic:client";
    const secret = "synthetic:secret%with/slashes";
    await store.put("client", clientId, {
      clientId, authMethod: "client_secret_basic", secretHash: hashToken(secret), redirectUris: [REDIRECT], issuedAt: 0,
    }, 60);
    const request = form("/token", { grant_type: "unsupported" });
    request.headers.set("authorization", `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`).toString("base64")}`);
    const response = await oauth.token(request);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, "unsupported_grant_type");
  });
});

describe("upstream OIDC claim validation", () => {
  it("accepts personal accounts and correctly authorized audience arrays", async () => {
    for (const audience of [
      { aud: CLIENT_ID },
      { aud: [CLIENT_ID] },
      { aud: [OTHER_ID, CLIENT_ID], azp: CLIENT_ID },
    ]) {
      const { user } = await fakeEntra({ ...validClaims(), ...audience }).redeemCode("code", "verifier");
      assert.equal(user.id, "synthetic-user");
    }
  });

  it("rejects missing, malformed, expired or wrongly targeted claims before accepting identity", async () => {
    const invalid = [
      { iss: undefined }, { aud: undefined }, { exp: undefined },
      { iss: "https://issuer.example/v2.0" },
      { iss: "https://login.microsoftonline.com/consumers/v2.0" },
      { aud: OTHER_ID }, { aud: [] },
      { aud: [OTHER_ID], azp: CLIENT_ID },
      { aud: [CLIENT_ID, OTHER_ID] },
      { aud: [CLIENT_ID, OTHER_ID], azp: OTHER_ID },
      { aud: CLIENT_ID, azp: OTHER_ID },
      { exp: Math.floor(Date.now() / 1000) },
      { exp: Math.floor(Date.now() / 1000) - 1 },
      { exp: "9999999999" },
    ];
    for (const claims of invalid) {
      await assert.rejects(fakeEntra({ ...validClaims(), ...claims }).redeemCode("code", "verifier"),
        (error) => error instanceof UpstreamError && error.code === "invalid_id_token");
    }
    await assert.rejects(fakeEntra("invalid.payload.token").redeemCode("code", "verifier"),
      (error) => error instanceof UpstreamError && error.code === "invalid_id_token");
    await assert.rejects(fakeEntra({ ...validClaims(), tid: OTHER_ID }).redeemCode("code", "verifier"),
      (error) => error instanceof UpstreamError && error.code === "not_personal_account");
  });
});

describe("persistent refresh-token family revocation", () => {
  it("revokes attacker replacements and old access on legitimate reuse across instances, not unrelated grants", async () => {
    const { oauth, store, config } = setup();
    const session = await signIn(oauth);
    const otherEntra = fakeEntra({ ...validClaims(), sub: "other-synthetic-user", preferred_username: "other@example.com" });
    const replica = new OAuthServer(config, store, otherEntra);
    const unrelated = await signIn(replica, "other@example.com");
    const grantId = (await oauth.verifyAccessToken(session.tokens.access_token)).extra.grantId;
    await oauth.graphAccessToken(grantId); // Populate this instance's Graph cache.
    const stolen = await refresh(replica, session);
    assert.equal(stolen.status, 200);
    const replacement = await stolen.json();
    assert.equal((await refresh(oauth, session)).status, 400);
    for (const server of [oauth, new OAuthServer(config, store, otherEntra)]) {
      await assert.rejects(server.verifyAccessToken(session.tokens.access_token));
      await assert.rejects(server.verifyAccessToken(replacement.access_token));
      await assert.rejects(server.graphAccessToken(grantId), ReconnectRequiredError);
      assert.equal((await refresh(server, session, replacement.refresh_token)).status, 400);
      assert.equal((await server.verifyAccessToken(unrelated.tokens.access_token)).clientId, unrelated.clientId);
    }
    assert.equal((await refresh(replica, unrelated)).status, 200);
    assert.equal(await store.get("refresh", hashToken(session.tokens.refresh_token)), undefined);
    assert.equal((await store.get("refreshFamily", hashToken(session.tokens.refresh_token))).grantId, grantId);
    assert.ok(await store.get("revoked", grantId));
  });

  it("rejects concurrent use on shared storage and invalidates any winner's credentials", async () => {
    const { oauth, store, config } = setup();
    const session = await signIn(oauth);
    const replica = new OAuthServer(config, store, fakeEntra());
    const results = await Promise.all([refresh(oauth, session), refresh(replica, session)]);
    assert.ok(results.some((response) => response.status === 400));
    for (const response of results) {
      if (response.status === 200) {
        const tokens = await response.json();
        await assert.rejects(oauth.verifyAccessToken(tokens.access_token));
        assert.equal((await refresh(replica, session, tokens.refresh_token)).status, 400);
      }
    }
    await assert.rejects(replica.verifyAccessToken(session.tokens.access_token));
  });

  it("upgrades live refresh tokens issued before reuse tracking without forcing reconnect", async () => {
    const { oauth, store } = setup();
    const session = await signIn(oauth);
    await store.delete("refreshFamily", hashToken(session.tokens.refresh_token));
    const response = await refresh(oauth, session);
    assert.equal(response.status, 200);
    const replacement = await response.json();
    assert.equal((await refresh(oauth, session)).status, 400);
    await assert.rejects(oauth.verifyAccessToken(replacement.access_token));
  });

  it("does not allow a deferred upstream refresh to resurrect a revoked grant", async () => {
    let release;
    let started;
    const pending = new Promise((resolve) => { release = resolve; });
    const entered = new Promise((resolve) => { started = resolve; });
    const entra = fakeEntra();
    entra.refresh = async () => {
      started();
      await pending;
      return { accessToken: "synthetic-new-graph-access", refreshToken: "synthetic-new-graph-refresh", accessTokenExpiresAt: Date.now() + 3600_000 };
    };
    const { oauth, store, config } = setup(entra);
    const session = await signIn(oauth);
    const grantId = (await oauth.verifyAccessToken(session.tokens.access_token)).extra.grantId;
    const grant = await store.get("grant", grantId);
    await store.put("grant", grantId, { ...grant, upstreamAccessTokenExpiresAt: 0 }, 3600);
    const graphRefresh = oauth.graphAccessToken(grantId);
    const rejected = assert.rejects(graphRefresh, ReconnectRequiredError);
    await entered;
    const replica = new OAuthServer(config, store, fakeEntra());
    const replacement = await (await refresh(replica, session)).json();
    assert.equal((await refresh(replica, session)).status, 400);
    release();
    await rejected;
    for (const server of [oauth, new OAuthServer(config, store, entra)]) {
      await assert.rejects(server.verifyAccessToken(session.tokens.access_token));
      await assert.rejects(server.verifyAccessToken(replacement.access_token));
      await assert.rejects(server.graphAccessToken(grantId), ReconnectRequiredError);
      assert.equal((await refresh(server, session, replacement.refresh_token)).status, 400);
    }
    assert.ok(await store.get("revoked", grantId));
  });

  it("does not resurrect a revoked grant when an MCP refresh storage write was already in flight", async () => {
    const { oauth, store, config } = setup();
    const session = await signIn(oauth);
    let release;
    let started;
    const pending = new Promise((resolve) => { release = resolve; });
    const entered = new Promise((resolve) => { started = resolve; });
    const replace = store.replace.bind(store);
    let defer = true;
    store.replace = async (kind, key, expected, row) => {
      if (kind === "grant" && defer) {
        defer = false;
        started();
        await pending;
      }
      return replace(kind, key, expected, row);
    };
    const rotating = refresh(oauth, session);
    await entered;
    const replica = new OAuthServer(config, store, fakeEntra());
    assert.equal((await refresh(replica, session)).status, 400);
    release();
    assert.equal((await rotating).status, 400);
    await assert.rejects(replica.verifyAccessToken(session.tokens.access_token));
  });

  it("consumes a Table-backed token only once across store instances", async () => {
    const table = tableFixture();
    const sealer = new Sealer(randomBytes(32));
    const a = new TableStore(sealer, table);
    const b = new TableStore(sealer, table);
    const key = hashToken("synthetic-token");
    await a.put("refresh", key, { grantId: "synthetic-grant", clientId: CLIENT_ID }, 60);
    const results = await Promise.all([a.take("refresh", key), b.take("refresh", key)]);
    assert.equal(results.filter(Boolean).length, 1);
    assert.equal(await b.get("refresh", key), undefined);
  });

  for (const backend of ["memory", "table"]) {
    it(`preserves concurrent upstream credentials during a deferred MCP renewal (${backend})`, async () => {
      const sealer = new Sealer(randomBytes(32));
      const table = tableFixture();
      const store = backend === "memory" ? new MemoryStore(sealer) : new TableStore(sealer, table);
      const otherStore = backend === "memory" ? store : new TableStore(sealer, table);
      const entra = fakeEntra();
      entra.refresh = async () => ({
        accessToken: "synthetic-updated-graph-access",
        refreshToken: "synthetic-updated-graph-refresh",
        accessTokenExpiresAt: Date.now() + 3600_000,
      });
      const { oauth, config } = setup(entra, store);
      const session = await signIn(oauth);
      const grantId = (await oauth.verifyAccessToken(session.tokens.access_token)).extra.grantId;
      const grant = await store.get("grant", grantId);
      await store.put("grant", grantId, { ...grant, upstreamAccessTokenExpiresAt: 0 }, 3600);
      let release;
      let started;
      const pending = new Promise((resolve) => { release = resolve; });
      const entered = new Promise((resolve) => { started = resolve; });
      const replace = store.replace.bind(store);
      let defer = true;
      store.replace = async (...args) => {
        if (args[0] === "grant" && defer) {
          defer = false;
          started();
          await pending;
        }
        return replace(...args);
      };
      const rotating = refresh(oauth, session);
      await entered;
      const replica = new OAuthServer(config, otherStore, entra);
      assert.equal(await replica.graphAccessToken(grantId), "synthetic-updated-graph-access");
      release();
      assert.equal((await rotating).status, 200);
      const latest = await store.get("grant", grantId);
      assert.equal(latest.upstreamRefreshToken, "synthetic-updated-graph-refresh");
      assert.equal(latest.upstreamAccessToken, "synthetic-updated-graph-access");
      assert.ok(latest.expiresAt >= grant.expiresAt);
      const renewedRow = await store.read("grant", grantId);
      assert.ok(renewedRow.expiresAt > Date.now() + 89 * 24 * 3600_000, "MCP renewal preserves the sliding lifetime");
      store.close();
      otherStore.close();
    });
  }
});

function streamed(path, bytes, chunkSize = 1024) {
  let offset = 0;
  const state = { cancelled: false, pulled: 0 };
  const stream = new ReadableStream({
    pull(controller) {
      if (offset >= bytes.byteLength) return controller.close();
      const next = bytes.subarray(offset, offset + chunkSize);
      offset += next.byteLength;
      state.pulled += next.byteLength;
      controller.enqueue(next);
    },
    cancel() { state.cancelled = true; },
  }, { highWaterMark: 0 });
  const request = new Request(`${BASE}${path}`, { method: "POST", body: stream, duplex: "half" });
  // These handlers must read the stream, not delegate to an unbounded convenience reader.
  request.text = () => { throw new Error("Unbounded request.text()"); };
  return { request, state };
}

describe("OAuth request stream byte budgets", () => {
  it("accepts exactly 16KiB across chunk boundaries, including split multibyte characters", async () => {
    const { oauth } = setup();
    const registration = JSON.stringify({ redirect_uris: [REDIRECT], token_endpoint_auth_method: "none", padding: "\u00e9" });
    const bytes = Buffer.from(registration + " ".repeat(LIMIT - Buffer.byteLength(registration)));
    const { request, state } = streamed("/register", bytes, 1);
    assert.equal((await oauth.register(request)).status, 201);
    assert.equal(state.pulled, LIMIT);
    assert.equal(state.cancelled, false);
  });

  it("cancels oversized registration, token and consent streams without draining them", async () => {
    const { oauth } = setup();
    for (const [path, handler, expected] of [
      ["/register", "register", 400],
      ["/token", "token", 401],
      ["/authorize/consent", "consent", 400],
    ]) {
      const { request, state } = streamed(path, Buffer.alloc(LIMIT * 8, 32));
      assert.equal((await oauth[handler](request)).status, expected);
      assert.equal(state.cancelled, true);
      assert.equal(state.pulled, LIMIT + 1024);
    }
  });

  it("rejects one byte over the boundary and multibyte bodies under the old character limit", async () => {
    const { oauth } = setup();
    for (const text of [
      JSON.stringify({ redirect_uris: [REDIRECT], padding: "\u00e9".repeat(9000) }),
      `${JSON.stringify({ redirect_uris: [REDIRECT] })}${" ".repeat(LIMIT)}`.slice(0, LIMIT + 1),
    ]) {
      const { request, state } = streamed("/register", Buffer.from(text), 257);
      assert.equal((await oauth.register(request)).status, 400);
      assert.equal(state.cancelled, true);
    }
  });

  it("accepts token and consent forms at the byte boundary, rejecting the same valid forms beyond it", async () => {
    const { oauth, store } = setup();
    const session = await signIn(oauth);
    const tokenBody = new URLSearchParams({
      client_id: session.clientId, grant_type: "refresh_token", refresh_token: session.tokens.refresh_token,
    }).toString();
    const padded = (text, size) => Buffer.from(`${text}&padding=${" ".repeat(size - Buffer.byteLength(text) - 9)}`);
    const oversized = streamed("/token", padded(tokenBody, LIMIT + 1), 1024);
    assert.equal((await oauth.token(oversized.request)).status, 401);
    assert.equal(oversized.state.cancelled, true);
    const exact = streamed("/token", padded(tokenBody, LIMIT), 1024);
    assert.equal((await oauth.token(exact.request)).status, 200);

    const txn = "synthetic-consent-transaction";
    const binding = "synthetic-browser-binding";
    await store.put("txn", txn, {
      clientId: session.clientId, redirectUri: REDIRECT, codeChallenge: pkceChallenge("synthetic-verifier"),
      bindingHash: hashToken(binding), upstreamVerifier: "synthetic-upstream-verifier", consented: false,
    }, 600);
    const consentBody = new URLSearchParams({ txn, decision: "allow" }).toString();
    for (const [size, status] of [[LIMIT + 1, 400], [LIMIT, 302]]) {
      const { request, state } = streamed("/authorize/consent", padded(consentBody, size), 1024);
      request.headers.set("origin", BASE);
      request.headers.set("cookie", `__Host-omcp_${txn.slice(0, 16)}=${binding}`);
      assert.equal((await oauth.consent(request)).status, status);
      assert.equal(state.cancelled, size > LIMIT);
    }
  });
});
