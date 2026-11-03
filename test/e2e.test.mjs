import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, it } from "node:test";
import { Client, StreamableHTTPClientTransport } from "@modelcontextprotocol/client";
import { createApp } from "../dist/app.js";
import { loadConfig } from "../dist/config.js";
import { Sealer } from "../dist/crypto.js";
import { OAuthServer } from "../dist/oauth.js";
import { MemoryStore } from "../dist/store.js";
import { EntraClient } from "../dist/upstream.js";

const BASE = "https://outlook-mcp.test";
const CLIENT_REDIRECT = "https://client.example/callback";
const MSA_TID = "9188040d-6c67-4c5b-b112-36a304b66dad";

const b64url = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const idToken = (claims) => `${b64url({ alg: "none" })}.${b64url(claims)}.sig`;

const fid = (name) => `AAMkAD${name.padEnd(40, "x")}`; // looks like a real (long) Graph folder ID
const FOLDERS = [
  { id: fid("inbox"), displayName: "Inbox", parentFolderId: null },
  { id: fid("travel"), displayName: "Travel", parentFolderId: null },
  { id: fid("projects"), displayName: "Projects", parentFolderId: null },
  { id: fid("inboxreceipts"), displayName: "Receipts", parentFolderId: fid("inbox") },
  { id: fid("scouting"), displayName: "Scouting", parentFolderId: fid("projects") },
  { id: fid("projreceipts"), displayName: "Receipts", parentFolderId: fid("projects") },
  { id: fid("longname"), displayName: "PersonalCorrespondenceAndTravelDocuments2026", parentFolderId: null },
  { id: fid("projtravel"), displayName: "Travel", parentFolderId: fid("projects") },
];

/** Fake Entra token endpoint plus fake Graph, standing in for the network. */
function fakeMicrosoft({ tid = MSA_TID, username = "user@example.com" } = {}) {
  const calls = { token: [], graph: [] };
  let refreshFails = false;
  let reportStatus = 200; // status the beta reportMessage endpoint answers with
  const throttleOnce = new Set(); // batch item URLs to answer 429 the first time
  let failBatchAt = 0; // 1-based $batch round trip to fail with 503 (0 = never)
  let dropItem = null; // batch item URL to leave out of the response
  const batches = []; // size of each $batch round trip
  const fetchFake = async (input, init = {}) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.hostname === "login.microsoftonline.com") {
      const form = new URLSearchParams(String(init.body));
      calls.token.push(Object.fromEntries(form));
      if (form.get("grant_type") === "refresh_token" && refreshFails) {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({
        access_token: `graph-at-${calls.token.length}`,
        refresh_token: `graph-rt-${calls.token.length}`,
        expires_in: 3600,
        id_token: idToken({ tid, oid: "user-oid", sub: "s", name: "Test User", preferred_username: username }),
      });
    }
    if (url.hostname === "graph.microsoft.com" && url.pathname === "/v1.0/$batch" && init.method === "POST") {
      const { requests } = JSON.parse(init.body);
      batches.push(requests.length);
      if (batches.length === failBatchAt) return Response.json({ error: { code: "ServiceUnavailable" } }, { status: 503 });
      const responses = [];
      for (const r of requests) {
        if (throttleOnce.delete(r.url)) { responses.push({ id: r.id, status: 429, headers: { "Retry-After": "0" } }); continue; }
        if (r.url === dropItem) continue;
        const inner = await fetchFake(`https://graph.microsoft.com/v1.0${r.url}`,
          { method: r.method, headers: init.headers, ...(r.body ? { body: JSON.stringify(r.body) } : {}) });
        const text = await inner.text();
        responses.push({ id: r.id, status: inner.status, body: text ? JSON.parse(text) : undefined });
      }
      return Response.json({ responses: responses.reverse() }); // Graph doesn't promise response order
    }
    if (url.hostname === "graph.microsoft.com") {
      const headers = new Headers(init.headers);
      calls.graph.push({ url: url.href, auth: headers.get("authorization"), method: init.method ?? "GET", body: init.body ? JSON.parse(init.body) : undefined });
      const action = /^\/(v1\.0|beta)\/me\/messages\/([^/]+)\/(move|reportMessage)$/.exec(url.pathname);
      if (action && init.method === "POST") {
        const [, version, id, verb] = action;
        if (id === "missing") return Response.json({ error: { code: "ErrorItemNotFound" } }, { status: 404 });
        if (verb === "move" && version === "v1.0") {
          const { destinationId } = JSON.parse(init.body);
          return Response.json({ id: `${id}-in-${destinationId}`, parentFolderId: destinationId, subject: "Hello" }, { status: 201 });
        }
        if (verb === "reportMessage" && version === "beta") {
          if (reportStatus !== 200) return Response.json({ error: { code: "BadRequest" } }, { status: reportStatus });
          return Response.json({ id: `${id}-in-inbox`, parentFolderId: "inbox" });
        }
      }
      if (url.pathname === "/v1.0/me") return Response.json({ displayName: "Test User", mail: username });
      const message = /^\/v1\.0\/me\/messages\/([^/]+)$/.exec(url.pathname);
      if (message && ["GET", "PATCH"].includes(init.method ?? "GET")) {
        const id = decodeURIComponent(message[1]);
        if (id === "missing") return Response.json({ error: { code: "ErrorItemNotFound" } }, { status: 404 });
        return Response.json({ id, parentFolderId: fid("inbox"), ...(init.method === "PATCH" ? JSON.parse(init.body) : {}) });
      }
      const folderList = /^\/v1\.0\/me\/mailFolders(?:\/([^/]+)\/childFolders)?$/.exec(url.pathname);
      if (folderList && init.method === "POST") {
        const parent = folderList[1] ? decodeURIComponent(folderList[1]) : null;
        const { displayName } = JSON.parse(init.body);
        const existing = FOLDERS.find((f) => f.parentFolderId === parent && f.displayName.toLowerCase() === displayName.toLowerCase());
        if (existing) return Response.json({ error: { code: "ErrorFolderExists" } }, { status: 409 });
        return Response.json({ id: fid(`new-${displayName}`), displayName, parentFolderId: parent ?? fid("root") }, { status: 201 });
      }
      if (folderList && (init.method ?? "GET") === "GET") {
        const parent = folderList[1] ? decodeURIComponent(folderList[1]) : null;
        const named = /^displayName eq '(.*)'$/.exec(url.searchParams.get("$filter") ?? "")?.[1]?.replaceAll("''", "'");
        return Response.json({ value: FOLDERS.filter((f) => f.parentFolderId === parent && (named === undefined || f.displayName === named)).map((f) => ({
          ...f, childFolderCount: FOLDERS.filter((c) => c.parentFolderId === f.id).length, totalItemCount: 3, unreadItemCount: 1,
        })) });
      }
      if (url.pathname.endsWith("/messages") && url.searchParams.get("$select") === "from,receivedDateTime,isRead" || url.searchParams.get("$skiptoken")?.startsWith("senders")) {
        // summarize_senders: 600 messages over pages of 250, newest first.
        const all = Array.from({ length: 600 }, (_, i) => ({
          from: { emailAddress: { address: i % 3 === 0 ? "Shop@Example.com" : i % 3 === 1 ? "news@example.com" : `p${i}@example.com`, name: "N" } },
          receivedDateTime: new Date(Date.UTC(2026, 9, 1) - i * 3600_000).toISOString(),
          isRead: i % 2 === 0,
        }));
        const skip = Number(url.searchParams.get("$skiptoken")?.slice(7) ?? 0);
        const size = Number(url.searchParams.get("$top") ?? 250);
        return Response.json({
          value: all.slice(skip, skip + size),
          ...(url.searchParams.get("$count") === "true" ? { "@odata.count": all.length } : {}),
          // Like real Graph: the folder key comes back in OData form, /mailFolders('inbox')/messages.
          ...(skip + size < all.length ? { "@odata.nextLink": `https://graph.microsoft.com${url.pathname.replace(/\/mailFolders\/([^/]+)\//, (_m, k) => `/mailFolders('${decodeURIComponent(k)}')/`)}?$top=${size}&$skiptoken=senders${skip + size}` } : {}),
        });
      }
      if (url.pathname.endsWith("/messages")) {
        return Response.json({
          value: [{ "@odata.etag": "W/\"abc\"", id: "m1", subject: "Hello" }],
          ...(url.searchParams.get("$count") === "true" ? { "@odata.count": 42 } : {}),
          // Real Graph nextLinks use the OData key form, e.g. /me/mailFolders('inbox')/messages.
          "@odata.nextLink": "https://graph.microsoft.com/v1.0/me/mailFolders('inbox')/messages?%24top=15&%24skip=15",
        });
      }
      return Response.json({ error: { code: "ErrorItemNotFound" } }, { status: 404 });
    }
    throw new Error(`Unexpected fetch to ${url.href}`);
  };
  return {
    fetchFake, calls, batches,
    failRefresh: () => { refreshFails = true; },
    rejectReport: (status) => { reportStatus = status; },
    throttle: (itemUrl) => throttleOnce.add(itemUrl),
    failBatch: (n) => { failBatchAt = n; },
    dropBatchItem: (itemUrl) => { dropItem = itemUrl; },
  };
}

function setup(env = {}) {
  const config = loadConfig({
    PUBLIC_URL: BASE,
    ENTRA_CLIENT_ID: "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13",
    ENTRA_CLIENT_SECRET: "test-secret-value",
    TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    ...env,
  });
  const ms = fakeMicrosoft(env.fake);
  const entra = new EntraClient(config.entraClientId, config.entraClientSecret, `${BASE}/oauth/callback`, ms.fetchFake);
  const oauth = new OAuthServer(config, new MemoryStore(new Sealer(config.encryptionKey)), entra);
  const app = createApp(config, oauth);
  return { app, ms, oauth };
}

const call = (app, path, init = {}) => app(new Request(BASE + path, init));
const form = (fields) => ({
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams(fields).toString(),
});

/** Walks the browser + client side of the full authorization-code flow. */
async function authorize(app, { register = {}, approve = true } = {}) {
  const reg = await call(app, "/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ client_name: "Test Agent", redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none", ...register }),
  });
  assert.equal(reg.status, 201);
  const client = await reg.json();

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const authUrl = `/authorize?${new URLSearchParams({
    response_type: "code", client_id: client.client_id, redirect_uri: CLIENT_REDIRECT,
    code_challenge: challenge, code_challenge_method: "S256", state: "xyz", resource: `${BASE}/mcp`,
  })}`;
  const consentPage = await call(app, authUrl);
  assert.equal(consentPage.status, 200);
  const html = await consentPage.text();
  assert.match(html, /Test Agent/);
  assert.match(html, /move between folders, mark read or unread, flag, categorize/, "consent lists every mail write");
  assert.match(html, /Mail folders: create/);
  const txn = /name="txn" value="([^"]+)"/.exec(html)[1];
  const cookie = consentPage.headers.get("set-cookie").split(";")[0];

  const consent = await call(app, "/authorize/consent", {
    ...form({ txn, decision: approve ? "allow" : "deny" }),
    headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie, Origin: BASE },
  });
  assert.equal(consent.status, 302);
  const next = new URL(consent.headers.get("location"));
  if (!approve) return { client, denied: next };
  assert.equal(next.hostname, "login.microsoftonline.com");
  assert.equal(next.searchParams.get("state"), txn);

  const callback = await call(app, `/oauth/callback?code=entra-code&state=${encodeURIComponent(txn)}`, { headers: { Cookie: cookie } });
  assert.equal(callback.status, 302);
  const back = new URL(callback.headers.get("location"));
  assert.equal(back.origin + back.pathname, CLIENT_REDIRECT);
  assert.equal(back.searchParams.get("state"), "xyz");
  assert.equal(back.searchParams.get("iss"), BASE);
  return { client, code: back.searchParams.get("code"), verifier, cookie, txn };
}

async function exchange(app, client, code, verifier) {
  const response = await call(app, "/token", form({
    grant_type: "authorization_code", client_id: client.client_id, code, code_verifier: verifier,
    redirect_uri: CLIENT_REDIRECT, resource: `${BASE}/mcp`,
  }));
  return { status: response.status, body: await response.json() };
}

async function mcpClient(app, accessToken) {
  const client = new Client({ name: "test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${BASE}/mcp`), {
    fetch: (input, init) => app(new Request(input, init)),
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
  }));
  return client;
}

describe("OAuth discovery", () => {
  it("returns 401 with a resource metadata pointer, and serves both metadata documents", async () => {
    const { app } = setup();
    const unauth = await call(app, "/mcp", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    assert.equal(unauth.status, 401);
    assert.match(unauth.headers.get("www-authenticate"), /resource_metadata="https:\/\/outlook-mcp\.test\/\.well-known\/oauth-protected-resource\/mcp"/);

    const prm = await (await call(app, "/.well-known/oauth-protected-resource/mcp")).json();
    assert.equal(prm.resource, `${BASE}/mcp`);
    assert.deepEqual(prm.authorization_servers.map((s) => s.replace(/\/$/, "")), [BASE]);
    const as = await (await call(app, "/.well-known/oauth-authorization-server")).json();
    assert.equal(as.registration_endpoint, `${BASE}/register`);
    assert.deepEqual(as.code_challenge_methods_supported, ["S256"]);
  });
});

describe("end-to-end", () => {
  let restoreFetch;
  beforeEach(() => { restoreFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = restoreFetch; });

  it("authorizes, calls tools with the user's Graph token, and rotates refresh tokens", async () => {
    const { app, ms } = setup();
    globalThis.fetch = ms.fetchFake; // GraphClient uses the global fetch
    const { client, code, verifier } = await authorize(app);
    assert.equal(ms.calls.token[0].code_verifier.length > 40, true, "upstream PKCE verifier sent");

    const tokens = await exchange(app, client, code, verifier);
    assert.equal(tokens.status, 200);
    assert.equal(tokens.body.token_type, "Bearer");

    const replay = await exchange(app, client, code, verifier);
    assert.equal(replay.body.error, "invalid_grant", "authorization codes are single-use");

    const mcp = await mcpClient(app, tokens.body.access_token);
    const { tools } = await mcp.listTools();
    assert.deepEqual(tools.map((t) => t.name).sort(),
      ["get_message", "get_profile", "list_contacts", "list_events", "list_mail_folders", "list_messages", "mark_not_junk",
        "move_message", "move_messages", "search_messages", "update_messages", "create_mail_folder", "summarize_senders"].sort());
    for (const name of ["move_message", "move_messages", "update_messages", "mark_not_junk", "create_mail_folder"]) {
      const tool = tools.find((t) => t.name === name);
      assert.equal(tool.annotations.readOnlyHint, false, `${name} is not read-only`);
      assert.equal(tool.annotations.destructiveHint, false, `${name} is reversible`);
    }
    const profile = await mcp.callTool({ name: "get_profile", arguments: {} });
    assert.match(profile.content[0].text, /Test User/);
    assert.equal(ms.calls.graph.at(-1).auth, "Bearer graph-at-1");

    const page = JSON.parse((await mcp.callTool({ name: "list_messages", arguments: {} })).content[0].text);
    assert.equal(page.items[0].subject, "Hello");
    const next = await mcp.callTool({ name: "list_messages", arguments: { nextLink: page.nextLink } });
    assert.equal(next.isError, undefined);
    const hijack = await mcp.callTool({ name: "list_messages", arguments: { nextLink: "https://evil.example/v1.0/me/mailFolders/inbox/messages" } });
    assert.equal(hijack.isError, true);
    for (const other of [
      "https://graph.microsoft.com/v1.0/me/mailFolders('sentitems')/messages?%24skip=15", // a different folder
      "https://graph.microsoft.com/v1.0/users('someone-else')/mailFolders('inbox')/messages", // another mailbox
      "https://graph.microsoft.com/v1.0/me/mailFolders('inbox')/messages/m1/attachments", // a sub-resource
    ]) {
      const before = ms.calls.graph.length;
      const r = await mcp.callTool({ name: "list_messages", arguments: { nextLink: other } });
      assert.equal(r.isError, true, other);
      assert.match(r.content[0].text, /nextLink does not belong to this tool's collection/, other);
      assert.ok(!ms.calls.graph.slice(before).some((c) => c.url === new URL(other).href), `never requested ${other}`);
    }
    await mcp.close();

    const refreshed = await call(app, "/token", form({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.body.refresh_token }));
    assert.equal(refreshed.status, 200);
    const reused = await call(app, "/token", form({ grant_type: "refresh_token", client_id: client.client_id, refresh_token: tokens.body.refresh_token }));
    assert.equal((await reused.json()).error, "invalid_grant", "refresh tokens rotate");
  });

  it("revokes access when Microsoft rejects the refresh token", async () => {
    const { app, ms, oauth } = setup();
    globalThis.fetch = ms.fetchFake;
    const { client, code, verifier } = await authorize(app);
    const { body } = await exchange(app, client, code, verifier);
    const info = await oauth.verifyAccessToken(body.access_token);
    ms.failRefresh();
    // Force the cached Graph token to look expired.
    oauth["graphTokens"].clear();
    const grant = await oauth["store"].get("grant", info.extra.grantId);
    await oauth["store"].put("grant", info.extra.grantId, { ...grant, upstreamAccessTokenExpiresAt: 0 }, 60);
    await assert.rejects(oauth.graphAccessToken(info.extra.grantId), /Reconnect/);
    await assert.rejects(oauth.verifyAccessToken(body.access_token), /Invalid or expired/);
  });
});

describe("write tools", () => {
  let restoreFetch;
  beforeEach(() => { restoreFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = restoreFetch; });

  async function connected() {
    const env = setup();
    globalThis.fetch = env.ms.fetchFake;
    const { client, code, verifier } = await authorize(env.app);
    const { body } = await exchange(env.app, client, code, verifier);
    return { ...env, mcp: await mcpClient(env.app, body.access_token), accessToken: body.access_token };
  }
  const result = (r) => JSON.parse(r.content[0].text);

  it("move_message posts the destination to v1.0 and returns the new ID", async () => {
    const { mcp, ms } = await connected();
    const r = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: "archive" } });
    assert.equal(r.isError, undefined);
    assert.deepEqual(result(r), { moved: true, id: "m1-in-archive", parentFolderId: "archive", subject: "Hello" });
    const call = ms.calls.graph.at(-1);
    assert.equal(call.method, "POST");
    assert.equal(call.url, "https://graph.microsoft.com/v1.0/me/messages/m1/move");
    assert.deepEqual(call.body, { destinationId: "archive" });
    await mcp.close();
  });

  it("move_message reports a missing message as an error", async () => {
    const { mcp } = await connected();
    const r = await mcp.callTool({ name: "move_message", arguments: { id: "missing", destination: "archive" } });
    assert.equal(r.isError, true);
    assert.match(r.content[0].text, /not found/);
    await mcp.close();
  });

  it("move_message rejects IDs that could alter the Graph path", async () => {
    const { mcp, ms } = await connected();
    const before = ms.calls.graph.length;
    const r = await mcp.callTool({ name: "move_message", arguments: { id: "../../users/x", destination: "inbox" } });
    assert.equal(r.isError, true);
    assert.equal(ms.calls.graph.length, before, "no Graph call made");
    await mcp.close();
  });

  it("mark_not_junk reports notJunk via beta reportMessage", async () => {
    const { mcp, ms } = await connected();
    const r = await mcp.callTool({ name: "mark_not_junk", arguments: { id: "j1" } });
    assert.equal(r.isError, undefined);
    assert.deepEqual(result(r), { reportedNotJunk: true, filterUpdated: true, id: "j1-in-inbox", parentFolderId: "inbox" });
    const call = ms.calls.graph.at(-1);
    assert.equal(call.url, "https://graph.microsoft.com/beta/me/messages/j1/reportMessage");
    assert.deepEqual(call.body, { IsMessageMoveRequested: true, ReportAction: "notJunk" });
    await mcp.close();
  });

  it("mark_not_junk falls back to moving to Inbox when reportMessage is unavailable, and says so", async () => {
    const { mcp, ms } = await connected();
    ms.rejectReport(400);
    const r = result(await mcp.callTool({ name: "mark_not_junk", arguments: { id: "j1" } }));
    assert.equal(r.filterUpdated, false);
    assert.equal(r.movedToInbox, true);
    assert.equal(r.id, "j1-in-inbox");
    assert.match(r.note, /Safe senders/);
    assert.equal(ms.calls.graph.at(-1).url, "https://graph.microsoft.com/v1.0/me/messages/j1/move");
    await mcp.close();
  });

  it("mark_not_junk does not fall back for a missing message or when moveToInbox is false", async () => {
    const { mcp, ms } = await connected();
    const missing = await mcp.callTool({ name: "mark_not_junk", arguments: { id: "missing" } });
    assert.equal(missing.isError, true);
    ms.rejectReport(400);
    const noMove = await mcp.callTool({ name: "mark_not_junk", arguments: { id: "j1", moveToInbox: false } });
    assert.equal(noMove.isError, true);
    assert.ok(!ms.calls.graph.some((c) => c.url.endsWith("/move")), "never moved");
    await mcp.close();
  });

  it("requests Mail.ReadWrite and forces reconnect for grants consented under the old scopes", async () => {
    const { ms, oauth, accessToken } = await connected();
    assert.match(ms.calls.token[0].scope, /Mail\.ReadWrite/);
    const info = await oauth.verifyAccessToken(accessToken);
    const store = oauth["store"];
    const grant = await store.get("grant", info.extra.grantId);
    const { version, ...legacy } = grant; // a grant written before scope versioning
    await store.put("grant", info.extra.grantId, legacy, 60);
    oauth["graphTokens"].clear();
    await assert.rejects(oauth.verifyAccessToken(accessToken), /Invalid or expired/);
    assert.equal(await store.get("grant", info.extra.grantId), undefined, "legacy grant discarded");
  });
});

describe("authorization safeguards", () => {
  it("rejects bad PKCE verifier, wrong client, and unknown resource", async () => {
    const { app } = setup();
    const { client, code } = await authorize(app);
    const bad = await exchange(app, client, code, randomBytes(32).toString("base64url"));
    assert.equal(bad.body.error, "invalid_grant");

    const other = await authorize(app);
    const wrongClient = await exchange(app, client, other.code, other.verifier);
    assert.equal(wrongClient.body.error, "invalid_grant");

    const reg = await (await call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none" }) })).json();
    const res = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CLIENT_REDIRECT, code_challenge: "a".repeat(43), code_challenge_method: "S256", resource: "https://other.example/mcp" })}`);
    assert.equal(new URL(res.headers.get("location")).searchParams.get("error"), "invalid_target");
  });

  it("never redirects to an unregistered redirect URI and requires PKCE", async () => {
    const { app } = setup();
    const reg = await (await call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none" }) })).json();
    const evil = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: "https://evil.example/cb", code_challenge: "a".repeat(43), code_challenge_method: "S256" })}`);
    assert.equal(evil.status, 400);
    assert.equal(evil.headers.get("location"), null);
    const noPkce = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CLIENT_REDIRECT })}`);
    assert.equal(new URL(noPkce.headers.get("location")).searchParams.get("error"), "invalid_request");
  });

  it("rejects unsafe redirect URIs at registration, allows loopback and native schemes", async () => {
    const { app } = setup();
    const register = (uris) => call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: uris }) });
    for (const uri of ["http://example.com/cb", "javascript:alert(1)", "data:text/html,x", "https://a.example/cb#frag"]) {
      assert.equal((await register([uri])).status, 400, uri);
    }
    assert.equal((await register(["http://127.0.0.1:33418/cb", "vscode://ms.vscode/cb"])).status, 201);
  });

  it("requires the consent cookie from the same browser", async () => {
    const { app } = setup();
    const reg = await (await call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none" }) })).json();
    const page = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CLIENT_REDIRECT, code_challenge: "a".repeat(43), code_challenge_method: "S256" })}`);
    const txn = /name="txn" value="([^"]+)"/.exec(await page.text())[1];
    const noCookie = await call(app, "/authorize/consent", form({ txn, decision: "allow" }));
    assert.equal(noCookie.status, 400);
    const crossSite = await call(app, "/authorize/consent", {
      ...form({ txn, decision: "allow" }),
      headers: { "Content-Type": "application/x-www-form-urlencoded", Cookie: page.headers.get("set-cookie").split(";")[0], Origin: "https://evil.example" },
    });
    assert.equal(crossSite.status, 403);
  });

  it("serves the consent page with headers that let real browsers submit it and follow the redirect", async () => {
    const { app } = setup();
    const reg = await (await call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none" }) })).json();
    const page = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CLIENT_REDIRECT, code_challenge: "a".repeat(43), code_challenge_method: "S256" })}`);
    // no-referrer makes Chromium send "Origin: null" on the POST, which the CSRF check rejects.
    assert.notEqual(page.headers.get("referrer-policy"), "no-referrer");
    // form-action is enforced on the post-submit redirect to Microsoft / the client.
    assert.doesNotMatch(page.headers.get("content-security-policy"), /form-action/);
  });

  it("returns access_denied to the client when the user declines", async () => {
    const { app } = setup();
    const { denied } = await authorize(app, { approve: false });
    assert.equal(denied.searchParams.get("error"), "access_denied");
    assert.equal(denied.searchParams.get("state"), "xyz");
  });

  it("authenticates confidential clients", async () => {
    const { app } = setup();
    const { client, code, verifier } = await authorize(app, { register: { token_endpoint_auth_method: "client_secret_basic" } });
    assert.ok(client.client_secret);
    const noSecret = await exchange(app, client, code, verifier);
    assert.equal(noSecret.status, 401);
    const basic = Buffer.from(`${client.client_id}:${client.client_secret}`).toString("base64");
    const ok = await call(app, "/token", {
      ...form({ grant_type: "authorization_code", code, code_verifier: verifier, redirect_uri: CLIENT_REDIRECT }),
      headers: { "Content-Type": "application/x-www-form-urlencoded", Authorization: `Basic ${basic}` },
    });
    // The failed attempt above consumed nothing: client auth runs before the code is redeemed.
    assert.equal(ok.status, 200);
  });

  it("blocks work/school accounts and accounts outside ALLOWED_USERS", async () => {
    for (const env of [{ fake: { tid: "00000000-0000-4000-8000-000000000001" } }, { ALLOWED_USERS: "owner@example.com", fake: {} }]) {
      const { app } = setup(env);
      const reg = await (await call(app, "/register", { method: "POST", body: JSON.stringify({ redirect_uris: [CLIENT_REDIRECT], token_endpoint_auth_method: "none" }) })).json();
      const page = await call(app, `/authorize?${new URLSearchParams({ response_type: "code", client_id: reg.client_id, redirect_uri: CLIENT_REDIRECT, code_challenge: "a".repeat(43), code_challenge_method: "S256" })}`);
      const txn = /name="txn" value="([^"]+)"/.exec(await page.text())[1];
      const cookie = page.headers.get("set-cookie").split(";")[0];
      const headers = { "Content-Type": "application/x-www-form-urlencoded", Cookie: cookie };
      await call(app, "/authorize/consent", { ...form({ txn, decision: "allow" }), headers });
      const cb = await call(app, `/oauth/callback?code=c&state=${encodeURIComponent(txn)}`, { headers: { Cookie: cookie } });
      assert.equal(cb.status, 403);
    }
  });
});

describe("token encryption", () => {
  it("round-trips and rejects tampered, truncated, or relocated ciphertext", () => {
    const sealer = new Sealer(randomBytes(32));
    const sealed = sealer.seal("refresh-token", "grant:abc");
    assert.equal(sealer.open(sealed, "grant:abc"), "refresh-token");
    assert.throws(() => sealer.open(sealed, "grant:other"));
    const bytes = Buffer.from(sealed, "base64");
    bytes[bytes.length - 1] ^= 1;
    assert.throws(() => sealer.open(bytes.toString("base64"), "grant:abc"));
    // A short tag (iv + 4-byte tag, no body) must never authenticate.
    assert.throws(() => sealer.open(Buffer.from(sealed, "base64").subarray(0, 16).toString("base64"), "grant:abc"));
  });
});

describe("mailbox tools", () => {
  let restoreFetch;
  beforeEach(() => { restoreFetch = globalThis.fetch; });
  afterEach(() => { globalThis.fetch = restoreFetch; });

  async function connected() {
    const env = setup();
    globalThis.fetch = env.ms.fetchFake;
    const { client, code, verifier } = await authorize(env.app);
    const { body } = await exchange(env.app, client, code, verifier);
    return { ...env, mcp: await mcpClient(env.app, body.access_token) };
  }
  const result = (r) => JSON.parse(r.content[0].text);
  const lastQuery = (ms) => new URL(ms.calls.graph.at(-1).url).searchParams;

  it("fields narrows $select (id always included), allows 100 per page, and strips etags", async () => {
    const { mcp, ms } = await connected();
    const page = result(await mcp.callTool({ name: "search_messages",
      arguments: { query: "from:shop@example.com", fields: ["receivedDateTime", "from", "subject", "subject"], top: 100 } }));
    assert.equal(lastQuery(ms).get("$select"), "id,receivedDateTime,from,subject");
    assert.equal(lastQuery(ms).get("$top"), "100");
    assert.deepEqual(page.items[0], { id: "m1", subject: "Hello" });

    await mcp.callTool({ name: "list_messages", arguments: {} });
    assert.match(lastQuery(ms).get("$select"), /bodyPreview,webLink$/, "default fields unchanged");
    await mcp.close();
  });

  it("list_mail_folders returns the whole tree with paths", async () => {
    const { mcp, ms } = await connected();
    const { items, count } = result(await mcp.callTool({ name: "list_mail_folders", arguments: {} }));
    assert.equal(count, 8);
    assert.deepEqual(items.map((f) => f.path).sort(), ["/Inbox", "/Inbox/Receipts", "/PersonalCorrespondenceAndTravelDocuments2026",
      "/Projects", "/Projects/Receipts", "/Projects/Scouting", "/Projects/Travel", "/Travel"]);
    for (const folder of items) { // every listed path round-trips as a folder argument
      await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: folder.path } });
      assert.deepEqual(ms.calls.graph.at(-1).body, { destinationId: folder.id }, folder.path);
    }
    const top = result(await mcp.callTool({ name: "list_mail_folders", arguments: { includeSubfolders: false } }));
    assert.equal(top.items.length, 4);
    await mcp.close();
  });

  it("resolves folder names and paths (case-insensitive) for moves and listings", async () => {
    const { mcp, ms } = await connected();
    const moves = { "/travel": fid("travel"), "projects/travel": fid("projtravel"), scouting: fid("scouting"),
      "projects/scouting": fid("scouting"), " Inbox / Receipts ": fid("inboxreceipts"), ARCHIVE: "archive",
      [fid("travel")]: fid("travel"), PersonalCorrespondenceAndTravelDocuments2026: fid("longname"),
      AAMkADunlistedHiddenFolderIdxxxxxxxxxxxxxxxxxxxxxx: "AAMkADunlistedHiddenFolderIdxxxxxxxxxxxxxxxxxxxxxx" };
    for (const [destination, expected] of Object.entries(moves)) {
      const r = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination } });
      assert.equal(r.isError, undefined, destination);
      assert.deepEqual(ms.calls.graph.at(-1).body, { destinationId: expected }, destination);
    }
    await mcp.callTool({ name: "list_messages", arguments: { folder: "Scouting" } });
    assert.equal(new URL(ms.calls.graph.at(-1).url).pathname, `/v1.0/me/mailFolders/${fid("scouting")}/messages`);
    const treeLoads = ms.calls.graph.filter((c) => new URL(c.url).pathname === "/v1.0/me/mailFolders").length;
    assert.ok(treeLoads <= Object.keys(moves).length + 1, "folder tree is loaded at most once per tool call");
    await mcp.close();
  });

  it("reports ambiguous or unknown folder names without moving anything", async () => {
    const { mcp, ms } = await connected();
    const ambiguous = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: "Receipts" } });
    assert.equal(ambiguous.isError, true);
    assert.match(ambiguous.content[0].text, /\/Inbox\/Receipts, \/Projects\/Receipts/);
    const topVsNested = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: "Travel" } });
    assert.equal(topVsNested.isError, true, "a bare name shared by a top-level and a nested folder is ambiguous");
    assert.match(topVsNested.content[0].text, /"\/Travel"/);
    const unknown = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: "Nope/Receipts" } });
    assert.match(unknown.content[0].text, /No folder at path/);
    assert.ok(!ms.calls.graph.some((c) => c.url.endsWith("/move")), "never moved");
    await mcp.close();
  });

  it("stops walking at 1,000 folders and refuses bare names it can't check for duplicates", async () => {
    const { FolderDirectory } = await import("../dist/folders.js");
    let requests = 0;
    const big = Array.from({ length: 1001 }, (_, i) => ({ id: fid(`f${i}`), displayName: `F${i}`, childFolderCount: i < 30 ? 1 : 0 }));
    const graph = { page: async (path) => { requests++; return { items: path === "/me/mailFolders" ? big : [{ id: fid("deep"), displayName: "Deep" }] }; } };
    const dir = new FolderDirectory(graph);
    const { folders, truncated } = await dir.directory();
    assert.equal(folders.length, 1000);
    assert.equal(truncated, true);
    assert.equal(requests, 1, "no child collections fetched once the cap is reached");
    await assert.rejects(dir.resolve("F5"), /more than 1000 folders/);
    assert.equal(await dir.resolve("/F5"), fid("f5"), "paths still resolve");
  });

  it("listed paths round-trip despite spaces, and colliding paths require the ID", async () => {
    const { FolderDirectory } = await import("../dist/folders.js");
    const tree = {
      "/me/mailFolders": [{ id: fid("sp"), displayName: " Spaced ", childFolderCount: 0 },
        { id: fid("slash"), displayName: "Projects/Scouting", childFolderCount: 0 },
        { id: fid("proj"), displayName: "Projects", childFolderCount: 1 }],
      [`/me/mailFolders/${fid("proj")}/childFolders`]: [{ id: fid("child"), displayName: "Scouting", childFolderCount: 0 }],
    };
    const dir = new FolderDirectory({ page: async (path) => ({ items: tree[path] ?? [] }) });
    const listed = (await dir.all()).find((f) => f.id === fid("sp"));
    assert.equal(await dir.resolve(listed.path), fid("sp"));
    assert.equal(await dir.resolve("spaced"), fid("sp"));
    await assert.rejects(dir.resolve("/Projects/Scouting"), /matches more than one folder.*Use the folder ID/);
    assert.equal(await dir.resolve(fid("child")), fid("child"), "the ID still works");
  });

  it("does not follow a nextLink once the cap is reached at a page boundary", async () => {
    const { FolderDirectory } = await import("../dist/folders.js");
    const pages = [];
    const page = (n) => ({ items: Array.from({ length: 500 }, (_, i) => ({ id: fid(`p${n}-${i}`), displayName: `P${n}-${i}` })),
      nextLink: "https://graph.microsoft.com/v1.0/me/mailFolders?$skip=" + (n + 1) * 500 });
    const graph = { page: async (_path, _q, next) => { pages.push(next ?? "first"); return page(pages.length - 1); } };
    const { folders, truncated } = await new FolderDirectory(graph).directory();
    assert.equal(folders.length, 1000);
    assert.equal(truncated, true);
    assert.equal(pages.length, 2, "third page never requested");
  });

  it("list_messages filters by date range and unread, with receivedDateTime leading the filter, and counts", async () => {
    const { mcp, ms } = await connected();
    const page = result(await mcp.callTool({ name: "list_messages", arguments: {
      folder: "inbox", unreadOnly: true, receivedAfter: "2026-01-01T00:00:00-08:00", receivedBefore: "2026-02-01T00:00:00Z", includeCount: true } }));
    const q = lastQuery(ms);
    assert.equal(q.get("$filter"),
      "receivedDateTime ge 2026-01-01T08:00:00.000Z and receivedDateTime lt 2026-02-01T00:00:00.000Z and isRead eq false");
    assert.equal(q.get("$orderby"), "receivedDateTime desc");
    assert.equal(q.get("$count"), "true");
    assert.equal(page.count, 42);

    await mcp.callTool({ name: "list_messages", arguments: { unreadOnly: true } });
    assert.equal(lastQuery(ms).get("$filter"), "receivedDateTime ge 1900-01-01T00:00:00Z and isRead eq false");
    await mcp.callTool({ name: "list_messages", arguments: {} });
    assert.equal(lastQuery(ms).get("$filter"), null, "no filter by default");
    assert.equal(lastQuery(ms).get("$count"), null);

    const backwards = await mcp.callTool({ name: "list_messages", arguments: {
      receivedAfter: "2026-02-01T00:00:00Z", receivedBefore: "2026-01-01T00:00:00Z" } });
    assert.equal(backwards.isError, true);
    assert.match(backwards.content[0].text, /receivedBefore must be after receivedAfter/);
    await mcp.close();
  });

  it("search_messages can be limited to one folder", async () => {
    const { mcp, ms } = await connected();
    await mcp.callTool({ name: "search_messages", arguments: { query: "from:godaddy.com", folder: "Inbox" } });
    assert.equal(new URL(ms.calls.graph.at(-1).url).pathname, "/v1.0/me/mailFolders/inbox/messages");
    assert.equal(lastQuery(ms).get("$search"), '"from:godaddy.com"');
    await mcp.callTool({ name: "search_messages", arguments: { query: "x" } });
    assert.equal(new URL(ms.calls.graph.at(-1).url).pathname, "/v1.0/me/messages", "all mail by default");
    await mcp.close();
  });

  it("move_messages moves many in batches of 20, reports each, and returns an undo list", async () => {
    const { mcp, ms } = await connected();
    const ids = [...Array.from({ length: 45 }, (_, i) => `m${i}`), "missing", "m0"];
    ms.throttle("/me/messages/m3/move");
    const r = result(await mcp.callTool({ name: "move_messages", arguments: { ids, destination: "/Travel" } }));
    assert.equal(r.destinationId, fid("travel"));
    assert.equal(r.moved, 45);
    assert.equal(r.failed, 1);
    assert.equal(r.results.length, 46, "duplicates ignored");
    assert.deepEqual(r.results[3], { id: "m3", status: "moved", newId: `m3-in-${fid("travel")}`, sourceFolderId: fid("inbox") },
      "throttled item retried, results matched to requests despite out-of-order responses");
    const missing = r.results.find((x) => x.id === "missing");
    assert.equal(missing.status, "failed");
    assert.match(missing.error, /Not found/);
    // 46 lookups (3 round trips), then 45 moves (3 round trips) with one retry of the throttled move.
    assert.deepEqual(ms.batches, [20, 20, 6, 20, 1, 20, 5], "throttled move retried within its own chunk");
    await mcp.close();
  });

  it("move_messages keeps completed results when a later round trip fails", async () => {
    const { mcp, ms } = await connected();
    const ids = Array.from({ length: 45 }, (_, i) => `m${i}`);
    ms.failBatch(5); // lookups take round trips 1-3; moves 4 (m0-m19), 5 (m20-m39, fails), 6 (never sent)
    const r = result(await mcp.callTool({ name: "move_messages", arguments: { ids, destination: "archive" } }));
    assert.equal(r.moved, 20);
    assert.equal(r.results[0].newId, "m0-in-archive", "undo entries for completed moves survive");
    assert.match(r.results[20].error, /may or may not have happened/);
    assert.match(r.results[44].error, /Not attempted.*Safe to retry/);
    await mcp.close();
  });

  it("move_messages reports an item Graph never answered instead of failing the call", async () => {
    const { mcp, ms } = await connected();
    ms.dropBatchItem("/me/messages/m1/move");
    const r = result(await mcp.callTool({ name: "move_messages", arguments: { ids: ["m0", "m1"], destination: "archive" } }));
    assert.equal(r.moved, 1);
    assert.equal(r.results[1].status, "failed");
    assert.match(r.results[1].error, /may or may not have happened/, "an unanswered move may still have run");
    await mcp.close();
  });

  it("update_messages marks read, flags and categorizes in batches, reporting each", async () => {
    const { mcp, ms } = await connected();
    const r = result(await mcp.callTool({ name: "update_messages", arguments: {
      ids: ["m1", "m2", "missing", "m1"], isRead: true, flag: "flagged", categories: ["Your call", "Your call", "Receipts"] } }));
    assert.equal(r.updated, 2);
    assert.equal(r.failed, 1);
    assert.match(r.results[2].error, /Not found/);
    const patches = ms.calls.graph.filter((c) => c.method === "PATCH");
    assert.equal(patches.length, 3);
    assert.equal(new URL(patches[0].url).pathname, "/v1.0/me/messages/m1");
    assert.deepEqual(patches[0].body, { isRead: true, flag: { flagStatus: "flagged" }, categories: ["Your call", "Receipts"] });

    await mcp.callTool({ name: "update_messages", arguments: { ids: ["m1"], categories: [] } });
    assert.deepEqual(ms.calls.graph.at(-1).body, { categories: [] }, "only the given changes are sent; [] clears");
    const nothing = await mcp.callTool({ name: "update_messages", arguments: { ids: ["m1"] } });
    assert.equal(nothing.isError, true, "at least one change required");
    await mcp.close();
  });

  it("create_mail_folder creates top-level and nested folders, and returns an existing one instead of failing", async () => {
    const { mcp, ms } = await connected();
    const top = result(await mcp.callTool({ name: "create_mail_folder", arguments: { name: "Scouting Trips" } }));
    assert.deepEqual(top, { created: true, id: fid("new-Scouting Trips"), displayName: "Scouting Trips", parentFolderId: fid("root") });
    assert.equal(new URL(ms.calls.graph.at(-1).url).pathname, "/v1.0/me/mailFolders");

    const nested = result(await mcp.callTool({ name: "create_mail_folder", arguments: { name: "2027", parent: "Projects/Scouting" } }));
    assert.equal(nested.created, true);
    assert.equal(new URL(ms.calls.graph.at(-1).url).pathname, `/v1.0/me/mailFolders/${fid("scouting")}/childFolders`);

    const again = result(await mcp.callTool({ name: "create_mail_folder", arguments: { name: "Scouting", parent: "/Projects" } }));
    assert.deepEqual(again, { created: false, id: fid("scouting"), displayName: "Scouting", parentFolderId: fid("projects") });

    // Every name create accepts can also be referenced (resolution fails only because the fake tree is fixed).
    const odd = await mcp.callTool({ name: "move_message", arguments: { id: "m1", destination: "Tax#2026?\\x" } });
    assert.match(odd.content[0].text, /No folder named "Tax#2026\?\\x"/);
        for (const name of ["a/b", "x\u0007"]) {
      const bad = await mcp.callTool({ name: "create_mail_folder", arguments: { name } });
      assert.equal(bad.isError, true, name);
    }
    await mcp.close();
  });

  it("summarize_senders groups the newest messages by sender across pages, capped at maxMessages", async () => {
    const { mcp, ms } = await connected();
    const full = result(await mcp.callTool({ name: "summarize_senders", arguments: { maxMessages: 2000, top: 2 } }));
    assert.equal(full.scanned, 600);
    assert.equal(full.totalMatching, 600);
    assert.equal(full.complete, true);
    assert.equal(full.distinctSenders, 202);
    assert.deepEqual(full.senders.map((x) => [x.address, x.count]), [["news@example.com", 200], ["shop@example.com", 200]]);
    const shop = full.senders[1];
    assert.equal(shop.unread, 100);
    assert.ok(shop.newest > shop.oldest);
    assert.equal(lastQuery(ms).get("$skiptoken"), "senders500", "followed nextLink across pages");

    const capped = result(await mcp.callTool({ name: "summarize_senders", arguments: { maxMessages: 300, unreadOnly: true } }));
    assert.equal(capped.scanned, 300);
    assert.equal(capped.complete, false);
    const first = new URL(ms.calls.graph.filter((c) => c.url.includes("from%2CreceivedDateTime")).at(-1).url).searchParams;
    assert.equal(first.get("$filter"), "receivedDateTime ge 1900-01-01T00:00:00Z and isRead eq false");
    const lastPagePartial = result(await mcp.callTool({ name: "summarize_senders", arguments: { maxMessages: 550 } }));
    assert.equal(lastPagePartial.complete, false, "cap reached inside the final page: not complete");
    const exact = result(await mcp.callTool({ name: "summarize_senders", arguments: { maxMessages: 600 } }));
    assert.equal(exact.complete, true);
    await mcp.close();
  });

  it("move_messages validates every ID and the destination before touching mail", async () => {
    const { mcp, ms } = await connected();
    const bad = await mcp.callTool({ name: "move_messages", arguments: { ids: ["m1", "../x"], destination: "inbox" } });
    assert.equal(bad.isError, true);
    const tooMany = await mcp.callTool({ name: "move_messages", arguments: { ids: Array.from({ length: 101 }, (_, i) => `m${i}`), destination: "inbox" } });
    assert.equal(tooMany.isError, true);
    const ambiguous = await mcp.callTool({ name: "move_messages", arguments: { ids: ["m1"], destination: "Receipts" } });
    assert.equal(ambiguous.isError, true);
    assert.equal(ms.batches.length, 0, "no batch sent");
    await mcp.close();
  });

  it("rejects unknown fields and oversized pages without calling Graph", async () => {
    const { mcp, ms } = await connected();
    const before = ms.calls.graph.length;
    for (const args of [{ fields: ["body"] }, { fields: ["id),attachments(x"] }, { top: 101 }]) {
      const r = await mcp.callTool({ name: "list_messages", arguments: args });
      assert.equal(r.isError, true, JSON.stringify(args));
    }
    assert.equal(ms.calls.graph.length, before);
    await mcp.close();
  });
});
