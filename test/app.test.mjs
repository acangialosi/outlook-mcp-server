import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { describe, it } from "node:test";
import { serve } from "@hono/node-server";
import { createApp } from "../dist/app.js";
import { loadConfig } from "../dist/config.js";

function application(trustProxy = false) {
  const config = loadConfig({
    PUBLIC_URL: "https://server.example",
    ENTRA_CLIENT_ID: "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13",
    ENTRA_CLIENT_SECRET: "synthetic-test-secret",
    TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
    TRUST_PROXY: String(trustProxy),
  });
  return createApp(config, {
    metadata: {},
    register: async () => new Response(null, { status: 201 }),
    verifyAccessToken: async () => { throw new Error("No token expected"); },
  });
}

function registration(forwarded) {
  return new Request("https://server.example/register", {
    method: "POST",
    headers: forwarded ? { "X-Forwarded-For": forwarded } : {},
  });
}

describe("OAuth rate-limit connection identity", () => {
  it("ignores forged forwarding headers by default and separates socket peers", async () => {
    const app = application();
    for (let i = 0; i < 30; i++) {
      assert.equal((await app(registration(`192.0.2.${i + 1}`), "198.51.100.1")).status, 201);
    }
    assert.equal((await app(registration("203.0.113.1"), "198.51.100.1")).status, 429);
    assert.equal((await app(registration("203.0.113.1"), "198.51.100.2")).status, 201);
  });

  it("uses only the final valid address from an explicitly trusted proxy", async () => {
    const app = application(true);
    for (let i = 0; i < 30; i++) {
      assert.equal((await app(registration(`192.0.2.${i + 1}, 2001:db8::1`), "198.51.100.1")).status, 201);
    }
    assert.equal((await app(registration("203.0.113.1, 2001:db8::1"), "198.51.100.1")).status, 429);
    assert.equal((await app(registration("203.0.113.1, 2001:db8::2"), "198.51.100.1")).status, 201);
  });

  it("falls back to the socket peer for missing or invalid forwarded addresses", async () => {
    const app = application(true);
    for (let i = 0; i < 30; i++) {
      assert.equal((await app(registration(`192.0.2.1, invalid-${i}`), "198.51.100.1")).status, 201);
    }
    assert.equal((await app(registration(), "198.51.100.1")).status, 429);
    assert.equal((await app(registration("192.0.2.1, invalid-final"), "198.51.100.1")).status, 429);
  });

  it("receives the actual connection address through the Node adapter", async () => {
    const app = application();
    const server = serve({
      fetch: (request, bindings) => app(request, bindings.incoming.socket.remoteAddress),
      port: 0,
      hostname: "127.0.0.1",
    });
    try {
      if (!server.listening) await once(server, "listening");
      const { port } = server.address();
      for (let i = 0; i < 31; i++) {
        const response = await fetch(`http://127.0.0.1:${port}/register`, {
          method: "POST", headers: { "X-Forwarded-For": `192.0.2.${i + 1}` },
        });
        assert.equal(response.status, i < 30 ? 201 : 429);
        await response.arrayBuffer();
      }
    } finally {
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    }
  });
});
