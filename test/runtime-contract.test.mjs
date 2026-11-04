import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { describe, it } from "node:test";
import { randomBytes } from "node:crypto";
import { z } from "zod";
import { GRAPH_SCOPES, GRANT_VERSION, loadConfig } from "../dist/config.js";
import { createApp } from "../dist/app.js";

const contract = JSON.parse(await readFile(new URL("../runtime-contract.json", import.meta.url), "utf8"));
const schema = z.strictObject({
  schemaVersion: z.literal(1),
  runtime: z.strictObject({ port: z.literal(8080), healthPath: z.literal("/healthz"), mcpPath: z.literal("/mcp") }),
  environment: z.strictObject({ required: z.array(z.string()).min(1), optional: z.array(z.string()) }),
  graph: z.strictObject({ scopes: z.array(z.url()).min(1), grantVersion: z.literal(2) }),
});
const required = {
  PUBLIC_URL: "https://server.example",
  ENTRA_CLIENT_ID: "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13",
  ENTRA_CLIENT_SECRET: "synthetic-test-secret",
  TOKEN_ENCRYPTION_KEY: randomBytes(32).toString("base64"),
};

describe("runtime compatibility contract", () => {
  it("validates the versioned schema and rejects incompatible changes", () => {
    schema.parse(contract);
    for (const changed of [
      { ...contract, schemaVersion: 2 },
      { ...contract, runtime: { ...contract.runtime, port: 8787 } },
      { ...contract, runtime: { ...contract.runtime, healthPath: "/ready" } },
      { ...contract, runtime: { ...contract.runtime, mcpPath: "/other" } },
      { ...contract, graph: { ...contract.graph, grantVersion: 1 } },
      { ...contract, unknown: true },
    ]) assert.equal(schema.safeParse(changed).success, false);
  });
  it("matches Graph scopes and grant version without upstream-only scopes", () => {
    assert.deepEqual(contract.graph.scopes, GRAPH_SCOPES);
    assert.equal(contract.graph.grantVersion, GRANT_VERSION);
    assert.equal(new Set(contract.graph.scopes).size, contract.graph.scopes.length);
  });
  it("distinguishes genuinely required configuration from defaults and optional settings", async () => {
    assert.deepEqual([...contract.environment.required].sort(), Object.keys(required).sort());
    const all = [...contract.environment.required, ...contract.environment.optional];
    assert.equal(new Set(all).size, all.length);
    const source = await readFile(new URL("../src/config.ts", import.meta.url), "utf8");
    const schemaSource = source.slice(source.indexOf("const schema ="), source.indexOf("export function loadConfig"));
    assert.deepEqual(all.sort(), [...schemaSource.matchAll(/^  ([A-Z_]+):/gm)].map((m) => m[1]).sort());
    const defaults = loadConfig(required);
    assert.equal(defaults.port, 8787);
    assert.equal(defaults.tableEndpoint, undefined);
    assert.equal(defaults.trustProxy, false);
    for (const name of contract.environment.required) {
      const missing = { ...required };
      delete missing[name];
      assert.throws(() => loadConfig(missing), new RegExp(name));
    }
    const configured = loadConfig({ ...required, PORT: String(contract.runtime.port),
      AZURE_TABLE_ENDPOINT: "https://storage.example", AZURE_TABLE_NAME: "testtable",
      ALLOWED_USERS: "USER@example.com", TRUST_PROXY: "true" });
    assert.equal(configured.port, contract.runtime.port);
    assert.equal(configured.tableEndpoint, "https://storage.example");
    assert.equal(configured.tableName, "testtable");
    assert.equal(configured.trustProxy, true);
    assert.equal(loadConfig({ ...required, TRUST_PROXY: "false" }).trustProxy, false);
    assert.throws(() => loadConfig({ ...required, TRUST_PROXY: "yes" }), /TRUST_PROXY/);
    assert.deepEqual([...configured.allowedUsers], ["user@example.com"]);
    for (const PORT of ["0", "65536", "not-a-port"]) assert.throws(() => loadConfig({ ...required, PORT }), /PORT/);
    const dockerfile = await readFile(new URL("../Dockerfile", import.meta.url), "utf8");
    assert.match(dockerfile, new RegExp(`PORT=${contract.runtime.port}\\b`));
    assert.match(dockerfile, new RegExp(`EXPOSE ${contract.runtime.port}\\b`));
  });
  it("serves the advertised health route and MCP authentication challenge", async () => {
    const config = loadConfig({ ...required, PORT: String(contract.runtime.port) });
    const app = createApp(config, { metadata: {}, verifyAccessToken: async () => { throw new Error("No token expected"); } });
    const health = await app(new Request(config.publicUrl + contract.runtime.healthPath));
    assert.equal(health.status, 200);
    assert.equal(await health.text(), "ok");
    assert.equal(config.mcpUrl, config.publicUrl + contract.runtime.mcpPath);
    const challenge = await app(new Request(config.mcpUrl));
    assert.equal(challenge.status, 401);
    assert.match(challenge.headers.get("www-authenticate"), /resource_metadata=/);
  });
});
