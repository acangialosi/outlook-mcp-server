import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { Sealer } from "./crypto.js";
import { OAuthServer } from "./oauth.js";
import { MemoryStore, TableStore } from "./store.js";
import { EntraClient } from "./upstream.js";

const config = loadConfig();
const sealer = new Sealer(config.encryptionKey);
const store = config.tableEndpoint ?
  TableStore.create(sealer, config.tableEndpoint, config.tableName) :
  new MemoryStore(sealer);
if (!config.tableEndpoint) console.warn("AZURE_TABLE_ENDPOINT not set: using in-memory storage (sign-ins are lost on restart).");

const entra = new EntraClient(config.entraClientId, config.entraClientSecret, `${config.publicUrl}/oauth/callback`);
const app = createApp(config, new OAuthServer(config, store, entra));

const server = serve({
  fetch: (request, bindings) => app(request, bindings.incoming.socket.remoteAddress),
  port: config.port,
}, ({ port }) => {
  console.log(`Outlook MCP server listening on :${port} — endpoint ${config.mcpUrl}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
