import { z } from "zod";

/** Microsoft Graph delegated scopes requested from each user's personal account. */
export const GRAPH_SCOPES = [
  "https://graph.microsoft.com/User.Read",
  "https://graph.microsoft.com/Mail.ReadWrite", // move messages, report not-junk
  "https://graph.microsoft.com/Calendars.Read",
  "https://graph.microsoft.com/Contacts.Read",
];

/**
 * Bump when GRAPH_SCOPES changes. Grants consented under an older version are discarded,
 * so MCP clients get a 401 and send the user back through consent for the new scopes.
 */
export const GRANT_VERSION = 2;

/** The scope this server issues to MCP clients. */
export const MCP_SCOPE = "outlook.read";

/** Tenant ID that Entra stamps on every personal Microsoft account (MSA) token. */
export const MSA_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad";

export interface Config {
  port: number;
  /** Public origin, e.g. https://outlook-mcp.example.com (no trailing slash). */
  publicUrl: string;
  /** The MCP endpoint and RFC 8707 resource identifier: `${publicUrl}/mcp`. */
  mcpUrl: string;
  entraClientId: string;
  entraClientSecret: string;
  /** 32-byte AES-256-GCM key that encrypts everything written to storage. */
  encryptionKey: Buffer;
  /** Azure Table endpoint (https://<account>.table.core.windows.net), or undefined for in-memory dev storage. */
  tableEndpoint?: string;
  tableName: string;
  /** If set, only these personal Microsoft accounts (lowercase emails) may connect. */
  allowedUsers?: Set<string>;
}

const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  PUBLIC_URL: z.url().refine((value) => {
    const url = new URL(value);
    return (url.protocol === "https:" || url.hostname === "localhost") && url.pathname === "/" && !url.search && !url.hash;
  }, "PUBLIC_URL must be an https origin (http allowed only for localhost) with no path."),
  ENTRA_CLIENT_ID: z.uuid(),
  ENTRA_CLIENT_SECRET: z.string().min(10),
  TOKEN_ENCRYPTION_KEY: z.base64().refine((value) => Buffer.from(value, "base64").length === 32,
    "TOKEN_ENCRYPTION_KEY must be 32 random bytes, base64-encoded."),
  AZURE_TABLE_ENDPOINT: z.url().optional(),
  AZURE_TABLE_NAME: z.string().regex(/^[A-Za-z][A-Za-z0-9]{2,62}$/).default("outlookmcp"),
  ALLOWED_USERS: z.string().optional(),
});

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const fields = parsed.error.issues.map((issue) => `${issue.path.join(".")}: ${issue.message}`);
    throw new Error(`Invalid configuration:\n  ${fields.join("\n  ")}`);
  }
  const value = parsed.data;
  const publicUrl = new URL(value.PUBLIC_URL).origin;
  return {
    port: value.PORT,
    publicUrl,
    mcpUrl: `${publicUrl}/mcp`,
    entraClientId: value.ENTRA_CLIENT_ID,
    entraClientSecret: value.ENTRA_CLIENT_SECRET,
    encryptionKey: Buffer.from(value.TOKEN_ENCRYPTION_KEY, "base64"),
    ...(value.AZURE_TABLE_ENDPOINT ? { tableEndpoint: value.AZURE_TABLE_ENDPOINT } : {}),
    tableName: value.AZURE_TABLE_NAME,
    ...(value.ALLOWED_USERS?.trim() ? {
      allowedUsers: new Set(value.ALLOWED_USERS.split(",").map((u) => u.trim().toLowerCase()).filter(Boolean)),
    } : {}),
  };
}
