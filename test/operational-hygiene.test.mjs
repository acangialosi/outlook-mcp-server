import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { inspectFile, scanTree } from "../scripts/operational-hygiene.mjs";

describe("operational-information hygiene", () => {
  it("rejects operational identifiers, paths, endpoints and personal addresses", () => {
    const cases = [
      ["tenant = " + ["12345678", "1234", "4321", "8123", "123456789abc"].join("-"), "unreviewed-identifier"],
      ["/" + "subscriptions/" + "sample", "azure-resource-path"],
      ["/" + "resourceGroups/" + "sample", "azure-resource-path"],
      ["https://service." + "azurecontainerapps.io", "azure-resource-endpoint"],
      ["https://account.table." + "core.windows.net", "azure-resource-endpoint"],
      ["https://registry." + "azurecr.io", "azure-resource-endpoint"],
      ["person@" + "outlook.com", "non-synthetic-email"],
      ["-----BEGIN " + "PRIVATE KEY-----", "key-material"],
    ];
    for (const [text, category] of cases) assert.ok(inspectFile("README.md", text).includes(category), category);
  });
  it("rejects private deployment files, credentials and unexpected artifacts", () => {
    for (const path of [".env", ".env.production", "infra/main.bicep", ".github/workflows/deploy.yml",
      "key.pem", "scripts/__pycache__/tool.pyc", "notes.txt", "archive.zip"]) {
      assert.ok(inspectFile(path, "").length, path);
    }
    assert.deepEqual(inspectFile(".env.example", "ENTRA_CLIENT_ID="), []);
  });
  it("permits documented public constants and reserved-domain synthetic examples only", () => {
    assert.deepEqual(inspectFile("src/config.ts", "9188040d-6c67-4c5b-b112-36a304b66dad"), []);
    assert.deepEqual(inspectFile("test/e2e.test.mjs", "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13"), []);
    assert.ok(inspectFile("README.md", "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13").length);
    assert.deepEqual(inspectFile("README.md", "alice@example.com user@local.test https://graph.microsoft.com"), []);
  });
  it("passes the complete application working tree", async () => {
    assert.deepEqual(await scanTree(fileURLToPath(new URL("..", import.meta.url))), []);
  });
});
