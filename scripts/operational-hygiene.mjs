import { readdir, readFile } from "node:fs/promises";
import { resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const publicIds = new Set([
  "9188040d-6c67-4c5b-b112-36a304b66dad", // Microsoft's well-known personal-account tenant
  "e1fe6dd8-ba31-4d61-89e7-88639da4683d",
  "570282fd-fa5c-430d-a7fd-fc8dc98a9dca",
  "024d486e-b451-40bb-833d-3e66d98c5c73",
  "465a38f9-76ea-45b9-9f34-9e8b0d4b0b42",
  "ff74d97f-43af-4b68-9f2a-b77ee6968c5d",
  "7427e0e9-2fba-42fe-b0c0-848c9e6a8182",
  "37f7f235-527c-4136-accd-4a02d197296e",
  "14dad69e-099b-42c9-810b-d002981feec1",
  "64a6cdd6-aab1-4aaf-94b8-3cc8405e90d0",
]);
const fixtureIds = new Set([
  "6f1c3b52-2d0e-4c7a-9b51-0c2f4e8a7d13",
  "00000000-0000-4000-8000-000000000001",
]);
const rootFiles = new Set([
  "README.md", "AGENTS.md", "CLAUDE.md", "runtime-contract.json",
  "package.json", "package-lock.json", "tsconfig.json", "Dockerfile",
  ".dockerignore", ".gitignore", ".gitattributes", ".gitleaks.toml", ".env.example",
]);

export function inspectFile(path, text) {
  path = path.replaceAll("\\", "/");
  const findings = [];
  const add = (category) => { if (!findings.includes(category)) findings.push(category); };
  const permitted = rootFiles.has(path) ||
    /^src\/[^/]+\.ts$/.test(path) ||
    /^test\/[^/]+\.test\.mjs$/.test(path) ||
    /^scripts\/[^/]+\.(?:mjs|py|sh)$/.test(path) ||
    /^\.github\/(?:copilot-instructions\.md|dependabot\.yml|rulesets\/[^/]+\.json|workflows\/(?:ci|security-tool-updates)\.yml)$/.test(path);
  if (!permitted) add("unexpected-file");
  if (/(?:^|\/)\.env(?:$|\.)/.test(path) && path !== ".env.example") add("environment-file");
  if (/(?:^|\/)(?:infra|deployment|__pycache__)(?:\/|$)|\.(?:pem|key|pfx|p12|pyc|exe|dll|zip|tgz|gz|bin|log)$/i.test(path)) add("deployment-or-artifact");
  if (/\/subscriptions\/|\/resourceGroups\/|\/providers\/Microsoft\./i.test(text)) add("azure-resource-path");
  if (/\b[a-z0-9][a-z0-9.-]*\.(?:azurecontainerapps\.io|azurecr\.io|azurewebsites\.net|(?:table|blob|queue|file)\.core\.windows\.net|vault\.azure\.net|database\.windows\.net|servicebus\.windows\.net|azurefd\.net|trafficmanager\.net)\b/i.test(text)) add("azure-resource-endpoint");
  for (const [id] of text.matchAll(/\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b/gi)) {
    const value = id.toLowerCase();
    if (!publicIds.has(value) && !(path.startsWith("test/") && fixtureIds.has(value)) &&
        !(path === "scripts/operational-hygiene.mjs" && fixtureIds.has(value))) add("unreviewed-identifier");
  }
  for (const [, domain] of text.matchAll(/\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})\b/gi)) {
    if (!/^(?:example\.(?:com|org|net)|(?:[a-z0-9-]+\.)*(?:example|test|invalid))$/i.test(domain)) add("non-synthetic-email");
  }
  if (/-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----/.test(text)) add("key-material");
  return findings;
}

export async function scanTree(root) {
  const findings = [];
  async function walk(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const absolute = resolve(directory, entry.name);
      const path = relative(root, absolute).replaceAll("\\", "/");
      if ([".git", "node_modules", "dist", ".security-selftest-work"].includes(path)) continue;
      if (entry.isSymbolicLink()) { findings.push({ path, category: "symbolic-link" }); continue; }
      if (entry.isDirectory()) { await walk(absolute); continue; }
      const data = await readFile(absolute);
      const categories = data.includes(0) ? ["binary-file"] : inspectFile(path, data.toString("utf8"));
      for (const category of categories) findings.push({ path, category });
    }
  }
  await walk(root);
  return findings;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const findings = await scanTree(resolve(process.argv[2] ?? "."));
    for (const { path, category } of findings) console.error(`${path}: ${category}`);
    if (findings.length) process.exitCode = 1;
    else console.log("Operational-information hygiene passed.");
  } catch {
    console.error("Operational-information hygiene failed to read the complete tree.");
    process.exitCode = 2;
  }
}
