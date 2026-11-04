# Public implementation workflow

Follow [AGENTS.md](../AGENTS.md). Work on a feature branch, keep each change focused, and describe
acceptance criteria, validation and deployment impact in the pull request. Never change visibility
without explicit owner approval. Do not commit or push when an approval gate or stopping point applies.
This application repository is already public with owner approval, not a private publication candidate.

## Application and security acceptance

- `npm test` builds TypeScript and runs fake-Entra/Graph end-to-end, runtime-contract and hygiene tests.
  A fresh checkout needs `npm ci` first, but no `.env`, live tenant, mailbox or credentials for tests.
  Tests must model real Graph URL shapes; never weaken assertions to pass a change.
- CI requires `test`, `docker`, and `security`. Security includes npm audit (moderate or higher),
  gitleaks across all refs/history/commit messages, Semgrep, and planted-problem self-tests.
- Gitleaks exceptions belong only in `.gitleaks.toml`: exact reviewed public values, never broad patterns.
- Every changed mail write also updates server instructions in `src/tools.ts`, consent text in
  `src/oauth.ts`, the README tool table and consent-page tests.
- Graph URLs use the fixed Graph base and validated, encoded identifiers. Paging must stay in the
  original collection. Do not relax authentication, authorization, scope or write safeguards.
- Keep secrets, non-synthetic personal email, operational endpoints/IDs, deployment files and artifacts
  out of source, documentation and history. Hygiene is an additional heuristic, not publication approval.

## Deployment-impact assessment

`runtime-contract.json` is the versioned handoff. Assess changes to ports, routes, environment,
storage/encryption, Graph scopes, grants and container behavior in every PR. Graph scope changes require
a grant-version bump and compatible contract/test updates so users re-consent. Breaking contract changes
require explicit coordination, not silent edits to schema version 1 compatibility.

The deployment operator coordinates changes in a separately managed configuration repository.
This repository must not identify that repository or hold deployment credentials/production authority.
Application CI only tests/builds; merging application code does not itself deploy it.

Before delivery, resolve review findings against the latest candidate and obtain the required security
clearance. Document missing tools or network restrictions rather than claiming checks passed.
