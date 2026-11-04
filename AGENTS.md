# Application boundary

- This repository contains application source, tests, runtime contract and generic security automation.
- The application repository is public with owner approval. Keep all contributions suitable for public
  source; changes to visibility still require explicit owner approval.
- Deployment is private, separately managed configuration. A deployment operator coordinates changes
  there; never add infrastructure, production identities, endpoints, secrets or operational records here.
- Use a feature branch. Respect explicit commit/push/merge stopping points and security review gates.
- Preserve behavior, Graph grants and consent safeguards unless a change is explicitly requested.
- From a fresh checkout, run `npm ci` then `npm test`; synthetic tests need no `.env`, tenant, mailbox
  or credentials. Run the security gates; report actual results and blockers, never assumed passes.
- For scanner maintenance, also run the credential-free Python stdlib tests documented in README.
- See [.github/copilot-instructions.md](.github/copilot-instructions.md) for implementation acceptance.
