# Application boundary

- This repository contains application source, tests, runtime contract and generic security automation.
- Deployment is private, separately managed configuration. A deployment operator coordinates changes
  there; never add infrastructure, production identities, endpoints, secrets or operational records here.
- Repository visibility must remain PRIVATE until the owner explicitly approves publication.
- Use a feature branch. Respect explicit commit/push/merge stopping points and security review gates.
- Preserve behavior, Graph grants and consent safeguards unless a change is explicitly requested.
- Run `npm test` and the security gates; report actual results and blockers, never assumed passes.
- See [.github/copilot-instructions.md](.github/copilot-instructions.md) for implementation acceptance.
