#!/usr/bin/env bash
# The security gates CI runs, in one place, so the self-test exercises exactly the same commands.
#   security-scan.sh deps    <dir>   npm audit of <dir>'s lockfile (fails on moderate or worse)
#   security-scan.sh secrets <repo>  gitleaks over every ref's history and every commit message
#   security-scan.sh sast    <dir>   Semgrep (ERROR/WARNING findings fail)
#   security-scan.sh hygiene <dir>   operational-information checks of the working tree
#   security-scan.sh selftest        plants one problem per gate in throwaway fixtures; every gate must fail
# Needs: GITLEAKS (path to the pinned gitleaks binary) for secrets; pipx for sast.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SEMGREP_VERSION=1.181.0

deps() { (cd "$1" && npm audit --audit-level=moderate); }
hygiene() { node "$ROOT/scripts/operational-hygiene.mjs" "$1"; }

secrets() {
  local repo="$1"
  # A shallow clone would silently skip history, so refuse it.
  if [ "$(git -C "$repo" rev-parse --is-shallow-repository)" != "false" ]; then
    echo "::error::Shallow history cannot be scanned completely; check out with fetch-depth: 0."; return 1
  fi
  # Include each merge's diff against its parents, not only ordinary commits on every ref.
  # Inline gitleaks:allow comments are ignored:
  # the only exceptions are the reviewed ones in .gitleaks.toml.
  local scan=("${GITLEAKS:?set GITLEAKS to the gitleaks binary}" --config "$ROOT/.gitleaks.toml" --ignore-gitleaks-allow
    --redact --verbose --no-banner --exit-code 1)
  "${scan[0]}" git "${scan[@]:1}" --log-opts="--all --diff-merges=separate" "$repo" &&
    git -C "$repo" log --all --format=%B | "${scan[0]}" stdin "${scan[@]:1}" ||
    { echo "::error::Secret detected (redacted above). Remove it from history and rotate the real credential."; return 1; }
}

sast() {
  # mcp-ssrf-typescript is excluded because every Graph request is built on a fixed
  # https://graph.microsoft.com base in src/graph.ts (IDs are validated and URL-encoded,
  # nextLink must match the tool's own collection, redirects are refused).
  (cd "$1" && pipx run "semgrep==$SEMGREP_VERSION" scan --metrics=off --error \
    --severity ERROR --severity WARNING \
    --config p/typescript --config p/javascript --config p/nodejs --config p/secrets \
    --config p/dockerfile --config p/github-actions --config p/security-audit \
    --exclude-rule typescript.mcp.security.mcp-ssrf-typescript \
    .)
}

# Run a gate that must FAIL on a planted problem, for the right reason: exit status 1 (every gate's
# "findings" status; tool or network errors exit otherwise) AND the expected finding in the output.
must_fail() {
  local what="$1" expect="$2" status=0; shift 2
  "$@" >"$WORK/out.log" 2>&1 || status=$?
  if [ "$status" -eq 0 ]; then
    echo "::error::Self-test failed: the gate passed on a planted problem ($what). Output:"; cat "$WORK/out.log"; return 1
  fi
  if [ "$status" -ne 1 ]; then
    echo "::error::Self-test failed: the gate errored (exit $status) on $what instead of reporting it. Output:"
    cat "$WORK/out.log"; return 1
  fi
  if ! grep -Eq "$expect" "$WORK/out.log"; then
    echo "::error::Self-test failed: the gate failed on $what, but not with the expected finding /$expect/. Output:"
    cat "$WORK/out.log"; return 1
  fi
  echo "ok: gate caught $what"
}

fixture_repo() { # fixture_repo <dir>: an empty git repo with a clean first commit on main
  git init -q -b main "$1" && git -C "$1" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
}

selftest() {
  WORK="$ROOT/.security-selftest-work"
  # Never reuse or remove a pre-existing directory; fixtures stay inside this checkout.
  mkdir "$WORK"; trap 'rm -rf "$WORK"' RETURN
  # Fake credentials are assembled at run time, so none appears literally in this repository.
  local aws="AKIA$(printf 'Z7QW3RTY%s' UIOPASDF)" pat="ghp_$(printf '1a2B3c4D5e6F7g8H9i0J%s' 1k2L3m4N5o6P7q8R)"
  local g=(-c user.name=t -c user.email=t@t)

  fixture_repo "$WORK/branch"   # secret only on a non-default branch: proves every ref is scanned
  git -C "$WORK/branch" checkout -q -b feature
  echo "aws_key = \"$aws\"" >"$WORK/branch/config.ini"
  git -C "$WORK/branch" add . && git -C "$WORK/branch" "${g[@]}" commit -q -m "add config"
  git -C "$WORK/branch" checkout -q main
  must_fail "a secret on a non-default branch" "aws-access-token" secrets "$WORK/branch"

  fixture_repo "$WORK/merge"
  git -C "$WORK/merge" checkout -q -b side
  git -C "$WORK/merge" "${g[@]}" commit -q --allow-empty -m side
  git -C "$WORK/merge" checkout -q main
  git -C "$WORK/merge" "${g[@]}" commit -q --allow-empty -m main
  git -C "$WORK/merge" "${g[@]}" merge -q --no-ff --no-commit side
  printf 'aws_key = "%s"\n' "$aws" >"$WORK/merge/config.ini"
  git -C "$WORK/merge" add config.ini
  git -C "$WORK/merge" "${g[@]}" commit -q -m merge
  git -C "$WORK/merge" rm -q config.ini
  git -C "$WORK/merge" "${g[@]}" commit -q -m cleanup
  must_fail "a historical merge-only secret" "aws-access-token" secrets "$WORK/merge"

  fixture_repo "$WORK/message"  # secret only in a commit message
  git -C "$WORK/message" "${g[@]}" commit -q --allow-empty -m "rotate token" -m "new token: $pat"
  must_fail "a secret in a commit message" "github-pat" secrets "$WORK/message"

  fixture_repo "$WORK/inline"   # secret behind an inline allow comment
  echo "\$key = \"$aws\" # gitleaks:allow" >"$WORK/inline/deploy.ps1"
  git -C "$WORK/inline" add . && git -C "$WORK/inline" "${g[@]}" commit -q -m "add script"
  must_fail "a secret behind an inline gitleaks:allow" "aws-access-token" secrets "$WORK/inline"

  fixture_repo "$WORK/allowlist" # past bypasses of the .gitleaks.toml exception: a secret on a line
  # containing "false", and a UUID-valued token under a Graph-permission-like name
  printf 'enabled = false; $t = "%s"\n' "$pat" >"$WORK/allowlist/settings.ps1"
  git -C "$WORK/allowlist" add . && git -C "$WORK/allowlist" "${g[@]}" commit -q -m "add settings"
  must_fail "a secret on a line containing false" "github-pat" secrets "$WORK/allowlist"
  fixture_repo "$WORK/uuid"
  printf '"Mail.Token" = "%s"\n' "9b2c4e1a-7f3d-4c8b-$(printf 'a1e5-6d2f8b9c0e7a')" >"$WORK/uuid/deploy.ps1"
  git -C "$WORK/uuid" add . && git -C "$WORK/uuid" "${g[@]}" commit -q -m "add token"
  must_fail "a UUID-valued token under a permission-like name" "generic-api-key" secrets "$WORK/uuid"

  git clone -q --depth 1 "file://$ROOT" "$WORK/shallow" 2>/dev/null
  must_fail "a shallow clone" "Shallow history" secrets "$WORK/shallow"

  mkdir "$WORK/deps"            # lodash 4.17.20 has published high-severity advisories
  cat >"$WORK/deps/package.json" <<'JSON'
{ "name": "fixture", "version": "1.0.0", "dependencies": { "lodash": "4.17.20" } }
JSON
  cat >"$WORK/deps/package-lock.json" <<'JSON'
{ "name": "fixture", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": {
  "": { "name": "fixture", "version": "1.0.0", "dependencies": { "lodash": "4.17.20" } },
  "node_modules/lodash": { "version": "4.17.20", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" } } }
JSON
  must_fail "a known-vulnerable package" "lodash.*(high|critical)|(high|critical).*lodash|Severity: (high|critical)" deps "$WORK/deps"

  # Separate fixtures, so losing either rule set is noticed even while the other still fires.
  mkdir "$WORK/sast-docker"     # a container that runs as root
  printf 'FROM node:24-alpine\nCMD ["node", "index.js"]\n' >"$WORK/sast-docker/Dockerfile"
  must_fail "a container running as root" "missing-user" sast "$WORK/sast-docker"
  mkdir "$WORK/sast-js"         # shell command injection
  printf 'const { exec } = require("child_process");\nmodule.exports = (req) => exec("ls " + req.query.dir);\n' >"$WORK/sast-js/index.js"
  must_fail "shell command injection" "detect-child-process|child-process" sast "$WORK/sast-js"
}

case "${1:-}" in
  deps|secrets|sast|hygiene) "$1" "${2:-.}" ;;
  selftest) selftest ;;
  *) echo "usage: $0 deps|secrets|sast|hygiene <dir> | selftest" >&2; exit 2 ;;
esac
