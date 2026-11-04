#!/usr/bin/env python3
"""Prepare a bounded scanner-pin patch, or publish one immutable review issue.

The weekly workflow prepares without credentials and grants only issues:write to
the publisher. It never pushes code, opens/approves a PR, or merges. An ordinary
human-pushed feature PR must still pass CI and latest-head Copilot review.
"""
from __future__ import annotations

import difflib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PIN_FILES = (".github/workflows/ci.yml", "scripts/security-scan.sh")
MAX_PATCH_BYTES = 24_000
TITLE = "Security scanner pin update proposal"
MARKER = "<!-- security-tool-pin-proposal:v1 -->"


def pin(text: str, pattern: str) -> str:
    matches = re.findall(pattern, text, re.M)
    if len(matches) != 1:
        raise ValueError("expected exactly one scanner pin")
    return matches[0]


def validated_patch(before: dict[str, str], after: dict[str, str]) -> str:
    """Reject anything beyond monotonic versions and their paired checksum."""
    patterns = {
        PIN_FILES[0]: (r"(?<=GITLEAKS_VERSION: )\S+", r"(?<=GITLEAKS_SHA256: )\S+"),
        PIN_FILES[1]: (r"(?<=^SEMGREP_VERSION=)\S+",),
    }
    if set(before) != set(PIN_FILES) or set(after) != set(PIN_FILES):
        raise ValueError("only scanner pin files are allowed")
    for path, rules in patterns.items():
        old = [pin(before[path], rule) for rule in rules]
        new = [pin(after[path], rule) for rule in rules]
        for version in (old[0], new[0]):
            if not re.fullmatch(r"\d+\.\d+\.\d+", version):
                raise ValueError("scanner versions must be stable")
        if tuple(map(int, new[0].split("."))) < tuple(map(int, old[0].split("."))):
            raise ValueError("scanner downgrades are not proposals")
        if len(rules) == 2:
            if not re.fullmatch(r"[0-9a-f]{64}", new[1]):
                raise ValueError("invalid scanner checksum")
            if old[0] == new[0] and old[1] != new[1]:
                raise ValueError("checksum changes require a version update")
        expected = before[path]
        for rule, value in zip(rules, new):
            expected = re.sub(rule, lambda _: value, expected, flags=re.M)
        if expected != after[path]:
            raise ValueError("proposal contains changes outside scanner pins")
    patch = "".join(
        "".join(difflib.unified_diff(before[path].splitlines(keepends=True),
                                    after[path].splitlines(keepends=True),
                                    fromfile=f"a/{path}", tofile=f"b/{path}"))
        for path in PIN_FILES if before[path] != after[path]
    )
    if len(patch.encode("utf-8")) > MAX_PATCH_BYTES:
        raise ValueError("scanner proposal exceeds the patch size limit")
    return patch


def prepare() -> str:
    if subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, check=True,
                      capture_output=True, text=True, timeout=30).stdout.strip():
        raise ValueError("prepare requires a clean tracked checkout")
    before = {path: (ROOT / path).read_text(encoding="utf-8") for path in PIN_FILES}
    subprocess.run([sys.executable, "-I", str(ROOT / "scripts/update_security_tools.py"), "apply"],
                   cwd=ROOT, check=True, timeout=480)
    changed = subprocess.run(["git", "diff", "--name-only", "HEAD"], cwd=ROOT, check=True,
                             capture_output=True, text=True, timeout=30).stdout.splitlines()
    if not set(changed).issubset(PIN_FILES):
        raise ValueError("updater changed files outside the scanner pin allowlist")
    after = {path: (ROOT / path).read_text(encoding="utf-8") for path in PIN_FILES}
    patch = validated_patch(before, after)
    if not patch:
        return ""
    base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise ValueError("expected an exact base commit")
    return json.dumps({"base": base, "patch": patch}, separators=(",", ":"))


def gh_api(endpoint: str, body: dict[str, str] | None = None) -> object:
    command = ["gh", "api", endpoint]
    if body is not None:
        command += ["--method", "POST", "--input", "-"]
    result = subprocess.run(command, input=json.dumps(body) if body is not None else None,
                            check=True, capture_output=True, text=True, timeout=60)
    return json.loads(result.stdout)


def publish(proposal: str, repository: str) -> int:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("expected this workflow's repository")
    data = json.loads(proposal)
    if (set(data) != {"base", "patch"} or not isinstance(data["base"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", data["base"])
            or not isinstance(data["patch"], str) or not data["patch"]
            or len(data["patch"].encode("utf-8")) > MAX_PATCH_BYTES):
        raise ValueError("invalid scanner proposal")
    # Bounded pagination, not eventually consistent search. Workflow concurrency
    # serializes publishers; never overwrite a maintainer's issue body/comments.
    for page in range(1, 11):
        issues = gh_api(f"repos/{repository}/issues?state=open&per_page=100&page={page}")
        for issue in issues:
            if "pull_request" not in issue and (
                    issue["title"] == TITLE or MARKER in (issue.get("body") or "")):
                print(f"Existing proposal #{issue['number']} awaits review; left unchanged.")
                return issue["number"]
        if len(issues) < 100:
            break
    else:
        raise ValueError("too many open issues to deduplicate safely")
    body = f"""{MARKER}
Eligible stable scanner updates (at least 14 days old). Any gitleaks archive update
is verified against its published SHA-256; Semgrep uses non-yanked PyPI files.
**Status: pending human review; no pins have been applied to the repository.**

Base commit: `{data["base"]}`. Only `.github/workflows/ci.yml` and
`scripts/security-scan.sh` scanner pins may change. This immutable proposal is not
a branch, a pull request, a passing test result, or approval.

Save the diff below as `scanner-pins.patch` in a clean checkout of that base, then:

```sh
git switch -c update-security-tools
git apply --check scanner-pins.patch
git apply scanner-pins.patch
```

Inspect the diff and remove the saved patch before committing. Rebase onto the
current default branch if needed and open an ordinary feature PR. Run the updater
tests and all required `test`, `docker`, and `security` checks on its exact head;
obtain latest-head Copilot review and resolve findings before any manual merge.
Close this issue once the pins land (or explain why the proposal is declined).

No automatic push/PR is made: `GITHUB_TOKEN`-generated push/PR events would not
start normal downstream CI. A maintainer's ordinary feature push/PR does. This
avoids additional tokens, Actions PR-creation settings, and automatic approvals.
Issue proposals, rather than automatically generated PRs, are the owner's choice.

````diff
{data["patch"]}````
"""
    created = gh_api(f"repos/{repository}/issues", {"title": TITLE, "body": body})
    print(f"Created scanner proposal #{created['number']}; human PR and CI are still required.")
    return created["number"]


def main() -> None:
    if sys.argv[1:] == ["prepare"]:
        proposal = prepare()
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
            output.write(f"proposal={proposal}\n")
    elif sys.argv[1:] == ["publish"]:
        publish(os.environ["PROPOSAL"], os.environ["GITHUB_REPOSITORY"])
    else:
        raise SystemExit("usage: security_tool_proposal.py prepare|publish")


if __name__ == "__main__":
    main()
