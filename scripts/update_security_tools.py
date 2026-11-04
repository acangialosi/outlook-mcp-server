#!/usr/bin/env python3
"""Keeps the pinned security scanners (gitleaks, Semgrep) current. Dependabot doesn't cover them.

    update_security_tools.py check   exit 1 and list updates if a pin is behind the newest eligible release
    update_security_tools.py apply   rewrite the pins (and gitleaks' SHA-256) in place; prints what changed

Eligible = a stable release (no pre-release suffix) published at least MIN_AGE_DAYS ago, so a compromised or
broken release has time to be caught upstream before it lands here. A gitleaks update is applied only after
the downloaded archive matches the checksum published with the release; that verified hash becomes the pin.
Stdlib only, so it runs anywhere Python 3.10+ does.
"""
from __future__ import annotations

import email.utils
import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CI = ROOT / ".github/workflows/ci.yml"
SCAN = ROOT / "scripts/security-scan.sh"
MIN_AGE_DAYS = 14
STABLE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
NOW = datetime.now(timezone.utc)


def version_key(v: str) -> tuple[int, int, int]:
    m = STABLE.match(v)
    assert m, v
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


ALLOWED_HOSTS = {"github.com", "pypi.org"}  # release redirects to GitHub's download CDN are followed by urllib


def http(url: str, method: str = "GET") -> urllib.request.addinfourl:
    # Only https URLs on the two release sources this script reads; never file:// or anything caller-chosen.
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError(f"refusing to fetch {url!r}")
    request = urllib.request.Request(url, method=method, headers={"User-Agent": "outlook-remote-mcp-tool-updates"})
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected -- scheme and host checked above
    return urllib.request.urlopen(request, timeout=60)  # noqa: S310


def gitleaks_asset(version: str, name: str) -> str:
    return f"https://github.com/gitleaks/gitleaks/releases/download/v{version}/{name}"


def latest_gitleaks() -> tuple[str, str] | None:
    """Newest eligible gitleaks release and its verified linux_x64 archive SHA-256."""
    tags = subprocess.run(["git", "ls-remote", "--tags", "--refs", "https://github.com/gitleaks/gitleaks"],
                          check=True, capture_output=True, text=True).stdout.split()
    versions = sorted({t.rsplit("/", 1)[-1].lstrip("v") for t in tags if STABLE.match(t.rsplit("/", 1)[-1])},
                      key=version_key, reverse=True)
    for version in versions[:15]:
        sums_url = gitleaks_asset(version, f"gitleaks_{version}_checksums.txt")
        try:
            with http(sums_url) as response:
                published = email.utils.parsedate_to_datetime(response.headers["Last-Modified"])
                sums = response.read().decode()
        except urllib.error.HTTPError as error:
            if error.code == 404:  # a tag without a published release (yet); any other failure must surface
                continue
            raise
        if NOW - published < timedelta(days=MIN_AGE_DAYS):
            continue
        archive = f"gitleaks_{version}_linux_x64.tar.gz"
        expected = next((line.split()[0] for line in sums.splitlines() if line.strip().endswith(archive)), None)
        if not expected:
            continue
        with http(gitleaks_asset(version, archive)) as response:
            actual = hashlib.sha256(response.read()).hexdigest()
        if actual != expected:
            raise SystemExit(f"gitleaks {version}: archive SHA-256 {actual} does not match published {expected}")
        return version, actual
    return None


def latest_semgrep() -> str | None:
    with http("https://pypi.org/pypi/semgrep/json") as response:
        releases = json.load(response)["releases"]
    eligible = []
    for version, files in releases.items():
        if not STABLE.match(version) or not files or all(f.get("yanked") for f in files):
            continue
        uploaded = min(datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00")) for f in files)
        if NOW - uploaded >= timedelta(days=MIN_AGE_DAYS):
            eligible.append(version)
    return max(eligible, key=version_key) if eligible else None


def pinned() -> dict[str, str]:
    ci, scan = CI.read_text(), SCAN.read_text()
    return {
        "gitleaks": re.search(r"GITLEAKS_VERSION: (\S+)", ci).group(1),  # type: ignore[union-attr]
        "gitleaks_sha256": re.search(r"GITLEAKS_SHA256: (\S+)", ci).group(1),  # type: ignore[union-attr]
        "semgrep": re.search(r"^SEMGREP_VERSION=(\S+)", scan, re.M).group(1),  # type: ignore[union-attr]
    }


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("check", "apply"):
        print(__doc__)
        return 2
    current = pinned()
    updates: list[str] = []
    gitleaks = latest_gitleaks()
    if gitleaks and version_key(gitleaks[0]) > version_key(current["gitleaks"]):
        updates.append(f"gitleaks {current['gitleaks']} -> {gitleaks[0]} (sha256 {gitleaks[1]}, verified)")
        if mode == "apply":
            ci = CI.read_text()
            ci = ci.replace(f"GITLEAKS_VERSION: {current['gitleaks']}", f"GITLEAKS_VERSION: {gitleaks[0]}")
            ci = ci.replace(f"GITLEAKS_SHA256: {current['gitleaks_sha256']}", f"GITLEAKS_SHA256: {gitleaks[1]}")
            CI.write_text(ci)
    semgrep = latest_semgrep()
    if semgrep and version_key(semgrep) > version_key(current["semgrep"]):
        updates.append(f"semgrep {current['semgrep']} -> {semgrep}")
        if mode == "apply":
            SCAN.write_text(SCAN.read_text().replace(f"SEMGREP_VERSION={current['semgrep']}", f"SEMGREP_VERSION={semgrep}"))
    print("\n".join(updates) if updates else
          f"Security tools are current (gitleaks {current['gitleaks']}, semgrep {current['semgrep']}; "
          f"releases must be {MIN_AGE_DAYS}+ days old).")
    return 1 if updates and mode == "check" else 0


if __name__ == "__main__":
    sys.exit(main())
