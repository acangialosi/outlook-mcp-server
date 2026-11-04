import contextlib
import hashlib
import io
import json
import shutil
import subprocess
import sys
import unittest
import urllib.error
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import update_security_tools as updater


class Response(io.BytesIO):
    def __init__(self, content, headers=None):
        super().__init__(content)
        self.headers = headers or {}


class ReleaseSelectionTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 6, 1, tzinfo=timezone.utc)
        self.clock = patch.object(updater, "NOW", self.now)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def semgrep(self, releases):
        with patch.object(updater, "http", return_value=Response(json.dumps({"releases": releases}).encode())):
            return updater.latest_semgrep()

    def file(self, age, yanked=False):
        return {"upload_time_iso_8601": (self.now - timedelta(days=age)).isoformat(), "yanked": yanked}

    def test_semgrep_stable_age_yanked_and_empty_filtering(self):
        self.assertEqual(self.semgrep({
            "1.1.0": [self.file(14)], "1.0.9": [self.file(30)],
            "1.2.0": [self.file(13)], "1.3.0": [self.file(30, True)],
            "1.4.0rc1": [self.file(40)], "1.5.0": [],
        }), "1.1.0")
        self.assertIsNone(self.semgrep({"1.0.0": [], "2.0.0": [self.file(1)]}))

    def test_old_yanked_file_does_not_age_a_recent_usable_release(self):
        self.assertEqual(self.semgrep({
            "1.0.0": [self.file(20)],
            "2.0.0": [self.file(30, True), self.file(1)],
        }), "1.0.0")

    def tags(self, *versions):
        return patch.object(updater.subprocess, "run",
                            return_value=subprocess.CompletedProcess([], 0, stdout="\n".join(
                                f"{'a' * 40}\trefs/tags/v{v}" for v in versions)))

    def sums(self, version, archive=b"verified scanner", age=20, filename=None):
        filename = filename or f"gitleaks_{version}_linux_x64.tar.gz"
        content = f"{hashlib.sha256(archive).hexdigest()}  {filename}\n".encode()
        date = self.now - timedelta(days=age)
        return Response(content, {"Last-Modified": date.strftime("%a, %d %b %Y %H:%M:%S GMT")})

    def missing(self, message):
        error = urllib.error.HTTPError("https://github.com", 404, message, {}, io.BytesIO())
        self.addCleanup(error.close)
        return error

    def test_gitleaks_skips_recent_unpublished_and_missing_asset_entries(self):
        absent = self.missing("missing")
        with self.tags("8.5.0-rc1", "8.4.0", "8.3.0", "8.2.0", "8.1.0"), patch.object(
                updater, "http", side_effect=[
                    self.sums("8.4.0", age=1), absent,
                    self.sums("8.2.0", filename="other-archive.tar.gz"),
                    self.sums("8.1.0"), Response(b"verified scanner"),
                ]) as fetch:
            self.assertEqual(updater.latest_gitleaks(),
                             ("8.1.0", hashlib.sha256(b"verified scanner").hexdigest()))
            self.assertEqual(fetch.call_count, 5)

    def test_gitleaks_requires_exact_archive_name_not_a_suffix(self):
        with self.tags("8.1.0"), patch.object(updater, "http", return_value=self.sums(
                "8.1.0", filename="wrong_gitleaks_8.1.0_linux_x64.tar.gz")) as fetch:
            self.assertIsNone(updater.latest_gitleaks())
            self.assertEqual(fetch.call_count, 1)

    def test_checksum_mismatch_or_missing_archive_fails_closed(self):
        for failure in (Response(b"tampered"), self.missing("missing archive")):
            with self.subTest(failure=type(failure).__name__), self.tags("8.1.0"), patch.object(
                    updater, "http", side_effect=[self.sums("8.1.0"), failure]):
                with self.assertRaises((SystemExit, urllib.error.HTTPError)):
                    updater.latest_gitleaks()

    def test_release_network_errors_are_not_treated_as_current(self):
        unavailable = urllib.error.HTTPError("https://github.com", 503, "unavailable", {}, io.BytesIO())
        self.addCleanup(unavailable.close)
        for failure in (urllib.error.URLError("offline"), unavailable):
            with self.subTest(failure=type(failure).__name__), self.tags("8.1.0"), patch.object(
                    updater, "http", side_effect=failure):
                with self.assertRaises(urllib.error.URLError):
                    updater.latest_gitleaks()
        with patch.object(updater, "http", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(urllib.error.URLError):
                updater.latest_semgrep()


class ApplyTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent.parent / (".scanner-test-" + uuid.uuid4().hex)
        self.root.mkdir()
        self.addCleanup(shutil.rmtree, self.root)
        self.ci, self.scan = self.root / "ci.yml", self.root / "scan.sh"
        self.ci.write_text("env:\n  GITLEAKS_VERSION: 8.0.0\n  GITLEAKS_SHA256: " + "a" * 64 + "\n")
        self.scan.write_text("SEMGREP_VERSION=1.0.0\n# preserve this\n")
        self.originals = (self.ci.read_bytes(), self.scan.read_bytes())
        for name, value in (("CI", self.ci), ("SCAN", self.scan)):
            mocked = patch.object(updater, name, value)
            mocked.start()
            self.addCleanup(mocked.stop)

    def run_main(self, mode):
        with patch.object(sys, "argv", ["update_security_tools.py", mode]), contextlib.redirect_stdout(io.StringIO()):
            return updater.main()

    def assert_original(self):
        self.assertEqual((self.ci.read_bytes(), self.scan.read_bytes()), self.originals)

    def test_check_reports_without_writing_then_apply_is_idempotent(self):
        with patch.object(updater, "latest_gitleaks", return_value=("8.1.0", "b" * 64)), patch.object(
                updater, "latest_semgrep", return_value="1.1.0"):
            self.assertEqual(self.run_main("check"), 1)
            self.assert_original()
            self.assertEqual(self.run_main("apply"), 0)
            self.assertIn("GITLEAKS_VERSION: 8.1.0", self.ci.read_text())
            self.assertIn("GITLEAKS_SHA256: " + "b" * 64, self.ci.read_text())
            self.assertEqual(self.scan.read_text(), "SEMGREP_VERSION=1.1.0\n# preserve this\n")
            with patch.object(Path, "write_text", side_effect=AssertionError("idempotent run wrote a file")):
                self.assertEqual(self.run_main("apply"), 0)

    def test_second_source_network_failure_never_partially_updates_first_pin(self):
        with patch.object(updater, "latest_gitleaks", return_value=("8.1.0", "b" * 64)), patch.object(
                updater, "latest_semgrep", side_effect=urllib.error.URLError("offline")):
            with self.assertRaises(urllib.error.URLError):
                self.run_main("apply")
        self.assert_original()

    def test_checksum_failure_never_writes_either_file(self):
        with patch.object(updater, "latest_gitleaks", side_effect=SystemExit("checksum mismatch")):
            with self.assertRaises(SystemExit):
                self.run_main("apply")
        self.assert_original()

    def test_write_failure_rolls_back_both_pin_files(self):
        write = Path.write_text

        def fail_second(path, *args, **kwargs):
            if path == self.scan:
                raise OSError("disk write failed")
            return write(path, *args, **kwargs)

        with patch.object(updater, "latest_gitleaks", return_value=("8.1.0", "b" * 64)), patch.object(
                updater, "latest_semgrep", return_value="1.1.0"), patch.object(Path, "write_text", fail_second):
            with self.assertRaisesRegex(OSError, "disk write failed"):
                self.run_main("apply")
        self.assert_original()

    def test_no_eligible_releases_or_older_versions_do_not_downgrade(self):
        for gitleaks, semgrep in ((None, None), (("7.0.0", "c" * 64), "0.9.0")):
            with self.subTest(gitleaks=gitleaks), patch.object(
                    updater, "latest_gitleaks", return_value=gitleaks), patch.object(
                    updater, "latest_semgrep", return_value=semgrep):
                self.assertEqual(self.run_main("apply"), 0)
                self.assert_original()


if __name__ == "__main__":
    unittest.main()
