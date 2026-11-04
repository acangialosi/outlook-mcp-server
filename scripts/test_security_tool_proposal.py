import json
import shutil
import subprocess
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import security_tool_proposal as proposal


def pins():
    return {
        proposal.PIN_FILES[0]: "env:\n  GITLEAKS_VERSION: 8.0.0\n  GITLEAKS_SHA256: " + "a" * 64 + "\n",
        proposal.PIN_FILES[1]: "SEMGREP_VERSION=1.0.0\n# preserved\n",
    }


class ProposalTests(unittest.TestCase):
    def setUp(self):
        self.before = pins()
        self.after = dict(self.before)
        self.after[proposal.PIN_FILES[0]] = self.before[proposal.PIN_FILES[0]].replace(
            "8.0.0", "8.1.0").replace("a" * 64, "b" * 64)
        self.after[proposal.PIN_FILES[1]] = self.before[proposal.PIN_FILES[1]].replace("1.0.0", "1.1.0")
        self.payload = json.dumps({"base": "a" * 40,
                                  "patch": proposal.validated_patch(self.before, self.after)})

    def test_only_monotonic_pin_edits_are_allowed(self):
        self.assertEqual(proposal.validated_patch(self.before, self.before), "")
        for change in (
                {**self.after, "README.md": "unrelated"},
                {**self.after, proposal.PIN_FILES[0]: self.after[proposal.PIN_FILES[0]] + "permissions: write-all\n"},
                {**self.after, proposal.PIN_FILES[1]: "SEMGREP_VERSION=0.1.0\n# preserved\n"},
                {**self.after, proposal.PIN_FILES[1]: "SEMGREP_VERSION=2.0.0rc1\n# preserved\n"},
                {**self.after, proposal.PIN_FILES[0]: self.before[proposal.PIN_FILES[0]].replace("a" * 64, "b" * 64)},
        ):
            with self.subTest(change=change), self.assertRaises(ValueError):
                proposal.validated_patch(self.before, change)

    def test_patch_size_is_bounded(self):
        with patch.object(proposal, "MAX_PATCH_BYTES", 10), self.assertRaisesRegex(ValueError, "size limit"):
            proposal.validated_patch(self.before, self.after)

    def test_create_once_then_preserve_existing_human_edits(self):
        issues = []
        requests = []

        def api(endpoint, body=None):
            if body is None:
                return issues
            requests.append(body)
            issues.append({"number": 7, "user": {"login": "github-actions[bot]", "type": "Bot"}, **body})
            return issues[-1]

        with patch.object(proposal, "gh_api", side_effect=api):
            self.assertEqual(proposal.publish(self.payload, "example/scanners"), 7)
            issues[0]["body"] += "\nMaintainer discussion must not be overwritten."
            self.assertEqual(proposal.publish(self.payload, "example/scanners"), 7)
        self.assertEqual(len(requests), 1)
        self.assertIn("a" * 40, requests[0]["body"])
        self.assertIn("GITHUB_TOKEN", requests[0]["body"])
        self.assertIn("exact head", requests[0]["body"])
        self.assertIn("Maintainer discussion", issues[0]["body"])

    def test_pagination_deduplicates_renamed_issue_and_ignores_prs(self):
        page1 = [{"title": "other", "body": "", "number": n} for n in range(100)]
        page1[0] = {"title": proposal.TITLE, "number": 1, "pull_request": {}}
        page2 = [{"title": "renamed by maintainer", "body": proposal.MARKER, "number": 123,
                  "user": {"login": "github-actions[bot]", "type": "Bot"}}]
        with patch.object(proposal, "gh_api", side_effect=[page1, page2]) as api:
            self.assertEqual(proposal.publish(self.payload, "example/scanners"), 123)
            self.assertEqual(api.call_count, 2)

    def test_user_created_marker_or_title_cannot_suppress_verified_proposal(self):
        impostor = {"title": proposal.TITLE, "body": proposal.MARKER, "number": 99,
                    "user": {"login": "someone-else", "type": "User"}}
        with patch.object(proposal, "gh_api", side_effect=[[impostor], {"number": 7}]) as api:
            self.assertEqual(proposal.publish(self.payload, "example/scanners"), 7)
            self.assertEqual(api.call_count, 2)
            self.assertIn("a" * 40, api.call_args.args[1]["body"])

    def test_network_failure_and_pagination_limit_fail_without_creating(self):
        with patch.object(proposal, "gh_api", side_effect=subprocess.CalledProcessError(1, ["gh"])):
            with self.assertRaises(subprocess.CalledProcessError):
                proposal.publish(self.payload, "example/scanners")
        full_page = [{"title": "other", "body": "", "number": n} for n in range(100)]
        with patch.object(proposal, "gh_api", return_value=full_page) as api:
            with self.assertRaisesRegex(ValueError, "deduplicate"):
                proposal.publish(self.payload, "example/scanners")
            self.assertEqual(api.call_count, 10)

    def test_invalid_payload_never_calls_github(self):
        for payload in ('{}', '{"base":"main","patch":"x"}'):
            with self.subTest(payload=payload), patch.object(proposal, "gh_api") as api:
                with self.assertRaises(ValueError):
                    proposal.publish(payload, "example/scanners")
                api.assert_not_called()

    def test_prepare_produces_an_actually_applicable_patch_without_network(self):
        root = Path(__file__).resolve().parent.parent / (".scanner-test-" + uuid.uuid4().hex)
        root.mkdir()
        def cleanup():
            for path in root.rglob("*"):
                path.chmod(0o700)
            shutil.rmtree(root)
        self.addCleanup(cleanup)
        run = subprocess.run
        run(["git", "init", "--quiet", str(root)], check=True)
        run(["git", "config", "core.autocrlf", "false"], cwd=root, check=True)
        for name, content in self.before.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        (root / "unrelated.txt").write_text("preserve unrelated files\n", encoding="utf-8")
        run(["git", "add", "."], cwd=root, check=True)
        run(["git", "-c", "user.name=Scanner Test", "-c", "user.email=test@example.invalid",
             "commit", "--quiet", "-m", "Synthetic scanner fixture"], cwd=root, check=True)

        def fake_updater(command, **kwargs):
            if command[-1] == "apply":
                for name, content in self.after.items():
                    (root / name).write_text(content, encoding="utf-8", newline="\n")
                return subprocess.CompletedProcess(command, 0)
            return run(command, **kwargs)

        with patch.object(proposal, "ROOT", root), patch.object(proposal.subprocess, "run", fake_updater):
            data = json.loads(proposal.prepare())
        for name, content in self.before.items():
            (root / name).write_text(content, encoding="utf-8", newline="\n")
        run(["git", "apply", "--check", "-"], cwd=root, input=data["patch"].encode(), check=True)
        run(["git", "apply", "-"], cwd=root, input=data["patch"].encode(), check=True)
        self.assertEqual({name: (root / name).read_text() for name in self.after}, self.after)
        run(["git", "checkout", "--", "."], cwd=root, check=True)

        def unexpected_write(command, **kwargs):
            result = fake_updater(command, **kwargs)
            if command[-1] == "apply":
                (root / "unrelated.txt").write_text("unrelated change\n", encoding="utf-8")
            return result

        with patch.object(proposal, "ROOT", root), patch.object(proposal.subprocess, "run", unexpected_write):
            with self.assertRaisesRegex(ValueError, "allowlist"):
                proposal.prepare()


if __name__ == "__main__":
    unittest.main()
