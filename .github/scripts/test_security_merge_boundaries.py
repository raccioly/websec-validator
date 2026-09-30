"""Automatic merge eligibility requires immutable heads and proven file scope."""
import contextlib
import importlib
import io
import os
import unittest
from unittest.mock import patch

import triage


class ClassificationBoundaryTests(unittest.TestCase):
    def test_protected_and_test_rename_origins_cannot_enter_docs_lane(self):
        for origin in ("AGENTS.md", "src/engine.py", ".github/workflows/ci.yml", "tests/test_existing.py"):
            file = {"filename": "docs/archive.md", "previous_filename": origin, "status": "renamed", "additions": 1, "deletions": 1}
            self.assertEqual(triage.verdict("google-labs-jules[bot]", "docs", [file])[0], "hold")
            file["status"] = "modified"
            self.assertEqual(triage.verdict("google-labs-jules[bot]", "docs", [file])[0], "hold")

    def test_balanced_privileged_logic_changes_and_missing_patches_hold(self):
        file = {"filename": ".github/workflows/ci.yml", "status": "modified", "additions": 1, "deletions": 1}
        title = "Bump actions/checkout from 7.0.0 to 7.0.1"
        for patch_text in (None, "@@ -1 +1 @@\n-    run: echo safe\n+    run: echo malicious", "@@ -1 +1 @@\n-    permissions: contents: read\n+    permissions: contents: write"):
            file["patch"] = patch_text
            self.assertEqual(triage.verdict("dependabot[bot]", title, [file])[0], "hold")

    def test_complete_same_action_pin_swap_is_the_legitimate_control(self):
        file = {"filename": ".github/workflows/ci.yml", "status": "modified", "additions": 1, "deletions": 1,
                "patch": "@@ -1 +1 @@\n-    uses: actions/checkout@" + "a" * 40 + "\n+    uses: actions/checkout@" + "b" * 40}
        title = "Bump actions/checkout from 7.0.0 to 7.0.1"
        self.assertEqual(triage.verdict("dependabot[bot]", title, [file])[0], "merge")
        file["additions"] = file["deletions"] = 2
        self.assertEqual(triage.verdict("dependabot[bot]", title, [file])[0], "hold", "incomplete patch must hold")
        file["additions"] = file["deletions"] = 1
        file["patch"] = file["patch"].replace("+    uses: actions/checkout@", "+    uses: other/action@")
        self.assertEqual(triage.verdict("dependabot[bot]", title, [file])[0], "hold")


class ImmutableHeadTests(unittest.TestCase):
    def setUp(self):
        with patch.dict(os.environ, {"REPO": "example/repo", "HEAD_SHA": "a" * 40}):
            self.module = importlib.import_module("auto_merge")
        self.pr = {"number": 1, "user": {"login": "google-labs-jules[bot]"}, "title": "docs: update",
                   "state": "open", "head": {"sha": self.module.HEAD_SHA}, "base": {"sha": "c" * 40}, "mergeable": True}

    def run_merge(self, fresh):
        files = [{"filename": "docs/guide.md", "status": "modified", "additions": 1, "deletions": 1}]
        with patch.object(self.module.gh, "get", side_effect=[[self.pr], {"files": files}, fresh]) as get, patch.object(self.module.gh, "paged", side_effect=AssertionError("PR files must not come from mutable pagination")), patch.object(self.module, "check_state", return_value=(True, "green")), patch.object(self.module.gh, "request", return_value=(200, {})) as request, contextlib.redirect_stdout(io.StringIO()):
            self.module.main()
        self.assertIn(self.module.HEAD_SHA, get.call_args_list[1].args[0])
        return request

    def test_head_movement_rejects_merge_even_with_green_old_checks(self):
        fresh = dict(self.pr, head={"sha": "b" * 40})
        request = self.run_merge(fresh)
        self.assertFalse(any(call.args[0] == "PUT" for call in request.call_args_list))

    def test_successful_merge_is_atomically_bound_to_checked_sha(self):
        request = self.run_merge(self.pr)
        merges = [call for call in request.call_args_list if call.args[0] == "PUT"]
        self.assertEqual(len(merges), 1)
        self.assertEqual(merges[0].args[2]["sha"], self.module.HEAD_SHA)


if __name__ == "__main__":
    unittest.main()
