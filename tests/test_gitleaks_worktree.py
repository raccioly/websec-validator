"""bug-218: gitleaks ran HISTORY mode only, so uncommitted working-tree secrets were invisible.

Verified before the fix: an uncommitted .env yields 0 hits from `gitleaks detect --source` and 2
from working-tree mode. trivy `fs` was the only working-tree secret path, so a run selecting only
gitleaks reported a clean tree that was not clean — and an uncommitted tree is precisely the state
an AI coding agent leaves behind mid-task.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import scanners


def _hit(file="app/.env", rule="aws-access-token", line=1, secret="AKIAQYLPMN5EXAMPLE1"):
    return {"File": file, "RuleID": rule, "StartLine": line,
            "Secret": secret, "Match": secret, "Description": "AWS access token"}


class GitleaksDualModeRegistryTests(unittest.TestCase):
    def test_both_passes_are_registered_and_runnable(self):
        keys = {s.key: s for s in scanners.REGISTRY}
        self.assertIn("gitleaks", keys)
        self.assertIn("gitleaks-dir", keys, "working-tree pass must be registered")
        self.assertIsNotNone(keys["gitleaks-dir"].argv, "working-tree pass must be runnable")
        self.assertEqual(keys["gitleaks-dir"].binary, keys["gitleaks"].binary,
                         "same binary — must not imply a second install")

    def test_modern_subcommands_are_used_when_available(self):
        with patch.object(scanners, "_gitleaks_has_subcommands", return_value=True):
            hist = scanners._gitleaks(Path("/t"), Path("/o.json"))
            tree = scanners._gitleaks_dir(Path("/t"), Path("/o.json"))
        self.assertEqual(hist[:3], ["gitleaks", "git", "/t"])
        self.assertEqual(tree[:3], ["gitleaks", "dir", "/t"])
        self.assertNotIn("--source", hist, "`git` takes a positional path and rejects --source")

    def test_legacy_gitleaks_falls_back_to_detect(self):
        """Pre-8.19 gitleaks has no git/dir subcommands — must degrade, never stop scanning."""
        with patch.object(scanners, "_gitleaks_has_subcommands", return_value=False):
            hist = scanners._gitleaks(Path("/t"), Path("/o.json"))
            tree = scanners._gitleaks_dir(Path("/t"), Path("/o.json"))
        self.assertEqual(hist[:4], ["gitleaks", "detect", "--source", "/t"])
        self.assertEqual(tree[:4], ["gitleaks", "detect", "--source", "/t"])
        self.assertIn("--no-git", tree, "legacy working-tree mode needs --no-git")
        self.assertNotIn("--no-git", hist)

    def test_subcommand_probe_failure_assumes_legacy_not_skip(self):
        scanners._GITLEAKS_DIR_SUPPORT.clear()
        with patch.object(scanners.subprocess, "run", side_effect=OSError("boom")):
            self.assertFalse(scanners._gitleaks_has_subcommands("gitleaks"))
        scanners._GITLEAKS_DIR_SUPPORT.clear()

    def test_doctor_does_not_list_gitleaks_twice(self):
        got = scanners.detect([])
        names = [e["key"] for e in got["available"] + got["missing"]]
        self.assertNotIn("gitleaks-dir", names,
                         "same binary — a second row would imply a second install")
        self.assertIn("gitleaks", names)


class GitleaksDualModeNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()

    def normalize(self, reports):
        """normalize_findings returns a SUMMARY and writes the findings to outdir/findings.json."""
        runs = []
        outdir = self.repo / "_out"
        outdir.mkdir(exist_ok=True)
        for key, doc in reports:
            out = outdir / f"{key}.json"
            out.write_text(json.dumps(doc))
            runs.append({"key": key, "output": str(out)})
        summary = scanners.normalize_findings(runs, outdir, target=self.repo)
        summary["findings"] = json.loads((outdir / "findings.json").read_text())
        return summary

    def test_working_tree_report_is_parsed_at_all(self):
        """The regression: a gitleaks-dir report must produce findings, not be dropped as unknown."""
        (self.repo / ".env").write_text("x")
        res = self.normalize([("gitleaks-dir", [_hit(file=".env")])])
        self.assertEqual(len(res["findings"]), 1)
        self.assertIn("gitleaks", res["findings"][0]["tools"])
        self.assertEqual(res["findings"][0]["scan_mode"], "dir")

    def test_history_pass_is_tagged_git(self):
        (self.repo / ".env").write_text("x")
        res = self.normalize([("gitleaks", [_hit(file=".env")])])
        self.assertEqual(res["findings"][0]["scan_mode"], "git")

    def test_same_secret_in_both_passes_is_one_finding(self):
        """Dual pass must add RECALL without inflating the count."""
        (self.repo / ".env").write_text("x")
        res = self.normalize([("gitleaks", [_hit(file=".env")]),
                              ("gitleaks-dir", [_hit(file=".env")])])
        self.assertEqual(len(res["findings"]), 1, "identical fingerprints must collapse")
        self.assertEqual(res["findings"][0]["scan_mode"], "git+dir")

    def test_distinct_secrets_across_passes_are_both_kept(self):
        (self.repo / ".env").write_text("x")
        (self.repo / "old.env").write_text("x")
        res = self.normalize([("gitleaks", [_hit(file="old.env", line=3)]),
                              ("gitleaks-dir", [_hit(file=".env", line=1)])])
        self.assertEqual(len(res["findings"]), 2)
        self.assertEqual({f["scan_mode"] for f in res["findings"]}, {"git", "dir"})

    def test_working_tree_hit_is_never_labelled_history_only(self):
        """A dir-mode hit is present in the tree by definition; 'rotate, already deleted' is wrong."""
        res = self.normalize([("gitleaks-dir", [_hit(file="gone.env")])])   # file absent on disk
        self.assertEqual(len(res["findings"]), 1)
        self.assertFalse(res["findings"][0].get("history_only"),
                         "dir-mode finding must not be annotated HISTORY-ONLY")
        self.assertNotIn("HISTORY-ONLY", res["findings"][0]["title"])

    def test_history_only_annotation_still_fires_for_git_mode(self):
        """Guard the behaviour the fix must NOT regress."""
        res = self.normalize([("gitleaks", [_hit(file="deleted.env")])])   # file absent on disk
        self.assertTrue(res["findings"][0].get("history_only"))
        self.assertIn("HISTORY-ONLY", res["findings"][0]["title"])

    def test_skip_dirs_post_filter_still_applies_to_working_tree_mode(self):
        """gitleaks has no skip flag — the post-filter is the only containment guarantee."""
        res = self.normalize([("gitleaks-dir", [_hit(file=".claude/worktrees/c/.env")])])
        self.assertEqual(res["findings"], [])

    def test_malformed_working_tree_report_marks_execution_incomplete(self):
        outdir = self.repo / "_out2"
        outdir.mkdir()
        out = outdir / "gitleaks-dir.json"
        out.write_text('{"not": "a findings list"}')
        res = scanners.normalize_findings([{"key": "gitleaks-dir", "output": str(out)}], outdir,
                                          target=self.repo)
        self.assertIn("gitleaks-dir", res.get("parse_failed", []))


class GitleaksLedgerPropagationTests(unittest.TestCase):
    def test_scan_mode_survives_into_the_ledger_summaries(self):
        """`summaries`/`all` uses a key whitelist; scan_mode must be on it or the ledger loses
        the committed-vs-working-tree distinction that justifies running both passes."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td).resolve()
            outdir = repo / "_o"
            outdir.mkdir()
            (repo / ".env").write_text("x")
            (outdir / "gitleaks-dir.json").write_text(json.dumps([_hit(file=".env")]))
            res = scanners.normalize_findings(
                [{"key": "gitleaks-dir", "output": str(outdir / "gitleaks-dir.json")}],
                outdir, target=repo)
        self.assertEqual(res["all"][0].get("scan_mode"), "dir")


class GitleaksSelectionTests(unittest.TestCase):
    def test_selecting_gitleaks_by_name_runs_both_passes(self):
        """`--scanners gitleaks` must not silently keep the history-only blind spot."""
        seen = []

        def fake_which(binary):
            return f"/usr/bin/{binary}"

        def fake_run(argv, **kw):
            seen.append(argv[1] if len(argv) > 1 else "")
            raise RuntimeError("stop after argv capture")

        with tempfile.TemporaryDirectory() as td:
            with patch.object(scanners.shutil, "which", side_effect=fake_which), \
                 patch.object(scanners.subprocess, "run", side_effect=fake_run), \
                 patch.object(scanners, "_gitleaks_has_subcommands", return_value=True):
                scanners.run_available(Path(td), Path(td), only=["gitleaks"])
        self.assertIn("git", seen, "history pass must run")
        self.assertIn("dir", seen, "working-tree pass must run")

    def test_selecting_another_scanner_does_not_pull_in_gitleaks(self):
        seen = []

        def fake_run(argv, **kw):
            seen.append(argv[0])
            raise RuntimeError("stop")

        with tempfile.TemporaryDirectory() as td:
            with patch.object(scanners.shutil, "which", side_effect=lambda b: f"/usr/bin/{b}"), \
                 patch.object(scanners.subprocess, "run", side_effect=fake_run):
                scanners.run_available(Path(td), Path(td), only=["semgrep"])
        self.assertNotIn("gitleaks", seen)


if __name__ == "__main__":
    unittest.main()
