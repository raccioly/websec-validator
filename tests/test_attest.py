"""`websec attest` — an evidence inventory, never a compliance determination.

The tests that matter here are the ones that stop this feature drifting into a badge. Compliance is
an attribute of an assessed ENTITY, determined solely by a qualified assessor and evidenced by their
report (PCI SSC FAQ 1258: "no single product can provide PCI DSS compliance"). A tool that renders a
verdict makes exactly the claim the standard forbids — so the absence of a verdict is pinned, not
assumed.

Citation accuracy is also pinned: a misattributed clause is the fastest way for an assessor to
discount the whole artifact, and the obvious citations are wrong.
"""
import os
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import attest, cli


class AttestOutputTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.repo = base / "r"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "a.py").write_text("def f():\n    return 1\n")
        subprocess.run(["git", "init", "-q", "."], cwd=self.repo, check=True)
        # Pin ambient git settings (pattern from test_diffscope.py): a hostile global
        # config with commit.gpgsign=true fails these commits outright, and a global
        # core.hooksPath would redirect hook installs out of the fixture repo.
        for _k, _v in (("user.email", "d@e.com"), ("user.name", "D"),
                       ("commit.gpgsign", "false"), ("core.autocrlf", "false"),
                       ("core.hooksPath", ".git/hooks"),
                       ("core.excludesFile", os.devnull)):
            subprocess.run(["git", "-C", str(self.repo), "config", _k, _v], check=True)
        subprocess.run(["git", "add", "-A"], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=self.repo, check=True)
        self.out = base / "out"
        cli.main(["run", str(self.repo), "--out", str(self.out)])
        self.run_dir = sorted(self.out.glob("runs/2*"))[-1]
        self.result = attest.build(self.run_dir)

    # ---- the anti-badge guardrails ----
    def test_the_word_compliant_never_appears(self):
        blob = json.dumps(self.result) + attest.render_text(self.result) \
            + json.dumps(attest.to_in_toto(self.result))
        self.assertNotIn("compliant", blob.lower().replace("compliance determination", "")
                         .replace("not a compliance", "").replace("provide pci dss compliance", ""))

    def test_no_verdict_score_or_percentage_is_rendered(self):
        import re
        self.assertIsNone(self.result["read_this_first"]["verdict"])
        text = attest.render_text(self.result)
        # Word-boundary matched: "bypassed" legitimately contains "passed", and the whole point of
        # that sentence is to say the gate CAN be bypassed.
        for banned in (r"\bpassed\b", r"\bscore\b", r"\bcertified\b", r"\d+\s*%", "✅"):
            self.assertIsNone(re.search(banned, text),
                              f"attest must not render {banned!r}")

    def test_gaps_are_ordered_before_evidence_in_the_data(self):
        """Leading with coverage invites absence to read as satisfaction."""
        keys = list(self.result["controls"][0].keys())
        self.assertLess(keys.index("not_evidenced"), keys.index("websec_evidence"))

    def test_gaps_are_ordered_before_evidence_in_the_rendering(self):
        text = attest.render_text(self.result)
        block = text.split("── ")[1]
        self.assertLess(block.index("NOT EVIDENCED"), block.index("evidence:"))

    def test_it_says_the_local_gate_is_bypassable(self):
        note = self.result["read_this_first"]["enforcement"]
        self.assertIn("bypassable", note)
        self.assertIn("not exhaustive", note)

    def test_it_says_approver_independence_is_not_evidenced(self):
        self.assertIn("not evidenced", self.result["read_this_first"]["approver_independence"])

    def test_disclaimer_tells_the_reader_to_read_gaps_first(self):
        self.assertIn("Read the gaps first", self.result["disclaimer"])
        self.assertIn("not that the control is satisfied", self.result["disclaimer"])

    def test_rows_with_no_evidence_are_counted_honestly(self):
        self.assertGreater(self.result["totals"]["with_no_websec_evidence"], 0)
        self.assertIn("NO websec evidence", attest.render_text(self.result))

    # ---- citation accuracy ----
    def test_dora_change_management_cites_the_delegated_regulation_not_dora_art_17(self):
        """DORA (2022/2554) Art. 17 is INCIDENT management. Change management is the RTS."""
        rows = [c for c in self.result["controls"] if "DORA" in c["framework"]]
        self.assertTrue(rows)
        for row in rows:
            self.assertIn("2024/1774", row["citation"])
            self.assertNotRegex(row["citation"], r"2022/2554,?\s*Art\.?\s*17")

    def test_pci_6_2_3_is_cited_as_permitting_automation(self):
        row = next(c for c in self.result["controls"] if c["clause"].startswith("6.2.3 "))
        self.assertIn("manual or automated", row["citation"])

    def test_pci_6_2_3_1_is_cited_as_conditional(self):
        row = next(c for c in self.result["controls"] if c["clause"].startswith("6.2.3.1"))
        self.assertIn("If manual code reviews are performed", row["citation"])
        self.assertEqual(row["websec_evidence"], [], "websec must not be offered against 6.2.3.1")

    def test_sox_row_states_there_is_no_article_to_cite(self):
        row = next(c for c in self.result["controls"] if c["framework"] == "SOX ITGC")
        self.assertIn("No SOX article", row["citation"])
        self.assertIn("33-8810", row["citation"])

    def test_pci_6_4_2_is_an_explicit_non_goal(self):
        row = next(c for c in self.result["controls"] if c["clause"].startswith("6.4.2"))
        self.assertEqual(row["websec_evidence"], [])
        self.assertIn("non-goal", " ".join(row["not_evidenced"]))

    # ---- it reports only what the run produced ----
    def test_evidence_is_not_claimed_when_attribution_is_absent(self):
        stripped = json.loads((self.run_dir / "findings-ledger.json").read_text())
        stripped.pop("attribution", None)
        (self.run_dir / "findings-ledger.json").write_text(json.dumps(stripped))
        result = attest.build(self.run_dir)
        blob = json.dumps(result["controls"])
        self.assertIn("recorded no VCS or CI attribution", blob)
        self.assertNotIn("attribution.vcs.commit + tree_clean", blob)

    def test_missing_run_directory_exits_2(self):
        self.assertEqual(cli.main(["attest", "--run", str(self.run_dir / "nope")]), 2)

    def test_a_directory_that_is_not_a_run_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(cli.main(["attest", "--run", td]), 2)

    def test_attest_always_exits_zero_because_it_does_not_judge(self):
        self.assertEqual(cli.main(["attest", "--run", str(self.run_dir), "--format", "json"]), 0)


class InTotoTests(unittest.TestCase):
    def test_statement_shape_is_unsigned_and_says_so(self):
        result = {"disclaimer": "d", "observed": {"analyzed_input_digest": "sha256:" + "a" * 64,
                                                  "verification_context": {"application_id": "app"}},
                  "controls": []}
        stmt = attest.to_in_toto(result)
        self.assertEqual(stmt["_type"], "https://in-toto.io/Statement/v1")
        self.assertEqual(stmt["subject"][0]["digest"]["sha256"], "a" * 64)
        self.assertIn("UNSIGNED BY DESIGN", stmt["predicate"]["signing"])

    def test_no_signature_field_is_emitted(self):
        """A websec-signed statement would attest only that websec ran."""
        stmt = attest.to_in_toto({"observed": {}, "controls": [], "disclaimer": ""})
        for banned in ("signature", "signatures", "payload", "payloadType"):
            self.assertNotIn(banned, stmt, "this is a bare Statement, not a signed DSSE envelope")


if __name__ == "__main__":
    unittest.main()
