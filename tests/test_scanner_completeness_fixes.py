"""#193 / #196 — scanner completeness must not be over-stated by out-of-scope or per-file parse noise.

#193: `--exclude` never reached Checkov's own traversal, and Checkov `parsing_errors` on excluded (or
SKIP_DIR) files still marked the scanner `error`, so every gated run exited 3.
#196: Semgrep `PartialParsing` / `Syntax error` on a single valid bash file marked the WHOLE scanner
`error`.

Report shapes below are copied from real runs (Checkov 3.3.19, Semgrep 1.177.0), not invented. The
invariant under test in both directions: a genuine scanner failure stays an execution error; only the
over-statement is removed, and an in-scope file that was not (fully) analysed stays NAMED.
"""
import fnmatch
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import coverage, scanners


def _checkov_row(check_type, *, parsing_errors=(), passed=0, failed=0, summary_parse_count=None):
    """A Checkov 3.3.19 per-framework report row (shape captured from `checkov -d … -o json`)."""
    failed_checks = [{"check_id": f"CKV_AWS_{i}", "file_path": "/infra/main.tf",
                      "file_line_range": [1, 3], "check_name": "check", "resource": f"aws_s3_bucket.b{i}"}
                     for i in range(failed)]
    passed_checks = [{"check_id": f"CKV_AWS_P{i}", "file_path": "/infra/main.tf",
                      "resource": "aws_s3_bucket.b"} for i in range(passed)]
    count = len(parsing_errors) if summary_parse_count is None else summary_parse_count
    return {"check_type": check_type,
            "results": {"passed_checks": passed_checks, "failed_checks": failed_checks,
                        "skipped_checks": [], "parsing_errors": list(parsing_errors)},
            "summary": {"passed": passed, "failed": failed, "skipped": 0, "parsing_errors": count,
                        "resource_count": 1 if (passed or failed) else 0, "checkov_version": "3.3.19"}}


def _semgrep_partial_parsing(path, line=3, col=41):
    """Verbatim shape of Semgrep 1.177.0's error for `TO=${1:?usage: ./send.sh +E164 [approved|session]}`."""
    span = {"path": path, "start": {"line": line, "col": col, "offset": 0},
            "end": {"line": line, "col": col + 1, "offset": 1}}
    return {"code": 3, "level": "warn", "type": ["PartialParsing", [span]],
            "message": f"Syntax error at line {path}:{line}:\n `|` was unexpected", "path": path,
            "spans": [{"file": path, "start": span["start"], "end": span["end"]}]}


def _semgrep_syntax_error(path):
    """Verbatim shape of Semgrep 1.177.0's whole-file `Syntax error` (string `type`, no rule_id)."""
    return {"code": 3, "level": "warn", "type": "Syntax error",
            "message": f"Syntax error at line {path}:1:\n `eval(x);` was unexpected", "path": path}


def _semgrep_rule_parse_error():
    """Verbatim shape of a FATAL Semgrep config error (exit code 2, level error)."""
    return {"code": 2, "level": "error", "type": "Rule parse error", "rule_id": "local.bad",
            "message": "Rule parse error in rule local.bad:\n Invalid pattern for Python"}


class _Harness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.out = self.base / "out"
        self.out.mkdir()

    def run_pipeline(self, key, doc, *, excludes=None, exit_code=0):
        path = self.base / f"{key}.json"
        path.write_text(json.dumps(doc))
        runs = [{"key": key, "name": key, "output": str(path), "exit_code": exit_code}]
        with patch.object(scanners.enrichment, "enrich_exploitability", return_value={}), \
             patch.object(scanners.enrichment, "enrich_reachability", return_value={}):
            unified = scanners.normalize_findings(runs, self.out, target=self.repo, excludes=excludes)
        facts = {}
        coverage.add_scanners(facts, {"available": [{"key": key}], "missing": []},
                              runs, unified, scan=True, only=[key])
        return unified, facts["coverage"]

    def abs(self, rel):
        return str(self.repo / rel)


# ---------------------------------------------------------------- #193: exclude reaches Checkov argv

class CheckovSkipPathArgvTests(unittest.TestCase):
    """Checkov's `--skip-path` is a REGEX `search`ed against the ABSOLUTE walk path (verified in
    checkov/common/runners/base_runner.py::filter_ignored_paths, 3.3.19), plus a raw substring test.
    A raw exclude like `out` would therefore also match a target that merely LIVES under
    `/home/x/layout/…` and silently skip the whole repo. The translated patterns must be anchored to
    the target root and reproduce websec's own exclude predicate exactly."""

    TARGET = "/srv/layout/out-repo"      # ancestors deliberately contain `out` and `layout`

    def patterns(self, excludes=()):
        return scanners._checkov_skip_paths(Path(self.TARGET), excludes)

    def test_argv_carries_a_skip_path_for_every_exclude(self):
        argv = scanners._checkov(Path(self.TARGET), Path("/tmp/o/checkov.json"), ["dumps", "out/**"])
        skip = [argv[i + 1] for i, a in enumerate(argv) if a == "--skip-path"]
        # one for the shared SKIP_DIRS contract + one per user exclude
        self.assertEqual(len(skip), 3)
        self.assertEqual(argv[:3], ["checkov", "-d", self.TARGET])

    def test_translation_agrees_with_websec_exclude_predicate(self):
        excludes = ["dumps", "out/**", "*.json", "tests/*", "infra/broken.tf", "a[bc].tf",
                    "mod?.tf", "a+b(c).tf", "fixtures/", "**/generated/**"]
        rels = ["dumps", "dumps/x.json", "src/dumps_old/a.tf", "out", "out/a.json", "out/deep/b.tf",
                "main.tf", "x.json", "dir/x.json", "tests/a.tf", "tests/deep/a.tf", "infra/broken.tf",
                "infra/main.tf", "ab.tf", "ad.tf", "mod1.tf", "mod12.tf", "a+b(c).tf", "ab(c).tf",
                "fixtures/a.tf", "fixtures", "x/generated/y.tf", "generated/y.tf"]
        for ex in excludes:
            (pattern,) = scanners._checkov_skip_paths(Path(self.TARGET), [ex])[1:]
            compiled = re.compile(pattern)
            for rel in rels:
                with self.subTest(exclude=ex, rel=rel):
                    expected = scanners._matches_excludes(rel, [ex])
                    self.assertEqual(bool(compiled.search(f"{self.TARGET}/{rel}")), expected)

    def test_patterns_never_match_the_target_or_its_ancestors(self):
        for pattern in self.patterns(["out", "layout", "srv", "repo"]):
            compiled = re.compile(pattern)
            for full in (self.TARGET, f"{self.TARGET}/main.tf", "/srv/layout/other/out/x.tf"):
                with self.subTest(pattern=pattern, full=full):
                    self.assertIsNone(compiled.search(full))
                    # Checkov ALSO does `p in full_path`; the anchored pattern can never be a substring.
                    self.assertNotIn(pattern, full)

    def test_skip_dirs_are_root_relative_segments(self):
        compiled = re.compile(self.patterns()[0])
        self.assertTrue(compiled.search(f"{self.TARGET}/out"))
        self.assertTrue(compiled.search(f"{self.TARGET}/out/connector.json"))
        self.assertTrue(compiled.search(f"{self.TARGET}/svc/node_modules/x/main.tf"))
        self.assertFalse(compiled.search(f"{self.TARGET}/outer/main.tf"))
        self.assertFalse(compiled.search(f"{self.TARGET}/infra/main.tf"))

    def test_symlinked_and_resolved_target_spellings_are_both_anchored(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = Path(tmp).resolve() / "repo"
            real.mkdir()
            link = Path(tmp).resolve() / "link"
            link.symlink_to(real)
            (pattern,) = scanners._checkov_skip_paths(link, ["dumps"])[1:]
            self.assertTrue(re.search(pattern, f"{link}/dumps/a.json"))
            self.assertTrue(re.search(pattern, f"{real}/dumps/a.json"))

    def test_patterns_compile_and_do_not_trip_checkovs_dot_escape(self):
        for pattern in self.patterns([".github", ".env*", "x"]):
            re.compile(pattern)
            # Checkov re.escape()s any pattern matching ^\.[^\.] — which would turn ours into a literal.
            self.assertIsNone(re.match(r"^\.[^\.]", pattern))


# ------------------------------------------------- #193: parse errors and the Checkov outcome

class CheckovParseErrorOutcomeTests(_Harness):

    def test_parse_errors_on_excluded_files_do_not_fail_checkov(self):
        """The exact #193 repro: a terraform_plan row whose only parse errors are excluded JSON dumps."""
        doc = [_checkov_row("terraform", passed=4, failed=1),
               _checkov_row("terraform_plan", parsing_errors=[self.abs("dumps/connector.json"),
                                                              self.abs("dumps/ctpl.json")])]
        for excludes in (["dumps"], ["dumps/**"], ["dumps/*.json"]):
            with self.subTest(excludes=excludes):
                unified, cov = self.run_pipeline("checkov", doc, excludes=excludes)
                self.assertEqual(unified["scanner_errors"], [])
                self.assertEqual(cov["scanners"]["checkov"]["outcome"], "completed")
                self.assertTrue(cov["execution_complete"])
                details = unified["report_details"]["checkov"]
                self.assertEqual(details["file_limitations_excluded"], 2)
                self.assertNotIn("file_limitations", details)
                self.assertEqual(unified["total"], 1)        # findings still there

    def test_parse_errors_under_a_skip_dir_do_not_fail_checkov(self):
        """`out/` is a SKIP_DIR: its findings were already dropped, its parse errors must be too."""
        doc = [_checkov_row("terraform", passed=2),
               _checkov_row("terraform_plan", parsing_errors=[self.abs("out/connector.json")])]
        unified, cov = self.run_pipeline("checkov", doc)
        self.assertEqual(unified["scanner_errors"], [])
        self.assertTrue(cov["execution_complete"])

    def test_in_scope_parse_error_in_an_evaluated_framework_is_a_named_file_limitation(self):
        doc = [_checkov_row("terraform", passed=4, failed=2,
                            parsing_errors=[self.abs("infra/broken.tf")])]
        unified, cov = self.run_pipeline("checkov", doc)
        self.assertEqual(unified["scanner_errors"], [])
        self.assertNotIn("checkov: error", [g["detail"] for g in cov["gaps"]])
        details = unified["report_details"]["checkov"]
        self.assertEqual(details["errors"], [])
        self.assertEqual(details["file_limitations"], [
            {"path": "infra/broken.tf", "reason": "parse_failed", "native_type": "parsing_error",
             "framework": "terraform", "message": ""}])
        # visible in coverage.json today, before any dedicated rendering
        self.assertEqual(cov["scanners"]["checkov"]["report_details"]["file_limitations"][0]["path"],
                         "infra/broken.tf")
        self.assertEqual(unified["total"], 2)

    def test_framework_that_evaluated_nothing_and_failed_to_parse_stays_an_error(self):
        """Never turn a real failure into a pass: a framework with only in-scope parse failures and
        zero evaluated resources produced NO result for that framework."""
        doc = [_checkov_row("terraform", passed=3),
               _checkov_row("terraform_plan", parsing_errors=[self.abs("plans/prod.json")])]
        unified, cov = self.run_pipeline("checkov", doc)
        self.assertEqual(unified["scanner_errors"], ["checkov"])
        self.assertFalse(cov["execution_complete"])
        self.assertIn("plans/prod.json", " ".join(unified["report_details"]["checkov"]["errors"]))

    def test_unattributed_parse_errors_stay_an_error(self):
        """A summary count with no file names cannot be listed per file — it stays a scanner error."""
        doc = [_checkov_row("terraform", passed=3, parsing_errors=[self.abs("infra/broken.tf")],
                            summary_parse_count=3)]
        unified, cov = self.run_pipeline("checkov", doc)
        self.assertEqual(unified["scanner_errors"], ["checkov"])
        self.assertFalse(cov["execution_complete"])

    def test_excluded_and_in_scope_mix_keeps_only_the_in_scope_file(self):
        doc = [_checkov_row("terraform", passed=3,
                            parsing_errors=[self.abs("dumps/a.tf"), self.abs("infra/broken.tf")])]
        unified, _ = self.run_pipeline("checkov", doc, excludes=["dumps"])
        details = unified["report_details"]["checkov"]
        self.assertEqual(unified["scanner_errors"], [])
        self.assertEqual([row["path"] for row in details["file_limitations"]], ["infra/broken.tf"])
        self.assertEqual(details["file_limitations_excluded"], 1)

    def test_crashed_checkov_exit_code_is_still_an_error(self):
        doc = [_checkov_row("terraform", passed=3)]
        unified, cov = self.run_pipeline("checkov", doc, exit_code=2)
        self.assertEqual(unified["scanner_errors"], ["checkov"])
        self.assertFalse(cov["execution_complete"])

    def test_absolute_path_outside_the_root_is_never_silently_excluded(self):
        """Fail open: a path that cannot be made root-relative must stay visible."""
        doc = [_checkov_row("terraform", passed=3, parsing_errors=["/elsewhere/dumps/a.tf"])]
        unified, _ = self.run_pipeline("checkov", doc, excludes=["dumps"])
        self.assertEqual(unified["report_details"]["checkov"]["file_limitations"][0]["path"],
                         "/elsewhere/dumps/a.tf")


# ---------------------------------------------------- #196: Semgrep per-file parse limitations

class SemgrepParseLimitationTests(_Harness):

    def doc(self, *errors, results=0):
        return {"version": "1.177.0", "errors": list(errors),
                "results": [{"check_id": "local.os-system", "path": self.abs("app.py"),
                             "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 20},
                             "extra": {"severity": "WARNING", "message": "os.system", "metadata": {}}}
                            for _ in range(results)],
                "paths": {"scanned": [self.abs("app.py"), self.abs("send.sh")]}}

    def test_partial_parsing_on_valid_bash_is_a_file_limitation_not_a_scanner_error(self):
        unified, cov = self.run_pipeline("semgrep", self.doc(_semgrep_partial_parsing(self.abs("send.sh")),
                                                             results=1))
        self.assertEqual(unified["scanner_errors"], [])
        self.assertNotIn("semgrep: error", [g["detail"] for g in cov["gaps"]])
        self.assertEqual(cov["scanners"]["semgrep"]["outcome"], "completed")
        details = unified["report_details"]["semgrep"]
        self.assertEqual(details["errors"], [])
        (row,) = details["file_limitations"]
        self.assertEqual((row["path"], row["reason"], row["native_type"]),
                         ("send.sh", "partial_parse", "PartialParsing"))
        self.assertIn("was unexpected", row["message"])
        self.assertEqual(cov["scanners"]["semgrep"]["report_details"]["file_limitations"], [row])
        self.assertEqual(unified["total"], 1)

    def test_whole_file_syntax_error_is_a_file_limitation(self):
        unified, _ = self.run_pipeline("semgrep", self.doc(_semgrep_syntax_error(self.abs("broken.js"))))
        self.assertEqual(unified["scanner_errors"], [])
        (row,) = unified["report_details"]["semgrep"]["file_limitations"]
        self.assertEqual((row["path"], row["reason"], row["native_type"]),
                         ("broken.js", "parse_failed", "Syntax error"))

    def test_lexical_and_other_syntax_errors_are_file_limitations(self):
        for kind in ("Lexical error", "Other syntax error"):
            with self.subTest(kind=kind):
                error = {**_semgrep_syntax_error(self.abs("x.rb")), "type": kind}
                unified, _ = self.run_pipeline("semgrep", self.doc(error))
                self.assertEqual(unified["scanner_errors"], [])

    def test_fatal_config_error_stays_a_scanner_error(self):
        unified, cov = self.run_pipeline("semgrep", self.doc(_semgrep_rule_parse_error()), exit_code=2)
        self.assertEqual(unified["scanner_errors"], ["semgrep"])
        self.assertFalse(cov["execution_complete"])
        # even with a clean exit code, a level:error non-parse diagnostic fails loud
        unified, _ = self.run_pipeline("semgrep", self.doc(_semgrep_rule_parse_error()))
        self.assertEqual(unified["scanner_errors"], ["semgrep"])

    def test_parse_type_at_error_level_stays_a_scanner_error(self):
        error = {**_semgrep_partial_parsing(self.abs("send.sh")), "level": "error"}
        unified, _ = self.run_pipeline("semgrep", self.doc(error))
        self.assertEqual(unified["scanner_errors"], ["semgrep"])

    def test_parse_error_without_a_file_stays_a_scanner_error(self):
        error = _semgrep_syntax_error("")
        error.pop("path")
        unified, _ = self.run_pipeline("semgrep", self.doc(error))
        self.assertEqual(unified["scanner_errors"], ["semgrep"])

    def test_abnormal_exit_with_only_parse_errors_stays_a_scanner_error(self):
        unified, cov = self.run_pipeline("semgrep", self.doc(_semgrep_partial_parsing(self.abs("send.sh"))),
                                         exit_code=2)
        self.assertEqual(unified["scanner_errors"], ["semgrep"])
        self.assertFalse(cov["execution_complete"])

    def test_parse_error_mixed_with_a_fatal_error_fails_but_still_names_the_file(self):
        unified, _ = self.run_pipeline("semgrep", self.doc(_semgrep_partial_parsing(self.abs("send.sh")),
                                                           {"code": 2, "level": "error", "type": "Fatal error",
                                                            "message": "boom"}))
        self.assertEqual(unified["scanner_errors"], ["semgrep"])
        self.assertEqual([r["path"] for r in unified["report_details"]["semgrep"]["file_limitations"]],
                         ["send.sh"])

    def test_rule_scoped_timeouts_are_unchanged(self):
        timeout = {"code": 3, "level": "warn", "type": ["Timeout"], "rule_id": "js.ssrf", "path": self.abs("a.js")}
        unified, cov = self.run_pipeline("semgrep", self.doc(timeout))
        self.assertEqual(cov["scanners"]["semgrep"]["outcome"], "partial")
        self.assertNotIn("file_limitations", unified["report_details"]["semgrep"])

    def test_parse_error_on_an_excluded_file_is_dropped_and_counted(self):
        unified, _ = self.run_pipeline("semgrep", self.doc(_semgrep_partial_parsing(self.abs("scripts/send.sh"))),
                                       excludes=["scripts/**"])
        details = unified["report_details"]["semgrep"]
        self.assertEqual(unified["scanner_errors"], [])
        self.assertNotIn("file_limitations", details)
        self.assertEqual(details["file_limitations_excluded"], 1)


# ------------------------------------------------------- real-tool end-to-end (when installed)

_SEND_SH = "#!/usr/bin/env bash\nset -euo pipefail\nTO=${1:?usage: ./send.sh +E164 [approved|session]}\necho \"$TO\"\n"


class RealToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.out = self.base / "out"
        self.out.mkdir()

    def normalize(self, runs, excludes=None):
        with patch.object(scanners.enrichment, "enrich_exploitability", return_value={}), \
             patch.object(scanners.enrichment, "enrich_reachability", return_value={}):
            return scanners.normalize_findings(runs, self.out, target=self.repo, excludes=excludes)

    @unittest.skipUnless(shutil.which("semgrep"), "semgrep required")
    def test_real_semgrep_partial_parsing_on_valid_bash(self):
        (self.repo / "send.sh").write_text(_SEND_SH)
        rules = self.base / "rules.yml"
        rules.write_text("rules:\n  - id: bash-echo\n    pattern: echo ...\n    message: echo\n"
                         "    languages: [bash]\n    severity: INFO\n")
        report = self.out / "semgrep.json"
        proc = subprocess.run(["semgrep", "scan", "--config", str(rules), "--json", "--output", str(report),
                               "--metrics", "off", str(self.repo)],
                              capture_output=True, text=True, timeout=300)
        errors = json.loads(report.read_text()).get("errors", [])
        if not any("PartialParsing" in json.dumps(e.get("type")) for e in errors):
            self.skipTest("this semgrep build parses the construct cleanly")
        unified = self.normalize([{"key": "semgrep", "name": "Semgrep", "exit_code": proc.returncode,
                                   "output": str(report)}])
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(unified["scanner_errors"], [])
        self.assertEqual([r["path"] for r in unified["report_details"]["semgrep"]["file_limitations"]],
                         ["send.sh"])

    @unittest.skipUnless(shutil.which("checkov"), "checkov required")
    def test_real_checkov_honours_exclude_and_skip_dirs(self):
        (self.repo / "infra").mkdir()
        (self.repo / "infra" / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n')
        for folder in ("dumps", "out"):
            (self.repo / folder).mkdir()
            # NDJSON — not valid JSON, so Checkov's terraform_plan discovery records a parsing error
            (self.repo / folder / "connector.json").write_text('{"id": 1}\n{"id": 2}\n')
        results = scanners.run_available(self.repo, self.out, excludes=["dumps"], only=["checkov"])
        self.assertEqual([r["key"] for r in results], ["checkov"])
        raw = json.loads(Path(results[0]["output"]).read_text())
        native_errors = [p for row in (raw if isinstance(raw, list) else [raw])
                         for p in (row.get("results") or {}).get("parsing_errors", [])]
        self.assertEqual(native_errors, [], "--skip-path did not reach Checkov's traversal")
        unified = self.normalize(results, excludes=["dumps"])
        self.assertEqual(unified["scanner_errors"], [])
        self.assertGreater(unified["total"], 0)


class CheckovTerraformPlanFrameworkTests(unittest.TestCase):
    """terraform_plan parses every *.json; it is skipped only when no file can be a plan."""

    PLAN = json.dumps({"format_version": "1.2", "terraform_version": "1.9.0",
                       "planned_values": {"root_module": {}}, "resource_changes": []})

    def _argv(self, files, excludes=()):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, text in files.items():
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text(text)
            return scanners._checkov(root, root / "out" / "checkov.json", excludes)

    def test_ordinary_json_only_skips_the_plan_framework(self):
        argv = self._argv({"tsconfig.app.json": '{ // comment\n"a": 1 }', "data/dump.json": '{"x": 1}'})
        self.assertIn("terraform_plan", argv[argv.index("--skip-framework") + 1])

    def test_a_plan_file_under_any_name_keeps_the_framework(self):
        argv = self._argv({"infra/whatever.json": self.PLAN, "tsconfig.app.json": "{}"})
        self.assertNotIn("--skip-framework", argv)

    def test_a_plan_only_inside_an_excluded_path_does_not_keep_it(self):
        argv = self._argv({"fixtures/plan.json": self.PLAN, "a.json": "{}"}, excludes=("fixtures",))
        self.assertIn("--skip-framework", argv)

    def test_undecidable_scan_keeps_the_framework(self):
        with patch.object(scanners, "_PLAN_SNIFF_MAX_FILES", 1):
            argv = self._argv({"a.json": "{}", "b.json": "{}"})
        self.assertNotIn("--skip-framework", argv)


if __name__ == "__main__":
    unittest.main()
