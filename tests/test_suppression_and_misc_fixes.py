"""Regression tests for the doc-grounding defect batch: `.websec-ignore` matching (L), the init
template's category vocabulary (D), feedback extension hints (E), client identifiers in shipped
code (T), the action's exit-code output (Q), Noir failed-vs-absent (P), Brakeman applicability (Z)
and the skill's `gate.failure_kind` vocabulary (W).
"""
from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import feedback, findings, init_scope, scanners  # noqa: E402
from websec_validator.extractors import routes  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402
from websec_validator.extractors.routes import RoutesExtractor  # noqa: E402
from websec_validator.extractors.stack import StackExtractor  # noqa: E402


def _row(location: str, title: str = "finding", category: str = "sast") -> dict:
    """A scanner row: the ledger turns it into a `static-<category>` finding at `location`."""
    return {"category": category, "key": title, "file": location, "title": title,
            "severity": "HIGH", "tools": ["semgrep"], "fingerprint": f"fp-{location}-{title}"}


def _ledger(rows: list, patterns: list) -> tuple:
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        ledger = findings.build_ledger({}, {"all": rows}, None, list(patterns))
    return ledger, err.getvalue()


def _kept(ledger: dict) -> set:
    return {f["location"] for f in ledger["findings"]}


# ---------------------------------------------------------------------------------------------
# L — `.websec-ignore` matching
# ---------------------------------------------------------------------------------------------
class IgnorePathSemanticsTests(unittest.TestCase):
    def test_directory_pattern_matches_whole_components_at_any_depth(self):
        self.assertTrue(findings._path_match("tests/", "tests/x.py"))
        self.assertTrue(findings._path_match("tests/", "a/tests/x.py"))
        self.assertFalse(findings._path_match("tests/", "contests/x.py"))
        self.assertFalse(findings._path_match("tests/", "a/tests"), "trailing / = directory only")
        self.assertTrue(findings._path_match("**/fixtures/", "pkg/fixtures/key.pem"))

    def test_anchored_pattern_only_matches_at_the_root(self):
        self.assertTrue(findings._path_match("/build/", "build/out.js"))
        self.assertFalse(findings._path_match("/build/", "src/build/out.js"))

    def test_contests_stays_suppressed_but_is_recorded_and_warned(self):
        ledger, err = _ledger([_row("tests/x.py:3"), _row("a/tests/y.py"), _row("contests/z.py:1")],
                              ["tests/"])
        # Nothing suppressed before is silently un-suppressed this release.
        self.assertEqual(ledger["findings"], [])
        self.assertEqual(ledger["suppressed"], 3)
        # …but the one hidden only by the old substring rule is surfaced.
        self.assertEqual(ledger["suppressed_legacy_substring"], 1)
        self.assertEqual(len(ledger["suppressed_legacy"]), 1)
        record = ledger["suppressed_legacy"][0]
        self.assertEqual(record["location"], "contests/z.py:1")
        self.assertTrue(record["suppression"]["legacy_substring"])
        self.assertEqual(record["suppression"]["patterns"], ["tests/"])
        warning, = ledger["suppression_warnings"]
        self.assertEqual((warning["pattern"], warning["pattern_kind"], warning["hidden"]),
                         ("tests/", "path", 1))
        self.assertEqual(warning["replacement"], ["/contests/z.py"])
        self.assertEqual(err.count("websec: .websec-ignore line 'tests/'"), 1)
        self.assertIn("/contests/z.py", err)

    def test_glob_now_matches_a_location_with_a_line_suffix(self):
        ledger, err = _ledger([_row("src/file.js:13"), _row("src/file.py:2")], ["*.js"])
        self.assertEqual(_kept(ledger), {"src/file.py:2"})
        self.assertEqual(ledger["suppressed_legacy_substring"], 0)
        self.assertEqual(err, "")

    def test_bare_word_keeps_legacy_substring_behaviour_with_a_warning(self):
        rows = [_row("src/app.py:3", title="unsafe test harness"),
                _row("test/helper.py:1", title="eval"),
                _row("src/main.py:9", title="sql")]
        ledger, err = _ledger(rows, ["test"])
        self.assertEqual(_kept(ledger), {"src/main.py:9"})
        self.assertEqual(ledger["suppressed_legacy_substring"], 2)
        warning, = ledger["suppression_warnings"]
        self.assertEqual((warning["pattern_kind"], warning["hidden"]), ("word", 2))
        self.assertEqual(warning["replacement"], ["/src/app.py", "test/"])
        self.assertEqual(err.count("websec: .websec-ignore line 'test' hid 2 finding(s)"), 1)

    def test_anchored_build_pattern(self):
        rows = [_row("build/out.js:1"), _row("src/build/x.js:4"), _row("rebuild/y.js:2")]
        ledger, _ = _ledger(rows, ["/build/"])
        # root build/ is now hidden; src/build/ was hidden by the old substring rule and stays
        # hidden (recorded + warned); rebuild/ was never hidden and still is not.
        self.assertEqual(_kept(ledger), {"rebuild/y.js:2"})
        self.assertEqual([r["location"] for r in ledger["suppressed_legacy"]], ["src/build/x.js:4"])
        self.assertEqual(ledger["suppression_warnings"][0]["replacement"], ["/src/build/x.js"])

    def test_exact_line_elsewhere_means_no_legacy_record(self):
        ledger, err = _ledger([_row("contests/z.py:1")], ["tests/", "contests/"])
        self.assertEqual(ledger["suppressed"], 1)
        self.assertEqual(ledger["suppressed_legacy_substring"], 0)
        self.assertEqual(err, "")

    def test_path_embedded_in_a_recon_location_matches_exactly(self):
        finding = {"category": "client-exposure", "title": "Secret exposed to client",
                   "location": "VITE_KEY  (src/websec_validator/extractors/client_exposure.py)"}
        hidden, legacy = findings._suppression_match(
            finding, ["src/websec_validator/extractors/client_exposure.py"])
        self.assertTrue(hidden)
        self.assertEqual(legacy, [])

    def test_category_lines_are_exact(self):
        rows = [_row("a.py", category="secret"), _row("b.py", category="sca")]
        ledger, err = _ledger(rows, ["category:static-secret"])
        self.assertEqual(_kept(ledger), {"b.py"})
        self.assertEqual(err, "")

    def test_union_is_a_superset_of_the_legacy_rule(self):
        """Strict monotonicity: anything the old rule hid is still hidden."""
        locations = ["tests/x.py:3", "contests/z.py", "src/build/a.js:1", "build/b.js",
                     "lib/test_utils.py", "GET /api/tests", "KEY  (web/tests/app.ts)", ""]
        patterns = ["tests/", "test", "/build/", "*.js", "build", "category:static-sast",
                    "src/", "api", "web/tests/app.ts", "TESTS/"]
        for location in locations:
            finding = {"category": "static-sast", "location": location, "title": "Test title"}
            for pattern in patterns:
                if findings._legacy_match(finding, pattern):
                    self.assertTrue(findings._suppressed(finding, [pattern]), (location, pattern))


# ---------------------------------------------------------------------------------------------
# D — init template category examples
# ---------------------------------------------------------------------------------------------
def _ledger_category_vocabulary() -> set:
    """Every category a ledger finding can carry: literal `_f(…, "<category>", …)` arguments, plus
    `static-<scanner category>` for the scanner rows (the scanners' own `category` constants)."""
    vocabulary, scanner_categories = set(), set()
    tree = ast.parse((ROOT / "src/websec_validator/findings.py").read_text())
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "_f"
                and len(node.args) > 1):
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                vocabulary.add(arg.value)
            elif isinstance(arg, ast.JoinedStr):
                prefix = "".join(v.value for v in arg.values if isinstance(v, ast.Constant))
                vocabulary.add(prefix + "*")
    for node in ast.walk(ast.parse((ROOT / "src/websec_validator/scanners.py").read_text())):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if (isinstance(key, ast.Constant) and key.value == "category"
                        and isinstance(value, ast.Constant) and isinstance(value.value, str)):
                    scanner_categories.add(value.value)
    for template in [v for v in vocabulary if v.endswith("*")]:
        vocabulary.discard(template)
        vocabulary |= {template[:-1] + category for category in scanner_categories}
    return vocabulary


class InitTemplateCategoryTests(unittest.TestCase):
    """Guard (D): the template's `category:static-secret` was verified CORRECT — scanner secrets
    reach the ledger as `static-secret`, and `category:secret` would hide nothing. This pins every
    example to a category the ledger really emits."""

    def test_every_category_example_is_a_real_ledger_category(self):
        vocabulary = _ledger_category_vocabulary()
        self.assertIn("static-secret", vocabulary)
        text = init_scope.render({"entries": []})
        examples = set(re.findall(r"category:([a-z0-9][a-z0-9-]*)", text))
        self.assertTrue(examples, "the template should show at least one category example")
        self.assertLessEqual(examples, vocabulary, examples - vocabulary)

    def test_the_example_category_actually_suppresses_a_scanner_secret(self):
        ledger, _ = _ledger([_row("config.py", category="secret")], ["category:static-secret"])
        self.assertEqual(ledger["suppressed"], 1)
        ledger, _ = _ledger([_row("config.py", category="secret")], ["category:secret"])
        self.assertEqual(ledger["suppressed"], 0)

    def test_template_describes_component_path_semantics(self):
        text = init_scope.render({"entries": []})
        self.assertNotIn("a path substring", text)
        self.assertIn("never contests/", text)


# ---------------------------------------------------------------------------------------------
# E — feedback --file-extension
# ---------------------------------------------------------------------------------------------
class FeedbackExtensionHintTests(unittest.TestCase):
    def missed(self, hint):
        return feedback.build_missed_record(attack_class="sqli", reason="missed a query",
                                            file_extension=hint)["missed"]["file_extension"]

    def test_dotted_bare_and_filename_forms_are_all_kept(self):
        for hint in (".ex", "ex", "controller.ex", "lib/app/controller.ex", " .ex "):
            self.assertEqual(self.missed(hint), ".ex", hint)
        self.assertEqual(self.missed("archive.tar.gz"), ".gz")
        self.assertEqual(self.missed("src/billing/charge_secrets.py"), ".py")

    def test_absent_hint_stays_empty(self):
        self.assertEqual(self.missed(""), "")

    def test_a_hint_with_no_extension_is_refused_not_dropped(self):
        for hint in ("src/Dockerfile", "a b", ".", "../x/"):
            with self.assertRaises(feedback.FeedbackError, msg=hint):
                self.missed(hint)


# ---------------------------------------------------------------------------------------------
# T — client identifiers in shipped code
# ---------------------------------------------------------------------------------------------
# The private-identifier list lives ONLY in the local, never-committed name-guard hook — the list is
# itself sensitive, so this public test must not spell it out. Where the hook is installed (the
# maintainer's checkout) the shipped tree is checked against the same list the commit guard uses;
# elsewhere (CI, forks) the test skips and the commit-time guard remains the control.
def _private_identifier_pattern():
    try:
        common = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--git-common-dir"],
                                capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    guard = (ROOT / common / "hooks" / "_names-guard.sh") if not Path(common).is_absolute() \
        else Path(common) / "hooks" / "_names-guard.sh"
    try:
        match = re.search(r"^PRIV_RE='([^']+)'", guard.read_text(encoding="utf-8"), re.M)
    except OSError:
        return None
    return re.compile(match.group(1), re.I) if match else None


class ClientIdentifierTests(unittest.TestCase):
    def test_policy_consistency_uses_neutral_wording(self):
        source = (ROOT / "src/websec_validator/extractors/policy_consistency.py").read_text()
        self.assertIn("a field-report regression", source)

    def test_shipped_tree_names_no_private_identifier(self):
        pattern = _private_identifier_pattern()
        if pattern is None:
            self.skipTest("local name-guard hook not installed; the commit-time guard is the control")
        offenders = []
        for base in ("src", "skills", "docs", "hooks"):
            for path in (ROOT / base).rglob("*"):
                if not path.is_file() or path.suffix in {".pyc", ".pdf"} or "__pycache__" in path.parts:
                    continue
                try:
                    text = path.read_text(encoding="utf-8")
                except (UnicodeDecodeError, OSError):
                    continue
                if pattern.search(text):
                    offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(offenders, [])


# ---------------------------------------------------------------------------------------------
# Q — action exit-code output
# ---------------------------------------------------------------------------------------------
_spec = importlib.util.spec_from_file_location("websec_action_q", ROOT / "scripts/run-action.py")
action = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(action)


def _action_outputs() -> dict:
    """{output-name: (step output key, description)} from action.yml's `outputs:` block."""
    block = (ROOT / "action.yml").read_text().split("\noutputs:\n", 1)[1].split("\nruns:", 1)[0]
    out, name = {}, None
    for line in block.splitlines():
        if re.match(r"^  [\w-]+:\s*$", line):
            name = line.strip()[:-1]
            out[name] = [None, None]
        elif name and line.strip().startswith("description:"):
            out[name][1] = line.split(":", 1)[1].strip().strip('"')
        elif name and line.strip().startswith("value:"):
            m = re.search(r"steps\.scan\.outputs\.(\w+)", line)
            out[name][0] = m.group(1) if m else None
    return {k: tuple(v) for k, v in out.items()}


class ActionExitCodeOutputTests(unittest.TestCase):
    def test_every_written_step_output_is_a_declared_action_output(self):
        from websec_validator import cli
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "repo").mkdir()
            (root / "repo/app.py").write_text('print("safe")\n')
            github_output = root / "github-output"
            env = {"WEBSEC_INPUT_PATH": str(root / "repo"), "WEBSEC_INPUT_OUT": str(root / "out"),
                   "WEBSEC_INPUT_SCAN": "false", "WEBSEC_INPUT_REQUIRE_COMPLETE": "true",
                   "WEBSEC_INPUT_FAIL_ON": "", "WEBSEC_INPUT_BASELINE": "", "WEBSEC_INPUT_SCANNERS": "",
                   "GITHUB_OUTPUT": str(github_output)}
            with patch.dict(os.environ, env), patch("shutil.which", return_value=None), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = action.run(cli.main)
            written = dict(line.split("=", 1) for line in github_output.read_text().splitlines())
        self.assertEqual(written["exit_code"], str(rc))
        declared = _action_outputs()
        exposed = {step_key: desc for step_key, desc in declared.values()}
        for key in written:
            self.assertIn(key, exposed, f"run-action writes `{key}` but action.yml does not expose it")
            self.assertTrue(exposed[key], f"output for `{key}` needs a description")
        self.assertIn("exit-code", declared)
        self.assertEqual(declared["exit-code"][0], "exit_code")


# ---------------------------------------------------------------------------------------------
# P — Noir failed vs absent; doctor data
# ---------------------------------------------------------------------------------------------
def _which_only(*names):
    return lambda binary, *a, **k: f"/usr/local/bin/{binary}" if binary in names else None


class NoirFailureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "app.py").write_text("from flask import Flask\napp = Flask(__name__)\n"
                                          "@app.route('/x')\ndef x():\n    return 'x'\n")

    def scan(self, run):
        status = {}
        with patch.object(routes.shutil, "which", _which_only("noir")), \
                patch.object(routes.subprocess, "run", run):
            eps = routes._noir_scan(self.root, None, status)
        return eps, status

    def test_timeout_is_failed_not_absent(self):
        def run(*a, **k):
            raise subprocess.TimeoutExpired(cmd="noir", timeout=300)
        eps, status = self.scan(run)
        self.assertIsNone(eps)
        self.assertEqual(status, {"state": "failed", "reason": "timed out after 300s"})

    def test_crash_with_empty_output_is_failed_not_zero_routes(self):
        def run(*a, **k):
            return subprocess.CompletedProcess(a[0], 139, "", "Segmentation fault (core dumped)\n")
        eps, status = self.scan(run)
        self.assertIsNone(eps)
        self.assertEqual(status["state"], "failed")
        self.assertEqual(status["reason"], "exit 139: Segmentation fault (core dumped)")

    def test_unparseable_output_is_failed(self):
        def run(argv, **k):
            Path(argv[argv.index("-o") + 1]).write_text("{not json")
            return subprocess.CompletedProcess(argv, 0, "", "")
        eps, status = self.scan(run)
        self.assertIsNone(eps)
        self.assertEqual(status["state"], "failed")

    def test_clean_zero_route_run_is_ok(self):
        def run(argv, **k):
            Path(argv[argv.index("-o") + 1]).write_text('{"endpoints": []}')
            return subprocess.CompletedProcess(argv, 0, "", "")
        eps, status = self.scan(run)
        self.assertEqual((eps, status["state"]), ([], "ok"))

    def test_absent(self):
        status = {}
        with patch.object(routes.shutil, "which", return_value=None):
            self.assertIsNone(routes._noir_scan(self.root, None, status))
        self.assertEqual(status["state"], "absent")

    def extract(self, fake):
        ctx = RepoContext(self.root)
        facts = {"stack": StackExtractor().extract(ctx, {})}
        with patch.object(routes, "_noir_scan", fake):
            return RoutesExtractor().extract(ctx, facts)

    def test_run_says_noir_failed_instead_of_install_noir(self):
        def broken(root, excludes=None, status=None):
            status.update(state="failed", reason="exit 139: Segmentation fault")
            return None
        out = self.extract(broken)
        self.assertEqual(out["noir"], {"state": "failed", "reason": "exit 139: Segmentation fault"})
        self.assertIn("OWASP Noir failed: exit 139: Segmentation fault", out["engine"])
        self.assertNotIn("install OWASP Noir", out["engine"])
        self.assertTrue(out["engine"].startswith("regex-fallback"))
        self.assertGreaterEqual(out["count"], 1, "the regex fallback still maps routes")

    def test_absent_noir_keeps_the_install_hint(self):
        out = self.extract(lambda root, excludes=None, status=None: None)
        self.assertEqual(out["noir"]["state"], "absent")
        self.assertIn("install OWASP Noir", out["engine"])

    def test_doctor_data_reports_route_engine_status(self):
        def run(argv, **k):
            return subprocess.CompletedProcess(argv, 127, "", "noir: error while loading shared libraries\n")
        with patch.object(scanners.shutil, "which", _which_only("noir")), \
                patch.object(scanners.subprocess, "run", run):
            engine = scanners.detect([])["route_engine"]
        self.assertEqual(engine["key"], "noir")
        self.assertEqual(engine["status"], "broken")
        self.assertIn("exited 127", engine["note"])

        def ok(argv, **k):
            return subprocess.CompletedProcess(argv, 0, "1.1.0\n", "")
        with patch.object(scanners.shutil, "which", _which_only("noir")), \
                patch.object(scanners.subprocess, "run", ok):
            engine = scanners.check_route_engine()
        self.assertEqual((engine["status"], engine["version"]), ("ok", "1.1.0"))
        with patch.object(scanners.shutil, "which", return_value=None):
            self.assertEqual(scanners.check_route_engine()["status"], "not_installed")

    def test_run_path_does_not_probe_noir(self):
        def forbidden(*a, **k):
            raise AssertionError("detect(check_versions=False) must not spawn a version probe")
        with patch.object(scanners.shutil, "which", _which_only("noir")), \
                patch.object(scanners.subprocess, "run", forbidden):
            engine = scanners.detect([], check_versions=False)["route_engine"]
        self.assertEqual(engine["status"], "not_checked")


# ---------------------------------------------------------------------------------------------
# Z — Brakeman only for a Rails app
# ---------------------------------------------------------------------------------------------
class BrakemanApplicabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.plain = Path(self.tmp.name) / "gem"
        (self.plain / "lib").mkdir(parents=True)
        (self.plain / "lib/tool.rb").write_text("puts 1\n")
        self.rails = Path(self.tmp.name) / "rails"
        (self.rails / "app/controllers").mkdir(parents=True)
        (self.rails / "config").mkdir()
        (self.rails / "config/application.rb").write_text("require 'rails/all'\n")

    def keys(self, det):
        return {s["key"] for s in det["available"] + det["missing"]}

    def test_detect_skips_brakeman_without_a_rails_app(self):
        det = scanners.detect(["ruby"], check_versions=False, target=self.plain)
        self.assertNotIn("brakeman", self.keys(det))
        self.assertEqual([row["key"] for row in det["not_applicable"]], ["brakeman"])
        self.assertIn("Rails", det["not_applicable"][0]["reason"])
        self.assertIn("brakeman", self.keys(scanners.detect(["ruby"], check_versions=False,
                                                            target=self.rails)))
        # No target known → the language-only rule (callers that cannot say where they scan).
        self.assertIn("brakeman", self.keys(scanners.detect(["ruby"], check_versions=False)))

    def run_brakeman(self, target):
        calls = []

        def run(argv, **k):
            calls.append(argv)
            Path(argv[argv.index("-o") + 1]).write_text('{"warnings": []}')
            return subprocess.CompletedProcess(argv, 0, "", "")
        with tempfile.TemporaryDirectory() as out, \
                patch.object(scanners.shutil, "which", _which_only("brakeman")), \
                patch.object(scanners.subprocess, "run", run):
            results = scanners.run_available(target, Path(out), ["ruby"], only=["brakeman"])
        return calls, results

    def test_brakeman_never_runs_on_a_non_rails_ruby_target(self):
        calls, results = self.run_brakeman(self.plain)
        self.assertEqual(calls, [])
        self.assertEqual(results, [])

    def test_brakeman_still_runs_on_a_rails_app(self):
        calls, results = self.run_brakeman(self.rails)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "brakeman")
        self.assertEqual(results[0]["key"], "brakeman")


# ---------------------------------------------------------------------------------------------
# W — skill documents every gate.failure_kind
# ---------------------------------------------------------------------------------------------
class SkillFailureKindTests(unittest.TestCase):
    def test_skill_lists_every_failure_kind_the_cli_emits(self):
        kinds = set()
        for line in (ROOT / "src/websec_validator/cli.py").read_text().splitlines():
            if "failure_kind=" in line:
                kinds |= set(re.findall(r'"([a-z][a-z+-]*)"', line.split("failure_kind=", 1)[1]))
        self.assertIn("no-analyzable-source", kinds)
        skill = (ROOT / "skills/security-pass/SKILL.md").read_text()
        missing = sorted(kind for kind in kinds if f"`{kind}`" not in skill)
        self.assertEqual(missing, [])


if __name__ == "__main__":
    unittest.main()
