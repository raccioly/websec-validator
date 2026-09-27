"""`websec gate` must answer the same policy question `run` does, about the files it was given.

Field report (a Cloudflare Worker repository, 0.19.0): every agent Edit got a blocking PostToolUse
error about `wrangler.jsonc` — a file the agent never touched, carrying a finding already
acknowledged in `.websec-ignore`. Two independent defects produced it, and a third hid behind them:

  1. `gate` and the agent hook built the ledger with NO ignore policy, so reviewed `fingerprint:`
     acknowledgements (and path/category suppressions) that `run` honours were ignored.
  2. Some extractors read config manifests directly whatever `--only` names, so a finding
     attributed to an unrequested file blocked a scoped check about a different file.
  3. `--only` was normalized with `.lstrip("./")`, which strips characters rather than a prefix:
     every path under a dot-directory (`.github/scripts/x.py`) or a dotfile (`.eslintrc.js`) was
     rewritten, matched nothing, and was reported "missed" — never analyzed.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import agenthook, cli, findings, gate, recon
from websec_validator.extractors.base import RepoContext

VULN = '''from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
'''

# A Worker whose route table lives in a config manifest. The routes extractor reads it directly,
# regardless of `--only`, and attributes a missing-authorization lead to `wrangler.jsonc`.
WRANGLER = '''{
  "name": "demo",
  "main": "src/index.ts",
  "routes": [{ "pattern": "example.com", "custom_domain": true }]
}
'''


def _git_repo(root: Path) -> None:
    subprocess.run(["git", "init", "-q", "."], cwd=root, check=True)
    # Pin ambient git settings (pattern from test_diffscope.py): a hostile global config must not
    # fail these commits or redirect hooks out of the fixture.
    for key, value in (("user.email", "d@e.com"), ("user.name", "D"),
                       ("commit.gpgsign", "false"), ("core.autocrlf", "false"),
                       ("core.hooksPath", ".git/hooks"), ("core.excludesFile", os.devnull)):
        subprocess.run(["git", "-C", str(root), "config", key, value], check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)


def _gate_json(repo: Path, *args: str) -> tuple[int, dict]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = cli.main(["gate", str(repo), "--format", "json", *args])
    return code, json.loads(out.getvalue())


def _event(cwd: Path, path: Path) -> dict:
    return {"hook_event_name": "PostToolUse", "tool_name": "Write", "cwd": str(cwd),
            "tool_input": {"file_path": str(path)}}


def _hook(event: dict) -> int:
    with contextlib.redirect_stderr(io.StringIO()):
        return agenthook.run(event, env={})


class GateHonoursIgnorePolicyTests(unittest.TestCase):
    """Defect 1: the in-loop check must apply `.websec-ignore` exactly as `run` does."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "r"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "src" / "app.py").write_text(VULN)
        (self.repo / "requirements.txt").write_text("flask==3.0.0\n")
        _git_repo(self.repo)
        code, _ = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(code, 1, "fixture must block before any policy is written")
        # An operator writes an acknowledgement from `run` output, so take the id from the
        # unscoped ledger — not from the gate under test.
        ledger = findings.build_ledger(recon.build_facts(self.repo, "t"), None)
        self.finding = next(f for f in ledger["findings"]
                            if str(f.get("file") or f.get("location")).startswith("src/app.py"))

    def _ignore(self, text: str) -> None:
        (self.repo / ".websec-ignore").write_text(text)

    def test_scoped_fingerprint_is_the_one_run_reports(self):
        """Acknowledgements only work in the loop if a scoped pass computes the same identity."""
        _, result = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(result["findings"][0]["fingerprint"], self.finding["fingerprint"])

    def test_active_acknowledgement_does_not_block(self):
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2999-12-31 "
                     "# reviewed: fixture\n")
        code, result = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(code, 0)
        self.assertEqual(result["acknowledged_count"], 1)
        self.assertEqual(result["acknowledged"][0]["fingerprint"], self.finding["fingerprint"])
        self.assertEqual(result["acknowledged"][0]["expires"], "2999-12-31")

    def test_expired_acknowledgement_excuses_nothing(self):
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2000-01-01 "
                     "# reviewed long ago\n")
        code, result = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(code, 1)
        self.assertEqual(result["acknowledged_count"], 0)
        self.assertIn("expired", result["findings"][0]["reopened_reason"])

    def test_expired_acknowledgement_says_why_in_the_retry_text(self):
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2000-01-01 # old\n")
        result = gate.evaluate(self.repo, ["src/app.py"], "medium", version="t",
                               scope_source="explicit")
        self.assertIn("acknowledgement expired", gate.render_text(result))

    def test_acknowledgement_without_a_reason_excuses_nothing(self):
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2999-12-31\n")
        code, result = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(code, 1)
        self.assertIn("missing-reason", result["findings"][0]["reopened_reason"])

    def test_category_suppression_applies(self):
        self._ignore(f"category:{self.finding['category']}\n")
        code, result = _gate_json(self.repo, "--only", "src/app.py")
        self.assertEqual(code, 0)
        self.assertEqual(result["findings"], [])

    def test_agent_hook_honours_the_same_acknowledgement(self):
        """The hook runs the gate in-process; it drifted from `run` exactly as `gate` did."""
        event = _event(self.repo, self.repo / "src" / "app.py")
        self.assertEqual(_hook(event), 2)
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2999-12-31 # reviewed\n")
        self.assertEqual(_hook(event), 0)

    def test_pass_text_discloses_the_acknowledgement(self):
        self._ignore(f"fingerprint:{self.finding['fingerprint']} expires:2999-12-31 # reviewed\n")
        result = gate.evaluate(self.repo, ["src/app.py"], "medium", version="t",
                               scope_source="explicit")
        self.assertTrue(result["passed"])
        self.assertIn("1 acknowledged in .websec-ignore", gate.render_text(result))


class GateScopeAttributionTests(unittest.TestCase):
    """Defect 2: a finding attributed to a file outside `--only` must not gate that scope."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "w"
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "wrangler.jsonc").write_text(WRANGLER)
        (self.repo / "package.json").write_text('{"name":"demo","devDependencies":{"wrangler":"4.0.0"}}\n')
        (self.repo / "src" / "index.ts").write_text(
            'export default { async fetch(r: Request) { return new Response("ok"); } };\n')
        (self.repo / "src" / "util.ts").write_text(
            "export const add = (a: number, b: number) => a + b;\n")
        _git_repo(self.repo)

    def test_manifest_finding_outside_the_scope_does_not_block(self):
        code, result = _gate_json(self.repo, "--only", "src/util.ts")
        self.assertEqual(code, 0, result)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["outside_scope_count"], 1)
        self.assertEqual(result["outside_scope"][0]["file"], "wrangler.jsonc")
        self.assertIn("did not cause them", result["outside_scope_note"])

    def test_the_same_finding_still_blocks_when_its_file_is_requested(self):
        """Attribution narrows the gate to the edit; it never hides a finding about the edit."""
        code, result = _gate_json(self.repo, "--only", "wrangler.jsonc")
        self.assertEqual(code, 1)
        self.assertEqual(result["findings"][0]["file"], "wrangler.jsonc")
        self.assertEqual(result["findings"][0]["scope"], "in-scope")

    def test_agent_hook_does_not_block_an_unrelated_edit(self):
        self.assertEqual(_hook(_event(self.repo, self.repo / "src" / "util.ts")), 0)

    def test_pass_text_discloses_what_was_set_aside(self):
        result = gate.evaluate(self.repo, ["src/util.ts"], "medium", version="t",
                               scope_source="explicit")
        self.assertIn("1 outside the changed files", gate.render_text(result))

    def test_run_still_reports_the_manifest_finding(self):
        """Out of the gate's scope is not out of the review: the unscoped ledger keeps it."""
        ledger = findings.build_ledger(recon.build_facts(self.repo, "t"), None)
        self.assertIn("wrangler.jsonc", [f.get("file") for f in ledger["findings"]])


class ScopeStateUnitTests(unittest.TestCase):
    """`outside-scope` requires positive evidence; anything less must keep gating."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "src").mkdir()
        (self.root / "src" / "a.py").write_text("x = 1\n")
        (self.root / "src" / "b.py").write_text("y = 2\n")

    def _facts(self, requested):
        return {"target": str(self.root),
                "analysis_scope": {"requested": requested, "matched": requested, "missed": []}}

    def test_route_only_location_is_unattributed_and_blocks(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH",
                             "title": "Missing authorization: POST /api/x", "location": "/api/x"}]}
        got = gate.verdict(led, self._facts(["src/a.py"]), "medium")
        self.assertFalse(got["passed"])
        self.assertEqual(got["findings"][0]["scope"], "unattributed")

    def test_nonexistent_file_is_unattributed_and_blocks(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "t",
                             "location": "src/ghost.py"}]}
        self.assertFalse(gate.verdict(led, self._facts(["src/a.py"]), "medium")["passed"])

    def test_existing_unrequested_file_is_outside_scope(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "t",
                             "location": "src/b.py:3"}]}
        got = gate.verdict(led, self._facts(["src/a.py"]), "medium")
        self.assertTrue(got["passed"])
        self.assertEqual(got["outside_scope_count"], 1)

    def test_line_suffixed_location_in_the_requested_file_blocks(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "t",
                             "location": "src/a.py:3"}]}
        got = gate.verdict(led, self._facts(["src/a.py"]), "medium")
        self.assertFalse(got["passed"])
        self.assertEqual(got["findings"][0]["scope"], "in-scope")

    def test_a_path_escaping_the_root_is_never_outside_scope(self):
        """A `..` path cannot be proven to be a repository file, so it keeps gating."""
        (self.root.parent / "outside.py").write_text("z = 3\n")
        self.addCleanup((self.root.parent / "outside.py").unlink)
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "t",
                             "location": "../outside.py"}]}
        self.assertFalse(gate.verdict(led, self._facts(["src/a.py"]), "medium")["passed"])

    def test_unscoped_verdict_keeps_every_finding(self):
        led = {"findings": [{"severity": "HIGH", "confidence": "HIGH", "title": "t",
                             "location": "src/b.py"}]}
        self.assertFalse(gate.verdict(led, {"target": str(self.root)}, "medium")["passed"])


class DotPathScopeTests(unittest.TestCase):
    """Defect 3: `--only` must match paths under dot-directories and dotfiles verbatim."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / "d"
        (self.repo / ".github" / "scripts").mkdir(parents=True)
        (self.repo / ".github" / "scripts" / "app.py").write_text(VULN)
        (self.repo / ".eslintrc.js").write_text("module.exports = {};\n")
        (self.repo / "app.py").write_text("x = 1\n")
        (self.repo / "requirements.txt").write_text("flask==3.0.0\n")
        _git_repo(self.repo)

    def test_dot_directory_path_is_matched(self):
        ctx = RepoContext(self.repo, only=[".github/scripts/app.py"])
        self.assertEqual(ctx.scope_matched, [".github/scripts/app.py"])
        self.assertEqual(ctx.scope_missed, [])

    def test_dotfile_is_matched(self):
        ctx = RepoContext(self.repo, only=[".eslintrc.js"])
        self.assertEqual(ctx.scope_matched, [".eslintrc.js"])

    def test_leading_dot_slash_on_a_dot_directory(self):
        ctx = RepoContext(self.repo, only=["./.github/scripts/app.py"])
        self.assertEqual(ctx.scope_matched, [".github/scripts/app.py"])

    def test_parent_traversal_is_not_rewritten_into_a_root_file(self):
        """lstrip turned `../app.py` into `app.py` and analysed a file nobody asked about."""
        ctx = RepoContext(self.repo, only=["../app.py"])
        self.assertEqual(ctx.scope_matched, [])
        self.assertEqual(ctx.scope_missed, ["../app.py"])

    def test_gate_blocks_a_vulnerability_under_a_dot_directory(self):
        code, result = _gate_json(self.repo, "--only", ".github/scripts/app.py")
        self.assertEqual(result["analyzed"], [".github/scripts/app.py"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
