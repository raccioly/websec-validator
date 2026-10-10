"""Scoping and path-translation defects that made a run or a gate pass on code it never examined.

Each class pins one defect found while grounding the documentation in the code:

  A. `run <subdir> --diff` compared repo-root paths with target-relative findings → fail-open.
  B. `gate <subdir>` did the same with `git status` paths → an uncommitted vulnerability "missed".
  C. `--only <directory>` matched nothing, and a request that matched nothing was not a coverage gap.
  D. every directory named `security/` was pruned by name; other pruned trees hid source silently.
  E. `gate` outside a git repository had no changed-file set and still reported a pass.
  F. a recon finding (which carries `location`, not `file`) rendered as "(no file)".

Every git repository here is hermetic in the same way as test_diffscope / test_gate_command: the
ambient settings these assertions depend on are pinned locally, so a hostile global config
(commit.gpgsign, core.hooksPath, autocrlf — see bug-217) cannot change the outcome.
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import cli, coverage, diffscope, gate  # noqa: E402
from websec_validator.extractors import base, run_all  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402

VULN = '''from flask import Flask, request
import subprocess
app = Flask(__name__)

@app.route("/ping")
def ping():
    host = request.args.get("host")
    return subprocess.check_output("ping -c1 " + host, shell=True)
'''
SAFE = "def add(a, b):\n    return a + b\n"


def _git(repo: Path, *args: str):
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


def _repo(root: Path) -> Path:
    """A monorepo with the application in `svc/`, committed on `main`, then a `feat` branch."""
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for key, value in (("user.email", "t@t"), ("user.name", "t"), ("commit.gpgsign", "false"),
                       ("core.autocrlf", "false"), ("core.hooksPath", ".git/hooks"),
                       ("core.excludesFile", os.devnull)):
        _git(root, "config", key, value)
    _git(root, "symbolic-ref", "HEAD", "refs/heads/main")
    (root / "svc" / "src").mkdir(parents=True)
    (root / "svc" / "src" / "safe.py").write_text(SAFE)
    (root / "svc" / "requirements.txt").write_text("flask==3.0.0\n")
    (root / "other").mkdir()
    (root / "other" / "tool.py").write_text(SAFE)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base")
    _git(root, "checkout", "-qb", "feat")
    return root


def _quiet(fn, *args, **kwargs):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = fn(*args, **kwargs)
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------- A. run <subdir> --diff
@unittest.skipUnless(shutil.which("git"), "git required")
class DiffScopeSubdirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = _repo(self.base / "repo")
        (self.repo / "svc" / "src" / "app.py").write_text(VULN)
        (self.repo / "other" / "tool.py").write_text(SAFE + "\n# touched outside the target\n")
        _git(self.repo, "add", "-A")
        _git(self.repo, "commit", "-qm", "vuln")

    def test_subdirectory_scope_is_relative_to_the_target(self):
        scope = diffscope.compute(self.repo / "svc", "main")
        self.assertIsNone(scope["error"])
        # Target-relative, so it compares equal to a finding's location; the change outside the
        # target is dropped (no finding of a `svc` run can sit in `other/`).
        self.assertEqual(set(scope["files"]), {"src/app.py"})
        self.assertEqual(scope["files"]["src/app.py"], [(1, VULN.count("\n"))])
        self.assertEqual(scope["repo_prefix"], "svc/")

    def test_top_level_scope_is_unchanged(self):
        scope = diffscope.compute(self.repo, "main")
        self.assertEqual(set(scope["files"]), {"svc/src/app.py", "other/tool.py"})
        self.assertEqual(scope["repo_prefix"], "")

    def test_subdirectory_finding_lands_in_the_changed_hunk(self):
        scope = diffscope.compute(self.repo / "svc", "main")
        ledger = {"findings": [{"location": "src/app.py:8", "file": "src/app.py"}]}
        counts = diffscope.annotate(ledger, scope)
        self.assertEqual(ledger["findings"][0]["diff_state"], "in-changed-hunk")
        self.assertEqual(counts["untouched"], 0)

    def _run(self, target: Path) -> int:
        out = self.base / ("out-" + target.name)
        code, _, _ = _quiet(cli.main, ["run", str(target), "--diff", "main", "--fail-on", "medium",
                                       "--out", str(out), "--format", "json"])
        return code

    def test_scoped_fail_on_gates_from_a_subdirectory_target(self):
        """The fail-open: the subdirectory run used to exit 0 over a new finding in a changed file."""
        self.assertEqual(self._run(self.repo / "svc"), 1)

    def test_scoped_fail_on_still_gates_from_the_repository_root(self):
        self.assertEqual(self._run(self.repo), 1)


# ---------------------------------------------------------------- B. gate <subdir>
@unittest.skipUnless(shutil.which("git"), "git required")
class GateSubdirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = _repo(Path(self.temp.name).resolve() / "repo")
        (self.repo / "svc" / "src" / "app.py").write_text(VULN)          # uncommitted, untracked
        (self.repo / "other" / "tool.py").write_text(SAFE + "# edit\n")  # modified outside svc

    def test_working_tree_paths_are_relative_to_a_subdirectory_target(self):
        found = gate.working_tree_paths(self.repo / "svc")
        self.assertEqual(found["paths"], ["src/app.py"])
        self.assertEqual(found["source"], "working-tree")

    def test_working_tree_paths_at_the_root_are_unchanged(self):
        found = gate.working_tree_paths(self.repo)
        self.assertEqual(found["paths"], ["other/tool.py", "svc/src/app.py"])

    def test_gate_on_a_subdirectory_blocks_the_uncommitted_vulnerability(self):
        code, out, _ = _quiet(cli.main, ["gate", str(self.repo / "svc"), "--format", "json"])
        result = json.loads(out)
        self.assertEqual(code, 1, result)
        self.assertEqual(result["analyzed"], ["src/app.py"])
        self.assertEqual(result["missed"], [])

    def test_gate_on_the_root_still_blocks(self):
        code, _, _ = _quiet(cli.main, ["gate", str(self.repo), "--format", "json"])
        self.assertEqual(code, 1)

    def test_rename_does_not_produce_a_phantom_path(self):
        """With -z the ORIGINAL name of a rename is the next token, not a record of its own."""
        (self.repo / "svc" / "src" / "app.py").unlink()
        (self.repo / "other" / "tool.py").write_text(SAFE)
        _git(self.repo, "mv", "svc/src/safe.py", "svc/src/renamed.py")
        found = gate.working_tree_paths(self.repo)
        self.assertEqual(found["paths"], ["svc/src/renamed.py"])
        self.assertEqual(gate.working_tree_paths(self.repo / "svc")["paths"], ["src/renamed.py"])


# ---------------------------------------------------------------- C. --only <directory>
class OnlyDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for rel, text in (("src/app.py", VULN), ("src/lib/util.py", SAFE), ("src2/other.py", SAFE),
                          ("top.py", SAFE), ("docs/guide.md", "# guide\n"),
                          ("requirements.txt", "flask==3.0.0\n")):
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def _selected(self, only):
        ctx = RepoContext(self.root, only=only)
        return sorted(ctx.rel(p) for p in ctx.code_files), ctx

    def test_a_directory_selects_every_file_below_it(self):
        for spelling in ("src", "src/", "./src"):
            selected, ctx = self._selected([spelling])
            self.assertEqual(selected, ["src/app.py", "src/lib/util.py"], spelling)
            self.assertEqual(ctx.scope_missed, [], spelling)

    def test_directory_matching_is_on_component_boundaries(self):
        selected, _ = self._selected(["src"])
        self.assertNotIn("src2/other.py", selected)

    def test_dot_selects_the_whole_tree(self):
        selected, ctx = self._selected(["."])
        self.assertEqual(selected, ["src/app.py", "src/lib/util.py", "src2/other.py", "top.py"])
        self.assertEqual(ctx.scope_missed, [])

    def test_files_and_directories_mix(self):
        selected, ctx = self._selected(["src/lib", "top.py", "ghost.py"])
        self.assertEqual(selected, ["src/lib/util.py", "top.py"])
        self.assertEqual(ctx.scope_missed, ["ghost.py"])

    def test_a_directory_cannot_reach_into_a_skipped_tree(self):
        (self.root / "node_modules" / "pkg").mkdir(parents=True)
        (self.root / "node_modules" / "pkg" / "index.js").write_text("module.exports = 1\n")
        selected, ctx = self._selected(["node_modules"])
        self.assertEqual(selected, [])
        self.assertEqual(ctx.scope_missed, ["node_modules"])

    def test_scope_that_selects_nothing_is_a_coverage_gap(self):
        facts = run_all(self.root, "test", only=["docs", "ghost.py"])
        self.assertEqual(facts["analysis_scope"]["missed"], ["docs", "ghost.py"])
        gaps = [g for g in facts["coverage"]["gaps"] if g["kind"] == "scope_missed"]
        self.assertEqual(len(gaps), 1, facts["coverage"]["gaps"])
        self.assertIn("docs", gaps[0]["detail"])
        self.assertIn("ghost.py", gaps[0]["detail"])
        self.assertFalse(gaps[0]["execution"])     # a scope limit, not a failed check
        self.assertEqual(facts["coverage"]["files"]["analysis_scope"],
                         {"requested": 2, "matched": 0, "missed": ["docs", "ghost.py"]})
        rendered = coverage.render_md(facts)
        self.assertIn("REQUESTED SCOPE NOT ANALYZED", rendered)
        self.assertNotIn("REQUESTED CHECKS COMPLETED", rendered)

    def test_partially_missed_scope_is_a_gap_but_not_the_empty_banner(self):
        facts = run_all(self.root, "test", only=["src", "ghost.py"])
        self.assertTrue(any(g["kind"] == "scope_missed" for g in facts["coverage"]["gaps"]))
        self.assertNotIn("REQUESTED SCOPE NOT ANALYZED", coverage.render_md(facts))

    def test_fully_matched_scope_adds_no_gap(self):
        facts = run_all(self.root, "test", only=["src"])
        self.assertFalse(any(g["kind"] == "scope_missed" for g in facts["coverage"]["gaps"]))

    def test_gate_only_directory_gates_a_finding_inside_it(self):
        """A finding under a requested directory is IN scope; exact-name matching called it
        outside-scope, which does not gate."""
        code, out, _ = _quiet(cli.main, ["gate", str(self.root), "--only", "src", "--format", "json"])
        result = json.loads(out)
        self.assertEqual(code, 1, result)
        self.assertIn("src/app.py", result["analyzed"])
        self.assertEqual(result["outside_scope_count"], 0)

    def test_scope_state_treats_a_requested_directory_as_covering_its_files(self):
        finding = {"file": "src/app.py", "location": "src/app.py:8"}
        self.assertEqual(gate.scope_state(finding, ["src"], self.root), "in-scope")
        self.assertEqual(gate.scope_state(finding, ["."], self.root), "in-scope")
        # Component boundary: `sr` is not a parent of `src/app.py`.
        self.assertEqual(gate.scope_state(finding, ["sr", "top.py"], self.root), "outside-scope")


# ---------------------------------------------------------------- D. skipped directories
class SkippedDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "app.py").write_text(SAFE)
        (self.root / "requirements.txt").write_text("flask==3.0.0\n")

    def write(self, rel, text=SAFE):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def _gaps(self, facts, kind):
        return [g for g in facts["coverage"]["gaps"] if g["kind"] == kind]

    def test_a_security_directory_is_analysed(self):
        """Auth middleware commonly lives in `security/`; pruning it by name was a silent hole."""
        self.assertNotIn("security", base.SKIP_DIRS)
        self.write("security/middleware.py", VULN)
        ctx = RepoContext(self.root)
        self.assertIn("security/middleware.py", [ctx.rel(p) for p in ctx.code_files])
        facts = run_all(self.root, "test")
        self.assertIn("security/middleware.py", facts["coverage"]["inputs"])

    def test_websec_output_store_is_skipped_by_content_whatever_its_name(self):
        """The narrow replacement for the name rule: this tool's own output (staged probe
        scripts included) is not application code, under `security/` or any other name."""
        for name in ("security", "reports"):
            run = self.write(f"{name}/runs/20261010-x/FACTS.json", "{}").parent
            self.write(f"{name}/runs/20261010-x/coverage.json", "{}")
            self.write(f"{name}/runs/20261010-x/probes/ssrf.py", VULN)
            os.symlink(Path("runs") / run.name, self.root / name / "latest", target_is_directory=True)
        ctx = RepoContext(self.root)
        rels = [ctx.rel(p) for p in ctx.code_files]
        self.assertFalse([r for r in rels if "probes" in r], rels)
        self.assertGreaterEqual(ctx.skip_counts.get("websec_output", 0), 2)
        # ...and the skip is disclosed with a count, so planting markers cannot hide code silently.
        listed = {row["path"] for row in ctx.skipped_code_dirs}
        self.assertEqual(listed, {"security/", "reports/"})

    def test_an_unpublished_run_directory_is_also_recognised(self):
        self.write("out-dir/runs/r1/FACTS.json", "{}")
        self.write("out-dir/runs/r1/coverage.json", "{}")
        self.write("out-dir/runs/r1/probes/bola.py", VULN)
        ctx = RepoContext(self.root)
        self.assertNotIn("out-dir/runs/r1/probes/bola.py", [ctx.rel(p) for p in ctx.code_files])

    def test_a_lone_facts_file_does_not_hide_a_directory(self):
        self.write("security/FACTS.json", "{}")
        self.write("security/auth.py", VULN)
        ctx = RepoContext(self.root)
        self.assertIn("security/auth.py", [ctx.rel(p) for p in ctx.code_files])

    def test_skipped_build_directory_holding_source_is_a_coverage_gap(self):
        self.write("build/handler.py", VULN)
        self.write("build/lib/more.ts", "export const x = 1\n")
        self.write("dist/bundle.css", "body{}\n")         # not an analysable suffix
        facts = run_all(self.root, "test")
        self.assertNotIn("build/handler.py", facts["coverage"]["inputs"])   # still skipped
        gaps = self._gaps(facts, "skipped_directory_code")
        self.assertEqual(len(gaps), 1, facts["coverage"]["gaps"])
        self.assertIn("build/ (2)", gaps[0]["detail"])
        self.assertNotIn("dist/", gaps[0]["detail"])
        self.assertFalse(gaps[0]["execution"])
        self.assertEqual(facts["coverage"]["files"]["skipped_code_files"], 2)
        self.assertEqual(facts["coverage"]["files"]["skipped_code_dirs"],
                         [{"path": "build/", "code_files": 2, "count_truncated": False}])

    def test_no_gap_when_skipped_directories_hold_no_source(self):
        self.write("dist/bundle.css", "body{}\n")
        self.write("node_modules/pkg/index.js", "module.exports = 1\n")   # not probed by design
        facts = run_all(self.root, "test")
        self.assertEqual(self._gaps(facts, "skipped_directory_code"), [])

    def test_operator_exclusion_is_not_reported_as_a_hole(self):
        self.write("build/handler.py")
        facts = run_all(self.root, "test", excludes=["build"])
        self.assertEqual(self._gaps(facts, "skipped_directory_code"), [])

    def test_the_probe_is_bounded(self):
        for index in range(6):
            self.write(f"target/gen/f{index}.py")
        with patch.object(base, "SKIPPED_CODE_PROBE_ENTRIES", 3):
            ctx = RepoContext(self.root)
        self.assertEqual(ctx.skipped_code_dirs,
                         [{"path": "target/", "code_files": 3, "count_truncated": True}])

    def test_private_directories_are_never_counted(self):
        self.write("vendor/.local/secret.py")
        ctx = RepoContext(self.root)
        self.assertEqual(ctx.skipped_code_dirs, [])


# ---------------------------------------------------------------- E. gate outside git
class GateOutsideGitTests(unittest.TestCase):
    def test_no_repository_means_the_scope_is_undetermined(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "app.py").write_text(VULN)
            found = gate.working_tree_paths(Path(td))
        self.assertEqual(found["source"], "not-a-git-repository")    # label unchanged
        self.assertIs(found["scope_determined"], False)
        self.assertTrue(gate.scope_undetermined(found))

    @unittest.skipUnless(shutil.which("git"), "git required")
    def test_a_clean_repository_is_determined_and_empty(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(Path(td).resolve() / "repo")
            found = gate.working_tree_paths(repo)
        self.assertEqual(found["paths"], [])
        self.assertIs(found["scope_determined"], True)
        self.assertFalse(gate.scope_undetermined(found))

    def test_failed_status_is_undetermined(self):
        self.assertTrue(gate.scope_undetermined({"paths": [], "source": "working-tree-unavailable"}))


# ---------------------------------------------------------------- F. "(no file)"
class GateRenderLocationTests(unittest.TestCase):
    def _text(self, finding):
        finding = {"severity": "HIGH", "confidence": "HIGH", "title": "t", **finding}
        result = gate.verdict({"findings": [finding]},
                              {"analysis_scope": {"matched": ["src/auth.ts"], "missed": []}}, "medium")
        return gate.render_text(result), result

    def test_a_location_only_finding_names_its_location(self):
        text, result = self._text({"location": "src/auth.ts:12"})
        self.assertIn("src/auth.ts:12", text)
        self.assertNotIn("(no file)", text)
        self.assertEqual(result["findings"][0]["location"], "src/auth.ts:12")

    def test_a_line_is_not_appended_twice(self):
        text, _ = self._text({"location": "src/auth.ts:12", "line": 12})
        self.assertNotIn("src/auth.ts:12:12", text)

    def test_file_and_line_render_as_before(self):
        text, _ = self._text({"file": "src/auth.ts", "location": "src/auth.ts:12", "line": 12})
        self.assertIn("[HIGH] src/auth.ts:12 ", text)

    def test_a_line_carried_only_by_the_location_is_kept(self):
        text, _ = self._text({"file": "src/auth.ts", "location": "src/auth.ts:12"})
        self.assertIn("[HIGH] src/auth.ts:12 ", text)

    def test_a_non_file_location_is_shown_rather_than_no_file(self):
        text, _ = self._text({"location": "(response headers)"})
        self.assertIn("(response headers)", text)


if __name__ == "__main__":
    unittest.main()
