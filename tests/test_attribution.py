"""Run attribution: WHICH change, and how much the identity evidence is actually worth.

The grading is the feature. A value the runner can set to any string is a label, not audit
evidence, and presenting one as identity would manufacture exactly the false assurance the tool
exists to avoid. These tests pin that: `assurance` is computed, tier 3 never promotes, and the
object never leaks into verification_context (which repairs compares by strict dict equality).
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import attribution, repairs


def _repo(root: Path, commit=True) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-q", "."], cwd=root, check=True)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Dev"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
    (root / "a.py").write_text("x = 1\n")
    if commit:
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        subprocess.run(["git", "commit", "-qm", "init"], cwd=root, check=True)
    return root


CI_ENV = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "acme/app", "GITHUB_SHA": "cafebabe",
          "GITHUB_RUN_ID": "77", "GITHUB_TRIGGERING_ACTOR": "alice", "GITHUB_EVENT_NAME": "push"}


class AssuranceGradingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()

    def test_ci_minted_outranks_everything_else(self):
        root = _repo(self.base / "r")
        got = attribution.build(root, actor="someone", env=dict(CI_ENV))
        self.assertEqual(got["assurance"], "ci-minted")
        self.assertEqual(got["ci"]["triggering_actor"], "alice")

    def test_ci_records_where_to_corroborate_the_claim(self):
        """The most valuable CI field: where an assessor checks this against a system we don't control."""
        got = attribution.build(_repo(self.base / "r"), env=dict(CI_ENV))
        self.assertEqual(got["ci"]["corroborate_at"],
                         "https://github.com/acme/app/actions/runs/77")

    def test_gitlab_runner_is_recognised(self):
        env = {"GITLAB_CI": "true", "CI_PROJECT_PATH": "grp/app", "CI_COMMIT_SHA": "abc",
               "CI_PIPELINE_ID": "9", "CI_PIPELINE_URL": "https://gitlab.com/grp/app/-/pipelines/9"}
        got = attribution.build(_repo(self.base / "r"), env=env)
        self.assertEqual(got["assurance"], "ci-minted")
        self.assertEqual(got["ci"]["provider"], "gitlab-ci")
        self.assertEqual(got["ci"]["corroborate_at"], "https://gitlab.com/grp/app/-/pipelines/9")

    def test_local_git_is_vcs_observed(self):
        got = attribution.build(_repo(self.base / "r"), env={})
        self.assertEqual(got["assurance"], "vcs-observed")
        self.assertRegex(got["vcs"]["commit"], r"^[0-9a-f]{40}$")
        self.assertTrue(got["vcs"]["tree_clean"])

    def test_dirty_tree_is_recorded_because_findings_do_not_describe_the_commit_alone(self):
        root = _repo(self.base / "r")
        (root / "b.py").write_text("y = 2\n")
        got = attribution.build(root, env={})
        self.assertFalse(got["vcs"]["tree_clean"])

    def test_actor_only_is_self_asserted_not_promoted(self):
        plain = self.base / "plain"
        (plain / "src").mkdir(parents=True)
        got = attribution.build(plain, actor="cfo@corp.com", env={})
        self.assertEqual(got["assurance"], "self-asserted")
        self.assertEqual(got["declared"]["operator"], "cfo@corp.com")
        self.assertNotIn("vcs", got)
        self.assertNotIn("ci", got)

    def test_declared_carries_its_warning_inline_in_the_artifact(self):
        """The warning must survive being pasted into an audit binder, so it lives in the data."""
        got = attribution.build(self.base, actor="anyone", env={})
        self.assertIn("NOT verified", got["declared"]["warning"])

    def test_declared_never_promotes_into_vcs_or_ci(self):
        env = {"WEBSEC_ACTOR": "attacker", "WEBSEC_AGENT_MODEL": "claimed-model"}
        got = attribution.build(_repo(self.base / "r"), env=env)
        self.assertEqual(got["assurance"], "vcs-observed")
        self.assertNotIn("attacker", json.dumps(got.get("vcs", {})))
        self.assertEqual(got["declared"]["agent"]["model"], "claimed-model")

    def test_assurance_is_computed_and_cannot_be_supplied(self):
        env = {"WEBSEC_ACTOR": "x", "assurance": "ci-minted", "WEBSEC_ASSURANCE": "ci-minted"}
        got = attribution.build(self.base / "nothing", env=env)
        self.assertEqual(got["assurance"], "self-asserted")

    def test_non_repo_with_nothing_declared_is_none(self):
        empty = self.base / "empty"
        empty.mkdir()
        got = attribution.build(empty, env={})
        self.assertEqual(got["assurance"], "none")

    def test_approver_independence_is_always_an_explicit_non_goal(self):
        for env in ({}, dict(CI_ENV)):
            got = attribution.build(_repo(self.base / f"r{len(env)}"), env=env)
            self.assertFalse(got["approver_independence"]["evidenced"])
            self.assertIn("not evidence that review occurred", got["approver_independence"]["note"])


class AttributionIsolationTests(unittest.TestCase):
    """attribution must never leak into verification_context: repairs compares it by STRICT dict
    equality in four places, so an extra key invalidates every previously emitted repair plan."""

    def test_repair_plan_context_is_unchanged_by_attribution(self):
        ledger = {"findings": [{"severity": "HIGH", "title": "t", "fingerprint": "fp1",
                                "category": "sast", "file": "a.py", "status": "open"}],
                  "verification_context": {"application_id": "app", "build_id": "b",
                                           "source_digest": "a" * 64},
                  "attribution": {"schema_version": "1.0", "assurance": "vcs-observed"}}
        plans = repairs.build(ledger, application_id="app", build_id="b", source_digest="a" * 64)
        for plan in plans:
            ctx = plan.get("original") or plan.get("context") or {}
            self.assertNotIn("attribution", ctx)
            self.assertNotIn("assurance", ctx)

    def test_attribution_never_raises_and_never_fails_a_run(self):
        """Evidence ABOUT a run must not be able to fail one."""
        for bad in (Path("/nonexistent/nope"), Path("/dev/null")):
            got = attribution.build(bad, env={})
            self.assertIn(got["assurance"], {"none", "self-asserted", "vcs-observed", "ci-minted"})

    def test_untrusted_env_values_are_bounded_and_null_stripped(self):
        env = dict(CI_ENV, GITHUB_TRIGGERING_ACTOR="a" * 5000 + "\x00b")
        got = attribution.build(Path("/tmp"), env=env)
        actor = got["ci"]["triggering_actor"]
        self.assertLessEqual(len(actor), 256)
        self.assertNotIn("\x00", actor)


if __name__ == "__main__":
    unittest.main()
