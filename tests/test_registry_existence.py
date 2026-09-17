"""Opt-in registry existence check — the AI slopsquat / hallucinated-dependency class.

Two properties dominate and both are tested offline with a stubbed prober:

  1. SUPPRESSION IS OFFLINE AND HAPPENS FIRST. The naive version of this check had a 100%
     false-positive rate (1 of 1) on a real monorepo — a private workspace package declared as
     `"*"` rather than `workspace:*`, which the spec-prefix filter cannot catch. Sending that name
     to npmjs was also a disclosure of an internal package name, and a private name that reaches a
     public registry cannot be un-sent.
  2. UNKNOWN IS NOT CLEAN. Measured UNKNOWN rates across four identical 200-name runs were
     0%, 0%, 0% and 4.5% — non-deterministic and outside operator control.
"""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import registry


def _deps(**over):
    base = {"declarations": [{"ecosystem": "npm", "name": "express", "spec": "^4", "file": "package.json"}],
            "local_names": [], "private_scopes": [], "private_index": "", "resolved_once": []}
    base.update(over)
    return base


def _prober(mapping, default="exists"):
    def run(eco, name):
        return {"state": mapping.get(name, default)}
    return run


class OfflineSuppressionTests(unittest.TestCase):
    def test_a_workspace_package_is_never_sent(self):
        """The exact measured false positive: private, declared as '*', not 'workspace:*'."""
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "@repo/cdk-lib", "spec": "*",
                                    "file": "packages/cdk/package.json"}],
                     local_names=["@repo/cdk-lib"])
        scheduled = registry.plan(deps)
        self.assertEqual(scheduled["queued"], [])
        self.assertEqual(len(scheduled["suppressed"]), 1)
        self.assertIn("published by a manifest", scheduled["suppressed"][0]["why"])

    def test_privately_bound_scope_is_never_sent(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "@acme/billing", "spec": "^1",
                                    "file": "package.json"}],
                     private_scopes=["acme"])
        self.assertEqual(registry.plan(deps)["queued"], [])

    def test_pip_private_index_suppresses_pypi_queries(self):
        deps = _deps(declarations=[{"ecosystem": "pip", "name": "internal-lib", "spec": "*",
                                    "file": "requirements.txt"}],
                     private_index="https://nexus.internal/simple")
        self.assertEqual(registry.plan(deps)["queued"], [])

    def test_public_names_are_still_queued(self):
        self.assertEqual([q["name"] for q in registry.plan(_deps())["queued"]], ["express"])

    def test_duplicate_names_are_queried_once(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "express", "spec": "^4", "file": "a"},
                                   {"ecosystem": "npm", "name": "express", "spec": "^5", "file": "b"}])
        self.assertEqual(len(registry.plan(deps)["queued"]), 1)

    def test_dry_run_plan_makes_no_requests(self):
        """plan() is pure: a private name that reaches the registry cannot be un-sent."""
        import socket
        seen = []
        original = socket.socket.connect
        socket.socket.connect = lambda self, addr: seen.append(addr)
        try:
            registry.plan(_deps())
        finally:
            socket.socket.connect = original
        self.assertEqual(seen, [])


class EndpointTests(unittest.TestCase):
    def test_npm_uses_the_packument_root_not_latest(self):
        """/{name}/latest 404s for a package with no latest dist-tag — a manufactured 'missing'."""
        url = registry.url_for("npm", "express")
        self.assertTrue(url.endswith("/express"))
        self.assertNotIn("/latest", url)

    def test_pypi_normalises_per_pep503(self):
        self.assertEqual(registry.url_for("pip", "Flask_Cors"),
                         registry.url_for("pip", "flask-cors"))

    def test_only_allowlisted_https_hosts_are_accepted(self):
        for bad in ("http://registry.npmjs.org/x", "https://evil.example/x",
                    "https://user:pw@pypi.org/simple/x/", "https://pypi.org:8443/simple/x/"):
            with self.subTest(url=bad):
                with self.assertRaises(ValueError):
                    registry._check_url(bad)

    def test_allowlisted_hosts_pass(self):
        registry._check_url("https://registry.npmjs.org/express")
        registry._check_url("https://pypi.org/simple/flask/")

    def test_invalid_names_are_unknown_not_missing(self):
        got = registry.probe("npm", "../../etc/passwd")
        self.assertEqual(got["state"], "unknown")


class ResultSemanticsTests(unittest.TestCase):
    def test_404_without_lockfile_evidence_is_nonexistent(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "ghost-pkg", "spec": "^1", "file": "p.json"}])
        got = registry.check(deps, prober=_prober({"ghost-pkg": "missing"}), rate=0)
        self.assertEqual(got["missing"][0]["class"], "dependency-nonexistent")

    def test_404_with_lockfile_evidence_is_unpublished_or_removed(self):
        """A package pulled for malware and a hallucination both 404; the fix differs."""
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "event-stream", "spec": "^3", "file": "p.json"}],
                     resolved_once=["event-stream"])
        got = registry.check(deps, prober=_prober({"event-stream": "missing"}), rate=0)
        self.assertEqual(got["missing"][0]["class"], "dependency-unpublished-or-removed")

    def test_unknown_makes_the_check_incomplete(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "x", "spec": "^1", "file": "p.json"}])
        got = registry.check(deps, prober=_prober({"x": "unknown"}), rate=0)
        self.assertFalse(got["complete"])
        self.assertEqual(len(got["unknown"]), 1)
        self.assertEqual(got["missing"], [])

    def test_unknown_is_never_reported_as_missing(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "x", "spec": "^1", "file": "p.json"}])
        got = registry.check(deps, prober=_prober({"x": "unknown"}), rate=0)
        self.assertEqual(registry.findings_from(got), [])

    def test_all_exists_is_complete(self):
        got = registry.check(_deps(), prober=_prober({}), rate=0)
        self.assertTrue(got["complete"])
        self.assertEqual(got["exists"], 1)

    def test_result_states_that_200_is_not_safety(self):
        """A squatter who already registered the hallucinated name also returns 200."""
        got = registry.check(_deps(), prober=_prober({}), rate=0)
        self.assertIn("NOT evidence the dependency is safe", got["note"])

    def test_findings_are_medium_low_confidence(self):
        deps = _deps(declarations=[{"ecosystem": "npm", "name": "ghost", "spec": "^1", "file": "p.json"}])
        got = registry.findings_from(registry.check(deps, prober=_prober({"ghost": "missing"}), rate=0))
        self.assertEqual(got[0]["severity"], "MEDIUM")
        self.assertEqual(got[0]["confidence"], "LOW")

    def test_removed_and_hallucinated_findings_read_differently(self):
        a = registry.findings_from(registry.check(
            _deps(declarations=[{"ecosystem": "npm", "name": "g", "spec": "^1", "file": "p"}]),
            prober=_prober({"g": "missing"}), rate=0))[0]
        b = registry.findings_from(registry.check(
            _deps(declarations=[{"ecosystem": "npm", "name": "g", "spec": "^1", "file": "p"}],
                  resolved_once=["g"]),
            prober=_prober({"g": "missing"}), rate=0))[0]
        self.assertIn("hallucinated", a["detail"])
        self.assertIn("removed or unpublished", b["detail"])
        self.assertNotEqual(a["kind"], b["kind"])


if __name__ == "__main__":
    unittest.main()


class OfflineContractTests(unittest.TestCase):
    """The DEFAULT pass must stay fully offline; the check is opt-in, the inventory is not."""

    def test_default_recon_makes_zero_network_calls(self):
        import socket
        import tempfile
        from websec_validator.extractors import run_all
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "package.json").write_text('{"name":"d","dependencies":{"express":"^4"}}')
            seen = []
            original = socket.socket.connect
            socket.socket.connect = lambda self, addr: seen.append(addr)
            try:
                facts = run_all(root, "t")
            finally:
                socket.socket.connect = original
        self.assertEqual(seen, [], "the default pass must make ZERO network calls")
        self.assertFalse(facts["dependencies"]["network"]["ran"])

    def test_declarations_are_collected_offline_for_the_optin_check(self):
        import tempfile
        from websec_validator.extractors import run_all
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "package.json").write_text(
                '{"name":"host","workspaces":["p/*"],"dependencies":{"express":"^4","@me/lib":"*"}}')
            (root / "p").mkdir()
            (root / "p" / "lib").mkdir()
            (root / "p" / "lib" / "package.json").write_text('{"name":"@me/lib","private":true}')
            deps = run_all(root, "t")["dependencies"]
        self.assertIn("@me/lib", deps["local_names"])
        queued = [q["name"] for q in registry.plan(deps)["queued"]]
        self.assertIn("express", queued)
        self.assertNotIn("@me/lib", queued, "a workspace package must never be sent")
