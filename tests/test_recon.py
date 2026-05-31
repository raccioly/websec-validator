"""Portable regression tests for the deterministic recon core.

Stdlib `unittest` only (no pytest, no Noir, no network) so it runs anywhere:
    python3 -m unittest discover -s tests
Route extraction is tested via the regex fallback + pure helpers, so Noir's
absence doesn't make the suite flaky.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import scanners                                  # noqa: E402
from websec_validator.extractors import routes                         # noqa: E402
from websec_validator.extractors.auth import AuthExtractor             # noqa: E402
from websec_validator.extractors.base import RepoContext               # noqa: E402
from websec_validator.extractors.stack import StackExtractor           # noqa: E402
from websec_validator.extractors.surface import SINKS, SurfaceExtractor  # noqa: E402
from websec_validator.extractors.tenant import TenantExtractor         # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def ctx(name):
    return RepoContext(FIX / name)


class StackTests(unittest.TestCase):
    def test_node(self):
        f = StackExtractor().extract(ctx("node_app"), {})
        self.assertIn("node", f["languages"])
        self.assertIn("express", f["frameworks"])
        self.assertIn("dynamodb", f["datastores"])

    def test_python(self):
        f = StackExtractor().extract(ctx("py_app"), {})
        self.assertIn("python", f["languages"])
        self.assertIn("flask", f["frameworks"])


class AuthTests(unittest.TestCase):
    def test_python_jwt(self):
        c = ctx("py_app")
        a = AuthExtractor().extract(c, {"stack": StackExtractor().extract(c, {})})
        self.assertIn("jwt", a["scheme"])


class TenantTests(unittest.TestCase):
    def test_node_groupid(self):
        t = TenantExtractor().extract(ctx("node_app"), {})
        self.assertIn("groupId", [c["key"] for c in t["candidates"]])


class SurfaceTests(unittest.TestCase):
    def test_ssrf_sink_detected(self):
        s = SurfaceExtractor().extract(ctx("node_app"), {"stack": {"datastores": ["dynamodb"]}})
        self.assertIn("ssrf", s["sinks"])

    def test_command_injection_regex_is_user_gated(self):
        rx = SINKS["command-injection"][2]
        self.assertTrue(rx.search("child_process.exec(req.body.cmd)"))
        self.assertFalse(rx.search("child_process.exec('ls -la')"))


class RouteUnitTests(unittest.TestCase):
    def test_clean_path(self):
        self.assertEqual(routes._clean_path("/api/users/:id"), "/api/users/{id}")
        self.assertEqual(routes._clean_path("/files/*key"), "/files/{key}")

    def test_is_noise(self):
        self.assertTrue(routes._is_noise("/assets/*.png"))
        self.assertTrue(routes._is_noise("/BASE_URL/x"))
        self.assertFalse(routes._is_noise("/api/users/{id}"))

    def test_normalize_noir_dedup_django_noise(self):
        eps = [
            {"method": "get", "url": "/api/x/:id", "params": [], "details": {"technology": "t", "code_paths": [{"path": "a"}]}},
            {"method": "GET", "url": "/api/x/{id}", "params": [], "details": {"technology": "t", "code_paths": [{"path": "a"}]}},
            {"method": "GET", "url": "/items/<int:pk>", "params": [], "details": {"technology": "django", "code_paths": [{"path": "b"}]}},
            {"method": "GET", "url": "/assets/*.png", "params": [], "details": {}},
        ]
        paths = {(r["method"], r["path"]) for r in routes._normalize_noir(eps)}
        self.assertIn(("GET", "/api/x/{id}"), paths)        # :id and {id} collapsed
        self.assertIn(("GET", "/items/{pk}"), paths)        # django <int:pk> normalized
        self.assertNotIn(("GET", "/assets/*.png"), paths)   # static-asset glob filtered
        self.assertEqual(sum(1 for _m, p in paths if p == "/api/x/{id}"), 1)

    def test_derive_targeting(self):
        d = routes._derive([
            {"method": "POST", "path": "/api/groups/{groupId}/items", "params": [{"name": "url", "where": "query"}]},
            {"method": "GET", "path": "/api/users/{id}", "params": []},
        ])
        self.assertTrue(d["ssrf_candidates"])
        self.assertTrue(d["idor_candidates"])
        self.assertTrue(d["write_endpoints"])

    def test_fallback_express_no_noir(self):
        paths = {(r["method"], r["path"]) for r in routes._fallback(ctx("node_app"))}
        self.assertIn(("GET", "/api/users/{id}"), paths)
        self.assertIn(("POST", "/api/groups/{groupId}/items"), paths)


class DedupTests(unittest.TestCase):
    def test_within_tool_dedup_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "gitleaks.json").write_text(json.dumps([
                {"RuleID": "aws", "File": "x.json", "StartLine": 1, "Description": "k"},
                {"RuleID": "aws", "File": "x.json", "StartLine": 1, "Description": "k"},  # duplicate
            ]))
            (d / "trivy.json").write_text(json.dumps({"Results": [{"Target": "package-lock.json",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "lodash",
                                     "Severity": "HIGH", "InstalledVersion": "1", "FixedVersion": "2"}]}]}))
            sr = [{"key": "gitleaks", "output": str(d / "gitleaks.json")},
                  {"key": "trivy", "output": str(d / "trivy.json")}]
            res = scanners.normalize_findings(sr, d)
            self.assertEqual(res["total_raw"], 3)
            self.assertEqual(res["total"], 2)        # 2 gitleaks dups → 1, plus 1 CVE
            self.assertEqual(res["by_severity"].get("HIGH"), 2)
            self.assertTrue((d / "findings.json").exists())


if __name__ == "__main__":
    unittest.main()
