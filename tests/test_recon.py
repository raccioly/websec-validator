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

from websec_validator import calibration, findings, probes, scanners   # noqa: E402
from websec_validator.extractors import routes                         # noqa: E402
from websec_validator.extractors.auth import AuthExtractor             # noqa: E402
from websec_validator.extractors.authz import AuthzExtractor           # noqa: E402
from websec_validator.extractors.base import RepoContext               # noqa: E402
from websec_validator.extractors.stack import StackExtractor           # noqa: E402
from websec_validator.extractors.schemas import SchemasExtractor       # noqa: E402
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


class SchemasTests(unittest.TestCase):
    def _build(self):
        d = Path(tempfile.mkdtemp())
        (d / "prisma").mkdir()
        (d / "prisma" / "schema.prisma").write_text(
            "model User {\n  id String @id\n  email String\n  role String\n  isAdmin Boolean\n  tenantId String\n}\n")
        (d / "models").mkdir()
        (d / "models" / "account.py").write_text(
            "from pydantic import BaseModel\nclass AccountUpdate(BaseModel):\n    name: str\n    balance: float\n")
        return d

    def test_detects_orms_entities_and_sensitive_fields(self):
        out = SchemasExtractor().extract(RepoContext(self._build()), {})
        self.assertIn("prisma", out["orms"])
        self.assertIn("pydantic", out["orms"])
        self.assertIn("User", [e["name"] for e in out["entities"]])
        # privileged fields a mass-assignment probe should target
        for f in ("role", "isAdmin", "tenantId", "balance"):
            self.assertIn(f, out["sensitive_fields"])

    def test_no_false_positives_on_modelless_fixture(self):
        out = SchemasExtractor().extract(ctx("node_app"), {})
        self.assertEqual(out["sensitive_fields"], [])
        self.assertEqual(out["orms"], [])


class CalibrationTests(unittest.TestCase):
    def test_wilson_interval(self):
        self.assertEqual(calibration.wilson(0, 0), (0.0, 1.0))      # no data → full ignorance
        lo, hi = calibration.wilson(1, 1)
        self.assertAlmostEqual(hi, 1.0, places=6)
        self.assertTrue(0.15 < lo < 0.25)                          # n=1 is NOT falsely certain (~0.21)
        lo5, hi5 = calibration.wilson(5, 10)
        self.assertTrue(lo5 < 0.5 < hi5)                           # centered on 0.5
        self.assertGreater(calibration.wilson(9, 10)[0], lo5)      # more hits ⇒ higher lower bound

    def test_is_real_matching(self):
        truth = [{"class": "missing-auth", "location_contains": "*"},
                 {"class": "mass-assignment", "location_contains": "register"}]
        self.assertTrue(calibration.is_real("missing-auth", "/anything", truth))   # wildcard
        self.assertTrue(calibration.is_real("mass-assignment", "/users/v1/register", truth))
        self.assertFalse(calibration.is_real("mass-assignment", "/login", truth))  # location mismatch
        self.assertFalse(calibration.is_real("ssrf", "/x", truth))                 # class mismatch ⇒ FP

    def _table(self):
        labeled = ([{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": True}] * 6 +
                   [{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": False}] * 4 +
                   [{"attack_class": "iac", "confidence": "MEDIUM", "is_real": False}] * 8)
        return calibration.fit(labeled, ["X"], researched_classes={"missing-auth"})

    def test_fit_aggregate_and_researched_filter(self):
        t = self._table()
        self.assertEqual(t["by_label"]["MEDIUM"]["n"], 18)         # iac findings still in the aggregate (FP)
        self.assertEqual(t["by_label"]["MEDIUM"]["k"], 6)
        self.assertIn("missing-auth|MEDIUM", t["by_class_label"])
        self.assertNotIn("iac|MEDIUM", t["by_class_label"])        # unresearched ⇒ no misleading p=0 cell

    def test_apply_fallback_tiers(self):
        t = self._table()
        self.assertEqual(calibration.apply("missing-auth", "MEDIUM", t)["basis"], "class+label")
        self.assertEqual(calibration.apply("iac", "MEDIUM", t)["basis"], "label")   # no class cell → aggregate
        self.assertEqual(calibration.apply("x", "HIGH", t)["basis"], "prior (uncalibrated)")  # no HIGH data
        self.assertEqual(calibration.apply("x", "MEDIUM", None)["basis"], "prior (uncalibrated)")  # no table

    def test_samples_from_dynamic_oracle(self):
        dyn = {"write_auth_enforcement": {"results": [
                  {"verdict": "EXECUTED-UNAUTH"}, {"verdict": "auth-enforced"},
                  {"verdict": "no-auth-gate (reached handler/validation)"}, {"verdict": "http-500"}]},
               "cross_tenant_bola": {"leaks": [{"path": "/x"}]}}
        s = calibration.samples_from_dynamic(dyn)
        ma = [x for x in s if x["attack_class"] == "missing-auth"]
        self.assertEqual(len(ma), 3)                       # executed + no-auth-gate + auth-enforced; http-* skipped
        self.assertEqual(sum(x["is_real"] for x in ma), 2)  # auth-enforced is a confirmed FALSE positive
        self.assertTrue(any(x["attack_class"] == "bola" and x["is_real"] for x in s))

    def test_merge_sums_counts_and_personalizes(self):
        shipped = {"meta": {"caveat": "base"},
                   "by_class_label": {"missing-auth|MEDIUM": {"n": 41, "k": 27, "p": 0.659, "ci": [0.5, 0.78]}},
                   "by_label": {"MEDIUM": {"n": 41, "k": 27}}, "prior": calibration.PRIOR}
        local = {"meta": {"samples": 3}, "by_class_label": {"missing-auth|MEDIUM": {"n": 3, "k": 2}},
                 "by_label": {"MEDIUM": {"n": 3, "k": 2}}}
        m = calibration._merge(shipped, local)
        self.assertEqual(m["by_class_label"]["missing-auth|MEDIUM"]["n"], 44)   # counts summed
        self.assertEqual(m["by_class_label"]["missing-auth|MEDIUM"]["k"], 29)
        self.assertTrue(m["meta"]["personalized"])
        self.assertEqual(m["meta"]["local_samples"], 3)

    def test_record_samples_roundtrip(self):
        saved = calibration.LOCAL_PATH
        try:
            calibration.LOCAL_PATH = Path(tempfile.mkdtemp()) / "local.json"
            calibration.record_samples([{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": True},
                                        {"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": False}])
            loc = calibration.load_local()
            self.assertEqual(loc["by_label"]["MEDIUM"], {"n": 2, "k": 1})
            self.assertEqual(loc["meta"]["samples"], 2)
        finally:
            calibration.LOCAL_PATH = saved


class FieldFeedbackBatch1Tests(unittest.TestCase):
    """Regressions for the field-test false positives (proxy.ts, self-scan, ASIA)."""

    def _next_app(self, proxy_body):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / "proxy.ts").write_text(proxy_body)
        (d / "src" / "r.ts").write_text("export async function POST(req){ return Response.json({}) }")
        ctx = RepoContext(d)
        facts = {"routes": {"endpoints": [
            {"method": "POST", "path": "/api/x", "code_path": str(d / "src" / "r.ts")}]}}
        return AuthzExtractor().extract(ctx, facts)

    def test_nextjs_proxy_ts_detected_as_global_auth(self):
        out = self._next_app(
            'export default auth((req) => { if (!req.auth) return NextResponse.json({}, {status: 401}); });\n'
            'export const config = { matcher: ["/((?!_next/static|favicon.ico).*)"] };')
        self.assertTrue(out["global_auth_middleware"])
        self.assertEqual(out["next_middleware"]["file"], "src/proxy.ts")
        self.assertTrue(out["next_middleware"]["is_auth"])
        self.assertEqual(out["write_endpoints_without_visible_guard"], [])  # the 42-HIGH FP cluster, gone

    def test_non_auth_middleware_does_not_falsely_guard(self):
        out = self._next_app('export function proxy(req){ return NextResponse.next(); }\n'
                             'export const config = { matcher: ["/((?!_next).*)"] };')
        self.assertFalse(out["global_auth_middleware"])             # not auth → not a guard
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 1)  # so the route IS still flagged

    def test_scanner_argv_excludes_self_output(self):
        self.assertIn("websec-out", scanners._trivy(Path("/repo"), Path("/o")))
        self.assertIn("websec-out", scanners._semgrep(Path("/repo"), Path("/o")))

    def test_aws_credential_tiering(self):
        self.assertEqual(scanners._aws_secret_tier("AKIAIOSFODNN7EXAMPLE", "")[0], "HIGH")
        self.assertEqual(scanners._aws_secret_tier("ASIAIOSFODNN7EXAMPLE", "")[0], "MEDIUM")
        self.assertEqual(scanners._aws_secret_tier("", "X-Amz-Signature=z&X-Amz-Credential=ASIA")[0], "LOW")
        rows = [{"File": "j.json", "RuleID": "aws", "Description": "AWS key",
                 "Secret": "ASIAEXAMPLE000000000", "Match": "X-Amz-Signature=zzz"}]
        self.assertEqual(scanners._norm_gitleaks(rows)[0]["severity"], "LOW")  # presigned ASIA ≠ HIGH


class FailOpenGuardTests(unittest.TestCase):
    """P0-4: a fail-open test env must NOT escalate untrustworthy unauth 'successes' to CRITICAL."""

    def _ledger(self, fail_open):
        authz = {"endpoint_guards": [{"method": "POST", "path": "/api/x", "code_path": "r.ts",
                                      "guarded": False, "analyzed": True, "public_hint": False}]}
        ex = {"method": "POST", "path": "/api/x", "status": 201, "verdict": "EXECUTED-UNAUTH"}
        dyn = {"write_auth_enforcement": {"results": [ex], "fail_open_suspected": fail_open}}
        return findings.build_ledger({"authz": authz}, None, dyn, [])["findings"][0]

    def test_fail_open_not_escalated(self):
        f = self._ledger(True)
        self.assertNotEqual(f["severity"], "CRITICAL")                       # not escalated
        self.assertTrue(any("UNTRUSTWORTHY" in e["detail"] for e in f["evidence"]))

    def test_healthy_env_still_escalates(self):
        self.assertEqual(self._ledger(False)["severity"], "CRITICAL")        # regression guard


class ProbeStagingTests(unittest.TestCase):
    """P0-3 / P1-2: probes ship with the target's real surface + an always-on unauth baseline."""

    def test_context_unauth_baseline_and_banner(self):
        d = Path(tempfile.mkdtemp())
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/sponsors"},
                                          {"method": "GET", "path": "/api/health"}],
                            "targeting": {"write_endpoints": ["POST /api/sponsors"]}},
                 "auth": {"scheme": "jwt", "token_location": "bearer"},
                 "tenant": {"candidates": [{"key": "tenantId"}]}}
        chosen = probes.applicable(facts)
        self.assertIn("unauth-baseline", chosen)              # always staged (P1-2)
        man = probes.stage(chosen, d, facts)
        ctx = json.loads((d / "probes" / "probe-context.json").read_text())
        self.assertIn("POST /api/sponsors", ctx["endpoints"]["writes"])   # real route, not template's
        self.assertEqual(ctx["auth"]["scheme"], "jwt")
        body = (d / "probes" / "unauth-baseline.sh").read_text()
        self.assertTrue(body.startswith("#!"))                # shebang preserved
        self.assertIn("DRAFT probe", body)                    # banner prepended
        self.assertIn("probe-context.json", body)
        ub = [m for m in man if m.get("key") == "unauth-baseline"][0]
        self.assertEqual(ub["targets"], ["POST /api/sponsors"])           # real per-probe targets

    def test_staged_probes_ship_lib_and_have_no_private_paths(self):
        d = Path(tempfile.mkdtemp())
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/x"}],
                            "targeting": {"write_endpoints": ["POST /api/x"]}},
                 "tenant": {"candidates": [{"key": "tenantId"}]}}
        probes.stage(probes.applicable(facts), d, facts)
        staged = list((d / "probes").glob("*"))
        names = {p.name for p in staged}
        self.assertIn("_lib.py", names)               # shared helper is always shipped
        self.assertIn("probe-context.json", names)
        blob = "\n".join(p.read_text() for p in staged if p.suffix in (".py", ".sh"))
        self.assertNotIn("security/zap", blob)        # no author-private fixture paths (P0-3)
        self.assertNotIn("security/pentest", blob)


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


class LedgerTests(unittest.TestCase):
    def _facts(self, guards):
        return {"authz": {"endpoint_guards": guards}, "surface": {"sinks": {}},
                "client_exposure": {}, "iac_ci": {}, "graphql": {}}

    def test_correlation_confidence_and_standards(self):
        facts = self._facts([
            {"method": "PUT", "path": "/api/settings/config", "code_path": "config.ts", "guarded": False, "analyzed": True, "public_hint": False},
            {"method": "POST", "path": "/api/settings/topics", "code_path": "topics.ts", "guarded": True, "analyzed": True, "public_hint": False},
        ])
        led = findings.build_ledger(facts, None, None, [])
        titles = [f["title"] for f in led["findings"]]
        self.assertTrue(any("config" in t for t in titles))     # no-guard write surfaced
        self.assertFalse(any("topics" in t for t in titles))    # guarded → excluded

        dyn = {"write_auth_enforcement": {"results": [
            {"method": "PUT", "path": "/api/settings/config", "status": 200, "verdict": "EXECUTED-UNAUTH"}]}}
        led2 = findings.build_ledger(facts, None, dyn, [])
        cfg = next(f for f in led2["findings"] if "config" in f["title"])
        self.assertEqual(cfg["confidence"], "HIGH")             # dynamic confirmation escalates
        self.assertEqual(cfg["severity"], "CRITICAL")
        self.assertEqual(len(cfg["evidence"]), 2)               # recon + dynamic evidence chain
        self.assertIn("CWE-862 Missing Authorization", cfg["standards"]["cwe"])
        self.assertTrue(cfg["remediation"])

    def test_suppression(self):
        facts = self._facts([{"method": "PUT", "path": "/api/x", "code_path": "x.ts", "guarded": False, "analyzed": True, "public_hint": False}])
        led = findings.build_ledger(facts, None, None, ["category:access-control"])
        self.assertEqual(led["total"], 0)
        self.assertEqual(led["suppressed"], 1)


if __name__ == "__main__":
    unittest.main()
