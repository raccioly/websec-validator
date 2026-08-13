"""Tests for the 0.2.5 hardening pass (from the agent-wallet dogfood run):
  - forged-token / unverified-signature bypass detection (bug: static said 'verify manually')
  - scanner contamination hygiene (bug-066): SKIP_DIR drop + gitignored-secret downgrade
  - rate-limit probe is FACTS-driven (bug-067)
Stdlib unittest only:  python3 -m unittest discover -s tests
"""
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import calibration, dynamic, findings, probes, scanners  # noqa: E402
from websec_validator.extractors.auth import AuthExtractor  # noqa: E402
from websec_validator.extractors.authz import AuthzExtractor  # noqa: E402
from websec_validator.extractors.base import RepoContext  # noqa: E402
from websec_validator.extractors.tenant import TenantExtractor  # noqa: E402

FACTS = {"routes": {"endpoints": [
    {"method": "GET", "path": "/api/bypass"},      # gated; accepts forged token  -> BYPASS
    {"method": "GET", "path": "/api/safe"},        # gated; rejects forged token  -> ok
    {"method": "GET", "path": "/api/ratelimited"},  # gated; forged -> 429         -> NOT a bypass
    {"method": "GET", "path": "/api/public"},      # 200 with no auth              -> skipped (not gated)
]}}


def _fake_request(method, url, token=None, timeout=20, data=None, cookie=None):
    authed = bool(token or cookie)
    if url.endswith("/api/bypass"):
        return (400 if authed else 401), "x"      # forged token reaches handler
    if url.endswith("/api/safe"):
        return 401, "x"                            # forged token still rejected
    if url.endswith("/api/ratelimited"):
        return (429 if authed else 401), "x"       # rate-limited, must NOT count as bypass
    if url.endswith("/api/public"):
        return 200, "x"                            # not gated unauthenticated
    return 404, ""


class ForgedTokenBypassTests(unittest.TestCase):
    def test_detects_only_the_real_bypass(self):
        with mock.patch.object(dynamic, "_request", _fake_request):
            r = dynamic.forged_token_bypass("http://t", FACTS)
        paths = [b["path"] for b in r["bypassed"]]
        self.assertEqual(paths, ["/api/bypass"])          # exactly the one that reached the handler
        self.assertEqual(r["tested"], 3)                  # public route skipped (baseline 200)

    def test_rate_limited_is_not_a_bypass(self):
        with mock.patch.object(dynamic, "_request", _fake_request):
            r = dynamic.forged_token_bypass("http://t", FACTS)
        self.assertNotIn("/api/ratelimited", [b["path"] for b in r["bypassed"]])

    def test_forged_jwt_is_three_part_and_bogus(self):
        tok = dynamic._forge_jwt({"exp": 9999999999})
        self.assertEqual(len(tok.split(".")), 3)
        self.assertTrue(tok.split(".")[2])                # has a (deliberately invalid) signature segment


class LedgerForgedBypassTests(unittest.TestCase):
    def test_bypass_becomes_critical(self):
        dyn = {"forged_token_bypass": {"bypassed": [
            {"method": "GET", "path": "/api/x", "baseline": 401, "forged": 400, "via": "Authorization: Bearer"}]}}
        led = findings.build_ledger({}, None, dyn, [])
        hit = [f for f in led["findings"] if "forged unsigned token" in f["title"]]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "CRITICAL")
        self.assertEqual(hit[0]["attack_class"], "unsafe-auth-decoder")


class SbomEmissionTests(unittest.TestCase):
    def test_skips_gracefully_when_trivy_absent(self):
        with mock.patch.object(scanners.shutil, "which", return_value=None):
            with tempfile.TemporaryDirectory() as d:
                r = scanners.write_sbom(Path(d), Path(d), "cyclonedx")
        self.assertFalse(r["available"])
        self.assertIn("trivy", r["reason"])

    def test_unknown_format_defaults_to_cyclonedx(self):
        # bad --sbom value must not crash the format lookup (argparse guards the CLI, but the
        # function is called elsewhere too)
        with mock.patch.object(scanners.shutil, "which", return_value=None):
            with tempfile.TemporaryDirectory() as d:
                r = scanners.write_sbom(Path(d), Path(d), "bogus")
        self.assertFalse(r["available"])   # trivy absent → skip, but no KeyError on the format

    @unittest.skipUnless(shutil.which("trivy"), "trivy required")
    def test_emits_valid_cyclonedx_with_components(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "requirements.txt").write_text("requests==2.20.0\nflask==1.0.0\n")
            r = scanners.write_sbom(d, d, "cyclonedx")
            self.assertTrue(r["available"])
            self.assertEqual(r["path"], "sbom.cdx.json")
            sbom = json.loads((d / "sbom.cdx.json").read_text())
        self.assertEqual(sbom.get("bomFormat"), "CycloneDX")
        names = {c.get("name") for c in sbom.get("components", [])}
        self.assertIn("flask", names)
        self.assertIn("requests", names)
        self.assertGreaterEqual(r["components"], 2)


class ScannerHygieneTests(unittest.TestCase):
    def test_in_skip_dir(self):
        self.assertTrue(scanners._in_skip_dir(".claude/worktrees/x/gitleaks.json"))
        self.assertTrue(scanners._in_skip_dir("node_modules/dep/a.js"))
        self.assertFalse(scanners._in_skip_dir("src/app/api/route.ts"))

    def test_skipdir_matched_relative_to_root_not_absolute(self):
        # Regression: a repo living UNDER a skip-named ANCESTOR (.claude/worktrees, vendor/,
        # target/) had every absolute-path route/finding silently dropped, because SKIP_DIRS
        # was matched against the ABSOLUTE path's segments (bug-005 recurrence). Match relative
        # to the scan root instead. Proven empirically: identical fixture → 2 routes at a clean
        # path, 0 routes under a `target/` ancestor.
        from websec_validator.extractors.base import path_in_skip_dir
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "target" / "app"        # 'target' is a SKIP_DIR — but it's an ANCESTOR
            (root / "src").mkdir(parents=True)
            real = root / "src" / "routes.js"
            real.write_text("x")
            self.assertIn("target", str(real).split("/"))          # the trap segment is present...
            self.assertFalse(path_in_skip_dir(str(real), root))    # ...but NOT below the root → keep it
            nm = root / "node_modules" / "dep.js"                  # a genuine skip-dir BELOW the root
            nm.parent.mkdir(parents=True)
            nm.write_text("x")
            self.assertTrue(path_in_skip_dir(str(nm), root))       # still correctly skipped
        # backward-compat: no root → legacy raw-segment behavior (single-arg call sites/tests)
        self.assertTrue(path_in_skip_dir("node_modules/dep/a.js"))
        self.assertFalse(path_in_skip_dir("src/app/api/route.ts"))

    def test_normalize_keeps_findings_when_repo_under_skipdir_ancestor(self):
        # End-to-end consequence: a trivy finding with an ABSOLUTE path under a skip-named
        # ancestor must SURVIVE when `target` is that repo root (else real secrets vanish on
        # anyone whose repo lives under e.g. ~/dev/vendor-portal/ or a .claude worktree).
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "vendor" / "app"        # 'vendor' ancestor
            (root / "src").mkdir(parents=True)
            abs_file = str(root / "src" / "config.ts")
            trivy = {"Results": [{"Target": abs_file, "Secrets": [
                {"RuleID": "private-key", "Title": "k", "Match": "-----BEGIN", "StartLine": 1}]}]}
            (root / "trivy.json").write_text(json.dumps(trivy))
            res = [{"key": "trivy", "output": str(root / "trivy.json"), "name": "Trivy", "category": "sca"}]
            summary = scanners.normalize_findings(res, root, target=root)
            files = [f["file"] for f in json.loads((root / "findings.json").read_text())]
        self.assertIn(abs_file, files)               # NOT dropped despite the 'vendor' ancestor
        self.assertEqual(summary["contamination_dropped"], 0)

    def test_exclude_dirs_includes_agent_tooling(self):
        self.assertIn(".claude", scanners.EXCLUDE_DIRS)
        self.assertIn(".worktrees", scanners.EXCLUDE_DIRS)

    def test_normalize_drops_skipdir_contamination(self):
        trivy = {"Results": [
            {"Target": ".claude/worktrees/copy/websec-out/scanners/gitleaks.json",
             "Secrets": [{"RuleID": "aws", "Title": "AWS key", "Match": "AKIA" + "A" * 16, "StartLine": 1}]},
            {"Target": "src/app/route.ts",
             "Secrets": [{"RuleID": "aws", "Title": "AWS key", "Match": "AKIA" + "B" * 16, "StartLine": 1}]},
        ]}
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "trivy.json").write_text(json.dumps(trivy))
            res = [{"key": "trivy", "output": str(d / "trivy.json"), "name": "Trivy", "category": "sca"}]
            summary = scanners.normalize_findings(res, d, target=None)
            files = [f["file"] for f in json.loads((d / "findings.json").read_text())]
        self.assertIn("src/app/route.ts", files)
        self.assertNotIn(".claude/worktrees/copy/websec-out/scanners/gitleaks.json", files)
        self.assertEqual(summary["contamination_dropped"], 1)

    @unittest.skipUnless(shutil.which("git"), "git required")
    def test_gitignored_secret_is_downgraded(self):
        trivy = {"Results": [
            {"Target": "secret.local",
             "Secrets": [{"RuleID": "aws", "Title": "AWS key", "Match": "AKIA" + "C" * 16, "StartLine": 1}]},
            {"Target": "src/real.ts",
             "Secrets": [{"RuleID": "aws", "Title": "AWS key", "Match": "AKIA" + "D" * 16, "StartLine": 1}]},
        ]}
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            subprocess.run(["git", "init", "-q", str(d)], check=True)
            (d / ".gitignore").write_text("*.local\n")
            out = d / "out"
            out.mkdir()
            (out / "trivy.json").write_text(json.dumps(trivy))
            res = [{"key": "trivy", "output": str(out / "trivy.json"), "name": "Trivy", "category": "sca"}]
            summary = scanners.normalize_findings(res, out, target=d)
            by_file = {f["file"]: f for f in json.loads((out / "findings.json").read_text())}
        self.assertEqual(by_file["secret.local"]["severity"], "LOW")           # gitignored → downgraded
        self.assertIn("local-only", by_file["secret.local"]["title"])
        self.assertEqual(by_file["src/real.ts"]["severity"], "HIGH")           # tracked → unchanged
        self.assertEqual(summary["local_only_downgraded"], 1)

    def test_user_exclude_reaches_scanner_findings(self):
        # DocGuard field report F2: `--exclude 'tests/**'` was honored by recon but gitleaks
        # findings under tests/ still surfaced as HIGH. Gitleaks has no path-exclude flag, so
        # the normalize_findings post-filter must enforce the user contract.
        gl = [{"RuleID": "stripe-access-token", "Description": "Stripe Access Token",
               "File": "tests/security.test.mjs", "StartLine": 3, "Secret": "sk_live_x", "Match": "sk_live_x"},
              {"RuleID": "stripe-access-token", "Description": "Stripe Access Token",
               "File": "src/billing.ts", "StartLine": 9, "Secret": "sk_live_y", "Match": "sk_live_y"}]
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "gitleaks.json").write_text(json.dumps(gl))
            res = [{"key": "gitleaks", "output": str(d / "gitleaks.json"),
                    "name": "Gitleaks", "category": "secrets"}]
            summary = scanners.normalize_findings(res, d, target=d, excludes=["tests/**"])
            files = [f["file"] for f in json.loads((d / "findings.json").read_text())]
        self.assertNotIn("tests/security.test.mjs", files)   # excluded — the fixed contract
        self.assertIn("src/billing.ts", files)               # product finding survives
        self.assertEqual(summary["user_excluded_dropped"], 1)

    def test_user_exclude_matches_absolute_paths_and_bare_dirs(self):
        # Trivy/Semgrep can emit ABSOLUTE paths; a bare-dir exclude ('tests') must match via
        # the same substring semantics RepoContext._excluded uses for recon.
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            abs_file = str(d / "tests" / "fixture.py")
            trivy = {"Results": [{"Target": abs_file, "Secrets": [
                {"RuleID": "aws-access-token", "Title": "AWS key",
                 "Match": "AKIA" + "E" * 16, "StartLine": 1}]}]}
            (d / "trivy.json").write_text(json.dumps(trivy))
            res = [{"key": "trivy", "output": str(d / "trivy.json"), "name": "Trivy", "category": "sca"}]
            summary = scanners.normalize_findings(res, d, target=d, excludes=["tests"])
            files = [f["file"] for f in json.loads((d / "findings.json").read_text())]
        self.assertEqual(files, [])
        self.assertEqual(summary["user_excluded_dropped"], 1)

    def test_no_excludes_drops_nothing(self):
        gl = [{"RuleID": "stripe-access-token", "Description": "Stripe Access Token",
               "File": "tests/security.test.mjs", "StartLine": 3, "Secret": "sk_live_x", "Match": "sk_live_x"}]
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "gitleaks.json").write_text(json.dumps(gl))
            res = [{"key": "gitleaks", "output": str(d / "gitleaks.json"),
                    "name": "Gitleaks", "category": "secrets"}]
            summary = scanners.normalize_findings(res, d, target=d)
        self.assertEqual(summary["user_excluded_dropped"], 0)
        self.assertEqual(summary["total"], 1)


class FixtureScopingTests(unittest.TestCase):
    """DocGuard field report F1: test/example/fixture code is not the product's attack surface."""

    GL = [{"RuleID": "stripe-access-token", "Description": "Stripe Access Token",
           "File": "tests/security.test.mjs", "StartLine": 3, "Secret": "sk_live_x", "Match": "sk_live_x"},
          {"RuleID": "stripe-access-token", "Description": "Stripe Access Token",
           "File": "src/billing.ts", "StartLine": 9, "Secret": "sk_live_y", "Match": "sk_live_y"}]

    def _normalize(self, include_fixtures):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "gitleaks.json").write_text(json.dumps(self.GL))
            res = [{"key": "gitleaks", "output": str(d / "gitleaks.json"),
                    "name": "Gitleaks", "category": "secrets"}]
            summary = scanners.normalize_findings(res, d, target=d,
                                                  include_fixtures=include_fixtures)
            by_file = {f["file"]: f for f in json.loads((d / "findings.json").read_text())}
        return summary, by_file

    def test_fixture_secret_demoted_not_dropped(self):
        summary, by_file = self._normalize(include_fixtures=False)
        f = by_file["tests/security.test.mjs"]
        self.assertEqual(f["severity"], "LOW")                    # demoted...
        self.assertIn("test/fixture", f["title"])                 # ...and annotated
        self.assertEqual(by_file["src/billing.ts"]["severity"], "HIGH")   # product secret untouched
        self.assertEqual(summary["test_fixture_downgraded"], 1)

    def test_include_fixtures_keeps_full_severity(self):
        summary, by_file = self._normalize(include_fixtures=True)
        self.assertEqual(by_file["tests/security.test.mjs"]["severity"], "HIGH")
        self.assertEqual(summary["test_fixture_downgraded"], 0)

    def test_fixture_routes_split_out_but_kept_in_facts(self):
        from websec_validator.extractors import routes
        from websec_validator.extractors.base import RepoContext
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "examples").mkdir()
        (d / "tests").mkdir()
        (d / "src" / "index.js").write_text("router.get('/api/real', h);\n")
        (d / "examples" / "app.js").write_text("router.post('/api/demo', h);\n")
        (d / "tests" / "server.test.js").write_text("router.get('/api/test-only', h);\n")
        with mock.patch.object(routes, "_noir_scan", return_value=None):
            out = routes.RoutesExtractor().extract(RepoContext(d), {})
            inc = routes.RoutesExtractor().extract(RepoContext(d, include_fixtures=True), {})
        paths = {e["path"] for e in out["endpoints"]}
        self.assertEqual(paths, {"/api/real"})                    # fixtures out of the surface
        self.assertEqual(out["fixture_excluded"], 2)
        fx = {e["path"] for e in out["fixture_endpoints"]}
        self.assertEqual(fx, {"/api/demo", "/api/test-only"})     # ...but kept, auditable
        self.assertIn("fixture_note", out)
        inc_paths = {e["path"] for e in inc["endpoints"]}
        self.assertEqual(inc_paths, {"/api/real", "/api/demo", "/api/test-only"})
        self.assertNotIn("fixture_excluded", inc)

    def test_tenant_ignores_fixture_files(self):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "tests").mkdir()
        (d / "src" / "app.js").write_text("const x = 1;\n")
        (d / "tests" / "app.test.js").write_text("groupId; groupId; groupId; groupId;\n")
        got = TenantExtractor().extract(RepoContext(d), {"routes": {"endpoints": []}})
        self.assertEqual(got["candidates"], [])                   # fixture-only key → no candidate
        inc = TenantExtractor().extract(RepoContext(d, include_fixtures=True),
                                        {"routes": {"endpoints": []}})
        self.assertTrue(any(c["key"] == "groupId" for c in inc["candidates"]))


class CrossTenantNumericIdTests(unittest.TestCase):
    def test_numeric_tenant_id_does_not_crash(self):
        # fix #6: tenant ids are often numeric (auto-increment); str.replace's 2nd arg must be a str,
        # so an int tenant would crash this authenticated path uncaught. Coerce with str().
        cfg = {"target": "http://t", "tenant_path_param": "groupId", "roles": {}}
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/api/groups/{groupId}/items"}]}}
        captured = []

        def fake_mint(c, role):
            return {"token": f"tok-{role}", "tenant": 1 if role == "agentA" else 2, "email": f"{role}@x"}

        def fake_request(method, url, token=None, timeout=20, data=None, cookie=None):
            captured.append(url)
            return 403, "x"
        with mock.patch.object(dynamic, "mint", fake_mint), mock.patch.object(dynamic, "_request", fake_request):
            r = dynamic.cross_tenant_bola(cfg, facts)
        self.assertNotIn("error", r)                                  # numeric ids didn't crash the replace
        self.assertTrue(any(u.endswith("/api/groups/2/items") for u in captured))  # int coerced into the path


class WriteAuthEnforcement500Tests(unittest.TestCase):
    def test_500_is_inconclusive_not_no_auth_gate(self):
        # a 500 may be the AUTH layer throwing, not the handler running unauth — must NOT become a
        # no-auth-gate verdict (would escalate to a HIGH missing-auth finding AND poison the
        # calibration oracle with a confirmed-real sample). Matches the forged-token engine.
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/x"}]}}

        def fake(method, url, token=None, timeout=20, data=None, cookie=None):
            return 500, "err"
        with mock.patch.object(dynamic, "_request", fake):
            r = dynamic.write_auth_enforcement("http://t", facts)
        self.assertEqual(r["results"][0]["verdict"], "http-500")     # inconclusive, not no-auth-gate
        self.assertEqual(r["no_auth_gate"], [])                       # so it feeds no missing-auth finding
        self.assertEqual(calibration.samples_from_dynamic({"write_auth_enforcement": r}), [])  # oracle clean

    def test_400_still_no_auth_gate(self):  # regression guard: real reached-handler codes unaffected
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/y"}]}}

        def fake(method, url, token=None, timeout=20, data=None, cookie=None):
            return 400, "bad"
        with mock.patch.object(dynamic, "_request", fake):
            r = dynamic.write_auth_enforcement("http://t", facts)
        self.assertTrue(r["results"][0]["verdict"].startswith("no-auth-gate"))


class ProbeRegistrationTests(unittest.TestCase):
    def test_auth_probes_gated_by_scheme(self):
        # P2: forged-token forges into bearer OR signed cookie → staged for token/cookie auth, NOT
        # for an app with no detected auth scheme. JWT-specific probes need actual JWT presence.
        self.assertIn("forged-token", probes.PROBES)
        self.assertIn("forged-token", probes.applicable({"auth": {"signal_counts": {"jwt": 2}}}))
        self.assertIn("forged-token", probes.applicable(
            {"auth": {"scheme": "hmac-signed-cookie", "signal_counts": {"hmac": 3}}}))
        self.assertNotIn("forged-token", probes.applicable({"routes": {"targeting": {}}}))
        # jwt-attacks / hs256 only when JWT is actually present (not for an HMAC-cookie app)
        self.assertNotIn("jwt-attacks", probes.applicable(
            {"auth": {"signal_counts": {"hmac": 3}, "cookie_names": ["sid"]}}))
        self.assertIn("hs256-brute-force", probes.applicable({"auth": {"signal_counts": {"jwt": 2}}}))

    def test_context_has_reads(self):
        ctx = probes.build_context({"routes": {"endpoints": [
            {"method": "GET", "path": "/api/a"}, {"method": "POST", "path": "/api/b"}], "targeting": {}}, "auth": {}})
        self.assertIn("reads", ctx["endpoints"])
        self.assertEqual(ctx["endpoints"]["reads"], ["GET /api/a"])


class SecretPrecisionTests(unittest.TestCase):
    """bug-072: low-precision generic/entropy secret rules -> MEDIUM (+verify note); specific
    rules (AKIA, private-key, …) keep HIGH. Nothing is hidden."""

    def test_generic_rule_detection(self):
        self.assertTrue(scanners._generic_secret("generic-api-key"))
        self.assertTrue(scanners._generic_secret("high-entropy-string"))
        self.assertFalse(scanners._generic_secret("aws-access-token"))
        self.assertFalse(scanners._generic_secret("private-key"))

    def test_gitleaks_generic_is_medium_specific_is_high(self):
        rows = [
            {"File": "src/lib/chains.ts", "RuleID": "generic-api-key", "Secret": "x" * 40, "Match": "x" * 40, "StartLine": 1},
            {"File": "src/k.pem", "RuleID": "private-key", "Secret": "-----BEGIN", "Match": "-----BEGIN", "StartLine": 1},
            {"File": "src/a.ts", "RuleID": "aws-access-token", "Secret": "AKIA" + "A" * 16, "Match": "AKIA" + "A" * 16, "StartLine": 1},
        ]
        by = {r["key"]: r for r in scanners._norm_gitleaks(rows)}
        self.assertEqual(by["generic-api-key"]["severity"], "MEDIUM")
        self.assertIn("generic/entropy", by["generic-api-key"]["title"])
        self.assertEqual(by["private-key"]["severity"], "HIGH")          # specific rule untouched
        self.assertEqual(by["aws-access-token"]["severity"], "HIGH")     # AKIA via _aws_secret_tier

    def test_trivy_generic_secret_is_medium(self):
        data = {"Results": [{"Target": "src/x.ts", "Secrets": [
            {"RuleID": "generic-api-key", "Title": "Generic API Key", "Match": "y" * 40, "StartLine": 2}]}]}
        secs = [f for f in scanners._norm_trivy(data) if f["category"] == "secret"]
        self.assertEqual(secs[0]["severity"], "MEDIUM")

    def test_medium_secret_gets_medium_confidence_in_ledger(self):
        unified = {"top": [{"severity": "MEDIUM", "category": "secret",
                            "title": "secret: Generic API Key — generic/entropy match", "file": "src/x.ts", "tools": ["gitleaks"]}]}
        led = findings.build_ledger({}, unified, None, [])
        hit = [f for f in led["findings"] if f["category"] == "static-secret"][0]
        self.assertEqual(hit["confidence"], "MEDIUM")


class DocExampleSecretTests(unittest.TestCase):
    """0.2.8: secrets in documentation/example files (curl examples in a README, .env.example
    placeholders) tier to LOW + a verify note. Real code files are untouched."""

    def test_is_doc_or_example(self):
        self.assertTrue(scanners._is_doc_or_example("README.md"))
        self.assertTrue(scanners._is_doc_or_example("docs/API-REFERENCE.md"))
        self.assertTrue(scanners._is_doc_or_example(".env.example"))
        self.assertTrue(scanners._is_doc_or_example("config/settings.sample.json"))
        self.assertFalse(scanners._is_doc_or_example("src/app/route.ts"))

    def test_gitleaks_doc_secret_to_low_code_stays_high(self):
        rows = [
            {"File": "README.md", "RuleID": "curl-auth-header", "Secret": "x" * 30, "Match": "Authorization: Bearer x", "StartLine": 1},
            {"File": "src/server.ts", "RuleID": "private-key", "Secret": "-----BEGIN", "Match": "-----BEGIN", "StartLine": 1},
        ]
        by = {r["file"]: r for r in scanners._norm_gitleaks(rows)}
        self.assertEqual(by["README.md"]["severity"], "LOW")
        self.assertIn("documentation/example", by["README.md"]["title"])
        self.assertEqual(by["src/server.ts"]["severity"], "HIGH")  # real code file untouched

    def test_trivy_doc_secret_to_low(self):
        data = {"Results": [{"Target": "docs/SECURITY.md", "Secrets": [
            {"RuleID": "curl-auth-header", "Title": "Auth header", "Match": "Bearer x", "StartLine": 1}]}]}
        secs = [f for f in scanners._norm_trivy(data) if f["category"] == "secret"]
        self.assertEqual(secs[0]["severity"], "LOW")


class CookieCoverageTests(unittest.TestCase):
    """0.2.7: extract auth cookie names so the forged-token engine covers cookie-ONLY apps."""

    def test_extracts_cookie_names(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "auth.ts").write_text(
                "const s = request.cookies.get('myapp_session');\n"
                "const p = req.cookies['ping_id_token'];\n"
                "const x = getCookie('dynamic_authentication_token');\n")
            out = AuthExtractor().extract(RepoContext(d), {"stack": {"frameworks": []}, "routes": {}})
        names = set(out["cookie_names"])
        self.assertIn("myapp_session", names)
        self.assertIn("ping_id_token", names)
        self.assertIn("dynamic_authentication_token", names)
        self.assertNotIn("get", names)  # reserved method name filtered

    def test_forged_bypass_detected_via_cookie(self):
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/api/cookieonly"}]}}

        def fake(method, url, token=None, timeout=20, data=None, cookie=None):
            if token:
                return 401, "x"                       # Bearer rejected
            if cookie and "sess=" in cookie:
                return 200, "x"                        # forged cookie accepted (cookie-only app)
            return 401, "x"                            # no-auth baseline (gated)
        with mock.patch.object(dynamic, "_request", fake):
            r = dynamic.forged_token_bypass("http://t", facts, cookie_names=["sess"])
        self.assertEqual([b["path"] for b in r["bypassed"]], ["/api/cookieonly"])
        self.assertTrue(r["bypassed"][0]["via"].startswith("cookie:"))


class NonWebAppFPTests(unittest.TestCase):
    """0.2.9 (bug-081): on a 0-route repo (library/CLI/scanner) FLAG auth/tenant as low-confidence
    + record tenant evidence files — but NEVER suppress. Suppression would be fragile (depends on
    the optional noir route scanner) and could drop a real backend whose routes didn't parse."""

    def test_auth_low_confidence_without_routes_but_still_detected(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "patterns.ts").write_text("const RULE = 'express-session';\n")
            out = AuthExtractor().extract(RepoContext(d), {"stack": {"frameworks": []}, "routes": {"endpoints": []}})
        self.assertFalse(out["reliable_signal"])                   # 0 routes, no framework -> flagged
        self.assertIn("session-cookie", out["schemes_detected"])   # NOT suppressed
        self.assertIn("No HTTP routes", out["note"])               # caveat surfaced

    def test_auth_reliable_with_routes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "app.ts").write_text("const RULE = 'express-session';\n")
            out = AuthExtractor().extract(RepoContext(d), {"stack": {"frameworks": []},
                                                           "routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})
        self.assertTrue(out["reliable_signal"])

    def test_tenant_records_files_and_not_multitenant_without_routes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a.ts").write_text("const x = groupId; const y = groupId; const z = groupId;\n")  # x3
            out = TenantExtractor().extract(RepoContext(d), {"routes": {"endpoints": []}})
        gc = next(c for c in out["candidates"] if c["key"] == "groupId")
        self.assertIn("a.ts", gc["files"])                         # evidence recorded
        self.assertFalse(out["multi_tenant_likely"])               # 0 routes -> not asserted even at >=3

    def test_tenant_multitenant_with_routes(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "a.ts").write_text("groupId groupId groupId\n")   # x3
            out = TenantExtractor().extract(RepoContext(d), {"routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})
        self.assertTrue(out["multi_tenant_likely"])                # routes + >=3 -> asserted


class StaticAtRiskRouteTests(unittest.TestCase):
    """0.2.9 (B): routes calling a guard defined alongside an unverified decoder are listed
    statically — the forged-token bypass set, even with no live target."""

    def test_unverified_signature_routes_listed(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "auth.ts").write_text(
                "export async function requireAuth(req){ const p = decodeJwtPayloadUnsafe(t); return p; }\n")
            (d / "route.ts").write_text(
                "import {requireAuth} from './auth';\nexport async function GET(req){ await requireAuth(req); }\n")
            facts = {"routes": {"endpoints": [
                {"method": "GET", "path": "/api/x", "code_path": str(d / "route.ts")}]}}
            out = AuthzExtractor().extract(RepoContext(d), facts)
        self.assertIn("GET /api/x", out["unverified_signature_routes"])


class DeferredFixTests(unittest.TestCase):
    """0.8.1 deferred findings from the PR #8 review: Checkov wired up, secret-dedup line,
    gitignored path-normalization, dynamic-phase scalar-tenant + structural-empty verdict."""

    # P1 — Checkov output is parsed (was 100% discarded)
    def test_checkov_parser_and_count(self):
        data = [{"check_type": "terraform", "results": {"failed_checks": [
            {"check_id": "CKV_AWS_20", "check_name": "S3 bucket is public",
             "file_path": "/main.tf", "file_line_range": [10, 12], "severity": None}]}}]
        rows = scanners._norm_checkov(data)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["tool"], "checkov")
        self.assertEqual(rows[0]["category"], "iac")
        self.assertEqual(rows[0]["severity"], "MEDIUM")        # null checkov severity → MEDIUM default
        self.assertIn("checkov", scanners._PARSERS)
        p = Path(tempfile.mkdtemp()) / "checkov.json"
        p.write_text(json.dumps(data))
        self.assertEqual(scanners._count_findings("checkov", p), 1)

    # P2 — two distinct secrets (same rule+file, different lines) must not collapse
    def test_secret_dedup_keeps_distinct_secrets_same_rule(self):
        trivy = {"Results": [{"Target": ".env", "Secrets": [
            {"RuleID": "generic-api-key", "StartLine": 3, "Match": "AAA", "Title": "s1"},
            {"RuleID": "generic-api-key", "StartLine": 9, "Match": "BBB", "Title": "s2"}]}]}
        rows = scanners._norm_trivy(trivy)
        self.assertEqual(len({r["fingerprint"] for r in rows}), 2)   # distinct → second not hidden

    # P3 — git check-ignore wants repo-relative paths; trivy emits absolute
    def test_gitignored_normalizes_absolute_paths(self):
        if not shutil.which("git"):
            self.skipTest("git not available")
        d = Path(tempfile.mkdtemp())
        subprocess.run(["git", "-C", str(d), "init", "-q"], check=True)
        (d / ".gitignore").write_text(".env.local\n")
        (d / ".env.local").write_text("SECRET=x")
        abs_path = str(d / ".env.local")              # absolute, as `trivy fs <abs>` emits
        self.assertIn(abs_path, scanners._gitignored(d, [abs_path]))

    # P4a — mint() no longer crashes on a scalar tenant id
    def test_first_tenant_scalar_and_list(self):
        self.assertEqual(dynamic._first_tenant([5, 6]), 5)
        self.assertEqual(dynamic._first_tenant(5), 5)             # was `5[0]` → TypeError
        self.assertEqual(dynamic._first_tenant("acme"), "acme")   # not a single char
        self.assertIsNone(dynamic._first_tenant(None))
        self.assertIsNone(dynamic._first_tenant([]))

    # P4b — LEAK verdict is structural, not a string allowlist
    def test_no_records_structural_emptiness(self):
        for empty in ("[]", "{}", '{"data":[]}', '{ "data": [] }', '{"items":[],"total":0}',
                      '{"data":[],"total":0,"page":1}', "   "):
            self.assertTrue(dynamic._no_records(empty), f"should read empty: {empty}")
        for has_data in ('[{"id":1}]', '{"data":[{"id":1}]}', '{"items":[{"x":1}]}'):
            self.assertFalse(dynamic._no_records(has_data), f"should read data: {has_data}")
        self.assertFalse(dynamic._no_records("not-json"))         # opaque → treat as a lead, don't mask


if __name__ == "__main__":
    unittest.main()


class HistoryOnlySecretTests(unittest.TestCase):
    """A committed secret whose file was later DELETED is still leaked — say so explicitly."""

    def test_missing_file_is_tagged_history_only(self):
        with tempfile.TemporaryDirectory() as d:
            raw = [{"tool": "gitleaks", "category": "secret", "file": "deleted.js",
                    "title": "secret: token"}]
            n = scanners._annotate_history_only_secrets(raw, Path(d))
        self.assertEqual(n, 1)
        self.assertTrue(raw[0]["history_only"])
        self.assertIn("HISTORY-ONLY", raw[0]["title"])
        self.assertIn("rotated", raw[0]["title"].lower())

    def test_file_still_present_is_not_tagged(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "live.js").write_text("x")
            raw = [{"tool": "gitleaks", "category": "secret", "file": "live.js",
                    "title": "secret: token"}]
            n = scanners._annotate_history_only_secrets(raw, Path(d))
        self.assertEqual(n, 0)
        self.assertNotIn("history_only", raw[0])

    def test_guard_is_the_field_not_a_title_substring(self):
        # regression: provider notes already say "...does NOT scrub pushed history", which a
        # substring guard mistook for "already annotated" and silently skipped the tag.
        with tempfile.TemporaryDirectory() as d:
            raw = [{"tool": "gitleaks", "category": "secret", "file": "gone.js",
                    "title": "secret: token — ROTATE FIRST; deleting does NOT scrub pushed history."}]
            n = scanners._annotate_history_only_secrets(raw, Path(d))
        self.assertEqual(n, 1)                       # still tagged despite 'history' in the title
        self.assertTrue(raw[0]["history_only"])

    def test_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            raw = [{"tool": "gitleaks", "category": "secret", "file": "gone.js", "title": "s"}]
            scanners._annotate_history_only_secrets(raw, Path(d))
            n2 = scanners._annotate_history_only_secrets(raw, Path(d))
        self.assertEqual(n2, 0)                      # no double-append
        self.assertEqual(raw[0]["title"].count("HISTORY-ONLY"), 1)

    def test_trivy_secrets_are_not_tagged(self):
        # trivy scans the WORKING TREE, so "file missing" carries no history meaning there.
        with tempfile.TemporaryDirectory() as d:
            raw = [{"tool": "trivy", "category": "secret", "file": "gone.js", "title": "s"}]
            n = scanners._annotate_history_only_secrets(raw, Path(d))
        self.assertEqual(n, 0)


class VerifySecretsOptInTests(unittest.TestCase):
    """TruffleHog live verification — powerful, but it egresses credentials, so it is OPT-IN ONLY."""

    def _run(self, **kw):
        with mock.patch.object(scanners.shutil, "which", return_value="/usr/bin/x"), \
             mock.patch.object(scanners.subprocess, "run") as m, \
             tempfile.TemporaryDirectory() as d:
            m.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            return [r["key"] for r in scanners.run_available(Path(d), Path(d), ["python"], **kw)]

    def test_never_runs_by_default_even_when_installed(self):
        # THE safety property: verification sends the found credential to a third-party API. It must
        # never happen because the binary merely exists on PATH.
        self.assertNotIn("trufflehog", self._run())

    def test_runs_only_when_explicitly_opted_in(self):
        self.assertIn("trufflehog", self._run(verify_secrets=True))

    def test_verified_secret_outranks_unverified(self):
        rows = scanners._norm_trufflehog([
            {"DetectorName": "AWS", "Verified": True,
             "SourceMetadata": {"Data": {"Filesystem": {"file": "a.py", "line": 3}}}},
            {"DetectorName": "Slack", "Verified": False,
             "SourceMetadata": {"Data": {"Filesystem": {"file": "b.py", "line": 9}}}},
        ])
        self.assertEqual(rows[0]["severity"], "CRITICAL")     # authenticated against the provider
        self.assertTrue(rows[0]["verified"])
        self.assertIn("VERIFIED LIVE", rows[0]["title"])
        self.assertEqual(rows[1]["severity"], "MEDIUM")       # matched, liveness unproven
        self.assertFalse(rows[1]["verified"])

    def test_jsonl_counting_does_not_use_whole_file_json(self):
        # trufflehog emits JSON-LINES; a whole-file json.loads raises and would silently report 0.
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "trufflehog.json"
            f.write_text('{"DetectorName":"AWS","Verified":true}\n{"DetectorName":"GH"}\n')
            self.assertEqual(scanners._count_findings("trufflehog", f), 2)

    def test_jsonl_is_parsed_by_normalize(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "trufflehog.json").write_text(
                '{"DetectorName":"AWS","Verified":true,'
                '"SourceMetadata":{"Data":{"Filesystem":{"file":"a.py","line":1}}}}\n'
                'not-json-progress-line\n')
            res = scanners.normalize_findings(
                [{"key": "trufflehog", "output": str(d / "trufflehog.json"),
                  "name": "TruffleHog", "category": "secrets"}], d, target=d)
        self.assertEqual(res["total"], 1)                     # parsed despite the junk line
        self.assertEqual(res["by_severity"].get("CRITICAL"), 1)

    def test_registered_as_opt_in(self):
        self.assertIn("trufflehog", scanners._OPT_IN_SCANNERS)


class RedirectAuthJudgmentTests(unittest.TestCase):
    """Field report: `websec dynamic --unauth` reported 26 endpoints (incl. /api/platform-admin/
    secrets) as OPEN-no-auth because _request followed a 307 → /login and scored the login page's
    200. A redirect-to-login is the app CORRECTLY refusing access; it must never read as 'open'."""

    def _server(self):
        import http.server
        import socketserver
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _login(self):
                b = b"<html><body>Please log in</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                if self.path == "/login":
                    self._login()
                else:
                    self.send_response(307)
                    self.send_header("Location", "/login")
                    self.end_headers()

            def do_POST(self):
                self.send_response(307)
                self.send_header("Location", "/login")
                self.end_headers()

        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def test_request_does_not_follow_redirects(self):
        base = self._server()
        code, body = dynamic._request("GET", base + "/api/secrets", token=None, timeout=5)
        self.assertEqual(code, 307)                          # the real status, not the login 200
        self.assertNotIn("log in", body.lower())             # never the login page body

    def test_unauth_reachability_scores_redirect_as_protected_not_open(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/api/platform-admin/secrets"}]}}
        r = dynamic.unauth_reachability(base, facts)
        self.assertEqual(r["open_no_auth"], [])              # THE bug: was reported OPEN
        self.assertEqual(r["results"][0]["verdict"], "redirect (likely to login)")
        self.assertEqual(r["results"][0]["status"], 307)

    def test_write_enforcement_scores_redirect_as_enforced_not_executed(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/users"}]}}
        r = dynamic.write_auth_enforcement(base, facts)
        self.assertEqual(r["executed_unauth"], [])           # was a CRITICAL false positive
        self.assertEqual(r["results"][0]["verdict"], "auth-enforced")

    def test_forged_token_redirect_is_not_a_bypass(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/api/admin"}]}}
        r = dynamic.forged_token_bypass(base, facts)
        self.assertEqual(r.get("bypassed", []), [])          # 307 ∉ _REACHED_HANDLER


class AuthVerdictMatrixTests(unittest.TestCase):
    """End-to-end verdict matrix against a REAL server covering every auth-response shape.

    The bug-208 fix must not OVER-correct: a genuinely open endpoint has to stay caught. This runs
    all shapes at once so a future change that silences true positives (or resurrects the redirect
    FP) fails here. No mocking of _request — mocked tests are what let bug-208 ship."""

    PATHS = ["/api/public-data", "/api/protected", "/api/redirected",
             "/api/flaky", "/api/throttled", "/api/empty"]

    def _server(self):
        import http.server
        import json as _json
        import socketserver
        import threading

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, body=b"", ctype="application/json"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def route(self):
                p = self.path
                if p == "/login":
                    return self._send(200, b"<html>login</html>", "text/html")
                if p == "/api/public-data":            # genuinely unauthenticated data
                    return self._send(200, _json.dumps({"items": [1, 2, 3]}).encode())
                if p == "/api/protected":
                    return self._send(401, b'{"error":"unauthorized"}')
                if p == "/api/redirected":             # protected VIA redirect (bug-208)
                    self.send_response(307)
                    self.send_header("Location", "/login")
                    self.end_headers()
                    return
                if p == "/api/flaky":
                    return self._send(500, b'{"error":"boom"}')
                if p == "/api/throttled":
                    return self._send(429, b'{"error":"slow down"}')
                if p == "/api/empty":
                    return self._send(200, b"")
                return self._send(404, b'{"error":"nf"}')

            do_GET = do_POST = route

        srv = socketserver.TCPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return f"http://127.0.0.1:{srv.server_address[1]}"

    def test_unauth_reachability_verdict_matrix(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "GET", "path": p} for p in self.PATHS]}}
        by = {r["path"]: r for r in dynamic.unauth_reachability(base, facts)["results"]}
        self.assertEqual(by["/api/public-data"]["verdict"], "OPEN-no-auth")   # TRUE positive kept
        self.assertEqual(by["/api/protected"]["verdict"], "protected")
        self.assertEqual(by["/api/redirected"]["verdict"], "redirect (likely to login)")
        self.assertEqual(by["/api/empty"]["verdict"], "open-empty")
        self.assertTrue(by["/api/flaky"]["verdict"].startswith("http-"))      # 500 inconclusive
        self.assertTrue(by["/api/throttled"]["verdict"].startswith("http-"))  # 429 not "open"

    def test_only_the_genuinely_open_endpoint_is_flagged_open(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "GET", "path": p} for p in self.PATHS]}}
        r = dynamic.unauth_reachability(base, facts)
        self.assertEqual([x["path"] for x in r["open_no_auth"]], ["/api/public-data"])

    def test_write_enforcement_verdict_matrix(self):
        base = self._server()
        facts = {"routes": {"endpoints": [{"method": "POST", "path": p} for p in self.PATHS]}}
        by = {r["path"]: r for r in dynamic.write_auth_enforcement(base, facts)["results"]}
        self.assertEqual(by["/api/public-data"]["verdict"], "EXECUTED-UNAUTH")  # TRUE positive kept
        self.assertEqual(by["/api/protected"]["verdict"], "auth-enforced")
        self.assertEqual(by["/api/redirected"]["verdict"], "auth-enforced")     # bug-208
        self.assertTrue(by["/api/flaky"]["verdict"].startswith("http-"))        # 500 NOT "no gate"
        self.assertTrue(by["/api/throttled"]["verdict"].startswith("http-"))
