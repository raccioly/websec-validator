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

from websec_validator import dynamic, findings, probes, scanners  # noqa: E402

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


class ScannerHygieneTests(unittest.TestCase):
    def test_in_skip_dir(self):
        self.assertTrue(scanners._in_skip_dir(".claude/worktrees/x/gitleaks.json"))
        self.assertTrue(scanners._in_skip_dir("node_modules/dep/a.js"))
        self.assertFalse(scanners._in_skip_dir("src/app/api/route.ts"))

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


class ProbeRegistrationTests(unittest.TestCase):
    def test_forged_token_always_staged(self):
        self.assertIn("forged-token", probes.ALWAYS)
        self.assertIn("forged-token", probes.PROBES)
        self.assertIn("forged-token", probes.applicable({"routes": {"targeting": {}}}))

    def test_context_has_reads(self):
        ctx = probes.build_context({"routes": {"endpoints": [
            {"method": "GET", "path": "/api/a"}, {"method": "POST", "path": "/api/b"}], "targeting": {}}, "auth": {}})
        self.assertIn("reads", ctx["endpoints"])
        self.assertEqual(ctx["endpoints"]["reads"], ["GET /api/a"])


if __name__ == "__main__":
    unittest.main()
