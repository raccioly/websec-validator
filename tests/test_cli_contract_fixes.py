"""CLI-contract regressions: exit codes, default run lookup, graph input and user-facing text.

The documented contract (cli.py EXIT_*; docs/reference/cli.md "Exit codes"):
  0 clean · 1 findings · 2 usage/configuration error (nothing scanned) · 3 checks did not complete.
Every test here failed against the code it pins a fix for.
"""
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from websec_validator import agenthook, calibration, cli, dynamic, findings, gate, graph_enrich  # noqa: E402


class _Workspace(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text('print("synthetic")\n')
        self.out = self.base / "out"

    def main(self, *argv):
        """Run the CLI in-process; return (exit_code, stdout, stderr). SystemExit is an exit code."""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr), \
                patch("shutil.which", return_value=None):
            try:
                code = cli.main(list(argv))
            except SystemExit as exit_:
                code = exit_.code
        return code, stdout.getvalue(), stderr.getvalue()

    def run_scan(self, *extra):
        return self.main("run", str(self.repo), "--out", str(self.out), *extra)

    def attempt(self, name):
        attempt = max((self.out / "runs").iterdir(), key=lambda path: path.stat().st_mtime_ns)
        return json.loads((attempt / name).read_text())


# ---- H1: usage/configuration errors exit 2, never 1 (the FINDINGS code) ----------------------
class UsageErrorsExitTwoTests(_Workspace):
    def test_no_string_sys_exit_remains_in_cli(self):
        # sys.exit("message") exits 1. A new one would silently re-open this defect.
        source = (ROOT / "src" / "websec_validator" / "cli.py").read_text()
        self.assertEqual(re.findall(r"^\s*sys\.exit\(\s*f?[\"']", source, re.MULTILINE), [])

    def test_target_that_is_not_a_directory_exits_2_with_message_on_stderr(self):
        missing = str(self.base / "nope")
        for command in ("run", "recon", "init", "doctor", "emit-context"):
            with self.subTest(command=command):
                code, _, err = self.main(command, missing)
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn("target is not a directory", err)

    def test_real_process_exits_2_and_prints_the_message_once(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
        proc = subprocess.run([sys.executable, "-m", "websec_validator.cli", "run", str(self.base / "nope")],
                              capture_output=True, text=True, env=env, cwd=self.base, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stderr.count("target is not a directory"), 1)

    def _facts(self):
        self.assertEqual(self.run_scan()[0], 0)
        return str(self.out / "latest" / "FACTS.json")

    def test_dynamic_argument_errors_exit_2_and_reserve_no_run(self):
        facts = self._facts()
        runs_before = sorted((self.out / "runs").iterdir())
        cases = {
            "--unauth requires --target": ["--unauth"],
            "localhost-only": ["--unauth", "--probe-writes", "--target", "https://example.invalid"],
            "config not found": ["--config", str(self.base / "missing.json")],
            "provide --config": [],
        }
        for message, extra in cases.items():
            with self.subTest(message=message):
                code, _, err = self.main("dynamic", "--facts", facts, "--out", str(self.out), *extra)
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn(message, err)
        # A usage error scans nothing, so it must leave no (empty, partial-looking) attempt behind.
        self.assertEqual(sorted((self.out / "runs").iterdir()), runs_before)

    def test_dynamic_missing_facts_exits_2(self):
        code, _, err = self.main("dynamic", "--facts", str(self.base / "none.json"), "--unauth",
                                 "--target", "http://127.0.0.1:9")
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("FACTS.json not found", err)

    def test_malformed_dynamic_inputs_exit_2_and_reserve_no_run(self):
        facts = self.base / "FACTS.json"
        facts.write_text("{}")
        bad = self.base / "bad.json"
        bad.write_text("{not json")
        incomplete = self.base / "incomplete.json"
        incomplete.write_text(json.dumps({"target": "http://127.0.0.1:1"}))
        cases = {"--config is not readable JSON": ["--config", str(bad), "--facts", str(facts)],
                 "missing required field(s): roles": ["--config", str(incomplete), "--facts", str(facts)],
                 "FACTS.json is not readable JSON": ["--unauth", "--target", "http://127.0.0.1:1",
                                                     "--facts", str(bad)]}
        for message, extra in cases.items():
            with self.subTest(message=message):
                code, _, err = self.main("dynamic", "--out", str(self.out), *extra)
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn(message, err)
                self.assertFalse((self.out / "runs").exists() and any((self.out / "runs").iterdir()))

    def test_calibrate_argument_errors_exit_2(self):
        ledger = self.base / "ledger.json"
        ledger.write_text("{}")
        cases = {
            "--ingest-dast report not found": ["--ingest-dast", str(self.base / "none.json"),
                                               "--ledger", str(ledger)],
            "needs --ledger": ["--ingest-dast", str(ledger)],
            "--ingest file not found": ["--ingest", str(self.base / "none.json")],
        }
        for message, extra in cases.items():
            with self.subTest(message=message):
                code, _, err = self.main("calibrate", *extra)
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn(message, err)

    def test_malformed_calibrate_inputs_exit_2_not_a_traceback(self):
        bad = self.base / "bad.json"
        bad.write_text("{not json")
        ledger = self.base / "ledger.json"
        ledger.write_text("{}")
        cases = {"--ingest file": ["--ingest", str(bad)],
                 "--ingest-dast report": ["--ingest-dast", str(bad), "--ledger", str(ledger)],
                 "--ledger": ["--ingest-dast", str(ledger), "--ledger", str(bad)]}
        for label, extra in cases.items():
            with self.subTest(label=label):
                code, _, err = self.main("calibrate", *extra)
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn(f"{label} is not readable JSON", err)

    def test_calibrate_that_measured_nothing_is_incomplete_not_findings(self):
        corpus = self.base / "corpus.json"
        corpus.write_text(json.dumps([{"name": "nothing", "truth": [{"attack_class": "ssrf"}]}]))
        with patch("websec_validator.proof._ensure_repo", return_value=None):
            code, out, _ = self.main("calibrate", "--corpus", str(corpus), "--workdir", str(self.base / "w"),
                                     "--out", str(self.base / "cal.json"))
        self.assertEqual(code, 3)
        self.assertIn("no labeled findings produced", out)
        self.assertFalse((self.base / "cal.json").exists())

    def test_calibrate_unwritable_overlay_exits_2(self):
        labels = self.base / "labels.json"
        labels.write_text(json.dumps([{"attack_class": "ssrf", "is_real": True}]))
        with patch.object(calibration, "record_samples", return_value=None):
            code, _, err = self.main("calibrate", "--ingest", str(labels))
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("nothing ingested", err)

    def test_calibrate_non_reproducible_claimspec_exits_2_and_keeps_its_message(self):
        with patch.object(calibration, "load", return_value={"by_label": {}}), \
                patch.object(calibration, "to_claimspec", side_effect=ValueError("stale ci")):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                cli.main(["calibrate", "--claimspec", str(self.base / "x.json")])
        self.assertEqual(caught.exception.code, cli.EXIT_USAGE)
        self.assertIn("non-reproducible", str(caught.exception))


# ---- H2 + H3: dynamic gates on dynamic evidence, and a definite finding outranks incomplete ----
class DynamicGateTests(_Workspace):
    def setUp(self):
        super().setUp()
        self.assertEqual(self.run_scan()[0], 0)
        facts = json.loads((self.out / "latest" / "FACTS.json").read_text())
        # A STATIC CRITICAL that `websec run` already gated: dev placeholder secret + JWT signing.
        facts.setdefault("auth", {})["insecure_secret_defaults"] = [
            {"file": "app.py", "literal": "dev-secret", "dev_ish": True, "env_var": "JWT_SECRET"}]
        facts["auth"]["signal_counts"] = {"jwt": 1}
        self.facts = self.base / "FACTS.json"
        self.facts.write_text(json.dumps(facts))
        self.config = self.base / "dynamic.json"
        self.config.write_text(json.dumps({"target": "http://127.0.0.1:1",
                                           "roles": {"a": {}, "b": {}}}))  # shape only; engine is mocked
        ledger = findings.build_ledger(facts, None, None)
        self.assertEqual(ledger["by_severity"].get("CRITICAL"), 1, "fixture must carry one static CRITICAL")

    def dynamic(self, *extra, unauth=None, bola=None):
        args = ["dynamic", "--facts", str(self.facts), "--out", str(self.out)]
        with patch.object(dynamic, "run_unauth", return_value=unauth), \
                patch.object(dynamic, "run_dynamic", return_value=bola):
            return self.main(*args, *extra)

    @staticmethod
    def leak(**extra):
        return {"cross_tenant_bola": {
            "agentA": {"email": "a@example.invalid", "tenant": "t1"},
            "agentB": {"email": "b@example.invalid", "tenant": "t2"}, "summary": "1 leak",
            "leaks": [{"direction": "A->B", "path": "/api/orders", "status": 200,
                       "state": "confirmed-vulnerable", "evidence_verified": True,
                       "controls": {"identity": True, "owner": True, "private": True}}], **extra}}

    def test_passing_dynamic_checks_exit_0_despite_a_static_critical(self):
        clean = {"unauth_reachability": {"target": "http://127.0.0.1:9", "summary": "all protected",
                                         "results": [], "state": "completed"}}
        code, out, _ = self.dynamic("--unauth", "--target", "http://127.0.0.1:9", unauth=clean)
        self.assertEqual(code, cli.EXIT_OK)
        gate_ = self.attempt("findings-ledger.json")["gate"]
        self.assertEqual(gate_["verdict"], "pass")
        self.assertEqual(gate_["static_findings_not_gated"], 1)
        self.assertIn("static CRITICAL", out)

    def test_confirmed_leak_with_incomplete_checks_exits_1_and_records_both(self):
        code, _, err = self.dynamic("--config", str(self.config), bola=self.leak(inconclusive=1))
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertIn("ALSO incomplete", err)
        gate_ = self.attempt("findings-ledger.json")["gate"]
        self.assertEqual(gate_["failure_kind"], "findings+incomplete")
        self.assertEqual(gate_["count_at_or_above"], 1)

    def test_confirmed_leak_on_complete_checks_exits_1(self):
        code, _, _ = self.dynamic("--config", str(self.config), bola=self.leak())
        self.assertEqual(code, cli.EXIT_FINDINGS)
        self.assertEqual(self.attempt("findings-ledger.json")["gate"]["failure_kind"], "findings")

    def test_static_critical_with_incomplete_checks_exits_3(self):
        unreachable = {"unauth_reachability": {"target": "http://127.0.0.1:9", "state": "inconclusive",
                                               "summary": "unreachable", "results": []}}
        code, _, _ = self.dynamic("--unauth", "--target", "http://127.0.0.1:9", unauth=unreachable)
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertEqual(self.attempt("findings-ledger.json")["gate"]["failure_kind"], "incomplete")


# ---- J: attest defaults to the published `latest`, never to a partial attempt -----------------
class AttestDefaultRunTests(_Workspace):
    def attest(self):
        return self.main("attest", "--out", str(self.out), "--repo", str(self.repo), "--format", "json")

    def test_default_is_the_published_latest_not_the_last_directory(self):
        self.assertEqual(self.run_scan()[0], 0)
        latest = (self.out / "latest").resolve()
        partial = self.out / "runs" / "99991231-235959-partial"
        partial.mkdir()
        (partial / "findings-ledger.json").write_text("{}")
        code, out, _ = self.attest()
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["observed"]["run_directory"], str(latest))

    def test_only_unpublished_attempts_is_incomplete_not_a_silent_pick(self):
        partial = self.out / "runs" / "20260101-000000-partial"
        partial.mkdir(parents=True)
        (partial / "findings-ledger.json").write_text("{}")
        code, out, err = self.attest()
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        self.assertEqual(out, "")
        self.assertIn("no completed run", err)
        self.assertIn("--run", err)

    def test_nothing_run_yet_is_a_usage_error(self):
        code, _, err = self.attest()
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertIn("no run directory found", err)


# ---- K: an explicitly requested graph that cannot be used makes execution incomplete ----------
class GraphInputTests(_Workspace):
    def test_explicit_missing_graph_is_an_execution_gap(self):
        missing = self.base / "no-such-graph.json"
        code, _, _ = self.run_scan("--graph", str(missing), "--require-complete")
        self.assertEqual(code, cli.EXIT_INCOMPLETE)
        cov = self.attempt("coverage.json")
        self.assertTrue(any(g["kind"] == "graph" and g["execution"] and "not found" in g["detail"]
                            for g in cov["gaps"]))
        ge = self.attempt("findings-ledger.json")["graph_enrichment"]
        self.assertFalse(ge["available"])
        self.assertTrue(ge["explicit_input"])
        self.assertFalse((self.out / "latest").exists())

    def test_enrich_ledger_records_explicit_missing_graph(self):
        ledger = {"findings": []}
        graph_enrich.enrich_ledger(ledger, self.repo, self.base / "absent.json")
        self.assertEqual(ledger["graph_enrichment"]["available"], False)
        self.assertIn("not found", ledger["graph_enrichment"]["reason"])

    def test_implicit_missing_graph_stays_a_silent_no_op(self):
        ledger = {"findings": []}
        graph_enrich.enrich_ledger(ledger, self.repo)
        self.assertNotIn("graph_enrichment", ledger)

    def test_implicit_oversized_graph_prints_a_specific_diagnostic(self):
        graph = self.repo / "graphify-out" / "graph.json"
        graph.parent.mkdir()
        graph.write_text('{"nodes": []}')
        with open(graph, "r+b") as handle:          # sparse: one byte over the graph's own cap
            handle.truncate(graph_enrich.MAX_GRAPH_BYTES + 1)
        code, out, _ = self.run_scan("--require-complete")
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("graph: enrichment unavailable", out)
        self.assertIn("oversized", out)
        reason = self.attempt("findings-ledger.json")["graph_enrichment"]["reason"]
        self.assertIn(str(graph.stat().st_size), reason)

    def test_reasons_name_what_to_fix(self):
        graph = self.base / "graph.json"
        for content, expected in (("{invalid", "not valid JSON"), ('{"edges": []}', "no top-level `nodes`")):
            with self.subTest(expected=expected):
                graph.write_text(content)
                ledger = {"findings": []}
                graph_enrich.enrich_ledger(ledger, self.repo, graph)
                self.assertIn(expected, ledger["graph_enrichment"]["reason"])
        excluded = self.repo / "graphify-out" / "graph.json"
        excluded.parent.mkdir()
        excluded.write_text('{"nodes": []}')
        ledger = {"findings": []}
        graph_enrich.enrich_ledger(ledger, self.repo, excludes=["graphify-out"])
        self.assertIn("excluded or out of scope", ledger["graph_enrichment"]["reason"])


# ---- G, M, V: help text says what the code does --------------------------------------------
class HelpTextTests(unittest.TestCase):
    def help_of(self, *argv):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), self.assertRaises(SystemExit):
            cli.main([*argv, "--help"])
        return " ".join(buf.getvalue().split())

    def test_every_listed_command_is_in_the_usage_metavar(self):
        parser = cli.build_parser()
        sub = next(a for a in parser._actions if a.dest == "cmd")
        listed = set(sub.metavar.strip("{}").split(","))
        described = {choice.dest for choice in sub._choices_actions}
        self.assertEqual(described - listed, set())
        self.assertTrue({"gate", "attest", "emit-context"} <= listed)
        self.assertFalse({"recon", "proof", "calibrate"} & listed, "developer commands stay hidden")

    def test_mcp_allow_root_help_matches_the_required_root(self):
        text = self.help_of("mcp")
        self.assertNotIn("default: startup directory", text)
        self.assertIn("REQUIRED with --http", text)
        err = io.StringIO()
        with patch.dict(os.environ, {"WEBSEC_MCP_TOKEN": "synthetic-token"}), contextlib.redirect_stderr(err):
            self.assertEqual(cli.main(["mcp", "--http", "--port", "0"]), cli.EXIT_USAGE)
        self.assertIn("allowed scan root", err.getvalue())

    def test_ingest_dast_help_claims_only_what_is_parsed(self):
        text = self.help_of("calibrate")
        self.assertNotIn("ZAP/Nuclei report", text)
        self.assertIn("Nuclei output is not supported", text)
        self.assertIn("checks[]", text)
        self.assertIn("pluginid", text)


# ---- R: the agent-hook install message names the threshold in force ---------------------------
class AgentHookThresholdTests(_Workspace):
    def test_install_message_reports_the_effective_threshold(self):
        with patch.dict(os.environ, {"WEBSEC_GATE_FAIL_ON": "critical"}):
            code, out, _ = self.main("hooks", "install", "--agent", "--path", str(self.repo))
        self.assertEqual(code, 0)
        self.assertIn("at or above CRITICAL", out)
        self.assertNotIn("at or above MEDIUM", out)

    def test_effective_threshold_mirrors_the_gate(self):
        self.assertEqual(list(agenthook._THRESHOLDS), gate.SEV_ORDER)
        self.assertEqual(agenthook.effective_fail_on({}), "medium")
        self.assertEqual(agenthook.effective_fail_on({"WEBSEC_GATE_FAIL_ON": "HIGH"}), "high")
        self.assertEqual(agenthook.effective_fail_on({"WEBSEC_GATE_FAIL_ON": "bogus"}), "medium")


# ---- U: the login-redirect guidance names only options that exist ----------------------------
class DynamicLoginGuidanceTests(unittest.TestCase):
    def test_redirect_message_points_at_real_config_fields(self):
        import urllib.error

        def _open(req, timeout=None):
            raise urllib.error.HTTPError(req.full_url, 302, "Found", {"Location": "/home"}, None)

        cfg = {"target": "http://x", "roles": {"agentA": {"username": "u", "password": "p"}}}
        with patch.object(dynamic._NO_REDIRECT_OPENER, "open", _open):
            error = dynamic.mint(cfg, "agentA")["error"]
        self.assertNotIn("supply tokens directly", error)
        self.assertIn("login_path", error)
        self.assertIn("token_json_path", error)


if __name__ == "__main__":
    unittest.main()
