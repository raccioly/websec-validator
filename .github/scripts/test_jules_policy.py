"""Unit tests for jules_policy.py — the rules that close, label and admit Jules PRs.

Titles and file sets below are taken from this repository's own Jules history, so each rule is
pinned against the case that motivated it.
"""

import datetime as dt
import pathlib
import re
import sys
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "src"))

import jules_policy as jp  # noqa: E402
import triage              # noqa: E402

NOW = "2026-10-11T12:00:00Z"
GATE = lambda files: triage.verdict(jp.JULES_LOGIN, "t", [  # noqa: E731
    f if isinstance(f, dict) else {"filename": f, "status": "added", "additions": 1, "deletions": 0}
    for f in files])


def pr(number, title, files, **extra):
    return {"number": number, "title": title, "files": files, "labels": [], **extra}


def closed(number, title, files, days_ago, merged=False, labels=()):
    when = (dt.datetime(2026, 10, 11, 12, tzinfo=dt.timezone.utc) - dt.timedelta(days=days_ago)).isoformat()
    return {"number": number, "title": title, "files": files, "labels": [{"name": l} for l in labels],
            "closed_at": when, "merged_at": when if merged else None}


def decide(new, open_prs=(), closed_prs=()):
    return jp.triage(new, list(open_prs), list(closed_prs), NOW, GATE)


class IdentityTests(unittest.TestCase):
    def test_recognises_jules_under_both_spellings_and_nobody_else(self):
        for login in ("google-labs-jules[bot]", "app/google-labs-jules", "Google-Labs-Jules[bot]"):
            self.assertTrue(jp.is_jules(login), login)
        for login in ("dependabot[bot]", "raccioly", "jules", "", None):
            self.assertFalse(jp.is_jules(login), login)

    def test_reads_a_routine_tag_only_for_a_known_routine(self):
        self.assertEqual(jp.parse_tag("[jules:fp-hunt] crypto_usage — two FPs"), ("fp-hunt", "crypto_usage"))
        self.assertEqual(jp.parse_tag(jp.tag_title("docs-drift", "intel/refresh") + " — x"),
                         ("docs-drift", "intel/refresh"))
        self.assertIsNone(jp.parse_tag("[jules:sentinel] crypto_usage"))
        self.assertIsNone(jp.parse_tag("fix: crypto_usage FP"))

    def test_the_duplicate_key_ignores_bookkeeping_and_shared_files(self):
        self.assertEqual(jp.dup_key(["CHANGELOG.md", "src/x.py", "AGENTS.md"]), frozenset({"src/x.py"}))
        self.assertEqual(jp.dup_key(["AGENTS.md"]), frozenset())


class NoiseTests(unittest.TestCase):
    def test_count_syncs_from_this_repository_are_noise(self):
        for title, files in [
            ("docs: sync test count metric", ["AGENTS.md", "docs/security-review/backlog-reconciliation.md"]),
            ("docs(metrics): update test count to 1867 and fix file reference", ["AGENTS.md"]),
            ("docs: update cross-referenced metrics to match codebase state",
             ["AGENTS.md", "README.md", "docs-canonical/ARCHITECTURE.md", "docs/METHODOLOGY.md"]),
        ]:
            self.assertIsNotNone(jp.noise_reason(title, files), title)

    def test_a_count_change_that_touches_code_is_not_noise(self):
        self.assertIsNone(jp.noise_reason("fix: correct the extractor count",
                                          ["src/websec_validator/extractors/__init__.py"]))

    def test_personas_no_ops_empty_prs_and_routine_edits_are_noise(self):
        self.assertIsNotNone(jp.noise_reason("🛡️ Sentinel: harden input", ["src/a.py"]))
        self.assertIsNotNone(jp.noise_reason("Bolt: faster walk", ["src/a.py"]))
        self.assertIsNotNone(jp.noise_reason("Docs are already up to date", ["README.md"]))
        self.assertIsNotNone(jp.noise_reason("anything", []))
        self.assertIsNotNone(jp.noise_reason("tune routine", [".jules/routines/fp-hunt.md"]))
        self.assertIsNotNone(jp.noise_reason("Fix flaky hooks test", ["tests/test_hooks.py", "CHANGELOG.md"]))

    def test_an_ordinary_fix_is_not_noise(self):
        self.assertIsNone(jp.noise_reason("Fix FP in client_integrity extractor",
                                          ["src/websec_validator/extractors/client_integrity.py",
                                           "tests/test_pentest_regressions.py"]))


class TriageTests(unittest.TestCase):
    CRYPTO = ["src/websec_validator/extractors/crypto_usage.py", "tests/test_pentest_regressions.py"]

    def test_closes_the_newer_of_two_prs_for_the_same_routine_target(self):
        old = pr(10, "[jules:fp-hunt] crypto_usage — nonce FP", ["src/a.py"])
        new = pr(11, "[jules:fp-hunt] crypto_usage — metadata FP", ["src/b.py"])
        d = decide(new, [old])
        self.assertEqual((d["action"], d["label"], d["ref"]), ("close", jp.LABELS["duplicate"], 10))

    def test_closes_the_newer_of_two_prs_with_the_same_identifying_files(self):
        d = decide(pr(12, "Fix weak hash FP", self.CRYPTO), [pr(9, "Refine crypto regex", self.CRYPTO)])
        self.assertEqual((d["action"], d["ref"]), ("close", 9))

    def test_never_closes_the_older_pr_in_favour_of_a_newer_one(self):
        d = decide(pr(9, "Refine crypto regex", self.CRYPTO), [pr(12, "Fix weak hash FP", self.CRYPTO)])
        self.assertEqual(d["action"], "keep")

    def test_a_shared_file_does_not_make_a_real_fix_a_duplicate_of_a_count_sync(self):
        # #187 (a real AGENTS.md fix) was closed as a duplicate of #185 (a count sync).
        sync = pr(185, "docs(metrics): update test count", ["AGENTS.md"])
        fix = pr(187, "docs: correct the DocGuard command table", ["AGENTS.md"])
        self.assertNotEqual(decide(fix, [sync])["label"], jp.LABELS["duplicate"])

    def test_closes_work_declined_within_the_window_and_allows_it_after(self):
        new = pr(200, "Fix weak hash FP again", self.CRYPTO)
        d = decide(new, closed_prs=[closed(189, "Fix FP crypto", self.CRYPTO, days_ago=5)])
        self.assertEqual((d["label"], d["ref"]), (jp.LABELS["declined"], 189))
        d = decide(new, closed_prs=[closed(100, "Fix FP crypto", self.CRYPTO, days_ago=90)])
        self.assertNotEqual(d["label"], jp.LABELS["declined"])

    def test_merged_queue_full_and_noise_closures_are_not_declines(self):
        new = pr(200, "Fix weak hash FP", self.CRYPTO)
        for c in (closed(150, "x", self.CRYPTO, 5, merged=True),
                  closed(151, "x", self.CRYPTO, 5, labels=[jp.LABELS["queue_full"]]),
                  closed(152, "x", self.CRYPTO, 5, labels=[jp.LABELS["noise"]])):
            self.assertNotEqual(decide(new, closed_prs=[c])["label"], jp.LABELS["declined"], c["number"])

    def test_closes_a_new_pr_once_the_queue_is_full_and_not_before(self):
        waiting = [pr(i, f"fix {i}", [f"src/m{i}.py"]) for i in range(1, jp.QUEUE_CAP)]
        self.assertEqual(decide(pr(50, "new", ["src/new.py"]), waiting)["action"], "keep")
        waiting.append(pr(jp.QUEUE_CAP, "fix", ["src/last.py"]))
        d = decide(pr(50, "new", ["src/new.py"]), waiting)
        self.assertEqual((d["action"], d["label"]), ("close", jp.LABELS["queue_full"]))

    def test_prs_closed_for_overflow_do_not_count_toward_the_queue(self):
        overflow = [dict(pr(i, "x", [f"src/q{i}.py"]), labels=[{"name": jp.LABELS["queue_full"]}])
                    for i in range(1, 10)]
        self.assertEqual(decide(pr(50, "new", ["src/new.py"]), overflow)["action"], "keep")

    def test_labels_a_kept_pr_eligible_only_when_the_gate_would_merge_it(self):
        self.assertEqual(decide(pr(60, "docs: clarify", ["docs/guides/monorepo.md"]))["label"],
                         jp.LABELS["eligible"])
        self.assertEqual(decide(pr(61, "fix FP", self.CRYPTO))["label"], jp.LABELS["review"])


class DocsAllowlistTests(unittest.TestCase):
    def test_user_docs_merge_but_rules_records_and_contracts_do_not(self):
        for path in ("README.md", "docs/quickstart.md", "docs/reference/cli.md", "docs/i18n/es/README.md"):
            self.assertTrue(jp.is_doc_path(path), path)
        for path in ("docs-canonical/ARCHITECTURE.md", "specs/001-x/spec.md", "AGENTS.md", "CHANGELOG.md",
                     "docs/security-review/validation.md", "BENCHMARKS.md", "docs/websec-explained.html"):
            self.assertFalse(jp.is_doc_path(path), path)

    def test_the_merge_gate_holds_what_the_old_any_md_rule_merged(self):
        for path in ("docs-canonical/SECURITY.md", "specs/002-x/spec.md", "docs/security-review/validation.md"):
            verdict, _ = GATE([path])
            self.assertEqual(verdict, "hold", path)


class TargetRotationTests(unittest.TestCase):
    CANDIDATES = ["a", "b", "c", "d"]

    def test_iso_weeks_follow_the_standard_at_year_boundaries(self):
        self.assertEqual(jp.iso_week("2026-01-01T00:00:00Z"), 1)
        self.assertEqual(jp.iso_week("2027-01-01T00:00:00Z"), 53)
        self.assertEqual(jp.iso_week("2025-12-29T00:00:00Z"), 1)

    def test_rotation_starts_at_the_week_and_moves_one_target_per_week(self):
        week = jp.iso_week(NOW)
        got = jp.pick_target("fp-hunt", self.CANDIDATES, [], [], NOW)
        self.assertEqual(got, {"go": True, "target": self.CANDIDATES[week % 4]})
        nxt = jp.pick_target("fp-hunt", self.CANDIDATES, [], [], "2026-10-18T12:00:00Z")
        self.assertEqual(nxt["target"], self.CANDIDATES[(week + 1) % 4])

    def test_skips_targets_open_or_declined_for_the_same_routine_only(self):
        first = self.CANDIDATES[jp.iso_week(NOW) % 4]
        busy = [pr(1, jp.tag_title("fp-hunt", first) + " — x", ["src/a.py"])]
        self.assertNotEqual(jp.pick_target("fp-hunt", self.CANDIDATES, busy, [], NOW)["target"], first)
        self.assertEqual(jp.pick_target("fn-hunt", self.CANDIDATES, busy, [], NOW)["target"], first)
        declined = [closed(2, jp.tag_title("fp-hunt", first), ["src/a.py"], days_ago=3)]
        self.assertNotEqual(jp.pick_target("fp-hunt", self.CANDIDATES, [], declined, NOW)["target"], first)

    def test_stops_on_a_full_queue_no_targets_every_target_taken_or_unknown_routine(self):
        full = [pr(i, "x", [f"src/{i}.py"]) for i in range(jp.QUEUE_CAP)]
        self.assertFalse(jp.pick_target("fp-hunt", self.CANDIDATES, full, [], NOW)["go"])
        self.assertFalse(jp.pick_target("fp-hunt", [], [], [], NOW)["go"])
        taken = [pr(i, jp.tag_title("fp-hunt", c), ["src/x.py"]) for i, c in enumerate(self.CANDIDATES)]
        self.assertFalse(jp.pick_target("fp-hunt", self.CANDIDATES, taken[:4], [], NOW)["go"])
        self.assertFalse(jp.pick_target("sentinel", self.CANDIDATES, [], [], NOW)["go"])


def _load_preflight():
    import importlib.util
    spec = importlib.util.spec_from_file_location("jules_preflight", HERE.parents[1] / ".jules" / "preflight.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PreflightTests(unittest.TestCase):
    """The target lists come from the repository, never from memory; the queue read fails closed."""

    def setUp(self):
        self.pf = _load_preflight()

    def test_target_lists_are_read_from_the_code(self):
        from websec_validator.extractors import REGISTRY
        from websec_validator.extractors.surface import SINKS
        self.assertEqual(self.pf.fn_hunt_targets(), sorted(SINKS))
        self.assertEqual(self.pf.fp_hunt_targets(), [e.name for e in REGISTRY])
        drift = self.pf.docs_drift_targets()
        self.assertIn("run", drift)
        self.assertIn("intel/refresh", drift)
        for target in drift + self.pf.fn_hunt_targets() + self.pf.fp_hunt_targets():
            self.assertIsNotNone(jp.parse_tag(jp.tag_title("docs-drift", target)), target)

    def test_an_unreadable_queue_is_a_stop_never_a_guess(self):
        import contextlib
        import io
        from unittest import mock
        out = io.StringIO()
        with mock.patch.object(self.pf, "api", side_effect=OSError("offline")), \
                contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as raised:
            self.pf.main(["fp-hunt"])
        self.assertEqual(raised.exception.code, self.pf.STOP)
        self.assertIn("failing closed", out.getvalue())

    def test_an_unknown_routine_stops(self):
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as raised:
            self.pf.main(["sentinel"])
        self.assertEqual(raised.exception.code, self.pf.STOP)

    def test_every_routine_has_a_routine_file_and_the_readme_schedules_it(self):
        readme = (HERE.parents[1] / ".jules" / "README.md").read_text(encoding="utf-8")
        for routine in jp.ROUTINES:
            self.assertTrue((HERE.parents[1] / ".jules" / "routines" / f"{routine}.md").is_file(), routine)
            self.assertIn(f"Follow .jules/routines/{routine}.md exactly.", readme)


class OneInterpreterTests(unittest.TestCase):
    """The first Jules snapshot failed on `websec --version`: the console script was not on PATH in
    the VM, where `python3` and `python` are different interpreters. Every .jules/ command must go
    through `python` and `python -m websec_validator`."""

    def test_no_bare_websec_or_python3_invocation_in_jules_files(self):
        jules = HERE.parents[1] / ".jules"
        offenders = []
        for path in sorted(jules.rglob("*")):
            if not path.is_file() or path.suffix not in {".md", ".sh"}:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                code = line.split("#", 1)[0] if path.suffix == ".sh" else line
                if re.search(r"(?:^|[`$(\s])websec\s+(?:run|demo|--version|--help|<)", code) \
                        or re.search(r"(?:^|[`\s])python3\s+(?:-m|\.jules|-c)", code):
                    offenders.append(f"{path.relative_to(jules)}:{number}: {line.strip()}")
        self.assertEqual(offenders, [])


class NoMentionTests(unittest.TestCase):
    def test_no_automation_mentions_the_agent_by_handle(self):
        # With Jules' Reactive Mode on, a mention is an instruction. bot_triage.py used to append
        # "@jules — before opening a PR…" to every close comment.
        roots = [HERE, HERE.parent / "workflows", HERE.parents[1] / ".jules"]
        offenders = []
        for root in roots:
            for path in sorted(root.rglob("*")) if root.exists() else []:
                if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".sh", ".md"} and path != pathlib.Path(__file__):
                    if re.search(r"@jules\b", path.read_text(encoding="utf-8"), re.I):
                        offenders.append(str(path.relative_to(HERE.parents[1])))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
