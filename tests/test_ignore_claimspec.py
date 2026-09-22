"""The claimspec `ignore` writer: `.websec-ignore` acknowledgements as the Guard-family format.

The interesting half of this writer is what it REFUSES to emit. claimspec's `ignore` kind exists so
an auditor can read why each suppression is there, and `reason` is required with a minimum length.
`.websec-ignore` holds two mechanisms: a `fingerprint:` acknowledgement carries a reason, an expiry
and a lifecycle state, while a bare gitignore pattern has its `#` comment discarded outright by
`load_suppressions`. Emitting the second kind with a synthesised reason would make an unreviewed
suppression read exactly like a reviewed one — so those are omitted and counted, and the tests below
pin the omissions at least as hard as the exports.

The round-trip test hands the document to the spec's own Node validator and is SKIPPED, never
silently passed, when node or a testguard checkout is missing. Point `WEBSEC_CLAIMSPEC_SPEC_DIR` at
a testguard `spec/` directory to run it.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator import cli, findings  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
TODAY = date(2026, 9, 22)

RUNNER = """
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [specDir, file] = process.argv.slice(2);
let validate;
try { ({ validate } = await import(pathToFileURL(specDir + '/lib/validate.mjs').href)); }
catch (e) { console.error(String(e)); process.exit(3); }
try {
  const r = validate('ignore', JSON.parse(readFileSync(file, 'utf8')));
  console.log(JSON.stringify(r));
  process.exit(r.ok ? 0 : 1);
} catch (e) { console.error(String(e)); process.exit(4); }
"""

# One file covering every state the parser can produce. Each line is asserted on below.
POLICY = """\
tests/fixtures/
category:dependency
fingerprint:aaaa1111 expires:2099-12-31 # vendored sample app, not deployed
fingerprint:bbbb2222 expires:2020-01-01 # lapsed: was a staging-only key
fingerprint:cccc3333 # legacy acknowledgement with no expiry but a real reason
fingerprint:dddd4444 expires:2099-12-31 # ok
fingerprint:eeee5555 expires:2099-12-31
fingerprint:ffff6666 expires:not-a-date # reviewed by the platform team
"""


def export(policy: str = POLICY, today: date = TODAY):
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / ".websec-ignore").write_text(policy)
        return findings.to_claimspec_ignore(root, today=today)


def by_pattern(doc):
    return {e["pattern"]: e for e in doc["entries"]}


class ExportedEntriesTests(unittest.TestCase):
    def test_document_shape_is_exactly_what_the_schema_allows(self):
        """`additionalProperties: false` with only `$schema`/`schemaVersion`/`entries` — which is
        why the omission report is returned SEPARATELY rather than carried inside the document."""
        doc, _ = export()
        self.assertEqual(set(doc), {"schemaVersion", "entries"})
        self.assertEqual(doc["schemaVersion"], 1)
        for entry in doc["entries"]:
            self.assertLessEqual(set(entry), {"kind", "pattern", "reason", "by", "at", "expires"})
            self.assertEqual(entry["kind"], "fingerprint")
            self.assertGreaterEqual(len(entry["reason"]), findings.CLAIMSPEC_REASON_MIN)
            self.assertLessEqual(len(entry["reason"]), findings.CLAIMSPEC_REASON_MAX)
            self.assertLessEqual(len(entry["pattern"]), findings.CLAIMSPEC_PATTERN_MAX)

    def test_an_active_acknowledgement_exports_with_its_reason(self):
        doc, _ = export()
        entry = by_pattern(doc)["aaaa1111"]
        self.assertEqual(entry["reason"], "vendored sample app, not deployed")

    def test_a_legacy_acknowledgement_exports_with_NO_expires(self):
        """It genuinely has no expiry; inventing one would be a claim the file does not make."""
        self.assertNotIn("expires", by_pattern(export()[0])["cccc3333"])

    def test_an_EXPIRED_acknowledgement_is_exported_rather_than_dropped(self):
        """The schema has `expires` so a consumer can warn. Dropping the entry instead would hide a
        lapsed suppression from the auditor the document is written for."""
        self.assertIn("bbbb2222", by_pattern(export()[0]))

    def test_the_expiry_instant_is_the_day_AFTER_the_stored_date(self):
        """websec keeps an acknowledgement alive through the whole of its stored day
        (`expiry >= today`); claimspec stores the instant after which it no longer applies. Writing
        midnight OF the stored day would retire the entry a day before websec's own gate does."""
        self.assertEqual(by_pattern(export()[0])["aaaa1111"]["expires"], "2100-01-01T00:00:00Z")
        self.assertEqual(findings._claimspec_expiry("2026-12-31"), "2027-01-01T00:00:00Z")

    def test_entries_are_ordered_deterministically(self):
        self.assertEqual([e["pattern"] for e in export()[0]["entries"]],
                         sorted(e["pattern"] for e in export()[0]["entries"]))


class RefusedEntriesTests(unittest.TestCase):
    """What the writer will NOT say. Each of these is a suppression an auditor must not see
    rubber-stamped by a reason websec invented for it."""

    def omitted(self, policy=POLICY):
        return {row["fingerprint"]: row for row in export(policy)[1]["omitted_acknowledgements"]}

    def test_an_acknowledgement_with_no_reason_is_omitted(self):
        doc, _ = export()
        self.assertNotIn("eeee5555", by_pattern(doc))
        self.assertEqual(self.omitted()["eeee5555"]["state"], "missing-reason")

    def test_a_reason_too_short_for_the_schema_is_omitted_not_padded(self):
        """`# ok` is below the schema's 8-character floor. Padding it to fit would be fabrication."""
        self.assertNotIn("dddd4444", by_pattern(export()[0]))
        self.assertIn("dddd4444", self.omitted())

    def test_a_malformed_expiry_is_omitted_rather_than_exported_as_never_expiring(self):
        """The dangerous direction: an entry the operator meant to time-limit, silently promoted to
        one that never expires because its expiry failed to parse."""
        self.assertNotIn("ffff6666", by_pattern(export()[0]))
        self.assertEqual(self.omitted()["ffff6666"]["state"], "malformed")

    def test_bare_patterns_are_counted_not_exported(self):
        """`load_suppressions` discards the `#` comment, so no reason exists for these anywhere."""
        doc, report = export()
        self.assertEqual(report["omitted_patterns"], 2)
        self.assertEqual([e for e in doc["entries"] if e["kind"] != "fingerprint"], [])

    def test_the_report_flags_an_incomplete_policy(self):
        self.assertFalse(export()[1]["complete"])

    def test_a_fully_reviewed_policy_reports_complete(self):
        """The control: `complete` must be reachable, or the flag says nothing."""
        doc, report = export("fingerprint:aaaa1111 expires:2099-12-31 # reviewed and accepted\n")
        self.assertTrue(report["complete"])
        self.assertEqual(report["entries"], 1)
        self.assertEqual(len(doc["entries"]), 1)

    def test_an_empty_policy_exports_an_empty_conforming_document(self):
        doc, report = export("")
        self.assertEqual(doc, {"schemaVersion": 1, "entries": []})
        self.assertTrue(report["complete"])

    def test_an_over_long_reason_is_truncated_rather_than_emitted_non_conforming(self):
        doc, _ = export(f"fingerprint:aaaa1111 # {'x' * 5000}\n")
        reason = by_pattern(doc)["aaaa1111"]["reason"]
        self.assertEqual(len(reason), findings.CLAIMSPEC_REASON_MAX)
        self.assertTrue(reason.endswith("[truncated]"))


class CliTests(unittest.TestCase):
    def run_cli(self, policy, dest):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ".websec-ignore").write_text(policy)
            cli.main(["init", str(root), "--claimspec", str(dest)])

    def test_the_cli_writes_the_document_and_leaves_websec_ignore_untouched(self):
        with tempfile.TemporaryDirectory() as td:
            root, dest = Path(td), Path(td) / "out" / "ignore.json"
            policy = root / ".websec-ignore"
            policy.write_text(POLICY)
            before = policy.read_bytes()
            cli.main(["init", str(root), "--claimspec", str(dest)])
            self.assertEqual(policy.read_bytes(), before, "an export must never rewrite the policy")
            doc = json.loads(dest.read_text())
            self.assertEqual(doc["schemaVersion"], 1)
            self.assertEqual({e["pattern"] for e in doc["entries"]},
                             {"aaaa1111", "bbbb2222", "cccc3333"})

    def test_the_cli_does_not_scaffold_when_exporting(self):
        """`--claimspec` reads policy; it must short-circuit before `init`'s proposal is computed,
        so an export can never create a `.websec-ignore` that did not exist."""
        with tempfile.TemporaryDirectory() as td:
            root, dest = Path(td), Path(td) / "ignore.json"
            (root / "app.py").write_text("x = 1\n")
            cli.main(["init", str(root), "--claimspec", str(dest)])
            self.assertFalse((root / ".websec-ignore").exists())
            self.assertEqual(json.loads(dest.read_text()), {"schemaVersion": 1, "entries": []})


class ClaimspecRoundTripTests(unittest.TestCase):
    """Hand the emitted document to the spec's own validator instead of trusting this file's
    reading of the schema."""

    def spec_dir(self) -> Path:
        env = os.environ.get("WEBSEC_CLAIMSPEC_SPEC_DIR")
        spec = Path(env).expanduser() if env else REPO.parent / "testguard" / "spec"
        if not shutil.which("node"):
            self.skipTest("node is not installed; the claimspec validator is a Node module")
        if not (spec / "schemas" / "ignore.schema.json").is_file() or \
           not (spec / "lib" / "validate.mjs").is_file():
            self.skipTest(f"no claimspec checkout at {spec} (set WEBSEC_CLAIMSPEC_SPEC_DIR)")
        return spec

    def test_the_emitted_document_conforms(self):
        spec = self.spec_dir()
        shapes = {"mixed": export()[0],
                  "empty": export("")[0],
                  "all-reviewed": export("fingerprint:aaaa1111 expires:2099-12-31 "
                                         "# reviewed and accepted\n")[0]}
        with tempfile.TemporaryDirectory() as td:
            runner = Path(td) / "validate-ignore.mjs"
            runner.write_text(RUNNER)
            for name, doc in shapes.items():
                with self.subTest(shape=name):
                    path = Path(td) / f"{name}.json"
                    path.write_text(json.dumps(doc, indent=2))
                    res = subprocess.run(["node", str(runner), str(spec), str(path)],
                                         capture_output=True, text=True, timeout=60)
                    if res.returncode == 3:
                        self.skipTest("claimspec validator could not load (npm install in "
                                      f"testguard?): {res.stderr.strip()}")
                    self.assertEqual(res.returncode, 0,
                                     f"{name}: {res.stdout.strip() or res.stderr.strip()}")


if __name__ == "__main__":
    unittest.main()
