"""#255: no absolute local path and no raw secret value in any run artifact."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _jvm_repo import ROOT, TempRepo
from websec_validator import scanners
from websec_validator.privacy import Scrubber, target_id


class ScrubberTests(unittest.TestCase):
    def test_paths(self):
        s = Scrubber("/tmp/acme/app", "/tmp/acme/out/runs/1")
        cases = {"/tmp/acme/app": "app", "/tmp/acme/app/src/x.js": "src/x.js", "/tmp/acme/app2/x": "/tmp/acme/app2/x",
                 "at /tmp/acme/app/src/x.js:3": "at src/x.js:3", "tmp/acme/app/pom.xml": "pom.xml",
                 "/tmp/acme/out/runs/1/scanners/g.json": "scanners/g.json"}
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(s.text(raw), expected)
        doc = s.obj({"target": "/tmp/acme/app", "sources": [{"path": "/tmp/acme/app/.websec-ignore"}]})
        self.assertEqual((doc["target"], doc["sources"][0]["path"], doc["target_id"]),
                         ("app", ".websec-ignore", target_id("/tmp/acme/app")))

    def test_secret_reports_are_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "gitleaks.json"
            doc = [{"RuleID": "generic-api-key", "Secret": "q8Wd3LmZx2Rt7Kp", "Match": "key: q8Wd3LmZx2Rt7Kp", "File": "a"}]
            path.write_text(json.dumps(doc))
            scanners._redact_report(path, doc)
            text = path.read_text()
            self.assertNotIn("q8Wd3LmZx2Rt7Kp", text)
            self.assertIn("REDACTED:sha256:", text)
            self.assertIn('"File": "a"', text)

    def test_checkov_root_anchored_path_is_relative(self):
        rows = scanners._norm_checkov([{"check_type": "secrets", "results": {"failed_checks": [
            {"check_id": "CKV_SECRET_6", "file_path": "/src/main/resources/config/dev.yaml", "file_line_range": [2, 2]}]}}])
        self.assertEqual(rows[0]["file"], "src/main/resources/config/dev.yaml")


class ArtifactTests(TempRepo):
    def test_no_artifact_contains_the_absolute_root(self):
        self.write("package.json", '{"name":"acme","version":"1.0.0","dependencies":{"express":"4.21.2"}}')
        self.write("server.js", "const app = require('express')();\napp.post('/x', (q, s) => s.send(q.body));\n")
        self.write(".websec-ignore", "# none\n")
        with tempfile.TemporaryDirectory() as holder:
            out = Path(holder) / "out"
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"))
            subprocess.run([sys.executable, "-m", "websec_validator", "run", str(self.root), "--out", str(out),
                            "--format", "json"], capture_output=True, text=True, env=env, timeout=300)
            run = next((out / "runs").iterdir())
            roots = {str(self.root), os.path.realpath(self.root)}
            for path in run.rglob("*"):
                if path.is_file():
                    text = path.read_text(errors="ignore")
                    for root in roots:
                        with self.subTest(file=path.name, root=root):
                            self.assertNotIn(root, text)
                            self.assertNotIn(str(out), text)
            ledger = json.loads((run / "findings-ledger.json").read_text())
            self.assertEqual(ledger["target"], self.root.name)
            self.assertEqual(ledger["target_id"], target_id(self.root))
            self.assertEqual(ledger["verification_context"]["application_id"], target_id(self.root))


if __name__ == "__main__":
    unittest.main()
