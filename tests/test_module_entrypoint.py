"""`python -m websec_validator` runs the same CLI as the `websec` console script.

Agent VMs and CI images do not always put the console script on PATH (the first Jules snapshot
failed on exactly that); the interpreter that installed the package must still reach it.
"""
import os
import subprocess
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def run(*args):
    env = dict(os.environ, PYTHONPATH=str(SRC))
    return subprocess.run([sys.executable, "-m", "websec_validator", *args],
                          capture_output=True, text=True, env=env, timeout=120)


class ModuleEntrypointTests(unittest.TestCase):
    def test_version(self):
        result = run("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("websec-validator", result.stdout)

    def test_usage_errors_keep_the_cli_exit_contract(self):
        result = run("run", str(SRC / "does-not-exist"))
        self.assertEqual(result.returncode, 2)

    def test_help_names_the_program_websec(self):
        result = run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("usage: websec"), result.stdout[:80])


if __name__ == "__main__":
    unittest.main()
