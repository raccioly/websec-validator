"""Child processes never inherit the caller's stdin.

In the Jules VM the test suite died mid-run when its output was attached to the agent's console,
and passed with stdin/stdout redirected: a spawned tool (route engine, scanner version probe, git)
that inherits an interactive or never-closing stdin can block on it. Every spawn in the package now
detaches stdin, and these tests keep it that way.
"""
import ast
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "src" / "websec_validator"
SPAWN = {"run", "Popen", "check_output", "check_call", "call"}


class StdinDetachedTests(unittest.TestCase):
    def test_every_spawn_in_the_package_sets_stdin_or_input(self):
        offenders = []
        for path in sorted(PKG.rglob("*.py")):
            if "templates" in path.parts:      # probe scripts a human runs interactively
                continue
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in SPAWN and isinstance(node.func.value, ast.Name)
                        and node.func.value.id == "subprocess"
                        and not {"stdin", "input"} & {k.arg for k in node.keywords}):
                    offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        self.assertEqual(offenders, [], "pass stdin=subprocess.DEVNULL (or input=...)")

    @unittest.skipIf(os.name == "nt", "POSIX shell stub")
    def test_a_tool_that_reads_stdin_cannot_hang_a_run(self):
        # A route engine that blocks on stdin, and a caller whose stdin never closes: before the
        # fix this waited for NOIR_TIMEOUT (300 s); now the stub reads EOF at once.
        with tempfile.TemporaryDirectory() as td:
            bin_dir, repo, out = Path(td, "bin"), Path(td, "repo"), Path(td, "out")
            bin_dir.mkdir(); repo.mkdir()
            stub = bin_dir / "noir"
            stub.write_text("#!/bin/sh\nread line\necho '{\"endpoints\": []}'\n")
            stub.chmod(0o755)
            (repo / "app.py").write_text("print('x')\n")
            env = dict(os.environ, PYTHONPATH=str(ROOT / "src"),
                       PATH=f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
            proc = subprocess.Popen([sys.executable, "-m", "websec_validator", "run", str(repo), "--out", str(out)],
                                    stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=env)
            try:
                code = proc.wait(timeout=90)
            except subprocess.TimeoutExpired:
                proc.kill()
                self.fail("websec run blocked on a child process reading the inherited stdin")
            finally:
                if proc.stdin:
                    proc.stdin.close()
            self.assertIn(code, (0, 1, 3))


if __name__ == "__main__":
    unittest.main()
