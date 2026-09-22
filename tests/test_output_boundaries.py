"""Output-base selection does not authorize nested runs symlink redirection."""
from pathlib import Path
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import cli


class OutputBoundaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / 'repo'; self.repo.mkdir()
        (self.repo / 'app.py').write_text('print("safe")\n')
        self.out = self.root / 'output'; self.out.mkdir()
        self.outside = self.root / 'outside'; self.outside.mkdir()
        self.error = io.StringIO()

    def invoke(self, *args):
        with patch('shutil.which', return_value=None), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(self.error):
            return cli.main(['run', str(self.repo), '--out', str(self.out), *args])

    def test_nested_symlink_is_rejected_before_any_outside_write_or_recon(self):
        (self.out / 'runs').symlink_to(self.outside, target_is_directory=True)
        (self.outside / 'sentinel').write_text('unchanged')
        with patch.object(cli.recon, 'build_facts', side_effect=AssertionError('analysis should not start')):
            self.assertEqual(self.invoke('--require-complete'), 2)
        self.assertEqual([path.name for path in self.outside.iterdir()], ['sentinel'])
        self.assertEqual((self.outside / 'sentinel').read_text(), 'unchanged')
        self.assertFalse((self.out / 'latest').exists())
        self.assertIn('cannot reserve output run', self.error.getvalue())
        self.assertIn('real directory', self.error.getvalue())

    def test_dangling_and_inroot_nested_links_are_not_accepted(self):
        for target in (self.outside / 'absent', self.out / 'other'):
            with self.subTest(target=target):
                if target.name == 'other':
                    target.mkdir()
                link = self.out / 'runs'; link.symlink_to(target, target_is_directory=True)
                self.assertEqual(self.invoke(), 2)
                self.assertTrue(link.is_symlink())
                if target.name == 'other':
                    self.assertEqual(list(target.iterdir()), [])
                else:
                    self.assertFalse(target.exists())
                link.unlink()

    def test_non_directory_runs_paths_fail_without_truncation_or_blocking(self):
        runs = self.out / 'runs'; runs.write_text('keep this file')
        self.assertEqual(self.invoke(), 2)
        self.assertEqual(runs.read_text(), 'keep this file')
        runs.unlink()
        if hasattr(os, 'mkfifo'):
            os.mkfifo(runs)
            self.assertEqual(self.invoke(), 2)
            self.assertTrue(runs.exists())

    def test_explicit_base_alias_is_resolved_and_unique_runs_are_preserved(self):
        alias = self.root / 'selected alias'; alias.symlink_to(self.out, target_is_directory=True)
        first, _ = cli._new_run_dir(str(alias))
        second, _ = cli._new_run_dir(str(alias))
        self.assertNotEqual(first, second)
        self.assertEqual(first.parent, self.out.resolve() / 'runs')
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())
        self.assertFalse((self.out / 'latest').exists())
        cli._publish_run(first)
        self.assertEqual((self.out / 'latest').resolve(), first)

    def test_directory_creation_fault_becomes_exit_two(self):
        with patch.object(cli.tempfile, 'mkdtemp', side_effect=PermissionError('synthetic write refusal')):
            self.assertEqual(self.invoke(), 2)
        self.assertIn('synthetic write refusal', self.error.getvalue())
        self.assertFalse((self.out / 'latest').exists())
        self.assertEqual(list((self.out / 'runs').iterdir()), [])

    def test_complete_and_partial_attempts_keep_latest_and_existing_artifacts(self):
        self.assertEqual(self.invoke('--require-complete'), 0)
        previous = (self.out / 'latest').resolve()
        previous_facts = (previous / 'FACTS.json').read_bytes()
        self.assertEqual(self.invoke('--scan', '--scanners', 'semgrep', '--require-complete'), 3)
        self.assertEqual((self.out / 'latest').resolve(), previous)
        self.assertEqual((previous / 'FACTS.json').read_bytes(), previous_facts)
        attempts = list((self.out / 'runs').iterdir())
        self.assertEqual(len(attempts), 2)
        current = next(path for path in attempts if path.resolve() != previous)
        self.assertFalse(json.loads((current / 'coverage.json').read_text())['execution_complete'])
        self.assertTrue((current / 'findings-ledger.json').is_file())

    def test_dynamic_refuses_output_redirect_before_any_probe(self):
        facts = self.root / 'facts.json'; facts.write_text('{}')
        (self.out / 'runs').symlink_to(self.outside, target_is_directory=True)
        with patch.object(cli.dynamic, 'run_unauth', side_effect=AssertionError('no probe authorized by a bad output path')), contextlib.redirect_stderr(self.error):
            rc = cli.main(['dynamic', '--facts', str(facts), '--out', str(self.out), '--unauth', '--target', 'http://127.0.0.1:1'])
        self.assertEqual(rc, 2)
        self.assertEqual(list(self.outside.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
