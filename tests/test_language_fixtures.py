"""Persist language limits from actual owned source fixtures, without executing them.

@req specs/001-continuous-security-improvement/spec.md#FR-004
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

FIXTURES = Path(__file__).parent / 'fixtures'


class LanguageFixtureTests(unittest.TestCase):
    def run_fixture(self, name):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            shutil.copytree(FIXTURES / name, root)
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(root),
                                     '--out', str(out), '--format', 'json'], cwd=owner, env=env,
                                    capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            run = out / 'runs' / json.loads(result.stdout)['generated']
            facts = json.loads((run / 'FACTS.json').read_text())
            return facts, (run / 'AGENT-BRIEFING.md').read_text()

    def test_recovered_original_elixir_is_unanalyzed_not_clean(self):
        facts, briefing = self.run_fixture('lang_elixir_vulnerable')
        cov = facts['coverage']
        self.assertEqual(cov['files']['unanalyzed_languages'], {'elixir': 2})
        self.assertTrue(cov['files']['no_analyzable_source'])
        self.assertTrue(cov['execution_complete'])
        self.assertFalse(cov['protection_complete'])
        self.assertIn('NO ANALYZABLE SOURCE', briefing)
        self.assertIn('NOT CHECKED, not secure', briefing)

    def test_authored_swift_source_persists_thin_coverage(self):
        facts, briefing = self.run_fixture('lang_swift_vulnerable')
        cov = facts['coverage']
        self.assertTrue(cov['execution_complete'])
        self.assertFalse(cov['protection_complete'])
        gaps = [g for g in cov['gaps'] if g['kind'] == 'thin_language_coverage']
        self.assertTrue(gaps)
        self.assertTrue(all(not g['execution'] for g in gaps))
        self.assertIn('swift', briefing.lower())
        self.assertIn('not evidence of absence', briefing)
