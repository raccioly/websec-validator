"""A real second Git checkout stays inert and separate from the installed engine.

@req specs/001-continuous-security-improvement/spec.md#FR-005
"""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO/'scripts/create-adoption-target.py'
spec = importlib.util.spec_from_file_location('adoption_checkout', SCRIPT)
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class AdoptionCheckoutTests(unittest.TestCase):
    def test_actual_git_checkout_heads_and_hostile_templates_stay_inert(self):
        with tempfile.TemporaryDirectory() as td:
            result = builder.create(Path(td), 'clean')
            target = Path(result['target'])
            self.assertNotEqual(target, REPO)
            self.assertEqual(builder.git(target,'rev-parse','HEAD'), result['commit'])
            self.assertEqual(builder.git(target,'status','--porcelain'), '')
            self.assertEqual(len(result['commit']), 40)
            self.assertTrue((target/'.git').is_dir())
            self.assertFalse(Path(result['marker']).exists())
            self.assertFalse((target/'.git/hooks/post-checkout').exists())

    def test_actual_cli_three_checkout_outcomes_and_unchanged_target(self):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            for case, expected in [('clean',0),('unsafe',1),('incomplete',3)]:
                with self.subTest(case=case):
                    result = builder.create(owner,case)
                    target = Path(result['target'])
                    env = dict(os.environ, PYTHONPATH=str(REPO/'src'),
                               WEBSEC_CALIBRATION_HOME=str(owner/'calibration'),
                               WEBSEC_UPDATE_HOME=str(owner/'release-cache'))
                    # Keep Git available for actual metadata intake; disable optional route/scanner dispatch.
                    env['PATH'] = '/usr/bin:/bin'
                    run = subprocess.run([sys.executable,'-m','websec_validator.cli','run',str(target),
                        '--out',str(owner/(case+'-out')),'--format','json','--require-complete','--fail-on','high'],
                        cwd=owner, env=env, capture_output=True,text=True,timeout=30)
                    self.assertEqual(run.returncode,expected,run.stderr)
                    generated = json.loads(run.stdout)['generated']
                    facts = json.loads((owner/(case+'-out')/'runs'/generated/'FACTS.json').read_text())
                    self.assertEqual(facts['coverage']['execution_complete'],case!='incomplete')
                    self.assertFalse(Path(result['marker']).exists())
                    self.assertEqual(builder.git(target,'rev-parse','HEAD'),result['commit'])
                    self.assertEqual(builder.git(target,'status','--porcelain'),'')

    def test_generator_cli_writes_runner_metadata_without_target_execution(self):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            command_file = owner/'command-output'
            env = dict(os.environ,GITHUB_OUTPUT=str(command_file))
            run = subprocess.run([sys.executable,'-I',str(SCRIPT),'--owner',td,'--case','clean'],
                                 env=env,capture_output=True,text=True,timeout=30)
            self.assertEqual(run.returncode,0,run.stderr)
            result = json.loads(run.stdout)
            self.assertIn('target='+result['target'],command_file.read_text())
            self.assertFalse(Path(result['marker']).exists())

    def test_invalid_case_and_private_owner_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            private = owner/'.LOCAL'
            private.mkdir()
            for root,case in [(owner,'unknown'),(private,'clean')]:
                with self.assertRaises(ValueError):
                    builder.create(root,case)
            self.assertEqual(list(private.iterdir()),[])
