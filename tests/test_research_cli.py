"""Shipped suite discoverability preserves the offline, human-review-only contract."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import cli, research


class ResearchCliTests(unittest.TestCase):
    def invoke(self, *arguments):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['research', *arguments])
        return code, json.loads(output.getvalue())

    def test_catalog_lists_only_named_shipped_suites_without_evaluation(self):
        with patch.object(research, 'evaluate', side_effect=AssertionError('catalog evaluated cases')):
            code, result = self.invoke('catalog')
        self.assertEqual(code, 0)
        self.assertEqual([row['id'] for row in result['suites']], ['control-scope'])
        suite = result['suites'][0]
        self.assertEqual((suite['proposal_count'], suite['case_count']), (3, 24))
        self.assertEqual(len({row['detector'] for row in suite['proposals']}), 3)
        self.assertEqual(result['detector_revision'], research.detector_revision())
        self.assertIn('not blind real-project validation', result['limitation'])

    def test_actual_suite_runs_all_cases_offline_without_activating_rules(self):
        with patch('socket.create_connection', side_effect=AssertionError('network forbidden')), \
                patch('subprocess.Popen', side_effect=AssertionError('execution forbidden')):
            code, result = self.invoke('evaluate', '--suite', 'control-scope')
        self.assertEqual(code, 0, result['errors'])
        self.assertEqual((result['proposal_count'], result['case_count']), (3, 24))
        self.assertTrue(result['promotion_eligible'])
        self.assertEqual(result['promotion_state'], 'eligible-for-human-review')
        self.assertFalse(result['source_executed'])
        self.assertFalse(result['installed'])
        for part in ('development', 'holdout'):
            self.assertEqual(result['metrics'][part], {'TP': 9, 'TN': 3, 'FP': 0, 'FN': 0,
                                                      'unknown': 0, 'samples': 12})
        self.assertEqual({row['detector_revision'] for row in result['proposals']},
                         {result['detector_revision']})
        self.assertIn('not blind real-project validation', result['limitation'])

    def test_one_regressed_detector_rejects_suite_and_retains_other_results(self):
        original = research._detected
        def regressed(context, name, detector, routes):
            detected = original(context, name, detector, routes)
            return False if name == 'crypto:password-hash' else detected
        with patch.object(research, '_detected', side_effect=regressed):
            code, result = self.invoke('evaluate', '--suite', 'control-scope')
        self.assertEqual(code, 2)
        self.assertFalse(result['promotion_eligible'])
        self.assertEqual(result['case_count'], 24)
        self.assertEqual(sum(row['promotion_eligible'] for row in result['proposals']), 2)
        self.assertEqual(result['metrics']['development']['FN'], 3)
        self.assertTrue(any('control-scope-crypto' in error for error in result['errors']))

    def test_empty_suite_and_revision_change_cannot_pass(self):
        with patch.object(research, 'control_scope_cases', return_value=[]):
            code, result = self.invoke('evaluate', '--suite', 'control-scope')
        self.assertEqual(code, 2)
        self.assertIn('suite has no proposals', result['errors'])
        groups = research.control_scope_cases()
        evaluated = research.evaluate(groups[0]['proposal'], groups[0]['cases'])
        with patch.object(research, 'control_scope_cases', return_value=groups[:1]), \
                patch.object(research, 'evaluate', return_value=evaluated), \
                patch.object(research, 'detector_revision', side_effect=[evaluated['detector_revision'], 'changed']):
            code, result = self.invoke('evaluate', '--suite', 'control-scope')
        self.assertEqual(code, 2)
        self.assertIn('detector revision changed', ' '.join(result['errors']))

    def test_invalid_selections_reject_before_file_reads_or_evaluation(self):
        with patch.object(cli, '_load_json_artifact', side_effect=AssertionError('input read')), \
                patch.object(research, 'evaluate_suite', side_effect=AssertionError('suite evaluated')):
            for supplied in ('unused.json', ''):
                code, result = self.invoke('evaluate', '--suite', 'control-scope', '--cases', supplied)
                self.assertEqual(code, 2)
                self.assertIn('--cases requires --proposal', result['error'])
            for args in [('evaluate', '--suite', '../arbitrary'),
                         ('evaluate', '--suite', 'control-scope', '--proposal', 'unused.json'),
                         ('evaluate', '--cases', 'unused.json')]:
                with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()), \
                        self.assertRaises(SystemExit) as error:
                    self.invoke(*args)
                self.assertEqual(error.exception.code, 2)
        with self.assertRaises(ValueError):
            research.evaluate_suite('../arbitrary')

    def test_example_and_both_file_forms_remain_supported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, bundle = self.invoke('example', '--out', str(root / 'bundle.json'))
            self.assertEqual(code, 0)
            self.assertEqual(self.invoke('evaluate', '--proposal', str(root / 'bundle.json'))[0], 0)
            (root / 'proposal.json').write_text(json.dumps(bundle['proposal']))
            (root / 'cases.json').write_text(json.dumps(bundle['cases']))
            self.assertEqual(self.invoke('evaluate', '--proposal', str(root / 'proposal.json'),
                                         '--cases', str(root / 'cases.json'))[0], 0)
            code, result = self.invoke('evaluate', '--proposal', str(root / 'bundle.json'), '--cases', '')
            self.assertEqual(code, 2)
            self.assertIn('error', result)

    def test_catalog_and_suite_outputs_never_overwrite_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'evidence.json'
            output.write_text('original evidence')
            for args in [('catalog',), ('evaluate', '--suite', 'control-scope')]:
                code, result = self.invoke(*args, '--out', str(output))
                self.assertEqual(code, 2)
                self.assertIn('error', result)
                self.assertEqual(output.read_text(), 'original evidence')


if __name__ == '__main__':
    unittest.main()
