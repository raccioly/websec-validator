"""Shipped data-only paired cases reuse the research evaluator's promotion gate."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import research


class ControlScopeResearchTests(unittest.TestCase):
    def test_shipped_pairs_all_pass_without_sample_execution(self):
        groups=research.control_scope_cases()
        self.assertEqual(len(groups),3)
        with patch('subprocess.Popen',side_effect=AssertionError('No external execution in research')):
            for group in groups:
                with self.subTest(detector=group['proposal']['detector']):
                    result=research.evaluate(group['proposal'],group['cases'])
                    self.assertTrue(result['promotion_eligible'],result['errors'])
                    self.assertFalse(result['source_executed'])
                    self.assertFalse(result['installed'])
                    for partition in ('development','holdout'):
                        self.assertEqual(result['metrics'][partition]['TP'],3)
                        self.assertEqual(result['metrics'][partition]['TN'],1)
                    if group['proposal']['detector'].startswith('integrations'):
                        self.assertIn('route discovery is not evaluated',result['fixture_route_basis'])

    def test_comment_false_negative_rejects_promotion(self):
        group=research.control_scope_cases()[2]
        original=research._detected
        def regressed(context,name,detector,routes):
            if any('PKCE support planned' in context.text(path) for path in context.code_files):
                return False
            return original(context,name,detector,routes)
        with patch.object(research,'_detected',side_effect=regressed):
            result=research.evaluate(group['proposal'],group['cases'])
        self.assertFalse(result['promotion_eligible'])
        self.assertEqual(result['metrics']['development']['FN'],1)
        self.assertEqual(result['metrics']['holdout']['FN'],1)

    def test_route_inventory_only_references_provided_fixture_files(self):
        group=research.control_scope_cases()[0]
        for bad in (None,{},[],[{'method':'POST','path':'/webhooks/a','file':'../outside.js'}],
                    [{'method':'POST','path':'/webhooks/a','file':'/tmp/outside.js'}],
                    [{'method':'POST','path':'/webhooks/a','file':'missing.js'}],
                    [{'method':'POST','path':'/webhooks/a','file':'handler.js','code_path':'/tmp/private'}],
                    [{'method':[],'path':'/webhooks/a','file':'handler.js'}],
                    [{'method':'POST','path':'/webhooks/\n','file':'handler.js'}]):
            cases=copy.deepcopy(group['cases']);cases[0]['route_inventory']=bad
            with self.subTest(bad=bad):
                result=research.evaluate(group['proposal'],cases)
                self.assertFalse(result['promotion_eligible'])
                self.assertEqual(result['metrics']['development']['unknown'],1)

    def test_route_count_bound_and_no_external_tools(self):
        group=research.control_scope_cases()[0]
        cases=copy.deepcopy(group['cases'])
        cases[0]['route_inventory']*=21
        self.assertFalse(research.evaluate(group['proposal'],cases)['promotion_eligible'])
        group=research.control_scope_cases()[1]
        group['cases'][0]['route_inventory']=[{'file':'handler.js','path':'/x','method':'POST'}]
        self.assertFalse(research.evaluate(group['proposal'],group['cases'])['promotion_eligible'])

    def test_existing_surface_example_remains_supported(self):
        data=research.example()
        result=research.evaluate(data['proposal'],data['cases'])
        self.assertTrue(result['promotion_eligible'],result['errors'])


if __name__ == '__main__': unittest.main()
