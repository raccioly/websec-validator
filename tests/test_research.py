import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import research

class ResearchTests(unittest.TestCase):
    def test_original_example_has_required_controls(self):
        result=research.evaluate(**research.example()); self.assertTrue(result['promotion_eligible'],result['errors'])
        for part in result['metrics'].values(): self.assertEqual((part['TP'],part['TN'],part['samples']),(1,1,2))
        self.assertEqual(result['promotion_state'],'eligible-for-human-review'); self.assertFalse(result['source_executed'])
        self.assertIn('not blind real-project',result['limitation'])
    def test_missing_holdout_or_safe_or_metadata_fails(self):
        for modify in (lambda x:x['cases'].pop(),lambda x:x['proposal'].pop('license'),lambda x:x['proposal'].update(detector_revision='old')):
            example=research.example();modify(example);self.assertFalse(research.evaluate(**example)['promotion_eligible'])
    def test_copied_holdout_content_does_not_pass(self):
        data=research.example();data['cases'][2]['files']=copy.deepcopy(data['cases'][0]['files'])
        self.assertIn('duplicate case content; development and holdout must be disjoint',research.evaluate(**data)['errors'])
    def test_false_positive_and_false_negative_block_promotion(self):
        data=research.example();data['cases'][0]['label']='safe';data['cases'][1]['label']='vulnerable'
        result=research.evaluate(**data);self.assertFalse(result['promotion_eligible'])
        self.assertEqual(result['metrics']['development']['FP'],1);self.assertEqual(result['metrics']['development']['FN'],1)
    def test_no_supplied_command_template_or_detector_executes(self):
        data=research.example();data['proposal'].update(command='touch forbidden',detector='downloaded:evil')
        with patch('subprocess.run',side_effect=AssertionError('no execution')):
            result=research.evaluate(**data)
        self.assertFalse(result['promotion_eligible']);self.assertGreater(result['metrics']['holdout']['unknown'],0)
    def test_fixture_path_cannot_escape(self):
        data=research.example();data['cases'][0]['files']={'../escape.py':'evil'}
        self.assertFalse(research.evaluate(**data)['promotion_eligible'])
    def test_source_code_is_only_data(self):
        data=research.example();data['cases'][1]['files']['app.py']='raise RuntimeError("must never execute")\n'
        self.assertTrue(research.evaluate(**data)['promotion_eligible'])
    def test_unknown_case_not_false_negative(self):
        data=research.example();data['cases'][0]['label']='unreviewed'
        result=research.evaluate(**data);self.assertEqual(result['metrics']['development']['unknown'],1);self.assertEqual(result['metrics']['development']['FN'],0)

    def test_malformed_types_reject_without_exception(self):
        for modify in (lambda x:x['cases'][0].update(id=[]), lambda x:x['cases'][0].update(id={}),
                       lambda x:x['cases'][0].update(partition={}),lambda x:x['cases'][0].update(files={1:'source'}),
                       lambda x:x['proposal'].update(detector=[]),lambda x:x['proposal'].update(primary_source='https://[bad')):
            data=research.example();modify(data);self.assertFalse(research.evaluate(**data)['promotion_eligible'])

    def test_skipped_or_empty_safe_fixtures_cannot_supply_negative_control(self):
        for name in ('.local/app.py','node_modules/app.js','test_app.py','scripts/helper.py'):
            for index in (1,3):
                data=research.example();data['cases'][index]['files']={name:'print("safe")'}
                result=research.evaluate(**data);self.assertFalse(result['promotion_eligible'], name)
                self.assertEqual(result['metrics'][data['cases'][index]['partition']]['TN'],0)
        data=research.example();data['cases'][1]['files']={'app.py':''}
        self.assertFalse(research.evaluate(**data)['promotion_eligible'])

if __name__ == '__main__': unittest.main()
