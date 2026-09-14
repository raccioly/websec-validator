import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import proof, calibration

PIN='a'*40
class ProofRevisionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.entry={'name':'fixture','repo':'https://github.com/example/repo','revision':PIN}
    def test_remote_pin_required_without_network(self):
        self.entry.pop('revision')
        with patch.object(proof,'_git',side_effect=AssertionError('network forbidden')):
            result=proof.prepare_repo(self.entry,self.root)
        self.assertIsNone(result['path']);self.assertEqual(result['revision_status'],'missing-or-invalid-pin')
    def test_cached_mismatched_revision_not_reused_or_reset(self):
        dest=self.root/'fixture';dest.mkdir();(dest/'keep').write_text('user work')
        with patch.object(proof,'_git',side_effect=['b'*40,str(dest)]) as git, patch.object(proof,'_clean_tree',return_value=True):
            result=proof.prepare_repo(self.entry,self.root)
        self.assertEqual(result['revision_status'],'cache-mismatch');self.assertEqual((dest/'keep').read_text(),'user work')
        self.assertEqual([call.args[0][0] for call in git.call_args_list],['rev-parse','rev-parse'])
    def test_cached_pinned_clean_revision_valid(self):
        dest=self.root/'fixture';dest.mkdir()
        with patch.object(proof,'_git',side_effect=[PIN,str(dest)]), patch.object(proof,'_clean_tree',return_value=True):result=proof.prepare_repo(self.entry,self.root)
        self.assertEqual(result['path'],str(dest));self.assertEqual(result['actual_revision'],PIN)
    def test_dirty_cache_refused(self):
        dest=self.root/'fixture';dest.mkdir()
        with patch.object(proof,'_git',side_effect=[PIN,str(dest)]), patch.object(proof,'_clean_tree',return_value=False):result=proof.prepare_repo(self.entry,self.root)
        self.assertIsNone(result['path'])
    def test_local_path_explicitly_unpinned(self):
        result=proof.prepare_repo({'local_path':str(self.root)},self.root)
        self.assertEqual(result['revision_status'],'local-path-unpinned')
    def test_aggregate_reports_unavailable(self):
        corpus=self.root/'corpus.json';corpus.write_text(json.dumps([self.entry,{'name':'local','local_path':str(self.root),'expect':{'min_endpoints':2}}]))
        prepared=[{'path':None,'revision_status':'unavailable'},{'path':str(self.root),'revision_status':'local-path-unpinned'}]
        with patch.object(proof,'prepare_repo',side_effect=prepared),patch.object(proof.recon,'build_facts',return_value={'routes':{'count':1},'coverage':{'execution_complete':True}}):
            result=proof.run_proof(corpus,self.root/'cache')
        self.assertEqual(result['aggregate']['analyzed_apps'],1);self.assertEqual(result['aggregate']['unavailable_apps'],1)
        self.assertEqual(result['aggregate']['failed_checks'],1)
    def test_shipped_pins_and_labels_honest(self):
        rows=json.loads((Path(proof.__file__).parent/'corpus.json').read_text())
        for row in rows:
            self.assertRegex(row['revision'],r'^[a-f0-9]{40}$')
            for truth in row['truth']: self.assertIsNone(calibration.is_real(truth['class'],'/any',[truth]))

    def test_raw_tree_bypasses_malicious_filters_and_assume_unchanged(self):
        dest=self.root/'fixture';dest.mkdir()
        proof._git(['init',str(dest)])
        (dest/'app.py').write_text('print("original")\n')
        (dest/'.gitattributes').write_text('*.py filter=evil\n')
        proof._git(['add','.'],dest)
        proof._git(['-c','user.name=Test','-c','user.email=test@example.invalid','commit','-m','fixture'],dest)
        marker=self.root/'executed'; script=self.root/'evil.sh'
        script.write_text('#!/bin/sh\ntouch "'+str(marker)+'"\ncat\n');script.chmod(0o700)
        proof._git(['update-index','--assume-unchanged','app.py'],dest)
        proof._git(['config','filter.evil.clean',str(script)],dest)
        proof._git(['config','core.fsmonitor',str(script)],dest)
        self.assertTrue(proof._clean_tree(dest))
        self.assertFalse(marker.exists())
        (dest/'app.py').write_text('print("changed")\n')
        self.assertFalse(proof._clean_tree(dest))
        self.assertFalse(marker.exists())

    def test_incomplete_execution_checks_are_unknown(self):
        result=proof._score({'expect':{'min_endpoints':1}},{'routes':{'count':1},'coverage':{'execution_complete':False}})
        self.assertEqual(result['unknown_checks'],1);self.assertIsNone(result['checks'][0]['pass'])
        self.assertEqual(result['total'],0)

    def test_invalid_entry_reports_unavailable(self):
        corpus=self.root/'bad.json';corpus.write_text('[null, 42]')
        result=proof.run_proof(corpus,self.root/'cache')
        self.assertEqual(result['aggregate']['unavailable_apps'],2)

    def test_malformed_paths_and_name_fail_as_data(self):
        for entry in ({'local_path':1},{**self.entry,'name':1}):
            self.assertIsNone(proof.prepare_repo(entry,self.root)['path'])

    def test_malformed_expectations_or_truth_report_unavailable_before_recon(self):
        corpus=self.root/'malformed.json';corpus.write_text(json.dumps([
            {'name':'a','local_path':str(self.root),'expect':{'min_endpoints':'two'}},
            {'name':'b','local_path':str(self.root),'truth':[None]}]))
        with patch.object(proof.recon,'build_facts',side_effect=AssertionError('invalid entry must not analyze')):
            result=proof.run_proof(corpus,self.root/'cache')
        self.assertEqual(result['aggregate']['unavailable_apps'],2)

if __name__ == '__main__':unittest.main()
