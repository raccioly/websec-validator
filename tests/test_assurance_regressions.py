"""Cross-field assurance: contradictory evidence, intelligence chronology and proof exits."""
import contextlib
import copy
from datetime import datetime, timezone
import gzip
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import cli, coverage, intel, proof, repairs
import test_lifecycle

NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)


def feeds(day, cve='CVE-2026-12345', score='.8', kev_day=None):
    kev_day = kev_day or day
    return {intel.EPSS_URL: gzip.compress(f'#model_version:v2026.06.15,score_date:2026-09-{day}\ncve,epss,percentile\n{cve},{score},.9\n'.encode(), mtime=0),
            intel.KEV_URL: json.dumps({'catalogVersion':f'2026.09.{kev_day}', 'dateReleased':f'2026-09-{kev_day}',
                                      'count':1, 'vulnerabilities':[{'cveID':cve,'dateAdded':f'2026-09-{kev_day}'}]}).encode()}


class RepairConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_lifecycle.RepairEvidenceTests('test_valid_fixed_build_transition_accepts_bound_evidence')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)

    def test_contradictory_execution_gap_cannot_verify_fix(self):
        fixture = self.fixture
        fixture.coverage['gaps'] = [{'kind':'extractor','execution':True,'detail':'surface crashed'}]
        fixture.coverage['files']['unreadable'] = ['app.js']
        fixture.record['rerun_ledger_sha256'] = repairs.digest(fixture.ledger)
        result = fixture.validate()
        self.assertFalse(result['accepted']); self.assertEqual(result['state'], 'verification-rejected')
        self.assertTrue(any('execution gap' in error for error in result['errors']))

    def test_minimal_positive_report_keeps_explicit_attestation_limit(self):
        result = self.fixture.validate()
        self.assertTrue(result['accepted'], result['errors'])
        self.assertIn('not attested', ' '.join(result['validation_limitations']))

    def test_each_execution_loss_and_failed_outcome_is_rejected(self):
        rows = [{'gaps':[{'execution':True}]}, {'files':{'unreadable':['app.py']}},
                {'files':{'oversized':['app.py']}}, {'files':{'truncated':True}},
                {'files':{'inventory_truncated':True}}, {'files':{'glob_truncated':['*.py']}},
                {'extractors':{'surface':{'outcome':'error'}}}, {'dynamic':{'bola':{'outcome':'inconclusive'}}},
                {'profile_errors':[{'error':'parse'}]}, {'profiles':[{'checks':[{'status':'error'}]}]},
                {'scanners':{'tool':{'selected':True,'ran':False,'installed':True,'runnable':True,'outcome':'completed'}}},
                {'scanners':{'tool':{'selected':True,'ran':True,'installed':True,'runnable':True,'outcome':'timeout'}}}]
        for row in rows:
            with self.subTest(row=row): self.assertTrue(coverage.execution_errors({'execution_complete':True, **row}))

    def test_scope_limits_and_unselected_tools_do_not_claim_execution_failure(self):
        manifest = {'execution_complete':True,'gaps':[{'kind':'scope','execution':False}],
                    'files':{'unsupported':['mobile.swift'],'excludes':['vendor/**']},
                    'scanners':{'tool':{'selected':False,'installed':False,'ran':False,'outcome':'unavailable'}},
                    'profiles':[{'checks':[{'status':'manual'},{'status':'not-applicable'}]}]}
        self.assertEqual(coverage.execution_errors(manifest), [])

    def test_malformed_detail_is_not_silently_ignored(self):
        for row in ({'gaps':{}}, {'gaps':[{'execution':'false'}]}, {'files':[]}, {'extractors':[]},
                    {'scanners':{'tool':{'selected':'false'}}}, {'profile_errors':None}, {'profiles':[None]},
                    {'profiles':[{'checks':[{'status':[]}]}]}):
            with self.subTest(row=row): self.assertTrue(coverage.execution_errors({'execution_complete':True, **row}))

    def test_native_scanner_diagnostics_cannot_contradict_completed_outcome(self):
        scanner = {'selected':True, 'ran':True, 'installed':True, 'runnable':True, 'outcome':'completed'}
        for details in ({'errors':['scanner reported errors']}, {'errors':None}, {'errors':{}}, []):
            with self.subTest(details=details):
                manifest = {'execution_complete':True, 'scanners':{'bandit':{**scanner, 'report_details':details}}}
                self.assertTrue(coverage.execution_errors(manifest))
        scanner['report_details'] = {'errors':[], 'skipped_checks':1}
        self.assertEqual(coverage.execution_errors({'execution_complete':True, 'scanners':{'bandit':scanner}}), [])
        fixture = self.fixture
        fixture.coverage['scanners'] = {'bandit':scanner}
        fixture.plan['original_scope_digest'] = repairs.scope_digest(fixture.coverage)
        fixture.record['rerun_ledger_sha256'] = repairs.digest(fixture.ledger)
        # Direct validator rejection remains independent of scope equivalence.
        scanner['report_details']['errors'] = ['scanner reported errors']
        fixture.record['rerun_ledger_sha256'] = repairs.digest(fixture.ledger)
        result = fixture.validate()
        self.assertFalse(result['accepted'])
        self.assertTrue(any('scanner reported errors' in error for error in result['errors']))

    def test_repair_scope_binds_selected_scanner_configuration_and_suppression_policy(self):
        original = {'scanners':{'bandit':{'selected':True, 'reported_version':'1.8',
                    'configuration_policy':'built-in defaults', 'suppression_policy':'ignore nosec'}}}
        original_digest = repairs.scope_digest(original)
        self.assertEqual(original_digest, repairs.scope_digest(copy.deepcopy(original)))
        for field in ('configuration_policy', 'suppression_policy'):
            changed = copy.deepcopy(original)
            changed['scanners']['bandit'][field] = 'target-controlled'
            self.assertNotEqual(original_digest, repairs.scope_digest(changed))
        original['scanners']['bandit']['report_details'] = {'errors':[], 'skipped_checks':3}
        self.assertEqual(original_digest, repairs.scope_digest(original))

    def test_completed_extractor_or_dynamic_row_cannot_override_error_diagnostics(self):
        for group in ('extractors', 'dynamic'):
            for diagnostic in ({'error':'ValueError'}, {'error':{}}, {'error':False},
                               {'errors':['failed']}, {'errors':None}, {'errors':''}):
                manifest = {'execution_complete':True, group:{'check':{'outcome':'completed', **diagnostic}}}
                with self.subTest(group=group, diagnostic=diagnostic):
                    self.assertTrue(coverage.execution_errors(manifest))
            for diagnostic in ({}, {'error':None}, {'error':''}, {'errors':[]}):
                manifest = {'execution_complete':True, group:{'check':{'outcome':'completed', **diagnostic}}}
                self.assertEqual(coverage.execution_errors(manifest), [])


class IntelligenceChronologyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
    def refresh(self, data, root=None):
        return intel.refresh(root or self.root, fetcher=data.__getitem__, now=NOW)

    def test_older_feed_preserves_current_snapshot_and_keV(self):
        initial=self.refresh(feeds('12'))
        for data in (feeds('11'), feeds('12',kev_day='11')):
            result=self.refresh(data)
            self.assertEqual(result['last_refresh']['outcome'],'failed')
            self.assertEqual(result['last_refresh']['reason'],'feed-rollback')
            self.assertEqual(result['snapshot_id'],initial['snapshot_id'])
            self.assertIn('CVE-2026-12345',intel.load_snapshot(self.root)['kev'])

    def test_newer_genuine_correction_is_accepted(self):
        self.refresh(feeds('11'))
        before=intel.reassess({'findings':[{'fingerprint':'stable','cve':'CVE-2026-12345'}]},self.root,now=NOW)['ledger']
        self.assertEqual(self.refresh(feeds('12','CVE-2026-54321'))['last_refresh']['outcome'],'success')
        result=intel.reassess(before,self.root,now=NOW)
        self.assertFalse(result['ledger']['findings'][0]['kev'])
        self.assertEqual(result['blocked_findings'],0)
        self.assertEqual(result['ledger']['findings'][0]['fingerprint'],'stable')

    def test_independent_older_cache_cannot_overwrite_newer_finding_evidence(self):
        self.refresh(feeds('12'))
        current=intel.reassess({'findings':[{'fingerprint':'stable','cve':'CVE-2026-12345'}]},self.root,now=NOW)['ledger']
        old=self.root/'older';self.refresh(feeds('11','CVE-2026-54321'),old)
        result=intel.reassess(current,old,now=NOW)
        self.assertEqual(result['blocked_findings'],1)
        self.assertEqual(result['ledger']['findings'],current['findings'])
        self.assertEqual(result['ledger']['metadata']['intel'],current['metadata']['intel'])
        self.assertEqual(result['events'],[])
        ledger_path=self.root/'ledger.json';ledger_path.write_text(json.dumps(current))
        with contextlib.redirect_stdout(io.StringIO()):
            code=cli.main(['intel','reassess','--ledger',str(ledger_path),'--cache-dir',str(old)])
        self.assertEqual(code,2)

    def test_publication_lock_is_bounded_and_stale_file_is_inert(self):
        with intel._publication_lock(self.root), patch.object(intel,'_LOCK_WAIT_SECONDS',.01):
            with self.assertRaises(TimeoutError):
                with intel._publication_lock(self.root): pass
        self.assertTrue((self.root/'refresh.lock').exists())
        with intel._publication_lock(self.root): pass

    def test_partial_finding_provenance_cannot_hide_newer_ledger_dates(self):
        self.refresh(feeds('12'))
        current = intel.reassess({'findings':[{'fingerprint':'stable','cve':'CVE-2026-12345'}]},self.root,now=NOW)['ledger']
        old = self.root/'older'; self.refresh(feeds('11','CVE-2026-54321'),old)
        for provenance in ({'snapshot_id':'imported'}, {'sources':[]},
                           {'sources':{'kev':{'feed_date':'not-date'}}}, {}):
            with self.subTest(provenance=provenance):
                altered = copy.deepcopy(current); altered['findings'][0]['intel'] = provenance
                result = intel.reassess(altered,old,now=NOW)
                self.assertEqual(result['blocked_findings'],1)
                self.assertEqual(result['ledger']['findings'],altered['findings'])
                self.assertEqual(result['ledger']['metadata']['intel'],current['metadata']['intel'])
                self.assertEqual(result['events'],[])

    def test_each_valid_provenance_layer_independently_prevents_rollback(self):
        self.refresh(feeds('12'))
        current = intel.reassess({'findings':[{'fingerprint':'stable','cve':'CVE-2026-12345'}]},self.root,now=NOW)['ledger']
        old = self.root/'older'; self.refresh(feeds('11','CVE-2026-54321'),old)
        old_report = intel.status(old,now=NOW)
        for layer in ('ledger','finding'):
            altered = copy.deepcopy(current)
            if layer == 'ledger': altered['findings'][0]['intel'] = old_report
            else: altered['metadata']['intel'] = old_report
            result = intel.reassess(altered,old,now=NOW)
            self.assertEqual(result['blocked_findings'],1)
            self.assertTrue(result['ledger']['findings'][0]['kev'])

    def test_dead_process_releases_publication_lock(self):
        source='from pathlib import Path; from websec_validator import intel; import sys,time\nwith intel._publication_lock(Path(sys.argv[1])):\n print("locked",flush=True)\n time.sleep(30)'
        process=subprocess.Popen([sys.executable,'-c',source,str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                                 text=True,env={**os.environ,'PYTHONPATH':str(Path(intel.__file__).parents[1])})
        self.addCleanup(lambda: process.poll() is None and process.kill())
        self.assertEqual(process.stdout.readline().strip(),'locked')
        process.kill();process.communicate(timeout=5)
        with intel._publication_lock(self.root): pass

    def test_last_good_is_reloaded_under_lock(self):
        old_data=feeds('11'); newer=feeds('12')
        original_fetcher=old_data.__getitem__
        def fetcher(url):
            if url==intel.KEV_URL: self.refresh(newer)
            return original_fetcher(url)
        result=intel.refresh(self.root,fetcher=fetcher,now=NOW)
        self.assertEqual(result['last_refresh']['reason'],'feed-rollback')
        self.assertEqual(result['sources']['kev']['feed_date'],'2026-09-12')


class ProofAssuranceCliTests(unittest.TestCase):
    def run_result(self, *, completed=1, unavailable=0, incomplete=0, passed=1, total=1, unknown=0, labels=7):
        rows=[]
        for index in range(completed+incomplete):
            rows.append({'name':'app'+str(index),'status':'analyzed','execution_complete':index<completed,
                         'passed':passed,'total':total,'unknown_labels':labels,'unknown_checks':unknown,
                         'revision_status':'pinned-verified','actual_revision':'a'*40,'checks':[]})
        rows.extend({'name':'missing'+str(i),'status':'unavailable','revision_status':'cache-mismatch'} for i in range(unavailable))
        result={'results':rows,'aggregate':{'apps':len(rows),'analyzed_apps':completed+incomplete,'completed_apps':completed,
                'incomplete_apps':incomplete,'unavailable_apps':unavailable,'checks_passed':passed,'checks_total':total,
                'failed_checks':total-passed,'unknown_checks':unknown,'unknown_labels':labels,
                'overall_coverage':passed/total if total else None}}
        with patch.object(proof,'run_proof',return_value=result),contextlib.redirect_stdout(io.StringIO()) as output:
            code=cli.main(['proof'])
        return code,output.getvalue()

    def test_unavailable_and_incomplete_never_exit_success(self):
        code,text=self.run_result(unavailable=2)
        self.assertEqual(code,2);self.assertIn('1 completed',text);self.assertIn('2 unavailable',text)
        code,text=self.run_result(completed=0,incomplete=1,passed=0,total=0,unknown=1)
        self.assertEqual(code,2);self.assertIn('1 incomplete',text);self.assertIn('1 checks',text)

    def test_complete_failed_and_passed_checks_have_distinct_exit(self):
        self.assertEqual(self.run_result(passed=0)[0],1)
        code,text=self.run_result(labels=7)
        self.assertEqual(code,0);self.assertIn('7 truth labels',text);self.assertIn('pinned-verified',text)
        self.assertIn('excluded from calibration',text)

    def test_no_evaluated_checks_exit_incomplete(self):
        self.assertEqual(self.run_result(completed=0,passed=0,total=0)[0],2)

    def test_proof_rejects_contradictory_completion_summary(self):
        result=proof._score({'expect':{'min_endpoints':1}},
                            {'routes':{'count':2},'coverage':{'execution_complete':True,'gaps':[{'execution':True,'kind':'extractor'}]}})
        self.assertIsNone(result['score']);self.assertEqual(result['unknown_checks'],1)

if __name__=='__main__':unittest.main()
