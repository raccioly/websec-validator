import copy
import gzip
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import intel, enrichment, calibration

NOW = datetime(2026, 9, 12, tzinfo=timezone.utc)

def feeds(epss='0.8', cve='CVE-2025-12345'):
    # mtime=0 is REQUIRED, not tidiness: gzip.compress() stamps the current epoch second into
    # the header (bytes 4..8), so building the same feed twice yields different BYTES whenever
    # the two calls straddle a second boundary. test_identical_refresh_source_keeps_semantic_id
    # builds the feeds once per refresh and compares snapshot ids; the id hashes
    # sources.epss.sha256, so it flipped at random — green locally, a rare red on CI. The
    # snapshot id was right to differ: the source bytes really had changed.
    return {intel.EPSS_URL: gzip.compress(('#model_version:v2026.06.15,score_date:2026-09-12\ncve,epss,percentile\n'+cve+','+epss+',0.95\n').encode(), mtime=0),
            intel.KEV_URL: json.dumps({'catalogVersion':'2026.09.12','dateReleased':'2026-09-12T10:00:00Z','count':1,
                                     'vulnerabilities':[{'cveID':cve,'dateAdded':'2026-09-11'}]}).encode()}

class IntelligenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
    def refresh(self, data=None):
        return intel.refresh(self.root, fetcher=(data or feeds()).__getitem__, now=NOW)
    def test_valid_refresh_offline_status_enrichment(self):
        state = self.refresh(); self.assertTrue(state['available']); self.assertEqual(state['freshness'], 'fresh')
        with patch.object(intel, '_fetch', side_effect=AssertionError('network forbidden')):
            rows = [{'cve':'CVE-2025-12345','title':'issue','severity':'HIGH'}]
            enrichment.enrich_exploitability(rows, self.root)
            self.assertTrue(rows[0]['kev']); self.assertEqual(rows[0]['epss'], 0.8)
            self.assertEqual(rows[0]['intel']['sources']['epss']['model_date'], '2026-06-15')
    def test_failure_preserves_previous_snapshot_and_records_failure(self):
        previous = self.refresh()['snapshot_id']
        bad = feeds('nan'); result = self.refresh(bad)
        self.assertEqual(result['snapshot_id'], previous); self.assertEqual(result['last_refresh']['outcome'], 'failed')
        self.assertEqual(intel.load_snapshot(self.root)['epss']['CVE-2025-12345'][0], 0.8)
    def test_atomic_publication_failure_keeps_current(self):
        previous = self.refresh()['snapshot_id']; real = intel._atomic
        def fail(path, data):
            if path.name == 'current.json': raise OSError('interrupted')
            return real(path, data)
        with patch.object(intel, '_atomic', side_effect=fail): self.refresh(feeds('0.7'))
        self.assertEqual(intel.status(self.root)['snapshot_id'], previous)
    def test_invalid_numbers_shapes_dates_and_duplicates(self):
        for probability in ('nan', 'inf', '-0.1', '1.1'):
            with self.subTest(probability=probability): self.assertFalse(self.refresh(feeds(probability))['available'])
        data = feeds(); obj = json.loads(data[intel.KEV_URL]); obj['count']=2; data[intel.KEV_URL]=json.dumps(obj).encode()
        self.assertFalse(self.refresh(data)['available'])
        with self.assertRaises(ValueError): intel._date('2099-01-01', NOW.date())
        with self.assertRaises(ValueError): intel.parse_epss(gzip.compress(b'cve,epss,percentile\nCVE-2025-12345,0.1,0.2'), NOW.date())
    def test_decompression_and_download_are_bounded(self):
        with patch.object(intel, 'MAX_EXPANDED', 20): self.assertFalse(self.refresh()['available'])
        with patch.object(intel, 'MAX_DOWNLOAD', 10): self.assertFalse(self.refresh()['available'])
    def test_redirect_policy(self):
        for url in ('http://www.cisa.gov/a','https://evil.test/a','https://user:pw@www.cisa.gov/a','https://www.cisa.gov:444/a'):
            with self.assertRaises(ValueError): intel._url(url)
        intel._url(intel.EPSS_URL)
    def test_integrity_and_staleness(self):
        state=self.refresh(); self.assertEqual(intel.status(self.root, now=datetime(2026,10,1,tzinfo=timezone.utc))['freshness'], 'stale')
        path=self.root/'snapshots'/(state['snapshot_id']+'.json'); obj=json.loads(path.read_text()); obj['epss']={};path.write_text(json.dumps(obj))
        self.assertFalse(intel.status(self.root)['available'])
    def test_reassess_preserves_id_and_no_duplicate_same_snapshot(self):
        self.refresh(); original={'findings':[{'fingerprint':'stable','cve':'CVE-2025-12345','kev':False,'epss':0.1}]}
        result=intel.reassess(original,self.root,now=NOW)
        self.assertIn('newly-exploited',[x['kind'] for x in result['events']]); self.assertEqual(result['ledger']['findings'][0]['fingerprint'],'stable')
        self.assertFalse(original['findings'][0]['kev'])
        self.assertEqual(intel.reassess(result['ledger'],self.root,now=NOW)['events'],[])
        self.assertIn('inventory/advisory rescan',result['limitations'][0])
    def test_feed_fixture_is_byte_stable_across_calls(self):
        """Guards the flake above at its source: two builds of the same feed must be identical
        bytes, or any test comparing snapshot ids is timing-dependent."""
        self.assertEqual(feeds()[intel.EPSS_URL], feeds()[intel.EPSS_URL])
        self.assertEqual(feeds()[intel.KEV_URL], feeds()[intel.KEV_URL])

    def test_identical_refresh_source_keeps_semantic_id(self):
        first=self.refresh(); second=intel.refresh(self.root,fetcher=feeds().__getitem__,now=datetime(2026,9,13,tzinfo=timezone.utc))
        self.assertEqual(first['snapshot_id'],second['snapshot_id'])
    def test_legacy_cache_is_explicitly_unverified(self):
        (self.root/'epss.csv').write_text('cve,epss,percentile\nCVE-2025-12345,0.4,0.6\nCVE-2025-99999,nan,0.2\n')
        rows=[{'cve':'CVE-2025-12345'},{'cve':'CVE-2025-99999'}]; enrichment.enrich_exploitability(rows,self.root)
        self.assertEqual(rows[0]['intel']['provenance'],'legacy-unverified'); self.assertNotIn('epss',rows[1])
    def test_shipped_calibration_is_reviewed_and_measured(self):
        """Relabelled 2026-09-22: the shipped table carries reviewed labels, not quarantined ones.

        The quarantine RULE — which withdrew the previous labels — is exercised against a synthetic
        historical table in test_calibration_claimspec, so it stays covered without pinning this
        test to whatever the corpus currently measures.
        """
        table = calibration.load_shipped()
        self.assertEqual(table['meta']['evidence_status'], 'reviewed')
        self.assertGreater(table['meta']['n_total'], 0)
        self.assertTrue(table['by_class_label'])
        self.assertNotIn('legacy_uncertain', table)
    def test_no_import_observation_never_claims_unreachable(self):
        (self.root/'app.py').write_text('import yaml\n')
        rows=[{'category':'sca','pkg':'requests','ecosystem':'pip','title':'CVE'}]; enrichment.enrich_reachability(rows,self.root)
        self.assertNotIn('likely unreachable', rows[0]['title']); self.assertIn('runtime reachability is unknown',rows[0]['title'])

    def test_absolute_download_deadline_stops_drip_feed(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def geturl(self): return intel.EPSS_URL
            def read1(self, count): return b'a'
        class Opener:
            def open(self, *args, **kwargs): return Response()
        with patch.object(intel, 'build_opener', return_value=Opener()), patch.object(intel.time, 'monotonic', side_effect=[0, 1, 61]):
            with self.assertRaises(TimeoutError): intel._fetch(intel.EPSS_URL)

    def test_loader_rejects_rehashed_invalid_schema_or_probability(self):
        self.refresh(); body=intel.load_snapshot(self.root); body['epss']['CVE-2025-12345'][0]=2
        sid=intel._hash(intel._encoded({k:v for k,v in body.items() if k not in {'snapshot_id','retrieved_at'}}))
        body['snapshot_id']=sid
        intel._atomic(self.root/'snapshots'/(sid+'.json'), body)
        intel._atomic(self.root/'current.json', {'snapshot_id':sid})
        self.assertIsNone(intel.load_snapshot(self.root))

    def test_detector_change_reports_rescan_without_claiming_new_detection(self):
        self.refresh(); ledger={'findings':[], 'coverage':{'detector_revision':'old'}}
        with patch('websec_validator.coverage.detector_revision',return_value='new'):
            result=intel.reassess(ledger,self.root,now=NOW)
            self.assertEqual(result['events'][0]['kind'],'detector-changed-rescan-required')
            self.assertEqual(intel.reassess(result['ledger'],self.root,now=NOW)['events'],[])
        self.assertEqual(result['ledger']['coverage']['detector_revision'],'old')

    def test_newly_exploited_acknowledged_debt_reopens_with_history(self):
        self.refresh()
        finding={'fingerprint':'accepted-cve','cve':'CVE-2025-12345','kev':False,'epss':.1,
                 'status':'acknowledged','ack_reason':'Scheduled upgrade','acknowledgement':{'reason':'Scheduled upgrade','expires':'2026-12-01'}}
        ledger={'findings':[],'acknowledged':[finding],'coverage':{'analyzed_input_digest':'same-source'}}
        result=intel.reassess(ledger,self.root,now=NOW)
        current=result['ledger']['findings'][0]
        self.assertEqual(current['fingerprint'],'accepted-cve');self.assertTrue(current['needs_review'])
        self.assertEqual(current['state'],'reopened');self.assertEqual(current['previous_acknowledgement']['reason'],'Scheduled upgrade')
        self.assertEqual(result['ledger']['acknowledged'],[])
        self.assertEqual(result['ledger']['coverage']['analyzed_input_digest'],'same-source')
        self.assertEqual(intel.reassess(result['ledger'],self.root,now=NOW)['events'],[])
        self.assertEqual(ledger['acknowledged'][0]['status'],'acknowledged')

    def test_extra_source_rehashed_snapshot_is_rejected_without_status_crash(self):
        self.refresh();body=intel.load_snapshot(self.root);body['sources']['unexpected']={}
        sid=intel._hash(intel._encoded({k:v for k,v in body.items() if k not in {'snapshot_id','retrieved_at'}}));body['snapshot_id']=sid
        intel._atomic(self.root/'snapshots'/(sid+'.json'),body);intel._atomic(self.root/'current.json',{'snapshot_id':sid})
        self.assertFalse(intel.status(self.root)['available'])

if __name__ == '__main__': unittest.main()
