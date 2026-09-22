"""Execution accounting and CLI publication regressions with synthetic inputs."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from websec_validator import cli, coverage, formats, recon, scanners
from websec_validator.extractors.base import RepoContext


class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / 'repo'
        self.repo.mkdir()
        (self.repo / 'app.py').write_text('print("synthetic")\n')
        self.out = self.base / 'out'

    def run_cli(self, *args, scanner_result=None, ledger=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch('shutil.which', return_value=None))
            if scanner_result is not None:
                stack.enter_context(patch.object(scanners, 'detect', return_value={
                    'available': [{'key': 'gitleaks', 'name': 'Gitleaks', 'category': 'secrets'}], 'missing': []}))
                stack.enter_context(patch.object(scanners, 'run_available', return_value=scanner_result))
            if ledger is not None:
                stack.enter_context(patch.object(cli.findings, 'build_ledger', return_value=ledger))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            return cli.main(['run', str(self.repo), '--out', str(self.out), *args])

    def latest(self, name):
        # Inspect the most recent attempt directly; partial attempts intentionally
        # do not displace the latest completed execution.
        attempt = max((self.out / 'runs').iterdir(), key=lambda path: path.stat().st_mtime_ns)
        return json.loads((attempt / name).read_text())

    def test_clean_requested_recon_is_complete_but_not_complete_protection(self):
        self.assertEqual(self.run_cli('--require-complete'), 0)
        cov = self.latest('coverage.json')
        self.assertTrue(cov['execution_complete'])
        self.assertFalse(cov['protection_complete'])
        self.assertEqual(cov['files']['read'], 1)
        self.assertTrue(cov['analyzed_input_digest'].startswith('sha256:'))
        self.assertEqual(self.latest('FACTS.json')['coverage'], cov)
        self.assertEqual(self.latest('findings-ledger.json')['coverage'], cov)
        self.assertEqual(self.latest('findings.envelope.json')['coverage'], cov)
        self.assertTrue(self.latest('results.sarif')['runs'][0]['invocations'][0]['executionSuccessful'])

    def test_scanner_timeout_fails_gate_and_keeps_partial_artifacts(self):
        self.assertEqual(self.run_cli(), 0)
        previous = (self.out / 'latest').resolve()
        result = [{'key': 'gitleaks', 'name': 'Gitleaks', 'status': 'timeout'}]
        self.assertEqual(self.run_cli('--scan', '--fail-on', 'high', scanner_result=result), 3)
        cov = self.latest('coverage.json')
        self.assertFalse(cov['execution_complete'])
        self.assertEqual(cov['scanners']['gitleaks']['outcome'], 'timeout')
        self.assertFalse(self.latest('results.sarif')['runs'][0]['invocations'][0]['executionSuccessful'])
        attempt = max((self.out / 'runs').iterdir(), key=lambda path: path.stat().st_mtime_ns)
        self.assertIn('PARTIAL SCAN', (attempt / 'REPORT.md').read_text())
        self.assertEqual((self.out / 'latest').resolve(), previous)

    def test_selected_missing_scanner_is_incomplete_but_optional_missing_is_not(self):
        self.assertEqual(self.run_cli('--scan', '--scanners', 'gitleaks', '--require-complete'), 3)
        self.assertEqual(self.latest('coverage.json')['scanners']['gitleaks']['outcome'], 'unavailable')
        self.assertEqual(self.run_cli('--require-complete'), 0)

    def test_detect_only_selection_does_not_claim_execution(self):
        facts = {'coverage': {'execution_complete': True, 'gaps': [], 'scanners': {}}}
        coverage.add_scanners(facts, {'available': [{'key':'prowler'}], 'missing': []}, [], None,
                              scan=True, only=['prowler'])
        self.assertFalse(facts['coverage']['execution_complete'])
        self.assertEqual(facts['coverage']['scanners']['prowler']['outcome'], 'unsupported_adapter')

    def test_scanner_subset_requires_scan(self):
        self.assertEqual(self.run_cli('--scanners', 'gitleaks'), 2)
        self.assertFalse(self.out.exists())

    def test_scanner_missing_output_and_scalar_json_cannot_pass(self):
        for report in (None, '{}', '[]', 'null'):
            with self.subTest(report=report):
                path = self.base / 'semgrep.json'
                if report is not None:
                    path.write_text(report)
                result = [{'key': 'semgrep', 'name': 'Semgrep', 'exit_code': 0, 'output': str(path)}]
                unified = scanners.normalize_findings(result, self.base)
                self.assertIn('semgrep', unified['parse_failed'])
                path.unlink(missing_ok=True)

    def test_scanner_valid_empty_report_and_reported_errors_are_distinct(self):
        path = self.base / 'semgrep.json'
        result = [{'key': 'semgrep', 'name': 'Semgrep', 'exit_code': 0, 'output': str(path)}]
        path.write_text('{"results":[],"errors":[],"version":"1.2.3"}')
        unified = scanners.normalize_findings(result, self.base)
        self.assertEqual(unified['parse_failed'], [])
        self.assertEqual(unified['report_versions'], {'semgrep':'1.2.3'})
        path.write_text('{"results":[],"errors":[{"message":"timeout"}]}')
        self.assertIn('semgrep', scanners.normalize_findings(result, self.base)['scanner_errors'])

    def test_empty_jsonl_is_distinct_from_unreadable_and_oversized(self):
        path = self.base / 'trufflehog.json'
        path.write_text('')
        result = [{'key':'trufflehog','name':'TruffleHog','exit_code':0,'output':str(path)}]
        self.assertEqual(scanners.normalize_findings(result, self.base)['parse_failed'], [])
        with patch.object(scanners, 'read_artifact', side_effect=PermissionError('synthetic')):
            self.assertEqual(scanners.normalize_findings(result, self.base)['parse_failed'], ['trufflehog'])
        with path.open('wb') as stream:
            stream.truncate(16 * 1024 * 1024 + 1)
        self.assertEqual(scanners.normalize_findings(result, self.base)['parse_failed'], ['trufflehog'])

    def test_openapi_exclusions_private_and_external_aliases_are_not_analyzed(self):
        outside = self.base / 'outside.json'
        outside.write_text('{"openapi":"3.0.0","paths":{"/outside":{"get":{}}}}')
        (self.repo / 'openapi.json').symlink_to(outside)
        (self.repo / '.local').mkdir()
        (self.repo / '.local' / 'swagger.json').write_text(outside.read_text())
        (self.repo / 'omit').mkdir()
        (self.repo / 'omit' / 'swagger.json').write_text(outside.read_text())
        self.assertEqual(self.run_cli('--exclude','omit'), 0)
        facts = self.latest('FACTS.json')
        self.assertEqual(facts['openapi']['specs'], [])
        self.assertEqual(set(facts['coverage']['inputs']), {'app.py'})

    def test_explicit_graph_inputs_cannot_overwrite_target_file_digest(self):
        (self.repo / 'package.json').write_text('{"name":"synthetic"}')
        graph = self.base / 'package.json'
        graph.write_text('{"nodes":[],"edges":[]}')
        self.assertEqual(self.run_cli('--graph',str(graph)), 0)
        inputs = self.latest('coverage.json')['inputs']
        import hashlib
        expected = hashlib.sha256((self.repo / 'package.json').read_bytes()).hexdigest()
        self.assertEqual(inputs['package.json'], expected)
        external = [key for key in inputs if key.startswith('external-graph:')]
        self.assertEqual(len(external), 1)
        self.assertNotEqual(inputs[external[0]], expected)

    def test_scanner_semantic_identity_fields_survive_summary(self):
        path = self.base / 'semgrep.json'
        path.write_text(json.dumps({'results':[{'check_id':'rules.ssrf','path':'app.py',
                              'start':{'line':3},'extra':{'severity':'ERROR','message':'unsafe'}}]}))
        result = [{'key':'semgrep','name':'Semgrep','output':str(path),'exit_code':0}]
        row = scanners.normalize_findings(result, self.base)['all'][0]
        self.assertEqual(row['key'], 'ssrf')
        self.assertEqual(row['line'], 3)

    def test_scanner_full_rule_and_native_occurrence_prevent_early_deduplication(self):
        path = self.base / 'semgrep.json'
        rows = [{'check_id':rule,'path':'app.py','start':{'line':3}, 'match_based_id':native,
                 'extra':{'severity':'ERROR','message':'unsafe'}}
                for rule,native in [('orgA.check','one'),('orgB.check','two'),('orgB.check','three')]]
        path.write_text(json.dumps({'results':rows}))
        result = [{'key':'semgrep','name':'Semgrep','output':str(path),'exit_code':0}]
        unified = scanners.normalize_findings(result, self.base)['all']
        self.assertEqual(len(unified), 3)
        self.assertEqual({row['rule_id'] for row in unified}, {'orgA.check','orgB.check'})
        self.assertEqual({row['semantic_id'] for row in unified}, {'one','two','three'})

    def test_large_source_is_disclosed_after_lazy_reads(self):
        (self.repo / 'app.py').write_text('x' * 40)
        with patch('websec_validator.extractors.base.MAX_BYTES', 20):
            self.assertEqual(self.run_cli('--fail-on', 'high'), 3)
        self.assertEqual(self.latest('coverage.json')['files']['oversized'], ['app.py'])

    def test_extractor_exception_is_disclosed(self):
        with patch('websec_validator.extractors.surface.SurfaceExtractor.extract', side_effect=RuntimeError('synthetic')):
            self.assertEqual(self.run_cli('--require-complete'), 3)
        cov = self.latest('coverage.json')
        self.assertEqual(cov['extractors']['surface']['outcome'], 'error')

    def test_unsupported_source_is_scope_gap_not_execution_failure(self):
        (self.repo / 'server.scala').write_text('object Server')
        self.assertEqual(self.run_cli('--require-complete'), 0)
        cov = self.latest('coverage.json')
        self.assertIn('server.scala', cov['files']['unsupported'])
        self.assertTrue(any(g['kind'] == 'unsupported_source' and not g['execution'] for g in cov['gaps']))

    def test_two_same_second_runs_are_distinct(self):
        first, _ = cli._new_run_dir(str(self.out))
        second, _ = cli._new_run_dir(str(self.out))
        self.assertNotEqual(first, second)
        self.assertFalse((self.out / 'latest').exists())
        cli._publish_run(first)
        self.assertEqual((self.out / 'latest').resolve(), first)
        cli._publish_run(second)
        self.assertEqual((self.out / 'latest').resolve(), second)

    def test_artifact_write_failure_preserves_previous_latest(self):
        self.assertEqual(self.run_cli(), 0)
        previous = (self.out / 'latest').resolve()
        with patch.object(cli.report, 'render', side_effect=OSError('synthetic disk failure')):
            with self.assertRaisesRegex(OSError, 'synthetic disk failure'):
                self.run_cli()
        self.assertEqual((self.out / 'latest').resolve(), previous)
        self.assertEqual(len(list((self.out / 'runs').iterdir())), 2)

    def test_source_digest_changes_with_content_but_not_timestamp(self):
        first = RepoContext(self.repo)
        list(first.iter_code())
        a = coverage.from_context(first, {})['analyzed_input_digest']
        (self.repo / 'app.py').touch()
        second = RepoContext(self.repo)
        list(second.iter_code())
        self.assertEqual(a, coverage.from_context(second, {})['analyzed_input_digest'])
        (self.repo / 'app.py').write_text('changed')
        third = RepoContext(self.repo)
        list(third.iter_code())
        self.assertNotEqual(a, coverage.from_context(third, {})['analyzed_input_digest'])

    def test_invalid_baseline_cannot_pass_gate(self):
        path = self.base / 'baseline.json'
        path.write_text('{broken')
        self.assertEqual(self.run_cli('--baseline', str(path), '--fail-on', 'high'), 3)
        self.assertTrue(any(g['kind'] == 'baseline' for g in self.latest('coverage.json')['gaps']))

    def test_changed_hunk_findings_are_included_in_diff_gate(self):
        ledger = {'findings':[{'title':'synthetic', 'attack_class':'ssrf', 'severity':'HIGH',
                              'confidence':'MEDIUM', 'location':'app.py', 'evidence':[],
                              'standards':{'cwe':[], 'owasp_api':[]},'remediation':'Validate the destination','category':'sast'}],
                  'total':1,'by_severity':{'HIGH':1},'by_confidence':{'MEDIUM':1},'suppressed':0}
        def annotate(current, scope):
            current['findings'][0]['diff_state'] = 'in-changed-hunk'
            return {'changed_files':1,'in_changed_file':1,'untouched':0}
        with patch.object(cli.diffscope, 'compute', return_value={'base':'main','files':{'app.py':[(1,2)]}}):
            with patch.object(cli.diffscope, 'annotate', side_effect=annotate):
                self.assertEqual(self.run_cli('--diff','main','--fail-on','high',ledger=ledger), 1)

    def test_unknown_hand_labels_are_preserved_without_success_claim(self):
        labels = self.base / 'labels.json'
        labels.write_text(json.dumps([{'attack_class':'ssrf','confidence':'LOW','is_real':None}]))
        args = cli.build_parser().parse_args(['calibrate','--ingest',str(labels)])
        with patch.object(cli.calibration, 'record_samples', return_value={'meta':{'samples':0}}) as record:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_calibrate(args), 2)
        self.assertIsNone(record.call_args.args[0][0]['is_real'])

    def test_unknown_only_corpus_does_not_crash_or_replace_calibration(self):
        corpus = self.base / 'corpus.json'
        corpus.write_text(json.dumps([{'name':'synthetic','truth':[{'class':'ssrf','path':'never.py'}]}]))
        output = self.base / 'calibration.json'; output.write_text('previous')
        args = cli.build_parser().parse_args(['calibrate','--corpus',str(corpus),'--out',str(output),
                                             '--workdir',str(self.base / 'work')])
        ledger = {'findings':[{'attack_class':'other-class','location':'app.py','confidence':'LOW'}]}
        with patch.object(cli.proof, '_ensure_repo', return_value=self.repo), patch.object(cli.recon, 'build_facts', return_value={}):
            with patch.object(cli.findings, 'build_ledger', return_value=ledger), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_calibrate(args), 2)
        self.assertEqual(output.read_text(), 'previous')

    def test_inconclusive_dynamic_attempt_keeps_prior_completed_latest(self):
        self.assertEqual(self.run_cli(), 0)
        previous = (self.out / 'latest').resolve()
        dyn = {'unauth_reachability':{'target':'http://127.0.0.1:9', 'state':'inconclusive',
                                     'summary':'unreachable','results':[], 'target_unreachable':True}}
        with patch.object(cli.dynamic, 'run_unauth', return_value=dyn), contextlib.redirect_stdout(io.StringIO()):
            code = cli.main(['dynamic','--unauth','--target','http://127.0.0.1:9','--out',str(self.out)])
        self.assertEqual(code, 3)
        self.assertEqual((self.out / 'latest').resolve(), previous)
        self.assertFalse(self.latest('coverage.json')['execution_complete'])
        ledger = self.latest('findings-ledger.json')
        self.assertEqual(ledger['coverage'], self.latest('coverage.json'))
        self.assertEqual(ledger['target'], str(self.repo))
        self.assertEqual(ledger['verification_context']['source_digest'],
                         ledger['coverage']['analyzed_input_digest'])

    def test_dynamic_candidates_show_details_without_confirmed_bypass_icons(self):
        self.assertEqual(self.run_cli(), 0)
        dyn = {'unauth_reachability': {'target':'http://127.0.0.1:9', 'summary':'observed', 'results':[]},
               'forged_token_bypass': {'summary':'candidate', 'state':'inconclusive', 'results':[
                   {'verdict':'candidate-bypass', 'baseline':401, 'forged':200, 'method':'GET',
                    'path':'/private', 'via':'bearer'}]},
               'write_auth_enforcement': {'summary':'redirect', 'state':'inconclusive', 'results':[
                   {'verdict':'redirect (auth enforcement unverified)', 'status':302,
                    'method':'POST', 'path':'/change'}]}}
        with patch.object(cli.dynamic, 'run_unauth', return_value=dyn), contextlib.redirect_stdout(io.StringIO()) as output:
            cli.main(['dynamic','--unauth','--probe-writes','--target','http://127.0.0.1:9','--out',str(self.out)])
        self.assertIn('candidate-bypass', output.getvalue())
        self.assertIn('/private', output.getvalue())
        self.assertIn('auth enforcement unverified', output.getvalue())
        self.assertNotIn('🚨 BYPASS', output.getvalue())
        self.assertNotIn('🔓', output.getvalue())

    def test_include_fixtures_changes_review_scope(self):
        first = RepoContext(self.repo)
        second = RepoContext(self.repo, include_fixtures=True)
        a = coverage.from_context(first, {})
        b = coverage.from_context(second, {})
        self.assertNotEqual(a['scope_digest'], b['scope_digest'])
        self.assertTrue(b['files']['include_fixtures'])

    def test_named_profile_unknowns_remain_scope_limits_without_execution_failure(self):
        facts = {'coverage':coverage.from_context(RepoContext(self.repo), {}), 'stack':{'profiles':{
            'service_inventory':[{'id':'service'}], 'profiles':[{'id':'synthetic', 'checks':[
                {'id':'direct','status':'completed'}, {'id':'unknown','status':'unknown'},
                {'id':'manual','status':'manual'}]}], 'limitations':['bounded syntax']}}}
        coverage.add_profiles(facts)
        self.assertTrue(facts['coverage']['execution_complete'])
        self.assertEqual(facts['coverage']['profiles'], facts['stack']['profiles']['profiles'])
        self.assertEqual(facts['coverage']['gaps'][-1]['kind'], 'profile_scope')
        self.assertFalse(facts['coverage']['gaps'][-1]['execution'])
        self.assertIn('1 named checks completed', coverage.render_md(facts))

    def test_profile_parse_errors_make_requested_execution_incomplete(self):
        facts = {'coverage':coverage.from_context(RepoContext(self.repo), {}), 'stack':{'profiles':{
            'errors':[{'file':'Info.plist','check':'ios-explicit-ats-exception','error':'invalid configuration'}]}}}
        coverage.add_profiles(facts)
        self.assertFalse(facts['coverage']['execution_complete'])
        self.assertEqual(facts['coverage']['gaps'][-1]['kind'], 'profile_error')

    def test_repair_verify_rejects_unbound_records_without_executing_commands(self):
        plan = self.base / 'plan.json'; plan.write_text('{}')
        record = self.base / 'record.json'; record.write_text('{"command":"do not execute"}')
        rerun = self.base / 'rerun.json'; rerun.write_text('{}')
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['repair-verify','--plan',str(plan),'--record',str(record),
                             '--rerun',str(rerun),'--evidence-root',str(self.repo)])
        self.assertEqual(code, 2)
        result = json.loads(output.getvalue())
        self.assertFalse(result['accepted'])
        self.assertFalse(result['tests_executed_by_websec'])

    def test_repair_verify_accepts_bound_before_and_after_evidence(self):
        import hashlib
        from websec_validator import repairs
        source = self.repo / 'app.js'
        source.write_text('document.write(location.search);')
        self.assertEqual(self.run_cli(), 0)
        plan = next(p for p in self.latest('repair-plans.json') if p['attack_class'] == 'xss')
        source.write_text('document.write("fixed");')
        self.assertEqual(self.run_cli(), 0)
        rerun = self.latest('findings-ledger.json')
        target = rerun['verification_context']
        metadata = {'plan_id':plan['plan_id'], 'finding_id':plan['finding_id']}
        def artifact(name, data):
            content = json.dumps(data)
            (self.base / name).write_text(content)
            return {'artifact':name, 'sha256':hashlib.sha256(content.encode()).hexdigest()}
        before = artifact('before.json', {**plan['original'], **metadata, 'test_id':'unsafe-html',
                          'kind':'negative', 'status':'failed', 'test_count':1, 'failed':1})
        negative = artifact('negative.json', {**target, **metadata, 'test_id':'unsafe-html',
                            'kind':'negative', 'status':'passed', 'test_count':1, 'failed':0, 'before':before})
        positive = artifact('positive.json', {**target, **metadata, 'test_id':'legitimate-html',
                            'kind':'positive', 'status':'passed', 'test_count':1, 'failed':0})
        record = {'plan_id':plan['plan_id'], 'original':plan['original'], 'target':target,
                  'rerun_ledger_sha256':repairs.digest(rerun), 'tests':[positive,negative]}
        for name,data in [('plan.json',plan),('record.json',record),('rerun.json',rerun)]:
            (self.base / name).write_text(json.dumps(data))
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(['repair-verify','--plan',str(self.base / 'plan.json'),
                             '--record',str(self.base / 'record.json'),'--rerun',str(self.base / 'rerun.json'),
                             '--evidence-root',str(self.base)])
        result = json.loads(output.getvalue())
        self.assertEqual(code, 0, result)
        self.assertTrue(result['accepted'])
        self.assertFalse(result['tests_executed_by_websec'])

    def test_mcp_cli_passes_repeated_roots_and_friendly_startup_error(self):
        args = cli.build_parser().parse_args(['mcp', '--http', '--allow-root', str(self.repo), '--allow-root', str(self.base)])
        with patch('websec_validator.mcp_server.serve_http', return_value=0) as serve:
            self.assertEqual(cli.cmd_mcp(args), 0)
        self.assertEqual(serve.call_args.kwargs['allowed_roots'], [str(self.repo), str(self.base)])
        with patch('websec_validator.mcp_server.serve_http', side_effect=ValueError('token required')):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.cmd_mcp(args), 2)


if __name__ == '__main__':
    unittest.main()
