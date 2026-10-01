"""Captured reports preserve provenance, unknown outcomes and contained writes.

@req specs/001-continuous-security-improvement/spec.md#FR-004
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/compare-reports.py'
spec = importlib.util.spec_from_file_location('comparison_script', SCRIPT)
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)


class ComparisonTests(unittest.TestCase):
    def setUp(self):
        self.owned = tempfile.TemporaryDirectory()
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name)
        self.labels = [dict(id='positive', file='app.py', line=10, attack_class='sqli', reviewed=True, real=True),
                       dict(id='negative', file='app.py', line=20, attack_class='sqli', reviewed=True, real=False)]
        scope = comparison.sha(b'["app.py"]')
        self.manifest = dict(schema_version=1, corpus_revision='a'*40, scope=['app.py'],
                             labels='labels.json', labels_sha256=self.save('labels.json', self.labels), reports=[])
        for tool in ('websec', 'semgrep', 'bandit'):
            rows = [self.row(tool, line) for line in (10, 20, 30)]
            doc = dict(findings=rows, total=3, coverage={'execution_complete': True}) if tool=='websec' else dict(results=rows, errors=[])
            if tool == 'bandit':
                doc['metrics'] = {'_totals': {'nosec': 0, 'skipped_tests': 0}}
            name = tool+'.json'
            self.manifest['reports'].append(dict(tool=tool, version='1.2.3', configuration_sha256='b'*64,
                engine_source_revision='d'*40, package_sha256='e'*64, detector_sha256='f'*64,
                scope_sha256=scope, status='completed', report=name, report_sha256=self.save(name, doc),
                rules={'sql-rule': dict(attack_class='sqli', reviewed=True)}))

    def save(self, name, value):
        data = (json.dumps(value)+'\n').encode()
        (self.root/name).write_bytes(data)
        return comparison.sha(data)

    def row(self, tool, line):
        secret = 'NEVER-PERSIST-SOURCE-OR-CREDENTIAL'
        if tool=='websec':
            return dict(rule_id='sql-rule', file='app.py', line=line, evidence=[secret], title=secret)
        if tool=='semgrep':
            return dict(check_id='sql-rule', path='app.py', start={'line': line}, extra={'message': secret, 'lines': secret})
        return dict(test_id='sql-rule', filename='app.py', line_number=line, code=secret, issue_text=secret)

    def result(self):
        return comparison.compare(self.root, self.manifest)

    def test_per_tool_unknown_policy_and_sanitized_rows(self):
        result = self.result()
        for tool in result['tools']:
            self.assertEqual(tool['counts'], {'tp':1, 'fp':1, 'unknown':1})
            self.assertEqual(tool['precision'], .5)
            self.assertEqual(tool['reviewed_positive_label_coverage'], 1)
            self.assertEqual(tool['engine_source_revision'], 'd'*40)
            self.assertEqual(tool['package_sha256'], 'e'*64)
            self.assertEqual(len(tool['rule_mapping_sha256']), 64)
        self.assertEqual(result['tools'][0]['detector_sha256'], 'f'*64)
        self.assertEqual(len(result['grading_manifest_sha256']), 64)
        self.assertNotIn('NEVER-PERSIST', json.dumps(result)+comparison.csv_text(result))
        self.assertEqual(len(result['findings']), 9)  # No cross-tool deduplication.

    def test_unreviewed_nonboolean_and_conflicting_labels_are_unknown(self):
        for value in ('false', 1, None):
            labels = copy.deepcopy(self.labels)
            labels[0]['real'] = value
            self.manifest['labels_sha256'] = self.save('labels.json', labels)
            self.assertEqual(self.result()['tools'][0]['counts']['unknown'], 2)
        labels = copy.deepcopy(self.labels)
        labels[0]['reviewed'] = False
        self.manifest['labels_sha256'] = self.save('labels.json', labels)
        self.assertEqual(self.result()['tools'][0]['counts']['unknown'], 2)
        labels = self.labels+[dict(self.labels[0], id='conflict', real=False)]
        self.manifest['labels_sha256'] = self.save('labels.json', labels)
        result = self.result()
        self.assertEqual(result['tools'][0]['counts']['unknown'], 2)
        self.assertEqual(result['reviewed_positive_labels'], 0)

    def test_unreviewed_rule_mapping_never_borrows_label_credit(self):
        self.manifest['reports'][0]['rules']['sql-rule']['reviewed'] = False
        self.assertEqual(self.result()['tools'][0]['counts'], dict(tp=0, fp=0, unknown=3))

    def test_duplicate_findings_preserve_precision_but_not_duplicate_label_hits(self):
        doc = dict(results=[self.row('bandit', 10)]*2, errors=[], metrics={'_totals': {'nosec': 0, 'skipped_tests': 0}})
        self.manifest['reports'][2]['report_sha256'] = self.save('bandit.json', doc)
        tool = self.result()['tools'][2]
        self.assertEqual(tool['counts']['tp'], 2)
        self.assertEqual(tool['reviewed_positive_label_hits'], 1)

    def test_partial_unavailable_malformed_are_not_clean_or_scored(self):
        self.manifest['reports'][0]['status'] = 'unavailable'
        self.manifest['reports'][1]['report_sha256'] = self.save('semgrep.json', dict(results=[], errors=[{'message':'SECRET'}]))
        self.manifest['reports'][2]['report_sha256'] = 'c'*64
        tools = self.result()['tools']
        self.assertEqual([row['status'] for row in tools], ['unavailable','partial','malformed'])
        self.assertTrue(all(row['precision'] is None for row in tools))
        self.assertIsNone(tools[0]['counts'])
        self.assertIsNone(tools[2]['counts'])

    def test_missing_websec_coverage_and_malformed_rows_are_not_completed(self):
        self.manifest['reports'][0]['report_sha256'] = self.save('websec.json', dict(total=0, findings=[]))
        self.assertEqual(self.result()['tools'][0]['status'], 'partial')
        self.manifest['reports'][1]['report_sha256'] = self.save('semgrep.json', dict(results=[None]))
        self.assertEqual(self.result()['tools'][1]['status'], 'malformed')

    def test_scope_and_labels_bytes_are_required_bindings(self):
        original = copy.deepcopy(self.manifest)
        for key, value in [('scope', ['other.py']), ('labels_sha256', 'c'*64), ('corpus_revision', 'main')]:
            self.manifest = copy.deepcopy(original)
            self.manifest[key] = value
            with self.assertRaises(ValueError):
                self.result()
        for key in ('engine_source_revision', 'package_sha256', 'detector_sha256'):
            self.manifest = copy.deepcopy(original)
            self.manifest['reports'][0].pop(key)
            with self.assertRaises(ValueError):
                self.result()

    def test_absolute_traversal_private_and_route_locations_stay_unknown(self):
        doc = dict(results=[dict(self.row('bandit', 10), filename=name)
                            for name in ('/app.py','../app.py','.LOCAL/app.py','/api/users')],
                   errors=[], metrics={'_totals': {'nosec': 0, 'skipped_tests': 0}})
        self.manifest['reports'][2]['report_sha256'] = self.save('bandit.json', doc)
        result = self.result()
        self.assertEqual(result['tools'][2]['counts']['unknown'], 4)
        self.assertTrue(all(row['file'] is None for row in result['findings'] if row['tool']=='bandit'))

    def test_private_or_symlink_inputs_are_not_read(self):
        sentinel = self.root/'outside.json'
        sentinel.write_text('SENSITIVE')
        (self.root/'alias.json').symlink_to(sentinel)
        with self.assertRaises(OSError):
            comparison.read_json(self.root, 'alias.json')
        private = self.root/'.local'
        private.mkdir()
        (private/'data.json').write_text('{}')
        with self.assertRaises(ValueError):
            comparison.read_json(private, 'data.json')

    def test_work_limits_and_duplicate_json_keys_fail_closed(self):
        with patch.object(comparison, 'MAX_ROWS', 1):
            with self.assertRaises(ValueError):
                self.result()
        (self.root/'duplicate.json').write_text('{"results":[],"results":[]}')
        with self.assertRaises(ValueError):
            comparison.read_json(self.root, 'duplicate.json')
        with self.assertRaises(ValueError):
            comparison.read_json(self.root, 'labels.json', limit=2)

    def test_csv_formula_prefix_is_escaped(self):
        result = self.result()
        result['findings'][0]['file'] = '=formula.py'
        self.assertIn("'=formula.py", comparison.csv_text(result))

    def test_native_skips_suppressions_and_malformed_diagnostics_are_not_scored(self):
        for key in ('nosec', 'skipped_tests'):
            doc = dict(results=[self.row('bandit', 10)], errors=[],
                       metrics={'_totals': {'nosec': 0, 'skipped_tests': 0}})
            doc['metrics']['_totals'][key] = 1
            self.manifest['reports'][2]['report_sha256'] = self.save('bandit.json', doc)
            tool = self.result()['tools'][2]
            self.assertEqual(tool['status'], 'partial')
            self.assertIsNone(tool['precision'])
        for tool, diagnostic in [('bandit', {'errors':False,'metrics':None}),
                                 ('bandit', {'metrics':{'_totals':{'nosec':False,'skipped_tests':0}}}),
                                 ('semgrep', {'errors':False,'skipped_rules':False}),
                                 ('semgrep', {'errors':[],'skipped_rules':False})]:
            doc = dict(results=[self.row(tool, 10)], errors=[])
            doc.update(diagnostic)
            entry = next(row for row in self.manifest['reports'] if row['tool']==tool)
            entry['report_sha256'] = self.save(tool+'.json', doc)
            self.assertEqual(next(row for row in self.result()['tools'] if row['tool']==tool)['status'], 'malformed')
        for diagnostic in ({'skipped_rules':['rule']}, {'paths':{'scanned':['app.py'],'skipped':[{'path':'other.py'}]}}):
            doc = dict(results=[], errors=[], **diagnostic)
            self.manifest['reports'][1]['report_sha256'] = self.save('semgrep.json', doc)
            self.assertEqual(self.result()['tools'][1]['status'], 'partial')

    def test_actual_cli_owned_outputs_and_alias_rejection_without_commands(self):
        self.save('manifest.json', self.manifest)
        env = dict(os.environ, PATH=str(self.root/'no-tools'))
        out = self.root/'output'
        command = [sys.executable, str(SCRIPT), str(self.root/'manifest.json'), '--out', str(out)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads((out/'comparison.json').read_text())['tools'][0]['precision'], .5)
        self.assertTrue((out/'findings.csv').is_file())
        sentinel = self.root/'sentinel'
        sentinel.write_text('UNTOUCHED')
        (out/'findings.csv').unlink()
        (out/'findings.csv').symlink_to(sentinel)
        before = (out/'comparison.json').read_bytes()
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(sentinel.read_text(), 'UNTOUCHED')
        self.assertEqual((out/'comparison.json').read_bytes(), before)
