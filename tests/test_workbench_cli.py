"""Offline workbench CLI contracts; network entry points use injected results."""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import cli, intel, research
from websec_validator import dast_ingest, dynamic


class WorkbenchCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def invoke(self, *arguments):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            code = cli.main(list(arguments))
        return code, json.loads(output.getvalue())

    def test_capabilities_reports_named_scope_offline(self):
        with patch.object(intel, '_fetch', side_effect=AssertionError('unexpected network')):
            code, data = self.invoke('capabilities')
        self.assertEqual(code, 0)
        self.assertTrue(data['profiles'])
        self.assertIn('named checks', data['scope'])

    def test_status_is_offline_and_missing_snapshot_is_visible(self):
        with patch.object(intel, '_fetch', side_effect=AssertionError('unexpected network')):
            code, data = self.invoke('intel','status','--cache-dir',str(self.root))
        self.assertEqual(code, 0)
        self.assertFalse(data['available'])
        self.assertEqual(data['freshness'], 'unavailable')

    def test_refresh_is_explicit_and_failed_refresh_returns_nonzero(self):
        for outcome, expected in [('success',0),('failed',2)]:
            with self.subTest(outcome=outcome), patch.object(intel, 'refresh', return_value={'last_refresh':{'outcome':outcome}}) as refresh:
                code, data = self.invoke('intel','refresh','--cache-dir',str(self.root))
            self.assertEqual(code, expected)
            refresh.assert_called_once_with(str(self.root))
            self.assertEqual(data['last_refresh']['outcome'], outcome)

    def test_reassessment_preserves_input_and_discloses_unavailable_intel(self):
        source = self.root / 'ledger.json'
        original = '{"findings":[],"verification_context":{"build_id":"before"}}'
        source.write_text(original)
        with patch.object(intel, '_fetch', side_effect=AssertionError('unexpected network')):
            code, data = self.invoke('intel','reassess','--cache-dir',str(self.root),
                                     '--ledger',str(source),'--out',str(self.root / 'result.json'))
        self.assertEqual(code, 2)
        self.assertEqual(data['ledger'], json.loads(original))
        self.assertTrue(data['limitations'])
        self.assertEqual(source.read_text(), original)

    def test_explicit_output_cannot_overwrite_evidence(self):
        output = self.root / 'existing.json'; output.write_text('previous evidence')
        code, data = self.invoke('research','example','--out',str(output))
        self.assertEqual(code, 2)
        self.assertIn('error', data)
        self.assertEqual(output.read_text(), 'previous evidence')

    def test_wrong_json_shapes_return_clear_errors(self):
        source = self.root / 'invalid-shape.json'
        source.write_text('{"findings":["invalid row"]}')
        code, data = self.invoke('intel','reassess','--ledger',str(source),'--cache-dir',str(self.root))
        self.assertEqual(code, 2)
        self.assertIn('error', data)
        source.write_text('{"proposal":[],"cases":{}}')
        code, data = self.invoke('research','evaluate','--proposal',str(source))
        self.assertEqual(code, 2)
        self.assertIn('error', data)

    def test_research_example_roundtrip_and_executable_proposal_rejected(self):
        bundle = self.root / 'example.json'
        code, example = self.invoke('research','example','--out',str(bundle))
        self.assertEqual(code, 0)
        code, result = self.invoke('research','evaluate','--proposal',str(bundle))
        self.assertEqual(code, 0, result)
        self.assertTrue(result['promotion_eligible'])
        self.assertEqual(result['promotion_state'], 'eligible-for-human-review')
        example['proposal']['command'] = 'do not execute'
        bundle.write_text(json.dumps(example))
        code, result = self.invoke('research','evaluate','--proposal',str(bundle))
        self.assertEqual(code, 2)
        self.assertFalse(result['promotion_eligible'])

    def test_malformed_and_special_explicit_inputs_fail_closed(self):
        source = self.root / 'invalid.json'; source.write_text('{bad')
        code, data = self.invoke('intel','reassess','--ledger',str(source),'--cache-dir',str(self.root))
        self.assertEqual(code, 2)
        self.assertIn('error', data)
        if hasattr(__import__('os'), 'mkfifo'):
            fifo = self.root / 'pipe'; __import__('os').mkfifo(fifo)
            code, data = self.invoke('research','evaluate','--proposal',str(fifo))
            self.assertEqual(code, 2)
            self.assertIn('error', data)

    def test_documented_dast_and_repair_contract_examples_validate(self):
        examples = Path(__file__).resolve().parents[1] / 'docs/security-review/examples'
        ledger = json.loads((examples / 'dast-ledger.json').read_text())
        for name, expected in [('dast-positive.json', True), ('dast-negative.json', False)]:
            report = json.loads((examples / name).read_text())
            result = dast_ingest.derive_labels(ledger, report)
            self.assertEqual([row['is_real'] for row in result['labels']], [expected])
        empty = dast_ingest.derive_labels(ledger, {'dast_context':ledger['dast_context'], 'alerts':[]})
        self.assertEqual(empty['labels'], [])
        repair = examples / 'repair'
        code, result = self.invoke('repair-verify','--plan',str(repair / 'plan.json'),
                                  '--record',str(repair / 'record.json'),
                                  '--rerun',str(repair / 'rerun-ledger.json'),'--evidence-root',str(repair))
        self.assertEqual(code, 0, result)
        self.assertFalse(result['tests_executed_by_websec'])

    def test_dynamic_config_example_controls_match_synthetic_identity_fixture(self):
        config = json.loads((Path(__file__).resolve().parents[1] / 'dynamic-config.example.json').read_text())
        controls = config['bola_controls']
        route = next(iter(controls['resources']))
        def mint(_config, role):
            return {'token':role,'tenant':role}
        def request(method, url, token, **kwargs):
            if url.endswith(controls['identity_path']):
                return 200, json.dumps({'id':controls['identities'][token]['value']})
            if token is None:
                return 401, 'denied'
            owner = url.split('/groups/')[1].split('/')[0]
            return 200, json.dumps({'items':[{'id':controls['resources'][route][owner]['value']}]})
        with patch.object(dynamic, 'mint', side_effect=mint), patch.object(dynamic, '_request', side_effect=request):
            result = dynamic.cross_tenant_bola(config, {'routes':{'endpoints':[{'method':'GET','path':route}]}})
        self.assertEqual(result['state'], 'confirmed-vulnerable')
        self.assertEqual(len(result['leaks']), 2)


if __name__ == '__main__':
    unittest.main()
