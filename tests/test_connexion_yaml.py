"""Registered YAML source is data; unsupported syntax never manufactures probe targets.

@req specs/001-continuous-security-improvement/spec.md#FR-003
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from websec_validator.extractors.authz import AuthzExtractor
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.routes import RoutesExtractor

REGISTER = 'import connexion\napp=connexion.App(__name__,specification_dir="contracts")\napp.add_api("api.yaml")\n'
CONTRACT = '''openapi: 3.0.0
servers:
  - url: /v1
paths:
  /private:
    post:
      operationId: handlers.private
      description: |
        Example prose is not executable routing.
        paths:
          /fake:
      responses:
        '200':
          description: OK
  /guarded:
    post:
      operationId: handlers.guarded
      security: []
'''


class ConnexionYamlTests(unittest.TestCase):
    def scan(self, contract=CONTRACT, source=REGISTER):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'contracts').mkdir()
            (root / 'contracts/api.yaml').write_text(contract)
            (root / 'app.py').write_text(source)
            (root / 'handlers.py').write_text('def private():\n return "unguarded"\n'
                'def guarded():\n requireAuth()\n return "guarded"\n')
            ctx = RepoContext(root)
            with patch('websec_validator.extractors.routes._noir_scan', return_value=None):
                facts = {'routes': RoutesExtractor().extract(ctx, {})}
            facts['authz'] = AuthzExtractor().extract(ctx, facts)
            return facts

    def test_literal_yaml_registration_and_exact_handlers_without_noir(self):
        facts = self.scan()
        self.assertEqual(facts['routes']['targeting']['write_endpoints'], ['POST /v1/guarded', 'POST /v1/private'])
        guards = {row['path']: row for row in facts['authz']['endpoint_guards']}
        self.assertFalse(guards['/v1/private']['guarded'])
        self.assertTrue(guards['/v1/guarded']['guarded'])
        self.assertTrue(all(row['spec_path']=='contracts/api.yaml' for row in facts['routes']['endpoints']))
        self.assertTrue(all(row['contract_mode']=='yaml-literal-subset' for row in facts['routes']['endpoints']))

    def test_literal_flask_config_does_not_replace_registration_receiver(self):
        source = REGISTER.replace('app.add_api', 'app.app.config["SECRET_KEY"]="example"\napp.add_api')
        self.assertEqual(len(self.scan(source=source)['routes']['endpoints']), 2)
        for source in (source.replace('app.app.config["SECRET_KEY"]', 'app.app'),
                       source.replace('app.app.config["SECRET_KEY"]', 'app.add_api'),
                       source.replace('app.app.config["SECRET_KEY"]', 'app.app.config')):
            self.assertEqual(self.scan(source=source)['routes']['endpoints'], [])

    def test_anchors_tags_merges_duplicates_and_path_references_are_unresolved(self):
        for contract in (CONTRACT.replace('post:', 'post: &shared', 1),
                         CONTRACT.replace('operationId: handlers.private', 'operationId: *shared'),
                         CONTRACT.replace('operationId: handlers.private', 'operationId: !custom handlers.private'),
                         CONTRACT.replace('operationId: handlers.private', '<<: {"operationId":"handlers.private"}'),
                         CONTRACT.replace('operationId: handlers.private', 'operationId: handlers.private\n      operationId: handlers.guarded'),
                         CONTRACT.replace('post:\n      operationId: handlers.private', '$ref: "#/components/pathItems/private"\n    post:\n      operationId: handlers.private')):
            with self.subTest(contract=contract):
                facts = self.scan(contract)
                self.assertEqual(facts['routes']['targeting']['write_endpoints'], [])
                self.assertTrue(facts['routes']['connexion']['gaps'])

    def test_unregistered_dynamic_base_and_multiple_servers_never_become_targets(self):
        for source, contract in (('', CONTRACT), (REGISTER.replace('"api.yaml"', 'spec_name'), CONTRACT),
                                 (REGISTER.replace('"api.yaml")', '"api.yaml",base_path=prefix)'), CONTRACT),
                                 (REGISTER, CONTRACT.replace('  - url: /v1', '  - url: /v1\n  - url: /v2'))):
            with self.subTest(source=source):
                self.assertEqual(self.scan(contract, source)['routes']['targeting']['write_endpoints'], [])

    def test_nested_descriptions_and_security_declarations_cannot_supply_operation(self):
        contract = CONTRACT.replace('      operationId: handlers.private',
            '      security:\n        - bearer: []').replace(
                'Example prose is not executable routing.', 'operationId: handlers.guarded')
        rows = {row['path']: row for row in self.scan(contract)['authz']['endpoint_guards']}
        self.assertFalse(rows['/v1/private']['analyzed'])
        self.assertFalse(rows['/v1/private']['guarded'])

    def test_json_compatible_yaml_preserves_exact_document_binding(self):
        contract = json.dumps({'openapi': '3.0.0', 'paths': {'/private': {'post': {'operationId': 'handlers.private'}}}})
        self.assertEqual(self.scan(contract)['routes']['targeting']['write_endpoints'], ['POST /private'])

    def test_block_handler_multiple_documents_and_ambiguous_server_are_not_targets(self):
        for contract in (CONTRACT.replace('operationId: handlers.private', 'operationId: |\n        handlers.guarded'),
                         '---\n---\n'+CONTRACT,
                         CONTRACT.replace('url: /v1', "url: /v1' # comment")):
            with self.subTest(contract=contract):
                facts = self.scan(contract)
                self.assertEqual(facts['routes']['targeting']['write_endpoints'], [])
                self.assertTrue(facts['routes']['connexion']['gaps'])

    def test_operation_identifier_is_exact_dotted_supplier_not_a_normalized_path(self):
        for identifier in ('handlers/guarded', 'handlers.guarded\\n', 'handlers.guarded-name'):
            with self.subTest(identifier=identifier):
                facts = self.scan(CONTRACT.replace('handlers.private', identifier))
                row = next(row for row in facts['authz']['endpoint_guards'] if row['path']=='/v1/private')
                self.assertFalse(row['guarded'])
                self.assertFalse(row['analyzed'])

    def test_literal_yaml_work_caps_are_execution_errors(self):
        from websec_validator import literal_yaml
        with patch.object(literal_yaml, 'MAX_NODES', 2):
            facts = self.scan()
        self.assertTrue(facts['routes']['connexion']['errors'])
        from websec_validator import coverage
        facts['coverage'] = {'execution_complete': True, 'gaps': []}
        coverage.add_routes(facts)
        self.assertFalse(facts['coverage']['execution_complete'])

    def test_actual_cli_persists_yaml_routes_and_auth_ledger_without_target_execution(self):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            (root / 'contracts').mkdir(parents=True)
            (root / 'contracts/api.yaml').write_text(CONTRACT)
            (root / 'app.py').write_text(REGISTER+'raise RuntimeError("never execute target")\n')
            (root / 'handlers.py').write_text('def private():\n return "unguarded"\n'
                'def guarded():\n requireAuth()\n return "guarded"\n')
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'), PATH=str(owner / 'no-tools'),
                       WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'), WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(root), '--out', str(out),
                '--format', 'json', '--require-complete', '--fail-on', 'high'], env=env, cwd=owner,
                capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            run = out / 'runs' / json.loads(result.stdout)['generated']
            facts = json.loads((run / 'FACTS.json').read_text())
            self.assertTrue(facts['coverage']['execution_complete'])
            self.assertEqual(len(facts['routes']['endpoints']), 2)
            ledger = json.loads((run / 'findings-ledger.json').read_text())
            self.assertEqual({row['location'] for row in ledger['findings'] if row['attack_class']=='missing-auth'}, {'/v1/private'})
