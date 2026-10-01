"""Retained framework controls use actual endpoint/binding evidence, never names alone.

@req specs/001-continuous-security-improvement/spec.md#FR-001
@req specs/001-continuous-security-improvement/spec.md#FR-002
"""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.authz import AuthzExtractor
from websec_validator.extractors.base import RepoContext
from websec_validator.findings import build_ledger


class FastApiCompositionTests(unittest.TestCase):
    def scan(self, dependency, *, extra='', parameter='user=Depends(get_current_user)'):
        source = ('from fastapi import FastAPI, Depends, HTTPException\n'
                  'import jwt\napp=FastAPI()\n' + dependency + '\n'
                  '@app.post("/private")\ndef private(' + parameter + '):\n return "private"\n'
                  '@app.post("/unprotected")\ndef unprotected():\n return "public"\n' + extra)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text(source)
            facts = {'stack': {'frameworks': ['fastapi']}, 'routes': {'endpoints': [
                {'method': 'POST', 'path': path, 'code_path': 'app.py'}
                for path in ('/private', '/unprotected')]}}
            facts['authz'] = AuthzExtractor().extract(RepoContext(root), facts)
            return facts, build_ledger(facts, None)

    def test_named_noop_dependency_cannot_guard_itself_or_sibling(self):
        facts, ledger = self.scan('def get_current_user():\n return None')
        self.assertEqual([row['guarded'] for row in facts['authz']['endpoint_guards']], [False, False])
        self.assertEqual(len([row for row in ledger['findings'] if row['attack_class'] == 'missing-auth']), 2)

    def test_visible_enforcing_dependency_is_bound_to_one_endpoint(self):
        dependency = ('def get_current_user(token):\n'
                      ' claims=jwt.decode(token,key,algorithms=["HS256"])\n'
                      ' if not claims:\n  raise HTTPException(status_code=401)\n'
                      ' return claims\n')
        facts, _ = self.scan(dependency)
        self.assertEqual([row['guarded'] for row in facts['authz']['endpoint_guards']], [True, False])

    def test_unused_import_or_sibling_guard_cannot_protect(self):
        facts, _ = self.scan('from external_auth import get_current_user',
                             extra='def elsewhere():\n requireAuth()\n', parameter='')
        self.assertEqual([row['guarded'] for row in facts['authz']['endpoint_guards']], [False, False])

    def test_presence_only_or_unreachable_rejection_is_not_enforcement(self):
        for dependency in ('def get_current_user(token):\n if not token:\n  raise HTTPException(status_code=401)\n return token',
                           'def get_current_user(token):\n claims=jwt.decode(token,key)\n if False:\n  raise HTTPException(status_code=401)\n return claims'):
            with self.subTest(dependency=dependency):
                facts, _ = self.scan(dependency)
                self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_reassigned_dependency_is_not_credited(self):
        dependency = ('def get_current_user(token):\n'
                      ' claims=jwt.decode(token,key,algorithms=["HS256"])\n'
                      ' if not claims:\n  raise HTTPException(status_code=401)\n'
                      ' return claims\nget_current_user=lambda:None\n')
        facts, _ = self.scan(dependency)
        self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_decoder_mutation_relative_import_and_disabled_verify_are_unverified(self):
        body = ('def get_current_user(token):\n claims=jwt.decode(token,key,algorithms=["HS256"])\n'
                ' if not claims:\n  raise HTTPException(status_code=401)\n return claims\n')
        for dependency in (body + 'jwt.decode=lambda *a,**k:{"sub":"guest"}\n',
                           body + 'from .fake import jwt\n',
                           body + 'from local_auth import *\n',
                           body.replace('decode(token,key,', 'decode(token,key,False,'),
                           body.replace('algorithms=["HS256"]', 'algorithms=["HS256"],verify=False'),
                           'from .jwt import decode\n' + body.replace('jwt.decode', 'decode'),
                           body + 'app.post=lambda *a,**k:lambda f:f\n'):
            with self.subTest(dependency=dependency):
                facts, _ = self.scan(dependency)
                self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_fixed_or_default_credential_is_not_caller_authentication(self):
        body = ('def get_current_user(token):\n claims=jwt.decode(token,key,algorithms=["HS256"])\n'
                ' if not claims:\n  raise HTTPException(status_code=401)\n return claims\n')
        for dependency in (body.replace('decode(token,', 'decode("public-valid-token",'),
                           body.replace('get_current_user(token)', 'get_current_user(token="public-valid-token")')):
            with self.subTest(dependency=dependency):
                facts, _ = self.scan(dependency)
                self.assertFalse(facts['authz']['endpoint_guards'][0]['guarded'])

    def test_mixed_flask_route_keeps_its_own_decorator_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text('from fastapi import FastAPI\nfrom flask import Flask\n'
                                        'app=Flask(__name__)\n@app.route("/private",methods=["POST"])\n'
                                        '@login_required\ndef private():\n return "ok"\n')
            facts = {'stack': {'frameworks': ['fastapi', 'flask']}, 'routes': {'endpoints': [
                {'method': 'POST', 'path': '/private', 'code_path': 'app.py', 'technology': 'flask'}]}}
            result = AuthzExtractor().extract(RepoContext(root), facts)
            self.assertTrue(result['endpoint_guards'][0]['guarded'])

    def test_analysis_is_built_once_for_multiple_endpoints(self):
        from unittest.mock import patch
        from websec_validator.extractors import authz
        with patch.object(authz, 'fastapi_guards', wraps=authz.fastapi_guards) as analyze:
            self.scan('def get_current_user():\n return None')
        self.assertEqual(analyze.call_count, 1)

    def test_cli_persists_exact_endpoint_guard_and_ledger_outcomes(self):
        import json
        import os
        import subprocess
        source = ('from fastapi import FastAPI, Depends, HTTPException\nimport jwt\napp=FastAPI()\n'
                  'def get_current_user(token):\n claims=jwt.decode(token,key,algorithms=["HS256"])\n'
                  ' if not claims:\n  raise HTTPException(status_code=401)\n return claims\n'
                  '@app.post("/private")\ndef private(user=Depends(get_current_user)):\n return "private"\n'
                  '@app.post("/unprotected")\ndef unprotected():\n return "public"\n')
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            target = owner / 'target'
            target.mkdir()
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-optional-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            for protected, program in ((True, source), (False, source.replace(
                    ' claims=jwt.decode(token,key,algorithms=["HS256"])\n if not claims:\n  raise HTTPException(status_code=401)\n return claims',
                    ' return None'))):
                with self.subTest(protected=protected):
                    (target / 'app.py').write_text(program)
                    out = owner / ('out-' + str(protected))
                    result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(target),
                                             '--out', str(out), '--format', 'json', '--fail-on', 'high'],
                                            cwd=owner, env=env, capture_output=True, text=True, timeout=20)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    envelope = json.loads(result.stdout)
                    run = out / 'runs' / envelope['generated']
                    ledger = json.loads((run / 'findings-ledger.json').read_text())
                    paths = {row['location'] for row in ledger['findings'] if row['attack_class'] == 'missing-auth'}
                    self.assertEqual(paths, {'/unprotected'} if protected else {'/private', '/unprotected'})


class ConnexionRegistrationTests(unittest.TestCase):
    def scan(self, source='', *, spec=None, noir=None, filename='api.json'):
        import json
        from unittest.mock import patch
        from websec_validator.extractors.routes import RoutesExtractor
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'target'
            root.mkdir()
            (root / 'app.py').write_text(source)
            (root / filename).write_text(json.dumps(spec if spec is not None else {
                'openapi': '3.0.0', 'paths': {'/items/{id}': {'post': {'responses': {}}}}}))
            with patch('websec_validator.extractors.routes._noir_scan', return_value=noir):
                return RoutesExtractor().extract(RepoContext(root), {})

    def test_registered_literal_contract_has_source_and_spec_provenance(self):
        result = self.scan('import connexion as c\napp=c.FlaskApp(__name__)\napp.add_api("api.json",base_path="/v1")\n')
        self.assertEqual(result['targeting']['write_endpoints'], ['POST /v1/items/{id}'])
        row = result['endpoints'][0]
        self.assertEqual(row['code_path'], 'app.py')
        self.assertEqual(row['spec_path'], 'api.json')
        self.assertEqual(row['source'], 'connexion-registration')
        self.assertIn('not deployed', result['connexion']['note'])

    def test_docs_only_noir_spec_never_becomes_write_target(self):
        noir = [{'method': 'POST', 'url': '/items/{id}', 'params': [],
                 'details': {'code_paths': [{'path': 'openapi.json'}]}}]
        result = self.scan(noir=noir, filename='openapi.json')
        self.assertEqual(result['endpoints'], [])
        self.assertEqual(result['targeting']['write_endpoints'], [])
        self.assertEqual(result['spec_derived_excluded'], 1)

    def test_unknown_reassigned_relative_and_nested_registration_are_not_targets(self):
        cases = ['from .connexion import App\napp=App(__name__)\napp.add_api("api.json")',
                 'import connexion\napp=connexion.App(__name__)\napp=None\napp.add_api("api.json")',
                 'import connexion\napp=connexion.App(__name__)\napp.add_api=lambda *a:None\napp.add_api("api.json")',
                 'import connexion\napp=connexion.App(__name__)\napp.add_api(spec_name)',
                 'import connexion\napp=connexion.App(__name__)\ndef unused():\n app.add_api("api.json")',
                 'import connexion\napp=connexion.App(__name__)\napp.add_api("api.json",arguments={"x":"y"})',
                 'import connexion\napp=connexion.App(__name__)\napp.add_api("api.json",**options)',
                 'import connexion\napp.add_api("api.json")\napp=connexion.App(__name__)',
                 'app=connexion.App(__name__)\nimport connexion\napp.add_api("api.json")']
        for source in cases:
            with self.subTest(source=source):
                result = self.scan(source)
                self.assertEqual(result['endpoints'], [])

    def test_escape_and_malformed_spec_are_disclosed_without_targets(self):
        for filename, spec in (('../outside.json', None), ('api.json', {'openapi': '3.0.0', 'paths': []})):
            with self.subTest(filename=filename):
                result = self.scan('import connexion\napp=connexion.App(__name__)\napp.add_api(' + repr(filename) + ')', spec=spec)
                self.assertEqual(result['endpoints'], [])
                self.assertTrue(result['connexion']['gaps'])

    def test_literal_spec_directory_and_swagger_base_path(self):
        # The source module's root, not the scanner process cwd, anchors the app.
        result = self.scan('from connexion import App\napp=App(__name__,specification_dir=".")\napp.add_api("api.json")',
                           spec={'swagger': '2.0', 'basePath': '/v2', 'paths': {'/users': {'get': {}}}})
        self.assertEqual([(r['method'], r['path']) for r in result['endpoints']], [('GET', '/v2/users')])

    def test_budget_errors_reach_execution_coverage(self):
        from unittest.mock import patch
        from websec_validator import coverage
        from websec_validator.extractors import connexion_routes
        with patch.object(connexion_routes, 'MAX_NODES', 3):
            result = self.scan('import connexion\napp=connexion.App(__name__)\napp.add_api("api.json")')
        facts = {'routes': result, 'coverage': {'execution_complete': True, 'gaps': []}}
        coverage.add_routes(facts)
        self.assertFalse(facts['coverage']['execution_complete'])
        self.assertTrue(facts['coverage']['route_discovery']['connexion']['errors'])

    def test_malformed_servers_and_path_items_are_disclosed(self):
        for spec in ({'openapi': '3.0.0', 'servers': [{'url': 'https://['}], 'paths': {'/ok': {'post': {}}}},
                     {'openapi': '3.0.0', 'paths': {'/ok': {'post': {}}, '/bad': ['get']}}):
            with self.subTest(spec=spec):
                result = self.scan('import connexion\napp=connexion.App(__name__)\napp.add_api("api.json")', spec=spec)
                self.assertEqual(result['endpoints'], [])
                self.assertTrue(result['connexion']['gaps'])

    def test_auth_uses_exact_operation_not_registration_or_security_declaration(self):
        import json
        from unittest.mock import patch
        from websec_validator.extractors.routes import RoutesExtractor
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text('import connexion\napp=connexion.App(__name__)\n'
                'app.add_api("api.json",base_path="/v1")\ndef unused():\n requireAuth()\n')
            (root / 'handlers.py').write_text('def private():\n return "unguarded"\n'
                'def guarded():\n requireAuth()\n return "guarded"\n'
                'def other():\n requireAuth()\n')
            paths = {name: {'post': {'operationId': operation, 'security': [{'bearer': []}]}}
                     for name, operation in (('/private', 'handlers.private'), ('/guarded', 'handlers.guarded'),
                                              ('/missing', 'handlers.missing'))}
            (root / 'api.json').write_text(json.dumps({'openapi': '3.0.0', 'paths': paths}))
            ctx = RepoContext(root)
            with patch('websec_validator.extractors.routes._noir_scan', return_value=None):
                facts = {'routes': RoutesExtractor().extract(ctx, {})}
            facts['authz'] = AuthzExtractor().extract(ctx, facts)
            rows = {row['path']: row for row in facts['authz']['endpoint_guards']}
            self.assertEqual((rows['/v1/private']['guarded'], rows['/v1/private']['analyzed']), (False, True))
            self.assertEqual((rows['/v1/guarded']['guarded'], rows['/v1/guarded']['analyzed']), (True, True))
            self.assertEqual((rows['/v1/missing']['guarded'], rows['/v1/missing']['analyzed']), (False, False))
            self.assertTrue(rows['/v1/missing']['unverified_controls'])
            ledger = build_ledger(facts, None)
            self.assertEqual({row['location'] for row in ledger['findings'] if row['attack_class'] == 'missing-auth'}, {'/v1/private'})

    def test_private_or_escaping_spec_alias_never_supplies_routes(self):
        import json
        from unittest.mock import patch
        from websec_validator.extractors.routes import RoutesExtractor
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            root.mkdir()
            outside = owner / 'outside.json'
            outside.write_text(json.dumps({'openapi': '3.0.0', 'paths': {'/write': {'post': {}}}}))
            (root / '.local').mkdir()
            (root / '.local' / 'api.json').write_bytes(outside.read_bytes())
            (root / 'alias.json').symlink_to(outside)
            for spec in ('alias.json', '.local/api.json', 'https://['):
                with self.subTest(spec=spec):
                    (root / 'app.py').write_text('import connexion\napp=connexion.App(__name__)\napp.add_api(' + repr(spec) + ')')
                    with patch('websec_validator.extractors.routes._noir_scan', return_value=None):
                        result = RoutesExtractor().extract(RepoContext(root), {})
                    self.assertEqual(result['endpoints'], [])
                    self.assertTrue(result['connexion']['gaps'])

    def test_cli_persists_registered_route_and_operation_ledger(self):
        import json
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            root.mkdir()
            (root / 'app.py').write_text('import connexion\napp=connexion.App(__name__)\napp.add_api("api.json",base_path="/v1")\n'
                                        'def unrelated():\n requireAuth()\n')
            (root / 'handlers.py').write_text('def private():\n return "unguarded"\n')
            (root / 'api.json').write_text(json.dumps({'openapi': '3.0.0', 'paths': {
                '/private': {'post': {'operationId': 'handlers.private'}}}}))
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            run = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(root), '--out', str(out),
                                  '--format', 'json', '--fail-on', 'high'], env=env, cwd=owner,
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 1, run.stderr)
            directory = out / 'runs' / json.loads(run.stdout)['generated']
            facts = json.loads((directory / 'FACTS.json').read_text())
            self.assertEqual(facts['routes']['endpoints'][0]['spec_path'], 'api.json')
            self.assertEqual(facts['coverage']['route_discovery']['connexion']['routes'], 1)
            ledger = json.loads((directory / 'findings-ledger.json').read_text())
            self.assertEqual({row['location'] for row in ledger['findings'] if row['attack_class'] == 'missing-auth'}, {'/v1/private'})


if __name__ == '__main__':
    unittest.main()
