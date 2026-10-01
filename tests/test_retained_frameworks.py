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


if __name__ == '__main__':
    unittest.main()
