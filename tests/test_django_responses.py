"""Django source observations stay on the returned response, never deployment proofs.

@req specs/001-continuous-security-improvement/spec.md#FR-004
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.transport_security import TransportSecurityExtractor

STRICT = "script-src 'self' 'nonce-example' 'strict-dynamic'; object-src 'none'"


class DjangoResponseTests(unittest.TestCase):
    def scan(self, source):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'views.py').write_text(source)
            return TransportSecurityExtractor().extract(RepoContext(root),
                {'stack': {'frameworks': ['django']}, 'routes': {'endpoints': []}})

    def source(self, middle='', returned='response'):
        return ('from django.shortcuts import render\ndef home(request):\n'
                ' response=render(request,"home.html")\n' + middle + ' return ' + returned + '\n')

    def test_headers_and_template_belong_to_returned_response_not_sibling(self):
        source = self.source(' response["Content-Security-Policy"]='+repr(STRICT)+'\n')
        source += 'def public(request):\n return render(request,"public.html")\n'
        out = self.scan(source)
        self.assertTrue(out['html_surface'])
        rows = out['django_responses']['observations']
        self.assertEqual([(row['view'], row['template']) for row in rows], [('home', 'home.html'), ('public', 'public.html')])
        self.assertTrue(rows[0]['strict_csp_shape'])
        self.assertFalse(rows[1]['strict_csp_shape'])
        self.assertFalse(out['strict_csp'])
        self.assertTrue(any(row.get('view') == 'public' and row['kind'] == 'django-response-csp-unverified'
                            for row in out['findings']))
        self.assertTrue(all(not row['deployment_verified'] for row in rows))

    def test_same_receiver_latest_literal_header_is_the_only_credit(self):
        for middle in (' other["Content-Security-Policy"]='+repr(STRICT)+'\n',
                       ' response["Content-Security-Policy"]='+repr(STRICT)+'\n response["Content-Security-Policy"]="default-src *"\n',
                       ' if enabled:\n  response["Content-Security-Policy"]='+repr(STRICT)+'\n',
                       ' response["Content-Security-Policy"]=policy\n',
                       ' response["Content-Security-Policy"]="script-src \'self\'; style-src \'nonce-example\'"\n',
                       ' response["Content-Security-Policy"]="script-src \'self\' \'strict-dynamic\'; script-src *"\n',
                       ' response["Content-Security-Policy"]='+repr(STRICT)+'\n mutate(response)\n'):
            with self.subTest(middle=middle):
                rows = self.scan(self.source(middle))['django_responses']['observations']
                self.assertEqual(len(rows), 1)
                self.assertFalse(rows[0]['strict_csp_shape'])

    def test_unrelated_mutated_shadowed_late_and_nested_render_are_not_bound(self):
        valid = self.source()
        for source in (valid.replace('django.shortcuts', 'other'),
                       valid.replace('def home(request)', 'def home(request,render)'),
                       valid.replace('def home', 'render=custom\ndef home'),
                       'import django.shortcuts\ndef home(request):\n return django.render(request,"home.html")\n',
                       valid.split('\n',1)[1]+'from django.shortcuts import render\n',
                       'from django.shortcuts import render\ndef factory():\n def unused(request):\n  return render(request,"home.html")\n',
                       valid.replace('return response', 'return other')):
            with self.subTest(source=source):
                self.assertEqual(self.scan(source)['django_responses']['observations'], [])

    def test_alias_import_and_direct_return_keep_literal_provenance(self):
        for source in ('from django.shortcuts import render as page\ndef home(request):\n return page(request,"home.html")\n',
                       'import django.shortcuts as pages\ndef home(request):\n return pages.render(request,"home.html")\n',
                       'import django.shortcuts\ndef home(request):\n return django.shortcuts.render(request,"home.html")\n'):
            self.assertEqual(self.scan(source)['django_responses']['observations'][0]['template'], 'home.html')
        self.assertEqual(self.scan(self.source().replace('"home.html"', 'template_name'))['django_responses']['observations'], [])

    def test_response_overwrite_and_alias_do_not_borrow_old_headers(self):
        middle = ' response["Content-Security-Policy"]='+repr(STRICT)+'\n'
        overwritten = middle+' response=render(request,"other.html")\n'
        rows = self.scan(self.source(overwritten))['django_responses']['observations']
        self.assertEqual(rows[0]['template'], 'other.html')
        self.assertFalse(rows[0]['strict_csp_shape'])
        rows = self.scan(self.source(middle+' alias=response\n alias.headers.clear()\n'))['django_responses']['observations']
        self.assertFalse(rows[0]['strict_csp_shape'])
        for tail in (' response["X-Other"]=mutate(response)\n',
                     ' other=render(request,"other.html",mutate(response))\n'):
            with self.subTest(tail=tail):
                rows = self.scan(self.source(middle+tail))['django_responses']['observations']
                self.assertFalse(rows[0]['strict_csp_shape'])

    def test_node_budget_is_an_execution_gap(self):
        from websec_validator.extractors import django_responses
        with patch.object(django_responses, 'MAX_NODES', 1):
            out = self.scan(self.source())
        self.assertTrue(out.get('error'))
        self.assertTrue(out['django_responses']['errors'])

    def test_actual_cli_keeps_same_response_evidence_without_target_execution(self):
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            target = owner / 'target'
            target.mkdir()
            (target / 'views.py').write_text(self.source(' response["Content-Security-Policy"]='+repr(STRICT)+'\n')+
                'def public(request):\n return render(request,"public.html")\nraise RuntimeError("target must not execute")\n')
            (target / 'requirements.txt').write_text('Django==5.2\n')
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'), PATH=str(owner / 'no-tools'),
                       WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'), WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(target),
                '--out', str(out), '--format', 'json', '--require-complete'], env=env, cwd=owner,
                text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            envelope = json.loads(result.stdout)
            run = out / 'runs' / envelope['generated']
            facts = json.loads((run / 'FACTS.json').read_text())
            self.assertTrue(facts['coverage']['execution_complete'])
            self.assertEqual(len(facts['transport_security']['django_responses']['observations']), 2)
            ledger = json.loads((run / 'findings-ledger.json').read_text())
            self.assertTrue(any(row['attack_class'] == 'missing-csp' for row in ledger['findings']))
