"""Django URL syntax is data; unresolved mounts never become network paths."""
from pathlib import Path
import contextlib
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator import coverage
from websec_validator import cli, inventory, recon
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors import django_urls
from websec_validator.extractors.routes import RoutesExtractor


class DjangoRouteTests(unittest.TestCase):
    def scan(self, files, *, integration=False, noir=None, excludes=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, text in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            ctx = RepoContext(root, excludes=excludes)
            facts = {"stack": {"frameworks": ["django"], "service_inventory": [
                {"id": ".", "root": ".", "languages": ["python"], "frameworks": ["django"]}]}}
            ctx.stack = facts["stack"]
            if integration:
                with patch("websec_validator.extractors.routes._noir_scan", return_value=noir):
                    return RoutesExtractor().extract(ctx, facts)
            return django_urls.analyze(ctx, facts)

    def app(self, urls):
        return {"project/settings.py": 'ROOT_URLCONF = "project.urls"', "project/urls.py": urls}

    def test_import_aliases_literals_and_unknown_methods(self):
        for imported, call in (("from django.urls import path", "path"),
                               ("from django.urls import path as route", "route"),
                               ("import django.urls as urlconf", "urlconf.path"),
                               ("import django.urls", "django.urls.path")):
            with self.subTest(imported=imported):
                out = self.scan(self.app(imported + '\nurlpatterns = [' + call + '("items/<int:pk>/", views.item)]'))
                self.assertEqual([(r["method"], r["path"]) for r in out["routes"]], [("ANY", "/items/{pk}/")])
                self.assertEqual(out["routes"][0]["params"][0]["name"], "pk")
                self.assertEqual(out["routes"][0]["methods_detected"], [])

    def test_shadowed_unrelated_and_commented_calls_are_not_django_routes(self):
        for source in ('from pathlib import Path as path\nurlpatterns=[path("items/")]',
                       'from django.urls import path\npath=custom\nurlpatterns=[path("items/",view)]',
                       'import django.urls\ndjango.urls.path=custom\nurlpatterns=[django.urls.path("items/",view)]',
                       'urlpatterns=[path("items/",view)]\nfrom django.urls import path',
                       'from custom import path\nurlpatterns=[path("items/",view)]\nfrom django.urls import path',
                       '# from django.urls import path\n# urlpatterns=[path("items/",view)]',
                       'source="urlpatterns=[path(\'items/\',view)]"'):
            self.assertEqual(self.scan(self.app(source))["routes"], [])

    def test_literal_module_and_inline_includes(self):
        files = self.app('from django.urls import path, include\nurlpatterns=[path("org/<int:org>/",include("catalog.urls"))]')
        files["catalog/urls.py"] = 'from django.urls import path, include\nurlpatterns=[path("items/<slug:slug>/",view),path("extra/",include([path("edit/",view)]))]'
        out = self.scan(files)
        self.assertEqual([r["path"] for r in out["routes"]], ["/org/{org}/items/{slug}/", "/org/{org}/extra/edit/"])
        self.assertEqual([p["name"] for p in out["routes"][0]["params"]], ["org", "slug"])

    def test_alias_module_include_and_tuple_inline(self):
        files = self.app('from django.urls import path as route, include as mount\nimport catalog.urls as catalog\nurlpatterns=[route("api/",mount(catalog)),route("x/",mount(([route("y/",view)],"app")))]')
        files["catalog/urls.py"] = 'from django.urls import path\nurlpatterns=[path("items/",view)]'
        self.assertEqual([r["path"] for r in self.scan(files)["routes"]], ["/api/items/", "/x/y/"])
        files = self.app('from django.urls import path, include\nfrom . import child as inner\nurlpatterns=[path("api/",include(inner))]')
        files["project/child.py"] = 'from django.urls import path\nurlpatterns=[path("items/",view)]'
        self.assertEqual([r["path"] for r in self.scan(files)["routes"]], ["/api/items/"])

    def test_dynamic_prefix_and_conditional_mutation_are_candidates(self):
        for source in ('from django.urls import path\nurlpatterns=[path(settings.PREFIX,view)]',
                       'from django.urls import path\nurlpatterns=[path("items/",view)]\nif settings.DEBUG:\n urlpatterns=[path("debug/",view)]',
                       'from django.urls import path\nurlpatterns=[path("items/",view)]\nif settings.DEBUG:\n urlpatterns.append(path("debug/",view))'):
            out = self.scan(self.app(source))
            self.assertEqual(out["routes"], [])
            self.assertTrue(out["candidates"])
            self.assertTrue(out["gaps"])
            self.assertEqual(out["errors"], [])
        for mutation in ('urlpatterns[0]=custom', 'del urlpatterns[:]', 'change(urlpatterns)'):
            out = self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]\n' + mutation))
            self.assertEqual(out["routes"], [])
            self.assertTrue(out["candidates"])

    def test_regex_is_preserved_without_fake_exact_path(self):
        out = self.scan(self.app('from django.urls import re_path\nurlpatterns=[re_path(r"^items/(?P<pk>[0-9]+)/$",view)]'))
        self.assertEqual(out["routes"], [])
        self.assertEqual(out["candidates"][0]["declared_pattern"], "^items/(?P<pk>[0-9]+)/$")
        self.assertFalse(out["candidates"][0]["mount_resolved"])

    def test_literal_braces_leading_slash_and_controls_are_not_normalized(self):
        for raw in ("items/{pk}/", "/items/", "items/\t", "items/\x7f", "items/\x85"):
            out = self.scan(self.app('from django.urls import path\nurlpatterns=[path(' + repr(raw) + ',view)]'))
            self.assertEqual(out["routes"], [])
            self.assertEqual(out["candidates"][0]["declared_pattern"], raw)
        out = self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/<int:pk>/",view)]'))
        self.assertEqual(out["routes"][0]["path"], "/items/{pk}/")
        self.assertEqual(out["routes"][0]["params"][0]["name"], "pk")

    def test_missing_external_escaping_and_shadowed_include_remain_unknown(self):
        for target in ('"thirdparty.urls"', '"../outside"', '"/tmp/outside"', 'dynamic'):
            out = self.scan(self.app('from django.urls import path, include\nurlpatterns=[path("api/",include(' + target + '))]'))
            self.assertEqual(out["routes"], [])
            self.assertTrue(out["gaps"])
        out = self.scan(self.app('from django.urls import path, include\ninclude=custom\nurlpatterns=[path("api/",include("child.urls"))]'))
        self.assertEqual(out["routes"], [])

    def test_cycles_parse_and_analysis_budgets_are_execution_losses(self):
        files = self.app('from django.urls import path, include\nurlpatterns=[path("again/",include("project.urls"))]')
        self.assertTrue(self.scan(files)["errors"])
        self.assertTrue(self.scan(self.app('urlpatterns = ['))["errors"])
        with patch.object(django_urls, "MAX_NODES", 3):
            self.assertTrue(self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]'))["errors"])
        with patch.object(django_urls, "MAX_MODULES", 1):
            self.assertTrue(self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]'))["errors"])
        with patch.object(django_urls, "MAX_TOTAL_NODES", 3):
            self.assertTrue(self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]'))["errors"])
        with patch.object(django_urls, "MAX_STEPS", 1):
            self.assertTrue(self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]'))["errors"])
        with patch.object(django_urls, "MAX_ROUTES", 1):
            out = self.scan(self.app('from django.urls import path\nurlpatterns=[path("a/",view),path("b/",view)]'))
            self.assertEqual(len(out["routes"]), 1)
            self.assertTrue(out["errors"])
        with patch.object(django_urls, "MAX_DEPTH", 1):
            files = self.app('from django.urls import path, include\nurlpatterns=[path("a/",include([path("b/",view)]))]')
            self.assertTrue(self.scan(files)["errors"])
        with patch.object(django_urls, "MAX_PATH", 2):
            self.assertTrue(self.scan(self.app('from django.urls import path\nurlpatterns=[path("items/",view)]'))["errors"])

    def test_no_target_import_execution_and_excluded_sources(self):
        files = self.app('from django.urls import path\nraise RuntimeError("must not execute")\nurlpatterns=[path("items/",view)]')
        self.assertEqual(len(self.scan(files)["routes"]), 1)
        self.assertEqual(self.scan(files, excludes=["project/urls.py"])["routes"], [])

    def test_unmounted_and_ambiguous_root_modules_are_candidates(self):
        files = {"project/urls.py": 'from django.urls import path\nurlpatterns=[path("items/",view)]'}
        out = self.scan(files)
        self.assertEqual(out["routes"], [])
        self.assertTrue(out["candidates"])
        files.update({"a.py": 'ROOT_URLCONF="project.urls"', "b.py": 'ROOT_URLCONF="other.urls"'})
        self.assertEqual(self.scan(files)["routes"], [])

    def test_symlink_include_cannot_read_outside_selected_root(self):
        with tempfile.TemporaryDirectory() as td:
            outer = Path(td)
            root = outer / "selected"
            root.mkdir()
            (root / "settings.py").write_text('ROOT_URLCONF="urls"')
            (root / "urls.py").write_text('from django.urls import path, include\nurlpatterns=[path("external/",include("outside"))]')
            external = outer / "outside.py"
            external.write_text('from django.urls import path\nurlpatterns=[path("private/",view)]')
            (root / "outside.py").symlink_to(external)
            context = RepoContext(root)
            out = django_urls.analyze(context, {})
            self.assertEqual(out["routes"], [])
            self.assertNotIn("outside.py", context.input_hashes)
            self.assertTrue(out["gaps"])

    def test_integration_fallback_and_noir_do_not_duplicate_any_route(self):
        files = self.app('from django.urls import path\nurlpatterns=[path("items/",view)]')
        out = self.scan(files, integration=True)
        self.assertEqual([(r["method"],r["path"]) for r in out["endpoints"]], [("ANY", "/items/")])
        noir = [{"method": "GET", "url": "/items/", "details": {"code_paths": [{"path": "project/urls.py"}]}}]
        out = self.scan(files, integration=True, noir=noir)
        self.assertEqual(len(out["endpoints"]), 1)
        self.assertEqual(out["endpoints"][0]["method"], "GET")

    def test_converted_nested_params_survive_recon_and_strict_cli_without_noir(self):
        files = self.app('from django.urls import path, include\nurlpatterns=[path("org/<int:org>/",include("catalog.urls"))]')
        files['requirements.txt'] = 'Django==5.2\n'
        files['catalog/urls.py'] = 'from django.urls import path\nurlpatterns=[path("items/<int:pk>/",view)]'
        with tempfile.TemporaryDirectory() as td:
            root, out = Path(td) / 'target', Path(td) / 'output'
            root.mkdir()
            for rel, text in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            with patch('shutil.which', return_value=None):
                facts = recon.build_facts(root, 'test')
                stdout, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    status = cli.main(['run', str(root), '--out', str(out),
                                       '--format', 'json', '--require-complete'])
            self.assertEqual(status, 0, stderr.getvalue())
            envelope = json.loads(stdout.getvalue())
            current = out / 'runs' / envelope['generated']
            saved = json.loads((current / 'FACTS.json').read_text())
            for result in (facts, saved):
                self.assertTrue(result['coverage']['execution_complete'])
                self.assertEqual(result['routes']['django']['errors'], [])
                endpoint, = result['routes']['endpoints']
                self.assertEqual((endpoint['method'], endpoint['path']),
                                 ('ANY', '/org/{org}/items/{pk}/'))
                self.assertEqual([(p['name'], p['where']) for p in endpoint['params']],
                                 [('org', 'path'), ('pk', 'path')])
                self.assertIn('ANY /org/{org}/items/{pk}/', result['routes']['targeting']['idor_candidates'])
                self.assertEqual(inventory.build(result)['endpoints'][0]['path_params'], ['org', 'pk'])
            self.assertTrue((current / 'AGENT-BRIEFING.md').is_file())

    def test_coverage_separates_scope_uncertainty_and_execution_failure(self):
        for source, expected in (('from django.urls import path\nurlpatterns=[path(settings.PREFIX,view)]', True),
                                 ('urlpatterns = [', False)):
            analysis = self.scan(self.app(source))
            facts = {"routes": {"django": analysis}, "coverage": {"execution_complete": True,"gaps":[]}}
            coverage.add_routes(facts)
            self.assertEqual(facts["coverage"]["execution_complete"], expected)
            self.assertIn("django", facts["coverage"]["route_discovery"])

    def test_contradictory_route_completion_and_malformed_evidence_are_rejected(self):
        valid = {"routes": 0, "candidates": 1, "gaps": [{"kind": "dynamic_root"}],
                 "errors": [], "diagnostics_truncated": 0, "limits": {"modules": 128}}
        self.assertEqual(coverage.execution_errors({"execution_complete": True,
                         "route_discovery": {"django": valid}}), [])
        for changed in ({"errors": [{"kind": "parse_error"}]}, {"errors": "error"},
                        {"diagnostics_truncated": 1}, {"diagnostics_truncated": False},
                        {"gaps": ["bad"]}, {"gaps": [{"execution": True}]},
                        {"routes": -1}, {"candidates": True}, {"limits": []}):
            with self.subTest(changed=changed):
                self.assertTrue(coverage.execution_errors({"execution_complete": True,
                                "route_discovery": {"django": {**valid, **changed}}}))
        for invalid in ([], {"django": []}):
            self.assertTrue(coverage.execution_errors({"execution_complete": True, "route_discovery": invalid}))
        facts = {"routes": {"django": {"errors": "bad"}}, "coverage": {"execution_complete": True, "gaps": []}}
        coverage.add_routes(facts)
        self.assertFalse(facts["coverage"]["execution_complete"])


if __name__ == "__main__":
    unittest.main()
