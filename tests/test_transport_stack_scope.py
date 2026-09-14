"""Browser header checks distinguish renderers from shared/native React code."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.stack import StackExtractor
from websec_validator.extractors.transport_security import TransportSecurityExtractor


class TransportStackScopeTests(unittest.TestCase):
    def scan(self, files, routes=None, include_fixtures=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data) if isinstance(data, dict) else data)
            ctx = RepoContext(root, include_fixtures=include_fixtures)
            facts = {'stack': StackExtractor().extract(ctx, {}),
                     'routes': {'endpoints': routes or []}}
            return TransportSecurityExtractor().extract(ctx, facts)

    def test_native_and_react_libraries_do_not_imply_browser(self):
        for deps in ({'react': '19'}, {'react': '19', 'react-native': '0.81'}):
            out = self.scan({'package.json': {'dependencies': deps},
                             'App.tsx': 'export default () => <View><Text>Hello</Text></View>;\n',
                             'Widget.jsx': 'export const Widget=()=> <div>Hello</div>;\n'})
            self.assertFalse(out['html_surface'])
            self.assertFalse(out['web_surface'])
            self.assertFalse(out['findings'])
            self.assertIn('not proof', out['surface_note'])

    def test_declared_browser_renderers_enable_baseline(self):
        for renderer in ('react-dom', 'react-native-web'):
            out = self.scan({'package.json': {'peerDependencies': {'react': '19', renderer: '19'}}})
            self.assertTrue(out['html_surface'])
            self.assertEqual(out['browser_renderers'], [renderer])
            self.assertIn('no-csp', [f['kind'] for f in out['findings']])

    def test_text_and_malformed_dependencies_do_not_imply_renderer(self):
        for package in ({'description': 'react-dom', 'scripts': {'start': 'react-native-web'}},
                        {'dependencies': ['react-dom']}, {'dependencies': {'react-dom': None}}):
            out = self.scan({'package.json': package})
            self.assertFalse(out['web_surface'])
            self.assertEqual(out['browser_renderers'], [])

    def test_product_first_manifest_policy_and_explicit_fixtures(self):
        files = {'Cargo.toml': '[package]\nname="library"\nversion="0.1.0"\n',
                 'tests/demo/package.json': {'dependencies': {'react-dom': '19'}}}
        self.assertFalse(self.scan(files)['web_surface'])
        self.assertTrue(self.scan(files, include_fixtures=True)['web_surface'])

    def test_routes_remain_http_evidence_for_native_monorepo(self):
        out = self.scan({'package.json': {'dependencies': {'react-native': '0.81', 'react': '19'}}},
                        [{'method': 'GET', 'path': '/health', 'code_path': 'server.js'}])
        self.assertTrue(out['web_surface'])
        self.assertFalse(out['html_surface'])
        self.assertIn('no-hsts', [f['kind'] for f in out['findings']])
        self.assertNotIn('no-csp', [f['kind'] for f in out['findings']])

    def test_native_sibling_does_not_hide_next_angular_or_renderer(self):
        for web in ('next', '@angular/core', 'react-dom', 'react-native-web'):
            out = self.scan({'mobile/package.json': {'dependencies': {'react-native': '0.81', 'react': '19'}},
                             'web/package.json': {'dependencies': {web: '1'}}})
            self.assertTrue(out['html_surface'])
            self.assertIn('no-csp', [f['kind'] for f in out['findings']])

    def test_actual_html_response_and_dom_evidence_remain(self):
        for name, source in (('server.js', "return new Response('<html>Hello</html>');"),
                             ('client.jsx', "const mount=document.getElementById('root');"),
                             ('index.html', '<html>Hello</html>')):
            self.assertTrue(self.scan({name: source})['html_surface'])
        for source in ('// document.getElementById("root");\n',
                       'const docs="document.createElement(\'div\')";',
                       "const report='<html>Hello</html>'; writeFile('report',report);"):
            self.assertFalse(self.scan({'package.json': {'dependencies': {'react': '19'}},
                                        'library.jsx': source})['web_surface'])

    def test_response_prose_and_unrelated_html_do_not_imply_browser(self):
        package = {'dependencies': {'react': '19', 'react-native': '0.81'}}
        for source in ("// return new Response('<html>Hello</html>');\n",
                       "/* return new Response('<html>Hello</html>'); */",
                       'const docs="return new Response(\'<html>Hello</html>\')";',
                       "const docs=`res.send('<html>Hello</html>')`;",
                       "const report='<html>Hello</html>'; return new Response('{}');",
                       "const report='<html>Hello</html>'; function other(){return res.send('ok');}"):
            with self.subTest(source=source):
                out = self.scan({'package.json': package, 'App.jsx': source})
                self.assertFalse(out['web_surface'])
                self.assertFalse(out['html_surface'])
        for source in ("return new Response('<html>Hello</html>');",
                       "return new Response(html,{headers:{'content-type':'text/html'}});",
                       "res.send('<html>Hello</html>');",
                       "return HttpResponse('<html>Hello</html>');"):
            with self.subTest(source=source):
                out = self.scan({'package.json': package, 'server.js': source})
                self.assertTrue(out['web_surface'])
                self.assertTrue(out['html_surface'])


if __name__ == '__main__':
    unittest.main()
