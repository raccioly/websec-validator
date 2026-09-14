"""Stack summaries share declared dependency and manifest-boundary evidence."""
from pathlib import Path
import contextlib
import io
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.stack import StackExtractor
from websec_validator.extractors import profiles
from websec_validator import cli


class StackMetadataTests(unittest.TestCase):
    def scan(self, files, include_fixtures=False):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, data in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(data) if isinstance(data, dict) else data)
            return StackExtractor().extract(RepoContext(root, include_fixtures=include_fixtures), {})

    def test_actual_dependency_keys_classify_angular_react_and_native(self):
        out = self.scan({'package.json': {'dependencies': {'@angular/core': '^20', 'react': '^19', 'react-native': '^0.81'}}})
        self.assertEqual(out['frameworks'], ['angular', 'react', 'react-native'])
        self.assertEqual(out['service_inventory'][0]['frameworks'], out['frameworks'])
        self.assertEqual(out['profiles']['profiles'], [])
        self.assertIn('does not prove', out['metadata_note'])

    def test_descriptions_scripts_and_other_json_fields_are_not_dependencies(self):
        out = self.scan({'package.json': {'name': 'react', 'description': 'spring android @angular/core',
            'scripts': {'express': 'react-native', 'pg': 'typescript'}, 'config': {'framework': 'next'},
            'exports': {'./feature': '@supabase/supabase-js'}, 'dependencies': {'@babel/parser': '^7'}}})
        self.assertEqual(out['frameworks'], [])
        self.assertEqual(out['datastores'], [])
        self.assertNotIn('typescript', out['languages'])
        self.assertEqual(out['service_inventory'][0]['frameworks'], [])

    def test_dependency_section_shapes_are_validated(self):
        for source in ('[]', 'null', '{broken', '{"dependencies": ["express"]}',
                       '{"dependencies":"react-native"}', '{"dependencies":{"express":true,"react":null}}'):
            with self.subTest(source=source):
                out = self.scan({'package.json': source})
                self.assertEqual(out['frameworks'], [])
                self.assertEqual(out['datastores'], [])
                self.assertTrue(out['profiles']['errors'])

    def test_malformed_siblings_preserve_valid_dependency_evidence(self):
        out = self.scan({'package.json': {'dependencies': {'express': '^4', 'react': None},
                                         'devDependencies': ['typescript'],
                                         'peerDependencies': {'@angular/core': '^20'}}})
        self.assertEqual(out['frameworks'], ['angular', 'express'])
        self.assertEqual(len(out['profiles']['errors']), 2)
        self.assertTrue(all(row['file'] == 'package.json' for row in out['profiles']['errors']))
        self.assertTrue(all(row['check'] == 'node-manifest-metadata' for row in out['profiles']['errors']))
        for package in ({}, {'dependencies': {}}, {'dependencies': {'express': '^4'}}):
            self.assertEqual(self.scan({'package.json': package})['profiles']['errors'], [])

    def test_manifest_diagnostics_are_bounded_and_omissions_visible(self):
        files = {f'service{index}/package.json': {'dependencies': ['express']} for index in range(5)}
        with patch.object(profiles, 'MAX_MANIFEST_ERRORS', 2):
            out = self.scan(files)
        self.assertEqual(len(out['profiles']['errors']), 3)
        self.assertIn('3 additional manifest diagnostics omitted', out['profiles']['errors'][-1]['error'])

    def test_malformed_metadata_fails_strict_cli_and_preserves_latest(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / 'repo'; root.mkdir()
            out = Path(td) / 'output'
            package = root / 'package.json'; package.write_text('{}')
            def invoke():
                with patch('shutil.which', return_value=None), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return cli.main(['run', str(root), '--out', str(out), '--require-complete'])
            self.assertEqual(invoke(), 0)
            latest = (out / 'latest').resolve()
            package.write_text('{"dependencies":["express"]}')
            self.assertEqual(invoke(), 2)
            self.assertEqual((out / 'latest').resolve(), latest)
            attempt = max((out / 'runs').iterdir(), key=lambda path: path.stat().st_mtime_ns)
            coverage = json.loads((attempt / 'coverage.json').read_text())
            self.assertFalse(coverage['execution_complete'])
            self.assertEqual(coverage['profile_errors'][0]['file'], 'package.json')

    def test_supported_declaration_sections_remain_dependency_hints(self):
        for section in ('dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'):
            with self.subTest(section=section):
                out = self.scan({'package.json': {section: {'express': '^4', 'pg': '^8', 'typescript': '^5'}}})
                self.assertIn('express', out['frameworks'])
                self.assertIn('postgres', out['datastores'])
                self.assertIn('typescript', out['languages'])
        out = self.scan({'package.json': {'dependencies': {'@remix-run/node': '^2', '@supabase/supabase-js': '^2'}}})
        self.assertIn('remix', out['frameworks'])
        self.assertIn('supabase', out['frameworks'])

    def test_mixed_rust_node_inventory_and_counts_agree(self):
        out = self.scan({'Cargo.toml': '[workspace]\nmembers=["engine"]\n',
                         'engine/Cargo.toml': '[package]\nname="engine"\nversion="0.1.0"\n',
                         'web/package.json': {'dependencies': {'react': '^19'}}})
        self.assertEqual(out['services'], 3)
        self.assertEqual(len(out['service_inventory']), 3)
        self.assertTrue(out['monorepo'])
        self.assertIn('rust', out['languages'])
        self.assertIn('cargo', out['package_managers'])
        own = {s['root']: s for s in out['service_inventory']}
        self.assertEqual(own['web']['frameworks'], ['react'])
        self.assertEqual(own['engine']['frameworks'], [])

    def test_product_first_fixture_selection_applies_across_languages(self):
        for product in ('Cargo.toml', 'go.mod', 'pom.xml', 'pyproject.toml'):
            with self.subTest(product=product):
                out = self.scan({product: '', 'examples/mobile/package.json': {'dependencies': {'react-native': '^0.81'}},
                                 'examples/mobile/yarn.lock': '', 'fixtures/rust/Cargo.toml': '[package]\nname="fixture"'})
                self.assertNotIn('react-native', out['frameworks'])
                self.assertNotIn('yarn', out['package_managers'])
                self.assertEqual([s['root'] for s in out['service_inventory']], ['.'])
                self.assertEqual(out['services'], 1)
                self.assertFalse(out['monorepo'])
                if product != 'Cargo.toml':
                    self.assertNotIn('cargo', out['package_managers'])

    def test_fixture_only_fallback_and_explicit_inclusion_stay_visible(self):
        fixture = {'examples/mobile/package.json': {'dependencies': {'react-native': '^0.81'}}}
        out = self.scan(fixture)
        self.assertIn('react-native', out['frameworks'])
        self.assertIn('examples/mobile', [s['root'] for s in out['service_inventory']])
        self.assertEqual(out['services'], len(out['service_inventory']))
        out = self.scan({'Cargo.toml': '', **fixture}, include_fixtures=True)
        self.assertIn('react-native', out['frameworks'])
        self.assertEqual(out['services'], 2)
        self.assertEqual(out['profiles']['profiles'][0]['id'], 'rust')
        self.assertNotIn('android', [p['id'] for p in out['profiles']['profiles']])

    def test_cli_and_native_templates_do_not_prove_a_native_app(self):
        out = self.scan({'package.json': {'name': 'generator-cli', 'bin': {'generate': 'cli.js'},
                                         'dependencies': {'@babel/parser': '^7'}},
                         'cli.js': 'console.log("generate a react-native app")',
                         'examples/app/package.json': {'dependencies': {'react-native': '^0.81'}},
                         'templates/App.tsx': 'export default () => <View />;'})
        self.assertEqual(out['frameworks'], [])
        self.assertEqual(out['profiles']['profiles'], [])
        self.assertEqual(out['services'], 1)

    def test_python_and_node_product_services_remain_visible(self):
        out = self.scan({'api/requirements-prod.txt': 'Django>=5\npsycopg2>=2\n',
                         'frontend/package.json': {'dependencies': {'@angular/core': '^20'}}})
        self.assertIn('django', out['frameworks'])
        self.assertIn('angular', out['frameworks'])
        self.assertIn('pip', out['package_managers'])
        self.assertEqual(out['services'], len(out['service_inventory']))
        own = {s['root']: s for s in out['service_inventory']}
        self.assertIn('django', own['api']['frameworks'])
        self.assertNotIn('django', own['frontend']['frameworks'])


if __name__ == '__main__':
    unittest.main()
