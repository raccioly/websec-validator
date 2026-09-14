"""Opt-in configs reuse trusted entrypoints; no hooks/schedules are activated."""
import ast
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
import venv
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / '.pre-commit-hooks.yaml'
LOCAL = ROOT / 'docs/integrations/pre-commit-config.yaml.example'
WORKFLOW = ROOT / 'docs/integrations/security-review.yml.example'


def copy_ignored(directory, names):
    """Prune private/cache entries and every symlink before copytree descends."""
    return {name for name in names
            if name.casefold() == '.local' or name == '__pycache__' or name.endswith('.pyc')
            or (Path(directory) / name).is_symlink()}


def field(text, name):
    match = re.search(r'^\s*' + re.escape(name) + r':\s*(.+)$', text, re.M)
    if not match:
        raise AssertionError('missing field ' + name)
    return match[1].strip()


def arguments(text):
    # These fixtures deliberately use a simple scalar list, not arbitrary YAML.
    raw = field(text, 'args')
    return [item.strip() for item in raw[1:-1].split(',')]


class AdoptionConfigurationTests(unittest.TestCase):
    def test_engine_copy_prunes_private_trees_and_all_symlinks_before_reads(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source, destination, outside = root / 'engine', root / 'copied', root / 'outside'
            source.mkdir()
            outside.mkdir()
            (source / '__init__.py').write_text('safe = True\n')
            (source / 'nested').mkdir()
            (source / 'nested' / 'data.json').write_text('{}')
            for parent, name in ((source, '.local'), (source / 'nested', '.LoCaL')):
                (parent / name).mkdir()
                (parent / name / 'unread.py').write_text('synthetic private fixture')
            (source / '__pycache__').mkdir()
            (source / 'stale.pyc').write_bytes(b'cache')
            (outside / 'unread.py').write_text('synthetic outside fixture')
            (source / 'file-link.py').symlink_to(outside / 'unread.py')
            (source / 'directory-link').symlink_to(outside, target_is_directory=True)
            (source / 'safe-link.py').symlink_to(source / '__init__.py')
            (source / 'dangling-link').symlink_to(outside / 'absent')
            real_scandir = os.scandir
            real_copy = shutil.copy2
            copied = []

            def guarded_scandir(path):
                current = Path(path)
                self.assertFalse(any(part.casefold() == '.local' for part in current.parts))
                self.assertFalse(current.is_symlink())
                self.assertNotEqual(current, outside)
                return real_scandir(path)

            def guarded_copy(src, dest):
                current = Path(src)
                self.assertFalse(current.is_symlink())
                self.assertFalse(any(part.casefold() == '.local' for part in current.parts))
                copied.append(current.relative_to(source).as_posix())
                return real_copy(src, dest)

            with patch('os.scandir', side_effect=guarded_scandir):
                shutil.copytree(source, destination, ignore=copy_ignored, copy_function=guarded_copy)
            self.assertEqual(sorted(copied), ['__init__.py', 'nested/data.json'])
            self.assertEqual(sorted(p.relative_to(destination).as_posix() for p in destination.rglob('*')),
                             ['__init__.py', 'nested', 'nested/data.json'])

    def test_manifest_gate_and_whole_repository_contract(self):
        text = MANIFEST.read_text()
        self.assertEqual(field(text, 'entry'), 'python -I -m websec_validator.cli run .')
        self.assertEqual(field(text, 'language'), 'python')
        for key in ('always_run', 'require_serial'):
            self.assertEqual(field(text, key), 'true')
        self.assertEqual(field(text, 'pass_filenames'), 'false')
        self.assertEqual(field(text, 'stages'), '[pre-commit, pre-push, manual]')
        self.assertEqual(arguments(text), ['--require-complete', '--fail-on', 'high', '--out', 'websec-out'])
        self.assertNotIn('--baseline', text)
        self.assertNotIn('--scan', text)

    def test_local_unreleased_example_has_explicit_trusted_path(self):
        text = LOCAL.read_text()
        self.assertIn('repo: local', text)
        self.assertEqual(field(text, 'language'), 'system')
        entry = ast.literal_eval(field(text, 'entry'))
        argv = shlex.split(entry)
        self.assertEqual(argv[0], '/ABSOLUTE/PATH/TO/TRUSTED/WEBSEC-VENV/bin/python')
        self.assertEqual(argv[1:], shlex.split(field(MANIFEST.read_text(), 'entry'))[1:])
        self.assertEqual(arguments(text), arguments(MANIFEST.read_text()))
        self.assertNotIn('additional_dependencies', text)
        self.assertNotIn('rev: v0.13', text)

    def test_workflow_separates_engine_target_and_current_artifacts(self):
        text = WORKFLOW.read_text()
        self.assertIn('  pull_request:', text)
        self.assertIn('  schedule:', text)
        self.assertNotIn('pull_request_target:', text)
        self.assertIn('permissions:\n  contents: read', text)
        self.assertNotIn('security-events: write', text)
        self.assertIn('repository: raccioly/websec-validator', text)
        self.assertIn('ref: ${{ vars.WEBSEC_REVIEWED_SHA }}', text)
        self.assertEqual(text.count('persist-credentials: false'), 2)
        self.assertIn('path: .websec-engine', text)
        self.assertIn('path: .websec-target', text)
        self.assertIn('uses: ./.websec-engine', text)
        self.assertNotIn('uses: ./.websec-target', text)
        self.assertIn('out: ${{ runner.temp }}/websec-review', text)
        self.assertIn('path: ${{ steps.audit.outputs.run-directory }}', text)
        self.assertIn("always() && steps.audit.outputs.run-directory != ''", text)
        self.assertIn('upload-sarif: "false"', text)
        self.assertIn('require-complete: "true"', text)
        self.assertNotIn('/latest', text)
        self.assertFalse((ROOT / '.github/workflows/security-review.yml').exists())
        actions = re.findall(r'uses: ([^\s]+)', text)
        for action in actions:
            if not action.startswith('./'):
                self.assertRegex(action, r'@[0-9a-f]{40}$')

    def test_workflow_revision_validation_uses_data_not_shell_interpolation(self):
        text = WORKFLOW.read_text()
        raw = text.split("python3 -I - <<'PY'\n", 1)[1].split('\n          PY', 1)[0]
        code = '\n'.join(line[10:] for line in raw.splitlines())
        self.assertNotIn('${{', code)
        for revision, expected in [('a' * 40, 0), ('A' * 40, 0), ('main', 1), ('', 1),
                                   ('a' * 40 + '\n', 1), ('$(touch marker)', 1)]:
            result = subprocess.run([sys.executable, '-I', '-c', code],
                                    env={**os.environ, 'WEBSEC_REVIEWED_SHA': revision},
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, expected, result.stderr)
        self.assertLess(text.index('Require a reviewed engine revision'), text.index('Check out trusted engine'))


class AdoptionEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        # Copy only the trusted engine into a fresh stdlib venv: no pip/dependencies.
        cls.environment = cls.root / 'trusted engine'
        venv.EnvBuilder(with_pip=False).create(cls.environment)
        cls.python = cls.environment / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
        site = subprocess.check_output([str(cls.python), '-I', '-c',
              'import sysconfig; print(sysconfig.get_path("purelib"))'], text=True).strip()
        shutil.copytree(ROOT / 'src/websec_validator', Path(site) / 'websec_validator',
                        ignore=copy_ignored)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_hook(self, source, *, oversized=False):
        with tempfile.TemporaryDirectory(dir=self.root) as td:
            target = Path(td)
            (target / 'app.py').write_text(source)
            if oversized:
                (target / 'huge.py').write_bytes(b'#' * (16 * 1024 * 1024 + 1))
            marker = target / 'target-code-executed'
            shadow = target / 'websec_validator'
            shadow.mkdir()
            (shadow / '__init__.py').write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nraise RuntimeError("target shadow")\n')
            argv = shlex.split(field(MANIFEST.read_text(), 'entry'))
            argv[0] = str(self.python)
            argv += arguments(MANIFEST.read_text()) + ['--format', 'json']
            env = {**os.environ, 'PYTHONPATH': str(target), 'PATH': str(self.python.parent)}
            result = subprocess.run(argv, cwd=target, env=env, capture_output=True, text=True, timeout=30)
            self.assertFalse(marker.exists(), 'target package shadow executed')
            envelope = json.loads(result.stdout)
            current = target / 'websec-out/runs' / envelope['generated']
            self.assertTrue((current / 'coverage.json').is_file())
            self.assertFalse((target / '.git/hooks').exists())
            return result.returncode, envelope

    def test_documented_entrypoint_ignores_target_import_shadow(self):
        status, envelope = self.run_hook('x = 1\n')
        self.assertEqual(status, 0)
        self.assertTrue(envelope['coverage']['execution_complete'])

    def test_documented_gate_blocks_high_findings(self):
        status, envelope = self.run_hook("import hashlib\ndef login(password):\n return hashlib.md5(password).hexdigest()\n")
        self.assertEqual(status, 1)
        self.assertTrue(envelope['coverage']['execution_complete'])
        self.assertGreater(envelope['summary']['by_severity'].get('HIGH', 0), 0)

    def test_documented_gate_blocks_read_loss_with_partial_artifact(self):
        status, envelope = self.run_hook('x=1\n', oversized=True)
        self.assertEqual(status, 2)
        self.assertFalse(envelope['coverage']['execution_complete'])


if __name__ == '__main__':
    unittest.main()
