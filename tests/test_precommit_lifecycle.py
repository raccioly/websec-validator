"""Opt-in real framework lifecycle. No hooks are installed outside an owned temp root."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get('WEBSEC_VALIDATE_PRECOMMIT') == '1',
                     'real pre-commit lifecycle is an opt-in development/CI integration check')
class PrecommitLifecycle(unittest.TestCase):
    # @req specs/001-continuous-security-improvement/spec.md#FR-005
    def test_real_install_staging_manual_push_and_foreign_hook_contract(self):
        from test_adoption_contracts import copy_ignored
        with tempfile.TemporaryDirectory() as td:
            owned = Path(td)
            engine, target = owned / 'trusted-engine', owned / 'target'
            engine.mkdir()
            target.mkdir()
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
                       PRE_COMMIT_HOME=str(owned / 'framework-cache'),
                       WEBSEC_UPDATE_HOME=str(owned / 'release-metadata'),
                       WEBSEC_CALIBRATION_HOME=str(owned / 'calibration'),
                       GIT_TERMINAL_PROMPT='0')
            # Ambient Git overrides must not redirect the temporary repositories.
            for key in list(env):
                if key.startswith('GIT_CONFIG_KEY_') or key.startswith('GIT_CONFIG_VALUE_') or key in {
                        'GIT_CONFIG_COUNT', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_CONFIG_PARAMETERS'}:
                    env.pop(key)
            hostile_template = owned / 'hostile-template'
            (hostile_template / 'hooks').mkdir(parents=True)
            (hostile_template / 'hooks/pre-commit').write_text('#!/bin/sh\nexit 99\n')
            (hostile_template / 'hooks/pre-commit').chmod(0o755)
            env['GIT_TEMPLATE_DIR'] = str(hostile_template)

            def run(argv, cwd=target, expected=0, timeout=30):
                result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
                self.assertEqual(result.returncode, expected, result.stdout+'\n'+result.stderr)
                return result

            def git(*args, cwd=target, expected=0):
                return run(['git', '-c', 'commit.gpgsign=false', *args], cwd, expected)

            for repo in (engine, target):
                git('init', '--template=', cwd=repo)
                git('config', 'user.name', 'WebSec isolated validation', cwd=repo)
                git('config', 'user.email', 'validation@example.invalid', cwd=repo)
                git('config', 'core.autocrlf', 'false', cwd=repo)
            shutil.copytree(ROOT / 'src', engine / 'src', ignore=copy_ignored)
            for name in ('pyproject.toml', 'README.md', '.pre-commit-hooks.yaml'):
                shutil.copy2(ROOT / name, engine / name)
            git('add', '.', cwd=engine)
            git('commit', '-m', 'owned trusted engine snapshot', cwd=engine)
            revision = git('rev-parse', 'HEAD', cwd=engine).stdout.strip()
            (target / '.pre-commit-config.yaml').write_text('repos:\n- repo: '+engine.as_uri()+'\n'
                '  rev: '+revision+'\n  hooks:\n  - id: websec-security\n')
            (target / '.gitignore').write_text('websec-out/\n')
            app = target / 'app.py'
            clean = 'x=1\n'
            unsafe = 'import hashlib\ndef login(password):\n return hashlib.md5(password).hexdigest()\n'
            app.write_text(clean)
            git('add', '.')
            git('commit', '-m', 'owned target baseline')
            framework = [sys.executable, '-m', 'pre_commit']
            run(framework + ['validate-config'])
            run(framework + ['validate-manifest', str(engine / '.pre-commit-hooks.yaml')])
            foreign = target / '.git/hooks/pre-commit'
            foreign.parent.mkdir(exist_ok=True)
            foreign_bytes = b'#!/bin/sh\necho FOREIGN_OWNED_SENTINEL\n'
            foreign.write_bytes(foreign_bytes)
            foreign.chmod(0o755)
            run(framework + ['install', '--install-hooks', '--hook-type', 'pre-commit', '--hook-type', 'pre-push'], timeout=180)
            self.assertEqual((target / '.git/hooks/pre-commit.legacy').read_bytes(), foreign_bytes)
            run(framework + ['run', 'websec-security', '--all-files', '--hook-stage', 'manual'])
            # Actual commit event blocks staged unsafe input, without accepting baseline.
            app.write_text(unsafe)
            git('add', 'app.py')
            git('commit', '-m', 'must reject staged unsafe input', expected=1)
            # Framework hides unstaged tracked changes; working tree is restored afterwards.
            app.write_text('x=2\n')
            git('add', 'app.py')
            app.write_text(unsafe)
            git('commit', '-m', 'clean index with unsafe unstaged changes')
            self.assertEqual(app.read_text(), unsafe)
            run(framework + ['run', 'websec-security', '--all-files', '--hook-stage', 'manual'], expected=1)
            run(framework + ['run', 'websec-security', '--all-files', '--hook-stage', 'pre-push'], expected=1)
            # Exercise the installed dispatcher with an actual push to an owned local remote.
            remote = owned / 'remote.git'
            git('init', '--template=', '--bare', str(remote))
            git('remote', 'add', 'origin', str(remote))
            git('push', 'origin', 'HEAD', expected=1)
            app.write_text('x=2\n')
            git('push', 'origin', 'HEAD')
            self.assertEqual(git('--git-dir='+str(remote), 'rev-parse', 'HEAD').stdout.strip(),
                             git('rev-parse', 'HEAD').stdout.strip())
            self.assertFalse((target / 'websec-out/baseline.json').exists())
            run(framework + ['uninstall', '--hook-type', 'pre-commit', '--hook-type', 'pre-push'])
            self.assertEqual(foreign.read_bytes(), foreign_bytes)


if __name__ == '__main__':
    unittest.main()
