"""Create an owned inert Git target checkout for the development integration matrix.

This is trusted test infrastructure, never a target-provided installer or arbitrary PR runner.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def git(root, *args, extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0',
               GIT_AUTHOR_NAME='Owned fixture', GIT_AUTHOR_EMAIL='fixture@example.invalid',
               GIT_COMMITTER_NAME='Owned fixture', GIT_COMMITTER_EMAIL='fixture@example.invalid')
    if extra:
        env.update(extra)
    return subprocess.run(['git', '-c', 'core.hooksPath='+os.devnull, '-c', 'core.fsmonitor=false',
                           '-c', 'commit.gpgsign=false', '-c', 'log.showSignature=false',
                           '-C', str(root), *args], env=env, capture_output=True, text=True,
                          check=True, timeout=30).stdout.strip()


def create(owner: Path, case: str):
    if case not in {'clean', 'unsafe', 'incomplete'}:
        raise ValueError('unsupported case')
    owner = owner.resolve(strict=True)
    if not owner.is_dir() or any(p.lower()=='.local' for p in owner.parts) or any(ord(c)<32 for c in str(owner)):
        raise ValueError('owner must be an operator-selected nonprivate directory')
    reserved = Path(tempfile.mkdtemp(prefix='websec-adoption-checkout-', dir=owner))
    seed, target, template = reserved/'seed', reserved/'target', reserved/'hostile-template'
    seed.mkdir()
    (template/'hooks').mkdir(parents=True)
    marker = reserved/'TARGET_EXECUTED'
    hostile = 'from pathlib import Path\nPath('+repr(str(marker))+').touch()\nraise RuntimeError("target stays data")\n'
    (seed/'hostile_backend.py').write_text(hostile)
    (seed/'websec_validator').mkdir()
    (seed/'websec_validator/__init__.py').write_text(hostile)
    (seed/'pyproject.toml').write_text('[build-system]\nrequires=[]\nbuild-backend="hostile_backend"\nbackend-path=["."]\n')
    (seed/'action.yml').write_text('runs:\n  using: composite\n  steps:\n  - shell: bash\n    run: exit 99\n')
    source = 'x=1\n'
    if case=='unsafe':
        source = 'import hashlib\ndef login(password):\n return hashlib.md5(password).hexdigest()\n'
    elif case=='incomplete':
        source = '#'*(16*1024*1024+1)
    (seed/'app.py').write_text(source)
    # A known executable sentinel is inert unless Git incorrectly uses target helpers/hooks.
    hook = '#!/bin/sh\n'+ 'touch "'+str(marker)+'"\nexit 99\n'
    # Double quote shell metacharacters cannot come from the temporary prefix; refuse unsafe owner.
    if any(c in str(marker) for c in ('"', '$', '`', '\\')):
        raise ValueError('unsafe hook-sentinel path')
    (template/'hooks/post-checkout').write_text(hook)
    (template/'hooks/post-checkout').chmod(0o700)
    git(seed, 'init', '--template=', '--initial-branch=fixture')
    git(seed, 'add', '--', 'app.py', 'hostile_backend.py', 'pyproject.toml', 'action.yml', 'websec_validator')
    git(seed, 'commit', '-m', 'owned inert fixture')
    head = git(seed, 'rev-parse', 'HEAD')
    (seed/'.git/hooks').mkdir()
    (seed/'.git/hooks/post-checkout').write_text(hook)
    (seed/'.git/hooks/post-checkout').chmod(0o700)
    # Manufacture hostile inherited template state, then explicitly refuse it while cloning.
    git(reserved, 'clone', '--no-hardlinks', '--template=', '--', str(seed), str(target),
        extra={'GIT_TEMPLATE_DIR': str(template)})
    git(target, 'checkout', '--detach', head)
    assert git(target, 'rev-parse', 'HEAD') == head
    assert not marker.exists()
    assert not (target/'.git/hooks/post-checkout').exists()
    assert git(target, 'status', '--porcelain') == ''
    # The scanned checkout itself has hostile local config; metadata intake must neutralize it.
    git(target, 'config', 'core.hooksPath', str(template/'hooks'))
    git(target, 'config', 'core.fsmonitor', str(template/'hooks/post-checkout'))
    return {'target': str(target), 'commit': head, 'marker': str(marker), 'owner': str(reserved)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner', type=Path, required=True)
    parser.add_argument('--case', choices=['clean','unsafe','incomplete'], required=True)
    args = parser.parse_args()
    result = create(args.owner, args.case)
    print(json.dumps(result))
    if os.environ.get('GITHUB_OUTPUT'):
        # Runner-selected command file; this path is never supplied by the scanned target.
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
            for key in ('target','commit','marker'):
                handle.write(key+'='+result[key]+'\n')
    return 0


if __name__=='__main__':
    raise SystemExit(main())
