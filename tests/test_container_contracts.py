"""Source/installer contracts; real image runtime checks run separately in CI."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/install-container-scanners.sh'


class ContainerContracts(unittest.TestCase):
    def plan(self, arch, **extra):
        return subprocess.run(['sh', str(SCRIPT), arch, '--plan'], env=dict(os.environ, **extra),
                              capture_output=True, text=True, timeout=5)

    # @req specs/001-continuous-security-improvement/spec.md#FR-005
    def test_architecture_plans_bind_exact_official_asset_digests(self):
        expected = {
            'amd64': [('noir_1.0.0_amd64.deb', 'e56082a4d74f6507c3118970baa934e13223c55f3e8a336916b68e4d70a19271'),
                      ('trivy_0.74.0_Linux-64bit.tar.gz', '2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a'),
                      ('gitleaks_8.30.1_linux_x64.tar.gz', '551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb')],
            'arm64': [('noir_1.0.0_arm64.deb', 'e7d28eb56c73b8a3a54f8b6dace1110ff898bddac94876efc59d7f08090f54a0'),
                      ('trivy_0.74.0_Linux-ARM64.tar.gz', 'b94ce1976bbf3c15b514b605ee88be7c6d94a29be2302847ff01cb794d47aad5'),
                      ('gitleaks_8.30.1_linux_arm64.tar.gz', 'e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080')]}
        for arch, rows in expected.items():
            result = self.plan(arch)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([tuple(line.split()) for line in result.stdout.splitlines()], rows)

    def test_unknown_arch_and_version_override_fail_before_network(self):
        for arch in ('', 'riscv64', '../amd64', 'AMD64'):
            self.assertEqual(self.plan(arch).returncode, 64)
        self.assertEqual(self.plan('amd64', TRIVY_VERSION='latest').returncode, 64)

    def test_all_digests_checked_before_extraction_or_install(self):
        text = SCRIPT.read_text()
        checked = text.index('sha256sum -c -')
        self.assertGreater(text.index('tar -xzf'), checked)
        self.assertGreater(text.index('apt-get update'), checked)
        self.assertNotRegex(text, r'\|\s*(?:ba)?sh(?:\s|$)')
        self.assertIn('mktemp -d /tmp/websec-scanners.', text)
        self.assertIn('trap cleanup EXIT', text)

    def test_mismatched_bytes_never_reach_privileged_install(self):
        import shutil
        if not shutil.which('sha256sum'):
            self.skipTest('sha256sum absent; execution contract is exercised on Linux CI')
        with tempfile.TemporaryDirectory() as td:
            owned = Path(td)
            curl = owned / 'curl'
            curl.write_text('#!/bin/sh\nwhile [ "$#" -gt 0 ]; do\n if [ "$1" = -o ]; then shift; printf corrupted > "$1"; exit 0; fi\n shift\ndone\nexit 1\n')
            curl.chmod(0o755)
            for name in ('tar', 'apt-get'):
                stub = owned / name
                stub.write_text('#!/bin/sh\nprintf activated > "'+str(owned / 'activated')+'"\nexit 99\n')
                stub.chmod(0o755)
            result = subprocess.run(['sh', str(SCRIPT), 'amd64'],
                env=dict(os.environ, PATH=str(owned)+os.pathsep+os.environ.get('PATH','')),
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('FAILED', result.stdout)
            self.assertFalse((owned / 'activated').exists())

    def test_core_bundled_health_privacy_and_top_level_pins(self):
        text = (ROOT / 'Dockerfile').read_text()
        core, bundled = text.split('FROM core AS bundled')
        self.assertIn('python:3.14-slim@sha256:', core)
        self.assertIn('HEALTHCHECK NONE', core)
        self.assertIn('USER websec', core)
        self.assertNotIn('semgrep', core)
        self.assertIn('ARG SEMGREP_VERSION=1.178.0', bundled)
        self.assertIn('ARG CHECKOV_VERSION=3.3.21', bundled)
        self.assertNotIn('contrib/install.sh', text)
        self.assertIn('**/.[lL][oO][cC][aA][lL]/', (ROOT / '.dockerignore').read_text())
        workflow = (ROOT / '.github/workflows/container-contracts.yml').read_text()
        for path in ('src/**', 'pyproject.toml', 'README.md', 'tests/test_container_contracts.py'):
            self.assertIn('      - '+path, workflow)
        self.assertIn('= "$IMAGE_ARCH"', workflow)


if __name__ == '__main__':
    unittest.main()
