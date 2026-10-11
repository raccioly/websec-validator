#!/usr/bin/env bash
# Jules environment setup for websec-validator.
#
# In Jules: this repository → Configuration → Initial Setup, enter
#     bash .jules/setup.sh
# and click "Run and Snapshot". Every later task starts from that snapshot.
#
# It fails — and so leaves no snapshot — when the suite is not green here. A red baseline inside
# the agent's VM is exactly what made this repository receive the same one-line "fix" 27 times: CI
# could never reproduce what the sandbox saw. Nothing here is `|| true`.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

echo "== toolchain"
python3 --version; git --version; node -v; npm -v
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python >= 3.11 required")'

echo "== the package, editable, with no dependencies (it has none at runtime)"
python3 -m pip install --quiet --no-deps --editable .
websec --version

echo "== the docs check at the pin RULES.md uses, cached into the snapshot"
npx -y docguard-cli@0.43.0 --version

echo "== the suite must be green here before any routine runs"
PYTHONPATH=src python3 -m unittest discover -s tests
python3 .jules/preflight.py --help > /dev/null

echo "== leave the tree exactly as cloned (Jules refuses a dirty tree)"
git reset --hard HEAD
git clean -fd
test -z "$(git status --porcelain)"
echo "ready"
