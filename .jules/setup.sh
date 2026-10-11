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
#
# ONE interpreter for everything: `python` (the VM's pyenv default), or $PYTHON if set. Never rely
# on the `websec` console script being on PATH — in the Jules VM `python3` and `python` are
# different interpreters and the script landed outside PATH, so `websec --version` failed the
# first snapshot. `python -m websec_validator` always reaches the package the same interpreter
# installed. The routines use the same form.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

PY="${PYTHON:-$(command -v python || command -v python3)}"

echo "== toolchain"
echo "interpreter: $PY"
"$PY" --version; git --version; node -v; npm -v
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else "Python >= 3.11 required")'

echo "== the package, editable, with no dependencies (it has none at runtime)"
"$PY" -m pip install --quiet --disable-pip-version-check --no-deps --editable . < /dev/null
"$PY" -m websec_validator --version

echo "== the docs check at the pin RULES.md uses, cached into the snapshot"
npx -y docguard-cli@0.43.0 --version < /dev/null

echo "== the suite must be green here before any routine runs"
# stdin detached and output to a file: attached to the Jules console, the run was killed mid-suite
# (a child process inheriting the console's stdin can block; websec now detaches stdin for every
# spawn, and this keeps setup independent of the console either way). The log tail is printed on
# failure so the snapshot error still says why.
LOG="${TMPDIR:-/tmp}/websec-suite.log"
if ! PYTHONPATH=src "$PY" -m unittest discover -s tests < /dev/null > "$LOG" 2>&1; then
  tail -80 "$LOG"
  echo "the suite is red in this VM: no snapshot" >&2
  exit 1
fi
tail -3 "$LOG"
"$PY" .jules/preflight.py --help < /dev/null > /dev/null

echo "== leave the tree exactly as cloned (Jules refuses a dirty tree)"
git reset --hard HEAD
git clean -fd
test -z "$(git status --porcelain)"
echo "ready"
