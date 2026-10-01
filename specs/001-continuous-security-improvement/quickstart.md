# Validation quickstart

Use supported Python and `PYTHONPATH=src`. Select an owned temporary `WEBSEC_CALIBRATION_HOME`
to avoid personalizing the operator's overlay. Run reproductions before/after each implementation.

```bash
python3 -m unittest discover -s tests
python3 -m unittest discover -s .github/scripts -p 'test_*.py'
python3 scripts/build-brief.py --check
docguard specs --write
docguard specs --check
docguard verify --evidence
docguard guard
```

Run CLI/ledger checks, independent review, compileall and isolated wheel smoke before release.
Record unavailable Docker/pre-commit tooling honestly; unexecuted matrices remain pending.
