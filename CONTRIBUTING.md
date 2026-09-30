# Contributing to websec-validator

Thanks for your interest! This project has a small, deliberate design surface, so please
read this page before opening a PR — it will save you a round-trip.

## Ground rules (the non-negotiables)

These are the invariants the whole tool is built on. PRs that break them will be declined
regardless of how useful the feature is:

1. **Zero runtime dependencies.** The package is stdlib-only. New third-party tools are
   integrated by *shelling out* to them when present (see `src/websec_validator/scanners.py`), never by
   importing them. `dependencies = []` in `pyproject.toml` stays empty.
2. **The core pass stays offline and read-only.** Default analysis must not contact the
   network or edit scanned source. Live target probes belong in the explicitly authorized
   `dynamic` phase; mutating probes stay localhost-only at every transport. External scanners,
   feed/registry queries and consent-driven release metadata checks are separate opt-ins.
3. **No LLM in the tool.** Extractors are deterministic. The AI half of the workflow lives
   in the *agent* consuming `AGENT-BRIEFING.md`, not in this codebase.
4. **Every detector earns its keep with tests.** New extractors and detector classes need
   unit tests with both positive fixtures (it fires) and negative fixtures (it stays quiet
   on the safe pattern) — false-positive discipline is the product.

## Dev setup

```bash
git clone https://github.com/raccioly/websec-validator
cd websec-validator
python3 -m pip install -e .        # Python 3.11+; no other deps needed
python3 -m unittest discover -s tests   # full suite, stdlib only, no network
```

Optional, to exercise the scanner integrations locally: `brew install noir trivy gitleaks semgrep`.

## Making a change

- **Bug fix / false positive**: open an issue first if you can share the (sanitized) code
  pattern that triggered it — FP reports are the most valuable input this project gets.
  Add a regression fixture under `tests/fixtures/` mirroring the pattern.
- **New detector / extractor**: describe the vulnerability class and the evidence the
  detector keys on in the issue before writing code. Detectors must cite a CWE and state
  their expected false-positive mode. Wire new findings through the ledger so they get
  CWE/ASVS citations and calibrated confidence like everything else.
- **Docs**: `docs-canonical/` files are design intent and are validated by DocGuard —
  update them when behavior changes, and note deliberate divergence in `DRIFT-LOG.md`.

## PR checklist

- [ ] `python3 -m unittest discover -s tests` passes (CI runs 3.11/3.12/3.13)
- [ ] New behavior has positive **and** negative test fixtures
- [ ] `CHANGELOG.md` gets an entry under `[Unreleased]`
- [ ] No new runtime dependency, no network access in the core pass
- [ ] `docs/METHODOLOGY.md` updated if a check's reasoning changed

## Reporting security issues

Not here — see [SECURITY.md](SECURITY.md) for private reporting.

## Publishing the technical brief

Keep `docs/websec-explained.html` and the landing page's snapshot version consistent. Separate
current behavior from dated proof/review results; changing a masthead does not rerun a benchmark.
After editing the HTML, use an already installed Chrome/Chromium (no package dependency):

```bash
python3 scripts/build-brief.py             # optionally: --chrome /path/to/chrome
python3 scripts/build-brief.py --check     # offline, no browser required
python3 -m unittest discover -s tests -p 'test*brief*.py'
docguard guard
```

Render and inspect **all eight PDF pages**, including SVG labels and page breaks, before committing
the HTML, PDF and generated `docs/websec-explained.manifest.json` together. Do not hand-edit the
manifest. CI's normal suite verifies source/PDF/renderer digests and tests stale, missing,
truncated and aliased artifacts. A matching digest proves a recorded publication pair, not prose
accuracy or visual quality; those require review. The builder is maintenance tooling, not shipped
runtime behavior or an automatic browser installer.

DocGuard's `generatedStaleness` checks marked Markdown sections against generated section bodies;
it does **not** verify rendered PDFs. Its metrics/evidence validators cover configured claims,
not every sentence or HTML/PDF byte. An enabled validator with no matching sections is not PDF
coverage. The separate artifact test closes the forgotten-rebuild gap.

## Releases

Maintainer-only, via tag-triggered Trusted Publishing (OIDC) to PyPI — see the
"Releasing" section in the [README](README.md#releasing-maintainer).
