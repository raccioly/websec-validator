# Contributing to websec-validator

Thanks for your interest! This project has a small, deliberate design surface. Read this page
before you open a PR. It saves you a review round-trip.

## Ground rules (the non-negotiables)

The whole tool is built on these invariants. We decline PRs that break them,
however useful the feature is:

1. **Zero runtime dependencies.** The package uses only the standard library. The tool integrates new
   third-party tools by *shelling out* to them when present (see `src/websec_validator/scanners.py`), never by
   importing them. `dependencies = []` in `pyproject.toml` stays empty.
2. **The core pass stays offline and read-only.** Default analysis must not contact the
   network or edit scanned source. Live probes of a target belong in the explicitly authorized
   `dynamic` phase. Mutating probes stay localhost-only at every transport. External scanners,
   feed/registry queries and consent-driven release metadata checks are separate opt-ins.
3. **No LLM in the tool.** Extractors are deterministic. The AI half of the workflow lives
   in the *agent* that reads `AGENT-BRIEFING.md`, not in this codebase.
4. **Every detector needs tests.** New extractors and detector classes need
   unit tests with both positive fixtures (the detector fires) and negative fixtures (it stays quiet
   on the safe pattern). Control of false positives is the product.

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
  pattern that triggered it. FP reports are the most valuable input this project gets.
  Add a regression fixture under `tests/fixtures/` that mirrors the pattern.
- **New detector / extractor**: before you write code, describe in the issue the vulnerability
  class and the evidence the detector keys on. Detectors must cite a CWE and state
  their expected false-positive mode. Wire new findings through the ledger. Then they get
  CWE/ASVS citations and calibrated confidence like every other finding.
- **Docs**: `docs-canonical/` files state design intent, and DocGuard validates them.
  Update them when behavior changes, and note deliberate divergence in `DRIFT-LOG.md`.
  User-facing docs live under `docs/`. See [Writing documentation](#writing-documentation).

## PR checklist

- [ ] `python3 -m unittest discover -s tests` passes (CI runs 3.11/3.12/3.13)
- [ ] New behavior has positive **and** negative test fixtures
- [ ] `CHANGELOG.md` gets an entry under `[Unreleased]`
- [ ] No new runtime dependency, no network access in the core pass
- [ ] `docs/METHODOLOGY.md` updated if a check's reasoning changed
- [ ] New subcommand / flag / language profile documented in `docs/reference/` (the docs tests fail otherwise)

## Writing documentation

The user documentation starts at [docs/README.md](docs/README.md) and follows a fixed layout.
`quickstart.md` and `installation.md` are at the top. Then come task-oriented `guides/`, the complete `reference/`,
background in `concepts/`, plus `troubleshooting.md`, `faq.md` and `glossary.md`.

- **Put each fact in one place** and link to it. The reference pages own flags, defaults, file
  formats and support tiers. Guides own *sequences of steps*. METHODOLOGY owns the *why*.
- **Show real commands only.** `tests/test_docs_reference.py` parses every `websec …` line in a
  docs code block and fails on an unknown subcommand or option. It also requires these items:
  a section headed ``## `websec <name>` `` in `docs/reference/cli.md` for every subcommand, every long option
  named there, every language/profile id in `docs/reference/languages.md`, relative
  links and anchors that resolve, and every page linked from the hub.
- **No release pins in guides.** Use `<reviewed-commit-sha>`. A pinned version is right for one
  release and silently wrong after it. Dated records (`MIGRATING-*.md`, `CHANGELOG.md`) may name versions.
- **No moving counts** (test totals, rule counts) outside the dated records and the numbers DocGuard
  tracks. When a count is in prose, every PR that changes it collides with every other PR.
- **Keep the caveats.** Limits, authorization warnings and "this does not prove" sentences are part
  of the contract. Do not trim them as marketing.
- **README links are absolute** (`https://github.com/raccioly/websec-validator/blob/main/...`)
  because PyPI renders the README and does not resolve relative links. Everything under `docs/`
  uses relative links, so it also works in a fork or a local checkout.
- **Translations** live in `docs/i18n/<lang>/` and cover the README and quickstart only. Each opens
  with an English banner that names the release it was translated from. English is authoritative.

## Reporting security issues

Not here — see [SECURITY.md](SECURITY.md) for private reporting.

## Publishing the technical brief

Keep `docs/websec-explained.html` and the landing page's snapshot version consistent. Keep current
behavior apart from dated proof/review results. Changing a masthead does not rerun a benchmark.
After you edit the HTML, use a Chrome/Chromium that is already installed (no package dependency):

```bash
python3 scripts/build-brief.py             # optionally: --chrome /path/to/chrome
python3 scripts/build-brief.py --check     # offline, no browser required
python3 -m unittest discover -s tests -p 'test*brief*.py'
docguard guard
```

Render and inspect **all eight PDF pages**, including SVG labels and page breaks. Then commit
the HTML, PDF and generated `docs/websec-explained.manifest.json` together. Do not hand-edit the
manifest. The normal CI suite verifies source/PDF/renderer digests. It also tests stale, missing,
truncated and aliased artifacts. A matching digest proves a recorded publication pair. It does not prove prose
accuracy or visual quality, which need review. The builder is maintenance tooling. It is not shipped
runtime behavior and not an automatic browser installer.

DocGuard's `generatedStaleness` checks marked Markdown sections against generated section bodies.
It does **not** verify rendered PDFs. Its metrics/evidence validators cover configured claims,
not every sentence or HTML/PDF byte. An enabled validator with no matching sections is not PDF
coverage. The separate artifact test catches a forgotten rebuild.

## Releases

Maintainer-only. The release train is driven by PRs. Keep the version in `pyproject.toml` as the single
source of truth. Add the matching dated changelog and migration guidance, and validate the combined
release branch. In the 0.x series, a feature addition or an incompatible contract increments the minor
version.

Review current main and overlapping PRs. Merge the approved release PR only after its
required CI checks pass. The resulting main commit subject must be `release: v<version>`, where
`<version>` is the version that `pyproject.toml` currently declares. Do not hard-code a number here,
because it drifts. [release-tag.yml](.github/workflows/release-tag.yml) validates that subject against the
package version, creates the matching tag/GitHub Release, and explicitly dispatches
[publish.yml](.github/workflows/publish.yml) at that tag. A version edit alone does not publish.

The publish workflow builds and installs the wheel and verifies its version and smoke test. Then it uses
PyPI Trusted Publishing (OIDC) through the `pypi` environment. Verify the completed workflow, tag,
GitHub Release and PyPI artifact before you report that publication succeeded. Do not bypass failed checks
with manual tags. Do not describe a locally built wheel as published.

The CLI and the Claude plugin have separate delivery paths. The CLI uses PyPI semver releases. The
plugin uses reviewed Git content and an explicit marketplace refresh. Plugin manifests deliberately
omit an independent version field. Check both sources when you diagnose stale instructions.

Translations under `docs/i18n/` state the release they were translated from. A release does not
need to re-translate them. But if a change alters the English README's commands or install steps, update
the translations in the same PR (or open an issue tagged `docs`).
