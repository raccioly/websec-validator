<!-- Thanks for contributing! See CONTRIBUTING.md for the ground rules. -->

## What & why

<!-- What does this change, and what problem does it solve? Link the issue if there is one. -->

## Checklist

- [ ] `python3 -m unittest discover -s tests` passes locally
- [ ] New behavior has **positive and negative** test fixtures (fires on the vuln, stays quiet on the safe pattern)
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] No new runtime dependency; core pass stays offline & read-only on the target
- [ ] `docs/METHODOLOGY.md` / `docs-canonical/` updated if behavior or design intent changed
