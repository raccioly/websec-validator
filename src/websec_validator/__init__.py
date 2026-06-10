"""websec-validator — local-first security recon that briefs an AI coding agent.

The tool does the deterministic half (read the repo, run the scanners it finds,
stage the probe library tailored to what it discovered) and emits, per immutable run:

  1. FACTS.json          — stack, routes, auth-model candidates, attack surface
  2. findings.json       — de-duplicated static scanner results (when --scan)
  3. findings-ledger.json — ranked, standards-cited, calibrated findings (recon + static + dynamic)
  4. AGENT-BRIEFING.md   — marching orders + the per-attack-class targeting
  5. REPORT.md           — the human-readable historical record
  6. CONSTITUTION.md     — the app's security invariants as checkable Given/When/Then
  7. probes/             — the probe library staged against THIS app's real surface

It never calls an LLM, never runs a server, and never needs a running instance of
the target app. Running the probes and applying fixes is the agent + human's job.
"""

# Single source of truth is pyproject.toml — derive __version__ from the installed
# package metadata so the two can never drift (the bug where `--version` lagged the release).
from importlib.metadata import PackageNotFoundError, version as _pkg_version

try:
    __version__ = _pkg_version("websec-validator")
except PackageNotFoundError:  # running straight from source, not installed
    __version__ = "0.0.0+source"
