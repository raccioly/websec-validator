"""websec-validator — local-first security recon that briefs an AI coding agent.

The tool does the deterministic half (read the repo, run the scanners it finds,
stage the probe library tailored to what it discovered) and emits three artifacts:

  1. findings.json    — de-duplicated static scanner results
  2. FACTS.json       — stack, routes, auth-model candidates, attack surface
  3. AGENT-BRIEFING.md — marching orders + staged probe scripts for your AI agent

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
