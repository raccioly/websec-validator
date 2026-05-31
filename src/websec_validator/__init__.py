"""websec-validator — local-first security recon that briefs an AI coding agent.

The tool does the deterministic half (read the repo, run the scanners it finds,
stage the probe library tailored to what it discovered) and emits three artifacts:

  1. findings.json    — de-duplicated static scanner results
  2. FACTS.json       — stack, routes, auth-model candidates, attack surface
  3. AGENT-BRIEFING.md — marching orders + staged probe scripts for your AI agent

It never calls an LLM, never runs a server, and never needs a running instance of
the target app. Running the probes and applying fixes is the agent + human's job.
"""

__version__ = "0.1.0"
