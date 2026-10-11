#!/usr/bin/env python3
"""Step 0 of every Jules routine: is there work, and which?

    python .jules/preflight.py <routine>

Prints `GO` and the one target for this run, or `STOP: <reason>`. Exit 0 on GO, 3 on STOP. A
routine that gets STOP ends without changes and without a pull request.

Reads the public GitHub API for this repository's Jules PRs (no token needed; GITHUB_TOKEN is used
when present). It fails closed: if the queue cannot be read, the answer is STOP, never a guess.
Server-side triage (.github/scripts/bot_triage.py) enforces the same policy after the fact; this
exists so the work is not done in the first place.

Maintenance tooling, not part of the package: nothing under src/ imports this, and the CLI's core
pass stays offline.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".github" / "scripts"))
sys.path.insert(0, str(ROOT / "src"))

import jules_policy as jp  # noqa: E402

REPO = os.environ.get("WEBSEC_REPO", "raccioly/websec-validator")
STOP = 3


def fn_hunt_targets() -> list:
    """Sink classes the surface extractor detects: each week, hunt one for missed variants."""
    from websec_validator.extractors.surface import SINKS
    return sorted(SINKS)


def fp_hunt_targets() -> list:
    """Every extractor, in registry order: each week, hunt one for false positives."""
    from websec_validator.extractors import REGISTRY
    return [e.name for e in REGISTRY]


def docs_drift_targets() -> list:
    """Every subcommand the real CLI defines, nested ones as `intel/refresh`."""
    import argparse as _ap
    from websec_validator.cli import build_parser

    out = []

    def walk(parser, prefix):
        for action in parser._actions:
            if isinstance(action, _ap._SubParsersAction):
                for name, sub in action.choices.items():
                    out.append("/".join(prefix + [name]))
                    walk(sub, prefix + [name])

    walk(build_parser(), [])
    return out


CANDIDATES = {"fn-hunt": fn_hunt_targets, "fp-hunt": fp_hunt_targets, "docs-drift": docs_drift_targets}


def details(routine: str, target: str) -> list:
    if routine == "fn-hunt":
        return [f"sink class: {target}  (SINKS['{target}'] in src/websec_validator/extractors/surface.py)"]
    if routine == "fp-hunt":
        return [f"extractor: {target}  (REGISTRY in src/websec_validator/extractors/__init__.py)"]
    cmd = target.replace("/", " ")
    return [f"compare: python -m websec_validator {cmd} --help  against every mention of `websec {cmd}` in README.md and docs/"]


def api(path: str):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "websec-jules-preflight"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    req = urllib.request.Request(f"https://api.github.com/repos/{REPO}{path}", headers=headers)
    with urllib.request.urlopen(req, timeout=20) as resp:   # noqa: S310 — fixed https host
        return json.load(resp)


def stop(reason: str):
    print(f"STOP: {reason}")
    sys.exit(STOP)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("routine")
    routine = parser.parse_args(argv).routine
    if routine not in jp.ROUTINES:
        stop(f'unknown routine "{routine}"; known: {", ".join(jp.ROUTINES)}')

    def shape(p):
        return {"number": p["number"], "title": p.get("title") or "", "labels": p.get("labels") or [],
                "merged_at": p.get("merged_at"), "closed_at": p.get("closed_at")}

    try:
        open_prs = [shape(p) for p in api("/pulls?state=open&per_page=100")
                    if jp.is_jules((p.get("user") or {}).get("login"))]
        closed_prs = [shape(p) for p in api("/pulls?state=closed&sort=updated&direction=desc&per_page=100")
                      if jp.is_jules((p.get("user") or {}).get("login"))]
    except Exception as error:   # any failure to read the queue is a STOP, never a guess
        stop(f"cannot read the pull request queue ({error}); failing closed")

    try:
        candidates = CANDIDATES[routine]()
    except Exception as error:
        stop(f"cannot list {routine} targets from the repository ({error}); failing closed")

    now = dt.datetime.now(dt.timezone.utc).isoformat()
    pick = jp.pick_target(routine, candidates, open_prs, closed_prs, now)
    if not pick["go"]:
        stop(pick["reason"])

    print("GO")
    print(f"routine: {routine}")
    print(f"target: {pick['target']}")
    for line in details(routine, pick["target"]):
        print(line)
    print(f"title: {jp.tag_title(routine, pick['target'])} — <one-line summary>")
    print(f"open Jules PRs: {len(open_prs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
