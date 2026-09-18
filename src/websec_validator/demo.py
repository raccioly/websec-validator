"""`websec demo` — a real run against a bundled sample, in a throwaway directory.

Adoption problem this solves: the output is the product, and you cannot see it without
first pointing the tool at something you care about. A sample removes that step.

It is a genuine run — the same recon, ledger and briefing code as `websec run`, not a
canned transcript — so what you see is what the tool actually produces today. It writes
only inside a temporary directory and never touches the current project.

The sample ships as `.txt` so nothing imports, lints or executes it, and it deliberately
contains no credential-shaped strings: a fake secret inside an installed package would be
found by other people's secret scanners pointed at site-packages.
"""
from __future__ import annotations

import shutil
import tempfile
from importlib import resources
from pathlib import Path

# Shipped name -> name it takes in the materialised sample.
FILES = {"app.py.txt": "app.py", "requirements.txt.txt": "requirements.txt"}


def materialize(destination: Path) -> Path:
    """Write the sample app into `destination`. Returns the sample root."""
    root = destination / "demo-app"
    (root / "src").mkdir(parents=True, exist_ok=True)
    base = resources.files("websec_validator").joinpath("templates/demo")
    for shipped, real in FILES.items():
        target = root / ("src/" + real if real.endswith(".py") else real)
        target.write_text(base.joinpath(shipped).read_text(encoding="utf-8"), encoding="utf-8")
    return root


def run(log=print) -> int:
    """Scan the bundled sample and summarise what it found."""
    from . import __version__, findings, recon

    temp = Path(tempfile.mkdtemp(prefix="websec-demo-"))
    try:
        root = materialize(temp)
        log(f"websec-validator v{__version__} — demo")
        log(f"\n  Scanning a bundled sample app ({root.name}); your project is untouched.")
        log("  This is a real run, not a recording.\n")

        facts = recon.build_facts(root, __version__, None)
        ledger = findings.build_ledger(facts, None)
        rows = ledger.get("findings") or []
        if not rows:
            # Never claim a clean demo: if the sample stops tripping the detectors that is
            # a regression in the tool, not a result worth showing.
            log("  No findings on the sample — that is a bug in the detectors, not a clean bill.")
            return 1

        log(f"  {len(rows)} finding(s):\n")
        for row in rows[:12]:
            log(f"    {row.get('severity', '?'):8} {row.get('attack_class', '?'):22} "
                f"{row.get('title', '')[:58]}")
        if len(rows) > 12:
            log(f"    … and {len(rows) - 12} more")

        log("\n  What to do with these:")
        log("    websec explain <attack-class>     what a class means and how to confirm it")
        log("    websec run ./your-project         the same pass against your own code")
        log("    websec run ./your-project --scan  add any scanners you have installed")
        log("\n  Severity, analyzer confidence and calibrated probability are separate signals.")
        log("  A finding is a lead to verify, not a confirmed vulnerability.")
        log("\n  `websec run` also writes AGENT-BRIEFING.md — the marching orders an agent"
            "\n  reads — plus the ledger, coverage record and SARIF. This summary is the"
            "\n  short version of the findings half.")
        return 0
    finally:
        shutil.rmtree(temp, ignore_errors=True)
