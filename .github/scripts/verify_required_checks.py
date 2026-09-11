"""Assert every check named in required-checks.json is actually produced by this workflow run.

The failure this prevents is silent and permanent: branch protection requiring a check name that no
job emits leaves every PR parked on "Expected — waiting for status to be reported", forever, with
nothing red to point at. Renaming a job in ci.yml is enough to cause it.

Checking against the live jobs API rather than parsing the YAML means matrix expansion, `name:`
overrides and expression interpolation are all resolved by GitHub itself.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import gh  # noqa: E402

REPO = os.environ["REPO"]
RUN_ID = os.environ["RUN_ID"]
ROOT = pathlib.Path(__file__).resolve().parents[1]

required = set(json.loads((ROOT / "required-checks.json").read_text())["required"])
jobs = {j["name"] for j in gh.paged(f"/repos/{REPO}/actions/runs/{RUN_ID}/jobs")}

print("jobs emitted by this run:")
for j in sorted(jobs):
    print(f"  {j}")

missing = required - jobs
if missing:
    print()
    for m in sorted(missing):
        print(f"::error::required check {m!r} is in .github/required-checks.json but no job in this "
              f"run emits it. Branch protection would park every PR on it forever.")
    print("::error::Fix the job name in ci.yml or the entry in required-checks.json — they must agree.")
    raise SystemExit(1)

print(f"\nall {len(required)} required check name(s) are emitted by this run")
