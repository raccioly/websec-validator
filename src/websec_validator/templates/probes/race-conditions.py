#!/usr/bin/env python3
"""
Race condition probe — fires N parallel requests at race-prone endpoints
and checks if the server's invariants hold.

Common race targets:
  - "claim" / "assign" endpoints — only one parallel claim should succeed
  - status / state toggles — multiple parallel calls should converge
  - inventory / quota decrements — should not allow over-spend
  - tag/label-add endpoints — should dedupe

For each target:
  - Fire PARALLEL_REQUESTS in parallel
  - Count successes (200/201)
  - Compare to expected_unique (usually 1 — only one assignment should win)
  - If success_count > expected_unique -> race condition likely

Uses async httpx for true parallelism (synchronous loops can't trigger races).

Install: pip install httpx
"""
import asyncio, httpx, json, os, re, sys
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib  # noqa: E402

TARGET = _lib.base_url()
_lib.require("OBJ_A")                      # an object id you own (the single-winner target)
OBJ_A = os.environ["OBJ_A"]
_tok, _cookie = os.environ.get("TOKEN_A"), os.environ.get("COOKIE_A")
HEADERS = {"Authorization": f"Bearer {_tok}"} if _tok else ({"Cookie": _cookie} if _cookie else {})
if not HEADERS:
    sys.exit("Supply auth: TOKEN_A=<jwt> (or COOKIE_A). See _lib.py.")

PARALLEL = 50  # concurrent requests per target

# Race-prone targets = this app's mutating endpoints (from probe-context.json). For each, the
# server should keep its single-winner / converge / dedupe invariant under PARALLEL concurrency.
TARGETS = [{"name": f"{m} {p}", "method": m, "url": TARGET + re.sub(r"\{[^}]+\}", OBJ_A, p),
            "payload": {}, "expected_unique": 1,
            "note": "parallel fire — a single-winner/converge/dedupe invariant should hold"}
           for m, p in _lib.write_endpoints()][:8]
if not TARGETS:
    sys.exit("No write endpoints in probe-context.json — nothing to probe.")

async def fire(client, t):
    """Single request, return (status_code, response_body_preview)"""
    try:
        r = await client.request(
            t['method'], t['url'],
            json=t['payload'],
            headers=HEADERS,
            timeout=30.0,
        )
        return (r.status_code, r.text[:120])
    except Exception as e:
        return (None, str(e)[:120])

async def run_target(t):
    print(f"  Firing {PARALLEL} parallel {t['method']} to {t['url'][len(TARGET):]}")
    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[fire(client, t) for _ in range(PARALLEL)])
    codes = Counter(r[0] for r in results)
    success = sum(1 for r in results if r[0] and 200 <= r[0] < 300)
    race_likely = success > t['expected_unique']
    print(f"  -> status counts: {dict(codes)}, successes: {success}, expected: {t['expected_unique']}")
    if race_likely:
        print(f"    !! RACE CONDITION SUSPECTED -- {success} successes vs {t['expected_unique']} expected")
    return {
        'name': t['name'],
        'parallel': PARALLEL,
        'status_counts': dict(codes),
        'success_count': success,
        'expected_unique': t['expected_unique'],
        'race_suspected': race_likely,
        'note': t['note'],
        'sample_responses': [r for r in results if r[0] and r[0] < 500][:3],
    }

async def main():
    findings = []
    for t in TARGETS:
        print(f"\n=== {t['name']}: {t['note']}")
        f = await run_target(t)
        findings.append(f)
    out = _lib.save("race-conditions", findings)
    crit = sum(1 for f in findings if f['race_suspected'])
    print(f"\n=== Summary ===")
    print(f"  race suspected on {crit}/{len(findings)} endpoints")
    print(f"  saved to {out}")
    return crit

if __name__ == '__main__':
    rc = asyncio.run(main())
    sys.exit(1 if rc > 0 else 0)
