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
import asyncio, httpx, json, sys
from pathlib import Path
from collections import Counter

ROOT = Path(__file__).resolve().parents[2].parent
fixture = json.loads((ROOT / 'security/pentest-prep/fixtures/test-context.json').read_text())
ENV = {}
for line in (ROOT / 'security/zap/.env').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        k, v = line.split('=', 1); ENV[k.strip()] = v.strip()

TARGET = fixture['target']
A_GROUP = fixture['agent_a']['group_id']
A_CONV = fixture['agent_a']['conversation_ids'][0]
A_USER_ID = fixture['agent_a'].get('user_id', '<AGENT_A_USER_ID>')

import subprocess
def login(u, p):
    r = subprocess.run(['curl','-fsS','-X','POST',f"{TARGET}/api/auth/login",
                        '-H','Content-Type: application/json',
                        '-d',json.dumps({'email':u,'password':p})],
                       capture_output=True, text=True)
    return json.loads(r.stdout)['tokens']['accessToken']

AGENT_TOK = login(ENV['ZAP_AGENT_USER'], ENV['ZAP_AGENT_PASS'])

PARALLEL = 50  # number of concurrent requests per target

# PROJECT-SPECIFIC START
# TODO: replace these with the race-prone endpoints from your project.
# Common shapes:
#   - assign / claim: one winner expected
#   - state toggle (snooze, archive, status flip): converges to one state
#   - tag/label add: deduplicates
#   - inventory decrement, points spend, quota use: must not over-spend
TARGETS = [
    {
        'name': 'assign-resource',
        'method': 'POST',
        'url': f"{TARGET}/api/groups/{A_GROUP}/conversations/{A_CONV}/assign",
        'payload': {'agentId': A_USER_ID},
        'expected_unique': 1,
        'note': '50 parallel assigns to self -- should only one succeed (or all idempotent 200s if backend dedupes)',
    },
    {
        'name': 'snooze-resource',
        'method': 'POST',
        'url': f"{TARGET}/api/groups/{A_GROUP}/conversations/{A_CONV}/snooze",
        'payload': {'snoozeUntil': '2027-01-01T00:00:00Z'},
        'expected_unique': 1,
        'note': 'Toggle endpoint -- multiple parallel calls should converge to one state',
    },
    {
        'name': 'status-toggle',
        'method': 'PUT',
        'url': f"{TARGET}/api/users/me/status",
        'payload': {'status': 'online'},
        'expected_unique': 1,
        'note': 'User status update -- parallel calls should converge',
    },
    {
        'name': 'tag-add',
        'method': 'POST',
        'url': f"{TARGET}/api/groups/{A_GROUP}/conversations/{A_CONV}/tags",
        'payload': {'tagId': 'race-test-tag-xxxxxxxx'},
        'expected_unique': 1,
        'note': '50 parallel adds of same tag -- should only add once if dedupe works',
    },
]
# PROJECT-SPECIFIC END

async def fire(client, t):
    """Single request, return (status_code, response_body_preview)"""
    try:
        r = await client.request(
            t['method'], t['url'],
            json=t['payload'],
            headers={'Authorization': f'Bearer {AGENT_TOK}'},
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
    out = ROOT / 'security/pentest-prep/reports/race-conditions/findings.json'
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(findings, indent=2))
    crit = sum(1 for f in findings if f['race_suspected'])
    print(f"\n=== Summary ===")
    print(f"  race suspected on {crit}/{len(findings)} endpoints")
    print(f"  saved to {out}")
    return crit

if __name__ == '__main__':
    rc = asyncio.run(main())
    sys.exit(1 if rc > 0 else 0)
