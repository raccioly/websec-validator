#!/usr/bin/env python3
"""
Mass assignment / BOPLA (Broken Object Property Level Authorization) probe.

Tests the OWASP API #3 attack class: handler accepts user-supplied fields
that should be controlled by the server. Specifically targets:

  1. PATCH /api/users/{userId} (self-edit) — try to escalate own role/groups
  2. POST /api/admin/users (create) — try to create privileged user
  3. PUT /api/admin/users/{id} (update) — try to escalate someone via admin path
  4. PATCH /api/auth/me variants — try to add ownership / billing fields

Findings classification:
  CRITICAL: extra field was applied (role/group escalation succeeded)
  HIGH:     extra field was accepted (200) and persisted but didn't fully escalate
  PASS:     extra field was stripped (200 but field ignored) OR rejected (4xx)

Usage:
  python3 mass-assignment.py
  (reads tokens from ../../zap/.env)
"""
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2].parent  # repo root
sys.path.insert(0, str(ROOT))

# Read .env (relative to the zap/ folder where the .env lives)
ENV = {}
for line in (ROOT / 'security/zap/.env').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        k, v = line.split('=', 1)
        ENV[k.strip()] = v.strip()

TARGET = ENV['ZAP_TARGET']

# TODO: adjust login URL and response parsing to your API.
def login(user, pwd):
    r = subprocess.run(['curl', '-fsS', '-X', 'POST', f'{TARGET}/api/auth/login',
                        '-H', 'Content-Type: application/json',
                        '-d', json.dumps({'email': user, 'password': pwd})],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"login failed for {user}: {r.stderr}")
    return json.loads(r.stdout)['tokens']['accessToken']

def get_me(tok):
    r = subprocess.run(['curl', '-fsS', f'{TARGET}/api/auth/me',
                        '-H', f'Authorization: Bearer {tok}'],
                       capture_output=True, text=True)
    return json.loads(r.stdout).get('user', {})

print(f"=== minting tokens ===")
ADMIN_TOK = login(ENV['ZAP_ADMIN_USER'], ENV['ZAP_ADMIN_PASS'])
AGENT_TOK = login(ENV['ZAP_AGENT_USER'], ENV['ZAP_AGENT_PASS'])
AGENT_ME = get_me(AGENT_TOK)
print(f"  agent: {AGENT_ME.get('email')} (id={AGENT_ME.get('id')})")
# TODO: adjust field names to your role/tenancy shape.
print(f"  agent role: {AGENT_ME.get('role')} roleIds={AGENT_ME.get('roleIds')} groupIds={AGENT_ME.get('groupIds')}")

# === The dangerous extras we try to inject ===
# PROJECT-SPECIFIC START
# TODO: tailor these to your project's user-model fields. Common escalations:
#   - role / roles / roleIds / scope / permissions
#   - tenant / org / workspace / groupIds — "add to all tenants"
#   - isAdmin / isOwner / isSuperuser / accessLevel
#   - createdBy / ownedBy / billingAccount — audit-log spoofing
#   - id / passwordHash — direct identity overwrite
DANGER_FIELDS = {
    'role': 'admin',
    'roleIds': ['role-platform-manager'],
    'groupIds': ['*-all-tenants-*'],
    'isAdmin': True,
    'accessLevel': 999,
    'permissions': ['*'],
    'createdBy': 'admin-user',
    'passwordHash': 'fake-hash',
    'id': 'attacker-chosen-id',
    'status': 'admin',
    'internalNotes': 'pwned',
}
# PROJECT-SPECIFIC END

findings = []

def probe(label, method, path, base_body, tok, expected_field_changes=None):
    """Issue request with payload = base_body ∪ DANGER_FIELDS, then re-fetch /me to see if anything stuck."""
    body = {**(base_body or {}), **DANGER_FIELDS}
    r = subprocess.run(['curl', '-s', '-X', method, f'{TARGET}{path}',
                        '-H', f'Authorization: Bearer {tok}',
                        '-H', 'Content-Type: application/json',
                        '-d', json.dumps(body),
                        '-w', '\nHTTP_CODE:%{http_code}'],
                       capture_output=True, text=True)
    out = r.stdout
    code = int(out.split('HTTP_CODE:')[-1].strip()) if 'HTTP_CODE:' in out else 0
    body_text = out.split('\nHTTP_CODE:')[0]

    me_after = get_me(tok)

    escalations = {}
    for k, v in DANGER_FIELDS.items():
        before = AGENT_ME.get(k)
        after = me_after.get(k)
        if after != before and after == v:
            escalations[k] = {'before': before, 'after': after}

    if escalations:
        severity = 'CRITICAL'
    elif code in (200, 201, 204):
        severity = 'HIGH' if 'roleIds' in body_text or 'groupIds' in body_text else 'PASS'
    elif code in (400, 403, 422):
        severity = 'PASS'
    else:
        severity = 'INVESTIGATE'

    findings.append({
        'label': label, 'method': method, 'path': path, 'status': code,
        'severity': severity, 'escalations_observed': escalations,
        'response_preview': body_text[:200],
    })

    mark = '!!' if severity == 'CRITICAL' else ('??' if severity == 'INVESTIGATE' else ('-' if severity == 'HIGH' else 'OK'))
    print(f"  [{mark}] [{severity}] {method} {path} -> {code}")
    if escalations:
        for k, change in escalations.items():
            print(f"       FIELD STUCK: {k}  {change['before']!r} -> {change['after']!r}")

# PROJECT-SPECIFIC START
# TODO: each probe targets a real user-edit endpoint in your project. Replace
# the paths and base_body fields with the real shape your API expects.
print()
print("=== Probe 1: PATCH /api/users/{me} with extras (self-edit path) ===")
probe('self-edit-patch', 'PATCH', f"/api/users/{AGENT_ME['id']}", {'name': AGENT_ME.get('name', 'Test')}, AGENT_TOK)

print()
print("=== Probe 2: PUT /api/users/{me} with extras (self-edit alt verb) ===")
probe('self-edit-put', 'PUT', f"/api/users/{AGENT_ME['id']}", {'name': AGENT_ME.get('name', 'Test')}, AGENT_TOK)

print()
print("=== Probe 3: PATCH /api/auth/me with extras (auth-namespace self-edit) ===")
probe('auth-me-patch', 'PATCH', "/api/auth/me", {'name': AGENT_ME.get('name', 'Test')}, AGENT_TOK)

print()
print("=== Probe 4: PUT /api/users/me with extras (string 'me' resolution) ===")
probe('me-alias-put', 'PUT', "/api/users/me", {'name': AGENT_ME.get('name', 'Test')}, AGENT_TOK)

print()
print("=== Probe 5: as AGENT (no users:manage), call admin PUT — should 403 ===")
probe('admin-put-as-agent', 'PUT', f"/api/admin/users/{AGENT_ME['id']}", {'name': AGENT_ME.get('name', 'Test')}, AGENT_TOK)

print()
print("=== Probe 6: as AGENT, call admin POST create — should 403 ===")
probe('admin-create-as-agent', 'POST', "/api/admin/users", {'name': 'pwn', 'email': 'pwn@test.com', 'password': 'Pwn123!@', 'role': 'admin'}, AGENT_TOK)

print()
print("=== Probe 7: as ADMIN, PUT user with mass-assignment payload (does the schema reject extras?) ===")
admin_me = get_me(ADMIN_TOK)
probe('admin-put-agent', 'PUT', f"/api/admin/users/{AGENT_ME['id']}",
      {'name': AGENT_ME.get('name', 'Test')}, ADMIN_TOK)
# PROJECT-SPECIFIC END

# Save findings
out_path = ROOT / 'security/pentest-prep/reports/mass-assignment/findings.json'
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(findings, indent=2))

# Summary
crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
high = sum(1 for f in findings if f['severity'] == 'HIGH')
investig = sum(1 for f in findings if f['severity'] == 'INVESTIGATE')
ok = sum(1 for f in findings if f['severity'] == 'PASS')

print()
print(f"=== Summary ===")
print(f"  CRITICAL (escalation observed):  {crit}")
print(f"  HIGH (field accepted, suspect):  {high}")
print(f"  INVESTIGATE (unusual response):  {investig}")
print(f"  PASS (rejected or stripped):     {ok}")
print(f"  Detailed JSON: {out_path}")

# Cleanup: restore agent's roleIds + tenantIds if they were modified
me_after = get_me(AGENT_TOK)
needs_restore = False
for f in ['groupIds', 'roleIds']:  # TODO: update to your tenancy/role field names
    if me_after.get(f) != AGENT_ME.get(f):
        needs_restore = True
        print(f"  ! AGENT's {f} was MODIFIED. Before: {AGENT_ME.get(f)} After: {me_after.get(f)}")
if needs_restore:
    print()
    print(f"  ! Restoring agent profile to original state via admin token...")
    restore_body = {'roleIds': AGENT_ME.get('roleIds', []), 'groupIds': AGENT_ME.get('groupIds', [])}
    r = subprocess.run(['curl', '-s', '-X', 'PUT', f"{TARGET}/api/admin/users/{AGENT_ME['id']}",
                        '-H', f'Authorization: Bearer {ADMIN_TOK}',
                        '-H', 'Content-Type: application/json',
                        '-d', json.dumps(restore_body),
                        '-w', '\nHTTP_CODE:%{http_code}'],
                       capture_output=True, text=True)
    print(f"  restore status: {r.stdout.split('HTTP_CODE:')[-1].strip()}")

sys.exit(1 if crit > 0 else 0)
