#!/usr/bin/env python3
"""
Extended BOLA probe — covers PATCH, PUT, DELETE, POST verbs across
tenant-scoped endpoints. The shell `bola-cross-tenant.sh` only tests GET +
one POST; write verbs miss authz checks more often than GETs.

Strategy:
  - As Agent A (Tenant A), attempt every mutating verb against Agent B's
    real resources in Tenant B.
  - Expected: 403 or 404.
  - If 200/204: BOLA — log the finding (no auto-rollback; some mutations
    can't be cleanly reverted from a black-box position).

DELETE-against-real-resource is SKIPPED. Instead we test the auth gate by
sending DELETE to a fabricated UUID — expect 403 BEFORE the 404 lookup.
"""
import json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2].parent
fixture = json.loads((ROOT / 'security/pentest-prep/fixtures/test-context.json').read_text())
TARGET = fixture['target']

A = fixture['agent_a']
B = fixture['agent_b']

ENV = {}
for line in (ROOT / 'security/zap/.env').read_text().splitlines():
    if '=' in line and not line.lstrip().startswith('#'):
        k, v = line.split('=', 1); ENV[k.strip()] = v.strip()

# TODO: adjust login URL and response parsing to your API.
def login(u, p):
    r = subprocess.run(['curl','-fsS','-X','POST',f"{TARGET}/api/auth/login",
                        '-H','Content-Type: application/json',
                        '-d',json.dumps({'email':u,'password':p})],
                       capture_output=True, text=True)
    return json.loads(r.stdout)['tokens']['accessToken']

A_TOK = login(ENV['ZAP_AGENT_USER'], ENV['ZAP_AGENT_PASS'])
B_TOK = login(ENV['ZAP_AGENT2_USER'], ENV['ZAP_AGENT2_PASS'])

# Pick a real resource ID from B's tenant as the cross-tenant target (Agent A attacks)
B_CONV = B['conversation_ids'][0] if B['conversation_ids'] else None
B_GROUP = B['group_id']
A_CONV = A['conversation_ids'][0] if A['conversation_ids'] else None
A_GROUP = A['group_id']
FABRICATED_CONV = '00000000-0000-0000-0000-000000000000'

if not B_CONV:
    print("ERROR: agent_b has no resource ids in the fixture. Aborting.", file=sys.stderr)
    sys.exit(2)

findings = []

def probe(label, method, path_template, body=None, target_group=B_GROUP, target_conv=B_CONV, tok=A_TOK, fab=False):
    path = path_template.format(g=target_group, id=target_conv if not fab else FABRICATED_CONV)
    cmd = ['curl','-s','-X',method,f"{TARGET}{path}",'-H',f'Authorization: Bearer {tok}',
           '-w','\nHTTP_CODE:%{http_code}']
    if body is not None:
        cmd += ['-H','Content-Type: application/json','-d',json.dumps(body)]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout
    code = int(out.split('HTTP_CODE:')[-1].strip()) if 'HTTP_CODE:' in out else 0
    body_text = out.split('\nHTTP_CODE:')[0]
    if code in (403, 404):
        sev, mark = 'PASS', 'OK'
    elif code in (200, 201, 204):
        sev, mark = 'CRITICAL', '!!'
    else:
        sev, mark = 'INVESTIGATE', '??'
    finding = {'label': label, 'method': method, 'path': path, 'status': code,
               'severity': sev, 'response_preview': body_text[:150]}
    findings.append(finding)
    print(f"  [{mark}] [{sev:11s}] {method:6s} {path}  -> {code}")
    return code, body_text

print(f"=== Extended BOLA write-verb tests ===")
print(f"  Attacker (A): {A['email']}  tenant={A_GROUP}")
print(f"  Target (B):   {B['email']}  tenant={B_GROUP}  resource={B_CONV}")
print()

# PROJECT-SPECIFIC START
# TODO: replace the path templates with mutating endpoints from your project.
# Look at your routes for any path with /:groupId or /:tenantId + a mutating verb.

# 1. PATCH/PUT primary tenant resource
print("--- Resource mutation (B's resource, attempted as A) ---")
probe('patch-conv-as-A', 'PATCH', '/api/groups/{g}/conversations/{id}', {'status': 'CLOSED'})
probe('put-conv-as-A',   'PUT',   '/api/groups/{g}/conversations/{id}', {'status': 'CLOSED'})

# 2. Workflow actions (assign, snooze, status flip — whatever your project has)
print()
print("--- Workflow actions on B's resource as A ---")
probe('assign-as-A',   'POST', '/api/groups/{g}/conversations/{id}/assign',   {'agentId': A['email']})
probe('unassign-as-A', 'POST', '/api/groups/{g}/conversations/{id}/unassign', {})
probe('snooze-as-A',   'POST', '/api/groups/{g}/conversations/{id}/snooze',   {'snoozeUntil': '2026-12-31T00:00:00Z'})
probe('spam-as-A',     'POST', '/api/groups/{g}/conversations/{id}/spam',     {})

# 3. Sub-resource operations (tags, labels, attachments — adapt to your model)
print()
print("--- Sub-resource operations on B's resource ---")
probe('tag-add-as-A',  'POST',   '/api/groups/{g}/conversations/{id}/tags', {'tagId': 'some-tag-id'})
probe('tag-del-as-A',  'DELETE', '/api/groups/{g}/conversations/{id}/tags/fake-tag-id')

# 4. Tenant-level mutations (modify or delete the tenant itself)
print()
print("--- Tenant-level mutations (B's tenant as A) ---")
probe('grp-put-as-A', 'PUT',    '/api/admin/groups/{g}', {'name': 'pwn'}, target_conv='')
probe('grp-del-as-A', 'DELETE', '/api/admin/groups/{g}', target_conv='')

# 5. DELETE with fabricated UUID — auth gate only (no real deletion since target doesn't exist)
print()
print("--- DELETE auth-gate check (fabricated UUID, no mutation possible) ---")
probe('delete-conv-fab', 'DELETE', '/api/groups/{g}/conversations/{id}', fab=True)
# PROJECT-SPECIFIC END

# 6. Same probes as B against A (verify symmetry)
print()
print(f"=== Reverse direction: B attacks A's tenant ===")
print(f"  Attacker (B): {B['email']}")
print(f"  Target (A):   {A['email']}  tenant={A_GROUP}  resource={A_CONV}")
print()

if A_CONV:
    probe('B->A: patch-conv',   'PATCH', '/api/groups/{g}/conversations/{id}', {'status':'CLOSED'},
          target_group=A_GROUP, target_conv=A_CONV, tok=B_TOK)
    probe('B->A: assign',       'POST',  '/api/groups/{g}/conversations/{id}/assign', {'agentId': B['email']},
          target_group=A_GROUP, target_conv=A_CONV, tok=B_TOK)
    probe('B->A: snooze',       'POST',  '/api/groups/{g}/conversations/{id}/snooze', {'snoozeUntil':'2026-12-31T00:00:00Z'},
          target_group=A_GROUP, target_conv=A_CONV, tok=B_TOK)

# Save
out = ROOT / 'security/pentest-prep/reports/custom-bola/write-verb-findings.json'
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(findings, indent=2))

crit = sum(1 for f in findings if f['severity'] == 'CRITICAL')
inv = sum(1 for f in findings if f['severity'] == 'INVESTIGATE')
ok = sum(1 for f in findings if f['severity'] == 'PASS')
print()
print("=== Summary ===")
print(f"  CRITICAL (BOLA confirmed):  {crit}")
print(f"  INVESTIGATE (odd status):   {inv}")
print(f"  PASS (403/404):             {ok}")
print(f"  Saved to: {out}")
sys.exit(1 if crit > 0 else 0)
