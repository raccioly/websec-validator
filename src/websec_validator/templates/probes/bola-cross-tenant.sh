#!/usr/bin/env bash
# BOLA / cross-tenant READ probe — FACTS-driven. Role A uses its OWN token against
# tenant B's id (and B→A), on this app's tenant-scoped routes (from probe-context.json).
# Expect 401/403/404. A 200 that returns the OTHER tenant's data = cross-tenant BOLA
# (OWASP API #1) — the thing an automated scanner can't tell from "just another 200".
#
# Env: TARGET, TOKEN_A, TOKEN_B (two accounts in DIFFERENT tenants), GROUP_A, GROUP_B
# (each account's tenant/group id). Bearer auth; cookie users: swap the -H below.
# Run only against a TEST instance you're authorized to probe.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json

BASE="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${BASE:-}" ] || [ "${BASE#FILL}" != "$BASE" ]; then echo "Set TARGET=http://host:port (or fill probe-context.json)"; exit 2; fi
: "${TOKEN_A:?set TOKEN_A=<jwt for an account in tenant A>}"
: "${TOKEN_B:?set TOKEN_B=<jwt for an account in a DIFFERENT tenant>}"
: "${GROUP_A:?set GROUP_A=<tenant/group id of account A>}"
: "${GROUP_B:?set GROUP_B=<tenant/group id of account B>}"

mapfile -t PATHS < <(python3 -c "
import json
c = json.load(open('$ctx'))['endpoints']
cand = c.get('idor_candidates') or [w.split(' ',1)[1] for w in c.get('writes',[]) if ' ' in w]
for p in cand:
    print(p.split(' ',1)[1] if (' ' in p and p.split(' ',1)[0].isupper()) else p)
" 2>/dev/null)
[ "${#PATHS[@]}" -eq 0 ] && { echo "No tenant-scoped / IDOR-candidate routes in probe-context.json."; exit 2; }

pass=0; leak=0
attack() {  # $1=token $2=target-group-id $3=label
  for raw in "${PATHS[@]}"; do
    path=$(python3 -c "import re,sys; print(re.sub(r'\{[^}]+\}', sys.argv[1], sys.argv[2]))" "$2" "$raw")
    code=$(curl -s -o /dev/null -w '%{http_code}' -m 15 -H "Authorization: Bearer $1" "$BASE$path")
    case "$code" in
      401|403|404) printf '  ok    %s  %-4s %s\n' "$code" "$3" "$path"; pass=$((pass+1)) ;;
      200|206)     printf '  LEAK  %s  %-4s %s   ← returned data for the OTHER tenant? verify\n' "$code" "$3" "$path"; leak=$((leak+1)) ;;
      *)           printf '  ??    %s  %-4s %s\n' "$code" "$3" "$path" ;;
    esac
  done
}

echo "=== cross-tenant BOLA vs $BASE   (expect 401/403/404) ==="
echo "--- A → B's tenant ($GROUP_B) ---"; attack "$TOKEN_A" "$GROUP_B" "A→B"
echo "--- B → A's tenant ($GROUP_A) ---"; attack "$TOKEN_B" "$GROUP_A" "B→A"
echo "summary: $pass blocked · $leak potential leak(s)"
[ "$leak" -gt 0 ] && echo "A 200 means the route served the OTHER tenant's id — confirm it's actually their data (not empty / your own), then debate-verify before reporting."
exit "$leak"
