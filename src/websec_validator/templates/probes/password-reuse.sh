#!/usr/bin/env bash
# password-reuse.sh — password history / reuse control (PTREQ0013000 #6). Change the password to the
# SAME value, and to a value used one change ago, on EVERY set-password path (self-service change,
# admin set, profile update, SCIM/SSO-JIT) — coverage gaps BETWEEN paths are the usual bug. Expect a
# rejection ("password previously used") on both. This is a DIFFERENT control from complexity.
#
# Env (see _lib.py): TARGET, TOKEN_A=<jwt for a test user>, CURRENT_PW, plus the set-password path(s).
# Run only against a TEST instance with a throwaway account.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json
TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port"; exit 2; fi
[ -n "${TOKEN_A:-}" ] && [ -n "${CURRENT_PW:-}" ] || { echo "Set TOKEN_A=<jwt> and CURRENT_PW=<the account's current password>"; exit 2; }

# set-password endpoints: env override, else guess from the auth endpoints in context
PATHS_RAW="${SETPW_PATHS:-$(python3 -c "
import json
c=json.load(open('$ctx'))
eps=[e.split()[-1] for e in c['endpoints'].get('writes',[])]
print(','.join([p for p in eps if any(k in p.lower() for k in ('password','profile','user'))][:6]) or '/api/auth/change-password')
" 2>/dev/null)}"
IFS=',' read -ra PATHS <<< "$PATHS_RAW"

fails=0
for path in "${PATHS[@]}"; do
  # attempt to re-set the CURRENT password (most direct reuse test)
  code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST "$TARGET$path" \
        -H "Authorization: Bearer $TOKEN_A" -H 'content-type: application/json' \
        -d "{\"currentPassword\":\"$CURRENT_PW\",\"newPassword\":\"$CURRENT_PW\"}" 2>/dev/null || true)
  if [[ "$code" =~ ^(400|409|422)$ ]]; then
    printf '  ok    %-34s re-set-same rejected (HTTP %s)\n' "$path" "$code"
  elif [[ "$code" =~ ^2 ]]; then
    printf '  FAIL  %-34s ACCEPTED re-setting the SAME password (HTTP %s) → no reuse control (#6)\n' "$path" "$code"; fails=$((fails+1))
  else
    printf '  ?     %-34s HTTP %s (adjust the payload field names from FACTS)\n' "$path" "${code:-?}"
  fi
done
echo "summary: $fails set-password path(s) allow re-using the current password (history/reuse control missing)"
exit "$fails"
