#!/usr/bin/env bash
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
# jwt-attacks.sh — manual JWT attack probe (FACTS-driven; no app-specific login).
#
# Five classic JWT attacks, run against a protected endpoint with a token YOU supply:
#   1. alg:none — if accepted, total auth bypass.   2. tampered claims + wrong HS256 sig.
#   3. expired exp.   4. stripped signature.   5. garbage token.   (each should 401/403)
# Optional 6. refresh-replay-after-logout if you set REFRESH_TOKEN + the routes exist.
#
# Env (see _lib.py): TARGET, TOKEN_A=<a real JWT from a logged-in TEST account>.
# Optional: TEST_PATH=/api/some/protected/route (else picked from probe-context.json),
#           REFRESH_TOKEN, LOGOUT_PATH, REFRESH_PATH. Run only against a TEST instance.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json

TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port (or fill probe-context.json)"; exit 2; fi
: "${TOKEN_A:?set TOKEN_A=<a real JWT from a logged-in test account>}"
ACCESS_TOKEN="$TOKEN_A"
# a protected endpoint to fire forged tokens at (override with TEST_PATH)
TEST_PATH="${TEST_PATH:-$(python3 -c "import json;c=json.load(open('$ctx'))['endpoints'];print((c.get('idor_candidates') or c.get('writes') or ['/']).__getitem__(0).split(' ',1)[-1])" 2>/dev/null)}"
TEST_URL="$TARGET${TEST_PATH:-/}"

b64url() { python3 -c "import sys,base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))"; }
IFS='.' read -r H P S <<< "$ACCESS_TOKEN"
PASS_COUNT=0; FAIL_COUNT=0; FAIL_LINES=()
check() {
  if [ "$3" = "$2" ]; then printf '  PASS  %-28s expected:%s actual:%s\n' "$1" "$2" "$3"; PASS_COUNT=$((PASS_COUNT+1));
  else printf '  FAIL  %-28s expected:%s actual:%s\n' "$1" "$2" "$3"; FAIL_COUNT=$((FAIL_COUNT+1)); FAIL_LINES+=("$1 expected $2 got $3"); fi
}
echo "=== JWT attacks vs $TEST_URL ==="
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $ACCESS_TOKEN"); check "sanity (legit token)" "200" "$code"
DECODED_P=$(echo "$P" | python3 -c "import sys,base64; d=sys.stdin.read(); print(base64.urlsafe_b64decode(d+'=='*(4-len(d)%4)).decode())" 2>/dev/null || echo '{}')

NEW_H=$(printf '{"alg":"none","typ":"JWT"}' | b64url); code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer ${NEW_H}.${P}."); check "alg:none bypass" "401" "$code"
HS=$(printf '{"alg":"HS256","typ":"JWT"}' | b64url)
TP=$(printf '%s' "$DECODED_P" | python3 -c "import sys,json,time
try: d=json.loads(sys.stdin.read() or '{}')
except Exception: d={}
d['admin']=True; d['exp']=int(time.time())+3600
print(json.dumps(d))" 2>/dev/null || echo '{}')
TPB=$(printf '%s' "$TP" | b64url)
WSIG=$(printf '%s.%s' "$HS" "$TPB" | python3 -c "import sys,hmac,hashlib,base64; print(base64.urlsafe_b64encode(hmac.new(b'wrong-secret',sys.stdin.buffer.read(),hashlib.sha256).digest()).decode().rstrip('='))")
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer ${HS}.${TPB}.${WSIG}"); check "tampered claims + wrong sig" "401" "$code"
EP=$(echo "$DECODED_P" | python3 -c "import sys,json,time;
try: d=json.loads(sys.stdin.read())
except: d={}
d['exp']=int(time.time())-60; print(json.dumps(d))" 2>/dev/null || echo '{}')
EPB=$(printf '%s' "$EP" | b64url); code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer ${H}.${EPB}.${S}"); check "expired exp" "401" "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer ${H}.${P}."); check "stripped signature" "401" "$code"
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer not-a-jwt"); check "garbage token" "401" "$code"

if [ -n "${REFRESH_TOKEN:-}" ]; then
  curl -s -o /dev/null -X POST "$TARGET${LOGOUT_PATH:-/api/auth/logout}" -H "Authorization: Bearer $ACCESS_TOKEN" -H 'content-type: application/json' -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}" || true
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET${REFRESH_PATH:-/api/auth/refresh}" -H 'content-type: application/json' -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")
  [ "$code" = "401" ] && echo "  PASS  refresh-after-logout         (invalidated)" || echo "  WARN  refresh-after-logout actual:$code (stateless replay? document the tradeoff)"
fi

echo "=== Summary: PASS=$PASS_COUNT FAIL=$FAIL_COUNT ==="
[ "$FAIL_COUNT" -gt 0 ] && { printf '  - %s\n' "${FAIL_LINES[@]}"; exit 1; }
echo "All JWT attacks blocked — auth layer holds."
