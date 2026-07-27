#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# websec-validator — DRAFT probe. Any example endpoints / auth / login below are
# PLACEHOLDERS from the template. THIS target's real surface — routes, auth scheme
# + token location, sensitive fields, tenant key — is in  ./probe-context.json
# (generated from FACTS.json for this app). Use those values before running; the
# agent should finalize this draft against probe-context.json, then fill secrets.
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
# rate-limit-burst — verify rate limiters actually fire, and that they can't be bypassed by
# spoofing X-Forwarded-For. FACTS-driven: reads the login route + base URL from
# ./probe-context.json (written by websec) — no separate .env needed.
#
# Three tests:
#   1. AUTH limiter — N+1 failed logins; expect a 429 by attempt N+1. (A limit of N ALLOWS N and
#      blocks the N+1th, so sending only N false-FAILs a working limiter — the classic off-by-one.)
#   2. General limiter — burst of GETs at a public endpoint; expect 429s once over the per-IP budget.
#   3. XFF bypass — once limited, rotate X-Forwarded-For between requests. If the limit lifts, the
#      backend keys on a client-controlled header without verifying the proxy chain (bypassable).
#
# Env: TARGET (or target_base_url in probe-context.json). Optional overrides:
#      AUTH_LIMIT (default 10), LOGIN_PATH, HEALTH_PATH.
# Usage:  TARGET=http://localhost:3000 bash rate-limit-burst.sh
set -uo pipefail
ctx="$(dirname "$0")/probe-context.json"
BASE="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${BASE:-}" ] || [ "${BASE#FILL}" != "$BASE" ]; then
  echo "Set TARGET=http://host:port (or fill target_base_url in probe-context.json)"; exit 2
fi
BASE="${BASE%/}"

# Login path: explicit override → the POST .../login from probe-context → a sane default.
LOGIN_PATH="${LOGIN_PATH:-$(python3 -c "
import json
c = json.load(open('$ctx'))
eps = c.get('auth', {}).get('login_endpoints', []) + c.get('endpoints', {}).get('auth_endpoints', [])
cand = [e.split(' ', 1)[1] for e in eps if e.upper().startswith('POST ') and 'login' in e.lower()]
print(cand[0] if cand else '/api/auth/login')
" 2>/dev/null)}"
LOGIN_PATH="${LOGIN_PATH:-/api/auth/login}"
HEALTH_PATH="${HEALTH_PATH:-/api/health}"
LIMIT="${AUTH_LIMIT:-10}"
N=$((LIMIT + 1))   # N+1: a limit of N allows N and blocks the (N+1)th

fails=0

echo "=== Test 1: AUTH limiter — $N failed logins at $LOGIN_PATH (expect a 429 by #$N) ==="
saw429=0
for i in $(seq 1 "$N"); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$LOGIN_PATH" \
         -H 'content-type: application/json' --data '{"email":"rl-test@example.com","password":"wrong"}' --max-time 15)
  printf '  attempt %2d → %s\n' "$i" "$code"
  [ "$code" = "429" ] && saw429=1
done
if [ "$saw429" = "1" ]; then
  echo "  PASS  AUTH limiter fired (saw 429)"
else
  echo "  FAIL  AUTH limiter never fired in $N attempts — misconfigured, or the limit is > $LIMIT (raise AUTH_LIMIT)"
  fails=$((fails+1))
fi
echo

echo "=== Test 2: general limiter — 200 GET $HEALTH_PATH in ~10s ==="
codes=$(seq 1 200 | xargs -n1 -P20 -I{} curl -s -o /dev/null -w '%{http_code}\n' "$BASE$HEALTH_PATH" --max-time 15)
n429=$(printf '%s\n' "$codes" | grep -c '^429$' || true)
n200=$(printf '%s\n' "$codes" | grep -c '^200$' || true)
echo "  200: $n200 · 429: $n429"
if [ "$n429" -gt 0 ]; then echo "  INFO  general limiter fires under burst"; else
  echo "  INFO  general limiter did not fire at 200 reqs — below threshold (raise for a real pentest)"; fi
echo

echo "=== Test 3: X-Forwarded-For spoof bypass ==="
for i in $(seq 1 "$N"); do
  curl -s -o /dev/null -X POST "$BASE$LOGIN_PATH" -H 'content-type: application/json' \
       --data '{"email":"xff-test@example.com","password":"wrong"}' --max-time 15 || true
done
baseline=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$LOGIN_PATH" \
           -H 'content-type: application/json' --data '{"email":"xff-test@example.com","password":"wrong"}' --max-time 15)
echo "  baseline (no XFF): $baseline"
spoofed=0
for xff in "1.2.3.4" "10.0.0.1" "192.168.1.99" "127.0.0.1" "1.1.1.1, 2.2.2.2"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$BASE$LOGIN_PATH" -H "X-Forwarded-For: $xff" \
         -H 'content-type: application/json' --data '{"email":"xff-test@example.com","password":"wrong"}' --max-time 15)
  printf '  XFF=%-22s → %s\n' "$xff" "$code"
  { [ "$baseline" = "429" ] && [ "$code" != "429" ]; } && spoofed=$((spoofed+1))
done
if [ "$baseline" != "429" ]; then
  echo "  SKIP  limiter not in 429 state for the baseline — can't test bypass (raise AUTH_LIMIT or the window)"
elif [ "$spoofed" -gt 0 ]; then
  echo "  FAIL  XFF spoof bypassed the limiter ($spoofed/5) — it keys on client-supplied XFF without verifying the proxy chain"
  fails=$((fails+1))
else
  echo "  PASS  XFF spoof did NOT bypass the limiter (all stayed 429)"
fi
echo
echo "=== summary: $fails failure(s) ==="
exit "$fails"
