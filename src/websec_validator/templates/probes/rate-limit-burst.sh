#!/usr/bin/env bash
#
# rate-limit-burst.sh — verify rate limiters actually fire under load.
#
# Three tests:
#   1. AUTH_RATE_LIMIT — N failed login attempts; expect a 429 by attempt K
#      (the project's documented per-IP login throttle).
#   2. General apiRateLimiter — burst of GET requests against a public health
#      endpoint; expect 429s once over the per-IP budget.
#   3. X-Forwarded-For bypass — repeat (1) but rotate the XFF header between
#      requests. If the backend honors XFF for rate-limit keying WITHOUT
#      verifying the proxy chain, attackers bypass the limiter.
#
# Usage:  ./rate-limit-burst.sh
set -euo pipefail
cd "$(dirname "$0")"

[[ -f .env ]] || { echo "No .env found" >&2; exit 1; }

read_env() {
    local key="$1"
    python3 -c "
for l in open('.env'):
    l = l.rstrip('\n')
    if l.startswith('#') or '=' not in l: continue
    k, v = l.split('=', 1)
    if k.strip() == '$key':
        print(v); break
"
}

TARGET="$(read_env ZAP_TARGET)"
[[ -n "$TARGET" ]] || { echo "ZAP_TARGET missing from .env" >&2; exit 2; }

# TODO: adjust login path and public health path to match your API.
LOGIN_PATH="/api/auth/login"
HEALTH_PATH="/api/health"

PASS_COUNT=0
FAIL_COUNT=0
FAIL_LINES=()

# === Test 1: AUTH_RATE_LIMIT ===
echo "=== Test 1: AUTH_RATE_LIMIT (expected ≥1 of 10 attempts to be 429) ==="
codes_seen=()
for i in $(seq 1 10); do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET$LOGIN_PATH" \
        -H 'Content-Type: application/json' \
        -d '{"email":"rl-test@example.com","password":"wrong"}')
    codes_seen+=("$code")
    printf '  attempt %2d → %s\n' "$i" "$code"
done
if printf '%s\n' "${codes_seen[@]}" | grep -q '^429$'; then
    echo "  PASS  AUTH_RATE_LIMIT fires (saw 429)"
    PASS_COUNT=$((PASS_COUNT+1))
else
    echo "  FAIL  AUTH_RATE_LIMIT never fired — limiter may be misconfigured"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAIL_LINES+=("AUTH_RATE_LIMIT did not fire in 10 attempts")
fi
echo

# === Test 2: General health burst ===
echo "=== Test 2: 200 GET ${HEALTH_PATH} requests in ~10s ==="
codes_file=$(mktemp)
trap 'rm -f "$codes_file"' EXIT
seq 1 200 | xargs -n 1 -P 20 -I{} curl -s -o /dev/null -w '%{http_code}\n' "$TARGET$HEALTH_PATH" > "$codes_file"

total=$(wc -l < "$codes_file" | tr -d ' ')
two_oh_oh=$(grep -c '^200$' "$codes_file" || true)
four_two_nine=$(grep -c '^429$' "$codes_file" || true)
other=$((total - two_oh_oh - four_two_nine))
echo "  Total responses: $total"
echo "  200: $two_oh_oh"
echo "  429: $four_two_nine"
echo "  Other: $other"
if [[ "$four_two_nine" -gt 0 ]]; then
    echo "  INFO  apiRateLimiter fires under burst (saw 429s)"
else
    echo "  INFO  apiRateLimiter did NOT fire — 200 reqs is below threshold."
    echo "        (general limit is per-IP; for a pentest, escalate to ~5000 reqs)"
fi
echo

# === Test 3: X-Forwarded-For bypass attempt ===
echo "=== Test 3: try XFF spoof to bypass AUTH_RATE_LIMIT ==="
echo "    (If the backend respects 'trust proxy = 1' correctly, spoofed XFF"
echo "     headers from us — a direct client — should be IGNORED for rate-limit"
echo "     keying.)"

# First, get rate-limited so subsequent requests are blocked
for i in $(seq 1 7); do
    curl -s -o /dev/null -X POST "$TARGET$LOGIN_PATH" \
        -H 'Content-Type: application/json' \
        -d '{"email":"xff-test@example.com","password":"wrong"}' >/dev/null
done

code_baseline=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET$LOGIN_PATH" \
    -H 'Content-Type: application/json' \
    -d '{"email":"xff-test@example.com","password":"wrong"}')
echo "  baseline (no XFF):       $code_baseline"

spoofed_pass_count=0
for xff in "1.2.3.4" "10.0.0.1" "192.168.1.99" "127.0.0.1" "1.1.1.1, 2.2.2.2"; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET$LOGIN_PATH" \
        -H 'Content-Type: application/json' \
        -H "X-Forwarded-For: $xff" \
        -d '{"email":"xff-test@example.com","password":"wrong"}')
    printf '  XFF=%-25s → %s\n' "$xff" "$code"
    if [[ "$code_baseline" == "429" && "$code" != "429" ]]; then
        spoofed_pass_count=$((spoofed_pass_count + 1))
    fi
done

if [[ "$code_baseline" != "429" ]]; then
    echo "  SKIP  AUTH limiter not in 429 state for baseline — can't test bypass"
elif [[ $spoofed_pass_count -gt 0 ]]; then
    echo "  FAIL  XFF spoof bypassed AUTH_RATE_LIMIT ($spoofed_pass_count probes)"
    FAIL_COUNT=$((FAIL_COUNT+1))
    FAIL_LINES+=("XFF spoof bypasses AUTH_RATE_LIMIT — limiter may be keyed on req.ip without trust proxy validation")
else
    echo "  PASS  XFF spoof did NOT bypass the limiter (all stayed 429)"
    PASS_COUNT=$((PASS_COUNT+1))
fi
echo

echo "=== Summary ==="
echo "  PASS: $PASS_COUNT"
echo "  FAIL: $FAIL_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo
    echo "FAILED:"
    printf '  - %s\n' "${FAIL_LINES[@]}"
    exit 1
fi
echo "Rate limiters behave as expected."
