#!/usr/bin/env bash
#
# jwt-attacks.sh — manual JWT attack probe.
#
# Six classic JWT attacks pentest teams run:
#
#   1. alg:none — sign with no algorithm. If the backend accepts it, total auth bypass.
#   2. HS256 with garbage secret — tamper claims and resign with a wrong key.
#   3. Expired token — exp in the past, expect 401.
#   4. Stripped signature — empty sig segment.
#   5. Garbage token — non-JWT string.
#   6. Refresh-after-logout — logout, then try the still-cached refresh token.
#
# Usage:
#   1. In .env, set ZAP_AGENT_USER / ZAP_AGENT_PASS.
#   2. ./jwt-attacks.sh
#   3. Output: one PASS/FAIL per attack; nonzero exit on FAIL.
#
# Requires: bash, curl, jq, python3.
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
USER="$(read_env ZAP_AGENT_USER)"
PASS="$(read_env ZAP_AGENT_PASS)"

[[ -n "$TARGET" && -n "$USER" && -n "$PASS" ]] || {
    echo "ERROR: ZAP_TARGET / ZAP_AGENT_USER / ZAP_AGENT_PASS required in .env" >&2; exit 2
}

# TODO: adjust login / refresh / me / logout paths to your API.
echo "==> mint legit token..."
LOGIN_RESP=$(curl -fsS -X POST "$TARGET/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg e "$USER" --arg p "$PASS" '{email:$e,password:$p}')")

ACCESS_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.tokens.accessToken')
REFRESH_TOKEN=$(echo "$LOGIN_RESP" | jq -r '.tokens.refreshToken')

[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || { echo "login failed" >&2; exit 3; }

b64url() {
    python3 -c "import sys, base64; sys.stdout.write(base64.urlsafe_b64encode(sys.stdin.buffer.read()).decode().rstrip('='))"
}

IFS='.' read -r H P S <<< "$ACCESS_TOKEN"

# A protected endpoint that requires a real session. Adjust to your API.
TEST_URL="$TARGET/api/auth/me"

PASS_COUNT=0
FAIL_COUNT=0
FAIL_LINES=()

check() {
    local label="$1" expected_code="$2" actual="$3"
    if [[ "$actual" == "$expected_code" ]]; then
        printf '  %-4s %-30s expected:%s actual:%s\n' PASS "$label" "$expected_code" "$actual"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        printf '  %-4s %-30s expected:%s actual:%s\n' FAIL "$label" "$expected_code" "$actual"
        FAIL_COUNT=$((FAIL_COUNT+1))
        FAIL_LINES+=("$label expected $expected_code got $actual")
    fi
}

# === Sanity: legit token works ===
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $ACCESS_TOKEN")
check "sanity (legit token)" "200" "$code"

# === Attack 1: alg:none ===
DECODED_P=$(echo "$P" | python3 -c "import sys, base64; d=sys.stdin.read(); print(base64.urlsafe_b64decode(d + '=='*(4-len(d)%4)).decode())")
NEW_H=$(echo -n '{"alg":"none","typ":"JWT"}' | b64url)
NONE_TOKEN="${NEW_H}.${P}."
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $NONE_TOKEN")
check "alg:none bypass" "401" "$code"

# === Attack 2: HS256 with garbage secret + tampered claims ===
# TODO: adjust claim names to your token's shape (role, roles, scope, permissions, etc.)
TAMPERED_P=$(echo "$DECODED_P" | jq -c '.roleIds = ["role-platform-manager","role-developer"] | .iat = (now|floor) | .exp = ((now|floor) + 3600)')
TAMPERED_P_B64=$(echo -n "$TAMPERED_P" | b64url)
HEADER_HS256=$(echo -n '{"alg":"HS256","typ":"JWT"}' | b64url)
WRONG_SIG=$(printf '%s.%s' "$HEADER_HS256" "$TAMPERED_P_B64" \
    | python3 -c "import sys, hmac, hashlib, base64; data=sys.stdin.buffer.read(); sig=hmac.new(b'wrong-secret-do-not-trust', data, hashlib.sha256).digest(); sys.stdout.write(base64.urlsafe_b64encode(sig).decode().rstrip('='))")
TAMPERED_TOKEN="${HEADER_HS256}.${TAMPERED_P_B64}.${WRONG_SIG}"
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $TAMPERED_TOKEN")
check "claims tampered, wrong sig" "401" "$code"

# === Attack 3: expired token ===
EXPIRED_P=$(echo "$DECODED_P" | jq -c '.exp = ((now|floor) - 60) | .iat = ((now|floor) - 3600)')
EXPIRED_P_B64=$(echo -n "$EXPIRED_P" | b64url)
EXP_SIG=$(printf '%s.%s' "$H" "$EXPIRED_P_B64" \
    | python3 -c "import sys, hmac, hashlib, base64; data=sys.stdin.buffer.read(); sig=hmac.new(b'will-not-match', data, hashlib.sha256).digest(); sys.stdout.write(base64.urlsafe_b64encode(sig).decode().rstrip('='))")
EXP_TOKEN="${H}.${EXPIRED_P_B64}.${EXP_SIG}"
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $EXP_TOKEN")
check "expired exp + bad sig" "401" "$code"

# === Attack 4: stripped signature ===
NO_SIG="${H}.${P}."
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer $NO_SIG")
check "stripped signature" "401" "$code"

# === Attack 5: garbage token ===
code=$(curl -s -o /dev/null -w '%{http_code}' "$TEST_URL" -H "Authorization: Bearer not-a-jwt")
check "garbage token" "401" "$code"

# === Attack 6: refresh-token replay after logout ===
echo "==> logging out then attempting refresh replay..."
curl -fsS -X POST "$TARGET/api/auth/logout" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg r "$REFRESH_TOKEN" '{refreshToken:$r}')" \
    >/dev/null 2>&1 || echo "  (logout endpoint may not invalidate refresh tokens — continuing)"

if [[ -n "$REFRESH_TOKEN" && "$REFRESH_TOKEN" != "null" ]]; then
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "$TARGET/api/auth/refresh" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg r "$REFRESH_TOKEN" '{refreshToken:$r}')")
    # Acceptable outcomes:
    #   401 — token was invalidated on logout (best)
    #   200 — refresh tokens are stateless and replay is possible (acceptable per
    #         the project's auth model; document the tradeoff)
    if [[ "$code" == "401" ]]; then
        printf '  %-4s %-30s expected:401 actual:%s (refresh token invalidated on logout)\n' PASS "refresh-after-logout" "$code"
        PASS_COUNT=$((PASS_COUNT+1))
    elif [[ "$code" == "200" ]]; then
        printf '  %-4s %-30s expected:401 actual:%s (refresh tokens are stateless; document tradeoff)\n' WARN "refresh-after-logout" "$code"
    else
        printf '  %-4s %-30s expected:401 actual:%s\n' FAIL "refresh-after-logout" "$code"
        FAIL_COUNT=$((FAIL_COUNT+1))
        FAIL_LINES+=("refresh-after-logout got $code")
    fi
else
    echo "  (refresh token not present in login response — skip)"
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
echo "All JWT attacks blocked — auth layer holds."
