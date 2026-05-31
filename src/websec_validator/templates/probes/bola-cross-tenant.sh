#!/usr/bin/env bash
#
# bola-cross-tenant.sh — manual BOLA / cross-tenant probe.
#
# ZAP's automated scanner can't tell when Agent A reading Agent B's tenant
# data is a violation — it just sees "another 200". This script does the
# two-account probe a pentest team will run on day 1:
#
#   1. Mint two agent tokens (Agent A in tenant_A, Agent B in tenant_B).
#   2. Discover each agent's accessible tenants via /api/auth/me (or your
#      project's equivalent "current user" endpoint).
#   3. For every tenant-scoped endpoint pattern, try Agent A's token against
#      Agent B's tenantId, and vice versa. Expect 403 or 404 (either prevents
#      the data leak).
#
# Usage:
#   1. In .env, set:
#         ZAP_AGENT_USER  / ZAP_AGENT_PASS   (Agent A in tenant X)
#         ZAP_AGENT2_USER / ZAP_AGENT2_PASS  (Agent B in tenant Y — DIFFERENT tenant)
#   2. ./bola-cross-tenant.sh
#   3. Output is one PASS/FAIL line per probe + a summary; nonzero exit on FAIL.
#
# Requires: bash, curl, jq, python3.
set -euo pipefail
cd "$(dirname "$0")"

[[ -f .env ]] || { echo "No .env found in $(pwd)" >&2; exit 1; }

# Parse .env literally (handles passwords with shell-special chars)
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
A_USER="$(read_env ZAP_AGENT_USER)"
A_PASS="$(read_env ZAP_AGENT_PASS)"
B_USER="$(read_env ZAP_AGENT2_USER)"
B_PASS="$(read_env ZAP_AGENT2_PASS)"

[[ -n "$TARGET" && -n "$A_USER" && -n "$A_PASS" && -n "$B_USER" && -n "$B_PASS" ]] || {
    cat >&2 <<EOF
ERROR: missing required .env values. Need:
  ZAP_TARGET, ZAP_AGENT_USER, ZAP_AGENT_PASS,
  ZAP_AGENT2_USER (the second agent in a DIFFERENT tenant), ZAP_AGENT2_PASS

The cross-tenant probe is moot if both agents are in the same tenant.
EOF
    exit 2
}

# TODO: adjust login URL / payload / response shape to match your API.
login() {
    local user="$1" pass="$2"
    local body
    body=$(jq -nc --arg e "$user" --arg p "$pass" '{email:$e,password:$p}')
    curl -fsS -X POST "$TARGET/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "$body" \
    | jq -r '.tokens.accessToken'
}

echo "==> minting Agent A token..."
A_TOKEN="$(login "$A_USER" "$A_PASS")"
[[ -n "$A_TOKEN" ]] || { echo "Agent A login failed" >&2; exit 3; }

echo "==> minting Agent B token..."
B_TOKEN="$(login "$B_USER" "$B_PASS")"
[[ -n "$B_TOKEN" ]] || { echo "Agent B login failed" >&2; exit 3; }

# TODO: adjust /api/auth/me to your project's "current user" endpoint.
# We need each agent's tenant-id list. Adjust the jq filter below to your shape.
fetch_me() {
    local token="$1"
    curl -fsS "$TARGET/api/auth/me" -H "Authorization: Bearer $token"
}

A_ME="$(fetch_me "$A_TOKEN")"
B_ME="$(fetch_me "$B_TOKEN")"

# TODO: this jq expects {user: {groupIds: [...]}} or {groupIds: [...]}.
# Change groupIds to whatever your tenancy field is (orgIds, workspaceIds, accountIds).
A_GROUPS=( $(echo "$A_ME" | jq -r '(.user.groupIds // .groupIds // []) | .[]') )
B_GROUPS=( $(echo "$B_ME" | jq -r '(.user.groupIds // .groupIds // []) | .[]') )

[[ ${#A_GROUPS[@]} -gt 0 ]] || { echo "Agent A has no tenant ids" >&2; exit 3; }
[[ ${#B_GROUPS[@]} -gt 0 ]] || { echo "Agent B has no tenant ids" >&2; exit 3; }

# Pick the first tenant each that the OTHER agent does NOT belong to
A_TARGET_GROUP=""
for g in "${A_GROUPS[@]}"; do
    if ! printf '%s\n' "${B_GROUPS[@]}" | grep -qx "$g"; then
        A_TARGET_GROUP="$g"; break
    fi
done
B_TARGET_GROUP=""
for g in "${B_GROUPS[@]}"; do
    if ! printf '%s\n' "${A_GROUPS[@]}" | grep -qx "$g"; then
        B_TARGET_GROUP="$g"; break
    fi
done

[[ -n "$A_TARGET_GROUP" && -n "$B_TARGET_GROUP" ]] || {
    echo "ERROR: Agent A and B share all tenants — cannot run a meaningful cross-tenant test." >&2
    echo "Agent A tenants: ${A_GROUPS[*]}" >&2
    echo "Agent B tenants: ${B_GROUPS[*]}" >&2
    echo "Move one agent into a different tenant via the admin UI, then re-run." >&2
    exit 3
}

echo "==> Agent A will try to access B's tenant: $B_TARGET_GROUP"
echo "==> Agent B will try to access A's tenant: $A_TARGET_GROUP"
echo

# PROJECT-SPECIFIC START
# Probe matrix: each is a (METHOD, PATH_TEMPLATE, EXPECTED_BLOCKED_CODES) tuple.
# {group} is substituted with the OTHER agent's tenant id. We accept 403 or 404
# (either prevents the leak). REPLACE these with your project's tenant-scoped
# endpoints. Look at backend routes for any path containing /:groupId or /:orgId.
PROBES=(
    "GET /api/groups/{group}/conversations 403|404"
    "GET /api/groups/{group}/users 403|404"
    "GET /api/groups/{group}/tags 403|404"
    "GET /api/groups/{group}/canned-responses 403|404"
    "POST /api/groups/{group}/tags 403|404"
    "GET /api/groups/{group} 403|404"
)
# PROJECT-SPECIFIC END

PASS=0
FAIL=0
FAIL_LINES=()

probe() {
    local label="$1" token="$2" method="$3" url="$4" allowed_codes="$5"
    local code
    if [[ "$method" == "GET" ]]; then
        code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' \
            -H "Authorization: Bearer $token" "$url")
    elif [[ "$method" == "POST" ]]; then
        code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X POST \
            -H "Authorization: Bearer $token" \
            -H 'Content-Type: application/json' \
            -d '{}' "$url")
    else
        code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -X "$method" \
            -H "Authorization: Bearer $token" "$url")
    fi
    if [[ "|$allowed_codes|" == *"|$code|"* ]]; then
        printf '  %-4s %-6s %-7s %s  expected:%s  actual:%s\n' "PASS" "$label" "$method" "$url" "$allowed_codes" "$code"
        PASS=$((PASS+1))
    else
        printf '  %-4s %-6s %-7s %s  expected:%s  actual:%s\n' "FAIL" "$label" "$method" "$url" "$allowed_codes" "$code"
        FAIL=$((FAIL+1))
        FAIL_LINES+=("$label $method $url got $code (expected $allowed_codes)")
    fi
}

echo "=== Agent A attacking Agent B's tenant ($B_TARGET_GROUP) ==="
for p in "${PROBES[@]}"; do
    method=$(echo "$p" | awk '{print $1}')
    path=$(echo "$p" | awk '{print $2}' | sed "s|{group}|$B_TARGET_GROUP|g")
    expected=$(echo "$p" | awk '{print $3}')
    probe "A→B" "$A_TOKEN" "$method" "$TARGET$path" "$expected"
done
echo
echo "=== Agent B attacking Agent A's tenant ($A_TARGET_GROUP) ==="
for p in "${PROBES[@]}"; do
    method=$(echo "$p" | awk '{print $1}')
    path=$(echo "$p" | awk '{print $2}' | sed "s|{group}|$A_TARGET_GROUP|g")
    expected=$(echo "$p" | awk '{print $3}')
    probe "B→A" "$B_TOKEN" "$method" "$TARGET$path" "$expected"
done

echo
echo "=== Summary ==="
echo "  PASS: $PASS"
echo "  FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
    echo
    echo "FAILED PROBES (these are real BOLA findings — investigate immediately):"
    printf '  - %s\n' "${FAIL_LINES[@]}"
    exit 1
fi
echo "All probes blocked — cross-tenant access control holds."
