#!/usr/bin/env bash
# error-disclosure-probe.sh — force the app to throw, then check the 500 body for a stack trace /
# internal file paths / dependency versions (REF-PENTEST #7). Sends malformed input (bad JSON,
# wrong types) to the write endpoints recon flagged, and greps the response for leak markers.
# Expect a generic message ("Internal Server Error") with NO stack frames.
#
# Env (see _lib.py): TARGET, optionally TOKEN_A=<jwt> / COOKIE_A. Run only against a TEST instance.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json

TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port (or fill probe-context.json)"; exit 2; fi
AUTH=()
[ -n "${TOKEN_A:-}" ] && AUTH=(-H "Authorization: Bearer $TOKEN_A")
[ -z "${TOKEN_A:-}" ] && [ -n "${COOKIE_A:-}" ] && AUTH=(-H "Cookie: $COOKIE_A")

# write endpoints are the best throw-targets (their validation/parse paths trip exceptions)
CANDS=()
while IFS= read -r line; do [ -n "$line" ] && CANDS+=("$line"); done < <(python3 -c "
import json
c = json.load(open('$ctx'))['endpoints']
for e in (c.get('writes', []) + c.get('reads', []))[:20]:
    print(e)
" 2>/dev/null)
[ "${#CANDS[@]}" -eq 0 ] && { echo 'No endpoints in probe-context.json.'; exit 0; }

# malformed payloads designed to trip unhandled exceptions
PAYLOADS=('{"x":' '{"id":{"$gt":""}}' '[]' '{"amount":"not-a-number","__proto__":{"x":1}}' 'not json at all')
# leak markers that should NEVER appear in a client-facing error body
MARKERS='at /|node_modules|Traceback \(most recent|File "|\.ts:[0-9]|\.js:[0-9]| line [0-9]|/Users/|/home/|/app/|webpack|TypeError:|ReferenceError:|Sequelize|PrismaClient|psql:|MongoError'

fails=0
for cand in "${CANDS[@]}"; do
  method="${cand%% *}"; path="${cand#* }"
  for body in "${PAYLOADS[@]}"; do
    resp=$(curl -s -m 8 -X "$method" "$TARGET$path" ${AUTH[@]+"${AUTH[@]}"} -H 'content-type: application/json' -d "$body" 2>&1 || true)
    if printf '%s' "$resp" | grep -qiE "$MARKERS"; then
      hit=$(printf '%s' "$resp" | grep -oiE "$MARKERS" | head -1)
      printf '  FAIL  %s %s  → leaks internals: %s\n' "$method" "$path" "$hit"; fails=$((fails+1)); break
    fi
  done
  [ "$fails" -eq 0 ] && printf '  ok    %s %s  generic error (no stack leaked)\n' "$method" "$path"
done
echo "summary: $fails endpoint(s) leaked a stack trace / internal path"
exit "$fails"
