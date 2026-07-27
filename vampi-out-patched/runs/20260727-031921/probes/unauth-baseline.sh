#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# websec-validator — DRAFT probe. Any example endpoints / auth / login below are
# PLACEHOLDERS from the template. THIS target's real surface — routes, auth scheme
# + token location, sensitive fields, tenant key — is in  ./probe-context.json
# (generated from FACTS.json for this app). Use those values before running; the
# agent should finalize this draft against probe-context.json, then fill secrets.
# ─────────────────────────────────────────────────────────────────────────────
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
# unauth-baseline — the cheapest, highest-value probe: hit every MUTATING route with
# NO credentials and expect 401/403. Any 2xx (or a non-401 that reached the handler)
# is a missing-authentication lead. Run this FIRST — it confirms the auth model before
# you spend effort on authorization/BOLA probes, and it catches both failure modes:
# a genuinely-open endpoint, AND an app whose auth fails OPEN in the test env (see below).
#
# Reads the target's real write routes from ./probe-context.json (written by websec).
# Usage:  TARGET=http://localhost:3000 bash unauth-baseline.sh
set -uo pipefail

ctx="$(dirname "$0")/probe-context.json"
BASE="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${BASE:-}" ] || [ "${BASE#FILL}" != "$BASE" ]; then
  echo "Set TARGET=http://host:port (or fill target_base_url in probe-context.json)"; exit 2
fi

EPS=()   # (portable; macOS bash 3.2 lacks `mapfile`)
while IFS= read -r line; do [ -n "$line" ] && EPS+=("$line"); done < <(python3 -c "import json;[print(e) for e in json.load(open('$ctx'))['endpoints']['writes']]" 2>/dev/null)
if [ "${#EPS[@]}" -eq 0 ]; then
  echo "No write endpoints in probe-context.json — add 'METHOD /path' lines under endpoints.writes."; exit 2
fi

echo "unauth baseline vs $BASE   (no credentials sent; each SHOULD be 401/403)"
echo "------------------------------------------------------------------------"
leads=0 ok=0
for ep in "${EPS[@]}"; do
  method="${ep%% *}"; path="${ep#* }"
  code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path" \
         -H 'content-type: application/json' --data '{}' --max-time 15)
  case "$code" in
    401|403) printf '  ok    %s  %s %s\n'   "$code" "$method" "$path"; ok=$((ok+1)) ;;
    000)     printf '  ????  conn-fail  %s %s (is the app running?)\n' "$method" "$path" ;;
    *)       printf '  LEAD  %s  %s %s   ← reached WITHOUT auth — verify\n' "$code" "$method" "$path"; leads=$((leads+1)) ;;
  esac
done
echo "------------------------------------------------------------------------"
echo "summary: $ok enforced (401/403) · $leads lead(s) reached without auth"
if [ "$ok" -eq 0 ] && [ "${#EPS[@]}" -gt 1 ]; then
  echo "⚠ EVERY route was reachable unauthenticated. Before concluding 'no auth', RULE OUT a"
  echo "  fail-OPEN test env: if the auth provider (Cognito/Auth0/etc.) isn't configured, the"
  echo "  middleware may be erroring through. Configure a valid/dummy provider (or mock a"
  echo "  session) and re-run — if these flip to 401, the app is fine and the env was the bug."
fi
exit "$leads"
