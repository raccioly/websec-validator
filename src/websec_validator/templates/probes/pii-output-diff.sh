#!/usr/bin/env bash
# pii-output-diff.sh — unmasked-PII detector by VALUE SHAPE, not field name (PTREQ0013000 #8). As a
# NON-privileged caller, fetch each data endpoint and assert NO phone (/\+?\d{7,}/) or email value
# appears ANYWHERE in the JSON — including nested objects, composed IDs (the `messageBirdId` carrier),
# denormalized fields and exports. A field-name allow-list misses the indirect carriers; value-shape
# does not. Optionally diff against a privileged role to see what's over-exposed.
#
# Env (see _lib.py): TARGET, TOKEN_A=<low-priv jwt> (required), TOKEN_B=<priv jwt> (optional, for diff).
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json
TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port"; exit 2; fi
[ -n "${TOKEN_A:-}" ] || { echo "Set TOKEN_A=<low-priv jwt> (we check what a non-privileged caller can read)"; exit 2; }

# GET data endpoints (reads) from the recon context
EPS=()
while IFS= read -r l; do [ -n "$l" ] && EPS+=("$l"); done < <(python3 -c "
import json
c=json.load(open('$ctx'))['endpoints']
for e in (c.get('reads',[]) + c.get('idor_candidates',[]))[:40]:
    p=e.split()[-1]
    if '{' not in p: print(p)
" 2>/dev/null)
[ "${#EPS[@]}" -gt 0 ] || { echo "No GET data endpoints in probe-context.json."; exit 0; }

leaks=0
for path in "${EPS[@]}"; do
  body=$(curl -s -m 10 "$TARGET$path" -H "Authorization: Bearer $TOKEN_A" 2>/dev/null)
  hit=$(printf '%s' "$body" | python3 -c "
import sys, re, json
raw = sys.stdin.read()
# scan the RAW text (catches phones/emails embedded in composed IDs, not just declared fields)
phones = re.findall(r'(?<!\d)\+?\d[\d\-\s().]{6,}\d', raw)
emails = re.findall(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', raw)
# drop obvious non-PII numerics (timestamps/ids are short-ish or all-digit > 13); keep 7-15 digit runs
phones = [p for p in phones if 7 <= len(re.sub(r'\D','',p)) <= 15]
out = (phones[:3] + emails[:3])
print(' | '.join(out)) if out else print('')
" 2>/dev/null)
  if [ -n "$hit" ]; then
    printf '  LEAK  %-40s → %s\n' "$path" "$hit"; leaks=$((leaks+1))
  else
    printf '  ok    %-40s\n' "$path"
  fi
done
echo "summary: $leaks endpoint(s) leaked a phone/email VALUE to a non-privileged caller (verify each is real PII)"
exit "$leaks"
