#!/usr/bin/env bash
# upload-matrix.sh — unrestricted-upload + serve-side stored-XSS matrix (PTREQ0013000 #2b). For each
# upload endpoint: send a polyglot (valid image magic bytes + trailing script) named `.php`, a spoofed
# Content-Type (HTML body declared image/png), a double-extension, and a raw SVG — then FETCH THE
# STORED OBJECT BACK and assert it is served as octet-stream/attachment with `nosniff` (not rendered).
#
# Env (see _lib.py): TARGET, TOKEN_A=<jwt> (uploads usually need auth). TEST instance only.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json
TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port"; exit 2; fi
AUTH=(); [ -n "${TOKEN_A:-}" ] && AUTH=(-H "Authorization: Bearer $TOKEN_A")
UP="${UPLOAD_PATH:-$(python3 -c "import json;print((json.load(open('$ctx'))['endpoints'].get('upload_candidates') or ['FILL /api/upload'])[0].split()[-1])" 2>/dev/null)}"
FIELD="${UPLOAD_FIELD:-file}"
[ "${UP#FILL}" != "$UP" ] || { echo "Set UPLOAD_PATH=/api/.../media and UPLOAD_FIELD=file (recon found none)"; exit 0; }

tmp=$(mktemp -d)
printf '\x89PNG\r\n\x1a\n<?php system($_GET[0]); ?>' > "$tmp/poly.php"     # PNG magic + PHP
printf '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' > "$tmp/x.svg"
printf '<html><body><script>alert(1)</script></body></html>' > "$tmp/h.png"  # HTML declared png

fails=0
try() {  # name, file, content-type
  loc=$(curl -s -m 15 "$TARGET$UP" "${AUTH[@]}" -F "$FIELD=@$2;type=$3;filename=$1" -D - -o /dev/null 2>/dev/null | tr -d '\r')
  url=$(printf '%s' "$loc" | grep -iE '^(location|x-stored-url|url):' | awk '{print $2}' | head -1)
  printf '  upload %-10s ' "$1"
  if [ -z "$url" ]; then echo "(no stored URL in response headers — inspect manually / the body)"; return; fi
  hdr=$(curl -s -m 10 -D - -o /dev/null "$url" 2>/dev/null | tr -d '\r')
  cto=$(printf '%s' "$hdr" | grep -iE 'x-content-type-options' | head -1)
  ct=$(printf '%s' "$hdr"  | grep -iE '^content-type:' | head -1)
  cd=$(printf '%s' "$hdr"  | grep -iE '^content-disposition:' | head -1)
  if printf '%s' "$cto" | grep -qi nosniff && { printf '%s' "$ct" | grep -qi 'octet-stream' || printf '%s' "$cd" | grep -qi attachment; }; then
    echo "ok  served safe ($ct; nosniff)"
  else
    echo "FAIL served renderable ($ct; nosniff=${cto:-none}; disp=${cd:-none})"; fails=$((fails+1))
  fi
}
try "Jpg.php" "$tmp/poly.php" "image/png"
try "h.png"   "$tmp/h.png"    "image/png"
try "x.svg"   "$tmp/x.svg"    "image/svg+xml"
rm -rf "$tmp"
echo "summary: $fails stored object(s) served renderable (no nosniff/attachment) — stored-XSS risk"
exit "$fails"
