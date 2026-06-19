#!/usr/bin/env bash
# ⚠ DEFENSIVE CHECK — run only against a system you own/operate, with consent. Not for production or third-party targets.
# client-integrity-checklist.sh — man-in-the-browser posture for a page that displays a fund-
# redirecting value (wallet/receive address, QR, routing #). Auto-checks Layer A (strict CSP); prints
# the Layer B (out-of-band anchor) checklist for the human. Honest limit: on-screen display can't be
# made tamper-proof on the web — the goal is DETECTABLE tampering, not impossible.
set -uo pipefail
cd "$(dirname "$0")"
ctx=probe-context.json
TARGET="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
PAGE="${PAGE:-/receive}"   # the page that renders the address
if [ -z "${TARGET:-}" ] || [ "${TARGET#FILL}" != "$TARGET" ]; then echo "Set TARGET=http://host:port (PAGE=/receive)"; exit 2; fi

hdrs=$(curl -s -m 8 -D - -o /dev/null "$TARGET$PAGE" 2>&1 || true)
csp=$(printf '%s' "$hdrs" | grep -i '^content-security-policy:' | head -1)
echo "== Layer A — strict CSP (kills the scalable supply-chain / injected-script vector) =="
fails=0
if [ -z "$csp" ]; then
  echo "  FAIL  no Content-Security-Policy header on $PAGE"; fails=$((fails+1))
else
  printf '  CSP: %s\n' "$(printf '%s' "$csp" | head -c 240)"
  printf '%s' "$csp" | grep -qiE "script-src[^;]*'self'" || { echo "  FAIL  script-src is not 'self'"; fails=$((fails+1)); }
  printf '%s' "$csp" | grep -qiE "'nonce-|strict-dynamic" || echo "  WARN  no nonce / strict-dynamic in script-src"
  if printf '%s' "$csp" | grep -qiE "'unsafe-(inline|eval)'"; then
    echo "  FAIL  script-src allows unsafe-inline/eval — injected script still runs"; fails=$((fails+1))
  fi
fi
echo
echo "== Layer B — out-of-band trust anchor (manual — verify with the human) =="
cat <<'EOF'
  [ ] A SECOND, browser-independent source of truth for the address?
      (emailed canonical address · short safety code/fingerprint · server-rendered identicon · EIP-55 checksum)
  [ ] Is the QR generated SERVER-SIDE from the session (not from a client value the page can rewrite)?
  [ ] Does "Copy" read a server-trusted JS value, not the rendered DOM text node?
  [ ] Is the same safety code shown in 2+ places (header + receive page) so a single-surface swap looks inconsistent?
  Residual (state plainly to security): a coherent MITB tamper of address+QR+code+identicon still wins
  against a user who never checks the out-of-band channel. That floor is inherent to the web platform
  (the reason hardware wallets exist) — document it; do not claim it is closed.
EOF
echo
echo "summary: $fails strict-CSP check(s) failed (Layer A). Layer B is the manual checklist above."
exit "$fails"
