#!/usr/bin/env bash
# ⚠ DEFENSIVE CHECK — run only against a TEST instance you own/operate, with consent, using a license
#   key YOU purchased. Not for production or third-party targets. Never share/replay someone else's key.
#
# entitlement-abuse — confirms the two license-verification gaps the recon flagged
# (entitlement-revocation-bypass + missing-usage-cap) on a licensed / browser-extension backend:
#
#   1. SEAT / DEVICE CAP  (missing-usage-cap): replay ONE valid key from N distinct device ids to a
#      gated endpoint. If every call returns 200, there is no per-license device cap — one shared key
#      works from unlimited devices. (Automated below.)
#
#   2. REVOCATION  (entitlement-revocation-bypass): buy → confirm the key works → refund/chargeback it
#      in the provider (Gumroad/Stripe/Paddle) → call again. Still 200 ⇒ the server trusts
#      success:true and never inspects the refunded/chargebacked/disputed state. (Manual — a refund
#      can't be scripted; steps are printed at the end.)
#
# Reads the gated (write) endpoints from ./probe-context.json (written by websec).
# Usage:  TARGET=https://your-test.example  KEY=<your-valid-test-license>  bash entitlement-abuse.sh
#         [DEVICE_FIELD=visitorId]  [KEY_FIELD=licenseKey]  [SEATS=5]
set -uo pipefail

ctx="$(dirname "$0")/probe-context.json"
BASE="${TARGET:-$(python3 -c "import json;print(json.load(open('$ctx'))['target_base_url'])" 2>/dev/null)}"
KEY="${KEY:-}"
KEY_FIELD="${KEY_FIELD:-licenseKey}"
DEVICE_FIELD="${DEVICE_FIELD:-visitorId}"   # the per-device id the client already sends (see FACTS tenant keys)
SEATS="${SEATS:-5}"

if [ -z "${BASE:-}" ] || [ "${BASE#FILL}" != "$BASE" ]; then
  echo "Set TARGET=https://your-test-host (or fill target_base_url in probe-context.json)"; exit 2
fi
if [ -z "$KEY" ]; then
  echo "Set KEY=<a valid TEST license key you own> — this probe never fabricates credentials."; exit 2
fi

EPS=()
while IFS= read -r line; do [ -n "$line" ] && EPS+=("$line"); done < <(python3 -c "import json;[print(e) for e in json.load(open('$ctx'))['endpoints']['writes']]" 2>/dev/null)
if [ "${#EPS[@]}" -eq 0 ]; then
  echo "No gated endpoints in probe-context.json — add the license-gated 'METHOD /path' lines under endpoints.writes."; exit 2
fi

echo "entitlement seat/device-cap replay vs $BASE   (one key, $SEATS distinct devices; a cap SHOULD block extras)"
echo "-----------------------------------------------------------------------------------------------------------"
for ep in "${EPS[@]}"; do
  method="${ep%% *}"; path="${ep#* }"
  ok=0; blocked=0
  for i in $(seq 1 "$SEATS"); do
    dev="probe-device-$(printf '%032x' "$i")"
    code=$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path" \
      -H "Content-Type: application/json" \
      -d "{\"$KEY_FIELD\":\"$KEY\",\"$DEVICE_FIELD\":\"$dev\"}")
    if [ "$code" = "200" ]; then ok=$((ok+1)); else blocked=$((blocked+1)); fi
  done
  verdict="NO-CAP (all $ok/$SEATS devices accepted — one key works everywhere)"
  [ "$blocked" -gt 0 ] && verdict="capped-after $ok (extras got a non-200 — a seat/device cap appears present)"
  printf '  %-6s %-40s %s\n' "$method" "$path" "$verdict"
done

cat <<'EOF'

manual revocation check (entitlement-revocation-bypass) — a refund can't be scripted:
  1. With KEY confirmed working above, refund/chargeback it in the provider dashboard.
  2. Re-run ONE call from the block above.
     • still 200  → CONFIRMED: server trusts success:true, never checks refunded/chargebacked/disputed.
     • now 403    → revocation is enforced (good).
Keep this probe in the repo; re-run after adding a seats table + a revocation check to prove it's fixed.
EOF
