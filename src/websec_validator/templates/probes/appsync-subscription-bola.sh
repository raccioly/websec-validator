#!/usr/bin/env bash
# appsync-subscription-bola.sh — broken subscription authorization / cross-group BOLA (REF-PENTEST
# #5). Open a subscription bound to ANOTHER tenant's groupId and see if the server streams events you
# must not receive. The pen test did exactly this with `onEvent(groupId)` from a low-priv user.
#
# Env: APPSYNC_URL, APPSYNC_API_KEY (or fold a real session into AUTH), VICTIM_GROUP_ID=<a group you
#      do NOT belong to>, SUB_FIELD=onEvent (the tenant-scoped field from graphql.subscription_authz).
set -uo pipefail
cd "$(dirname "$0")"
URL="${APPSYNC_URL:-FILL_ME}"; KEY="${APPSYNC_API_KEY:-}"; VG="${VICTIM_GROUP_ID:-FILL_ME}"; FIELD="${SUB_FIELD:-onEvent}"
if [ "${URL#FILL}" != "$URL" ] || [ "${VG#FILL}" != "$VG" ]; then
  echo "Set APPSYNC_URL, VICTIM_GROUP_ID (a group you must NOT be able to read), SUB_FIELD (default onEvent)"; exit 2
fi
python3 - "$URL" "$KEY" "$VG" "$FIELD" <<'PY'
import base64, json, sys
url, key, vg, field = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
host = url.split("//", 1)[1].split("/", 1)[0]
realtime = url.replace("appsync-api", "appsync-realtime-api").replace("https://", "wss://")
auth = {"host": host}
if key:
    auth["x-api-key"] = key
hdr = base64.b64encode(json.dumps(auth).encode()).decode()
ws_url = realtime + "?header=" + hdr + "&payload=e30="
query = "subscription($g:String!){ " + field + "(groupId:$g){ groupId } }"
start = {"id": "1", "type": "start",
         "payload": {"data": json.dumps({"query": query, "variables": {"groupId": vg}}),
                     "extensions": {"authorization": auth}}}
try:
    import websocket
except Exception:
    print("  (websocket-client not installed) — MANUAL REPRO:")
    print("  open " + ws_url + " (graphql-ws), connection_init, then 'start' with this payload:")
    print("    " + json.dumps(start))
    print("  If you get start_ack and then data for groupId=" + vg + " (which you do NOT own) -> cross-group BOLA (#5).")
    sys.exit(0)
try:
    ws = websocket.create_connection(ws_url, timeout=8, header=["Sec-WebSocket-Protocol: graphql-ws"])
    ws.send(json.dumps({"type": "connection_init"})); ws.recv()
    ws.send(json.dumps(start)); resp = ws.recv()
    if "start_ack" in resp or '"data"' in resp:
        print("  FAIL  subscription to foreign groupId=" + vg + " ACCEPTED (" + resp[:80] + ") -> cross-group BOLA (#5).")
        sys.exit(1)
    print("  ok    server rejected the foreign-group subscription: " + resp[:80]); sys.exit(0)
except Exception as e:
    print("  ?     error (may be a correct rejection): " + str(e)[:120]); sys.exit(0)
PY
