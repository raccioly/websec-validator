#!/usr/bin/env bash
# appsync-cswsh.sh — Cross-Site WebSocket Hijacking on the AppSync realtime endpoint (PTREQ0013000
# #4). The graphql-ws handshake must validate Origin; if it doesn't, a page on evil.com can open an
# authenticated socket. Opens the realtime WS with a FORGED Origin and checks for connection_ack.
#
# Env: APPSYNC_URL=https://<id>.appsync-api.<region>.amazonaws.com/graphql
#      APPSYNC_API_KEY=da2-...  (per the report the key is already disclosed in the client JS, so
#      this models the real attacker). TEST instance only.
set -uo pipefail
cd "$(dirname "$0")"
URL="${APPSYNC_URL:-FILL_ME}"; KEY="${APPSYNC_API_KEY:-FILL_ME}"
if [ "${URL#FILL}" != "$URL" ] || [ "${KEY#FILL}" != "$KEY" ]; then
  echo "Set APPSYNC_URL=https://<id>.appsync-api.<region>.amazonaws.com/graphql and APPSYNC_API_KEY=da2-..."; exit 2
fi
python3 - "$URL" "$KEY" <<'PY'
import base64, json, sys
url, key = sys.argv[1], sys.argv[2]
host = url.split("//", 1)[1].split("/", 1)[0]
realtime = url.replace("appsync-api", "appsync-realtime-api").replace("https://", "wss://")
hdr = base64.b64encode(json.dumps({"host": host, "x-api-key": key}).encode()).decode()
ws_url = realtime + "?header=" + hdr + "&payload=e30="
try:
    import websocket  # pip install websocket-client
except Exception:
    print("  (websocket-client not installed) — MANUAL REPRO:")
    print("  1) open this socket from a client that sets  Origin: http://evil.com")
    print("     " + ws_url)
    print("  2) send {\"type\":\"connection_init\"}; a {\"type\":\"connection_ack\"} back with a forged")
    print("     Origin means Origin is NOT validated -> CSWSH. Then run appsync-subscription-bola.sh.")
    sys.exit(0)
try:
    ws = websocket.create_connection(
        ws_url, timeout=8,
        header=["Sec-WebSocket-Protocol: graphql-ws", "Origin: http://evil.com"])
    ws.send(json.dumps({"type": "connection_init"}))
    ack = ws.recv()
    if "connection_ack" in ack:
        print("  FAIL  forged-Origin (evil.com) handshake ACCEPTED -> CSWSH (#4); Origin is not validated.")
        sys.exit(1)
    print("  ok    no connection_ack with a forged Origin: " + ack[:80]); sys.exit(0)
except Exception as e:
    print("  ?     handshake error (could be a correct Origin rejection, or wrong endpoint/auth): " + str(e)[:120])
    sys.exit(0)
PY
