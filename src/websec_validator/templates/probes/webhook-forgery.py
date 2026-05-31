#!/usr/bin/env python3
"""
Webhook forgery probe — signature verification for inbound webhooks.

A correct webhook verifier uses:
  - crypto.timingSafeEqual (or HMAC compare_digest) — not raw == comparison
  - fail-closed — reject if ANY required header is missing or malformed
  - timestamp-age check — reject signatures older than ~5 minutes to prevent
    captured-and-replayed-later forgeries

This probe tests:
  1. No signature header               -> expect 401
  2. Invalid signature (random b64)    -> expect 401
  3. Garbage signature (non-b64)       -> expect 401
  4. Missing timestamp                 -> expect 401
  5. Far-future timestamp              -> expect 401 ideally (replay-window check)
  6. Far-past timestamp                -> same
  7. Truncated signature               -> expect 401
  8. Empty body                        -> expect 401
  9. Wrong content-type                -> expect 401
"""
import json, os, subprocess, time, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import _lib  # noqa: E402

TARGET = _lib.base_url()

# PROJECT-SPECIFIC START
# TODO: replace with your project's inbound-webhook path, signature header
# name, and timestamp header name. Examples:
#   Bird / MessageBird: /webhooks/messagebird, messagebird-signature, messagebird-timestamp
#   Stripe:             /webhooks/stripe,      Stripe-Signature  (combined ts+sig)
#   Twilio:             /webhooks/twilio,      X-Twilio-Signature
#   GitHub:             /webhooks/github,      X-Hub-Signature-256
#   Custom:             /webhooks/<provider>,  X-Signature, X-Timestamp
# set WEBHOOK_PATH / SIG_HEADER / TS_HEADER env vars, or edit these. probe-context.json
# lists this app's detected integrations/webhooks to pick the real path from.
WEBHOOK_PATH = os.environ.get("WEBHOOK_PATH", "/webhooks/<provider>")
SIG_HEADER = os.environ.get("SIG_HEADER", "x-signature")
TS_HEADER  = os.environ.get("TS_HEADER", "x-timestamp")

URL = f"{TARGET}{WEBHOOK_PATH}"

# TODO: realistic payload shape for your provider.
PAYLOAD = json.dumps({
    "event": "message.received",
    "type": "message",
    "channelId": "channel-id-xxx",
    "message": {
        "id": "fake-msg-id",
        "from": "+15551234567",
        "content": "hello from attacker",
    }
})
# PROJECT-SPECIFIC END

probes = [
    # (name, headers, body, expected_code, expected_reason)
    ('no-signature',           {},                                                                             PAYLOAD, 401, 'no sig'),
    ('invalid-signature-b64',  {SIG_HEADER: 'aW52YWxpZA=='},                                                   PAYLOAD, 401, 'bad sig'),
    ('garbage-signature',      {SIG_HEADER: 'not-base64-!'},                                                   PAYLOAD, 401, 'malformed sig'),
    ('missing-timestamp',      {SIG_HEADER: 'aW52YWxpZA=='},                                                   PAYLOAD, 401, 'no timestamp'),
    ('zero-timestamp',         {SIG_HEADER: 'aW52YWxpZA==', TS_HEADER: '0'},                                   PAYLOAD, 401, 'timestamp epoch 0'),
    ('far-future-timestamp',   {SIG_HEADER: 'aW52YWxpZA==', TS_HEADER: '4070908800'},                          PAYLOAD, 401, 'timestamp year 2099'),
    ('far-past-timestamp',     {SIG_HEADER: 'aW52YWxpZA==', TS_HEADER: '1000000000'},                          PAYLOAD, 401, 'timestamp year 2001'),
    ('truncated-signature',    {SIG_HEADER: 'a'},                                                              PAYLOAD, 401, 'too short'),
    ('empty-body',             {SIG_HEADER: 'aW52YWxpZA==', TS_HEADER: str(int(time.time()))},                 '',      401, 'empty body'),
    ('wrong-content-type',     {SIG_HEADER: 'aW52YWxpZA==', TS_HEADER: str(int(time.time())), 'Content-Type': 'text/plain'}, PAYLOAD, 401, 'wrong ct'),
]

findings = []
print(f"=== Webhook forgery probes against {URL} ===\n")

for name, headers, body, expected, reason in probes:
    cmd = ['curl', '-s', '-X', 'POST', URL, '-w', '\nHTTP_CODE:%{http_code}']
    for h, v in headers.items():
        cmd += ['-H', f'{h}: {v}']
    if 'Content-Type' not in headers:
        cmd += ['-H', 'Content-Type: application/json']
    cmd += ['-d', body]
    r = subprocess.run(cmd, capture_output=True, text=True)
    out = r.stdout
    code = int(out.split('HTTP_CODE:')[-1].strip()) if 'HTTP_CODE:' in out else 0
    body_text = out.split('\nHTTP_CODE:')[0]
    expected_ok = code == expected
    mark = 'OK' if expected_ok else '!!'
    sev = 'PASS' if expected_ok else 'FAIL'
    print(f"  [{mark}] [{sev}] {name:30s} expected={expected} actual={code} ({reason})")
    findings.append({
        'name': name, 'expected': expected, 'actual': code, 'pass': expected_ok,
        'body_preview': body_text[:120],
    })

out_p = _lib.save("webhook-forgery", findings)

passed = sum(1 for f in findings if f['pass'])
print(f"\n=== Summary ===")
print(f"  {passed}/{len(findings)} probes returned expected 401")
print(f"  Saved: {out_p}")

# Replay-window note
print()
print("=== Note on timestamp-age / replay window ===")
print("  Even if the HMAC is correct, captured webhooks should not replay forever.")
print("  Look in your handler for code like:")
print("    const age = Math.abs(Date.now()/1000 - parseInt(timestamp));")
print("    if (age > 300) return res.status(401).json({error:'webhook timestamp out of window'});")
print("  If that check is missing, log it as a finding (low severity, easy fix).")
