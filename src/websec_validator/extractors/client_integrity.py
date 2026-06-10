"""Client-integrity / tamperable-display extractor — the man-in-the-browser (MITB) class.

This is the agent-wallet lesson, generalized. When an app renders a **security-critical value**
whose tampering redirects money — a wallet/receive address, a payment routing/account number, the
QR that encodes it — that on-screen value is rewritable by code running in the victim's own browser
(malware, a rogue extension, or a poisoned JS dependency in the app's own bundle). No web app can
make on-screen display cryptographically tamper-proof; that's an inherent limit of the platform
(it's why hardware wallets exist), accepted by Coinbase/MetaMask/banks alike.

So this is deliberately a **LOW-confidence, architectural** flag, not a deterministic vuln. It can't
prove tampering is possible; it checks whether the two controls that actually move the needle are
present — and says so honestly:

  Layer A (kill the SCALABLE vector): a strict Content-Security-Policy (`script-src 'self'` + a
           nonce, no `unsafe-inline` / `unsafe-eval`) so an injected / supply-chain script can't run.
  Layer B (anchor trust OFF the browser surface): an out-of-band verification path — emailed
           canonical address, a short safety code / fingerprint, a server-rendered identicon, an
           EIP-55 checksum — so a single-surface tamper is at least *detectable* by the user.

A sensitive-display app missing A and/or B gets a flag pointing at exactly those layers. This is
NOT a "your app is broken" claim — it's a "verify these compensating controls" lead for the agent.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

# A value whose on-screen tampering redirects funds (the gate — financial/address-class signal).
SENSITIVE_VALUE = re.compile(
    r"\b(?:wallet|receive|receiving|deposit|recipient|payout|beneficiary|payment|destination)[_-]?address\b"
    r"|\bwalletAddress\b|\btoAddress\b|\bpayTo\b|\brouting[_-]?number\b|\baccount[_-]?number\b|\biban\b"
    r"|\b0x[0-9a-fA-F]{40}\b|crypto.{0,12}address|blockchain.{0,12}address", re.I)
QR_SIGNAL = re.compile(r"\bqrcode\b|\bQRCode\b|react-qr|qrcode\.react|qr-code|toDataURL\(", re.I)
CLIPBOARD = re.compile(r"navigator\.clipboard|clipboard\.writeText|copyToClipboard|useCopyToClipboard|writeText\(")
CLIENT_MARKER = re.compile(r"['\"]use client['\"]|from\s+['\"]react|next/|\.tsx['\"]?|document\.|window\.")

# Layer A — strict CSP detection
CSP_PRESENT = re.compile(r"Content-Security-Policy|contentSecurityPolicy", re.I)
CSP_SCRIPT_SELF = re.compile(r"script-src[^;'\"]*'self'", re.I)
CSP_NONCE = re.compile(r"'nonce-|nonce-\$\{|\bstrict-dynamic\b", re.I)
CSP_UNSAFE = re.compile(r"'unsafe-(?:inline|eval)'", re.I)

# Layer B — out-of-band trust anchor detection
OOB_ANCHOR = re.compile(
    r"safety[_-]?code|safetyCode|fingerprint|identicon|blockie|jazzicon|emoji[_-]?code"
    r"|out[_-]of[_-]band|toChecksumAddress|getAddress\(|checksumAddress|\beip[_-]?55\b|verifyAddress"
    r"|address[_-]?verif|verif\w*[_-]?address|sendVerificationEmail|canonical[_-]?address", re.I)

# WebSocket / realtime auth model — the CSWSH determinant (PTREQ0013000 #4). CSWSH is only
# exploitable when the socket authenticates via an AMBIENT COOKIE the browser auto-attaches
# cross-origin. A token placed in the connection payload / subprotocol and stored origin-scoped is
# NOT exploitable (SOP blocks a cross-origin page from reading it). This lets us ANSWER a CSWSH
# scanner flag instead of guessing — the retest pushed back on exactly this and won.
WS_USAGE = re.compile(r"new\s+WebSocket\(|socket\.io|graphql-ws|subscriptions-transport-ws|appsync-realtime"
                      r"|\bwss?://", re.I)
WS_COOKIE_AUTH = re.compile(r"withCredentials\s*:\s*true|credentials\s*:\s*['\"]include['\"]"
                            r"|document\.cookie[\s\S]{0,80}?(?:socket|ws\b|websocket)", re.I)


class ClientIntegrityExtractor(Extractor):
    name = "client_integrity"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        sensitive, qr_files, clip_files = [], [], []
        csp_present = csp_self = csp_nonce = csp_unsafe = False
        oob = []
        ws_usage = ws_cookie = False
        for _p, rel, text in ctx.iter_code():
            if SENSITIVE_VALUE.search(text):
                if len(sensitive) < 30:
                    sensitive.append(rel)
            if QR_SIGNAL.search(text) and len(qr_files) < 30:
                qr_files.append(rel)
            if CLIPBOARD.search(text) and len(clip_files) < 30:
                clip_files.append(rel)
            if CSP_PRESENT.search(text):
                csp_present = True
                if CSP_SCRIPT_SELF.search(text):
                    csp_self = True
                if CSP_NONCE.search(text):
                    csp_nonce = True
                if CSP_UNSAFE.search(text):
                    csp_unsafe = True
            if OOB_ANCHOR.search(text) and len(oob) < 20:
                oob.append(rel)
            if WS_USAGE.search(text):
                ws_usage = True
            if WS_COOKIE_AUTH.search(text):
                ws_cookie = True

        # strict = a real `script-src 'self'` (+ a nonce / strict-dynamic) with NO unsafe-inline/eval
        strict_csp = bool(csp_present and csp_self and csp_nonce and not csp_unsafe)
        out_of_band = bool(oob)
        ws_cookie_auth = bool(ws_usage and ws_cookie)   # the CSWSH determinant (ambient-cookie WS auth)

        findings = []
        present = bool(sensitive)
        if present:
            shown = ", ".join(sorted(set(sensitive))[:5])
            if not strict_csp:
                why = ("no Content-Security-Policy found" if not csp_present
                       else "CSP allows 'unsafe-inline'/'unsafe-eval' in script-src" if csp_unsafe
                       else "CSP present but not a strict script-src 'self' + nonce policy")
                findings.append({
                    "severity": "MEDIUM", "confidence": "LOW", "attack_class": "tamperable-display",
                    "issue": "security-critical value rendered client-side without a strict CSP",
                    "detail": f"This app renders a fund-redirecting value ({shown}) but {why}. A poisoned "
                              "dependency or injected script (man-in-the-browser) can then rewrite the "
                              "displayed/copied address or swap the QR for EVERY user at once (the scalable "
                              "vector). Add Layer A: `script-src 'self'` + per-request nonce + `strict-dynamic`, "
                              "no unsafe-inline/eval, object-src 'none'. (Ship report-only first to avoid "
                              "breaking wallet SDKs, then enforce.)"})
            if not out_of_band:
                findings.append({
                    "severity": "LOW", "confidence": "LOW", "attack_class": "tamperable-display",
                    "issue": "no out-of-band trust anchor for the displayed address",
                    "detail": f"No second, browser-independent source of truth was found for {shown} "
                              "(emailed canonical address, a short safety code / fingerprint, a server-rendered "
                              "identicon, or an EIP-55 checksum). Without one, a single-surface tamper is "
                              "undetectable by the user. Add Layer B: anchor trust OFF the browser surface so "
                              "the user can cross-check. NOTE: on-screen display can never be made "
                              "cryptographically tamper-proof on the web — the goal is detectable, not "
                              "impossible (the limit that hardware wallets exist to solve)."})

        # CSWSH is ONLY real when the WS auth is an ambient cookie (PTREQ0013000 #4). This lets us
        # answer a CSWSH scanner flag instead of guessing — a bearer token in the payload is not it.
        if ws_cookie_auth:
            findings.append({
                "severity": "MEDIUM", "confidence": "LOW", "attack_class": "cswsh",
                "issue": "WebSocket authenticated via an ambient cookie (Cross-Site WebSocket Hijacking)",
                "detail": "A WebSocket/realtime connection appears to authenticate via a cookie "
                          "(withCredentials / credentials:'include'), which the browser auto-attaches "
                          "cross-origin — so a page on any origin can open an authenticated socket (CSWSH, #4). "
                          "Validate the Origin on the handshake, or move the credential into the connection "
                          "payload / subprotocol and store it origin-scoped (not a cookie). If WS auth is "
                          "already a token in the payload, CSWSH is NOT exploitable."})

        return {
            "sensitive_display": sorted(set(sensitive)),
            "websocket_auth": ("cookie (CSWSH-exposed — validate Origin)" if ws_cookie_auth
                               else "token-or-none (CSWSH not exploitable)" if ws_usage
                               else "no websocket detected"),
            "qr_generation": sorted(set(qr_files)),
            "clipboard_copy": sorted(set(clip_files)),
            "strict_csp": strict_csp,
            "csp_present": csp_present,
            "csp_has_unsafe": csp_unsafe,
            "out_of_band_anchor": out_of_band,
            "anchors_found": sorted(set(oob)),
            "findings": findings,
            "note": ("Renders fund-redirecting value(s) — review man-in-the-browser exposure: strict CSP (kill the "
                     "scalable vector) + an out-of-band anchor (make tamper detectable). This is the inherent "
                     "web-platform limit; treat as architectural, LOW-confidence." if present else
                     "No security-critical display values detected — MITB/tamperable-display class N/A."),
        }
