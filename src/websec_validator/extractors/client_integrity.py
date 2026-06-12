"""Client-trust-boundary / tamperable-display extractor — the man-in-the-browser (MITB) class.

Generalized from the agent-wallet lesson: when an app renders a **security-critical sink value** —
ANY value the user ACTS ON by reading or copying, where a silent swap causes irreversible loss or
misdirection — that on-screen value is rewritable by code running in the victim's own browser
(malware, a rogue extension, a poisoned JS dependency in the app's own bundle). TLS protects the
wire, not the DOM.

The sink set is deliberately GENERIC and classified by BLAST RADIUS, not by app type — the pen-test
team's principle: detect by **data-flow role**, never by keyword/category. The same probe that finds
a swapped crypto address finds a swapped IBAN, a swapped 2FA seed, or a swapped webhook URL. The
keyword lists below are a STARTING SET, not the whole detector:
  - money-movement   : crypto/wallet address, IBAN/routing/account/SWIFT, payee/pay-to        → HIGH
  - credential       : 2FA/TOTP seed, recovery/mnemonic phrase, private/API/license key        → HIGH
  - config/integrity : webhook/callback URL, DNS record, invoice payment instructions          → MEDIUM
Severity tracks IRREVERSIBILITY; confidence stays LOW — this is an architectural "verify the
compensating controls" lead, never a "your app is broken" claim. No web app can make on-screen
display cryptographically tamper-proof; that's an inherent platform limit (it's why hardware wallets
exist), accepted by Coinbase/MetaMask/banks alike.

The two controls that actually move the needle:
  Layer A (kill the SCALABLE vector): a strict Content-Security-Policy (`script-src 'self'` + a
           nonce, no `unsafe-inline`/`unsafe-eval`) so an injected/supply-chain script can't run.
           (The framework-agnostic CSP/HSTS *baseline* audit lives in `transport_security.py`.)
  Layer B (anchor trust OFF the browser surface): an out-of-band verification path — emailed
           canonical value, a short safety code / fingerprint, a server-rendered identicon, an
           EIP-55 / IBAN checksum — so a single-surface tamper is at least *detectable*.

Also emitted here (same trust boundary):
  - weak-fingerprint  : a safety-code/fingerprint truncated to too few bits is grindable offline (#7).
  - overclaimed-control: code or UI copy asserting a CLIENT-SIDE check is "tamper-proof" / "MitB-proof"
    is a genuine finding — it makes teams overtrust a tripwire and under-invest in the real,
    out-of-band/server-side control (#8).
  - cswsh             : a WebSocket authenticated via an AMBIENT COOKIE (the CSWSH determinant).
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

# --- Security-critical sink values, classified by blast radius (severity ∝ irreversibility) ---
SINK_MONEY = re.compile(
    r"\b(?:wallet|receive|receiving|deposit|recipient|payout|beneficiary|payment|destination|payee)[_-]?address\b"
    r"|\bwalletAddress\b|\btoAddress\b|\bpayTo\b|\bpayee\b|\brouting[_-]?number\b|\baccount[_-]?number\b"
    r"|\biban\b|\bswift[_-]?code\b|\bsort[_-]?code\b|\b0x[0-9a-fA-F]{40}\b"
    r"|crypto.{0,12}address|blockchain.{0,12}address", re.I)
SINK_CREDENTIAL = re.compile(
    r"\b(?:totp|2fa|mfa|authenticator)[_-]?(?:seed|secret|key)\b|\botpauth://"
    r"|\b(?:recovery|seed|mnemonic)[_-]?phrase\b|\bmnemonic\b|\bprivate[_-]?key\b|\brecovery[_-]?code\b"
    r"|\b(?:api|license|licence|access)[_-]?key\b|\bclient[_-]?secret\b", re.I)
SINK_CONFIG = re.compile(
    r"\bwebhook[_-]?url\b|\bcallback[_-]?url\b|\bdns[_-]?record\b|\bnameserver\b|\bcname[_-]?record\b"
    r"|\binvoice[\s\S]{0,18}(?:account|iban|instructions|number)\b", re.I)

# --- Sink-role signals: the value is demonstrably SEEN/COPIED/LINKED (data-flow gate) ---
QR_SIGNAL = re.compile(r"\bqr[\s_-]?code\b|QRCode|react-qr|qrcode\.react|toDataURL\(", re.I)
CLIPBOARD = re.compile(r"navigator\.clipboard|clipboard\.writeText|copyToClipboard|useCopyToClipboard"
                       r"|writeText\(|execCommand\(\s*['\"]copy")
HREF_SINK = re.compile(r"href=\{|href=['\"](?:tel:|mailto:|bitcoin:|ethereum:|lightning:)"
                       r"|\b(?:to|toAddress|recipient|amount|payee)\s*=\s*\{")
# #2 — the sink value arrives over a client-side round-trip the browser (and a MitB) can intercept,
# rather than being server-rendered. A newly-added client fetch for a once-server-rendered value is a
# regression in itself (manufactures a tamper vector).
CLIENT_FETCH = re.compile(r"\bfetch\(|\baxios\b|useSWR\b|useQuery\b|useLazyQuery\b|\$\.(?:ajax|get|post)\b"
                          r"|XMLHttpRequest|\.get\(['\"]/(?:api|v\d)|graphql\b", re.I)

# Layer A — strict CSP detection (kept self-contained; transport_security.py owns the baseline audit)
CSP_PRESENT = re.compile(r"Content-Security-Policy|contentSecurityPolicy", re.I)
CSP_SCRIPT_SELF = re.compile(r"script-src[^;'\"]*'self'", re.I)
CSP_NONCE = re.compile(r"'nonce-|nonce-\$\{|\bstrict-dynamic\b", re.I)
CSP_UNSAFE = re.compile(r"'unsafe-(?:inline|eval)'", re.I)

# Layer B — out-of-band trust anchor detection
OOB_ANCHOR = re.compile(
    r"safety[_-]?code|safetyCode|fingerprint|identicon|blockie|jazzicon|emoji[_-]?code"
    r"|out[_-]of[_-]band|toChecksumAddress|getAddress\(|checksumAddress|\beip[_-]?55\b|verifyAddress"
    r"|address[_-]?verif|verif\w*[_-]?address|sendVerificationEmail|canonical[_-]?address|mod[_-]?97", re.I)

# #7 — a fingerprint / safety-code derived from a TRUNCATED hash is grindable offline. Flag a hash/HMAC
# sliced to a small char count (hex → 4 bits/char, so .slice(0,12) ≈ 48 bits < the 60-bit floor), or a
# *code variable sliced short. Heuristic robustness note, not a deterministic vuln.
WEAK_FINGERPRINT = re.compile(
    r"(?:sha256|sha1|sha512|md5|createHash|createHmac|\bhmac\b|digest)\b[\s\S]{0,90}?"
    r"\.(?:slice|substring|substr)\(\s*0\s*,\s*([1-9]|1[0-4])\b"
    r"|(?:safety|finger|verif|short|otp)[_-]?code\b[\s\S]{0,50}?\.(?:slice|substring|substr)\(\s*0\s*,\s*([1-9]|1[0-4])\b",
    re.I)
# #8 — dishonest control framing: a CLIENT-side check asserted to be unbeatable. Genuine finding.
OVERCLAIM = re.compile(
    r"tamper[\s_-]?proof|tamper[\s_-]?resistant|mitb[\s_-]?proof|man-in-the-browser[\s_-]?proof"
    r"|impossible to (?:tamper|forge|fake|modify|intercept)|cryptographically (?:guaranteed|proven|secure)"
    r"|can(?:'|no)?t be (?:tampered|forged|faked|modified|intercepted)|unhackable|100% (?:secure|safe)", re.I)

# WebSocket / realtime auth model — the CSWSH determinant (REF-PENTEST #4). CSWSH is only
# exploitable when the socket authenticates via an AMBIENT COOKIE the browser auto-attaches
# cross-origin. A token in the connection payload / subprotocol, stored origin-scoped, is NOT
# exploitable (SOP blocks a cross-origin page from reading it).
WS_USAGE = re.compile(r"new\s+WebSocket\(|socket\.io|graphql-ws|subscriptions-transport-ws|appsync-realtime"
                      r"|\bwss?://", re.I)
WS_COOKIE_AUTH = re.compile(r"withCredentials\s*:\s*true|credentials\s*:\s*['\"]include['\"]"
                            r"|document\.cookie[\s\S]{0,80}?(?:socket|ws\b|websocket)", re.I)


class ClientIntegrityExtractor(Extractor):
    name = "client_integrity"
    category = "exposure"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        sinks: dict[str, str] = {}          # rel -> blast radius (money|credential|config)
        qr_files, clip_files = [], []
        csp_present = csp_self = csp_nonce = csp_unsafe = False
        oob, weak_fp, overclaim, tamper_vectors = [], [], [], []
        ws_usage = ws_cookie = False
        for _p, rel, text in ctx.iter_code():
            has_copy = bool(CLIPBOARD.search(text) or QR_SIGNAL.search(text) or HREF_SINK.search(text))
            # genuine browser-DISPLAY surface: a frontend file by extension, an explicit client component,
            # or a known client-framework marker — NOT a backend service/repository that merely references
            # an `account`/`recipient` field (the real-repo FP: backend message processors, SDK models).
            client_file = (rel.lower().endswith((".tsx", ".jsx", ".vue", ".svelte", ".astro", ".html", ".hbs"))
                           or "use client" in text[:400] or "@Component(" in text
                           or "customElements.define" in text or "LitElement" in text)
            # money sinks are specific on a client surface; the broader credential/config set additionally
            # requires a copy/QR/href signal so a stray `apiKey` reference isn't noise.
            radius = None
            if client_file and SINK_MONEY.search(text):
                radius = "money"
            elif client_file and has_copy and SINK_CREDENTIAL.search(text):
                radius = "credential"
            elif client_file and has_copy and SINK_CONFIG.search(text):
                radius = "config"
            if radius:
                sinks.setdefault(rel, radius)
                if CLIENT_FETCH.search(text):   # #2 — sink fed by an interceptable client round-trip
                    tamper_vectors.append(rel)

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
            if client_file and WEAK_FINGERPRINT.search(text) and len(weak_fp) < 20:
                weak_fp.append(rel)   # client-side safety code only — a backend HMAC truncation is out of scope
            if client_file and OVERCLAIM.search(text) and len(overclaim) < 20:
                overclaim.append(rel)
            if WS_USAGE.search(text):
                ws_usage = True
            if WS_COOKIE_AUTH.search(text):
                ws_cookie = True

        # strict = a real `script-src 'self'` (+ a nonce / strict-dynamic) with NO unsafe-inline/eval
        strict_csp = bool(csp_present and csp_self and csp_nonce and not csp_unsafe)
        out_of_band = bool(oob)
        ws_cookie_auth = bool(ws_usage and ws_cookie)   # the CSWSH determinant (ambient-cookie WS auth)

        radii = set(sinks.values())
        present = bool(sinks)
        # severity tracks blast radius: a money/credential sink swap is irreversible → HIGH.
        high_blast = bool(radii & {"money", "credential"})
        sev_csp = "HIGH" if high_blast else "MEDIUM"
        sev_oob = "MEDIUM" if high_blast else "LOW"

        findings = []
        if present:
            shown = ", ".join(sorted(sinks)[:5])
            kinds = "/".join(sorted(radii))
            if not strict_csp:
                why = ("no Content-Security-Policy found" if not csp_present
                       else "CSP allows 'unsafe-inline'/'unsafe-eval' in script-src" if csp_unsafe
                       else "CSP present but not a strict script-src 'self' + nonce policy")
                findings.append({
                    "severity": sev_csp, "confidence": "LOW", "attack_class": "tamperable-display",
                    "file": sorted(sinks)[0],
                    "issue": "security-critical value rendered client-side without a strict CSP",
                    "detail": f"This app renders a {kinds}-class sink value the user reads/copies ({shown}) but "
                              f"{why}. A poisoned dependency or injected script (man-in-the-browser) can then "
                              "rewrite the displayed/copied value or swap the QR for EVERY user at once (the scalable "
                              "vector). Add Layer A: `script-src 'self'` + per-request nonce + `strict-dynamic`, no "
                              "unsafe-inline/eval, object-src 'none'. (Ship report-only first to avoid breaking SDKs, "
                              "then enforce.) Severity tracks irreversibility — a swapped money/credential value is "
                              "unrecoverable."})
            if not out_of_band:
                findings.append({
                    "severity": sev_oob, "confidence": "LOW", "attack_class": "tamperable-display",
                    "file": sorted(sinks)[0],
                    "issue": "no out-of-band trust anchor for the displayed security-critical value",
                    "detail": f"No second, browser-independent source of truth was found for {shown} "
                              "(emailed canonical value, a short safety code / fingerprint, a server-rendered "
                              "identicon, an EIP-55 / IBAN-mod-97 checksum). Without one, a single-surface tamper is "
                              "undetectable by the user. Add Layer B: anchor trust OFF the browser surface so the user "
                              "can cross-check. NOTE: on-screen display can never be made cryptographically "
                              "tamper-proof on the web — the goal is detectable, not impossible."})

        # #2 — sink value arrives via an interceptable client round-trip (server-render or sign it)
        if present and tamper_vectors:
            findings.append({
                "severity": sev_oob, "confidence": "LOW", "attack_class": "client-tamper-vector",
                "file": sorted(set(tamper_vectors))[0],
                "issue": "security-critical value populated by a client-side fetch (interceptable in the browser)",
                "detail": f"The sink value in {', '.join(sorted(set(tamper_vectors))[:4])} is populated by a client-side "
                          "fetch/XHR whose response the browser — and a man-in-the-browser — can intercept and rewrite, "
                          "rather than being server-rendered. Prefer server-render; if a round-trip is unavoidable, SIGN "
                          "the payload and verify integrity, don't trust raw response fields. A NEWLY-added client "
                          "round-trip for a once-server-rendered value is itself a regression."})

        # #7 — grindable fingerprint/safety-code (robustness note, only meaningful when a sink exists)
        if present and weak_fp:
            findings.append({
                "severity": "LOW", "confidence": "LOW", "attack_class": "weak-fingerprint",
                "file": sorted(set(weak_fp))[0],
                "issue": "safety-code / fingerprint derived from a truncated hash (grindable)",
                "detail": f"A fingerprint/safety-code in {', '.join(sorted(set(weak_fp))[:4])} is a hash/HMAC sliced "
                          "to a small character count. ~40-48 bits is brute-forceable on a commodity GPU in hours, so "
                          "an attacker can grind a tampered value that yields a MATCHING code. Target >=60 bits, kept "
                          "human-comparable (grouped base32, e.g. XXXX-XXXX-XXXX). Verify the slice length / encoding."})

        # #8 — over-claimed control framing (genuine finding: it manufactures misplaced trust)
        if overclaim:
            findings.append({
                "severity": "LOW", "confidence": "MEDIUM", "attack_class": "overclaimed-control",
                "file": sorted(set(overclaim))[0],
                "issue": "client-side check framed as tamper-proof / cryptographically guaranteed",
                "detail": f"Code or UI copy in {', '.join(sorted(set(overclaim))[:4])} asserts a CLIENT-SIDE control "
                          "is tamper-proof / MitB-proof / cryptographically guaranteed. On the web that claim is false "
                          "(the DOM is rewritable post-TLS) and it's a real finding: it makes teams and auditors "
                          "OVERTRUST a tripwire and under-invest in the actual out-of-band / server-side control. "
                          "Scope the claim honestly ('opportunistic tamper tripwire, not a guarantee') and ensure the "
                          "trust root is out-of-band or server-side."})

        # CSWSH is ONLY real when the WS auth is an ambient cookie (REF-PENTEST #4).
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
            "sensitive_display": sorted(sinks),
            "sink_blast_radius": dict(sorted(sinks.items())),
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
            "weak_fingerprints": sorted(set(weak_fp)),
            "overclaimed_controls": sorted(set(overclaim)),
            "client_fetch_sinks": sorted(set(tamper_vectors)),
            "findings": findings,
            "note": (f"Renders {'/'.join(sorted(radii))}-class security-critical value(s) — review man-in-the-browser "
                     "exposure: strict CSP (kill the scalable vector) + an out-of-band anchor (make tamper "
                     "detectable). Inherent web-platform limit; treat as architectural, LOW-confidence." if present else
                     "No security-critical display values detected — MITB/tamperable-display class N/A."),
        }
