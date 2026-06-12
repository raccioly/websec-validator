"""Integrations + webhooks extractor.

Inbound webhooks that don't verify a signature are a forgery/replay surface;
each outbound third-party SDK is a trust boundary + secret-handling surface.
Reads the route inventory to find webhook endpoints, then checks each handler
file for signature-verification code.
"""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path

from .base import Extractor, RepoContext

WEBHOOK_PATH = re.compile(r"webhook|/hook|/callback|/inbound", re.I)
# Signals that a handler ACTUALLY verifies an inbound signature. The bare word `signature` used to
# be here and was over-broad: a comment like "no signature verification" — or any stray mention —
# SUPPRESSED the finding (a false negative, the worst failure for a security tool). Keep crypto
# primitives, known signature HEADER names (reading one implies verification intent), webhook
# libraries, and VERB-prefixed signature idioms (verify/check/validate/compute…Signature) — drop
# the standalone word. Erring toward MORE flagging is the safe direction; the human verifies.
SIG_VERIFY = re.compile(
    r"createHmac|\bhmac\b|timingSafeEqual|X-Hub-Signature|X-Signature|Stripe-Signature|"
    r"\bsvix\b|constant_time_compare|compare_digest|verifyWebhook|webhookSecret|"
    r"(?:verif|check|validate|assert|compute|expected|valid)\w*[_-]?[Ss]ignature", re.I)

SDKS = {"stripe": "Stripe", "twilio": "Twilio", "@sendgrid": "SendGrid", "messagebird": "MessageBird/Bird",
        "@slack": "Slack", "openai": "OpenAI", "@anthropic": "Anthropic", "octokit": "GitHub",
        "plaid": "Plaid", "@aws-sdk": "AWS", "aws-sdk": "AWS", "firebase": "Firebase",
        "mailgun": "Mailgun", "@sentry": "Sentry", "paypal": "PayPal", "squareup": "Square",
        "@google-cloud": "GCP", "appsync": "AppSync", "wpapi": "WordPress", "@wordpress": "WordPress"}

# --- #5 Abusable outbound-action endpoint: a handler that fires an outbound message (email/SMS/push)
# or an expensive action. Cloud/provider-agnostic. The risk is an UNAUTHENTICATED or weakly-limited
# costly/abusable action (spam, bill amplification, user harassment, account enumeration). Auth often
# lives in middleware, so this is a LOW-confidence "verify these controls" lead, not an assertion.
# A real outbound SEND CALL — a method invocation that actually sends a message — kept comms-specific so
# it does NOT collide with Express `res.send(` or an EventEmitter `.publish(`. (The earlier "references an
# SDK" match produced many FPs on a real-world app: it fired on config/types/repositories/tests.)
SEND_CALL = re.compile(
    r"\.sendMail\s*\(|\.sendEmail\s*\(|sgMail\.send\s*\(|transporter\.sendMail|resend\.emails\.send"
    r"|\.messages\.create\s*\(|client\.messages\.create|ses(?:v2|Client)?\.send(?:Email)?\s*\("
    r"|SendEmailCommand|SendRawEmailCommand|SendTemplatedEmailCommand|sns(?:Client)?\.publish\s*\(|PublishCommand"
    r"|\.sendSms\s*\(|\.send_sms\s*\(|mailgun[\s\S]{0,20}\.(?:messages|send)\s*\(|postmark[\s\S]{0,30}\.send", re.I)
# The file must look like a server REQUEST HANDLER / serverless function (where "no auth" is meaningful),
# not a library, model, repository, test, or client page.
HANDLER_CTX = re.compile(
    r"export default async (?:function\s+\w+\s*)?\(?\s*(?:req|request|event|ctx)\b|export (?:async )?function handler"
    r"|export const (?:POST|GET|PUT|DELETE|PATCH)\b|app\.(?:get|post|put|delete|patch)\s*\("
    r"|router\.(?:get|post|put|delete|patch|use)\s*\(|exports\.handler|def (?:handler|lambda_handler)\b"
    r"|@app\.(?:route|post|get)|@router\.|Deno\.serve|addEventListener\(\s*['\"]fetch", re.I)
HANDLER_DIR = re.compile(r"(?:^|/)(?:api|functions|handlers|routes|controllers)/|pages/api/|app/api/", re.I)
SKIP_ACTION_FILE = re.compile(
    r"\.(?:spec|test|stories|d)\.[tj]sx?$|/(?:e2e|__tests__|__mocks__|tests?|scripts?|capacity-test|k6|mocks?|fixtures?)/"
    r"|\.config\.[tj]s|(?:^|/)(?:config|types?|constants?)\.[tj]sx?$", re.I)
AUTH_GUARD = re.compile(r"requireAuth|getServerSession|getSession|isAuthenticated|@login_required|login_required"
                        r"|verifyToken|requireUser|ensureAuth|withAuth|req\.user|ctx\.user|request\.user"
                        r"|authMiddleware|passport\.|@authenticated|Depends\([^)]*[Aa]uth", re.I)
RATE_LIMIT = re.compile(r"rate[\s_-]?limit|rateLimit|express-rate-limit|\bthrottle|\bbottleneck\b|slowDown"
                        r"|\blimiter\b|RateLimiter|flask[_-]?limiter|slowapi|@ratelimit", re.I)
RATE_PER_PRINCIPAL = re.compile(r"keyGenerator[\s\S]{0,70}?(?:user|sub|principal|account|apiKey)"
                                r"|per[\s_-]?user|by[\s_-]?user|user\.id|userId|req\.user", re.I)
# --- #6 Redundant / non-centralized secret fetch: the SAME secret-manager key pulled more than once
# in one path widens the exposure window and signals bespoke loading. AWS/GCP/Azure/Vault.
SECRET_FETCH = re.compile(
    r"(?:getSecretValue|getSecret|accessSecretVersion|GetSecretValueCommand|getParameter|GetParameterCommand"
    r"|read_secret|kv\.get|getSecretString)\s*\(\s*\{?[^)]*?['\"]([^'\"]+)['\"]", re.I)


class IntegrationsExtractor(Extractor):
    name = "integrations"
    category = "surface"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        endpoints = (facts.get("routes") or {}).get("endpoints", [])
        webhook_eps = [e for e in endpoints if WEBHOOK_PATH.search(e.get("path", ""))]

        unverified = []
        for e in webhook_eps:
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            if not (text and SIG_VERIFY.search(text)):
                unverified.append(f"{e['method']} {e['path']}  ({ctx.rel(Path(cp)) if cp else '?'})")

        # #5 outbound-action endpoints + #6 redundant secret fetches (one shared code walk)
        findings = []
        for _p, rel, text in ctx.iter_code():
            if (SEND_CALL.search(text) and not SKIP_ACTION_FILE.search(rel)
                    and (HANDLER_CTX.search(text) or HANDLER_DIR.search(rel))):
                has_auth = bool(AUTH_GUARD.search(text))
                has_rl = bool(RATE_LIMIT.search(text))
                if not has_auth and not has_rl:
                    findings.append({"severity": "MEDIUM", "confidence": "LOW", "kind": "unguarded-outbound-action",
                                     "attack_class": "abusable-action-endpoint", "file": rel,
                                     "detail": f"{rel} fires an outbound message (email/SMS/push) with NO auth-guard and "
                                               "NO rate-limit signal in the handler — an abusable, often costly action "
                                               "(spam, bill amplification, harassment, account/enumeration). VERIFY auth "
                                               "isn't applied in middleware; then add auth + CSRF + rate limits on BOTH "
                                               "per-IP AND per-authenticated-principal (IP-only is bypassable)."})
                elif has_rl and not RATE_PER_PRINCIPAL.search(text):
                    findings.append({"severity": "LOW", "confidence": "LOW", "kind": "ip-only-rate-limit",
                                     "attack_class": "abusable-action-endpoint", "file": rel,
                                     "detail": f"{rel} sends outbound messages behind a rate-limiter with no visible "
                                               "per-principal key — if keyed on IP only it's bypassed via proxy pools / "
                                               "IPv6 rotation. Add a per-authenticated-principal limit dimension."})
            dup = sorted({k for k, n in Counter(i.strip() for i in SECRET_FETCH.findall(text)).items() if n >= 2})
            if dup:
                findings.append({"severity": "LOW", "confidence": "LOW", "kind": "redundant-secret-fetch",
                                 "attack_class": "redundant-secret-fetch", "file": rel,
                                 "detail": f"{rel} fetches the same secret-manager key more than once "
                                           f"({', '.join(dup[:3])}) — each fetch widens the exposure window and suggests "
                                           "non-centralized loading. Fetch once per request and reuse it via the "
                                           "project's secret-provider abstraction."})

        blob = " ".join(ctx.text(p) for p in ctx.glob("**/package.json", 80)).lower()
        blob += " ".join(ctx.text(p) for p in (ctx.glob("**/requirements*.txt", 40) + ctx.glob("**/pyproject.toml", 40))).lower()
        detected = sorted({label for dep, label in SDKS.items() if dep.lower() in blob})

        return {
            "webhook_endpoints": [f"{e['method']} {e['path']}" for e in webhook_eps],
            "webhooks_without_sig_verification": sorted(set(unverified)),   # HIGH if non-empty
            "third_party_integrations": detected,
            "findings": findings,   # #5 abusable-action-endpoint + #6 redundant-secret-fetch
            "note": "Webhooks with no signature-verification code in their handler = forgery/replay risk "
                    "(run webhook-forgery; verify against your middleware). Each integration is an outbound "
                    "trust + secret-handling surface (SSRF, secret leakage, supply-chain).",
        }
