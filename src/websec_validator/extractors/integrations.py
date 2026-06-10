"""Integrations + webhooks extractor.

Inbound webhooks that don't verify a signature are a forgery/replay surface;
each outbound third-party SDK is a trust boundary + secret-handling surface.
Reads the route inventory to find webhook endpoints, then checks each handler
file for signature-verification code.
"""

from __future__ import annotations

import re
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

        blob = " ".join(ctx.text(p) for p in ctx.glob("**/package.json", 80)).lower()
        blob += " ".join(ctx.text(p) for p in (ctx.glob("**/requirements*.txt", 40) + ctx.glob("**/pyproject.toml", 40))).lower()
        detected = sorted({label for dep, label in SDKS.items() if dep.lower() in blob})

        return {
            "webhook_endpoints": [f"{e['method']} {e['path']}" for e in webhook_eps],
            "webhooks_without_sig_verification": sorted(set(unverified)),   # HIGH if non-empty
            "third_party_integrations": detected,
            "note": "Webhooks with no signature-verification code in their handler = forgery/replay risk "
                    "(run webhook-forgery; verify against your middleware). Each integration is an outbound "
                    "trust + secret-handling surface (SSRF, secret leakage, supply-chain).",
        }
