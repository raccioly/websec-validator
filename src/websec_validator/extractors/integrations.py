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
# A STRONG webhook path (explicit /webhook(s) or a provider webhook route) is unambiguous — flag it on
# no-sig even without deep body-read evidence. A WEAK path (/callback, /inbound, /hook alone) overlaps
# with OAuth callbacks and misc handlers, so it additionally REQUIRES receiver evidence before flagging.
WEBHOOK_STRONG = re.compile(
    r"/webhooks?\b|/wh/|/hooks/|(?:stripe|github|gitlab|slack|shopify|twilio|sendgrid|paypal|square|"
    r"plaid|clerk|svix|mailgun|postmark|linear|calendly|lemonsqueezy|paddle)[-_/]?(?:hook|webhook|event)", re.I)
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

# A real inbound-webhook RECEIVER reads the raw body and/or dispatches on an event type or a provider
# signature header. Without this evidence a GET health-check, an OAuth authorization-code callback, or
# webhook-SUBSCRIPTION management CRUD sitting at a webhook-ish path (WEBHOOK_PATH includes /callback)
# is wrongly flagged unsigned — the dominant webhook-forgery FP across several real repos.
WEBHOOK_RECEIVER = re.compile(
    r"\brawBody\b|raw_body|req(?:uest)?\.body\b|await\s+req(?:uest)?\.(?:text|json|blob|buffer|arrayBuffer)\s*\("
    r"|bodyParser\.raw|express\.raw|request\.data\b|await\s+request\.body"
    r"|\bevent\.type\b|payload\.type|\.type\s*===|switch\s*\(\s*(?:event|payload|type|body)"
    r"|x-hub-signature|stripe-signature|x-signature|x-webhook-signature|x-slack-signature|x-line-signature|svix-id", re.I)
# An OAuth authorization-code callback — authenticated by state/PKCE, has no HMAC to verify → not a webhook.
OAUTH_CALLBACK = re.compile(
    r"searchParams\.get\s*\(\s*['\"](?:code|state)['\"]|\?code=|grant_type|authorization_code"
    r"|exchange\w*[Cc]ode|/oauth/|openid|passport\.authenticate|getToken\s*\(", re.I)
# Webhook-SUBSCRIPTION management CRUD (create/list/delete a subscription at a provider) — receives no
# signed event; an unsigned finding is wrong (if it's unguarded that's a missing-auth, handled elsewhere).
WEBHOOK_MGMT = re.compile(
    r"createWebhook|deleteWebhook|listWebhooks|updateWebhook|registerWebhook|pingWebhook|testWebhook|triggerWebhook|sendWebhook"
    r"|webhooks?\.(?:create|list|delete|update|ping|test|trigger|send)|['\"][^'\"]*/webhook[- ]?(?:subscriptions?|endpoints?|configs?)"
    r"|/webhooks?/[^'\"]*/(?:ping|test|trigger|send|retry)\b", re.I)
# a CALL to a signature-verification helper (its impl may live in another file) — verification intent.
VERIFY_HELPER_CALL = re.compile(
    r"\b(?:verify|validate|check|assert)\w*(?:Signature|Webhook|Hmac|Sig|Event)\s*\(|constructEvent\s*\(", re.I)

# --- License / subscription / payment providers called via a RAW fetch (not an npm SDK), so the
# SDK-name scan below misses them. Detected by API host so an entitlement check surfaces as a
# third-party trust boundary regardless of provider or naming. Add hosts freely — nothing here is
# specific to any one app. ---
VERIFY_PROVIDERS = {
    "api.gumroad.com": "Gumroad", "api.lemonsqueezy.com": "Lemon Squeezy",
    "api.paddle.com": "Paddle", "vendors.paddle.com": "Paddle", "checkout.paddle.com": "Paddle",
    "sandbox-api.paddle.com": "Paddle", "api.stripe.com": "Stripe", "api.keygen.sh": "Keygen",
    "api.paypal.com": "PayPal", "api-m.paypal.com": "PayPal", "api.chargebee.com": "Chargebee",
    "api.fastspring.com": "FastSpring", "api.polar.sh": "Polar", "api.creem.io": "Creem",
}
# A handler that checks a paid entitlement — a license OR a subscription. Broad on purpose (any
# provider, any naming); the findings below additionally require a truthy-grant tell.
ENTITLEMENT_VERIFY = re.compile(
    r"licen[sc]es?/(?:verify|validate|activate)|/v\d+/validate|verify_?licen[sc]e|verify_?key"
    r"|activate_?licen[sc]e|licen[sc]e_?key|\bentitlement|subscriptions?/|/customers?/"
    r"|checkout/sessions|has_?active_?subscription|is_?subscribed|verify_?subscription", re.I)
# The grant keys on a truthy success/valid/activated flag …
GRANT_ON_SUCCESS = re.compile(r"\.success\b|\.valid\b|\.activated\b|\.meta\.valid\b|['\"]valid['\"]\s*:", re.I)
# … but a SOUND check ALSO inspects revocation/validity state. PROVIDER-AGNOSTIC concept vocabulary
# (refund / chargeback / dispute / cancel / expire / revoke / suspend / a status compared to
# active|paid), matched as CODE — a property access, a quoted key/value, or a *_at/status field —
# never a bare prose word, so a comment ("no revocation check", "we still need refund handling") can't
# SUPPRESS the finding (the comment-suppression FN trap the SIG_VERIFY note above learned the hard
# way). This is intentionally not tied to any single provider's field spellings.
_REVOKE = (r"refunded|chargebacked|charged_back|disputed|revoked|revocation|suspended|voided"
           r"|cancell?ed|canceled|cancel_at_period_end|inactive|past_due|unpaid")
# NOTE: expiry (`expires_at`/`ended_at`) is DELIBERATELY excluded from the bare-field match — it
# collides with a row's OWN expiry data column (a real false negative: it would mark an uncapped app
# safe). Expiry only counts when subscription-scoped (`subscription_ended_at`) or a property/quoted
# revocation value, so a plain `row.expires_at` select can't suppress the finding.
REVOCATION_CHECK = re.compile(
    r"\.\s*(?:" + _REVOKE + r"|active|valid_?until|current_period_end)\b"
    r"|['\"](?:" + _REVOKE + r"|active|paused|trialing)['\"]"
    r"|\bsubscription_(?:cancell?ed|canceled|ended|failed|expires?)(?:_(?:at|on|date))?\b"
    r"|\b(?:sub(?:scription)?_?)?status\b\s*[=!]==", re.I)
# A per-principal usage cap — seat / device / machine / activation / quota / concurrency — OR a real
# server-side use-count, named HOWEVER the app names it (provider-agnostic). Its ABSENCE (with no
# rate-limiter) is finding #1. Matched as CODE idioms — compound identifiers, a table, a comparison —
# never a bare word, so a comment ("no seat cap") can't suppress it. `uses` is excluded from the
# compound (it collides with `increment_uses_count`); server-side use-counting is caught only by the
# explicit `increment_uses_count: true` (the `"false"` opt-OUT must not read as a cap).
USAGE_CAP = re.compile(
    r"(?:max|per|distinct|active|registered|allowed|remaining|current|total)[_-]?"
    r"(?:seats?|devices?|machines?|activations?|installs?|sessions?)"
    r"|(?:seats?|devices?|machines?|activations?|installs?|sessions?|usage)[_-]?"
    r"(?:count|counts?|limit|limits?|cap|caps?|max|quota|used|remaining|left)"
    r"|\b\w+[_-](?:seats?|devices?|machines?|activations?)\b"
    r"|\bseats?\b\s*(?:\.\s*(?:length|count|size)|[<>]=?)"
    r"|\bquota\b|\bconcurren\w*|\bsimultaneous\b"
    r"|increment_uses_count['\"]?\s*[:=]\s*['\"]?true", re.I)
# The seat/device-cap risk is a LICENSED-APP concept — a license KEY reused across devices. An ordinary
# per-user WEB SaaS (Stripe subscription, session-authed) has no shared-credential-across-devices problem,
# so the usage-cap finding must be gated to a real license/activation/device vocabulary (real-repo FP:
# a real Workers app's Stripe subscription/checkout flagged no-per-license-usage-cap).
LICENSED_APP = re.compile(
    r"licen[sc]e|\bactivation|machine[_-]?id|device[_-]?id|\bseat|\bhwid\b|fingerprint"
    r"|keygen|gumroad|lemonsqueezy|per[_-]?device|per[_-]?seat|\bactivations?\b|device[_-]?limit", re.I)

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
            if str(e.get("method", "")).upper() in ("GET", "HEAD"):
                continue                                     # an inbound webhook receiver is POST/PUT, not GET
            cp = e.get("code_path", "")
            text = ctx.text(Path(cp)) if cp else ""
            if not text:
                continue                                     # unanalyzable — don't guess it's unsigned
            if OAUTH_CALLBACK.search(text) or WEBHOOK_MGMT.search(text):
                continue                                     # OAuth callback / mgmt CRUD — not a signed receiver
            if not WEBHOOK_STRONG.search(e.get("path", "")) and not WEBHOOK_RECEIVER.search(text):
                continue                                     # WEAK webhook path + no receiver evidence → not a webhook
            if SIG_VERIFY.search(text) or VERIFY_HELPER_CALL.search(text):
                continue                                     # verifies inline OR via an imported helper
            unverified.append(f"{e['method']} {e['path']}  ({ctx.rel(Path(cp)) if cp else '?'})")

        # #5 outbound-action endpoints + #6 redundant secret fetches + entitlement-trust (one code walk)
        findings = []
        providers: set = set()
        for _p, rel, text in ctx.iter_code():
            hit_provider = False
            for host, label in VERIFY_PROVIDERS.items():
                if host in text:
                    providers.add(label)
                    hit_provider = True

            # --- License / subscription entitlement verification trust (provider-agnostic) ---
            if ((hit_provider or ENTITLEMENT_VERIFY.search(text)) and not SKIP_ACTION_FILE.search(rel)
                    and (HANDLER_CTX.search(text) or HANDLER_DIR.search(rel))):
                # #2 — grants on success alone, never inspecting revocation state (HIGH confidence:
                # a concrete dataflow tell). /verify returns success:true after a refund.
                if GRANT_ON_SUCCESS.search(text) and not REVOCATION_CHECK.search(text):
                    findings.append({"severity": "HIGH", "confidence": "HIGH",
                                     "kind": "entitlement-revocation-not-checked",
                                     "attack_class": "entitlement-revocation-bypass", "file": rel,
                                     "detail": f"{rel} grants access on a truthy license/subscription result "
                                               "(success/valid/activated) but never inspects REVOCATION state "
                                               "(refunded / chargebacked / disputed / cancelled / expired / a "
                                               "status compared to active). Most providers still report the "
                                               "license as valid after a refund or chargeback, so buy → use → "
                                               "refund/chargeback → keep access works indefinitely. Inspect the "
                                               "purchase/subscription object and reject revoked states before granting."})
                # #1 — entitlement-gated feature with NO per-license seat/device cap, rate limit, or
                # server-side use-count (LOW confidence: verify the control isn't in middleware).
                if (not RATE_LIMIT.search(text) and not USAGE_CAP.search(text)
                        and LICENSED_APP.search(text)):     # only a licensed-app (key-across-devices), not web SaaS
                    findings.append({"severity": "MEDIUM", "confidence": "LOW",
                                     "kind": "no-per-license-usage-cap",
                                     "attack_class": "missing-usage-cap", "file": rel,
                                     "detail": f"{rel} gates a server-backed feature on a valid entitlement with NO "
                                               "per-principal seat/device/activation cap, rate limit, or server-side "
                                               "use-count — one shared or leaked credential works from unlimited "
                                               "devices indefinitely. Track distinct devices/seats/activations per "
                                               "license and reject beyond the limit, or rate-limit per license "
                                               "(never per IP alone). Verify the cap isn't applied in middleware."})

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
        detected = sorted({label for dep, label in SDKS.items() if dep.lower() in blob} | providers)

        return {
            "webhook_endpoints": [f"{e['method']} {e['path']}" for e in webhook_eps],
            "webhooks_without_sig_verification": sorted(set(unverified)),   # HIGH if non-empty
            "third_party_integrations": detected,
            "findings": findings,   # #5 abusable-action-endpoint + #6 redundant-secret-fetch
            "note": "Webhooks with no signature-verification code in their handler = forgery/replay risk "
                    "(run webhook-forgery; verify against your middleware). Each integration is an outbound "
                    "trust + secret-handling surface (SSRF, secret leakage, supply-chain).",
        }
