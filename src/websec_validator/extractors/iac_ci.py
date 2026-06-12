"""IaC + CI/CD extractor — the pipeline + infra attack surface.

The commonly-missed P0 surface: GitHub Actions script injection via untrusted
context, third-party actions pinned to mutable tags, Dockerfiles running as root,
and committed Terraform state. Pure static globbing — no tools required (zizmor /
Checkov can be layered later for depth).
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

# untrusted GitHub Actions contexts an attacker can control
UNTRUSTED = re.compile(
    r"\$\{\{\s*github\.(?:head_ref|event\.(?:pull_request|issue|comment|review|"
    r"head_commit|workflow_run)[^}]*|event\.[^}]*\.(?:title|body|name|email|ref|label|message)[^}]*)\s*\}\}")
USES = re.compile(r"uses:\s*([^\s@#]+)@([^\s#'\"]+)")
SHA40 = re.compile(r"^[0-9a-f]{40}$")

# CDK / managed-AppSync auth (REF-PENTEST #4 CSWSH, + the #2/#5 attack surface). Regex over CDK
# TypeScript, not an AST — aliased/helper-extracted constructs can evade it (honest FN risk).
APPSYNC_API = re.compile(r"appsync\.GraphqlApi|new\s+GraphqlApi|CfnGraphQLApi|aws-cdk-lib/aws-appsync|@aws-cdk/aws-appsync")
# defaultAuthorization block resolving to API_KEY → the realtime/WebSocket endpoint takes a static
# key with no Origin/cookie binding (anonymous subscribe + CSWSH). `[^{}]*` keeps it to one object.
APPSYNC_DEFAULT_APIKEY = re.compile(
    r"defaultAuthorization\s*:\s*\{[^{}]*authorizationType\s*:\s*[^,}]*\bAPI_KEY\b", re.S)
APPSYNC_APIKEY_MODE = re.compile(r"AuthorizationType\.API_KEY|authorizationType\s*:\s*['\"]?API_KEY")
WAFV2 = re.compile(r"wafv2\.CfnWebACL|\bCfnWebACL\b|aws_wafv2|wafv2\.CfnWebACLAssociation")
WAF_ASSOC = re.compile(r"CfnWebACLAssociation|WebACLAssociation")
# WAF used as the PRIMARY control for an app-layer flaw — a bypassable band-aid, not a remediation
# (REF-PENTEST #2/#11). A byteMatchStatement/regex matching `__schema`, SQL keywords or `<script`
# means the app-layer bug is still there; the string-match is evadable via encoding + only one door.
WAF_APPLAYER_MATCH = re.compile(
    r"(?:byteMatchStatement|searchString|RegexPatternSet|regexString)[\s\S]{0,220}?"
    r"(__schema|__type|UNION\s+SELECT|information_schema|<script|onerror=|\bor\s+1\s*=\s*1\b|sleep\s*\()", re.I)


class IacCiExtractor(Extractor):
    name = "iac_ci"
    category = "infra"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings = []

        # --- GitHub Actions ---
        for wf in ctx.glob(".github/workflows/*.yml") + ctx.glob(".github/workflows/*.yaml"):
            rel, text = ctx.rel(wf), ctx.text(wf)
            contexts = sorted(set(UNTRUSTED.findall(text)))
            if contexts:
                findings.append({"severity": "HIGH", "kind": "gha-script-injection", "file": rel,
                                 "detail": "untrusted context in workflow (dangerous if used in a run: step) — "
                                           + ", ".join("github." + c for c in contexts[:4])})
            unpinned = sorted({f"{a}@{r}" for a, r in USES.findall(text)
                               if not SHA40.match(r) and not a.startswith("./")})
            if unpinned:
                findings.append({"severity": "MEDIUM", "kind": "gha-unpinned-action", "file": rel,
                                 "detail": "actions pinned to a mutable tag (pin to a commit SHA): "
                                           + ", ".join(unpinned[:6])})

        # --- Dockerfiles ---
        for df in ctx.glob("**/Dockerfile") + ctx.glob("**/Dockerfile.*"):
            rel, text = ctx.rel(df), ctx.text(df)
            users = re.findall(r"^\s*USER\s+(\S+)", text, re.M)
            if not users or users[-1].lower() in ("root", "0"):
                findings.append({"severity": "MEDIUM", "kind": "docker-root",
                                 "file": rel, "detail": "container runs as root (add a non-root USER)"})
            if "HEALTHCHECK" not in text:
                findings.append({"severity": "LOW", "kind": "docker-no-healthcheck",
                                 "file": rel, "detail": "no HEALTHCHECK defined"})

        # --- Terraform state committed ---
        for tf in ctx.glob("**/*.tfstate")[:5]:
            findings.append({"severity": "HIGH", "kind": "terraform-state-committed", "file": ctx.rel(tf),
                             "detail": "tfstate may contain plaintext secrets (DB passwords, keys) — must not be committed"})

        # --- CDK / managed-AppSync auth (#4 anonymous default-auth; WAF-as-control smell #2) ---
        appsync_files, waf_present, waf_assoc = [], False, False
        for _p, rel, text in ctx.iter_code():
            if not rel.endswith((".ts", ".js", ".mjs", ".cjs")):
                continue
            if WAFV2.search(text):
                waf_present = True
            if WAF_ASSOC.search(text):
                waf_assoc = True
            if WAF_APPLAYER_MATCH.search(text):
                tok = (WAF_APPLAYER_MATCH.search(text).group(1) or "").strip()
                findings.append({"severity": "MEDIUM", "kind": "waf-as-app-control", "file": rel,
                                 "detail": f"A WAF string/regex match on an app-layer attack token ({tok!r}) is used as a "
                                           "control. A WAF is a bypassable compensating control, never the remediation: "
                                           "string-matches are evaded by encoding (the retest bypassed `__schema` with a "
                                           "Unicode escape) and only cover one endpoint. Fix at the app/engine layer "
                                           "(disable introspection, parametrize queries) and keep the WAF as defense-in-depth."})
            if APPSYNC_API.search(text):
                appsync_files.append(rel)
                if APPSYNC_DEFAULT_APIKEY.search(text):
                    findings.append({"severity": "HIGH", "kind": "appsync-apikey-default", "file": rel,
                                     "detail": "AppSync defaultAuthorization is API_KEY — the API (HTTP + realtime) accepts "
                                               "a static key by default, and that key typically ships to the browser, so "
                                               "this is effectively ANONYMOUS/unauthenticated access. Make the default "
                                               "USER_POOL/OIDC/IAM/LAMBDA; keep API_KEY (if needed) to a scoped additional "
                                               "mode. (NB: this is NOT in itself CSWSH — that needs cookie-based WS auth; "
                                               "see the client_integrity websocket-auth check.)"})
                elif APPSYNC_APIKEY_MODE.search(text):
                    findings.append({"severity": "MEDIUM", "kind": "appsync-apikey-mode", "file": rel,
                                     "detail": "AppSync accepts an API_KEY authorization mode — confirm it is NOT the "
                                               "default and is tightly scoped; api keys are bearer-only (no Origin check)."})
        if appsync_files and waf_present:
            findings.append({"severity": "LOW", "kind": "appsync-waf-verify", "file": appsync_files[0],
                             "detail": "A WAFv2 WebACL exists in the IaC"
                                       + ("" if waf_assoc else " but no CfnWebACLAssociation was found")
                                       + " — VERIFY it is associated to THIS AppSync API (resourceArn === api.arn). "
                                         "WAF string-match rules are bypassable (Unicode-escape / junk-byte padding, "
                                         "#2); never treat WAF presence as mitigation of a missing app-layer control."})

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"findings": findings, "by_severity": by_sev,
                "workflows_scanned": len(ctx.glob(".github/workflows/*.yml") + ctx.glob(".github/workflows/*.yaml"))}
