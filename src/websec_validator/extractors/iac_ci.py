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

# CDK / managed-AppSync auth (PTREQ0013000 #4 CSWSH, + the #2/#5 attack surface). Regex over CDK
# TypeScript, not an AST — aliased/helper-extracted constructs can evade it (honest FN risk).
APPSYNC_API = re.compile(r"appsync\.GraphqlApi|new\s+GraphqlApi|CfnGraphQLApi|aws-cdk-lib/aws-appsync|@aws-cdk/aws-appsync")
# defaultAuthorization block resolving to API_KEY → the realtime/WebSocket endpoint takes a static
# key with no Origin/cookie binding (anonymous subscribe + CSWSH). `[^{}]*` keeps it to one object.
APPSYNC_DEFAULT_APIKEY = re.compile(
    r"defaultAuthorization\s*:\s*\{[^{}]*authorizationType\s*:\s*[^,}]*\bAPI_KEY\b", re.S)
APPSYNC_APIKEY_MODE = re.compile(r"AuthorizationType\.API_KEY|authorizationType\s*:\s*['\"]?API_KEY")
WAFV2 = re.compile(r"wafv2\.CfnWebACL|\bCfnWebACL\b|aws_wafv2|wafv2\.CfnWebACLAssociation")
WAF_ASSOC = re.compile(r"CfnWebACLAssociation|WebACLAssociation")


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

        # --- CDK / managed-AppSync auth (#4 CSWSH; surfaces the #2/#5 boundary) ---
        appsync_files, waf_present, waf_assoc = [], False, False
        for _p, rel, text in ctx.iter_code():
            if not rel.endswith((".ts", ".js", ".mjs", ".cjs")):
                continue
            if WAFV2.search(text):
                waf_present = True
            if WAF_ASSOC.search(text):
                waf_assoc = True
            if APPSYNC_API.search(text):
                appsync_files.append(rel)
                if APPSYNC_DEFAULT_APIKEY.search(text):
                    findings.append({"severity": "HIGH", "kind": "appsync-apikey-default", "file": rel,
                                     "detail": "AppSync defaultAuthorization is API_KEY — the realtime WebSocket "
                                               "accepts a static key with no Origin/cookie binding (Cross-Site "
                                               "WebSocket Hijacking + anonymous subscribe). Make the default "
                                               "USER_POOL/OIDC/IAM/LAMBDA; keep API_KEY (if needed) as a scoped "
                                               "additional mode only."})
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
