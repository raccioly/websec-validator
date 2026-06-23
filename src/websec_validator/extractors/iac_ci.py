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
# A context that resolves to a commit SHA / git ref is hex-constrained by GitHub, so it is NOT
# free-text shell-injectable — when EVERY flagged context is SHA/ref-typed, drop to INFO.
SHA_CONTEXT = re.compile(r"\.(?:head_sha|base\.sha|after|before|merge_commit_sha|[\w.]*\bsha\b)\b", re.I)
USES = re.compile(r"uses:\s*([^\s@#]+)@([^\s#'\"]+)")
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def _gha_run_bodies(text: str) -> str:
    """Return only the `run:` step script bodies — the lone shell-injection sink. `${{ }}` in
    `if:`/`env:`/`with:` is evaluated as a GitHub EXPRESSION (not interpolated into a shell), so
    flagging contexts there is a false positive (the deploy-*.yml job-level `if:` blocks)."""
    lines = text.split("\n")
    out: list = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)-?\s*run:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        indent, rest = len(m.group(1)), m.group(2).strip()
        if rest in ("|", "|-", "|+", ">", ">-", ">+", ""):     # block scalar → take indented body
            i += 1
            while i < len(lines):
                ln = lines[i]
                if ln.strip() == "" or (len(ln) - len(ln.lstrip())) > indent:
                    out.append(ln)
                    i += 1
                else:
                    break
            continue
        out.append(rest)
        i += 1
    return "\n".join(out)

# CDK / managed-AppSync auth (REF-PENTEST #4 CSWSH, + the #2/#5 attack surface). Regex over CDK
# TypeScript, not an AST — aliased/helper-extracted constructs can evade it (honest FN risk).
APPSYNC_API = re.compile(r"appsync\.GraphqlApi|new\s+GraphqlApi|CfnGraphQLApi|aws-cdk-lib/aws-appsync|@aws-cdk/aws-appsync")
# defaultAuthorization block resolving to API_KEY → the realtime/WebSocket endpoint takes a static
# key with no Origin/cookie binding (anonymous subscribe + CSWSH). `[^{}]*` keeps it to one object.
APPSYNC_DEFAULT_APIKEY = re.compile(
    r"defaultAuthorization\s*:\s*\{[^{}]*authorizationType\s*:\s*[^,}]*\bAPI_KEY\b", re.S)
APPSYNC_APIKEY_MODE = re.compile(r"AuthorizationType\.API_KEY|authorizationType\s*:\s*['\"]?API_KEY")
# docker-compose host-exposure (the host-takeover surface the FN hunt found)
COMPOSE_SOCK = re.compile(r"/var/run/docker\.sock|(?:^|[\s'\"])docker\.sock", re.I)
COMPOSE_PID_HOST = re.compile(r"\bpid\s*:\s*['\"]?host\b", re.I)
COMPOSE_PRIVILEGED = re.compile(r"\bprivileged\s*:\s*true\b", re.I)
COMPOSE_HOST_ROOT = re.compile(r"-\s*['\"]?/:/|:/rootfs\b", re.I)
COMPOSE_NET_HOST = re.compile(r"\bnetwork_mode\s*:\s*['\"]?host\b", re.I)
COMPOSE_CAP = re.compile(r"cap_add[\s\S]{0,80}?\b(SYS_ADMIN|ALL|NET_ADMIN|SYS_PTRACE|SYS_MODULE)\b")
COMPOSE_SECRET_ENV = re.compile(
    r"^\s*-?\s*[A-Z0-9_]*(?:API_?KEY|SECRET|PASSWORD|PASSWD|_TOKEN|ACCESS_?KEY|DATABASE_URL|PRIVATE_KEY)[A-Z0-9_]*\s*[:=]",
    re.I | re.M)
COMPOSE_SECRETS_BLOCK = re.compile(r"^secrets\s*:", re.I | re.M)
# a secret-suppression entry that silences a REAL secret file (not an example/template) — the leak is
# being hidden from CI, not rotated/purged (the CRITICAL committed-.env.prod class).
SUPPRESS_SECRET_FILE = re.compile(r"\.env(?:\.[\w-]+)?\b|/secrets?/|\.pem\b|id_rsa|\.p12\b|\.pfx\b|(?<![\w.])\.key\b|credentials?\b", re.I)
SUPPRESS_EXAMPLE = re.compile(r"\.(?:example|sample|template|dist|local)\b|\bexamples?/", re.I)
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
            # Only contexts that land inside a `run:` script body are shell-injection sinks.
            contexts = sorted(set(UNTRUSTED.findall(_gha_run_bodies(text))))
            if contexts:
                sha_only = all(SHA_CONTEXT.search(c) for c in contexts)
                sev = "LOW" if sha_only else "HIGH"
                extra = (" — all flagged contexts are SHA/ref-typed (hex-constrained by GitHub, not "
                         "free-text injectable); verify, low exploitability" if sha_only else "")
                findings.append({"severity": sev, "kind": "gha-script-injection", "file": rel,
                                 "detail": "untrusted context interpolated into a run: step — "
                                           + ", ".join(contexts[:4]) + extra})
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

        # --- docker-compose host-exposure (no compose parser existed; whole class was invisible) ---
        compose = (ctx.glob("**/docker-compose*.yml") + ctx.glob("**/docker-compose*.yaml")
                   + ctx.glob("**/compose.yml") + ctx.glob("**/compose.yaml"))
        for cf in compose:
            rel, text = ctx.rel(cf), ctx.text(cf)
            if COMPOSE_SOCK.search(text):
                findings.append({"severity": "HIGH", "kind": "compose-docker-sock-mount", "file": rel,
                                 "detail": "A container mounts the host Docker socket (/var/run/docker.sock). Even "
                                           "read-only, the Docker API leaks every container's env/secrets and can enable "
                                           "container escape / host takeover from one compromised service. Use a "
                                           "restricted socket-proxy or a non-API log/discovery path instead."})
            if COMPOSE_PID_HOST.search(text) or COMPOSE_HOST_ROOT.search(text):
                findings.append({"severity": "HIGH", "kind": "compose-host-namespace-mount", "file": rel,
                                 "detail": "A container shares the host PID namespace (`pid: host`) and/or bind-mounts the "
                                           "host root filesystem (`/:/rootfs`). One compromised container then sees every "
                                           "host process/env and the whole filesystem. Scope mounts to exact paths; drop "
                                           "`pid: host` unless a specific collector needs it; add no-new-privileges."})
            if COMPOSE_PRIVILEGED.search(text):
                findings.append({"severity": "HIGH", "kind": "compose-privileged", "file": rel,
                                 "detail": "`privileged: true` grants near-host-root capabilities to the container — a "
                                           "trivial escape path. Remove it; grant only the specific cap_add it needs."})
            if COMPOSE_NET_HOST.search(text) or COMPOSE_CAP.search(text):
                findings.append({"severity": "MEDIUM", "kind": "compose-host-network-or-caps", "file": rel,
                                 "detail": "`network_mode: host` or a dangerous `cap_add` (SYS_ADMIN/ALL/NET_ADMIN/…) "
                                           "weakens isolation. Prefer a bridge network with explicit port maps and the "
                                           "minimum capability set; pair with `cap_drop: [ALL]`."})
            if COMPOSE_SECRET_ENV.search(text) and COMPOSE_SECRETS_BLOCK.search(text):
                findings.append({"severity": "LOW", "kind": "compose-plaintext-secret-env", "file": rel,
                                 "detail": "Secret-named values are passed via plaintext `environment:` while this file "
                                           "ALSO declares a `secrets:` block — so the better pattern is known but not used "
                                           "for these. Container env is readable via `docker inspect` / the docker.sock / "
                                           "/proc/<pid>/environ. Move provider keys to file-based Docker secrets."})

        # --- secret-suppression audit: a real-secret leak silenced (not rotated/purged) ---
        for ig in (".gitleaksignore", ".trivyignore", ".semgrepignore"):
            txt = ctx.manifest(ig)
            if not txt:
                continue
            for raw in txt.splitlines():
                ln = raw.split("#", 1)[0].strip()
                if not ln or SUPPRESS_EXAMPLE.search(ln):
                    continue
                if SUPPRESS_SECRET_FILE.search(ln):
                    findings.append({"severity": "HIGH", "kind": "suppressed-secret-leak",
                                     "attack_class": "secret", "file": ig,
                                     "detail": f"`{ig}` suppresses a finding that points at a REAL secret file "
                                               f"(`{ln[:80]}`). Suppressing a leak tells CI it's a known false positive — "
                                               "but a leak in a `.env`/secrets/key file is a TRUE positive. The credential "
                                               "is still extractable from git history. ROTATE the secret, PURGE the blob "
                                               "(git filter-repo/BFG), THEN remove the ignore entry — don't silence it."})

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
