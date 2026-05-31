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

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {"findings": findings, "by_severity": by_sev,
                "workflows_scanned": len(ctx.glob(".github/workflows/*.yml") + ctx.glob(".github/workflows/*.yaml"))}
