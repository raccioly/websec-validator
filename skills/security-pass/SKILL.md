---
name: security-pass
description: Run a local-first security pass on a Python or Node codebase. Use when the user wants to security-review, pentest, find vulnerabilities, check for BOLA/IDOR/JWT/SSRF/mass-assignment issues, or "see if my app is safe" before shipping. Runs deterministic recon + static scanners, stages a tailored probe suite, and produces an AGENT-BRIEFING the agent then executes with the human.
---

# websec-validator — security pass

You are running a security pass on a codebase. A CLI does the deterministic recon; **you** do the
reasoning, run the probes, and propose fixes — with the human supplying credentials and reviewing
every diff.

## Step 0 — make sure the `websec` CLI is installed

```bash
websec --version || pipx install git+https://github.com/raccioly/websec-validator
```

If `pipx` isn't available, `pip install git+https://github.com/raccioly/websec-validator` works too.
Noir (the route engine) is optional — `brew install noir` for best coverage; there's a regex fallback.

## Step 1 — generate the briefing

```bash
websec run <repo-path> --scan      # drop --scan if scanners are slow / not installed
```

(`websec <repo-path>` with no subcommand does the same thing.) This writes `websec-out/` with the
briefing, a full `REPORT.md`, the findings ledger, and staged probes.

## Step 2 — read the artifacts

Read `websec-out/AGENT-BRIEFING.md` (your marching orders) and `websec-out/FACTS.json` (the
structured recon). Do not re-derive what's already there.

## Step 3 — confirm the auth/tenant model (do not skip)

The briefing lists **tenant-key candidates**. Ask the human which one (if any) is THE tenant
boundary — the field that isolates one customer/group/org from another. Every BOLA probe depends on
this. If the app is single-tenant, say so and skip the cross-tenant probes.

## Step 4 — triage the static findings

Go through the scanner results. On a NoSQL/JSON API, most injection/SQLi/PII alerts are false
positives — say which and why. Surface the real ones (leaked secrets, real CVEs, IaC misconfig)
with a proposed fix. Each finding carries a calibrated `P(real)` + confidence interval — treat a
wide CI or `basis: prior` as "thin data, lean on the debate below, not the number."

## Step 5 — finalize and run the probes

The staged probes in `websec-out/probes/` are **drafts**. For each relevant one:
- fill the placeholders from `FACTS.json` + what the human confirmed (hosts, routes, role tokens),
- **ask the human for a running TEST instance URL + test accounts** — never fabricate credentials,
  never run destructive probes against production,
- run it, record the result (PASS counts like "14/14 blocked" are the evidence that it held).

Verify each finding with a 4-role debate before reporting it (Advocate → Challenger → Mediator →
Explainer); the Challenger trying to *refute* it is the false-positive killer.

## Step 6 — fix and re-verify

For anything not blocked: propose a fix, let the human review the diff, apply it, then **re-run the
same probe** to confirm it's now blocked. Keep the probes in the repo as a regression suite.

## Step 7 — hand back a report

Summarize: what was tested, what held (with PASS counts), what's open (repro + fix), and which
probes are now regression tests. Cite `FACTS.json` and `scanners/` as evidence.

## Rules

- The tool needs no running app; the **probes do**. Keep that seam clear with the human.
- No credentials get fabricated or committed. Add `websec-out/` to `.gitignore`.
- You are advisory + hands-on-with-approval: the human approves every code change and every probe
  run against a real environment. Production is out of scope without explicit written authorization.
