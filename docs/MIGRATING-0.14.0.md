# Migrating to websec-validator 0.14.0

0.14.0 changes evidence and execution contracts. Review this guide before replacing an older CLI,
agent instruction, baseline consumer or CI job. Package version lives only in `pyproject.toml`;
FACTS, ledger and JSON envelope use **schema 2.0**. SARIF remains **2.1.0**.

## Preserve existing evidence

Keep old run artifacts and accepted baselines as immutable history. Install the selected release
into your trusted CLI environment, verify `websec --version`, and record the source/artifact revision.
A dirty editable checkout is not identified by its version label alone. Refresh plugin instructions
separately from the Python engine; the plugin manifests do not carry a duplicate package version.

Generate a new run against the intended target and scope. Do not rewrite old reports to claim that
they satisfy the new contract. Before accepting a new baseline, inspect new, changed and reopened
findings plus coverage gaps. A successful narrower policy must not silently accept a broader one.

## Consume schema 2.0 and the exact current attempt

Use the [published schemas](../src/websec_validator/schemas/) and check `schema_version` explicitly.
Read `coverage` from facts/ledger/envelope and `coverage.json` beside the report. It distinguishes
requested execution from exclusions, unsupported/manual scope and evidence uncertainty.
`protection_complete` is false: a finished static pass does not prove full protection.

```bash
websec run ./my-app --out ./websec-out --format json --require-complete
```

Capture this invocation's stdout JSON and exit status. Its `generated` identifier selects
`websec-out/runs/<generated>/`, containing `FACTS.json`, `coverage.json`, `findings-ledger.json`,
`AGENT-BRIEFING.md`, `REPORT.md`, `results.sarif` and staged probes. Early errors may emit no usable
envelope. Do not select a previous run when that happens. The
[agent skill](../skills/security-pass/SKILL.md) contains a tested selector including path checks.

`latest` points only to the latest fully executed run. A partial attempt remains in its unique
run directory but does not replace that pointer. A completed run containing findings can replace
`latest`; pointer advancement is not policy acceptance. Nested `runs` symlinks are refused.

## Interpret exit codes and analyzer selection

- **0:** requested command completed under its configured gate; inspect scope and uncertainty.
- **1:** the requested findings policy failed on a completed security run.
- **2:** invalid input or incomplete requested execution under a completeness/severity gate.

Use `--require-complete` for execution gating and `--fail-on high` (or your selected severity) for
findings. `--scan` runs available runnable optional adapters. Missing unselected optional tools
are reported as unavailable scope; an explicitly selected missing tool cannot become a completed
check. `--scanners` requires `--scan`. Parse errors, timeouts, read loss and hard caps preserve
partial artifacts and fail requested completeness. External tools still have their own filesystem,
configuration and network behavior; the Python reader does not sandbox them.

## Finding identities, baselines and review policy

Fingerprint version 2 uses semantic occurrence evidence where available. Legacy V1 aliases support
migration, but do not guarantee every old line-based record matches after source changes. SARIF
exports a canonical V2 fingerprint and retained V1 alias where available. CVE findings distinguish
manifest, package/ecosystem and installed occurrence; an upgrade that remains vulnerable can create
a new occurrence. Advisory aliases are not fingerprint migration aliases.

Lifecycle states include new, unchanged, changed, reopened and no longer observed. **No longer
observed is not verified fixed.** Deprecated `fixed_count` stays zero. New-only gates include changed
and reopened findings; expired acknowledgements or stronger vulnerability intelligence can reopen a
finding. Review acknowledgement/suppression evidence and scope instead of automatically advancing a
baseline after an advisory or failed gate.

Ignore/acknowledgement discovery defaults to the target repository, not an unrelated invoking
working directory. Invalid explicitly supplied baselines remain an error. Preserve old policy files,
review the new target-bound behavior, and approve any resulting baseline changes deliberately.

## Imported and dynamic evidence

SARIF import preserves native tool/rule identities, traces, suppressions, result kinds and report
hashes. Native suppression does not authorize a local ignore. Missing/failed invocation evidence,
invalid references and caps make requested execution incomplete. Producer success still leaves
source freshness unverified; an imported report hash is not an analyzed-source digest. Imported
absence cannot independently prove a repair.

Dynamic/DAST observations require expected policy, known-positive and known-negative controls,
matching application/build/source context, and retained evidence. HTTP status alone, missing
findings, unconfigured BOLA probes and unknown calibration labels do not establish success.
The [evidence examples](security-review/examples/README.md) show accepted shapes.

Repair plans require meaningful bound before/after regression artifacts, the rerun ledger and
consistent complete scope. `repair-verify` validates operator-supplied artifacts; it does not run
their test commands or independently attest their execution. Keep unknown outcomes unknown.

## Refresh integrations safely

Re-run `websec install <host>` only after verifying the selected engine. Known generated skills and
complete shared blocks can be refreshed; foreign files and ambiguous markers are refused without
writes. Native hooks use isolated trusted Python and keep accepted gate policy separate from
advisory/failed runs. The [pre-commit/CI examples](integrations/README.md) are opt-in and require
configuration; no hook or schedule is activated merely by upgrading the package.

For CI, pin a reviewed 0.14.0-or-later engine commit, keep engine and untrusted target checkouts
separate, and upload only current-attempt artifacts. Reassess changing CVEs with explicitly refreshed
scanner databases or intelligence; a pinned static engine does not obtain new rules automatically.
