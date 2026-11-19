# Migrating to websec-validator 0.14.0

0.14.0 changes evidence and execution contracts. Read this guide before you replace an older CLI,
agent instruction, baseline consumer or CI job. The package version lives only in `pyproject.toml`.
FACTS, the ledger and the JSON envelope use **schema 2.0**. SARIF stays at **2.1.0**.

## Preserve existing evidence

Keep old run artifacts and accepted baselines as immutable history. Install the release you chose
into your trusted CLI environment. Verify `websec --version`, and record the source/artifact revision.
The version label alone does not identify a dirty editable checkout. Refresh plugin instructions
separately from the Python engine. The plugin manifests do not carry a duplicate package version.

Generate a new run against the intended target and scope. Do not rewrite old reports to claim that
they meet the new contract. Before you accept a new baseline, inspect new, changed and reopened
findings and the coverage gaps. A narrower policy that passes must not silently accept a broader one.

## Consume schema 2.0 and the exact current attempt

Use the [published schemas](../src/websec_validator/schemas/) and check `schema_version` explicitly.
Read `coverage` from facts, the ledger and the envelope, and read `coverage.json` beside the report. It separates
requested execution from exclusions, unsupported/manual scope and evidence uncertainty.
`protection_complete` is false. A finished static pass does not prove full protection.

```bash
websec run ./my-app --out ./websec-out --format json --require-complete
```

Capture the stdout JSON and the exit status of this invocation. Its `generated` identifier selects
`websec-out/runs/<generated>/`. That directory holds `FACTS.json`, `coverage.json`, `findings-ledger.json`,
`AGENT-BRIEFING.md`, `REPORT.md`, `results.sarif` and staged probes. An early error can emit no usable
envelope. If that happens, do not select a previous run. The
[agent skill](../skills/security-pass/SKILL.md) contains a tested selector that includes path checks.

`latest` points only to the latest fully executed run. A partial attempt stays in its own
run directory and does not replace that pointer. A completed run that contains findings can replace
`latest`. A moved pointer is not policy acceptance. websec refuses nested `runs` symlinks.

## Interpret exit codes and analyzer selection

- **0:** the requested command completed under its configured gate. Inspect the scope and the uncertainty.
- **1:** the requested findings policy failed on a completed security run.
- **2:** the input was invalid, or the requested execution was incomplete under a completeness/severity gate.

Use `--require-complete` for execution gating. Use `--fail-on high` (or the severity you choose) for
findings. `--scan` runs the optional adapters that are available and runnable. websec reports
missing optional tools that you did not select as unavailable scope. A missing tool that you selected explicitly cannot become a completed
check. `--scanners` requires `--scan`. Parse errors, timeouts, read loss and hard caps keep the
partial artifacts and fail requested completeness. External tools still have their own filesystem,
configuration and network behavior. The Python reader does not sandbox them.

## Finding identities, baselines and review policy

Fingerprint version 2 uses semantic occurrence evidence where it is available. Legacy V1 aliases help
migration, but they do not guarantee that every old line-based record matches after the source changes. SARIF
exports a canonical V2 fingerprint and the retained V1 alias where available. CVE findings separate
the manifest, the package/ecosystem and the installed occurrence. An upgrade that is still vulnerable can create
a new occurrence. Advisory aliases are not fingerprint migration aliases.

Lifecycle states include new, unchanged, changed, reopened and no longer observed. **No longer
observed is not verified fixed.** The deprecated `fixed_count` stays zero. New-only gates include changed
and reopened findings. Expired acknowledgements or stronger vulnerability intelligence can reopen a
finding. After an advisory or a failed gate, review the acknowledgement/suppression evidence and scope. Do not move a
baseline forward automatically.

Discovery of ignore and acknowledgement files defaults to the target repository, not an unrelated invoking
working directory. An invalid baseline that you supply explicitly is still an error. Keep old policy files,
review the new target-bound behavior, and approve any resulting baseline changes deliberately.

## Imported and dynamic evidence

SARIF import keeps the native tool/rule identities, traces, suppressions, result kinds and report
hashes. A native suppression does not authorize a local ignore. Missing or failed invocation evidence,
invalid references and caps make requested execution incomplete. Even when the producer succeeds, the
source freshness is still unverified. An imported report hash is not an analyzed-source digest. Imported
absence cannot prove a repair on its own.

Dynamic/DAST observations need an expected policy, known-positive and known-negative controls,
a matching application/build/source context, and retained evidence. These do not establish success: an HTTP status alone, missing
findings, unconfigured BOLA probes and unknown calibration labels.
The [evidence examples](security-review/examples/README.md) show accepted shapes.

Repair plans need meaningful bound before/after regression artifacts, the rerun ledger and
a consistent, complete scope. `repair-verify` validates the artifacts that the operator supplies. It does not run
their test commands and does not attest their execution on its own. Keep unknown outcomes unknown.

## Refresh integrations safely

Re-run `websec install <host>` only after you verify the engine you selected. The command can refresh known generated skills and
complete shared blocks. It refuses foreign files and ambiguous markers, and writes nothing for them. Native hooks use isolated trusted Python and keep the accepted gate policy separate from
advisory or failed runs. The [pre-commit/CI examples](integrations/README.md) are opt-in and need
configuration. An upgrade of the package does not activate any hook or schedule.

For CI, pin a reviewed engine commit from 0.14.0 or later. Keep the engine checkout and the untrusted target checkout
separate, and upload only artifacts from the current attempt. To reassess CVEs that change, refresh the
scanner databases or intelligence explicitly. A pinned static engine does not obtain new rules automatically.
