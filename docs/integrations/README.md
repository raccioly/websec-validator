# Opt-in security review integrations

These examples reuse the existing CLI, [native hooks](../../src/websec_validator/hooks.py),
[composite Action](../../action.yml), and [agent skill](../../skills/security-pass/SKILL.md).
Adding files to this documentation directory activates nothing. Review the configuration before
copying it into a target repository; no hooks or hosted schedule were installed by this work.
These contracts are introduced in 0.14.0. The historical v0.13.0 tag does not contain them.

## pre-commit framework

The root [.pre-commit-hooks.yaml](../../.pre-commit-hooks.yaml) publishes `websec-security` for a
reviewed 0.14.0-or-later commit containing this manifest. Its Python environment installs the **trusted
engine repository**, not the application being scanned. It launches isolated Python, scans the
repository root, fails incomplete execution or HIGH/CRITICAL findings, and does not automatically
accept a baseline. Optional external analyzers are not executed with `--scan` by this default hook;
Noir route discovery may run if installed. Inspect the coverage manifest for unavailable/manual scope.

For a trusted local checkout, use the
[local config example](pre-commit-config.yaml.example). Replace the explicit absolute Python path
with a trusted venv containing the reviewed engine. Do not point it to the application's own package,
Python environment or editable source. This `language: system` local entry performs no package
installation. With pre-commit already available, opt in yourself:

```bash
# First copy/configure the example as .pre-commit-config.yaml and ignore websec-out/.
pre-commit validate-config
pre-commit run websec-security --all-files --hook-stage manual
# Optional activation, after reviewing the result:
pre-commit install --hook-type pre-commit --hook-type pre-push
```

`pass_filenames: false` makes this a whole-repository check; `always_run` covers changes such as
file deletions. At the pre-commit stage, pre-commit temporarily hides unstaged changes to tracked
files. The scanner can still see untracked files under its normal policy, so this is not an exact
Git-index snapshot. Manual and pre-push runs inspect the working tree, not every pushed Git object.
The framework itself manages its temporary stash; the example does not issue Git stash commands.
[pre-commit documentation](https://pre-commit.com/)

If adopting a remote configuration, use a reviewed full commit SHA containing this manifest
as `rev`, not a floating branch or the old version tag. Review target `.pre-commit-config.yaml`
changes before running them: pre-commit can execute any configured hook, beyond this one. Do not
replace an existing hook dispatcher blindly or install two dispatchers for the same event.

## Native hooks and agent skills

The existing `websec hooks install` provides advisory post-commit review; `--pre-push` adds a gate.
These native hooks already preserve approved baseline policy separately from advisory/failed runs.
They inspect the working tree and use trusted isolated Python. Choose a single dispatcher for each
Git event. `websec install <host>` installs the reviewed agent guidance and refuses ambiguous or
foreign ownership. Neither example needs a duplicate hook runner or a new CLI command.

## Pull-request and weekly workflow

The [workflow example](security-review.yml.example) is inactive until copied to `.github/workflows/`.
Set the repository variable `WEBSEC_REVIEWED_SHA` to a reviewed **40-character upstream commit SHA**
that contains the hardened Action. The repository is fixed to `raccioly/websec-validator`; revision
validation reads an environment variable, without substituting it into shell code. SHA shape is
validation, not trust: the operator must inspect that upstream revision before setting it.

The engine and review target occupy separate directories. The target's package installer, tests,
Git hooks and local Action are never invoked. The job uses `pull_request`, not `pull_request_target`,
with `contents: read` and no persisted checkout credentials. The Action builds only the selected
trusted engine. Existing official Action SHAs are reused. Follow
[GitHub's secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

The example runs core review with `scan: false`, `require-complete: true` and a HIGH findings gate.
It uploads artifacts only from the Action's **current attempt** output, including partial results;
missing current output never falls back to `latest`. Reports can contain sensitive source evidence,
so review repository/artifact access and retention. SARIF stays in the artifact bundle. Uploading to
Code Scanning is a separate opt-in requiring suitable `security-events: write` permissions; do not
add privileged fork-PR execution to work around upload restrictions.

A weekly run uses the default branch and can be delayed or disabled by GitHub's scheduling rules.
It is not a guarantee of continuous coverage. A pinned engine does not gain new detection rules
without a deliberate reviewed revision update. The default workflow does not refresh intelligence
or scan a vulnerability database. To review changing CVEs, explicitly provision reviewed scanner
executables/databases, enable `scan`, and name required `scanners` so a missing tool fails visibly.
Alternatively, use authorized `websec intel refresh` and offline reassessment of an existing CVE
ledger; reassessment does not perform a new source analysis. Record engine, scanner and feed
provenance. [GitHub schedule behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)


## Validation limits

Tests execute the documented hook argv in an isolated stdlib venv containing a trusted engine copy,
including target import-shadowing, finding-gate and incomplete-read controls. The copy prunes private
`.local` trees case-insensitively and skips every symlink before descent or payload copying.
Configuration tests check the examples' limited scalar structure and revision-validation code.
The pre-commit framework and a YAML parser were unavailable in the validation environment, so no
full pre-commit installation/staging lifecycle or hosted workflow run was performed. Run
`pre-commit validate-config` and review a workflow check in your configured environment before adoption.
