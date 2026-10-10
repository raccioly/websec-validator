# Run websec in other CI systems

This guide covers running websec-validator outside GitHub Actions: GitLab CI, Azure DevOps, Jenkins,
CircleCI and container-based pipelines. When you finish, your pipeline will gate on findings, fail
visibly on incomplete runs, and keep the run's SARIF and JSON envelope as artifacts. It also covers
SBOM output and importing SARIF from other analyzers.

websec is a stdlib-only Python CLI, so every CI system follows the same pattern. Only the GitLab
example below is spelled out in full. The others are *illustrative*: they show the pattern, but
this project does not test them, so adapt and verify them in your pipeline.

## The generic pattern

1. **Use a trusted engine.** Install a reviewed version of websec from PyPI, or build the container
   image from a reviewed source checkout. Never install websec from the repository you are scanning;
   the target is untrusted input.
2. **Check out the target as data.** Give websec read access; it does not execute the target's
   code, installers or tests.
3. **Run with explicit gates:**

   ```bash
   websec run . --fail-on high --require-complete
   ```

4. **Keep the artifacts even when the job fails.** Save `websec-out/` (or at least the current run
   directory) with an "always" or "on failure" policy. Reports can contain sensitive source
   evidence, so restrict access and keep them only as long as needed.
5. **Act on the exit code:**

   | Code | Meaning |
   |---|---|
   | `0` | The gate ran and nothing met the threshold. This does not prove protection |
   | `1` | Findings at or above `--fail-on`. If the run was also incomplete, the count is a floor |
   | `2` | Usage or configuration error; nothing was scanned |
   | `3` | Requested checks did not complete; not a pass. Read `coverage.gaps` |

   For the full contract, including `gate.failure_kind`, see
   [exit codes in the GitHub Actions guide](github-actions.md#exit-codes).

> [!IMPORTANT]
> Without `--fail-on` or `--require-complete`, an incomplete run exits `0`. Always pass at least
> `--require-complete` in CI.

What lands in each run directory (`websec-out/runs/<generated>/`):

| File | Use in CI |
|---|---|
| `results.sarif` | SARIF 2.1.0, always written. Feed it to any tool that accepts SARIF |
| `findings.envelope.json` | Versioned JSON envelope for dashboards and scripts |
| `coverage.json` | What ran, what didn't, and why |
| `findings-ledger.json` | The full ledger, including the recorded `gate` verdict |
| `diff-scope.json` | With `--diff`: changed files and exact added-line ranges |
| `sbom.cdx.json` / `sbom.spdx.json` | With `--sbom` |

`websec-out/latest` advances only after a **completed** run. A partial attempt keeps its own
directory and leaves `latest` pointing at the previous completed run. To get the current attempt
regardless of outcome, add `--format json` and read the `generated` field from stdout. See the
[outputs reference](../../reference/outputs.md).

## GitLab CI

websec writes SARIF and `findings.envelope.json`. It does **not** write GitLab's native security
report formats, so this job keeps them as plain job artifacts. It does not declare them under
`artifacts:reports`.

```yaml
# .gitlab-ci.yml
websec:
  stage: test
  image: python:3.12-slim
  variables:
    PIP_DISABLE_PIP_VERSION_CHECK: "1"
  before_script:
    # git: websec reads Git metadata (attribution, --diff).
    - apt-get update && apt-get install -y --no-install-recommends git
    - python -m pip install pipx
    - python -m pipx install "websec-validator==<reviewed-version>"
    - export PATH="$HOME/.local/bin:$PATH"
    - websec --version
  script:
    - websec run . --fail-on high --require-complete --out websec-out
  artifacts:
    when: always
    expire_in: 7 days
    paths:
      - websec-out/
```

Replace `<reviewed-version>` with the release you have reviewed. Python 3.11 or newer is required.

**Merge-request mode** *(illustrative)*: scope the gate to changed files. websec diffs
`<ref>...HEAD`, so the target branch must exist in the clone:

```yaml
websec-mr:
  extends: websec
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  variables:
    GIT_DEPTH: "0"
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - websec run . --diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME" --fail-on high --require-complete --out websec-out
```

If the ref can't be resolved, websec records a `diff` coverage gap and runs unscoped. Under
`--require-complete` that exits `3`.

## Azure DevOps *(illustrative)*

```yaml
# azure-pipelines.yml
steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: "3.12"
  - script: |
      python -m pip install --disable-pip-version-check "websec-validator==<reviewed-version>"
      websec run "$(Build.SourcesDirectory)" --fail-on high --require-complete --out "$(Build.ArtifactStagingDirectory)/websec-out"
    displayName: websec security review
  - task: PublishPipelineArtifact@1
    condition: always()
    inputs:
      targetPath: $(Build.ArtifactStagingDirectory)/websec-out
      artifact: websec
```

If you use a SARIF viewer extension for Azure DevOps, point it at the `results.sarif` inside the run
directory. Check that extension's documentation for the artifact name and layout it expects.

## Jenkins and CircleCI *(illustrative)*

Both follow the generic pattern: a Python 3.11+ image or agent, a pinned install, one `websec run`
command and an always-archive step.

Jenkins (declarative):

```groovy
pipeline {
  agent { docker { image 'python:3.12-slim' } }
  stages {
    stage('websec') {
      steps {
        // Keep the engine's virtualenv outside the workspace being scanned.
        sh 'python -m venv /tmp/websec-venv && /tmp/websec-venv/bin/pip install "websec-validator==<reviewed-version>"'
        sh '/tmp/websec-venv/bin/websec run . --fail-on high --require-complete --out websec-out'
      }
    }
  }
  post {
    always { archiveArtifacts artifacts: 'websec-out/**', allowEmptyArchive: true }
  }
}
```

CircleCI:

```yaml
version: 2.1
jobs:
  websec:
    docker:
      - image: cimg/python:3.12
    steps:
      - checkout
      - run: pip install "websec-validator==<reviewed-version>"
      # Record the exit code instead of failing here, so the artifacts are stored either way.
      - run: |
          set +e
          websec run . --fail-on high --require-complete --out websec-out
          echo $? > websec-exit-code
      - store_artifacts:
          path: websec-out
      - run:
          name: Apply the websec gate
          command: exit "$(cat websec-exit-code)"
workflows:
  security:
    jobs: [websec]
```

## Container-based CI

No image is published. Build it from a reviewed checkout of the engine source, not from the
repository you are scanning:

```bash
docker build -t websec-validator .                 # default "bundled" target
docker build --target core -t websec-core .        # stdlib engine only, no scanners
```

Then mount the target at `/scan`:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/scan" \
  websec-validator run /scan --out /scan/websec-out --fail-on high --require-complete
```

- The bundled image carries Noir, Trivy, Gitleaks, Semgrep and Checkov. OSV-Scanner, Prowler,
  Bandit, gosec and Brakeman are absent, and are reported as missing rather than silently skipped.
- **Bundling isn't running.** Noir runs on every `run`. The four static scanners run only when you
  add `--scan`.
- Both targets run as a non-root user. Pass `--user` so output files belong to the CI user.
  `HEALTHCHECK NONE` is deliberate for the one-shot CLI.
- The digests pinned in the Dockerfile check base and archive bytes. They don't make apt or
  transitive Python dependencies fully reproducible. See the
  [container policy](../../integrations/README.md#container-policy-and-reviewed-downloads).

## Feed dashboards with `findings.envelope.json`

`findings.envelope.json` is a versioned, self-describing wrapper around the ledger, so a dashboard
doesn't have to reverse-engineer internal shapes. Top-level fields: `schema_version`, `tool`,
`tool_version`, `generated`, `target`, `summary` (`total`, `by_severity`, `by_confidence`,
`suppressed`, `acknowledged`, `dynamic_included`), `calibration`, `verification_context`,
`attribution`, `coverage` and `findings`. JSON Schemas ship in the package; see the
[outputs reference](../../reference/outputs.md).

A stdlib-only post-processing step, for example to fail a job if the envelope says execution was
incomplete:

```bash
python3 -I - websec-out/latest/findings.envelope.json <<'PY'
import json, sys
env = json.load(open(sys.argv[1]))
print(env["summary"]["by_severity"])
if not (env.get("coverage") or {}).get("execution_complete"):
    sys.exit("websec: requested checks did not complete; see coverage.gaps")
PY
```

`latest` names the last **completed** run only. To inspect an incomplete attempt, read the envelope
from that attempt's own directory, or capture `websec run ... --format json` stdout.

## Emit an SBOM

```bash
websec run . --sbom                 # CycloneDX → sbom.cdx.json
websec run . --sbom spdx            # SPDX JSON → sbom.spdx.json
```

- The SBOM is produced by **Trivy**, offline, and doesn't require `--scan`. Trivy must be on `PATH`.
- If Trivy is missing or fails, websec records an `sbom` coverage gap. Under `--fail-on` or
  `--require-complete`, the run exits `3` instead of passing without the SBOM you asked for.

## Import SARIF from other analyzers

Reuse analysis you already run, such as CodeQL, without websec executing that analyzer:

```bash
websec run . --sarif ./codeql.sarif --sarif ./other-analysis.sarif --require-complete
```

- Up to 8 `--sarif` reports per run; more is a usage error (exit `2`).
- Import is **offline**. websec never executes the analyzer and never loads any source path or URL
  referenced inside the report. Only safe relative paths are supported.
- Native tool and rule identities, traces and report hashes are preserved in `sarif-imports.json`
  and in the unified ledger.
- Unknown analyzer execution, malformed references and size caps become visible incomplete checks.
- Native suppressions stay as metadata until you acknowledge them locally.
- **Source freshness is unverified.** A report hash is not a source digest, and a finding absent
  from an imported report can't verify a repair.

## See also

- [GitHub Actions](github-actions.md): the composite Action, Code Scanning upload, PR mode.
- [Pre-commit and git hooks](pre-commit-and-git-hooks.md): gates before code leaves a laptop.
- [Monorepos](../monorepo.md): scoping a run to one service.
- [Configuration reference](../../reference/configuration.md) and
  [CLI reference](../../reference/cli.md).
