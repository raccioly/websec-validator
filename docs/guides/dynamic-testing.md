# Dynamic testing against a TEST instance

This guide covers websec-validator's optional live phase: authenticated cross-tenant BOLA checks,
unauthenticated reachability checks, and the probe drafts websec stages for you. It also covers
how to use websec's predictions to aim a DAST scan and how to feed the results back. When you
finish, you know what each live check sends, what its verdicts mean, and what they cannot prove.

> [!CAUTION]
> **Authorized TEST instances only.** Everything on this page sends real HTTP requests to a running
> application. Run it only against a TEST instance that you own or are explicitly authorized to
> test, with test accounts you control. **Never point it at production** or at third-party systems.
> You own every credential and authorize every live run. If you are not sure that you are
> authorized, stop.

The static pass (`websec run`) never touches a running app. Nothing on this page happens unless you
invoke it explicitly.

## What exists

| Capability | Command | Sends |
|---|---|---|
| Authenticated cross-tenant BOLA | `websec dynamic --config <file>` | One login POST per test identity, then GET requests only |
| Unauthenticated reachability and forged-token check | `websec dynamic --unauth --target <url>` | GET requests only |
| Write-verb auth enforcement | add `--probe-writes` to `--unauth` | POST/PUT/PATCH/DELETE, **localhost only** |
| Staged probe drafts | `websec-out/runs/<generated>/probes/` | Nothing until a human or agent runs them |
| DAST feedback | `websec calibrate --ingest-dast` | Nothing; offline |

## The safety model

These rules come from [`docs-canonical/SECURITY.md`](../../docs-canonical/SECURITY.md). The
transports enforce them (`dynamic.py` and the staged `probes/_lib.py` and `probes/_lib.bash`). CLI
flags are not the only guard:

- **Read-only by default.** `--config` and `--unauth` issue GET-only probes. With `--config`, the
  only non-GET request is the login POST of your TEST credentials to your configured login endpoint.
  That request is credential setup, not a write probe, and it never follows redirects.
- **Write probes are localhost-only.** `--probe-writes` is refused unless `--target` is `localhost`,
  `127.0.0.1`, `::1` or `0.0.0.0`. websec refuses any non-GET/HEAD/OPTIONS request to another host
  before sending. Empty bodies and dummy ids reduce impact, but **even these requests can change
  state**, so use an isolated test instance. Staged shell drafts need the staged transport library.
  A draft copied without its guard fails closed. GraphQL POST drafts also require localhost.
- **Side-effecting paths are skipped.** GET can still trigger work. So websec excludes paths that
  look like `/cron`, `/seed`, `generate`, `/trigger`, `/sync`, `/send`, `/run`, `upload`, `/refresh`,
  `/rebuild`, `/process`, `/dispatch`, `/import`, `/export` or `/scrape` from every probe.
- **Redirects are never followed.** websec treats a `3xx` from a protected route as a refusal. It
  does not follow the redirect to a login page that would read as `200`.
- **Status codes are observations, not proof.** A success response alone does not establish data
  access. A redirect, a `401`/`403` or an empty body alone does not establish authorization.

## Before you start

1. Run a **complete** static pass on the code that the TEST instance runs:

   ```bash
   websec run ./my-app
   ```

   `websec dynamic` reads `websec-out/latest/FACTS.json` by default. `latest` advances only after a
   completed run. Use `--facts <path>` to choose a specific run and `--out <dir>` to change the
   output base.

2. Read the briefing. Confirm the **tenant boundary** and **auth model** with whoever owns the
   app. The cross-tenant check has no meaning for a single-tenant app.

3. Have a running TEST instance and, for `--config`, two test identities in **two different
   tenants**, each owning a private record you can recognize.

## Authenticated cross-tenant BOLA (`--config`)

The check logs in two identities (`agentA`, `agentB`). It then tries each identity against the
other tenant's data in both directions (A to B and B to A). It uses GET routes whose **only** path
parameter is the tenant parameter.

### 1. Write the config

Start from [`dynamic-config.example.json`](../../dynamic-config.example.json) at the repository root.
That file is in the source repository, not in the installed package. Copy it from a reviewed
checkout, or write the JSON yourself:

```bash
cp dynamic-config.example.json dynamic-config.json
echo "dynamic-config.json" >> .gitignore      # it holds TEST credentials
```

| Field | Default | Meaning |
|---|---|---|
| `target` | required | Base URL of the TEST instance |
| `login_path` | `/api/auth/login` | JSON login endpoint, POSTed once per role |
| `token_json_path` | `tokens.accessToken` | Dotted path to the bearer token in the login response |
| `user_json_path` | `user` | Dotted path to the user object in the login response |
| `tenant_field` | `groupIds` | Field on the user object holding the tenant id or ids (a list or a single value) |
| `tenant_path_param` | `groupId` | The `{param}` in route templates that is the tenant boundary |
| `roles.agentA`, `roles.agentB` | required | The login body for each identity, sent as-is (keys starting with `_` are dropped). Use whatever field names your login expects, such as `email` or `username` |
| `application_id`, `build_id` | optional | The deployed application and build identity, attached as provenance to confirmed leaks |
| `bola_controls` | optional | Fixture controls that make a definite verdict possible (see below) |

`bola_controls`:

| Field | Meaning |
|---|---|
| `expected_policy` | Must be `tenant-isolated` |
| `identity_path` | Relative GET path (starts with `/`, no `{params}`) that returns the signed-in identity |
| `identities.agentA` / `agentB` | `{json_path, value}` that each identity's `identity_path` response must show. Same `json_path`, different values |
| `resources[<route template>].agentA` / `agentB` | `{json_path, value}` marking a private record owned by each identity's tenant on that route |

Provision distinct private records owned by each test identity. Credentials stay in this file.
websec reads them at runtime and never writes them to artifacts.

### 2. Run it

```bash
websec dynamic --config dynamic-config.json --facts websec-out/latest/FACTS.json
```

The summary line reads like
`N/M controlled reads blocked · K confirmed leak(s) · I inconclusive`, and each confirmed leak
prints as `LEAK <direction> <path>`.

### 3. Read the verdicts

Each check has a **state**:

| State | When |
|---|---|
| `confirmed-vulnerable` | All controls passed: both identity checks, the owner read its own marker, an anonymous request was denied, **and** the attacker read the victim's marker twice |
| `blocked` | Controls passed and the attacker got `401`/`403`/`404`, a soft-deny body, or provably empty data |
| `inconclusive` | Anything else, including **every** result when `bola_controls` is missing or mismatched |
| `not-tested` | No eligible GET route had the tenant parameter as its only parameter |

> [!IMPORTANT]
> Without `bola_controls`, websec cannot confirm a leak *or* confirm isolation. websec reports a
> `200` with data as "candidate cross-tenant data" for you to investigate, and the run exits `3`.
> HTTP status alone does not prove access control. Conclusions apply only to the identities and
> fixtures you supplied.

The check stops as `inconclusive` if either login fails. It also stops as `inconclusive` if both
identities resolve to the same tenant.

## Unauthenticated reachability (`--unauth`)

```bash
websec dynamic --unauth --target http://localhost:3000
```

This runs two read-only checks with no credentials:

1. **Reachability.** It sends a GET to each data-read route that has no unfilled `{param}` (up to
   50). It records only the status code and byte size, never the body. Verdicts include `protected`,
   `redirect (likely to login)`, `soft-deny`, `OPEN-no-auth`, `open-empty` and `404`.
2. **Forged-token check.** This check covers each GET route (up to 60) that refuses an anonymous
   request. It presents a structurally valid JWT with a **deliberately invalid signature**, as a
   bearer token and in each auth cookie name recon found. A route that then answers `2xx` is a
   `candidate-bypass`. It is a lead to verify, not a confirmed bypass.

Take these two warnings seriously:

- **Fail-open suspected.** Suppose nothing enforced auth. In a test environment, the likeliest cause
  is an unconfigured or erroring auth provider that lets every request through. Configure a valid
  (even dummy) provider and re-run before you conclude that authentication is missing. Until you
  observe an auth-enforced response, treat all authN/authZ results as untrustworthy.
- **Target unreachable.** If every request failed at the transport layer, nothing was tested. That
  is not a clean result.

websec reports endpoints over the caps as untested. It does not drop them silently.

### Write-verb enforcement (`--probe-writes`, localhost only)

```bash
websec dynamic --unauth --probe-writes --target http://localhost:3000
```

This adds unauthenticated POST/PUT/PATCH/DELETE requests (up to 80 endpoints). Each request has an
empty `{}` body, and `websec-nonexistent-id` replaces path parameters. It also extends the
forged-token check to write routes. Verdicts are status observations only: `auth-enforced`
(`401`/`403`), or `candidate unauthenticated response` (`2xx`) to investigate. `404`/`405` and
validation errors are inconclusive, never an auth signal. Validation can run before authentication,
and a `2xx` may be public or a soft denial.

`--config` and `--unauth` are separate modes. If you pass both, only `--unauth` runs.

## Results, exit codes and calibration

Each dynamic run gets its own directory under `websec-out/runs/`. The directory contains:

- `dynamic-findings.json` (`--config`) or `dynamic-unauth-findings.json` (`--unauth`)
- `findings-ledger.json`, `REPORT.md`, `CONSTITUTION.md`, `FACTS.json` and `coverage.json`, with
  the dynamic evidence merged in

| Exit | Meaning |
|---|---|
| `1` | A finding with dynamic evidence (a verified cross-tenant leak) is CRITICAL. Checked first |
| `3` | Some requested checks were inconclusive or not tested, and nothing was confirmed; `latest` is not advanced |
| `0` | Checks completed and no dynamic check confirmed a CRITICAL finding |
| `2` | Argument or configuration error; no run directory is reserved |

Read these exit codes with two points in mind:

- **A confirmed leak wins.** A run with a confirmed leak *and* inconclusive rows exits `1`. It prints
  a stderr note that the checks were also incomplete, and records `gate.failure_kind =
  findings+incomplete`. `3` is common on its own, because any inconclusive row, cap overflow or
  error marks the run incomplete. Read the per-row results. Do not treat `3` as a tool failure.
- **Static findings do not set the exit code.** The merged ledger includes the static recon
  findings from the `FACTS.json` you supplied, but `websec run` already gated those. `dynamic`
  gates only what it confirmed (`gate.static_findings_not_gated` counts the rest).

websec folds confirmed dynamic results into your **local** calibration overlay
(`~/.cache/websec-validator/`, or `$WEBSEC_CALIBRATION_HOME`). So `P(real)` adapts to your apps over
time. The overlay never leaves your machine.

## Staged probe drafts (`probes/`)

Every `websec run` stages a probe library tailored to the app in
`websec-out/runs/<generated>/probes/`. The drafts include BOLA reads and writes, mass assignment,
JWT attacks, forged tokens, SSRF, rate limits, uploads and more. What recon found decides which
drafts websec stages. Staging sends nothing.

- `probe-context.json` holds **this** app's real routes, auth scheme, token location, sensitive
  fields and tenant keys. Every draft carries a banner that says its example values are
  placeholders.
- The briefing's §5 lists each staged probe, its attack class and what it needs from you.
- Probes read auth and ids from environment variables: `TARGET`; `TOKEN_A`/`TOKEN_B`, or
  `COOKIE_A`/`COOKIE_B`, or `APIKEY`; `OBJ_A`/`OBJ_B`; `GROUP_A`/`GROUP_B`. The header of each
  draft lists its exact needs.

To run a probe, first finalize the draft against `probe-context.json` (the agent or you can do
this). Then run it:

```bash
cd websec-out/runs/<generated>/probes
TARGET=http://localhost:3000 \
TOKEN_A=<test-token-tenant-A> TOKEN_B=<test-token-tenant-B> \
GROUP_A=<tenant-A-id> GROUP_B=<tenant-B-id> \
bash bola-cross-tenant.sh
```

Rules for agents and humans alike:

- Review every draft before running it. Run one approved probe at a time.
- Never fabricate or commit credentials.
- Use known-positive and known-negative identities and resources. A `200` from a draft is a lead
  ("returned data for the OTHER tenant? verify"), not a confirmed vulnerability.
- Keep finalized probes after you run them. Re-run them after a fix to show that the access is still
  blocked.

## Aim the pentest instead of competing with it

Dynamic scanners rediscover at runtime, at great expense, much of what is already visible in the
source. The briefing uses the static results to aim the scanners:

- **§4b, predicted alerts.** websec maps static findings that have a known dynamic signature to the
  scanner alert they will produce. For example, `missing-csp` maps to ZAP 10038/10055, `sqli` to ZAP
  40018 or sqlmap, and `ssrf` to ZAP OAST 40046. Each mapping names the source location that causes
  it. Fix those findings and the scan comes back clean on them. The scan then confirms the fixes and
  does not discover anything.
- **§4b, blind spots.** These are classes that no scanner finds automatically, with the reason why.
  Examples are BOLA, missing auth, mass assignment, RLS gaps, JWT verification options, committed
  secrets and supply-chain issues. **A clean scan is not "safe."**
- **§5b, a phased runbook** against `$BASE_URL`, your own test instance. Phase 1 is safe read-only
  recon. Phase 2 is authorization testing with two identities, the class scanners miss. Phase 3 is
  injection fired only at sink-backed endpoints, gated behind an explicit authorization warning.
  Every item names a real target and a confirm/disconfirm oracle. websec stages these items. It
  never runs them.

### Close the loop: `websec calibrate --ingest-dast`

```bash
websec calibrate --ingest-dast zap.json --ledger websec-out/latest/findings-ledger.json
```

This command works offline. It matches a real scan report against the ledger's DAST-predictable
findings. It folds **evidence-bound** verdicts into your local calibration overlay.

- **Matching is exact, not by class.** A scanner alert confirms a finding only when the plugin id
  maps to the finding's class *and* the full context matches: `application_id`, `build_id`,
  `identity`, `endpoint`, `method` and `parameter`. Authenticated identities also need
  `auth_verified: true`. Attach this context as a `dast_context` envelope to your report and ledger.
- **Report shapes read:** ZAP-style JSON (`site[].alerts[]` with numeric `pluginid` and `instances`),
  or a generic `alerts[]` list carrying ZAP plugin ids. Matching uses numeric ZAP plugin ids from
  the prediction table. websec does not parse Nuclei output, even though §4b names Nuclei as the
  expected scanner for some predictions. A report or ledger that is not valid JSON is a usage error
  (exit `2`).
- **Silence is not refutation.** A finding that the scan did not flag stays **unjudged**. A
  passive-only baseline cannot test SQLi, so its silence proves nothing. To refute a finding, you
  need an explicit `checks[]` row for that exact context, with `completed: true`,
  `coverage_complete: true`, `auth_verified: true` and `outcome: "not-vulnerable"`. Do not
  manufacture these rows from an empty report. Conflicting positive and negative evidence stays
  unjudged.
- **Blind-spot classes are never scored**, because a scanner's silence there means nothing.
- If nothing matched, the command says so and exits `2`. websec folds nothing.

The synthetic fixtures in [`docs/security-review/examples/`](../security-review/examples/README.md)
show the exact `dast_context`, positive and negative shapes. They are format examples only. Never
ingest them into a real project's calibration.

## See also

- [AI agents](ai-agents.md): what the agent should do with the briefing before any live step.
- [Triage and suppression](triage-and-suppression.md): working the findings ledger.
- [How it works](../concepts/how-it-works.md) and [METHODOLOGY](../METHODOLOGY.md): why each check
  exists.
- [Outputs reference](../reference/outputs.md) and [CLI reference](../reference/cli.md).
