# Using websec-validator in a monorepo

This guide is for repositories that hold several services or packages: npm/pnpm/Yarn workspaces,
Turborepo or Nx layouts, a Python backend next to a Next.js frontend, or a set of Rust crates. It
covers how websec draws service boundaries, what changes when you scan a subdirectory instead of
the root, and how to split CI per service without losing coverage.

**Short version:** run from the repository root, scope non-product packages with `.websec-ignore`
or `--exclude`, and keep a root run even if you also gate per service.

## How websec sees a monorepo

### Service boundaries come from the nearest manifest

During the stack pass, every product manifest in the tree defines a service rooted at its
directory. The recognised manifests are:

`package.json`, `pyproject.toml`, `requirements*.txt`, `setup.py`, `Pipfile`, `pom.xml`,
`build.gradle`, `build.gradle.kts`, `go.mod`, `Gemfile`, `composer.json`, `Cargo.toml`,
`Package.swift`, `CMakeLists.txt` and `*.csproj`.

A file belongs to the **deepest** service root that contains it. The repository root (`.`) is
always a service, so files outside any nested manifest fall back to it. Manifests under test,
example or fixture paths are left out of the inventory unless you pass `--include-fixtures` (or the
repository has no product manifest at all).

The inventory is written to `FACTS.json` → `stack.service_inventory` and `coverage.json` →
`service_inventory`. Example from a small synthetic workspace:

```json
[
  {"id": ".",               "manifests": ["package.json"],                     "frameworks": []},
  {"id": "apps/web",        "manifests": ["apps/web/package.json"],            "frameworks": ["next", "react"]},
  {"id": "services/api",    "manifests": ["services/api/package.json"],        "frameworks": ["express"], "datastores": ["dynamodb"]},
  {"id": "services/worker", "manifests": ["services/worker/requirements.txt"], "frameworks": ["flask"]}
]
```

`FACTS.json` → `stack.monorepo` is `true` when there is more than one service, or when the root has
a `pnpm-workspace.yaml`, `lerna.json`, `nx.json` or `turbo.json`.

Route, access-control, sink and cookie evidence is attributed to a service through these
boundaries, which keeps each service's route and datastore evidence separate. The stack extractor
records its own caveat: boundaries are **approximate**, and a declared dependency does not prove
installation or deployment.

> [!NOTE]
> A language whose build file is not on that list does not form a service. In a workspace with an
> Elixir app (`mix.exs`), those files fall under the nearest enclosing service, are not analysed,
> and appear in `coverage.json` → `files.unanalyzed_languages`. See
> [language support](../reference/languages.md).

### Repository-wide signals

Some browser-hardening checks treat a control found **anywhere** in the repository as present.
Examples are a clickjacking guard (`X-Frame-Options`, CSP `frame-ancestors`, helmet frameguard) and
CSRF token plumbing. In a monorepo, a guard in one app can therefore mask its absence in another.
Verify those controls per deployed app, ideally against the live response headers.

### Workspace package names

websec collects the `name` of every `package.json` and `pyproject.toml` in the repository. These
names feed the opt-in dependency-existence check: with `--network`, names your repository
publishes itself are **suppressed offline, before any request**, so an internal workspace package
is never sent to a public registry. `workspace:`, `file:`, `link:`, `portal:`, `catalog:` and
`npm:` specs are not treated as public registry declarations. This is a name list gathered from
manifests, not a resolved workspace dependency graph. Preview exactly what would be sent:

```bash
websec run . --network-dry-run
```

### Rust workspaces

Each `Cargo.toml` is a manifest boundary, so each crate directory in a Cargo workspace becomes its
own service in the inventory. websec does not read the `[workspace]` members table. Rust code gets
the named-check profile only (explicit `reqwest` invalid-certificate acceptance). Check
`websec capabilities` for its limits.

## Next.js header gap

Every `next.config.js`, `next.config.mjs` and `next.config.ts` in the tree is read, not only the
root one, so `packages/web/next.config.ts` is not invisible. For each one:

| Config | Finding |
|---|---|
| no `headers()` block | MEDIUM `nextjs-no-security-headers` (attack class `missing-csp`) |
| `headers()` present but missing CSP or `X-Frame-Options`/`frame-ancestors` | LOW `nextjs-partial-security-headers` |

A static read cannot see your CDN or edge. If headers are set upstream, confirm it against the live
response and record a dated `fingerprint:` acknowledgement whose reason names where they are
configured. See [triage and suppression](triage-and-suppression.md).

## Root run vs subdirectory run

Pointing websec at a subdirectory makes that directory the whole world for the run:

| | `websec run .` (root) | `websec run services/api` (subdirectory) |
|---|---|---|
| Service inventory | every service | only manifests under `services/api/` |
| Finding locations | relative to the repository root | relative to `services/api/` |
| `.websec-ignore` read | `./.websec-ignore` | `services/api/.websec-ignore` only. The root file is **not** applied. |
| Shared code in sibling packages | read | not read. Evidence in `packages/shared/` is invisible. |
| `--diff <ref>` | works | works; changes outside `services/api/` are ignored |
| `websec gate` (working-tree default) | works | works; only changes under `services/api/` are analysed |

Since 0.22.0, `--diff` and the working-tree default of `websec gate` translate Git's
repository-relative paths into paths relative to the target, and ignore changes outside it, where
no finding of that run can be. `diff-scope.json` records the target's position in the repository
as `repo_prefix` (`services/api/` here, empty at the root). Earlier releases compared the two
unconverted, so a subdirectory `--diff` gate classed every finding as untouched.

### Narrowing analysis with `--only`

`--only` narrows what is read and matched while the tree is still walked in full, so stack
detection, ignore policy and fixture classification stay the same. It takes file or directory
paths relative to the target:

```bash
websec run . --only services/api/src/routes.js --only services/api/src/auth.js
websec run . --only services/api
```

A directory selects every analysable file below it, on whole path components: `services/api`
does not select `services/api2/`. A requested path that selected no analysable file (absent,
excluded, empty, or an unsupported language) is listed under `FACTS.json` →
`analysis_scope.missed` and reported as a `scope_missed` coverage gap. If no entry selected
anything, the banner reads **REQUESTED SCOPE NOT ANALYZED**.

### Excluding packages

To leave packages out of a root run:

```bash
websec run . --exclude 'packages/legacy-admin/**' --exclude 'tools/**'
```

`--exclude` keeps a path out of recon and the static scanners. For committed, reviewable scoping,
put the same directories in the root `.websec-ignore` instead (findings are dropped and counted).
`websec init` searches four directory levels deep, so nested harnesses such as
`backend/capacity-test/` or `services/api/tests/` are proposed with their file counts.

## CI: one gate or one job per service

**One root job** is the simplest correct setup. It sees cross-service evidence and applies one
`.websec-ignore`:

```bash
websec run . --diff origin/main --fail-on high --require-complete
```

**A job per service** gives each team its own report and threshold. Give each its own output
directory and `.websec-ignore`, and gate it on a stored per-service baseline or, in PR mode, with
`--diff`:

```bash
for svc in services/api services/worker apps/web; do
  name=$(basename "$svc")
  websec run "$svc" --out "websec-out/$name" --require-complete \
    --fail-on high --baseline "baselines/$name/findings-ledger.json"
done
```

This loop runs every service, but its exit status is only the last service's. In a real job,
collect each exit code and fail at the end. In a CI matrix, the same command runs once per matrix
entry. Subdirectory jobs do not see
code in sibling packages, so keep a periodic root run as well. See
[GitHub Actions](ci/github-actions.md) and [other CI](ci/other-ci.md) for workflow syntax.

## See also

- [Adopting websec in an existing project](existing-projects.md)
- [Triage and suppression](triage-and-suppression.md)
- [CLI reference](../reference/cli.md)
- [Methodology](../METHODOLOGY.md)
