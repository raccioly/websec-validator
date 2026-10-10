# Language and framework support

This page says what `websec` actually analyses in each language, and what it only recognises. Use
it to decide how much a clean run on your stack is worth. Everything here comes from the code: the
extractors in `src/websec_validator/extractors/`, the profile catalog in
[`profiles.py`](../../src/websec_validator/extractors/profiles.py), the walker in
[`base.py`](../../src/websec_validator/extractors/base.py) and the scanner registry in
[`scanners.py`](../../src/websec_validator/scanners.py).

> [!IMPORTANT]
> A completed run with no findings means the requested checks ran and matched nothing. It does not
> mean the code is secure, and for most languages below it means much less than that. Read
> [What a clean run means for your stack](#what-a-clean-run-means-for-your-stack) before you rely
> on one.

## Support tiers at a glance

| Tier | What websec does | Languages (canonical id) |
|---|---|---|
| 1. Deep analysis | All 22 extractors, with rules written for these languages' idioms and frameworks | Python (`python`), JavaScript (`node`), TypeScript (`typescript`) |
| 2. Named sink checks | A bounded profile of direct-syntax command/query checks (plus literal routes for Java and .NET). The other extractors still read the files, but their rules target tier-1 idioms | Java (`java`), C# (`csharp`), Go (`go`), Ruby (`ruby`), PHP (`php`) |
| 3. Configuration or manual checks only | One explicit configuration check, or a manual-review placeholder. No injection, secret or authorization rules. Reported as a `thin_language_coverage` gap | Kotlin (`kotlin`), Swift (`swift`), Objective-C (`objective-c`), Rust (`rust`), C (`c`), C++ (`cpp`) |
| 4. Recognised, not analysed | Counted and named in `coverage.json`; never read or matched | See [tier 4](#tier-4-recognised-but-not-analysed) |

The split between tiers 1, 2 and 3 is the code's own: `coverage.thin_languages()` treats `python`,
`node` and `typescript` as first-class, credits languages that have a profile with a `sink` check,
and reports every other language it read as thin.

Two capabilities sit across the tiers:

- **Route discovery** uses [OWASP Noir](https://github.com/owasp-noir/noir) when it is installed,
  plus websec's own registration lanes. See [Route discovery](#route-discovery).
- **Third-party scanners** run only under `--scan`. Most are language-agnostic; three are selected
  per language. See [Scanners under `--scan`](#scanners-under---scan).

## Language matrix

| Language (id) | Suffixes | Tier | Named profiles | Language-specific scanner (`--scan`) | Dependency reachability |
|---|---|---|---|---|---|
| Python (`python`) | `.py` | 1 | — | Bandit | Yes |
| JavaScript (`node`) | `.js` `.jsx` `.mjs` `.cjs` `.vue` `.svelte` | 1 | — | — | Yes (npm) |
| TypeScript (`typescript`) | `.ts` `.tsx` `.mts` `.cts` | 1 | — | — | Yes (npm) |
| Java (`java`) | `.java` | 2 | `java-spring`, `android` | — | `n/a` |
| C# (`csharp`) | `.cs` (`.csproj` read as a manifest) | 2 | `dotnet` | — | `n/a` |
| Go (`go`) | `.go` | 2 | `go` | gosec | `n/a` |
| Ruby (`ruby`) | `.rb` | 2 | `ruby` | Brakeman | `n/a` |
| PHP (`php`) | `.php` | 2 | `php` | — | `n/a` |
| Kotlin (`kotlin`) | `.kt` `.kts` | 3 | `android` | — | `n/a` |
| Swift (`swift`) | `.swift` | 3 | `ios` | — | `n/a` |
| Objective-C (`objective-c`) | `.m` `.mm` | 3 | `ios` | — | `n/a` |
| Rust (`rust`) | `.rs` | 3 | `rust` | — | `n/a` |
| C (`c`) | `.c` `.h` | 3 | `native` | — | `n/a` |
| C++ (`cpp`) | `.cpp` `.hpp` | 3 | `native` | — | `n/a` |

Notes on the columns:

- **Suffixes** are `profiles._LANG`. `.vue` and `.svelte` files are labelled `node`.
- **Dependency reachability** applies to CVEs found under `--scan`. websec looks for an import of
  the vulnerable package in first-party source and tags the CVE `imported` or `declared-only`. It
  parses JS/TS and Python imports only; CVEs in other ecosystems are tagged `n/a` rather than
  guessed. See [How it works: prioritization](../concepts/how-it-works.md#prioritization).
- Other file types the extractors read without a language label: HTML and Jinja templates
  (`.html` `.htm` `.jinja` `.jinja2` `.j2`), Prisma schemas (`.prisma`), GraphQL SDL and AppSync
  VTL resolvers (`.graphql` `.gql` `.vtl`).

## Tier 1: deep analysis

All 22 extractors run over every analysable file. Their patterns are written against JS/TS and
Python idioms (`req.body`, `request.args`, decorators, `res.json(...)`), and several lanes parse
Python with the standard-library `ast` module. These are the framework-aware lanes the code
contains:

| Framework or surface | What websec does | Module |
|---|---|---|
| Express (and routers written as `obj.get('/path', …)`, such as Hono or itty-router) | Generic router-call route heuristic; per-route middleware guards; global `app.use(auth)`; router-mount auth resolved through the local import graph | `routes.py`, `authz.py` |
| Fastify | `onRequest`/`preHandler` auth hooks (global or instance-scoped) credited as guards | `authz.py` |
| Name-based guards (NestJS, Flask-Login, Passport, NextAuth and similar) | Guard names such as `@UseGuards`, `@Roles`, `@login_required`, `@jwt_required`, `passport.authenticate`, `getServerSession` credited by name | `authz.py` |
| Next.js | App Router `route.ts`/`route.js`/`route.tsx` routes (regex fallback); `middleware.ts`/`proxy.ts` matcher coverage; `next.config.*` security-header gaps | `routes.py`, `authz.py`, `transport_security.py` |
| tRPC | Local router composition; HTTP paths only through visible Express mounts | `trpc_routes.py` |
| Supabase Edge Functions | `supabase/functions/<name>/index.ts` with `Deno.serve` becomes `/functions/v1/<name>` | `routes.py` |
| AWS SAM | `Api`/`HttpApi` events and Function URLs, including `AuthType: NONE` | `routes.py` |
| Raw HTTP servers | `http.createServer`, `Bun.serve`, Python `http.server`; a single `/*` catch-all with a note when no path literal is recoverable | `routes.py` |
| Django | URLconf discovery from syntax, without importing modules; unresolved includes stay candidates; CSP on the exact returned template response | `django_urls.py`, `django_responses.py` |
| Flask | Decorator routes (regex fallback); Flask-SQLAlchemy model columns via `ast` | `routes.py`, `schemas.py` |
| FastAPI | Decorator routes (regex fallback); endpoint-local `Depends` guard evidence via `ast`; `UploadFile` upload provenance | `framework_auth.py`, `python_uploads.py` |
| Connexion | Literal top-level registration with a JSON or literal-subset YAML spec; guard detection narrowed to the `operationId` function | `connexion_routes.py`, `authz.py` |
| Data models | Pydantic, SQLAlchemy, Django models, Prisma, Mongoose, TypeORM, Zod, Sequelize; privileged-field extraction | `schemas.py` |
| Plain SQL | `CREATE TABLE` and row-level-security (`CREATE POLICY`, `ENABLE ROW LEVEL SECURITY`) in committed `.sql` files | `schemas.py`, `stack.py` |
| Password validators | Zod, Joi, yup, express-validator, class-validator blocks on a `password` field | `policy_consistency.py` |
| Templates and DOM | `innerHTML`, `dangerouslySetInnerHTML`, Vue `v-html`, Jinja `\|safe`, `mark_safe`, `Markup()` | `surface.py` |
| LLM SDKs | Vercel AI SDK, OpenAI, Anthropic, LangChain, litellm, Bedrock and Gemini call shapes | `llm_security.py` |
| Browser extensions | `manifest.json` with `manifest_version` (MV2/MV3) | `webext.py` |
| Request-to-sink flow | Bounded intraprocedural Python request-to-query flow; simple local JS assignments | `sql_flow.py`, `assigned_flow.py` |

Platform manifests (`wrangler.*`, `vercel.json`, `netlify.toml`, `serverless.yml`) and dependency
names in `package.json`/Python manifests add framework and datastore labels in `FACTS.json`. A
label is a hint, not analysis. Detected framework labels with no lane above (for example Koa,
Starlette, Sanic, Tornado, aiohttp, Angular) get the generic tier-1 rules only; their routes come
from Noir or the generic router heuristic.

Even in tier 1 the analysis is bounded: regex and AST passes with byte and node budgets. Aliases,
wrappers, cross-function flow, dynamic registration and deployment behaviour stay unverified.
[METHODOLOGY: scoped framework and adoption evidence](../METHODOLOGY.md#scoped-framework-and-adoption-evidence)
states each lane's limit.

## Tier 2 and 3: named-check profiles

A named profile is a small, fixed set of checks for direct syntax or explicit configuration. Run
`websec capabilities` to print the catalog as JSON; it reads no target.

```bash
websec capabilities
```

| Profile id | Languages | Check ids | What the check matches |
|---|---|---|---|
| `java-spring` | `java` | `java-direct-command`, `java-direct-query`, `spring-literal-routes` | `Runtime.getRuntime().exec` / `new ProcessBuilder`, and `executeQuery`/`executeUpdate`/`execute`/`createQuery`/`createNativeQuery`, where a request read (`request.getParameter`/`getHeader`/`getQueryString`) appears directly in the argument. Literal `@GetMapping`-style routes |
| `dotnet` | `csharp` | `dotnet-direct-command`, `dotnet-direct-query`, `dotnet-literal-routes` | `Process.Start` / `new ProcessStartInfo`, and `new SqlCommand` / `FromSqlRaw` / `ExecuteSqlRaw` / `ExecuteSqlCommand`, fed directly by `Request.Query`/`Form`/`Headers[...]`. Literal `MapGet(...)` and `[HttpGet("...")]` routes |
| `go` | `go` | `go-direct-command`, `go-direct-query` | `exec.Command(Context)` and `.Query`/`QueryRow`/`Exec(Context)` fed directly by `r.FormValue(...)` or `r.URL.Query().Get(...)` |
| `ruby` | `ruby` | `ruby-direct-command`, `ruby-direct-query` | `system`/`exec`/`IO.popen` and `.execute`/`find_by_sql`/`where` fed directly by `params[...]`; literal-key hash `where` conditions count as parameterized |
| `php` | `php` | `php-direct-command`, `php-direct-query` | `system`/`exec`/`shell_exec`/`passthru`/`popen` and `->query`/`->exec`/`mysqli_query` fed directly by `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE` |
| `android` | `java`, `kotlin` | `android-explicit-cleartext` | `android:usesCleartextTraffic="true"` in `AndroidManifest.xml` |
| `ios` | `swift`, `objective-c` | `ios-explicit-ats-exception` | `NSAllowsArbitraryLoads`, `NSAllowsArbitraryLoadsInWebContent` or `NSAllowsArbitraryLoadsForMedia` set to true in `Info.plist` |
| `rust` | `rust` | `rust-reqwest-invalid-certificates` | `.danger_accept_invalid_certs(true)` or `.tls_danger_accept_invalid_certs(true)` in a service that references `reqwest` |
| `native` | `c`, `cpp` | `native-memory-review` | Manual check: source inventory only |

Every profile carries this limitation, verbatim from the catalog: *"Direct syntax only; aliases,
binding resolution, authorization, build variants and cross-function flows require review."* The
`native` profile adds: *"C/C++ source inventory only; memory safety is not analyzed."*

How profiles are selected and reported:

- Profiles are applied per **service**. A service is the nearest directory holding a manifest
  (`package.json`, `pyproject.toml`, `requirements*.txt`, `setup.py`, `Pipfile`, `pom.xml`,
  `build.gradle`, `build.gradle.kts`, `go.mod`, `Gemfile`, `composer.json`, `Cargo.toml`,
  `Package.swift`, `CMakeLists.txt` or a `.csproj`). Manifest boundaries approximate deployment
  boundaries; they do not prove them.
- A profile is selected when one of its languages appears in the service. `android` and `ios` are
  selected only when an `AndroidManifest.xml` or `Info.plist` is found.
- Each selected check is recorded in `coverage.json` under `profiles[].checks[]` with a `status`:
  `completed` (files were examined), `unknown` (no applicable input) or `manual`. Any check that is
  not `completed` adds a `profile_scope` gap.
- Tier-2 and tier-3 files are still read by the 22 extractors. Their rules target tier-1 idioms, so
  an incidental match is possible but is not claimed coverage. For routes in these languages, guard
  recognition is name-based and tuned on JS/TS and Python frameworks, so treat "no visible guard" as
  a weaker lead.
- Tier-3 languages also produce a `thin_language_coverage` gap: *"files were read, but websec has no
  injection, secret or authorization rules for these languages."*

## Tier 4: recognised but not analysed

These suffixes are program source that no extractor reads (`base.UNANALYZED_SOURCE_EXT`). The walker
lists them in `coverage.files.unsupported`, counts them per language in
`coverage.files.unanalyzed_languages`, and adds two gaps: `unsupported_source` and
`language_without_analyzer`. Neither gap makes the run incomplete, because nothing failed to run.

| Family | Languages (id) and suffixes |
|---|---|
| JVM and functional | Scala (`scala`) `.scala` · Clojure (`clojure`) `.clj` `.cljs` `.cljc` · Groovy (`groovy`) `.groovy` `.gradle` |
| BEAM | Elixir (`elixir`) `.ex` `.exs` · Erlang (`erlang`) `.erl` `.hrl` |
| Scripting and systems | Perl (`perl`) `.pl` `.pm` · Lua (`lua`) `.lua` · R (`r`) `.r` · Julia (`julia`) `.jl` · Dart (`dart`) `.dart` · Zig (`zig`) `.zig` · Nim (`nim`) `.nim` · Crystal (`crystal`) `.cr` · Haskell (`haskell`) `.hs` · OCaml (`ocaml`) `.ml` · F# (`f#`) `.fs` `.fsx` · Tcl (`tcl`) `.tcl` · Visual Basic (`visual-basic`) `.vb` · Pascal (`pascal`) `.pas` · D (`d`) `.d` · Fortran (`fortran`) `.f90` |
| Shells | Shell (`shell`) `.sh` `.bash` `.zsh` · PowerShell (`powershell`) `.ps1` `.psm1` |
| Server-side templates | ERB (`erb-template`) `.erb` · Haml (`haml-template`) `.haml` · Slim (`slim-template`) `.slim` · Twig (`twig-template`) `.twig` · Handlebars (`handlebars-template`) `.hbs` · EJS (`ejs-template`) `.ejs` · Pug (`pug-template`) `.pug` · Mustache (`mustache-template`) `.mustache` · Liquid (`liquid-template`) `.liquid` · Blade (`blade-template`) `.blade` |

Two special cases:

- **SQL (`sql`).** The language map names `.sql`, but `.sql` is deliberately not in the unanalysed
  set: `schemas.py` and `stack.py` read committed `.sql` files for `CREATE TABLE` and row-level
  security. SQL files therefore never appear as a `language_without_analyzer` gap.
- **Gradle (`groovy`).** `build.gradle` is read as a manifest for language and framework labels, but
  its `.gradle` suffix is also counted as unanalysed Groovy. The gap text says the file was never
  read; for `build.gradle` that is true of its code, not of its manifest metadata.

File types outside both sets (YAML, JSON, TOML, Markdown and so on) are not presumed to be source.
Specific extractors still read named configuration files: see [Configuration and supply-chain
surfaces](#configuration-and-supply-chain-surfaces).

## Route discovery

The endpoint inventory is the attack surface, so route coverage matters as much as language
coverage.

- **OWASP Noir.** When `noir` is on `PATH`, `websec run` invokes it on every run (not only under
  `--scan`). Noir parses many frameworks across languages; that coverage is Noir's, documented in
  [the Noir project](https://github.com/owasp-noir/noir), not a claim websec makes. websec drops
  Noir routes under skipped directories, `--exclude` paths, frontend API-client code and
  fixture/example directories.
- **Without Noir, when an installed Noir fails, or when Noir finds zero routes**, websec falls back
  to its regex pass: Next.js App Router files, FastAPI and Flask decorators, and the generic
  router-call heuristic. The `routes.engine` field in `FACTS.json` records which engine produced
  the list, and `routes.noir` records Noir's outcome (`state` `ok`, `absent` or `failed`, with a
  `reason`). A failed Noir is reported on the console and as a `route_engine` coverage gap, and
  `websec doctor` shows whether the installed Noir works.
- **Always added, whichever engine ran:** the router-call heuristic, Supabase Edge Functions, AWS
  SAM, raw HTTP servers, Connexion and tRPC registration, Django URLconf discovery, and the literal
  Spring and ASP.NET routes from the `java-spring` and `dotnet` profiles.
- The router-call heuristic matches the shape `<object>.<verb>('/path', …)`. Routers in other
  languages written in that shape can also match; that is incidental, not claimed support.

Install Noir for anything beyond tier 1; the regex fallback is narrow. Unresolved Django includes
and similar cases are kept as candidates and listed in `coverage.route_discovery`, never silently
promoted to routes.

## Scanners under `--scan`

The registry holds 11 scanner entries. A plain `websec run` detects them and executes none; `--scan`
executes the installed, runnable ones. `--scanners` narrows the set and makes each named scanner
required.

| Key | Category | Selected when | Notes |
|---|---|---|---|
| `trivy` | SCA, secrets, misconfiguration | Always | Also produces the SBOM for `--sbom` |
| `osv-scanner` | SCA | Always | Runs recursively; the same CVE from Trivy and OSV-Scanner merges into one row |
| `gitleaks` | Secrets (git history) | Always | `--scanners gitleaks` also selects `gitleaks-dir` |
| `gitleaks-dir` | Secrets (working tree) | Always | Second pass of the same binary |
| `semgrep` | SAST | Always | Invoked with `--config auto` plus websec's bundled rules |
| `checkov` | IaC | Always | |
| `bandit` | SAST | `python` detected | Built-in defaults; target `.bandit`/pyproject settings and inline `nosec` are ignored |
| `gosec` | SAST | `go` detected | |
| `brakeman` | SAST (Rails) | `ruby` detected and an `app/` directory at the scan root | Brakeman's own Rails precondition. Without `app/`, `websec doctor` lists it as not applicable to the target and it is not run |
| `trufflehog` | Secret verification | Only with `--verify-secrets` | Sends discovered credentials to their providers; off by default |
| `prowler` | Cloud posture | Never executed | Detected and reported only; the registry has no invocation for it |

Scanners are third-party executables with their own network and trust boundaries. For example,
Semgrep's `--config auto` fetches registry rules, and Trivy and OSV-Scanner consult advisory
databases. websec's own recon makes no network calls unless you opt in; see the
[CLI reference](cli.md) for `--network` and `--verify-secrets`.

## Configuration and supply-chain surfaces

These are read regardless of application language:

| Surface | What is checked | Module |
|---|---|---|
| GitHub Actions (`.github/workflows/*.yml`) | Expression injection (run-position aware), actions pinned to mutable tags | `iac_ci.py` |
| Dockerfiles, `docker-compose*.yml`, `compose.yml` | Container runs as root, no health check; `docker.sock` and host-namespace mounts, `privileged`, host network or dangerous `cap_add`, secret-named `environment:` values in a file that also declares `secrets:` | `iac_ci.py` |
| Terraform state (`*.tfstate`) | Committed state files | `iac_ci.py` |
| AWS CDK (TypeScript/JavaScript) | AppSync `API_KEY` default or additional authorization, WAF used as an app-layer control, build-injected public variables | `iac_ci.py`, `client_exposure.py` |
| AppSync GraphQL SDL and VTL | Introspection, subscription authorization | `graphql.py` |
| `.gitleaksignore` | Secret suppression covering a real secrets file | `iac_ci.py` |
| Committed `.env*` files (gitignored and test files skipped) | Credential-shaped values by value shape; `*.example`/`*.sample` files and placeholders are reported at a lower tier | `client_exposure.py` |
| Agent and MCP config (`.mcp.json`, `.claude/settings.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md` and others) | Hidden Unicode, fetch-and-execute hooks, blanket MCP auto-approve, base-URL overrides, unpinned MCP servers, literal secrets in MCP `env`/`headers` | `agent_config.py` |
| npm manifests and lockfiles | Malicious lifecycle scripts; lockfile drift (JSON lockfiles only); advisory unpinned and dependency-confusion names | `dependencies.py` |
| Python manifests (`requirements*.txt`, `pyproject.toml`, `Pipfile`) | Advisory unpinned and dependency-confusion names | `dependencies.py` |

The offline `dependencies` extractor covers the `npm` and `pip` ecosystems. `--network` adds a
registry existence check for npm and PyPI names. For CVEs in other ecosystems (Go modules, crates,
gems, Composer, Maven, NuGet), rely on Trivy or OSV-Scanner under `--scan`.

## What a clean run means for your stack

A completed run is a statement about execution, not protection. `coverage.json` always carries
`"protection_complete": false` and the limitation *"Completed execution does not prove absence of
vulnerabilities or full framework coverage."* Before trusting an empty findings list:

1. **Open `coverage.json`** (in the run directory; see [Outputs](outputs.md)) and read `gaps`. Gaps
   with `"execution": true` mean a requested check did not complete. Gaps with
   `"execution": false` are scope limits: `language_without_analyzer`, `thin_language_coverage`,
   `profile_scope`, `walker_policy`, `excluded_scope`, `skipped_directory_code`, `scope_missed`,
   `route_engine` and others.
2. **Check `files.unanalyzed_languages`** for languages that were never read, and `profiles` for
   which named checks ran and with what status.
3. **Check `files.skipped_counts` and `files.skipped_code_dirs`.** Directories such as `build`,
   `dist`, `out`, `target`, `vendor` and `coverage` are skipped by policy, as are vendored and
   minified bundles. They are counted and disclosed, not analysed. When one of those six
   directories holds files with an analysable suffix, they are counted and listed in
   `files.skipped_code_dirs` with a `skipped_directory_code` gap.
4. **Check `routes.engine` in `FACTS.json`.** A regex fallback on a non-tier-1 stack usually means
   most endpoints were not discovered.

When the tree contains source but none of it is analysable, `coverage.files.no_analyzable_source`
is `true` and the console and report lead with **NO ANALYZABLE SOURCE**. By default the exit code is
still `0`. To make CI fail instead, pass `--require-analyzed`:

```bash
websec run . --require-analyzed
```

The run then exits `3` with gate verdict `no-analyzable-source`. This only fires when *no* file was
analysable. A mixed repository, for example an Elixir service beside one JavaScript file, completes
normally and reports the Elixir files as a gap, so read the gaps rather than relying on the exit
code alone. For execution failures (scanner timeouts, read caps, a missing required scanner), use
`--require-complete`. Exit codes are listed in the [CLI reference](cli.md).

## Requesting a language or framework

- **Open a feature request** with the
  [feature-request template](https://github.com/raccioly/websec-validator/issues/new?template=feature-request.yml).
  It asks for the gap, the deterministic signal a detector would key on (the tool contains no LLM,
  so extractors must be deterministic), a sanitized example of the vulnerable pattern, and whether
  an existing scanner such as a Semgrep rule could cover it instead.
- **Attach a reproduction** from a real run: the relevant part of `coverage.json` showing the
  `language_without_analyzer` or `thin_language_coverage` gap, and `routes.engine` from
  `FACTS.json`.
- **Research proposals** (`websec research example`, `websec research evaluate --proposal`) are
  data-only cases evaluated against an allowlist of already-shipped detectors. They can show that an
  existing detector misses a concrete pattern, but they cannot add a language. Passing means
  eligible for human review, not automatic promotion.
- Contributors adding a profile or extractor follow [CONTRIBUTING.md](../../CONTRIBUTING.md). A new
  language id or profile id must be named on this page; the docs tests fail otherwise.

## See also

- [How it works](../concepts/how-it-works.md): the extractor families and the deterministic/agent split
- [Outputs](outputs.md): where `coverage.json` and `FACTS.json` live and what they contain
- [CLI reference](cli.md): `--scan`, `--scanners`, `--require-analyzed`, `--require-complete`, exit codes
- [Monorepos](../guides/monorepo.md): service boundaries and per-service scoping
- [METHODOLOGY](../METHODOLOGY.md#layer-1--recon-the-22-extractors): the reasoning behind each extractor
- [Glossary](../glossary.md)
