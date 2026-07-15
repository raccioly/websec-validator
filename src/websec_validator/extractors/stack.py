"""Stack extractor — languages, frameworks, package managers, datastores.

Monorepo-aware: aggregates every package.json / Python manifest in the tree
(node_modules excluded by SKIP_DIRS), so a backend/ service's Express + DynamoDB
deps are seen even when the repo root is just a workspace shell. Runs first; its
result is stashed on ctx.stack for later extractors.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_script_file, is_test_file


def _is_fixture_manifest(ctx: RepoContext, p) -> bool:
    rel = ctx.rel(p)
    return bool(is_test_file(rel) or is_script_file(rel))


def _product_first(ctx: RepoContext, paths: list, repo_has_product: bool) -> list:
    """Drop manifests under test/example/fixture dirs, per DocGuard field report F4.

    A Node CLI whose only prod dep is @babel/parser was flagged Express+Flask because its
    tests/fixtures/ and examples/ ship whole Express/Flask apps whose manifests got aggregated.

    The fallback is CROSS-LANGUAGE: keep fixture manifests only when the repo has NO product
    manifest of ANY language (a fixtures-only repo still gets a stack model instead of reading
    `languages: ?`). Without this, a Python project (product pyproject.toml, only fixture
    package.json — like websec itself) would resurrect its fixtures' Express and read as Node."""
    if getattr(ctx, "include_fixtures", False):
        return paths
    product = [p for p in paths if not _is_fixture_manifest(ctx, p)]
    if product:
        return product
    return [] if repo_has_product else paths

NODE_FRAMEWORKS = {"express": "express", "fastify": "fastify", "koa": "koa",
                   "@nestjs/core": "nestjs", "next": "next", "@hapi/hapi": "hapi",
                   "next-auth": "nextauth", "@remix-run": "remix", "svelte": "sveltekit",
                   "@apollo/server": "apollo-graphql", "graphql": "graphql"}
PY_FRAMEWORKS = {"fastapi": "fastapi", "flask": "flask", "django": "django",
                 "starlette": "starlette", "sanic": "sanic", "tornado": "tornado",
                 "aiohttp": "aiohttp"}
DATASTORES = {"pg": "postgres", "postgres": "postgres", "mysql": "mysql",
              "mysql2": "mysql", "mongodb": "mongo", "mongoose": "mongo",
              "@aws-sdk/client-dynamodb": "dynamodb", "@aws-sdk/lib-dynamodb": "dynamodb",
              "dynamodb": "dynamodb", "redis": "redis", "ioredis": "redis",
              "sqlite": "sqlite", "prisma": "prisma(sql)", "sequelize": "sql-orm",
              "typeorm": "sql-orm", "drizzle-orm": "sql-orm", "sqlalchemy": "sql-orm",
              "psycopg2": "postgres", "pymongo": "mongo", "boto3": "aws"}


class StackExtractor(Extractor):
    name = "stack"
    category = "inventory"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        langs, frameworks, managers, datastores = set(), set(), set(), set()

        _node_manifests = ctx.glob("**/package.json", 120)
        _py_manifests = (ctx.glob("**/requirements*.txt", 80) + ctx.glob("**/pyproject.toml", 80)
                         + ctx.glob("**/setup.py", 80) + ctx.glob("**/Pipfile", 80))
        # cross-language: is ANY manifest product code? (decides whether fixtures-only stacks
        # fall back to their fixture manifests — see _product_first)
        repo_has_product = any(not _is_fixture_manifest(ctx, p)
                               for p in (_node_manifests + _py_manifests))

        pkgs = _product_first(ctx, _node_manifests, repo_has_product)
        node_text = " ".join(ctx.text(p) for p in pkgs)
        if node_text:
            langs.add("node")
            managers.add("npm")
            for dep, label in NODE_FRAMEWORKS.items():
                if f'"{dep}"' in node_text or f'"{dep}/' in node_text:
                    frameworks.add(label)
            for dep, label in DATASTORES.items():
                if f'"{dep}"' in node_text:
                    datastores.add(label)
            if '"typescript"' in node_text or ctx.glob("**/tsconfig.json", 1):
                langs.add("typescript")
        if ctx.glob("**/pnpm-lock.yaml", 1):
            managers.add("pnpm")
        if ctx.glob("**/yarn.lock", 1):
            managers.add("yarn")

        py_manifests = _product_first(ctx, _py_manifests, repo_has_product)
        py_text = " ".join(ctx.text(p) for p in py_manifests).lower()
        if py_text.strip():
            langs.add("python")
            managers.add("pip")
            for dep, label in PY_FRAMEWORKS.items():
                if dep in py_text:
                    frameworks.add(label)
            for dep, label in DATASTORES.items():
                if dep in py_text:
                    datastores.add(label)
        if ctx.glob("**/go.mod", 1):
            langs.add("go")
        if ctx.glob("**/Gemfile", 1):
            langs.add("ruby")

        # P5: managed-platform config (wrangler / vercel / netlify / serverless) declares the framework
        # + datastore + cron surface that package.json deps don't reveal — so a KV/Workers app no
        # longer reads as `datastores: ?` (which down-ranks SQLi noise) and the cron surface is shown.
        cron_triggers: list = []
        wrangler = ctx.manifest("wrangler.jsonc") + ctx.manifest("wrangler.toml") + ctx.manifest("wrangler.json")
        if wrangler:
            frameworks.add("cloudflare-workers")
            if re.search(r"kv_namespaces|KVNamespace", wrangler, re.I):
                datastores.add("cloudflare-kv")
            if re.search(r"d1_databases|D1Database", wrangler, re.I):
                datastores.add("sqlite")                 # D1 is SQLite-backed
            if re.search(r"r2_buckets|R2Bucket", wrangler, re.I):
                datastores.add("r2-object-store")
            if re.search(r"durable_objects|DurableObjectNamespace", wrangler, re.I):
                datastores.add("durable-objects")
            for mm in re.finditer(r"crons?\s*[=:]\s*\[([^\]]*)\]", wrangler):
                cron_triggers += re.findall(r"['\"]([^'\"]+)['\"]", mm.group(1))
        vercel = ctx.manifest("vercel.json")
        if vercel:
            frameworks.add("vercel")
            cron_triggers += re.findall(r'"schedule"\s*:\s*"([^"]+)"', vercel)
        if ctx.manifest("netlify.toml"):
            frameworks.add("netlify")
        if ctx.manifest("serverless.yml") + ctx.manifest("serverless.yaml"):
            frameworks.add("serverless")

        # --- Manifest-LESS stacks a package.json/requirements scan misses entirely.
        # A browser extension + Deno/Supabase edge functions ship NO package.json, so without this
        # the whole app reads as `languages: ?` — which zeroes out every downstream extractor.
        # File-extension fallback + Deno/Supabase/WebExtension/SQL-schema detection restore a real
        # stack model for these manifest-less stacks. ---
        code_exts = {p.suffix.lower() for p in ctx.code_files}
        if not langs:                                   # nothing from manifests → infer from source
            if code_exts & {".ts", ".tsx", ".mts", ".cts"}:
                langs.update({"node", "typescript"})
            elif code_exts & {".js", ".jsx", ".mjs", ".cjs"}:
                langs.add("node")
            if ".py" in code_exts:
                langs.add("python")
            if ".go" in code_exts:
                langs.add("go")
            if ".rb" in code_exts:
                langs.add("ruby")

        # Deno + Supabase edge functions — `Deno.serve` handlers are HTTP endpoints (routes.py maps them).
        deno_sig = bool(ctx.glob("**/deno.json", 1) or ctx.glob("**/deno.jsonc", 1))
        supabase_fns = bool(ctx.glob("supabase/functions/**/index.ts", 1)
                            or ctx.glob("supabase/functions/**/index.js", 1))
        supabase_cfg = ctx.exists("supabase/config.toml") or bool(ctx.glob("supabase/**/*.sql", 1))
        if not deno_sig:
            for _p, _rel, text in ctx.iter_code():
                if "Deno.serve" in text or "Deno.env" in text:
                    deno_sig = True
                    break
        if deno_sig:
            langs.update({"node", "typescript"})
            frameworks.add("deno")
        if supabase_fns:
            frameworks.add("supabase-edge")
        if supabase_fns or supabase_cfg or "@supabase/supabase-js" in node_text:
            frameworks.add("supabase")
            datastores.add("postgres")                  # Supabase is Postgres-backed

        # WebExtension / Chrome extension (MV2/MV3): a manifest.json declaring manifest_version.
        for mf in ctx.glob("**/manifest.json", 40):
            if '"manifest_version"' in ctx.text(mf):
                frameworks.add("webextension")
                langs.add("node")                       # extension code is JS
                break

        # SQL schema / migration files imply a SQL datastore even with no ORM dependency.
        for sf in ctx.glob("**/*.sql", 60):
            stext = ctx.text(sf)
            if re.search(r"\bCREATE\s+TABLE\b", stext, re.I):
                datastores.add("postgres" if re.search(
                    r"gen_random_uuid|timestamptz|\bjsonb\b|ROW LEVEL SECURITY|CREATE POLICY", stext, re.I)
                    else "sql")
                break

        result = {
            "languages": sorted(langs),
            "frameworks": sorted(frameworks),
            "package_managers": sorted(managers),
            "datastores": sorted(datastores),
            "cron_triggers": sorted(set(cron_triggers)),
            "monorepo": len(pkgs) > 1 or ctx.exists("pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json"),
            "services": len(pkgs),
        }
        ctx.stack = result
        return result
