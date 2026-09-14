"""Stack extractor — languages, frameworks, package managers, datastores.

Monorepo-aware: aggregates every package.json / Python manifest in the tree
(node_modules excluded by SKIP_DIRS), so a backend/ service's Express + DynamoDB
deps are seen even when the repo root is just a workspace shell. Runs first; its
result is stashed on ctx.stack for later extractors.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_script_file, is_test_file
from .profiles import analyze as analyze_profiles, manifest_paths, node_metadata


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
                   "@apollo/server": "apollo-graphql", "graphql": "graphql",
                   "@angular/core": "angular", "react": "react", "react-native": "react-native"}
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

        selected_manifests = manifest_paths(ctx)
        _node_manifests = [path for path in selected_manifests if path.name == "package.json"]
        _py_manifests = [path for path in selected_manifests
                         if path.name in {"pyproject.toml", "setup.py", "Pipfile"}
                         or (path.name.startswith("requirements") and path.suffix == ".txt")]
        # cross-language: is ANY manifest product code? (decides whether fixtures-only stacks
        # fall back to their fixture manifests — see _product_first)
        repo_has_product = any(not _is_fixture_manifest(ctx, p)
                               for p in selected_manifests)

        pkgs = _product_first(ctx, _node_manifests, repo_has_product)
        node_deps = set()
        if pkgs:
            langs.add("node")
            managers.add("npm")
            for path in pkgs:
                metadata = node_metadata(ctx.text(path))
                node_deps.update(metadata["dependencies"])
                frameworks.update(metadata["frameworks"])
                datastores.update(metadata["datastores"])
                langs.update(metadata["languages"])
            if _product_first(ctx, ctx.glob("**/tsconfig.json"), repo_has_product):
                langs.add("typescript")
        if _product_first(ctx, ctx.glob("**/pnpm-lock.yaml"), repo_has_product):
            managers.add("pnpm")
        if _product_first(ctx, ctx.glob("**/yarn.lock"), repo_has_product):
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
        if any(path.name == "go.mod" for path in selected_manifests):
            langs.add("go")
        if any(path.name == "Gemfile" for path in selected_manifests):
            langs.add("ruby")
        if any(path.name == "Cargo.toml" for path in selected_manifests):
            langs.add("rust")
            managers.add("cargo")

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
        if supabase_fns or supabase_cfg or "@supabase/supabase-js" in node_deps:
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
        }
        profiles = analyze_profiles(ctx)
        result["service_inventory"] = profiles["service_inventory"]
        result["services"] = len(profiles["service_inventory"])
        result["monorepo"] = result["services"] > 1 or ctx.exists("pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json")
        result["metadata_note"] = "Manifest and source hints; service boundaries are approximate. Dependency presence does not prove installation, deployment or a native application."
        result["profiles"] = profiles
        for key in ("languages", "frameworks", "datastores"):
            result[key] = sorted(set(result[key]) | {value for service in profiles["service_inventory"]
                                                    for value in service[key]})
        ctx.stack = result
        return result
