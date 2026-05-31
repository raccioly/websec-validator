"""Stack extractor — languages, frameworks, package managers, datastores.

Monorepo-aware: aggregates every package.json / Python manifest in the tree
(node_modules excluded by SKIP_DIRS), so a backend/ service's Express + DynamoDB
deps are seen even when the repo root is just a workspace shell. Runs first; its
result is stashed on ctx.stack for later extractors.
"""

from __future__ import annotations

from .base import Extractor, RepoContext

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

        pkgs = ctx.glob("**/package.json", 120)
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

        py_manifests = (ctx.glob("**/requirements*.txt", 80) + ctx.glob("**/pyproject.toml", 80)
                        + ctx.glob("**/setup.py", 80) + ctx.glob("**/Pipfile", 80))
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

        result = {
            "languages": sorted(langs),
            "frameworks": sorted(frameworks),
            "package_managers": sorted(managers),
            "datastores": sorted(datastores),
            "monorepo": len(pkgs) > 1 or ctx.exists("pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json"),
            "services": len(pkgs),
        }
        ctx.stack = result
        return result
