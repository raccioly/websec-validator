"""Stack extractor — languages, frameworks, package managers, datastores.

Runs first; its result is stashed on ctx.stack so later extractors can branch on
it (e.g. "only look for SQL injection sinks if there's a SQL datastore").
"""

from __future__ import annotations

from .base import Extractor, RepoContext

NODE_FRAMEWORKS = {"express": "express", "fastify": "fastify", "koa": "koa",
                   "@nestjs/core": "nestjs", "next": "next", "@hapi/hapi": "hapi",
                   "next-auth": "nextauth", "@remix-run": "remix", "svelte": "sveltekit"}
PY_FRAMEWORKS = {"fastapi": "fastapi", "flask": "flask", "django": "django",
                 "starlette": "starlette", "sanic": "sanic", "tornado": "tornado",
                 "aiohttp": "aiohttp"}
DATASTORES = {"pg": "postgres", "postgres": "postgres", "mysql": "mysql",
              "mysql2": "mysql", "mongodb": "mongo", "mongoose": "mongo",
              "@aws-sdk/client-dynamodb": "dynamodb", "dynamodb": "dynamodb",
              "redis": "redis", "ioredis": "redis", "sqlite": "sqlite",
              "prisma": "prisma(sql)", "sequelize": "sql-orm", "typeorm": "sql-orm",
              "drizzle-orm": "sql-orm", "sqlalchemy": "sql-orm", "psycopg2": "postgres",
              "pymongo": "mongo", "boto3": "aws"}


class StackExtractor(Extractor):
    name = "stack"
    category = "inventory"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        langs, frameworks, managers, datastores = set(), set(), set(), set()

        pkg = ctx.manifest("package.json")
        if pkg:
            langs.add("node")
            managers.add("npm")
            for dep, label in NODE_FRAMEWORKS.items():
                if f'"{dep}"' in pkg or f'"{dep}/' in pkg:
                    frameworks.add(label)
            for dep, label in DATASTORES.items():
                if f'"{dep}"' in pkg:
                    datastores.add(label)
            if "typescript" in pkg or ctx.glob("tsconfig.json", limit=1):
                langs.add("typescript")
        if ctx.exists("pnpm-lock.yaml"):
            managers.add("pnpm")
        if ctx.exists("yarn.lock"):
            managers.add("yarn")

        py = " ".join(ctx.manifest(m) for m in
                      ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")).lower()
        if py.strip():
            langs.add("python")
            managers.add("pip")
            for dep, label in PY_FRAMEWORKS.items():
                if dep in py:
                    frameworks.add(label)
            for dep, label in DATASTORES.items():
                if dep in py:
                    datastores.add(label)
        if ctx.exists("go.mod"):
            langs.add("go")
        if ctx.exists("Gemfile"):
            langs.add("ruby")

        result = {
            "languages": sorted(langs),
            "frameworks": sorted(frameworks),
            "package_managers": sorted(managers),
            "datastores": sorted(datastores),
            "monorepo": ctx.exists("pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json"),
        }
        ctx.stack = result   # share with later extractors
        return result
