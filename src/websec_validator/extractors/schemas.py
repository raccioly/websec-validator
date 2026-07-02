"""Schema / entity extractor — the data model + its sensitive fields.

Borrowed from DocGuard's multilang model scanners. Finds ORM/schema models
(Pydantic, SQLAlchemy, Django, Prisma, Mongoose, TypeORM, Zod, Sequelize) and the
**sensitive field names** they use (role, isAdmin, groupId, passwordHash, …). That
turns mass-assignment / BOPLA probes from a generic guess into "try injecting THIS
app's privileged fields", and surfaces the object-ownership/tenant fields BOLA
depends on.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

DECLS = [
    ("pydantic", re.compile(r"class\s+(\w+)\s*\([^)]*BaseModel")),
    ("sqlalchemy", re.compile(r"class\s+(\w+)\s*\([^)]*\bBase\b[^)]*\)")),
    ("django", re.compile(r"class\s+(\w+)\s*\([^)]*models\.Model")),
    ("prisma", re.compile(r"\bmodel\s+(\w+)\s*\{")),
    ("mongoose", re.compile(r"\b(\w+)\s*=\s*(?:new\s+)?(?:mongoose\.)?Schema\s*\(")),
    ("typeorm", re.compile(r"@Entity\([^)]*\)\s*(?:export\s+)?class\s+(\w+)")),
    ("zod", re.compile(r"\b(\w+)\s*=\s*z\.object\s*\(")),
    ("sequelize", re.compile(r"sequelize\.define\s*\(\s*['\"](\w+)['\"]")),
]

SENSITIVE = re.compile(
    r"^(roles?|is_?admin|admin|permissions?|scopes?|password|password_?hash|pwd|"
    r"owner|owner_?id|user_?id|group_?id|tenant_?id|org_?id|organization_?id|account_?id|"
    r"balance|credits?|is_?verified|verified|status|plan|tier|enabled|active|api_?key|"
    r"secret|token|email_?verified|stripe_?customer|subscription|"
    # licensed/extension ownership keys — the BOLA isolation boundary for per-license/per-device apps
    r"license_?hash|license_?key|licence_?key|visitor_?id|device_?id|subscription_?id|customer_?id)$", re.I)

# CREATE TABLE [IF NOT EXISTS] [schema.]<name> ( — a plain SQL schema file (not an ORM), globbed
# separately because `.sql` isn't in CODE_EXT.
SQL_TABLE = re.compile(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\"`]?(?:\w+\.)?([A-Za-z_]\w*)[\"`]?\s*\(", re.I)

MODELISH_PATH = re.compile(r"/models?/|/schemas?/|/entit|\.prisma$|\.model\.|\.entity\.", re.I)
IDENT = re.compile(r"\b([A-Za-z_]\w*)\b")


class SchemasExtractor(Extractor):
    name = "schemas"
    category = "data"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        orms: set = set()
        entities: list = []
        sensitive: set = set()

        for _p, rel, text in ctx.iter_code():
            is_model_file = bool(MODELISH_PATH.search(rel))
            for label, rx in DECLS:
                for m in rx.finditer(text):
                    orms.add(label)
                    is_model_file = True
                    if m.groups() and m.group(1) and len(entities) < 80:
                        entities.append({"name": m.group(1), "type": label, "file": rel})
            if is_model_file:
                for w in IDENT.findall(text):
                    if SENSITIVE.match(w):
                        sensitive.add(w)

        # Plain SQL schema files (schema.sql / migrations) — globbed explicitly since `.sql` isn't in
        # CODE_EXT. A CREATE TABLE with a license_hash / owner column is exactly the ownership boundary
        # BOLA must isolate, and it's invisible to every iter_code()-based extractor without this.
        for sf in ctx.glob("**/*.sql", 60):
            stext = ctx.text(sf)
            srel = ctx.rel(sf)
            for m in SQL_TABLE.finditer(stext):
                orms.add("sql-ddl")
                if len(entities) < 80:
                    entities.append({"name": m.group(1), "type": "sql-table", "file": srel})
            for w in IDENT.findall(stext):
                if SENSITIVE.match(w):
                    sensitive.add(w)

        # de-dup entities by (name,type)
        seen, ents = set(), []
        for e in entities:
            k = (e["name"], e["type"])
            if k not in seen:
                seen.add(k)
                ents.append(e)

        return {
            "orms": sorted(orms),
            "entity_count": len(ents),
            "entities": ents[:60],
            "sensitive_fields": sorted(sensitive),
            "note": "Mass-assignment/BOPLA probes should try injecting these app-specific privileged "
                    "fields into update/create payloads; ownership/tenant fields here are what BOLA must isolate.",
        }
