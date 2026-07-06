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

# A TENANCY-restricted subset of SENSITIVE: a column that makes a row OWNED (per-user/tenant) — the
# thing Row-Level Security has to isolate. Gating the no-RLS finding on an owner column (not any table)
# is the primary FP suppressor: a global lookup (countries/feature_flags/_prisma_migrations) has none.
OWNER_COL = re.compile(
    r"\b(owner_?id|user_?id|tenant_?id|org_?id|organization_?id|account_?id|group_?id|workspace_?id|"
    r"team_?id|company_?id|customer_?id|created_?by|profile_?id|license_?hash|license_?key)\b", re.I)
# RLS artifacts, counted across the WHOLE .sql corpus (policies routinely live in a later migration than
# the CREATE TABLE, so aggregate — any RLS token anywhere = this repo manages RLS in-code → don't flag).
RLS_POLICY = re.compile(r"\bCREATE\s+POLICY\b", re.I)
RLS_ENABLE = re.compile(r"\bALTER\s+TABLE\b[\s\S]{0,200}?\b(?:ENABLE|FORCE)\s+ROW\s+LEVEL\s+SECURITY\b", re.I)

MODELISH_PATH = re.compile(r"/models?/|/schemas?/|/entit|\.prisma$|\.model\.|\.entity\.", re.I)
IDENT = re.compile(r"\b([A-Za-z_]\w*)\b")


_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")
_SQL_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _strip_sql_comments(text: str) -> str:
    """Blank out `-- …` and `/* … */` comments before RLS/table detection. A comment like
    `-- TODO: add a create policy` must NOT count as an RLS artifact (that would falsely suppress the
    no-RLS finding) — the comment-token hazard the codebase already learned for SIG_VERIFY."""
    return _SQL_BLOCK_COMMENT.sub(" ", _SQL_LINE_COMMENT.sub(" ", text))


def _table_body(text: str, open_paren: int) -> str:
    """Slice a CREATE TABLE column list by matching the opening `(` to its balanced `)` — so an owner
    column is only credited to the table it actually belongs to (not a neighbouring table's body)."""
    depth = 0
    for i in range(open_paren, min(len(text), open_paren + 8000)):
        c = text[i]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:i]
    return text[open_paren + 1:open_paren + 8000]


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
        sql_ddl_present = False
        sql_table_count = 0
        owner_scoped: list = []
        rls_policy_count = 0
        rls_enabled_count = 0
        for sf in ctx.glob("**/*.sql", 60):
            stext = _strip_sql_comments(ctx.text(sf))   # comments must not count as tables or RLS tokens
            srel = ctx.rel(sf)
            rls_policy_count += len(RLS_POLICY.findall(stext))
            rls_enabled_count += len(RLS_ENABLE.findall(stext))
            for m in SQL_TABLE.finditer(stext):
                orms.add("sql-ddl")
                sql_ddl_present = True
                sql_table_count += 1
                if len(entities) < 80:
                    entities.append({"name": m.group(1), "type": "sql-table", "file": srel})
                # is this table OWNED (per-user/tenant)? test only its own column body, not the file.
                body = _table_body(stext, m.end() - 1)
                if OWNER_COL.search(body) and len(owner_scoped) < 40:
                    cols = sorted({c.lower() for c in OWNER_COL.findall(body)})
                    owner_scoped.append({"name": m.group(1), "file": srel, "columns": cols})
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
            # Committed-SQL RLS posture — feeds the no-RLS-at-all correlation in build_ledger (the Lovable /
            # CVE-2025-48757 class). Repo-corpus aggregates: RLS on ANY table anywhere counts as "RLS present".
            "sql_ddl_present": sql_ddl_present,
            "sql_table_count": sql_table_count,
            "owner_scoped_tables": owner_scoped,
            "rls_policy_count": rls_policy_count,
            "rls_enabled_count": rls_enabled_count,
            "note": "Mass-assignment/BOPLA probes should try injecting these app-specific privileged "
                    "fields into update/create payloads; ownership/tenant fields here are what BOLA must isolate.",
        }
