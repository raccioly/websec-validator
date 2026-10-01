"""Schema / entity extractor — the data model + its sensitive fields.

Borrowed from DocGuard's multilang model scanners. Finds ORM/schema models
(Pydantic, SQLAlchemy, Django, Prisma, Mongoose, TypeORM, Zod, Sequelize) and the
**sensitive field names** they use (role, isAdmin, groupId, passwordHash, …). That
turns mass-assignment / BOPLA probes from a generic guess into "try injecting THIS
app's privileged fields", and surfaces the object-ownership/tenant fields BOLA
depends on.
"""

from __future__ import annotations

import ast
from collections import Counter
from itertools import islice
import re
import warnings

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
MAX_MODEL_SOURCE = 512 * 1024
MAX_MODEL_NODES = 20_000
MAX_MODEL_TOTAL_BYTES = 8 * 1024 * 1024


def _flask_models(source: str) -> list[dict]:
    """Import-bound top-level db.Model declarations; target code remains data.

    Imported extension objects and app factories remain unresolved, not runtime
    model/DB proof. Only actual bound column/typed declarations supply new fields.
    """
    if len(source.encode('utf-8')) > MAX_MODEL_SOURCE:
        raise ValueError('Flask model source byte budget exceeded')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            tree = ast.parse(source)
        nodes = list(islice(ast.walk(tree), MAX_MODEL_NODES + 1))
    except (SyntaxError, RecursionError) as error:
        raise ValueError('Flask model source syntax unresolved') from error
    if len(nodes) > MAX_MODEL_NODES:
        raise ValueError('Flask model AST node budget exceeded')
    writes = Counter(node.id for node in nodes if isinstance(node, ast.Name)
                     and isinstance(node.ctx, (ast.Store, ast.Del)))
    writes.update(node.arg for node in nodes if isinstance(node, ast.arg))
    writes.update(node.name for node in nodes if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)))
    imports, import_lines = {}, {}
    for node in nodes:
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(node.ctx, (ast.Store, ast.Del)):
            root = node.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name):
                writes[root.id] += 1
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {'setattr', 'delattr'}:
            if node.args and isinstance(node.args[0], ast.Name):
                writes[node.args[0].id] += 1
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                if alias.name == '*':
                    return []
                name = alias.asname or alias.name.split('.')[0]
                writes[name] += 1
                if node not in tree.body or (isinstance(node, ast.ImportFrom) and node.level):
                    continue
                imports[name] = ((node.module or '') + '.' + alias.name if isinstance(node, ast.ImportFrom)
                                 else alias.name if alias.asname else alias.name.split('.')[0])
                import_lines[name] = node.lineno
    imports = {name: value for name, value in imports.items() if writes[name] == 1}

    def qualified(expr):
        if isinstance(expr, ast.Name):
            return imports.get(expr.id, '')
        if isinstance(expr, ast.Attribute):
            base = qualified(expr.value)
            return base + '.' + expr.attr if base else ''
        return ''

    receivers = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and writes[node.targets[0].id] == 1 and isinstance(node.value, ast.Call)
                and qualified(node.value.func) == 'flask_sqlalchemy.SQLAlchemy'):
            root = node.value.func
            while isinstance(root, ast.Attribute):
                root = root.value
            if isinstance(root, ast.Name) and import_lines.get(root.id, node.lineno) < node.lineno:
                receivers[node.targets[0].id] = node.lineno
    rows = []
    for node in tree.body:
        if not isinstance(node, ast.ClassDef) or not any(
                isinstance(base, ast.Attribute) and base.attr == 'Model' and isinstance(base.value, ast.Name)
                and base.value.id in receivers and receivers[base.value.id] < node.lineno for base in node.bases):
            continue
        fields = set()
        field_writes = Counter()
        for statement in node.body:
            if isinstance(statement, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                field_writes.update(target.id for target in targets if isinstance(target, ast.Name))
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                field_writes[statement.name] += 1

        def earlier_import(expr, line):
            while isinstance(expr, ast.Attribute):
                expr = expr.value
            return isinstance(expr, ast.Name) and import_lines.get(expr.id, line) < line

        for statement in node.body:
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            value = statement.value
            column = (isinstance(value, ast.Call) and (
                (qualified(value.func) in {'sqlalchemy.Column', 'sqlalchemy.orm.mapped_column'}
                 and earlier_import(value.func, statement.lineno))
                or isinstance(value.func, ast.Attribute) and value.func.attr == 'Column'
                and isinstance(value.func.value, ast.Name) and value.func.value.id in receivers))
            annotation = statement.annotation if isinstance(statement, ast.AnnAssign) else None
            typed = (isinstance(annotation, ast.Subscript) and qualified(annotation.value) == 'sqlalchemy.orm.Mapped'
                     and earlier_import(annotation.value, statement.lineno))
            if column or typed:
                targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
                fields.update(target.id for target in targets if isinstance(target, ast.Name) and field_writes[target.id] == 1)
        rows.append({'name': node.name, 'type': 'sqlalchemy', 'fields': sorted(fields)})
    return rows


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
        model_errors = []
        model_bytes = 0

        for _p, rel, text in ctx.iter_code():
            is_model_file = bool(MODELISH_PATH.search(rel))
            flask_candidate = _p.suffix == '.py' and bool(re.search(r'\b(?:from|import)\s+flask_sqlalchemy\b', text))
            other_model = False
            if flask_candidate:
                model_bytes += len(text.encode('utf-8'))
                try:
                    if model_bytes > MAX_MODEL_TOTAL_BYTES:
                        raise ValueError('Flask model aggregate source budget exceeded')
                    for row in _flask_models(text):
                        orms.add('sqlalchemy')
                        if len(entities) < 80:
                            entities.append({**row, 'file': rel})
                        sensitive.update(field for field in row['fields'] if SENSITIVE.match(field))
                except ValueError as error:
                    if len(model_errors) < 50:
                        model_errors.append({'file': rel, 'detail': str(error)})
            for label, rx in DECLS:
                for m in rx.finditer(text):
                    orms.add(label)
                    is_model_file = True
                    other_model = True
                    if m.groups() and m.group(1) and len(entities) < 80:
                        entities.append({"name": m.group(1), "type": label, "file": rel})
            if is_model_file and (not flask_candidate or other_model):
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
            **({'error': 'Flask model source analysis incomplete; see model_analysis.errors'} if model_errors else {}),
            'model_analysis': {'errors': model_errors, 'source_bytes': model_bytes,
                               'limits': {'source_bytes_per_file': MAX_MODEL_SOURCE,
                                          'nodes_per_file': MAX_MODEL_NODES, 'source_bytes_total': MAX_MODEL_TOTAL_BYTES},
                               'limitations': ['Literal top-level local extension/model declarations only; imported db objects, '
                                               'factories and runtime model installation remain unverified.']},
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
