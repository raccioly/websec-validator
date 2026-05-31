"""Attack-surface extractor — code-level dangerous sinks.

Complements the route-param targeting in routes.py: this finds the sinks in CODE
(outbound HTTP, shell exec, filesystem reads, raw SQL, template render, eval/
deserialization) so probes can be pointed at the files that actually contain the
risky operation. Gated by stack where it helps (only flag SQL sinks if there's a
SQL datastore).
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

SINKS = {
    "ssrf-outbound-http": re.compile(r"\b(?:fetch|axios(?:\.\w+)?|got|node-fetch|requests\.\w+|httpx\.\w+|urllib\.request|http\.get|undici)\s*\(", re.I),
    "command-exec": re.compile(r"child_process|\bexec\s*\(|execSync|spawn\s*\(|os\.system|subprocess\.(?:run|Popen|call)|Deno\.run"),
    "fs-read-write": re.compile(r"fs\.(?:readFile|writeFile|createReadStream|unlink)|open\s*\(|pathlib\.Path\([^)]*\)\.(?:read|write)|sendFile"),
    "raw-sql": re.compile(r"\.(?:query|execute|raw)\s*\(\s*[`'\"].*\$\{|\bcursor\.execute\s*\(|sequelize\.query|knex\.raw|text\s*=\s*f[\"']", re.I),
    "template-render": re.compile(r"render_template_string|Template\s*\(|ejs\.render|pug\.compile|Handlebars\.compile|nunjucks"),
    "eval-deserialize": re.compile(r"\beval\s*\(|new Function\s*\(|pickle\.loads|yaml\.load\s*\(|vm\.runInContext|child_process"),
    "redirect": re.compile(r"res\.redirect\s*\(|RedirectResponse\s*\(|return redirect\s*\("),
}


class SurfaceExtractor(Extractor):
    name = "surface"
    category = "sinks"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        datastores = set((facts.get("stack") or {}).get("datastores", []))
        has_sql = any("sql" in d or d in ("postgres", "mysql", "sqlite") for d in datastores)

        found: dict = {k: [] for k in SINKS}
        for _p, rel, text in ctx.iter_code():
            for cls, rx in SINKS.items():
                if cls == "raw-sql" and not has_sql:
                    continue
                if rx.search(text) and len(found[cls]) < 30:
                    found[cls].append(rel)

        found = {k: v for k, v in found.items() if v}   # drop empties
        return {
            "sinks": found,
            "datastore_class": ("sql" if has_sql else ("nosql" if datastores else "unknown")),
            "note": "On a NoSQL/JSON API, scanner SQLi alerts are usually false positives — "
                    "triage accordingly. Cross-reference these sink files with routes.targeting.",
        }
