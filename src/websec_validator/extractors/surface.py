"""Attack-surface extractor — code-level dangerous sinks, user-control-aware.

Each signature embeds a user-input marker (`req.`/`request.`/string concat/
template interpolation/format) so a match means "dangerous op fed by something
that looks attacker-influenced", not merely "this function is used anywhere".
Signatures derived from the recon-engine research. Each class maps to the probe
that exercises it, so the briefing can point probes at the right files.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext

# user-controlled markers (kept loose on purpose)
_U = r"(?:req\.|request\.|\+|`[^`]*\$\{|f['\"]|%\s*[\(%]|\.format\s*\(|searchParams|nextUrl|params\[)"

# class -> (probe it feeds, gating, compiled regex)
#   gating: None | "sql" | "nosql"  (datastore-dependent classes)
SINKS = {
    "ssrf": ("ssrf-probes", None, re.compile(
        r"(?:axios|got|node-fetch|superagent|needle|httpx|urllib\.request)\b.*\b" + _U
        + r"|\bfetch\s*\(\s*" + _U + r"|requests\.(?:get|post|put|request)\s*\(\s*" + _U)),
    "command-injection": ("ssrf-probes", None, re.compile(
        r"(?:child_process\.exec|\bexecSync|\bexec|\bspawn|os\.system|subprocess\.(?:run|call|check_output|Popen))\s*\([^)]*"
        + _U + r"|shell\s*=\s*True")),
    "sql-injection": ("bola-write-verbs", "sql", re.compile(
        r"(?:\.query|\.execute|\.raw|cursor\.execute|sequelize\.query|knex\.raw)\s*\([^)]*(?:\$\{|\+|%\s*[\(%]|\.format\s*\(|f['\"])")),
    "nosql-injection": ("bola-write-verbs", "nosql", re.compile(
        r"\.(?:find|findOne|update|updateOne|deleteOne|aggregate)\s*\(\s*(?:req\.|request\.)|\$where")),
    "path-traversal": ("bola-write-verbs", None, re.compile(
        r"(?:fs\.(?:readFile|writeFile|createReadStream|unlink|readdir)|sendFile|os\.path\.join|\bopen|path\.(?:join|resolve))\s*\([^)]*"
        + _U)),
    "ssti": ("ssrf-probes", None, re.compile(
        r"(?:render_template_string|renderString|nunjucks\.renderString|ejs\.render|pug\.compile|Handlebars\.compile|new\s+Template|Template\s*\()\s*\([^)]*"
        + _U)),
    "open-redirect": ("bola-write-verbs", None, re.compile(
        r"(?:res\.redirect|HttpResponseRedirect|RedirectResponse|return\s+redirect|res\.setHeader\s*\(\s*['\"]Location)\s*\([^)]*"
        + _U)),
    "insecure-deserialization": ("bola-write-verbs", None, re.compile(
        r"pickle\.loads?\s*\(|cPickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader)|node-serialize.*unserialize\s*\(|\bunserialize\s*\(")),
    "xxe": ("ssrf-probes", None, re.compile(
        r"libxmljs\.parseXml\s*\(|lxml\.etree\.(?:parse|fromstring|XML)\s*\(|xml\.etree\.ElementTree\.(?:parse|fromstring)\s*\(|new\s+DOMParser")),
    "prototype-pollution": ("mass-assignment", None, re.compile(
        r"(?:_\.merge|_\.mergeWith|_\.defaultsDeep|Object\.assign)\s*\([^)]*(?:req\.|request\.)|\.update\s*\([^)]*request\.(?:json|get_json|form)")),
    "redos": ("ssrf-probes", None, re.compile(
        r"new\s+RegExp\s*\([^)]*(?:req\.|request\.|\+)|re\.(?:compile|match|search|fullmatch)\s*\([^,)]*(?:request\.|f['\"])")),
    "eval-injection": ("bola-write-verbs", None, re.compile(
        r"\beval\s*\([^)]*" + _U + r"|new\s+Function\s*\([^)]*" + _U)),
}


class SurfaceExtractor(Extractor):
    name = "surface"
    category = "sinks"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        datastores = set((facts.get("stack") or {}).get("datastores", []))
        has_sql = any("sql" in d or d in ("postgres", "mysql", "sqlite") for d in datastores)
        has_nosql = any(d in ("mongo", "dynamodb") for d in datastores)

        found: dict = {k: [] for k in SINKS}
        counts: dict = {k: 0 for k in SINKS}
        for _p, rel, text in ctx.iter_code():
            for cls, (_probe, gate, rx) in SINKS.items():
                if gate == "sql" and not has_sql:
                    continue
                if gate == "nosql" and not has_nosql:
                    continue
                if rx.search(text):
                    counts[cls] += 1
                    if len(found[cls]) < 60:
                        found[cls].append(rel)

        sinks = {k: {"probe": SINKS[k][0], "count": counts[k], "files": found[k]}
                 for k in SINKS if counts[k]}
        return {
            "sinks": sinks,
            "sink_counts": {k: counts[k] for k in SINKS if counts[k]},
            "datastore_class": ("sql" if has_sql else ("nosql" if has_nosql else "unknown")),
            "note": "Each sink hit is user-input-gated (req./request./concat/interp), so these are "
                    "higher-confidence leads. Cross-reference the files with routes.targeting to pick "
                    "the endpoint to probe. On a NoSQL/JSON API, SQLi alerts from generic scanners are "
                    "usually false positives.",
        }
