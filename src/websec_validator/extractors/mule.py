"""MuleSoft flows and DataWeave — the `mule` profile (#250).

Direct syntax only, read from flow XML (`src/main/mule/**/*.xml` or a `<mule xmlns=".../mule/core">`
root) and `.dwl` files. The XML is matched with bounded regular expressions, not parsed: a repository
file is untrusted input, and the stdlib XML parsers expand entities.

Checks:
  * mule-listener-routes — `<http:listener path>` per flow, joined with the listener-config
    `basePath`, method from `allowedMethods` (else ANY). Fed into the route inventory.
  * mule-dynamic-query — `<db:sql>` that is a `#[...]` expression concatenating with `++`, `$(` or
    interpolation instead of `:param` + `<db:input-parameters>`; HIGH when it reads `attributes`.
  * mule-dynamic-request-url — `<http:request url|path="#[...]">` built from request attributes (SSRF).
  * mule-insecure-tls — `<tls:trust-store insecure="true">`, or `enabledProtocols` with TLSv1/TLSv1.1.
  * mule-plaintext-credential — a literal `password`/`clientSecret`/`token`/`secret`/`apiKey` value in
    a connector config or in `src/main/resources/**/*.yaml|*.properties` (placeholders exempt).
  * mule-listener-no-tls — a listener connection with no `protocol="HTTPS"` and no `<tls:context>`.
  * dataweave-readurl — `readUrl(` with a non-literal first argument, and `java!` calls (review).
API Manager policies applied outside the repository are not visible, so listener routes carry an
unresolved-central-policy note instead of a missing-guard verdict.
"""
from __future__ import annotations

import re

_ATTR = r"""\s{name}\s*=\s*(["'])(.*?)\1"""
_FLOW = re.compile(r"<(?:flow|sub-flow)\b[^>]*\bname\s*=\s*([\"'])(.*?)\1[^>]*>(.*?)</(?:flow|sub-flow)>", re.S)
_LISTENER = re.compile(r"<http:listener\b(?![-\w])([^>]*)>", re.S)
_LISTENER_CONFIG = re.compile(r"<http:listener-config\b([^>]*)>(.*?)</http:listener-config>", re.S)
_DB_SQL = re.compile(r"<db:sql\b[^>]*>(.*?)</db:sql>", re.S)
_REQUEST = re.compile(r"<http:request\b(?![-\w])([^>]*)>", re.S)
_TRUST = re.compile(r"<tls:trust-store\b[^>]*\binsecure\s*=\s*[\"']true[\"']", re.I)
_PROTOCOLS = re.compile(r"enabledProtocols\s*=\s*[\"']([^\"']*)[\"']", re.I)
_CREDENTIAL_ATTR = re.compile(r"\s((?:password|clientSecret|client_secret|secret|token|apiKey|api_key|passphrase|keyPassword)"
                              r")\s*=\s*([\"'])(.*?)\2", re.I)
_CREDENTIAL_LINE = re.compile(r"^\s*([\w.-]*(?:password|secret|token|apikey|api_key|clientsecret|passphrase)[\w.-]*)\s*[:=]\s*"
                              r"[\"']?([^\"'#\n]*)", re.I | re.M)
_PLACEHOLDER = re.compile(r"^\s*(?:\$\{|#\[|p\(|Mule::p\(|\{\{|<|$)|secure::", re.I)
_REQUEST_DATA = re.compile(r"\battributes\s*\.\s*(?:uriParams|queryParams|headers|requestPath|rawRequestPath|queryString)"
                           r"|\bpayload\b|\bvars\.\w*(?:param|input|body|query)", re.I)


def _attr(attrs: str, name: str) -> str | None:
    match = re.search(_ATTR.format(name=re.escape(name)), attrs, re.S | re.I)
    return match[2] if match else None


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _dynamic_sql(expression: str) -> bool:
    body = expression.strip()
    if not body.startswith("#["):
        return False
    return bool(re.search(r"\+\+|\$\(|\bas\s+String\b.*\+\+", body))


def analyze_flow(text: str, rel: str) -> dict:
    routes, sinks, findings = [], [], []
    configs = {}
    for config in _LISTENER_CONFIG.finditer(text):
        name = _attr(config[1], "name") or ""
        connection = config[2]
        https = (_attr(connection, "protocol") or "").upper() == "HTTPS" or "<tls:context" in connection
        configs[name] = {"base": (_attr(config[1], "basePath") or "").strip("/"), "https": https,
                         "line": _line(text, config.start())}
        if not https:
            findings.append({"rule_id": "mule-listener-no-tls", "line": _line(text, config.start()),
                             "attack_class": "transport-security", "severity": "LOW", "confidence": "MEDIUM",
                             "cwe": "CWE-319", "title": f"Mule HTTP listener {name or '(unnamed)'} accepts plain HTTP",
                             "evidence": "<http:listener-connection> without protocol=\"HTTPS\" or <tls:context>",
                             "remediation": "Terminate TLS on the listener (protocol=\"HTTPS\" with a tls:context), or "
                                            "document the gateway that terminates it.",
                             "limitations": ["A gateway or load balancer in front of the app is not visible."]})
    for flow in _FLOW.finditer(text):
        body, offset = flow[3], flow.start(3)
        for listener in _LISTENER.finditer(body):
            attrs = listener[1]
            path = _attr(attrs, "path")
            if path is None:
                continue
            config = configs.get(_attr(attrs, "config-ref") or "", {})
            methods = [m.strip().upper() for m in (_attr(attrs, "allowedMethods") or "").split(",") if m.strip()] or ["ANY"]
            full = "/" + "/".join(part.strip("/") for part in (config.get("base", ""), path) if part.strip("/"))
            for method in methods:
                routes.append({"method": method, "path": full.replace("*", "{*}") if full.endswith("/*") else full,
                               "params": [], "technology": "mule", "code_path": rel, "source": "mule-listener",
                               "flow": flow[2], "line": _line(text, offset + listener.start()),
                               "central_auth_note": "API Manager policies and gateway authentication applied outside "
                                                    "the repository are not visible; verify the effective policy",
                               "limitations": ["Direct listener syntax only; APIkit routing and API Manager policies "
                                               "are not resolved."]})
        for sql in _DB_SQL.finditer(body):
            expression = sql[1]
            if not _dynamic_sql(expression):
                continue
            bound = bool(_REQUEST_DATA.search(expression))
            sinks.append({"kind": "sql-injection", "offset": offset + sql.start(), "expression": sql[0][:300],
                          "request_bound": ["attributes"] if bound else [], "flow": flow[2],
                          "source": ("request attributes concatenated into db:sql" if bound else
                                     "a DataWeave expression concatenated into db:sql; provenance requires review")
                                    + "; use :param with <db:input-parameters>"})
        for request in _REQUEST.finditer(body):
            attrs = request[1]
            for field in ("url", "path", "host"):
                value = _attr(attrs, field)
                if value and value.strip().startswith("#[") and _REQUEST_DATA.search(value):
                    sinks.append({"kind": "ssrf", "offset": offset + request.start(), "expression": request[0][:300],
                                  "request_bound": [field], "flow": flow[2],
                                  "source": f"the outbound request {field} is built from request data"})
                    break
    for match in _TRUST.finditer(text):
        findings.append({"rule_id": "mule-insecure-tls", "line": _line(text, match.start()),
                         "attack_class": "transport-security", "severity": "MEDIUM", "confidence": "HIGH",
                         "cwe": "CWE-295", "title": "Mule TLS trust store accepts any certificate",
                         "evidence": "<tls:trust-store insecure=\"true\">",
                         "remediation": "Remove insecure=\"true\" and trust the partner's CA or certificate explicitly.",
                         "limitations": ["Environment-specific overrides are not resolved."]})
    for match in _PROTOCOLS.finditer(text):
        weak = [p for p in re.split(r"[\s,]+", match[1]) if p.upper() in ("TLSV1", "TLSV1.0", "TLSV1.1", "SSLV3")]
        if weak:
            findings.append({"rule_id": "mule-insecure-tls", "line": _line(text, match.start()),
                             "attack_class": "transport-security", "severity": "MEDIUM", "confidence": "HIGH",
                             "cwe": "CWE-327", "title": "Mule TLS context enables deprecated protocols",
                             "evidence": "enabledProtocols includes " + ", ".join(weak),
                             "remediation": "Allow TLSv1.2 and TLSv1.3 only.",
                             "limitations": ["Runtime defaults are not resolved."]})
    findings.extend(_credentials(text, _CREDENTIAL_ATTR, rel))
    findings.extend(_dataweave(text))
    return {"routes": routes, "sinks": sinks, "findings": findings}


def _credentials(text: str, pattern, rel: str) -> list:
    rows = []
    for match in pattern.finditer(text):
        key, value = (match[1], match[3]) if pattern is _CREDENTIAL_ATTR else (match[1], match[2])
        value = (value or "").strip()
        if len(value) < 6 or _PLACEHOLDER.search(value) or re.fullmatch(r"(?i)(?:true|false|null|none|changeme|x+|\*+)", value):
            continue
        rows.append({"rule_id": "mule-plaintext-credential", "line": _line(text, match.start()),
                     "attack_class": "secret", "severity": "HIGH", "confidence": "MEDIUM", "cwe": "CWE-798",
                     "title": f"Mule connector credential `{key}` is a literal value",
                     "evidence": f"{key} has a literal value in {rel} (value not shown)",
                     "remediation": "Move it to a secure properties file (${secure::...}) or a vault, and rotate it.",
                     "limitations": ["Test-only and environment-specific files are not distinguished."]})
    return rows


def _dataweave(text: str) -> list:
    rows = []
    for match in re.finditer(r"\breadUrl\s*\(\s*([^,)]+)", text):
        argument = match[1].strip()
        if re.fullmatch(r"(['\"]).*\1", argument):
            continue
        rows.append({"rule_id": "dataweave-readurl", "line": _line(text, match.start()),
                     "attack_class": "ssrf", "severity": "MEDIUM", "confidence": "LOW", "cwe": "CWE-918",
                     "title": "DataWeave readUrl() with a non-literal location",
                     "evidence": f"readUrl({argument[:60]}, ...)",
                     "remediation": "Read only fixed classpath resources; never a location from request data.",
                     "limitations": ["Where the argument comes from is not traced."]})
    for match in re.finditer(r"\bjava!\s*[\w.:]+", text):
        rows.append({"rule_id": "dataweave-readurl", "line": _line(text, match.start()),
                     "attack_class": "eval-injection", "severity": "LOW", "confidence": "LOW", "cwe": "CWE-470",
                     "title": "DataWeave calls Java directly (java!)", "evidence": match[0][:80],
                     "remediation": "Review that the called method takes no request data.",
                     "limitations": ["Called method behavior is not analyzed."]})
    return rows


def analyze_properties(text: str, rel: str) -> list:
    """Literal credentials in a Mule app's `src/main/resources` YAML/properties file."""
    return _credentials(text, _CREDENTIAL_LINE, rel)


def is_mule_app(ctx) -> bool:
    if ctx.dialect_files.get("mule-flow-xml"):
        return True
    return False
