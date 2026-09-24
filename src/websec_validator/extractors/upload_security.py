"""Upload-security extractor — unrestricted file upload + unsafe serve (REF-PENTEST #2b).

The polyglot / MIME-spoof class the retest exploited. An upload handler is unsafe when it:
  (a) only DENY-lists executables instead of positively ALLOW-listing by SNIFFED magic bytes,
  (b) builds the storage key/path from the client `originalname`/`filename` (so `Jpg.php` with PNG
      magic bytes is stored executable),
  (c) trusts the client-supplied `mimetype`/`Content-Type`, or
  (d) accepts `image/svg+xml` (SVG carries inline <script>).
And the SERVE side leaks it when a file-serving response returns the stored object WITHOUT
`X-Content-Type-Options: nosniff` + a download disposition, so the object is re-interpreted as HTML
same-origin → stored XSS. The fix is defense-in-depth across BOTH upload and serve, so we check both.
"""

from __future__ import annotations

import re

from .base import Extractor, RepoContext, is_client_file, is_test_file
from .syntax import call_expression, direct_call, in_literal, js_functions, split_arguments, without_comments

UPLOAD_MARK = re.compile(r"\bmulter\b|req\.files?\b|multipart/form-data|formidable|busboy|fileFilter"
                         r"|uploadMedia|presignedPost|\.upload\s*\(", re.I)
DENY_LIST = re.compile(r"isExecutableMimeType|blockedMimeTypes|blacklist|deny[_-]?list|forbidden(?:Ext|Mime)|isBlocked", re.I)
# positive allow-list, ideally by sniffed bytes (file-type / magic detection), not by declared type.
# `ACCEPTED_*` / `acceptedMimeTypes` is the same intent under a different name (was missed → FP).
ALLOW_LIST = re.compile(r"isAllowedMediaType|allowedMimeTypes|allow[_-]?list|whitelist|ALLOWED_(?:MIME|TYPES|EXT)"
                        r"|ACCEPTED_(?:MIME|TYPES?|EXT)|accepted(?:Mime|File|Content)?(?:Types?|Extensions?)"
                        r"|\bfile-type\b|fileTypeFrom|magic[_-]?byte|detectContentType|\.fromBuffer\b|sniff", re.I)
KEY_FROM_NAME = re.compile(r"(?:Key|key|path|filepath|destination|filename\s*\()\s*[:=(][^;\n]{0,90}"
                           r"(?:\b(?:originalname|originalName|file\.name)\b|`[^`]*\$\{[^}]*\b(?:originalname|originalName)\b[^}]*\}[^`]*`)", re.I)

TRUST_CLIENT_MIME = re.compile(r"(?:\b(?:req|request)\.files?(?:\.[\w$]+)*|\bfile)\.mimetype\b|headers\[['\"]content-type['\"]\]", re.I)
ACCEPT_SVG = re.compile(r"image/svg\+xml|['\"]svg['\"]", re.I)
# file-serving: streaming a STORED/PROXIED object back to the client. Tightened to genuine
# file-bytes sinks — the old rule matched a bare `getObject` token (a local coercion helper) and a
# Prometheus `res.set('Content-Type', registry.contentType)` (the /metrics endpoint), both FPs.
SERVE_FILE = re.compile(r"res\.sendFile|\.sendFile\s*\(|\.getObject\s*\(|createReadStream|proxyMedia"
                        r"|streamObject|\.pipe\s*\(\s*res\b|fs\.createReadStream", re.I)
NOSNIFF = re.compile(r"nosniff", re.I)
# `Content-Disposition: attachment` fully defeats the MIME-sniff→stored-XSS vector (the browser
# downloads instead of rendering), so a serve site that sets it is SAFE even without nosniff.
ATTACHMENT = re.compile(r"attachment\s*;|disposition[^,;]{0,30}attachment|['\"]attachment['\"]|buildContentDisposition", re.I)


def _response_file_sites(source: str) -> list[dict]:
    """Find concrete response operations, not standalone filesystem/object reads."""
    sites = []
    sink = re.compile(r"\b([\w$]+)\.(sendFile|send)\s*\(|\.pipe\s*\(\s*(res|response)\b|\bnew\s+Response\s*\(")
    byte_source = re.compile(r"createReadStream|\breadFile(?:Sync)?\s*\(|\.getObject\s*\(|\bstreamObject\s*\(")
    for match in sink.finditer(source):
        if in_literal(source, match.start()):
            continue
        expression = call_expression(source, match.start())
        if match[2] == "send" or match[0].startswith("new"):
            args = split_arguments(expression[expression.find("(") + 1:-1])
            body = args[0] if args else ""
            if not any(not in_literal(body, item.start()) for item in byte_source.finditer(body)):
                continue
        elif match[2] == "sendFile":
            args = split_arguments(expression[expression.find("(") + 1:-1])
            if args:
                arg0 = args[0].strip()
                # Filter out pure string literal arguments for sendFile (e.g., hardcoded static paths)
                if re.fullmatch(r'''"[^"\\]*"|'[^'\\]*'|`[^`$\\]*`''', arg0):
                    continue

                # Further heuristics for static sendFile
                # if options variable is used, check if it contains a root definition before this call
                if len(args) > 1:
                    opt_var = args[1].strip()
                    if opt_var.isalnum():
                        # Look backward in the source for the assignment of this variable
                        # e.g., const options = { root: ... }
                        prefix = source[:match.start()]
                        if re.search(r'\b' + re.escape(opt_var) + r'\s*=\s*\{[^}]*\broot\s*:', prefix):
                            continue

        sites.append({"start": match.start(), "expression": expression,
                      "kind": match[2] or ("pipe" if match[3] else "response"),
                      "receiver": match[1] or match[3] or ""})
    return sites


def _object_properties(value: str, *, header_names: bool = False) -> dict | None:
    """Read direct object fields only; ambiguous spreads/duplicates stay unknown."""
    value = value.strip()
    if not value.startswith("{") or not value.endswith("}"):
        return None
    properties = {}
    for field in split_arguments(value[1:-1]):
        if not field:
            continue
        match = re.fullmatch(r'''(?:([\w$]+)|"([^"\\]+)"|'([^'\\]+)')\s*:\s*(.+)''', field, re.S)
        if not match:
            return None
        key = match[1] or match[2] or match[3]
        key = key.lower() if header_names else key
        if key in properties:
            return None
        properties[key] = match[4].strip()
    return properties


def _response_header_control(source: str, site: dict, scopes: list[dict]) -> bool:
    """Accept literal headers on this response or a straight header-only prefix."""
    expression = site["expression"]

    def protected(key, value):
        return ((key.lower() == "x-content-type-options" and value.lower() == "nosniff")
                or (key.lower() == "content-disposition" and re.match(r"attachment(?:\s*;|$)", value, re.I)))

    arguments = split_arguments(expression[expression.find("(") + 1:-1]) if expression.endswith(")") else []
    if len(arguments) > 1 and site["kind"] in {"sendFile", "response"}:
        options = _object_properties(arguments[1])
        if options is None:
            return False
        if "headers" in options:
            headers = _object_properties(options["headers"], header_names=True)
            if headers is None:
                return False
            # Only the direct response options.headers field controls this sink.
            # A headers object in the file-read argument or a nested unused option
            # is not response policy. Unknown values cannot prove protection.
            return any(re.fullmatch(r'''"[^"\\]*"|'[^'\\]*' ''', value, re.X)
                       and protected(key, value[1:-1]) for key, value in headers.items())
    scopes_here = [scope for scope in scopes if scope["body_start"] <= site["start"] < scope["end"]]
    scope = min(scopes_here, key=lambda row: row["end"] - row["start"]) if scopes_here else None
    start = scope["body_start"] if scope else 0
    # Everything before this statement must be a same-receiver header setter.
    prefix = source[start:site["start"]]
    prefix = prefix[:prefix.rfind(";") + 1].strip()
    if not prefix or not site["receiver"]:
        return False
    values = {}
    while prefix:
        setter = re.match(re.escape(site["receiver"]) + r"\.(?:setHeader|set|header)\s*\(", prefix)
        if not setter:
            return False
        call = call_expression(prefix, 0)
        args = split_arguments(call[call.find("(") + 1:-1])
        if len(args) != 2 or any(not re.fullmatch(r'''"[^"\\]*"|'[^'\\]*' ''', arg, re.X) for arg in args):
            return False
        values[args[0][1:-1].lower()] = args[1][1:-1]
        prefix = prefix[len(call):].lstrip()
        if not prefix.startswith(";"):
            return False
        prefix = prefix[1:].lstrip()
    return any(protected(key, value) for key, value in values.items())


def _byte_allowlist(scope: dict | None, file_object: str, source: str) -> bool:
    """A narrow detected-byte allowlist that rejects before processing this upload.

    Named predicates, imports and unrelated sniff calls remain unverified. The
    buffer must belong to the same file whose declared MIME is being consumed.
    """
    if not scope or not file_object or js_functions(scope["body"]):
        return False
    body = scope["body"].strip()
    sniff = re.match(r"const\s+([\w$]+)\s*=\s*await\s+fileTypeFromBuffer\(\s*"
                     + re.escape(file_object) + r"\.buffer\s*\)\s*;", body)
    if not sniff:
        return False
    if not direct_call("fileTypeFromBuffer(" + file_object + ".buffer)", "fileTypeFromBuffer", program=source):
        return False
    tail = body[sniff.end():].lstrip()
    guard = re.match(r"if\s*\(\s*" + re.escape(sniff[1])
                     + r"\??\.mime\s*!==\s*(['\"])(image/(?:png|jpeg|webp)|application/pdf)\1\s*\)\s*", tail)
    if not guard:
        return False
    stop = tail[guard.end():].lstrip()
    reject = re.match(r"(?:\{\s*)?return(?:\s+(?:false|null)|\s+[\w$]+\.status\(\s*(?:400|415)\s*\)\.(?:end|send)\(\s*\))?\s*;", stop)
    if not reject:
        return False
    # Mutating the file/detected object after the check breaks this simple proof.
    after = stop[reject.end():]
    roots = {file_object.split(".")[0], sniff[1]}
    for root in roots:
        if re.search(r"\b" + re.escape(root) + r"(?:\.[\w$]+)*\s*=(?!=)", after):
            return False
    return True



def _is_safe_mime(source: str, match) -> bool:
    line_start = source.rfind('\n', 0, match.start()) + 1
    line_end = source.find('\n', match.start())
    if line_end == -1:
        line_end = len(source)
    line = source[line_start:line_end]

    # We only consider it safe if the specific expression containing the match is a logging call.
    # To approximate this on a single line safely without parsing AST:
    # If there is a log call on the line, we check if the log call appears *before* the match
    # and there are no statement boundaries (; or { or }) between the log call and the match.
    log_match = re.search(r'\b(?:console\.(?:log|info|debug|warn|error)|logger\.(?:info|debug|warn|error|log))\b', line)
    if log_match:
        # Check from log_match to our actual match inside the line
        match_offset_in_line = match.start() - line_start
        if log_match.start() < match_offset_in_line:
            between = line[log_match.end():match_offset_in_line]
            if not re.search(r'[;{}]', between):
                return True
    return False

def _mime_unsafe(source: str, match, scopes: list[dict]) -> bool:
    containing = [scope for scope in scopes if scope["body_start"] <= match.start() < scope["end"]]
    scope = min(containing, key=lambda item: item["end"]-item["start"]) if containing else None
    file_match = re.search(r"([\w$]+(?:\.[\w$]+)*)\.mimetype", match[0])
    return not _byte_allowlist(scope, file_match[1] if file_match else "", source)


class UploadSecurityExtractor(Extractor):
    name = "upload_security"
    category = "sinks"

    def extract(self, ctx: RepoContext, facts: dict) -> dict:
        findings = []
        upload_files, serve_files = [], []
        for _p, rel, text in ctx.iter_code():
            # test fixtures/mocks aren't a deployed surface; a React CLIENT component (.tsx / 'use client')
            # renders <img src> and calls uploadMedia(file) but can NOT set HTTP response headers or build
            # an S3 key — flagging serve-nosniff/upload-from-filename on it is a category error (real-repo FP).
            if is_test_file(rel) or is_client_file(rel, text):
                continue
            is_upload = bool(UPLOAD_MARK.search(text))
            if is_upload:
                upload_files.append(rel)
                source = without_comments(text, _p.suffix)
                scopes = js_functions(source)
                mime_sites = [match for match in TRUST_CLIENT_MIME.finditer(source)
                              if not in_literal(source, match.start()) and not _is_safe_mime(source, match)]
                unsafe_mime = [match for match in mime_sites if _mime_unsafe(source, match, scopes)]
                deny_sites = [match for match in DENY_LIST.finditer(source) if not in_literal(source, match.start())]
                if deny_sites and (unsafe_mime or not mime_sites):
                    findings.append({"severity": "MEDIUM", "kind": "upload-denylist-only", "file": rel,
                                     "detail": "Upload handler blocks a deny-list but has no positive allow-list by "
                                               "SNIFFED magic bytes — a payload that sniffs to octet-stream/unknown "
                                               "passes. Allow-list the supported types by detected content, reject the rest."})
                if KEY_FROM_NAME.search(text):
                    findings.append({"severity": "HIGH", "kind": "upload-key-from-filename", "file": rel,
                                     "detail": "Stored object key/path is built from the client filename "
                                               "(`originalname`) — a polyglot named `Jpg.php` with valid image magic "
                                               "bytes is stored executable. Derive the stored name/extension from the "
                                               "DETECTED type, never the upload filename."})
                if unsafe_mime:
                    findings.append({"severity": "MEDIUM", "kind": "upload-trusts-client-mime", "file": rel,
                                     "line": source.count("\n", 0, unsafe_mime[0].start()) + 1,
                                     "detail": "Storage/validation decision uses the client-supplied `mimetype`/"
                                               "Content-Type, which is attacker-controlled. No supported enforcing "
                                               "byte-type allowlist was found for that file in the same handler; "
                                               "named helpers and complex controls remain unverified. Sniff the bytes instead."})
                if ACCEPT_SVG.search(text):
                    findings.append({"severity": "MEDIUM", "kind": "upload-accepts-svg", "file": rel,
                                     "detail": "`image/svg+xml` is accepted — SVG can carry inline <script> and renders "
                                               "as HTML. Drop SVG from the allow-list, or sanitize + serve as attachment."})
            if SERVE_FILE.search(text) or "Response" in text or ".send(" in text:
                source = without_comments(text, _p.suffix)
                sites = _response_file_sites(source)
                scopes = js_functions(source) if sites else []
                for site in sites:
                    if not _response_header_control(source, site, scopes):
                        serve_files.append(rel)
                        findings.append({"severity": "HIGH", "kind": "serve-no-nosniff", "file": rel,
                                         "line": source.count("\n", 0, site["start"]) + 1,
                                         "control_scope": "response operation; complex header flow unverified",
                                         "detail": "A file response has no supported literal nosniff or attachment "
                                                   "control bound to this operation. Verify its origin, content type "
                                                   "and headers before concluding stored XSS is reachable. Send "
                                                   "X-Content-Type-Options: nosniff and serve browser-executable "
                                                   "uploads as application/octet-stream with attachment disposition."})

        by_sev: dict = {}
        for f in findings:
            by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
        return {
            "findings": findings,
            "upload_handlers": sorted(set(upload_files))[:20],
            "serve_paths_no_nosniff": sorted(set(serve_files))[:20],
            "by_severity": by_sev,
            "note": ("Upload handler(s) detected — verify positive allow-list by sniffed bytes, stored name derived "
                     "from detected type, and nosniff+attachment on serve (REF-PENTEST #2b). " if upload_files
                     else "No upload handlers detected. ")
                    + "Probe with the upload matrix (polyglot, spoofed MIME, double-extension, SVG) then FETCH the "
                      "stored object back and assert it's served as octet-stream/attachment with nosniff.",
        }
