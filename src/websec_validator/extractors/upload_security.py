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

UPLOAD_MARK = re.compile(r"\bmulter\b|req\.files?\b|multipart/form-data|formidable|busboy|fileFilter"
                         r"|uploadMedia|presignedPost|\.upload\s*\(", re.I)
DENY_LIST = re.compile(r"isExecutableMimeType|blockedMimeTypes|blacklist|deny[_-]?list|forbidden(?:Ext|Mime)|isBlocked", re.I)
# positive allow-list, ideally by sniffed bytes (file-type / magic detection), not by declared type.
# `ACCEPTED_*` / `acceptedMimeTypes` is the same intent under a different name (was missed → FP).
ALLOW_LIST = re.compile(r"isAllowedMediaType|allowedMimeTypes|allow[_-]?list|whitelist|ALLOWED_(?:MIME|TYPES|EXT)"
                        r"|ACCEPTED_(?:MIME|TYPES?|EXT)|accepted(?:Mime|File|Content)?(?:Types?|Extensions?)"
                        r"|\bfile-type\b|fileTypeFrom|magic[_-]?byte|detectContentType|\.fromBuffer\b|sniff", re.I)
KEY_FROM_NAME = re.compile(r"(?:(?:upload)?[Kk]ey|path|filepath|destination|uploadDir)\s*[:=(][^;\n]{0,90}\b(?:originalname|originalName|file\.name)\b"
                           r"|(?:const|let|var)\s+filename\s*=\s*[^;\n]{0,90}\b(?:originalname|originalName|file\.name)\b"
                           r"|filename\s*[:(]\s*(?:function|\([^)]*\)\s*=>)[^;\n]{0,90}\b(?:originalname|originalName|file\.name)\b"
                           r"|`[^`]*\$\{[^}]*\boriginalname\b[^}]*\}[^`]*`", re.I)
TRUST_CLIENT_MIME = re.compile(r"(?:req\.files?\.[\w$.]*\.|\bfile\.)mimetype\b|headers\[['\"]content-type['\"]\]", re.I)
ACCEPT_SVG = re.compile(r"image/svg\+xml|['\"]svg['\"]", re.I)
# file-serving: streaming a STORED/PROXIED object back to the client. Tightened to genuine
# file-bytes sinks — the old rule matched a bare `getObject` token (a local coercion helper) and a
# Prometheus `res.set('Content-Type', registry.contentType)` (the /metrics endpoint), both FPs.
SERVE_FILE = re.compile(r"res\.sendFile|\.sendFile\s*\(|createReadStream|proxyMedia|streamObject|\.pipe\s*\(\s*res\b|fs\.createReadStream", re.I)
NOSNIFF = re.compile(r"nosniff", re.I)
# `Content-Disposition: attachment` fully defeats the MIME-sniff→stored-XSS vector (the browser
# downloads instead of rendering), so a serve site that sets it is SAFE even without nosniff.
ATTACHMENT = re.compile(r"attachment\s*;|disposition[^,;]{0,30}attachment|['\"]attachment['\"]|buildContentDisposition", re.I)


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
                if DENY_LIST.search(text) and not ALLOW_LIST.search(text):
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
                if TRUST_CLIENT_MIME.search(text) and not ALLOW_LIST.search(text):
                    findings.append({"severity": "MEDIUM", "kind": "upload-trusts-client-mime", "file": rel,
                                     "detail": "Storage/validation decision uses the client-supplied `mimetype`/"
                                               "Content-Type, which is attacker-controlled. Sniff the bytes instead."})
                if ACCEPT_SVG.search(text):
                    findings.append({"severity": "MEDIUM", "kind": "upload-accepts-svg", "file": rel,
                                     "detail": "`image/svg+xml` is accepted — SVG can carry inline <script> and renders "
                                               "as HTML. Drop SVG from the allow-list, or sanitize + serve as attachment."})
            if SERVE_FILE.search(text) and not NOSNIFF.search(text) and not ATTACHMENT.search(text):
                serve_files.append(rel)
                findings.append({"severity": "HIGH", "kind": "serve-no-nosniff", "file": rel,
                                 "detail": "A stored/proxied file is served with no `X-Content-Type-Options: nosniff` "
                                           "and no `Content-Disposition: attachment` — the browser MIME-sniffs the body "
                                           "and can render a stored file as HTML same-origin (stored XSS). Always send "
                                           "nosniff, and force any browser-executable type (html/svg/xml/js) to "
                                           "`application/octet-stream` + attachment."})

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
