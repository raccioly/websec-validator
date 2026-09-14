"""Inert paired reproductions derived from selected pinned public-source leads."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from websec_validator.extractors.authz import AuthzExtractor
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.iac_ci import IacCiExtractor
from websec_validator.extractors.upload_security import UploadSecurityExtractor


class PublicPrecisionTests(unittest.TestCase):
    def scan(self, cls, files, facts=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for rel, source in files.items():
                path = root / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source)
            return cls().extract(RepoContext(root), facts or {})

    def decoders(self, source):
        return self.scan(AuthzExtractor, {"module.ts": source})["unsafe_auth_decoders"]

    def test_archive_error_messages_are_not_auth_decisions(self):
        # Actual f8ad7c0: error.ts formats ZIP metadata; unauthorized is message text.
        source = "function getUnsafeZipError(meta){return 'unauthorized';} getUnsafeZipError(meta);"
        self.assertEqual(self.decoders(source), [])
        self.assertEqual(self.decoders(source.replace("Zip", "Archive")), [])
        self.assertEqual(self.decoders("// requireAdmin(token)\nparseUnsafeArchive(meta);"), [])

    def test_real_token_decoders_and_renamed_guards_remain_visible(self):
        for name in ("requireAuth", "requireAdmin", "authorizeUser"):
            source = "function " + name + "(token){const claims=decodeJwtPayloadUnsafe(token);if(claims.role==='admin')return claims;}"
            self.assertEqual([row["decoder"] for row in self.decoders(source)], ["decodeJwtPayloadUnsafe"])

    def test_sibling_auth_helpers_do_not_taint_archive_calls(self):
        source = "function format(meta){return getUnsafeZipError(meta);} function requireAdmin(req){return checkedSession(req);}"
        self.assertEqual(self.decoders(source), [])
        source += "function requireAuth(req){return decodeJwtPayloadUnsafe(req.cookies.sid);}"
        rows = self.decoders(source)
        self.assertEqual([row["decoder"] for row in rows], ["decodeJwtPayloadUnsafe"])
        self.assertEqual(rows[0]["guard"], "requireAuth")

    def test_only_guard_containing_decoder_marks_routes_at_risk(self):
        files = {"auth.ts": "export function requireAuth(req){return decodeJwtPayloadUnsafe(req.cookies.sid);} export function requireAdmin(req){return checkedSession(req);}",
                 "raw.ts": "import {requireAuth} from './auth'; export function GET(req){return requireAuth(req);}",
                 "checked.ts": "import {requireAdmin} from './auth'; export function GET(req){return requireAdmin(req);}"}
        facts = {"routes": {"endpoints": [{"method": "GET", "path": "/raw", "code_path": "raw.ts"},
                                            {"method": "GET", "path": "/checked", "code_path": "checked.ts"}]}}
        out = self.scan(AuthzExtractor, files, facts)
        self.assertIn("GET /raw", out["unverified_signature_routes"])
        self.assertNotIn("GET /checked", out["unverified_signature_routes"])

    def serves(self, source):
        return [f for f in self.scan(UploadSecurityExtractor, {"module.js": source})["findings"]
                if f["kind"] == "serve-no-nosniff"]

    def test_local_file_and_object_reads_do_not_imply_browser_delivery(self):
        # Actual release-note checker and filesystem adapter use local stream destinations.
        for source in ("fs.createReadStream(path).pipe(process.stdout);",
                       "fs.createReadStream(from).pipe(fs.createWriteStream(to));",
                       "export function readFile(path){return fs.createReadStream(path);}",
                       "const object=await s3.getObject(key);cache(object);",
                       "new Response('hello',{extra:()=>fs.createReadStream(path)});",
                       'const sample="res.sendFile(path)"; // createReadStream\n'):
            self.assertEqual(self.serves(source), [])

    def test_real_response_operations_remain_visible(self):
        for source in ("res.sendFile(path);", "getObject(key).pipe(res);",
                       "function serve(req,res){fs.createReadStream(req.query.file).pipe(res);}",
                       "return new Response(await readFile(path));",
                       "reply.send(fs.createReadStream(path));"):
            self.assertEqual(len(self.serves(source)), 1)

    def test_headers_bind_to_the_actual_response(self):
        for source in ("res.sendFile(path,{headers:{'Content-Disposition':'attachment; filename=x'}});",
                       "function serve(req,res){res.setHeader('X-Content-Type-Options','nosniff');getObject(key).pipe(res);}"):
            self.assertEqual(self.serves(source), [])
        for extra in ("// nosniff\n", "function other(res){res.setHeader('X-Content-Type-Options','nosniff');}",
                      "const disposition='attachment';"):
            self.assertEqual(len(self.serves(extra + "res.sendFile(path);")), 1)
        self.assertEqual(len(self.serves("function serve(req,res){if(ok)res.setHeader('X-Content-Type-Options','nosniff');res.sendFile(path);}")), 1)
        self.assertEqual(len(self.serves("function serve(req,res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Content-Type-Options','other');res.sendFile(path);}")), 1)
        self.assertEqual(len(self.serves("res.sendFile(path,{unused:{'X-Content-Type-Options':'nosniff'}});")), 1)
        self.assertEqual(len(self.serves("res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff','X-Content-Type-Options':'other'}});")), 1)

    def test_nested_or_file_read_headers_do_not_protect_response(self):
        for source in ("res.sendFile(path,{unused:{headers:{'X-Content-Type-Options':'nosniff'}}});",
                       "return new Response(await readFile(path,{headers:{'X-Content-Type-Options':'nosniff'}}));",
                       "new Response(readFile(path),{unused:{headers:{'X-Content-Type-Options':'nosniff'}}});",
                       "res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff'},...options});",
                       "res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff',[name]:value}});",
                       "res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff'},headers:other});",
                       "res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff'},[key]:other});",
                       "getObject(key).pipe(res,{headers:{'X-Content-Type-Options':'nosniff'}});",
                       "new Response(readFile(path),{HEADERS:{'X-Content-Type-Options':'nosniff'}});",
                       "res.sendFile(path,{Headers:{'X-Content-Type-Options':'nosniff'}});",
                       "res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff' + suffix}});"):
            with self.subTest(source=source):
                self.assertEqual(len(self.serves(source)), 1)
        for source in ("res.sendFile(path,{headers:{'X-Content-Type-Options':'nosniff'}});",
                       "new Response(readFile(path),{headers:{'X-Content-Type-Options':'nosniff'}});",
                       "new Response(readFile(path),{headers:{'x-content-type-options':'nosniff'}});"):
            self.assertEqual(self.serves(source), [])

    def workflow(self, expression):
        source = "jobs:\n  job:\n    steps:\n      - run: echo " + expression + "\n"
        return [f for f in self.scan(IacCiExtractor, {".github/workflows/main.yml": source})["findings"]
                if f["kind"] == "gha-script-injection"]

    def test_exact_numeric_contexts_are_not_script_injection(self):
        for expression in ("${{ github.event.issue.number }}", "${{ github.event.pull_request.number }}"):
            self.assertEqual(self.workflow(expression), [])

    def test_text_and_mixed_context_expressions_remain_high(self):
        for expression in ("${{ github.event.issue.title }}", "${{ github.event.comment.body }}",
                           "${{ github.head_ref }}", "${{ github.event.issue.number || github.event.issue.title }}",
                           "${{ github.event.pull_request.head.sha || github.event.issue.title }}",
                           "${{ github.event.issue.unknown_number }}"):
            self.assertEqual([f["severity"] for f in self.workflow(expression)], ["HIGH"])


if __name__ == "__main__":
    unittest.main()
