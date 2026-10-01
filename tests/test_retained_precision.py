"""Paired reproducers for retained precision intents; safe siblings cannot hide unsafe sites.

@req specs/001-continuous-security-improvement/spec.md#FR-002
"""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor
from websec_validator.extractors.upload_security import UploadSecurityExtractor
from websec_validator.extractors.pii_exposure import PiiExposureExtractor
from websec_validator.extractors.surface import SurfaceExtractor
from websec_validator.extractors.llm_security import LlmSecurityExtractor


class RetainedPrecisionTests(unittest.TestCase):
    def scan(self, extractor, source, suffix='.js'):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / ('app' + suffix)).write_text(source)
            return extractor().extract(RepoContext(root), {
                'stack': {'frameworks': ['express'], 'datastores': ['postgres']},
                'routes': {'endpoints': [{'method': 'POST', 'path': '/x', 'code_path': 'app' + suffix}]}})

    def kinds(self, extractor, source, suffix='.js'):
        return [row['kind'] for row in self.scan(extractor, source, suffix)['findings']]

    def test_jwt_direct_options_and_unsafe_sibling(self):
        safe = 'jwt.verify(token,key,{algorithms:["HS256"]});'
        self.assertNotIn('jwt-verify-no-algorithms', self.kinds(CryptoUsageExtractor, safe))
        self.assertIn('jwt-verify-no-algorithms', self.kinds(CryptoUsageExtractor, safe + 'jwt.verify(other,key);'))

    def test_jwt_nested_unknown_spread_duplicate_or_empty_options_are_not_policy(self):
        for options in ('{unused:{algorithms:["HS256"]}}', 'config', '{algorithms:[]}',
                        '{algorithms:["HS256"],...unknown}', '{algorithms:["HS256"],algorithms:[]}',
                        '{algorithms:["none"]}', '{algorithms:algorithms}'):
            with self.subTest(options=options):
                self.assertIn('jwt-verify-no-algorithms', self.kinds(CryptoUsageExtractor,
                              'jwt.verify(token,key,' + options + ');'))

    def test_jwt_quoted_example_and_comment_are_not_invocations(self):
        for source in ('const example="jwt.verify(token,key)";', '// jwt.verify(token,key)\n'):
            self.assertNotIn('jwt-verify-no-algorithms', self.kinds(CryptoUsageExtractor, source))

    def test_upload_logs_comments_and_generated_key_are_not_name_storage(self):
        for middle in ('console.log("key="+req.file.originalname);', '// key = req.file.originalname\n'):
            source = 'app.post("/upload",(req,res)=>{' + middle + 'store({Key:randomUUID()});});'
            self.assertNotIn('upload-key-from-filename', self.kinds(UploadSecurityExtractor, source))
        self.assertIn('upload-key-from-filename', self.kinds(UploadSecurityExtractor,
                      'app.post("/upload",(req,res)=>{store({Key:req.file.originalname});});'))

    def test_svg_rejection_prose_vs_actual_acceptance(self):
        reject = 'app.post("/upload",(req,res)=>{if(req.file.mimetype==="image/svg+xml") return res.status(415).end();store(req.file.buffer);});'
        self.assertNotIn('upload-accepts-svg', self.kinds(UploadSecurityExtractor, reject))
        accept = 'app.post("/upload",(req,res)=>{if(req.file.mimetype==="image/svg+xml") store(req.file.buffer);});'
        self.assertIn('upload-accepts-svg', self.kinds(UploadSecurityExtractor, accept))

    def test_pii_boolean_is_not_raw_customer(self):
        for sent in ('true', 'false', 'Boolean(customer)', '!!customer'):
            source = 'app.get("/x",(req,res)=>{const customer=db.get("email phone");res.json(' + sent + ');});'
            self.assertNotIn('raw-entity-pii-response', self.kinds(PiiExposureExtractor, source))
        source = 'app.get("/x",(req,res)=>{const customer=db.get("email phone");const exists=Boolean(customer);res.json(exists);});'
        self.assertNotIn('raw-entity-pii-response', self.kinds(PiiExposureExtractor, source))

    def test_svg_allowlist_callback_and_unused_nested_store(self):
        for source in ('const allowed=["image/svg+xml"];if(allowed.includes(req.file.mimetype))store(req.file.buffer);',
                       'multer({fileFilter:(req,file,cb)=>{cb(null,file.mimetype==="image/svg+xml");}});'):
            self.assertIn('upload-accepts-svg', self.kinds(UploadSecurityExtractor, source))
        for source in ('const allowed=["image/svg+xml"];store(req.file.buffer);',
                       'multer({fileFilter:(req,file,cb)=>{cb(null,false);}});',
                       'const allowed=["image/png"];function unused(){const allowed=["image/svg+xml"];}if(allowed.includes(req.file.mimetype))store(req.file.buffer);',
                       'if(req.file.mimetype==="image/svg+xml"){function unused(){cb(null,req.file.mimetype==="image/svg+xml");}}',
                       'if(req.file.mimetype==="image/svg+xml"){function unused(){store(req.file.buffer);}}'):
            self.assertNotIn('upload-accepts-svg', self.kinds(UploadSecurityExtractor, source))

    def test_only_literal_destructured_keys_prove_pii_removal(self):
        for fields, safe in (('email,phone', True), ('[email]:ignored,phone', False)):
            source = 'app.get("/x",(req,res)=>{const customer=db.get("email phone");const {' + fields + ',...safe}=customer;res.json(safe);});'
            self.assertEqual('raw-entity-pii-response' in self.kinds(PiiExposureExtractor, source), not safe)

    def test_partial_pii_removal_keeps_remaining_field_visible(self):
        for projection in ('const {email,...safe}=customer;', "const safe=omit(customer,['email']);"):
            source = 'app.get("/x",(req,res)=>{const customer=db.get("email phone");' + projection + 'res.json(safe);});'
            self.assertIn('raw-entity-pii-response', self.kinds(PiiExposureExtractor, source))

    def test_static_regex_self_vs_actual_request_pattern(self):
        out = self.scan(SurfaceExtractor, 'import re\npattern=re.compile("self")\n', '.py')
        self.assertEqual(out['sink_counts'].get('redos', 0), 0)
        out = self.scan(SurfaceExtractor, 'import re\npattern=re.compile(request.args["pattern"])\n', '.py')
        self.assertEqual(out['sink_counts'].get('redos', 0), 1)

    def test_quoted_node_env_vs_real_error_response(self):
        out = self.scan(SurfaceExtractor, 'const hint="NODE_ENV !== \'production\' stack";')
        self.assertEqual(out['sink_counts'].get('error-disclosure', 0), 0)
        out = self.scan(SurfaceExtractor, 'app.get("/x",(req,res)=>{try{work()}catch(err){res.status(500).json({error:err.stack})}});')
        self.assertEqual(out['sink_counts'].get('error-disclosure', 0), 1)

    def test_guard_failure_must_belong_to_security_invocation(self):
        for source in ('function scan_dir(path){try{return readDir(path);}catch(e){return {allowed:true};}}',
                       'const scanner=new Scanner();function list(path){try{return scanner.scan_dir(path);}catch(e){return {allowed:true};}}',
                       'async function moderate(text){return checkContent(text);}function other(){try{otherWork();}catch(e){return {allowed:true};}}',
                       'async function moderate(text){try{return await checkContent(text);}catch(e){return "example: allowed:true";}}'):
            with self.subTest(source=source):
                self.assertNotIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor, source))
        source = 'async function moderate(text){try{return await checkContent(text);}catch(e){return {allowed:true};}}'
        self.assertIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor, source))
        self.assertIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor,
                      'export async function scanInput(t){try{return await check(t);}catch(e){return {allowed:true}}}'))


if __name__ == '__main__':
    unittest.main()
