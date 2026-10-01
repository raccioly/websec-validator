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

    def test_identity_hash_must_flow_to_actual_principal_use(self):
        for source in ('function avatar(email){const h=createHash("sha256").update(email).digest("hex");return h;}\nconst userId=req.user.id;',
                       'const avatar=createHash("sha256").update(email).digest("hex");const tenantId=randomUUID();',
                       'function avatar(email){const h=createHash("sha256").update(email).digest("hex");const userId=req.user.id;return h;}',
                       'function id(email){let h=createHash("sha256").update(email).digest("hex");h=randomUUID();return formatUuid(h);}',
                       'const tenantId=()=>createHash("sha256").update(email).digest("hex");',
                       'const tenantId=createHash("sha256").update("email").digest("hex");',
                       'const tenantId=createHash("sha256").update(email).digest("hex")==="";',
                       'const example="tenantId = createHash(\'sha256\').update(email).digest(\'hex\')";'):
            with self.subTest(source=source):
                self.assertNotIn('predictable-principal', self.kinds(CryptoUsageExtractor, source))
        for source in ('const tenantId=createHash("sha256").update(email).digest("hex");',
                       'function id(email){const h=createHash("sha256").update(email).digest("hex");return formatUuid(h);}',
                       'function id(email){const h=createHash("sha256").update(email).digest("hex");const tenantId=h;return tenantId;}'):
            with self.subTest(source=source):
                self.assertIn('predictable-principal', self.kinds(CryptoUsageExtractor, source))

    def test_password_update_metadata_does_not_hide_actual_credentials(self):
        for value in ('passwordUpdatedAt', 'password_updated_at', 'passwordUpdatedTimestamp'):
            with self.subTest(value=value):
                self.assertNotIn('weak-password-hash', self.kinds(CryptoUsageExtractor,
                    'createHash("sha256").update(' + value + ').digest("hex");'))
                self.assertIn('weak-password-hash', self.kinds(CryptoUsageExtractor,
                    'createHash("sha256").update(' + value + ' + password).digest("hex");'))
                self.assertNotIn('weak-password-hash', self.kinds(CryptoUsageExtractor,
                    'function verifyPassword(){return createHash("sha256").update(' + value + ').digest("hex");}'))

    def test_hibp_prefix_purpose_binds_only_its_own_digest(self):
        safe = ('import { createHash } from "node:crypto";\nasync function checkBreached(password){'
                'const hash=createHash("sha1").update(password).digest("hex").toUpperCase();'
                'const prefix=hash.slice(0,5);const suffix=hash.slice(5);'
                'const response=await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);'
                'return (await response.text()).includes(suffix);}')
        self.assertNotIn('weak-password-hash', self.kinds(CryptoUsageExtractor, safe))
        for source in (safe + 'function setPassword(password){return createHash("sha1").update(password).digest("hex");}',
                       safe.replace('hash.slice(0,5)', 'hash.slice(0,6)'),
                       safe.replace('api.pwnedpasswords.com', 'api.pwnedpasswords.com.evil.test'),
                       safe.replace('${prefix}', '${hash}'),
                       safe.replace('(password){', '(password,fetch){'),
                       safe.replace('(password){', '(password,createHash){'),
                       'fetch=sendToElsewhere;' + safe,
                       'createHash=fakeHash;' + safe,
                       'const {fetch}=other;' + safe,
                       'Object.defineProperty(globalThis,"fetch",{value:other});' + safe,
                       safe.split('\n')[0] + '\nfunction outer(fetch){' + safe.split('\n',1)[1] + '}',
                       safe.split('\n')[0] + '\nfunction outer(createHash){' + safe.split('\n',1)[1] + '}',
                       safe.replace('return (await', 'savePasswordHash(hash);return (await')):
            with self.subTest(source=source):
                self.assertIn('weak-password-hash', self.kinds(CryptoUsageExtractor, source))

    def test_python_principal_result_binding_and_unrelated_identity_hash(self):
        for source, expected in (
                ('import hashlib\navatar=hashlib.sha256(email.encode()).hexdigest()\nuser_id=random_id()', False),
                ('import hashlib\ntenant_id=hashlib.sha256(email.encode()).hexdigest()', True),
                ('import hashlib\nh=hashlib.sha256(email.encode()).hexdigest()\nuser_id=h', True),
                ('import hashlib\nh=hashlib.sha256(email.encode()).hexdigest()\nh=random_id()\nuser_id=h', False),
                ('tenant_id="hashlib.sha256(email)"', False),
                ('import hashlib\ntenant_id=lambda:hashlib.sha256(email.encode()).hexdigest()', False),
                ('import hashlib\ntenant_id=hashlib.sha256(b"email").hexdigest()', False),
                ('import hashlib\ndef avatar(email):\n h=hashlib.sha256(email.encode()).hexdigest()\n return h\ndef other():\n user_id=h', False)):
            with self.subTest(source=source):
                self.assertEqual('predictable-principal' in self.kinds(CryptoUsageExtractor, source, '.py'), expected)

    def test_principal_branch_overwrite_does_not_clear_may_flow(self):
        source = ('function id(email){let h=createHash("sha256").update(email).digest("hex");'
                  'if(flag){h=randomUUID();}return formatUuid(h);}')
        self.assertIn('predictable-principal', self.kinds(CryptoUsageExtractor, source))

    def test_hash_analysis_budget_discloses_incompleteness(self):
        from unittest.mock import patch
        from websec_validator.extractors import crypto_usage
        with patch.object(crypto_usage, 'MAX_HASH_EVENTS', 1):
            result = self.scan(CryptoUsageExtractor, 'const h=createHash("sha256").update(email).digest("hex");const tenantId=h;')
        self.assertTrue(result.get('error'))
        self.assertTrue(result['hash_flow']['errors'])

    def test_upload_logs_comments_and_generated_key_are_not_name_storage(self):
        for middle in ('console.log("key="+req.file.originalname);', '// key = req.file.originalname\n'):
            source = 'app.post("/upload",(req,res)=>{' + middle + 'store({Key:randomUUID()});});'
            self.assertNotIn('upload-key-from-filename', self.kinds(UploadSecurityExtractor, source))
        self.assertIn('upload-key-from-filename', self.kinds(UploadSecurityExtractor,
                      'app.post("/upload",(req,res)=>{store({Key:req.file.originalname});});'))

    def test_filename_binding_requires_storage_not_a_variable_name(self):
        for middle, unsafe in (
                ('const filename=req.file.originalname;logger.info(filename);store({Key:randomUUID()});', False),
                ('const chosen=req.file.originalname;store({Key:chosen});', True),
                ('let chosen=req.file.originalname;chosen=randomUUID();store({Key:chosen});', False),
                ('let chosen=req.file.originalname;if(flag){chosen=randomUUID();}store({Key:chosen});', True),
                ('function unused(){const chosen=req.file.originalname;}store({Key:chosen});', False),
                ('const chosen=req.file.originalname;store({Key:randomUUID(),Body:chosen});', False),
                ('const chosen=req.file.originalname;fs.writeFile(chosen,req.file.buffer);', True)):
            with self.subTest(middle=middle):
                source = 'app.post("/upload",(req,res)=>{' + middle + '});'
                self.assertEqual('upload-key-from-filename' in self.kinds(UploadSecurityExtractor, source), unsafe)

    def test_pii_projector_keys_and_implementation_must_be_unambiguous(self):
        for projection, unsafe in (
                ('const safe=pick(customer,["id"]);', False),
                ('const safe=pick(customer,[field]);', True),
                ('const safe=pick(customer,["id",...fields]);', True),
                ('const safe=pick(customer,["id"]) && customer;', True),
                ('const safe=omit(customer,["email","phone"]) || customer;', True),
                ('function omit(customer,keys){return customer;}const safe=omit(customer,["email","phone"]);', True),
                ('omit=passthrough;const safe=omit(customer,["email","phone"]);', True),
                ('_.pick=passthrough;const safe=_.pick(customer,["id"]);', True),
                ('const safe=omit(customer,["email","phone"]);', False)):
            with self.subTest(projection=projection):
                source = 'app.get("/x",(req,res)=>{const customer=db.get("email phone");' + projection + 'res.json(safe);});'
                self.assertEqual('raw-entity-pii-response' in self.kinds(PiiExposureExtractor, source), unsafe)

    def test_filename_assignment_expression_budget_is_an_execution_gap(self):
        source = 'const chosen=' + ' '*9000 + 'req.file.originalname;store({Key:chosen});'
        result = self.scan(UploadSecurityExtractor, source)
        self.assertTrue(result.get('error'))
        self.assertTrue(result['filename_analysis']['errors'])

    def test_static_fstring_and_dynamic_interpolation_are_distinct(self):
        for argument, count in (('f"self"', 0), ('rf"self"', 0), ('f"request.args"', 0),
                                ('f"{{self}}"', 0), ('f"{request.args[\'pattern\']}"', 1)):
            with self.subTest(argument=argument):
                out = self.scan(SurfaceExtractor, 'import re\npattern=re.compile(' + argument + ')\n', '.py')
                self.assertEqual(out['sink_counts'].get('redos', 0), count)

    def test_nested_try_security_failure_belongs_to_its_own_catch(self):
        deny = ('async function moderate(text){try{try{return await checkContent(text);}'
                'catch(e){return {allowed:false};}otherWork();}catch(e){return {allowed:true};}}')
        self.assertNotIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor, deny))
        self.assertIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor,
                      deny.replace('return {allowed:false}', 'return {allowed:true}')))
        self.assertIn('llm-guardrail-fail-open', self.kinds(LlmSecurityExtractor,
                      deny.replace('otherWork()', 'checkContent(text)')))

    def test_actual_cli_persists_operation_bound_precision_facts_and_ledger(self):
        import json
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            target = owner / 'target'
            target.mkdir()
            (target / 'app.js').write_text(
                'app.post("/upload",(req,res)=>{const chosen=req.file.originalname;store({Key:chosen});});'
                'app.get("/pii",(req,res)=>{const customer=db.get("email phone");const safe=pick(customer,[field]);res.json(safe);});'
                'async function moderate(text){try{return await checkContent(text);}catch(e){return {allowed:true};}}')
            (target / 'patterns.py').write_text('from flask import request\nimport re\n'
                'inert=re.compile(f"self")\npattern=re.compile(f"{request.args[\'pattern\']}")\n')
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            result = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(target),
                '--out', str(out), '--format', 'json', '--fail-on', 'medium', '--require-complete'],
                cwd=owner, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 1, result.stderr)
            envelope = json.loads(result.stdout)
            run = out / 'runs' / envelope['generated']
            facts = json.loads((run / 'FACTS.json').read_text())
            self.assertTrue(facts['coverage']['execution_complete'])
            self.assertEqual(facts['surface']['sink_counts']['redos'], 1)
            self.assertTrue(facts['upload_security']['filename_analysis']['occurrences'])
            for dimension, kind in (('upload_security', 'upload-key-from-filename'),
                                    ('pii_exposure', 'raw-entity-pii-response'),
                                    ('llm_security', 'llm-guardrail-fail-open')):
                self.assertTrue(any(row['kind'] == kind for row in facts[dimension]['findings']))
            ledger = json.loads((run / 'findings-ledger.json').read_text())
            self.assertTrue(ledger['findings'])

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
