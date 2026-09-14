"""Controls in comments, sibling functions and other routes cannot hide a sink."""
from pathlib import Path
import sys
import tempfile
import unittest
import os
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.integrations import IntegrationsExtractor
from websec_validator.extractors.upload_security import UploadSecurityExtractor
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor
from websec_validator.extractors.auth import AuthExtractor
from websec_validator.extractors.syntax import js_functions


class RemainingControlScopeTests(unittest.TestCase):
    def scan(self, extractor, source, name='app.js', route='/webhooks/payments'):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/name; path.write_text(source)
            facts={'routes':{'endpoints':[{'method':'POST','path':route,'code_path':str(path)}]}}
            return extractor().extract(RepoContext(root), facts)

    def webhook(self, source):
        return self.scan(IntegrationsExtractor,source)['webhooks_without_sig_verification']

    def kinds(self, extractor, source, name='app.js'):
        return {row['kind'] for row in self.scan(extractor,source,name)['findings']}

    def test_unsigned_webhook_is_not_protected_by_comment_or_sibling(self):
        base="app.post('/webhooks/payments',(req,res)=>{fulfillOrder(req.body);res.end();});"
        for extra in ('', '\n// TODO verifyWebhook(req.body)',
                      '\nfunction other(body,sig,key){return stripe.webhooks.constructEvent(body,sig,key);}',
                      '\nconst example="verifyWebhook(req.body)";',
                      "\napp.post('/webhooks/other',(req,res)=>{const event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],endpointSecret);fulfillOrder(event);});"):
            with self.subTest(extra=extra): self.assertEqual(len(self.webhook(base+extra)),1)

    def test_actual_webhook_control_and_unverified_variants(self):
        safe="app.post('/webhooks/payments',(req,res)=>{const event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],endpointSecret);fulfillOrder(event);res.end();});"
        self.assertEqual(self.webhook(safe),[])
        for unsafe in (safe.replace('constructEvent(req.body','constructEvent(other.body'),
                       safe.replace('endpointSecret','req.secret'),
                       safe.replace('const event=stripe.webhooks.constructEvent', 'const event=verifyWebhook'),
                       "app.post('/webhooks/payments',(req,res)=>{console.log(req.headers['stripe-signature']);fulfillOrder(req.body);});",
                       "app.post('/webhooks/payments',(req,res)=>{fulfillOrder(req.body);const event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],endpointSecret);});"):
            self.assertEqual(len(self.webhook(unsafe)),1)

    def test_hmac_rejecting_control_and_replaced_primitive(self):
        safe="const crypto=require('crypto');app.post('/webhooks/payments',(req,res)=>{const h=crypto.createHmac('sha256',key).update(req.body).digest('hex');if(h!==req.headers['stripe-signature'])return res.status(401).end();fulfillOrder(req.body);});"
        self.assertEqual(self.webhook(safe),[])
        self.assertEqual(len(self.webhook(safe+'crypto.createHmac=fake;')),1)

    def test_verified_webhook_payload_cannot_be_replaced(self):
        head="app.post('/webhooks/payments',(req,res)=>{const event=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],endpointSecret);"
        self.assertEqual(self.webhook(head+'fulfillOrder(event);res.end();});'),[])
        for write in ('req.body=req.query;', "req['body']=req.query;", 'req=other;',
                      'req[field]=req.query;', 'Object.assign(req,{body:req.query});'):
            self.assertEqual(len(self.webhook(head+write+'fulfillOrder(req.body);res.end();});')),1)

    def test_upload_mime_comment_and_unrelated_sniff_do_not_suppress(self):
        base="app.post('/upload',upload.single('file'),(req,res)=>{if(req.file.mimetype === 'image/png') save(req.file.buffer);res.end();});"
        for extra in ('', '\n// TODO sniff magic bytes', '\nasync function other(buffer){return fileTypeFromBuffer(buffer);}',
                      '\nconst note="allowedMimeTypes";'):
            with self.subTest(extra=extra): self.assertIn('upload-trusts-client-mime',self.kinds(UploadSecurityExtractor,base+extra))

    def test_byte_allowlist_must_guard_same_file(self):
        safe="app.post('/upload',upload.single('file'),async(req,res)=>{const type=await fileTypeFromBuffer(req.file.buffer);if(type?.mime !== 'image/png')return res.status(415).end();save(req.file.buffer,req.file.mimetype);});"
        self.assertNotIn('upload-trusts-client-mime',self.kinds(UploadSecurityExtractor,safe))
        for unsafe in (safe.replace('fileTypeFromBuffer(req.file.buffer)','fileTypeFromBuffer(other.buffer)'),
                       safe.replace("!== 'image/png'", "=== 'image/png'"),
                       safe.replace('return res.status(415).end();','console.log(type.mime);'),
                       safe.replace('save(req.file.buffer','req.file=other;save(req.file.buffer'),
                       safe+'\nfunction fileTypeFromBuffer(buffer){return {mime:"image/png"};}'):
            with self.subTest(unsafe=unsafe): self.assertIn('upload-trusts-client-mime',self.kinds(UploadSecurityExtractor,unsafe))

    def test_weak_hash_survives_pkce_and_kdf_mentions(self):
        for base in ("function hashPassword(password){return crypto.createHash('sha256').update(password).digest('hex');}",
                     "function verifyPassword(input){return createHash('sha256').update(input).digest('hex');}"):
            for extra in ('', '\n// PKCE support planned',
                          "\nfunction oauth(codeVerifier){return crypto.createHash('sha256').update(codeVerifier).digest('base64url');}",
                          '\nfunction other(value){return bcrypt.hash(value,12);}'):
                with self.subTest(base=base,extra=extra): self.assertIn('weak-password-hash',self.kinds(CryptoUsageExtractor,base+extra))

    def test_pkce_exception_belongs_only_to_its_own_hash_argument(self):
        weak="const digest=crypto.createHash('sha256').update(input).digest('hex');"
        pkce="const challenge=crypto.createHash('sha256').update(codeVerifier).digest('base64url');"
        for body in (weak+pkce,pkce+weak):
            self.assertIn('weak-password-hash',self.kinds(CryptoUsageExtractor,'function hashPassword(input){'+body+'return digest;}'))
        self.assertNotIn('weak-password-hash',self.kinds(CryptoUsageExtractor,'function hashPassword(input){const digest=bcrypt.hash(input,12);'+pkce+'return digest;}'))

    def test_python_direct_password_hash_and_legitimate_pkce(self):
        self.assertIn('weak-password-hash',self.kinds(CryptoUsageExtractor,'import hashlib\ndef hash_password(password):\n return hashlib.sha256(password.encode()).hexdigest()\n# PKCE here\n','auth.py'))
        for safe in ("function oauth(codeVerifier){return crypto.createHash('sha256').update(codeVerifier).digest('base64url');}",
                     "function hashPassword(password){return bcrypt.hash(password,12);}",
                     "// createHash('sha256').update(password)\nconst help='PKCE';"):
            self.assertNotIn('weak-password-hash',self.kinds(CryptoUsageExtractor,safe))

    def test_scope_locator_long_identifiers_and_many_siblings_have_hard_deadline(self):
        script = "from websec_validator.extractors.syntax import js_functions\nassert js_functions('a'*25000)==[]\nsource=''.join('function f'+str(i)+'(x){return x;}' for i in range(2000))\nassert len(js_functions(source))==2000\n"
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True, timeout=5,
                                env={**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1]/'src')})
        self.assertEqual(result.returncode,0,result.stderr)

    def test_scope_locator_keeps_literals_opaque_and_nested_scopes_distinct(self):
        source = 'const s="function fake(x){return x}"; const t=`function hidden(x){}`; function outer(x){const nested=(y)=>{return "}"+y;};} function sibling(z){return z;}'
        scopes=js_functions(source)
        self.assertEqual([scope['name'] for scope in scopes],['outer','nested','sibling'])
        self.assertTrue(all(scope['complete'] for scope in scopes))

    def test_oversized_control_scope_retains_unknown_login(self):
        source='async function login(password){'+' ' * 25000+'if(password.length>=8 && await bcrypt.compare(password,storedHash))return user;return null;}'
        scopes=js_functions(source)
        self.assertEqual(len(scopes),1)
        self.assertFalse(scopes[0]['complete'])
        self.assertFalse(scopes[0]['simple_params'])
        result=self.scan(AuthExtractor,source)
        self.assertTrue(any(row['kind']=='login-without-hash-compare' for row in result['broken_auth']))


if __name__ == '__main__': unittest.main()
