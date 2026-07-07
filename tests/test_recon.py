"""Portable regression tests for the deterministic recon core.

Stdlib `unittest` only (no pytest, no Noir, no network) so it runs anywhere:
    python3 -m unittest discover -s tests
Route extraction is tested via the regex fallback + pure helpers, so Noir's
absence doesn't make the suite flaky.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import calibration, findings, probes, scanners   # noqa: E402
from websec_validator.extractors import routes                         # noqa: E402
from websec_validator.extractors.auth import AuthExtractor             # noqa: E402
from websec_validator.extractors.authz import AuthzExtractor           # noqa: E402
from websec_validator.extractors.base import RepoContext               # noqa: E402
from websec_validator.extractors.stack import StackExtractor           # noqa: E402
from websec_validator.extractors.schemas import SchemasExtractor       # noqa: E402
from websec_validator.extractors.integrations import IntegrationsExtractor  # noqa: E402
from websec_validator.extractors.surface import SINKS, SurfaceExtractor  # noqa: E402
from websec_validator.extractors.tenant import TenantExtractor         # noqa: E402
from websec_validator.extractors.client_exposure import ClientExposureExtractor  # noqa: E402
from websec_validator.extractors.pii_exposure import PiiExposureExtractor  # noqa: E402
from websec_validator.extractors.upload_security import UploadSecurityExtractor  # noqa: E402
from websec_validator.extractors.iac_ci import IacCiExtractor          # noqa: E402
from websec_validator.extractors.transport_security import TransportSecurityExtractor  # noqa: E402
from websec_validator.extractors.llm_security import LlmSecurityExtractor  # noqa: E402
from websec_validator.extractors.crypto_usage import CryptoUsageExtractor  # noqa: E402
from websec_validator.extractors.authz_dataflow import AuthzDataflowExtractor  # noqa: E402
from websec_validator.extractors.agent_config import AgentConfigExtractor  # noqa: E402
from websec_validator.extractors.dependencies import DependenciesExtractor  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def ctx(name):
    return RepoContext(FIX / name)


class StackTests(unittest.TestCase):
    def test_node(self):
        f = StackExtractor().extract(ctx("node_app"), {})
        self.assertIn("node", f["languages"])
        self.assertIn("express", f["frameworks"])
        self.assertIn("dynamodb", f["datastores"])

    def test_python(self):
        f = StackExtractor().extract(ctx("py_app"), {})
        self.assertIn("python", f["languages"])
        self.assertIn("flask", f["frameworks"])

    def test_wrangler_config_detects_kv_and_workers(self):
        # P5: managed-platform config reveals framework + datastore that deps don't (KV ⇒ down-rank SQLi).
        d = Path(tempfile.mkdtemp())
        (d / "wrangler.jsonc").write_text('{ "name": "x", "kv_namespaces": [{"binding": "CACHE"}] }\n')
        (d / "src.ts").write_text("export default { fetch() {} };\n")
        out = StackExtractor().extract(RepoContext(d), {})
        self.assertIn("cloudflare-workers", out["frameworks"])
        self.assertIn("cloudflare-kv", out["datastores"])


class AuthTests(unittest.TestCase):
    def test_python_jwt(self):
        c = ctx("py_app")
        a = AuthExtractor().extract(c, {"stack": StackExtractor().extract(c, {})})
        self.assertIn("jwt", a["scheme"])


class TamperableDisplayGateTests(unittest.TestCase):
    """Consequence gate — a money sink needs an act-on-it signal (copy/QR/href or a real value-SHAPE),
    not just a matching field NAME; an intended one-time secret reveal is not a MitB defect."""
    def _td(self, files):
        from websec_validator.extractors.client_integrity import ClientIntegrityExtractor
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name).write_text(body)
        f = ClientIntegrityExtractor().extract(RepoContext(d), {})
        return [x for x in f["findings"] if x["attack_class"] == "tamperable-display"]

    def test_name_only_money_label_not_flagged(self):
        # a client file that references walletAddress but never copies/QRs/links it or shows a real value
        td = self._td({"Nav.tsx": "export const Nav=()=> <div>{account_number_label}</div>;\n"})
        self.assertEqual(td, [])

    def test_copied_address_flagged(self):
        td = self._td({"Recv.tsx": "'use client'\nexport const R=({walletAddress})=> <button "
                                   "onClick={()=>navigator.clipboard.writeText(walletAddress)}>copy</button>;\n"})
        self.assertTrue(td)

    def test_one_time_reveal_not_flagged(self):
        td = self._td({"Key.tsx": "'use client'\nexport const K=({apiKey})=> <div>Save this key now — it "
                                  "cannot be retrieved again.<button onClick={()=>navigator.clipboard.writeText(apiKey)}>copy</button></div>;\n"})
        self.assertEqual(td, [])


class BrokenAuthTests(unittest.TestCase):
    """Broken-auth backdoors — the CRITICAL total-bypass bugs the route/guard model can't see (the
    endpoint IS 'guarded', just by something forgeable). Found via the real-repo FN audit."""
    def _ba(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name).write_text(body)
        return AuthExtractor().extract(RepoContext(d), {"stack": {}, "routes": {}})["broken_auth"]

    def test_dev_token_backdoor_critical(self):
        ba = self._ba({"auth.ts": "if (token.startsWith('dev-')) { const role='dev-admin'; return {role}; }\n"})
        self.assertTrue(any(b["kind"] == "dev-token-backdoor" and b["severity"] == "CRITICAL" for b in ba))

    def test_accept_any_credential_critical(self):
        ba = self._ba({"auth.ts": "async authorize(credentials){\n// For MVP, accept any email/password\n"
                                  "if(credentials.password.length>=8) return {id:'user-1'};\n}\n"})
        self.assertTrue(any(b["kind"] == "accept-any-credential" and b["severity"] == "CRITICAL" for b in ba))

    def test_fail_open_signature_verify(self):
        ba = self._ba({"billing.ts": "if (env.STRIPE_WEBHOOK_SECRET) {\n"
                                     "  const valid = await verifyStripeSignature(rawBody, sig, env.STRIPE_WEBHOOK_SECRET);\n"
                                     "  if(!valid) return new Response('bad',{status:400});\n}\n"})
        self.assertTrue(any(b["kind"] == "fail-open-verification" for b in ba))

    def test_real_login_with_bcrypt_not_flagged(self):
        ba = self._ba({"auth.ts": "async authorize(c){ const u=await db.user(c.email);\n"
                                  "if(await bcrypt.compare(c.password,u.passwordHash)) return u; }\n"})
        self.assertEqual(ba, [])


class TenantTests(unittest.TestCase):
    def test_node_groupid(self):
        t = TenantExtractor().extract(ctx("node_app"), {})
        self.assertIn("groupId", [c["key"] for c in t["candidates"]])


class SurfaceTests(unittest.TestCase):
    def test_ssrf_sink_detected(self):
        s = SurfaceExtractor().extract(ctx("node_app"), {"stack": {"datastores": ["dynamodb"]}})
        self.assertIn("ssrf", s["sinks"])

    def test_command_injection_regex_is_user_gated(self):
        rx = SINKS["command-injection"][2]
        self.assertTrue(rx.search("child_process.exec(req.body.cmd)"))
        self.assertFalse(rx.search("child_process.exec('ls -la')"))

    def test_xss_sink_regex_detects_dom_and_template(self):
        rx = SINKS["xss"][2]
        self.assertTrue(rx.search("el.innerHTML = req.query.q"))
        self.assertTrue(rx.search("<div dangerouslySetInnerHTML={{__html: props.body}} />"))
        self.assertTrue(rx.search('<div v-html="comment"></div>'))
        self.assertTrue(rx.search("{{ user_bio | safe }}"))
        # a static string assignment is not user-influenced → no match
        self.assertFalse(rx.search("el.innerHTML = '<b>hi</b>'"))

    def test_xss_suppressed_when_file_sanitizes(self):
        d = Path(tempfile.mkdtemp())
        (d / "render.js").write_text(
            "import DOMPurify from 'dompurify';\n"
            "el.innerHTML = DOMPurify.sanitize(req.query.q);\n")
        s = SurfaceExtractor().extract(RepoContext(d), {"stack": {}})
        self.assertNotIn("xss", s["sinks"])

    def test_xss_flagged_without_sanitizer(self):
        d = Path(tempfile.mkdtemp())
        (d / "render.js").write_text("el.innerHTML = req.query.q + '<hr>'\n")
        s = SurfaceExtractor().extract(RepoContext(d), {"stack": {}})
        self.assertIn("xss", s["sinks"])

    def test_request_sinks_suppressed_on_non_web_repo(self):
        # a Python CLI (analyzed: languages set) with NO routes + NO web framework → SSRF has no HTTP
        # attacker in the loop; suppress it. A real web app (frameworks set) still fires (control).
        d = Path(tempfile.mkdtemp())
        (d / "risk.py").write_text("import requests\ndef gate(u):\n    return requests.get(u)\n")
        cli = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["python"], "frameworks": []}})
        self.assertNotIn("ssrf-outbound-http", cli["sinks"])
        web = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["python"], "frameworks": ["flask"]}})
        self.assertIn("ssrf-outbound-http", web["sinks"])


class TransportSecurityTests(unittest.TestCase):
    def _run(self, files, facts=None):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        base = {"stack": {"frameworks": ["express"]},
                "routes": {"endpoints": [{"method": "POST", "path": "/x"}]}}
        base.update(facts or {})
        return TransportSecurityExtractor().extract(RepoContext(d), base)

    def test_clickjacking_flagged_when_no_xfo(self):
        out = self._run({"server.js": "app.get('/', (req,res)=>res.send('<html>hi</html>'))\n"})
        self.assertIn("no-clickjacking-protection", [f["kind"] for f in out["findings"]])
        self.assertFalse(out["clickjacking_protected"])

    def test_clickjacking_not_flagged_with_frame_ancestors(self):
        out = self._run({"server.js": "res.setHeader('Content-Security-Policy', \"frame-ancestors 'none'\")\n"
                                       "res.send('<html>hi</html>')\n"})
        self.assertNotIn("no-clickjacking-protection", [f["kind"] for f in out["findings"]])
        self.assertTrue(out["clickjacking_protected"])

    def test_csrf_flagged_on_cookie_auth_without_token_or_samesite(self):
        facts = {"auth": {"scheme": "session-cookie", "token_location": "cookie", "cookie_names": ["sid"]}}
        out = self._run({"app.js": "app.post('/pay',(req,res)=>{res.cookie('sid',t,{httpOnly:true})})\n"}, facts)
        self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_csrf_not_flagged_with_csrf_lib(self):
        facts = {"auth": {"scheme": "session-cookie", "token_location": "cookie", "cookie_names": ["sid"]}}
        out = self._run({"app.js": "const csurf=require('csurf'); app.use(csurf());\napp.post('/pay',h)\n"}, facts)
        self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_csrf_not_flagged_for_bearer_api(self):
        facts = {"auth": {"scheme": "jwt (bearer)", "token_location": "bearer"}}
        out = self._run({"app.js": "app.post('/pay', requireAuth, h)\n"}, facts)
        self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_no_transport_findings_on_non_web_tool(self):
        # A Python CLI that emits an HTML report string but has no web framework and no routes is NOT
        # a served browser surface — CSP/HSTS/clickjacking must not fire (real-repo FP: a real CLI).
        out = self._run(
            {"report.py": "html='<!DOCTYPE html><html><body>hi</body></html>'\nopen('r.html','w').write(html)\n"},
            {"stack": {"frameworks": []}, "routes": {"endpoints": []}})
        kinds = [f["kind"] for f in out["findings"]]
        self.assertNotIn("no-clickjacking-protection", kinds)
        self.assertNotIn("no-csp", kinds)
        self.assertFalse(out["web_surface"])


class FileClassTests(unittest.TestCase):
    def test_python_test_files_recognized(self):
        from websec_validator.extractors.base import is_test_file
        for p in ("test_curl.py", "tests/x.py", "app/foo_test.py", "conftest.py", "pkg/test_helpers.py"):
            self.assertTrue(is_test_file(p), p)
        for p in ("src/api.py", "testimonials.py", "latest_data.py", "contest.py"):
            self.assertFalse(is_test_file(p), p)


class PathScopedGuardMountTests(unittest.TestCase):
    """Real-repo FP (a real monorepo backends, 116+36 guarded routes flagged): `app.use('/api', requireAuth)`
    on its own line, routers mounted on /api in LATER statements. Express applies middleware in order."""
    def test_guard_mount_covers_routers_mounted_after_it(self):
        d = Path(tempfile.mkdtemp())
        (d / "server.ts").write_text(
            "import authRoutes from './routes/authRoutes';\n"
            "import conversationRoutes from './routes/conversationRoutes';\n"
            "app.use('/api/auth', authRoutes);\n"        # BEFORE the guard → public (login)
            "app.use('/api', requireAuth);\n"            # standalone path-scoped guard mount
            "app.use('/api', conversationRoutes);\n")    # AFTER the guard → protected
        (d / "routes").mkdir()
        (d / "routes" / "conversationRoutes.ts").write_text(
            "const router = Router();\nrouter.post('/groups/:id/messages', h);\nexport default router;\n")
        (d / "routes" / "authRoutes.ts").write_text(
            "const router = Router();\nrouter.post('/login', h);\nexport default router;\n")
        facts = {"routes": {"endpoints": [
            {"method": "POST", "path": "/groups/:id/messages",
             "code_path": str(d / "routes" / "conversationRoutes.ts")},
            {"method": "POST", "path": "/login", "code_path": str(d / "routes" / "authRoutes.ts")}]}}
        out = AuthzExtractor().extract(RepoContext(d), facts)
        guards = {e["path"]: e["guarded"] for e in out["endpoint_guards"]}
        self.assertTrue(guards["/groups/:id/messages"])   # covered by app.use('/api', requireAuth)


class GuardAliasTests(unittest.TestCase):
    """Real-repo FP (a real Next.js app, 92 handlers): app-specific HOF wrappers that compose a known guard
    (withDealAuth = withAuth(...)), called with a TS generic (`withDealAuth<{dealId}>(...)`), + a
    secret-bearer cron guard (`Bearer ${CRON_SECRET}`) — all now credited as guarded."""
    def test_hof_wrapper_generic_and_secret_bearer_credited(self):
        d = Path(tempfile.mkdtemp())
        (d / "lib").mkdir()
        (d / "lib" / "mw.ts").write_text(
            "export function withAuth(h){ return async(req)=>{ const s=await getServerSession();"
            " if(!s) return new Response('',{status:401}); return h(req);} }\n"
            "export function withDealAuth(h){ return withAuth(async(req)=>h(req)); }\n")
        (d / "api").mkdir()
        (d / "api" / "deal.ts").write_text(
            "import { withDealAuth } from '../lib/mw';\n"
            "export const GET = withDealAuth<{dealId:string}>(async(req)=>{ return Response.json({}); });\n")
        (d / "api" / "cron.ts").write_text(
            "export async function GET(req){ const a=req.headers.get('authorization');"
            " if(a!==`Bearer ${process.env.CRON_SECRET}`) return new Response('',{status:401}); }\n")
        facts = {"routes": {"endpoints": [
            {"method": "GET", "path": "/api/deals/:dealId", "code_path": str(d / "api" / "deal.ts")},
            {"method": "GET", "path": "/api/cron", "code_path": str(d / "api" / "cron.ts")}]}}
        out = AuthzExtractor().extract(RepoContext(d), facts)
        g = {e["path"]: e["guarded"] for e in out["endpoint_guards"]}
        self.assertTrue(g["/api/deals/:dealId"], "withDealAuth<...>( generic wrapper should be credited")
        self.assertTrue(g["/api/cron"], "Bearer ${CRON_SECRET} secret-bearer guard should be credited")

    def test_outbound_bearer_does_not_credit_but_inline_auth_does(self):
        # REGRESSION: an OUTBOUND `Bearer ${apiKey}` header a handler BUILDS must NOT be read as an inbound
        # guard (this hid a real Next.js app's unauth /api/auth/seed backdoor). Inline `await auth()`+401 DOES credit.
        d = Path(tempfile.mkdtemp())
        (d / "api").mkdir()
        (d / "api" / "seed.ts").write_text(
            "import { hashPassword } from '@/lib/auth';\n"
            "export async function POST(req){ const h={Authorization:`Bearer ${apiKey}`};"
            " await createUser({password: process.env.SEED_DEFAULT_PASSWORD||'x'}); return Response.json({}); }\n")
        (d / "api" / "chat.ts").write_text(
            "export async function POST(req){ const session=await auth(); "
            "if(!session?.user?.id) return NextResponse.json({e:1},{status:401}); return Response.json({}); }\n")
        facts = {"routes": {"endpoints": [
            {"method": "POST", "path": "/api/auth/seed", "code_path": str(d / "api" / "seed.ts")},
            {"method": "POST", "path": "/api/deals/:id/chat", "code_path": str(d / "api" / "chat.ts")}]}}
        g = {e["path"]: e["guarded"] for e in AuthzExtractor().extract(RepoContext(d), facts)["endpoint_guards"]}
        self.assertFalse(g["/api/auth/seed"], "outbound Bearer + util import must NOT credit an unauth handler")
        self.assertTrue(g["/api/deals/:id/chat"], "inline await auth() + 401 should be credited")


class SamRoutesTests(unittest.TestCase):
    """AWS SAM / serverless route modeling — real-repo FN (several real repos backends were
    0-routes/unprobed). Api events + Function URLs → routes; AuthType:NONE → a public-endpoint signal."""
    def _rows(self):
        from websec_validator.extractors.routes import _sam_routes
        d = Path(tempfile.mkdtemp())
        (d / "src" / "handlers").mkdir(parents=True)
        (d / "src" / "handlers" / "auth.ts").write_text("export const login = async(e)=>({statusCode:200});\n")
        (d / "live").mkdir()
        (d / "live" / "lambda_handlers.py").write_text("def handler_dashboard(event, ctx):\n    return {}\n")
        (d / "template.yaml").write_text(
            "Resources:\n"
            "  LoginFn:\n    Type: AWS::Serverless::Function\n    Properties:\n"
            "      Handler: dist/handlers/auth.login\n"
            "      Events:\n        ApiEv:\n          Type: Api\n          Properties:\n"
            "            Path: /api/auth/login\n            Method: post\n"
            "  DashFn:\n    Type: AWS::Serverless::Function\n    Properties:\n"
            "      Handler: live.lambda_handlers.handler_dashboard\n"
            "      FunctionUrlConfig:\n        AuthType: NONE\n")
        return _sam_routes(RepoContext(d))

    def test_api_event_and_function_url_detected(self):
        rows = self._rows()
        paths = {(r["method"], r["path"]) for r in rows}
        self.assertIn(("POST", "/api/auth/login"), paths)          # Api event
        self.assertIn(("GET", "/"), paths)                          # Function URL (HTTP root)
        self.assertTrue(any(r.get("sam_auth_type") == "NONE" for r in rows))

    def test_handler_resolved_dist_to_src(self):
        login = [r for r in self._rows() if r["path"] == "/api/auth/login"][0]
        self.assertTrue(login["code_path"].endswith("src/handlers/auth.ts"), login["code_path"])

    def test_nextjs_destructured_factory_route_detected(self):
        # a Next App Router route.ts that exports handlers via a destructured factory
        # (`export const { GET, POST } = makeRouteHandler(...)`, Keystatic/Auth.js) — real-repo recall gap (a real Next.js app)
        from websec_validator.extractors.routes import _fallback_next_app_router
        d = Path(tempfile.mkdtemp())
        rd = d / "app" / "src" / "app" / "api" / "keystatic" / "[...params]"   # monorepo-nested app dir
        rd.mkdir(parents=True)
        (rd / "route.ts").write_text("import { makeRouteHandler } from '@keystatic/next/route-handler';\n"
                                     "export const { POST, GET } = makeRouteHandler({config});\n")
        paths = {(r["method"], r["path"]) for r in _fallback_next_app_router(RepoContext(d))}
        self.assertIn(("GET", "/api/keystatic/{params}"), paths)      # detected + path not '/src/app/...'
        self.assertIn(("POST", "/api/keystatic/{params}"), paths)

    def test_own_openapi_spec_promotable_vendored_not(self):
        # VAmPI-style: an app's OWN openapi3.yml is spec-derived (SPEC_PATH) but NOT under a vendor dir,
        # so it's promotable to the route list; a node_modules swagger stays vendored. (proof: VAmPI 19→0→19)
        from websec_validator.extractors.routes import _is_spec_derived, _VENDOR_DIR
        self.assertTrue(_is_spec_derived("openapi_specs/openapi3.yml"))
        self.assertFalse(bool(_VENDOR_DIR.search("openapi_specs/openapi3.yml")))       # promotable
        self.assertTrue(bool(_VENDOR_DIR.search("node_modules/swagger-ui/openapi.yaml")))  # vendored, stays out


class RoutesClientFilterTests(unittest.TestCase):
    """Real-repo FP (combined frontend+backend monorepo): Noir parsed the React axios API-client files
    as server routes → every one flagged missing-auth. A client CALLS; it doesn't SERVE."""
    def _f(self, code_path, ctx):
        from websec_validator.extractors.routes import _looks_nonserver_route
        return _looks_nonserver_route(code_path, ctx)

    def test_frontend_api_client_excluded_serverless_and_server_kept(self):
        d = Path(tempfile.mkdtemp())
        (d / "api").mkdir()
        (d / "api" / "conversations.ts").write_text(
            "import { api } from './client';\nexport const getConvos = () => api.get('/groups/1/conversations');\n")
        (d / "fn.js").write_text(                          # Cloudflare Pages Function that calls axios
            "import axios from 'axios';\nexport async function onRequestPost({request}){ return axios.get('http://w'); }\n")
        (d / "server.ts").write_text("const router = Router();\nrouter.get('/y', h);\n")
        ctx = RepoContext(d)
        self.assertTrue(self._f(str(d / "api" / "conversations.ts"), ctx))   # frontend client → excluded
        self.assertFalse(self._f(str(d / "fn.js"), ctx))                     # serverless handler → kept
        self.assertFalse(self._f(str(d / "server.ts"), ctx))                 # express router → kept

    def test_netlify_redirects_excluded(self):
        d = Path(tempfile.mkdtemp())
        (d / "public").mkdir()
        (d / "public" / "_redirects").write_text("/* /index.html 200\n")
        self.assertTrue(self._f(str(d / "public" / "_redirects"), RepoContext(d)))


class SchemasTests(unittest.TestCase):
    def _build(self):
        d = Path(tempfile.mkdtemp())
        (d / "prisma").mkdir()
        (d / "prisma" / "schema.prisma").write_text(
            "model User {\n  id String @id\n  email String\n  role String\n  isAdmin Boolean\n  tenantId String\n}\n")
        (d / "models").mkdir()
        (d / "models" / "account.py").write_text(
            "from pydantic import BaseModel\nclass AccountUpdate(BaseModel):\n    name: str\n    balance: float\n")
        return d

    def test_detects_orms_entities_and_sensitive_fields(self):
        out = SchemasExtractor().extract(RepoContext(self._build()), {})
        self.assertIn("prisma", out["orms"])
        self.assertIn("pydantic", out["orms"])
        self.assertIn("User", [e["name"] for e in out["entities"]])
        # privileged fields a mass-assignment probe should target
        for f in ("role", "isAdmin", "tenantId", "balance"):
            self.assertIn(f, out["sensitive_fields"])

    def test_no_false_positives_on_modelless_fixture(self):
        out = SchemasExtractor().extract(ctx("node_app"), {})
        self.assertEqual(out["sensitive_fields"], [])
        self.assertEqual(out["orms"], [])


class IntegrationsTests(unittest.TestCase):
    def _run(self, handler_src):
        d = Path(tempfile.mkdtemp())
        (d / "h.js").write_text(handler_src)
        facts = {"routes": {"endpoints": [
            {"method": "POST", "path": "/webhooks/stripe", "code_path": str(d / "h.js")}]}}
        return IntegrationsExtractor().extract(RepoContext(d), facts)

    def test_unverified_webhook_flagged_despite_signature_word_in_comment(self):
        # the bare-word `signature` SIG_VERIFY alternative used to SUPPRESS the finding when a
        # comment merely mentioned signatures — a false negative. Only real verification counts now.
        out = self._run("// no signature verification here\n"
                        "router.post('/webhooks/stripe', (req,res)=>res.json({ok:1}));\n")
        self.assertEqual(len(out["webhooks_without_sig_verification"]), 1)

    def test_genuinely_verified_webhook_not_flagged(self):
        out = self._run("const crypto=require('crypto');\n"
                        "router.post('/webhooks/stripe', (req,res)=>{\n"
                        "  const h=crypto.createHmac('sha256',k).update(req.body).digest('hex');\n"
                        "  if(h!==req.headers['stripe-signature']) return res.status(401).end();\n});\n")
        self.assertEqual(out["webhooks_without_sig_verification"], [])

    def _run_path(self, method, path, handler_src):
        d = Path(tempfile.mkdtemp())
        (d / "h.js").write_text(handler_src)
        facts = {"routes": {"endpoints": [{"method": method, "path": path, "code_path": str(d / "h.js")}]}}
        return IntegrationsExtractor().extract(RepoContext(d), facts)

    def test_oauth_callback_not_flagged_as_webhook(self):
        # /callback matches WEBHOOK_PATH but is an OAuth authz-code callback (state/PKCE) — not a webhook.
        out = self._run_path("GET", "/auth/callback",
                             "router.get('/auth/callback',(req,res)=>{const code=req.query.code; exchangeCode(code);});\n")
        self.assertEqual(out["webhooks_without_sig_verification"], [])

    def test_webhook_mgmt_crud_not_flagged(self):
        out = self._run_path("POST", "/settings/webhooks",
                             "router.post('/settings/webhooks',(req,res)=>{ return createWebhook(req.body.url); });\n")
        self.assertEqual(out["webhooks_without_sig_verification"], [])

    def test_get_webhook_stub_not_flagged(self):
        out = self._run_path("GET", "/webhooks/health", "router.get('/webhooks/health',(req,res)=>res.json({ok:1}));\n")
        self.assertEqual(out["webhooks_without_sig_verification"], [])


class CsrfBaselineTests(unittest.TestCase):
    def _run(self, frameworks, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name).write_text(body)
        facts = {"stack": {"frameworks": frameworks},
                 "routes": {"endpoints": [{"method": "POST", "path": "/x"}]},
                 "auth": {"scheme": "session-cookie", "token_location": "cookie", "cookie_names": ["sid"]}}
        return TransportSecurityExtractor().extract(RepoContext(d), facts)

    def test_plain_session_app_flagged(self):
        out = self._run(["express"], {"app.js": "app.post('/x',(req,res)=>{res.cookie('sid',t)});\n"})
        self.assertIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_nextauth_default_not_flagged(self):
        # NextAuth defaults SameSite=Lax — the classic ambient-cookie CSRF doesn't apply
        out = self._run(["next", "nextauth"], {"app.js": "app.post('/x',(req,res)=>{res.cookie('sid',t)});\n"})
        self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])

    def test_server_actions_not_flagged(self):
        out = self._run(["next"], {"actions.ts": "'use server'\nexport async function save(fd){ /* mutate */ }\n"})
        self.assertNotIn("no-csrf-protection", [f["kind"] for f in out["findings"]])


class CalibrationTests(unittest.TestCase):
    def test_wilson_interval(self):
        self.assertEqual(calibration.wilson(0, 0), (0.0, 1.0))      # no data → full ignorance
        lo, hi = calibration.wilson(1, 1)
        self.assertAlmostEqual(hi, 1.0, places=6)
        self.assertTrue(0.15 < lo < 0.25)                          # n=1 is NOT falsely certain (~0.21)
        lo5, hi5 = calibration.wilson(5, 10)
        self.assertTrue(lo5 < 0.5 < hi5)                           # centered on 0.5
        self.assertGreater(calibration.wilson(9, 10)[0], lo5)      # more hits ⇒ higher lower bound

    def test_is_real_matching(self):
        truth = [{"class": "missing-auth", "location_contains": "*"},
                 {"class": "mass-assignment", "location_contains": "register"}]
        self.assertTrue(calibration.is_real("missing-auth", "/anything", truth))   # wildcard
        self.assertTrue(calibration.is_real("mass-assignment", "/users/v1/register", truth))
        self.assertFalse(calibration.is_real("mass-assignment", "/login", truth))  # location mismatch
        self.assertFalse(calibration.is_real("ssrf", "/x", truth))                 # class mismatch ⇒ FP

    def _table(self):
        labeled = ([{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": True}] * 6 +
                   [{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": False}] * 4 +
                   [{"attack_class": "iac", "confidence": "MEDIUM", "is_real": False}] * 8)
        return calibration.fit(labeled, ["X"], researched_classes={"missing-auth"})

    def test_fit_aggregate_and_researched_filter(self):
        t = self._table()
        self.assertEqual(t["by_label"]["MEDIUM"]["n"], 18)         # iac findings still in the aggregate (FP)
        self.assertEqual(t["by_label"]["MEDIUM"]["k"], 6)
        self.assertIn("missing-auth|MEDIUM", t["by_class_label"])
        self.assertNotIn("iac|MEDIUM", t["by_class_label"])        # unresearched ⇒ no misleading p=0 cell

    def test_apply_fallback_tiers(self):
        t = self._table()
        self.assertEqual(calibration.apply("missing-auth", "MEDIUM", t)["basis"], "class+label")
        self.assertEqual(calibration.apply("iac", "MEDIUM", t)["basis"], "label")   # no class cell → aggregate
        self.assertEqual(calibration.apply("x", "HIGH", t)["basis"], "prior (uncalibrated)")  # no HIGH data
        self.assertEqual(calibration.apply("x", "MEDIUM", None)["basis"], "prior (uncalibrated)")  # no table

    def test_samples_from_dynamic_oracle(self):
        dyn = {"write_auth_enforcement": {"results": [
                  {"verdict": "EXECUTED-UNAUTH"}, {"verdict": "auth-enforced"},
                  {"verdict": "no-auth-gate (reached handler/validation)"}, {"verdict": "http-500"}]},
               "cross_tenant_bola": {"leaks": [{"path": "/x"}]}}
        s = calibration.samples_from_dynamic(dyn)
        ma = [x for x in s if x["attack_class"] == "missing-auth"]
        self.assertEqual(len(ma), 3)                       # executed + no-auth-gate + auth-enforced; http-* skipped
        self.assertEqual(sum(x["is_real"] for x in ma), 2)  # auth-enforced is a confirmed FALSE positive
        self.assertTrue(any(x["attack_class"] == "bola" and x["is_real"] for x in s))

    def test_merge_sums_counts_and_personalizes(self):
        shipped = {"meta": {"caveat": "base"},
                   "by_class_label": {"missing-auth|MEDIUM": {"n": 41, "k": 27, "p": 0.659, "ci": [0.5, 0.78]}},
                   "by_label": {"MEDIUM": {"n": 41, "k": 27}}, "prior": calibration.PRIOR}
        local = {"meta": {"samples": 3}, "by_class_label": {"missing-auth|MEDIUM": {"n": 3, "k": 2}},
                 "by_label": {"MEDIUM": {"n": 3, "k": 2}}}
        m = calibration._merge(shipped, local)
        self.assertEqual(m["by_class_label"]["missing-auth|MEDIUM"]["n"], 44)   # counts summed
        self.assertEqual(m["by_class_label"]["missing-auth|MEDIUM"]["k"], 29)
        self.assertTrue(m["meta"]["personalized"])
        self.assertEqual(m["meta"]["local_samples"], 3)

    def test_record_samples_roundtrip(self):
        saved = calibration.LOCAL_PATH
        try:
            calibration.LOCAL_PATH = Path(tempfile.mkdtemp()) / "local.json"
            calibration.record_samples([{"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": True},
                                        {"attack_class": "missing-auth", "confidence": "MEDIUM", "is_real": False}])
            loc = calibration.load_local()
            self.assertEqual(loc["by_label"]["MEDIUM"], {"n": 2, "k": 1})
            self.assertEqual(loc["meta"]["samples"], 2)
        finally:
            calibration.LOCAL_PATH = saved


class FieldFeedbackBatch1Tests(unittest.TestCase):
    """Regressions for the field-test false positives (proxy.ts, self-scan, ASIA)."""

    def test_unsafe_decoder_feeding_auth_flagged(self):  # F5
        d = Path(tempfile.mkdtemp())
        (d / "requireAdmin.ts").write_text(
            "export function requireAdmin(req){ const p = decodeJwtPayloadUnsafe(req.cookies.t); if(!p.isAdmin) throw 0; }")
        (d / "util.ts").write_text("export const add = (a,b) => a+b")   # no auth + no unsafe → not flagged
        out = AuthzExtractor().extract(RepoContext(d), {"routes": {"endpoints": []}})
        self.assertIn("decodeJwtPayloadUnsafe", [u["decoder"] for u in out["unsafe_auth_decoders"]])

    def _next_app(self, proxy_body):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / "src" / "proxy.ts").write_text(proxy_body)
        (d / "src" / "r.ts").write_text("export async function POST(req){ return Response.json({}) }")
        ctx = RepoContext(d)
        facts = {"routes": {"endpoints": [
            {"method": "POST", "path": "/api/x", "code_path": str(d / "src" / "r.ts")}]}}
        return AuthzExtractor().extract(ctx, facts)

    def test_nextjs_proxy_ts_detected_as_global_auth(self):
        out = self._next_app(
            'export default auth((req) => { if (!req.auth) return NextResponse.json({}, {status: 401}); });\n'
            'export const config = { matcher: ["/((?!_next/static|favicon.ico).*)"] };')
        self.assertTrue(out["global_auth_middleware"])
        self.assertEqual(out["next_middleware"]["file"], "src/proxy.ts")
        self.assertTrue(out["next_middleware"]["is_auth"])
        self.assertEqual(out["write_endpoints_without_visible_guard"], [])  # the 42-HIGH FP cluster, gone

    def test_non_auth_middleware_does_not_falsely_guard(self):
        out = self._next_app('export function proxy(req){ return NextResponse.next(); }\n'
                             'export const config = { matcher: ["/((?!_next).*)"] };')
        self.assertFalse(out["global_auth_middleware"])             # not auth → not a guard
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 1)  # so the route IS still flagged

    def test_scanner_argv_excludes_self_output(self):
        self.assertIn("websec-out", scanners._trivy(Path("/repo"), Path("/o")))
        self.assertIn("websec-out", scanners._semgrep(Path("/repo"), Path("/o")))

    def test_aws_credential_tiering(self):
        self.assertEqual(scanners._aws_secret_tier("AKIAIOSFODNN7EXAMPLE", "")[0], "HIGH")
        self.assertEqual(scanners._aws_secret_tier("ASIAIOSFODNN7EXAMPLE", "")[0], "MEDIUM")
        self.assertEqual(scanners._aws_secret_tier("", "X-Amz-Signature=z&X-Amz-Credential=ASIA")[0], "LOW")
        rows = [{"File": "j.json", "RuleID": "aws", "Description": "AWS key",
                 "Secret": "ASIAEXAMPLE000000000", "Match": "X-Amz-Signature=zzz"}]
        self.assertEqual(scanners._norm_gitleaks(rows)[0]["severity"], "LOW")  # presigned ASIA ≠ HIGH


class FailOpenGuardTests(unittest.TestCase):
    """P0-4: a fail-open test env must NOT escalate untrustworthy unauth 'successes' to CRITICAL."""

    def _ledger(self, fail_open):
        authz = {"endpoint_guards": [{"method": "POST", "path": "/api/x", "code_path": "r.ts",
                                      "guarded": False, "analyzed": True, "public_hint": False}]}
        ex = {"method": "POST", "path": "/api/x", "status": 201, "verdict": "EXECUTED-UNAUTH"}
        dyn = {"write_auth_enforcement": {"results": [ex], "fail_open_suspected": fail_open}}
        return findings.build_ledger({"authz": authz}, None, dyn, [])["findings"][0]

    def test_fail_open_not_escalated(self):
        f = self._ledger(True)
        self.assertNotEqual(f["severity"], "CRITICAL")                       # not escalated
        self.assertTrue(any("UNTRUSTWORTHY" in e["detail"] for e in f["evidence"]))

    def test_healthy_env_still_escalates(self):
        self.assertEqual(self._ledger(False)["severity"], "CRITICAL")        # regression guard


class ProbeStagingTests(unittest.TestCase):
    """P0-3 / P1-2: probes ship with the target's real surface + an always-on unauth baseline."""

    def test_context_unauth_baseline_and_banner(self):
        d = Path(tempfile.mkdtemp())
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/sponsors"},
                                          {"method": "GET", "path": "/api/health"}],
                            "targeting": {"write_endpoints": ["POST /api/sponsors"]}},
                 "auth": {"scheme": "jwt", "token_location": "bearer"},
                 "tenant": {"candidates": [{"key": "tenantId"}]}}
        chosen = probes.applicable(facts)
        self.assertIn("unauth-baseline", chosen)              # always staged (P1-2)
        man = probes.stage(chosen, d, facts)
        ctx = json.loads((d / "probes" / "probe-context.json").read_text())
        self.assertIn("POST /api/sponsors", ctx["endpoints"]["writes"])   # real route, not template's
        self.assertEqual(ctx["auth"]["scheme"], "jwt")
        body = (d / "probes" / "unauth-baseline.sh").read_text()
        self.assertTrue(body.startswith("#!"))                # shebang preserved
        self.assertIn("DRAFT probe", body)                    # banner prepended
        self.assertIn("probe-context.json", body)
        ub = [m for m in man if m.get("key") == "unauth-baseline"][0]
        self.assertEqual(ub["targets"], ["POST /api/sponsors"])           # real per-probe targets

    def test_staged_probes_ship_lib_and_have_no_private_paths(self):
        d = Path(tempfile.mkdtemp())
        facts = {"routes": {"endpoints": [{"method": "POST", "path": "/api/x"}],
                            "targeting": {"write_endpoints": ["POST /api/x"]}},
                 "tenant": {"candidates": [{"key": "tenantId"}]}}
        probes.stage(probes.applicable(facts), d, facts)
        staged = list((d / "probes").glob("*"))
        names = {p.name for p in staged}
        self.assertIn("_lib.py", names)               # shared helper is always shipped
        self.assertIn("probe-context.json", names)
        blob = "\n".join(p.read_text() for p in staged if p.suffix in (".py", ".sh"))
        self.assertNotIn("security/zap", blob)        # no author-private fixture paths (P0-3)
        self.assertNotIn("security/pentest", blob)


class ExcludeAndScannerSelectTests(unittest.TestCase):  # F4
    def test_repocontext_honors_excludes(self):
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir(); (d / "keep").mkdir()
        (d / "src" / "a.py").write_text("x=1")
        (d / "keep" / "b.py").write_text("y=1")
        ctx = RepoContext(d, excludes=["src"])
        rels = {ctx.rel(p) for p in ctx.code_files}
        self.assertIn("keep/b.py", rels)
        self.assertNotIn("src/a.py", rels)        # --exclude src dropped it

    def test_scanner_argv_includes_user_excludes(self):
        self.assertIn("docs", scanners._trivy(Path("/r"), Path("/o"), excludes=["docs"]))
        self.assertIn("docs", scanners._semgrep(Path("/r"), Path("/o"), excludes=["docs"]))


class RouteUnitTests(unittest.TestCase):
    def test_clean_path(self):
        self.assertEqual(routes._clean_path("/api/users/:id"), "/api/users/{id}")
        self.assertEqual(routes._clean_path("/files/*key"), "/files/{key}")

    def test_is_noise(self):
        self.assertTrue(routes._is_noise("/assets/*.png"))
        self.assertTrue(routes._is_noise("/BASE_URL/x"))
        self.assertFalse(routes._is_noise("/api/users/{id}"))

    def test_normalize_noir_dedup_django_noise(self):
        eps = [
            {"method": "get", "url": "/api/x/:id", "params": [], "details": {"technology": "t", "code_paths": [{"path": "a"}]}},
            {"method": "GET", "url": "/api/x/{id}", "params": [], "details": {"technology": "t", "code_paths": [{"path": "a"}]}},
            {"method": "GET", "url": "/items/<int:pk>", "params": [], "details": {"technology": "django", "code_paths": [{"path": "b"}]}},
            {"method": "GET", "url": "/assets/*.png", "params": [], "details": {}},
        ]
        app, _spec = routes._normalize_noir(eps)
        paths = {(r["method"], r["path"]) for r in app}
        self.assertIn(("GET", "/api/x/{id}"), paths)        # :id and {id} collapsed
        self.assertIn(("GET", "/items/{pk}"), paths)        # django <int:pk> normalized
        self.assertNotIn(("GET", "/assets/*.png"), paths)   # static-asset glob filtered
        self.assertEqual(sum(1 for _m, p in paths if p == "/api/x/{id}"), 1)

    def test_vendored_spec_routes_split_out(self):  # B1
        eps = [
            {"method": "GET", "url": "/api/sponsors", "details": {"code_paths": [{"path": "src/app/api/sponsors/route.ts"}]}},
            {"method": "POST", "url": "/vault/accounts", "details": {"code_paths": [{"path": "docs-implementation/fireblocks-swagger.yaml"}]}},
            {"method": "POST", "url": "/graphql", "details": {"code_paths": [{"path": "packages/cdk/schemas/appsync.graphql"}]}},
            {"method": "GET", "url": "/users", "details": {"code_paths": [{"path": "node_modules/some-lib/openapi.json"}]}},
        ]
        app, spec = routes._normalize_noir(eps)
        self.assertEqual([(r["method"], r["path"]) for r in app], [("GET", "/api/sponsors")])  # only the real handler
        self.assertEqual(len(spec), 3)                       # swagger + graphql + node_modules openapi excluded

    def test_derive_targeting(self):
        d = routes._derive([
            {"method": "POST", "path": "/api/groups/{groupId}/items", "params": [{"name": "url", "where": "query"}]},
            {"method": "GET", "path": "/api/users/{id}", "params": []},
        ])
        self.assertTrue(d["ssrf_candidates"])
        self.assertTrue(d["idor_candidates"])
        self.assertTrue(d["write_endpoints"])

    def test_fallback_express_no_noir(self):
        paths = {(r["method"], r["path"]) for r in routes._fallback(ctx("node_app"))}
        self.assertIn(("GET", "/api/users/{id}"), paths)
        self.assertIn(("POST", "/api/groups/{groupId}/items"), paths)

    def test_fallback_flask_multiroute_no_route_dropped(self):
        # Regression: a greedy DOTALL methods= group used to reach across the file, mis-assigning
        # the LAST methods=[...] to the FIRST route and swallowing every route in between. Each
        # @route must be parsed independently — /b must survive and keep ITS own POST.
        d = Path(tempfile.mkdtemp())
        (d / "app.py").write_text(
            '@app.route("/a")\ndef a(): ...\n'
            '@app.route("/b", methods=["POST"])\ndef b(): ...\n'
            '@app.route("/c")\ndef c(): ...\n')
        got = {(r["method"], r["path"]) for r in routes._fallback_regex(RepoContext(d))}
        self.assertEqual(got, {("GET", "/a"), ("POST", "/b"), ("GET", "/c")})

    def test_router_heuristic_catches_modern_routers_and_guards_fps(self):
        # P1: generic router-call heuristic — hand-rolled / itty / Hono / Workers, ANY object name.
        d = Path(tempfile.mkdtemp())
        (d / "index.ts").write_text(
            "router.get('/api/health', h);\n"
            "api.post('/api/todos/:id', h);\n"
            "r.delete('/api/items/:id', h);\n"
            "app.on('PUT', '/api/users/:id', h);\n"
            "const cache = new Map(); cache.get('lookup-key');\n"   # FP guard: no leading slash
            "btn.on('click', fn);\n")                                # FP guard: .on(non-method, non-path)
        paths = {(r["method"], r["path"]) for r in routes._router_calls(RepoContext(d))}
        self.assertIn(("GET", "/api/health"), paths)
        self.assertIn(("POST", "/api/todos/:id"), paths)
        self.assertIn(("DELETE", "/api/items/:id"), paths)
        self.assertIn(("PUT", "/api/users/:id"), paths)
        self.assertNotIn(("GET", "lookup-key"), paths)              # cache.get('lookup-key') is not a route
        self.assertFalse(any("click" in p for _, p in paths))      # btn.on('click') is not a route

    def test_coverage_warning_when_handlers_outnumber_routes(self):
        # P1: many handler-ish fns but ~0 mapped routes ⇒ coverage warning (the hand-rolled-router failure mode).
        d = Path(tempfile.mkdtemp())
        (d / "w.ts").write_text(
            "export default { fetch(request, env, ctx) { return dispatch(request); } };\n"
            + "".join(f"const h{i} = (req, res) => res.end();\n" for i in range(8)))
        out = routes.RoutesExtractor().extract(RepoContext(d), {})
        self.assertIsNotNone(out["coverage_warning"])
        self.assertIn("INCOMPLETE", out["coverage_warning"])

    def test_wrangler_build_dir_routes_excluded(self):
        # 0.6.1: .wrangler / .vercel dev-build caches hold BUNDLED output → phantom duplicate routes.
        d = Path(tempfile.mkdtemp())
        (d / "src").mkdir()
        (d / ".wrangler" / "tmp").mkdir(parents=True)
        (d / "src" / "index.ts").write_text("router.get('/api/real', h);\n")
        (d / ".wrangler" / "tmp" / "bundle.js").write_text("router.get('/api/phantom', h);\n")
        paths = {e["path"] for e in routes.RoutesExtractor().extract(RepoContext(d), {})["endpoints"]}
        self.assertIn("/api/real", paths)
        self.assertNotIn("/api/phantom", paths)


class DedupTests(unittest.TestCase):
    def test_within_tool_dedup_and_counts(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "gitleaks.json").write_text(json.dumps([
                {"RuleID": "aws", "File": "x.json", "StartLine": 1, "Description": "k"},
                {"RuleID": "aws", "File": "x.json", "StartLine": 1, "Description": "k"},  # duplicate
            ]))
            (d / "trivy.json").write_text(json.dumps({"Results": [{"Target": "package-lock.json",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "PkgName": "lodash",
                                     "Severity": "HIGH", "InstalledVersion": "1", "FixedVersion": "2"}]}]}))
            sr = [{"key": "gitleaks", "output": str(d / "gitleaks.json")},
                  {"key": "trivy", "output": str(d / "trivy.json")}]
            res = scanners.normalize_findings(sr, d)
            self.assertEqual(res["total_raw"], 3)
            self.assertEqual(res["total"], 2)        # 2 gitleaks dups → 1, plus 1 CVE
            self.assertEqual(res["by_severity"].get("HIGH"), 2)
            self.assertTrue((d / "findings.json").exists())


class LedgerTests(unittest.TestCase):
    def _facts(self, guards):
        return {"authz": {"endpoint_guards": guards}, "surface": {"sinks": {}},
                "client_exposure": {}, "iac_ci": {}, "graphql": {}}

    def test_correlation_confidence_and_standards(self):
        facts = self._facts([
            {"method": "PUT", "path": "/api/settings/config", "code_path": "config.ts", "guarded": False, "analyzed": True, "public_hint": False},
            {"method": "POST", "path": "/api/settings/topics", "code_path": "topics.ts", "guarded": True, "analyzed": True, "public_hint": False},
        ])
        led = findings.build_ledger(facts, None, None, [])
        titles = [f["title"] for f in led["findings"]]
        self.assertTrue(any("config" in t for t in titles))     # no-guard write surfaced
        self.assertFalse(any("topics" in t for t in titles))    # guarded → excluded

        dyn = {"write_auth_enforcement": {"results": [
            {"method": "PUT", "path": "/api/settings/config", "status": 200, "verdict": "EXECUTED-UNAUTH"}]}}
        led2 = findings.build_ledger(facts, None, dyn, [])
        cfg = next(f for f in led2["findings"] if "config" in f["title"])
        self.assertEqual(cfg["confidence"], "HIGH")             # dynamic confirmation escalates
        self.assertEqual(cfg["severity"], "CRITICAL")
        self.assertEqual(len(cfg["evidence"]), 2)               # recon + dynamic evidence chain
        self.assertIn("CWE-862 Missing Authorization", cfg["standards"]["cwe"])
        self.assertTrue(cfg["remediation"])

    def test_suppression(self):
        facts = self._facts([{"method": "PUT", "path": "/api/x", "code_path": "x.ts", "guarded": False, "analyzed": True, "public_hint": False}])
        led = findings.build_ledger(facts, None, None, ["category:access-control"])
        self.assertEqual(led["total"], 0)
        self.assertEqual(led["suppressed"], 1)

    def test_webhook_without_sig_enters_ledger(self):
        # parity fix: unverified webhooks were surfaced in the briefing but never ranked/calibrated.
        facts = {"integrations": {"webhooks_without_sig_verification": ["POST /webhooks/stripe  (h.ts)"]}}
        led = findings.build_ledger(facts, None, None, [])
        hit = [f for f in led["findings"] if f["attack_class"] == "webhook-forgery"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["severity"], "MEDIUM")
        self.assertIn("CWE-345 Insufficient Verification of Data Authenticity", hit[0]["standards"]["cwe"])
        self.assertTrue(hit[0]["remediation"])

    def test_sink_attack_class_maps_to_specific_cwe(self):
        # surface.py emits `sql-injection`/`nosql-injection`/`redos`/`eval-injection`; each must cite
        # its SPECIFIC CWE, not fall back to the generic "sast" (CWE-710).
        facts = {"surface": {"sinks": {
            "sql-injection": {"count": 1, "files": ["a.ts"]},
            "nosql-injection": {"count": 1, "files": ["b.ts"]},
            "redos": {"count": 1, "files": ["c.ts"]},
            "eval-injection": {"count": 1, "files": ["d.ts"]}}},
            "stack": {"datastores": ["postgres"]}}
        by = {f["title"]: f for f in findings.build_ledger(facts, None, None, [])["findings"]}
        self.assertEqual(by["sql-injection sink (1 site(s))"]["attack_class"], "sqli")
        self.assertIn("CWE-89 SQL Injection", by["sql-injection sink (1 site(s))"]["standards"]["cwe"])
        self.assertEqual(by["nosql-injection sink (1 site(s))"]["attack_class"], "nosql-injection")
        self.assertTrue(by["nosql-injection sink (1 site(s))"]["standards"]["cwe"][0].startswith("CWE-943"))
        self.assertEqual(by["eval-injection sink (1 site(s))"]["attack_class"], "eval-injection")
        # a specific remediation, not the generic default
        self.assertNotEqual(by["redos sink (1 site(s))"]["remediation"], "Review and remediate per the cited standard.")

    def test_sqli_not_downranked_when_sql_orm_present(self):
        # fix #9: stack.py emits `sql-orm`/`prisma(sql)` labels; findings._sql must count them as SQL
        # so a SQL-ORM + Mongo app isn't misread as nosql-only and its SQLi wrongly cut to LOW.
        sinks = {"surface": {"sinks": {"sql-injection": {"count": 1, "files": ["db.ts"]}}}}
        led = findings.build_ledger({**sinks, "stack": {"datastores": ["sql-orm", "mongo"]}}, None, None, [])
        self.assertEqual([f for f in led["findings"] if "sql-injection" in f["title"]][0]["severity"], "MEDIUM")
        led2 = findings.build_ledger({**sinks, "stack": {"datastores": ["mongo"]}}, None, None, [])
        self.assertEqual([f for f in led2["findings"] if "sql-injection" in f["title"]][0]["severity"], "LOW")

    def test_ledger_consumes_full_static_set_not_just_top15(self):
        # 20 HIGH static findings → all 20 must reach the ledger (was silently capped at top-15,
        # dropping HIGH/CRITICAL CVEs/secrets ranked #16+ from the ledger + calibration).
        allf = [{"severity": "HIGH", "category": "sca", "title": f"CVE-{i}", "file": f"p{i}", "tools": ["trivy"]}
                for i in range(20)]
        led = findings.build_ledger({}, {"top": allf[:15], "all": allf}, None, [])
        self.assertEqual(len([f for f in led["findings"] if f["attack_class"] == "cve"]), 20)
        # back-compat: a caller passing only `top` still works
        led2 = findings.build_ledger({}, {"top": allf[:15]}, None, [])
        self.assertEqual(len([f for f in led2["findings"] if f["attack_class"] == "cve"]), 15)


class Wave1FalsePositiveTests(unittest.TestCase):
    """Regressions for the FP-killer wave validated on a real LLM-agent monorepo (mount-auth, ssrf, client
    exposure, pii dead-control, upload-serve, gha-injection, cookie-secure)."""

    # --- router-mount auth (the 292→~30 missing-auth fix) ---
    def _mount_repo(self, server_body, route_files):
        d = Path(tempfile.mkdtemp())
        (d / "server.ts").write_text(server_body)
        (d / "routes").mkdir()
        for name, body in route_files.items():
            (d / "routes" / name).write_text(body)
        return d

    def _authz(self, d, code_path, method="DELETE", path="/:id"):
        eps = [{"method": method, "path": path, "code_path": str(d / "routes" / code_path)}]
        return AuthzExtractor().extract(RepoContext(d), {"routes": {"endpoints": eps}})

    def test_router_mount_auth_covers_subrouter(self):
        d = self._mount_repo(
            "import { createXRouter } from './routes/x.js';\n"
            "app.use('/api/x', authMiddleware({ secret }), createXRouter(db));\n",
            {"x.ts": "export function createXRouter(){ const router=Router();"
                     " router.delete('/:id', h); return router; }"})
        out = self._authz(d, "x.ts")
        self.assertTrue(out["mount_auth_detected"])
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 0)   # covered at the mount

    def test_unauthed_app_mount_not_covered(self):
        d = self._mount_repo(
            "import { createPubRouter } from './routes/pub.js';\n"
            "app.use('/public', createPubRouter());\n",                  # no auth middleware
            {"pub.ts": "export function createPubRouter(){ const router=Router();"
                       " router.delete('/:id', h); return router; }"})
        out = self._authz(d, "pub.ts")
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 1)    # genuinely unguarded

    def test_inner_subrouter_inherits_parent_auth(self):
        # auth at /api/x mount; x.ts mounts y via inner `router.use` WITHOUT re-stating auth (inherits)
        d = self._mount_repo(
            "import { createXRouter } from './routes/x.js';\n"
            "app.use('/api/x', authMiddleware(), createXRouter(db));\n",
            {"x.ts": "import { createYRouter } from './y.js';\n"
                     "export function createXRouter(){ const router=Router();"
                     " router.use('/y', createYRouter()); return router; }",
             "y.ts": "export function createYRouter(){ const router=Router();"
                     " router.post('/:id', h); return router; }"})
        out = self._authz(d, "y.ts", method="POST", path="/:id")
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 0)    # inherited from parent mount

    def test_test_harness_mount_does_not_mark_unauthed(self):
        # a *.test.ts harness mounts the router unauthed; the real app mounts it WITH auth → covered
        d = self._mount_repo(
            "import { createXRouter } from './routes/x.js';\n"
            "app.use('/api/x', authMiddleware(), createXRouter(db));\n",
            {"x.ts": "export function createXRouter(){ const router=Router();"
                     " router.delete('/:id', h); return router; }",
             "x.test.ts": "import { createXRouter } from './x.js';\n"
                          "app.use(createXRouter());  // unauth harness\n"})
        out = self._authz(d, "x.ts")
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 0)

    def test_custom_auth_helper_recognized(self):
        d = Path(tempfile.mkdtemp())
        (d / "route.ts").write_text(
            "export async function GET(req){ const a = await getRequestSessionAuth(req);"
            " if (a.status !== 'ready') return createSessionAuthFailureResponse(); return Response.json({}); }")
        eps = [{"method": "GET", "path": "/api/x", "code_path": str(d / "route.ts")}]
        out = AuthzExtractor().extract(RepoContext(d), {"routes": {"endpoints": eps}})
        self.assertEqual(out["guard_summary"]["no_visible_guard"], 0)

    # --- SSRF gating (41 ssrf FPs → 0) ---
    def _surface(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            (d / name).write_text(body)
        return SurfaceExtractor().extract(RepoContext(d), {"stack": {"datastores": []}})

    def test_ssrf_requires_request_source(self):
        s = self._surface({"h.ts": "app.get('/x', async (req,res)=>{ await fetch(`${req.query.url}`); });"})
        self.assertIn("ssrf", s["sinks"])

    def test_ssrf_skips_client_relative_fetch(self):
        s = self._surface({"comp.tsx": "export function C(){ return fetch(`/api/x/${id}`); }"})
        self.assertNotIn("ssrf", s["sinks"])

    def test_ssrf_skips_hardcoded_host_with_token(self):
        s = self._surface({"adapter.ts": "export function send(){ return fetch(`https://api.telegram.org/bot${this.token}/send`); }"})
        self.assertNotIn("ssrf", s["sinks"])

    def test_command_injection_argv_shell_false_is_safe(self):
        s = self._surface({"r.py": "subprocess.run(cmd, capture_output=True, shell=False, timeout=t)"})
        self.assertNotIn("command-injection", s["sinks"])

    # --- client exposure: per-package frontend gating + analytics allowlist ---
    def _client(self, deps, files):
        d = Path(tempfile.mkdtemp())
        (d / "package.json").write_text('{"dependencies": {%s}}' % deps)
        for name, body in files.items():
            (d / name).write_text(body)
        return ClientExposureExtractor().extract(RepoContext(d), {})

    def test_backend_public_var_not_flagged(self):
        out = self._client('"express": "4"', {"config.ts": "const k = process.env.NEXT_PUBLIC_API_KEY;"})
        self.assertEqual(out["public_secret_leaks"], [])

    def test_frontend_public_var_flagged(self):
        out = self._client('"next": "15"', {"config.ts": "const k = process.env.NEXT_PUBLIC_API_KEY;"})
        self.assertTrue(out["public_secret_leaks"])

    def test_analytics_token_is_info_not_leak(self):
        out = self._client('"next": "15"', {"a.ts": "const k = process.env.NEXT_PUBLIC_POSTHOG_TOKEN;"})
        self.assertEqual(out["public_secret_leaks"], [])
        self.assertTrue(out["intended_public_analytics"])

    def test_client_exposure_skips_test_files(self):
        out = self._client('"next": "15"', {"a.test.ts": "process.env.NEXT_PUBLIC_API_KEY = 'x';"})
        self.assertEqual(out["public_secret_leaks"], [])

    # --- PII dead-control: same-file wiring is not "dead" ---
    def test_masker_called_same_file_not_dead(self):
        d = Path(tempfile.mkdtemp())
        (d / "log.ts").write_text("function maskEmail(e){ return e; }\nconst x = maskEmail('a@b.com');")
        out = PiiExposureExtractor().extract(RepoContext(d), {})
        self.assertNotIn("maskEmail", out["dead_controls"])

    def test_unused_masker_is_dead_low(self):
        d = Path(tempfile.mkdtemp())
        (d / "m.ts").write_text("export function maskEmail(e){ return e; }")
        out = PiiExposureExtractor().extract(RepoContext(d), {})
        self.assertIn("maskEmail", out["dead_controls"])
        sev = {f["kind"]: f["severity"] for f in out["findings"]}
        self.assertEqual(sev.get("dead-pii-control"), "LOW")

    def test_secret_masker_excluded_from_pii(self):
        d = Path(tempfile.mkdtemp())
        (d / "m.ts").write_text("export function maskDatabaseUrl(u){ return u; }")
        out = PiiExposureExtractor().extract(RepoContext(d), {})
        self.assertNotIn("maskDatabaseUrl", out["dead_controls"])

    # --- upload serve: Content-Disposition: attachment is safe ---
    def test_serve_with_attachment_is_safe(self):
        d = Path(tempfile.mkdtemp())
        (d / "s.ts").write_text("res.sendFile(p, { headers: { 'Content-Disposition': 'attachment; filename=x' } });")
        out = UploadSecurityExtractor().extract(RepoContext(d), {})
        self.assertFalse([f for f in out["findings"] if f["kind"] == "serve-no-nosniff"])

    def test_serve_without_nosniff_or_attachment_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / "s.ts").write_text("res.sendFile(absolutePath);")
        out = UploadSecurityExtractor().extract(RepoContext(d), {})
        self.assertTrue([f for f in out["findings"] if f["kind"] == "serve-no-nosniff"])

    # --- GHA script-injection: position-aware (run: body only) ---
    def _gha(self, wf_body):
        d = Path(tempfile.mkdtemp())
        (d / ".github" / "workflows").mkdir(parents=True)
        (d / ".github" / "workflows" / "ci.yml").write_text(wf_body)
        return IacCiExtractor().extract(RepoContext(d), {})

    def test_gha_injection_in_run_flagged(self):
        out = self._gha("jobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n")
        k = [f for f in out["findings"] if f["kind"] == "gha-script-injection"]
        self.assertTrue(k)
        self.assertEqual(k[0]["severity"], "HIGH")
        # the matched context is already a full `${{ github.… }}` string — don't re-prefix `github.`
        self.assertNotIn("github.${{", k[0]["detail"])
        self.assertIn("${{ github.event.pull_request.title }}", k[0]["detail"])

    def test_gha_context_in_if_not_flagged(self):
        out = self._gha("jobs:\n  b:\n    if: ${{ github.event.pull_request.title == 'x' }}\n"
                        "    steps:\n      - run: echo hi\n")
        self.assertFalse([f for f in out["findings"] if f["kind"] == "gha-script-injection"])

    # --- cookie Secure recognized when set conditionally ---
    def test_cookie_secure_conditional_recognized(self):
        d = Path(tempfile.mkdtemp())
        (d / "s.ts").write_text("res.cookie('t', v, { httpOnly: true, secure: isProduction(), sameSite: 'lax' });")
        out = TransportSecurityExtractor().extract(
            RepoContext(d), {"stack": {"frameworks": []}, "routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})
        self.assertTrue(out["cookie_security"]["secure"])
        self.assertFalse([f for f in out["findings"] if f["kind"] == "cookie-flags"])


class Wave2DetectorTests(unittest.TestCase):
    """New-capability detectors: LLM/AI-agent security, docker-compose, secret-suppression."""

    def _llm(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return LlmSecurityExtractor().extract(RepoContext(d), {})

    def _kinds(self, out):
        return {f["kind"] for f in out["findings"]}

    def test_unbounded_generation_flagged(self):
        out = self._llm({"svc.ts": "export async function run(p){ return await generateText({ model, prompt: p }); }"})
        self.assertIn("llm-unbounded-generation", self._kinds(out))
        self.assertTrue(out["is_ai_app"])

    def test_bounded_generation_not_flagged(self):
        out = self._llm({"svc.ts": "await generateText({ model, prompt: p, maxOutputTokens: 512, abortSignal: s });"})
        self.assertNotIn("llm-unbounded-generation", self._kinds(out))

    def test_insecure_output_handling_flagged(self):
        out = self._llm({"loop.ts": "await generateText({model,prompt});\n"
                                    "if (text.includes('\"tool_use\"')) dispatch(JSON.parse(completion));"})
        self.assertIn("llm-insecure-output-handling", self._kinds(out))

    def test_indirect_prompt_injection_flagged(self):
        out = self._llm({"rag.ts": "await generateText({ model, prompt: `Context: ${excerptText}` });"})
        self.assertIn("llm-indirect-prompt-injection", self._kinds(out))

    def test_sanitized_prompt_not_flagged(self):
        out = self._llm({"rag.ts": "const c = sanitizePromptString(excerptText);\n"
                                   "await generateText({ model, prompt: `Context: ${c}` });"})
        self.assertNotIn("llm-indirect-prompt-injection", self._kinds(out))

    def test_llm_skips_scripts(self):
        out = self._llm({"scripts/migrate.ts": "await generateText({ model, prompt: p });"})
        self.assertEqual(out["findings"], [])

    def test_guardrail_fail_open_flagged(self):
        out = self._llm({"guard.ts": "export async function scanInput(t){ try { return await check(t); } "
                                     "catch (e) { return { allowed: true }; } }"})
        self.assertIn("llm-guardrail-fail-open", self._kinds(out))

    # --- docker-compose host exposure ---
    def _compose(self, body):
        d = Path(tempfile.mkdtemp())
        (d / "docker-compose.yml").write_text(body)
        return IacCiExtractor().extract(RepoContext(d), {})

    def test_compose_docker_sock_flagged(self):
        out = self._compose("services:\n  p:\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock:ro\n")
        kinds = {f["kind"] for f in out["findings"]}
        self.assertIn("compose-docker-sock-mount", kinds)

    def test_compose_privileged_flagged(self):
        out = self._compose("services:\n  x:\n    privileged: true\n")
        self.assertIn("compose-privileged", {f["kind"] for f in out["findings"]})

    def test_compose_clean_not_flagged(self):
        out = self._compose("services:\n  web:\n    image: app:1\n    ports:\n      - '3000:3000'\n")
        comp = [f for f in out["findings"] if f["kind"].startswith("compose-")]
        self.assertEqual(comp, [])

    # --- secret-suppression audit ---
    def test_suppressed_real_secret_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / ".gitleaksignore").write_text("abc123:.env.prod:generic-api-key:3\n")
        out = IacCiExtractor().extract(RepoContext(d), {})
        sup = [f for f in out["findings"] if f["kind"] == "suppressed-secret-leak"]
        self.assertTrue(sup)
        self.assertEqual(sup[0]["severity"], "HIGH")
        self.assertEqual(sup[0]["attack_class"], "secret")

    def test_suppressed_example_file_not_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / ".gitleaksignore").write_text("abc123:.env.example:generic-api-key:3\n# a comment\n")
        out = IacCiExtractor().extract(RepoContext(d), {})
        self.assertEqual([f for f in out["findings"] if f["kind"] == "suppressed-secret-leak"], [])


class Wave2bDetectorTests(unittest.TestCase):
    """Reverse-proxy prefix-escape + crypto-usage detectors."""

    def _surface(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return SurfaceExtractor().extract(RepoContext(d), {"stack": {"datastores": ["postgres"]}})

    def test_proxy_prefix_escape_flagged(self):
        out = self._surface({"route.ts": "const p = endpoint.join('/');\n"
                                         "await fetch(`${config.upstream}/api/x/${p}`, { headers });"})
        self.assertEqual(len(out.get("proxy_prefix_escape", [])), 1)

    def test_proxy_with_dotseg_guard_not_flagged(self):
        out = self._surface({"route.ts": "if (endpoint.includes('..')) return bad();\n"
                                         "const p = endpoint.join('/');\n"
                                         "await fetch(`${config.upstream}/api/x/${p}`);"})
        self.assertEqual(out.get("proxy_prefix_escape", []), [])

    def _crypto(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            d.joinpath(name).write_text(body)
        return CryptoUsageExtractor().extract(RepoContext(d), {})

    def _kinds(self, out):
        return {f["kind"] for f in out["findings"]}

    def test_weak_password_hash_flagged(self):
        out = self._crypto({"auth.ts": "export function verifyPassword(input){ "
                                       "return createHash('sha256').update(input).digest('hex'); }"})
        k = [f for f in out["findings"] if f["kind"] == "weak-password-hash"]
        self.assertTrue(k)
        self.assertEqual(k[0]["severity"], "HIGH")

    def test_bcrypt_password_not_flagged(self):
        out = self._crypto({"auth.ts": "export async function verifyPassword(p, h){ return bcrypt.compare(p, h); }"})
        self.assertNotIn("weak-password-hash", self._kinds(out))

    def test_jwt_verify_without_algorithms_flagged(self):
        out = self._crypto({"mw.ts": "const { payload } = await jwtVerify(token, key);"})
        self.assertIn("jwt-verify-no-algorithms", self._kinds(out))

    def test_jwt_verify_with_algorithms_not_flagged(self):
        out = self._crypto({"mw.ts": "const { payload } = await jwtVerify(token, key, { algorithms: ['HS256'] });"})
        self.assertNotIn("jwt-verify-no-algorithms", self._kinds(out))

    def test_predictable_principal_flagged(self):
        out = self._crypto({"id.ts": "export function toId(email){ const h = createHash('sha256').update(email)"
                                     ".digest('hex'); return formatUuid(h) as tenantId; }"})
        self.assertIn("predictable-principal", self._kinds(out))

    def test_timing_unsafe_compare_flagged(self):
        out = self._crypto({"m.ts": "if ((req.header('authorization') ?? '') !== expected) return deny();"})
        self.assertIn("timing-unsafe-compare", self._kinds(out))

    def test_timing_safe_compare_not_flagged(self):
        out = self._crypto({"m.ts": "if (!crypto.timingSafeEqual(Buffer.from(req.header('authorization')||''), "
                                    "Buffer.from(expected))) return deny();"})
        self.assertNotIn("timing-unsafe-compare", self._kinds(out))

    def test_hibp_sha1_not_flagged(self):
        code = "def check_pwned_password(password: str):\n  sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()\n  return fetch(f'https://api.pwnedpasswords.com/range/{sha1_hash[:5]}')"
        out = self._crypto({"auth.py": code})
        self.assertNotIn("weak-password-hash", self._kinds(out))

    def test_password_reset_token_not_flagged(self):
        code = "def verify_password_reset_token(token: str, db_token_hash: str):\n  token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()\n  return crypto.timingSafeEqual(token_hash, db_token_hash)"
        out = self._crypto({"auth.py": code})
        self.assertNotIn("weak-password-hash", self._kinds(out))

    def test_avatar_hash_not_flagged(self):
        code = "def get_user_avatar(email: str):\n  user_id = hashlib.sha256(email.strip().lower().encode('utf-8')).hexdigest()\n  return f'https://www.gravatar.com/avatar/{user_id}?d=identicon'"
        out = self._crypto({"avatar.py": code})
        self.assertNotIn("predictable-principal", self._kinds(out))

    def test_jwt_verify_options_variable_not_flagged(self):
        code = "import { jwtVerifyOptions } from './config';\nexport async function verifyMyToken(token, key) {\n  const { payload } = await jwt.verify(token, key, jwtVerifyOptions);\n  return payload;\n}"
        out = self._crypto({"mw.ts": code})
        self.assertNotIn("jwt-verify-no-algorithms", self._kinds(out))

    def test_predictable_principal_cache_key_not_flagged(self):
        code = "const crypto = require('crypto');\nfunction getUserData(userId) {\n  const cacheKey = crypto.createHash('sha256').update(userId).digest('hex');\n  return redis.get(`cache:user:${cacheKey}`);\n}"
        out = self._crypto({"cache.js": code})
        self.assertNotIn("predictable-principal", self._kinds(out))


class Wave3DeferredDetectorTests(unittest.TestCase):
    """0.8.0 deferred-backlog detectors: CORS, Next-config headers, SRI, host-redirect,
    follows-redirect, unsigned-cookie authz, claim-authz, transaction-local RLS."""

    # --- transport: CORS / SRI / next-config ---
    def _transport(self, files, frameworks=("next", "express")):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return TransportSecurityExtractor().extract(
            RepoContext(d), {"stack": {"frameworks": list(frameworks)}, "routes": {"endpoints": [{"method": "GET", "path": "/x"}]}})

    def _tkinds(self, out):
        return {f["kind"] for f in out["findings"]}

    def test_cors_reflect_with_credentials_high(self):
        out = self._transport({"srv.ts": "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);\n"
                                          "res.setHeader('Access-Control-Allow-Credentials', 'true');"})
        hi = [f for f in out["findings"] if f["kind"] == "cors-credentials-any-origin"]
        self.assertTrue(hi)
        self.assertEqual(hi[0]["severity"], "HIGH")

    def test_cors_allowlist_not_flagged(self):
        out = self._transport({"srv.ts": "app.use(cors({ origin: ['https://app.example.com'], credentials: true }));"})
        self.assertNotIn("cors-credentials-any-origin", self._tkinds(out))

    def test_external_script_without_sri_flagged(self):
        out = self._transport({"docs.ts": "res.send(`<html><script src=\"https://cdn.jsdelivr.net/npm/x/y.js\"></script></html>`);"})
        self.assertIn("external-script-no-sri", self._tkinds(out))

    def test_external_script_with_sri_not_flagged(self):
        out = self._transport({"docs.ts": "res.send(`<html><script src=\"https://cdn/x.js\" integrity=\"sha384-abc\"></script></html>`);"})
        self.assertNotIn("external-script-no-sri", self._tkinds(out))

    def test_nextjs_config_no_headers_flagged(self):
        out = self._transport({"packages/web/next.config.ts": "export default { reactStrictMode: true };"})
        self.assertIn("nextjs-no-security-headers", self._tkinds(out))

    def test_nextjs_config_with_headers_not_flagged(self):
        out = self._transport({"packages/web/next.config.ts":
                               "export default { async headers(){ return [{ source:'/(.*)', headers:["
                               "{key:'Content-Security-Policy',value:\"default-src 'self'\"},"
                               "{key:'X-Frame-Options',value:'DENY'}]}]; } };"})
        ks = self._tkinds(out)
        self.assertNotIn("nextjs-no-security-headers", ks)
        self.assertNotIn("nextjs-partial-security-headers", ks)

    # --- surface: host-redirect / follows-redirect ---
    def _surface(self, files, ds=("postgres",)):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            p = d / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return SurfaceExtractor().extract(RepoContext(d), {"stack": {"datastores": list(ds)}})

    def test_host_header_redirect_flagged(self):
        out = self._surface({"h.ts": "const host = req.headers['x-forwarded-host'];\n"
                                     "return res.redirect(`https://${host}/next`);"})
        self.assertEqual(len(out["host_header_redirect"]), 1)

    def test_host_header_redirect_with_allowlist_not_flagged(self):
        out = self._surface({"h.ts": "const host = req.headers['x-forwarded-host'];\n"
                                     "const base = allowedHosts.includes(host) ? host : publicWebOrigin;\n"
                                     "return res.redirect(`https://${base}/next`);"})
        self.assertEqual(out["host_header_redirect"], [])

    def test_follows_redirects_no_allowlist_flagged(self):
        out = self._surface({"job.py": "r = httpx.get(url, follow_redirects=True)"})
        self.assertEqual(len(out["follows_redirect_no_allowlist"]), 1)

    def test_follows_redirects_disabled_not_flagged(self):
        out = self._surface({"job.py": "r = httpx.get(url, follow_redirects=False)"})
        self.assertEqual(out["follows_redirect_no_allowlist"], [])

    # --- authz_dataflow: cookie-authz / claim-authz / rls-context ---
    def _adf(self, files):
        d = Path(tempfile.mkdtemp())
        for name, body in files.items():
            d.joinpath(name).write_text(body)
        return AuthzDataflowExtractor().extract(RepoContext(d), {})

    def _akinds(self, out):
        return {f["kind"] for f in out["findings"]}

    def test_unsigned_cookie_authz_flagged(self):
        out = self._adf({"mw.ts": "const lvl = req.cookies.get('twin-access-level');\n"
                                  "if (lvl !== 'full') return new Response('forbidden', { status: 403 });"})
        self.assertIn("unsigned-cookie-authz", self._akinds(out))

    def test_cookie_authz_with_jwt_verify_not_flagged(self):
        out = self._adf({"mw.ts": "const lvl = req.cookies.get('twin-access-level');\n"
                                  "const ok = await jwtVerify(req.cookies.get('twin-token'), key);\n"
                                  "if (lvl !== 'full') return new Response('forbidden', { status: 403 });"})
        self.assertNotIn("unsigned-cookie-authz", self._akinds(out))

    def test_claim_based_authz_flagged(self):
        out = self._adf({"acl.ts": "export function canAccessDocument(ctx, doc){ "
                                   "return ctx.tenantOffice === doc.authorOffice; }"})
        self.assertIn("claim-based-authz", self._akinds(out))

    def test_rls_context_no_transaction_flagged(self):
        out = self._adf({"rls.ts": "await db.execute(sql`SELECT set_config('app.user_id', ${userId}, true)`);"})
        self.assertIn("rls-context-no-transaction", self._akinds(out))

    def test_rls_context_in_transaction_not_flagged(self):
        out = self._adf({"rls.ts": "await db.transaction(async (tx) => { "
                                   "await tx.execute(sql`SELECT set_config('app.user_id', ${userId}, true)`); });"})
        self.assertNotIn("rls-context-no-transaction", self._akinds(out))


# ---------------------------------------------------------------------------------------------------
class AgentConfigTests(unittest.TestCase):
    """P2 — agent-config / MCP attack surface (OWASP Agentic Top 10). Repo-own agent wiring read as
    untrusted DATA, never executed. 5 structural classes; tool-description poisoning is deferred. The
    clean control MIRRORS this repo's real OpenWolf config + a multilingual file with a legit LRM."""

    def _kinds(self, fixture):
        f = AgentConfigExtractor().extract(ctx(fixture), {})
        return f, {x["kind"] for x in f["findings"]}

    def test_poisoned_fires_all_five_classes(self):
        f, kinds = self._kinds("agent_config_poisoned")
        self.assertEqual(kinds, {"hidden-unicode", "hook-autoexec", "mcp-autoapprove",
                                 "baseurl-override", "mcp-unpinned-server"})

    def test_clean_config_is_silent(self):
        f, kinds = self._kinds("agent_config_clean")
        self.assertEqual(f["findings"], [], f"benign OpenWolf-shaped config must not fire: {kinds}")

    def test_hidden_unicode_reports_codepoint_and_line(self):
        f, _ = self._kinds("agent_config_poisoned")
        hu = [x for x in f["findings"] if x["kind"] == "hidden-unicode"][0]
        self.assertEqual(hu["file"], "CLAUDE.md")
        self.assertIn("U+202E", hu["detail"])
        self.assertIn("line", hu)

    def test_legit_lrm_not_flagged(self):
        # AGENTS.md control has U+200E (LRM) which is EXCLUDED from BAD_CP — multilingual repos are safe.
        f, kinds = self._kinds("agent_config_clean")
        self.assertNotIn("hidden-unicode", kinds)

    def test_pinned_mcp_server_not_flagged(self):
        f, _ = self._kinds("agent_config_poisoned")
        unpinned = [x for x in f["findings"] if x["kind"] == "mcp-unpinned-server"]
        self.assertEqual(len(unpinned), 1)              # only the @evil/mcp-server, not the pinned one
        self.assertIn("evil", unpinned[0]["detail"])

    def test_benign_hook_shape_not_flagged(self):
        # `node "$CLAUDE_PROJECT_DIR/..."` and `python3 tools/x.py` (no -c/-e, no fetch|sh) must be silent.
        f, kinds = self._kinds("agent_config_clean")
        self.assertNotIn("hook-autoexec", kinds)

    def test_vendor_baseurl_not_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / ".mcp.json").write_text('{"env": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com"}}')
        f = AgentConfigExtractor().extract(RepoContext(d), {})
        self.assertNotIn("baseurl-override", {x["kind"] for x in f["findings"]})

    def test_explicit_autoapprove_list_not_flagged(self):
        d = Path(tempfile.mkdtemp())
        (d / ".mcp.json").write_text('{"autoApprove": ["read_file", "list_dir"]}')
        f = AgentConfigExtractor().extract(RepoContext(d), {})
        self.assertNotIn("mcp-autoapprove", {x["kind"] for x in f["findings"]})

    def test_malformed_json_does_not_crash(self):
        d = Path(tempfile.mkdtemp())
        (d / ".mcp.json").write_text('{"mcpServers": {  not valid json ]]')
        f = AgentConfigExtractor().extract(RepoContext(d), {})   # must not raise
        self.assertIn("agent_surface_present", f)

    def test_no_agent_surface_is_empty(self):
        d = Path(tempfile.mkdtemp())
        (d / "app.py").write_text("print('hi')")
        f = AgentConfigExtractor().extract(RepoContext(d), {})
        self.assertFalse(f["agent_surface_present"])
        self.assertEqual(f["findings"], [])

    def test_findings_reach_ledger_with_owasp_agentic_mapping(self):
        facts = {"agent_config": AgentConfigExtractor().extract(ctx("agent_config_poisoned"), {})}
        led = findings.build_ledger(facts, None, None, [])
        classes = {x["attack_class"] for x in led["findings"]}
        self.assertIn("agent-config-hidden-unicode", classes)
        self.assertIn("agent-mcp-autoapprove", classes)
        # OWASP Agentic Top 10 citation flows through _cite()/STANDARDS
        hu = [x for x in led["findings"] if x["attack_class"] == "agent-config-hidden-unicode"][0]
        self.assertTrue(any("ASI" in o for o in hu["standards"]["owasp_api"]))


# ---------------------------------------------------------------------------------------------------
class LogInjectionTests(unittest.TestCase):
    """P1 — log injection (CWE-117), the 17th sink class. LOW severity (log forging, not RCE). The
    load-bearing FP guard is that no regex arm may cross a comma — so STRUCTURED/parametrized logging
    never matches. Server-only (client/CLI/no-web-surface suppressed)."""

    rx = SINKS["log-injection"][2]

    def test_regex_fires_on_concatenation_and_interpolation(self):
        for s in ("logger.info('user: ' + req.query.name)",
                  "logger.info(`login ${req.query.u}`)",
                  'logging.info(f"ip={request.headers.get(\'x\')}")',
                  "console.error(req.body)",
                  "winston.warn('bad ' + request.args.get('q'))"):
            self.assertTrue(self.rx.search(s), f"should flag: {s}")

    def test_regex_ignores_structured_logging(self):
        # the comma guard: a user value in a SEPARATE argument is parametrized/structured logging → safe
        for s in ("logger.info('user=%s', req.query.name)",
                  "logging.info('path=%s', request.args.get('p'))",
                  "logger.info({ user: req.query.u }, 'login')",
                  "log.info('event', extra={'user': request.user})",
                  "logger.info('server started on port 3000')",
                  "console.log(user.name)"):
            self.assertFalse(self.rx.search(s), f"should NOT flag: {s}")

    def test_bare_print_is_not_a_log_sink(self):
        # protects the tool's own cli.py print() idiom and every CLI that prints user input
        self.assertFalse(self.rx.search("print('target: ' + req.query.x)"))

    def test_fires_in_server_file(self):
        d = Path(tempfile.mkdtemp())
        (d / "server.js").write_text("function h(req,res){ logger.info('u: ' + req.query.name); }\n")
        s = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["node"], "frameworks": ["express"]}})
        self.assertIn("log-injection", s["sinks"])

    def test_suppressed_on_client_file(self):
        d = Path(tempfile.mkdtemp())
        (d / "Widget.tsx").write_text("export const W = () => { console.log('u:' + req.query.name); return null; }\n")
        s = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["node"], "frameworks": ["express"]}})
        self.assertNotIn("log-injection", s["sinks"])

    def test_suppressed_on_non_web_repo(self):
        d = Path(tempfile.mkdtemp())
        (d / "app.py").write_text("def h():\n    logging.info(f\"x={request.args.get('x')}\")\n")
        cli = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["python"], "frameworks": []}})
        self.assertNotIn("log-injection", cli["sinks"])
        web = SurfaceExtractor().extract(RepoContext(d), {"stack": {"languages": ["python"], "frameworks": ["flask"]}})
        self.assertIn("log-injection", web["sinks"])

    def test_ledger_ranks_low_with_cwe_117(self):
        facts = {"surface": {"sinks": {"log-injection": {"probe": "log-forging-verify",
                                                         "count": 1, "files": ["server.js"]}}}}
        led = findings.build_ledger(facts, None, None, [])
        li = [x for x in led["findings"] if x["attack_class"] == "log-injection"]
        self.assertTrue(li)
        self.assertEqual(li[0]["severity"], "LOW")
        self.assertTrue(any("CWE-117" in c for c in li[0]["standards"]["cwe"]))


# ---------------------------------------------------------------------------------------------------
class DependenciesTests(unittest.TestCase):
    """P3 — offline supply-chain hygiene (22nd extractor). LEDGER = malicious-install-script + lockfile-
    drift ONLY. Unpinned versions and dependency-confusion names are ADVISORY facts, NEVER routed to the
    ledger (the load-bearing FP-safety guarantee). Zero network in the default pass."""

    def _dep(self, fixture):
        return DependenciesExtractor().extract(ctx(fixture), {})

    def test_malicious_install_script_fires(self):
        f = self._dep("dep_supplychain")
        self.assertIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_benign_lifecycle_scripts_silent(self):
        # husky install / patch-package / tsc are NOT fetch-and-execute → no finding
        f = self._dep("dep_benign_monorepo")
        self.assertNotIn("malicious-install-script", [x["kind"] for x in f["findings"]])

    def test_lockfile_drift_fires_on_missing_dep(self):
        f = self._dep("dep_supplychain_drift")
        drift = [x for x in f["findings"] if x["kind"] == "lockfile-drift"]
        self.assertEqual(len(drift), 1)              # only dotenv (express+helmet are in the lock)
        self.assertIn("dotenv", drift[0]["detail"])

    def test_no_lockfile_means_no_drift(self):
        f = self._dep("node_app")                    # ^-range deps, NO lockfile
        self.assertNotIn("lockfile-drift", [x["kind"] for x in f["findings"]])

    def test_unpinned_is_advisory_only_never_ledger(self):
        f = self._dep("node_app")
        self.assertGreater(f["counts"]["unpinned"], 0)     # surfaced as advisory
        self.assertEqual(f["findings"], [])                # but NOT in the ledger-bound findings[]

    def test_workspace_and_public_scope_not_confusion(self):
        f = self._dep("dep_benign_monorepo")
        self.assertEqual(f["counts"]["confusion_candidates"], 0)   # @myorg workspace:/file:, @aws-sdk allowlisted

    def test_pinned_pip_is_clean(self):
        f = self._dep("dep_benign_pip")
        self.assertEqual(f["findings"], [])
        self.assertEqual(f["counts"]["unpinned"], 0)

    def test_malformed_json_does_not_crash(self):
        f = self._dep("dep_malformed")               # must not raise
        self.assertEqual(f["findings"], [])

    def test_network_never_runs_in_default_pass(self):
        for fx in ("dep_supplychain", "node_app", "dep_benign_pip"):
            self.assertFalse(self._dep(fx)["network"]["ran"])

    def test_ledger_routes_findings_but_not_advisory(self):
        # dep_supplychain (install-script) → routed; dep_benign_monorepo (only unpinned) → nothing routed
        led_bad = findings.build_ledger({"dependencies": self._dep("dep_supplychain")}, None, None, [])
        self.assertIn("malicious-install-script", {x["attack_class"] for x in led_bad["findings"]})
        led_ok = findings.build_ledger({"dependencies": self._dep("dep_benign_monorepo")}, None, None, [])
        self.assertNotIn("supply-chain", {x["category"] for x in led_ok["findings"]})

    def test_install_script_cwe_mapping(self):
        led = findings.build_ledger({"dependencies": self._dep("dep_supplychain")}, None, None, [])
        mis = [x for x in led["findings"] if x["attack_class"] == "malicious-install-script"][0]
        self.assertTrue(any("CWE-506" in c for c in mis["standards"]["cwe"]))


if __name__ == "__main__":
    unittest.main()
