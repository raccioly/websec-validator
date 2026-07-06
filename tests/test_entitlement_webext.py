"""Regression tests for the entitlement / licensing + WebExtension client-trust classes.

Covers the manifest-less stack (a browser extension + Deno/Supabase edge functions, NO package.json)
and the license-verification trust gaps: granting on `success`/`valid` alone (no revocation check),
no per-principal usage cap, and client-side entitlement gates. The detectors are provider-AGNOSTIC —
the cross-provider cases below (Gumroad / Stripe / Lemon Squeezy, various cap/revocation namings)
prove nothing is fitted to one provider or app. Stdlib unittest only — no Noir, no network.
"""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import findings, probes                                   # noqa: E402
from websec_validator.extractors import routes                                  # noqa: E402
from websec_validator.extractors.base import RepoContext                        # noqa: E402
from websec_validator.extractors.stack import StackExtractor                    # noqa: E402
from websec_validator.extractors.schemas import SchemasExtractor                # noqa: E402
from websec_validator.extractors.tenant import TenantExtractor                  # noqa: E402
from websec_validator.extractors.integrations import IntegrationsExtractor      # noqa: E402
from websec_validator.extractors.webext import WebExtExtractor                  # noqa: E402
from websec_validator.extractors.client_exposure import ClientExposureExtractor  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"


def _sb_jwt(role: str) -> str:
    """A Supabase-style JWT literal (header.payload.sig) with the given role claim."""
    import base64
    import json
    b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'iss': 'supabase', 'ref': 'proj', 'role': role})}.{'s' * 32}"


def ctx(name):
    return RepoContext(FIX / name)


def tmp_ctx(files: dict):
    """Build a RepoContext over an inline {relpath: content} tree (for negative/fixed cases)."""
    d = Path(tempfile.mkdtemp())
    for rel, content in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return RepoContext(d)


# ---------------------------------------------------------------------------------------------------
class ManifestlessStackTests(unittest.TestCase):
    def test_detects_deno_supabase_webext_without_package_json(self):
        f = StackExtractor().extract(ctx("webext_licensed"), {})
        self.assertIn("typescript", f["languages"])       # file-extension fallback (no package.json)
        self.assertIn("deno", f["frameworks"])
        self.assertIn("supabase-edge", f["frameworks"])
        self.assertIn("webextension", f["frameworks"])
        self.assertIn("postgres", f["datastores"])         # from supabase + schema.sql

    def test_sql_schema_only_still_infers_postgres(self):
        c = tmp_ctx({"db/schema.sql": "CREATE TABLE t (id uuid DEFAULT gen_random_uuid(), x jsonb);\n"})
        f = StackExtractor().extract(c, {})
        self.assertIn("postgres", f["datastores"])


class SupabaseRouteTests(unittest.TestCase):
    def test_edge_function_becomes_a_post_route(self):
        c = ctx("webext_licensed")
        eps = routes._supabase_edge_routes(c)
        paths = {(e["method"], e["path"]) for e in eps}
        self.assertIn(("POST", "/functions/v1/get-insights"), paths)

    def test_shared_helpers_are_not_routes(self):
        c = tmp_ctx({
            "supabase/functions/_shared/util.ts": "export const x = 1;\n",
            "supabase/functions/do-thing/index.ts": 'Deno.serve(async (req) => new Response("ok"));\n',
        })
        paths = {e["path"] for e in routes._supabase_edge_routes(c)}
        self.assertIn("/functions/v1/do-thing", paths)
        self.assertNotIn("/functions/v1/_shared", paths)

    def test_deno_serve_counts_as_a_handler_signal(self):
        self.assertTrue(routes.HANDLER_SIG.search("Deno.serve(async (req) => {}"))


class SchemaOwnershipTests(unittest.TestCase):
    def test_sql_table_and_license_hash_field(self):
        s = SchemasExtractor().extract(ctx("webext_licensed"), {})
        self.assertIn("alert_configs", [e["name"] for e in s["entities"]])
        self.assertIn("license_hash", s["sensitive_fields"])


class OwnershipTenantTests(unittest.TestCase):
    def test_license_key_is_a_tenant_candidate(self):
        t = TenantExtractor().extract(ctx("webext_licensed"), {"routes": {"endpoints": [{}]}})
        keys = [c["key"] for c in t["candidates"]]
        self.assertTrue(any(k in keys for k in ("licenseKey", "license_key", "licenseHash", "license_hash")))


class EntitlementVerificationTests(unittest.TestCase):
    def _findings(self, c):
        return IntegrationsExtractor().extract(c, {"routes": {"endpoints": []}})

    def test_gumroad_provider_detected_via_raw_fetch(self):
        out = self._findings(ctx("webext_licensed"))
        self.assertIn("Gumroad", out["third_party_integrations"])

    def test_revocation_bypass_flagged_high_confidence(self):
        out = self._findings(ctx("webext_licensed"))
        rev = [f for f in out["findings"] if f["attack_class"] == "entitlement-revocation-bypass"]
        self.assertTrue(rev)
        self.assertEqual(rev[0]["confidence"], "HIGH")     # user-chosen: #2 is a concrete dataflow tell
        self.assertEqual(rev[0]["severity"], "HIGH")

    def test_missing_usage_cap_flagged_as_lead(self):
        out = self._findings(ctx("webext_licensed"))
        cap = [f for f in out["findings"] if f["attack_class"] == "missing-usage-cap"]
        self.assertTrue(cap)
        self.assertEqual(cap[0]["confidence"], "LOW")

    def test_revocation_check_present_suppresses_finding(self):
        # the disclosure's FIX: inspect purchase.refunded/chargebacked/disputed before granting.
        fixed = tmp_ctx({"supabase/functions/get/index.ts": (
            'const GUMROAD_VERIFY_URL="https://api.gumroad.com/v2/licenses/verify";\n'
            'Deno.serve(async (req) => {\n'
            '  const { licenseKey } = await req.json();\n'
            '  const r = await (await fetch(GUMROAD_VERIFY_URL)).json();\n'
            '  const p = r.purchase || {};\n'
            '  if (r.success && !p.refunded && !p.chargebacked && !p.disputed) return new Response("ok");\n'
            '  return new Response("no", { status: 403 });\n'
            '});\n')})
        out = self._findings(fixed)
        self.assertFalse([f for f in out["findings"] if f["attack_class"] == "entitlement-revocation-bypass"])

    def test_seat_cap_present_suppresses_usage_cap_finding(self):
        # a claimSeat()/license_seats cap means #1 should NOT fire.
        capped = tmp_ctx({"supabase/functions/get/index.ts": (
            'const GUMROAD_VERIFY_URL="https://api.gumroad.com/v2/licenses/verify";\n'
            'Deno.serve(async (req) => {\n'
            '  const { licenseKey } = await req.json();\n'
            '  const r = await (await fetch(GUMROAD_VERIFY_URL)).json();\n'
            '  const p = r.purchase || {};\n'
            '  if (!r.success || p.refunded) return new Response("no",{status:403});\n'
            '  if (!(await claimSeat(licenseKey))) return new Response("seat",{status:403}); // MAX_SEATS\n'
            '  return new Response("ok");\n'
            '});\n')})
        out = self._findings(capped)
        self.assertFalse([f for f in out["findings"] if f["attack_class"] == "missing-usage-cap"])

    def test_prose_comment_does_not_suppress(self):
        # a comment "no revocation check" must NOT read as a real check (comment-suppression FN trap).
        c = tmp_ctx({"api/get.ts": (
            'export default async function handler(req) {\n'
            '  const r = await (await fetch("https://api.gumroad.com/v2/licenses/verify")).json();\n'
            '  // NOTE: no revocation check here, no seat cap either\n'
            '  if (r.success) return ok();\n'
            '}\n')})
        out = self._findings(c)
        self.assertTrue([f for f in out["findings"] if f["attack_class"] == "entitlement-revocation-bypass"])


class WebExtClientTrustTests(unittest.TestCase):
    def test_client_side_entitlement_gate_flagged(self):
        w = WebExtExtractor().extract(ctx("webext_licensed"), {})
        self.assertTrue(w["is_extension"])
        gates = w["client_entitlement_gates"]
        self.assertTrue(any("background.js" in g or "popup.js" in g for g in gates))
        self.assertTrue([f for f in w["findings"] if f["attack_class"] == "client-side-entitlement"])

    def test_excessive_host_permissions_flagged(self):
        w = WebExtExtractor().extract(ctx("webext_licensed"), {})
        self.assertTrue([f for f in w["findings"] if f["attack_class"] == "excessive-permissions"])

    def test_main_world_content_script_flagged(self):
        w = WebExtExtractor().extract(ctx("webext_licensed"), {})
        self.assertTrue(w["main_world_content_script"])
        self.assertTrue([f for f in w["findings"] if f["attack_class"] == "extension-message-trust"])

    def test_scoped_permissions_do_not_false_fire(self):
        scoped = tmp_ctx({"manifest.json": (
            '{ "manifest_version": 3, "name": "x", "version": "1",'
            ' "host_permissions": ["https://api.example.com/*"],'
            ' "content_scripts": [{"matches": ["https://example.com/*"], "js": ["c.js"]}] }'),
            "bg.js": 'chrome.storage.local.get("x");\n'})
        w = WebExtExtractor().extract(scoped, {})
        self.assertTrue(w["is_extension"])
        self.assertFalse([f for f in w["findings"] if f["attack_class"] == "excessive-permissions"])
        self.assertFalse(w["main_world_content_script"])


def _handler(body: str) -> str:
    return "export default async function handler(req) {\n" + body + "\n}\n"


class ProviderAgnosticTests(unittest.TestCase):
    """Proof the detectors key on GENERIC concepts, not one provider's field spellings or one app's
    fix-code identifiers (claimSeat / MAX_SEATS / purchase.refunded)."""

    def _has(self, files, cls):
        out = IntegrationsExtractor().extract(tmp_ctx(files), {"routes": {"endpoints": []}})
        return [f for f in out["findings"] if f["attack_class"] == cls]

    # --- #2 fires across different providers (host-driven, not license-word-driven) ---
    def test_revocation_bypass_fires_for_stripe(self):
        c = {"api/pay.ts": _handler(
            'const r = await (await fetch("https://api.stripe.com/v1/subscriptions/sub")).json();\n'
            'if (r.success) return grant();')}
        self.assertTrue(self._has(c, "entitlement-revocation-bypass"))

    def test_revocation_bypass_fires_for_lemonsqueezy(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.lemonsqueezy.com/v1/licenses/validate")).json();\n'
            'if (r.valid) return grant();')}
        self.assertTrue(self._has(c, "entitlement-revocation-bypass"))

    # --- #2 SUPPRESSED by a revocation check written in ANY provider's vocabulary ---
    def test_stripe_status_check_suppresses(self):
        c = {"api/pay.ts": _handler(
            'const r = await (await fetch("https://api.stripe.com/v1/subscriptions/sub")).json();\n'
            'if (r.success && r.subscription.status === "active") return grant();')}
        self.assertFalse(self._has(c, "entitlement-revocation-bypass"))

    def test_lemonsqueezy_cancel_and_expiry_check_suppresses(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.lemonsqueezy.com/v1/licenses/validate")).json();\n'
            'if (r.valid && !r.cancelled && r.ends_at > Date.now()) return grant();')}
        self.assertFalse(self._has(c, "entitlement-revocation-bypass"))

    def test_keygen_suspended_check_suppresses(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.keygen.sh/v1/licenses/actions/validate")).json();\n'
            'if (r.meta.valid && r.data.attributes.status !== "SUSPENDED") return grant();')}
        self.assertFalse(self._has(c, "entitlement-revocation-bypass"))

    # --- #1 SUPPRESSED by a usage cap named ANY way (not just claimSeat / MAX_SEATS) ---
    def test_device_count_cap_suppresses(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.stripe.com/v1/subscriptions/s")).json();\n'
            'if (activeDevices >= maxDevices) return deny();\n'
            'if (r.success && r.subscription.status === "active") return grant();')}
        self.assertFalse(self._has(c, "missing-usage-cap"))

    def test_seats_table_cap_suppresses(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.gumroad.com/v2/licenses/verify")).json();\n'
            'const rows = await db.from("license_seats").select("*");\n'
            'if (r.success && !r.purchase.refunded) return grant();')}
        self.assertFalse(self._has(c, "missing-usage-cap"))

    def test_usage_quota_cap_suppresses(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.lemonsqueezy.com/v1/licenses/validate")).json();\n'
            'if (usageQuota <= usesRemaining) return deny();\n'
            'if (r.valid && !r.cancelled) return grant();')}
        self.assertFalse(self._has(c, "missing-usage-cap"))

    def test_no_cap_still_fires_regardless_of_provider(self):
        c = {"api/lic.ts": _handler(
            'const r = await (await fetch("https://api.paddle.com/2.0/licenses/validate")).json();\n'
            'if (r.success && r.subscription.status === "active") return grant();')}  # revocation ok, but no cap
        self.assertTrue(self._has(c, "missing-usage-cap"))


class SupabaseKeyTierTests(unittest.TestCase):
    """A Supabase anon/publishable key is intended-public (RLS-protected); a service_role key is a
    real leak. The generic secret scanners flag both as a JWT — the ledger must tell them apart."""

    def _cx(self, files):
        return ClientExposureExtractor().extract(tmp_ctx(files), {})

    def test_anon_key_is_intended_public_not_a_value_leak(self):
        cx = self._cx({"extension/bg.js": f'const KEY = "{_sb_jwt("anon")}";\n'})
        self.assertTrue(cx["intended_public_supabase"])
        self.assertFalse(cx["supabase_service_role_in_client"])
        self.assertFalse([l for l in cx["public_secret_value_leaks"] if l.startswith("JWT")])

    def test_service_role_key_is_flagged(self):
        cx = self._cx({"extension/bg.js": f'const KEY = "{_sb_jwt("service_role")}";\n'})
        self.assertTrue(cx["supabase_service_role_in_client"])

    def test_new_publishable_and_secret_prefixes(self):
        cx = self._cx({"a.ts": 'const k = "sb_publishable_abcdefghij1234567890";\n'
                               'const s = "sb_secret_abcdefghij1234567890";\n'})
        self.assertTrue(cx["intended_public_supabase"])
        self.assertTrue(cx["supabase_service_role_in_client"])

    def test_scanner_jwt_finding_on_anon_key_downgraded_to_info(self):
        facts = {"client_exposure": {"intended_public_supabase": ["ext/bg.js"],
                                     "supabase_service_role_in_client": []},
                 "stack": {"datastores": []}}
        unified = {"all": [{"category": "secret", "title": "Uncovered a JSON Web Token",
                            "file": "ext/bg.js", "severity": "HIGH", "tools": ["gitleaks"]}]}
        led = findings.build_ledger(facts, unified, None, [])
        jwt = [f for f in led["findings"] if "web token" in f["title"].lower()]
        self.assertTrue(jwt)
        self.assertEqual(jwt[0]["severity"], "INFO")

    def test_service_role_reaches_ledger_as_critical(self):
        facts = {"client_exposure": {"intended_public_supabase": [],
                                     "supabase_service_role_in_client": ["api/db.ts"]},
                 "stack": {"datastores": []}}
        led = findings.build_ledger(facts, None, None, [])
        svc = [f for f in led["findings"] if "service_role" in f["title"].lower()]
        self.assertTrue(svc)
        self.assertEqual(svc[0]["severity"], "CRITICAL")

    def test_arbitrary_jwt_not_downgraded(self):
        # a non-Supabase JWT (no supabase iss / role) is NOT reclassified as intended-public
        import base64
        import json
        b64 = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()
        tok = f"{b64({'alg': 'HS256'})}.{b64({'sub': 'user', 'name': 'x'})}.{'s' * 20}"
        cx = self._cx({"api/x.ts": f'const t = "{tok}"; // use client\n'})
        self.assertFalse(cx["intended_public_supabase"])


class LedgerAndProbeWiringTests(unittest.TestCase):
    def test_new_classes_resolve_real_standards(self):
        for cls in ("entitlement-revocation-bypass", "missing-usage-cap", "client-side-entitlement",
                    "excessive-permissions", "extension-message-trust"):
            self.assertIn(cls, findings.STANDARDS, f"{cls} missing a CWE/OWASP citation")
            self.assertIn(cls, findings.REMEDIATION, f"{cls} missing a remediation")
            cwes = findings.STANDARDS[cls][0]
            self.assertTrue(cwes and cwes[0].startswith("CWE-"))

    def test_entitlement_findings_reach_the_ledger(self):
        from websec_validator import recon
        f = recon.build_facts(FIX / "webext_licensed", "test")
        led = findings.build_ledger(f, None, None, [])
        classes = {x["attack_class"] for x in led["findings"]}
        self.assertIn("entitlement-revocation-bypass", classes)
        self.assertIn("client-side-entitlement", classes)

    def test_entitlement_probe_staged_when_findings_present(self):
        facts = {"integrations": {"findings": [{"attack_class": "entitlement-revocation-bypass"}]}}
        self.assertIn("entitlement-abuse", probes.applicable(facts))


# ---------------------------------------------------------------------------------------------------
class MissingRlsTests(unittest.TestCase):
    """P0 — no-Row-Level-Security-at-all (the Lovable / CVE-2025-48757 class). Owner-scoped tables in
    committed SQL with ZERO RLS artifacts anywhere. Distinct attack_class 'missing-rls' (never reuses
    'rls-context', which is the set_config-timing bug). Heavy FP guards: owner-column gate, cross-file
    corpus aggregation, postgres/supabase stack gate, truncation guard, dashboard caveat + MEDIUM/LOW."""

    def _classes(self, fixture):
        from websec_validator import recon
        f = recon.build_facts(FIX / fixture, "test")
        return f, findings.build_ledger(f, None, None, [])

    def _synthetic(self, *, truncated=False, datastores=None, frameworks=None,
                   owner_tables=True, policy=0, enabled=0, anon=False):
        return {
            "files_truncated": truncated,
            "stack": {"datastores": datastores if datastores is not None else ["postgres"],
                      "frameworks": frameworks if frameworks is not None else ["supabase"]},
            "schemas": {"sql_ddl_present": True,
                        "owner_scoped_tables": ([{"name": "orders", "file": "s.sql", "columns": ["user_id"]}]
                                                if owner_tables else []),
                        "rls_policy_count": policy, "rls_enabled_count": enabled},
            "client_exposure": {"intended_public_supabase": ["src/db.ts"] if anon else []},
        }

    def test_schemas_fact_shape(self):
        f = SchemasExtractor().extract(ctx("rls_missing"), {})
        self.assertTrue(f["sql_ddl_present"])
        self.assertEqual(f["rls_policy_count"], 0)
        self.assertEqual(f["rls_enabled_count"], 0)
        self.assertEqual({t["name"] for t in f["owner_scoped_tables"]}, {"profiles", "documents"})

    def test_fires_on_owner_scoped_table_without_policy(self):
        _f, led = self._classes("rls_missing")
        mr = [x for x in led["findings"] if x["attack_class"] == "missing-rls"]
        self.assertTrue(mr, "expected a missing-rls finding on the no-RLS fixture")
        self.assertEqual((mr[0]["severity"], mr[0]["confidence"]), ("MEDIUM", "LOW"))  # no committed anon key

    def test_present_in_separate_migration_suppresses(self):
        _f, led = self._classes("rls_present")
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_global_lookup_tables_do_not_fire(self):
        f = SchemasExtractor().extract(ctx("rls_global_only"), {})
        self.assertEqual(f["owner_scoped_tables"], [])
        _f, led = self._classes("rls_global_only")
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_webext_licensed_fixture_still_clean(self):
        # its shipped supabase/schema.sql HAS enable-RLS + create-policy → must not regress to a finding
        _f, led = self._classes("webext_licensed")
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_mysql_stack_does_not_fire(self):
        led = findings.build_ledger(self._synthetic(datastores=["mysql"], frameworks=[]), None, None, [])
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_truncated_scan_suppresses(self):
        led = findings.build_ledger(self._synthetic(truncated=True), None, None, [])
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_anon_key_present_escalates_to_high(self):
        led = findings.build_ledger(self._synthetic(anon=True), None, None, [])
        mr = [x for x in led["findings"] if x["attack_class"] == "missing-rls"]
        self.assertTrue(mr)
        self.assertEqual((mr[0]["severity"], mr[0]["confidence"]), ("HIGH", "MEDIUM"))

    def test_any_rls_token_in_corpus_suppresses(self):
        # a single ENABLE ROW LEVEL SECURITY anywhere (enabled=1) flips the finding off — conservative.
        led = findings.build_ledger(self._synthetic(enabled=1), None, None, [])
        self.assertNotIn("missing-rls", [x["attack_class"] for x in led["findings"]])

    def test_standards_and_remediation_distinct_from_rls_context(self):
        self.assertIn("missing-rls", findings.STANDARDS)
        self.assertIn("missing-rls", findings.REMEDIATION)
        self.assertNotEqual(findings.REMEDIATION["missing-rls"], findings.REMEDIATION["rls-context"])


if __name__ == "__main__":
    unittest.main()
