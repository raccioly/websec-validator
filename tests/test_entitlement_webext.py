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

FIX = Path(__file__).resolve().parent / "fixtures"


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


if __name__ == "__main__":
    unittest.main()
