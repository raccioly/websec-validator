"""PII projections that demonstrably REMOVE the field are not raw-entity exposures (#142).

The original PR asserted only that the false positive was gone. On a PII detector the other
direction is the whole point: an over-broad projection rule turns a leak into silence. Every
suppression below is paired with the near-miss where PII survives the projection and must still
be reported.

@req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-007
"""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.pii_exposure import PiiExposureExtractor

FETCH = "const customer=await db.customer.findById(req.params.id).select('email phone ssn');"


class PiiProjectionTests(unittest.TestCase):
    def pii(self, middle="", sent="customer"):
        source = "app.get('/c/:id',async(req,res)=>{" + FETCH + middle + "res.json(" + sent + ");});"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "a").mkdir()
            (root / "a" / "app.js").write_text(source)
            facts = {"stack": {"frameworks": ["express"],
                               "service_inventory": [{"id": "a", "root": "a"}]},
                     "routes": {"endpoints": [{"method": "GET", "path": "/c/:id",
                                               "code_path": "a/app.js"}]},
                     "auth": {}}
            out = PiiExposureExtractor().extract(RepoContext(root), facts)
        return [f for f in out["findings"] if f["kind"] == "raw-entity-pii-response"]

    def test_the_harness_reports_a_raw_entity(self):
        """Guards every assertion below: a silent harness would make them all vacuous."""
        self.assertTrue(self.pii(), "the unprojected entity must fire, or these tests prove nothing")

    def test_destructuring_rest_that_drops_pii_is_a_projection(self):
        self.assertEqual(self.pii("const {email,phone,ssn,...safe}=customer;", "safe"), [])

    def test_omit_of_pii_fields_is_a_projection(self):
        for call in ("omit(customer,['email','phone','ssn'])", "_.omit(customer,['email','ssn'])"):
            with self.subTest(call=call):
                self.assertEqual(self.pii(f"const safe={call};", "safe"), [])

    def test_pick_of_only_non_pii_fields_is_a_projection(self):
        for call in ("pick(customer,['id','name'])", "_.pick(customer,['id','createdAt'])"):
            with self.subTest(call=call):
                self.assertEqual(self.pii(f"const safe={call};", "safe"), [])

    # --- the near misses: PII survives, so the finding must survive --------------------------
    def test_pick_that_KEEPS_a_pii_field_still_reports(self):
        self.assertTrue(self.pii("const safe=pick(customer,['id','email']);", "safe"),
                        "email survived the projection — suppressing this hides a real leak")

    def test_omit_that_removes_only_NON_pii_still_reports(self):
        self.assertTrue(self.pii("const safe=omit(customer,['createdAt']);", "safe"))

    def test_destructuring_rest_that_drops_nothing_sensitive_still_reports(self):
        self.assertTrue(self.pii("const {createdAt,...safe}=customer;", "safe"))

    def test_a_projection_bound_to_a_DIFFERENT_name_does_not_clear_the_entity(self):
        """Projecting into `safe` does not make sending `customer` acceptable."""
        self.assertTrue(self.pii("const safe=pick(customer,['id']);", "customer"))


if __name__ == "__main__":
    unittest.main()
