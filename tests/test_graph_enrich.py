"""Tests for optional graphify blast-radius enrichment.

Unit-tests the location→node mapping and reverse-reachability radius on synthetic graphs, then an
integration test drives `websec run` with a graphify-out/graph.json dropped next to a fixture app.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import graph_enrich              # noqa: E402
from websec_validator.cli import main                  # noqa: E402


def _graph(nodes, links, commit="deadbeef"):
    return {"directed": True, "multigraph": False, "graph": {},
            "nodes": nodes, "links": links, "built_at_commit": commit}


class LocationParseTests(unittest.TestCase):
    def test_strips_line_suffix(self):
        self.assertEqual(graph_enrich._location_file("src/a.js:42"), "src/a.js")
        self.assertEqual(graph_enrich._location_file("src/a.js:L42"), "src/a.js")
        self.assertEqual(graph_enrich._location_file("./src/a.js"), "src/a.js")
        self.assertEqual(graph_enrich._location_file("src/a.js"), "src/a.js")

    def test_keeps_windows_drive(self):
        # A colon after a letter (drive) is not a line ref; only a trailing :<digits> is stripped.
        self.assertEqual(graph_enrich._location_file("a.js:abc"), "a.js:abc")


class EnrichTests(unittest.TestCase):
    def _ledger(self, *locations):
        return {"findings": [{"title": "t", "location": loc, "severity": "HIGH"} for loc in locations],
                "total": len(locations)}

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.target = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_graph(self, graph):
        gp = self.target / "graphify-out" / "graph.json"
        gp.parent.mkdir(parents=True, exist_ok=True)
        gp.write_text(json.dumps(graph))
        return gp

    def test_no_graph_is_noop(self):
        ledger = self._ledger("src/a.js")
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertNotIn("graph_enrichment", out)
        self.assertNotIn("graph", out["findings"][0])

    def test_blast_radius_counts_dependents(self):
        # helper.js is imported by a.js and b.js; a.js is also imported by c.js.
        nodes = [
            {"id": "helper", "label": "helper.js", "source_file": "src/helper.js", "community": 1},
            {"id": "a", "label": "a.js", "source_file": "src/a.js", "community": 1},
            {"id": "b", "label": "b.js", "source_file": "src/b.js", "community": 2},
            {"id": "c", "label": "c.js", "source_file": "src/c.js", "community": 2},
        ]
        links = [
            {"source": "a", "target": "helper", "relation": "imports"},
            {"source": "b", "target": "helper", "relation": "imports"},
            {"source": "c", "target": "a", "relation": "imports"},
        ]
        self._write_graph(_graph(nodes, links))
        ledger = self._ledger("src/helper.js:10")
        out = graph_enrich.enrich_ledger(ledger, self.target)
        g = out["findings"][0]["graph"]
        # a, b (direct) + c (transitive via a) all depend on helper.
        self.assertEqual(g["blast_radius"], 3)
        self.assertEqual(out["graph_enrichment"]["mapped"], 1)
        self.assertEqual(out["graph_enrichment"]["max_blast_radius"], 3)

    def test_leaf_has_zero_radius(self):
        nodes = [
            {"id": "helper", "label": "helper.js", "source_file": "src/helper.js"},
            {"id": "a", "label": "a.js", "source_file": "src/a.js"},
        ]
        links = [{"source": "a", "target": "helper", "relation": "imports"}]
        self._write_graph(_graph(nodes, links))
        ledger = self._ledger("src/a.js")   # nobody imports a.js
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertEqual(out["findings"][0]["graph"]["blast_radius"], 0)

    def test_unmapped_finding_gets_no_graph_block(self):
        nodes = [{"id": "a", "label": "a.js", "source_file": "src/a.js"}]
        self._write_graph(_graph(nodes, []))
        ledger = self._ledger("src/a.js", "src/ghost.js")
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertIn("graph", out["findings"][0])
        self.assertNotIn("graph", out["findings"][1])
        self.assertEqual(out["graph_enrichment"]["unmapped"], 1)

    def test_non_dependency_edges_ignored(self):
        # a `contains` edge is structural, not a dependency — must not count toward blast radius.
        nodes = [
            {"id": "helper", "label": "helper.js", "source_file": "src/helper.js"},
            {"id": "a", "label": "a.js", "source_file": "src/a.js"},
        ]
        links = [{"source": "a", "target": "helper", "relation": "contains"}]
        self._write_graph(_graph(nodes, links))
        ledger = self._ledger("src/helper.js")
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertEqual(out["findings"][0]["graph"]["blast_radius"], 0)

    def test_malformed_graph_is_noop(self):
        gp = self.target / "graphify-out" / "graph.json"
        gp.parent.mkdir(parents=True, exist_ok=True)
        gp.write_text("{ this is not json")
        ledger = self._ledger("src/a.js")
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertNotIn("graph_enrichment", out)

    def test_suffix_match_when_paths_anchored_differently(self):
        nodes = [{"id": "h", "label": "helper.js", "source_file": "pkg/src/helper.js"},
                 {"id": "a", "label": "a.js", "source_file": "pkg/src/a.js"}]
        links = [{"source": "a", "target": "h", "relation": "imports"}]
        self._write_graph(_graph(nodes, links))
        ledger = self._ledger("src/helper.js")   # finding path lacks the pkg/ prefix
        out = graph_enrich.enrich_ledger(ledger, self.target)
        self.assertEqual(out["findings"][0]["graph"]["blast_radius"], 1)


class SurfacingTests(unittest.TestCase):
    """Blast radius must be visible in the artifacts consumers actually read: SARIF, REPORT, briefing."""

    def _enriched_ledger(self):
        from websec_validator import baseline
        ledger = {
            "schema_version": "1.0",
            "findings": [{
                "title": "SQLi sink", "category": "sink", "attack_class": "sqli",
                "severity": "HIGH", "confidence": "MEDIUM", "location": "src/db.js",
                "evidence": [{"layer": "recon"}],
                "standards": {"cwe": ["CWE-89"], "asvs": [], "owasp_api": []},
                "remediation": "parameterize", "status": "open",
                "graph": {"nodes": ["db"], "blast_radius": 12,
                          "dependents": ["a.js", "b.js", "c.js"], "community": 1, "truncated": False},
            }],
            "total": 1, "by_severity": {"HIGH": 1}, "by_confidence": {"MEDIUM": 1},
            "graph_enrichment": {"graph": "graphify-out/graph.json", "nodes": 50,
                                 "mapped": 1, "unmapped": 0, "max_blast_radius": 12},
        }
        baseline.annotate(ledger)
        return ledger

    def test_sarif_carries_blast_radius(self):
        from websec_validator import formats
        sarif = formats.to_sarif(self._enriched_ledger(), {"target": "x"}, "1.0")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["blastRadius"], 12)
        self.assertIn("Blast radius: 12", result["message"]["text"])

    def test_report_shows_blast_radius(self):
        from websec_validator import report
        md = report.render({"target": "x", "stack": {}}, {"available": [], "missing": []}, [],
                           None, [], "ts", self._enriched_ledger())
        self.assertIn("blast radius", md.lower())
        self.assertIn("12", md)

    def test_briefing_shows_blast_radius_section(self):
        from websec_validator import briefing
        md = briefing.render({"target": "x", "stack": {}}, {"available": [], "missing": []}, [], [],
                            None, self._enriched_ledger())
        self.assertIn("Blast radius", md)
        self.assertIn("src/db.js", md)

    def test_briefing_omits_section_without_enrichment(self):
        from websec_validator import briefing
        md = briefing.render({"target": "x", "stack": {}}, {"available": [], "missing": []}, [], [], None, None)
        self.assertNotIn("3d.", md)


class IntegrationTests(unittest.TestCase):
    def test_websec_run_enriches_when_graph_present(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td)
            (target / "app.py").write_text("import os\n")
            gp = target / "graphify-out" / "graph.json"
            gp.parent.mkdir(parents=True, exist_ok=True)
            gp.write_text(json.dumps(_graph(
                [{"id": "app", "label": "app.py", "source_file": "app.py"}], [])))
            out = target / "out"
            rc = main(["run", str(target), "--out", str(out), "--format", "json"])
            self.assertEqual(rc, 0)
            ledger = json.loads((out / "latest" / "findings-ledger.json").read_text())
            self.assertIn("graph_enrichment", ledger)
            self.assertEqual(ledger["graph_enrichment"]["nodes"], 1)


if __name__ == "__main__":
    unittest.main()
