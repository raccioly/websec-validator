"""The claimspec `calibration` writer: websec's internal table rendered as the Guard-family shared
format, without changing the internal shape or the runtime cascade.

Two layers. The structural tests run everywhere and pin the field mapping, the provenance kinds and
the arithmetic. The round-trip test hands the emitted documents to the spec's own Node validator
(testguard `spec/lib/validate.mjs`), which recomputes every `p`/`ci`; it is skipped — never silently
passed — when `node`, a testguard checkout, or a schema that knows the calibration format is absent.
Point `WEBSEC_CLAIMSPEC_SPEC_DIR` at a testguard `spec/` directory to run it against a specific one;
otherwise the sibling checkout `../testguard/spec` is tried.
"""
import contextlib
import copy
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import calibration, cli  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
SHIPPED = json.loads((REPO / 'src' / 'websec_validator' / 'calibration.json').read_text())
STAMP = '2026-09-18T00:00:00Z'
ISO = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$')
KEY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]*(\|[A-Za-z0-9][A-Za-z0-9._-]*)*$')
LOCAL = {'schema_version': 2, 'meta': {'source': 'local evidence overlay', 'samples': 7, 'runs': 3},
         'by_class_label': {'bola|MEDIUM': {'n': 6, 'k': 5}, 'missing-auth|MEDIUM': {'n': 1, 'k': 0}},
         'by_label': {'MEDIUM': {'n': 7, 'k': 5}}, 'observations': {}}

# The runner is written to a temp dir at test time; `ajv` resolves from the validator's own location.
RUNNER = '''
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const [specDir, file] = process.argv.slice(2);
let validate;
try { ({ validate } = await import(pathToFileURL(specDir + '/lib/validate.mjs').href)); }
catch (e) { console.error(String(e)); process.exit(3); }
try {
  const r = validate('calibration', JSON.parse(readFileSync(file, 'utf8')));
  console.log(JSON.stringify(r));
  process.exit(r.ok ? 0 : 1);
} catch (e) { console.error(String(e)); process.exit(4); }
'''


def shapes():
    """The four tables a consumer can meet: raw shipped, what `load()` returns today (the shipped
    table is quarantined), an operator's overlay with no shipped table, and the two merged."""
    return {
        'shipped': calibration.to_claimspec(copy.deepcopy(SHIPPED), computed_at=STAMP),
        'runtime': calibration.to_claimspec(calibration.load(), computed_at=STAMP),
        'local-only': calibration.to_claimspec(calibration._merge(None, copy.deepcopy(LOCAL)), computed_at=STAMP),
        'merged': calibration.to_claimspec(calibration._merge(copy.deepcopy(SHIPPED), copy.deepcopy(LOCAL)), computed_at=STAMP),
    }


def _load_as_shipped(table):
    """Run calibration.load_shipped() against `table` instead of the packaged file."""
    import unittest.mock
    from importlib import resources
    payload = json.dumps(table)

    class _Res:
        def read_text(self, *a, **k):
            return payload

    class _Files:
        def joinpath(self, *a):
            return _Res()

    with unittest.mock.patch.object(resources, "files", lambda *a, **k: _Files()):
        return calibration.load_shipped()


class ClaimspecWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # no operator overlay unless a test writes one
        p = patch.object(calibration, 'LOCAL_PATH', self.root / 'calibration-local.json'); p.start(); self.addCleanup(p.stop)

    def test_shipped_table_maps_field_for_field(self):
        doc = calibration.to_claimspec(copy.deepcopy(SHIPPED), computed_at=STAMP)
        self.assertEqual(doc['schemaVersion'], 1)
        self.assertEqual(doc['tool']['name'], 'websec-validator'); self.assertTrue(doc['tool']['version'])
        self.assertEqual((doc['method'], doc['confidence'], doc['measures']), ('wilson', 0.95, 'finding-real'))
        self.assertEqual(doc['bucketBy'], 'attackClass|confidence'); self.assertEqual(doc['minN'], SHIPPED['meta']['min_n'])
        src = doc['source']
        self.assertEqual(src['kind'], 'human-label'); self.assertEqual(src['evidenceStatus'], 'verified')
        self.assertEqual(src['corpus'], SHIPPED['meta']['corpus'])
        self.assertEqual(src['caveat'], SHIPPED['meta']['caveat']); self.assertEqual(src['limitation'], SHIPPED['meta']['limitation'])
        for key in ('n_total', 'unmatched_rule', 'researched_classes'):
            self.assertEqual(src['detail'][key], SHIPPED['meta'][key])
        self.assertEqual(set(doc['buckets']), set(SHIPPED['by_class_label']))
        for key, cell in SHIPPED['by_class_label'].items():
            self.assertEqual(doc['buckets'][key], {'n': cell['n'], 'positives': cell['k'], 'p': cell['p'], 'ci': cell['ci']})
        self.assertEqual(doc['backoff'][0]['bucketBy'], 'confidence')
        self.assertEqual(set(doc['backoff'][0]['buckets']), set(SHIPPED['by_label']))
        self.assertEqual(doc['fallback'], {'basis': 'uncalibrated-prior', 'values': SHIPPED['prior']})
        self.assertEqual(doc['computedAt'], STAMP)

    def test_every_cell_reproduces_from_its_counts_with_either_z(self):
        for name, doc in shapes().items():
            tiers = [(doc['bucketBy'], doc['buckets'])] + [(t['bucketBy'], t['buckets']) for t in doc['backoff']]
            for by, buckets in tiers:
                arity = by.count('|') + 1
                for key, cell in buckets.items():
                    with self.subTest(shape=name, key=key):
                        self.assertRegex(key, KEY); self.assertEqual(key.count('|') + 1, arity)
                        self.assertLessEqual(cell['positives'], cell['n'])
                        n, k = cell['n'], cell['positives']
                        self.assertEqual(cell['p'], round(k / n, 3) if n else None)
                        candidates = [[round(v, 3) for v in calibration.wilson(k, n, z)] for z in (calibration.Z95, 1.96)]
                        self.assertIn(cell['ci'], candidates)
                        if n:
                            self.assertTrue(cell['ci'][0] <= cell['p'] <= cell['ci'][1])

    def test_runtime_table_exports_the_reviewed_corpus_measurements(self):
        """The corpus was relabelled on 2026-09-22, so the runtime table carries real cells."""
        doc = calibration.to_claimspec(calibration.load(), computed_at=STAMP)
        self.assertEqual(doc['source']['evidenceStatus'], 'verified')
        self.assertEqual(doc['source']['kind'], 'human-label')
        self.assertTrue(doc['buckets']); self.assertTrue(doc['backoff'][0]['buckets'])
        self.assertEqual(doc['source']['corpus'], SHIPPED['meta']['corpus'])
        self.assertEqual(doc['fallback']['values'], calibration.PRIOR)

    def test_a_historical_table_is_still_quarantined_with_empty_buckets(self):
        """The mechanism that withdrew the old labels must survive the relabel.

        Exercised against a synthetic historical table, so this stays a test of the QUARANTINE RULE
        rather than a snapshot of whatever the corpus currently says.
        """
        historical = copy.deepcopy(SHIPPED)
        historical['meta']['evidence_status'] = 'historical-unverified'
        quarantined = calibration._merge(_load_as_shipped(historical), None)
        doc = calibration.to_claimspec(quarantined, computed_at=STAMP)
        self.assertEqual(doc['source']['evidenceStatus'], 'quarantined')
        self.assertEqual(doc['buckets'], {}); self.assertEqual(doc['backoff'][0]['buckets'], {})
        self.assertIn('retained for audit', doc['source']['caveat'])
        self.assertGreater(doc['source']['detail']['historical_uncertain_samples'], 0)
        self.assertEqual(doc['fallback']['values'], calibration.PRIOR)

    def test_local_only_overlay_is_a_tool_oracle_without_corpus_provenance(self):
        doc = calibration.to_claimspec(calibration._merge(None, copy.deepcopy(LOCAL)), computed_at=STAMP)
        self.assertEqual(doc['source']['kind'], 'tool-oracle'); self.assertEqual(doc['source']['evidenceStatus'], 'verified')
        self.assertTrue(doc['source']['caveat'].startswith(calibration.LOCAL_ONLY_CAVEAT))
        self.assertNotIn('corpus', doc['source']); self.assertNotIn('limitation', doc['source'])
        self.assertIs(doc['source']['detail']['shipped_table'], False); self.assertEqual(doc['source']['detail']['local_samples'], 7)
        self.assertEqual(doc['buckets']['bola|MEDIUM'], {'n': 6, 'positives': 5, 'p': 0.833, 'ci': [round(v, 3) for v in calibration.wilson(5, 6)]})

    def test_merged_table_is_mixed_and_carries_summed_counts(self):
        doc = calibration.to_claimspec(calibration._merge(copy.deepcopy(SHIPPED), copy.deepcopy(LOCAL)), computed_at=STAMP)
        self.assertEqual(doc['source']['kind'], 'mixed'); self.assertEqual(doc['source']['evidenceStatus'], 'verified')
        base = SHIPPED['by_class_label']['missing-auth|MEDIUM']
        cell = doc['buckets']['missing-auth|MEDIUM']
        merged_n, merged_k = base['n'] + 1, base['k'] + 0     # LOCAL adds missing-auth 0/1
        self.assertEqual((cell['n'], cell['positives'], cell['p']),
                         (merged_n, merged_k, round(merged_k / merged_n, 3)))
        self.assertEqual(doc['backoff'][0]['buckets']['MEDIUM']['n'],
                         SHIPPED['by_label']['MEDIUM']['n'] + 7)
        self.assertIn('local sample(s) folded in', doc['source']['caveat']); self.assertEqual(doc['source']['corpus'], SHIPPED['meta']['corpus'])

    def test_zero_trial_cell_has_null_p_and_maximal_ignorance(self):
        table = {'meta': {}, 'by_class_label': {'sqli|LOW': calibration._cell(0, 0)}, 'by_label': {}, 'prior': calibration.PRIOR}
        doc = calibration.to_claimspec(table, computed_at=STAMP)
        self.assertEqual(doc['buckets']['sqli|LOW'], {'n': 0, 'positives': 0, 'p': None, 'ci': [0.0, 1.0]})
        self.assertEqual(doc['source']['caveat'], calibration.CAVEAT)  # always written, even with no meta
        self.assertNotIn('detail', doc['source'])  # nothing to say ≠ an empty object

    def test_writer_refuses_a_cell_whose_numbers_do_not_reproduce(self):
        stale = copy.deepcopy(SHIPPED)
        cell = stale['by_class_label']['missing-auth|MEDIUM']
        counts = f"{cell['k']}/{cell['n']}"          # derived, so a relabel cannot stale this test
        cell['p'] = round(cell['p'] + 0.1, 3)
        with self.assertRaisesRegex(ValueError, r"'missing-auth\|MEDIUM'.*" + re.escape(counts)):
            calibration.to_claimspec(stale, computed_at=STAMP)
        bad = copy.deepcopy(SHIPPED); bad['by_label']['LOW'] = {'n': 2, 'k': 3, 'p': 1.5, 'ci': [0.0, 1.0]}
        with self.assertRaisesRegex(ValueError, "'LOW'"):
            calibration.to_claimspec(bad, computed_at=STAMP)

    def test_default_timestamp_is_iso_utc(self):
        self.assertRegex(calibration.to_claimspec(copy.deepcopy(SHIPPED))['computedAt'], ISO)

    def test_cli_exports_the_runtime_table_to_a_file_or_stdout(self):
        out = self.root / 'nested' / 'calibration.claimspec.json'
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(['calibrate', '--claimspec', str(out)]), 0)
        self.assertIn('evidenceStatus=verified', buf.getvalue())
        doc = json.loads(out.read_text())
        self.assertEqual(doc['schemaVersion'], 1); self.assertEqual(doc['measures'], 'finding-real')
        with contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(['calibrate', '--claimspec', '-']), 0)
        self.assertEqual(json.loads(buf.getvalue())['bucketBy'], 'attackClass|confidence')

    def test_cli_reports_no_table_instead_of_inventing_one(self):
        with patch.object(calibration, 'load', return_value=None), contextlib.redirect_stdout(io.StringIO()) as buf:
            self.assertEqual(cli.main(['calibrate', '--claimspec', str(self.root / 'x.json')]), 2)
        self.assertIn('Nothing to export', buf.getvalue()); self.assertFalse((self.root / 'x.json').exists())

    def test_cli_refuses_to_export_a_non_reproducible_table(self):
        stale = copy.deepcopy(SHIPPED); stale['by_label']['LOW']['ci'] = [0.0, 0.5]
        with patch.object(calibration, 'load', return_value=stale), self.assertRaises(SystemExit) as ctx:
            cli.main(['calibrate', '--claimspec', str(self.root / 'x.json')])
        self.assertIn('non-reproducible', str(ctx.exception)); self.assertFalse((self.root / 'x.json').exists())


class ClaimspecRoundTripTests(unittest.TestCase):
    """Hand every emitted shape to the spec's own validator, which recomputes p and every ci."""

    def spec_dir(self) -> Path:
        env = os.environ.get('WEBSEC_CLAIMSPEC_SPEC_DIR')
        spec = Path(env).expanduser() if env else REPO.parent / 'testguard' / 'spec'
        schema = spec / 'schemas' / 'calibration.schema.json'
        if not shutil.which('node'):
            self.skipTest('node is not installed; the claimspec validator is a Node module')
        if not schema.is_file() or not (spec / 'lib' / 'validate.mjs').is_file():
            self.skipTest(f'no claimspec checkout at {spec} (set WEBSEC_CLAIMSPEC_SPEC_DIR)')
        if 'measures' not in json.loads(schema.read_text()).get('properties', {}):
            self.skipTest(f'claimspec checkout at {spec} predates the calibration format (testguard#95)')
        return spec

    def test_every_shape_conforms_to_the_claimspec_validator(self):
        spec = self.spec_dir()
        with tempfile.TemporaryDirectory() as td, patch.object(calibration, 'LOCAL_PATH', Path(td) / 'calibration-local.json'):
            runner = Path(td) / 'validate-calibration.mjs'; runner.write_text(RUNNER)
            for name, doc in shapes().items():
                with self.subTest(shape=name):
                    path = Path(td) / f'{name}.json'; path.write_text(json.dumps(doc, indent=2))
                    res = subprocess.run(['node', str(runner), str(spec), str(path)], capture_output=True, text=True, timeout=60)
                    if res.returncode == 3:
                        self.skipTest(f'claimspec validator could not load (npm install in testguard?): {res.stderr.strip()}')
                    self.assertEqual(res.returncode, 0, f'{name}: {res.stdout.strip() or res.stderr.strip()}')


if __name__ == '__main__':
    unittest.main()
