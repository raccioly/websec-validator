"""Retained calibration acceptance uses complete reviewed evidence and observable scores."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from websec_validator import calibration, cli


class RetainedCalibrationTests(unittest.TestCase):
    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-008
    def test_every_truth_row_in_class_must_be_explicitly_reviewed(self):
        reviewed = {'class': 'sqli', 'review_status': 'reviewed', 'is_real': True}
        self.assertEqual(calibration.reviewed_classes([{'truth': [reviewed]}]), {'sqli'})
        for pending in ({'class': 'sqli', 'review_status': 'pending', 'is_real': False},
                        {'class': 'sqli', 'review_status': 'reviewed', 'is_real': None},
                        {'class': 'sqli', 'is_real': True}):
            with self.subTest(pending=pending):
                self.assertEqual(calibration.reviewed_classes([{'truth': [reviewed]}, {'truth': [pending]}]), set())
        other = {'class': 'xss', 'review_status': 'pending', 'is_real': None}
        self.assertEqual(calibration.reviewed_classes([{'truth': [reviewed, other]}]), {'sqli'})

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-011
    def test_measured_and_synthetic_tables_report_brier_without_unknown_labels(self):
        labels = [{'attack_class': 'xss', 'confidence': 'LOW', 'is_real': True}] * 5
        labels += [{'attack_class': 'xss', 'confidence': 'LOW', 'is_real': None}]
        for table in (calibration.fit(labels, ['owned-fixture'], {'xss'}), calibration.fit_synthetic(labels)):
            self.assertEqual(table['meta']['score']['n'], 5)
            self.assertEqual(table['meta']['score']['brier'], 0.0)
            self.assertEqual(table['meta']['n_total'], 5)

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-011
    def test_accepted_feedback_persists_and_cli_reports_score(self):
        with tempfile.TemporaryDirectory() as td, patch.object(calibration, 'LOCAL_PATH', Path(td) / 'local.json'):
            from websec_validator.coverage import detector_revision
            revision = detector_revision()
            candidate = calibration.record_candidate({'verdict': 'false-positive', 'finding': {
                'attack_class': 'xss', 'confidence': 'LOW', 'fingerprint': 'owned'}}, detector_revision=revision)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = cli.main(['calibrate', '--accept', candidate['candidate_id'], '--reason', 'reviewed exact fixture'])
            self.assertEqual(code, 0)
            self.assertIn('Brier', output.getvalue())
            stored = json.loads(calibration.LOCAL_PATH.read_text())
            self.assertEqual(stored['meta']['score']['n'], 1)
            self.assertIn('strictly proper', stored['meta']['score']['rule'])

    def test_unverified_samples_cannot_create_score(self):
        with tempfile.TemporaryDirectory() as td, patch.object(calibration, 'LOCAL_PATH', Path(td) / 'local.json'):
            stored = calibration.record_samples([{'attack_class': 'xss', 'confidence': 'LOW', 'is_real': False}])
            self.assertIsNone(stored['meta'].get('score'))

    def test_explicit_evidence_ingest_cli_reports_score(self):
        with tempfile.TemporaryDirectory() as td, patch.object(calibration, 'LOCAL_PATH', Path(td) / 'local.json'):
            labels = Path(td) / 'labels.json'
            labels.write_text(json.dumps([{'attack_class': 'xss', 'confidence': 'LOW', 'is_real': True,
                'sample_id': 'owned', 'evidence_verified': True, 'provenance': {'kind': 'owned-fixture'}}]))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = cli.main(['calibrate', '--ingest', str(labels)])
            self.assertEqual(code, 0)
            self.assertIn('Local-evidence Brier', output.getvalue())

    def test_merge_does_not_label_original_score_as_score_of_changed_predictions(self):
        shipped = calibration.fit([{'attack_class': 'xss', 'confidence': 'LOW', 'is_real': True}] * 5, ['fixture'], {'xss'})
        local = {'schema_version': 2, 'meta': {'samples': 5, 'score': {'brier': 0.0, 'n': 5}},
                 'by_class_label': {'xss|LOW': {'n': 5, 'k': 0}}, 'by_label': {'LOW': {'n': 5, 'k': 0}}}
        merged = calibration._merge(shipped, local)
        self.assertEqual(merged['by_class_label']['xss|LOW']['p'], 0.5)
        self.assertNotIn('score', merged['meta'])
        self.assertEqual(merged['meta']['source_scores']['shipped_snapshot']['brier'], 0.0)
        self.assertIn('no score of merged', merged['meta']['source_scores']['note'])

    # @req specs/002-calibration-honesty-and-structural-coverage/spec.md#FR-011
    def test_synthetic_cli_reports_score_and_never_writes_measured_overlay(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            pairs = root / 'pairs.json'
            pairs.write_text(json.dumps([{'id': str(i), 'extractor': 'CryptoUsageExtractor',
                'attack_class': 'jwt-verify-no-algorithms', 'confidence': 'LOW', 'file': 'app.js',
                'vulnerable': 'jwt.verify(token,key);',
                'control': 'jwt.verify(token,key,{algorithms:["HS256"]});'} for i in range(5)]))
            with patch.object(calibration, 'SYNTHETIC_PATH', root / 'synthetic.json'), \
                 patch.object(calibration, 'LOCAL_PATH', root / 'measured.json'):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = cli.main(['calibrate', '--synthetic', '--pairs', str(pairs)])
                self.assertEqual(code, 0)
                self.assertIn('Brier', output.getvalue())
                self.assertFalse(calibration.LOCAL_PATH.exists())
                self.assertEqual(json.loads(calibration.SYNTHETIC_PATH.read_text())['meta']['score']['n'], 5)


if __name__ == '__main__':
    unittest.main()
