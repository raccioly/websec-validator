"""Python upload evidence belongs to actual handlers, values and operations."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.upload_security import UploadSecurityExtractor


PREFIX = 'from fastapi import FastAPI, UploadFile, HTTPException\napp=FastAPI()\n'


class PythonUploadTests(unittest.TestCase):
    def scan(self, body, *, prefix=PREFIX, parameters='file: UploadFile'):
        source = prefix + '@app.post("/upload")\nasync def upload(' + parameters + '):\n' + body
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text(source)
            return UploadSecurityExtractor().extract(RepoContext(root), {})

    def kinds(self, body, **kwargs):
        return {row['kind'] for row in self.scan(body, **kwargs)['findings']}

    # @req specs/001-continuous-security-improvement/spec.md#FR-002
    def test_actual_filename_storage_and_mime_decision_are_detected(self):
        kinds = self.kinds(' path="uploads/"+file.filename\n with open(path,"wb") as output:\n'
                           '  output.write(await file.read())\n if file.content_type=="image/png":\n'
                           '  store(await file.read())\n')
        self.assertIn('upload-key-from-filename', kinds)
        self.assertIn('upload-trusts-client-mime', kinds)

    def test_metadata_logs_returns_and_unused_filename_are_not_storage(self):
        kinds = self.kinds(' filename=file.filename\n logger.info(file.content_type)\n'
                           ' return {"filename":file.filename,"type":file.content_type}\n')
        self.assertEqual(kinds, set())

    def test_generated_path_and_straight_overwrite_clear_filename_flow(self):
        for body in (' path="uploads/"+random_id()\n with open(path,"wb") as output:\n  output.write(await file.read())',
                     ' path=file.filename\n path="generated.png"\n with open(path,"wb") as output:\n  output.write(await file.read())'):
            with self.subTest(body=body):
                self.assertNotIn('upload-key-from-filename', self.kinds(body))

    def test_branch_overwrite_keeps_possible_filename_flow(self):
        self.assertIn('upload-key-from-filename', self.kinds(' path=file.filename\n'
            ' if flag:\n  path="generated.png"\n with open(path,"wb") as output:\n  output.write(await file.read())'))

    def test_bound_annotation_and_route_receiver_not_names_alone(self):
        for prefix, parameters in ((PREFIX.replace('UploadFile, ', ''), 'file: UploadFile'),
                                   (PREFIX.replace('from fastapi', 'from .fastapi'), 'file: UploadFile'),
                                   (PREFIX + 'UploadFile=Fake\n', 'file: UploadFile'),
                                   (PREFIX + 'app=Fake()\n', 'file: UploadFile'),
                                   (PREFIX, 'file: Other'),
                                   (PREFIX, 'file: UploadFile, UploadFile=None')):
            with self.subTest(prefix=prefix, parameters=parameters):
                self.assertEqual(self.scan(' store(file.filename,await file.read())',
                                           prefix=prefix, parameters=parameters)['upload_handlers'], [])

    def test_annotated_alias_is_supported_and_sibling_helper_does_not_taint(self):
        prefix = PREFIX.replace('UploadFile,', 'UploadFile as UF,') + 'from typing import Annotated as Ann\n'
        result = self.scan(' store(file.filename,await file.read())', prefix=prefix,
                           parameters='file: Ann[UF, "metadata"]')
        self.assertIn('upload-key-from-filename', {row['kind'] for row in result['findings']})
        self.assertNotIn('upload-key-from-filename', self.kinds(' def unused():\n  store(file.filename)\n'
                                                             ' store("generated.png",await file.read())'))

    def test_named_sniff_or_unrelated_bytes_do_not_credit_mime(self):
        for check in (' sniff(file)\n', ' detected=magic.from_buffer(other,mime=True)\n',
                      ' detected="image/png"\n'):
            self.assertIn('upload-trusts-client-mime', self.kinds(check +
                ' if file.content_type=="image/png":\n  store(await file.read())', prefix=PREFIX+'import magic\n'))

    def test_same_file_detected_type_rejection_is_local_evidence_only(self):
        safe = (' data=await file.read()\n detected=magic.from_buffer(data,mime=True)\n'
                ' if detected not in {"image/png","image/jpeg"}:\n'
                '  raise HTTPException(status_code=415)\n'
                ' store("generated.png",data,content_type=file.content_type)\n')
        self.assertNotIn('upload-trusts-client-mime', self.kinds(safe, prefix=PREFIX+'import magic\n'))
        for body in (safe.replace('raise HTTPException(status_code=415)', 'logger.warning("bad")'),
                     safe.replace('file.read()', 'other.read()'),
                     safe.replace('not in', 'in'),
                     safe.replace('"image/jpeg"', '"image/svg+xml"')):
            with self.subTest(body=body):
                self.assertIn('upload-trusts-client-mime', self.kinds(body, prefix=PREFIX+'import magic\n'))
        self.assertIn('upload-key-from-filename', self.kinds(safe.replace('"generated.png",data',
                      'file.filename,data'), prefix=PREFIX+'import magic\n'))

    def test_read_only_open_and_python_literals_are_not_write_storage(self):
        self.assertEqual(self.kinds(' example="store(file.filename)"\n with open(file.filename,"rb") as stream:\n  return stream.read()'), set())

    def test_metadata_comparisons_inside_logging_remain_decisions(self):
        self.assertIn('upload-trusts-client-mime', self.kinds(' logger.info(file.content_type=="image/png")'))
        self.assertIn('upload-trusts-client-mime', self.kinds(' print=store\n print(file.content_type)'))

    def test_modified_or_partial_bytes_and_changed_branch_cannot_keep_credit(self):
        safe = (' data=await file.read()\n detected=magic.from_buffer(data,mime=True)\n'
                ' if detected not in {"image/png"}:\n  raise HTTPException(status_code=415)\n'
                ' store("generated.png",data,content_type=file.content_type)\n')
        for body in (safe.replace('await file.read()', 'b"safe"+await file.read()'),
                     safe.replace('file.read()', 'file.read(10)'),
                     safe.replace('if detected not in', 'detected=transform(detected)\n if detected not in'),
                     safe.replace(' store(', ' if flag:\n  file.content_type="other"\n store('),
                     safe.replace(' store(', ' if flag:\n  data=other\n store('),
                     safe.replace(' store(', ' if flag:\n  file.file=other\n store('),
                     safe.replace('"generated.png",data', '"generated.png",other'),
                     safe.replace('await file.read()', 'file.file')):
            with self.subTest(body=body):
                self.assertIn('upload-trusts-client-mime', self.kinds(body, prefix=PREFIX+'import magic\n'))

    def test_cli_persists_upload_evidence_and_ledger(self):
        import json
        import os
        import subprocess
        with tempfile.TemporaryDirectory() as td:
            owner = Path(td)
            root = owner / 'target'
            root.mkdir()
            (root / 'app.py').write_text(PREFIX + '@app.post("/upload")\nasync def upload(file: UploadFile):\n'
                ' store(file.filename,await file.read(),content_type=file.content_type)\n')
            out = owner / 'out'
            env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / 'src'),
                       PATH=str(owner / 'no-tools'), WEBSEC_CALIBRATION_HOME=str(owner / 'calibration'),
                       WEBSEC_UPDATE_HOME=str(owner / 'release-metadata'))
            run = subprocess.run([sys.executable, '-m', 'websec_validator.cli', 'run', str(root), '--out', str(out),
                                  '--format', 'json', '--fail-on', 'high'], env=env, cwd=owner,
                                 capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 1, run.stderr)
            directory = out / 'runs' / json.loads(run.stdout)['generated']
            facts = json.loads((directory / 'FACTS.json').read_text())
            self.assertEqual({row['kind'] for row in facts['upload_security']['findings']},
                             {'upload-key-from-filename', 'upload-trusts-client-mime'})
            ledger = json.loads((directory / 'findings-ledger.json').read_text())
            self.assertTrue(any(row['attack_class'] == 'unrestricted-upload' for row in ledger['findings']))

    def test_budget_failure_is_incomplete_not_clean(self):
        from unittest.mock import patch
        from websec_validator.extractors import python_uploads
        with patch.object(python_uploads, 'MAX_NODES', 3):
            result = self.scan(' store(file.filename,await file.read())')
        self.assertTrue(result.get('error'))
        self.assertTrue(result['python_analysis']['errors'])


if __name__ == '__main__':
    unittest.main()
