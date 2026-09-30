"""The PDF must not silently outlive its HTML source (bug-363)."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("brief_builder", REPO / "scripts/build-brief.py")
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class BriefArtifactBinding(unittest.TestCase):
    def setUp(self):
        self.owned = tempfile.TemporaryDirectory()
        self.addCleanup(self.owned.cleanup)
        self.root = Path(self.owned.name)
        for name in builder.FILES:
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((REPO / name).read_bytes())
        self.manifest = self.root / builder.MANIFEST
        self.manifest.write_text(json.dumps(builder.snapshot(self.root)), encoding="utf-8")

    def test_committed_pair_is_current_offline(self):
        with patch.object(builder.subprocess, "run", side_effect=AssertionError("no browser")):
            builder.check(REPO)

    def test_unchanged_fixture_passes(self):
        builder.check(self.root)

    def test_source_edit_without_rebuild_fails(self):
        source = self.root / builder.FILES[0]
        source.write_text(source.read_text() + "<!-- new content -->", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stale"):
            builder.check(self.root)

    def test_pdf_changed_without_manifest_fails(self):
        pdf = self.root / builder.FILES[1]
        pdf.write_bytes(pdf.read_bytes().replace(b"%PDF-", b"%PDF- ", 1))
        with self.assertRaisesRegex(ValueError, "stale"):
            builder.check(self.root)

    def test_truncated_pdf_fails(self):
        (self.root / builder.FILES[1]).write_bytes(b"%PDF-1.4\ntruncated")
        with self.assertRaisesRegex(ValueError, "eight-page"):
            builder.check(self.root)

    def test_renderer_change_needs_rebuild(self):
        script = self.root / builder.FILES[2]
        script.write_text(script.read_text() + "\n# changed\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "stale"):
            builder.check(self.root)

    def test_missing_manifest_fails(self):
        self.manifest.unlink()
        with self.assertRaises(FileNotFoundError):
            builder.check(self.root)

    def test_malformed_manifest_fails(self):
        self.manifest.write_text("{", encoding="utf-8")
        with self.assertRaises(ValueError):
            builder.check(self.root)

    def test_symlinked_output_is_rejected_and_preserved(self):
        pdf = self.root / builder.FILES[1]
        outside = self.root / "sentinel.pdf"
        outside.write_bytes(b"owned sentinel")
        pdf.unlink()
        pdf.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "aliased"):
            builder.check(self.root)
        self.assertEqual(outside.read_bytes(), b"owned sentinel")

    def test_alias_parent_is_rejected(self):
        (self.root / "aliases").symlink_to(self.root / "docs", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "aliased"):
            builder.regular_destination(self.root, "aliases/websec-explained.pdf")

    def test_bad_render_preserves_published_pair(self):
        pdf = self.root / builder.FILES[1]
        before = (pdf.read_bytes(), self.manifest.read_bytes())

        def failed_render(argv, **kwargs):
            output = next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--print-to-pdf="))
            Path(output).write_bytes(b"%PDF-1.4\ntruncated")

        with patch.object(builder, "REPO", self.root), patch.object(builder.subprocess, "run", failed_render):
            with self.assertRaisesRegex(ValueError, "eight-page"):
                builder.build("installed-test-browser")
        self.assertEqual((pdf.read_bytes(), self.manifest.read_bytes()), before)
