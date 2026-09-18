"""Engine provenance: which install is actually running.

A version string alone does not identify the engine. These tests pin the distinction
between an index install and everything else, because the failure that motivated the
module was a `pipx` install pinned to `file:///tmp/...whl` that stayed two releases
behind while `pipx upgrade` reported "already at latest".
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from websec_validator import provenance  # noqa: E402


class FakeDist:
    def __init__(self, direct_url=None, version="1.2.3", path="/opt/x/site-packages/d.dist-info",
                 location="/opt/x/site-packages"):
        self.version = version
        self._payload = direct_url
        self._path = Path(path)
        self._location = location

    def read_text(self, name):
        return json.dumps(self._payload) if name == "direct_url.json" and self._payload else None

    def locate_file(self, _):
        return self._location


def describe_with(dist, imported="/opt/x/site-packages/websec_validator"):
    with patch.object(provenance.metadata, "distribution", return_value=dist), \
         patch.object(Path, "resolve", lambda self: self):
        info = provenance.describe()
    info["imported_from"] = imported
    return info


class SourceClassificationTests(unittest.TestCase):
    def test_absent_direct_url_is_an_index_install(self):
        # PEP 610 writes direct_url.json only for non-index installs, so its absence is
        # the positive signal — this is the one case that may be called trusted.
        with patch.object(provenance.metadata, "distribution", return_value=FakeDist()):
            info = provenance.describe()
        self.assertEqual(info["source"], "index")
        self.assertIs(info["trusted_index"], True)

    def test_local_file_install_is_flagged_and_names_the_path(self):
        url = "file:///private/tmp/websec_validator-0.14.0-py3-none-any.whl"
        with patch.object(provenance.metadata, "distribution",
                          return_value=FakeDist({"url": url, "archive_info": {}})):
            info = provenance.describe()
        self.assertEqual(info["source"], "local-file")
        self.assertIs(info["trusted_index"], False)
        self.assertIn(url, info["detail"])
        self.assertIn("stay behind", info["detail"])

    def test_editable_install_is_flagged(self):
        with patch.object(provenance.metadata, "distribution",
                          return_value=FakeDist({"url": "file:///src/app",
                                                 "dir_info": {"editable": True}})):
            info = provenance.describe()
        self.assertEqual(info["source"], "editable")
        self.assertIs(info["trusted_index"], False)

    def test_vcs_install_records_the_commit(self):
        with patch.object(provenance.metadata, "distribution",
                          return_value=FakeDist({"url": "https://git/x",
                                                 "vcs_info": {"vcs": "git", "commit_id": "a" * 40}})):
            info = provenance.describe()
        self.assertEqual(info["source"], "vcs")
        self.assertIn("aaaaaaaaaaaa", info["detail"])

    def test_egg_info_source_tree_is_not_called_an_index_install(self):
        # The trap: an .egg-info has no direct_url.json, so the PEP 610 test alone would
        # call a local source build "index" and stamp it trusted — a false clean signal.
        with patch.object(provenance.metadata, "distribution",
                          return_value=FakeDist(path="/repo/src/websec_validator.egg-info")):
            info = provenance.describe()
        self.assertEqual(info["source"], "source-tree")
        self.assertIs(info["trusted_index"], False)

    def test_missing_metadata_does_not_raise(self):
        # Diagnostics must never be the thing that breaks `doctor`.
        with patch.object(provenance.metadata, "distribution", side_effect=Exception("boom")):
            info = provenance.describe()
        self.assertEqual(info["source"], "no-metadata")

    def test_unparseable_direct_url_is_ignored_rather_than_crashing(self):
        class Broken(FakeDist):
            def read_text(self, name):
                return "{not json"
        with patch.object(provenance.metadata, "distribution", return_value=Broken()):
            info = provenance.describe()
        self.assertEqual(info["source"], "index")


class RenderingTests(unittest.TestCase):
    def test_non_index_installs_carry_a_warning_line(self):
        with patch.object(provenance, "describe",
                          return_value={"version": "1", "source": "local-file", "detail": "d",
                                        "location": "/loc", "trusted_index": False,
                                        "imported_from": "/loc/websec_validator"}):
            out = "\n".join(provenance.lines())
        self.assertIn("LOCAL FILE", out)
        self.assertIn("did not come from an index", out)

    def test_index_install_has_no_warning(self):
        with patch.object(provenance, "describe",
                          return_value={"version": "1", "source": "index", "detail": "d",
                                        "location": "/loc", "trusted_index": True,
                                        "imported_from": "/loc/websec_validator"}):
            out = "\n".join(provenance.lines())
        self.assertNotIn("⚠", out)

    def test_importing_code_outside_the_installed_distribution_is_reported(self):
        # A source tree ahead of the installed copy on sys.path: the version describes
        # the install, the behaviour comes from the tree.
        with patch.object(provenance, "describe",
                          return_value={"version": "1", "source": "index", "detail": "d",
                                        "location": "/opt/site-packages", "trusted_index": True,
                                        "imported_from": "/home/me/repo/src/websec_validator"}):
            out = "\n".join(provenance.lines())
        self.assertIn("NOT inside the installed distribution", out)


if __name__ == "__main__":
    unittest.main()
