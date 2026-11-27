"""#245: lockfiles and .sql files have their own budget; limits are configurable and disclosed;
a partial run is published under `partial/` and its directory is in the JSON envelope."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _jvm_repo import ROOT, TempRepo
from websec_validator.extractors.base import RepoContext, parse_size


class DataBudgetTests(TempRepo):
    def test_lockfiles_do_not_consume_the_source_cache(self):
        lock = json.dumps({"name": "a", "lockfileVersion": 3,
                           "packages": {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(3000)}})
        for index in range(3):
            self.write(f"apps/a{index}/package.json", '{"name":"a","dependencies":{"left-pad":"1.3.0"}}')
            self.write(f"apps/a{index}/package-lock.json", lock)
        self.write("src/index.js", "export const ok = 1;\n")
        with mock.patch.dict(os.environ, {"WEBSEC_MAX_SOURCE_BYTES": str(len(lock) + 4096)}):
            facts = self.facts()
        cov = facts["coverage"]
        self.assertTrue(cov["execution_complete"], cov["gaps"])
        self.assertGreaterEqual(cov["files"]["data_bytes"], 3 * len(lock))
        self.assertLess(cov["files"]["source_bytes"], len(lock))
        self.assertEqual(cov["files"]["read_policy"]["max_cached_raw_bytes_per_context"], len(lock) + 4096)

    def test_many_sql_migrations_complete(self):
        self.write("src/index.js", "export const ok = 1;\n")
        for index in range(75):
            self.write(f"db/migrations/V{index:03d}__t.sql", f"CREATE TABLE t{index} (id uuid primary key);\n")
        cov = self.facts()["coverage"]
        self.assertTrue(cov["execution_complete"], cov["gaps"])
        self.assertEqual(cov["files"]["glob_truncated"], [])
        self.assertEqual(cov["files"]["read_policy"]["data_inputs"]["max_sql_files"], 5000)

    def test_sql_limit_is_configurable_and_disclosed(self):
        for index in range(5):
            self.write(f"db/V{index}.sql", "CREATE TABLE t (id int);\n")
        with mock.patch.dict(os.environ, {"WEBSEC_MAX_SQL_FILES": "3"}):
            cov = self.facts()["coverage"]
        self.assertFalse(cov["execution_complete"])
        self.assertIn({"pattern": "**/*.sql", "limit": 3}, cov["files"]["glob_truncated"])

    def test_large_data_files_are_not_cached(self):
        self.write("package-lock.json", json.dumps({"packages": {"x": "y" * (2 * 1024 * 1024)}}))
        ctx = RepoContext(self.root)
        text = ctx.text(self.root / "package-lock.json")
        self.assertGreater(len(text), 2 * 1024 * 1024)
        self.assertEqual(ctx.cached_source_bytes, 0)
        ctx.text(self.root / "package-lock.json")
        self.assertEqual(ctx.data_bytes_read, len(text.encode()))   # a re-read is not charged twice

    def test_size_parsing(self):
        self.assertEqual(parse_size("64M"), 64 * 1024 * 1024)
        self.assertEqual(parse_size("1GiB"), 1024 ** 3)
        self.assertEqual(parse_size("4096"), 4096)
        for bad in ("", "-1", "12X", "0"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_size(bad)


class PartialPointerTests(TempRepo):
    def run_cli(self, *args, env=None):
        environment = dict(os.environ, PYTHONPATH=str(ROOT / "src"), **(env or {}))
        return subprocess.run([sys.executable, "-m", "websec_validator", "run", str(self.root), *args],
                              capture_output=True, text=True, env=environment, timeout=300)

    def test_partial_run_is_published_as_partial_and_named_in_json(self):
        self.write("src/index.js", "export const ok = 1;\n")
        for index in range(3):
            self.write(f"db/V{index}.sql", "CREATE TABLE t (id int);\n")
        holder = tempfile.TemporaryDirectory()
        self.addCleanup(holder.cleanup)
        out = Path(holder.name) / "out"
        result = self.run_cli("--format", "json", "--out", str(out), "--max-sql-files", "2")
        envelope = json.loads(result.stdout[result.stdout.index("{"):])
        self.assertFalse(envelope["run"]["execution_complete"])
        self.assertEqual(envelope["run"]["published_as"], "partial")
        self.assertTrue((out / "partial").is_symlink())
        self.assertFalse((out / "latest").exists())
        self.assertEqual((out / "partial").resolve(), Path(envelope["run"]["directory"]).resolve())

    def test_invalid_limit_fails_before_work(self):
        result = self.run_cli("--max-source-bytes", "lots")
        self.assertEqual(result.returncode, 2)
        self.assertIn("--max-source-bytes", result.stderr)


if __name__ == "__main__":
    unittest.main()
