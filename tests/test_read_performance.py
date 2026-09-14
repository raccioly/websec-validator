"""Inventory spelling reuse must never cache filesystem authorization."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext


class InventoryPathCacheTests(unittest.TestCase):
    def test_nonmatching_globs_reuse_inventory_relative_paths(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.py').write_text('print(1)')
            ctx = RepoContext(root)
            with patch.object(Path, 'relative_to', side_effect=AssertionError('recomputed lexical inventory')):
                for _ in range(3):
                    self.assertEqual(ctx.glob('package.json'), [])
                    self.assertEqual(ctx.rel(root / 'app.py'), 'app.py')
            self.assertEqual(len(ctx._relative_files), len(ctx._files))

    def test_retargeted_alias_is_rechecked_by_glob_and_read(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            (root / 'real.py').write_text('print(1)')
            alias = root / 'alias.py'
            alias.symlink_to('real.py')
            ctx = RepoContext(root)
            self.assertEqual(ctx.text(alias), 'print(1)')
            alias.unlink()
            alias.symlink_to(Path(outside) / 'outside.py')
            (Path(outside) / 'outside.py').write_text('print(2)')
            with patch.object(ctx, '_open_file', side_effect=AssertionError('escaped source read')):
                self.assertNotIn(alias, ctx.glob('*.py'))
                self.assertEqual(ctx.text(alias), '')
            self.assertGreater(ctx.skip_counts.get('outside_root', 0), 0)

    def test_explicit_paths_do_not_grow_inventory_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ctx = RepoContext(root)
            for index in range(100):
                path = root / f'optional-{index}.json'
                self.assertEqual(ctx.rel(path), path.name)
                self.assertFalse(ctx.exists(path.name))
            (root / 'later.py').write_text('print(1)')
            self.assertEqual(ctx.text(root / 'later.py'), 'print(1)')
            self.assertEqual(ctx._relative_files, {})

    def test_matching_candidates_keep_stat_checks_and_updated_exclusions(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            path = root / 'app.py'
            path.write_text('print(1)')
            ctx = RepoContext(root)
            with patch.object(ctx, '_allowed', wraps=ctx._allowed) as allowed:
                self.assertEqual(ctx.glob('*.py'), [path])
                allowed.assert_called_once_with(path, traversal=True)
            ctx.excludes.append('app.py')
            self.assertEqual(ctx.glob('*.py'), [])
            self.assertEqual(ctx.text(path), '')
            ctx.excludes.clear()
            path.unlink()
            self.assertEqual(ctx.glob('*.py'), [])


if __name__ == '__main__':
    unittest.main()
