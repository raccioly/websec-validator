"""Inventory spelling reuse must never cache filesystem authorization."""
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors import syntax
from websec_validator import findings, recon


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


class DerivedTextCacheTests(unittest.TestCase):
    def test_comment_free_python_does_not_need_tokenization(self):
        with patch.object(syntax.tokenize, 'generate_tokens', side_effect=AssertionError('unneeded lexer')):
            self.assertEqual(syntax.without_comments('value = "é"\n', '.py'), 'value = "é"\n')
        self.assertEqual(syntax.without_comments('value = "# literal" # comment\n', '.py'),
                         'value = "# literal"          \n')

    def test_sparse_markers_preserve_literals_incomplete_source_and_newlines(self):
        cases = [
            ('abc', 'abc'),
            ('abc // note\nnext', 'abc        \nnext'),
            ('abc /* note\nend */ next', 'abc        \n       next'),
            ('"https://example.invalid" // note', '"https://example.invalid"        '),
            ('`// literal` /* note */x', '`// literal`           x'),
            ('abc /* unfinished', 'abc              '),
            ('abc "unterminated // literal', 'abc "unterminated // literal'),
            ('é <!-- note\nend --> x', 'é          \n        x'),
        ]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(syntax.without_comments(source, '.js'), expected)
        self.assertEqual(syntax.without_comments('<pre>eval(x)</pre>', '.html'), '                  ')
        self.assertEqual(syntax.without_comments('<pre>eval(x)</pre>', '.js'), '<pre>eval(x)</pre>')

    def test_reuses_exact_text_and_suffix_including_empty_result(self):
        source = 'value = "# literal"  # comment\n'
        with patch.object(syntax, '_without_comments', wraps=syntax._without_comments) as transform:
            with syntax.derived_text_cache() as cache:
                first = syntax.without_comments(source, '.py')
                self.assertEqual(syntax.without_comments(source, '.py'), first)
                self.assertEqual(first, 'value = "# literal"           \n')
                self.assertEqual(syntax.without_comments('', '.py'), '')
                self.assertEqual(syntax.without_comments('', '.py'), '')
                self.assertEqual(transform.call_count, 2)
                self.assertEqual(len(cache.entries), 2)
            self.assertEqual(cache.retained_bytes, 0)
            self.assertEqual(cache.entries, {})
        self.assertIsNone(syntax._TEXT_CACHE.get())

    def test_suffix_changed_content_and_transformed_inputs_have_distinct_keys(self):
        source = '<pre>eval(request.body)</pre>\n// comment\n'
        with syntax.derived_text_cache():
            for text, suffix in [(source, '.html'), (source, '.js'),
                                 (source + 'run();', '.html'), ('é = 1 # 注释\n', '.py')]:
                expected = syntax._without_comments(text, suffix)
                self.assertEqual(syntax.without_comments(text, suffix), expected)
                self.assertEqual(len(expected), len(text))
                self.assertEqual([i for i, ch in enumerate(expected) if ch == '\n'],
                                 [i for i, ch in enumerate(text) if ch == '\n'])
                self.assertEqual(syntax.without_comments(expected, suffix),
                                 syntax._without_comments(expected, suffix))
            self.assertNotEqual(syntax.without_comments(source, '.html'),
                                syntax.without_comments(source, '.js'))

    def test_byte_budget_and_oversized_entries_recompute_without_losing_text(self):
        source = 'x // comment\n'
        expected = syntax._without_comments(source, '.js')
        size = sum(sys.getsizeof(value) for value in (source, '.js', expected, (source, '.js')))
        with syntax.derived_text_cache(max_bytes=size) as cache:
            self.assertEqual(syntax.without_comments(source, '.js'), expected)
            self.assertEqual(cache.retained_bytes, size)
            other = 'y // comment\n'
            self.assertEqual(syntax.without_comments(other, '.js'), syntax._without_comments(other, '.js'))
            self.assertEqual(len(cache.entries), 1)
            self.assertLessEqual(cache.retained_bytes, size)
            self.assertNotIn((source, '.js'), cache.entries)
            large = '🦊' * 100 + '\n// comment\n'
            with patch.object(syntax, '_without_comments', wraps=syntax._without_comments) as transform:
                for _ in range(2):
                    self.assertEqual(syntax.without_comments(large, '.js'), syntax._without_comments(large, '.js'))
                self.assertEqual(transform.call_count, 4)
            self.assertNotIn((large, '.js'), cache.entries)
            self.assertLessEqual(cache.retained_bytes, size)

    def test_entry_eviction_preserves_results_and_recent_reuse(self):
        with syntax.derived_text_cache(max_entries=2) as cache:
            for source in ['a // note', 'b // note', 'a // note', 'c // note']:
                self.assertEqual(syntax.without_comments(source, '.js'), syntax._without_comments(source, '.js'))
            self.assertEqual(list(cache.entries), [('a // note', '.js'), ('c // note', '.js')])
            self.assertEqual(syntax.without_comments('b // note', '.js'), 'b        ')
            self.assertEqual(len(cache.entries), 2)

    def test_disabled_cache_and_unscoped_calls_do_not_retain_source(self):
        for limits in ({'max_bytes': 0}, {'max_entries': 0}):
            with syntax.derived_text_cache(**limits) as cache:
                self.assertEqual(syntax.without_comments('x // note', '.js'), 'x        ')
                self.assertEqual(cache.entries, {})
                self.assertEqual(cache.retained_bytes, 0)
        with patch.object(syntax, '_without_comments', wraps=syntax._without_comments) as transform:
            syntax.without_comments('x // note', '.js')
            syntax.without_comments('x // note', '.js')
            self.assertEqual(transform.call_count, 2)

    def test_nested_scope_and_exception_restore_and_clear_owners(self):
        with syntax.derived_text_cache() as outer:
            syntax.without_comments('outer // note', '.js')
            with self.assertRaisesRegex(RuntimeError, 'injected'):
                with syntax.derived_text_cache() as inner:
                    self.assertIsNot(inner, outer)
                    syntax.without_comments('inner // note', '.js')
                    raise RuntimeError('injected')
            self.assertIs(syntax._TEXT_CACHE.get(), outer)
            self.assertEqual(inner.entries, {})
            self.assertEqual(inner.retained_bytes, 0)
            self.assertEqual(list(outer.entries), [('outer // note', '.js')])
        self.assertIsNone(syntax._TEXT_CACHE.get())
        self.assertEqual(outer.entries, {})

    def test_concurrent_scans_do_not_share_or_retain_text(self):
        barrier = threading.Barrier(2)
        def scan(source):
            self.assertIsNone(syntax._TEXT_CACHE.get())
            with syntax.derived_text_cache() as cache:
                syntax.without_comments(source, '.js')
                barrier.wait(timeout=5)
                self.assertEqual(list(cache.entries), [(source, '.js')])
            self.assertIsNone(syntax._TEXT_CACHE.get())
            return cache
        with ThreadPoolExecutor(max_workers=2) as workers:
            pending = [workers.submit(scan, source) for source in ['one // note', 'two // note']]
            caches = [future.result(timeout=10) for future in pending]
        self.assertIsNot(caches[0], caches[1])
        self.assertTrue(all(not cache.entries and cache.retained_bytes == 0 for cache in caches))

    def test_cached_transform_does_not_bypass_retargeted_reader(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            (root / 'real.py').write_text('value = 1 # comment\n')
            alias = root / 'alias.py'
            alias.symlink_to('real.py')
            ctx = RepoContext(root)
            with syntax.derived_text_cache():
                self.assertEqual(syntax.without_comments(ctx.text(alias), '.py'), 'value = 1          \n')
                alias.unlink()
                destination = Path(outside) / 'outside.py'
                destination.write_text('outside = 2')
                alias.symlink_to(destination)
                self.assertEqual(syntax.without_comments(ctx.text(alias), '.py'), '')
                self.assertGreater(ctx.skip_counts.get('outside_root', 0), 0)

    def test_actual_recon_facts_ledger_and_read_losses_match_disabled_cache(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'requirements.txt').write_text('Flask==3.0.0\n')
            (root / 'app.py').write_text(
                'from flask import Flask, request\napp = Flask(__name__)\n'
                '@app.get("/query")\ndef query():\n'
                '    return db.execute("SELECT " + request.args["q"])\n')
            # Pair a real finding with an unread input; reuse must not turn partial execution green.
            (root / 'oversized.py').write_bytes(b'x' * 2_000_001)
            enabled = recon.build_facts(root, 'test')
            with patch.object(syntax, 'MAX_DERIVED_TEXT_ENTRIES', 0):
                disabled = recon.build_facts(root, 'test')
            self.assertEqual(enabled, disabled)
            self.assertFalse(enabled['coverage']['execution_complete'])
            enabled_ledger = findings.build_ledger(enabled, None, None)
            self.assertEqual(enabled_ledger, findings.build_ledger(disabled, None, None))
            self.assertTrue(any(row['attack_class'] == 'sqli' for row in enabled_ledger['findings']))
            self.assertIsNone(syntax._TEXT_CACHE.get())

    def test_driver_cleans_up_when_context_creation_fails(self):
        from websec_validator import extractors
        captured = []
        def reject(*args, **kwargs):
            cache = syntax._TEXT_CACHE.get()
            captured.append(cache)
            syntax.without_comments('source // note', '.js')
            raise ValueError('repository root changed after authorization')
        with patch.object(extractors, 'RepoContext', side_effect=reject):
            with self.assertRaisesRegex(ValueError, 'root changed'):
                extractors.run_all(Path('.'), 'test')
        self.assertIsNone(syntax._TEXT_CACHE.get())
        self.assertEqual(captured[0].entries, {})
        self.assertEqual(captured[0].retained_bytes, 0)


if __name__ == '__main__':
    unittest.main()
