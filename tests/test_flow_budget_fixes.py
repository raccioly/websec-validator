"""Issue #194: the JS assigned-flow lane must complete ordinary modules and stay bounded.

Measured root causes (0.21.x): a quote inside a regex literal (`/'/g`, `/["']/`) opened a phantom
string, so the next assignment scanned to the 8192-character expression bound and the walk stopped,
dropping every later sink; a right-hand side longer than that bound (an `async (event) => {...}`
handler) did the same; and the 128-scope cap rejected modules with ordinary function counts.
"""
from pathlib import Path
import random
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator import recon
from websec_validator.extractors import assigned_flow, syntax
from websec_validator.extractors.base import RepoContext
from websec_validator.extractors.surface import SurfaceExtractor

SINK = '''
export async function listItems(req, res) {
  const params = {
    TableName: TABLE,
    KeyConditionExpression: "pk = :pk",
    ExpressionAttributeValues: { ":pk": `TENANT#${req.params.tenant}` },
  };
  const out = await ddb.query(params);
  res.json(out.Items);
}
'''


def module(extra_validation='', functions=18):
    """A ~460-line plain ES module: DynamoDB access, validation, object literals, chained writes.

    `extra_validation` goes into the first validator only: a single quote-bearing regex is the
    realistic case, and repeated ones pair their phantom quotes up and hide the defect.
    """
    head = '''import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, GetCommand } from "@aws-sdk/lib-dynamodb";
import crypto from "node:crypto";

const client = new DynamoDBClient({ region: process.env.AWS_REGION || "us-east-1" });
const ddb = DynamoDBDocumentClient.from(client, { marshallOptions: { removeUndefinedValues: true } });
const TABLE = process.env.TABLE_NAME || "acme";
const EMAIL_RE = /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/;
const SLUG_RE = /^[a-z0-9-]{1,64}$/;
'''
    body = ''.join(f'''
export function validateInput{i}(body) {{
  const errors = [];
  if (!body || typeof body !== "object") {{
    errors.push("body must be an object");
    return {{ ok: false, errors }};
  }}
  const name = String(body.name || ""){extra_validation if i == 0 else ''}.trim();
  const email = String(body.email || "").toLowerCase();
  if (!name) errors.push("name required");
  if (!EMAIL_RE.test(email)) errors.push("invalid email");
  const match = SLUG_RE.exec(body.slug || "");
  let slug = match ? match[0] : null;
  slug = slug || crypto.randomUUID();
  return {{ ok: errors.length === 0, errors, value: {{ name, email, slug }} }};
}}

export async function getItem{i}(id) {{
  const params = {{
    TableName: TABLE,
    Key: {{ pk: `ITEM#${{id}}`, sk: "META" }},
  }};
  const result = await ddb.send(new GetCommand(params));
  return result.Item || null;
}}
''' for i in range(functions))
    return head + body + SINK


def lane(source):
    return assigned_flow.javascript(source, {'bytes': 0, 'events': 0})


class OrdinaryModulesComplete(unittest.TestCase):
    def assert_complete(self, source):
        result = lane(source)
        self.assertEqual(result['errors'], [])
        sinks = [row for row in result['occurrences'] if row['sink_class'] == 'sql-injection']
        self.assertEqual(len(sinks), 1, 'the request-derived query after the hard part is still reached')
        self.assertEqual(sinks[0]['line'], source.count('\n', 0, source.index('ddb.query(')) + 1)
        return result

    def test_plain_module_baseline(self):
        source = module()
        self.assertGreater(source.count('\n'), 450)
        self.assert_complete(source)

    def test_quote_inside_regex_literal_does_not_stop_the_walk(self):
        for regex in (r""".replace(/'/g, "")""", r""".replace(/["']/g, "")""", r""".replace(/[`]/g, "")"""):
            with self.subTest(regex=regex):
                self.assert_complete(module(extra_validation=regex))

    def test_long_function_valued_right_hand_side_completes(self):
        handler = ('\nexport const handler = async (event) => {\n'
                   + ''.join(f'  const v{i} = await getItem{i % 18}(event.pathParameters.id);\n'
                             f'  if (!v{i}) {{ return {{ statusCode: 404, body: JSON.stringify({{ error: "missing {i}" }}) }}; }}\n'
                             for i in range(90))
                   + '  return { statusCode: 200 };\n};\n')
        source = module().replace(SINK, handler + SINK)
        self.assertGreater(len(handler), syntax.MAX_EXPRESSION)
        self.assert_complete(source)

    def test_large_object_of_methods_completes(self):
        routes = ('\nexport const routes = {\n'
                  + ''.join(f'  async r{i}(req) {{\n    const item = await getItem{i % 18}(req.params.id);\n'
                            f'    return {{ status: 200, item }};\n  }},\n' for i in range(80))
                  + '};\n')
        self.assertGreater(len(routes), syntax.MAX_EXPRESSION)
        self.assert_complete(module().replace(SINK, routes + SINK))

    def test_scope_budget_scales_with_file_size(self):
        source = module(functions=110)  # 220 functions in ~80 KB: well under one scope per 64 bytes
        self.assertGreater(len(syntax.js_functions(source)), assigned_flow.MAX_SCOPES)
        self.assert_complete(source)
        self.assertEqual(assigned_flow.scope_limit(1), assigned_flow.MAX_SCOPES)
        self.assertEqual(assigned_flow.scope_limit(10 ** 9), assigned_flow.MAX_SCOPES_CAP)

    def test_realistic_module_has_no_coverage_gap_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'lib').mkdir()
            (root / 'lib' / 'acme.mjs').write_text(module(extra_validation=r""".replace(/'/g, "")"""))
            (root / 'package.json').write_text('{"name": "acme", "type": "module"}')
            with patch('shutil.which', return_value=None):
                facts = recon.build_facts(root, 'test')
        self.assertEqual(facts['surface']['assigned_flow']['errors'], [])
        self.assertNotIn('error', facts['surface'])
        self.assertEqual(facts['coverage']['extractors']['surface']['outcome'], 'completed')
        self.assertNotIn({'kind': 'extractor', 'detail': 'surface', 'execution': True}, facts['coverage']['gaps'])


class RegexLiteralBlanking(unittest.TestCase):
    def test_only_operand_position_slashes_are_regex_literals(self):
        blank = assigned_flow._without_regex_bodies
        for source in ('a = b / c / d;', 'x = y++ / 2 / z;', 'n = obj.in / 2 / k;', 'r = f(x) / 2 / g;',
                       'el = <div>{a}</div> {c / d};', 's = "a/\'b/c";', '// it\'s /x/ \nq = 1;',
                       '/* /\'/ */ q = 1;', 'u = `a/${b}/c`;', 'w = arr[0] / 2 / v;'):
            with self.subTest(source=source):
                self.assertEqual(blank(source), source)
        for source, expected in (("q = s.replace(/'/g, '');", "q = s.replace(/ /g, '');"),
                                 ('re = /["\']/;', 're = /    /;'),
                                 ("return /a'b/.test(x)", 'return /   /.test(x)'),
                                 ('ok = !/[/]x"/.test(s);', 'ok = !/     /.test(s);')):
            with self.subTest(source=source):
                self.assertEqual(blank(source), expected)
                self.assertEqual(len(blank(source)), len(source))

    def test_request_flow_beside_a_regex_is_retained(self):
        source = ("function h(req) {\n  const q = String(req.query.id).replace(/'/g, \"\");\n"
                  "  const sql = \"SELECT * FROM t WHERE id='\" + q + \"'\";\n  return db.query(sql);\n}\n")
        rows = lane(source)['occurrences']
        self.assertEqual([(row['line'], row['source_lines']) for row in rows], [(4, [2])])


class EquivalentFasterPrimitives(unittest.TestCase):
    """The rewritten primitives are identical wherever the old ones produced an accepted result."""

    def test_expression_end_matches_syntax_below_the_bound(self):
        rng = random.Random(194)
        alphabet = list('ab =;\n\n  +?.[](){}"\'`\\') + ['\t', '\x0b', '\x1c', '\x85', ' ', ' ',
                                                        'x=', '=>', 'req.query']
        for size in [120] * 4000 + [12_000] * 40:
            text = ''.join(rng.choice(alphabet) for _ in range(rng.randint(1, size)))
            start = rng.randint(0, min(len(text), 200))
            expected = syntax.expression_end(text, start)
            actual, _closed = assigned_flow._expression_end(text, start, start + syntax.MAX_EXPRESSION)
            self.assertEqual(actual, expected, (text[:80], start))

    def test_scope_owner_is_the_shortest_containing_scope(self):
        def reference(scopes, position):
            rows = [row for row in scopes if row['body_start'] <= position < row['end']]
            return min(rows, key=lambda row: row['end'] - row['start'])['body_start'] if rows else 0
        rng = random.Random(194)
        pieces = ['function f(a){', 'const g=(b)=>{', 'x=1;', '}', 'if(a){', 'h(c){', 'y=req.query.a;',
                  '\n', ' ', '"}"', "'{'", 'arr.map((v)=>{', '})', ')']
        for _ in range(1500):
            code = ''.join(rng.choice(pieces) for _ in range(rng.randint(1, 60)))
            scopes = syntax.js_functions(code)
            owner = assigned_flow._scope_owner(scopes)
            for position in range(len(code) + 1):
                self.assertEqual(owner(position), reference(scopes, position), (code, position))


class AdversarialInputStaysBounded(unittest.TestCase):
    CASES = {
        # One level per line: a single 15 KB line is skipped by the walker as a vendored asset.
        'nested.js': 'function h(req){x=' + ''.join(f'(v{i}=\n' for i in range(2000)) + 'req.query.a'
                     + ')\n' * 2000 + ';db.query(x);}',
        'continued.js': 'function h(req){q=a\n' + '+v=a\n' * 2000 + ';db.query(q);}' + ' ' * 300_000,
    }

    def test_limit_is_reached_quickly_and_reported_for_that_file_only(self):
        sibling = 'function h(req){const q=req.query.a;db.query(q);}\n'
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for name, source in self.CASES.items():
                (root / name).write_text(source)
            (root / 'ordinary.js').write_text(sibling)
            started = time.perf_counter()
            result = SurfaceExtractor().extract(RepoContext(root), {'stack': {'datastores': ['postgres']}})
            elapsed = time.perf_counter() - started
        # Measured ~0.2 s; the old implementation needed 0.1 s only because it gave up at the first
        # long expression. The generous bound guards against an unbounded rescan, not machine speed.
        self.assertLess(elapsed, 5.0)
        flow = result['assigned_flow']
        limited = {row['file'] for row in flow['errors'] if row['kind'] == 'LimitReached'}
        self.assertEqual(limited, set(self.CASES))
        self.assertLessEqual(flow['work']['extended'], assigned_flow.MAX_TOTAL_EXTENDED)
        sinks = {row['file'] for row in result['sink_occurrences']
                 if row['sink_class'] == 'sql-injection' and row.get('source_lines')}
        self.assertIn('ordinary.js', sinks, 'a limit in one file never costs a sibling its result')

    def test_per_file_allowance_is_size_proportional_and_capped(self):
        for name, source in self.CASES.items():
            with self.subTest(name=name):
                budget = {'bytes': 0, 'events': 0}
                result = assigned_flow.javascript(source, budget)
                self.assertEqual(result['errors'][-1]['detail'], 'JS assignment expression budget exceeded')
                self.assertLessEqual(budget['extended'], min(assigned_flow.EXTENDED_FACTOR * len(source),
                                                             assigned_flow.MAX_EXTENDED_PER_FILE))

    def test_run_total_allowance_is_shared_across_files(self):
        budget = {'bytes': 0, 'events': 0, 'extended': assigned_flow.MAX_TOTAL_EXTENDED}
        handler = 'export const handler = async (req) => {\n' + '  const a = 1;\n' * 1200 + '};\nfunction h(req){db.query(req.query.a);}\n'
        result = assigned_flow.javascript(handler, budget)
        self.assertEqual(result['errors'], [{'kind': 'LimitReached', 'detail': 'JS assignment expression budget exceeded'}])
        self.assertEqual(budget['extended'], assigned_flow.MAX_TOTAL_EXTENDED)


class FailuresStayVisible(unittest.TestCase):
    def test_limit_is_disclosed_and_run_is_not_complete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'nested.js').write_text(AdversarialInputStaysBounded.CASES['nested.js'])
            with patch('shutil.which', return_value=None):
                facts = recon.build_facts(root, 'test')
        rows = facts['surface']['assigned_flow']['errors']
        self.assertEqual([(row['file'], row['kind']) for row in rows], [('nested.js', 'LimitReached')])
        self.assertFalse(facts['coverage']['execution_complete'])

    def test_genuine_exception_in_the_lane_is_an_execution_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / 'app.js').write_text('function h(req){const q=req.query.a;db.query(q);}\n')
            with patch('shutil.which', return_value=None), \
                    patch.object(assigned_flow, 'javascript', side_effect=RuntimeError('synthetic')):
                facts = recon.build_facts(root, 'test')
        self.assertEqual(facts['coverage']['extractors']['surface'], {'outcome': 'error', 'error': 'RuntimeError'})
        self.assertIn({'kind': 'extractor', 'detail': 'surface', 'execution': True}, facts['coverage']['gaps'])
        self.assertFalse(facts['coverage']['execution_complete'])


if __name__ == '__main__':
    unittest.main()
