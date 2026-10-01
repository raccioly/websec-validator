"""Offline, per-tool comparison of captured reports against explicit reviewed labels.

Never executes tools or target code. Capture provenance is operator-declared; hashes bind bytes,
not the truth of a claimed tool execution. See BENCHMARKS.md for the manifest contract.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from websec_validator.output import checked_path, write_text

MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 50_000
IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}\Z')
HASH = re.compile(r'[a-f0-9]{64}\Z')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def read_json(base, name, limit=MAX_BYTES):
    if any(part.lower() == '.local' for part in Path(base).resolve().parts):
        raise ValueError('private input directory')
    path = checked_path(base, relative(name))
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('report must be a regular file')
    with path.open('rb') as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError('report byte limit exceeded')
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON'))), sha(data)


def relative(value):
    if (type(value) is not str or not value or len(value) > 512 or '\\' in value
            or any(ord(c) < 32 for c in value)):
        raise ValueError('invalid relative path')
    parts = value.split('/')
    if any(p in {'', '.', '..'} or p.lower() == '.local' for p in parts) or ':' in parts[0]:
        raise ValueError('invalid or private relative path')
    if PurePosixPath(value).is_absolute():
        raise ValueError('absolute path is not comparable')
    return value


def identifier(value):
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise ValueError('invalid identifier')
    return value


def digest(value):
    if type(value) is not str or not HASH.fullmatch(value):
        raise ValueError('missing SHA256 binding')
    return value


def bounded_rows(value):
    if type(value) is not list or len(value) > MAX_ROWS or any(type(v) is not dict for v in value):
        raise ValueError('invalid or oversized rows')
    return value


def observed(tool, doc):
    if type(doc) is not dict:
        raise ValueError('report must be an object')
    rows = bounded_rows(doc.get('findings' if tool == 'websec' else 'results'))
    partial = False
    if tool == 'websec':
        if doc.get('total') != len(rows) or type(doc.get('total')) is not int:
            raise ValueError('ledger total mismatch')
        # No coverage attestation is not a completed WebSec capture.
        partial = type(doc.get('coverage')) is not dict or doc['coverage'].get('execution_complete') is not True
    else:
        partial = bool(bounded_rows(doc.get('errors')))
        if tool == 'bandit':
            metrics = doc.get('metrics')
            if type(metrics) is not dict or type(metrics.get('_totals')) is not dict:
                raise ValueError('missing Bandit metric totals')
            for key in ('nosec', 'skipped_tests'):
                count = metrics['_totals'].get(key)
                if type(count) is not int or count < 0:
                    raise ValueError('invalid Bandit suppression count')
                partial |= count > 0
        else:
            skipped = doc.get('skipped_rules', [])
            if type(skipped) is not list or len(skipped) > MAX_ROWS:
                raise ValueError('invalid skipped-rule diagnostics')
            partial |= bool(skipped)
            if 'paths' in doc:
                paths = doc['paths']
                if type(paths) is not dict or type(paths.get('scanned')) is not list:
                    raise ValueError('invalid path diagnostics')
                partial |= bool(bounded_rows(paths.get('skipped', [])))
    result = []
    for row in rows:
        if tool == 'semgrep':
            rule, file = row.get('check_id'), row.get('path')
            start = row.get('start')
            line = start.get('line') if type(start) is dict else None
        elif tool == 'bandit':
            rule, file, line = row.get('test_id'), row.get('filename'), row.get('line_number')
        else:
            rule = row.get('rule_id') or row.get('attack_class')
            file, line = row.get('file'), row.get('line')
            if not file:
                location = row.get('location')
                match = re.fullmatch(r'([^:]+):(\d+)', location) if type(location) is str else None
                if match:
                    file, line = match[1], int(match[2])
        rule = identifier(rule)
        # Route-only and absolute locations are unknown, never guessed into file labels.
        try:
            file = relative(file)
        except ValueError:
            file = None
        if type(line) is not int or not 0 < line <= 10_000_000:
            line = None
        result.append((rule, file, line))
    return result, partial


def compare(base, manifest):
    if (type(manifest) is not dict or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1):
        raise ValueError('unsupported manifest')
    revision = manifest.get('corpus_revision')
    if type(revision) is not str or not re.fullmatch(r'[a-f0-9]{40}', revision):
        raise ValueError('corpus needs an immutable Git revision')
    scope = manifest.get('scope')
    if type(scope) is not list or not scope or len(scope) > MAX_ROWS:
        raise ValueError('explicit nonempty scope required')
    scope = sorted({relative(file) for file in scope})
    scope_sha = sha(json.dumps(scope, separators=(',', ':')).encode())
    labels, labels_sha = read_json(base, manifest.get('labels'))
    if labels_sha != digest(manifest.get('labels_sha256')):
        raise ValueError('labels digest mismatch')
    labels = bounded_rows(labels)
    index, ids, positives = {}, set(), set()
    for label in labels:
        label_id = identifier(label.get('id'))
        if label_id in ids:
            raise ValueError('duplicate label ID')
        ids.add(label_id)
        file, attack = relative(label.get('file')), identifier(label.get('attack_class'))
        line = label.get('line')
        if type(line) is not int or not 0 < line <= 10_000_000:
            raise ValueError('labels require an exact source line')
        if file not in scope:
            raise ValueError('label outside common scope')
        if label.get('reviewed') is True and type(label.get('real')) is bool:
            index.setdefault((file, line, attack), []).append(label)
            if label['real']:
                positives.add(label_id)
    # Contradictory reviewed labels are not known positive denominator evidence.
    positives = {label['id'] for rows in index.values()
                 if {row['real'] for row in rows} == {True} for label in rows}
    reports = bounded_rows(manifest.get('reports'))
    if not reports or len(reports) > 3:
        raise ValueError('one to three per-tool reports required')
    summaries, findings, tools = [], [], set()
    for report in reports:
        tool = report.get('tool')
        if tool not in {'websec', 'semgrep', 'bandit'} or tool in tools:
            raise ValueError('unsupported or repeated tool')
        tools.add(tool)
        version = report.get('version')
        if type(version) is not str or not version or len(version) > 128 or any(ord(c) < 32 for c in version):
            raise ValueError('explicit tool version required')
        config = digest(report.get('configuration_sha256'))
        engine = report.get('engine_source_revision')
        if type(engine) is not str or not re.fullmatch(r'[a-f0-9]{40}', engine):
            raise ValueError('immutable engine source revision required')
        package = digest(report.get('package_sha256'))
        detector = digest(report.get('detector_sha256')) if tool == 'websec' else None
        if report.get('scope_sha256') != scope_sha:
            raise ValueError('report scope mismatch')
        mapping = report.get('rules')
        if type(mapping) is not dict or len(mapping) > MAX_ROWS:
            raise ValueError('explicit rule mapping required')
        checked_mapping = {}
        for rule, entry in mapping.items():
            identifier(rule)
            if type(entry) is not dict:
                raise ValueError('invalid rule mapping')
            if entry.get('reviewed') is True:
                checked_mapping[rule] = identifier(entry.get('attack_class'))
        state = report.get('status')
        if state not in {'completed', 'partial', 'unavailable'}:
            raise ValueError('invalid capture status')
        summary = {'tool': tool, 'version': version, 'configuration_sha256': config,
                   'engine_source_revision': engine, 'package_sha256': package, 'detector_sha256': detector,
                   'rule_mapping_sha256': sha(json.dumps(mapping, sort_keys=True, separators=(',', ':')).encode()),
                   'status': state, 'report_sha256': None, 'counts': None, 'precision': None,
                   'reviewed_positive_label_hits': None, 'reviewed_positive_label_coverage': None}
        summaries.append(summary)
        if state == 'unavailable':
            continue
        try:
            doc, raw_sha = read_json(base, report.get('report'))
            if raw_sha != digest(report.get('report_sha256')):
                raise ValueError('report digest mismatch')
            summary['report_sha256'] = raw_sha
            rows, partial = observed(tool, doc)
        except (OSError, ValueError, TypeError, RecursionError):
            summary['status'] = 'malformed'
            summary['reason'] = 'unusable report or byte binding'
            continue
        if partial:
            summary['status'] = 'partial'
        counts, hits = {'tp': 0, 'fp': 0, 'unknown': 0}, set()
        for number, (rule, file, line) in enumerate(rows, 1):
            attack = checked_mapping.get(rule)
            matches = index.get((file, line, attack), []) if file in scope else []
            decisions = {label['real'] for label in matches}
            outcome = 'unknown' if len(decisions) != 1 else 'tp' if True in decisions else 'fp'
            counts[outcome] += 1
            label_ids = sorted(label['id'] for label in matches) if outcome != 'unknown' else []
            if outcome == 'tp':
                hits.update(label_ids)
            findings.append({'tool': tool, 'ordinal': number, 'rule': rule, 'file': file,
                             'line': line, 'attack_class': attack, 'outcome': outcome, 'label_ids': label_ids})
        summary['counts'] = counts
        summary['reviewed_positive_label_hits'] = len(hits)
        if summary['status'] == 'completed':
            denominator = counts['tp'] + counts['fp']
            summary['precision'] = counts['tp'] / denominator if denominator else None
            summary['reviewed_positive_label_coverage'] = len(hits) / len(positives) if positives else None
    return {'schema_version': 1, 'corpus_revision': revision, 'scope_sha256': scope_sha,
            'grading_manifest_sha256': sha(json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()),
            'labels_sha256': labels_sha, 'provenance_assurance': 'operator-declared captures; byte-bound only',
            'reviewed_positive_labels': len(positives), 'tools': summaries, 'findings': findings,
            'limitations': ['No general vulnerability recall or agent-benefit measurement.',
                            'Unknown findings are excluded from TP/FP; partial captures have no precision score.',
                            'Rule and label review claims are operator-declared, not authenticated.']}


def csv_text(result):
    output = io.StringIO(newline='')
    writer = csv.writer(output)
    fields = ['tool', 'ordinal', 'rule', 'file', 'line', 'attack_class', 'outcome', 'label_ids']
    writer.writerow(fields)
    for finding in result['findings']:
        row = dict(finding, label_ids=';'.join(finding['label_ids']))
        values = []
        for field in fields:
            value = '' if row[field] is None else str(row[field])
            values.append("'" + value if value.startswith(('=', '+', '-', '@', '\t', '\r')) else value)
        writer.writerow(values)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('--out', type=Path, required=True, help='operator-selected output directory')
    args = parser.parse_args()
    try:
        manifest, manifest_sha = read_json(args.manifest.parent, args.manifest.name, 1024 * 1024)
        result = compare(args.manifest.parent, manifest)
        result['capture_manifest_sha256'] = manifest_sha
        # Validate both destinations before any publication. Explicit base aliases remain permitted.
        checked_path(args.out, 'comparison.json')
        checked_path(args.out, 'findings.csv')
        write_text(args.out, 'comparison.json', json.dumps(result, indent=2) + '\n')
        write_text(args.out, 'findings.csv', csv_text(result))
    except (OSError, ValueError, TypeError, RecursionError):
        parser.exit(2, 'comparison: invalid manifest or contained artifact; no raw source/error text emitted\n')
    print('Captured-report comparison written; capture provenance is operator-declared, not a tool execution.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
