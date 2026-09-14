"""Evaluate data-only synthetic proposals with an allowlist of shipped detectors."""
from __future__ import annotations

import hashlib
import json
import tempfile
from datetime import date
from importlib import resources
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

from .coverage import detector_revision
from .extractors.base import RepoContext, is_test_file, is_script_file
from .extractors.surface import SurfaceExtractor
from .extractors.integrations import IntegrationsExtractor
from .extractors.upload_security import UploadSecurityExtractor
from .extractors.crypto_usage import CryptoUsageExtractor

DETECTORS = {'surface:ssrf': 'ssrf', 'surface:xss': 'xss', 'surface:command-injection': 'command-injection',
             'integrations:webhook-signature': 'webhooks_without_sig_verification',
             'upload:client-mime': 'upload-trusts-client-mime', 'crypto:password-hash': 'weak-password-hash'}
LIMITATION = ('Synthetic development and holdout cases are authored regression evidence, not blind real-project validation. '
              'Content separation does not establish independent design or production superiority. Promotion means eligible for human review only.')
SUITES = ('control-scope',)


def example():
    data = json.loads(resources.files('websec_validator').joinpath('research/example.json').read_text())
    data['proposal']['detector_revision'] = detector_revision()
    return data


def control_scope_cases():
    """Original shipped regression proposals; never download or execute fixture source."""
    data = json.loads(resources.files('websec_validator').joinpath('research/control-scope-cases.json').read_text())
    for group in data:
        group['proposal']['detector_revision'] = detector_revision()
    return data


def _suite_cases(name):
    # Names select shipped data only, never caller paths, imports, or commands.
    if name != 'control-scope':
        raise ValueError('unknown shipped research suite')
    return control_scope_cases()


def catalog():
    """List supported shipped suites without evaluating or activating detectors."""
    suites = []
    for name in SUITES:
        groups = _suite_cases(name)
        suites.append({'id': name, 'proposals': [
            {'id': group['proposal']['id'], 'detector': group['proposal']['detector'],
             'cases': len(group['cases'])} for group in groups],
            'proposal_count': len(groups), 'case_count': sum(len(group['cases']) for group in groups)})
    return {'schema_version': '1.0', 'suites': suites, 'detector_revision': detector_revision(),
            'installed': False, 'source_executed': False, 'limitation': LIMITATION}


def evaluate_suite(name):
    """Evaluate every proposal in one shipped suite, retaining individual verdicts."""
    revision = detector_revision()
    groups = _suite_cases(name)
    results = [evaluate(group['proposal'], group['cases']) for group in groups]
    metrics = {part: {key: 0 for key in ('TP', 'FN', 'TN', 'FP', 'unknown', 'samples')}
               for part in ('development', 'holdout')}
    errors = []
    if not results:
        errors.append('suite has no proposals')
    for result in results:
        for part, counts in metrics.items():
            for key in counts:
                counts[key] += result['metrics'][part][key]
        if result['promotion_eligible'] is not True:
            errors.append('proposal rejected: ' + str(result['proposal_id']))
        errors.extend(str(result['proposal_id']) + ': ' + error for error in result['errors'])
        if result['detector_revision'] != revision:
            errors.append('detector revision changed during suite evaluation')
    if detector_revision() != revision:
        errors.append('detector revision changed during suite evaluation')
    return {'schema_version': '1.0', 'suite_id': name, 'detector_revision': revision,
            'proposal_count': len(results), 'case_count': sum(part['samples'] for part in metrics.values()),
            'metrics': metrics, 'proposals': results, 'errors': sorted(set(errors)),
            'promotion_eligible': not errors,
            'promotion_state': 'eligible-for-human-review' if not errors else 'rejected',
            'installed': False, 'source_executed': False, 'limitation': LIMITATION}


def _route_inventory(case, detector_name):
    routes = case.get('route_inventory', [])
    if detector_name != 'integrations:webhook-signature':
        return [] if routes == [] else None
    if not isinstance(routes, list) or not 1 <= len(routes) <= 20:
        return None
    for row in routes:
        if (not isinstance(row, dict) or set(row) != {'method', 'path', 'file'}
                or not isinstance(row['method'], str) or row['method'] not in {'POST', 'PUT', 'PATCH', 'DELETE', 'GET', 'HEAD'}
                or not isinstance(row['path'], str) or not row['path'].startswith('/') or len(row['path']) > 512
                or any(ord(char) < 32 for char in row['path'])
                or not isinstance(row['file'], str) or row['file'] not in case['files']):
            return None
    return routes


def _detected(context, detector_name, detector, routes):
    if detector_name.startswith('surface:'):
        return bool(SurfaceExtractor().extract(context, {'stack': {}}).get('sinks', {}).get(detector))
    if detector_name == 'integrations:webhook-signature':
        facts = {'routes': {'endpoints': [{'method': row['method'], 'path': row['path'],
                                         'code_path': str(context.root / row['file'])} for row in routes]}}
        return bool(IntegrationsExtractor().extract(context, facts).get(detector))
    extractor = UploadSecurityExtractor() if detector_name == 'upload:client-mime' else CryptoUsageExtractor()
    return any(row.get('kind') == detector for row in extractor.extract(context, {})['findings'])


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _metadata(proposal):
    errors = []
    if not isinstance(proposal, dict):
        return ['proposal must be an object']
    for key in ('id', 'version', 'primary_source', 'source_date', 'provenance', 'license', 'affected_ecosystem',
                'prerequisites', 'remediation', 'detector_revision'):
        value = proposal.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 8192:
            errors.append('missing or invalid metadata: ' + key)
    try:
        source = urlsplit(str(proposal.get('primary_source', '')))
        if source.scheme != 'https' or not source.hostname or source.username or source.password:
            errors.append('primary_source must be HTTPS; attribution still requires human review')
    except ValueError:
        errors.append('invalid primary_source URL')
    try:
        if date.fromisoformat(proposal.get('source_date', '')) > date.today():
            errors.append('source_date is in the future')
    except (TypeError, ValueError):
        errors.append('invalid source_date')
    if proposal.get('detector_revision') != detector_revision():
        errors.append('detector_revision does not match the shipped implementation')
    if not isinstance(proposal.get('detector'), str) or proposal.get('detector') not in DETECTORS:
        errors.append('detector is not in the shipped allowlist')
    if proposal.get('schema_version') != '1.0':
        errors.append('unsupported proposal schema_version')
    for key in ('command', 'code', 'template', 'install', 'script'):
        if key in proposal:
            errors.append('executable proposal field prohibited: ' + key)
    return errors


def evaluate(proposal, cases):
    """Source is only written into disposable fixtures and read as text; never imported or executed."""
    errors = _metadata(proposal)
    metrics = {part: {key: 0 for key in ('TP', 'FN', 'TN', 'FP', 'unknown', 'samples')} for part in ('development', 'holdout')}
    rows, hashes, ids = [], {}, set()
    if not isinstance(cases, list) or not 1 <= len(cases) <= 100:
        errors.append('cases must contain 1..100 data-only fixtures')
        cases = []
    detector_name = proposal.get('detector') if isinstance(proposal, dict) else None
    detector = DETECTORS.get(detector_name) if isinstance(detector_name, str) else None
    for index, case in enumerate(cases):
        row = {'index': index, 'outcome': 'unknown'}
        rows.append(row)
        if not isinstance(case, dict):
            errors.append('case must be an object'); continue
        part, label, files = case.get('partition'), case.get('label'), case.get('files')
        row.update(id=case.get('id'), partition=part, label=label)
        if not isinstance(part, str) or part not in metrics:
            errors.append('case partition must be development or holdout'); continue
        counter = metrics[part]; counter['samples'] += 1
        if not isinstance(case.get('id'), str) or not case['id'].strip() or case['id'] in ids:
            errors.append('case IDs must be unique strings'); counter['unknown'] += 1; continue
        ids.add(case['id'])
        valid = (label in ('safe', 'vulnerable') and isinstance(files, dict) and 1 <= len(files) <= 10)
        if valid:
            for name, source in files.items():
                if not isinstance(name, str) or not name or is_test_file(name) or is_script_file(name):
                    valid = False; break
                path = PurePosixPath(name)
                if (not isinstance(source, str) or not source.strip() or len(source.encode()) > 65536 or path.is_absolute()
                        or '..' in path.parts or '\\' in name or path.suffix not in {'.py', '.js', '.ts'}):
                    valid = False
        routes = _route_inventory(case, detector_name) if valid else None
        if not valid or detector is None or routes is None:
            counter['unknown'] += 1; errors.append('invalid or unsupported case'); continue
        # Ignore path/whitespace changes when detecting copied fixtures across partitions.
        content_hash = _hash('\n'.join(sorted(''.join(source.split()) for source in files.values())))
        row['content_hash'] = content_hash
        if content_hash in hashes:
            errors.append('duplicate case content; development and holdout must be disjoint')
        hashes[content_hash] = part
        try:
            with tempfile.TemporaryDirectory(prefix='websec-research-') as directory:
                root = Path(directory)
                for name, source in files.items():
                    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_text(source)
                context = RepoContext(root, include_fixtures=True)
                detected = _detected(context, detector_name, detector, routes)
                if context.unreadable or context.oversized or context.truncated or set(context.input_hashes) != set(files):
                    raise ValueError('fixture coverage incomplete')
            outcome = ('TP' if detected else 'FN') if label == 'vulnerable' else ('FP' if detected else 'TN')
            row.update(outcome=outcome, detected=detected); counter[outcome] += 1
        except Exception as error:
            row['error'] = type(error).__name__; counter['unknown'] += 1
    for part, counter in metrics.items():
        if not counter['TP'] or not counter['TN']:
            errors.append(part + ' requires detected vulnerable and clean safe cases')
        if any(counter[k] for k in ('FP', 'FN', 'unknown')):
            errors.append(part + ' has failing or unknown cases')
    return {'schema_version': '1.0', 'proposal_id': proposal.get('id') if isinstance(proposal, dict) else None,
            'detector_revision': detector_revision(), 'metrics': metrics, 'results': rows, 'errors': sorted(set(errors)),
            'promotion_eligible': not errors, 'promotion_state': 'eligible-for-human-review' if not errors else 'rejected',
            'installed': False, 'source_executed': False,
            'metadata_basis': 'Operator-declared provenance; primary-source relevance and licensing require human review.',
            'fixture_route_basis': 'Provided bounded route inventory; route discovery is not evaluated.' if detector_name == 'integrations:webhook-signature' else 'not used',
            'limitation': LIMITATION}
