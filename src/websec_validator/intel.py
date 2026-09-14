"""Explicit public-feed refresh; all consumers are offline. No project data is uploaded."""
from __future__ import annotations

import copy
from contextlib import contextmanager
import csv
import gzip
import hashlib
import io
import json
import math
import os
import re
import stat
import tempfile
import time
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .extractors.base import read_artifact

EPSS_URL = 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'
KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
MAX_DOWNLOAD = 40 * 1024 * 1024
MAX_EXPANDED = 128 * 1024 * 1024
FRESH_DAYS = 7
_LOCK_WAIT_SECONDS = 2.0
_CVE = re.compile(r'CVE-\d{4}-\d{4,}')
_HOSTS = {'epss.empiricalsecurity.com', 'www.cisa.gov', 'github.com', 'raw.githubusercontent.com',
          'objects.githubusercontent.com', 'release-assets.githubusercontent.com'}


def cache_path(cache_dir=None):
    return Path(cache_dir or os.environ.get('WEBSEC_ENRICH_DIR') or
                Path(os.environ.get('XDG_CACHE_HOME', Path.home() / '.cache')) / 'websec')


def _now(now=None):
    return now or datetime.now(timezone.utc)


def _hash(value):
    return hashlib.sha256(value).hexdigest()


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _url(url):
    parsed = urlsplit(url)
    if parsed.scheme != 'https' or parsed.hostname not in _HOSTS or parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ValueError('feed redirect is outside the allowed HTTPS publishers')


class _Redirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url):
    _url(url)
    deadline = time.monotonic() + 60
    with build_opener(_Redirect()).open(Request(url, headers={'User-Agent': 'websec-validator/intel',
                                                            'Accept-Encoding': 'identity'}), timeout=20) as response:
        _url(response.geturl())
        chunks, size = [], 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('feed absolute read deadline exceeded')
            chunk = response.read1(min(65536, MAX_DOWNLOAD + 1 - size))
            if not chunk:
                break
            chunks.append(chunk); size += len(chunk)
            if size > MAX_DOWNLOAD:
                raise ValueError('feed download exceeds size limit')
        data = b''.join(chunks)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError('feed download exceeds size limit')
    return data


def _date(value, today):
    if not isinstance(value, str):
        raise ValueError('missing feed date')
    if len(value) > 10:
        datetime.fromisoformat(value.replace('Z', '+00:00'))
    parsed = date.fromisoformat(value[:10])
    if parsed > today:
        raise ValueError('feed date is in the future')
    return parsed.isoformat()


def _prob(value):
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError('EPSS probability/percentile outside [0,1]')
    return value


def parse_epss(raw, today):
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError('EPSS download exceeds limit')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as compressed:
        content = compressed.read(MAX_EXPANDED + 1)
    if len(content) > MAX_EXPANDED:
        raise ValueError('EPSS decompression exceeds limit')
    text = content.decode('utf-8-sig')
    comments = '\n'.join(line for line in text.splitlines() if line.startswith('#'))
    score = re.search(r'score_date\s*:\s*(\d{4}-\d{2}-\d{2})', comments)
    model = re.search(r'model_version\s*:\s*([^,\s]+)', comments)
    if not score or not model:
        raise ValueError('EPSS missing score_date/model_version')
    model_date = re.search(r'(\d{4})[.-](\d{2})[.-](\d{2})', model[1])
    if not model_date:
        raise ValueError('EPSS model version lacks date')
    metadata = {'feed_date': _date(score[1], today), 'model_version': model[1],
                'model_date': _date('-'.join(model_date.groups()), today)}
    if metadata['model_date'] > metadata['feed_date']:
        raise ValueError('EPSS model date is after its score date')
    reader = csv.DictReader(line for line in text.splitlines() if not line.startswith('#'))
    if reader.fieldnames != ['cve', 'epss', 'percentile']:
        raise ValueError('unexpected EPSS columns')
    rows = {}
    for row in reader:
        cve = row.get('cve', '')
        if not _CVE.fullmatch(cve) or cve in rows or None in row:
            raise ValueError('invalid or duplicate EPSS CVE')
        rows[cve] = [_prob(row['epss']), _prob(row['percentile'])]
    if not rows:
        raise ValueError('empty EPSS feed')
    return rows, metadata


def parse_kev(raw, today):
    if len(raw) > MAX_DOWNLOAD:
        raise ValueError('KEV download exceeds limit')
    data = json.loads(raw)
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('invalid KEV feed shape')
    rows = data['vulnerabilities']
    if not rows or type(data.get('count')) is not int or data['count'] != len(rows) or not data.get('catalogVersion'):
        raise ValueError('KEV catalog count/version missing or inconsistent')
    out = {}
    for row in rows:
        if not isinstance(row, dict) or not _CVE.fullmatch(row.get('cveID', '')) or row['cveID'] in out:
            raise ValueError('invalid or duplicate KEV CVE')
        out[row['cveID']] = {'date_added': _date(row.get('dateAdded'), today)}
    return out, {'feed_date': _date(data.get('dateReleased'), today), 'published_at': data['dateReleased'],
                 'catalog_version': data['catalogVersion']}


def _atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.intel-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(_encoded(value)); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextmanager
def _publication_lock(root):
    """OS advisory lock; process exit releases it. The inert lock file may remain after a crash."""
    root.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(root / 'refresh.lock', os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('refresh lock must be a regular file')
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b'0')
        if os.name == 'nt':
            import msvcrt
            def acquire():
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            def acquire():
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        deadline = time.monotonic() + _LOCK_WAIT_SECONDS
        while True:
            try:
                acquire()
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('another refresh is publishing; retry later') from None
                time.sleep(min(.05, max(0, deadline - time.monotonic())))
        yield
    finally:
        os.close(descriptor)


def _source_time(source):
    if not isinstance(source, dict):
        return None
    value = source.get('published_at') or source.get('feed_date')
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (ValueError, TypeError, AttributeError):
        return None


def _older_sources(candidate, previous):
    """Compare each publisher independently; a newer EPSS file cannot mask older KEV data."""
    if not isinstance(previous, dict):
        return []
    older = []
    for key in ('epss', 'kev'):
        before, after = _source_time(previous.get(key)), _source_time(candidate.get(key))
        if before is not None and after is not None and after < before:
            older.append(key)
    return older


def refresh(cache_dir=None, *, fetcher=None, now=None):
    """Explicit download, then serialized compare-and-publish; older feed dates never replace newer ones."""
    root, clock = cache_path(cache_dir), _now(now)
    fetcher = fetcher or _fetch
    try:
        epss_raw, kev_raw = fetcher(EPSS_URL), fetcher(KEV_URL)
        epss, ep_meta = parse_epss(epss_raw, clock.date())
        kev, kev_meta = parse_kev(kev_raw, clock.date())
        body = {'schema_version': '1.0', 'retrieved_at': clock.isoformat(), 'epss': epss, 'kev': kev,
                'sources': {'epss': {'url': EPSS_URL, 'sha256': _hash(epss_raw), **ep_meta},
                            'kev': {'url': KEV_URL, 'sha256': _hash(kev_raw), **kev_meta}}}
        # Identical downloaded feeds reuse a semantic snapshot ID; retrieval time is metadata only.
        snapshot_id = _hash(_encoded({k: v for k, v in body.items() if k != 'retrieved_at'}))
        body['snapshot_id'] = snapshot_id
        with _publication_lock(root):
            previous = load_snapshot(root, now=clock)
            older = _older_sources(body['sources'], previous.get('sources', {}) if previous else {})
            if older:
                raise ValueError('older public feed rejected: ' + ', '.join(older))
            _atomic(root / 'snapshots' / (snapshot_id + '.json'), body)
            _atomic(root / 'current.json', {'snapshot_id': snapshot_id})
            _atomic(root / 'last-refresh.json', {'outcome': 'success', 'attempted_at': clock.isoformat(), 'snapshot_id': snapshot_id})
    except Exception as error:
        # Error type avoids reflecting URLs containing unexpected credentials or raw feed content.
        _atomic(root / 'last-refresh.json', {'outcome': 'failed', 'attempted_at': clock.isoformat(),
                                           'error': type(error).__name__, 'reason': 'feed-rollback' if 'older' in locals() and older else 'download-validation-or-publication',
                                           'detail': 'public feed download, validation or snapshot publication failed; last valid snapshot retained'})
    result = status(root, now=clock)
    result["network_used"] = fetcher is _fetch
    return result


def _read(path, limit=MAX_EXPANDED * 2):
    return json.loads(read_artifact(path, max_bytes=limit))


def _valid_snapshot(body, now=None):
    """Revalidate local data, not just its self-declared content hash. This is not a signature."""
    if not isinstance(body, dict) or body.get('schema_version') != '1.0':
        return False
    today = _now(now).date()
    retrieved = datetime.fromisoformat(body['retrieved_at'])
    if retrieved.tzinfo is None or retrieved.date() > today:
        return False
    sources = body['sources']
    if not isinstance(sources, dict) or set(sources) != {'epss', 'kev'}:
        return False
    for key, url in (('epss', EPSS_URL), ('kev', KEV_URL)):
        row = sources[key]
        if row.get('url') != url or not re.fullmatch(r'[a-f0-9]{64}', row.get('sha256', '')):
            return False
        _date(row['feed_date'], today)
        if 'published_at' in row and _date(row['published_at'], today) != row['feed_date']:
            return False
    _date(sources['epss']['model_date'], today)
    version = sources['epss'].get('model_version')
    if not isinstance(version, str):
        return False
    model_date = re.search(r'(\d{4})[.-](\d{2})[.-](\d{2})', version)
    if not model_date or '-'.join(model_date.groups()) != sources['epss']['model_date']:
        return False
    if sources['epss']['model_date'] > sources['epss']['feed_date']:
        return False
    if not isinstance(sources['kev'].get('catalog_version'), str) or not sources['kev']['catalog_version']:
        return False
    for key in ('epss', 'kev'):
        if not isinstance(body.get(key), dict) or not body[key]:
            return False
        for cve, value in body[key].items():
            if not _CVE.fullmatch(cve):
                return False
            if key == 'epss':
                if not isinstance(value, list) or len(value) != 2 or any(type(v) not in (int, float) for v in value):
                    return False
                for v in value:
                    _prob(v)
            else:
                _date(value['date_added'], today)
    return True


def load_snapshot(cache_dir=None, *, now=None):
    root = cache_path(cache_dir)
    try:
        pointer = _read(root / 'current.json', 4096)
        sid = pointer.get('snapshot_id', '')
        if not isinstance(sid, str) or not re.fullmatch(r'[a-f0-9]{64}', sid):
            return None
        body = _read(root / 'snapshots' / (sid + '.json'))
        actual = _hash(_encoded({k: v for k, v in body.items() if k not in {'snapshot_id', 'retrieved_at'}}))
        return body if body.get('snapshot_id') == sid == actual and _valid_snapshot(body, now=now) else None
    except (OSError, ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return None


def status(cache_dir=None, *, now=None):
    root, clock = cache_path(cache_dir), _now(now)
    snapshot = load_snapshot(root, now=clock)
    try:
        last = _read(root / 'last-refresh.json', 8192)
        if not isinstance(last, dict):
            raise ValueError('invalid refresh record')
    except (OSError, ValueError):
        last = {'outcome': 'never-or-unreadable'}
    result = {'available': bool(snapshot), 'last_refresh': last, 'freshness_days': FRESH_DAYS,
              'network_used': False, 'integrity_basis': 'Local content hash; HTTPS transport and schema checked on refresh, not a publisher signature.', 'legacy_cache_present': (root / 'epss.csv').exists() or (root / 'kev.json').exists()}
    if snapshot:
        ages = {key: (clock.date() - date.fromisoformat(row['feed_date'])).days for key, row in snapshot['sources'].items()}
        result.update(snapshot_id=snapshot['snapshot_id'], sources=snapshot['sources'], retrieved_at=snapshot['retrieved_at'],
                      age_days=ages, freshness='stale' if max(ages.values()) > FRESH_DAYS else 'fresh', provenance='validated-public-feed-snapshot')
    else:
        result.update(freshness='unavailable', provenance='legacy-unverified' if result['legacy_cache_present'] else 'none')
    return result


def cve_id(finding):
    for value in (finding.get('cve'), finding.get('key'), finding.get('title')):
        match = re.search(r'\bCVE-\d{4}-\d{4,}\b', str(value or ''), re.I)
        if match:
            return match[0].upper()
    return ''


def reassess(ledger, cache_dir=None, *, now=None):
    """Re-evaluate known CVEs only, preserving finding identity and source analysis evidence."""
    if not isinstance(ledger, dict) or any(not isinstance(ledger.get(key, []), list) or
            any(not isinstance(row, dict) for row in ledger.get(key, [])) for key in ('findings', 'acknowledged')):
        raise ValueError('ledger findings and acknowledged must contain finding objects')
    if any(not isinstance(ledger.get(key, {}), dict) for key in ('metadata', 'coverage')):
        raise ValueError('ledger metadata and coverage must be objects')
    result, events = copy.deepcopy(ledger), []
    snapshot, report = load_snapshot(cache_dir, now=now), status(cache_dir, now=now)
    limitation = 'Known CVEs only: discovering new dependency CVEs requires an inventory/advisory rescan. Synthetic or feed changes do not prove exploitability.'
    if not snapshot:
        return {'ledger': result, 'events': [], 'intel': report, 'limitations': [limitation]}
    sid = snapshot['snapshot_id']
    from .coverage import detector_revision
    current_revision = detector_revision()
    previous_revision = result.get('metadata', {}).get('reassessment_detector_revision') or result.get('coverage', {}).get('detector_revision')
    if previous_revision and previous_revision != current_revision:
        events.append({'event_id': _hash(_encoded(['detector', current_revision, previous_revision])),
                       'kind': 'detector-changed-rescan-required', 'previous': previous_revision,
                       'current': current_revision, 'limitation': 'No source checks were rerun during reassessment.'})
    result.setdefault('metadata', {})['reassessment_detector_revision'] = current_revision
    acknowledged = result.get('acknowledged', [])
    reopened, blocked, applied = [], [], 0
    for finding in result.get('findings', []) + acknowledged:
        cve = cve_id(finding)
        if not cve:
            continue
        # Neither provenance layer can erase the other's chronology. Incomplete
        # imported evidence has unknown age, so preserve it for explicit review.
        layers = [('ledger', result.get('metadata', {}).get('intel')),
                  ('finding', finding.get('intel'))]
        older, invalid = set(), []
        old_intel = {}
        for name, provenance in layers:
            if provenance is None:
                continue
            sources = provenance.get('sources') if isinstance(provenance, dict) else None
            if (not isinstance(sources, dict)
                    or any(_source_time(sources.get(key)) is None for key in ('epss', 'kev'))):
                invalid.append(name)
                continue
            older.update(_older_sources(snapshot['sources'], sources))
            old_intel = provenance
        if older or invalid:
            blocked.append({'finding_id': finding.get('fingerprint') or finding.get('id') or cve,
                            'reason': ('existing intelligence provenance is incomplete or malformed' if invalid else
                                       'candidate snapshot is older than existing finding evidence'),
                            'sources': sorted(older), 'invalid_provenance': invalid})
            continue
        applied += 1
        previous = {key: finding.get(key) for key in ('epss', 'epss_pct', 'kev', 'intel_status')}
        finding['kev'] = cve in snapshot['kev']
        if cve in snapshot['epss']:
            finding['epss'], finding['epss_pct'] = snapshot['epss'][cve]
        else:
            finding.pop('epss', None); finding.pop('epss_pct', None)
        finding['intel_status'] = 'listed' if cve in snapshot['epss'] or finding['kev'] else 'not-listed (not evidence of safety)'
        old_sid = old_intel.get('snapshot_id')
        finding['intel'] = report
        # Preserve acceptance history while reopening newly exploited or newly high-EPSS debt.
        old_probability = previous['epss'] if type(previous['epss']) in (int, float) and math.isfinite(previous['epss']) else 0
        increased = (finding['kev'] and previous['kev'] is not True) or (finding.get('epss', 0) >= .5 and old_probability < .5)
        if any(finding is row for row in acknowledged) and increased:
            finding.update(status='open', state='reopened', needs_review=True,
                           reopened_reason='Threat intelligence increased: review prior risk acceptance')
            finding['previous_acknowledgement'] = copy.deepcopy(finding.get('acknowledgement', {'reason': finding.get('ack_reason')}))
            reopened.append(finding)
        if old_sid != sid:
            for key in previous:
                if previous[key] != finding.get(key):
                    kind = 'newly-exploited' if key == 'kev' and finding['kev'] else key + '-changed'
                    identity = finding.get('fingerprint') or finding.get('id') or cve
                    events.append({'event_id': _hash(_encoded([identity, sid, kind])), 'finding_id': identity,
                                   'kind': kind, 'previous': previous[key], 'current': finding.get(key), 'snapshot_id': sid})
    if reopened:
        result.setdefault('findings', []).extend(reopened)
        result['acknowledged'] = [row for row in acknowledged if not any(row is item for item in reopened)]
        result['acknowledged_n'] = len(result['acknowledged'])
        result['total'] = len(result['findings'])
        for field, key in (('by_severity', 'severity'), ('by_confidence', 'confidence')):
            if field in result:
                result[field] = {}
                for row in result['findings']:
                    value = row.get(key, 'UNKNOWN')
                    result[field][value] = result[field].get(value, 0) + 1
    result.setdefault('metadata', {})['intel_reassessment'] = {'candidate': report, 'applied_findings': applied, 'blocked': blocked}
    if not blocked:
        result['metadata']['intel'] = report
    return {'ledger': result, 'events': events, 'intel': report, 'limitations': [limitation],
            'applied_findings': applied, 'blocked_findings': len(blocked), 'warnings': blocked}
