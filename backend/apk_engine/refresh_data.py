"""
Rebuild the engine's bundled reference data from its published sources.

    python -m apk_engine.refresh_data

Needs a network connection and, for the stalkerware snapshot, PyYAML — so it
runs on a connected build machine, never on the air-gapped workstation, which
receives the resulting files inside the image. Every file written is recorded
in ``data/sources.json`` with where it came from, when, its SHA-256 and its
licence, so an examiner can say exactly which snapshot a match came from.

Licences of what is bundled
===========================
* Exodus Privacy tracker signatures — Open Database License 1.0; contents under
  the Database Contents License 1.0 (github.com/Exodus-Privacy/exodus, README).
  The extracted file is a derivative database and stays under ODbL.
* stalkerware-indicators (Echap) — CC-BY-4.0. Only ``ioc.yaml`` (stalkerware)
  and ``samples.csv`` are taken. ``watchware.yaml`` — parental-monitoring apps —
  is deliberately left out, so a parental-control app is never reported as a
  stalkerware match.
* IANA root-zone TLD list — published by IANA for public use.
"""

import csv
import datetime
import hashlib
import io
import json
import os
import urllib.request

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')

EXODUS_URLS = (
    ('https://reports.exodus-privacy.eu.org/api/trackers', 'Exodus Privacy API'),
    # MobSF redistributes the same API response; used when the API is unreachable.
    ('https://raw.githubusercontent.com/MobSF/Mobile-Security-Framework-MobSF/master/'
     'mobsf/signatures/exodus_trackers', 'Exodus Privacy API response as redistributed by MobSF'),
)
STALKERWARE_REPO = 'AssoEchap/stalkerware-indicators'
TLD_URL = 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt'


def _get(url, timeout=60):
    request = urllib.request.Request(url, headers={'User-Agent': 'NetForensiq-refresh'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _write(name, payload):
    path = os.path.join(DATA_DIR, name)
    with open(path, 'wb') as handle:
        handle.write(payload)
    return hashlib.sha256(payload).hexdigest()


def refresh():
    os.makedirs(DATA_DIR, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
    sources = {}

    # ── Exodus tracker signatures ─────────────────────────────────────────
    raw, via = None, ''
    for url, label in EXODUS_URLS:
        try:
            raw, via = _get(url), f'{label} ({url})'
            json.loads(raw)
            break
        except Exception:
            raw = None
    if raw is None:
        raise SystemExit('Exodus tracker data could not be retrieved from any source.')
    trackers = json.loads(raw)['trackers']
    slim = sorted(({
        'id': t['id'], 'name': t['name'], 'website': t.get('website', ''),
        'categories': t.get('categories', []),
        'code_signature': t.get('code_signature', ''),
        'network_signature': t.get('network_signature', ''),
    } for t in trackers.values()), key=lambda t: t['id'])
    sources['exodus_trackers.json'] = {
        'retrieved': now, 'via': via, 'records': len(slim),
        'licence': 'ODbL-1.0 (contents DbCL-1.0)',
        'attribution': 'Tracker signatures © Exodus Privacy, https://exodus-privacy.eu.org/',
        'sha256': _write('exodus_trackers.json',
                         json.dumps({'trackers': slim}, indent=1, sort_keys=True).encode()),
    }

    # ── stalkerware-indicators, pinned to a commit ────────────────────────
    import yaml  # build-time only

    commit = json.loads(_get(f'https://api.github.com/repos/{STALKERWARE_REPO}/commits/master'))
    sha, committed = commit['sha'], commit['commit']['committer']['date']
    base = f'https://raw.githubusercontent.com/{STALKERWARE_REPO}/{sha}'
    iocs = yaml.safe_load(_get(f'{base}/ioc.yaml'))
    products = [{
        'name': e['name'], 'type': e.get('type', ''),
        'aliases': e.get('names', []),
        'packages': e.get('packages', []),
        'certificates_sha1': [c.upper() for c in e.get('certificates', [])],
        'c2_domains': (e.get('c2') or {}).get('domains', []),
        'c2_ips': (e.get('c2') or {}).get('ips', []),
    } for e in iocs]
    samples = [
        {'sha256': row['SHA256'].lower(), 'package': row['Package Name'],
         'certificate_sha1': (row['Certificate'] or '').upper(), 'product': row['App']}
        for row in csv.DictReader(io.StringIO(_get(f'{base}/samples.csv').decode()))
    ]
    sources['stalkerware_indicators.json'] = {
        'retrieved': now, 'via': f'https://github.com/{STALKERWARE_REPO} at {sha}',
        'upstream_commit_date': committed,
        'records': {'products': len(products), 'samples': len(samples)},
        'licence': 'CC-BY-4.0',
        'attribution': 'Stalkerware indicators © Echap, https://github.com/AssoEchap/stalkerware-indicators',
        'sha256': _write('stalkerware_indicators.json', json.dumps(
            {'products': products, 'samples': samples}, indent=1, sort_keys=True).encode()),
    }

    # ── IANA TLD list ─────────────────────────────────────────────────────
    tlds = _get(TLD_URL)
    sources['tlds.txt'] = {
        'retrieved': now, 'via': TLD_URL, 'version_line': tlds.decode().splitlines()[0],
        'licence': 'IANA public data',
        'sha256': _write('tlds.txt', tlds),
    }

    _write('sources.json', json.dumps(sources, indent=2, sort_keys=True).encode())
    return sources


if __name__ == '__main__':
    print(json.dumps(refresh(), indent=2))
