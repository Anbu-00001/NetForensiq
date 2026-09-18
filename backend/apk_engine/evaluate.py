"""
Measure every signal over labelled corpora.

    python -m apk_engine evaluate --benign DIR... --malicious DIR... [--description TEXT]
        Writes data/baselines.json (or --out) from this corpus.

    python -m apk_engine evaluate --benign DIR... --malicious DIR... --check
        Does not write. Reports the tiers these apps receive under the baselines
        already in force — the held-out test.

Why both modes exist
====================
Baselines are measured on a corpus, and a signal is validated if it fired on
none of that corpus's legitimate apps. Re-examining the *same* apps afterwards
must therefore give zero legitimate apps at tier 2 or above, by construction —
that number would prove nothing, and this tool says so rather than print it as
an accuracy figure (the data-snooping and base-rate pitfalls in Arp et al.).
A false-positive rate is only measured by ``--check`` on apps that were not
used to build the baselines.

Each sample is examined through the real command line in its own process, the
same path the web application uses, so the measurement includes the isolation
and anything that goes wrong in it.
"""

import concurrent.futures
import datetime
import json
import os
import subprocess
import sys

from . import ENGINE_VERSION, baselines as baseline_store
from .engine import signals
from .stats import upper_bound
from .verdict import decide

TIMEOUT_SECONDS = 900

# One sample at a time by default, each under a hard memory limit. androguard's
# cross-reference analysis needs roughly 0.1 GB per MB of DEX (Flipkart: 29.7 MB
# of DEX, 2.93 GB peak). Three large apps in parallel with no limit exhausted a
# 15 GB workstation during development and froze it; a sample that exceeds the
# limit now fails on its own and is recorded as not examined.
DEFAULT_MEMORY_MB = 6144


def _collect(directories, label):
    files = []
    for directory in directories:
        for root, _dirs, names in os.walk(directory):
            for name in sorted(names):
                if name.lower().endswith('.apk'):
                    files.append((os.path.join(root, name), label))
    return files


def _run(path, memory_mb=DEFAULT_MEMORY_MB):
    backend = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        completed = subprocess.run(
            [sys.executable, '-m', 'apk_engine', 'examine', '--apk', path,
             '--max-memory-mb', str(memory_mb), '--max-cpu-seconds', str(TIMEOUT_SECONDS + 60)],
            capture_output=True, timeout=TIMEOUT_SECONDS, cwd=backend,
            env={'PATH': os.environ.get('PATH', ''), 'PYTHONPATH': backend,
                 'APK_ENGINE_BASELINES': os.environ.get('APK_ENGINE_BASELINES', '')})
        return json.loads(completed.stdout)
    except Exception as exc:
        return {'failed': f'{type(exc).__name__}: {exc}'}


def _retier(report, baselines):
    for finding in (report.get('integrity') or {}).get('findings', []):
        finding['baseline'] = baseline_store.status(baselines, finding['id'])
    for behaviour in report.get('behaviours') or []:
        behaviour['baseline'] = baseline_store.status(baselines, behaviour['id'])
    examined_code = bool((report.get('code') or {}).get('dex_files')) or \
        bool((report.get('code') or {}).get('no_code'))
    examined_manifest = bool((report.get('identity') or {}).get('package'))
    return decide(report.get('integrity'), report.get('behaviours') or [],
                  report.get('intel'), examined_code, examined_manifest)


def evaluate(benign_dirs, malicious_dirs, out=None, jobs=1, description='', check=False,
             memory_mb=DEFAULT_MEMORY_MB):
    corpus = _collect(benign_dirs, 'benign') + _collect(malicious_dirs, 'malicious')
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(jobs, 1)) as pool:
        futures = {pool.submit(_run, path, memory_mb): (path, label) for path, label in corpus}
        for future in concurrent.futures.as_completed(futures):
            path, label = futures[future]
            report = future.result()
            results.append((path, label, report))
            status = report.get('failed') or report.get('assessment', {}).get('label', '?')
            print(f'  {label:9s} {os.path.basename(path)[:48]:48s} {status}', file=sys.stderr)

    examined = [(p, l, r) for p, l, r in results if 'failed' not in r
                and (r.get('assessment') or {}).get('tier', 0) > 0]
    failures = [{'file': os.path.basename(p), 'label': l,
                 'reason': r.get('failed') or '; '.join(r.get('errors', [])[:2])}
                for p, l, r in results if (p, l, r) not in examined]

    counts = {'benign': 0, 'malicious': 0}
    fired = {}
    manifest = []
    for path, label, report in examined:
        counts[label] += 1
        name = (report.get('identity') or {}).get('package') or os.path.basename(path)
        manifest.append({'sha256': report['file']['sha256'], 'label': label, 'name': name})
        for signal_id, on in signals(report).items():
            record = fired.setdefault(signal_id, {'benign_fired': 0, 'malicious_fired': 0,
                                                  'benign_examples': []})
            if on:
                record[f'{label}_fired'] += 1
                if label == 'benign' and len(record['benign_examples']) < 10:
                    record['benign_examples'].append(name)

    if check:
        baselines = baseline_store.load()
    else:
        baselines = {
            'measured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
            'engine_version': ENGINE_VERSION,
            'corpus': {'benign': counts['benign'], 'malicious': counts['malicious'],
                       'description': description, 'manifest': sorted(manifest, key=lambda m: m['name']),
                       'not_examined': failures},
            'signals': dict(sorted(fired.items())),
        }
        path = out or baseline_store.DEFAULT_PATH
        with open(path, 'w', encoding='utf-8') as handle:
            json.dump(baselines, handle, indent=1)
        print(f'\nWrote {path}', file=sys.stderr)

    tiers = {'benign': {}, 'malicious': {}}
    for path, label, report in examined:
        assessment = _retier(report, baselines)
        tiers[label].setdefault(assessment['tier'], []).append(
            (report.get('identity') or {}).get('package') or os.path.basename(path))

    _print_summary(counts, fired, tiers, failures, check)
    return baselines


def _print_summary(counts, fired, tiers, failures, check):
    n_b, n_m = counts['benign'], counts['malicious']
    print(f'\nExamined: {n_b} legitimate, {n_m} malicious. Not examined: {len(failures)}.')
    for failure in failures:
        print(f'  not examined: {failure["label"]} {failure["file"]} — {failure["reason"][:120]}')
    print('\n| Signal | Legitimate apps | 95% upper bound | Malicious apps | Legitimate examples |')
    print('|---|---|---|---|---|')
    for signal_id, record in sorted(fired.items()):
        bound = upper_bound(record['benign_fired'], n_b)
        bound_text = f'{bound:.1%}' if bound is not None else '—'
        print(f"| `{signal_id}` | {record['benign_fired']} / {n_b} | {bound_text} | "
              f"{record['malicious_fired']} / {n_m} | {', '.join(record['benign_examples'][:4])} |")
    print('\nTiers:')
    for label in ('benign', 'malicious'):
        for tier in sorted(tiers[label], reverse=True):
            names = tiers[label][tier]
            print(f'  {label:9s} tier {tier}: {len(names)}  {", ".join(names[:6])}')
    if not check:
        print('\nThese tiers are in-sample: the legitimate apps above produced the baselines, so '
              'none of them can reach tier 2 or 3 by construction. That is not a false-positive '
              'rate. Measure one with --check on apps that were not in this corpus.')
