#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Turn the raw records of the evaluation runs into validation/results.json and
validation/apk_samples.csv — the data the validation report is generated from.

Nothing here is typed in. Every count is derived from a run log and a corpus
manifest that were written when the run happened, and the derivation is checked
against the engine's own tally where the log carries one. A number that cannot
be derived is left out, not estimated.

This is the one script that needs the corpora on disk, so it is a maintainer's
tool: it reads logs and manifests under a local `apk_corpus/` and `mal/` tree
and writes small files into the repository. The report itself
(scripts/build_validation_report.py) needs only the files this writes.

    python scripts/extract_validation_data.py \\
        --analysis ../apk_corpus/analysis --mal ~/26_class/mal \\
        --benign ../apk_corpus/benign

MalwareBazaar's terms ask that samples not be redistributed. Only their SHA-256
digests are written here — identifiers anyone with their own key can use to fetch
the same samples — and none of the contributor names in the manifests.
"""
import argparse
import csv
import hashlib
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Tier numbers, from the engine's own labels (apk_engine/verdict.py). The label
# is what the logs carry.
TIER_OF_LABEL = {
    'Known harmful software': 4,
    'Harmful behaviour demonstrated': 3,
    'Built to evade inspection': 2,
    'Not the application it claims to be': 3,
    'No harmful behaviour established': 1,
    'Could not be examined': 0,
}
LINE = re.compile(r'^  (benign|malicious)\s+(\S+)\s+(.+?)\s*$')


def clopper_pearson(k, n, alpha=0.05):
    """Exact two-sided interval for k successes in n trials, by bisection."""
    def cdf(p, upto):
        return sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(upto + 1))

    def bisect(test, lo=0.0, hi=1.0):
        for _ in range(80):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if test(mid) else (lo, mid)
        return (lo + hi) / 2

    lower = 0.0 if k == 0 else bisect(lambda p: 1 - cdf(p, k - 1) < alpha / 2)
    upper = 1.0 if k == n else bisect(lambda p: cdf(p, k) > alpha / 2)
    return round(lower, 4), round(upper, 4)


def one_sided_upper_zero(n, alpha=0.05):
    """Exact one-sided upper bound when nothing in n fired."""
    return round(1 - alpha ** (1 / n), 4)


TALLY = re.compile(r'^\s+(benign|malicious) tier (\d): (\d+)')


def parse_check_log(path):
    """
    Per-sample verdicts, from the lines before the log's own "Tiers:" summary.

    The summary is not discarded: it is the engine's own tally, and the counts
    derived from the per-sample lines must equal it for every tier it lists
    (it omits tier 0). A disagreement means the parse is wrong and stops the run.
    """
    rows, tally, in_summary = [], {}, False
    for raw in Path(path).read_text(encoding='utf-8', errors='replace').splitlines():
        if raw.startswith('Tiers:'):
            in_summary = True
            continue
        if in_summary:
            match = TALLY.match(raw)
            if match:
                tally[(match.group(1), int(match.group(2)))] = int(match.group(3))
            continue
        match = LINE.match(raw)
        if match:
            side, name, label = match.groups()
            if label not in TIER_OF_LABEL:
                raise SystemExit(f'{path}: unknown tier label {label!r} on {name}')
            rows.append({'side': side, 'name': name, 'label': label,
                         'tier': TIER_OF_LABEL[label]})
    for (side, tier), count in tally.items():
        derived = sum(1 for r in rows if r['side'] == side and r['tier'] == tier)
        if derived != count:
            raise SystemExit(f'{path}: derived {derived} {side} samples at tier {tier}, '
                             f'but the log\'s own summary says {count}')
    return rows


def tier_counts(rows):
    counts = {str(t): 0 for t in range(5)}
    for row in rows:
        counts[str(row['tier'])] += 1
    return counts


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def manifest_hashes(path):
    manifest = json.loads(Path(path).read_text())
    return manifest, [s['sha256'] for s in manifest['samples']]


def map_prefixes(rows, hashes, what):
    """Logs truncate hash-named samples to 48 characters; restore the full digest."""
    by_prefix = {}
    for digest in hashes:
        by_prefix.setdefault(digest[:48], []).append(digest)
    for row in rows:
        stem = row['name'].removesuffix('.apk')
        found = by_prefix.get(stem[:48], [])
        if len(found) != 1:
            raise SystemExit(f'{what}: cannot map {row["name"]!r} to exactly one manifest digest')
        row['sha256'] = found[0]


def summarise(rows, side):
    rows = [r for r in rows if r['side'] == side]
    counts = tier_counts(rows)
    n = len(rows)
    examined = n - counts['0']
    out = {'n': n, 'tiers': counts, 'could_not_be_examined': counts['0'], 'examined': examined}
    flagged = n - counts['0'] - counts['1']
    out['reached_a_tier'] = flagged
    if side == 'malicious':
        out['detected_of_n'] = flagged
        out['detection_rate'] = round(flagged / n, 4) if n else None
        out['ci95'] = clopper_pearson(flagged, n) if n else None
    else:
        out['false_positives'] = flagged
        out['false_positives_of_examined'] = [flagged, examined]
        out['ci95'] = (one_sided_upper_zero(examined) if flagged == 0 and examined else
                       (clopper_pearson(flagged, examined) if examined else None))
        out['ci95_kind'] = ('one-sided upper bound' if flagged == 0 else 'two-sided')
    return out


def preregistration(analysis):
    """
    What the v6 pre-registration (apk_corpus/analysis/PREREGISTRATION.md) said
    would happen to the native-code signals, against what the baseline run found.
    Derived from the merged v6 baseline, not restated.
    """
    merged = json.loads((analysis / 'baseline_v6' / 'baselines_v6_merged.json').read_text())
    corpus = merged['corpus']
    native = {k: v for k, v in merged['signals'].items() if k.startswith('cap.native')}
    zero = {k: v for k, v in native.items() if v['benign_fired'] == 0}
    best = max(zero.items(), key=lambda kv: kv[1]['malicious_fired']) if zero else None
    return {
        'rule_for_use': 'a native signal may raise a tier only if it fired on zero legitimate apps',
        'benign_n': corpus['benign'], 'malicious_n': corpus['malicious'],
        'native_signals_measured': len(native),
        'native_signals_with_zero_benign': len(zero),
        'best_zero_benign_signal': ({'signal': best[0], 'benign_fired': 0,
                                     'malicious_fired': best[1]['malicious_fired']}
                                    if best else None),
        'any_signal_zero_benign_and_20_malicious': any(
            v['benign_fired'] == 0 and v['malicious_fired'] >= 20 for v in native.values()),
        'predictions': [
            {'claim': 'at least one native signal fires on 0 of 201 benign and >= 20 of 200 malicious',
             'probability': 0.70},
            {'claim': 'the blind score reaches >= 70/100', 'probability': 0.35},
            {'claim': 'the blind score reaches the 80/100 target', 'probability': 0.12},
        ],
        'source': 'apk_corpus/analysis/PREREGISTRATION.md, v6 section',
    }


def engine_comparison(samples):
    """
    Where the same corpus was examined by two engine images, how many samples got
    a different tier. The v6 image adds a native-code survey that no rule uses;
    this is the evidence that it changed no verdict.
    """
    by_run = {}
    for row in samples:
        by_run.setdefault(row['run'], {})[row['sha256']] = row['tier']
    out = []
    for older, newer in (('heldout-v5', 'heldout-v6'), ('fresh-benign-v5', 'fresh-benign-v6')):
        if older in by_run and newer in by_run:
            a, b = by_run[older], by_run[newer]
            out.append({'older': older, 'newer': newer, 'compared': len(a),
                        'differing': sum(1 for k in a if a[k] != b.get(k))})
    return out


def network_section(mal, repo):
    """The capture corpora and each capture's result, from the measurement runs."""
    def load(name):
        return json.loads((mal / name).read_text())['captures']

    def results(captures, role, label):
        return {c['capture']: {'role': role, 'label': label, 'packets': c['packets'],
                               'flows': c['flows'], 'dns_records': c['dns_records'],
                               'findings': c['findings_total'],
                               'rules_fired': {rule: v['count'] for rule, v in c['by_rule'].items()}}
                for c in captures}

    per_capture = {}
    per_capture.update(results(load('base_rates_benign_v158a.json'), 'design', 'benign'))
    per_capture.update(results(load('base_rates_benign_heldout.json'), 'held-out', 'benign'))
    per_capture.update(results(load('base_rates_malicious_v158a.json'), 'attack', 'malicious'))
    per_capture.update(results(load('base_rates_dns_tunnel.json'), 'attack', 'malicious'))

    corpus = []
    for entry in json.loads((mal / 'benign_pcaps' / 'corpus_manifest.json').read_text()):
        corpus.append({'name': entry['name'], 'sha256': entry['sha256'], 'bytes': entry['bytes'],
                       'label': 'benign', 'role': 'design', 'source_url': entry['source_url'],
                       'kind': entry.get('kind', 'full')})
    for line in (mal / 'benign_pcaps_heldout' / 'corpus_manifest.tsv').read_text().splitlines():
        name, url, size, digest = line.split('\t')
        corpus.append({'name': name, 'sha256': digest, 'bytes': int(size), 'label': 'benign',
                       'role': 'held-out', 'source_url': url, 'kind': 'full'})

    provenance = {}
    for prov in (repo / 'backend' / 'reference_captures').glob('*.provenance.json'):
        data = json.loads(prov.read_text())
        provenance[prov.name.removesuffix('.provenance.json')] = data
    for name in sorted(n for n, v in per_capture.items() if v['label'] == 'malicious'):
        path = (mal / 'malicious_captures_set' / name).resolve()
        known = provenance.get(name, {})
        url = known.get('source_url', '')
        if name == 'dns-tunnel-iodine.pcap':
            url = ('https://github.com/elastic/examples/blob/master/Security%20Analytics/'
                   'dns_tunnel_detection/dns-tunnel-iodine.pcap')
        corpus.append({'name': name, 'sha256': sha256_file(path), 'bytes': path.stat().st_size,
                       'label': 'malicious', 'role': 'attack', 'source_url': url,
                       'ground_truth_url': known.get('ground_truth_url', ''), 'kind': 'full'})
    return {
        'corpus': sorted(corpus, key=lambda c: (c['label'], c['role'], c['name'])),
        'per_capture': per_capture,
        'rule_table_sha256': sha256_file(repo / 'backend' / 'capture' / 'data' / 'rule_base_rates.json'),
        'rule_table': json.loads((repo / 'backend' / 'capture' / 'data' / 'rule_base_rates.json').read_text()),
        'method': 'scripts/measure_rule_base_rates.py, one child process per capture, sequential; '
                  'table built by scripts/rule_base_rate_report.py --emit',
        'engine_state': 'the working tree of 19-20 Sep 2026, measured before the changes were '
                        'committed; no image or commit identifier was recorded for these runs',
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--analysis', required=True, help='apk_corpus/analysis')
    parser.add_argument('--mal', required=True, help='the mal/ directory')
    parser.add_argument('--benign', required=True, help='apk_corpus/benign')
    parser.add_argument('--out', default=str(Path(__file__).resolve().parents[1] / 'validation'))
    args = parser.parse_args()

    analysis, mal, benign_dir, out = (Path(args.analysis), Path(args.mal),
                                      Path(args.benign), Path(args.out))
    out.mkdir(parents=True, exist_ok=True)

    manifests = {}
    hashes = {}
    for key, folder in (('design', 'malwarebazaar'), ('heldout', 'malwarebazaar_heldout'),
                        ('blind', 'malwarebazaar_blind')):
        manifests[key], hashes[key] = manifest_hashes(mal / folder / 'corpus_manifest.json')

    shipped = analysis.parent.parent / 'NetForensiq' / 'backend' / 'apk_engine' / 'data' / 'baselines.json'
    if not shipped.exists():
        shipped = Path(__file__).resolve().parents[1] / 'backend' / 'apk_engine' / 'data' / 'baselines.json'
    shipped_sha = sha256_file(shipped)

    # Which baseline table each run used. The v5 runs mounted
    # baseline_v4/baselines_v4_merged.json (research/154); that run's log does not
    # record it, so it is stated as inferred and the hash equality is shown.
    v4_merged = analysis / 'baseline_v4' / 'baselines_v4_merged.json'
    v4_sha = sha256_file(v4_merged) if v4_merged.exists() else None

    runs = []
    samples = []

    def add_run(run_id, corpus, side, log, *, date, image, baselines_sha, baselines_note,
                hash_list=None, benign_files=None):
        rows = parse_check_log(log)
        rows = [r for r in rows if r['side'] == side]
        if hash_list is not None:
            map_prefixes(rows, hash_list, run_id)
            for digest in hash_list:
                if digest not in {r['sha256'] for r in rows}:
                    # An absent sample is reported, not silently ignored.
                    pass
        else:
            for row in rows:
                path = benign_files / row['name']
                row['sha256'] = sha256_file(path) if path.exists() else ''
        run = {'id': run_id, 'corpus': corpus, 'label': side, 'date': date,
               'engine_image': image, 'baselines_sha256': baselines_sha,
               'baselines_note': baselines_note, 'log': str(Path(log).relative_to(analysis.parent)),
               **summarise(rows, side)}
        if hash_list is not None:
            run['manifest_count'] = len(hash_list)
            run['all_manifest_samples_present'] = (
                {r['sha256'] for r in rows} == set(hash_list))
        runs.append(run)
        for row in rows:
            samples.append({'corpus': corpus, 'run': run_id, 'sha256': row['sha256'],
                            'package_file': '' if hash_list is not None else row['name'],
                            'tier': row['tier'], 'tier_label': row['label']})

    v5_note = ('baseline_v4/baselines_v4_merged.json, mounted over the image\'s copy '
               '(research/154 s.6.6). The run log does not record the hash; this file is '
               f'byte-identical to the shipped table: {"yes" if v4_sha == shipped_sha else "NO"}.')
    add_run('design-v5', 'design', 'malicious', analysis / 'baseline_v5' / 'designset_check.txt.log',
            date='2026-09-19', image='netforensiq-engine:sandbox-v5', baselines_sha=v4_sha,
            baselines_note=v5_note, hash_list=hashes['design'])
    add_run('heldout-v5', 'heldout', 'malicious', analysis / 'baseline_v5' / 'heldout_check.txt.log',
            date='2026-09-19', image='netforensiq-engine:sandbox-v5', baselines_sha=v4_sha,
            baselines_note=v5_note, hash_list=hashes['heldout'])
    fresh_dir = benign_dir / 'fresh_heldout'
    add_run('fresh-benign-v5', 'fresh-benign', 'benign', analysis / 'baseline_v5' / 'fresh_check.txt.log',
            date='2026-09-19', image='netforensiq-engine:sandbox-v5', baselines_sha=v4_sha,
            baselines_note=v5_note, benign_files=fresh_dir)

    v6_note = 'recorded by the run (blind_v6/baselines.sha256) and equal to the shipped table'
    blind_log = analysis / 'blind_v6' / 'blind_check.txt.log'
    add_run('blind-v6', 'blind', 'malicious', blind_log, date='2026-10-01',
            image='netforensiq-engine:sandbox-v6', baselines_sha=shipped_sha,
            baselines_note=v6_note, hash_list=hashes['blind'])
    add_run('fresh-benign-v6', 'fresh-benign', 'benign', analysis / 'blind_v6' / 'fresh_check.txt.log',
            date='2026-10-01', image='netforensiq-engine:sandbox-v6', baselines_sha=shipped_sha,
            baselines_note=v6_note, benign_files=fresh_dir)

    rerun = analysis / 'validation_v6' / 'heldout_check.txt.log'
    if rerun.exists() and 'VALIDATION RERUN DONE' in (analysis / 'validation_v6' / 'chain.log').read_text():
        recorded = (analysis / 'validation_v6' / 'baselines.sha256').read_text().split()[0]
        add_run('heldout-v6', 'heldout', 'malicious', rerun, date='2026-10-02',
                image='netforensiq-engine:sandbox-v6', baselines_sha=recorded,
                baselines_note='recorded by the run (validation_v6/baselines.sha256)',
                hash_list=hashes['heldout'])

    # The corpora, described by what the manifests say about how they were chosen.
    corpora = {}
    for key in ('design', 'heldout', 'blind'):
        m = manifests[key]
        corpora[key] = {
            'kind': 'malicious', 'n': m['count'], 'source': m['source'],
            'acquired': m['acquired'], 'selection': m['selection'], 'note': m['note'],
            'digests_in': 'validation/apk_samples.csv',
        }
    benign_baseline = json.loads(shipped.read_text())['corpus']
    corpora['baseline'] = {
        'kind': 'both', 'benign': benign_baseline['benign'],
        'malicious': benign_baseline['malicious'],
        'description': benign_baseline.get('description', ''),
        'note': 'The corpus the shipped baselines were measured on; per-sample list in '
                'backend/apk_engine/data/baselines.json (manifest).',
    }
    corpora['fresh-benign'] = {
        'kind': 'benign', 'n': len([f for f in fresh_dir.iterdir() if f.suffix == '.apk']),
        'source': 'F-Droid', 'note': 'Sampled with a new seed from F-Droid and not used for '
        'baselines, rule design or defect-finding (research/154).'}

    results = {
        'generated': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
        'shipped_baselines_sha256': shipped_sha,
        'definition': {
            'detected': 'the sample reached tier 2, 3 or 4',
            'false_positive': 'a legitimate app that reached tier 2, 3 or 4',
            'tier_1': 'examined; no harmful behaviour established — never "safe"',
            'tier_0': 'could not be examined — never a clean result',
        },
        'corpora': corpora,
        'apk_runs': runs,
        'engine_comparison': engine_comparison(samples),
        'preregistration': preregistration(analysis),
        'network': network_section(mal, Path(__file__).resolve().parents[1]),
    }
    (out / 'results.json').write_text(json.dumps(results, indent=1, sort_keys=True) + '\n')

    with open(out / 'apk_samples.csv', 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=['corpus', 'run', 'sha256', 'package_file',
                                                    'tier', 'tier_label'])
        writer.writeheader()
        for row in sorted(samples, key=lambda r: (r['run'], r['sha256'], r['package_file'])):
            writer.writerow(row)

    for run in runs:
        print(f'{run["id"]:18s} n={run["n"]:3d} tiers={run["tiers"]} '
              + (f'detected {run["detected_of_n"]}/{run["n"]}' if run['label'] == 'malicious'
                 else f'false positives {run["false_positives"]}/{run["examined"]} examined'))
    print(f'wrote {out}/results.json and apk_samples.csv ({len(samples)} rows)')


if __name__ == '__main__':
    sys.exit(main())
