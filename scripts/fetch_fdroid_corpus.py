#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Fetch a reproducible corpus of legitimate Android packages from F-Droid.

Why this exists
---------------
Every "fired on none of the legitimate apps" claim the engine makes is only as
strong as the number of apps behind it. With 31, the exact one-sided 95% upper
bound on a clean signal's true benign rate is 9.2% — the claim licensed is
"fewer than about 1 in 11", which is not enough to deploy. Roughly 300 apps
brings that under 1%, roughly 3,000 under 0.1%. Nothing else moves that number:
not better rules, not more careful wording.

F-Droid is the right source for three reasons. The builds are reproducible and
publicly addressable, so anyone can re-acquire the exact bytes this corpus was
measured on and contradict the measurement. The licences permit redistribution,
so the corpus manifest is not a list of files only we can obtain. And the
catalogue is full of applications that legitimately do the alarming things —
install packages, create VPN interfaces, read SMS, drive accessibility, run
shell commands — which is what makes a benign corpus worth measuring against.
A corpus of torches and calculators would prove nothing.

Selection is deterministic
--------------------------
Packages are sorted by name and sampled with a fixed seed, so two people running
this with the same ``--count`` and ``--seed`` get the same corpus. That is the
point: a benign base rate measured on an unrepeatable sample is an anecdote.
The sample is representative rather than hand-picked, which is deliberately
different from the 23 adversarially chosen apps already in the corpus — keep
both, because they answer different questions. The adversarial set asks "can a
signal survive apps that look like malware"; the representative set asks "how
often does it fire in the wild".

This script is not run automatically, and nothing in the engine calls it. It
downloads several gigabytes over a long time, and the measurement that follows
is memory-hungry — see research/150 and the evaluate command's own limits.

    python scripts/fetch_fdroid_corpus.py --count 300 --out apk_corpus/benign/fdroid_sample
    python -m apk_engine evaluate --benign <that dir> ... --jobs 1 --max-memory-mb 6144

Re-running resumes: a package already on disk with the expected size is kept.
"""

import argparse
import hashlib
import io
import json
import os
import random
import sys
import time
import urllib.request
import zipfile

REPO = 'https://f-droid.org/repo'
INDEX = f'{REPO}/index-v1.jar'
USER_AGENT = 'NetForensiq-corpus-builder/1.0 (+research use)'


def fetch(url, timeout=120):
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def load_index(cache_path):
    """The F-Droid index, from a local cache when one is already present."""
    if cache_path and os.path.exists(cache_path):
        with open(cache_path, 'rb') as handle:
            raw = handle.read()
    else:
        print(f'Fetching {INDEX} …', file=sys.stderr)
        raw = fetch(INDEX)
        if cache_path:
            with open(cache_path, 'wb') as handle:
                handle.write(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        return json.loads(archive.read('index-v1.json'))


def candidates(index):
    """
    One current release per application, with the metadata to re-acquire it.

    Only the newest version of each package is taken: several versions of the
    same application are not independent observations, and counting them would
    inflate the corpus without widening it.
    """
    chosen = []
    for package, releases in sorted(index.get('packages', {}).items()):
        usable = [r for r in releases if r.get('apkName') and r.get('hash')
                  and r.get('hashType', '').lower() == 'sha256']
        if not usable:
            continue
        newest = max(usable, key=lambda r: r.get('versionCode') or 0)
        chosen.append({'package': package, 'apk': newest['apkName'],
                       'sha256': newest['hash'], 'size': newest.get('size') or 0,
                       'version': newest.get('versionName') or ''})
    return chosen


def download(entry, out_dir, retries=4, delay=1.0):
    """
    One package, resumable and retried.

    A network interruption mid-run (an interface switch, a resolver blip) is
    not a statement about the sample or the index, so it is retried rather than
    recorded as a permanent failure — the same reasoning already applied to
    abuse.ch's 502s in fetch_malwarebazaar_corpus.py. This one was added after
    exactly that happened here: a mid-fetch network change turned 211 of 300
    packages into hard failures with no chance to recover automatically.
    """
    target = os.path.join(out_dir, f"{entry['package']}.apk")
    if os.path.exists(target) and (not entry['size']
                                   or os.path.getsize(target) == entry['size']):
        return 'kept'
    payload = None
    for attempt in range(1, retries + 1):
        try:
            payload = fetch(f"{REPO}/{entry['apk']}", timeout=300)
            break
        except Exception as exc:
            if attempt == retries:
                return f'FAILED ({type(exc).__name__}: {exc})'
            time.sleep(delay * (2 ** attempt))
    digest = hashlib.sha256(payload).hexdigest()
    if digest != entry['sha256']:
        # The index states the digest. A mismatch means the file is not the one
        # the index describes, and a corpus of unverified bytes is worthless.
        return f"REJECTED (sha256 {digest[:16]}… != index {entry['sha256'][:16]}…)"
    with open(target, 'wb') as handle:
        handle.write(payload)
    return 'downloaded'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[1],
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--count', type=int, default=300, help='packages to sample')
    parser.add_argument('--out', required=True, help='directory to write .apk files into')
    parser.add_argument('--seed', type=int, default=20260918,
                        help='fixed so the sample is reproducible')
    parser.add_argument('--index-cache', default='',
                        help='reuse a previously downloaded index-v1.jar')
    parser.add_argument('--delay', type=float, default=1.0,
                        help='seconds between downloads; be a good citizen')
    parser.add_argument('--list-only', action='store_true',
                        help='print the selection and the manifest, download nothing')
    args = parser.parse_args(argv)

    index = load_index(args.index_cache)
    pool = candidates(index)
    print(f'{len(pool)} packages in the index', file=sys.stderr)
    if args.count < len(pool):
        pool = random.Random(args.seed).sample(pool, args.count)
        pool.sort(key=lambda e: e['package'])

    manifest = {
        'source': REPO,
        'index_version': index.get('repo', {}).get('version', ''),
        'index_timestamp': index.get('repo', {}).get('timestamp', ''),
        'seed': args.seed, 'count': len(pool),
        'note': 'Deterministic sample: same seed and count reproduce this list exactly.',
        'packages': pool,
    }
    if args.list_only:
        json.dump(manifest, sys.stdout, indent=1)
        sys.stdout.write('\n')
        return 0

    os.makedirs(args.out, exist_ok=True)
    tally = {}
    for position, entry in enumerate(pool, 1):
        try:
            outcome = download(entry, args.out, delay=args.delay)
        except Exception as exc:
            outcome = f'FAILED ({type(exc).__name__}: {exc})'
        tally[outcome.split()[0]] = tally.get(outcome.split()[0], 0) + 1
        print(f'[{position}/{len(pool)}] {entry["package"]}: {outcome}', file=sys.stderr)
        if outcome == 'downloaded' and args.delay:
            time.sleep(args.delay)

    with open(os.path.join(args.out, 'corpus_manifest.json'), 'w', encoding='utf-8') as handle:
        json.dump(dict(manifest, outcomes=tally), handle, indent=1)
        handle.write('\n')
    print(f'{tally} -> {args.out}', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
