#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Freeze dated snapshots of every authored file's fingerprint, for timestamping.

What it is for
==============
"Who wrote this first?" is a question about time, and a repository cannot answer
it about itself — commit dates are whatever the committer's clock said, and a
copy can be re-committed with any date at all. An independent timestamp can.

This lists the SHA-256 of every file NetForensiq's author wrote — code, tests,
research notes, documentation — in a fixed, sorted order. Timestamping that one
file with OpenTimestamps (see PROVENANCE/README.md) anchors all of them at once:
anyone can later show that a specific file, byte for byte, was part of this work
on or before the anchored date, without trusting this repository, GitHub or the
author.

Not to be confused with scripts/record_provenance.py, which records where a
downloaded reference capture came from. That is evidence provenance; this is
authorship.

What is listed
==============
Authored text only. Not third-party data (tracker signatures, stalkerware
indicators, the IANA TLD list — see THIRD_PARTY_NOTICES.md), not packet
captures, samples or evidence, not dependencies or build output. Listing someone
else's data in an authorship manifest would claim something untrue.

Layout
======
Each stamp is frozen in its own directory, PROVENANCE/stamps/<UTC time>/, as a
manifest and its .ots proof. A stamp is never rebuilt or overwritten: the whole
point of an early proof is that it describes the code as it was then, and
regenerating it in place would replace the earliest evidence with later
evidence. New work gets a new snapshot beside the old ones, so the directory
becomes a timeline.

Usage:
    python scripts/provenance_manifest.py              # show what a snapshot would hold
    python scripts/provenance_manifest.py --snapshot   # freeze a new stamp (and ots-stamp it)
    python scripts/provenance_manifest.py --check      # what changed since the latest stamp
"""

import argparse
import datetime
import hashlib
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, 'PROVENANCE')
STAMPS = os.path.join(OUT_DIR, 'stamps')

EXTENSIONS = {'.py', '.js', '.jsx', '.sh', '.md', '.cff', '.yml', '.yaml', '.html', '.css', '.toml'}
NAMED = {'LICENSE', 'Dockerfile', 'VERSION', 'package.json', '.gitignore', '.dockerignore'}
SKIP_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build', 'staticfiles',
             'static_collected', 'media', '.pytest_cache', '.mypy_cache', 'graphify-out', '.codegraph',
             'evidence_store', 'reference_captures', 'synthetic_captures', 'RealAttacksPCAP',
             'sandbox_results', 'PROVENANCE', 'test-results', 'playwright-report', '.serena'}
# Bundled third-party data, by path — authored by others, so never listed here.
THIRD_PARTY = {
    os.path.join('backend', 'apk_engine', 'data', 'exodus_trackers.json'),
    os.path.join('backend', 'apk_engine', 'data', 'stalkerware_indicators.json'),
    os.path.join('backend', 'apk_engine', 'data', 'tlds.txt'),
}


def authored_files():
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), ROOT)
            if rel in THIRD_PARTY:
                continue
            if name in NAMED or os.path.splitext(name)[1] in EXTENSIONS:
                yield rel


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def build():
    lines = [f'{sha256(os.path.join(ROOT, rel))}  {rel.replace(os.sep, "/")}'
             for rel in authored_files()]
    return '\n'.join(sorted(lines, key=lambda l: l[66:])) + '\n'


def latest_stamp():
    if not os.path.isdir(STAMPS):
        return None
    names = sorted(d for d in os.listdir(STAMPS)
                   if os.path.isfile(os.path.join(STAMPS, d, 'manifest.sha256')))
    return os.path.join(STAMPS, names[-1]) if names else None


def _entries(text):
    return {line[66:]: line[:64] for line in text.splitlines() if len(line) > 66}


def main(argv=None):
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--snapshot', action='store_true', help='freeze a new dated stamp')
    group.add_argument('--check', action='store_true', help='changes since the latest stamp')
    args = parser.parse_args(argv)
    text = build()
    count = text.count('\n')
    whole = hashlib.sha256(text.encode('utf-8')).hexdigest()

    if args.check:
        latest = latest_stamp()
        if latest is None:
            print('No stamp yet — run with --snapshot.')
            return 1
        with open(os.path.join(latest, 'manifest.sha256'), encoding='utf-8') as handle:
            stamped = _entries(handle.read())
        now = _entries(text)
        changed = sorted(p for p in now if p in stamped and now[p] != stamped[p])
        added = sorted(p for p in now if p not in stamped)
        removed = sorted(p for p in stamped if p not in now)
        name = os.path.basename(latest)
        if not (changed or added or removed):
            print(f'Nothing has changed since stamp {name} ({count} files).')
            return 0
        print(f'Since stamp {name}: {len(changed)} changed, {len(added)} added, '
              f'{len(removed)} removed. Run --snapshot to stamp the current state.')
        for label, paths in (('changed', changed), ('added', added), ('removed', removed)):
            for path in paths[:10]:
                print(f'  {label:8s} {path}')
        return 1

    if not args.snapshot:
        print(f'{count} authored files; a snapshot now would have SHA-256 {whole}')
        return 0

    stamp_dir = os.path.join(STAMPS, datetime.datetime.now(datetime.timezone.utc)
                             .strftime('%Y-%m-%dT%H%MZ'))
    if os.path.exists(stamp_dir):
        sys.exit(f'{stamp_dir} already exists; stamps are never overwritten. Wait a minute.')
    os.makedirs(stamp_dir)
    manifest = os.path.join(stamp_dir, 'manifest.sha256')
    with open(manifest, 'w', encoding='utf-8') as handle:
        handle.write(text)
    print(f'{count} authored files -> {os.path.relpath(manifest, ROOT)}')
    print(f'manifest SHA-256: {whole}')
    ots = shutil.which('ots')
    if ots:
        # Only the manifest's hash is sent, to the public OpenTimestamps calendars.
        subprocess.run([ots, 'stamp', manifest], check=False)
    else:
        print('ots not found: pip install opentimestamps-client, then '
              f'`ots stamp {os.path.relpath(manifest, ROOT)}`')
    return 0


if __name__ == '__main__':
    sys.exit(main())
