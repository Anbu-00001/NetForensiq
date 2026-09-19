#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Write PROVENANCE/manifest.sha256: a fingerprint of every authored file.

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

Usage:
    python scripts/provenance_manifest.py          # write the manifest
    python scripts/provenance_manifest.py --check  # exit 1 if it is out of date
"""

import argparse
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, 'PROVENANCE')
MANIFEST = os.path.join(OUT_DIR, 'manifest.sha256')

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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    text = build()
    count = text.count('\n')
    if args.check:
        try:
            current = open(MANIFEST, encoding='utf-8').read()
        except FileNotFoundError:
            print('No manifest yet — run without --check.')
            return 1
        if current == text:
            print(f'Manifest is current ({count} files).')
            return 0
        print('Manifest is out of date: files changed since it was written. Rebuild it and '
              're-stamp (see PROVENANCE/README.md).')
        return 1
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(MANIFEST, 'w', encoding='utf-8') as handle:
        handle.write(text)
    whole = hashlib.sha256(text.encode('utf-8')).hexdigest()
    print(f'{count} authored files -> {os.path.relpath(MANIFEST, ROOT)}')
    print(f'manifest SHA-256: {whole}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
