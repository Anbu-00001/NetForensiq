#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
A digest of the source tree, so a release can be tied to the code it was built from
without trusting a commit message.

It hashes each tracked file, then hashes the sorted list of (path, file hash) — so two
checkouts of the same commit agree whatever their timestamps, permissions or line of
descent. A release manifest records this digest; a recipient with a checkout of the
named commit runs this script and compares.

    python scripts/tree_digest.py            # tracked files of the repository containing this script
    python scripts/tree_digest.py --list files.txt   # paths from a file, one per line

Standard library only: it is meant to be run by someone who trusts nothing else here.
"""
import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def tree_digest(files, base):
    """Digest over (path, SHA-256) for each file, in sorted order. `files` are relative to `base`."""
    outer = hashlib.sha256()
    for relative in sorted(files):
        outer.update(f'{relative}\0{sha256_file(Path(base) / relative)}\n'.encode('utf-8'))
    return outer.hexdigest()


def tracked_files(base=REPO):
    listing = subprocess.run(['git', '-C', str(base), 'ls-files', '-z'],
                             capture_output=True, text=True, timeout=60)
    if listing.returncode != 0:
        raise SystemExit('not a git checkout: pass --list with the paths to include')
    return [f for f in listing.stdout.split('\0') if f and (Path(base) / f).is_file()]


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--list', help='a file of paths, one per line, relative to the repository')
    args = parser.parse_args()
    files = ([line.strip() for line in Path(args.list).read_text().splitlines() if line.strip()]
             if args.list else tracked_files())
    print(f'{tree_digest(files, REPO)}  ({len(files)} files)')


if __name__ == '__main__':
    sys.exit(main())
