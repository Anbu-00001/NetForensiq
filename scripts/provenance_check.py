#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Is this project NetForensiq? Compare a suspected copy against the original.

The situation it is for
=======================
A project turns up — a hackathon entry, a GitHub repository, a ZIP someone sent
— that looks a lot like this one, credited to someone else. The useful question
is not "is it similar" but "how much of it is this, and were the notices that
credit the author taken out". This answers both, file by file, from content
alone: paths, file names and directory layout are ignored, so a renamed file or
a GitHub ZIP with a `NetForensiq-main/` prefix still matches.

Three levels of match, each stronger evidence than a looser one:

  identical        byte-for-byte the same file.
  header removed   identical once the SPDX licence header and whitespace are
                   ignored — the file was copied and the lines naming the author
                   were deleted. The MIT licence's one condition is that those
                   lines stay; this is the finding that matters most.
  derived          most of its distinctive lines appear in NetForensiq — copied,
                   then edited.

It also reports whether the copy still carries the licence and copyright notice,
because a copy that keeps them is legitimate use, not a problem.

Pair the result with PROVENANCE/: this shows the copy matches NetForensiq, and
the OpenTimestamps proof shows NetForensiq existed first.

Usage:
    python scripts/provenance_check.py /path/to/suspect-directory
    python scripts/provenance_check.py suspect.zip
    python scripts/provenance_check.py suspect.zip --json report.json
"""

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import provenance_manifest  # noqa: E402

ROOT = provenance_manifest.ROOT
TEXT_EXT = provenance_manifest.EXTENSIONS
HEADER = re.compile(r'SPDX-License-Identifier|Copyright \(c\)')
MIN_LINE = 28          # shorter lines ("import os", "}") match everything
DERIVED = 0.60         # share of a file's distinctive lines found in the original
MAX_FILE = 2_000_000


def _normalise(text):
    kept = [line for line in text.splitlines() if not HEADER.search(line)]
    return re.sub(r'\s+', '', '\n'.join(kept))


def _lines(text):
    out = set()
    for line in text.splitlines():
        line = re.sub(r'\s+', ' ', line).strip()
        if len(line) >= MIN_LINE and not HEADER.search(line):
            out.add(hashlib.sha1(line.encode('utf-8')).hexdigest())
    return out


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def load_original():
    raw, normal, line_index = {}, {}, {}
    for rel in provenance_manifest.authored_files():
        if os.path.splitext(rel)[1] not in TEXT_EXT:
            continue
        with open(os.path.join(ROOT, rel), 'rb') as handle:
            data = handle.read()
        text = data.decode('utf-8', 'replace')
        raw[_digest(data)] = rel
        normal[_digest(_normalise(text).encode())] = rel
        for h in _lines(text):
            line_index.setdefault(h, set()).add(rel)
    return raw, normal, line_index


def suspect_files(target):
    """(name, bytes) for every text file in a directory or a ZIP."""
    if os.path.isdir(target):
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in provenance_manifest.SKIP_DIRS]
            for name in filenames:
                if os.path.splitext(name)[1] not in TEXT_EXT and name != 'LICENSE':
                    continue
                path = os.path.join(dirpath, name)
                if os.path.getsize(path) <= MAX_FILE:
                    with open(path, 'rb') as handle:
                        yield os.path.relpath(path, target), handle.read()
    else:
        with zipfile.ZipFile(target) as archive:
            for info in archive.infolist():
                base = info.filename.rsplit('/', 1)[-1]
                if info.is_dir() or info.file_size > MAX_FILE:
                    continue
                if os.path.splitext(base)[1] not in TEXT_EXT and base != 'LICENSE':
                    continue
                yield info.filename, archive.read(info)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='suspected copy: a directory or a .zip')
    parser.add_argument('--json', help='also write the full report here')
    args = parser.parse_args(argv)

    raw, normal, line_index = load_original()
    copyright_line = provenance_manifest_copyright()
    results, notices = [], {'licence_file': False, 'copyright_line': False, 'spdx_headers': 0}

    for name, data in suspect_files(args.target):
        text = data.decode('utf-8', 'replace')
        base = name.rsplit('/', 1)[-1]
        if base == 'LICENSE':
            notices['licence_file'] = True
            notices['copyright_line'] |= copyright_line in text
        if copyright_line in text and 'SPDX-License-Identifier' in text:
            notices['spdx_headers'] += 1
        if os.path.splitext(base)[1] not in TEXT_EXT:
            continue

        verdict, original = 'unrelated', None
        if _digest(data) in raw:
            verdict, original = 'identical', raw[_digest(data)]
        elif _digest(_normalise(text).encode()) in normal:
            verdict, original = 'header removed', normal[_digest(_normalise(text).encode())]
        else:
            lines = _lines(text)
            if lines:
                hits = {}
                for h in lines:
                    for rel in line_index.get(h, ()):
                        hits[rel] = hits.get(rel, 0) + 1
                if hits:
                    best, count = max(hits.items(), key=lambda kv: kv[1])
                    if count / len(lines) >= DERIVED:
                        verdict, original = 'derived', best
        results.append({'file': name, 'verdict': verdict, 'original': original})

    counts = {}
    for r in results:
        counts[r['verdict']] = counts.get(r['verdict'], 0) + 1
    matched = sum(v for k, v in counts.items() if k != 'unrelated')
    total = len(results)

    print(f'Suspected copy: {args.target}')
    print(f'{total} source/text file(s) examined.\n')
    for label in ('identical', 'header removed', 'derived', 'unrelated'):
        print(f'  {label:15s} {counts.get(label, 0):5d}')
    share = matched / total * 100 if total else 0
    print(f'\n{matched} of {total} files ({share:.0f}%) come from NetForensiq.')

    print('\nAttribution in the copy:')
    print(f'  LICENSE file present ............. {"yes" if notices["licence_file"] else "NO"}')
    print(f'  "{copyright_line}" kept ... {"yes" if notices["copyright_line"] else "NO"}')
    print(f'  files still carrying the header .. {notices["spdx_headers"]}')

    stripped = counts.get('header removed', 0)
    if matched and (stripped or not notices['copyright_line']):
        print('\nFINDING: this copy contains NetForensiq code with the author\'s notices '
              'removed' + (f' ({stripped} file(s) had the licence header deleted)' if stripped else '')
              + '. The MIT licence requires those notices to be kept.')
    elif matched:
        print('\nThe copy keeps the licence and copyright notice: that is permitted use.')
    else:
        print('\nNo NetForensiq code found.')

    for r in [r for r in results if r['verdict'] == 'header removed'][:15]:
        print(f'  header removed: {r["file"]}  <-  {r["original"]}')

    if args.json:
        with open(args.json, 'w', encoding='utf-8') as handle:
            json.dump({'target': args.target, 'counts': counts, 'notices': notices,
                       'files': results}, handle, indent=1)
    return 0


def provenance_manifest_copyright():
    """The copyright line, from the single source of truth."""
    import importlib.util
    path = os.path.join(ROOT, 'backend', 'netforensiq_backend', 'provenance.py')
    spec = importlib.util.spec_from_file_location('provenance', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.COPYRIGHT


if __name__ == '__main__':
    sys.exit(main())
