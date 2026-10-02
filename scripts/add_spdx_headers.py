#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Give every source file a two-line licence and copyright header.

Why per file and not just LICENSE
=================================
LICENSE covers the repository. Code rarely travels as a repository: a file is
copied into another project, a module is pasted into a gist, a ZIP is unpacked
and half of it kept. The MIT condition — keep the copyright notice in "all
copies or substantial portions" — is only practical to honour, and only
visible when it is not honoured, if the notice is in the file itself. SPDX is
the standard form, readable by people and by licence scanners alike.

The text comes from backend/netforensiq_backend/provenance.py, so the author
and repository are written once. `--check` exits non-zero if any source file
is missing its header or carries a stale one; run it in CI.

What it touches
===============
Python, shell, JavaScript and JSX under backend/, frontend/src/ and scripts/.
Never: virtualenvs, node_modules, generated migrations, build output, empty
files, or bundled third-party data — a header claiming copyright over someone
else's code would be the one thing worse than no header.

Usage:
    python scripts/add_spdx_headers.py           # add or update headers
    python scripts/add_spdx_headers.py --check   # report only; exit 1 if any missing
"""

import argparse
import importlib.util
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOTS = ('backend', os.path.join('frontend', 'src'), 'scripts')
SKIP_DIRS = {'.venv', 'venv', 'node_modules', '__pycache__', 'migrations', 'staticfiles',
             'static_collected', 'dist', 'build', 'media', '.pytest_cache'}
COMMENT = {'.py': '#', '.sh': '#', '.js': '//', '.jsx': '//'}
MARKER = 'SPDX-License-Identifier'


def _provenance():
    path = os.path.join(ROOT, 'backend', 'netforensiq_backend', 'provenance.py')
    spec = importlib.util.spec_from_file_location('provenance', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def source_files():
    for base in ROOTS:
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, base)):
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
            for name in sorted(filenames):
                if os.path.splitext(name)[1] in COMMENT:
                    yield os.path.join(dirpath, name)


def expected_header(path, spdx_lines):
    prefix = COMMENT[os.path.splitext(path)[1]]
    return [f'{prefix} {line}' for line in spdx_lines]


def split_preamble(lines):
    """
    Lines that must stay first: a shebang, and Python's encoding declaration.

    PEP 263 requires the encoding cookie on line 1 or 2, and a shebang only works
    on line 1, so the header goes after them rather than above them.
    """
    keep = 0
    if lines and lines[0].startswith('#!'):
        keep = 1
    if len(lines) > keep and 'coding' in lines[keep] and lines[keep].lstrip().startswith('#'):
        keep += 1
    return lines[:keep], lines[keep:]


def process(path, spdx_lines, write):
    with open(path, encoding='utf-8') as handle:
        text = handle.read()
    if not text.strip():
        return 'empty'
    lines = text.split('\n')
    header = expected_header(path, spdx_lines)
    preamble, body = split_preamble(lines)

    existing = [i for i, line in enumerate(body[:4]) if MARKER in line]
    if existing:
        start = existing[0]
        if body[start:start + len(header)] == header:
            return 'ok'
        if not write:
            return 'stale'
        body = body[:start] + header + body[start + len(header):]
        status = 'updated'
    else:
        if not write:
            return 'missing'
        body = header + body
        status = 'added'

    with open(path, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(preamble + body))
    return status


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true',
                        help='report only; exit 1 if any header is missing or stale')
    args = parser.parse_args(argv)

    spdx_lines = _provenance().SPDX_LINES
    counts, problems = {}, []
    for path in source_files():
        status = process(path, spdx_lines, write=not args.check)
        counts[status] = counts.get(status, 0) + 1
        if status in ('missing', 'stale'):
            problems.append((status, os.path.relpath(path, ROOT)))

    summary = ', '.join(f'{k} {v}' for k, v in sorted(counts.items()))
    print(f'SPDX headers: {summary}')
    for status, path in problems[:20]:
        print(f'  {status:8s} {path}')
    if args.check and problems:
        print(f'{len(problems)} file(s) need `python scripts/add_spdx_headers.py`.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
