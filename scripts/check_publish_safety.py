#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Refuse to publish anything that could hurt someone.

What it looks for
=================
This project handles three kinds of dangerous material, and a public repository
is the worst place for any of them to land:

* **live malware** — MalwareBazaar samples, APKs and DEX files, and the
  password-protected archives they travel in;
* **people's data** — packet captures, the evidence store, the application
  database;
* **secrets** — private keys, API tokens, the evidence encryption key, `.env`
  files, and a Django SECRET_KEY written into code.

`.gitignore` already excludes all of these. This is the second line, for the day
someone renames a file, adds `-f`, or copies a sample into a new directory the
ignore rules do not cover. It classifies files by **content**, not by name: a
DEX is recognised by its magic bytes and an APK by what its ZIP contains, so a
sample renamed `notes.txt` is still caught.

What it checks
==============
Exactly what would be published: `git ls-files --cached --others
--exclude-standard` when run inside a git work tree, which is what a commit could
include. Outside one (a ZIP about to be shared, say), `--no-git` walks the
directory instead.

Exit 0 means nothing dangerous was found; exit 1 lists every finding.

Usage:
    python scripts/check_publish_safety.py            # in the repository
    python scripts/check_publish_safety.py --no-git   # any directory
"""

import argparse
import os
import re
import subprocess
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WALK_SKIP = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build',
             'staticfiles', '.pytest_cache', '.mypy_cache', 'graphify-out', '.codegraph'}
MAX_TEXT_SCAN = 2_000_000
LARGE_FILE = 50_000_000

SECRET_PATTERNS = [
    ('private key', re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY')),
    ('GitHub token', re.compile(rb'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}')),
    ('GitHub fine-grained token', re.compile(rb'\bgithub_pat_[A-Za-z0-9_]{40,}')),
    ('AWS access key', re.compile(rb'\bAKIA[0-9A-Z]{16}\b')),
    ('Slack token', re.compile(rb'\bxox[baprs]-[A-Za-z0-9-]{10,}')),
    ('Django SECRET_KEY literal',
     re.compile(rb'''SECRET_KEY\s*=\s*['"][^'"\s]{20,}['"]''')),
    ('auth key assigned in code',
     re.compile(rb'''(?i)(?:auth[_-]?key|api[_-]?key|access[_-]?token)\s*[=:]\s*['"][A-Za-z0-9]{32,}['"]''')),
]
FORBIDDEN_NAMES = [
    ('environment file', re.compile(r'(^|/)\.env(\.[^/]*)?$'), re.compile(r'\.env\.example$')),
    ('key file', re.compile(r'\.(key|pem|p12|pfx|jks|keystore)$'), None),
    ('application database', re.compile(r'\.sqlite3?(-wal|-shm|-journal)?$|\.db$'), None),
    ('packet capture', re.compile(r'\.(pcap|pcapng|cap)(\.gz)?$'), None),
    ('evidence store (case exhibits)', re.compile(r'(^|/)evidence_store/'), None),
]
# The evidence store's own at-rest format (evidence/crypto.py). Ciphertext, so it
# looks like nothing by content — which is exactly why it gets its own rule: a
# sealed exhibit is case evidence whether or not it can be read.
EVIDENCE_MAGIC = b'NFENCv1'
# Documentation legitimately shows what a setting looks like. A value that says it
# is a placeholder is not a secret.
PLACEHOLDER = re.compile(rb'(?i)change[-_]?me|example|placeholder|your[-_]|<[^>]+>|x{8,}|\.\.\.')
PCAP_MAGIC = (b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\x4d\x3c\xb2\xa1',
              b'\xa1\xb2\x3c\x4d', b'\x0a\x0d\x0d\x0a')


def candidates(use_git):
    if use_git:
        try:
            out = subprocess.run(
                ['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
                cwd=ROOT, capture_output=True, check=True).stdout
            return [p for p in out.decode('utf-8', 'replace').split('\0') if p]
        except (OSError, subprocess.CalledProcessError):
            print('(not a git work tree — walking the directory instead)', file=sys.stderr)
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in WALK_SKIP]
        for name in filenames:
            found.append(os.path.relpath(os.path.join(dirpath, name), ROOT))
    return found


def classify_archive(path):
    """An APK, a MalwareBazaar-style encrypted archive, or neither."""
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = {i.filename for i in infos}
            if 'AndroidManifest.xml' in names or any(n.endswith('.dex') for n in names):
                return 'Android package (APK)'
            if infos and all(i.flag_bits & 0x1 for i in infos):
                return 'password-protected archive (the form malware samples are shipped in)'
    except Exception:
        return None
    return None


def inspect(relpath):
    path = os.path.join(ROOT, relpath)
    findings = []
    for label, pattern, exempt in FORBIDDEN_NAMES:
        if pattern.search(relpath) and not (exempt and exempt.search(relpath)):
            findings.append(label)
    try:
        size = os.path.getsize(path)
        with open(path, 'rb') as handle:
            head = handle.read(8)
    except OSError:
        return findings
    if head[:7] == EVIDENCE_MAGIC:
        findings.append('encrypted evidence exhibit')
    if head[:4] == b'dex\n':
        findings.append('DEX bytecode')
    if head[:4] in PCAP_MAGIC:
        findings.append('packet capture (by content)')
    if head[:4] == b'PK\x03\x04':
        kind = classify_archive(path)
        if kind:
            findings.append(kind)
    if size > LARGE_FILE:
        findings.append(f'large file ({size // 1_000_000} MB)')
    if size <= MAX_TEXT_SCAN and b'\0' not in head:
        try:
            with open(path, 'rb') as handle:
                data = handle.read()
        except OSError:
            data = b''
        for label, pattern in SECRET_PATTERNS:
            if any(not PLACEHOLDER.search(m.group(0)) for m in pattern.finditer(data)):
                findings.append(f'possible {label}')
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-git', action='store_true',
                        help='walk the directory instead of asking git what would be published')
    args = parser.parse_args(argv)

    files = candidates(use_git=not args.no_git)
    problems = [(f, found) for f in sorted(files) if (found := inspect(f))]
    print(f'{len(files)} file(s) checked.')
    if not problems:
        print('Nothing dangerous found: no samples, captures, databases or secrets.')
        return 0
    print(f'{len(problems)} file(s) must not be published:')
    for relpath, found in problems:
        print(f'  {relpath}\n      {"; ".join(found)}')
    return 1


if __name__ == '__main__':
    sys.exit(main())
