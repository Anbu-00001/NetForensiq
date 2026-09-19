#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
How often does each detection rule fire on traffic that is not an attack?

The question this answers
=========================
The APK engine may not raise a tier on a signal until that signal has been
measured against legitimate software: 201 F-Droid apps, and a signal that
fires on any of them cannot carry a verdict on its own. The network rules
have never had the equivalent. They were written from published indicators in
a handful of malicious captures, and every one of them is a claim — "this host
is beaconing", "this is a covert channel" — made without a measurement of how
often the same sentence gets said about a laptop fetching updates.

This runs every rule over a corpus of benign captures and counts. Nothing
here decides anything; it produces the number that a decision would need.

How it runs
===========
One child process per capture, sequentially, each with an address-space
ceiling. That is the same shape `apk_runner` uses and for the same two
reasons: a capture that exhausts memory kills one child rather than the
machine, and memory is actually returned between captures instead of
accumulating across a corpus. A 15 GB laptop importing eighteen captures in
one process is how you lose the laptop.

Each child imports into its own copy of a migrated database, so a capture
cannot see another's flows and the runs are independent.

Usage::

    python scripts/measure_rule_base_rates.py \\
        --captures /home/anbu/26_class/mal/benign_pcaps \\
        --label benign --out /tmp/base_rates_benign.json
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.abspath(os.path.join(HERE, '..', 'backend'))
DEFAULT_MEMORY_MB = int(os.environ.get('RULE_MEASURE_MEMORY_MB', '6144'))


# ── child: import one capture and report what fired ────────────────────────

def run_one(path, database, memory_mb):
    """Import one capture, analyse it, and print a JSON result on stdout."""
    if memory_mb:
        try:
            import resource
            value = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (value, value))
        except (ImportError, ValueError, OSError):
            pass

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
    os.environ['SQLITE_NAME'] = database
    os.environ.setdefault('SECRET_KEY', 'rule-base-rate-measurement')
    os.environ.setdefault('DEBUG', 'False')
    sys.path.insert(0, BACKEND)

    import django
    django.setup()

    from capture.service import run_pcap_import


    started = time.perf_counter()
    session, (flows, dns) = run_pcap_import(path, name=os.path.basename(path))
    imported = time.perf_counter() - started

    # run_pcap_import already analyses. Re-reading the findings is what we
    # want, not re-running them.
    findings = list(session.detections.all())
    by_rule = {}
    for finding in findings:
        entry = by_rule.setdefault(finding.rule_id, {
            'count': 0, 'severities': {}, 'subjects': set(), 'example': ''})
        entry['count'] += 1
        entry['severities'][finding.severity] = entry['severities'].get(finding.severity, 0) + 1
        if finding.subject_ip:
            entry['subjects'].add(finding.subject_ip)
        if not entry['example']:
            entry['example'] = finding.title
    for entry in by_rule.values():
        entry['subjects'] = len(entry['subjects'])

    return {
        'capture': os.path.basename(path),
        'bytes': os.path.getsize(path),
        'packets': session.packet_count,
        'flows': flows,
        'dns_records': dns,
        'seconds': round(imported, 1),
        'findings_total': len(findings),
        'rules_fired': sorted(by_rule),
        'by_rule': by_rule,
    }


# ── parent: walk the corpus, one child each ────────────────────────────────

def migrate_template(directory):
    """A migrated, empty database each child gets a private copy of."""
    template = os.path.join(directory, 'template.sqlite3')
    environment = dict(os.environ)
    environment.update({
        'SQLITE_NAME': template,
        'SECRET_KEY': environment.get('SECRET_KEY', 'rule-base-rate-measurement'),
        'DEBUG': 'False',
    })
    result = subprocess.run(
        [sys.executable, 'manage.py', 'migrate', '--no-input'],
        cwd=BACKEND, env=environment, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f'could not prepare the database:\n{result.stdout}\n{result.stderr}')
    return template


def captures_in(directory):
    found = []
    for name in sorted(os.listdir(directory)):
        if name.endswith(('.pcap', '.pcapng')):
            found.append(os.path.join(directory, name))
    return found


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--captures', help='directory of .pcap files')
    parser.add_argument('--label', default='benign',
                        help='what this corpus is, recorded in the output')
    parser.add_argument('--out', required=True)
    parser.add_argument('--memory-mb', type=int, default=DEFAULT_MEMORY_MB)
    parser.add_argument('--timeout', type=int, default=3600)
    # The child half.
    parser.add_argument('--one', help=argparse.SUPPRESS)
    parser.add_argument('--database', help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.one:
        print(json.dumps(run_one(args.one, args.database, args.memory_mb)))
        return

    paths = captures_in(args.captures)
    if not paths:
        sys.exit(f'no captures in {args.captures}')

    workspace = tempfile.mkdtemp(prefix='netforensiq-baserate-')
    template = migrate_template(workspace)
    results, failures = [], []

    for index, path in enumerate(paths, 1):
        database = os.path.join(workspace, f'run{index}.sqlite3')
        shutil.copy(template, database)
        name = os.path.basename(path)
        print(f'[{index}/{len(paths)}] {name} ({os.path.getsize(path) / 1e6:.0f} MB)',
              flush=True)
        command = [sys.executable, os.path.abspath(__file__),
                   '--one', path, '--database', database,
                   '--memory-mb', str(args.memory_mb), '--out', args.out]
        try:
            child = subprocess.run(command, capture_output=True, text=True,
                                   timeout=args.timeout)
        except subprocess.TimeoutExpired:
            failures.append({'capture': name, 'reason': f'timed out after {args.timeout}s'})
            print('    timed out', flush=True)
            os.remove(database)
            continue

        try:
            result = json.loads(child.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            tail = (child.stderr or '').strip().splitlines()[-3:]
            reason = f'exit {child.returncode}: ' + ' | '.join(tail)
            failures.append({'capture': name, 'reason': reason[:500]})
            print(f'    failed — {reason[:160]}', flush=True)
            os.remove(database)
            continue

        results.append(result)
        print(f"    {result['packets']:,} packets, {result['flows']:,} flows, "
              f"{result['findings_total']} findings "
              f"({', '.join(result['rules_fired']) or 'none'}) in {result['seconds']}s",
              flush=True)
        os.remove(database)
        with open(args.out, 'w') as handle:
            json.dump({'label': args.label, 'captures': results,
                       'failures': failures}, handle, indent=1)

    with open(args.out, 'w') as handle:
        json.dump({'label': args.label, 'captures': results, 'failures': failures},
                  handle, indent=1)
    shutil.rmtree(workspace, ignore_errors=True)

    fired = {}
    for result in results:
        for rule in result['rules_fired']:
            fired[rule] = fired.get(rule, 0) + 1
    print(f'\n{len(results)} captures examined, {len(failures)} failed')
    for rule, count in sorted(fired.items(), key=lambda r: -r[1]):
        print(f'  {rule:34s} fired on {count}/{len(results)} captures')


if __name__ == '__main__':
    main()
