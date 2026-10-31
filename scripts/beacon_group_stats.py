#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Interval statistics for every repeated connection group in a set of captures.

The beacon rules decide from a few numbers per group of connections: how many,
over how long, how regular. This prints those numbers for every group, whether
or not a rule fires on it, so a rule change can be judged against what the
traffic actually looks like rather than against a list of findings.

It decides nothing. Run it on the development half of a corpus while a rule is
being written, and on the held-out half only after the rule is frozen.

One child process per capture, each with an address-space ceiling and its own
copy of a migrated database, as in measure_rule_base_rates.py.

Usage::

    python scripts/beacon_group_stats.py --captures DIR --out groups.json
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from measure_rule_base_rates import BACKEND, captures_in, migrate_template  # noqa: E402

MIN_GROUP = 4  # RITA's unique_connection_threshold floor; smaller groups are not listed


def group_stats(starts, sizes):
    """The statistics the beacon rules use, for one group's connection starts."""
    starts = sorted(starts)
    gaps = [b - a for a, b in zip(starts, starts[1:]) if b - a > 0]
    out = {'connections': len(starts), 'span_s': round(starts[-1] - starts[0], 1),
           'intervals': len(gaps)}
    if len(gaps) >= 2:
        mean = statistics.fmean(gaps)
        out['median_s'] = round(statistics.median(gaps), 2)
        out['cv'] = round(statistics.pstdev(gaps) / mean, 4) if mean else None
    long_gaps = sorted(g for g in gaps if g >= 30)
    if long_gaps:
        best = 0
        for g in long_gaps:
            best = max(best, sum(1 for h in long_gaps if g <= h <= g + 2))
        out['flare_share'] = round(best / len(long_gaps), 4)
        out['flare_intervals'] = len(long_gaps)
    sizes = [s for s in sizes if s > 0]
    if len(sizes) >= 2 and statistics.fmean(sizes):
        out['bytes_cov'] = round(statistics.pstdev(sizes) / statistics.fmean(sizes), 4)
    return out


def run_one(path, database, memory_mb):
    if memory_mb:
        import resource
        value = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (value, value))
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
    os.environ['SQLITE_NAME'] = database
    os.environ.setdefault('SECRET_KEY', 'beacon-group-stats')
    os.environ.setdefault('DEBUG', 'False')
    sys.path.insert(0, BACKEND)
    import django
    django.setup()

    from capture.detection import (flow_direction, is_internal, is_link_scoped,
                                   session_home_networks)
    from capture.service import run_pcap_import

    session, _ = run_pcap_import(path, name=os.path.basename(path))
    home = session_home_networks(session)
    groups = defaultdict(list)
    for flow in session.flows.all():
        # The service port: a flow stored server-first has the client's
        # ephemeral port in dst_port.
        initiator, peer, port = flow_direction(flow)
        key = (('sni', initiator, flow.tls_sni.lower(), port, flow.protocol) if flow.tls_sni
               else ('ip', initiator, peer, port, flow.protocol))
        groups[key].append(flow)

    rows = []
    for (kind, initiator, destination, port, proto), flows in groups.items():
        if len(flows) < MIN_GROUP:
            continue
        _, peer, _ = flow_direction(flows[0])
        row = {'grouped_by': kind, 'initiator': initiator, 'peer': destination,
               'port': port, 'protocol': proto,
               'outbound': bool(is_internal(initiator, home) and not is_internal(peer, home)
                                and not is_link_scoped(peer)),
               'sni': sorted({f.tls_sni for f in flows if f.tls_sni})[:3]}
        row.update(group_stats([f.first_seen.timestamp() for f in flows],
                               [f.bytes_sent or 0 for f in flows]))
        rows.append(row)
    rows.sort(key=lambda r: -r['connections'])
    return {'capture': os.path.basename(path), 'groups': rows,
            'fired': sorted(set(session.detections.values_list('rule_id', flat=True)))}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--captures')
    parser.add_argument('--out', required=True)
    parser.add_argument('--memory-mb', type=int, default=5000)
    parser.add_argument('--one', help=argparse.SUPPRESS)
    parser.add_argument('--database', help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.one:
        print(json.dumps(run_one(args.one, args.database, args.memory_mb)))
        return

    results = []
    with tempfile.TemporaryDirectory(prefix='nf-groups-') as workspace:
        template = migrate_template(workspace)
        for index, path in enumerate(captures_in(args.captures), 1):
            database = os.path.join(workspace, f'run{index}.sqlite3')
            shutil.copy(template, database)
            done = subprocess.run(
                [sys.executable, __file__, '--one', path, '--database', database,
                 '--memory-mb', str(args.memory_mb), '--out', args.out],
                cwd=BACKEND, capture_output=True, text=True, timeout=3600)
            os.remove(database)
            if done.returncode != 0:
                results.append({'capture': os.path.basename(path), 'error': done.stderr[-400:]})
                print(f'[{index}] {os.path.basename(path)}: FAILED', file=sys.stderr)
                continue
            results.append(json.loads(done.stdout.strip().splitlines()[-1]))
            print(f'[{index}] {os.path.basename(path)}: {len(results[-1]["groups"])} groups',
                  file=sys.stderr)
    with open(args.out, 'w') as handle:
        json.dump(results, handle, indent=1)


if __name__ == '__main__':
    main()
