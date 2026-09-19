#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Turn two base-rate runs into the table that says what each rule is worth.

Reads the JSON `measure_rule_base_rates.py` writes for a benign corpus and for
a malicious one, and prints one row per rule.

Three columns decide everything, and they are not the same question:

* **benign captures fired on** — the number the network side has never had.
  A rule that fires on ordinary traffic is not thereby wrong, but it cannot
  carry a verdict by itself, exactly as in the APK engine.
* **malicious captures fired on** — whether the rule does anything at all.
* **findings per 1,000 flows** — because captures differ by three orders of
  magnitude in size, and "fired on 1 of 5" hides whether that was one finding
  or nine hundred.

A rule that fired nowhere is printed too, and marked. It is not validated; it
is untested, and the two must never be allowed to look alike.
"""

import argparse
import json
import math
from datetime import date

# Every rule the engine can emit, so a rule that fired nowhere still appears.
# Kept here rather than imported, because this script runs against result
# files that may have been produced by a different revision of the engine —
# and a row silently vanishing between runs is the thing to avoid.
ALL_RULES = [
    'C2_BEACON_PERIODIC',
    'C2_BEACON_KEEPALIVE',
    'COVERT_CHANNEL_UNKNOWN_PORT',
    'DNS_TUNNEL_LONG_LABEL',
    'DNS_TUNNEL_SUBDOMAIN_VOLUME',
    'EXFIL_VOLUME_ASYMMETRY',
    'ICMP_TUNNEL_OVERSIZED',
    'RECON_PORT_SCAN',
    'IOC_FEED_MATCH',
    'HOST_CORROBORATED',
    'ANOMALY_STATISTICAL',
]


def summarise(paths):
    """One run, or several runs over different corpora read as one."""
    merged = {'captures': [], 'label': 'none'}
    for path in paths or []:
        with open(path) as handle:
            run = json.load(handle)
        merged['captures'].extend(run.get('captures', []))
        merged['label'] = run.get('label', merged['label'])
    return merged


def tally(run):
    captures = run.get('captures', [])
    fired, findings, flows = {}, {}, 0
    for capture in captures:
        flows += capture.get('flows', 0)
        for rule, entry in (capture.get('by_rule') or {}).items():
            fired[rule] = fired.get(rule, 0) + 1
            findings[rule] = findings.get(rule, 0) + entry.get('count', 0)
    return captures, fired, findings, flows


def clopper_pearson_upper(fired, total):
    """One-sided 95% upper bound when nothing fired; else the plain rate."""
    if total == 0:
        return None
    if fired == 0:
        return 1 - 0.05 ** (1 / total)
    return fired / total


def exact_upper_95(fired, total):
    """
    One-sided 95% Clopper-Pearson upper bound on a rate seen as fired/total.

    The p at which seeing `fired` or fewer would happen only 5% of the time,
    found by bisection on the binomial CDF — no statistics library needed, and
    for fired == 0 it reduces to 1 - 0.05 ** (1 / total), the rule of three's
    exact form.
    """
    if total == 0:
        return None
    if fired >= total:
        return 1.0

    def cdf(p):
        return sum(math.comb(total, k) * p ** k * (1 - p) ** (total - k)
                   for k in range(fired + 1))

    low, high = fired / total, 1.0
    for _ in range(60):
        mid = (low + high) / 2
        if cdf(mid) > 0.05:
            low = mid
        else:
            high = mid
    return high


def emit(path, b_caps, b_fired, b_findings, m_caps, m_fired, measured, note):
    """The table the engine publishes with each finding (capture/base_rates.py)."""
    rules = {}
    for rule in ALL_RULES:
        bf, mf = b_fired.get(rule, 0), m_fired.get(rule, 0)
        rules[rule] = {
            'benign_fired': bf,
            'benign_captures': len(b_caps),
            'benign_findings': b_findings.get(rule, 0),
            'benign_upper95': round(exact_upper_95(bf, len(b_caps)), 4),
            'malicious_fired': mf,
            'malicious_captures': len(m_caps),
        }
    table = {
        'measured': measured,
        'method': note,
        'benign_corpus': sorted(c['capture'] for c in b_caps),
        'malicious_corpus': sorted(c['capture'] for c in m_caps),
        'rules': rules,
    }
    with open(path, 'w') as handle:
        json.dump(table, handle, indent=1, sort_keys=True)
        handle.write('\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--benign', required=True, action='append',
                        help='benign run; repeat to read several corpora as one')
    parser.add_argument('--malicious', action='append')
    parser.add_argument('--emit', help='also write the table the engine reads')
    parser.add_argument('--measured', default=date.today().isoformat())
    parser.add_argument('--note', default='research/158_NETWORK_RULES_MEASURED_AGAIN.md')
    args = parser.parse_args()

    benign_run = summarise(args.benign)
    malicious_run = summarise(args.malicious)

    b_caps, b_fired, b_findings, b_flows = tally(benign_run)
    m_caps, m_fired, m_findings, m_flows = tally(malicious_run)

    print(f'benign corpus   : {len(b_caps)} captures, {b_flows:,} flows')
    print(f'malicious corpus: {len(m_caps)} captures, {m_flows:,} flows')
    print()
    header = (f'{"rule":30s} {"benign":>12s} {"per 1k flows":>13s} '
              f'{"malicious":>11s} {"verdict-capable":>16s}')
    print(header)
    print('-' * len(header))

    for rule in ALL_RULES:
        bf, mf = b_fired.get(rule, 0), m_fired.get(rule, 0)
        b_rate = (b_findings.get(rule, 0) / b_flows * 1000) if b_flows else 0
        if bf == 0 and mf == 0:
            note = 'UNTESTED'
        elif bf == 0:
            note = 'yes'
        else:
            note = 'no — fires benign'
        print(f'{rule:30s} {bf:>5d}/{len(b_caps):<6d} {b_rate:>13.3f} '
              f'{mf:>5d}/{len(m_caps):<5d} {note:>16s}')

    print()
    if b_caps:
        bound = clopper_pearson_upper(0, len(b_caps)) or 0.0
        print(f'A rule that fired on 0 of {len(b_caps)} benign captures has a one-sided '
              f'95% upper bound of {bound * 100:.1f}% on its true benign rate. '
              f'{len(b_caps)} captures is a small corpus and that bound is wide; it is '
              f'reported so the weakness is visible rather than implied.')

    noisy = [(r, b_fired[r], b_findings[r]) for r in ALL_RULES if b_fired.get(r)]
    if noisy:
        print('\nFires on legitimate traffic (cannot carry a verdict alone):')
        for rule, caps, count in sorted(noisy, key=lambda r: -r[1]):
            print(f'  {rule:30s} {caps} capture(s), {count} finding(s)')

    if args.emit:
        emit(args.emit, b_caps, b_fired, b_findings, m_caps, m_fired,
             args.measured, args.note)
        print(f'\nwrote {args.emit}')

    untested = [r for r in ALL_RULES if not b_fired.get(r) and not m_fired.get(r)]
    if untested:
        print('\nFired nowhere in either corpus — untested, not validated:')
        for rule in untested:
            print(f'  {rule}')


if __name__ == '__main__':
    main()
