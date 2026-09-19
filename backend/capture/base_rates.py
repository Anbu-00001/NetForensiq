# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
What each network rule has been measured to do on ordinary traffic.

The APK engine will not let a signal raise a tier until it has been counted
against legitimate software, and every capability it reports carries that
count. The network rules had nothing equivalent until research/157 measured
them, and even then the number lived in a report nobody reading a finding
would see. An officer told "10.0.2.15 is beaconing" deserves to know, on the
same screen, how often the rule saying so says it about people browsing the
web.

The table is data/rule_base_rates.json, written by
scripts/rule_base_rate_report.py --emit from measured runs — never edited by
hand. Three things are read from it:

1. **Every finding carries its rule's measured rate** — `evidence
   ['measured_base_rate']`, including a sentence an officer can read aloud.
   It is copied into the finding when it is made, so a report printed later
   states what was known when the finding was made, not what is known now.

2. **Only rules that fired on no ordinary capture may corroborate.** The same
   bar as the APK engine: a signal that fires on legitimate traffic can be
   reported but cannot carry a conclusion. HOST_CORROBORATED — the one
   finding allowed to say CRITICAL — used to count agreement among rules that
   each fire on ordinary traffic, and fired on 7 of 16 benign captures and 0
   of 7 attacks. Agreement between unspecific rules is not evidence.

3. **A rule that has fired on ordinary traffic and never on an attack is
   capped at LOW.** It has not been shown to tell the two apart, whatever its
   thresholds cite; it stays visible, with its numbers, so nothing is hidden.

A rule missing from the table is *unmeasured*, which is not the same as
clean, and it is treated as unable to corroborate.
"""
import json
import os
from functools import lru_cache

TABLE_PATH = os.path.join(os.path.dirname(__file__), 'data', 'rule_base_rates.json')

# Never allowed to corroborate, whatever the table says: it is the
# unsupervised signal, and it is documented as a lead rather than a finding.
NEVER_CORROBORATES = {'ANOMALY_STATISTICAL', 'HOST_CORROBORATED'}


@lru_cache(maxsize=1)
def table():
    try:
        with open(TABLE_PATH) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {'rules': {}}


def rate(rule_id):
    return table().get('rules', {}).get(rule_id)


def may_corroborate(rule_id):
    measured = rate(rule_id)
    return (rule_id not in NEVER_CORROBORATES and measured is not None
            and measured['benign_fired'] == 0)


def unproven(rule_id):
    """Fired on ordinary traffic, never on an attack."""
    measured = rate(rule_id)
    return bool(measured and measured['benign_fired'] > 0
                and measured['malicious_fired'] == 0)


def statement(rule_id):
    measured = rate(rule_id)
    if measured is None:
        return ('This rule has not been measured against ordinary traffic. '
                'How often it fires on innocent traffic is unknown.')
    bf, bn = measured['benign_fired'], measured['benign_captures']
    mf, mn = measured['malicious_fired'], measured['malicious_captures']
    bound = measured['benign_upper95'] * 100
    text = (f'Measured {table().get("measured", "")}: this rule fired on {bf} of {bn} '
            f'captures of ordinary traffic (true rate plausibly up to {bound:.0f}%, '
            f'95% upper bound) and on {mf} of {mn} captures of real attacks.')
    if bf == 0 and mf == 0:
        return text + (' It has fired on neither, so it is untested rather than '
                       'validated: silence on ordinary traffic says nothing about '
                       'whether it catches anything.')
    if bf == 0:
        return text + ' It has not been seen to fire on ordinary traffic.'
    if mf == 0:
        return text + (' It has not been shown to tell an attack from ordinary '
                       'traffic, so it is reported at LOW and cannot count towards '
                       'corroboration.')
    return text + (' It fires on ordinary traffic, so on its own it is a reason to look, '
                   'not a conclusion, and it cannot count towards corroboration.')


def annotate(finding):
    """Attach the measured rate to a finding, and apply the LOW cap."""
    from .models import Detection

    measured = rate(finding.rule_id)
    evidence = dict(finding.evidence or {})
    evidence['measured_base_rate'] = {
        **(measured or {}),
        'measured': table().get('measured') if measured else None,
        'source': table().get('method') if measured else None,
        'may_corroborate': may_corroborate(finding.rule_id),
        'statement': statement(finding.rule_id),
    }
    if unproven(finding.rule_id) and finding.severity != Detection.Severity.LOW:
        evidence['measured_base_rate']['severity_as_written'] = finding.severity
        finding.severity = Detection.Severity.LOW
    finding.evidence = evidence
    return finding
