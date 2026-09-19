# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Which signals have earned the right to move a verdict.

Every integrity indicator, capability and behaviour is a *signal*, and each has
a measured record: how many apps in the legitimate corpus it fired on, and how
many in the malicious corpus. The record is produced by ``python -m apk_engine
evaluate`` and stored in data/baselines.json together with the list of corpus
files by SHA-256, so the measurement can be repeated.

A signal is **validated** — allowed to raise the evidence tier — only if it
fired on *zero* legitimate apps in a corpus of at least MIN_BENIGN. Anything
that fired on a legitimate app is **experimental**: reported, with its count,
and unable to change the verdict. A signal with no record is **unmeasured** and
treated the same way. This is the base-rate discipline Arp et al. call P8 in
"Dos and Don'ts of Machine Learning in Computer Security": a detector's value
depends on how often it fires where the thing it detects is absent.

Validated is not a promise. With zero firings in n apps the exact 95% upper
bound on the false-positive rate is 1 - 0.05**(1/n) — about 9% for n = 31 —
and the report prints that bound beside every count.
"""

import json
import os

from .stats import upper_bound

DEFAULT_PATH = os.path.join(os.path.dirname(__file__), 'data', 'baselines.json')

# Below this many legitimate apps a zero count bounds nothing useful (the 95%
# upper bound is above 10%), so no signal is validated on a smaller corpus.
MIN_BENIGN = 30


def load(path=None):
    path = path or os.environ.get('APK_ENGINE_BASELINES') or DEFAULT_PATH
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def status(baselines, signal_id):
    corpus = baselines.get('corpus', {})
    benign_n = corpus.get('benign', 0)
    malicious_n = corpus.get('malicious', 0)
    record = baselines.get('signals', {}).get(signal_id)
    if record is None or benign_n == 0:
        return {'status': 'unmeasured', 'benign_fired': None, 'benign_n': benign_n,
                'malicious_fired': None, 'malicious_n': malicious_n,
                'upper_bound_95': None, 'measured_at': baselines.get('measured_at', '')}
    benign_fired = record.get('benign_fired', 0)
    if benign_fired == 0 and benign_n >= MIN_BENIGN:
        verdict = 'validated'
    else:
        verdict = 'experimental'
    bound = upper_bound(benign_fired, benign_n)
    return {
        'status': verdict,
        'benign_fired': benign_fired, 'benign_n': benign_n,
        'benign_examples': record.get('benign_examples', [])[:5],
        'malicious_fired': record.get('malicious_fired', 0), 'malicious_n': malicious_n,
        'upper_bound_95': round(bound, 4) if bound is not None else None,
        'measured_at': baselines.get('measured_at', ''),
    }
