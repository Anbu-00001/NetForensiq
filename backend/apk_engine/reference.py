"""
Loaders for the bundled reference data (see data/sources.json for provenance).
"""

import functools
import json
import os
import re

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


def _load_json(name):
    with open(os.path.join(DATA_DIR, name), encoding='utf-8') as handle:
        return json.load(handle)


@functools.lru_cache(maxsize=1)
def sources():
    try:
        return _load_json('sources.json')
    except FileNotFoundError:
        return {}


@functools.lru_cache(maxsize=1)
def trackers():
    return _load_json('exodus_trackers.json')['trackers']


@functools.lru_cache(maxsize=1)
def tracker_code_prefixes():
    """(package prefix, tracker name) pairs, for attributing code."""
    pairs = []
    for tracker in trackers():
        for prefix in (tracker.get('code_signature') or '').split('|'):
            prefix = prefix.strip()
            if prefix:
                pairs.append((prefix if prefix.endswith('.') else prefix + '.', tracker['name']))
    return tuple(pairs)


@functools.lru_cache(maxsize=1)
def tracker_network_patterns():
    """(compiled host regex, tracker name) pairs, for attributing endpoints."""
    patterns = []
    for tracker in trackers():
        signature = tracker.get('network_signature') or ''
        if signature:
            try:
                patterns.append((re.compile(signature, re.I), tracker['name']))
            except re.error:
                continue
    return tuple(patterns)


@functools.lru_cache(maxsize=1)
def tlds():
    with open(os.path.join(DATA_DIR, 'tlds.txt'), encoding='ascii') as handle:
        return frozenset(line.strip().lower() for line in handle
                         if line.strip() and not line.startswith('#'))


@functools.lru_cache(maxsize=1)
def stalkerware():
    return _load_json('stalkerware_indicators.json')
