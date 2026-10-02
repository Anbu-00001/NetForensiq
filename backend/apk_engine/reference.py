# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Loaders for the bundled reference data (see data/sources.json for provenance).
"""

import functools
import json
import os
import re

PACKAGE_DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
# What callers have always meant by DATA_DIR: the data shipped in this package.
DATA_DIR = PACKAGE_DATA_DIR

# The files a signed update bundle may replace (capture/updates.py). Reference
# data about *what exists in the world* — trackers, stalkerware indicators, the
# list of top-level domains — which is the kind of data that goes stale.
#
# Deliberately not on this list:
#   baselines.json    defines which signals count as validated. Changing it
#                     changes the method, which is re-validation (research/163),
#                     not an update.
#   known_signers.json  asserts which signing keys belong to which publishers.
#                     A wrong entry makes a forged app look genuine, or a
#                     genuine one look forged, so it ships with the software and
#                     is reviewed with it.
UPDATABLE = ('exodus_trackers.json', 'stalkerware_indicators.json', 'tlds.txt')


def data_path(name):
    """
    Where to read `name` from: the update overlay when it supplies the file,
    otherwise the data shipped in the package.

    The overlay is a directory named by APK_ENGINE_DATA_DIR, set by the web
    process from the last applied update bundle. Only files in UPDATABLE are ever
    taken from it, so a malformed or hostile overlay cannot replace the
    baselines. With no overlay this returns exactly what it always did.
    """
    overlay = os.environ.get('APK_ENGINE_DATA_DIR', '')
    if overlay and name in UPDATABLE:
        candidate = os.path.join(overlay, name)
        if os.path.isfile(candidate):
            return candidate
    return os.path.join(PACKAGE_DATA_DIR, name)


def _load_json(name):
    with open(data_path(name), encoding='utf-8') as handle:
        return json.load(handle)


@functools.lru_cache(maxsize=1)
def sources():
    try:
        with open(os.path.join(PACKAGE_DATA_DIR, 'sources.json'), encoding='utf-8') as handle:
            merged = json.load(handle)
    except FileNotFoundError:
        merged = {}
    # An applied update records where its files came from, in its own
    # sources.json inside the overlay. Entries for anything not updatable are
    # ignored, for the same reason the files are.
    overlay = os.environ.get('APK_ENGINE_DATA_DIR', '')
    if overlay:
        try:
            with open(os.path.join(overlay, 'sources.json'), encoding='utf-8') as handle:
                merged.update({k: v for k, v in json.load(handle).items() if k in UPDATABLE})
        except (OSError, ValueError):
            pass
    return merged


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
    with open(data_path('tlds.txt'), encoding='ascii') as handle:
        return frozenset(line.strip().lower() for line in handle
                         if line.strip() and not line.startswith('#'))


@functools.lru_cache(maxsize=1)
def stalkerware():
    return _load_json('stalkerware_indicators.json')
