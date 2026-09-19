# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Where does this app keep its logic — and did we actually read it?

Why this exists
===============
``codemap`` indexes DEX bytecode. An app built with Flutter, React Native,
.NET MAUI, Unity or Cordova keeps its logic somewhere else entirely: an ELF
snapshot, a Hermes bytecode bundle, packed CIL assemblies, or JavaScript under
``assets/``. For such an app androguard sees a bootstrap stub, every capability
detector finds nothing, and the verdict comes out tier 1 — *"No harmful
behaviour established"*.

For a banking trojan written in Flutter that sentence is false reassurance, and
false reassurance in a forensic report is the failure this engine exists to
avoid. So the gap is reported: the examiner is told which runtime holds the
code and that it was not examined, rather than being shown an empty findings
list that reads like a clean result.

Being a framework app is ordinary and proves nothing. Measured on the 300
held-out F-Droid packages, 42 (14.0%) are framework-based — 28 Flutter, 8
Cordova, 6 React Native with Hermes, 1 React Native. Nothing here raises a
tier; it only records what was and was not read.

Marker paths are each framework's own published layout, not a vendor claim.
"""

import re
import zipfile

RUNTIMES = {
    'flutter': {
        'name': 'Flutter (Dart, compiled ahead of time)',
        'holds': 'lib/<abi>/libapp.so',
        'markers': (r'^lib/[^/]+/libflutter\.so$', r'^lib/[^/]+/libapp\.so$',
                    r'^assets/flutter_assets/'),
    },
    'react_native_hermes': {
        'name': 'React Native with Hermes bytecode',
        'holds': 'assets/index.android.bundle',
        'markers': (r'^assets/index\.android\.bundle$', r'^lib/[^/]+/libhermes'),
    },
    'react_native': {
        'name': 'React Native (JavaScript bundle)',
        'holds': 'assets/index.android.bundle',
        'markers': (r'^lib/[^/]+/libreactnativejni\.so$',),
    },
    'dotnet': {
        'name': '.NET (Xamarin or MAUI) managed assemblies',
        'holds': 'assemblies/',
        'markers': (r'^assemblies/', r'^lib/[^/]+/libmonodroid\.so$',
                    r'^lib/[^/]+/libnetcoremain\.so$', r'^lib/[^/]+/libxamarin-app\.so$'),
    },
    'unity': {
        'name': 'Unity with the IL2CPP backend',
        'holds': 'lib/<abi>/libil2cpp.so',
        'markers': (r'^lib/[^/]+/libil2cpp\.so$', r'^lib/[^/]+/libunity\.so$',
                    r'^assets/bin/Data/Managed/Metadata/global-metadata\.dat$'),
    },
    'web': {
        'name': 'Cordova or Capacitor (JavaScript in assets)',
        'holds': 'assets/www/',
        'markers': (r'^assets/www/index\.html$', r'^assets/www/cordova\.js$',
                    r'^assets/public/index\.html$'),
    },
}
COMPILED = {key: tuple(re.compile(p) for p in spec['markers']) for key, spec in RUNTIMES.items()}

# A DEX this small alongside a framework runtime is a bootstrap, not an
# application. Chosen as an order-of-magnitude line, not a tuned threshold, and
# reported as such: it only decides how strongly the gap is worded.
STUB_DEX_BYTES = 400_000


def detect(names):
    """Which runtimes this package carries, from its ZIP entry names."""
    found = []
    for key, patterns in COMPILED.items():
        if any(p.match(n) for n in names for p in patterns):
            found.append(key)
    # React Native with Hermes already implies React Native.
    if 'react_native_hermes' in found and 'react_native' in found:
        found.remove('react_native')
    return found


def gaps(found, dex_bytes):
    """
    Plain sentences naming what was not examined. Empty when there is nothing
    to disclose.
    """
    notes = []
    for key in found:
        spec = RUNTIMES[key]
        notes.append(
            f"This package carries {spec['name']}. Code written for that runtime lives in "
            f"{spec['holds']}, which this engine does not read: only DEX bytecode is indexed. "
            'Behaviour implemented there has not been examined.')
    if found and dex_bytes is not None and dex_bytes < STUB_DEX_BYTES:
        notes.append(
            f'Its DEX is {dex_bytes:,} bytes, small enough to be a bootstrap for that runtime '
            'rather than the application itself, so most of this package was not examined.')
    return notes


# Where a dropper's second stage is carried, if it ships with one.
PAYLOAD_DIRS = ('assets/', 'res/raw/')
PAYLOAD_MAGIC = {b'PK\x03\x04': 'archive', b'dex\n': 'dex'}
MAX_ENTRIES_CHECKED = 400


# An opaque payload: a large entry whose bytes are indistinguishable from random.
#
# Measured on 19 Sep 2026, the design corpus: a DEX under 100 KB beside an entry of
# at least 1 MB at entropy >= 7.99 fired on 38 of 200 malicious samples and on 0 of
# 300 F-Droid apps — and the counts did not move across any threshold tried between
# 7.98 and 7.99, 500 KB and 1 MB, or 100 KB and 200 KB of DEX, which is the reason
# to trust it is describing a structure rather than a fitted cut.
#
# Deliberately NOT filtered by extension. The first version of this measurement
# excluded .dat and .pak as "naturally compressed" and missed exactly the samples
# it was looking for: the payloads were named dbliqgnjl.dat, core_profile.pak and
# util_index.cache. A name is the payload's author's choice.
#
# The entropy window is the first 64 KB, the same window the measurement used. A
# real compressed format also scores high, which is why this is only ever read
# together with a stub-sized DEX (behaviours._encrypted_code_payload).
OPAQUE_MIN_BYTES = 1_000_000
OPAQUE_MIN_ENTROPY = 7.99
OPAQUE_WINDOW = 65536
OPAQUE_MAX_CHECKED = 64


def _entropy(data):
    if not data:
        return 0.0
    import math
    from collections import Counter
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def opaque_payloads(apk_path):
    """
    Large entries outside lib/ whose first 64 KB are statistically random.

    Bounded twice: only entries of at least 1 MB are read, only their first 64 KB,
    and at most OPAQUE_MAX_CHECKED of them — a package cannot make this read more
    than 4 MB however it is built.
    """
    found = []
    try:
        archive = zipfile.ZipFile(apk_path)
    except Exception:
        return found
    checked = 0
    for info in archive.infolist():
        if checked >= OPAQUE_MAX_CHECKED:
            break
        name = info.filename
        if (info.is_dir() or info.file_size < OPAQUE_MIN_BYTES or name.startswith('lib/')
                or (name.startswith('classes') and name.endswith('.dex'))):
            continue
        checked += 1
        try:
            with archive.open(info) as handle:
                head = handle.read(OPAQUE_WINDOW)
        except Exception:
            continue
        score = _entropy(head)
        if score >= OPAQUE_MIN_ENTROPY:
            found.append({'name': name, 'size': info.file_size, 'entropy': round(score, 4)})
    return found


def bundled_payloads(apk_path):
    """
    Entries under assets/ or res/raw/ that are themselves an archive or a DEX.

    Identified by magic bytes, not by extension, because a dropper that names
    its payload ``config.dat`` is the normal case rather than the exception.
    Reads eight bytes per entry and stops after MAX_ENTRIES_CHECKED, so a
    package with tens of thousands of entries cannot turn this into a denial of
    service against the examiner.
    """
    found = []
    try:
        archive = zipfile.ZipFile(apk_path)
    except Exception:
        return found
    checked = 0
    for info in archive.infolist():
        if checked >= MAX_ENTRIES_CHECKED:
            break
        if not info.filename.startswith(PAYLOAD_DIRS) or info.file_size < 1024:
            continue
        checked += 1
        try:
            with archive.open(info) as handle:
                head = handle.read(8)
        except Exception:
            continue
        for magic, kind in PAYLOAD_MAGIC.items():
            if head.startswith(magic):
                found.append(f'{info.filename} ({kind}, {info.file_size:,} bytes)')
                break
    return found
