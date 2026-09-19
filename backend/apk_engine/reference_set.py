# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Does this package have the identity it claims?

Why this layer exists
=====================
The behaviour rules ask what a package *does*. For the fraud that actually
reaches Indian complainants — an APK called "PENSION CARD VERIFICATION", a fake
bank, a fake e-challan, a fake pay-commission calculator — the question worth
answering first is what the package *claims to be*, because the answer is an
identity fact rather than a statistical one:

    This file declares the package name ``com.example.pension``. The reference
    set records that name as signed by certificate A. This file is signed by
    certificate B. They are different keys, so this file was not produced by
    the holder of A.

That statement is certain, reproducible by the defence, and needs no corpus.
What it does *not* establish is malice, and nothing here says otherwise: the
same application legitimately redistributed through another store is signed by
a different key too. Which is why the strength of the finding is taken from the
reference entry's own declared authority, not assumed:

``publisher``
    The examiner asserts this is *the* authorised signing key — taken from the
    app's own listing on the store that distributes it. A mismatch then means
    the file is not the publisher's. Tier 3.
``distributor``
    The key was observed on a build from one distribution channel (this is what
    :func:`build` produces automatically). A mismatch means only that the file
    is not *that* build. Tier 2, and the finding says so in those words.

Baselines do not apply here, deliberately, and for the same reason they do not
apply to an intelligence identity match (see intel.py): a mismatch is not a
detector that could fire by chance on a legitimate app, it is a comparison of
two certificate digests. What it *is* sensitive to is the reference set being
wrong, so every entry carries the file it was measured from.

The reference set ships nearly empty on purpose. It is built where it is
deployed::

    python -m apk_engine reference --from /path/to/trusted/apks \\
        --authority publisher --note "Downloaded from Google Play, 18 Sep 2026"

A forensic laboratory points that at the genuine government and banking apps it
has acquired, and from then on every examination is checked against them.
"""

import datetime
import json
import os
import re

from . import reference

# Google requires a signing key whose validity ends after this date for
# publication on Play ("the key you use to sign your app must have a validity
# period ending after 22 October 2033"), so a certificate expiring earlier
# cannot have signed a Play-distributed build under that key.
# https://developer.android.com/studio/publish/app-signing
PLAY_MINIMUM_NOT_AFTER = datetime.date(2033, 10, 22)

DATA_FILE = 'known_signers.json'
AUTHORITY_TIER = {'publisher': 3, 'distributor': 2}


def load():
    try:
        with open(os.path.join(reference.DATA_DIR, DATA_FILE), encoding='utf-8') as handle:
            return json.load(handle)
    except (FileNotFoundError, ValueError):
        return {'entries': {}, 'built': '', 'note': '', 'entry_count': 0}


def _normalised(label):
    """A label reduced to what a person reading it on a launcher would compare."""
    return re.sub(r'[^a-z0-9]+', '', (label or '').casefold())


def _not_after(certificate):
    raw = (certificate or {}).get('not_after') or ''
    try:
        return datetime.date.fromisoformat(raw[:10])
    except ValueError:
        return None


def check(identity, data=None):
    """
    Compare a package's claimed identity against the reference set.

    Returns the same shape whether or not the set is populated, so the report
    always states what it was checked against — including "nothing".
    """
    data = load() if data is None else data
    entries = data.get('entries') or {}
    result = {
        'checked_against': {'entries': len(entries), 'built': data.get('built', ''),
                            'note': data.get('note', '')},
        'findings': [],
        'claims': {'package': (identity or {}).get('package') or '',
                   'label': (identity or {}).get('label') or ''},
    }
    if not identity:
        return result

    package = result['claims']['package']
    label = result['claims']['label']
    certificates = (identity.get('signing') or {}).get('certificates') or []
    present = {c['sha256'] for c in certificates}

    entry = entries.get(package)
    if entry and present and not (present & set(entry.get('certificates_sha256') or [])):
        authority = entry.get('authority', 'distributor')
        tier = AUTHORITY_TIER.get(authority, 2)
        if authority == 'publisher':
            title = f'Not signed by the authorised key for {package}'
            statement = (
                f'The package declares the name {package}. The reference set records that name '
                f'as signed by {entry["certificates_sha256"][0][:16]}…, on the authority of '
                f'"{entry.get("source", {}).get("note", "the examiner")}". This file is signed by '
                f'{sorted(present)[0][:16]}…. The keys differ, so this file was not produced by '
                'the holder of the authorised key.')
        else:
            title = f'Not the recorded build of {package}'
            statement = (
                f'The package declares the name {package}, which the reference set records with a '
                f'different signing key, observed on a build from '
                f'"{entry.get("source", {}).get("note", "another channel")}". This file is '
                'therefore not that build. A legitimate redistribution through another store '
                'would also differ, so this alone does not establish who produced the file.')
        result['findings'].append({
            'id': 'identity.signer_not_authorised', 'title': title, 'statement': statement,
            'establishes': 'identity', 'tier': tier, 'authority': authority,
            'claimed_package': package,
            'expected_sha256': list(entry.get('certificates_sha256') or []),
            'observed_sha256': sorted(present),
            'source': entry.get('source', {}),
            'lookalikes': ['The same application redistributed by another store, which signs '
                           'with its own key (F-Droid and Google Play builds of the same app '
                           'differ this way).',
                           'An enterprise or government re-signing of a genuine app.'],
        })

    # A name on the launcher that belongs to a package in the reference set,
    # carried by a package that is not it.
    if label and package not in entries:
        wanted = _normalised(label)
        for known_package, known in entries.items():
            if wanted and wanted == _normalised(known.get('label')):
                result['findings'].append({
                    'id': 'identity.label_claims_another_package',
                    'title': f'Presents itself as "{known.get("label")}" under a different package name',
                    'statement': (
                        f'The launcher label is "{label}". The reference set records that label '
                        f'for the package {known_package}; this file declares {package}. The name '
                        'a user sees and the identity Android enforces do not agree.'),
                    'establishes': 'claim', 'tier': 0,
                    'claimed_package': package, 'impersonates': known_package,
                    'source': known.get('source', {}),
                    'lookalikes': ['Two unrelated applications can share a generic label.',
                                   'A publisher shipping the same app under a second package name.'],
                })
                break

    for certificate in certificates:
        expiry = _not_after(certificate)
        if expiry and expiry < PLAY_MINIMUM_NOT_AFTER:
            result['findings'].append({
                'id': 'cert.expires_before_play_minimum',
                'title': 'Signing certificate expires too early for Google Play',
                'statement': (
                    f'The signing certificate is valid until {expiry.isoformat()}. Google requires '
                    f'a key whose validity ends after {PLAY_MINIMUM_NOT_AFTER.isoformat()} for '
                    'publication on Play, so this file was not distributed through Play under '
                    'this key.'),
                'establishes': 'claim', 'tier': 0,
                'certificate_sha256': certificate['sha256'],
                'not_after': certificate.get('not_after', ''),
                'source': {'note': 'developer.android.com/studio/publish/app-signing'},
                'lookalikes': ['Applications distributed outside Play — F-Droid builds, in-house '
                               'and government distributions — are under no such requirement.'],
            })
            break

    return result


# ── building a reference set ────────────────────────────────────────────────

def build(apk_paths, authority='distributor', note=''):
    """
    Read trusted packages and record package name → authorised signing keys.

    Every entry names the file it came from, by SHA-256, so a disputed entry can
    be traced back to the package it was measured from.
    """
    import hashlib

    from loguru import logger
    logger.disable('androguard')
    from androguard.core.apk import APK

    from .identity import read_identity

    entries, failures = {}, []
    for path in sorted(apk_paths):
        try:
            identity = read_identity(APK(path, raw=False))
        except Exception as exc:
            failures.append(f'{os.path.basename(path)}: {type(exc).__name__}: {exc}')
            continue
        package = identity.get('package')
        digests = sorted({c['sha256'] for c in identity['signing']['certificates']})
        if not package or not digests:
            failures.append(f'{os.path.basename(path)}: no package name or no certificate')
            continue
        with open(path, 'rb') as handle:
            file_sha256 = hashlib.sha256(handle.read()).hexdigest()
        existing = entries.get(package, {'certificates_sha256': []})
        entries[package] = {
            'label': identity.get('label') or '',
            'certificates_sha256': sorted(set(existing['certificates_sha256']) | set(digests)),
            'authority': authority,
            'source': {'file': os.path.basename(path), 'sha256': file_sha256,
                       'version_name': identity.get('version_name') or '', 'note': note},
        }
    return {
        'schema': 'netforensiq.apk-reference-set/1',
        'built': datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        'authority': authority,
        'note': note,
        'entry_count': len(entries),
        'entries': dict(sorted(entries.items())),
        'failures': failures,
    }


def write(data, path=None):
    path = path or os.path.join(reference.DATA_DIR, DATA_FILE)
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
        handle.write('\n')
    return path
