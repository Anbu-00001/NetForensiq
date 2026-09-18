"""
Was this package built to defeat analysis tools?

The question is answered from the file's structure, using apkInspector, which
parses a ZIP the way Android's installer does rather than the way the ZIP
specification says to. That difference is the whole attack: Android treats an
unknown compression method as a supported one and installs the app, while
JADX, APKtool and Androguard refuse the same entry (Zimperium, 2023). A sample
whose manifest no tool can read reports no permissions — the evasion makes the
most dangerous samples look the most harmless.

What changed from the old module
================================
The old code added 35 points whenever *its own* parser failed on a manifest.
That rewarded our bugs, not the sample's tricks. Here every indicator is a
specific structural fact apkInspector reports, with the bytes that prove it.

Why each indicator carries its own base rate
============================================
apkInspector's authors ran it over top apps and found that a few *legitimate*
APKs have discrepancies between local and central headers, and some have more
than one end-of-central-directory record — which is why the library has a
non-strict mode that ignores those fields. So "tampered" is not one signal. Each
indicator below is reported separately, and only those measured at zero on the
legitimate corpus may raise the evidence tier (see baselines.py).
"""

import io
import contextlib

from .sources import cite, attack

# indicator id -> (title, what it means, sources)
INDICATORS = {
    'zip.unknown_compression_method': (
        'Compression method field forged',
        'An entry declares a compression method that is neither stored (0) nor deflate (8). '
        'Android installs such packages regardless; general-purpose tools refuse the entry.',
        ('zimperium-2023-compression', 'konfety-2025', 'apkinspector'),
    ),
    'zip.header_mismatch': (
        'Local and central headers disagree',
        'The two copies of an entry\'s header — which the ZIP format requires to agree — '
        'contain different values in fields legitimate APKs do not vary.',
        ('apkinspector',),
    ),
    'zip.entry_sets_differ': (
        'Entries present in only one directory',
        'Some entries exist only in the central directory or only as local headers, so '
        'different parsers see different file lists.',
        ('apkinspector',),
    ),
    'zip.path_collisions': (
        'File and directory names collide',
        'An entry name is used both as a file and as a directory prefix.',
        ('apkinspector',),
    ),
    'zip.empty_filename': (
        'Entry with an empty name',
        'A central-directory entry has no filename.',
        ('apkinspector',),
    ),
    'zip.encryption_flag_on_package': (
        'Encryption flag set on an unencrypted package',
        'General-purpose bit 0 is set, so tools treat the APK as password-protected, while '
        'Android ignores the flag and installs it.',
        ('konfety-2025',),
    ),
    'zip.oversized_filename': (
        'Entry name longer than Android accepts',
        'An entry name exceeds 255 bytes; Android and analysis tools disagree on how to handle it.',
        ('zimperium-2023-compression',),
    ),
    'axml.bad_magic': (
        'Manifest does not start like binary XML',
        'AndroidManifest.xml begins with an unexpected chunk type.',
        ('apkinspector',),
    ),
    'axml.string_count_mismatch': (
        'Manifest string pool count forged',
        'The string pool declares a different number of strings than it contains.',
        ('zimperium-2023-compression', 'apkinspector'),
    ),
    'axml.attribute_size': (
        'Manifest attribute size forged',
        'Element attributes declare a non-standard size.',
        ('apkinspector',),
    ),
    'axml.attribute_start': (
        'Manifest attribute offset forged',
        'Element attributes declare a non-standard start offset.',
        ('apkinspector',),
    ),
    'axml.attribute_names': (
        'Manifest attribute names blanked',
        'Attributes reference empty name strings, relying on the resource map alone.',
        ('apkinspector',),
    ),
    'axml.junk_between_elements': (
        'Data injected between manifest elements',
        'Bytes that belong to no element sit between XML chunks.',
        ('apkinspector',),
    ),
    'axml.zero_size_namespace_end': (
        'Namespace end chunk with zero size',
        'A namespace-end node declares a zero-size header.',
        ('apkinspector',),
    ),
    'axml.unknown_chunk': (
        'Unknown chunk type in manifest',
        'The manifest contains a chunk type binary XML does not define.',
        ('apkinspector',),
    ),
}

_MANIFEST_KEYS = {
    'unexpected_starting_signature_of_androidmanifest': 'axml.bad_magic',
    'string_pool': 'axml.string_count_mismatch',
    'unexpected_attribute_size': 'axml.attribute_size',
    'unexpected_attribute_start': 'axml.attribute_start',
    'unexpected_attribute_names': 'axml.attribute_names',
    'invalid_data_between_elements': 'axml.junk_between_elements',
    'zero_size_header_for_namespace_end_nodes': 'axml.zero_size_namespace_end',
    'unknown_chunk_type': 'axml.unknown_chunk',
}


def _finding(indicator_id, evidence):
    title, meaning, source_keys = INDICATORS[indicator_id]
    return {
        'id': indicator_id,
        'title': title,
        'meaning': meaning,
        'evidence': evidence,
        'sources': cite(*source_keys),
        'attack': attack('T1406'),
    }


def check(apk_bytes):
    """
    Return every structural tampering indicator found, with its evidence.

    ``checked`` is False only if apkInspector itself could not parse the file;
    the reason is kept, and nothing is inferred from the failure.
    """
    from apkInspector.headers import ZipEntry
    from apkInspector.indicators import (
        extract_file_based_on_header_info,
        manifest_tampering_indicators,
        zip_tampering_indicators,
    )

    result = {'checked': False, 'error': '', 'findings': []}
    found = {}

    def add(indicator_id, evidence):
        found.setdefault(indicator_id, []).append(evidence)

    try:
        with contextlib.redirect_stdout(io.StringIO()):
            zip_report = zip_tampering_indicators(io.BytesIO(apk_bytes), False)
            entries = ZipEntry.parse(io.BytesIO(apk_bytes)).to_dict()
    except Exception as exc:
        result['error'] = f'apkInspector could not parse the ZIP structure: {exc}'
        return result

    for key, value in zip_report.items():
        if key == 'empty_keys':
            add('zip.empty_filename', {'present': bool(value)})
        elif key == 'unique_entries':
            add('zip.entry_sets_differ', {'entries': sorted(map(str, value))[:20]})
        elif key == 'path_collisions':
            add('zip.path_collisions', {'count': value})
        elif isinstance(value, dict):
            methods = {k: v for k, v in value.items() if 'compression method' in k}
            if 'central compression method' in value or 'local compression method' in value:
                add('zip.unknown_compression_method', dict(entry=key, **{
                    k.replace(' ', '_'): v for k, v in methods.items()}))
            if value.get('differing headers'):
                add('zip.header_mismatch', {'entry': key, 'fields': value['differing headers']})

    central = entries.get('central_directory', {})
    local = entries.get('local_headers', {})
    for name in set(central) | set(local):
        flags = [h.get('general_purpose_bit_flag', 0) for h in (central.get(name), local.get(name)) if h]
        if any(f & 0x1 for f in flags):
            add('zip.encryption_flag_on_package', {'entry': name, 'flags': flags})
        if len(str(name).encode('utf-8', 'replace')) > 255:
            add('zip.oversized_filename', {'entry': str(name)[:80] + '…',
                                           'bytes': len(str(name).encode('utf-8', 'replace'))})

    manifest_central = central.get('AndroidManifest.xml')
    manifest_local = local.get('AndroidManifest.xml')
    if manifest_central and manifest_local:
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                manifest_bytes = extract_file_based_on_header_info(
                    io.BytesIO(apk_bytes), manifest_local, manifest_central)[0]
                manifest_report = manifest_tampering_indicators(io.BytesIO(manifest_bytes))
            for key, value in manifest_report.items():
                indicator = _MANIFEST_KEYS.get(key)
                if indicator:
                    add(indicator, value if isinstance(value, dict) else {'value': value})
        except Exception as exc:
            result['error'] = f'AndroidManifest.xml structure could not be checked: {exc}'

    # Encryption-flag findings on *every* entry would drown the report for a
    # Konfety-style sample; one finding with the first few entries is enough.
    for indicator_id, evidence in sorted(found.items()):
        result['findings'].append(_finding(indicator_id, {
            'count': len(evidence), 'examples': evidence[:5]}))
    result['checked'] = True
    return result
