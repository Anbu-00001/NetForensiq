# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The case package: one signed JSON file a lab can hand to a court, to defence
counsel or to another laboratory, and that the other side can check on their own
machine without this software and without a network.

What is in it
-------------
For each exhibit: the identity and hashes the Section 63 certificate certifies,
the acquisition block, a content re-check made at export time, the *whole*
custody log with every field that goes into each entry hash, and the
certificates' own particulars with the SHA-256 of each rendered PDF. For the
tool: its version and the SHA-256 of the two measurement tables its findings
rest on. Not in it: the evidence bytes (the recipient already has the file or
will be given it separately — the package says what its hash must be), stored
paths, account names, or any packet content.

What checking it proves — and what it cannot
--------------------------------------------
* The signature proves the manifest has not been altered since it was signed and
  was signed by the holder of a particular key.
* The custody chain proves the log is internally consistent: no entry changed,
  none removed from the middle, sequence unbroken.
* A recipient with the exhibit file can hash it and see whether it is the file
  the package describes.

It does **not** prove the key belongs to the laboratory it claims to — the
recipient must compare the key fingerprint with one obtained some other way —
and a chain cannot show that the whole log was not rebuilt *before* signing,
which only an external anchor could. The verifier states both.

Why the manifest is a string inside the envelope
------------------------------------------------
The signature covers the exact bytes of `manifest_json`. Signing a parsed object
would require both sides to serialise it identically — key order, whitespace,
number formatting, unicode escaping — and the first mismatch looks exactly like
tampering. Signing the text sidesteps canonicalisation entirely.
"""
import base64
import hashlib
import json
import re
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from . import signing

FORMAT = 'netforensiq.case-package/1'
MANIFEST_SCHEMA = 'netforensiq.case-manifest/1'
# Prepended to what is signed, so this signature cannot be replayed as one over
# a different document type.
CONTEXT = b'netforensiq.case-package/1\n'

# How a custody entry hash is made, stated in the package itself so a recipient
# who has never seen this software can reproduce it with sha256sum.
CHAIN_RECIPE = (
    "sha256 of the UTF-8 text formed by joining these fields with '|': "
    'evidence_id, sequence, action, actor_badge, actor_ip, detail, timestamp, '
    "previous_hash. Only detail may contain '|', so the text splits one way only."
)

# Fields of a custody entry that must not contain '|'. With these free of it, the
# hashed text has exactly one reading; a package where one holds '|' is rejected,
# because its fields could have been re-split without changing any hash.
NO_PIPE_FIELDS = ('action', 'actor_badge', 'actor_ip', 'timestamp', 'previous_hash')

HOW_TO_VERIFY = (
    'Open nfverify.html (a single offline page; it makes no network requests), '
    'choose this file, and compare the key fingerprint it shows with one you '
    'obtained from the laboratory by some other route. Then, to check an '
    'exhibit file or a certificate PDF, choose it too.'
)

_HEX64 = re.compile(r'^[0-9a-f]{64}$')


class PackageError(Exception):
    """The package cannot be built as asked."""


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def _optional_sha256(path):
    try:
        return _sha256_file(path)
    except OSError:
        return None


def _iso(value):
    return value.isoformat() if value else None


def custody_entry(event):
    """
    One log entry, with the exact strings that were hashed.

    `actor_badge` and `actor_ip` are stringified the way `compute_hash` does it
    (`None` becomes the empty string), and `timestamp` is `isoformat()` — which
    omits the fractional part when the microsecond is zero, a difference a
    reimplementation formatting dates itself would get wrong. The recipient is
    given the string, not asked to reconstruct it.
    """
    return {
        'sequence': event.sequence,
        'action': event.action,
        'actor_badge': str(event.actor_badge or ''),
        'actor_ip': str(event.actor_ip or ''),
        'detail': event.detail or '',
        'timestamp': event.timestamp.isoformat() if event.timestamp else '',
        'previous_hash': event.previous_hash or '',
        'entry_hash': event.entry_hash,
    }


def _certificate(cert):
    return {
        'reference': cert.reference,
        'issued_at': _iso(cert.generated_at),
        'is_complete': cert.is_complete,
        'certified_sha256': cert.certified_sha256,
        'certified_sha1': cert.certified_sha1,
        'certified_md5': cert.certified_md5,
        'certified_algorithm': cert.certified_algorithm,
        'part_a': {
            'name': cert.part_a_name, 'designation': cert.part_a_designation,
            'organisation': cert.part_a_organisation,
            'signed_at': _iso(cert.part_a_signed_at),
        },
        'part_b': {
            'name': cert.part_b_name, 'designation': cert.part_b_designation,
            'organisation': cert.part_b_organisation,
            'qualification': cert.part_b_qualification,
            'signed_at': _iso(cert.part_b_signed_at),
        },
        'findings_summary': cert.findings_summary,
        # Lets a recipient confirm the PDF they were handed is the one issued.
        'pdf_sha256': _optional_sha256(cert.pdf_path) if cert.pdf_path else None,
    }


def _exhibit(record):
    intact, computed = record.verify()
    events = list(record.custody_events.order_by('sequence'))
    entries = [custody_entry(e) for e in events]
    return {
        'evidence_id': record.id,
        'exhibit_number': record.exhibit_number,
        'original_filename': record.original_filename,
        'file_size_bytes': record.file_size_bytes,
        'sha256': record.sha256_hash,
        'sha1': record.sha1_hash,
        'md5': record.md5_hash,
        'hash_algorithm_declared': record.hash_algorithm_declared,
        'sealed_at': _iso(record.created_at),
        'status': record.status,
        'provenance': record.provenance,
        'provenance_label': record.get_provenance_display(),
        'is_demonstration_only': record.is_demonstration_only,
        'provenance_detail': record.provenance_detail,
        'acquisition': {
            'timestamp': _iso(record.acquisition_timestamp),
            'device_type': record.device_type,
            'device_make_model': record.device_make_model,
            'device_serial': record.device_serial,
            'device_identifier': record.device_identifier,
            'custodian_relationship': record.custodian_relationship,
            'seized_from': record.seized_from,
            'notes': record.acquisition_notes,
        },
        'case_reference': record.case_reference,
        'fir_number': record.fir_number,
        'police_station': record.police_station,
        # Re-hashed at export, not copied from the record: a package that says
        # "intact" because it was intact when sealed is a package that cannot
        # report a file changed since.
        'content_check': {
            'intact': bool(intact),
            'checked_at': timezone.now().isoformat(),
            'computed_sha256': computed,
        },
        'custody': {
            'recipe': CHAIN_RECIPE,
            'event_count': len(entries),
            'head_hash': entries[-1]['entry_hash'] if entries else '',
            'events': entries,
        },
        'certificates': [
            _certificate(c) for c in record.certificates.order_by('generated_at')],
    }


def _case(case):
    if case is None:
        return None
    return {
        'case_number': case.case_number, 'title': case.title,
        'fir_number': case.fir_number, 'police_station': case.police_station,
        'district': case.district, 'offence_sections': case.offence_sections,
        'status': case.status, 'opened_on': _iso(case.opened_on),
    }


def _tool():
    from apk_engine import ENGINE_VERSION

    from netforensiq_backend.version import get_version

    base = Path(settings.BASE_DIR)
    return {
        'name': 'NetForensiq',
        'version': get_version(),
        'apk_engine_version': ENGINE_VERSION,
        # The two measurement tables the findings' error rates come from.
        'rule_base_rates_sha256': _optional_sha256(
            base / 'capture' / 'data' / 'rule_base_rates.json'),
        'apk_baselines_sha256': _optional_sha256(
            base / 'apk_engine' / 'data' / 'baselines.json'),
    }


def build_case_package(records, *, case=None, private_key=None):
    """
    Build and sign a package over `records` (a non-empty list of EvidenceRecord).

    Returns (text, summary). The caller records the custody event *before*
    calling this, so the event is in the package: a package whose own export is
    missing from its log would be a package that had not been exported.
    """
    records = list(records)
    if not records:
        raise PackageError('A package needs at least one exhibit.')

    key = private_key or signing.load_private_key(create=True)
    public = signing.public_key_bytes(key)

    manifest = {
        'schema': MANIFEST_SCHEMA,
        'generated_at': timezone.now().isoformat(),
        'tool': _tool(),
        'case': _case(case),
        'exhibits': [_exhibit(r) for r in records],
    }
    manifest_json = json.dumps(
        manifest, sort_keys=True, ensure_ascii=False, separators=(',', ':'))

    signature = signing.sign(CONTEXT, manifest_json.encode('utf-8'), key)
    envelope = {
        'format': FORMAT,
        'how_to_verify': HOW_TO_VERIFY,
        'manifest_json': manifest_json,
        'signature': {
            'algorithm': 'ed25519',
            'public_key': base64.b64encode(public).decode(),
            'key_fingerprint': signing.fingerprint(public),
            'value': base64.b64encode(signature).decode(),
        },
    }
    text = json.dumps(envelope, indent=1, ensure_ascii=False) + '\n'

    fingerprint = signing.fingerprint(public)
    return text, {
        'exhibits': [e['exhibit_number'] for e in manifest['exhibits']],
        'key_fingerprint': fingerprint,
        'all_content_intact': all(
            e['content_check']['intact'] for e in manifest['exhibits']),
    }


# ───────────────────────── reference verifier ─────────────────────────
#
# The same checks the browser verifier makes, written separately. Two
# implementations that must agree catch what one cannot: the cross-language
# tests build a package here and verify it there, and the reverse.

def entry_hash(evidence_id, entry):
    payload = '|'.join([
        str(evidence_id), str(entry['sequence']), entry['action'],
        entry['actor_badge'], entry['actor_ip'], entry['detail'],
        entry['timestamp'], entry['previous_hash'],
    ])
    return hashlib.sha256(payload.encode('utf-8')).hexdigest()


def chain_problems(evidence_id, custody):
    """Every way the log fails to hold together, as sentences. Empty means intact."""
    events = custody.get('events') or []
    problems = []
    if not events:
        return ['the custody log is empty']
    previous = ''
    for index, entry in enumerate(events):
        n = entry.get('sequence')
        if n != index + 1:
            problems.append(
                f'entry {index + 1} is numbered {n}: an entry is missing or reordered')
        if entry.get('previous_hash') != previous:
            problems.append(
                f'entry #{n}: previous_hash does not match the entry before it')
        for field in NO_PIPE_FIELDS:
            if '|' in str(entry.get(field) or ''):
                problems.append(
                    f"entry #{n}: {field} contains '|', so the entry's hash does not "
                    'fix which text belongs to which field')
        if not _HEX64.match(str(entry.get('entry_hash', ''))):
            problems.append(f'entry #{n}: entry_hash is not a SHA-256 digest')
        elif entry_hash(evidence_id, entry) != entry['entry_hash']:
            problems.append(f'entry #{n}: content has been altered')
        previous = entry.get('entry_hash', '')
    if custody.get('event_count') != len(events):
        problems.append(
            f'the package says {custody.get("event_count")} entries, it carries {len(events)}')
    if custody.get('head_hash') != previous:
        problems.append('the package head_hash is not the last entry\'s hash')
    return problems


def normalise_fingerprint(text):
    return re.sub(r'[^0-9a-f]', '', (text or '').lower())


def verify_package(text, expected_fingerprint=None):
    """
    Verify a package. Returns {'ok', 'checks', 'fingerprint', 'manifest'}.

    `checks` is a list of {'id', 'level', 'text'}, level one of 'pass', 'fail',
    'info'. `ok` is True only if nothing failed. A package whose signature does
    not verify returns no manifest: its contents are not to be trusted or shown
    as if they were.
    """
    checks = []

    def add(check_id, level, message):
        checks.append({'id': check_id, 'level': level, 'text': message})

    result = {'ok': False, 'checks': checks, 'fingerprint': None, 'manifest': None}

    try:
        envelope = json.loads(text)
    except ValueError:
        # No parser detail: each language words its own, and the two verifiers
        # are required to give identical results.
        add('envelope', 'fail', 'not valid JSON')
        return result
    if not isinstance(envelope, dict) or envelope.get('format') != FORMAT:
        add('envelope', 'fail', f'not a {FORMAT} file')
        return result
    add('envelope', 'pass', f'format {FORMAT}')

    manifest_json = envelope.get('manifest_json')
    sig = envelope.get('signature') or {}
    try:
        public = base64.b64decode(sig.get('public_key', ''), validate=True)
        value = base64.b64decode(sig.get('value', ''), validate=True)
    except ValueError:
        add('signature', 'fail', 'the signature or public key is not valid base64')
        return result
    if sig.get('algorithm') != 'ed25519' or not isinstance(manifest_json, str):
        add('signature', 'fail', 'unsupported or missing signature')
        return result

    fingerprint = signing.fingerprint(public)
    result['fingerprint'] = fingerprint

    if not signing.verify(CONTEXT, manifest_json.encode('utf-8'), value, public):
        add('signature', 'fail',
            'the signature does not match the manifest: the file has been altered '
            'since it was signed, or was not signed by this key')
        return result
    add('signature', 'pass', 'the manifest is exactly as it was signed')

    if sig.get('key_fingerprint') and sig['key_fingerprint'] != fingerprint:
        add('fingerprint', 'fail',
            'the fingerprint written in the file is not the fingerprint of its key')
    elif expected_fingerprint:
        if normalise_fingerprint(expected_fingerprint) == fingerprint:
            add('fingerprint', 'pass',
                'the signing key matches the fingerprint you supplied')
        else:
            add('fingerprint', 'fail',
                'the signing key does NOT match the fingerprint you supplied')
    else:
        add('fingerprint', 'info',
            'signed by key ' + signing.display_fingerprint(fingerprint) + '. A valid '
            'signature shows the file is unaltered and came from the holder of this '
            'key; it does not show the key is the laboratory\'s. Compare the '
            'fingerprint with one you obtained separately.')

    try:
        manifest = json.loads(manifest_json)
    except ValueError:
        add('manifest', 'fail', 'the signed manifest is not valid JSON')
        return result
    if manifest.get('schema') != MANIFEST_SCHEMA:
        add('manifest', 'fail', f'unsupported manifest schema {manifest.get("schema")!r}')
        return result
    result['manifest'] = manifest

    for exhibit in manifest.get('exhibits', []):
        number = exhibit.get('exhibit_number', '?')
        problems = chain_problems(exhibit.get('evidence_id'), exhibit.get('custody') or {})
        if problems:
            for problem in problems:
                add(f'chain:{number}', 'fail', f'{number}: {problem}')
        else:
            count = (exhibit.get('custody') or {}).get('event_count')
            add(f'chain:{number}', 'pass',
                f'{number}: custody chain intact ({count} entries, every hash recomputed)')

        for field in ('sha256',):
            if not _HEX64.match(str(exhibit.get(field, ''))):
                add(f'hash:{number}', 'fail', f'{number}: {field} is not a SHA-256 digest')

        check = exhibit.get('content_check') or {}
        if check.get('intact'):
            add(f'content:{number}', 'info',
                f'{number}: the laboratory re-hashed the stored file at export and it '
                f'matched. This is the laboratory\'s statement; hash your own copy to '
                f'check it yourself.')
        else:
            add(f'content:{number}', 'fail',
                f'{number}: the stored file did NOT match its sealed hash when the '
                f'package was made')

        for cert in exhibit.get('certificates', []):
            if cert.get('certified_sha256') != exhibit.get('sha256'):
                add(f'certificate:{cert.get("reference")}', 'fail',
                    f'certificate {cert.get("reference")} certifies a different hash '
                    f'from the exhibit it is filed against')

    result['ok'] = not any(c['level'] == 'fail' for c in checks)
    return result
