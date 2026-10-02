# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The signed update bundle: how new indicator feeds and engine reference data cross
an air gap without trusting whatever happened to be on the USB stick.

This module is the *format*: building a bundle, and checking one without
touching a database. The publisher's tool (scripts/make_update_bundle.py) uses it
on a connected machine; capture/updates.py uses it on the evidence workstation and
adds trust, replay protection and the act of applying.

What an update can and cannot change
------------------------------------
Two kinds of item, nothing else:

* `ioc_feed` — an indicator list (a file in one of the formats the importer
  reads), imported through the same path as `manage.py import_ioc_feed`.
* `engine_data` — one of the three reference files the APK examination engine
  reads and that go stale: Exodus tracker signatures, stalkerware indicators, the
  list of top-level domains.

The detection rules, the baseline table that decides which signals are validated,
and the set of known publisher signing keys are deliberately *not* updatable. They
define the method and what counts as genuine; changing them is re-validation
(research/163), not an update, and a bundle format that could carry them would make
the signing key the key to the method.

Threats, from The Update Framework's list
-----------------------------------------
(https://theupdateframework.io/docs/security/), and what is and is not done:

| attack                         | here |
|--------------------------------|------|
| arbitrary content              | an Ed25519 signature over the manifest; the key must be one the operator chose to trust |
| rollback (older files)         | a per-publisher `sequence` that must exceed the last one applied |
| fast-forward (inflated number) | **not prevented** for a holder of the key; the answer is to stop trusting that key |
| indefinite freeze              | an `expires` date, enforced against the machine's clock (which on an air-gapped machine is only as good as its operator's) |
| endless data                   | size limits on the bundle, each item, and the number of items |
| mix and match                  | one signed manifest names every payload by SHA-256; they are applied together or not at all |
| wrong content installed        | item types and engine file names are on an allow-list; nothing is named by the bundle's own paths |
| key compromise                 | **single key per publisher**, no threshold signing; mitigated only by removing the key from the trust list |

The signature covers the manifest text and the manifest names each payload by
SHA-256, so payloads need no signature of their own.
"""
import base64
import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

from . import signing

FORMAT = 'netforensiq.update-bundle/1'
MANIFEST_SCHEMA = 'netforensiq.update-manifest/1'
# Prepended to what is signed: a signature over a bundle is not a valid signature
# over a case package or a release manifest, even from the same key.
CONTEXT = b'netforensiq.update-bundle/1\n'

MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_ITEM_BYTES = 32 * 1024 * 1024
MAX_ITEMS = 32

# Kept equal to apk_engine.reference.UPDATABLE and capture.models.IOCFeed.Format
# by tests, because this module must be usable without Django (the publisher's
# tool runs on a machine that has only Python and `cryptography`).
ENGINE_FILES = ('exodus_trackers.json', 'stalkerware_indicators.json', 'tlds.txt')
IOC_FORMATS = ('feodo_ip', 'urlhaus', 'plain_ip', 'plain_domain')

_HEX64 = re.compile(r'^[0-9a-f]{64}$')


class BundleError(Exception):
    """Base class. `code` is a stable short name for the kind of refusal."""
    code = 'refused'


class MalformedBundle(BundleError):
    code = 'malformed'


class BadSignature(BundleError):
    code = 'bad-signature'


@dataclass
class Item:
    kind: str
    payload_id: str
    data: bytes
    sha256: str
    meta: dict = field(default_factory=dict)


@dataclass
class Parsed:
    manifest: dict
    payloads: dict
    public_key: bytes
    fingerprint: str
    bundle_sha256: str


def _parse_time(value, what):
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        raise MalformedBundle(f'{what} is not an ISO 8601 timestamp: {value!r}')
    if moment.tzinfo is None:
        # A date without a zone means a different moment on every machine.
        raise MalformedBundle(f'{what} has no time zone: {value!r}')
    return moment


def build_bundle(spec, read, private_key):
    """
    Build and sign a bundle. Returns its text.

    `spec` is a dict: publisher (display name), sequence (int >= 1), expires (ISO
    8601 with zone), created (optional), items (list). `read(path)` returns the
    bytes of a payload file — the caller decides where paths resolve, so this
    function never reads the filesystem itself and cannot be talked into reading
    something it should not.
    """
    items = spec.get('items') or []
    if not items or len(items) > MAX_ITEMS:
        raise MalformedBundle(f'a bundle needs between 1 and {MAX_ITEMS} items')
    sequence = spec.get('sequence')
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise MalformedBundle('sequence must be an integer of at least 1')
    created = spec.get('created') or datetime.now(timezone.utc).isoformat()
    _parse_time(created, 'created')
    _parse_time(spec.get('expires'), 'expires')

    manifest_items, payloads = [], {}
    for index, item in enumerate(items, 1):
        data = read(item['path'])
        if len(data) > MAX_ITEM_BYTES:
            raise MalformedBundle(f'{item["path"]} is larger than {MAX_ITEM_BYTES} bytes')
        entry = {'type': item['type'], 'payload': f'item{index}',
                 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)}
        if item['type'] == 'ioc_feed':
            entry.update({k: item.get(k, '') for k in
                          ('name', 'format', 'retrieved_on', 'source', 'licence', 'notes')})
        elif item['type'] == 'engine_data':
            entry.update({'file': item.get('file') or item['path'].rsplit('/', 1)[-1]})
            entry.update({k: item.get(k, '') for k in
                          ('attribution', 'licence', 'via', 'retrieved')})
        else:
            raise MalformedBundle(f'unknown item type {item["type"]!r}')
        manifest_items.append(entry)
        payloads[entry['payload']] = base64.b64encode(data).decode()

    manifest = {
        'schema': MANIFEST_SCHEMA,
        'publisher': spec.get('publisher', ''),
        'sequence': sequence,
        'created': created,
        'expires': spec['expires'],
        'items': manifest_items,
    }
    manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                               separators=(',', ':'))
    public = signing.public_key_bytes(private_key)
    signature = signing.sign(CONTEXT, manifest_json.encode('utf-8'), private_key)
    envelope = {
        'format': FORMAT,
        'manifest_json': manifest_json,
        'signature': {
            'algorithm': 'ed25519',
            'public_key': base64.b64encode(public).decode(),
            'key_fingerprint': signing.fingerprint(public),
            'value': base64.b64encode(signature).decode(),
        },
        'payloads': payloads,
    }
    text = json.dumps(envelope, ensure_ascii=False) + '\n'
    if len(text.encode('utf-8')) > MAX_BUNDLE_BYTES:
        raise MalformedBundle(f'the finished bundle exceeds {MAX_BUNDLE_BYTES} bytes')
    return text


def parse_and_verify_signature(text):
    """
    Parse a bundle and check its signature. Raises MalformedBundle or BadSignature.

    Says nothing about whether the signer is *trusted*, or about time, sequence
    or content: those are policy and live in capture/updates.py.
    """
    raw = text if isinstance(text, (bytes, bytearray)) else text.encode('utf-8')
    if len(raw) > MAX_BUNDLE_BYTES:
        raise MalformedBundle(f'larger than the {MAX_BUNDLE_BYTES}-byte limit')
    try:
        envelope = json.loads(raw)
    except ValueError:
        raise MalformedBundle('not valid JSON')
    if not isinstance(envelope, dict) or envelope.get('format') != FORMAT:
        raise MalformedBundle(f'not a {FORMAT} file')

    sig = envelope.get('signature') or {}
    manifest_json = envelope.get('manifest_json')
    if sig.get('algorithm') != 'ed25519' or not isinstance(manifest_json, str):
        raise MalformedBundle('unsupported or missing signature')
    try:
        public = base64.b64decode(sig.get('public_key', ''), validate=True)
        value = base64.b64decode(sig.get('value', ''), validate=True)
    except ValueError:
        raise MalformedBundle('the signature or public key is not valid base64')

    fingerprint = signing.fingerprint(public)
    if not signing.verify(CONTEXT, manifest_json.encode('utf-8'), value, public):
        raise BadSignature('the signature does not match the manifest')
    if sig.get('key_fingerprint') and sig['key_fingerprint'] != fingerprint:
        raise BadSignature('the fingerprint written in the file is not the fingerprint of its key')

    try:
        manifest = json.loads(manifest_json)
    except ValueError:
        raise MalformedBundle('the signed manifest is not valid JSON')
    if not isinstance(manifest, dict) or manifest.get('schema') != MANIFEST_SCHEMA:
        raise MalformedBundle('unsupported manifest schema')

    payloads = {}
    for key, encoded in (envelope.get('payloads') or {}).items():
        try:
            payloads[key] = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            raise MalformedBundle(f'payload {key!r} is not valid base64')
    return Parsed(manifest, payloads, public, fingerprint, hashlib.sha256(raw).hexdigest())


def validate_items(manifest, payloads, now):
    """
    Check every item against its payload and the allow-lists. Returns
    (items, problems). A problem is a (code, message) pair; nothing is applied
    while any exists.
    """
    problems, items = [], []
    entries = manifest.get('items')
    if not isinstance(entries, list) or not entries:
        return [], [('no-items', 'the manifest lists no items')]
    if len(entries) > MAX_ITEMS:
        return [], [('too-many-items', f'more than {MAX_ITEMS} items')]

    seen_files = set()
    for entry in entries:
        kind, pid = entry.get('type'), entry.get('payload')
        label = entry.get('name') or entry.get('file') or pid
        data = payloads.get(pid)
        if data is None:
            problems.append(('missing-payload', f'{label}: the payload is not in the bundle'))
            continue
        if len(data) > MAX_ITEM_BYTES:
            problems.append(('item-too-large', f'{label}: larger than {MAX_ITEM_BYTES} bytes'))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if not _HEX64.match(str(entry.get('sha256', ''))) or digest != entry['sha256']:
            problems.append(('payload-mismatch',
                             f'{label}: the payload does not match the SHA-256 the manifest names'))
            continue

        if kind == 'ioc_feed':
            problems.extend(_check_ioc(entry, data, now, label))
        elif kind == 'engine_data':
            name = entry.get('file')
            if name not in ENGINE_FILES:
                problems.append(('not-updatable',
                                 f'{name!r} is not a file an update may replace '
                                 f'(allowed: {", ".join(ENGINE_FILES)})'))
                continue
            if name in seen_files:
                problems.append(('duplicate-file', f'{name} appears twice'))
                continue
            seen_files.add(name)
            problems.extend(_check_engine_file(name, data))
        else:
            problems.append(('unknown-type', f'{label}: unknown item type {kind!r}'))
            continue
        items.append(Item(kind, pid, data, digest, dict(entry)))
    return items, problems


def _check_ioc(entry, data, now, label):
    problems = []
    if entry.get('format') not in IOC_FORMATS:
        problems.append(('bad-format', f'{label}: format {entry.get("format")!r} is not one of '
                                       f'{", ".join(IOC_FORMATS)}'))
    if not (entry.get('name') or '').strip() or len(entry['name']) > 160:
        problems.append(('bad-name', f'{label}: the feed needs a name of at most 160 characters'))
    try:
        retrieved = date.fromisoformat(entry.get('retrieved_on', ''))
    except ValueError:
        problems.append(('bad-date', f'{label}: retrieved_on must be YYYY-MM-DD'))
    else:
        # The importer refuses this too: every staleness figure printed on a
        # finding is measured from the date, so it cannot be in the future.
        if retrieved > (now + timedelta(days=1)).date():
            problems.append(('future-date', f'{label}: retrieved_on is in the future'))
    for key, limit in (('source', 500), ('licence', 300), ('notes', 2000)):
        if len(entry.get(key, '')) > limit:
            problems.append(('too-long', f'{label}: {key} is longer than {limit} characters'))
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        problems.append(('bad-encoding', f'{label}: the feed is not UTF-8 text'))
    return problems


def _check_engine_file(name, data):
    try:
        if name.endswith('.json'):
            parsed = json.loads(data.decode('utf-8'))
            if not isinstance(parsed, dict):
                return [('bad-content', f'{name}: expected a JSON object')]
        else:
            data.decode('ascii')
    except (ValueError, UnicodeDecodeError):
        return [('bad-content', f'{name}: not valid {"JSON" if name.endswith(".json") else "ASCII text"}')]
    return []


def assess_time(manifest, now, allow_expired=False):
    """(created, expires, problems) for the manifest's two timestamps."""
    problems = []
    try:
        created = _parse_time(manifest.get('created'), 'created')
        expires = _parse_time(manifest.get('expires'), 'expires')
    except MalformedBundle as exc:
        return None, None, [('bad-time', str(exc))]
    if expires <= created:
        problems.append(('bad-time', 'expires is not after created'))
    if now > expires and not allow_expired:
        problems.append(('expired', f'expired on {expires.isoformat()}'))
    return created, expires, problems
