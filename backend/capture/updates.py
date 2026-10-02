# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Applying a signed update bundle on the evidence workstation.

evidence/update_bundle.py defines the format and checks what a bundle says about
itself. This module decides what the *machine* is willing to do with it:

1. **Trust.** A bundle is accepted only from a key the operator has chosen to
   trust, by an explicit act that requires typing the key's fingerprint
   (`manage.py trust_publisher`). A bundle carrying a key is not evidence that the
   key should be trusted; anyone can make one.
2. **Replay and rollback.** Each publisher's `sequence` must exceed the last one
   applied, and the database refuses a second application of the same sequence even
   if two operators race.
3. **Expiry**, against this machine's clock, overridable only knowingly (and the
   override is recorded).
4. **Atomicity.** Indicator feeds are imported in one transaction with the audit
   row, and engine data is staged in a new directory and switched in by an atomic
   rename of a link. A bundle is applied wholly or not at all.

It is a command-line operation on purpose. Accepting update content through the
web interface would put a file parser and a signature check behind a login on a
machine whose whole point is to be hard to feed things; a person at a terminal who
has to type a fingerprint is the control.
"""
import json
import os
import shutil
import tempfile
import uuid
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import Optional

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

from evidence import signing, update_bundle
from evidence.update_bundle import BadSignature, BundleError, MalformedBundle

from .ioc import import_feed
from .models import UpdateBundle


class BundleRefused(BundleError):
    """The bundle failed one or more checks. `issues` lists them all."""
    code = 'refused'

    def __init__(self, issues):
        self.issues = issues
        super().__init__('; '.join(message for _, message in issues))


@dataclass
class Assessment:
    """Everything known about a bundle before anything is done with it."""
    signature_valid: bool = False
    fingerprint: str = ''
    publisher_name: str = ''
    trusted: bool = False
    sequence: int = 0
    last_applied: int = 0
    created: Optional[datetime] = None
    expires: Optional[datetime] = None
    bundle_sha256: str = ''
    items: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    parsed: Optional[update_bundle.Parsed] = None
    verified_items: list = field(default_factory=list)

    @property
    def acceptable(self):
        return self.signature_valid and not self.issues


# ───────────────────────────── trust ─────────────────────────────

def _trust_path():
    return Path(settings.TRUSTED_PUBLISHERS_FILE)


def trusted_publishers():
    """{fingerprint: {name, public_key, added}} for every key the operator trusts."""
    path = _trust_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except ValueError as exc:
        # A corrupt trust file must not be read as "trust nobody" and then
        # quietly repaired by the next `trust_publisher`; stop and say so.
        raise BundleError(f'{path} is not valid JSON: {exc}')
    return {entry['fingerprint']: entry for entry in data.get('publishers', [])}


def _write_trust(entries):
    path = _trust_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps({'publishers': list(entries.values())}, indent=1, sort_keys=True) + '\n')
    os.replace(tmp, path)


def trust_publisher(name, public_key_b64, typed_fingerprint):
    """
    Add a key to the trust list — only if the operator can state its fingerprint.

    The fingerprint is typed, not pasted from the bundle being examined, which is
    the point: it should arrive by another route (a call, a printed notice) so
    that "this bundle's key" and "the key I decided to trust" are checked against
    each other and not against themselves.
    """
    import base64

    try:
        public = base64.b64decode(public_key_b64, validate=True)
    except ValueError:
        raise BundleError('the public key is not valid base64')
    if len(public) != signing.PUBLIC_BYTES:
        raise BundleError(f'a public key is {signing.PUBLIC_BYTES} bytes, got {len(public)}')
    actual = signing.fingerprint(public)
    from evidence.case_package import normalise_fingerprint
    if normalise_fingerprint(typed_fingerprint) != actual:
        raise BundleError(
            f'that fingerprint does not match the key. The key\'s fingerprint is '
            f'{signing.display_fingerprint(actual)}; if that is not the one you were '
            f'given, do not trust this key.')
    entries = trusted_publishers()
    entries[actual] = {'fingerprint': actual, 'name': name,
                       'public_key': base64.b64encode(public).decode(),
                       'added': timezone.now().isoformat()}
    _write_trust(entries)
    return entries[actual]


def untrust_publisher(fingerprint):
    from evidence.case_package import normalise_fingerprint
    entries = trusted_publishers()
    key = normalise_fingerprint(fingerprint)
    if key not in entries:
        raise BundleError('no trusted publisher has that fingerprint')
    removed = entries.pop(key)
    _write_trust(entries)
    return removed


# ─────────────────────────── assessment ───────────────────────────

def last_sequence(fingerprint):
    row = (UpdateBundle.objects.filter(publisher_fingerprint=fingerprint)
           .order_by('-sequence').first())
    return row.sequence if row else 0


def assess(text, *, now=None, allow_expired=False):
    """
    Check a bundle without changing anything, collecting *every* problem.

    A dry run should show an operator all of what is wrong, not the first thing.
    A bad or missing signature stops the assessment: nothing else in a bundle
    whose signature fails is worth reporting as though it were trustworthy.
    """
    now = now or timezone.now()
    result = Assessment()
    try:
        parsed = update_bundle.parse_and_verify_signature(text)
    except MalformedBundle as exc:
        result.issues.append(('malformed', str(exc)))
        return result
    except BadSignature as exc:
        result.issues.append(('bad-signature', str(exc)))
        return result

    manifest = parsed.manifest
    result.parsed = parsed
    result.signature_valid = True
    result.fingerprint = parsed.fingerprint
    result.publisher_name = str(manifest.get('publisher', ''))[:200]
    result.bundle_sha256 = parsed.bundle_sha256

    result.trusted = parsed.fingerprint in trusted_publishers()
    if not result.trusted:
        result.issues.append((
            'untrusted',
            f'the signing key {signing.display_fingerprint(parsed.fingerprint)} is not on this '
            f'machine\'s trust list. If you have been given that fingerprint by the publisher, '
            f'add the key with `manage.py trust_publisher`.'))

    sequence = manifest.get('sequence')
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        result.issues.append(('bad-sequence', 'the sequence is not a positive integer'))
    else:
        result.sequence = sequence
        result.last_applied = last_sequence(parsed.fingerprint)
        if sequence <= result.last_applied:
            word = 'already applied' if sequence == result.last_applied else 'older than one already applied'
            result.issues.append((
                'rollback',
                f'sequence {sequence} is {word} (the last applied from this publisher is '
                f'{result.last_applied}). Applying it would roll the data back.'))

    created, expires, problems = update_bundle.assess_time(manifest, now, allow_expired)
    result.created, result.expires = created, expires
    result.issues.extend(problems)

    items, item_problems = update_bundle.validate_items(manifest, parsed.payloads, now)
    result.verified_items = items
    result.issues.extend(item_problems)
    result.items = [{'type': i.kind, 'sha256': i.sha256, 'size': len(i.data),
                     'name': i.meta.get('name') or i.meta.get('file') or i.payload_id}
                    for i in items]
    return result


# ───────────────────────────── applying ─────────────────────────────

def _engine_root():
    return Path(settings.UPDATES_ROOT) / 'apk_engine'


def _stage_engine_data(items, parsed, sequence):
    """
    Build the next overlay directory: whatever the current overlay holds, plus
    these files, plus a sources.json recording where each came from. Returns the
    staged directory, or None when the bundle carries no engine data.
    """
    engine_items = [i for i in items if i.kind == 'engine_data']
    if not engine_items:
        return None

    root = _engine_root()
    root.mkdir(parents=True, exist_ok=True)
    staging = root / f'.staging-{uuid.uuid4().hex}'
    staging.mkdir()
    try:
        carried_sources = {}
        current = root / 'current'
        if current.exists():
            for source in current.iterdir():
                if source.name in update_bundle.ENGINE_FILES:
                    shutil.copy2(source, staging / source.name)
            try:
                carried_sources = json.loads((current / 'sources.json').read_text())
            except (OSError, ValueError):
                carried_sources = {}

        for item in engine_items:
            name = item.meta['file']
            (staging / name).write_bytes(item.data)
            carried_sources[name] = {
                'attribution': item.meta.get('attribution', ''),
                'licence': item.meta.get('licence', ''),
                'retrieved': item.meta.get('retrieved', ''),
                'sha256': item.sha256,
                'via': (item.meta.get('via') or '') +
                       (' · ' if item.meta.get('via') else '') +
                       f'signed update bundle #{sequence}, key {parsed.fingerprint[:16]}',
            }
        (staging / 'sources.json').write_text(json.dumps(carried_sources, indent=1, sort_keys=True))

        final = root / f'{sequence:06d}-{parsed.fingerprint[:8]}-{parsed.bundle_sha256[:8]}'
        os.rename(staging, final)
        return final
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def _switch_current(final):
    """Point `current` at the new overlay directory, atomically."""
    root = _engine_root()
    link = root / 'current'
    temporary = root / f'.current-{uuid.uuid4().hex}'
    os.symlink(final.name, temporary)
    os.replace(temporary, link)


def apply_bundle(text, *, actor='', now=None, allow_expired=False):
    """
    Apply a bundle, wholly or not at all. Returns the UpdateBundle row.

    Raises BundleRefused, with every problem listed, if any check fails; nothing
    has changed when that happens.
    """
    now = now or timezone.now()
    assessment = assess(text, now=now, allow_expired=allow_expired)
    if not assessment.acceptable:
        raise BundleRefused(assessment.issues)

    parsed = assessment.parsed
    items = assessment.verified_items
    expired = bool(assessment.expires and now > assessment.expires)

    final = _stage_engine_data(items, parsed, assessment.sequence)
    row = None
    scratch = Path(tempfile.mkdtemp(prefix='nf-update-', dir=_ensure(Path(settings.UPDATES_ROOT))))
    try:
        with transaction.atomic():
            try:
                row = UpdateBundle.objects.create(
                    publisher_fingerprint=parsed.fingerprint,
                    publisher_name=assessment.publisher_name,
                    sequence=assessment.sequence,
                    bundle_sha256=parsed.bundle_sha256,
                    created=assessment.created, expires=assessment.expires,
                    applied_by=actor[:150], applied_after_expiry=expired,
                    contents=assessment.items)
            except IntegrityError:
                # Two operators applying the same sequence at once: one wins.
                raise BundleRefused([('rollback', 'that sequence has just been applied')])

            for item in items:
                if item.kind != 'ioc_feed':
                    continue
                safe = ''.join(c if c.isalnum() or c in '-._' else '_' for c in item.meta['name'])[:80]
                path = scratch / f'{safe or "feed"}.txt'
                path.write_bytes(item.data)
                try:
                    import_feed(
                        path, name=item.meta['name'], fmt=item.meta['format'],
                        retrieved_on=date.fromisoformat(item.meta['retrieved_on']),
                        source=item.meta.get('source', ''), licence=item.meta.get('licence', ''),
                        notes=(item.meta.get('notes', '') + ('\n' if item.meta.get('notes') else '') +
                               f'Applied from signed update bundle #{assessment.sequence} '
                               f'(key {parsed.fingerprint[:16]}).'))
                except ValueError as exc:
                    # An empty parse, say. Everything above rolls back with it.
                    raise BundleRefused([('bad-feed', f'{item.meta["name"]}: {exc}')])
    except BaseException:
        if final is not None:
            shutil.rmtree(final, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    if final is not None:
        _switch_current(final)
    return row


def _ensure(path):
    path.mkdir(parents=True, exist_ok=True)
    return str(path)
