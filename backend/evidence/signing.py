# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Ed25519 signatures for what this installation hands to someone else.

Why a signature, when the custody log is already hash-chained
------------------------------------------------------------
A hash chain proves a log is *internally consistent*: change or drop an entry
and every later link breaks. It cannot prove nobody rebuilt the whole chain —
whoever holds the data can recompute every hash from the first entry. So a
case package that carried only a chain would verify perfectly after being
forged end to end.

A signature closes that, but only against someone who does not hold the
signing key, and only for a recipient who has the key's fingerprint from
somewhere other than the package. Both halves matter and the verifier says so;
see `verifier/README.md`.

What is signed
--------------
Each use signs `context + data`, where the context names the document type
("netforensiq.case-package/1\\n"). A signature over a case package is therefore
not a valid signature over an update bundle or a release manifest, even though
one key could be used for all of them.

Strictness
----------
`cryptography` (OpenSSL) verifies per RFC 8032, including the canonical-S
check. The browser verifier asks noble-curves for the same (`zip215: false`),
since its default is the more permissive ZIP215 rules. A test signs in Python
and verifies in Node, and the reverse, so the two cannot drift apart silently.
"""
import base64
import hashlib
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from django.conf import settings

SEED_BYTES = 32
PUBLIC_BYTES = 32
SIGNATURE_BYTES = 64


class SigningKeyError(Exception):
    """The configured key is unusable. Never swallowed: a wrong key is not a missing one."""


def _key_file():
    return Path(getattr(settings, 'SIGNING_KEY_FILE',
                        Path(settings.BASE_DIR) / '.signing.key'))


def _from_seed(seed, source):
    if len(seed) != SEED_BYTES:
        raise SigningKeyError(
            f'{source} must decode to {SEED_BYTES} bytes, got {len(seed)}.')
    return Ed25519PrivateKey.from_private_bytes(seed)


def load_private_key(create=False):
    """
    The signing key, or None when there is none and `create` is False.

    Order: an explicit setting (so a deployment can keep it off this disk), then
    the key file. `create=True` generates the file, and only then — a key made
    by importing a module is a key made by running the test suite.
    """
    configured = getattr(settings, 'PACKAGE_SIGNING_KEY', '') or os.getenv(
        'PACKAGE_SIGNING_KEY', '')
    if configured:
        try:
            return _from_seed(base64.b64decode(configured, validate=True),
                              'PACKAGE_SIGNING_KEY')
        except ValueError as exc:
            raise SigningKeyError(f'PACKAGE_SIGNING_KEY is not valid base64: {exc}')

    path = _key_file()
    if path.exists():
        return _read(path)

    if not create:
        return None

    seed = os.urandom(SEED_BYTES)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Written 0600 from the moment it exists, not chmod'ed afterwards — the
        # window between create and chmod is the whole vulnerability.
        handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Two workers exporting for the first time at once: the other won.
        return _read(path)
    with os.fdopen(handle, 'w') as fh:
        fh.write(base64.b64encode(seed).decode())
    return _from_seed(seed, str(path))


def _read(path):
    try:
        seed = base64.b64decode(path.read_text().strip(), validate=True)
    except ValueError as exc:
        raise SigningKeyError(f'{path} is not valid base64: {exc}')
    return _from_seed(seed, str(path))


def public_key_bytes(private_key):
    return private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint(public_key):
    """SHA-256 of the raw 32-byte public key, hex. What a person compares."""
    return hashlib.sha256(public_key).hexdigest()


def display_fingerprint(hex_digest):
    """Grouped for reading aloud or comparing on paper: 8 groups of 8."""
    return ' '.join(hex_digest[i:i + 8] for i in range(0, len(hex_digest), 8))


def sign(context, data, private_key=None):
    """Signature over `context + data`. `context` and `data` are bytes."""
    key = private_key or load_private_key(create=True)
    if key is None:  # cannot happen with create=True; keeps the failure loud
        raise SigningKeyError('no signing key is available')
    return key.sign(context + data)


def verify(context, data, signature, public_key):
    """True only for a valid RFC 8032 signature; never raises on bad input."""
    if len(public_key) != PUBLIC_BYTES or len(signature) != SIGNATURE_BYTES:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, context + data)
        return True
    except (InvalidSignature, ValueError):
        return False
