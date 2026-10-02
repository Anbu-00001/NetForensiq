#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Make signed update bundles — the publisher's side, run on a *connected* machine.

Needs Python 3.10+ and `cryptography`; not Django, not the platform.

    # Once: make a publishing key. Keep the key file private and backed up.
    make_update_bundle.py keygen --out publisher.key

    # Describe a bundle, then build it:
    make_update_bundle.py build --key publisher.key --spec spec.json --out update-0003.nfupd.json

    # Look inside any bundle (no key needed), e.g. before carrying it across:
    make_update_bundle.py inspect update-0003.nfupd.json

spec.json:

    {
      "publisher": "Cyber Crime PS lab",
      "sequence": 3,                      # one more than the last bundle you published
      "expires": "2027-01-01T00:00:00+05:30",
      "items": [
        {"type": "ioc_feed", "path": "feodo.csv", "name": "Feodo Tracker IP blocklist",
         "format": "feodo_ip", "retrieved_on": "2026-10-01",
         "source": "https://feodotracker.abuse.ch/", "licence": "CC0"},
        {"type": "engine_data", "path": "stalkerware_indicators.json",
         "attribution": "Echap stalkerware-indicators", "licence": "CC-BY-4.0",
         "retrieved": "2026-10-01T00:00:00+00:00", "via": "github.com/AssoEchap/stalkerware-indicators"}
      ]
    }

Paths are relative to the spec file. On the evidence workstation the operator then
runs `manage.py trust_publisher` once with the key's fingerprint (printed by
`keygen`), and `manage.py import_update_bundle` for each bundle. See RUN_OFFLINE.md.
"""
import argparse
import base64
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'backend'))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from evidence import signing, update_bundle  # noqa: E402


def keygen(args):
    seed = os.urandom(signing.SEED_BYTES)
    try:
        # 0600 from the moment it exists; refuse to overwrite an existing key.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        sys.exit(f'{args.out} already exists. Refusing to overwrite a signing key.')
    with os.fdopen(fd, 'w') as handle:
        handle.write(base64.b64encode(seed).decode() + '\n')
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = signing.public_key_bytes(key)
    fingerprint = signing.fingerprint(public)
    print(f'Wrote {args.out} (mode 0600). Keep it private; back it up somewhere that is not this machine.')
    print(f'\nFingerprint (give this to each lab by another route — a call, a printed notice):')
    print(f'  {signing.display_fingerprint(fingerprint)}')
    print(f'\nOn each evidence workstation, once:')
    print(f'  python manage.py trust_publisher --name "<your lab>" \\')
    print(f'      --public-key {base64.b64encode(public).decode()} \\')
    print(f'      --fingerprint "{signing.display_fingerprint(fingerprint)}"')


def _load_key(path):
    try:
        seed = base64.b64decode(Path(path).read_text().strip(), validate=True)
    except (OSError, ValueError) as exc:
        sys.exit(f'cannot read the key {path}: {exc}')
    if len(seed) != signing.SEED_BYTES:
        sys.exit(f'{path} does not hold a {signing.SEED_BYTES}-byte key')
    return Ed25519PrivateKey.from_private_bytes(seed)


def build(args):
    spec_path = Path(args.spec).resolve()
    spec = json.loads(spec_path.read_text())

    def read(relative):
        target = (spec_path.parent / relative).resolve()
        # Paths come from the spec; they stay inside its directory.
        if spec_path.parent not in target.parents and target != spec_path.parent:
            sys.exit(f'{relative}: refusing a path outside the spec\'s directory')
        return target.read_bytes()

    try:
        text = update_bundle.build_bundle(spec, read, _load_key(args.key))
    except (update_bundle.BundleError, KeyError, OSError) as exc:
        sys.exit(f'cannot build the bundle: {exc}')
    Path(args.out).write_text(text, encoding='utf-8')
    parsed = update_bundle.parse_and_verify_signature(text)
    print(f'Wrote {args.out} ({len(text):,} bytes), sequence {parsed.manifest["sequence"]}, '
          f'expires {parsed.manifest["expires"]}')
    print(f'Signed by {signing.display_fingerprint(parsed.fingerprint)}')


def inspect(args):
    text = Path(args.bundle).read_bytes()
    try:
        parsed = update_bundle.parse_and_verify_signature(text)
    except update_bundle.BundleError as exc:
        sys.exit(f'{exc.code}: {exc}')
    manifest = parsed.manifest
    print(f'signature valid; signed by {signing.display_fingerprint(parsed.fingerprint)}')
    print(f'publisher (as claimed) {manifest.get("publisher")}')
    print(f'sequence {manifest.get("sequence")}  created {manifest.get("created")}  '
          f'expires {manifest.get("expires")}')
    from datetime import datetime, timezone
    _items, problems = update_bundle.validate_items(manifest, parsed.payloads, datetime.now(timezone.utc))
    for entry in manifest.get('items', []):
        print(f'  {entry.get("type"):11s} {entry.get("name") or entry.get("file")}  '
              f'{entry.get("size", 0):,} bytes  sha256 {str(entry.get("sha256"))[:16]}…')
    for code, message in problems:
        print(f'  PROBLEM [{code}] {message}')
    sys.exit(1 if problems else 0)


def main():
    parser = argparse.ArgumentParser(description=(__doc__ or '').split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('keygen'); p.add_argument('--out', required=True); p.set_defaults(fn=keygen)
    p = sub.add_parser('build')
    p.add_argument('--key', required=True); p.add_argument('--spec', required=True)
    p.add_argument('--out', required=True); p.set_defaults(fn=build)
    p = sub.add_parser('inspect'); p.add_argument('bundle'); p.set_defaults(fn=inspect)
    args = parser.parse_args()
    args.fn(args)


if __name__ == '__main__':
    main()
