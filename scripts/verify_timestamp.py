#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Check the PROVENANCE timestamp against the Bitcoin blockchain, without a node.

`ots verify` is the reference check, but it needs a local Bitcoin Core node,
which almost nobody asked to verify a claim will have. This does the same
comparison against public block data instead:

1. the proof must be for this manifest — its recorded digest must equal the
   SHA-256 of the stamped manifest as it is on disk;
2. following the proof's operations from that digest must arrive at a value
   that Bitcoin block N committed to — the block header's merkle root;
3. that merkle root is fetched from **two independent block explorers**, and
   both must agree, so the result does not rest on trusting either one.

If all three hold, the manifest — and so every file hash in it — existed no
later than block N's timestamp. Nothing is sent anywhere except a request for a
public block by height.

A proof made recently is still *pending*: the calendar servers have the hash
but Bitcoin has not confirmed it yet. That is reported as such, not as failure.

Requires: pip install opentimestamps-client  (for the proof format only)

Usage:
    python scripts/verify_timestamp.py                     # every stamp in PROVENANCE/stamps/
    python scripts/verify_timestamp.py --manifest PROVENANCE/stamps/<time>/manifest.sha256
"""

import argparse
import datetime
import hashlib
import json
import os
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPLORERS = ('https://blockstream.info/api', 'https://mempool.space/api')


def fetch(url):
    request = urllib.request.Request(url, headers={'User-Agent': 'NetForensiq-verify-timestamp'})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode('utf-8')


def block_at(height):
    """(merkle_root, unix_time) for a height, required to agree across explorers."""
    seen = {}
    for base in EXPLORERS:
        block_hash = fetch(f'{base}/block-height/{height}').strip()
        block = json.loads(fetch(f'{base}/block/{block_hash}'))
        seen[base] = (block['merkle_root'], block['timestamp'], block_hash)
    values = {v[:2] for v in seen.values()}
    if len(values) != 1:
        raise RuntimeError(f'explorers disagree about block {height}: {seen}')
    merkle_root, when = values.pop()
    return merkle_root, when, next(iter(seen.values()))[2]


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', help='one stamp; default is every stamp, oldest first')
    args = parser.parse_args(argv)
    if args.manifest:
        return verify(args.manifest)
    stamps = os.path.join(ROOT, 'PROVENANCE', 'stamps')
    names = sorted(os.listdir(stamps)) if os.path.isdir(stamps) else []
    if not names:
        sys.exit('No stamps in PROVENANCE/stamps/.')
    worst = 0
    for name in names:
        print(f'=== stamp {name} ===')
        worst = max(worst, verify(os.path.join(stamps, name, 'manifest.sha256')))
        print()
    return worst


def verify(manifest):
    proof_path = manifest + '.ots'

    try:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation, PendingAttestation
        from opentimestamps.core.serialize import StreamDeserializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile
    except ImportError:
        sys.exit('Needs the proof-format library: pip install opentimestamps-client')

    with open(manifest, 'rb') as handle:
        digest = hashlib.sha256(handle.read()).digest()
    with open(proof_path, 'rb') as handle:
        proof = DetachedTimestampFile.deserialize(StreamDeserializationContext(handle))

    print(f'manifest : {os.path.relpath(manifest, ROOT)}')
    print(f'SHA-256  : {digest.hex()}')
    if proof.file_digest != digest:
        print('FAIL: the proof is for a different file — the manifest has changed since '
              'it was stamped. Rebuild and re-stamp, or check out the stamped version.')
        return 1
    print('proof    : commits to exactly this manifest')

    bitcoin, pending = [], []
    for msg, attestation in proof.timestamp.all_attestations():
        if isinstance(attestation, BitcoinBlockHeaderAttestation):
            bitcoin.append((attestation.height, msg))
        elif isinstance(attestation, PendingAttestation):
            pending.append(attestation.uri)

    if not bitcoin:
        print(f'status   : PENDING — {len(pending)} calendar(s) hold the hash; Bitcoin has not '
              f'confirmed it yet. Run `ots upgrade {os.path.relpath(proof_path, ROOT)}` later.')
        return 2

    verified = False
    for height, msg in sorted(bitcoin):
        try:
            merkle_root, when, block_hash = block_at(height)
        except Exception as exc:
            print(f'block {height}: could not fetch from both explorers ({exc})')
            continue
        # The proof carries the merkle root in the header's internal byte order;
        # explorers display it byte-reversed.
        match = msg[::-1].hex() == merkle_root
        stamp = datetime.datetime.fromtimestamp(when, datetime.timezone.utc)
        print(f'block {height}: {"MATCH" if match else "MISMATCH"} — merkle root {merkle_root}')
        print(f'             block {block_hash}')
        print(f'             mined {stamp:%Y-%m-%d %H:%M:%S} UTC '
              f'(confirmed identically by {len(EXPLORERS)} independent explorers)')
        verified |= match

    if verified:
        print('\nVERIFIED: this manifest, and every file hash in it, existed no later than '
              'the block time above.')
        return 0
    print('\nFAIL: no Bitcoin attestation in the proof matches the blockchain.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
