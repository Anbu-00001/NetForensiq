"""
Provenance manifests for capture files.

The problem this solves
-----------------------
`generate_traffic` produces a PCAP that is structurally indistinguishable from
a real one, and the evidence layer will happily seal it, hash it and print a
Section 63 certificate over it. Handed that PDF, nobody could tell whether the
traffic was seized from a suspect's network or invented by us ten seconds
earlier. For a system whose entire claim is evidentiary integrity, that is the
most dangerous thing in the codebase.

So every file the project puts in front of a user now carries a sidecar
manifest saying where it came from, and intake reads it. A capture we
generated says so, on screen and on the certificate, in terms a court could
not mistake. A capture downloaded from a published corpus says that instead,
with the URL it came from and the URL of its ground truth.

Why a sidecar and not a heuristic
---------------------------------
Guessing "this looks synthetic" from packet contents would be a heuristic, and
a heuristic that is wrong in either direction is worse than no claim at all.
The manifest is a statement of fact by whatever produced or fetched the file,
and it carries the file's SHA-256 so it cannot be detached and reattached to a
different capture without the mismatch being visible.

A file with no manifest is *unattested* — not thereby proven real. Only an
officer declaring it at intake makes it `seized`.

What this is not
----------------
It is **not a security control.** Anyone who can write to the capture directory
can write a manifest, and the digest binds a manifest to a file without proving
who wrote either. It is not signed, and signing it would only move the question
to who holds the key.

What it does is make an *accident* impossible: a demonstration capture cannot
quietly become an exhibit because someone forgot which file was which. Every
failure mode is closed in the alarming direction — a missing, unreadable or
mismatched manifest yields `unattested`, never `seized` — and the manifest is
copied into the evidence store beside the sealed file, so re-processing an
exhibit does not lose what is known about it.

Defeating it requires deliberately forging a statement of origin, which is the
same act as forging any other part of a case file and is answered the same way.
"""

import json
from datetime import datetime, timezone as dt_timezone
from pathlib import Path

MANIFEST_SUFFIX = '.provenance.json'
TOOL = 'netforensiq'

KIND_SYNTHETIC = 'synthetic'
KIND_REFERENCE = 'reference'
VALID_KINDS = (KIND_SYNTHETIC, KIND_REFERENCE)

SYNTHETIC_DETAIL = (
    'Traffic constructed by NetForensiq for demonstration and testing. '
    'It was never observed on any network and is not evidence of anything.'
)


def manifest_path(pcap_path):
    return Path(str(pcap_path) + MANIFEST_SUFFIX)


def write_manifest(pcap_path, *, kind, detail='', **fields):
    """
    Record where this file came from.

    The digest is taken here, over the file as written, so a later reader can
    tell whether the manifest still describes the bytes beside it.
    """
    if kind not in VALID_KINDS:
        raise ValueError(f"Unknown provenance kind {kind!r}; expected one of {VALID_KINDS}")

    from evidence.crypto import EvidenceDecryptionError, readable
    from evidence.models import hash_file

    path = Path(pcap_path)
    digests, size = hash_file(path)

    payload = {
        'kind': kind,
        'tool': TOOL,
        'file_size_bytes': size,
        'sha256': digests['sha256'],
        'recorded_at': datetime.now(dt_timezone.utc).isoformat(),
        'detail': detail or (SYNTHETIC_DETAIL if kind == KIND_SYNTHETIC else ''),
        **fields,
    }
    manifest_path(path).write_text(json.dumps(payload, indent=2))
    return payload


def read_manifest(pcap_path):
    """
    The manifest beside `pcap_path`, or None.

    Returns None — rather than raising — when the sidecar is missing,
    unreadable, or describes a different file. In every one of those cases the
    only truthful thing to say about the capture is nothing, and the caller
    records it as unattested.
    """
    from evidence.crypto import EvidenceDecryptionError, readable
    from evidence.models import hash_file

    path = manifest_path(pcap_path)
    if not path.exists():
        return None

    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError):
        return None

    if not isinstance(payload, dict) or payload.get('tool') != TOOL:
        return None
    if payload.get('kind') not in VALID_KINDS:
        return None

    claimed = payload.get('sha256')
    if claimed:
        try:
            # Against the plaintext, because that is what the manifest
            # describes. Once the evidence store is encrypted the bytes on disk
            # hash to something else entirely, and comparing against those
            # rejected every manifest — which downgraded a synthetic capture to
            # "origin unknown", the quieter and more dangerous of the two
            # answers.
            with readable(Path(pcap_path)) as plaintext:
                digests, _ = hash_file(plaintext)
        except (OSError, EvidenceDecryptionError):
            return None
        if digests['sha256'] != claimed:
            # The manifest belongs to some other file. Saying nothing is
            # correct: we know it is not a description of this one.
            return None

    return payload


def describe(payload):
    """One line an investigator can read, built only from recorded fields."""
    if not payload:
        return ''

    if payload['kind'] == KIND_SYNTHETIC:
        bits = ['Generated by NetForensiq']
        if payload.get('scenario'):
            bits.append(f"scenario '{payload['scenario']}'")
        if payload.get('seed') is not None:
            bits.append(f"seed {payload['seed']}")
        return ' · '.join(bits) + '. ' + payload.get('detail', '')

    bits = ['Public reference capture']
    if payload.get('source_name'):
        bits.append(payload['source_name'])
    if payload.get('source_url'):
        bits.append(payload['source_url'])
    line = ' · '.join(bits)
    if payload.get('ground_truth_url'):
        line += f" · ground truth: {payload['ground_truth_url']}"
    return line + ('. ' + payload['detail'] if payload.get('detail') else '')
