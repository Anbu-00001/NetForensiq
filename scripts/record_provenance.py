#!/usr/bin/env python
"""
Write a provenance manifest beside a capture file.

Used by fetch_reference_captures.sh, and usable by hand when a capture arrives
by some other route:

    cd backend && .venv/bin/python ../scripts/record_provenance.py \
        reference_captures/foo.pcap --kind reference \
        --source-url https://… --source-name "…" --ground-truth-url https://…

Run it from the backend directory so Django's settings resolve.
"""

import argparse
import os
import sys

# Python puts *this script's* directory on sys.path, not the working
# directory, so the Django project is not importable without this.
sys.path.insert(0, os.getcwd())

import django  # noqa: E402

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
django.setup()

from capture.provenance import write_manifest, read_manifest  # noqa: E402

REFERENCE_DETAIL = (
    'Real captured traffic published by malware-traffic-analysis.net with a '
    'written analysis. Used to validate detection against traffic this project '
    'did not create. It is not evidence in any case.'
)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap')
    parser.add_argument('--kind', choices=['reference', 'synthetic'], required=True)
    parser.add_argument('--source-name', default='')
    parser.add_argument('--source-url', default='')
    parser.add_argument('--ground-truth-url', default='')
    parser.add_argument('--detail', default='')
    args = parser.parse_args()

    if read_manifest(args.pcap):
        print(f"  manifest already valid for {os.path.basename(args.pcap)}")
        return

    manifest = write_manifest(
        args.pcap,
        kind=args.kind,
        source_name=args.source_name,
        source_url=args.source_url,
        ground_truth_url=args.ground_truth_url,
        detail=args.detail or (REFERENCE_DETAIL if args.kind == 'reference' else ''),
    )
    print(f"  provenance recorded · sha256 {manifest['sha256'][:16]}…")


if __name__ == '__main__':
    main()
