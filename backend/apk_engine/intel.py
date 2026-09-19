# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Matches against published indicator sets bundled with the engine.

Why some matches raise the tier and others do not
=================================================
A **file hash** or **signing certificate** match is an identity match: the
sample *is* a file, or was signed by a key, that the source attributes to a
named product. If it is wrong, the error is in the source entry, whose snapshot
and licence the report shows — not a statistical coincidence.

A **package name** or **domain** match is weaker. Package names are free text
anyone can reuse, and a domain can be shared infrastructure. Those are shown as
supporting intelligence and never move the tier on their own.

The stalkerware set is Echap's ``ioc.yaml`` only; its watchware list (parental
monitoring) is excluded at snapshot time, see refresh_data.py.
"""

from . import reference
from .sources import PHA

STRONG = ('file_hash', 'signing_certificate')


def match(sha256, identity, app_hosts):
    data = reference.stalkerware()
    source = reference.sources().get('stalkerware_indicators.json', {})
    provenance = {
        'source': 'stalkerware-indicators (Echap)',
        'snapshot': source.get('via', ''),
        'upstream_commit_date': source.get('upstream_commit_date', ''),
        'licence': source.get('licence', 'CC-BY-4.0'),
        'attribution': source.get('attribution', ''),
    }
    matches = []

    def add(kind, value, product, strength):
        matches.append(dict(provenance, kind=kind, value=value, product=product,
                            category=PHA['stalkerware']['name'], strength=strength))

    sha256 = (sha256 or '').lower()
    for sample in data.get('samples', []):
        if sample['sha256'] == sha256:
            add('file_hash', sha256, sample['product'], 'identity')

    certificates = {c['sha1'] for c in identity.get('signing', {}).get('certificates', [])} if identity else set()
    package = (identity or {}).get('package') or ''
    hosts = set(app_hosts or ())
    for product in data.get('products', []):
        for cert in certificates & set(product.get('certificates_sha1', [])):
            add('signing_certificate', cert, product['name'], 'identity')
        if package and package in product.get('packages', []):
            add('package_name', package, product['name'], 'supporting')
        for domain in hosts & set(product.get('c2_domains', [])):
            add('c2_domain', domain, product['name'], 'supporting')

    return {
        'matches': matches,
        'identity_match': any(m['kind'] in STRONG for m in matches),
        'checked_against': provenance,
    }
