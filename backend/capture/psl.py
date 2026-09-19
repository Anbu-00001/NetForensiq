# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Registered domains, by the Public Suffix List.

The DNS tunnelling rules group queries by "the domain they are under", and
used to take that to mean the last two labels. That is right for example.com
and wrong almost everywhere a false positive came from (research/157):

  * `ec2-3-80-1-2.compute-1.amazonaws.com` — every EC2 instance is a different
    customer, and the PSL says so (`*.compute-1.amazonaws.com`). Grouped under
    `amazonaws.com`, one laptop's cloud traffic read as "66 unique subdomains".
  * `e1234.a.akamaiedge.net` — the PSL lists `akamaiedge.net` itself as a
    suffix; each edge hostname is its own registered name.
  * `foo.bar.co.uk` — the last two labels are `co.uk`, a public suffix under
    which every British company would be one "domain".

The list is Mozilla's, maintained for exactly this purpose ("to determine the
boundary between a registrable domain and a public suffix"). Both sections are
used: the ICANN section for country-code structure, the private section because
that is where cloud and dynamic-DNS providers declare that their customers are
separate — duckdns.org, trycloudflare.com and amazonaws.com among them. That
cuts both ways, and correctly: a tunnel under `x.duckdns.org` is grouped under
`x.duckdns.org`, not merged with every other DuckDNS customer.

Shipped as a snapshot (data/public_suffix_list.dat, MPL-2.0) because the engine
runs offline. The version line is read from the file and reported with every
finding that used it, so a result can be reproduced against the list it was
made with.

Algorithm: https://github.com/publicsuffix/list/wiki/Format — the longest
matching rule prevails, an exception rule beats everything, and "*" is the
implicit default when nothing matches.
"""
import os
import re
from functools import lru_cache

PSL_PATH = os.path.join(os.path.dirname(__file__), 'data', 'public_suffix_list.dat')


@lru_cache(maxsize=1)
def _load():
    rules, exceptions, version = set(), set(), 'unknown'
    with open(PSL_PATH, encoding='utf-8') as handle:
        for raw in handle:
            line = raw.strip()
            if line.startswith('// VERSION:'):
                version = line.split(':', 1)[1].strip()
            if not line or line.startswith('//'):
                continue
            # "Each line is only read up to the first whitespace."
            line = line.split()[0].lower()
            target = exceptions if line.startswith('!') else rules
            line = line.lstrip('!')
            try:
                # Queries arrive on the wire in ASCII (punycode); the list
                # carries internationalised entries in Unicode.
                line = '.'.join(
                    label if label == '*' else label.encode('idna').decode('ascii')
                    for label in line.split('.')
                )
            except UnicodeError:
                continue
            target.add(line)
    return frozenset(rules), frozenset(exceptions), version


def version():
    return _load()[2]


# Reverse-mapping names are grouped by the zone an address holder is actually
# delegated, not by the PSL. The list does contain `in-addr.arpa`, which would
# make `4.in-addr.arpa` a "registered domain" covering 16 million addresses
# held by thousands of unrelated networks — and a browser resolving the
# addresses it talks to would look like one host generating hundreds of names
# under one domain (662 of them, on one ordinary capture). Reverse delegation
# is made on octet boundaries for IPv4 (RFC 1035 s.3.5; RFC 2317 for the
# classless case beneath a /24) and on nibble boundaries for IPv6 (RFC 3596
# s.2.5). The groups used are the smallest ordinary assignments: a /24 and a
# /64. A tunnel run through reverse DNS needs a delegated reverse zone, so it
# stays inside one group and is still counted.
_IN_ADDR = re.compile(r'^(?:[0-9]+\.)*([0-9]+\.[0-9]+\.[0-9]+\.in-addr\.arpa)$')
_IP6 = re.compile(r'^(?:[0-9a-f]\.)*((?:[0-9a-f]\.){16}ip6\.arpa)$')


@lru_cache(maxsize=65536)
def registered_domain(name):
    """
    The registrable domain `name` belongs to, e.g.
    `a.b.example.co.uk` -> `example.co.uk`.

    Returns the name itself when it *is* a public suffix, or has no labels
    above one, since there is no larger unit to group it under.
    """
    name = (name or '').strip().rstrip('.').lower()
    if not name:
        return name
    for pattern in (_IN_ADDR, _IP6):
        match = pattern.match(name)
        if match:
            return match.group(1)

    rules, exceptions, _ = _load()
    labels = name.split('.')

    suffix_len = 1  # the implicit "*" rule
    for i in range(len(labels)):
        candidate = '.'.join(labels[i:])
        if candidate in exceptions:
            # An exception rule's public suffix is the rule minus its
            # leftmost label, and it prevails over every other match.
            suffix_len = len(labels) - i - 1
            break
        wildcard = '.'.join(['*'] + labels[i + 1:]) if i + 1 <= len(labels) else None
        if candidate in rules or (wildcard and wildcard in rules):
            # Scanning from the left, the first hit is the longest rule.
            suffix_len = len(labels) - i
            break

    if len(labels) <= suffix_len:
        return name
    return '.'.join(labels[-(suffix_len + 1):])
