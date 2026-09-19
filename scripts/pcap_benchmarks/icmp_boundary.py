# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Test the RFC4884 rule scapy actually implements, at its boundaries."""
import sys
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.inet import IP, ICMP, TCP
from scapy.packet import Raw

def naive(m):                       # my prototype rule from the benchmark
    t = m[0]
    hdr = 20 if t in (13,14) else 12 if t in (17,18) else 8
    body = m[hdr:] if len(m) > hdr else b''
    return body[:128] if t in (3,4,5,11,12) else body

def rfc4884(m):                     # what scapy's source says it does
    t = m[0]
    hdr = 20 if t in (13,14) else 12 if t in (17,18) else 8
    body = m[hdr:] if len(m) > hdr else b''
    if t in (3, 11, 12) and len(m) >= 144:
        return body[:128]
    return body

print(f"{'type':>5} {'msglen':>7} {'scapy':>6} {'naive':>6} {'rfc4884':>8}   verdict")
bad_naive = bad_rfc = 0
for t in (3, 4, 5, 11, 12):
    for extra in range(60, 135):
        quoted = bytes(IP(src='10.0.0.1', dst='10.0.0.2') / TCP() / Raw(b'A'*extra))
        m = bytes(ICMP(type=t, code=0)) + quoted
        s = bytes(ICMP(m).payload)
        n, r = naive(m), rfc4884(m)
        if n != s: bad_naive += 1
        if r != s: bad_rfc += 1
        if (n != s or r != s) and 130 <= len(m) <= 150:
            print(f"{t:>5} {len(m):>7} {len(s):>6} {len(n):>6} {len(r):>8}   "
                  f"{'naive WRONG' if n!=s else ''}{' rfc WRONG' if r!=s else ''}")
print(f"\nover {5*75} synthetic messages: naive wrong {bad_naive}, rfc4884 wrong {bad_rfc}")
