# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Is scapy's 128-byte cut the RFC 4884 'length' octet (original datagram in 32-bit words)?"""
import sys, collections
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.inet import ICMP
from capture import fastparse
PCAP = sys.argv[1]
stats = collections.Counter(); ok = bad = 0
for data, ts, lt in fastparse.iter_frames(PCAP):
    p = fastparse.parse(data, lt)
    if not (p and p[2] == 'ICMP' and p[6]): continue
    m = p[6]
    if m[0] not in (3, 11) or len(m) < 8: continue
    s = len(bytes(ICMP(m).payload))
    length_octet = m[5]
    stats[(length_octet, s)] += 1
    if length_octet and s == length_octet * 4: ok += 1
    elif not length_octet and s == len(m) - 8: ok += 1
    else: bad += 1
print(f"RFC 4884 rule (len == length_octet*4) holds: {ok}, violated: {bad}")
for (lo, s), c in stats.most_common(6):
    print(f"   length octet={lo:3d} (={lo*4} bytes)  scapy payload={s:4d}  x{c}")
