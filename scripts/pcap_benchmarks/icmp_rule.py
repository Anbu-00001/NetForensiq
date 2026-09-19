# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Hypothesis: scapy ICMP payload == m[hdr:hdr+128] for error types. Test it."""
import sys, collections
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.inet import ICMP
from capture import fastparse

_TS, _AM, _ERR = (13, 14), (17, 18), (3, 4, 5, 11, 12)

def rule(m):
    if not m or len(m) < 4: return b''
    t = m[0]
    hdr = 20 if t in _TS else 12 if t in _AM else 8
    body = m[hdr:] if len(m) > hdr else b''
    return body[:128] if t in _ERR else body

agree = total = 0
bad = collections.Counter()
for path in sys.argv[1:]:
    for data, ts, lt in fastparse.iter_frames(path):
        p = fastparse.parse(data, lt)
        if not (p and p[2] == 'ICMP' and p[6]): continue
        m = p[6]; total += 1
        try: s = bytes(ICMP(m).payload)
        except Exception: s = b''
        if s == rule(m): agree += 1
        else: bad[(m[0], len(m), len(s), len(rule(m)))] += 1
        if total >= 80000: break
print(f"identical {agree}/{total}  ({agree/total*100:.3f}%)")
for k, c in bad.most_common(5):
    print(f"   type={k[0]} msglen={k[1]} scapy={k[2]} rule={k[3]}  x{c}")
