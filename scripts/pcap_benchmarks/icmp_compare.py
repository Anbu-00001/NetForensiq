# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Where does an ICMP header end? scapy vs a table. Must match exactly."""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.inet import ICMP
from capture import fastparse

# scapy's ICMP field list is type/code/cksum (4) + 4 more bytes, except the
# timestamp family which carries three 4-byte stamps after id/seq.
_TIMESTAMP = (13, 14)
_ADDRMASK = (17, 18)

def proto_payload(msg):
    if not msg or len(msg) < 4:
        return b''
    t = msg[0]
    if t in _TIMESTAMP:
        hdr = 20
    elif t in _ADDRMASK:
        hdr = 12
    else:
        hdr = 8
    return msg[hdr:] if len(msg) > hdr else b''

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
msgs = []
for data, ts, lt in fastparse.iter_frames(PCAP):
    p = fastparse.parse(data, lt)
    if p and p[2] == 'ICMP' and p[6]:
        msgs.append(p[6])
    if len(msgs) >= LIMIT: break
print(f"{os.path.basename(PCAP)}: {len(msgs)} ICMP messages")
if not msgs: sys.exit()

def scapy_payload(m):
    try: return bytes(ICMP(m).payload)
    except Exception: return b''

t=time.perf_counter(); S=[scapy_payload(m) for m in msgs]; ts_=time.perf_counter()-t
t=time.perf_counter(); F=[proto_payload(m) for m in msgs]; tf=time.perf_counter()-t
agree=sum(1 for a,b in zip(S,F) if a==b)
print(f"  scapy     {ts_:7.3f}s")
print(f"  table     {tf:7.3f}s      speedup {ts_/tf:.0f}x")
print(f"  identical {agree}/{len(msgs)}")
from collections import Counter
bad=Counter(m[0] for m,a,b in zip(msgs,S,F) if a!=b)
if bad: print(f"  mismatching ICMP types: {dict(bad)}")
