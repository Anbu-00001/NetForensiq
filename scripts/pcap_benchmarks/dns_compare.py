# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Prototype vs scapy: identical output? how much faster?"""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from scapy.layers.dns import DNS
from capture import fastparse
import fastdns_proto as fd

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
msgs = []
for data, ts, lt in fastparse.iter_frames(PCAP):
    p = fastparse.parse(data, lt)
    if p and 53 in (p[3], p[4]) and p[6]:
        msgs.append((p[2], p[6]))
    if len(msgs) >= LIMIT: break
print(f"{os.path.basename(PCAP)}: {len(msgs)} port-53 payloads")

def scapy_read(proto, payload):
    try:
        d = DNS(payload[2:]) if proto == 'TCP' else DNS(payload)
        if not d.qd: return None
        qn = d.qd.qname.decode('utf-8', 'ignore')
        qt = d.qd.get_field('qtype').i2repr(d.qd, d.qd.qtype)
        ans = []
        for i in range(int(getattr(d, 'ancount', 0) or 0)):
            try: a = d.an[i]
            except Exception: break
            if getattr(a, 'type', None) in (1, 28):
                v = getattr(a, 'rdata', None)
                if v is not None:
                    ans.append(v.decode() if isinstance(v, bytes) else str(v))
        return (int(d.id), int(d.qr), qn, qt, ans)
    except Exception:
        return None

def proto_read(proto, payload):
    r = fd.parse(payload[2:] if proto == 'TCP' else payload)
    if r is None: return None
    return (r['id'], r['qr'], r['qname'].decode('utf-8','ignore'), r['qtype'], r['answers'])

t = time.perf_counter(); S = [scapy_read(p, b) for p, b in msgs]; t_s = time.perf_counter()-t
t = time.perf_counter(); F = [proto_read(p, b) for p, b in msgs]; t_f = time.perf_counter()-t

agree = sum(1 for a, b in zip(S, F) if a == b)
both_none = sum(1 for a, b in zip(S, F) if a is None and b is None)
print(f"  scapy     {t_s:7.3f}s")
print(f"  prototype {t_f:7.3f}s      speedup {t_s/t_f:.0f}x")
print(f"  identical {agree}/{len(msgs)}  ({both_none} both-None)")
for a, b in zip(S, F):
    if a != b:
        print(f"  first difference:\n    scapy={a}\n    proto={b}"); break
