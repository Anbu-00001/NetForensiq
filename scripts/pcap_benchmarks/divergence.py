"""How often do the two real divergences actually occur, across every capture?"""
import os, sys, collections
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP
from capture import fastparse, fastdns

CAPS = []
for d in ('/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend/reference_captures',
          '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend/synthetic_captures',
          '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/RealAttacksPCAP'):
    if os.path.isdir(d):
        CAPS += [os.path.join(d, f) for f in sorted(os.listdir(d))
                 if f.endswith(('.pcap', '.pcapng'))]

dns_total = dns_bad = icmp_total = icmp_bad = 0
short53 = 0
phantom = collections.Counter()
icmp_bad_kinds = collections.Counter()
icmp_len_change = collections.Counter()

for path in CAPS:
    try:
        frames = fastparse.iter_frames(path)
    except Exception as e:
        print(f"  (skip {os.path.basename(path)}: {e})"); continue
    for data, _ts, lt in frames:
        if not fastparse.supports(lt): continue
        p = fastparse.parse(data, lt)
        if p is None: continue
        _s, _d, proto, sp, dp, _f, payload = p
        if 53 in (sp, dp) and payload:
            dns_total += 1
            if len(payload) < 12: short53 += 1
            try:
                ref = fastdns.from_scapy(DNS(payload[2:]) if proto == 'TCP' else DNS(payload))
            except Exception:
                ref = None
            got = fastdns.parse(payload, over_tcp=(proto == 'TCP'))
            if ref != got:
                dns_bad += 1
                if ref is not None and got is None:
                    phantom[ref.qname] += 1
        if proto == 'ICMP' and payload:
            icmp_total += 1
            try: ref = bytes(ICMP(payload).payload)
            except Exception: ref = b''
            got = fastparse.icmp_payload(payload)
            if ref != got:
                icmp_bad += 1
                icmp_bad_kinds[payload[0]] += 1
                icmp_len_change[len(ref) - len(got)] += 1

print(f"captures examined: {len(CAPS)}")
print(f"DNS  messages {dns_total:7d}   divergent {dns_bad:6d} "
      f"({dns_bad/max(dns_total,1)*100:.3f}%)   payload<12 octets: {short53}")
for name, c in phantom.most_common(3): print(f"      phantom qname {name!r} x{c}")
print(f"ICMP messages {icmp_total:7d}   divergent {icmp_bad:6d} "
      f"({icmp_bad/max(icmp_total,1)*100:.3f}%)")
print(f"      by type: {dict(icmp_bad_kinds)}")
print(f"      scapy_len - ours: {dict(list(icmp_len_change.most_common(6)))}")
