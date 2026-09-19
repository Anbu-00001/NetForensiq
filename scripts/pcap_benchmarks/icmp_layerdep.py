import sys
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
MODE = sys.argv[1]
if MODE == 'all':
    from scapy.all import conf          # loads every layer, as capture.service does
from scapy.layers.inet import ICMP
from capture import fastparse
P='/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend/reference_captures/2024-12-18-one-week-of-server-scans-and-probes-and-web-traffic.pcap'
bad=tot=0; first=None
for data,_ts,lt in fastparse.iter_frames(P):
    p = fastparse.parse(data, lt)
    if p is None or p[2]!='ICMP' or not p[6]: continue
    m=p[6]; tot+=1
    ref=bytes(ICMP(m).payload); got=fastparse.icmp_payload(m)
    if ref!=got:
        bad+=1
        if first is None:
            first=(len(m), len(ref), len(got))
            inner = ICMP(m).payload
            first_layers = [l.name for l in [inner] + [inner.payload]*0] 
            names=[]; cur=inner
            while cur:
                names.append(cur.__class__.__name__)
                cur = cur.payload if cur.payload else None
                if len(names)>8: break
            first_layers = names
print(f"scapy layers loaded: {MODE:4s}  ICMP={tot}  divergent={bad}")
if first: print(f"   first: msglen={first[0]} scapy={first[1]} ours={first[2]}  chain={first_layers}")
