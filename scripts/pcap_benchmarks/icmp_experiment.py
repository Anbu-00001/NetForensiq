"""Where exactly does scapy cut the quoted packet? Vary the input and watch."""
import sys
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.packet import Raw

for proto, inner in (('TCP', TCP(sport=80, dport=1234)), ('UDP', UDP(sport=53, dport=9)),
                     ('ICMP-echo', ICMP(type=8))):
    print(f"--- quoted transport = {proto} ---")
    for extra in (0, 10, 50, 100, 108, 120, 200, 400):
        quoted = IP(src='10.0.0.1', dst='10.0.0.2') / inner / Raw(b'A' * extra)
        raw = bytes(quoted)
        msg = bytes(ICMP(type=3, code=1)) + raw
        got = len(bytes(ICMP(msg).payload))
        print(f"   quoted={len(raw):4d}  scapy payload={got:4d}  "
              f"{'= quoted' if got == len(raw) else 'CUT'}")
