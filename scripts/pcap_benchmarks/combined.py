"""End-to-end with both scapy uses replaced by the prototypes."""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession
from capture.service import persist_results, _analyse_after_ingest
import fastdns_proto as fd

_TS, _AM, _ERR = (13, 14), (17, 18), (3, 4, 5, 11, 12)

class Shim:
    """Mimics the handful of attributes _process_dns reads off a scapy DNS."""
    __slots__ = ('id', 'qr', 'ancount', 'qd', 'an', '_answers')
    class _Q:
        __slots__ = ('qname', '_qtype')
        def __init__(s, n, t): s.qname, s._qtype = n, t
        def get_field(s, _): return s
        def i2repr(s, _o, _v): return s._qtype
        @property
        def qtype(s): return s._qtype
    def __init__(self, r):
        self.id, self.qr, self.ancount = r['id'], r['qr'], r['ancount']
        self.qd = self._Q(r['qname'], r['qtype'])
        self._answers = r['answers']
        self.an = [type('A', (), {'type': 1, 'rdata': a})() for a in r['answers']]

def fast_dns(self, scapy_pkt, protocol, payload):
    if scapy_pkt is not None: return None
    if not payload: return None
    r = fd.parse(payload[2:] if protocol == 'TCP' else payload)
    return Shim(r) if r else None

def fast_icmp(self, m):
    if not m or len(m) < 4: return b''
    t = m[0]
    hdr = 20 if t in _TS else 12 if t in _AM else 8
    body = m[hdr:] if len(m) > hdr else b''
    return body[:128] if t in _ERR else body

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2]); FAST = sys.argv[3] == 'fast'
if FAST:
    FlowAggregator._dns_layer = fast_dns
    FlowAggregator._icmp_payload = fast_icmp

t0 = time.perf_counter()
agg = FlowAggregator(); n = 0
for d, ts, lt in fastparse.iter_frames(PCAP):
    agg.process_frame(d, ts, lt); n += 1
    if n >= LIMIT: break
flows, dns = agg.finalize()
t_parse = time.perf_counter() - t0
s = CaptureSession.objects.create(name='COMB', source_type=CaptureSession.Source.PCAP,
                                  pcap_filename=PCAP, state=CaptureSession.State.RUNNING)
t0 = time.perf_counter(); persist_results(s, flows, dns, agg); t_p = time.perf_counter()-t0
t0 = time.perf_counter(); summ = _analyse_after_ingest(s); t_d = time.perf_counter()-t0
tot = t_parse + t_p + t_d
print(f"  [{'prototypes' if FAST else 'scapy     '}] parse {t_parse:6.2f}s  persist {t_p:5.2f}s  "
      f"detect {t_d:5.2f}s  TOTAL {tot:6.2f}s   flows={len(flows)} dns={len(dns)} findings={summ.get('total')}")
s.delete()
