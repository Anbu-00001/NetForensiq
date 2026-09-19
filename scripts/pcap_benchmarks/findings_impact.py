"""Does the ICMP payload definition change any finding, or only bytes?"""
import os, sys
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()          # loads scapy.all via capture.service
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession
from capture.service import persist_results, _analyse_after_ingest

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])

def run(label, use_fast):
    orig = FlowAggregator._icmp_payload
    if use_fast:
        FlowAggregator._icmp_payload = lambda self, m: fastparse.icmp_payload(m)
    agg = FlowAggregator(); n = 0
    for d, ts, lt in fastparse.iter_frames(PCAP):
        agg.process_frame(d, ts, lt); n += 1
        if n >= LIMIT: break
    flows, dns = agg.finalize()
    FlowAggregator._icmp_payload = orig
    s = CaptureSession.objects.create(name=f'IMPACT-{label}',
        source_type=CaptureSession.Source.PCAP, pcap_filename=PCAP,
        state=CaptureSession.State.RUNNING)
    persist_results(s, flows, dns, agg)
    _analyse_after_ingest(s)
    fs = sorted((f.rule_id, f.subject_ip, f.title) for f in s.detections.all())
    ent = sorted(round(f.payload_entropy or 0, 6) for f in s.flows.all())
    s.delete()
    return fs, ent

a_f, a_e = run('scapy', False)
b_f, b_e = run('fast', True)
print(f"{os.path.basename(PCAP)}")
print(f"  findings  scapy={len(a_f)}  fast={len(b_f)}  identical={a_f == b_f}")
diff = sum(1 for x, y in zip(a_e, b_e) if x != y)
print(f"  flow payload_entropy values differing: {diff} of {len(a_e)}")
if a_f != b_f:
    only_a = [x for x in a_f if x not in b_f]; only_b = [x for x in b_f if x not in a_f]
    print(f"  only with scapy: {only_a[:3]}")
    print(f"  only with fast : {only_b[:3]}")
