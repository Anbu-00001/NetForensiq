"""Total scapy share of aggregation: DNS dissection + ICMP boundary."""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from capture import fastparse
from capture.processor import FlowAggregator

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
frames = []
for f in fastparse.iter_frames(PCAP):
    frames.append(f)
    if len(frames) >= LIMIT: break

REAL_DNS, REAL_ICMP = FlowAggregator._dns_layer, FlowAggregator._icmp_payload

def timed(label, dns, icmp):
    FlowAggregator._dns_layer = REAL_DNS if dns else (lambda s,*a,**k: None)
    FlowAggregator._icmp_payload = REAL_ICMP if icmp else (lambda s,p: p)
    agg = FlowAggregator()
    t = time.perf_counter(); pf = agg.process_frame
    for d,ts,l in frames: pf(d,ts,l)
    el = time.perf_counter()-t
    FlowAggregator._dns_layer, FlowAggregator._icmp_payload = REAL_DNS, REAL_ICMP
    print(f"  {label:26s} {el:7.2f}s")
    return el

print(f"{os.path.basename(PCAP)}  ({len(frames)} packets)")
full  = timed("full", True, True)
nodns = timed("without scapy DNS", False, True)
noicmp= timed("without scapy ICMP", True, False)
none_ = timed("without either", False, False)
print(f"  -> scapy total = {(full-none_)/full*100:.1f}% of aggregation "
      f"({full-none_:.2f}s of {full:.2f}s)")
