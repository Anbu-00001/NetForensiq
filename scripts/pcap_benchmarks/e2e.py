# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""End-to-end import broken into its three phases: parse, persist, detect."""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from django.utils import timezone
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession
from capture.service import persist_results, _analyse_after_ingest

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])

t0 = time.perf_counter()
agg = FlowAggregator(); n = 0; pf = agg.process_frame
for d, ts, lt in fastparse.iter_frames(PCAP):
    pf(d, ts, lt); n += 1
    if n >= LIMIT: break
flows, dns = agg.finalize()
t_parse = time.perf_counter() - t0

session = CaptureSession.objects.create(
    name='BENCH-DELETE-ME', source_type=CaptureSession.Source.PCAP,
    pcap_filename=PCAP, state=CaptureSession.State.RUNNING)

t0 = time.perf_counter()
counts = persist_results(session, flows, dns, agg)
t_persist = time.perf_counter() - t0

t0 = time.perf_counter()
summary = _analyse_after_ingest(session)
t_detect = time.perf_counter() - t0

total = t_parse + t_persist + t_detect
print(f"{os.path.basename(PCAP)}  {n} packets -> {len(flows)} flows, {len(dns)} dns")
print(f"  parse + aggregate (scapy/py) {t_parse:7.2f}s  {t_parse/total*100:5.1f}%")
print(f"  persist (Django ORM+SQLite)  {t_persist:7.2f}s  {t_persist/total*100:5.1f}%")
print(f"  detection rules (pure py)    {t_detect:7.2f}s  {t_detect/total*100:5.1f}%")
print(f"  TOTAL                        {total:7.2f}s   findings={summary.get('total')}")
session.delete()
