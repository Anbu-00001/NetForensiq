# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Decompose the current PCAP import into its stages and time each one.

Each stage is a superset of the one above it, so the marginal cost of a stage
is its time minus the previous stage's. Nothing is estimated: every number
below is a wall-clock measurement of this machine reading this file.
"""
import os, sys, time, resource

sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')

PCAP = sys.argv[1]
LIMIT = int(sys.argv[2]) if len(sys.argv) > 2 else 400_000

from scapy.utils import RawPcapReader
from capture import fastparse


def rss_mb():
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def stage_0_disk():
    """Pure sequential read of the bytes, nothing parsed. The floor."""
    t = time.perf_counter()
    n = 0
    with open(PCAP, 'rb') as fh:
        while True:
            b = fh.read(1 << 20)
            if not b:
                break
            n += len(b)
    return time.perf_counter() - t, n


def stage_1_frames():
    """scapy RawPcapReader: record framing + a metadata object per packet."""
    t = time.perf_counter()
    n = 0
    reader = RawPcapReader(PCAP)
    try:
        for _data, _meta in reader:
            n += 1
            if n >= LIMIT:
                break
    finally:
        reader.close()
    return time.perf_counter() - t, n


def stage_2_frames_ts():
    """What service._read_into actually consumes: bytes + float ts + linktype."""
    t = time.perf_counter()
    n = 0
    for _data, _ts, _lt in fastparse.iter_frames(PCAP):
        n += 1
        if n >= LIMIT:
            break
    return time.perf_counter() - t, n


def stage_3_parse():
    """+ fastparse.parse: the struct header extraction."""
    t = time.perf_counter()
    n = ok = 0
    parse = fastparse.parse
    for data, _ts, lt in fastparse.iter_frames(PCAP):
        if parse(data, lt) is not None:
            ok += 1
        n += 1
        if n >= LIMIT:
            break
    return time.perf_counter() - t, n, ok


def stage_4_aggregate():
    """+ FlowAggregator.process_frame: entropy, flow table, app-layer."""
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
    django.setup()
    from capture.processor import FlowAggregator
    agg = FlowAggregator()
    t = time.perf_counter()
    n = 0
    pf = agg.process_frame
    for data, ts, lt in fastparse.iter_frames(PCAP):
        pf(data, ts, lt)
        n += 1
        if n >= LIMIT:
            break
    el = time.perf_counter() - t
    return el, n, len(agg.flows) + len(agg.completed)


print(f"file   : {PCAP}")
print(f"size   : {os.path.getsize(PCAP)/1e6:.1f} MB")
print(f"limit  : {LIMIT} packets\n")

d, nbytes = stage_0_disk()
print(f"0 disk read whole file        {d:7.2f}s  ({nbytes/1e6/d:.0f} MB/s)")

f1, n1 = stage_1_frames()
print(f"1 RawPcapReader frames        {f1:7.2f}s  ({n1} pkts, {n1/f1/1000:.0f}k pkt/s)")

f2, n2 = stage_2_frames_ts()
print(f"2 + timestamp/linktype        {f2:7.2f}s  (marginal {f2-f1:+.2f}s)")

f3, n3, ok = stage_3_parse()
print(f"3 + fastparse.parse           {f3:7.2f}s  (marginal {f3-f2:+.2f}s, {ok}/{n3} parsed)")

f4, n4, flows = stage_4_aggregate()
print(f"4 + FlowAggregator            {f4:7.2f}s  (marginal {f4-f3:+.2f}s, {flows} flows)")

print()
print("share of stage-4 total:")
print(f"  frame reading (scapy)   {f2/f4*100:5.1f}%")
print(f"  header parse (struct)   {(f3-f2)/f4*100:5.1f}%")
print(f"  flow aggregation        {(f4-f3)/f4*100:5.1f}%")
print(f"\npeak RSS {rss_mb():.0f} MB")
