# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Is the persist cost batch_size, or the ORM itself?"""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession, Flow

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
agg = FlowAggregator(); n = 0
for d, ts, lt in fastparse.iter_frames(PCAP):
    agg.process_frame(d, ts, lt); n += 1
    if n >= LIMIT: break
flows, _dns = agg.finalize()
recs = []
for f in flows:
    r = dict(f); r.pop('_uid'); r.pop('_timestamps', None); recs.append(r)
print(f"{len(recs)} flow rows")

for bs in (500, 2000, 5000, None):
    s = CaptureSession.objects.create(name=f'BATCH-{bs}',
        source_type=CaptureSession.Source.PCAP, pcap_filename=PCAP,
        state=CaptureSession.State.RUNNING)
    objs = [Flow(session=s, **r) for r in recs]
    t = time.perf_counter()
    created = Flow.objects.bulk_create(objs, batch_size=bs)
    el = time.perf_counter() - t
    have_pks = sum(1 for o in created if o.pk is not None)
    print(f"  batch_size={str(bs):5s}  {el:6.2f}s   pks returned: {have_pks}/{len(created)}")
    s.delete()
