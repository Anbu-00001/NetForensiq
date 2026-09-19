# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Like-for-like: same source dicts -> rows in the same table, ORM vs raw driver."""
import os, sys, time, sqlite3
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
flows, dns = agg.finalize()

s1 = CaptureSession.objects.create(name='FAIR-ORM', source_type=CaptureSession.Source.PCAP,
                                   pcap_filename=PCAP, state=CaptureSession.State.RUNNING)
recs = []
for f in flows:
    r = dict(f); r.pop('_uid'); r.pop('_timestamps', None); recs.append(r)

t = time.perf_counter()
Flow.objects.bulk_create([Flow(session=s1, **r) for r in recs], batch_size=500)
t_orm = time.perf_counter() - t

s2 = CaptureSession.objects.create(name='FAIR-RAW', source_type=CaptureSession.Source.PCAP,
                                   pcap_filename=PCAP, state=CaptureSession.State.RUNNING)
fields = [f for f in Flow._meta.concrete_fields if f.column != 'id']
con = sqlite3.connect(os.environ['SQLITE_NAME'])
t = time.perf_counter()
tuples = []
for r in recs:
    o = Flow(session=s2, **r)                      # same value coercion Django does
    tuples.append(tuple(f.get_prep_value(getattr(o, f.attname)) for f in fields))
cols = ','.join(f.column for f in fields)
con.execute('BEGIN')
con.executemany(f"INSERT INTO capture_flow ({cols}) VALUES ({','.join('?'*len(fields))})", tuples)
con.commit()
t_raw = time.perf_counter() - t
con.close()

a = Flow.objects.filter(session=s1).count(); b = Flow.objects.filter(session=s2).count()
print(f"{len(recs)} flow rows  (ORM wrote {a}, raw wrote {b})")
print(f"  Flow() + bulk_create        {t_orm:6.2f}s")
print(f"  Flow() + executemany        {t_raw:6.2f}s     {t_orm/t_raw:.1f}x faster")
s1.delete(); s2.delete()
