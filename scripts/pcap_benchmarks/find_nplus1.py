# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import os, sys, traceback
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from django.db.models import Model
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession
from capture.service import persist_results
from capture import ioc

PCAP = sys.argv[1]
agg = FlowAggregator(); n = 0
for d, ts, lt in fastparse.iter_frames(PCAP):
    agg.process_frame(d, ts, lt); n += 1
    if n >= 40000: break
flows, dns = agg.finalize()
s = CaptureSession.objects.create(name='BENCH4', source_type=CaptureSession.Source.PCAP,
                                  pcap_filename=PCAP, state=CaptureSession.State.RUNNING)
persist_results(s, flows, dns, agg)

orig = Model.refresh_from_db
seen = {}
def spy(self, using=None, fields=None, **kw):
    st = traceback.extract_stack()[-4:-1]
    key = tuple(f"{os.path.basename(f.filename)}:{f.lineno} {f.name}" for f in st)
    seen[(type(self).__name__, fields and tuple(fields), key)] = \
        seen.get((type(self).__name__, fields and tuple(fields), key), 0) + 1
    return orig(self, using=using, fields=fields, **kw)
Model.refresh_from_db = spy
ioc.match_session(s)
Model.refresh_from_db = orig
for (model, fields, st), c in sorted(seen.items(), key=lambda kv: -kv[1])[:5]:
    print(f"{c:6d}x  {model}  deferred fields={fields}")
    for fr in st: print(f"           {fr}")
s.delete()
