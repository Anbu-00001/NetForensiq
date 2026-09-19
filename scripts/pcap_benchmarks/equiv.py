# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Seed indicators that DO match, then compare old vs new .only() row-for-row."""
import os, sys, time
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from django.db import connection, reset_queries
from django.conf import settings
from capture import fastparse, ioc
from capture.processor import FlowAggregator
from capture.models import CaptureSession, IOCFeed, IOCIndicator
from capture.service import persist_results

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
agg = FlowAggregator(); n = 0
for d, ts, lt in fastparse.iter_frames(PCAP):
    agg.process_frame(d, ts, lt); n += 1
    if n >= LIMIT: break
flows, dns = agg.finalize()
s = CaptureSession.objects.create(name='EQUIV', source_type=CaptureSession.Source.PCAP,
                                  pcap_filename=PCAP, state=CaptureSession.State.RUNNING,
                                  home_net='192.168.0.0/16')
persist_results(s, flows, dns, agg)

# Seed from what this capture actually contains, so hits are non-zero.
feed = IOCFeed.objects.create(name='EQUIV-TEST', source='http://example.invalid',
                              fmt=IOCFeed.Format.choices[0][0], retrieved_on='2026-09-19')
ext = [f.dst_ip for f in s.flows.all()[:400] if not f.dst_ip.startswith('192.168')]
names = [r.query_name for r in s.dns_records.all()[:400] if r.query_name]
made = 0
for v in list(dict.fromkeys(ext))[:60]:
    IOCIndicator.objects.create(feed=feed, kind=IOCIndicator.Kind.IPV4, value=v); made += 1
for v in list(dict.fromkeys(names))[:60]:
    IOCIndicator.objects.create(feed=feed, kind=IOCIndicator.Kind.DOMAIN, value=v.lower()); made += 1
print(f"seeded {made} indicators")

settings.DEBUG = True
def norm(hits):
    return sorted((h['indicator'].value, h['subject_ip'], h['observed'], h['where'],
                   str(h['seen_at']), h['staleness_days'],
                   h['flow'].id if h['flow'] else None) for h in hits)

reset_queries(); t = time.perf_counter(); new = ioc.match_session(s); t_new = time.perf_counter()-t
q_new = len(connection.queries)

src = open('/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend/capture/ioc.py').read()
old = (src.replace("'id', 'session_id', 'src_ip', 'dst_ip', 'initiator_ip', 'tls_sni',\n        'http_host', 'first_seen',",
                   "'id', 'src_ip', 'dst_ip', 'initiator_ip', 'tls_sni', 'http_host',\n        'first_seen',")
          .replace("'id', 'session_id', 'src_ip', 'query_name', 'timestamp'",
                   "'id', 'src_ip', 'query_name', 'timestamp'"))
assert old != src
ns = dict(ioc.__dict__); exec(compile(old, 'old.py', 'exec'), ns)
reset_queries(); t = time.perf_counter(); prev = ns['match_session'](s); t_old = time.perf_counter()-t
q_old = len(connection.queries)

print(f"  old .only()  {t_old:7.2f}s  queries={q_old:6d}  hits={len(prev)}")
print(f"  new .only()  {t_new:7.2f}s  queries={q_new:6d}  hits={len(new)}")
print(f"  identical hits: {norm(prev) == norm(new)}")
print(f"  speedup {t_old/t_new:.1f}x")
IOCIndicator.objects.filter(feed=feed).delete(); feed.delete(); s.delete()
