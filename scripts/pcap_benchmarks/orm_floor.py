# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""How much of 'persist' is Django, and how much is SQLite itself?"""
import os, sys, time, sqlite3
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from capture import fastparse
from capture.processor import FlowAggregator
from capture.models import CaptureSession, Flow
from capture.service import persist_results

PCAP = sys.argv[1]; LIMIT = int(sys.argv[2])
agg = FlowAggregator(); n = 0
for d, ts, lt in fastparse.iter_frames(PCAP):
    agg.process_frame(d, ts, lt); n += 1
    if n >= LIMIT: break
flows, dns = agg.finalize()

s = CaptureSession.objects.create(name='ORM', source_type=CaptureSession.Source.PCAP,
                                  pcap_filename=PCAP, state=CaptureSession.State.RUNNING)
t = time.perf_counter(); persist_results(s, flows, dns, agg); t_orm = time.perf_counter()-t
cols = [f.column for f in Flow._meta.concrete_fields if f.column != 'id']
_c = sqlite3.connect(os.environ['SQLITE_NAME'])
rows = _c.execute(f"SELECT {','.join(cols)} FROM capture_flow WHERE session_id=?",
                  [s.id]).fetchall()
_c.close()
s.delete()

# Same rows, same database file, raw driver — the floor Django is measured against.
con = sqlite3.connect(os.environ['SQLITE_NAME'])
con.execute("CREATE TABLE IF NOT EXISTS _floor AS SELECT * FROM capture_flow WHERE 0")
con.execute("DELETE FROM _floor")
ph = ','.join('?' * len(cols))
t = time.perf_counter()
con.executemany(f"INSERT INTO _floor ({','.join(cols)}) VALUES ({ph})", rows)
con.commit(); t_raw = time.perf_counter()-t
con.execute("DROP TABLE _floor"); con.commit(); con.close()

print(f"{len(rows)} flow rows + {len(dns)} dns rows")
print(f"  Django ORM bulk_create (both tables) {t_orm:6.2f}s")
print(f"  raw sqlite3 executemany (flows only) {t_raw:6.2f}s")
print(f"  -> ORM overhead is at most {t_orm - t_raw:.2f}s; a non-Django rewrite")
print(f"     cannot go below the {t_raw:.2f}s SQLite itself costs for these rows")
