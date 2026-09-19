# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Do the remaining .only() call sites trigger the same N+1? Measure, don't reason."""
import os, sys, traceback, collections
sys.path.insert(0, '/home/anbu/26_class/GujaratPolice_Hackathon/NetForensiq/backend')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'netforensiq_backend.settings')
import django; django.setup()
from django.db import connection, reset_queries
from django.conf import settings
from django.db.models import Model

settings.DEBUG = True
hits = collections.Counter()
orig = Model.refresh_from_db
def spy(self, using=None, fields=None, **kw):
    st = traceback.extract_stack()[-4:-1]
    hits[(type(self).__name__, fields and tuple(fields))] += 1
    return orig(self, using=using, fields=fields, **kw)
Model.refresh_from_db = spy

from evidence import posture
reset_queries()
for name in dir(posture):
    fn = getattr(posture, name)
    if callable(fn) and not name.startswith('_') and name not in ('datetime',):
        try:
            import inspect
            if inspect.isfunction(fn) and not inspect.signature(fn).parameters:
                fn()
        except Exception:
            pass
Model.refresh_from_db = orig
print(f"deferred-field reloads triggered: {sum(hits.values())}")
for k, c in hits.most_common(5): print(f"   {k}  x{c}")
print(f"queries issued: {len(connection.queries)}")
