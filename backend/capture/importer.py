# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Run a capture import outside the request that asked for it.

The problem this solves
=======================
Uploading a capture used to hash it, seal it, parse it, persist it and run
every detection rule *inside the HTTP request*, with the browser waiting on
`timeout: 0` and nothing to show for it. Measured on real captures
(research/155):

* a 46 MB capture took 102 seconds, during which the page showed a spinner and
  no figure of any kind;
* anything that dropped the connection in those 102 seconds — a proxy read
  timeout, a closed lid, Wi-Fi — left the browser spinning forever, even
  though the server went on to finish the import perfectly;
* a 209 MB capture exhausted the worker's memory, and took the worker with it.

That is the most likely explanation of an upload at the hackathon that "kept
loading and never finished".

Why a separate process and not a thread
=======================================
`capture.monitor` runs the live monitor in a thread, and says why: a task
queue wants a broker, which wants a second service, which wants a network, and
this box is air-gapped. All of that still holds, and none of it argues for a
thread *here*:

* **Memory.** An import's peak is set by the number of conversations in the
  capture. In a thread, that peak is inside the web worker, and a capture that
  exhausts it takes down every request that worker was serving. A child holds
  its own memory, and `RLIMIT_AS` makes exhausting it kill the child and
  nothing else — the same trade `apk_runner` already makes for androguard.
* **Lifetime.** gunicorn recycles workers (`max_requests`) and kills any that
  go quiet. A thread started inside a request dies with its worker, silently,
  leaving a session that says "running" for ever. A child process outlives the
  worker that started it.

So: the parent seals the file and creates the session row, the child does the
work, and the two meet in the database — the same boundary `monitor` uses,
for the same reason.

What the parent does NOT hand over
==================================
The child is `manage.py run_import`, started with a session id and nothing
else. No file contents, no user object, no request — everything it needs is
already on the row it was given, which also means anything it writes is
attributable to that session without the parent having to be believed.
"""

import os
import subprocess
import sys

from django.conf import settings
from django.db import connections
from django.utils import timezone

from .models import CaptureSession

# An import that has not reported in this long is one whose worker is gone.
#
# Progress is written every TICK_PACKETS packets, which on the slowest capture
# measured (a 209 MB file on a laptop) was under 20 seconds, and detection
# reports at its start and end. Detection itself has no inner heartbeat and
# took 43 seconds on the largest session measured, so the threshold has to
# clear that with room to spare on a slower machine.
#
# Being wrong in the two directions is not symmetrical: calling a live import
# dead tells an officer to re-import a capture that is about to finish, while
# waiting a few extra minutes only delays a message. Ten minutes.
STALE_AFTER_SECONDS = int(os.environ.get('IMPORT_STALE_AFTER_SECONDS', '600'))

# Address-space ceiling for the child, as for the APK engine.
#
# Reaching it raises MemoryError inside the child, which records the session
# as failed with the remedy (split the capture) and exits — instead of the
# kernel's OOM killer choosing a victim on a workstation with 15 GB and an
# analyst in the middle of something else.
MEMORY_MB = int(os.environ.get('IMPORT_MEMORY_MB', '6144'))


def _child_python():
    return os.environ.get('IMPORT_PYTHON') or sys.executable


def _another_process_can_reach_the_database():
    """
    Whether handing this session to a child process could work at all.

    An in-memory SQLite database exists only inside the process that opened
    it, so a child would connect to a *different*, empty database — or, worse,
    to whatever the settings name in a deployment, which is not the database
    the caller is using. That is exactly the shape of the test suite, and the
    first run of it launched children that went looking for the developer's
    real database.

    So this is not a test flag: it is the precondition for the split existing
    at all, checked rather than assumed.
    """
    override = getattr(settings, 'CAPTURE_IMPORT_INLINE', None)
    if override is not None:
        return not override
    connection = connections['default']
    in_memory = getattr(connection, 'is_in_memory_db', None)
    return not (callable(in_memory) and in_memory())


def start(session):
    """
    Launch the import for `session` and return immediately.

    The child is detached (`start_new_session`) so that it is not in the web
    worker's process group: a gunicorn restart signals the group, and an
    import half-way through a capture must not be one of the things that stops.

    Where a child could not reach the database (see above) the import is run
    here instead, in the calling process. Slower for the caller and identical
    in what it produces — the child runs the same function.
    """
    if not _another_process_can_reach_the_database():
        from .service import run_pcap_import
        run_pcap_import(
            pcap_path=session.pcap_filename, session=session,
            home_net=session.home_net, user=session.started_by,
            evidence=session.evidence,
        )
        return
    command = [
        _child_python(), 'manage.py', 'run_import',
        '--session', str(session.pk), '--memory-mb', str(MEMORY_MB),
    ]
    subprocess.Popen(
        command,
        cwd=str(settings.BASE_DIR),
        stdin=subprocess.DEVNULL,
        # The child writes its own outcome to the session row. Its stdout and
        # stderr go to the server's, where a traceback is worth having and
        # nothing is relied upon.
        stdout=None, stderr=None,
        start_new_session=True,
    )


def progress_of(session):
    """
    What to tell the Import page about this session, as plain fields.

    `stale` is the one that matters: a session can be RUNNING because an
    import is under way, or because the process doing it no longer exists.
    Those look identical on the row and mean opposite things to the officer
    waiting on it, so the distinction is drawn here rather than left to the
    reader.
    """
    updated = session.progress_updated_at
    running = session.state == CaptureSession.State.RUNNING
    age = (timezone.now() - updated).total_seconds() if updated else None
    stale = bool(running and age is not None and age > STALE_AFTER_SECONDS)

    total = session.progress_total_bytes
    percent = None
    if total:
        percent = round(min(session.progress_bytes_read / total, 1.0) * 100, 1)

    return {
        'session_id': session.pk,
        'state': session.state,
        'stage': session.progress_stage,
        'stage_label': (CaptureSession.Stage(session.progress_stage).label
                        if session.progress_stage else ''),
        'packets_read': session.progress_packets,
        'flows_written': session.progress_flows,
        'bytes_read': session.progress_bytes_read,
        'total_bytes': total,
        # Named for what it is. The figure behind it is an estimate that can
        # lag the true position — see service._Progress._read_estimate.
        'percent_estimate': percent,
        'updated_at': updated,
        'seconds_since_update': round(age, 1) if age is not None else None,
        'stale': stale,
        'error_message': session.error_message,
        'packet_count': session.packet_count,
        'flow_count': session.flow_count,
    }


def abandon_stale(session):
    """
    Record a session whose worker vanished as failed.

    Called when the API notices the gap, so that the state an officer is shown
    is the state that is stored: a row left at "running" for ever is a claim
    that work is happening.
    """
    session.state = CaptureSession.State.FAILED
    session.ended_at = timezone.now()
    session.error_message = (
        'The import stopped reporting progress and its process is no longer '
        'running. Nothing was lost: the capture is sealed in evidence and can '
        'be imported again. If this repeats on the same file, it is most '
        'likely running out of memory — split it with `editcap -c` or import '
        'it on a machine with more.'
    )
    session.save(update_fields=['state', 'ended_at', 'error_message'])
    return session
