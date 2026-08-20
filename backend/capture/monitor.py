"""
Live monitoring, reachable from the interface rather than only from a shell.

The gap this closes
===================
The monitoring loop in `service._run_live_monitor` is real: it sniffs an
interface, re-derives the whole session every window, runs every rule, and
pushes findings that were not there last window to the configured sinks. It
had one problem — the only way to reach it was
`manage.py capture_live --window N`, and `CaptureSessionViewSet` is read-only.

So "real-time alerting for active threats" was true of the software and false
of the product. The officers this is built for are given a browser, not a
shell account on the forensic workstation, and a capability nobody in the
intended audience can invoke has not been delivered.

Why a thread and not a task queue
=================================
Celery, RQ and friends want a broker, which wants a second service, which
wants a network. This box is air-gapped and often a single machine. One
supervised thread inside the application, with the state to describe it, is
the honest shape for the deployment — and it fails visibly, because the status
endpoint reports the thread's real state rather than what was asked for.

One at a time, deliberately
===========================
`start()` refuses while a monitor is running. Two sniffers on one interface
would each see the traffic, write two sets of flows, and raise two findings
for one event — and an officer looking at the alert count would be looking at
a number with no meaning. The refusal names the running session so the caller
knows what to stop.

What this does not claim
========================
Nothing here makes the platform an intrusion prevention system. It observes,
it records, and it tells somebody. It never blocks, never resets a connection
and never quarantines a host: those are actions on a live network, and a tool
whose output is meant to be evidence must not also be a participant in the
events it is describing.
"""

import threading
import time
from collections import deque

from django.utils import timezone

# The whole live state of the box, and there is only one.
_lock = threading.Lock()
_state = None

# How many windows to keep for the interface's activity strip. Twenty windows
# at the default thirty seconds is ten minutes of history — enough to see a
# burst and short enough that the endpoint stays small.
HISTORY = 20

# Bounds on the window, and the reason for each.
#
# Below five seconds the loop spends more time re-deriving the session than
# watching the wire, and the findings that matter are claims about a time
# series that a five-second slice cannot support. Above five minutes the
# feature stops being able to call itself live.
MIN_WINDOW = 5
MAX_WINDOW = 300
DEFAULT_WINDOW = 30


class MonitorBusy(RuntimeError):
    """A monitor is already running on this installation."""


class MonitorRefused(RuntimeError):
    """The monitor cannot start, and the reason is worth reading."""


def _blank(interface, window_seconds, home_net, bpf_filter):
    return {
        'running': True,
        'interface': interface,
        'window_seconds': window_seconds,
        'home_net': home_net,
        'bpf_filter': bpf_filter,
        'session_id': None,
        'session_name': '',
        'started_at': timezone.now(),
        'stopping': False,
        'error': '',
        # Counters. Every one of these is measured, not estimated.
        'windows': 0,
        'packets': 0,
        'flows': 0,
        'findings_total': 0,
        'findings_new_total': 0,
        'alerts_attempted': 0,
        'alerts_delivered': 0,
        'last_window_at': None,
        'recent': deque(maxlen=HISTORY),
        'newest_findings': deque(maxlen=8),
        'deliveries': deque(maxlen=8),
        'thread': None,
        'stop_event': threading.Event(),
    }


def status():
    """
    What the monitor is doing, or the last thing it did.

    Never raises and never blocks on the capture thread: this is polled from a
    dashboard, and a status endpoint that can hang is a dashboard that can
    hang.
    """
    with _lock:
        if _state is None:
            return {
                'running': False,
                'ever_run': False,
                'note': (
                    'No live monitor has been started on this installation. '
                    'Analysis of imported captures is unaffected — monitoring '
                    'is for watching an interface as traffic happens.'
                ),
            }

        thread = _state.get('thread')
        alive = bool(thread and thread.is_alive())
        recent = list(_state['recent'])

        return {
            'running': alive,
            'ever_run': True,
            'stopping': _state['stopping'] and alive,
            'interface': _state['interface'],
            'window_seconds': _state['window_seconds'],
            'home_net': _state['home_net'],
            'bpf_filter': _state['bpf_filter'],
            'session_id': _state['session_id'],
            'session_name': _state['session_name'],
            'started_at': _state['started_at'].isoformat(),
            'error': _state['error'],
            'windows': _state['windows'],
            'packets': _state['packets'],
            'flows': _state['flows'],
            'findings_total': _state['findings_total'],
            'findings_new_total': _state['findings_new_total'],
            'alerts_attempted': _state['alerts_attempted'],
            'alerts_delivered': _state['alerts_delivered'],
            # The freshness of the numbers, not just the numbers. A stalled
            # capture leaves a plausible packet count frozen in place, and
            # without this there is nothing to tell it from a quiet one.
            'last_window_at': (
                _state['last_window_at'].isoformat()
                if _state['last_window_at'] else None
            ),
            'seconds_since_window': (
                round((timezone.now() - _state['last_window_at']).total_seconds(), 1)
                if _state['last_window_at'] else None
            ),
            'recent': recent,
            'newest_findings': list(_state['newest_findings']),
            'deliveries': list(_state['deliveries']),
            'sinks': _describe_sinks(),
        }


def _describe_sinks():
    """
    Where an alert would go, stated before one is raised.

    An operator has to be able to see that nothing is configured *before* the
    incident, not discover it afterwards from an empty inbox. Silence with no
    sink configured is correct behaviour on an air-gapped box, and it is only
    correct if it is visible.
    """
    from django.conf import settings

    syslog_host = getattr(settings, 'ALERT_SYSLOG_HOST', '') or ''
    webhook = getattr(settings, 'ALERT_WEBHOOK_URL', '') or ''

    sinks = []
    if syslog_host:
        sinks.append({
            'kind': 'syslog',
            'target': f'{syslog_host}:{getattr(settings, "ALERT_SYSLOG_PORT", 514)}',
            'transport': getattr(settings, 'ALERT_SYSLOG_PROTOCOL', 'udp'),
        })
    if webhook:
        sinks.append({'kind': 'webhook', 'target': webhook, 'transport': 'https'})

    return {
        'configured': len(sinks),
        'sinks': sinks,
        'note': (
            'Findings are recorded either way. A sink is where they are also '
            'pushed to.' if sinks else
            'No alert sink is configured, so findings are recorded and nothing '
            'leaves this machine. On an air-gapped workstation that is the '
            'correct setting, not a fault.'
        ),
    }


def start(*, interface, window_seconds=DEFAULT_WINDOW, home_net='',
          bpf_filter='', user=None, name=''):
    """
    Begin watching an interface. Returns the status dict.

    Refuses loudly rather than starting something that cannot work: without
    CAP_NET_RAW scapy sniffs nothing at all and reports no error, which on a
    demonstration is the worst possible failure — a console that looks alive
    and is deaf.
    """
    from .privileges import can_capture

    window_seconds = max(MIN_WINDOW, min(int(window_seconds or DEFAULT_WINDOW),
                                         MAX_WINDOW))

    ok, reason = can_capture()
    if not ok:
        raise MonitorRefused(reason)

    global _state
    with _lock:
        thread = _state.get('thread') if _state else None
        if thread and thread.is_alive():
            raise MonitorBusy(
                f"A monitor is already running on {_state['interface']} "
                f"(session #{_state['session_id']}). Stop it before starting "
                f"another: two sniffers on one interface raise two findings "
                f"for one event."
            )
        _state = _blank(interface, window_seconds, home_net, bpf_filter)
        worker = threading.Thread(
            target=_run, name='netforensiq-monitor', daemon=True,
            kwargs={'interface': interface, 'window_seconds': window_seconds,
                    'home_net': home_net, 'bpf_filter': bpf_filter,
                    'user': user, 'name': name},
        )
        _state['thread'] = worker
        worker.start()

    # A short grace period so the caller gets the session identifier rather
    # than a status with a null in it, without blocking for a whole window.
    for _ in range(40):
        if status().get('session_id'):
            break
        time.sleep(0.05)
    return status()


def stop(timeout=None):
    """
    Ask the monitor to finish at the end of its current window.

    Not a kill. The loop persists flows and runs detection inside the window,
    and interrupting that halfway would leave a session holding flows nothing
    has been analysed against — which looks exactly like a capture in which
    nothing was found.
    """
    with _lock:
        if _state is None:
            return status()
        thread = _state.get('thread')
        if not (thread and thread.is_alive()):
            return status()
        _state['stopping'] = True
        _state['stop_event'].set()
        window = _state['window_seconds']

    thread.join(timeout if timeout is not None else window + 30)
    return status()


def _record_window(payload):
    """Fold one window's result into the published state."""
    with _lock:
        if _state is None:
            return
        _state['windows'] = payload['window']
        _state['packets'] = payload['packets']
        _state['flows'] = payload['flows']
        _state['findings_total'] = payload['findings_total']
        _state['findings_new_total'] += payload['findings_new']
        _state['last_window_at'] = timezone.now()
        _state['recent'].append({
            'window': payload['window'],
            'at': _state['last_window_at'].isoformat(),
            'packets': payload['packets'],
            'flows': payload['flows'],
            'findings_new': payload['findings_new'],
        })
        for title in payload.get('new', [])[:8]:
            _state['newest_findings'].appendleft({
                'title': title,
                'at': _state['last_window_at'].isoformat(),
            })
        for delivery in payload.get('alerts', []):
            _state['alerts_attempted'] += 1
            if delivery.get('ok'):
                _state['alerts_delivered'] += 1
            _state['deliveries'].appendleft(delivery)


def _run(*, interface, window_seconds, home_net, bpf_filter, user, name):
    """The thread body. Every exit path writes something a reader can act on."""
    from django.db import close_old_connections

    from .service import run_live_capture

    def on_window(payload):
        _record_window(payload)

    def should_stop():
        with _lock:
            return _state is not None and _state['stop_event'].is_set()

    try:
        run_live_capture(
            interface=interface,
            window_seconds=window_seconds,
            home_net=home_net,
            bpf_filter=bpf_filter,
            user=user,
            name=name or None,
            on_window=on_window,
            should_stop=should_stop,
            on_session=_publish_session,
        )
    except Exception as exc:
        with _lock:
            if _state is not None:
                _state['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        # The thread owns a database connection of its own; leaving it open
        # holds a SQLite handle for the lifetime of the process.
        close_old_connections()
        with _lock:
            if _state is not None:
                _state['running'] = False


def _publish_session(session):
    """Called once, as soon as the session row exists."""
    with _lock:
        if _state is not None:
            _state['session_id'] = session.id
            _state['session_name'] = session.name
