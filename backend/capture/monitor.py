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

Why the state is in the database
================================
It was a module-level dict, which worked in development and failed in the
container. The application runs under gunicorn with three workers: `start`
spawned its thread inside one process, and the next `status` request was
balanced onto another, which had never heard of it. The monitor ran, saw
traffic and raised findings while the dashboard reported that nothing had ever
been started — the exact failure this panel exists to prevent, produced by the
panel itself.

Shared state between processes has to live somewhere both can reach. There is
already a database. `LiveMonitorState` is one row, rewritten each window, and
`stop` crosses the same boundary in reverse: it sets a flag the capture thread
reads between windows, wherever that thread happens to be running. No broker,
no shared memory, nothing extra to install on a machine with no network.

Why a thread and not a task queue
=================================
Celery and friends want a broker, which wants a second service, which wants a
network. This box is air-gapped and often a single machine. One supervised
thread inside the application, with a row describing it, is the honest shape
for the deployment.

One at a time, deliberately
===========================
`start()` refuses while a monitor is running. Two sniffers on one interface
would each see the traffic, write two sets of flows, and raise two findings for
one event — and an officer reading the alert count would be reading a number
with no meaning.

What this does not claim
========================
Nothing here makes the platform an intrusion prevention system. It observes,
records, and tells somebody. It never blocks, never resets a connection and
never quarantines a host: those are actions on a live network, and a tool whose
output is meant to be evidence must not also be a participant in the events it
describes.
"""

import threading
import time

from django.utils import timezone

from .models import LiveMonitorState

# How many windows to keep for the activity strip. Twenty at the default
# thirty seconds is ten minutes of history — long enough to show a burst,
# short enough that the row stays small.
HISTORY = 20

# Bounds on the window, and the reason for each.
#
# Below five seconds the loop spends longer re-deriving the session than
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


def status():
    """
    What the monitor is doing, or the last thing it did.

    Reads the row, so it answers the same way from any worker. Never raises:
    this is polled by a dashboard, and a status call that can fail is a
    dashboard that can go blank for no reason the reader can see.
    """
    state = LiveMonitorState.load()

    if not state.started_at:
        return {
            'running': False,
            'ever_run': False,
            # The sinks belong here too, not only once a capture is running.
            'sinks': _describe_sinks(),
            'note': (
                'No live monitor has been started on this installation. '
                'Analysis of imported captures is unaffected — monitoring is '
                'for watching an interface as traffic happens.'
            ),
        }

    stale = state.is_stale
    silence = (
        round((timezone.now() - state.last_heartbeat_at).total_seconds(), 1)
        if state.last_heartbeat_at else None
    )

    return {
        # A row claiming to run whose thread has gone silent is reported as not
        # running, with the reason. A monitor that stopped without saying so is
        # the failure this panel is built around; it must not be the panel's
        # own failure mode.
        'running': bool(state.running and not stale),
        'ever_run': True,
        'stale': stale,
        'stopping': state.stop_requested and state.running and not stale,
        'interface': state.interface,
        'window_seconds': state.window_seconds,
        'home_net': state.home_net,
        'bpf_filter': state.bpf_filter,
        'session_id': state.session_id,
        'session_name': state.session.name if state.session else '',
        'started_at': state.started_at.isoformat(),
        'ended_at': state.ended_at.isoformat() if state.ended_at else None,
        'error': (
            state.error or
            ('The process running this capture stopped without closing it '
             f'down — nothing has been recorded for {silence:.0f}s. The '
             'figures below are the last that were confirmed.'
             if stale else '')
        ),
        'windows': state.windows,
        'packets': state.packets,
        'flows': state.flows,
        'findings_total': state.findings_total,
        'findings_new_total': state.findings_new_total,
        'alerts_attempted': state.alerts_attempted,
        'alerts_delivered': state.alerts_delivered,
        # The freshness of the numbers, not just the numbers.
        'last_window_at': (
            state.last_window_at.isoformat() if state.last_window_at else None),
        'seconds_since_window': silence,
        'recent': state.recent,
        'newest_findings': state.newest_findings,
        'deliveries': state.deliveries,
        'sinks': _describe_sinks(),
    }


def start(*, interface, window_seconds=DEFAULT_WINDOW, home_net='',
          bpf_filter='', user=None, name=''):
    """
    Begin watching an interface. Returns the status dict.

    Refuses loudly rather than starting something that cannot work: without
    CAP_NET_RAW scapy sniffs nothing and reports no error, which on a
    demonstration is the worst possible failure — a console that looks alive
    and is deaf.
    """
    from .privileges import can_capture

    window_seconds = max(MIN_WINDOW,
                         min(int(window_seconds or DEFAULT_WINDOW), MAX_WINDOW))

    ok, reason = can_capture()
    if not ok:
        raise MonitorRefused(reason)

    state = LiveMonitorState.load()
    if state.running and not state.is_stale:
        raise MonitorBusy(
            f'A monitor is already running on {state.interface} '
            f'(session #{state.session_id}). Stop it before starting another: '
            f'two sniffers on one interface raise two findings for one event.'
        )

    LiveMonitorState.objects.filter(pk=1).update(
        running=True, stop_requested=False, interface=interface,
        window_seconds=window_seconds, home_net=home_net,
        bpf_filter=bpf_filter, session=None, started_by=user,
        started_at=timezone.now(), ended_at=None, last_window_at=None,
        last_heartbeat_at=timezone.now(), error='',
        windows=0, packets=0, flows=0, findings_total=0, findings_new_total=0,
        alerts_attempted=0, alerts_delivered=0,
        recent=[], newest_findings=[], deliveries=[],
    )

    worker = threading.Thread(
        target=_run, name='netforensiq-monitor', daemon=True,
        kwargs={'interface': interface, 'window_seconds': window_seconds,
                'home_net': home_net, 'bpf_filter': bpf_filter,
                'user': user, 'name': name},
    )
    worker.start()

    # A short grace period so the caller gets a session identifier rather than
    # a null, without blocking for a whole window.
    for _ in range(40):
        if LiveMonitorState.load().session_id:
            break
        time.sleep(0.05)
    return status()


def stop(timeout=None):
    """
    Ask the monitor to finish at the end of its current window.

    Not a kill, and it crosses processes: the flag goes in the row and the
    capture thread reads it between windows, wherever it is running. The loop
    persists flows and runs detection inside a window, and interrupting that
    halfway would leave a session holding traffic nothing has been analysed
    against — which looks exactly like a capture in which nothing was found.
    """
    state = LiveMonitorState.load()
    if not state.running:
        return status()

    LiveMonitorState.objects.filter(pk=1).update(stop_requested=True)

    deadline = time.monotonic() + (
        timeout if timeout is not None else state.window_seconds + 30)
    while time.monotonic() < deadline:
        if not LiveMonitorState.load().running:
            break
        time.sleep(0.25)
    return status()


def _record_window(payload):
    """Fold one window's result into the row. Runs in the capture thread."""
    state = LiveMonitorState.load()
    now = timezone.now()

    recent = list(state.recent)[-(HISTORY - 1):]
    recent.append({
        'window': payload['window'],
        'at': now.isoformat(),
        'packets': payload['packets'],
        'flows': payload['flows'],
        'findings_new': payload['findings_new'],
    })

    newest = [{'title': t, 'at': now.isoformat()}
              for t in payload.get('new', [])[:8]] + list(state.newest_findings)

    deliveries = list(payload.get('alerts', [])) + list(state.deliveries)
    attempted = state.alerts_attempted + len(payload.get('alerts', []))
    delivered = state.alerts_delivered + sum(
        1 for d in payload.get('alerts', []) if d.get('ok'))

    LiveMonitorState.objects.filter(pk=1).update(
        windows=payload['window'],
        packets=payload['packets'],
        flows=payload['flows'],
        findings_total=payload['findings_total'],
        findings_new_total=state.findings_new_total + payload['findings_new'],
        alerts_attempted=attempted,
        alerts_delivered=delivered,
        last_window_at=now,
        last_heartbeat_at=now,
        recent=recent,
        newest_findings=newest[:8],
        deliveries=deliveries[:8],
    )


def _should_stop():
    """Read across the process boundary, once per window."""
    return LiveMonitorState.objects.filter(pk=1, stop_requested=True).exists()


def _publish_session(session):
    """Called once, as soon as the session row exists."""
    from django.db import models
    session_id = getattr(session, 'pk', None)
    if not isinstance(session, models.Model):
        session_id = None
    LiveMonitorState.objects.filter(pk=1).update(
        session_id=session_id, last_heartbeat_at=timezone.now())


def _run(*, interface, window_seconds, home_net, bpf_filter, user, name):
    """The thread body. Every exit path leaves the row saying something true."""
    from django.db import close_old_connections

    from .service import run_live_capture

    close_old_connections()
    error = ''
    try:
        run_live_capture(
            interface=interface,
            window_seconds=window_seconds,
            home_net=home_net,
            bpf_filter=bpf_filter,
            user=user,
            name=name or None,
            on_window=_record_window,
            should_stop=_should_stop,
            on_session=_publish_session,
        )
    except Exception as exc:
        error = f'{type(exc).__name__}: {exc}'
    finally:
        try:
            LiveMonitorState.objects.filter(pk=1).update(
                running=False, stop_requested=False,
                ended_at=timezone.now(), error=error,
            )
        finally:
            # The thread owns a database connection of its own; leaving it open
            # holds a handle for the lifetime of the process.
            close_old_connections()
