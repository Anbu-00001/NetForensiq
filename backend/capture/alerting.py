"""
Pushing findings to whatever is listening, and recording whether it worked.

Why delivery gets its own audit trail
-------------------------------------
An alert nobody received, that the system believes it sent, is worse than no
alerting at all: the operator stops watching the console because they expect to
be told. So every attempt is written down — destination, transport, how many
findings, and the outcome including the error text. "We alerted the SOC at
02:14" is a claim someone will be asked to support.

What "real-time" honestly means here
------------------------------------
This platform mostly analyses captures that have already been seized, so the
alert fires when detection completes, not when the packet crossed the wire.
Anything else would be a lie about a file that stopped changing when it was
taken into custody. For live capture the same call sits at the end of each
detection pass, so the latency is the pass, not the pipeline.

Air-gapped by assumption
------------------------
Delivery is over plain sockets and urllib, both standard library, so nothing
here needs a package the offline bundle does not already carry. The default
destination is nothing at all: a forensic workstation with no configured sink
must not attempt outbound connections, and silence is the correct behaviour
rather than a misconfiguration to warn about.

Never raises into analysis
--------------------------
A SIEM that is down must not fail an import or roll back a detection run. Every
send is wrapped; failures are recorded and returned, never propagated.
"""

import json
import socket
import ssl
import urllib.error
import urllib.request
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone

from . import siem
from .attack_mapping import beaconing_hosts_in

# Order matters: it is what "at or above this severity" means.
SEVERITY_ORDER = ['low', 'medium', 'high', 'critical']

# A capture with three thousand statistical outliers must not become three
# thousand alerts. Past this the batch is delivered as a summary, which is the
# thing an operator can actually act on.
MAX_ALERTS_PER_BATCH = 100

SOCKET_TIMEOUT_SECONDS = 5
WEBHOOK_TIMEOUT_SECONDS = 10


class DeliveryResult:
    """What happened, in a form the caller can log and the API can serialise."""

    def __init__(self, transport, destination, attempted, delivered, error=''):
        self.transport = transport
        self.destination = destination
        self.attempted = attempted
        self.delivered = delivered
        self.error = error
        self.at = timezone.now()

    @property
    def ok(self):
        return self.delivered == self.attempted and not self.error

    def as_dict(self):
        return {
            'transport': self.transport,
            'destination': self.destination,
            'attempted': self.attempted,
            'delivered': self.delivered,
            'ok': self.ok,
            'error': self.error,
            'at': self.at.isoformat(),
        }

    def __repr__(self):
        return f'<DeliveryResult {self.transport} {self.destination} {self.as_dict()}>'


def _at_or_above(severity, floor):
    try:
        return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(floor)
    except ValueError:
        # An unrecognised severity is delivered rather than dropped. Losing a
        # finding because someone added a severity level is the wrong failure.
        return True


def configured_sinks():
    """
    Where alerts go, from settings. Empty by default and that is not an error.
    """
    sinks = []
    syslog_host = getattr(settings, 'ALERT_SYSLOG_HOST', '') or ''
    if syslog_host:
        sinks.append({
            'transport': 'syslog',
            'host': syslog_host,
            'port': int(getattr(settings, 'ALERT_SYSLOG_PORT', 514)),
            'protocol': str(getattr(settings, 'ALERT_SYSLOG_PROTOCOL', 'udp')).lower(),
        })
    webhook = getattr(settings, 'ALERT_WEBHOOK_URL', '') or ''
    if webhook:
        sinks.append({'transport': 'webhook', 'url': webhook})
    return sinks


def select(detections, floor=None):
    """
    The findings worth sending, and whether anything was held back.

    Returns (selected, suppressed_count). Suppression is reported rather than
    silent: the receiving system is told how many it is not being shown.
    """
    floor = floor or getattr(settings, 'ALERT_MIN_SEVERITY', 'high')
    eligible = [d for d in detections if _at_or_above(d.severity, floor)]
    # Most serious first, so a truncated batch keeps the findings that matter.
    eligible.sort(key=lambda d: SEVERITY_ORDER.index(d.severity)
                  if d.severity in SEVERITY_ORDER else len(SEVERITY_ORDER),
                  reverse=True)
    if len(eligible) <= MAX_ALERTS_PER_BATCH:
        return eligible, 0
    return eligible[:MAX_ALERTS_PER_BATCH], len(eligible) - MAX_ALERTS_PER_BATCH


# ── transports ─────────────────────────────────────────────────────────────

def _send_syslog(sink, lines):
    """RFC 5424 records over UDP or TCP."""
    host, port, protocol = sink['host'], sink['port'], sink['protocol']
    delivered = 0
    if protocol == 'tcp':
        with socket.create_connection((host, port), SOCKET_TIMEOUT_SECONDS) as sock:
            for line in lines:
                # Octet-counted framing (RFC 6587 s.3.4.1). Newline framing
                # breaks the moment a message legitimately contains one, and
                # CEF extensions can.
                payload = line.encode('utf-8')
                sock.sendall(f'{len(payload)} '.encode('ascii') + payload)
                delivered += 1
        return delivered

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(SOCKET_TIMEOUT_SECONDS)
    try:
        for line in lines:
            # UDP syslog is fire-and-forget by design. Counting these as
            # "delivered" would overstate it, so the caller's record says the
            # transport is unacknowledged.
            sock.sendto(line.encode('utf-8'), (host, port))
            delivered += 1
    finally:
        sock.close()
    return delivered


def _send_webhook(sink, records, suppressed):
    """One POST carrying the batch as JSON."""
    url = sink['url']
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError(f'Unsupported webhook scheme: {parsed.scheme!r}')

    body = json.dumps({
        'source': 'netforensiq',
        'sent_at': timezone.now().isoformat(),
        'count': len(records),
        # Named so the receiver cannot mistake a truncated batch for the whole
        # picture.
        'withheld_over_batch_limit': suppressed,
        'findings': records,
    }).encode('utf-8')

    request = urllib.request.Request(
        url, data=body, method='POST',
        headers={'Content-Type': 'application/json',
                 'User-Agent': 'NetForensiq'},
    )
    token = getattr(settings, 'ALERT_WEBHOOK_TOKEN', '') or ''
    if token:
        request.add_header('Authorization', f'Bearer {token}')

    # An air-gapped deployment routinely uses a private CA or a self-signed
    # certificate for its own SIEM. Verification stays on by default and is
    # turned off only by explicit configuration, so nobody disables it by
    # accident.
    context = None
    if parsed.scheme == 'https' and getattr(settings, 'ALERT_WEBHOOK_INSECURE', False):
        context = ssl._create_unverified_context()

    with urllib.request.urlopen(request, timeout=WEBHOOK_TIMEOUT_SECONDS,
                                context=context) as response:
        if not 200 <= response.status < 300:
            raise urllib.error.HTTPError(
                url, response.status, response.reason, response.headers, None)
    return len(records)


# ── entry point ────────────────────────────────────────────────────────────

def dispatch(detections, session=None, observer=None):
    """
    Send eligible findings to every configured sink.

    Returns a list of DeliveryResult, one per sink, empty when none are
    configured. Never raises: analysis must complete whether or not the SIEM
    is reachable.
    """
    sinks = configured_sinks()
    if not sinks:
        return []

    detections = list(detections)
    selected, suppressed = select(detections)
    if not selected:
        return []

    beaconing = beaconing_hosts_in(session) if session is not None else frozenset()

    results = []
    for sink in sinks:
        try:
            if sink['transport'] == 'syslog':
                lines = [siem.to_syslog(d, observer, beaconing) for d in selected]
                if suppressed:
                    lines.append(_suppression_notice(suppressed, observer))
                delivered = _send_syslog(sink, lines)
                destination = f"{sink['host']}:{sink['port']}/{sink['protocol']}"
            else:
                records = [siem.to_ecs(d, observer, beaconing) for d in selected]
                delivered = _send_webhook(sink, records, suppressed)
                destination = sink['url']
            results.append(DeliveryResult(
                sink['transport'], destination, len(selected), delivered))
        except Exception as exc:
            # Deliberately broad. A socket error, a DNS failure, a TLS refusal
            # and a malformed URL are all the same thing from here: the alert
            # did not arrive, and analysis carries on regardless.
            destination = sink.get('url') or f"{sink.get('host')}:{sink.get('port')}"
            results.append(DeliveryResult(
                sink['transport'], destination, len(selected), 0,
                error=f'{type(exc).__name__}: {exc}'))
    return results


def _suppression_notice(suppressed, observer=None):
    """A syslog line saying what was held back, so the count is not lost."""
    host = observer or socket.gethostname()
    stamp = timezone.now().isoformat()
    priority = siem.SYSLOG_FACILITY * 8 + siem.SYSLOG_SEVERITY['medium']
    return (
        f'<{priority}>1 {stamp} {host} netforensiq - BATCH_TRUNCATED - '
        f'{suppressed} further finding(s) were not forwarded: the batch limit '
        f'is {MAX_ALERTS_PER_BATCH}. Query the platform for the full set.'
    )
