"""
Threat-intelligence feeds: importing them, and matching a capture against them.

The whole module is built around one uncomfortable fact: **a blocklist match is
somebody else's opinion, dated.** Everything below exists to make sure that
opinion arrives in an officer's hands with the things needed to weigh it.

What a match is worth
---------------------
An IP blocklist says an address was doing something bad *at some point*.
Addresses are reassigned constantly — a cloud instance's address may belong to
four different customers in a year — so a list downloaded long after a capture
can name an address that had nothing to do with the traffic recorded. The gap
between when the traffic happened and when the list was compiled is therefore
not a detail; it is the main thing determining whether the match means
anything. `_staleness` computes it and every finding states it.

For the same reason a feed match is capped at HIGH and never CRITICAL. Our own
rules cite a measured value against a published threshold; this cites a third
party. Letting borrowed evidence outrank measured evidence would be the wrong
way round.

What is not supported, and why
------------------------------
abuse.ch's SSL blocklist publishes **JA3** MD5s. This tool computes **JA4**.
They are different constructions over different inputs and neither can be
derived from the other, so a JA3 indicator could be imported and would then sit
in the database forever without ever matching a flow — a feed reporting a
healthy entry count and silently contributing nothing. The format is left out
rather than shipped as decoration.

Never fetched
-------------
Nothing here opens a socket. Feeds are downloaded on some other machine,
carried to the workstation, and imported from a file whose SHA-256 is recorded
alongside the officer's statement of where and when they got it. See the
docstring on `IOCFeed` for why an evidence machine must not be making its own
outbound connections.
"""

import csv
import hashlib
import io
import ipaddress
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import IOCFeed, IOCIndicator

# abuse.ch files open with a comment block; several carry the generation time
# in it, e.g. "# Last updated: 2026-08-19 06:52:03 UTC".
_GENERATED = re.compile(
    r'#\s*(?:last\s+updated|generated)\s*:?\s*'
    r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})',
    re.IGNORECASE,
)

# A domain, loosely. Deliberately permissive — the feed decides what is in it;
# this only rejects things that plainly are not names, so a parsing slip cannot
# quietly load blank or partial values.
_DOMAIN = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+$')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _published_from(text):
    """The feed's own generation time, or None. Never the import time."""
    match = _GENERATED.search(text)
    if not match:
        return None
    stamp = match.group(1).replace('T', ' ')
    try:
        return datetime.strptime(stamp, '%Y-%m-%d %H:%M:%S').replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def _classify_address(value):
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return None
    return IOCIndicator.Kind.IPV6 if parsed.version == 6 else IOCIndicator.Kind.IPV4


def _rows(text):
    """Data rows, with comments and blanks removed but line text preserved."""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        yield raw.rstrip('\n')


def _csv_fields(line):
    return next(csv.reader(io.StringIO(line)), [])


def parse(text, fmt):
    """
    (indicators, published_on) for one feed file.

    An indicator is a dict, not a model instance, so parsing is testable
    without a database and so a malformed file is rejected before anything is
    written.

    Rows that do not parse are **skipped, not guessed at**. A feed format that
    changed upstream should import fewer entries and be noticed, rather than
    importing garbage that later matches something.
    """
    published = _published_from(text)
    found = []
    seen = set()

    def add(kind, value, context='', listed_on=None, line=''):
        value = (value or '').strip().strip('"').lower()
        if not value:
            return
        key = (kind, value)
        if key in seen:
            return
        seen.add(key)
        found.append({
            'kind': kind, 'value': value, 'context': context.strip()[:300],
            'listed_on': listed_on, 'source_line': line[:2000],
        })

    for line in _rows(text):
        if fmt == IOCFeed.Format.PLAIN_IP:
            kind = _classify_address(line.split()[0] if line.split() else '')
            if kind:
                add(kind, line.split()[0], line=line)

        elif fmt == IOCFeed.Format.PLAIN_DOMAIN:
            candidate = line.split()[0] if line.split() else ''
            if _DOMAIN.match(candidate):
                add(IOCIndicator.Kind.DOMAIN, candidate, line=line)

        elif fmt == IOCFeed.Format.FEODO_IP:
            # first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware
            fields = _csv_fields(line)
            if len(fields) < 2:
                continue
            kind = _classify_address(fields[1].strip())
            if not kind:
                continue
            context_bits = []
            if len(fields) > 5 and fields[5].strip():
                context_bits.append(fields[5].strip())
            if len(fields) > 2 and fields[2].strip():
                context_bits.append(f'port {fields[2].strip()}')
            add(kind, fields[1], ' · '.join(context_bits),
                _date_or_none(fields[0]), line)

        elif fmt == IOCFeed.Format.URLHAUS:
            # id,dateadded,url,url_status,last_online,threat,tags,link,reporter
            fields = _csv_fields(line)
            if len(fields) < 3:
                continue
            url = fields[2].strip()
            if not url:
                continue
            threat = fields[5].strip() if len(fields) > 5 else ''
            add(IOCIndicator.Kind.URL, url, threat,
                _date_or_none(fields[1]), line)
            # The host is indexed too: a capture sees a name resolved and a
            # connection made, and almost never the full path.
            host = (urlparse(url).hostname or '').strip()
            if host:
                kind = _classify_address(host)
                add(kind or IOCIndicator.Kind.DOMAIN, host,
                    threat, _date_or_none(fields[1]), line)

    return found, published


def _date_or_none(value):
    value = (value or '').strip()
    for pattern in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(value, pattern).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def import_feed(path, *, name, fmt, retrieved_on, source='', licence='',
                notes='', imported_by=None):
    """
    Load a feed file into the database, recording what it was.

    Refuses an empty parse rather than creating a feed with no entries: a feed
    row that exists and matches nothing looks exactly like a feed that is
    working and finding nothing, and the difference matters.
    """
    data = open(path, 'rb').read()
    text = data.decode('utf-8', errors='replace')
    indicators, published = parse(text, fmt)

    if not indicators:
        raise ValueError(
            f'{path} parsed to zero indicators as {fmt}. Either the format is '
            f'wrong or the file changed upstream — importing it would create a '
            f'feed that silently matches nothing.'
        )

    feed = IOCFeed.objects.create(
        name=name, source=source, fmt=fmt,
        file_name=getattr(path, 'name', str(path)).split('/')[-1],
        file_sha256=digest(data), file_bytes=len(data),
        retrieved_on=retrieved_on, published_on=published,
        licence=licence, notes=notes,
        entry_count=len(indicators), imported_by=imported_by,
    )
    IOCIndicator.objects.bulk_create(
        [IOCIndicator(feed=feed, **row) for row in indicators],
        batch_size=2000,
    )
    return feed


def _staleness(feed, captured_at):
    """
    How far the feed's knowledge sits from the traffic, in days, and which way.

    Positive means the feed is newer than the capture — the ordinary case, and
    the one where reassignment is a live concern. Negative means the feed
    predates the traffic, which is the stronger match: the address was already
    listed when the packets were sent.
    """
    if captured_at is None:
        return None
    basis = feed.published_on
    if basis is None:
        basis = datetime.combine(
            feed.retrieved_on, datetime.min.time(), tzinfo=timezone.utc)
    return round((basis - captured_at).total_seconds() / 86400, 1)


def _index(kinds):
    """{value: [indicator, …]} for the kinds asked for, across every feed."""
    index = {}
    rows = (IOCIndicator.objects
            .filter(kind__in=kinds)
            .select_related('feed'))
    for row in rows:
        index.setdefault(row.value, []).append(row)
    return index


def match_session(session):
    """
    Every place a capture touches something a loaded feed names.

    Returns a list of dicts. Building Detection rows is `detection.py`'s job;
    this stays free of that so it can be tested, and reused by anything else
    that wants to know.

    The external end of a flow is the one checked. Matching an internal address
    against a blocklist would fire on the victim, which is both wrong and the
    kind of wrong that gets noticed in court.
    """
    from .detection import is_internal, session_home_networks

    if not IOCFeed.objects.exists():
        return []

    networks = session_home_networks(session)
    address_index = _index([IOCIndicator.Kind.IPV4, IOCIndicator.Kind.IPV6])
    name_index = _index([IOCIndicator.Kind.DOMAIN])

    hits = []

    def record(indicator, *, flow, subject, observed, where, seen_at):
        hits.append({
            'indicator': indicator,
            'feed': indicator.feed,
            'flow': flow,
            'subject_ip': subject,
            'observed': observed,
            'where': where,
            'seen_at': seen_at,
            'staleness_days': _staleness(indicator.feed, seen_at),
        })

    flows = session.flows.all().only(
        'id', 'src_ip', 'dst_ip', 'initiator_ip', 'tls_sni', 'http_host',
        'first_seen',
    )

    for flow in flows:
        internal = flow.initiator_ip or flow.src_ip
        peer = flow.dst_ip if internal == flow.src_ip else flow.src_ip

        for address in {flow.src_ip, flow.dst_ip}:
            if not address or is_internal(address, networks):
                continue
            for indicator in address_index.get(address.lower(), []):
                record(indicator, flow=flow, subject=internal, observed=address,
                       where='conversation endpoint', seen_at=flow.first_seen)

        for name, where in ((flow.tls_sni, 'TLS server name'),
                            (flow.http_host, 'HTTP Host header')):
            if not name:
                continue
            for indicator in _names_matching(name_index, name):
                record(indicator, flow=flow, subject=internal,
                       observed=name.lower(), where=where,
                       seen_at=flow.first_seen)

    for record_row in session.dns_records.all().only(
            'id', 'src_ip', 'query_name', 'timestamp'):
        for indicator in _names_matching(name_index, record_row.query_name):
            hits.append({
                'indicator': indicator,
                'feed': indicator.feed,
                'flow': None,
                'subject_ip': record_row.src_ip,
                'observed': record_row.query_name.lower().rstrip('.'),
                'where': 'DNS query',
                'seen_at': record_row.timestamp,
                'staleness_days': _staleness(indicator.feed, record_row.timestamp),
            })

    return hits


def _names_matching(index, observed):
    """
    Exact name matches only, plus the parent-domain case.

    A feed listing `evil.example` should match `c2.evil.example`, because that
    is what a listed domain means. It must not match `notevil.example`, which a
    naive substring test would — the check walks label boundaries.
    """
    name = (observed or '').strip().lower().rstrip('.')
    if not name:
        return []

    out = []
    labels = name.split('.')
    for cut in range(len(labels) - 1):
        candidate = '.'.join(labels[cut:])
        out.extend(index.get(candidate, []))
    return out
