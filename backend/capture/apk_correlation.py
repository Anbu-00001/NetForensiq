"""
Match what a package names against what the network evidence recorded.

This is the part a standalone scanner cannot do. A host written into the app's
code is a capability; the same host resolved or contacted in a sealed capture is
an event, with a time and an exhibit number.

Only the hosts the report attributes to the app itself are used (see
apk_engine/endpoints.py). SDK traffic — analytics, crash reporting, ad networks —
is left out: that a capture contains a DNS lookup for an analytics domain proves
nothing about this sample, and matching it would bury the one lookup that does.

Threat-feed matches are shown as corroboration and do not change the evidence
tier. A feed can list shared infrastructure, and how often a legitimate app's
hosts appear in the imported feeds has not been measured.
"""

from apk_engine.endpoints import hosts_for_correlation


def correlate_with_captures(report, limit=60):
    from .models import DNSRecord, Flow, IOCIndicator

    hosts, ips = hosts_for_correlation(report.get('endpoints') or {})
    urls = sorted({example for item in (report.get('endpoints') or {}).get('app', [])
                   for example in item.get('examples', []) if '://' in example})
    matches = []

    if hosts:
        rows = (DNSRecord.objects.filter(query_name__in=hosts[:400])
                .select_related('session', 'session__evidence')[:limit])
        for row in rows:
            session = row.session
            matches.append({
                'kind': 'dns', 'indicator': row.query_name,
                'detail': f'Resolved by {row.src_ip}',
                'session_id': session.id if session else None,
                'session_name': session.name if session else '',
                'exhibit': session.evidence.exhibit_number if session and session.evidence else '',
                'at': row.timestamp.isoformat() if row.timestamp else '',
            })

    if ips:
        rows = (Flow.objects.filter(dst_ip__in=ips[:400])
                .select_related('session', 'session__evidence')[:limit])
        for row in rows:
            session = row.session
            matches.append({
                'kind': 'flow', 'indicator': row.dst_ip,
                'detail': f'Contacted by {row.src_ip} on port {row.dst_port}',
                'session_id': session.id if session else None,
                'session_name': session.name if session else '',
                'exhibit': session.evidence.exhibit_number if session and session.evidence else '',
                'at': row.first_seen.isoformat() if row.first_seen else '',
            })

    feed_matches = []
    values = hosts + ips + urls
    if values:
        rows = (IOCIndicator.objects.filter(value__in=values[:800])
                .select_related('feed')[:limit])
        for row in rows:
            feed = row.feed
            feed_matches.append({
                'kind': 'feed', 'indicator': row.value,
                'detail': (f'Listed by {feed.name}, retrieved {feed.retrieved_on}'
                           if feed else 'Listed by an imported feed'),
                'source_line': row.source_line[:300],
            })

    return {
        'matches': matches[:limit],
        'feed_matches': feed_matches[:limit],
        'checked_hosts': len(hosts), 'checked_ips': len(ips), 'checked_urls': len(urls),
        'tier_effect': 'none — corroboration only',
    }
