"""
Per-machine summaries — the answer to "which computer?"

Why this exists
---------------
The dashboard could tell an officer there were 166,972 flows. No investigation
has ever turned on that number. The questions actually asked are "which machine
was compromised", "who was it talking to", and "what did it do" — and until now
those had to be reconstructed by reading a findings list one row at a time.

This module groups everything the system knows by the machine it concerns, so a
capture reduces to a short list of hosts, each with a plain sentence about what
it did.

Computed, not stored
--------------------
There is no HostProfile table and no migration. Every figure here is derived
from Flow and Detection rows on request, so it cannot drift out of step with
the findings the way a cached summary would, and a re-run of the detection
engine is reflected immediately.

Roles are proposals, not facts
------------------------------
The role assigned to a host — resolver, gateway, server, client — is inferred
from behaviour observed in this capture alone. A machine that answered DNS for
three others is *probably* the resolver, but a capture is a keyhole and the
inference can be wrong. Every role therefore carries the observation that
produced it, so an officer can disagree with it, and none of them feeds a
detection rule.
"""

from collections import defaultdict

from .detection import THRESHOLDS, is_internal, session_home_networks
from .models import Detection, Flow

# A host answering on this port for more than one peer is proposed as the
# network's resolver. Port 53 is DNS by IANA assignment, not by our choice.
DNS_PORT = 53

# How many distinct peers a host must serve before "server" describes it better
# than "client". Two is the smallest number that is not a coincidence: one peer
# is a conversation, two is a service.
#
# [OUR HEURISTIC] Deliberately not registered in THRESHOLDS: no detection rule
# reads it, and putting a presentation-only figure into the table an officer is
# told lists every threshold the engine compares against would overstate what
# the engine does.
MIN_PEERS_FOR_SERVICE = 2

# Severity ordering, worst first, for picking a host's headline finding.
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'info')


def _role(host, stats, resolver_ips, gateway_ips):
    """
    What this machine appears to be, and why.

    Returns (role, evidence). The evidence is the observation in words, so the
    proposal can be checked rather than taken on trust.
    """
    if host in resolver_ips:
        return 'resolver', (
            f'answered DNS on port {DNS_PORT} for '
            f'{len(stats["dns_clients"])} other machines'
        )
    if host in gateway_ips:
        return 'gateway', (
            f'carried traffic for {len(stats["internal_peers"])} internal '
            f'machines reaching outside the monitored network'
        )
    if (stats['flows_received'] > stats['flows_initiated']
            and len(stats['peers']) >= MIN_PEERS_FOR_SERVICE):
        ports = sorted(stats['listening_ports'])[:4]
        return 'server', (
            f'accepted {stats["flows_received"]} connections from '
            f'{len(stats["peers"])} machines'
            + (f' on port{"s" if len(ports) > 1 else ""} '
               f'{", ".join(str(p) for p in ports)}' if ports else '')
        )
    if len(stats['unique_ports_contacted']) >= THRESHOLDS['scan_unique_ports'][0]:
        return 'scanner', (
            f'contacted {len(stats["unique_ports_contacted"])} distinct ports — '
            f'at or above the {THRESHOLDS["scan_unique_ports"][0]}-port '
            f'threshold this engine treats as scanning'
        )
    return 'client', (
        f'opened {stats["flows_initiated"]} conversations and accepted '
        f'{stats["flows_received"]}'
    )


def _verdict(stats, findings, internal):
    """
    One sentence an officer can read aloud.

    States what was observed and what was concluded, and never asserts intent —
    the engine sees timing and volume, not motive.
    """
    if not findings:
        side = 'inside' if internal else 'outside'
        return (
            f'Nothing was flagged against this machine. It is {side} the '
            f'monitored network and accounted for {stats["flow_count"]} '
            f'conversations.'
        )

    worst = findings[0]
    rules = {f['rule_id'] for f in findings}
    if len(rules) == 1:
        return (
            f'Flagged by one rule ({worst["rule_id"]}), at {worst["severity"]} '
            f'severity: {worst["title"]}'
        )
    return (
        f'Flagged by {len(rules)} independent rules, the most serious at '
        f'{worst["severity"]} severity: {worst["title"]}. Independent rules '
        f'agreeing on one machine is a stronger signal than any one alone.'
    )


def profile_hosts(session, limit=None):
    """
    Every machine seen in this capture, worst first.

    `limit` caps the returned list; the total is still reported so the interface
    can say how many were left out rather than silently truncating.
    """
    networks = session_home_networks(session)

    stats = defaultdict(lambda: {
        'flow_count': 0, 'flows_initiated': 0, 'flows_received': 0,
        'bytes_out': 0, 'bytes_in': 0,
        'peers': set(), 'internal_peers': set(), 'external_peers': set(),
        'listening_ports': set(), 'unique_ports_contacted': set(),
        'dns_clients': set(), 'dns_queries': 0,
        'first_seen': None, 'last_seen': None,
        'protocols': set(), 'app_protocols': set(),
        'server_names': set(), 'ja4': set(),
    })

    # Who talked to whom, collapsed to one entry per pair. This is what a link
    # chart draws: an officer looking at a diagram asks about the line between
    # two machines, not about the 179 separate conversations it stands for.
    edges = defaultdict(lambda: {
        'flows': 0, 'bytes': 0, 'protocols': set(), 'risk': 0,
    })

    fields = (
        'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'initiator_ip', 'bytes_sent', 'bytes_received',
        'first_seen', 'last_seen', 'app_protocol', 'dns_query_count',
        'tls_sni', 'http_host', 'ja4_fingerprint', 'risk_score',
    )
    for flow in Flow.objects.filter(session=session).values(*fields):
        initiator = flow['initiator_ip'] or flow['src_ip']
        responder = flow['dst_ip'] if initiator == flow['src_ip'] else flow['src_ip']
        server_port = flow['dst_port'] if initiator == flow['src_ip'] else flow['src_port']

        if initiator and responder:
            edge = edges[(initiator, responder)]
            edge['flows'] += 1
            edge['bytes'] += (flow['bytes_sent'] or 0) + (flow['bytes_received'] or 0)
            if flow['app_protocol'] or flow['protocol']:
                edge['protocols'].add(flow['app_protocol'] or flow['protocol'])
            edge['risk'] = max(edge['risk'], flow['risk_score'] or 0)

        for host, peer, is_initiator in ((initiator, responder, True),
                                         (responder, initiator, False)):
            if not host:
                continue
            s = stats[host]
            s['flow_count'] += 1
            s['peers'].add(peer)
            if flow['protocol']:
                s['protocols'].add(flow['protocol'])
            if flow['app_protocol']:
                s['app_protocols'].add(flow['app_protocol'])

            if is_internal(peer, networks):
                s['internal_peers'].add(peer)
            else:
                s['external_peers'].add(peer)

            if is_initiator:
                s['flows_initiated'] += 1
                s['bytes_out'] += flow['bytes_sent'] or 0
                s['bytes_in'] += flow['bytes_received'] or 0
                if server_port:
                    s['unique_ports_contacted'].add(server_port)
                s['dns_queries'] += flow['dns_query_count'] or 0
                for name in (flow['tls_sni'], flow['http_host']):
                    if name:
                        s['server_names'].add(name)
                if flow['ja4_fingerprint']:
                    s['ja4'].add(flow['ja4_fingerprint'])
            else:
                s['flows_received'] += 1
                s['bytes_out'] += flow['bytes_received'] or 0
                s['bytes_in'] += flow['bytes_sent'] or 0
                if server_port:
                    s['listening_ports'].add(server_port)
                if server_port == DNS_PORT:
                    s['dns_clients'].add(peer)

            for key, value in (('first_seen', flow['first_seen']),
                               ('last_seen', flow['last_seen'])):
                if value is None:
                    continue
                current = s[key]
                if current is None:
                    s[key] = value
                elif key == 'first_seen':
                    s[key] = min(current, value)
                else:
                    s[key] = max(current, value)

    # Findings, grouped by the machine they name.
    by_host = defaultdict(list)
    for d in Detection.objects.filter(session=session).values(
            'rule_id', 'severity', 'title', 'subject_ip', 'triage_status'):
        if d['subject_ip']:
            by_host[d['subject_ip']].append(d)

    resolvers = {h for h, s in stats.items()
                 if len(s['dns_clients']) >= MIN_PEERS_FOR_SERVICE}
    gateways = {h for h, s in stats.items()
                if len(s['internal_peers']) >= MIN_PEERS_FOR_SERVICE
                and s['flows_received'] > 0 and not is_internal(h, networks)}

    rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
    profiles = []
    for host, s in stats.items():
        findings = sorted(
            by_host.get(host, []),
            key=lambda d: rank.get(d['severity'], len(SEVERITY_ORDER)),
        )
        internal = is_internal(host, networks)
        role, role_evidence = _role(host, s, resolvers, gateways)

        profiles.append({
            'ip': host,
            'is_internal': internal,
            'role': role,
            'role_evidence': role_evidence,
            'verdict': _verdict(s, findings, internal),

            'flow_count': s['flow_count'],
            'flows_initiated': s['flows_initiated'],
            'flows_received': s['flows_received'],
            'bytes_out': s['bytes_out'],
            'bytes_in': s['bytes_in'],
            'peer_count': len(s['peers']),
            'internal_peer_count': len(s['internal_peers']),
            'external_peer_count': len(s['external_peers']),
            'unique_ports_contacted': len(s['unique_ports_contacted']),
            'listening_ports': sorted(s['listening_ports'])[:8],
            'dns_queries': s['dns_queries'],
            'first_seen': s['first_seen'],
            'last_seen': s['last_seen'],
            'protocols': sorted(s['protocols']),
            'app_protocols': sorted(s['app_protocols']),
            'server_names': sorted(s['server_names'])[:8],
            'ja4_fingerprints': sorted(s['ja4']),

            'finding_count': len(findings),
            'distinct_rules': sorted({f['rule_id'] for f in findings}),
            'worst_severity': findings[0]['severity'] if findings else None,
            'findings': [
                {'rule_id': f['rule_id'], 'severity': f['severity'],
                 'title': f['title'], 'triage_status': f['triage_status']}
                for f in findings[:10]
            ],
            'untriaged_findings': sum(
                1 for f in findings if f['triage_status'] == 'new'
            ),
        })

    # Worst first: implicated machines, then by how many rules agree, then by
    # traffic. An officer opening this page should not have to hunt for the
    # machine the capture is about.
    profiles.sort(key=lambda p: (
        rank.get(p['worst_severity'], len(SEVERITY_ORDER)),
        -len(p['distinct_rules']),
        -p['flow_count'],
    ))

    total = len(profiles)
    if limit is not None:
        kept = profiles[:limit]

        # Then pull in the direct peers of any implicated machine, even if they
        # ranked below the cut. "Who did the infected computer talk to" is the
        # next question after "which computer", and a link chart that drew the
        # suspect host with its counterparties missing would answer neither.
        # Capped so one busy host cannot drag the whole capture back in.
        shown = {p['ip'] for p in kept}
        wanted = set()
        for p in kept:
            if not p['finding_count']:
                continue
            for (src, dst) in edges:
                if src == p['ip'] and dst not in shown:
                    wanted.add(dst)
                elif dst == p['ip'] and src not in shown:
                    wanted.add(src)

        by_ip = {p['ip']: p for p in profiles}
        extra = [by_ip[ip] for ip in wanted if ip in by_ip][:limit]
        profiles = kept + extra

    # Only edges between machines the caller can see. An edge to a node that
    # was not returned would draw a line to nowhere.
    visible = {p['ip'] for p in profiles}
    implicated = {p['ip'] for p in profiles if p['finding_count']}
    edge_list = sorted(
        (
            {
                'source': src, 'target': dst,
                'flows': e['flows'], 'bytes': e['bytes'],
                'protocols': sorted(p for p in e['protocols'] if p),
                'risk_score': e['risk'],
                # An edge is drawn as implicated when either end is. The rule
                # named a machine, not a link, so this is presentation rather
                # than a finding — it points the eye, it does not conclude.
                'touches_finding': src in implicated or dst in implicated,
            }
            for (src, dst), e in edges.items()
            if src in visible and dst in visible
        ),
        key=lambda e: (-e['risk_score'], -e['bytes']),
    )

    return {
        'hosts': profiles,
        'edges': edge_list,
        'total_hosts': total,
        'shown': len(profiles),
        'internal_hosts': sum(1 for p in profiles if p['is_internal']),
        'implicated_hosts': sum(1 for p in profiles if p['finding_count']),
        'home_networks': [str(n) for n in networks],
    }
