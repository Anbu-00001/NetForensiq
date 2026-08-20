"""
Exporting findings to a SIEM.

Why a forensic tool exports to a SIEM at all
--------------------------------------------
This platform examines a capture after the fact. A Security Operations Centre
watches a network in the present. They are different jobs, and the honest
reason to connect them is that a finding here is often the first hard evidence
for something the SOC saw as noise a week ago — and the SOC's console is where
an analyst already works. Making findings arrive there, in the format that
console already parses, is the difference between a report someone opens and a
report someone acts on.

Three formats, because SOCs are not standardised
------------------------------------------------
**ECS (Elastic Common Schema)** — JSON, one object per finding. The default:
Elastic/OpenSearch is the most common stack in Indian government SOCs, and ECS
has real field names for the things this tool knows about.

**CEF (Common Event Format)** — the ArcSight lineage, still what many
appliances speak. A pipe-delimited header and key=value extensions.

**RFC 5424 syslog** — the lowest common denominator. Anything ingests it.

What is deliberately not exported
---------------------------------
No case reference, no FIR number, no officer name, no exhibit content. A SIEM
is an operational system with a broad readership; the case around a finding is
not operational data. The exhibit number is included so an analyst who sees
something can ask for the record, which is the correct direction of travel.
"""

import json
import socket
from datetime import timezone as dt_timezone

# CEF is a fixed-arity pipe-delimited header. The version is the literal 0 in
# every CEF 0 implementation; the rest identify the producing product.
CEF_VERSION = 0
CEF_VENDOR = 'NetForensiq'
CEF_PRODUCT = 'PacketForensics'

# CEF severity is 0-10. Our four levels are spread across that range rather
# than compressed into the top of it, so a consumer's own thresholds behave.
CEF_SEVERITY = {'low': 3, 'medium': 5, 'high': 8, 'critical': 10}

# ECS event.severity is a producer-defined number; 0-100 is the common
# convention rather than a requirement of the schema.
ECS_SEVERITY = {'low': 21, 'medium': 47, 'high': 73, 'critical': 99}

# RFC 5424 numeric severities. local0 (16) is the conventional facility for an
# application; the priority value is facility * 8 + severity.
SYSLOG_FACILITY = 16
SYSLOG_SEVERITY = {'low': 6, 'medium': 5, 'high': 4, 'critical': 2}

# ECS categorisation for a detection-engine finding about network traffic.
ECS_CATEGORIES = ['intrusion_detection', 'network']

# The schema version these documents claim to follow. ECS requires it in every
# document — a consumer uses it to decide how to read every other field, and
# Elastic's own tooling treats a document without it as un-normalised.
#
# Pinned rather than tracked automatically: it states the version we actually
# built and tested against. Raising it is a decision to re-check the field
# names, not a version bump.
ECS_VERSION = '8.11.0'

# `event.type` narrows `event.category`. Every finding used to be typed
# `info`, which is ECS's "nothing more specific applies" — true of none of
# them. The values below are from ECS's allowed set for the categories above;
# nothing is invented, and a rule with no better answer keeps `info` rather
# than being forced into a type that reads as a stronger claim than the rule
# makes.
ECS_EVENT_TYPES = {
    'RECON_PORT_SCAN': ['connection', 'start'],
    'C2_BEACON_PERIODIC': ['connection', 'protocol'],
    'C2_BEACON_KEEPALIVE': ['connection', 'protocol'],
    'DNS_TUNNEL_LONG_LABEL': ['protocol'],
    'DNS_TUNNEL_SUBDOMAIN_VOLUME': ['protocol'],
    'ICMP_TUNNEL_OVERSIZED': ['protocol'],
    'COVERT_CHANNEL_UNKNOWN_PORT': ['connection', 'protocol'],
    'EXFIL_VOLUME_ASYMMETRY': ['connection'],
    # A blocklist hit is ECS's `indicator` — the event exists because an
    # indicator matched, which is precisely what that value is for.
    'IOC_FEED_MATCH': ['indicator'],
}


def _ecs_event_types(detection):
    """`event.type` for one finding, defaulting to ECS's own catch-all."""
    return ECS_EVENT_TYPES.get(detection.rule_id, ['info'])


def _escape_cef_header(value):
    """
    Escape a CEF *header* field.

    Getting this wrong shifts every later field by one, and the consumer reads
    a severity as a signature id without complaining — a silent corruption
    rather than a parse error, which is the worse of the two.
    """
    return str(value).replace('\\', '\\\\').replace('|', '\\|')


def _escape_cef_extension(value):
    """In extensions the equals sign delimits too, and a newline ends the record."""
    return (
        str(value).replace('\\', '\\\\').replace('=', '\\=')
        .replace('\n', ' ').replace('\r', ' ')
    )


def _endpoints(detection):
    """The two ends of the conversation, or {} when the finding has no flow."""
    flow = detection.flow
    if not flow:
        return {}
    initiator = flow.initiator_ip or flow.src_ip
    peer = flow.dst_ip if initiator == flow.src_ip else flow.src_ip
    return {
        'source_ip': initiator,
        'destination_ip': peer,
        'source_port': flow.initiator_port or flow.src_port,
        'destination_port': flow.dst_port,
        'transport': (flow.protocol or '').lower(),
        'protocol': (flow.app_protocol or '').lower(),
        'bytes': (flow.bytes_sent or 0) + (flow.bytes_received or 0),
        # Kept apart as well as summed. CEF's `in` and `out` are *directional*
        # — inbound and outbound octets — and we were putting the combined
        # total in `in`, which overstates inbound traffic by exactly the
        # outbound volume. On an exfiltration finding, the field a SOC would
        # look at to see data leaving was reporting the wrong number in the
        # wrong direction.
        'bytes_from_source': flow.bytes_sent or 0,
        'bytes_to_source': flow.bytes_received or 0,
        'first_seen': flow.first_seen,
    }


def _product_version():
    from netforensiq_backend.version import get_version
    return get_version()


def to_ecs(detection, observer=None, beaconing_hosts=frozenset()):
    """One finding as an Elastic Common Schema document."""
    ends = _endpoints(detection)
    evidence = getattr(detection.session, 'evidence', None)

    detected_at = detection.created_at.astimezone(dt_timezone.utc)
    # `@timestamp` is when the *activity* happened; `event.created` is when we
    # noticed. ECS is explicit about the distinction and both were previously
    # set to the analysis time, so a SOC timeline plotted a week of findings as
    # a single spike at the moment the PCAP was imported — which is the one
    # thing a timeline must not do. Falls back to the detection time only when
    # the finding has no flow behind it to date.
    happened_at = ends.get('first_seen')
    activity = (happened_at.astimezone(dt_timezone.utc)
                if happened_at else detected_at)

    document = {
        '@timestamp': activity.isoformat(),
        # Required by ECS in every document: "must exist in all events".
        # Consumers use it to decide how to interpret every other field, so an
        # omitted version is not a cosmetic gap — Elastic's own tooling treats
        # documents without it as un-normalised.
        'ecs': {'version': ECS_VERSION},
        'event': {
            'kind': 'alert',
            'category': ECS_CATEGORIES,
            'created': detected_at.isoformat(),
            'type': _ecs_event_types(detection),
            'severity': ECS_SEVERITY.get(detection.severity, 0),
            'provider': CEF_PRODUCT,
            'module': 'netforensiq',
            'dataset': 'netforensiq.detection',
            'id': str(detection.id),
            # Whether a rule or the unsupervised model produced this. A SOC
            # tuning alert fatigue must be able to separate them, and omitting
            # it would be the same overclaim the interface refuses to make.
            'action': detection.method,
            'reason': detection.title,
        },
        'rule': {
            'id': detection.rule_id,
            'name': detection.title,
            'category': detection.category,
            'description': detection.rationale or '',
        },
        'observer': {
            'vendor': CEF_VENDOR,
            'product': CEF_PRODUCT,
            'type': 'forensics',
            'hostname': observer or socket.gethostname(),
        },
        'message': detection.title,
    }

    # ECS threat.* — the fields a SOC pivots on. Arrays because ATT&CK
    # genuinely maps some behaviour to more than one technique, and because
    # ECS defines these as arrays for exactly that reason. Omitted entirely
    # rather than sent empty for the two rules that honestly do not map.
    from .attack_mapping import classify
    techniques = classify(detection, beaconing_hosts)
    if techniques:
        # ECS keeps sub-techniques in their own object. A dotted identifier
        # such as T1071.004 belongs in `threat.technique.subtechnique.id` with
        # its parent T1071 in `threat.technique.id` — put whole into the
        # technique field, a dashboard grouping by technique buckets T1071 and
        # T1071.004 as two unrelated strings and the parent's count is wrong.
        parents, subs = [], []
        for technique in techniques:
            if '.' in technique['id']:
                subs.append(technique)
                parent_id = technique['id'].split('.', 1)[0]
                if parent_id not in [p['id'] for p in parents]:
                    parents.append({
                        'id': parent_id,
                        'name': technique['name'].split(':', 1)[0].strip(),
                        'url': f'https://attack.mitre.org/techniques/{parent_id}/',
                    })
            elif technique['id'] not in [p['id'] for p in parents]:
                parents.append(technique)

        threat = {
            'framework': 'MITRE ATT&CK',
            'technique': {
                'id': [t['id'] for t in parents],
                'name': [t['name'] for t in parents],
                'reference': [t['url'] for t in parents],
            },
            'tactic': {
                'id': sorted({t['tactic_id'] for t in techniques}),
                'name': sorted({t['tactic'] for t in techniques}),
                # The tactic URL was the one reference ECS defines that we did
                # not send, and it is built the same way as the technique's.
                'reference': [
                    f'https://attack.mitre.org/tactics/{tid}/'
                    for tid in sorted({t['tactic_id'] for t in techniques})
                ],
            },
        }
        if subs:
            threat['technique']['subtechnique'] = {
                'id': [t['id'] for t in subs],
                'name': [t['name'] for t in subs],
                'reference': [t['url'] for t in subs],
            }
        document['threat'] = threat

    if ends:
        document['source'] = {'ip': ends['source_ip'], 'port': ends['source_port']}
        document['destination'] = {
            'ip': ends['destination_ip'], 'port': ends['destination_port'],
        }
        document['network'] = {
            'transport': ends['transport'],
            'protocol': ends['protocol'],
            'bytes': ends['bytes'],
        }

    # `related.ip` is every address the event mentions, in one field. It exists
    # so "show me everything that touched this address" is a single query
    # rather than one per field name, and that is the first query a SOC analyst
    # runs. Cheap to fill and useless to omit.
    addresses = [a for a in (
        document.get('source', {}).get('ip'),
        document.get('destination', {}).get('ip'),
        detection.subject_ip,
    ) if a]
    if addresses:
        document['related'] = {'ip': sorted(set(addresses))}

    if evidence:
        # The exhibit number, so an analyst who sees this can ask for the
        # record. Not the case reference, the FIR, or the seizure details.
        document['file'] = {'hash': {'sha256': evidence.sha256_hash}}
        document['netforensiq'] = {'exhibit_number': evidence.exhibit_number}

    return document


def to_cef(detection, observer=None, beaconing_hosts=frozenset()):
    """One finding as a CEF 0 record."""
    ends = _endpoints(detection)

    fields = [
        CEF_VENDOR,
        CEF_PRODUCT,
        _product_version(),
        detection.rule_id,
        detection.title,
        CEF_SEVERITY.get(detection.severity, 0),
    ]
    header = f'CEF:{CEF_VERSION}|' + '|'.join(
        _escape_cef_header(part) for part in fields
    )

    extensions = {
        'rt': int(detection.created_at.timestamp() * 1000),
        'cat': detection.category,
        'act': detection.method,
        'msg': detection.rationale or detection.title,
        'externalId': detection.id,
        # cs1/cs2 are CEF's custom string slots. They mean nothing without
        # their Label pair — a consumer shows the label to the analyst.
        'cs1': detection.severity,
        'cs1Label': 'netforensiqSeverity',
        'cs2': getattr(getattr(detection.session, 'evidence', None),
                       'exhibit_number', '') or '',
        'cs2Label': 'exhibitNumber',
    }

    # CEF has no threat-intelligence fields, so the techniques go in a custom
    # slot. Space-separated because CEF extensions hold a single value and a
    # finding can carry two.
    from .attack_mapping import classify
    techniques = classify(detection, beaconing_hosts)
    if techniques:
        extensions['cs3'] = ' '.join(t['id'] for t in techniques)
        extensions['cs3Label'] = 'mitreAttackTechnique'
    if ends:
        extensions.update({
            'src': ends['source_ip'], 'spt': ends['source_port'],
            'dst': ends['destination_ip'], 'dpt': ends['destination_port'],
            'proto': ends['transport'].upper(),
            # Directional, as the CEF dictionary defines them: `in` is inbound
            # octets and `out` is outbound. Both were previously collapsed into
            # `in` as a combined total, which reported the wrong number in the
            # wrong direction on exactly the findings — exfiltration — where
            # direction is the whole point.
            'in': ends['bytes_to_source'],
            'out': ends['bytes_from_source'],
        })

    body = ' '.join(
        f'{key}={_escape_cef_extension(value)}'
        for key, value in extensions.items() if value not in (None, '')
    )
    return f'{header}|{body}'


def to_syslog(detection, observer=None, beaconing_hosts=frozenset()):
    """One finding as RFC 5424, carrying the CEF record as its message."""
    priority = SYSLOG_FACILITY * 8 + SYSLOG_SEVERITY.get(detection.severity, 6)
    stamp = detection.created_at.astimezone(dt_timezone.utc).isoformat()
    host = observer or socket.gethostname()
    # VERSION is the literal 1; '-' is RFC 5424's NILVALUE for an absent field.
    return (
        f'<{priority}>1 {stamp} {host} netforensiq - {detection.rule_id} - '
        f'{to_cef(detection, observer, beaconing_hosts)}'
    )


FORMATS = {
    'ecs': ('application/x-ndjson',
            lambda d, o, h: json.dumps(to_ecs(d, o, h))),
    'cef': ('text/plain; charset=utf-8', to_cef),
    'syslog': ('text/plain; charset=utf-8', to_syslog),
}


def export(detections, fmt='ecs', observer=None, beaconing_hosts=None):
    """
    Render findings, one record per line.

    `beaconing_hosts` is passed in rather than derived here: it decides T1041
    against T1048 for exfiltration findings, and it is one query over the
    session, not a property of any single row. Computing it inside the loop
    would run that query once per finding; computing it by peeking at the
    first record would silently be wrong for a multi-session export.
    Omitted, the mapping falls back to the less specific technique rather than
    guessing.

    Newline-delimited rather than a JSON array: every log shipper reads a line
    at a time, and an array has to be held whole in memory before it parses.
    A generator, so a session with thousands of findings streams rather than
    being assembled.
    """
    if fmt not in FORMATS:
        raise ValueError(
            f'Unknown format: {fmt}. Choose from {", ".join(sorted(FORMATS))}.'
        )
    _content_type, render = FORMATS[fmt]
    hosts = frozenset(beaconing_hosts or ())

    for detection in detections:
        yield render(detection, observer, hosts) + '\n'
