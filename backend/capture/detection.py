"""
Detection engine — deterministic rules first, model second.

Every rule records the value it observed, the threshold it compared against,
and where that threshold came from. An investigator asked "why is this
flagged?" reads the answer off the record; nothing here depends on a model's
opinion. Thresholds are cited in THRESHOLDS below and in
research/SPEC_02_DETECTION_ALGORITHMS.md.

Where no citable value exists the constant is tagged OUR_HEURISTIC and that
tag is carried into the stored evidence, so an overclaim is impossible to make
by accident.
"""

import ipaddress
import math
import statistics
from collections import defaultdict

from django.conf import settings
from django.db import transaction

from .models import Detection, Flow


# Snort and Suricata both define $HOME_NET — the address space you are
# defending — and write egress rules against it. Without that notion, a rule
# meant to catch "an internal host reaching out to something odd" also fires on
# every scanner on the internet reaching in, which on an internet-facing
# capture is thousands of alerts. Default is the RFC 1918 private ranges, as
# in Snort's shipped configuration; override with HOME_NET in settings.
DEFAULT_HOME_NET = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', 'fd00::/8')
SRC_HOME_NET = ('Snort/Suricata $HOME_NET convention; default RFC 1918 private '
                'address space')


def _home_networks():
    nets = getattr(settings, 'HOME_NET', None) or DEFAULT_HOME_NET
    parsed = []
    for entry in nets:
        try:
            parsed.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            continue
    return parsed


def is_internal(ip):
    """True if the address falls inside the monitored network."""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in _home_networks())


def flow_direction(flow):
    """
    (initiator_ip, peer_ip, service_port) for a flow.

    The service port is the *responder's* port — the thing being connected to.
    Reading dst_port blindly is wrong whenever the capture recorded the
    responder as the source, which is common for inbound connections, and
    yields the client's ephemeral port instead of the service.
    """
    initiator = flow.initiator_ip or flow.src_ip
    if initiator == flow.src_ip:
        return initiator, flow.dst_ip, flow.dst_port
    return initiator, flow.src_ip, flow.src_port


SRC_RITA = 'RITA (Active Countermeasures) pkg/beacon/analyzer.go + etc/rita.yaml'
SRC_BINWALK = 'binwalk shipped entropy defaults (7.6 rising / 6.8 falling, 1024-byte blocks)'
SRC_SIMPLE_SCAN = 'ncsa/bro-simple-scan current defaults (25 remote host+port combos / 15 min)'
SRC_SNORT3 = 'Snort 3 port_scan inspector defaults (Cisco Talos)'
SRC_FARNHAM = 'Farnham & Atlasis (2013), DNS tunnelling label length — secondary source only'
# Stronger than the Farnham secondary citation: the tunnel tools themselves.
# RFC 1035 §2.3.4 caps a label at 63 octets and a whole name at 255. Tunnels
# have to fill that budget to move data, so they sit just under the ceiling —
# dnscat2 hardcodes MAX_FIELD_LENGTH 62, one octet below the maximum, and
# iodine's -M defaults to the full 255-octet hostname. Ordinary hostnames are
# nowhere near it, which is what makes label length discriminating at all.
SRC_DNS_TUNNEL_TOOLS = (
    'RFC 1035 §2.3.4 (label ≤63, name ≤255 octets); dnscat2 '
    'client/tunnel_drivers/driver_dns.c MAX_FIELD_LENGTH=62 (verified against '
    'source); iodine iodine(8) -M max upstream hostname, default 255'
)
SRC_PING = 'ping(8) default payload: 56 bytes Linux / 32 bytes Windows'
OUR_HEURISTIC = '[OUR HEURISTIC] no citable source; see SPEC_02 heuristics table'
SRC_ZEEK_IDLE = ('Zeek scripts/base/init-bare.zeek — tcp_inactivity_timeout 5 min, '
                 'udp_inactivity_timeout 1 min (verified against source, not docs)')


# Ports where an unrecognised, long-lived encrypted channel is unremarkable.
# Sourced from the IANA Service Name and Transport Protocol Port Number
# Registry (system/well-known range) restricted to services that legitimately
# carry sustained sessions. Membership is deliberately generous: a false
# negative here is better than flagging routine traffic.
WELL_KNOWN_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 989,
    990, 993, 995, 1194, 1433, 1521, 1723, 3128, 3306, 3389, 5060, 5061, 5222,
    5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
})
SRC_IANA = ('IANA Service Name and Transport Protocol Port Number Registry '
            '— well-known service ports')


THRESHOLDS = {
    # ── beaconing ──
    'beacon_min_connections': (23, SRC_RITA + ' — DefaultConnectionThresh, counted as '
                                              'CONNECTIONS between a host pair (not packets '
                                              'within one connection)'),
    'beacon_alert_score': (0.80, 'Practitioner guidance (Black Hills InfoSec; Cyb3r-Monk KQL '
                                 'uses 0.85). RITA itself ranks rather than hard-cuts. '
                                 '[OUR HEURISTIC, informed by practitioner sources]'),
    'beacon_skew_iqr_floor': (10, SRC_RITA + ' — Bowley skew suppressed when Q3-Q1 < 10'),
    'beacon_ds_smallness_norm': (65535, SRC_RITA + ' — data-size smallness normaliser'),

    # ── DNS tunnelling ──
    'dns_label_length': (52, f'{SRC_DNS_TUNNEL_TOOLS}. Set below the 62–63 octet '
                             f'ceiling the tools actually emit, so a tunnel that '
                             f'pads slightly short is still caught. Corroborated by '
                             f'{SRC_FARNHAM}'),
    'dns_label_entropy': (3.5, OUR_HEURISTIC + ' — grounded in Base32/64 alphabet-entropy ceiling'),
    'dns_entropy_min_label_len': (20, OUR_HEURISTIC),
    'dns_unique_subdomains': (50, OUR_HEURISTIC + ' — scaled down from resolver-scale figures'),

    # ── port scan ──
    'scan_unique_ports': (25, f'{SRC_SIMPLE_SCAN}; matches Snort 3 port_scan ports=25 ({SRC_SNORT3})'),
    'scan_window_seconds': (900, SRC_SIMPLE_SCAN + ' — 15-minute rolling window'),

    # ── exfiltration ──
    'exfil_entropy_high': (7.6, SRC_BINWALK),
    'exfil_entropy_falling': (6.8, SRC_BINWALK),
    'exfil_ratio': (10.0, OUR_HEURISTIC + ' — outbound:inbound, loosely informed by practitioner guidance'),
    # An absolute byte floor cannot work across capture scales: 50 MB is
    # reasonable on a day of enterprise traffic and absurd on a 40-minute
    # capture. The volume test is therefore relative to the capture itself
    # (95th percentile of outbound bytes), with a small absolute floor purely
    # to stop trivial flows qualifying. Both values are reported in evidence.
    'exfil_volume_percentile': (95, OUR_HEURISTIC + ' — flow must be in the top 5% of '
                                                    'outbound volume for its own capture'),
    'exfil_absolute_floor': (100 * 1024, OUR_HEURISTIC + ' — 100 KB, suppresses trivial flows only'),

    # ── ICMP tunnelling ──
    'icmp_payload_bytes': (100, OUR_HEURISTIC + f' — grounded in {SRC_PING}'),
    # A tunnel is a sustained exchange. A single oversized echo reply is an
    # ordinary answer to a scanner that sent a large ping payload — echo
    # replies mirror the request. On a real week-long capture, 238 of 461
    # remaining findings were single-packet flows.
    'icmp_min_packets': (10, OUR_HEURISTIC + ' — a covert channel carries a stream; '
                                             'one-off oversized echoes are ping replies'),

    # ── keepalive beaconing inside one persistent connection ──
    # RITA's model assumes a beacon opens a NEW connection each time. Remote
    # access trojans frequently hold one TCP connection open and beacon inside
    # it, which RITA's connection counting cannot see. This is our own rule for
    # that case, scored with RITA's MADM formula so the alert threshold means
    # the same thing in both.
    'keepalive_min_intervals': (20, OUR_HEURISTIC + ' — below ~20 samples the MAD estimate '
                                                    'is too unstable to act on'),

    # ── flow aggregation (not a detection threshold, but it shapes every one
    #    of them: it decides where one conversation ends and the next begins) ──
    'flow_idle_timeout_tcp': (300, SRC_ZEEK_IDLE),
    'flow_idle_timeout_udp': (60, SRC_ZEEK_IDLE),

    # ── unrecognised long-lived channel ──
    'unknown_channel_min_duration': (60, OUR_HEURISTIC + ' — long enough to be a session '
                                                         'rather than a probe or a failed '
                                                         'connection attempt'),
    'unknown_channel_ports': ('not in IANA well-known service list', SRC_IANA),
}


def _t(name):
    """Threshold value only."""
    return THRESHOLDS[name][0]


def _cite(name):
    """(value, source) for embedding in a Detection's evidence."""
    value, source = THRESHOLDS[name]
    return {'threshold': value, 'source': source}


# ──────────────────────────────────────────────────────────────────────────
# RITA beacon scoring
# ──────────────────────────────────────────────────────────────────────────

def _percentile(sorted_values, p):
    """
    RITA's percentile: round(p * (n-1)), 0-indexed, no interpolation.

    Matching this exactly matters — at low sample counts the choice of
    percentile method materially changes skew and MADM.
    """
    if not sorted_values:
        return 0.0
    idx = int(round(p * (len(sorted_values) - 1)))
    return sorted_values[max(0, min(idx, len(sorted_values) - 1))]


def bowley_skewness(sorted_values):
    """
    (Q1 + Q3 - 2*Q2) / (Q3 - Q1).

    Returns 0 when the distribution is too narrow or degenerate to score,
    mirroring RITA's guard conditions rather than emitting a wild value.
    """
    if len(sorted_values) < 3:
        return 0.0
    q1 = _percentile(sorted_values, 0.25)
    q2 = _percentile(sorted_values, 0.50)
    q3 = _percentile(sorted_values, 0.75)

    if (q3 - q1) < _t('beacon_skew_iqr_floor'):
        return 0.0
    if q2 == q1 or q2 == q3:
        return 0.0
    return (q1 + q3 - 2 * q2) / (q3 - q1)


def madm(values, centre=None):
    """Median absolute deviation about the median."""
    if not values:
        return 0.0
    med = centre if centre is not None else statistics.median(values)
    return statistics.median([abs(v - med) for v in values])


def _ceil3(x):
    return math.ceil(x * 1000) / 1000


def beacon_subscores(intervals, sizes):
    """
    RITA's timestamp and data-size subscores.

    Implements the current analyzer.go behaviour (MADM divided by the median
    interval), not the stale README formula which uses a fixed divisor of 30.
    """
    result = {'ts_score': 0.0, 'ds_score': 0.0}

    nonzero = sorted(i for i in intervals if i > 0)
    if len(nonzero) >= 2:
        ts_skew_score = 1 - abs(bowley_skewness(nonzero))
        ts_mid = statistics.median(nonzero)
        ts_madm = madm(nonzero, ts_mid)
        ts_madm_score = max(0.0, 1 - (ts_madm / ts_mid)) if ts_mid > 0 else 0.0
        result['ts_score'] = _ceil3((ts_skew_score + ts_madm_score) / 2)
        result['ts_skew_score'] = round(ts_skew_score, 4)
        result['ts_madm_score'] = round(ts_madm_score, 4)
        result['interval_median'] = round(ts_mid, 4)

    sizes = sorted(s for s in sizes if s > 0)
    if len(sizes) >= 2:
        ds_skew_score = 1 - abs(bowley_skewness(sizes))
        ds_mid = statistics.median(sizes)
        ds_madm_score = max(0.0, 1 - (madm(sizes, ds_mid) / ds_mid)) if ds_mid > 0 else 0.0
        try:
            ds_mode = statistics.mode(sizes)
        except statistics.StatisticsError:
            ds_mode = ds_mid
        ds_smallness = max(0.0, 1 - (ds_mode / _t('beacon_ds_smallness_norm')))
        result['ds_score'] = _ceil3((ds_skew_score + ds_madm_score + ds_smallness) / 3)
        result['ds_skew_score'] = round(ds_skew_score, 4)
        result['ds_madm_score'] = round(ds_madm_score, 4)
        result['ds_smallness_score'] = round(ds_smallness, 4)

    return result


def score_connection_beacon(intervals, sizes):
    """
    Composite RITA score over inter-connection intervals and payload sizes.

    RITA weights timestamp and data-size subscores equally. Its duration and
    histogram subscores need 6 h and 11 h of activity respectively, so they are
    omitted on shorter captures and the score is renormalised over what could
    actually be computed — recorded in the evidence so the omission is visible
    rather than silently depressing every short capture's score.
    """
    subscores = beacon_subscores(intervals, sizes)

    components = {}
    if 'ts_skew_score' in subscores:
        components['ts'] = subscores['ts_score']
    if 'ds_skew_score' in subscores:
        components['ds'] = subscores['ds_score']
    if not components:
        return 0.0, {'omitted_subscores': ['ts and ds (insufficient samples)']}

    score = round(sum(components.values()) / len(components), 4)
    detail: dict = dict(subscores)
    detail['components'] = {k: round(v, 4) for k, v in components.items()}
    detail['omitted_subscores'] = ['duration (needs >=6h)', 'histogram (needs >=11h)']
    detail['renormalised'] = True
    detail['interval_median_s'] = subscores.get('interval_median', 0.0)
    return score, detail


def score_beacon(flow):
    """
    Score one flow for beaconing.

    RITA weights four subscores at 0.25 each, but its duration and histogram
    subscores need 6 h and 11 h of activity respectively. Captures shorter
    than that cannot produce them, so rather than scoring those components
    zero — which would silently penalise every short capture — we renormalise
    over the subscores we could actually compute and record that we did so.
    """
    ts_mid = flow.interval_median
    ts_madm_score = max(0.0, 1 - (flow.interval_mad / ts_mid)) if ts_mid > 0 else 0.0
    # Dispersion already encodes MAD/median; skew is unavailable from summary
    # stats alone, so the TS score here uses the dispersion component only and
    # says so in the evidence.
    ts_score = _ceil3(ts_madm_score)

    duration_hours = (flow.duration_seconds or 0) / 3600.0
    components = {'ts': ts_score}
    omitted = []
    if duration_hours < 6:
        omitted.append('duration (needs >=6h of activity)')
    if duration_hours < 11:
        omitted.append('histogram (needs >=11h of activity)')

    score = sum(components.values()) / len(components)
    return round(score, 4), {
        'components': {k: round(v, 4) for k, v in components.items()},
        'omitted_subscores': omitted,
        'renormalised': bool(omitted),
        'interval_median_s': ts_mid,
        'interval_mad_s': flow.interval_mad,
        'dispersion': flow.interval_dispersion,
        'connection_count': flow.packets_sent,
    }


# ──────────────────────────────────────────────────────────────────────────
# Rules
# ──────────────────────────────────────────────────────────────────────────

def rule_beaconing(session):
    """
    RITA's beacon model: repeated CONNECTIONS between a host pair.

    This counts connections between (initiator, peer), not packets inside one
    connection. The distinction is the whole algorithm — an earlier version of
    this rule used packets-within-a-flow as a stand-in for RITA's connection
    count, which happens to agree on synthetic traffic that opens one
    connection per beacon, and is meaningless on a real capture where a single
    TCP session carries thousands of packets. Real malware traffic exposed it.

    Because we hold each connection's start time, the intervals here are true
    inter-connection gaps, so the full Bowley-skew + MADM score can be computed
    rather than the dispersion component alone.
    """
    findings = []
    min_conns = _t('beacon_min_connections')
    alert = _t('beacon_alert_score')

    pairs = defaultdict(list)
    for flow in session.flows.all():
        initiator = flow.initiator_ip or flow.src_ip
        peer = flow.dst_ip if initiator == flow.src_ip else flow.src_ip
        pairs[(initiator, peer)].append(flow)

    for (initiator, peer), flows in pairs.items():
        if len(flows) < min_conns:
            continue
        # C2 beaconing is by definition an internal host calling *out* to a
        # controller. An external host connecting in repeatedly is a scanner,
        # and RECON_PORT_SCAN already covers it. On a real internet-facing
        # capture every one of 155 "beacons" was inbound scanning.
        if not is_internal(initiator) or is_internal(peer):
            continue

        flows.sort(key=lambda f: f.first_seen)
        starts = [f.first_seen.timestamp() for f in flows]
        intervals = [b - a for a, b in zip(starts, starts[1:])]
        if len(intervals) < 2:
            continue

        sizes = [(f.bytes_sent or 0) for f in flows]
        score, detail = score_connection_beacon(intervals, sizes)
        if score < alert:
            continue

        period = detail.get('interval_median_s', 0.0)
        ports = sorted({f.dst_port for f in flows if f.dst_port})
        findings.append(Detection(
            session=session, flow=flows[0],
            rule_id='C2_BEACON_PERIODIC',
            title=f'Periodic callback to {peer} every ~{period:.0f}s',
            category='command_and_control',
            severity=Detection.Severity.HIGH if score >= 0.9 else Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=min(score, 1.0),
            subject_ip=initiator,
            rationale=(
                f'{initiator} opened {len(flows)} separate connections to {peer} '
                f'(port(s) {", ".join(map(str, ports)) or "n/a"}) at a median interval of '
                f'{period:.2f}s. Automated callbacks cluster tightly around a target '
                f'period; human-driven traffic does not. Scored {score:.3f} against an '
                f'alert threshold of {alert}. Note: legitimate polling software (NTP, '
                f'monitoring agents, update checkers) also produces regular intervals and '
                f'must be ruled out by an analyst.'
            ),
            evidence={
                'observed_score': score,
                'connection_count': len(flows),
                **_cite('beacon_alert_score'),
                'min_connections': _cite('beacon_min_connections'),
                'algorithm': SRC_RITA,
                **detail,
            },
        ))
    return findings


def rule_beaconing_keepalive(session):
    """
    Beaconing *inside* one persistent connection.

    A remote access trojan often holds a single TCP session open and sends
    periodic keepalives down it. RITA never sees this — it counts connections,
    and there is only ever one. Scored with RITA's MADM formula so a score here
    means what a score there means, but the rule itself is ours.
    """
    findings = []
    alert = _t('beacon_alert_score')
    min_intervals = _t('keepalive_min_intervals')

    for flow in session.flows.filter(interval_count__gte=min_intervals):
        median = flow.interval_median or 0.0
        if median <= 0:
            continue

        initiator, peer, _ = flow_direction(flow)
        if not is_internal(initiator) or is_internal(peer):
            continue  # egress only — see rule_beaconing

        # RITA's MADM subscore, applied to intra-connection send intervals.
        score = _ceil3(max(0.0, 1 - (flow.interval_mad / median)))
        if score < alert:
            continue

        peer = flow.dst_ip if (flow.initiator_ip or flow.src_ip) == flow.src_ip else flow.src_ip
        findings.append(Detection(
            session=session, flow=flow,
            rule_id='C2_BEACON_KEEPALIVE',
            title=f'Regular keepalive to {peer}:{flow.dst_port} every ~{median:.1f}s',
            category='command_and_control',
            severity=Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=min(score, 1.0),
            subject_ip=flow.initiator_ip or flow.src_ip,
            rationale=(
                f'A single connection to {peer}:{flow.dst_port} stayed open for '
                f'{flow.duration_seconds:.0f}s and sent {flow.interval_count + 1} packets at a '
                f'median interval of {median:.2f}s (MAD {flow.interval_mad:.2f}s, '
                f'dispersion {flow.interval_dispersion:.3f}). Periodicity this tight inside '
                f'one long-lived session is characteristic of a keepalive, which may be a '
                f'remote access trojan holding a channel open — or an entirely ordinary '
                f'application heartbeat. This rule is ours, not RITA\'s: RITA counts '
                f'connections and would see only one here.'
            ),
            evidence={
                'observed_score': score,
                'scoring_formula': 'RITA MADM subscore (1 - MAD/median) applied to '
                                   'intra-connection send intervals',
                **_cite('beacon_alert_score'),
                'min_intervals': _cite('keepalive_min_intervals'),
                'interval_median_s': median,
                'interval_mad_s': flow.interval_mad,
                'dispersion': flow.interval_dispersion,
                'sample_count': flow.interval_count,
                'rule_provenance': OUR_HEURISTIC,
            },
        ))
    return findings


def rule_unknown_long_channel(session):
    """
    A sustained conversation on a non-standard port that we cannot identify.

    Neither a recognised application protocol nor a TLS SNI, held open for
    minutes, to a port outside the well-known range. That combination is not
    proof of anything — but it is the shape of a covert channel, and it is
    cheap for an analyst to rule out.
    """
    findings = []
    min_duration = _t('unknown_channel_min_duration')

    for flow in session.flows.filter(
        duration_seconds__gte=min_duration, protocol='TCP',
    ):
        initiator, peer, service_port = flow_direction(flow)

        # Egress only. An external host connecting *in* to an odd port is a
        # scanner, not a covert channel, and on an internet-facing capture
        # there are thousands of them.
        if not is_internal(initiator) or is_internal(peer):
            continue
        if service_port in WELL_KNOWN_PORTS:
            continue
        if flow.app_protocol or flow.tls_sni:
            continue
        if not flow.bytes_sent or not flow.bytes_received:
            continue  # one-directional: a stalled connection, not a channel

        findings.append(Detection(
            session=session, flow=flow,
            rule_id='COVERT_CHANNEL_UNKNOWN_PORT',
            title=f'Unidentified {flow.duration_seconds:.0f}s channel to '
                  f'{peer}:{service_port}',
            category='command_and_control',
            severity=Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=0.6,
            subject_ip=initiator,
            rationale=(
                f'{initiator} held a connection to '
                f'{peer}:{service_port} open for {flow.duration_seconds:.0f}s, '
                f'exchanging {flow.bytes_sent:,} bytes out and {flow.bytes_received:,} in. '
                f'The port is outside the IANA well-known service range, no application '
                f'protocol was identified, and no TLS SNI was presented — so there is '
                f'nothing declaring what this traffic is. Ordinary encrypted traffic on 443 '
                f'announces its destination hostname in the SNI; this does not. Benign '
                f'explanations exist (peer-to-peer software, games, bespoke line-of-business '
                f'applications) and an analyst should rule them out.'
            ),
            evidence={
                'duration_seconds': flow.duration_seconds,
                'service_port': service_port,
                'initiator': initiator,
                'peer': peer,
                'direction': 'egress (initiator inside HOME_NET)',
                'home_net_source': SRC_HOME_NET,
                'app_protocol': flow.app_protocol or None,
                'tls_sni': flow.tls_sni or None,
                'payload_entropy': flow.payload_entropy,
                'bytes_sent': flow.bytes_sent,
                'bytes_received': flow.bytes_received,
                **_cite('unknown_channel_min_duration'),
                'port_list_source': _cite('unknown_channel_ports'),
                'rule_provenance': OUR_HEURISTIC,
            },
        ))
    return findings


def rule_dns_tunnelling(session):
    findings = []
    label_len = _t('dns_label_length')
    uniq_thresh = _t('dns_unique_subdomains')

    # Long, high-entropy labels.
    # Aggregated per (source, parent domain) rather than raised per query: one
    # tunnel produces hundreds of oversized queries, and an analyst facing 500
    # near-identical alerts stops reading them. One finding, with the evidence
    # rolled up, is both more usable and more honest about what was observed.
    long_label = defaultdict(lambda: {
        'count': 0, 'max_len': 0, 'max_entropy': 0.0,
        'samples': [], 'flow': None,
    })

    for record in session.dns_records.filter(subdomain_length__gte=label_len):
        labels = record.query_name.split('.')
        parent = '.'.join(labels[-2:]) if len(labels) >= 2 else record.query_name
        entry = long_label[(record.src_ip, parent)]
        entry['count'] += 1
        entry['max_len'] = max(entry['max_len'], record.subdomain_length)
        entry['max_entropy'] = max(entry['max_entropy'], record.query_entropy)
        entry['flow'] = entry['flow'] or record.flow
        if len(entry['samples']) < 3:
            entry['samples'].append(record.query_name[:120])

    for (src_ip, parent), entry in long_label.items():
        findings.append(Detection(
            session=session, flow=entry['flow'],
            rule_id='DNS_TUNNEL_LONG_LABEL',
            title=f'{entry["count"]} oversized DNS labels under {parent} from {src_ip}',
            category='exfiltration',
            severity=Detection.Severity.HIGH,
            method=Detection.Method.RULE,
            confidence=min(entry['max_len'] / (label_len * 2), 1.0),
            subject_ip=src_ip,
            rationale=(
                f'{src_ip} issued {entry["count"]} queries under {parent} whose subdomain '
                f'labels reach {entry["max_len"]} characters (peak entropy '
                f'{entry["max_entropy"]:.2f} bits/char). DNS tunnelling encodes payload into '
                f'subdomain labels, producing long high-entropy names; ordinary domains do '
                f'not. Threshold {label_len} chars. Antivirus reputation lookups and some '
                f'CDNs legitimately use long encoded labels and must be ruled out.'
            ),
            evidence={
                'observed_query_count': entry['count'],
                'observed_max_label_length': entry['max_len'],
                'observed_max_entropy': entry['max_entropy'],
                'parent_domain': parent,
                'samples': entry['samples'],
                **_cite('dns_label_length'),
            },
        ))

    # Many distinct subdomains under one registrable domain
    per_parent = defaultdict(set)
    for src_ip, qname in session.dns_records.values_list('src_ip', 'query_name'):
        labels = qname.split('.')
        parent = '.'.join(labels[-2:]) if len(labels) >= 2 else qname
        per_parent[(src_ip, parent)].add(qname)

    for (src_ip, parent), names in per_parent.items():
        if len(names) <= uniq_thresh:
            continue
        findings.append(Detection(
            session=session, flow=None,
            rule_id='DNS_TUNNEL_SUBDOMAIN_VOLUME',
            title=f'{len(names)} unique subdomains of {parent} from {src_ip}',
            category='exfiltration',
            severity=Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=min(len(names) / (uniq_thresh * 4), 1.0),
            subject_ip=src_ip,
            rationale=(
                f'{src_ip} resolved {len(names)} distinct subdomains under {parent} '
                f'within this capture. Tunnelling clients generate a fresh subdomain per '
                f'data chunk, so unique-name volume under a single parent is a stronger '
                f'signal than any individual query. Threshold {uniq_thresh}. '
                f'CDNs and antivirus reputation lookups legitimately do this and must be '
                f'whitelisted before acting.'
            ),
            evidence={
                'observed_unique_subdomains': len(names),
                'parent_domain': parent,
                'sample': sorted(names)[:5],
                **_cite('dns_unique_subdomains'),
            },
        ))
    return findings


def rule_port_scan(session):
    findings = []
    port_thresh = _t('scan_unique_ports')

    per_pair = defaultdict(lambda: {'ports': set(), 'syn_only': 0, 'flows': 0})
    for flow in session.flows.filter(protocol='TCP'):
        # Must be the responder's port. Reading dst_port directly yields the
        # initiator's own ephemeral port whenever the capture recorded the
        # responder as the source, which would count 30 random high ports as a
        # "scan". This is the same defect that made the covert-channel rule
        # fire 5,853 times on a real capture.
        initiator, peer, service_port = flow_direction(flow)
        entry = per_pair[(initiator, peer)]
        entry['ports'].add(service_port)
        entry['flows'] += 1
        # A SYN with no ACK ever returned is the half-open scan signature.
        if 'S' in (flow.tcp_flags_seen or '') and 'A' not in (flow.tcp_flags_seen or ''):
            entry['syn_only'] += 1

    for (src, dst), entry in per_pair.items():
        if len(entry['ports']) < port_thresh:
            continue
        syn_ratio = entry['syn_only'] / entry['flows'] if entry['flows'] else 0
        findings.append(Detection(
            session=session, flow=None,
            rule_id='RECON_PORT_SCAN',
            title=f'Port scan: {src} probed {len(entry["ports"])} ports on {dst}',
            category='reconnaissance',
            severity=Detection.Severity.HIGH if syn_ratio > 0.8 else Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=min(len(entry['ports']) / (port_thresh * 4), 1.0),
            subject_ip=src,
            rationale=(
                f'{src} contacted {len(entry["ports"])} distinct TCP ports on {dst}. '
                f'{entry["syn_only"]} of {entry["flows"]} connections were SYN without a '
                f'completed handshake ({syn_ratio:.0%}), the half-open scan signature. '
                f'Threshold {port_thresh} distinct ports. Vulnerability scanners and '
                f'monitoring systems produce identical traffic and should be whitelisted.'
            ),
            evidence={
                'observed_unique_ports': len(entry['ports']),
                'syn_only_connections': entry['syn_only'],
                'total_connections': entry['flows'],
                'target': dst,
                **_cite('scan_unique_ports'),
            },
        ))
    return findings


def rule_exfiltration(session):
    findings = []
    entropy_high = _t('exfil_entropy_high')
    ratio_thresh = _t('exfil_ratio')
    floor = _t('exfil_absolute_floor')
    pct = _t('exfil_volume_percentile')

    outbound = sorted(
        v for v in session.flows.values_list('bytes_sent', flat=True) if v > 0
    )
    if not outbound:
        return findings

    idx = min(int(len(outbound) * pct / 100), len(outbound) - 1)
    volume_threshold = max(outbound[idx], floor)

    for flow in session.flows.all():
        total_out = flow.bytes_sent
        total_in = flow.bytes_received or 1
        ratio = total_out / total_in

        if total_out < volume_threshold or ratio < ratio_thresh:
            continue

        peer = flow.dst_ip if flow.initiator_ip == flow.src_ip else flow.src_ip
        high_entropy = flow.payload_entropy >= entropy_high
        # TLS is encrypted by design, so entropy alone means nothing there.
        # Saying so on the record is what keeps this defensible.
        tls_caveat = flow.app_protocol in ('TLS', 'HTTPS') or flow.dst_port == 443

        findings.append(Detection(
            session=session, flow=flow,
            rule_id='EXFIL_VOLUME_ASYMMETRY',
            title=f'{total_out / 1_048_576:.1f} MB outbound to {peer} ({ratio:.0f}:1)',
            category='exfiltration',
            severity=Detection.Severity.HIGH if high_entropy and not tls_caveat
            else Detection.Severity.MEDIUM,
            method=Detection.Method.RULE,
            confidence=min(ratio / (ratio_thresh * 5), 1.0),
            subject_ip=flow.initiator_ip,
            rationale=(
                f'{flow.initiator_ip} sent {total_out:,} bytes to {peer}:{flow.dst_port} '
                f'while receiving only {flow.bytes_received:,} — a {ratio:.0f}:1 outbound '
                f'asymmetry. Mean payload entropy {flow.payload_entropy:.2f} bits/byte '
                f'({"above" if high_entropy else "below"} the {entropy_high} threshold at '
                f'which content is indistinguishable from encrypted or compressed data). '
                + ('NOTE: this flow is TLS, where high entropy is expected and is NOT by '
                   'itself evidence of anything. The asymmetry, not the entropy, is the signal here.'
                   if tls_caveat else '')
            ),
            evidence={
                'observed_bytes_sent': total_out,
                'observed_bytes_received': flow.bytes_received,
                'observed_ratio': round(ratio, 2),
                'observed_entropy': flow.payload_entropy,
                'volume_threshold_applied': volume_threshold,
                'volume_threshold_basis': f'p{pct} of outbound volume in this capture, '
                                          f'floored at {floor} bytes',
                'entropy_threshold': _cite('exfil_entropy_high'),
                'ratio_threshold': _cite('exfil_ratio'),
                'is_tls': tls_caveat,
            },
        ))
    return findings


def rule_icmp_tunnel(session):
    findings = []
    size_thresh = _t('icmp_payload_bytes')

    for flow in session.flows.filter(protocol='ICMP'):
        if flow.avg_packet_size < size_thresh:
            continue

        # dst_port carries type*256 + code (see processor._classify). Only echo
        # request (8) and echo reply (0) are candidates: every ICMP tunnel in
        # the wild — ptunnel, icmpsh, icmptunnel — rides echo. ICMP *error*
        # messages quote the offending packet's header and 8 bytes of payload
        # (RFC 792), so a busy server answering scans emits hundreds of large
        # unreachables that are not tunnels. On a real week-long server capture
        # that single distinction removed 795 of 799 findings.
        icmp_type = (flow.dst_port or 0) >> 8
        if icmp_type not in (0, 8):
            continue

        total_packets = (flow.packets_sent or 0) + (flow.packets_received or 0)
        if total_packets < _t('icmp_min_packets'):
            continue

        peer = flow.dst_ip if flow.initiator_ip == flow.src_ip else flow.src_ip
        findings.append(Detection(
            session=session, flow=flow,
            rule_id='ICMP_TUNNEL_OVERSIZED',
            title=f'Oversized ICMP to {peer} (avg {flow.avg_packet_size:.0f} B)',
            category='covert_channel',
            severity=Detection.Severity.HIGH,
            method=Detection.Method.RULE,
            confidence=min(flow.avg_packet_size / (size_thresh * 8), 1.0),
            subject_ip=flow.initiator_ip,
            rationale=(
                f'{flow.initiator_ip} sent {flow.packets_sent} ICMP packets to {peer} '
                f'averaging {flow.avg_packet_size:.0f} bytes with payload entropy '
                f'{flow.payload_entropy:.2f}. Standard ping sends a 56-byte payload on '
                f'Linux and 32 bytes on Windows; sustained payloads above {size_thresh} '
                f'bytes indicate data carried inside echo requests.'
            ),
            evidence={
                'observed_avg_packet_size': flow.avg_packet_size,
                'observed_entropy': flow.payload_entropy,
                'packet_count': flow.packets_sent,
                'icmp_type': icmp_type,
                'icmp_type_name': 'echo request' if icmp_type == 8 else 'echo reply',
                'total_packets': total_packets,
                **{'min_packets_' + k: v for k, v in _cite('icmp_min_packets').items()},
                'error_types_excluded': 'ICMP error messages quote the original packet '
                                        'header (RFC 792) and are large by design',
                'baseline': SRC_PING,
                **_cite('icmp_payload_bytes'),
            },
        ))
    return findings


RULES = [
    rule_beaconing,
    rule_beaconing_keepalive,
    rule_unknown_long_channel,
    rule_dns_tunnelling,
    rule_port_scan,
    rule_exfiltration,
    rule_icmp_tunnel,
]

SEVERITY_WEIGHT = {
    Detection.Severity.LOW: 10,
    Detection.Severity.MEDIUM: 35,
    Detection.Severity.HIGH: 70,
    Detection.Severity.CRITICAL: 95,
}


@transaction.atomic
def analyse_session(session, clear_existing=True):
    """
    Run every rule over a completed capture and persist the findings.

    Returns a summary dict. Re-running replaces prior rule output so an
    analyst's triage decisions are never silently duplicated.
    """
    if clear_existing:
        session.detections.filter(method=Detection.Method.RULE).delete()

    findings = []
    for rule in RULES:
        findings.extend(rule(session))

    Detection.objects.bulk_create(findings, batch_size=500)

    # Roll findings up onto their flows so tables can sort by risk.
    per_flow = defaultdict(int)
    for finding in findings:
        if finding.flow_id:
            per_flow[finding.flow_id] = max(
                per_flow[finding.flow_id], SEVERITY_WEIGHT[finding.severity],
            )

    for flow_id, score in per_flow.items():
        Flow.objects.filter(pk=flow_id).update(risk_score=score, is_analyzed=True)
    session.flows.filter(is_analyzed=False).update(is_analyzed=True, risk_score=0)

    by_severity = defaultdict(int)
    by_rule = defaultdict(int)
    for finding in findings:
        by_severity[finding.severity] += 1
        by_rule[finding.rule_id] += 1

    return {
        'total': len(findings),
        'by_severity': dict(by_severity),
        'by_rule': dict(by_rule),
        'flows_flagged': len(per_flow),
    }
