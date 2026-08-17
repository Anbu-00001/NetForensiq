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
from django.db.models import Q

from .models import Detection, Flow
from .processor import DEFAULT_IDLE_TIMEOUT, IDLE_TIMEOUT_SECONDS


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
SRC_SIMPLE_SCAN = (
    'ncsa/bro-simple-scan scripts/scan.zeek, read from source: scan_threshold=25 '
    '(unique host+port combinations for a REMOTE scanner), local_scan_threshold=250 '
    '(for a LOCAL one), scan_timeout=15min'
)
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


# Ports on which a long-lived, unidentified channel is unremarkable.
#
# This is NOT the IANA well-known range and must not be described as one. That
# range is 0-1023; more than a third of the entries below sit outside it
# (3306, 3389, 5432, 5985, 6379, 8080, 9200, 27017 …) and a few — 8000, 8888,
# 34567 — are conventions rather than IANA assignments at all. It is a curated
# list, seeded from the IANA registry and extended with the services that in
# practice hold sustained sessions on a corporate network.
#
# Curated means heuristic, so it is tagged as one. Membership is deliberately
# generous: a false negative here is better than flagging routine traffic.
WELL_KNOWN_PORTS = frozenset({
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 631, 636, 873, 989,
    990, 993, 995, 1194, 1433, 1521, 1723, 3128, 3306, 3389, 5060, 5061, 5222,
    5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 8888, 9200, 27017,
})
SRC_PORT_LIST = (
    OUR_HEURISTIC + ' — curated list of ports carrying sustained sessions, seeded '
    'from the IANA Service Name and Transport Protocol Port Number Registry but '
    'deliberately extended beyond the 0-1023 well-known range'
)


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
    'scan_unique_ports': (25, f'{SRC_SIMPLE_SCAN}; the same figure as Snort 3 '
                              f'port_scan ports=25 ({SRC_SNORT3})'),
    # bro-simple-scan holds a host inside HOME_NET to a far higher bar, because
    # internal hosts legitimately touch many ports (backup agents, monitoring,
    # vulnerability scanners run by the organisation itself).
    'scan_unique_ports_local': (250, SRC_SIMPLE_SCAN + ' — local_scan_threshold'),
    # NOT a fixed rolling window. bro-simple-scan's comment is explicit:
    # "Failed connection attempts are tracked until not seen for this
    # interval" — an inactivity timeout. An earlier version of this file cited
    # it as a 15-minute rolling window and implemented neither.
    'scan_inactivity_timeout': (900, SRC_SIMPLE_SCAN + ' — scan_timeout, an INACTIVITY '
                                                       'timeout: probing is one episode '
                                                       'until the source goes quiet for '
                                                       'this long'),

    # ── exfiltration ──
    # binwalk's 7.6/6.8 pair is hysteresis for walking *through* a file:
    # entropy rising past 7.6 opens a high-entropy region, falling below 6.8
    # closes it. We hold one averaged figure per flow, with no sequence to
    # track, so only the rising edge transfers. The falling edge was published
    # here for a while and applied by nothing.
    'exfil_entropy_high': (7.6, SRC_BINWALK + ' — rising edge only; the falling edge is '
                                'hysteresis for intra-file scanning and has no meaning '
                                'for a per-flow average'),
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
    # The rule compares avg_packet_size, which is the whole frame — IP and
    # ICMP headers included. Naming it 'payload' and citing a payload
    # baseline described a stricter test than the code performs: a stock
    # Linux ping is 56 B of payload in an 84 B packet, so a '100-byte
    # payload' gate is really a ~72-byte payload gate.
    'icmp_packet_bytes': (100, OUR_HEURISTIC + f' — measured on the whole frame. '
                              f'{SRC_PING}, which is 84 B and 60 B on the wire '
                              f'once the 20 B IP and 8 B ICMP headers are counted'),
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

    # risk_score is a 0-100 figure on the dashboard's "Flagged flows" card and
    # the default sort of the flow table. It came from four bare literals with
    # no source and no tag — exactly what the provenance endpoint exists to
    # prevent. Published here and read from here.
    'risk_score_low': (10, OUR_HEURISTIC + ' — flow risk score for a low-severity finding'),
    'risk_score_medium': (35, OUR_HEURISTIC + ' — medium'),
    'risk_score_high': (70, OUR_HEURISTIC + ' — high'),
    'risk_score_critical': (95, OUR_HEURISTIC + ' — critical'),

    # ── severity and confidence ──
    # These decide the colour, the ranking and the urgency an officer sees, so
    # they are as consequential as any detection threshold. They were literals
    # buried in the rule bodies with no source and no heuristic tag, which is
    # exactly the thing the provenance endpoint exists to prevent.
    'beacon_severity_high_score': (0.90, OUR_HEURISTIC + ' — beacon score at which a '
                                                         'finding is raised from medium '
                                                         'to high'),
    'scan_syn_ratio_high': (0.80, OUR_HEURISTIC + ' — share of connections that are SYN '
                                                  'without a completed handshake before a '
                                                  'scan is raised to high'),
    'unknown_channel_confidence': (0.60, OUR_HEURISTIC + ' — fixed confidence: the rule is '
                                                         'categorical, so there is no '
                                                         'observed magnitude to scale'),
    # Confidence is reported as observed/(threshold x N), capped at 1.0. N is a
    # presentation choice about how far past a threshold counts as certain, not
    # a measured quantity, and is labelled as such.
    'confidence_scale_multiplier': (4, OUR_HEURISTIC + ' — a finding reaches full '
                                                       'confidence at four times its '
                                                       'threshold'),

    # ── flow aggregation (not a detection threshold, but it shapes every one
    #    of them: it decides where one conversation ends and the next begins) ──
    # Read from processor.IDLE_TIMEOUT_SECONDS rather than restated, so the
    # published figure cannot drift from the one actually applied. These
    # were duplicated as literals here and happened to agree.
    'flow_idle_timeout_tcp': (IDLE_TIMEOUT_SECONDS['TCP'], SRC_ZEEK_IDLE),
    'flow_idle_timeout_udp': (IDLE_TIMEOUT_SECONDS['UDP'], SRC_ZEEK_IDLE),
    'flow_idle_timeout_icmp': (IDLE_TIMEOUT_SECONDS['ICMP'], SRC_ZEEK_IDLE),
    'flow_idle_timeout_default': (DEFAULT_IDLE_TIMEOUT,
                                  SRC_ZEEK_IDLE + ' — protocols not listed above'),

    # ── unrecognised long-lived channel ──
    'unknown_channel_min_duration': (60, OUR_HEURISTIC + ' — long enough to be a session '
                                                         'rather than a probe or a failed '
                                                         'connection attempt'),
    'unknown_channel_ports': ('not in the curated sustained-session port list',
                              SRC_PORT_LIST),
}


# Entries that shape detection without being applied by any single rule.
# They are published because they change what the rules see — where one
# conversation ends and the next begins — but a reader must not take them for
# a test some rule performs.
INFORMATIONAL_THRESHOLDS = frozenset({
    'flow_idle_timeout_tcp',
    'flow_idle_timeout_udp',
    'flow_idle_timeout_icmp',
    'flow_idle_timeout_default',
})


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
            severity=(Detection.Severity.HIGH
                      if score >= _t('beacon_severity_high_score')
                      else Detection.Severity.MEDIUM),
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
            confidence=_t('unknown_channel_confidence'),
            subject_ip=initiator,
            rationale=(
                f'{initiator} held a connection to '
                f'{peer}:{service_port} open for {flow.duration_seconds:.0f}s, '
                f'exchanging {flow.bytes_sent:,} bytes out and {flow.bytes_received:,} in. '
                f'The port is not one we recognise as carrying sustained sessions, no application '
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
    entropy_thresh = _t('dns_label_entropy')
    entropy_min_len = _t('dns_entropy_min_label_len')

    # Long, high-entropy labels.
    # Aggregated per (source, parent domain) rather than raised per query: one
    # tunnel produces hundreds of oversized queries, and an analyst facing 500
    # near-identical alerts stops reading them. One finding, with the evidence
    # rolled up, is both more usable and more honest about what was observed.
    long_label = defaultdict(lambda: {
        'count': 0, 'max_len': 0, 'max_entropy': 0.0,
        'samples': [], 'flow': None,
    })

    # Length AND entropy, not length OR entropy.
    #
    # The widening form was tried first — flag anything past 52 characters, or
    # anything past 20 characters that is also high-entropy — on the reasoning
    # that a tunnel under a long parent domain has less room per label. On real
    # traffic it immediately flagged
    # `sunshine-bizrate-inc-software.trycloudflare.com` as DNS tunnelling.
    #
    # That host is genuinely malicious: it is the AsyncRAT campaign's payload
    # delivery infrastructure, named in the published ground truth. But it is a
    # Cloudflare quick-tunnel hostname made of dictionary words, not encoded
    # payload, and calling it a DNS tunnel is a wrong finding that happens to
    # point at a right host. An officer acting on the stated reason would be
    # looking for something that is not there.
    #
    # Hyphenated English words sit at roughly the same Shannon entropy as
    # hex-encoded payload (~3.5-4.0 bits/char), so entropy cannot widen the net
    # on its own. It can usefully narrow it: a label that is both at tunnel
    # length and high-entropy is a stronger call than length alone. The minimum
    # length guard remains because entropy over a handful of characters is too
    # unstable to act on.
    matches = session.dns_records.filter(
        subdomain_length__gte=max(label_len, entropy_min_len),
        query_entropy__gte=entropy_thresh,
    )
    for record in matches:
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
            confidence=min(entry['max_len'] / (label_len * _t('confidence_scale_multiplier')), 1.0),
            subject_ip=src_ip,
            rationale=(
                f'{src_ip} issued {entry["count"]} queries under {parent} whose subdomain '
                f'labels reach {entry["max_len"]} characters (peak entropy '
                f'{entry["max_entropy"]:.2f} bits/char). DNS tunnelling encodes payload into '
                f'subdomain labels, producing long high-entropy names; ordinary domains do '
                f'not. Flagged only when a label reaches both {label_len} characters '
                f'and {entropy_thresh} bits/char — length alone catches hostnames made of '
                f'dictionary words, which are suspicious for other reasons but are not '
                f'tunnels. Antivirus '
                f'reputation lookups and some CDNs legitimately use long encoded labels '
                f'and must be ruled out.'
            ),
            evidence={
                'observed_query_count': entry['count'],
                'observed_max_label_length': entry['max_len'],
                'observed_max_entropy': entry['max_entropy'],
                'parent_domain': parent,
                'samples': entry['samples'],
                'matched_on': 'label length AND entropy, both required',
                **_cite('dns_label_length'),
                'entropy_threshold': _cite('dns_label_entropy'),
                'entropy_min_length': _cite('dns_entropy_min_label_len'),
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
            confidence=min(len(names) / (uniq_thresh * _t('confidence_scale_multiplier')), 1.0),
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
    """
    Port scanning, using ncsa/bro-simple-scan's thresholds with one deliberate
    departure from its aggregation.

    Taken from that tool, verified against its source:

    * `scan_threshold = 25` unique **host+port combinations** — so probing one
      port across many hosts counts, which a per-destination port count misses.
    * `local_scan_threshold = 250`. A host inside HOME_NET gets a far higher
      bar: internal backup agents, monitoring boxes and the organisation's own
      vulnerability scanners legitimately touch many ports.
    * `scan_timeout = 15min`, which its comment defines as an inactivity
      timeout — "tracked until not seen for this interval" — not a rolling
      window. An earlier version of this rule cited it as a window and
      implemented neither.

    **Where we depart, and why.** bro-simple-scan is a streaming detector: it
    can only hold state for so long, so probing that resumes after the timeout
    starts a fresh count and a slow sweep never trips it. Its own comment
    concedes this ("A higher interval will detect slower scanners"). Applying
    that model to a stored capture measured what the tool would have alerted on
    in real time, not what is in the evidence: on a week of real traffic it
    reported 100 episodes from 16 sources, having discarded 291 other hosts
    that scanned the same server slowly.
    
    Slow-and-low is precisely what a careful attacker does, and a forensic tool
    holds the whole capture, so the count here is cumulative per source. The
    timeout is still applied — to describe the shape of the activity, and to
    report the largest single burst — but it no longer decides what is seen.
    """
    findings = []
    remote_thresh = _t('scan_unique_ports')
    local_thresh = _t('scan_unique_ports_local')
    timeout = _t('scan_inactivity_timeout')

    per_source = defaultdict(list)
    for flow in session.flows.filter(protocol='TCP').order_by('first_seen'):
        initiator, peer, service_port = flow_direction(flow)
        if initiator:
            per_source[initiator].append((flow.first_seen, peer, service_port, flow))

    for source, probes in per_source.items():
        combos = {(peer, port) for _, peer, port, _ in probes}
        threshold = local_thresh if is_internal(source) else remote_thresh
        if len(combos) < threshold:
            continue

        # Episode structure: how concentrated was the probing?
        episodes = []
        current = []
        previous = None
        for entry in probes:
            if previous is not None and (entry[0] - previous).total_seconds() > timeout:
                episodes.append(current)
                current = []
            current.append(entry)
            previous = entry[0]
        if current:
            episodes.append(current)

        largest = max(
            (len({(peer, port) for _, peer, port, _ in ep}) for ep in episodes),
            default=0,
        )
        targets = {peer for _, peer, _, _ in probes}
        syn_only = sum(
            1 for _, _, _, f in probes
            if 'S' in (f.tcp_flags_seen or '') and 'A' not in (f.tcp_flags_seen or '')
        )
        syn_ratio = syn_only / len(probes) if probes else 0
        span = (probes[-1][0] - probes[0][0]).total_seconds()
        target_label = next(iter(targets)) if len(targets) == 1 else f'{len(targets)} hosts'
        slow = len(episodes) > 1 and largest < threshold

        findings.append(Detection(
            session=session, flow=probes[0][3],
            rule_id='RECON_PORT_SCAN',
            title=f'Port scan: {source} probed {len(combos)} host+port combinations '
                  f'on {target_label}',
            category='reconnaissance',
            severity=(Detection.Severity.HIGH
                      if syn_ratio > _t('scan_syn_ratio_high')
                      else Detection.Severity.MEDIUM),
            method=Detection.Method.RULE,
            confidence=min(len(combos) / (threshold * _t('confidence_scale_multiplier')), 1.0),
            subject_ip=source,
            rationale=(
                f'{source} probed {len(combos)} distinct host+port combinations across '
                f'{len(targets)} host(s) over {span:.0f}s, in {len(episodes)} episode(s) '
                f'separated by gaps of more than {timeout:.0f}s. The largest single episode '
                f'reached {largest} combinations. {syn_only} of {len(probes)} connections '
                f'were SYN without a completed handshake ({syn_ratio:.0%}), the half-open '
                f'scan signature. Threshold {threshold} combinations, applied because this '
                f'source is {"inside" if is_internal(source) else "outside"} the monitored '
                f'network.'
                + (' No single episode reached the threshold on its own — this is slow '
                   'probing spread across the capture, which a streaming detector holding '
                   'state for only 15 minutes would not have reported.' if slow else '')
                + ' Vulnerability scanners and monitoring systems produce identical traffic '
                  'and should be whitelisted.'
            ),
            evidence={
                'observed_host_port_combinations': len(combos),
                'observed_target_hosts': len(targets),
                'episode_count': len(episodes),
                'largest_episode_combinations': largest,
                'spread_below_streaming_threshold': slow,
                'total_span_seconds': round(span, 1),
                'syn_only_connections': syn_only,
                'total_connections': len(probes),
                'source_is_internal': is_internal(source),
                'threshold_applied': threshold,
                'aggregation': 'cumulative across the capture, not per episode — see the '
                               'rule docstring for why this departs from bro-simple-scan',
                'home_net_source': SRC_HOME_NET,
                **_cite('scan_unique_ports' if not is_internal(source)
                        else 'scan_unique_ports_local'),
                'inactivity_timeout': _cite('scan_inactivity_timeout'),
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
            confidence=min(ratio / (ratio_thresh * _t('confidence_scale_multiplier')), 1.0),
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
    size_thresh = _t('icmp_packet_bytes')

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
            confidence=min(flow.avg_packet_size / (size_thresh * _t('confidence_scale_multiplier')), 1.0),
            subject_ip=flow.initiator_ip,
            rationale=(
                f'{flow.initiator_ip} sent {flow.packets_sent} ICMP packets to {peer} '
                f'averaging {flow.avg_packet_size:.0f} bytes per packet (payload entropy '
                f'{flow.payload_entropy:.2f}). Standard ping sends 56 bytes of payload on '
                f'Linux and 32 on Windows — 84 and 60 bytes on the wire once headers are '
                f'counted. Sustained packets above {size_thresh} bytes carry more than a '
                f'ping needs, which is what a tunnel through echo requests looks like.'
            ),
            evidence={
                'observed_avg_packet_size': flow.avg_packet_size,
                'measured_on': 'whole frame including IP and ICMP headers',
                'observed_entropy': flow.payload_entropy,
                'packet_count': flow.packets_sent,
                'icmp_type': icmp_type,
                'icmp_type_name': 'echo request' if icmp_type == 8 else 'echo reply',
                'total_packets': total_packets,
                **{'min_packets_' + k: v for k, v in _cite('icmp_min_packets').items()},
                'error_types_excluded': 'ICMP error messages quote the original packet '
                                        'header (RFC 792) and are large by design',
                'baseline': SRC_PING,
                **_cite('icmp_packet_bytes'),
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

# Single source of truth, shared with Detection.Meta ordering. Published in
# THRESHOLDS so the 0-100 risk_score shown on the dashboard is not an
# unexplained number.
SEVERITY_WEIGHT = {
    Detection.Severity.LOW: _t('risk_score_low'),
    Detection.Severity.MEDIUM: _t('risk_score_medium'),
    Detection.Severity.HIGH: _t('risk_score_high'),
    Detection.Severity.CRITICAL: _t('risk_score_critical'),
}


@transaction.atomic
def analyse_session(session, clear_existing=True):
    """
    Run every rule over a completed capture and persist the findings.

    **Triage decisions survive re-analysis.** Re-running used to delete every
    rule-generated row and recreate it as NEW — which discarded triage_status,
    reviewed_by, reviewed_at and review_note for the whole session. The
    docstring called that a safeguard against duplication; what it actually did
    was erase the investigators' record from a one-click button.

    A finding is now matched to its predecessor on (rule_id, subject_ip,
    title), and any decision recorded against that predecessor is carried
    forward. Those three together identify the same claim about the same host:
    the rule that made it, who it is about, and what it said. If a rule's
    thresholds change enough to alter the title, the finding is genuinely a
    different assertion and correctly arrives unreviewed.
    """
    carried = {}
    if clear_existing:
        previous = session.detections.filter(method=Detection.Method.RULE)
        for old_finding in previous:
            if old_finding.triage_status != Detection.Triage.NEW:
                carried[(old_finding.rule_id, old_finding.subject_ip, old_finding.title)] = {
                    'triage_status': old_finding.triage_status,
                    'reviewed_by_id': old_finding.reviewed_by_id,
                    'reviewed_at': old_finding.reviewed_at,
                    'review_note': old_finding.review_note,
                }
        previous.delete()

    findings = []
    for rule in RULES:
        findings.extend(rule(session))

    # Restore analyst decisions before the rows are written.
    restored = 0
    for finding in findings:
        prior = carried.get((finding.rule_id, finding.subject_ip, finding.title))
        if prior:
            for field, value in prior.items():
                setattr(finding, field, value)
            restored += 1

    # bulk_create bypasses Model.save(), so the rank must be set here or
    # every finding sorts as 0.
    for finding in findings:
        finding.severity_rank = SEVERITY_WEIGHT.get(finding.severity, 0)

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
        'triage_decisions_carried_forward': restored,
        'triage_decisions_lost': max(len(carried) - restored, 0),
        'by_severity': dict(by_severity),
        'by_rule': dict(by_rule),
        'flows_flagged': len(per_flow),
    }
