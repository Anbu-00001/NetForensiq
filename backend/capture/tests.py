"""
Tests over the labeled synthetic corpus.

The synthetic generator is what makes these possible: it plants known attacks
at known parameters, so we can assert that the pipeline recovers them rather
than merely that it runs without raising.
"""

import tempfile
from pathlib import Path

from django.test import TestCase, override_settings
from scapy.all import Raw, wrpcap

from .detection import THRESHOLDS, analyse_session, bowley_skewness, madm
from .features import dns_query_features, interval_features, shannon_entropy
from .models import Detection
from .service import run_pcap_import
from .synthetic import (
    generate_benign, generate_c2_beaconing, generate_c2_beaconing_connections,
    generate_data_exfiltration,
    generate_dns_tunneling, generate_icmp_tunnel, generate_port_scan,
)


def write_pcap(packets):
    path = Path(tempfile.mkdtemp()) / 'test.pcap'
    wrpcap(str(path), packets)
    return path


class FeatureTests(TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(shannon_entropy(b''), 0.0)
        self.assertEqual(shannon_entropy(b'aaaaaaaa'), 0.0)
        # 256 distinct byte values = maximum entropy for a byte alphabet
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=3)

    def test_dns_features_ignore_registrable_domain(self):
        feats = dns_query_features('a8f3d9e2b1c4f7a0.tunnel.example.com')
        # 'example.com' is stripped; the tunnel payload is the leftmost label
        self.assertEqual(feats['subdomain_length'], len('a8f3d9e2b1c4f7a0'))
        self.assertEqual(feats['label_count'], 4)

    def test_dns_features_short_domain_has_no_subdomain(self):
        feats = dns_query_features('example.com')
        self.assertEqual(feats['subdomain_length'], 0)

    def test_interval_features_detect_periodicity(self):
        # Perfectly periodic: dispersion must be 0
        periodic = [i * 30.0 for i in range(20)]
        feats = interval_features(periodic)
        self.assertAlmostEqual(feats['interval_median'], 30.0, places=3)
        self.assertEqual(feats['interval_mad'], 0.0)
        self.assertEqual(feats['interval_dispersion'], 0.0)

    def test_interval_features_need_enough_samples(self):
        self.assertEqual(interval_features([1.0, 2.0])['interval_count'], 0)

    def test_madm_is_robust_to_outliers(self):
        # A single wild value must not move the MAD the way it moves stddev
        steady = [30.0] * 20
        self.assertEqual(madm(steady), 0.0)
        self.assertEqual(madm(steady + [9000.0]), 0.0)

    def test_bowley_skew_guards_narrow_distributions(self):
        # IQR below RITA's floor of 10 forces skew to 0 rather than a wild value
        self.assertEqual(bowley_skewness([1.0, 1.1, 1.2, 1.3]), 0.0)


class TimestampFidelityTests(TestCase):
    """
    The defect this project's whole timeline depends on.

    processor.py previously stamped every packet with time.time() at parse
    time, which destroyed all timing on imported PCAPs.
    """

    def test_packet_timestamps_survive_import(self):
        packets = generate_c2_beaconing(beacon_count=40, base_time=1_700_000_000.0)
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name='ts-fidelity')

        self.assertIsNotNone(session.capture_start)
        self.assertIsNotNone(session.capture_end)
        span = (session.capture_end - session.capture_start).total_seconds()
        # 40 beacons at ~30s apart spans roughly 20 minutes
        self.assertGreater(span, 900)

        flow = session.flows.first()
        # The planted period is 30s with +/-1.5s jitter
        self.assertAlmostEqual(flow.interval_median, 30.0, delta=2.0)
        self.assertLess(flow.interval_dispersion, 0.2)

    def test_direction_is_anchored_to_initiator(self):
        packets = generate_data_exfiltration(packet_count=120, base_time=1_700_000_000.0)
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name='direction')
        flow = session.flows.order_by('-bytes_sent').first()
        # Exfiltration means the initiator pushes data outward
        self.assertGreater(flow.bytes_ratio, 0.5)
        self.assertEqual(flow.initiator_ip, flow.src_ip if
                         flow.initiator_ip == flow.src_ip else flow.initiator_ip)


class DetectionTests(TestCase):
    """Each planted attack must be recovered by its corresponding rule."""

    def _analyse(self, packets, name):
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name=name)
        analyse_session(session)
        return session

    def _rule_ids(self, session):
        return set(session.detections.values_list('rule_id', flat=True))

    def test_beaconing_over_repeated_connections_detected(self):
        """
        RITA's shape: a new connection per callback, periodicity in the gaps
        between them. This is the case rule_beaconing actually models.
        """
        session = self._analyse(
            generate_c2_beaconing_connections(
                beacon_count=40, base_time=1_700_000_000.0), 'beacon-conns')
        self.assertIn('C2_BEACON_PERIODIC', self._rule_ids(session))

    def test_beaconing_inside_one_persistent_connection_detected(self):
        """
        The other shape: one session held open with periodic keepalives, which
        RITA cannot see because it counts connections and there is only one.
        Real AsyncRAT traffic behaves this way.
        """
        session = self._analyse(
            generate_c2_beaconing(beacon_count=60, base_time=1_700_000_000.0), 'beacon-keepalive')
        self.assertIn('C2_BEACON_KEEPALIVE', self._rule_ids(session))

    def test_connection_beacon_counts_connections_not_packets(self):
        """
        Guards the bug real traffic exposed: an earlier rule used packets-in-a-
        flow as a stand-in for RITA's connection count. A single long-lived
        connection, however many packets it carries, is one connection and must
        not satisfy the 23-connection threshold on its own.
        """
        session = self._analyse(
            generate_c2_beaconing(beacon_count=90, base_time=1_700_000_000.0), 'single-conn')
        self.assertNotIn('C2_BEACON_PERIODIC', self._rule_ids(session))

    def test_dns_tunnelling_detected(self):
        session = self._analyse(
            generate_dns_tunneling(query_count=140, base_time=1_700_000_000.0), 'dns')
        found = self._rule_ids(session)
        self.assertTrue({'DNS_TUNNEL_LONG_LABEL', 'DNS_TUNNEL_SUBDOMAIN_VOLUME'} & found)

    def test_port_scan_detected(self):
        session = self._analyse(
            generate_port_scan(base_time=1_700_000_000.0), 'scan')
        self.assertIn('RECON_PORT_SCAN', self._rule_ids(session))

    def test_icmp_tunnel_detected(self):
        session = self._analyse(
            generate_icmp_tunnel(packet_count=120, base_time=1_700_000_000.0), 'icmp')
        self.assertIn('ICMP_TUNNEL_OVERSIZED', self._rule_ids(session))

    def test_benign_traffic_is_quiet(self):
        """
        The false-positive guard. A detector that flags everything is useless,
        so benign baseline traffic must not trip the C2 or scan rules.
        """
        session = self._analyse(
            generate_benign(packet_count=600, base_time=1_700_000_000.0), 'benign')
        found = self._rule_ids(session)
        self.assertNotIn('C2_BEACON_PERIODIC', found)
        self.assertNotIn('RECON_PORT_SCAN', found)

    def test_dns_findings_are_aggregated_not_per_query(self):
        """One tunnel must not produce one alert per query — that is alert fatigue."""
        session = self._analyse(
            generate_dns_tunneling(query_count=200, base_time=1_700_000_000.0), 'dns-agg')
        long_label = session.detections.filter(rule_id='DNS_TUNNEL_LONG_LABEL')
        self.assertLessEqual(long_label.count(), 3)
        if long_label.exists():
            self.assertGreater(long_label.first().evidence['observed_query_count'], 10)

    def test_every_detection_carries_its_provenance(self):
        session = self._analyse(
            generate_c2_beaconing(beacon_count=60, base_time=1_700_000_000.0), 'prov')
        for detection in session.detections.all():
            self.assertTrue(detection.rationale, 'detection must explain itself')
            self.assertTrue(detection.evidence, 'detection must carry observed values')

    def test_detections_start_awaiting_human_review(self):
        session = self._analyse(
            generate_c2_beaconing(beacon_count=60, base_time=1_700_000_000.0), 'triage')
        for detection in session.detections.all():
            self.assertEqual(detection.triage_status, Detection.Triage.NEW)


class ThresholdProvenanceTests(TestCase):
    def test_every_threshold_declares_a_source(self):
        for key, (value, source) in THRESHOLDS.items():
            self.assertTrue(source, f'{key} has no recorded source')
            self.assertIsNotNone(value)

    def test_heuristics_are_labelled_as_such(self):
        """
        Any threshold we invented must say so. This is the guard against
        quietly presenting a made-up number as though it were sourced.
        """
        for key, (_, source) in THRESHOLDS.items():
            if 'HEURISTIC' in source:
                self.assertIn('[OUR HEURISTIC', source,
                              f'{key} mentions heuristic without the standard tag')


class IPv6Tests(TestCase):
    def test_ipv6_packets_are_not_dropped(self):
        from scapy.layers.inet6 import IPv6
        from scapy.layers.inet import TCP

        packets = []
        t = 1_700_000_000.0
        for i in range(10):
            pkt = IPv6(src='2001:db8::1', dst='2001:db8::2') / TCP(sport=40000, dport=443)
            pkt.time = t + i
            packets.append(pkt)

        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name='ipv6')
        self.assertEqual(session.packet_count, 10)
        self.assertGreater(session.flows.count(), 0)


class DirectionAndNoiseTests(TestCase):
    """
    Regressions found by running against real captures rather than our own
    synthetic corpus. Each of these fired hundreds to thousands of times on a
    week of real internet-facing server traffic before it was fixed.
    """

    def _analyse(self, packets, name, home_net=None):
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name=name)
        if home_net is None:
            analyse_session(session)
        else:
            with override_settings(HOME_NET=home_net):
                analyse_session(session)
        return session

    def _rule_ids(self, session):
        return set(session.detections.values_list('rule_id', flat=True))

    def test_inbound_connections_are_not_reported_as_c2_beaconing(self):
        """
        An external host connecting in repeatedly is a scanner, not an
        internal host calling out to a controller. On a real capture all 155
        'beacons' were inbound.
        """
        packets = generate_c2_beaconing_connections(
            beacon_count=40, base_time=1_700_000_000.0,
            infected='203.0.113.9',        # external initiator
            c2_server='192.168.10.5',      # our host is the destination
        )
        session = self._analyse(packets, 'inbound-beacon')
        self.assertNotIn('C2_BEACON_PERIODIC', self._rule_ids(session))

    def test_outbound_beaconing_from_home_net_still_fires(self):
        """The mirror of the above: egress from inside must still be caught."""
        packets = generate_c2_beaconing_connections(
            beacon_count=40, base_time=1_700_000_000.0,
            infected='192.168.10.5', c2_server='203.0.113.9',
        )
        session = self._analyse(packets, 'outbound-beacon')
        self.assertIn('C2_BEACON_PERIODIC', self._rule_ids(session))

    def test_home_net_is_configurable(self):
        """
        The RFC 1918 default is wrong for a capture of a public-facing server.
        Setting HOME_NET to the monitored range must make its egress visible.
        """
        packets = generate_c2_beaconing_connections(
            beacon_count=40, base_time=1_700_000_000.0,
            infected='203.161.44.208', c2_server='198.51.100.7',
        )
        default = self._analyse(packets, 'public-default')
        self.assertNotIn('C2_BEACON_PERIODIC', self._rule_ids(default))

        configured = self._analyse(
            packets, 'public-configured', home_net=['203.161.44.0/24'])
        self.assertIn('C2_BEACON_PERIODIC', self._rule_ids(configured))

    def test_icmp_error_messages_are_not_reported_as_tunnels(self):
        """
        ICMP errors quote the offending packet's header (RFC 792), so they are
        large by design. A busy server answering scans emits hundreds; 795 of
        799 findings on a real capture were these.
        """
        from scapy.layers.inet import ICMP, IP

        packets = []
        t = 1_700_000_000.0
        for i in range(40):
            # Type 3 = destination unreachable, carrying a quoted header
            pkt = (IP(src='192.168.10.5', dst='203.0.113.9')
                   / ICMP(type=3, code=3)
                   / Raw(load=b'Q' * 300))
            pkt.time = t + i
            packets.append(pkt)

        session = self._analyse(packets, 'icmp-errors')
        self.assertNotIn('ICMP_TUNNEL_OVERSIZED', self._rule_ids(session))

    def test_single_oversized_echo_is_not_a_tunnel(self):
        """
        Echo replies mirror the request payload, so one large reply to a
        scanner's large ping is ordinary. A tunnel carries a stream.
        """
        from scapy.layers.inet import ICMP, IP

        pkt = (IP(src='192.168.10.5', dst='203.0.113.9')
               / ICMP(type=8) / Raw(load=b'Z' * 400))
        pkt.time = 1_700_000_000.0

        session = self._analyse([pkt], 'icmp-single')
        self.assertNotIn('ICMP_TUNNEL_OVERSIZED', self._rule_ids(session))

    def test_icmp_echo_tunnel_still_detected(self):
        """The genuine case must survive both new conditions."""
        session = self._analyse(
            generate_icmp_tunnel(packet_count=120, base_time=1_700_000_000.0),
            'icmp-real-tunnel')
        self.assertIn('ICMP_TUNNEL_OVERSIZED', self._rule_ids(session))

    def test_service_port_is_read_from_the_responder(self):
        """
        Reading dst_port blindly yields the client's ephemeral port whenever
        the capture recorded the responder as the source — which is how the
        covert-channel rule ended up flagging 5,853 inbound scans.
        """
        from capture.detection import flow_direction

        class FakeFlow:
            initiator_ip = '203.0.113.9'
            src_ip = '192.168.10.5'   # responder recorded as source
            src_port = 5985           # the actual service
            dst_ip = '203.0.113.9'
            dst_port = 55684          # the client's ephemeral port

        initiator, peer, service_port = flow_direction(FakeFlow())
        self.assertEqual(initiator, '203.0.113.9')
        self.assertEqual(peer, '192.168.10.5')
        self.assertEqual(service_port, 5985)


class FlowSplittingTests(TestCase):
    """
    A 5-tuple is not a connection.

    Clients reuse ephemeral ports, so over a long capture the same tuple
    recurs for conversations far apart in time. Without splitting they merge
    into one record whose duration and intervals are meaningless — a real
    week-long server capture produced flows reporting 22,736 seconds while
    carrying 148 bytes.
    """

    @staticmethod
    def _tcp(src, dst, sport, dport, flags, when, payload=b''):
        from scapy.layers.inet import IP, TCP
        pkt = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = when
        return pkt

    def _import(self, packets, name):
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name=name)
        return session

    def test_a_new_syn_on_a_reused_port_starts_a_new_flow(self):
        """Exact, not heuristic: a SYN on a tuple already carrying traffic."""
        t = 1_700_000_000.0
        packets = []
        for conn in range(3):
            base = t + conn * 10  # well inside the 300s TCP idle timeout
            packets += [
                self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'S', base),
                self._tcp('203.0.113.5', '192.168.1.10', 443, 51000, 'SA', base + 0.02),
                self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'PA', base + 0.05, b'x' * 40),
                self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'FA', base + 0.09),
            ]

        session = self._import(packets, 'syn-reuse')
        self.assertEqual(
            session.flows.count(), 3,
            'three connections on one reused ephemeral port must be three flows',
        )

    def test_an_idle_gap_ends_a_flow(self):
        """
        Captures often begin mid-stream and never show a SYN, so the timeout
        has to stand on its own. UDP idles out after 60s.
        """
        from scapy.layers.inet import IP, UDP
        t = 1_700_000_000.0
        packets = []
        for offset in (0, 1, 2, 500, 501):     # a 498s silence in the middle
            pkt = IP(src='192.168.1.10', dst='203.0.113.5') / UDP(sport=40000, dport=9999)
            pkt.time = t + offset
            packets.append(pkt)

        session = self._import(packets, 'udp-idle')
        self.assertEqual(session.flows.count(), 2)

    def test_traffic_within_the_timeout_stays_one_flow(self):
        """The mirror: normal conversation must not be shredded into fragments."""
        t = 1_700_000_000.0
        packets = [
            self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'S', t),
            self._tcp('203.0.113.5', '192.168.1.10', 443, 51000, 'SA', t + 0.02),
        ]
        for i in range(20):
            packets.append(self._tcp(
                '192.168.1.10', '203.0.113.5', 51000, 443, 'PA', t + 1 + i * 5, b'y' * 60))

        session = self._import(packets, 'single-conn-intact')
        self.assertEqual(session.flows.count(), 1)

    def test_split_flows_report_their_own_durations(self):
        """
        The defect this fixes: duration must describe the conversation, not
        the span between unrelated reuses of the same port.
        """
        t = 1_700_000_000.0
        packets = []
        for conn in range(2):
            base = t + conn * 4000        # far apart, as in a week-long capture
            packets += [
                self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'S', base),
                self._tcp('203.0.113.5', '192.168.1.10', 443, 51000, 'SA', base + 0.02),
                self._tcp('192.168.1.10', '203.0.113.5', 51000, 443, 'PA', base + 1.0, b'z' * 50),
            ]

        session = self._import(packets, 'durations')
        durations = sorted(f.duration_seconds for f in session.flows.all())
        self.assertEqual(len(durations), 2)
        for d in durations:
            self.assertLess(
                d, 10.0,
                f'flow duration {d}s spans the gap between separate connections',
            )

    def test_dns_records_link_to_the_right_flow_instance(self):
        """
        DNS records used to be matched back by 5-tuple. Once one tuple can
        yield several flows, that attaches every record to whichever flow
        happened to be created last.
        """
        from scapy.layers.inet import IP, UDP
        from scapy.layers.dns import DNS, DNSQR

        t = 1_700_000_000.0
        packets = []
        for i, offset in enumerate((0, 500)):   # second query after a UDP idle-out
            pkt = (IP(src='192.168.1.10', dst='8.8.8.8')
                   / UDP(sport=40000, dport=53)
                   / DNS(rd=1, qd=DNSQR(qname=f'host{i}.example.com')))
            pkt.time = t + offset
            packets.append(pkt)

        session = self._import(packets, 'dns-split')
        self.assertEqual(session.flows.count(), 2)

        linked = [r for r in session.dns_records.all() if r.flow_id]
        self.assertEqual(len(linked), 2)
        self.assertEqual(
            len({r.flow_id for r in linked}), 2,
            'each DNS query must attach to the flow it was actually seen in',
        )


class ThresholdsAreActuallyAppliedTests(TestCase):
    """
    The provenance panel publishes every THRESHOLDS entry to the user as if it
    governed detection. Eight of them did not: a 15-minute scan window that was
    never implemented, an entropy gate the DNS rule never consulted, a binwalk
    falling edge with no sequence to apply it to, and idle timeouts restated as
    literals somewhere else. A published threshold that nothing reads is a
    false statement about how the system works.
    """

    def test_every_published_threshold_is_read_by_the_engine(self):
        import re
        from pathlib import Path as _Path

        source = _Path(__file__).with_name('detection.py').read_text()

        # Keys reached through _t(...) / _cite(...) anywhere in the module
        used = set(re.findall(r"_(?:t|cite)\(\s*'([a-z0-9_]+)'", source))
        # Keys resolved dynamically, e.g. _cite(x if cond else y)
        used |= set(re.findall(r"'([a-z0-9_]+)'\s+if\s+", source))
        used |= set(re.findall(r"else\s+'([a-z0-9_]+)'", source))

        # Aggregation parameters are published deliberately and are exempt,
        # but only because they are explicitly listed as such.
        from .detection import INFORMATIONAL_THRESHOLDS
        unused = sorted(set(THRESHOLDS) - used - INFORMATIONAL_THRESHOLDS)
        self.assertEqual(
            unused, [],
            'these thresholds are published to users but read by no rule: '
            + ', '.join(unused),
        )

    def test_every_threshold_names_a_source(self):
        for key, (_value, source) in THRESHOLDS.items():
            self.assertTrue(source and source.strip(),
                            f'{key} has no source string')

    def test_no_threshold_claims_a_citation_it_does_not_have(self):
        """
        A source that says [OUR HEURISTIC] anywhere must carry the tag at a
        position the API's prefix check can see, or the UI reports our own
        invention as though it were sourced.
        """
        for key, (_value, source) in THRESHOLDS.items():
            if 'HEURISTIC' in source:
                self.assertIn(
                    '[OUR HEURISTIC', source,
                    f'{key} mentions a heuristic without the machine-readable tag',
                )


class TriageSurvivesReanalysisTests(TestCase):
    """
    Re-running detection used to delete every rule-generated finding and
    recreate it as NEW, discarding the whole session's triage record — from a
    one-click button whose docstring called the deletion a safeguard.
    """

    def _session(self):
        packets = generate_c2_beaconing_connections(
            beacon_count=40, base_time=1_700_000_000.0)
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name='triage-survival')
        analyse_session(session)
        return session

    def test_a_reviewed_finding_keeps_its_decision(self):
        from accounts.models import User
        session = self._session()
        officer = User.objects.create_user(
            username='io-triage', password='x', badge_id='T-1', department='Cyber')

        finding = session.detections.first()
        self.assertIsNotNone(finding)
        finding.triage_status = Detection.Triage.DISMISSED
        finding.reviewed_by = officer
        finding.review_note = 'known monitoring agent'
        finding.save()

        summary = analyse_session(session)

        self.assertEqual(summary['triage_decisions_carried_forward'], 1)
        restored = session.detections.get(
            rule_id=finding.rule_id, subject_ip=finding.subject_ip)
        self.assertEqual(restored.triage_status, Detection.Triage.DISMISSED)
        self.assertEqual(restored.reviewed_by_id, officer.pk)
        self.assertEqual(restored.review_note, 'known monitoring agent')

    def test_untouched_findings_stay_new(self):
        session = self._session()
        analyse_session(session)
        self.assertTrue(
            all(d.triage_status == Detection.Triage.NEW
                for d in session.detections.all()),
            'nothing was reviewed, so nothing should come back reviewed',
        )


class SeverityOrderingTests(TestCase):
    """
    Ordering on the severity CharField sorted alphabetically: descending gave
    medium > low > high > critical, so the Findings list put the least urgent
    rows first under severity-coloured chips implying rank.
    """

    def test_high_severity_findings_come_before_medium(self):
        from capture.models import CaptureSession

        session = CaptureSession.objects.create(name='ordering')
        for severity in (Detection.Severity.MEDIUM, Detection.Severity.LOW,
                         Detection.Severity.CRITICAL, Detection.Severity.HIGH):
            Detection.objects.create(
                session=session, rule_id=f'T_{severity}', title=str(severity),
                category='test', severity=severity,
                method=Detection.Method.RULE, confidence=0.5,
            )

        order = list(session.detections.values_list('severity', flat=True))
        self.assertEqual(
            order,
            ['critical', 'high', 'medium', 'low'],
            'findings must be ordered by urgency, not alphabetically',
        )

    def test_rank_is_set_when_findings_are_bulk_created(self):
        """analyse_session uses bulk_create, which bypasses Model.save()."""
        packets = generate_port_scan(base_time=1_700_000_000.0)
        path = write_pcap(packets)
        session, _ = run_pcap_import(path, name='rank-bulk')
        analyse_session(session)

        for d in session.detections.all():
            self.assertEqual(d.severity_rank, Detection.SEVERITY_RANK[d.severity])
            self.assertGreater(d.severity_rank, 0)


# ─────────────────────────────────────────────────────────────────────────
# JA4 TLS client fingerprinting
# ─────────────────────────────────────────────────────────────────────────

def _build_client_hello(
    ciphers, extensions, sig_algs=(), alpn=(b'h2',), server_name=b'example.test',
    supported_versions=(0x0304,), legacy_version=0x0303,
):
    """
    Assemble a real ClientHello on the wire format.

    Built by hand rather than captured so a test can state exactly which
    ciphers and extensions went in — which is the only way to check the
    fingerprint that comes out against FoxIO's published values.
    """
    def u16(value):
        return value.to_bytes(2, 'big')

    ext_bytes = b''
    for ext_type in extensions:
        if ext_type == 0x0000:
            host = server_name
            payload = u16(len(host) + 3) + b'\x00' + u16(len(host)) + host
        elif ext_type == 0x0010:
            names = b''.join(bytes([len(a)]) + a for a in alpn)
            payload = u16(len(names)) + names
        elif ext_type == 0x000D:
            values = b''.join(u16(v) for v in sig_algs)
            payload = u16(len(values)) + values
        elif ext_type == 0x002B:
            values = b''.join(u16(v) for v in supported_versions)
            payload = bytes([len(values)]) + values
        else:
            payload = b''
        ext_bytes += u16(ext_type) + u16(len(payload)) + payload

    cipher_bytes = b''.join(u16(c) for c in ciphers)

    body = (
        u16(legacy_version)
        + b'\x00' * 32                       # random
        + b'\x20' + b'\x11' * 32             # session id
        + u16(len(cipher_bytes)) + cipher_bytes
        + b'\x01\x00'                        # one compression method: null
        + u16(len(ext_bytes)) + ext_bytes
    )
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + u16(len(handshake)) + handshake


# The worked example in FoxIO-LLC/ja4, technical_details/JA4.md.
SPEC_CIPHERS = [
    0x1301, 0x1302, 0x1303, 0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9,
    0xCCA8, 0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
]
SPEC_EXTENSIONS = [
    0x001B, 0x0000, 0x0033, 0x0010, 0x4469, 0x0017, 0x002D, 0x000D,
    0x0005, 0x0023, 0x0012, 0x002B, 0xFF01, 0x000B, 0x000A, 0x0015,
]
SPEC_SIG_ALGS = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601]


class JA4FingerprintTests(TestCase):
    """
    Checked against the reference values published with the specification.

    A fingerprint implementation that agrees only with itself proves nothing;
    these assert the exact strings FoxIO documents, so a regression in the
    parser shows up as a mismatch with the standard rather than as a
    different-but-plausible hash.
    """

    def test_matches_the_published_reference_fingerprint(self):
        from .tls_fingerprint import fingerprint_payload

        payload = _build_client_hello(
            SPEC_CIPHERS, SPEC_EXTENSIONS, sig_algs=SPEC_SIG_ALGS,
        )
        ja4, raw, sni = fingerprint_payload(payload)

        self.assertEqual(ja4, 't13d1516h2_8daaf6152771_e5627efa2ab1')
        self.assertEqual(sni, 'example.test')
        self.assertIn('002f,0035,009c,009d,1301', raw)

    def test_grease_values_are_ignored(self):
        """
        RFC 8701 GREASE entries are noise a client inserts deliberately.

        Counting them would make the same browser fingerprint differently on
        every connection, which is the failure that retired JA3.
        """
        from .tls_fingerprint import fingerprint_payload

        greased_ciphers = [0x0A0A] + SPEC_CIPHERS + [0x3A3A]
        greased_extensions = [0x1A1A] + SPEC_EXTENSIONS
        payload = _build_client_hello(
            greased_ciphers, greased_extensions, sig_algs=SPEC_SIG_ALGS,
        )
        ja4, _, _ = fingerprint_payload(payload)

        self.assertEqual(ja4, 't13d1516h2_8daaf6152771_e5627efa2ab1')

    def test_no_sni_reports_i_and_no_alpn_reports_00(self):
        from .tls_fingerprint import fingerprint_payload

        extensions = [e for e in SPEC_EXTENSIONS if e not in (0x0000, 0x0010)]
        payload = _build_client_hello(
            SPEC_CIPHERS, extensions, sig_algs=SPEC_SIG_ALGS,
        )
        ja4, _, sni = fingerprint_payload(payload)

        self.assertTrue(ja4.startswith('t13i1514' + '00'), ja4)
        self.assertEqual(sni, '')

    def test_missing_signature_algorithms_drops_the_underscore(self):
        """The spec's second worked example: the extension list hashes alone."""
        from .tls_fingerprint import fingerprint_payload

        # The extension is still advertised — it just carries no algorithms,
        # which is the case the spec describes.
        payload = _build_client_hello(SPEC_CIPHERS, SPEC_EXTENSIONS, sig_algs=())
        ja4, _, _ = fingerprint_payload(payload)

        self.assertEqual(ja4, 't13d1516h2_8daaf6152771_6d807ffa2a79')

    def test_a_truncated_handshake_yields_nothing_rather_than_a_guess(self):
        from .tls_fingerprint import fingerprint_payload

        payload = _build_client_hello(SPEC_CIPHERS, SPEC_EXTENSIONS)
        ja4, raw, sni = fingerprint_payload(payload[:40])

        self.assertEqual((ja4, raw, sni), ('', '', ''))

    def test_non_tls_payload_is_not_fingerprinted(self):
        from .tls_fingerprint import fingerprint_payload

        self.assertEqual(
            fingerprint_payload(b'GET / HTTP/1.1\r\nHost: example.test\r\n\r\n'),
            ('', '', ''),
        )
