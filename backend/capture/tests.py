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
