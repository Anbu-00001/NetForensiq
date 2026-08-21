"""
The fast reader must agree with the dissector, exactly.

Why this file is the whole justification for `fastparse`
=======================================================
Replacing a well-tested dissector with hand-written `struct` offsets is the
kind of optimisation that buys speed with silent wrongness: a header read at
the wrong offset does not raise, it invents a port number. Nothing about a
faster import is worth a flow record that describes a conversation which never
happened.

So the claim being tested is not "the fast path parses plausibly". It is that
for the same capture file, the two readers produce the *same flows, the same
DNS records, the same byte and packet counts and the same timestamps* — and
therefore the same findings, since detection is a pure function of those.

The equivalence tests run over the project's real reference captures where
they are present, and over purpose-built captures for the shapes the reference
files do not contain (IPv6, VLAN tags, fragments, DNS over TCP).
"""

import os
import tempfile

from django.test import SimpleTestCase
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Dot1Q, Ether
from scapy.utils import PcapReader, wrpcap

from . import fastparse
from .processor import FlowAggregator

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REFERENCE_DIR = os.path.join(HERE, 'reference_captures')
SYNTHETIC_DIR = os.path.join(HERE, 'synthetic_captures')


def ingest_with_scapy(path):
    aggregator = FlowAggregator()
    with PcapReader(str(path)) as reader:
        for packet in reader:
            aggregator.process(packet)
    return aggregator


def ingest_with_fastparse(path):
    aggregator = FlowAggregator()
    for data, timestamp, linktype in fastparse.iter_frames(path):
        aggregator.process_frame(data, timestamp, linktype)
    return aggregator


def normalise_flows(flows):
    """Flows keyed by identity, with the bookkeeping ids stripped."""
    table = {}
    for flow in flows:
        record = dict(flow)
        record.pop('_uid', None)
        record.pop('_timestamps', None)
        key = (record['src_ip'], record['src_port'], record['dst_ip'],
               record['dst_port'], record['protocol'],
               record['first_seen'], record['last_seen'])
        table[key] = record
    return table


def normalise_dns(records):
    return sorted(
        (r['src_ip'], r['query_name'], r['query_type'], r['subdomain_length'],
         r['label_count'], r['query_entropy'], r['timestamp'].isoformat())
        for r in records
    )


class EquivalenceMixin:
    """Assert both readers agree about one capture file, field by field."""

    def assert_readers_agree(self, path):
        scapy_side = ingest_with_scapy(path)
        fast_side = ingest_with_fastparse(path)

        self.assertEqual(scapy_side.total_packets, fast_side.total_packets,
                         'packet counts differ')
        self.assertEqual(scapy_side.total_bytes, fast_side.total_bytes,
                         'byte counts differ')
        # Timestamps drive every interval, duration and beacon period, so an
        # approximate match here is not a match.
        self.assertEqual(scapy_side.first_packet_time, fast_side.first_packet_time,
                         'first packet timestamp differs')
        self.assertEqual(scapy_side.last_packet_time, fast_side.last_packet_time,
                         'last packet timestamp differs')

        scapy_flows, scapy_dns = scapy_side.finalize()
        fast_flows, fast_dns = fast_side.finalize()

        left = normalise_flows(scapy_flows)
        right = normalise_flows(fast_flows)
        self.assertEqual(set(left) - set(right), set(),
                         'flows the dissector found and the fast reader missed')
        self.assertEqual(set(right) - set(left), set(),
                         'flows the fast reader invented')

        for key in left:
            self.assertEqual(left[key], right[key], f'flow fields differ for {key}')

        self.assertEqual(normalise_dns(scapy_dns), normalise_dns(fast_dns),
                         'DNS records differ')


class SyntheticCaptureEquivalenceTests(EquivalenceMixin, SimpleTestCase):
    """
    Shapes the reference captures do not contain.

    Written rather than downloaded because the point is to exercise the
    branches — VLAN, IPv6, fragmentation, DNS over TCP — not to be realistic.
    """

    def _roundtrip(self, packets):
        handle, path = tempfile.mkstemp(suffix='.pcap')
        os.close(handle)
        try:
            wrpcap(path, packets)
            self.assert_readers_agree(path)
        finally:
            os.unlink(path)

    def test_plain_tcp_and_udp(self):
        self._roundtrip([
            Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=80,
                                                               flags='S'),
            Ether() / IP(src='10.0.0.2', dst='10.0.0.1') / TCP(sport=80, dport=1234,
                                                               flags='SA'),
            Ether() / IP(src='10.0.0.1', dst='10.0.0.2') / TCP(sport=1234, dport=80,
                                                               flags='PA') / b'GET / HTTP/1.1\r\nHost: x\r\n\r\n',
            Ether() / IP(src='10.0.0.1', dst='8.8.8.8') / UDP(sport=5555, dport=53)
            / DNS(rd=1, qd=DNSQR(qname='example.test')),
        ])

    def test_vlan_tagged_and_qinq(self):
        self._roundtrip([
            Ether() / Dot1Q(vlan=10) / IP(src='10.0.0.3', dst='10.0.0.4')
            / TCP(sport=2000, dport=443, flags='S'),
            Ether() / Dot1Q(vlan=10) / Dot1Q(vlan=20)
            / IP(src='10.0.0.5', dst='10.0.0.6') / UDP(sport=3000, dport=161) / b'\x00' * 40,
        ])

    def test_ipv6_traffic(self):
        self._roundtrip([
            Ether() / IPv6(src='fd00::1', dst='fd00::2') / TCP(sport=4000, dport=22,
                                                               flags='S'),
            Ether() / IPv6(src='fd00::2', dst='fd00::1') / UDP(sport=53, dport=4001)
            / b'\x00' * 20,
        ])

    def test_icmp_echo_and_error(self):
        self._roundtrip([
            Ether() / IP(src='10.0.0.7', dst='10.0.0.8') / ICMP(type=8) / (b'ping' * 8),
            Ether() / IP(src='10.0.0.8', dst='10.0.0.7') / ICMP(type=0) / (b'pong' * 8),
            # A destination-unreachable quoting the packet that caused it —
            # the case where scapy's payload boundary sits inside the quote.
            Ether() / IP(src='10.0.0.9', dst='10.0.0.7') / ICMP(type=3, code=3)
            / IP(src='10.0.0.7', dst='10.0.0.9') / UDP(sport=1, dport=9999),
            Ether() / IP(src='10.0.0.7', dst='10.0.0.9') / ICMP(type=13),
        ])

    def test_dns_over_tcp_is_length_prefixed(self):
        message = bytes(DNS(rd=1, qd=DNSQR(qname='tunnel.example.test')))
        framed = len(message).to_bytes(2, 'big') + message
        self._roundtrip([
            Ether() / IP(src='10.0.0.10', dst='10.0.0.11')
            / TCP(sport=5000, dport=53, flags='PA') / framed,
        ])

    def test_fragments_do_not_grow_phantom_ports(self):
        payload = b'A' * 200
        first = Ether() / IP(src='10.0.0.12', dst='10.0.0.13', flags='MF',
                             frag=0) / UDP(sport=6000, dport=7000) / payload
        later = Ether() / IP(src='10.0.0.12', dst='10.0.0.13', frag=25,
                             proto=17) / payload
        self._roundtrip([first, later])

    def test_non_ip_frames_are_skipped_by_both(self):
        self._roundtrip([
            Ether(type=0x0806) / (b'\x00' * 28),          # ARP
            Ether() / IP(src='10.0.0.14', dst='10.0.0.15') / TCP(sport=1, dport=2),
        ])


class ReferenceCaptureEquivalenceTests(EquivalenceMixin, SimpleTestCase):
    """
    The real captures the project ships, when they are present.

    Skipped rather than failed when a capture is absent: the large reference
    files are not in version control, and a developer without them should not
    see a red suite for a file they were never given.
    """

    def _assert_or_skip(self, path):
        if not os.path.exists(path):
            self.skipTest(f'{os.path.basename(path)} not present')
        self.assert_readers_agree(path)

    def test_demo_storyline(self):
        self._assert_or_skip(os.path.join(SYNTHETIC_DIR, 'demo_storyline.pcap'))

    def test_asyncrat_infection_traffic(self):
        self._assert_or_skip(os.path.join(
            REFERENCE_DIR, '2024-03-14-AsyncRAT-and-XWorm-infection-traffic.pcap'))


class LinkTypeSupportTests(SimpleTestCase):
    """
    The fast reader must be honest about what it can read, because the caller
    uses that answer to decide whether to fall back to the dissector.
    """

    def test_ethernet_is_supported(self):
        self.assertTrue(fastparse.supports(fastparse.DLT_ETHERNET))

    def test_an_unknown_link_type_is_not_claimed(self):
        # 143 is DLT_DOCSIS. If this module ever learns to read it, this test
        # should be updated deliberately rather than deleted in passing.
        self.assertFalse(fastparse.supports(143))
        self.assertIsNone(fastparse.parse(b'\x00' * 64, linktype=143))

    def test_truncated_frames_are_refused_not_guessed(self):
        # An Ethernet header promising IPv4 with nothing behind it.
        self.assertIsNone(fastparse.parse(b'\x00' * 12 + b'\x08\x00'))
        # A frame too short to hold even a link header.
        self.assertIsNone(fastparse.parse(b'\x00' * 4))

    def test_malformed_tcp_data_offset_is_read_as_the_dissector_reads_it(self):
        """
        A real frame from the 4SICS ICS capture whose TCP header declares a
        data offset of zero — below the 20-octet minimum in RFC 9293 s.3.1.

        The equivalence check found this one packet in 2,274,747. Refusing it
        cost one packet, one flow and 62 bytes against the dissector's
        numbers; scapy reads the header as a plain 20 octets and keeps the
        packet, so the fast reader must too. A capture is full of malformed
        packets, and how many packets it contains must not depend on which
        reader opened it.
        """
        frame = bytes.fromhex(
            '00e06200170a00077c1a618308004500002c5f91000031064ec5'
            'c0a80216c0a8580f1f930a4833064cc5000000000000'
        ).ljust(62, b'\x00'[0:1])

        parsed = fastparse.parse(frame)
        self.assertIsNotNone(parsed, 'a malformed header must not lose the packet')
        src, dst, protocol, sport, dport, _flags, payload = parsed
        self.assertEqual((src, dst, protocol), ('192.168.2.22', '192.168.88.15', 'TCP'))
        self.assertEqual((sport, dport), (8083, 2632))
        # Exactly what bytes(pkt[TCP].payload) yields for this frame.
        self.assertEqual(payload, b'\x00' * 8)

    def test_linktype_of_reads_the_file_header(self):
        handle, path = tempfile.mkstemp(suffix='.pcap')
        os.close(handle)
        try:
            wrpcap(path, [Ether() / IP(dst='10.0.0.1') / TCP()])
            self.assertEqual(fastparse.linktype_of(path), fastparse.DLT_ETHERNET)
        finally:
            os.unlink(path)
