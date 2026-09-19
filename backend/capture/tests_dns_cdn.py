# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
DNS tunnelling vs a CDN (research/158).

The rule used to group by the last two labels and count every distinct name.
On ordinary traffic that produced "66 unique subdomains of amazonaws.com",
"59 of akamaiedge.net" and "662 of in-addr.arpa". These tests pin the two
changes that remove those — the Public Suffix List for grouping, Elastic's
"loose ends" test for counting — and that a tunnel is still caught.
"""
from django.test import SimpleTestCase, TestCase
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw

from .detection import analyse_session
from .psl import registered_domain
from .tests import write_pcap
from .service import run_pcap_import

HOST, RESOLVER = '10.20.30.40', '10.20.30.1'


class RegisteredDomainTests(SimpleTestCase):
    """Official PSL test vectors are checked in research/158; these are ours."""

    def test_ordinary_and_country_code_domains(self):
        self.assertEqual(registered_domain('a.b.example.com'), 'example.com')
        self.assertEqual(registered_domain('www.example.co.uk'), 'example.co.uk')
        self.assertEqual(registered_domain('Example.COM.'), 'example.com')

    def test_cloud_customers_are_separate(self):
        # `*.compute-1.amazonaws.com` is in the private section.
        self.assertEqual(
            registered_domain('ec2-3-80-1-2.compute-1.amazonaws.com'),
            'ec2-3-80-1-2.compute-1.amazonaws.com')
        self.assertEqual(registered_domain('e1234.a.akamaiedge.net'), 'a.akamaiedge.net')

    def test_dynamic_dns_customer_is_one_group(self):
        # A tunnel under a DuckDNS name stays together, and apart from
        # every other DuckDNS customer.
        self.assertEqual(registered_domain('abc123.mytunnel.duckdns.org'),
                         'mytunnel.duckdns.org')

    def test_reverse_lookups_group_by_delegated_zone(self):
        self.assertEqual(registered_domain('4.3.2.1.in-addr.arpa'), '3.2.1.in-addr.arpa')
        name = '.'.join('0123456789abcdef0123456789abcdef') + '.ip6.arpa'
        self.assertEqual(registered_domain(name),
                         '.'.join('0123456789abcdef0123456789abcdef'[16:]) + '.ip6.arpa')


def _lookup(name, address, t, txid):
    query = IP(src=HOST, dst=RESOLVER) / UDP(sport=40000 + txid % 20000, dport=53) / DNS(
        id=txid, rd=1, qd=DNSQR(qname=name))
    query.time = t
    reply = IP(src=RESOLVER, dst=HOST) / UDP(sport=53, dport=40000 + txid % 20000) / DNS(
        id=txid, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, type='A', rdata=address))
    reply.time = t + 0.01
    return [query, reply]


def _connect(address, t, sport):
    out = IP(src=HOST, dst=address) / TCP(sport=sport, dport=443, flags='PA') / Raw(b'x' * 200)
    out.time = t
    back = IP(src=address, dst=HOST) / TCP(sport=443, dport=sport, flags='PA') / Raw(b'y' * 900)
    back.time = t + 0.05
    return [out, back]


class LooseEndTests(TestCase):
    NAMES = 80  # above the 50-name threshold

    def _rules(self, packets, name):
        session, _ = run_pcap_import(write_pcap(packets), name=name)
        analyse_session(session)
        return session, set(session.detections.values_list('rule_id', flat=True))

    def _cdn(self, connect):
        packets, t = [], 1_700_000_000.0
        for i in range(self.NAMES):
            address = f'198.51.100.{i + 1}'
            packets += _lookup(f'edge{i:03d}.static.cdn-example.net', address, t, i + 1)
            if connect:
                packets += _connect(address, t + 0.1, 50000 + i)
            t += 2.0
        if not connect:
            # Some non-DNS traffic, so the capture can answer "did the host
            # use the names" — the answer is simply no.
            packets += _connect('192.0.2.200', t, 60000)
        return packets

    def test_names_the_host_went_on_to_use_are_not_a_tunnel(self):
        _, rules = self._rules(self._cdn(connect=True), 'cdn-used')
        self.assertNotIn('DNS_TUNNEL_SUBDOMAIN_VOLUME', rules)

    def test_the_same_names_never_used_are(self):
        session, rules = self._rules(self._cdn(connect=False), 'cdn-unused')
        self.assertIn('DNS_TUNNEL_SUBDOMAIN_VOLUME', rules)
        finding = session.detections.get(rule_id='DNS_TUNNEL_SUBDOMAIN_VOLUME')
        self.assertEqual(finding.evidence['registered_domain'], 'cdn-example.net')
        self.assertEqual(finding.evidence['observed_unused_subdomains'], self.NAMES)
        self.assertTrue(finding.evidence['connection_evidence_available'])

    def test_reverse_lookups_across_networks_are_not_one_domain(self):
        packets, t = [], 1_700_000_000.0
        for i in range(self.NAMES):
            packets += _lookup(f'7.{i}.51.198.in-addr.arpa', '192.0.2.9', t, i + 1)
            t += 1.0
        packets += _connect('192.0.2.200', t, 60000)
        _, rules = self._rules(packets, 'reverse')
        self.assertNotIn('DNS_TUNNEL_SUBDOMAIN_VOLUME', rules)
