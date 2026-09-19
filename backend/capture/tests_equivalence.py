# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Differential gating: a fast path may only ship if it agrees with the dissector.

Why this file exists as a thing of its own
==========================================
`tests_fastparse.py` proved one fast path correct by diffing it against scapy
over real captures. That worked, and the method — not the parser — turned out
to be the reusable asset, so this file generalises it: scapy is kept as an
*oracle*, and every module that replaces a scapy call must reproduce its output
exactly before it is allowed near the ingest path.

The method earned its place twice while `fastdns` and `fastparse.icmp_payload`
were being written, both times by rejecting something that looked finished:

* An ICMP shortcut that was 800x faster and matched scapy on **all 73,935**
  ICMP messages in the reference captures was still wrong — on message sizes
  and types those captures happen not to contain. Corpus agreement is not
  proof; the generated cases in `IcmpBoundaryTests` are what caught it.
* A DNS qtype table built from the common types rendered 42 as `'42'` where
  scapy renders `'APL'`, and 0 and 65535 as numbers where scapy says
  `'RESERVED'`.

Why identical and not merely correct
====================================
Findings already recorded in evidence were derived through scapy. A fast path
that is *more* correct than scapy would silently reclassify old captures on
re-import, so the bar is agreement, quirks included. Where scapy departs from
the RFC, the departure is reproduced and commented at the site.

For a tool whose output is evidence this is the claim worth being able to make
in court: not that the parser got faster, but that the findings did not move,
across a named and counted corpus.
"""

import os

from django.test import SimpleTestCase
from scapy.layers.dns import DNS, DNSQR, DNSRR, dnsqtypes
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Raw

from . import fastdns, fastparse

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REFERENCE_DIR = os.path.join(HERE, 'reference_captures')
SYNTHETIC_DIR = os.path.join(HERE, 'synthetic_captures')

# Coverage is asserted, not hoped for. If a reference capture goes missing the
# corpus tests would otherwise pass vacuously while testing nothing, which is
# the failure mode that makes a green suite misleading.
MINIMUM_DNS_MESSAGES = 200
MINIMUM_ICMP_MESSAGES = 200

# Ceilings on the two deliberate divergences, so they stay exceptional. The
# corpus currently holds 1 short-body DNS payload out of 65,342 and 94
# re-serialised ICMP quotes out of 13,511 in the capture that has them; these
# are set with room above the observed values but far below "the parser broke".
MAX_INVENTED_DNS = 10
MAX_RESERIALISED_ICMP_RATIO = 0.02


def _captures():
    """Every capture available to test against, reference and synthetic."""
    found = []
    for directory in (REFERENCE_DIR, SYNTHETIC_DIR):
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if name.endswith(('.pcap', '.pcapng')):
                found.append(os.path.join(directory, name))
    return found


def _scapy_dns(payload, over_tcp):
    """The oracle: what the aggregator used to read, through scapy."""
    try:
        if over_tcp:
            message = DNS(payload[2:]) if len(payload) > 2 else None
        else:
            message = DNS(payload)
    except Exception:
        return None
    return fastdns.from_scapy(message)


class QtypeTableTests(SimpleTestCase):
    """The copied table must not drift from the one scapy actually uses."""

    def test_table_matches_scapy(self):
        self.assertEqual(
            fastdns.QTYPES, dict(dnsqtypes),
            'fastdns.QTYPES has drifted from scapy.layers.dns.dnsqtypes. A '
            'scapy upgrade that adds or renames a query type changes how a '
            'query is labelled in evidence, so the table is updated here '
            'deliberately rather than discovered later.')

    def test_unknown_types_render_as_the_number(self):
        query = DNSQR(qname='x.test.')
        field = query.get_field('qtype')
        for value in (999, 4242, 31337):
            self.assertEqual(fastdns.QTYPES.get(value, str(value)),
                             field.i2repr(query, value))


class DnsCorpusTests(SimpleTestCase):
    """
    Every DNS message in every capture, with the one deliberate divergence.

    scapy builds a `DNS` object out of whatever it is handed, and when the body
    is too short to hold a 12-octet header it leaves the fields at their class
    defaults — producing a question for `www.example.com.`, scapy's default
    qname, that was never on the wire. The old ingest path recorded that as a
    DNSRecord.

    This module returns None instead. That is a divergence, and it is the
    intended direction: refusing to read a header that is not there is not the
    same kind of error as inventing one, and a fabricated query name in
    evidence is worse than a missing one. The corpus contains exactly one such
    payload (a DNS-over-TCP length prefix with no message after it), so the
    correction is real but tiny.
    """

    def test_agrees_with_scapy_except_where_scapy_invents_a_message(self):
        compared = invented = 0
        for path in _captures():
            for data, _timestamp, linktype in fastparse.iter_frames(path):
                if not fastparse.supports(linktype):
                    continue
                parsed = fastparse.parse(data, linktype)
                if parsed is None:
                    continue
                _src, _dst, protocol, sport, dport, _flags, payload = parsed
                if 53 not in (sport, dport) or not payload:
                    continue

                over_tcp = protocol == 'TCP'
                expected = _scapy_dns(payload, over_tcp)
                actual = fastdns.parse(payload, over_tcp=over_tcp)
                compared += 1
                if expected == actual:
                    continue

                # The only tolerated difference: too few octets for a header,
                # so scapy answered from its defaults and we declined.
                body = payload[2:] if over_tcp else payload
                self.assertLess(
                    len(body), 12,
                    f'DNS mismatch in {os.path.basename(path)} on a '
                    f'{len(body)}-octet body that was long enough to read: '
                    f'scapy={expected!r} fastdns={actual!r}')
                self.assertIsNone(
                    actual,
                    f'fastdns read a message out of {len(body)} octets')
                invented += 1

        self.assertGreaterEqual(
            compared, MINIMUM_DNS_MESSAGES,
            f'only {compared} DNS messages were compared; the corpus has '
            f'shrunk and this test is no longer evidence of anything')
        self.assertLessEqual(
            invented, MAX_INVENTED_DNS,
            f'{invented} payloads were too short for a DNS header; that is '
            f'more than the corpus used to contain, so either the corpus or '
            f'the parse guard has changed')


class IcmpCorpusTests(SimpleTestCase):
    """
    Every ICMP message in every capture, with the one deliberate divergence.

    `bytes(ICMP(m).payload)` does not return bytes from the wire. It returns
    the *re-serialisation* of whatever scapy dissected the quoted packet into,
    and for an ICMP error quoting a UDP datagram that scapy recognises — CLDAP
    and SNMP both appear in the reference captures — the ASN.1 is re-encoded
    with different length forms. The result is a different byte string, of a
    different length, from the one the capture holds.

    Worse, it depends on which scapy layers are loaded. Measured on
    `2024-12-18-one-week-of-server-scans…`, 13,511 ICMP messages:

        only scapy.layers.inet imported      0 divergent
        scapy.all imported (what the app does via capture.service)   94 divergent

    So the payload the old path recorded — and therefore `payload_entropy`,
    and therefore what the ICMP tunnelling rule reads — was a function of the
    import graph rather than of the capture. That is not a property evidence
    can have.

    `fastparse.icmp_payload` returns a contiguous slice of the message every
    time, which is deterministic and is what was actually observed. This
    changes stored `payload_entropy` on 450 of 94,811 flows in that capture
    (0.47%) and changed **no finding at all** (184 before, 184 after). The
    invariant is asserted here; the findings comparison is recorded in
    research/153_PCAP_ENGINE_PERFORMANCE.md.
    """

    def test_output_is_always_bytes_from_the_wire(self):
        compared = reserialised = 0
        for path in _captures():
            for data, _timestamp, linktype in fastparse.iter_frames(path):
                if not fastparse.supports(linktype):
                    continue
                parsed = fastparse.parse(data, linktype)
                if parsed is None or parsed[2] != 'ICMP' or not parsed[6]:
                    continue
                message = parsed[6]
                actual = fastparse.icmp_payload(message)
                compared += 1

                # The invariant that replaces equality with scapy: whatever we
                # return was in the message, contiguously, at the offset the
                # header length implies.
                self.assertIn(
                    actual, (message[8:], message[8:128 + 8], message[12:],
                             message[20:], b''),
                    f'icmp_payload returned something that is not a header-'
                    f'aligned slice of a type={message[0]} message')

                try:
                    expected = bytes(ICMP(message).payload)
                except Exception:
                    expected = b''
                if expected != actual:
                    # Only tolerated when scapy rebuilt a dissected quote.
                    reserialised += 1

        self.assertGreaterEqual(
            compared, MINIMUM_ICMP_MESSAGES,
            f'only {compared} ICMP messages were compared; the corpus has '
            f'shrunk and this test is no longer evidence of anything')
        self.assertLessEqual(
            reserialised / max(compared, 1), MAX_RESERIALISED_ICMP_RATIO,
            f'{reserialised} of {compared} ICMP messages differ from scapy, '
            f'which is more than re-serialisation of quoted packets explains')


class IcmpBoundaryTests(SimpleTestCase):
    """
    The cases the reference captures do not contain.

    These exist because a flat "cut at 128 octets" rule passed the corpus test
    above on all 73,935 messages and was still wrong. RFC 4884 s.5.2 only
    applies from 144 octets, and only to the types that carry the extension
    fields — so the interesting sizes are 137 to 143, and the interesting types
    are 4 and 5, which never get cut at all.
    """

    def _check(self, kind, quoted_extra):
        quoted = bytes(IP(src='10.1.1.1', dst='10.2.2.2') / TCP()
                       / Raw(b'A' * quoted_extra))
        message = bytes(ICMP(type=kind, code=0)) + quoted
        expected = bytes(ICMP(message).payload)
        self.assertEqual(
            expected, fastparse.icmp_payload(message),
            f'type={kind} message={len(message)} octets: scapy kept '
            f'{len(expected)}, fastparse kept '
            f'{len(fastparse.icmp_payload(message))}')

    def test_across_the_rfc4884_threshold(self):
        # 60..134 extra bytes puts the whole message either side of 144.
        for kind in (3, 4, 5, 11, 12):
            for extra in range(60, 135):
                self._check(kind, extra)

    def test_types_without_extension_fields_are_never_cut(self):
        # 4 and 5 quote a packet but carry no RFC 4884 fields, so however long
        # the quoted packet is, scapy keeps all of it.
        for kind in (4, 5):
            message = bytes(ICMP(type=kind, code=0)) + bytes(
                IP() / UDP() / Raw(b'B' * 400))
            self.assertEqual(bytes(ICMP(message).payload),
                             fastparse.icmp_payload(message))

    def test_short_and_empty_messages(self):
        for message in (b'', b'\x03', b'\x03\x01', b'\x08\x00\x00\x00',
                        bytes(ICMP(type=8))):
            try:
                expected = bytes(ICMP(message).payload) if len(message) >= 4 else b''
            except Exception:
                expected = b''
            self.assertEqual(expected, fastparse.icmp_payload(message))

    def test_timestamp_and_address_mask_headers(self):
        for kind in (13, 14, 17, 18):
            message = bytes(ICMP(type=kind)) + b'C' * 40
            self.assertEqual(bytes(ICMP(message).payload),
                             fastparse.icmp_payload(message))


class DnsMalformedTests(SimpleTestCase):
    """
    Hostile and broken DNS, where the fast reader is most likely to diverge.

    A forensic tool reads captures made of attacker-controlled traffic, so the
    malformed cases are not edge cases here — they are the evidence. RFC 9267
    s.3 names unbounded pointer following and pointer loops as the two
    anti-patterns that matter; both are covered, and both are resolved the way
    scapy resolves them rather than the way the RFC recommends, for the
    continuity reason in the module docstring.
    """

    def _both(self, payload, over_tcp=False):
        return _scapy_dns(payload, over_tcp), fastdns.parse(payload, over_tcp=over_tcp)

    def test_pointer_loop_to_itself(self):
        # A name at offset 12 whose pointer points at offset 12.
        payload = bytes(DNS(id=1, qd=DNSQR(qname='a.test.')))[:12] + b'\xc0\x0c'
        expected, actual = self._both(payload)
        self.assertEqual(expected, actual)

    def test_two_pointers_pointing_at_each_other(self):
        header = bytes(DNS(id=2, qd=DNSQR(qname='a.test.')))[:12]
        payload = header + b'\xc0\x0e' + b'\xc0\x0c' + b'\x00\x01\x00\x01'
        expected, actual = self._both(payload)
        self.assertEqual(expected, actual)

    def test_forward_pointer(self):
        # RFC 1035 requires a backward pointer; scapy follows this one anyway.
        header = bytes(DNS(id=3, qd=DNSQR(qname='a.test.')))[:12]
        payload = (header + b'\xc0\x10' + b'\x00\x01\x00\x01'
                   + b'\x02hi\x00' + b'\x00\x01\x00\x01')
        expected, actual = self._both(payload)
        self.assertEqual(expected, actual)

    def test_reserved_label_types(self):
        # 0x40 and 0x80 are reserved label types that scapy treats as pointers.
        header = bytes(DNS(id=4, qd=DNSQR(qname='a.test.')))[:12]
        for marker in (b'\x40\x0c', b'\x80\x0c', b'\x40\xff', b'\x80\x00'):
            payload = header + marker + b'\x00\x01\x00\x01'
            expected, actual = self._both(payload)
            self.assertEqual(expected, actual, f'marker {marker!r}')

    def test_truncated_at_every_offset(self):
        full = bytes(DNS(id=5, qd=DNSQR(qname='deep.sub.domain.test.'),
                         an=DNSRR(rrname='deep.sub.domain.test.', type='A',
                                  rdata='203.0.113.9')))
        for cut in range(0, len(full)):
            payload = full[:cut]
            expected, actual = self._both(payload)
            if cut < 12:
                # Below a full header scapy answers from its class defaults and
                # invents a question; see DnsCorpusTests for why we decline.
                self.assertIsNone(actual, f'truncated to {cut} octets')
                continue
            self.assertEqual(expected, actual, f'truncated to {cut} octets')

    def test_incomplete_jump_token(self):
        header = bytes(DNS(id=6, qd=DNSQR(qname='a.test.')))[:12]
        expected, actual = self._both(header + b'\xc0')
        self.assertEqual(expected, actual)

    def test_zero_question_count(self):
        # qdcount forced to 0 on a full header. `_process_dns` returns early on
        # a message with no question section, so there is nothing to build.
        payload = bytearray(bytes(DNS(id=7, qd=DNSQR(qname='a.test.'))))
        payload[4:6] = b'\x00\x00'
        self.assertIsNone(fastdns.parse(bytes(payload)))

    def test_declared_answers_exceeding_the_message(self):
        message = DNS(id=8, qr=1, qd=DNSQR(qname='a.test.'),
                      an=DNSRR(rrname='a.test.', type='A', rdata='198.51.100.4'))
        payload = bytearray(bytes(message))
        payload[6:8] = (4000).to_bytes(2, 'big')       # ancount lies
        expected, actual = self._both(bytes(payload))
        self.assertEqual(expected, actual)

    def test_root_name(self):
        payload = bytes(DNS(id=9))[:12] + b'\x00' + b'\x00\x01\x00\x01'
        payload = payload[:4] + b'\x00\x01' + payload[6:]   # qdcount = 1
        expected, actual = self._both(payload)
        self.assertEqual(expected, actual)

    def test_label_running_past_the_end(self):
        header = bytes(DNS(id=10, qd=DNSQR(qname='a.test.')))[:12]
        payload = header + b'\x3fshort'                 # claims 63, has 5
        expected, actual = self._both(payload)
        self.assertEqual(expected, actual)

    def test_dns_over_tcp_length_prefix(self):
        message = bytes(DNS(id=11, qd=DNSQR(qname='tcp.test.')))
        payload = len(message).to_bytes(2, 'big') + message
        expected, actual = self._both(payload, over_tcp=True)
        self.assertEqual(expected, actual)
        self.assertIsNotNone(actual)

    def test_dns_over_tcp_with_no_body(self):
        for payload in (b'', b'\x00', b'\x00\x10'):
            self.assertIsNone(fastdns.parse(payload, over_tcp=True))


class DnsAnswerTests(SimpleTestCase):
    """Answer-section reading, which feeds the DNS-to-flow correlation."""

    def test_a_and_aaaa_addresses(self):
        # ancount is set explicitly: chaining DNSRR with `/` builds a record
        # chain but leaves ancount at 1, so the message would declare fewer
        # answers than it carries and the walk would stop after the first.
        message = DNS(id=12, qr=1, qd=DNSQR(qname='both.test.'), ancount=2,
                      an=(DNSRR(rrname='both.test.', type='A', rdata='192.0.2.7')
                          / DNSRR(rrname='both.test.', type='AAAA',
                                  rdata='2001:db8::1')))
        payload = bytes(message)
        expected, actual = _scapy_dns(payload, False), fastdns.parse(payload)
        self.assertEqual(expected, actual)
        self.assertEqual(['192.0.2.7', '2001:db8::1'], actual.answers)

    def test_ipv6_zero_compression_matches_scapy(self):
        for address in ('2001:db8::1', '::1', '::', 'fe80::200:5eff:fe00:5213',
                        '2001:0:0:1:0:0:0:1', '1:2:3:4:5:6:7:8',
                        '2001:db8:0:0:1:0:0:1'):
            message = DNS(id=13, qr=1, qd=DNSQR(qname='v6.test.'),
                          an=DNSRR(rrname='v6.test.', type='AAAA', rdata=address))
            payload = bytes(message)
            self.assertEqual(_scapy_dns(payload, False), fastdns.parse(payload),
                             f'AAAA rdata {address}')

    def test_non_address_records_are_ignored(self):
        message = DNS(id=14, qr=1, qd=DNSQR(qname='cname.test.'),
                      an=DNSRR(rrname='cname.test.', type='CNAME',
                               rdata='elsewhere.test.'))
        payload = bytes(message)
        self.assertEqual(_scapy_dns(payload, False), fastdns.parse(payload))
        self.assertEqual([], fastdns.parse(payload).answers)

    def test_compressed_answer_names(self):
        # scapy compresses the rrname against the question by default, which is
        # the common real shape and the one that exercises pointer following in
        # the answer walk.
        message = DNS(id=15, qr=1, qd=DNSQR(qname='c.test.'),
                      an=DNSRR(rrname='c.test.', type='A', rdata='192.0.2.9'))
        payload = bytes(message)
        self.assertEqual(_scapy_dns(payload, False), fastdns.parse(payload))
