"""
Tests for TCP reassembly and cleartext protocol decoding.

The cases that matter are the awkward ones: out-of-order arrival, gaps,
retransmissions, and overlapping segments that disagree. A reassembler that
handles only clean captures produces confident nonsense on real ones.
"""

from django.test import TestCase
from scapy.layers.inet import IP, TCP

from . import protocols, reassembly

CLIENT, SERVER = '10.0.0.5', '203.0.113.9'
CPORT, SPORT = 51234, 21
TUPLE = (CLIENT, CPORT, SERVER, SPORT)
ISN_C, ISN_S = 1000, 5000


def syn():
    return IP(src=CLIENT, dst=SERVER) / TCP(sport=CPORT, dport=SPORT, flags='S', seq=ISN_C)


def synack():
    return IP(src=SERVER, dst=CLIENT) / TCP(sport=SPORT, dport=CPORT, flags='SA', seq=ISN_S)


def c2s(offset, payload):
    """A client segment whose first byte sits `offset` bytes into the stream."""
    return (IP(src=CLIENT, dst=SERVER)
            / TCP(sport=CPORT, dport=SPORT, flags='PA', seq=ISN_C + 1 + offset)
            / payload)


def s2c(offset, payload):
    return (IP(src=SERVER, dst=CLIENT)
            / TCP(sport=SPORT, dport=CPORT, flags='PA', seq=ISN_S + 1 + offset)
            / payload)


def run(packets):
    return reassembly.reassemble(list(enumerate(packets, start=1)), TUPLE)


class OrderingTests(TestCase):
    def test_segments_in_order_reassemble_to_the_original(self):
        client, _ = run([syn(), synack(), c2s(0, b'USER anon\r\n'), c2s(11, b'PASS x\r\n')])
        self.assertEqual(client.data(), b'USER anon\r\nPASS x\r\n')
        self.assertTrue(client.is_complete)
        self.assertFalse(client.is_ambiguous)

    def test_segments_out_of_order_reassemble_to_the_original(self):
        client, _ = run([syn(), synack(), c2s(11, b'PASS x\r\n'), c2s(0, b'USER anon\r\n')])
        self.assertEqual(client.data(), b'USER anon\r\nPASS x\r\n')
        self.assertTrue(client.is_complete)

    def test_the_syn_consumes_one_sequence_number(self):
        """
        Off by one here shifts every byte of the stream. It is invisible in
        text and fatal in a binary, so it gets its own test.
        """
        client, _ = run([syn(), synack(), c2s(0, b'ABCD')])
        self.assertEqual(client.data(), b'ABCD')

    def test_both_directions_are_reassembled_independently(self):
        client, server = run([
            syn(), synack(),
            s2c(0, b'220 ready\r\n'),
            c2s(0, b'USER anon\r\n'),
            s2c(11, b'331 ok\r\n'),
        ])
        self.assertEqual(client.data(), b'USER anon\r\n')
        self.assertEqual(server.data(), b'220 ready\r\n331 ok\r\n')


class DamageTests(TestCase):
    def test_a_missing_segment_becomes_a_reported_gap_not_a_join(self):
        """
        Closing a gap silently produces a file that looks complete and is not.
        """
        client, _ = run([syn(), synack(), c2s(0, b'AAAA'), c2s(8, b'CCCC')])

        self.assertFalse(client.is_complete)
        self.assertEqual(len(client.gaps), 1)
        self.assertEqual(client.gaps[0].offset, 4)
        self.assertEqual(client.gaps[0].length, 4)
        # Two runs, not one eight-byte blob.
        self.assertEqual(len(client.runs), 2)
        self.assertEqual(client.runs[0], (0, b'AAAA'))
        self.assertEqual(client.runs[1], (8, b'CCCC'))

    def test_a_gap_is_described_in_words_for_the_report(self):
        client, _ = run([syn(), synack(), c2s(0, b'AAAA'), c2s(8, b'CCCC')])
        self.assertIn('missing at offset 4', ' '.join(client.caveats()))

    def test_an_identical_retransmission_is_counted_not_duplicated(self):
        client, _ = run([syn(), synack(), c2s(0, b'HELLO'), c2s(0, b'HELLO')])
        self.assertEqual(client.data(), b'HELLO')
        self.assertEqual(client.retransmissions, 1)
        self.assertFalse(client.is_ambiguous)

    def test_a_capture_that_began_mid_connection_says_so(self):
        client, _ = run([c2s(0, b'RETR secret.zip\r\n')])
        self.assertTrue(client.started_mid_stream)
        self.assertFalse(client.is_complete)
        self.assertIn('began after this connection was established',
                      ' '.join(client.caveats()))


class AmbiguityTests(TestCase):
    """
    The case an IDS resolves by guessing the destination OS, and a forensic
    tool must not.
    """

    def test_conflicting_overlap_makes_the_reconstruction_ambiguous(self):
        client, _ = run([syn(), synack(), c2s(0, b'GET /safe'), c2s(5, b'/evil')])

        self.assertTrue(client.is_ambiguous)
        self.assertEqual(len(client.conflicts), 1)
        conflict = client.conflicts[0]
        self.assertEqual(conflict.offset, 5)
        self.assertEqual(conflict.kept_from_packet, 3)
        self.assertEqual(conflict.contradicted_by_packet, 4)

    def test_the_first_arrival_is_kept_and_the_policy_is_named(self):
        client, _ = run([syn(), synack(), c2s(0, b'AAAA'), c2s(0, b'BBBB')])
        self.assertEqual(client.data(), b'AAAA')
        self.assertEqual(reassembly.POLICY, 'first-arrival')

    def test_the_conflict_is_described_as_a_thing_someone_could_have_seen_differently(self):
        client, _ = run([syn(), synack(), c2s(0, b'AAAA'), c2s(0, b'BBBB')])
        described = client.conflicts[0].describe()
        self.assertIn('might have kept the other', described)

    def test_a_clean_stream_is_not_marked_ambiguous(self):
        client, _ = run([syn(), synack(), c2s(0, b'AAAA'), c2s(4, b'BBBB')])
        self.assertFalse(client.is_ambiguous)
        self.assertEqual(client.data(), b'AAAABBBB')


class FtpDecodeTests(TestCase):
    def _session(self):
        return run([
            syn(), synack(),
            s2c(0, b'220 vsFTPd ready\r\n'),
            c2s(0, b'USER rakesh\r\n'),
            s2c(18, b'331 password please\r\n'),
            c2s(13, b'PASS hunter2\r\n'),
            s2c(39, b'230 logged in\r\n'),
            c2s(27, b'RETR customer-list.csv\r\n'),
        ])

    def test_the_exchange_is_read_back_as_commands(self):
        client, server = self._session()
        decoded = protocols.decode(client, server, CPORT, SPORT)
        self.assertEqual(decoded['protocol'], 'ftp')
        self.assertTrue(decoded['decoded'])
        commands = [e['command'] for e in decoded['events'] if 'command' in e]
        self.assertEqual(commands, ['USER', 'PASS', 'RETR'])

    def test_the_summary_names_the_account_and_the_file(self):
        client, server = self._session()
        decoded = protocols.decode(client, server, CPORT, SPORT)
        self.assertEqual(decoded['accounts_used'], ['rakesh'])
        self.assertEqual(decoded['files_transferred'], ['customer-list.csv'])

    def test_a_cleartext_password_is_kept_but_flagged(self):
        """
        Deleting it would destroy evidence; printing it unmarked would put it
        in a photocopied case file. It is kept and tagged.
        """
        client, server = self._session()
        decoded = protocols.decode(client, server, CPORT, SPORT)
        password = [e for e in decoded['events'] if e.get('command') == 'PASS'][0]
        self.assertTrue(password['sensitive'])
        self.assertEqual(password['argument'], 'hunter2')
        self.assertTrue(decoded['credentials_in_the_clear'])

    def test_the_transcript_says_the_file_itself_is_elsewhere(self):
        client, server = self._session()
        decoded = protocols.decode(client, server, CPORT, SPORT)
        self.assertIn('separate data connection', decoded['note'])

    def test_server_replies_are_read_back_with_their_codes(self):
        client, server = self._session()
        decoded = protocols.decode(client, server, CPORT, SPORT)
        codes = [e['code'] for e in decoded['events'] if 'code' in e]
        self.assertEqual(codes, ['220', '331', '230'])


class EncryptedTests(TestCase):
    def test_tls_is_reported_as_encrypted_not_as_unrecognised(self):
        """
        'Encrypted, contents not recoverable' is actionable. An empty
        transcript invites the conclusion that nothing was said.
        """
        client, server = reassembly.reassemble([], (CLIENT, 51234, SERVER, 443))
        decoded = protocols.decode(client, server, 51234, 443)
        self.assertEqual(decoded['protocol'], 'tls')
        self.assertFalse(decoded['decoded'])
        self.assertIn('session keys', decoded['reason'])

    def test_an_unknown_port_says_the_identification_is_a_guess(self):
        client, server = reassembly.reassemble([], (CLIENT, 51234, SERVER, 9999))
        decoded = protocols.decode(client, server, 51234, 9999)
        self.assertEqual(decoded['protocol'], 'unknown')
        self.assertIn('guess', decoded['reason'])


class CaveatPropagationTests(TestCase):
    def test_a_transcript_rebuilt_across_a_gap_carries_the_warning(self):
        client, server = run([syn(), synack(), c2s(0, b'USER a\r\n'), c2s(20, b'QUIT\r\n')])
        decoded = protocols.decode(client, server, CPORT, SPORT)
        self.assertFalse(decoded['reconstruction_complete'])
        self.assertTrue(any('missing at offset' in c for c in decoded['caveats']))

    def test_an_ambiguous_transcript_is_marked_ambiguous(self):
        client, server = run([syn(), synack(), c2s(0, b'USER aaaa'), c2s(5, b'bbbb')])
        decoded = protocols.decode(client, server, CPORT, SPORT)
        self.assertTrue(decoded['reconstruction_ambiguous'])


class GapDoesNotSwallowDataTests(TestCase):
    """
    A decoder that reads only up to the first gap reports a shorter session
    than took place — and reports it with no indication that it did.
    """

    def test_commands_after_a_gap_are_still_decoded(self):
        client, server = run([
            syn(), synack(),
            c2s(0, b'USER rakesh\r\n'),
            # 13..29 never captured
            c2s(30, b'RETR customer-list.csv\r\n'),
        ])
        decoded = protocols.decode(client, server, CPORT, SPORT)

        self.assertEqual(decoded['files_transferred'], ['customer-list.csv'])
        self.assertFalse(decoded['reconstruction_complete'])

    def test_a_line_is_never_spliced_across_a_gap(self):
        """
        Joining the tail of one run to the head of the next would invent a
        command nobody sent.
        """
        client, server = run([
            syn(), synack(),
            c2s(0, b'USER rak'),
            c2s(40, b'esh\r\nQUIT\r\n'),
        ])
        decoded = protocols.decode(client, server, CPORT, SPORT)

        self.assertNotIn('rakesh', decoded['accounts_used'])
        self.assertIn('QUIT', [e.get('command') for e in decoded['events']])


class TranscriptEndpointTests(TestCase):
    """
    The permission boundary, which is the security-relevant claim here.

    Every other read in this API is metadata and is open to a records viewer.
    A transcript is the substance of a communication, and reading it is a
    privileged act even though the verb is GET.
    """

    def setUp(self):
        import tempfile
        from pathlib import Path

        from django.test import override_settings
        from rest_framework.test import APIClient
        from scapy.utils import wrpcap

        from accounts.models import User
        from evidence.service import ingest_evidence
        from .models import CaptureSession, Flow

        self.client = APIClient()
        self.viewer = User.objects.create_user(
            username='v', password='x', badge_id='TV-1',
            role=User.Role.VIEWER, is_approved=True,
        )
        self.investigator = User.objects.create_user(
            username='i', password='x', badge_id='TI-1',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )

        tmp = Path(tempfile.mkdtemp())
        pcap = tmp / 'ftp.pcap'
        wrpcap(str(pcap), [syn(), synack(),
                           s2c(0, b'220 ready\r\n'),
                           c2s(0, b'USER rakesh\r\n'),
                           c2s(13, b'PASS hunter2\r\n')])
        with override_settings(EVIDENCE_ROOT=tmp / 'store'):
            self.record = ingest_evidence(pcap, exhibit_number='TR-1',
                                          collected_by=self.investigator)

        self.session = CaptureSession.objects.create(
            name='transcript', evidence=self.record,
        )
        from django.utils import timezone
        now = timezone.now()
        self.flow = Flow.objects.create(
            session=self.session, src_ip=CLIENT, dst_ip=SERVER,
            src_port=CPORT, dst_port=SPORT, protocol='TCP',
            first_seen=now, last_seen=now,
        )

    def test_a_viewer_is_refused_and_told_why(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.get(f'/api/flows/{self.flow.id}/transcript/')
        self.assertEqual(response.status_code, 403)
        self.assertIn('Investigator clearance', str(response.data))

    def test_an_investigator_gets_the_conversation_back(self):
        self.client.force_authenticate(self.investigator)
        response = self.client.get(f'/api/flows/{self.flow.id}/transcript/')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['protocol'], 'ftp')
        self.assertEqual(response.data['accounts_used'], ['rakesh'])
        self.assertEqual(response.data['reassembly_policy'], 'first-arrival')

    def test_reading_a_conversation_is_recorded_against_the_exhibit(self):
        from evidence.models import CustodyEvent

        self.client.force_authenticate(self.investigator)
        self.client.get(f'/api/flows/{self.flow.id}/transcript/')

        last = self.record.custody_events.order_by('-sequence').first()
        self.assertEqual(last.action, CustodyEvent.Action.VIEWED)
        self.assertIn('Reconstructed the conversation', last.detail)
        self.assertEqual(last.actor, self.investigator)

    def test_a_session_with_no_exhibit_behind_it_is_refused_clearly(self):
        from .models import CaptureSession, Flow
        from django.utils import timezone

        loose = CaptureSession.objects.create(name='no-exhibit')
        now = timezone.now()
        flow = Flow.objects.create(
            session=loose, src_ip=CLIENT, dst_ip=SERVER,
            src_port=CPORT, dst_port=SPORT, protocol='TCP',
            first_seen=now, last_seen=now,
        )
        self.client.force_authenticate(self.investigator)
        response = self.client.get(f'/api/flows/{flow.id}/transcript/')

        self.assertEqual(response.status_code, 409)
        self.assertIn('no sealed exhibit', str(response.data['detail']))

    def test_a_udp_flow_is_refused_rather_than_reassembled(self):
        from .models import Flow
        from django.utils import timezone

        now = timezone.now()
        udp = Flow.objects.create(
            session=self.session, src_ip=CLIENT, dst_ip=SERVER,
            src_port=CPORT, dst_port=53, protocol='UDP',
            first_seen=now, last_seen=now,
        )
        self.client.force_authenticate(self.investigator)
        response = self.client.get(f'/api/flows/{udp.id}/transcript/')

        self.assertEqual(response.status_code, 400)
        self.assertIn('UDP', str(response.data['detail']))


class FastReaderAgreesWithScapyTests(TestCase):
    """
    The header parser exists for speed. It is only worth having if it reads the
    same bytes a full dissector does, so this writes real captures and compares
    the two paths field for field.
    """

    def _both_ways(self, packets, four_tuple=None):
        import tempfile
        from pathlib import Path

        from scapy.utils import RawPcapReader, wrpcap

        four_tuple = four_tuple or TUPLE
        path = Path(tempfile.mkdtemp()) / 'compare.pcap'
        wrpcap(str(path), packets)

        via_scapy = reassembly.reassemble(list(enumerate(packets, start=1)), four_tuple)

        records = []
        with RawPcapReader(str(path)) as reader:
            for index, (raw, _meta) in enumerate(reader, start=1):
                record = reassembly._parse_tcp(raw, reader.linktype, index)
                if record is not None:
                    records.append(record)
        via_headers = reassembly.reassemble_records(records, four_tuple)
        return via_scapy, via_headers

    def _assert_same(self, a, b):
        for scapy_stream, header_stream in zip(a, b):
            self.assertEqual(scapy_stream.runs, header_stream.runs)
            self.assertEqual(scapy_stream.bytes_recovered, header_stream.bytes_recovered)
            self.assertEqual(len(scapy_stream.gaps), len(header_stream.gaps))
            self.assertEqual(len(scapy_stream.conflicts), len(header_stream.conflicts))
            self.assertEqual(scapy_stream.started_mid_stream,
                             header_stream.started_mid_stream)

    def test_a_clean_conversation_reads_identically(self):
        self._assert_same(*self._both_ways([
            syn(), synack(),
            s2c(0, b'220 ready\r\n'),
            c2s(0, b'USER rakesh\r\n'),
            c2s(13, b'PASS hunter2\r\n'),
        ]))

    def test_a_conversation_with_a_gap_reads_identically(self):
        self._assert_same(*self._both_ways([
            syn(), synack(), c2s(0, b'AAAA'), c2s(40, b'BBBB'),
        ]))

    def test_ethernet_padding_is_not_mistaken_for_payload(self):
        """
        Ethernet pads frames to 60 bytes. Taking payload length from the frame
        rather than from the IP header appends those zeros to the stream, which
        looks like real data and corrupts everything after it.
        """
        from scapy.all import Ether

        # Padding is applied by the NIC, not by scapy, so the frame is built
        # and padded by hand — otherwise this test would pass without ever
        # exercising the thing it names.
        frame = bytes(Ether() / c2s(0, b'ABC'))
        padded = frame + b'\x00' * (60 - len(frame))
        self.assertEqual(len(padded), 60)

        record = reassembly._parse_tcp(padded, reassembly.LINKTYPE_ETHERNET, 1)

        self.assertEqual(record.payload, b'ABC',
                         'trailing Ethernet padding was appended to the stream')

    def test_a_vlan_tagged_frame_is_stripped(self):
        import tempfile
        from pathlib import Path

        from scapy.all import Dot1Q, Ether
        from scapy.utils import RawPcapReader, wrpcap

        path = Path(tempfile.mkdtemp()) / 'vlan.pcap'
        wrpcap(str(path), [Ether() / Dot1Q(vlan=42) / c2s(0, b'TAGGED')])

        with RawPcapReader(str(path)) as reader:
            raw, _ = next(iter(reader))
            record = reassembly._parse_tcp(raw, reader.linktype, 1)

        self.assertIsNotNone(record, 'VLAN tag was not stripped')
        self.assertEqual(record.payload, b'TAGGED')
        self.assertEqual(record.src, CLIENT)


class OrientationTests(TestCase):
    """
    A flow's src_ip is whichever address appeared first, which for traffic seen
    from the server side is the server. A transcript oriented on it shows the
    server issuing the client's commands — wrong, and wrong silently.
    """

    def _flow(self, **kwargs):
        from django.utils import timezone

        from .models import CaptureSession, Flow

        session = CaptureSession.objects.create(name='orient')
        now = timezone.now()
        defaults = dict(
            session=session, src_ip=SERVER, dst_ip=CLIENT,
            src_port=SPORT, dst_port=CPORT, protocol='TCP',
            first_seen=now, last_seen=now,
        )
        defaults.update(kwargs)
        return Flow.objects.create(**defaults)

    def test_the_recorded_initiator_decides_which_side_is_the_client(self):
        flow = self._flow(initiator_ip=CLIENT, initiator_port=CPORT,
                          initiator_confirmed=True)
        self.assertEqual(reassembly.conversation_endpoints(flow),
                         (CLIENT, CPORT, SERVER, SPORT))

    def test_an_unconfirmed_initiator_falls_back_to_capture_order(self):
        """
        Guessing would be worse. Capture order is at least a stated rule, and
        the transcript says protocol identification is an inference anyway.
        """
        flow = self._flow(initiator_confirmed=False)
        self.assertEqual(reassembly.conversation_endpoints(flow),
                         (SERVER, SPORT, CLIENT, CPORT))

    def test_an_initiator_already_on_the_src_side_is_left_alone(self):
        flow = self._flow(src_ip=CLIENT, dst_ip=SERVER, src_port=CPORT,
                          dst_port=SPORT, initiator_ip=CLIENT,
                          initiator_port=CPORT, initiator_confirmed=True)
        self.assertEqual(reassembly.conversation_endpoints(flow),
                         (CLIENT, CPORT, SERVER, SPORT))
