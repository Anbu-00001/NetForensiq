# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Writing a capture out in pieces must not change what the capture says.

The method is the one `tests_equivalence.py` sets out: keep the slow, obviously
correct thing as an oracle, and let the fast thing ship only where it agrees
byte for byte. Here the oracle is the aggregator reading a whole file and
handing over everything at the end — what every import did until now — and the
candidate is the same aggregator draining flows as it goes.

What could go wrong, and is therefore tested
============================================
A flow written out early is a flow that is no longer in memory to be added to.
`_starts_new_flow` attaches a packet to an existing flow if it arrives within
that protocol's inactivity timeout of the flow's last packet, so writing one
out too early would split one conversation into two — a quiet change to the
duration, interval and beacon-period figures that findings rest on.

`drain` therefore keeps a flow for STREAM_MARGIN_SECONDS past its timeout, and
these tests exercise the boundary from both sides: a late packet inside the
margin must still find its flow, and a capture whose packets are more out of
order than the margin must be recognised rather than quietly mis-analysed.
"""

import os
import tempfile
from pathlib import Path
from unittest import mock

from django.core.management import call_command
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, TCP, UDP, wrpcap

from . import importer
from .models import CaptureSession, DNSRecord, Flow
from .processor import FlowAggregator, STREAM_MARGIN_SECONDS
from .service import TICK_PACKETS


def _at(packet, moment):
    packet.time = moment
    return packet


def _tcp(src, dst, sport, dport, moment, flags='PA'):
    return _at(Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags),
               moment)


def _write(packets, name='streaming.pcap'):
    directory = tempfile.mkdtemp(prefix='netforensiq-streaming-')
    path = Path(directory) / name
    wrpcap(str(path), packets)
    return str(path)


def _read_whole(path):
    """The oracle: everything held until the end, as imports used to work."""
    aggregator = FlowAggregator()
    from .service import _read_into
    _read_into(aggregator, path)
    flows, dns = aggregator.finalize()
    return aggregator, flows, dns


def _read_streaming(path, every=None):
    """The candidate: flows handed over as they can no longer change."""
    aggregator = FlowAggregator()
    from .service import _read_into
    drained = []
    batches = []

    def tick():
        batch = aggregator.drain()
        batches.append(len(batch))
        drained.extend(batch)

    if every is None:
        _read_into(aggregator, path, on_tick=tick)
    else:
        # A tick every `every` packets, for files far smaller than TICK_PACKETS.
        count = {'n': 0}
        original = aggregator.process_frame

        def counted(*args, **kwargs):
            original(*args, **kwargs)
            count['n'] += 1
            if count['n'] % every == 0:
                tick()

        with mock.patch.object(aggregator, 'process_frame', counted):
            _read_into(aggregator, path)

    drained.extend(aggregator.drain(force=True))
    return aggregator, drained, aggregator.dns_output(), batches


def _by_uid(records):
    return {record['_uid']: record for record in records}


class DrainEquivalenceTests(SimpleTestCase):
    """The same capture, read both ways, must produce the same flows."""

    def assert_same(self, path, every=1):
        _, whole_flows, whole_dns = _read_whole(path)
        _, streamed_flows, streamed_dns, _ = _read_streaming(path, every=every)

        self.assertEqual(len(whole_flows), len(streamed_flows),
                         'streaming changed the number of flows')
        self.assertEqual(_by_uid(whole_flows), _by_uid(streamed_flows),
                         'streaming changed a flow record')
        self.assertEqual(whole_dns, streamed_dns)
        return whole_flows

    def test_flows_that_go_idle_are_written_out_and_unchanged(self):
        """
        The case the whole change exists for: a capture long enough that early
        conversations are finished by the time the later ones are read.
        """
        packets = []
        for index in range(10):
            # Each conversation is an hour after the last, so by the end every
            # earlier one is far past its timeout.
            base = 1_700_000_000 + index * 3600
            for step in range(4):
                packets.append(_tcp('10.0.0.5', f'10.0.0.{20 + index}',
                                    40000 + index, 443, base + step))
        path = _write(packets)
        flows = self.assert_same(path)
        self.assertEqual(len(flows), 10)

        # And the point of it: memory is actually released as it goes.
        aggregator, _, _, batches = _read_streaming(path, every=4)
        self.assertGreater(sum(batches), 0,
                           'nothing was written out before the end of the file')
        self.assertEqual(aggregator.flows, {},
                         'the forced drain must leave nothing behind')

    def test_a_late_packet_inside_the_margin_still_finds_its_flow(self):
        """
        A packet that arrives out of order, but by less than the margin, must
        land in the flow it belongs to — not start a second one.
        """
        base = 1_700_000_000
        packets = [
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base),
            # Push the watermark far ahead, so the first flow is past its
            # timeout (TCP: 300 s) but inside timeout + margin.
            _tcp('10.0.0.6', '10.0.0.9', 40002, 443, base + 400),
            _tcp('10.0.0.7', '10.0.0.9', 40003, 443, base + 500),
            # Now the late one, 10 s after the first packet of flow one.
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + 10),
        ]
        path = _write(packets)
        flows = self.assert_same(path)

        first = [f for f in flows if 40001 in (f['src_port'], f['dst_port'])]
        self.assertEqual(len(first), 1, 'the late packet started a second flow')
        self.assertEqual(first[0]['packets_sent'] + first[0]['packets_received'], 2)

    def test_a_reused_port_still_starts_a_new_flow(self):
        """A fresh SYN on a tuple already carrying traffic, across a drain."""
        base = 1_700_000_000
        packets = [
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base, flags='S'),
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + 1),
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + 2, flags='S'),
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + 3),
        ]
        flows = self.assert_same(_write(packets))
        self.assertEqual(len(flows), 2)

    def test_a_dns_answer_arriving_after_its_flow_was_written_out(self):
        """
        The linking case. A query's flow can be written to the database long
        before the reply is read, and the record still has to point at it.
        """
        base = 1_700_000_000
        query = _at(Ether() / IP(src='10.0.0.5', dst='10.0.0.53')
                    / UDP(sport=51000, dport=53)
                    / DNS(id=0x4242, rd=1, qd=DNSQR(qname='c2.example.net')), base)
        # Far enough ahead that the query's flow is drained before this.
        reply = _at(Ether() / IP(src='10.0.0.53', dst='10.0.0.5')
                    / UDP(sport=53, dport=51000)
                    / DNS(id=0x4242, qr=1, qd=DNSQR(qname='c2.example.net'),
                          an=DNSRR(rrname='c2.example.net', rdata='203.0.113.9')),
                    base + 5000)
        _, _, dns = _read_whole(_write([query, reply]))
        self.assertEqual(len(dns), 1)
        self.assertEqual(dns[0]['response_ip'], '203.0.113.9')

        path = _write([query, reply])
        _, flows, streamed_dns, _ = _read_streaming(path, every=1)
        self.assertEqual(streamed_dns[0]['response_ip'], '203.0.113.9')
        self.assertIn(streamed_dns[0]['flow_uid'],
                      [f['_uid'] for f in flows])

    def test_reordering_is_measured_not_assumed(self):
        """
        The margin is only safe while packets are not more out of order than
        it. That is a property of a file, so it is measured on every import.
        """
        base = 1_700_000_000
        packets = [
            _tcp('10.0.0.5', '10.0.0.9', 40001, 443, base),
            _tcp('10.0.0.5', '10.0.0.9', 40002, 443, base + 900),
            _tcp('10.0.0.5', '10.0.0.9', 40003, 443, base + 30),
        ]
        aggregator, _, _ = _read_whole(_write(packets))
        self.assertAlmostEqual(aggregator.max_reordering, 870, places=3)
        self.assertGreater(
            aggregator.max_reordering, STREAM_MARGIN_SECONDS,
            'this capture is deliberately more out of order than the margin')

    def test_an_ordered_capture_stays_inside_the_margin(self):
        base = 1_700_000_000
        packets = [_tcp('10.0.0.5', '10.0.0.9', 40000 + i, 443, base + i)
                   for i in range(50)]
        aggregator, _, _ = _read_whole(_write(packets))
        self.assertEqual(aggregator.max_reordering, 0.0)


class StreamedImportTests(TestCase):
    """The same comparison, but through the database the officer reads."""

    def test_stored_flows_match_the_whole_file_reading(self):
        base = 1_700_000_000
        packets = []
        for index in range(12):
            moment = base + index * 3600
            packets.append(_tcp('10.0.0.5', f'10.0.0.{30 + index}',
                                41000 + index, 8080, moment, flags='S'))
            packets.append(_tcp(f'10.0.0.{30 + index}', '10.0.0.5',
                                8080, 41000 + index, moment + 1, flags='SA'))
        path = _write(packets)

        _, expected, _ = _read_whole(path)

        from .service import run_pcap_import
        session, (flows, _dns) = run_pcap_import(path, name='streamed')

        self.assertEqual(flows, len(expected))
        self.assertEqual(session.flow_count, len(expected))
        self.assertEqual(Flow.objects.filter(session=session).count(), len(expected))

        stored = {
            (f.src_ip, f.src_port, f.dst_ip, f.dst_port, f.protocol,
             f.packets_sent, f.packets_received, f.bytes_sent, f.bytes_received,
             round(f.duration_seconds, 6))
            for f in session.flows.all()
        }
        wanted = {
            (f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port'], f['protocol'],
             f['packets_sent'], f['packets_received'], f['bytes_sent'],
             f['bytes_received'], round(f['duration_seconds'], 6))
            for f in expected
        }
        self.assertEqual(stored, wanted)

    def test_dns_records_keep_their_flow_across_batches(self):
        base = 1_700_000_000
        packets = [
            _at(Ether() / IP(src='10.0.0.5', dst='10.0.0.53')
                / UDP(sport=51000, dport=53)
                / DNS(id=1, rd=1, qd=DNSQR(qname='one.example.net')), base),
            _at(Ether() / IP(src='10.0.0.5', dst='10.0.0.53')
                / UDP(sport=51001, dport=53)
                / DNS(id=2, rd=1, qd=DNSQR(qname='two.example.net')), base + 4000),
        ]
        session, _ = __import__(
            'capture.service', fromlist=['run_pcap_import']
        ).run_pcap_import(_write(packets), name='dns-batches')

        records = DNSRecord.objects.filter(session=session).order_by('query_name')
        self.assertEqual([r.query_name for r in records],
                         ['one.example.net', 'two.example.net'])
        self.assertTrue(all(r.flow_id for r in records),
                        'every DNS record must still name the flow that carried it')
        self.assertEqual(records[0].flow.dns_query_count, 1)

    def test_a_session_is_not_called_finished_until_it_is_analysed(self):
        """
        Found by measuring, not by reading: the session used to be marked
        COMPLETED as soon as the flows were written, so for the ~43 seconds
        the rules then took, a capture appeared on the dashboard as a finished
        analysis with no findings — which reads as "nothing was found".
        """
        from . import detection

        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + i)
                       for i in range(5)])

        seen = {}
        real_analyse = detection.analyse_session

        def watched(session, *args, **kwargs):
            session.refresh_from_db()
            seen['state'] = session.state
            seen['stage'] = session.progress_stage
            seen['flow_count'] = session.flow_count
            return real_analyse(session, *args, **kwargs)

        with mock.patch.object(detection, 'analyse_session', watched):
            from .service import run_pcap_import
            session, _ = run_pcap_import(path, name='not-yet-finished')

        self.assertEqual(seen['state'], CaptureSession.State.RUNNING,
                         'a session must not say completed before it is analysed')
        self.assertEqual(seen['stage'], CaptureSession.Stage.ANALYSING)
        # The counts are recorded before the rules run, because they are true
        # before the rules run — it is the verdict that is not.
        self.assertEqual(seen['flow_count'], 1)

        session.refresh_from_db()
        self.assertEqual(session.state, CaptureSession.State.COMPLETED)
        self.assertIsNotNone(session.ended_at)

    def test_progress_is_recorded_and_ends_at_done(self):
        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base + i)
                       for i in range(20)])
        from .service import run_pcap_import
        session, _ = run_pcap_import(path, name='progress')

        session.refresh_from_db()
        self.assertEqual(session.progress_stage, CaptureSession.Stage.DONE)
        self.assertEqual(session.progress_packets, 20)
        self.assertIsNotNone(session.progress_updated_at)
        self.assertEqual(session.progress_total_bytes, os.path.getsize(path))
        self.assertLessEqual(session.progress_bytes_read, session.progress_total_bytes)


class RulesDoNotHoldTheWriteLockTests(TestCase):
    """
    Detection reads for tens of seconds and writes for a fraction of one.

    Those two used to be inside one transaction, and because Django opens
    transactions with BEGIN IMMEDIATE, the reading held SQLite's single write
    lock throughout — long enough for an officer's sign-in to time out
    (research/155 s.4.1). This asserts the property directly rather than the
    timing that made it visible.
    """

    def test_a_rule_runs_outside_any_transaction(self):
        from django.db import transaction

        from . import detection

        seen = {}
        # TestCase wraps every test in a transaction, so `in_atomic_block` is
        # True whatever the code does. What can be measured is the *nesting*
        # the code adds: Django pushes a savepoint id for each atomic block it
        # opens inside another, so a rule running with the same depth as the
        # caller is a rule that no transaction was opened around.
        depth_outside = len(transaction.get_connection().savepoint_ids)

        def probe(session):
            seen['depth'] = len(transaction.get_connection().savepoint_ids)
            return []

        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base)])
        from .service import run_pcap_import
        session, _ = run_pcap_import(path, name='lock-probe')

        with mock.patch.object(detection, 'RULES', [probe]):
            detection.analyse_session(session, dispatch_alerts=False)

        self.assertIn('depth', seen, 'the probe rule never ran')
        self.assertEqual(
            seen['depth'], depth_outside,
            'detection must not hold a transaction open while the rules run')

    def test_the_writing_half_does_open_one(self):
        """The counterpart: the writes themselves are still in a transaction."""
        from django.db import transaction

        from . import detection
        from .models import Detection

        depth_outside = len(transaction.get_connection().savepoint_ids)
        seen = {}
        real_bulk_create = Detection.objects.bulk_create

        def watched(*args, **kwargs):
            seen['depth'] = len(transaction.get_connection().savepoint_ids)
            return real_bulk_create(*args, **kwargs)

        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base)])
        from .service import run_pcap_import
        session, _ = run_pcap_import(path, name='write-depth')

        with mock.patch.object(Detection.objects, 'bulk_create', watched):
            detection.analyse_session(session, dispatch_alerts=False)

        self.assertGreater(seen['depth'], depth_outside,
                           'findings must still be written inside a transaction')

    def test_findings_are_still_written_all_or_nothing(self):
        """
        Splitting the reading out must not split the writing up. A failure
        after the findings are inserted but before the flows are scored has to
        take the findings with it — a half-written analysis is a page of
        findings with no way to tell it is incomplete.
        """
        from . import detection
        from .models import Detection

        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base)])
        from .service import run_pcap_import
        session, _ = run_pcap_import(path, name='atomic-writes')
        flow = session.flows.first()

        def one_finding(_session):
            return [Detection(
                session=session, flow=flow, rule_id='test.probe',
                title='Probe finding', category='test',
                severity=Detection.Severity.HIGH, confidence=1.0,
                rationale='exists only to be rolled back', subject_ip='10.0.0.5',
            )]

        def explode(*args, **kwargs):
            raise RuntimeError('the flow scoring failed')

        before = session.detections.count()
        with mock.patch.object(detection, 'RULES', [one_finding]):
            with mock.patch.object(detection.Flow.objects, 'filter', explode):
                with self.assertRaises(RuntimeError):
                    detection.analyse_session(session, dispatch_alerts=False)

        self.assertEqual(session.detections.count(), before,
                         'a failed write must leave no findings behind')


class ImportLauncherTests(TestCase):
    """The parent/child split, without pretending a subprocess ran."""

    def test_an_in_memory_database_is_never_handed_to_a_child(self):
        """
        A child process cannot reach an in-memory SQLite database. The first
        run of this suite proved why it matters: children went looking for the
        developer's real database instead.
        """
        self.assertFalse(importer._another_process_can_reach_the_database())

    def test_the_child_command_is_the_one_that_exists(self):
        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40001, 443, base)])
        session = CaptureSession.objects.create(
            name='launch', source_type=CaptureSession.Source.PCAP,
            pcap_filename=path, state=CaptureSession.State.RUNNING,
        )

        with mock.patch.object(importer, '_another_process_can_reach_the_database',
                               return_value=True):
            with mock.patch('subprocess.Popen') as popen:
                importer.start(session)

        command = popen.call_args[0][0]
        self.assertEqual(command[1:5], ['manage.py', 'run_import', '--session',
                                        str(session.pk)])
        self.assertTrue(popen.call_args[1]['start_new_session'],
                        'the child must outlive the worker that started it')

        # And that command, run here, does the work it claims to.
        call_command('run_import', session=session.pk)
        session.refresh_from_db()
        self.assertEqual(session.state, CaptureSession.State.COMPLETED)
        self.assertEqual(session.packet_count, 1)

    def test_a_missing_capture_file_fails_the_session_with_a_reason(self):
        from django.core.management.base import CommandError

        session = CaptureSession.objects.create(
            name='gone', source_type=CaptureSession.Source.PCAP,
            pcap_filename='/nowhere/missing.pcap',
            state=CaptureSession.State.RUNNING,
        )
        with self.assertRaises(CommandError):
            call_command('run_import', session=session.pk)

        session.refresh_from_db()
        self.assertEqual(session.state, CaptureSession.State.FAILED)
        self.assertIn('not where the session says', session.error_message)


class ProgressEndpointTests(TestCase):
    """What the Import page is told while it waits."""

    def setUp(self):
        from accounts.models import User
        self.officer = User.objects.create_user(
            username='prog-officer', password='a-long-enough-password',
            badge_id='B-901', department='Cyber',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.officer)

    def _session(self, **kwargs):
        fields = dict(
            name='in-progress', source_type=CaptureSession.Source.PCAP,
            state=CaptureSession.State.RUNNING,
            progress_stage=CaptureSession.Stage.READING,
            progress_packets=120_000, progress_flows=4_000,
            progress_bytes_read=5_000_000, progress_total_bytes=20_000_000,
            progress_updated_at=timezone.now(),
        )
        fields.update(kwargs)
        return CaptureSession.objects.create(**fields)

    def test_a_running_import_reports_what_it_has_done(self):
        session = self._session()
        body = self.client.get(f'/api/sessions/{session.pk}/progress/').data
        self.assertEqual(body['state'], 'running')
        self.assertEqual(body['stage'], 'reading')
        self.assertEqual(body['stage_label'], 'Reading packets')
        self.assertEqual(body['packets_read'], 120_000)
        self.assertEqual(body['flows_written'], 4_000)
        self.assertEqual(body['percent_estimate'], 25.0)
        self.assertFalse(body['stale'])

    def test_an_import_whose_worker_vanished_is_not_reported_as_running(self):
        """
        A row that says "running" for ever is a claim that work is happening.
        """
        stale_at = timezone.now() - timezone.timedelta(
            seconds=importer.STALE_AFTER_SECONDS + 60)
        session = self._session(progress_updated_at=stale_at)

        body = self.client.get(f'/api/sessions/{session.pk}/progress/').data
        self.assertEqual(body['state'], 'failed')
        self.assertIn('stopped reporting progress', body['error_message'])
        self.assertIn('sealed in evidence', body['error_message'])

        session.refresh_from_db()
        self.assertEqual(session.state, CaptureSession.State.FAILED)

    def test_a_finished_import_reports_its_totals(self):
        session = self._session(
            state=CaptureSession.State.COMPLETED,
            progress_stage=CaptureSession.Stage.DONE,
            packet_count=500_923, flow_count=223_120,
        )
        body = self.client.get(f'/api/sessions/{session.pk}/progress/').data
        self.assertEqual(body['state'], 'completed')
        self.assertEqual(body['packet_count'], 500_923)
        self.assertEqual(body['flow_count'], 223_120)
        self.assertFalse(body['stale'])

    def test_progress_needs_a_signed_in_account(self):
        session = self._session()
        self.assertEqual(
            APIClient().get(f'/api/sessions/{session.pk}/progress/').status_code,
            401)


class TickCadenceTests(SimpleTestCase):
    """The cadence is a property of the file, not of the machine."""

    def test_the_tick_is_counted_in_packets(self):
        self.assertIsInstance(TICK_PACKETS, int)
        self.assertGreater(TICK_PACKETS, 0)

    def test_ticks_happen_at_the_same_places_every_run(self):
        base = 1_700_000_000
        path = _write([_tcp('10.0.0.5', '10.0.0.9', 40000 + i, 443, base + i * 1000)
                       for i in range(40)])
        first = _read_streaming(path, every=7)[3]
        second = _read_streaming(path, every=7)[3]
        self.assertEqual(first, second)
