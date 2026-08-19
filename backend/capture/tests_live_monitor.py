"""
Tests for live monitoring — detection while the capture is still running.

The property under test is the one that decides whether an operator keeps the
alert channel switched on: a finding is announced when it first appears and
not again on every subsequent window. An alerting system that repeats itself
every thirty seconds gets muted within a shift, and a muted channel catches
nothing.

Scapy's sniffer is replaced with one that replays packets from a list. Sniffing
a real interface needs CAP_NET_RAW and an interface with traffic on it, neither
of which a test suite should assume.
"""

import time
from unittest import mock

from django.test import TestCase, override_settings
from scapy.layers.inet import IP, TCP

from . import service
from .models import CaptureSession, Detection, Flow
from .processor import FlowAggregator


class FakeSniffer:
    """
    Stands in for scapy's AsyncSniffer.

    Feeds its packets to the callback a few at a time on each `deliver()`, so a
    test can simulate traffic arriving between windows rather than all at once.
    """

    instances = []

    def __init__(self, **kwargs):
        self.prn = kwargs['prn']
        self.started = False
        self.stopped = False
        FakeSniffer.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def deliver(self, packets):
        for packet in packets:
            self.prn(packet)


def scan_packets(ports, start=0.0, src='203.0.113.9', dst='10.0.0.5'):
    """
    A half-open port scan from outside the monitored network.

    Chosen over a beacon fixture because it is the cheapest rule to trip
    deterministically: scan_unique_ports is 25 for an external source, against
    beacon_min_connections of 23 spread over a periodic time series. This test
    is about the monitoring loop, not about the detector.
    """
    packets = []
    for i in range(ports):
        packet = IP(src=src, dst=dst) / TCP(sport=50000 + i, dport=1 + i, flags='S')
        packet.time = start + i * 0.01
        packets.append(packet)
    return packets


class AggregatorThreadSafetyTests(TestCase):
    def test_the_plain_aggregator_pays_for_no_lock(self):
        """Reading a multi-gigabyte PCAP must not lock once per packet."""
        aggregator = FlowAggregator()
        self.assertNotIsInstance(aggregator._lock, type(FlowAggregator(thread_safe=True)._lock))

    def test_finalize_does_not_consume_the_accumulated_state(self):
        """
        Live monitoring calls finalize() every window on a session that is
        still growing. If it drained the aggregator, each window would report
        only its own traffic and beaconing would never be detectable.
        """
        aggregator = FlowAggregator(thread_safe=True)
        for packet in scan_packets(6):
            aggregator.process(packet)

        first, _ = aggregator.finalize()
        second, _ = aggregator.finalize()

        self.assertTrue(first)
        self.assertEqual(len(first), len(second))
        self.assertEqual(aggregator.total_packets, 6)


@override_settings(ALERT_MIN_SEVERITY='low')
class MonitorLoopTests(TestCase):
    def setUp(self):
        FakeSniffer.instances.clear()
        self.windows = []
        self.dispatched = []

    def _run(self, deliveries, window_seconds=0.01, duration=None):
        """
        Drive the loop with `deliveries` — one list of packets per window.

        Real time is not waited on: sleep is stubbed, and the packets for the
        next window are handed to the fake sniffer as the loop sleeps.
        """
        pending = list(deliveries)
        duration = duration if duration is not None else len(deliveries) * window_seconds

        def fake_sleep(_seconds):
            if pending:
                FakeSniffer.instances[-1].deliver(pending.pop(0))

        clock = {'now': 0.0}

        def fake_monotonic():
            clock['now'] += window_seconds
            return clock['now']

        def record(finding, session=None, observer=None):
            self.dispatched.append([f.title for f in finding])
            return []

        with mock.patch.object(service, 'AsyncSniffer', FakeSniffer, create=True), \
             mock.patch('scapy.sendrecv.AsyncSniffer', FakeSniffer), \
             mock.patch('time.sleep', fake_sleep), \
             mock.patch('time.monotonic', fake_monotonic), \
             mock.patch('capture.alerting.dispatch', side_effect=record):
            return service.run_live_capture(
                interface='lo', duration=duration, window_seconds=window_seconds,
                home_net='10.0.0.0/8', name='monitor-test',
                on_window=self.windows.append,
            )

    def test_findings_appear_while_the_capture_is_still_running(self):
        """
        The whole point. A recording that is analysed at the end reports
        nothing until it ends.
        """
        self._run([scan_packets(40), scan_packets(10, start=100.0)])

        self.assertTrue(self.windows, 'no window closed')
        self.assertTrue(
            any(w['findings_total'] > 0 for w in self.windows),
            'no finding was made before the capture finished',
        )

    def test_a_finding_is_alerted_once_and_not_re_announced(self):
        """
        The property that keeps the channel switched on. Re-announcing the same
        beacon every window is how an operator learns to ignore it.
        """
        self._run([scan_packets(40), [], []])

        announced = [title for batch in self.dispatched for title in batch]
        self.assertEqual(len(announced), len(set(announced)),
                         f'a finding was announced more than once: {announced}')

    def test_each_window_reports_what_it_saw(self):
        self._run([scan_packets(30), scan_packets(5, start=100.0)])

        self.assertTrue(self.windows)
        for window in self.windows:
            self.assertIn('packets', window)
            self.assertIn('findings_total', window)
            self.assertIn('findings_new', window)
            self.assertGreater(window['packets'], 0)

    def test_flows_are_replaced_each_window_not_duplicated(self):
        """
        The aggregator holds the whole session, so appending its output every
        window would multiply every flow by the number of windows.

        Traffic arrives only in the first window; the count must then hold
        steady rather than climbing. Comparing 5-tuples would not show this —
        the same tuple seen again after an idle gap is legitimately a second
        flow, so uniqueness is the wrong test.
        """
        session, _ = self._run([scan_packets(20), [], []])

        counts = [w['flows'] for w in self.windows]
        self.assertGreater(counts[0], 0)
        self.assertEqual(len(set(counts)), 1,
                         f'flow count changed with no new traffic: {counts}')
        self.assertEqual(Flow.objects.filter(session=session).count(), counts[0])

    def test_the_sniffer_is_stopped_when_the_capture_ends(self):
        """An abandoned sniffer thread keeps writing into a finished session."""
        self._run([scan_packets(4)])
        self.assertTrue(FakeSniffer.instances[-1].stopped)

    def test_recording_mode_is_unchanged_when_no_window_is_given(self):
        """
        Monitoring is opt-in. Without --window the command must behave exactly
        as it did, because that is the path the evidence workflow uses.
        """
        with mock.patch.object(service, 'sniff') as sniff:
            session, _ = service.run_live_capture(interface='lo', duration=1)
        self.assertTrue(sniff.called)
        self.assertEqual(session.source_type, CaptureSession.Source.LIVE)


class FingerprintTests(TestCase):
    def test_a_finding_is_identified_by_its_claim_not_its_row(self):
        """
        Each analysis pass rewrites the rows, so a database id changes every
        window while the claim stays the same. Matching on the id would alert
        every time.
        """
        session = CaptureSession.objects.create(name='fp')
        common = dict(session=session, rule_id='C2_BEACON_PERIODIC',
                      severity='high', category='c2', rationale='r',
                      subject_ip='10.0.0.5', title='Periodic callback to X')
        first = Detection.objects.create(**common)
        second = Detection.objects.create(**common)

        self.assertNotEqual(first.id, second.id)
        self.assertEqual(service._fingerprint(first), service._fingerprint(second))
