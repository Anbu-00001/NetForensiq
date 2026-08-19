"""
Tests for real-time alert delivery.

The interesting assertions are all about failure. Anyone can test that a
working socket receives bytes; what matters in an evidence system is that a
SIEM which is down does not fail an analysis, and that the system never
records an alert as delivered when it was not.
"""

import http.server
import json
import socket
import threading

from django.test import TestCase, override_settings
from . import alerting
from .models import CaptureSession, Detection


def make_detection(session, severity='critical', rule_id='C2_BEACON_PERIODIC'):
    return Detection.objects.create(
        session=session,
        rule_id=rule_id,
        severity=severity,
        title=f'{rule_id} on 10.0.0.5',
        subject_ip='10.0.0.5',
        category='c2',
        rationale='Threshold crossed.',
        evidence={'observed': 45.0, 'threshold': 60.0, 'source': 'test'},
    )


class SelectionTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(name='sel')

    @override_settings(ALERT_MIN_SEVERITY='high')
    def test_findings_below_the_floor_are_not_pushed(self):
        low = make_detection(self.session, severity='low')
        high = make_detection(self.session, severity='high')
        selected, suppressed = alerting.select([low, high])
        self.assertEqual(selected, [high])
        self.assertEqual(suppressed, 0)

    @override_settings(ALERT_MIN_SEVERITY='high')
    def test_an_unrecognised_severity_is_delivered_rather_than_dropped(self):
        """Losing a finding because someone added a severity is the wrong failure."""
        odd = make_detection(self.session, severity='catastrophic')
        selected, _ = alerting.select([odd])
        self.assertEqual(selected, [odd])

    @override_settings(ALERT_MIN_SEVERITY='low')
    def test_a_huge_batch_is_capped_and_the_remainder_is_counted(self):
        made = [make_detection(self.session, severity='low')
                for _ in range(alerting.MAX_ALERTS_PER_BATCH + 25)]
        selected, suppressed = alerting.select(made)
        self.assertEqual(len(selected), alerting.MAX_ALERTS_PER_BATCH)
        self.assertEqual(suppressed, 25)

    @override_settings(ALERT_MIN_SEVERITY='low')
    def test_a_capped_batch_keeps_the_most_serious_findings(self):
        """Truncation must not throw away the critical ones."""
        for _ in range(alerting.MAX_ALERTS_PER_BATCH):
            make_detection(self.session, severity='low')
        critical = make_detection(self.session, severity='critical')

        selected, _ = alerting.select(list(Detection.objects.all()))

        self.assertIn(critical, selected)


class NoSinkTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(name='quiet')

    def test_no_configured_sink_means_no_attempt_and_no_error(self):
        """
        An air-gapped workstation has nothing to alert. Silence is correct
        behaviour, not a misconfiguration to warn about.
        """
        make_detection(self.session)
        self.assertEqual(alerting.configured_sinks(), [])
        self.assertEqual(alerting.dispatch(Detection.objects.all()), [])


@override_settings(ALERT_MIN_SEVERITY='low')
class SyslogDeliveryTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(name='syslog')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(3)
        self.port = self.sock.getsockname()[1]

    def tearDown(self):
        self.sock.close()

    def test_a_finding_arrives_as_rfc5424(self):
        make_detection(self.session)
        with override_settings(ALERT_SYSLOG_HOST='127.0.0.1',
                               ALERT_SYSLOG_PORT=self.port,
                               ALERT_SYSLOG_PROTOCOL='udp'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)

        payload, _ = self.sock.recvfrom(65535)
        line = payload.decode()
        self.assertTrue(line.startswith('<'))
        self.assertIn('netforensiq', line)
        self.assertIn('C2_BEACON_PERIODIC', line)
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0].ok)

    def test_a_truncated_batch_sends_a_notice_saying_so(self):
        for _ in range(alerting.MAX_ALERTS_PER_BATCH + 3):
            make_detection(self.session, severity='low')

        with override_settings(ALERT_SYSLOG_HOST='127.0.0.1',
                               ALERT_SYSLOG_PORT=self.port,
                               ALERT_SYSLOG_PROTOCOL='udp'):
            alerting.dispatch(Detection.objects.all(), session=self.session)

        seen = []
        try:
            while True:
                payload, _ = self.sock.recvfrom(65535)
                seen.append(payload.decode())
        except socket.timeout:
            pass
        self.assertTrue(any('BATCH_TRUNCATED' in line for line in seen))
        self.assertTrue(any('3 further finding' in line for line in seen))


@override_settings(ALERT_MIN_SEVERITY='low')
class FailureTests(TestCase):
    """A sink that is down must not take the analysis with it."""

    def setUp(self):
        self.session = CaptureSession.objects.create(name='broken')
        make_detection(self.session)

    def test_an_unreachable_tcp_syslog_is_recorded_not_raised(self):
        # Port 1 on loopback: nothing listens, and connection is refused fast.
        with override_settings(ALERT_SYSLOG_HOST='127.0.0.1',
                               ALERT_SYSLOG_PORT=1,
                               ALERT_SYSLOG_PROTOCOL='tcp'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)

        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].ok)
        self.assertEqual(results[0].delivered, 0)
        self.assertTrue(results[0].error)

    def test_a_refused_webhook_is_recorded_not_raised(self):
        with override_settings(ALERT_WEBHOOK_URL='http://127.0.0.1:1/alerts'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)

        self.assertFalse(results[0].ok)
        self.assertIn('Error', results[0].error)

    def test_a_nonsense_webhook_scheme_is_refused_before_any_connection(self):
        with override_settings(ALERT_WEBHOOK_URL='ftp://example.invalid/alerts'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)

        self.assertFalse(results[0].ok)
        self.assertIn('Unsupported webhook scheme', results[0].error)

    def test_a_failed_delivery_never_claims_to_have_been_delivered(self):
        with override_settings(ALERT_WEBHOOK_URL='http://127.0.0.1:1/alerts'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)
        self.assertEqual(results[0].as_dict()['delivered'], 0)
        self.assertIs(results[0].as_dict()['ok'], False)


@override_settings(ALERT_MIN_SEVERITY='low')
class WebhookDeliveryTests(TestCase):
    """A real HTTP server, because urllib's behaviour is the thing under test."""

    received = []

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                WebhookDeliveryTests.received.append({
                    'body': json.loads(self.rfile.read(length)),
                    'auth': self.headers.get('Authorization'),
                })
                self.send_response(202)
                self.end_headers()

            def log_message(self, *args):
                pass

        cls.server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        super().tearDownClass()

    def setUp(self):
        WebhookDeliveryTests.received.clear()
        self.session = CaptureSession.objects.create(name='hook')
        make_detection(self.session)

    def test_the_batch_arrives_as_ecs_json(self):
        with override_settings(ALERT_WEBHOOK_URL=f'http://127.0.0.1:{self.port}/a'):
            results = alerting.dispatch(Detection.objects.all(), session=self.session)

        self.assertTrue(results[0].ok)
        body = self.received[0]['body']
        self.assertEqual(body['source'], 'netforensiq')
        self.assertEqual(body['count'], 1)
        # Elastic Common Schema, so an existing SIEM ingests it without a parser.
        self.assertIn('event', body['findings'][0])

    def test_the_receiver_is_told_how_many_were_withheld(self):
        for _ in range(alerting.MAX_ALERTS_PER_BATCH + 4):
            make_detection(self.session, severity='low')
        total = Detection.objects.count()

        with override_settings(ALERT_WEBHOOK_URL=f'http://127.0.0.1:{self.port}/a'):
            alerting.dispatch(Detection.objects.all(), session=self.session)

        body = self.received[0]['body']
        self.assertEqual(body['count'], alerting.MAX_ALERTS_PER_BATCH)
        # Every finding is accounted for: sent plus withheld equals the set.
        self.assertEqual(body['count'] + body['withheld_over_batch_limit'], total)

    def test_a_configured_token_is_sent_as_a_bearer_header(self):
        with override_settings(ALERT_WEBHOOK_URL=f'http://127.0.0.1:{self.port}/a',
                               ALERT_WEBHOOK_TOKEN='s3cret'):
            alerting.dispatch(Detection.objects.all(), session=self.session)
        self.assertEqual(self.received[0]['auth'], 'Bearer s3cret')

    def test_no_token_means_no_authorization_header(self):
        with override_settings(ALERT_WEBHOOK_URL=f'http://127.0.0.1:{self.port}/a',
                               ALERT_WEBHOOK_TOKEN=''):
            alerting.dispatch(Detection.objects.all(), session=self.session)
        self.assertIsNone(self.received[0]['auth'])
