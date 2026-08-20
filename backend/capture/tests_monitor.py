"""
Tests over live monitoring as reached from the browser.

The monitoring loop itself is covered by `tests_live_monitor.py`. What is
tested here is the supervisor around it — the part that decides whether the
feature is honest:

  that starting is refused, with a reason, on a box that cannot capture
  (scapy without CAP_NET_RAW sniffs nothing and reports no error, which on a
  demonstration is a console that looks alive and is deaf);

  that two monitors cannot run at once, because two sniffers on one interface
  raise two findings for one event;

  that the status says how *fresh* its numbers are, because a stalled capture
  leaves a plausible packet count frozen in place;

  and that it says where an alert would go before one is raised, rather than
  leaving an operator to discover an unconfigured sink from an empty inbox.
"""

from unittest.mock import patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import User

from . import monitor


class MonitorSupervisorTests(TestCase):
    def setUp(self):
        monitor._state = None

    def tearDown(self):
        monitor._state = None

    def test_a_box_that_cannot_capture_is_refused_with_the_reason(self):
        with patch('capture.privileges.can_capture',
                   return_value=(False, 'CAP_NET_RAW is not held by this process.')):
            with self.assertRaises(monitor.MonitorRefused) as caught:
                monitor.start(interface='eth0')
        self.assertIn('CAP_NET_RAW', str(caught.exception))

    def test_nothing_started_reports_that_plainly(self):
        state = monitor.status()
        self.assertFalse(state['running'])
        self.assertFalse(state['ever_run'])
        self.assertIn('No live monitor has been started', state['note'])

    def test_a_second_monitor_is_refused_while_one_runs(self):
        """
        Two sniffers on one interface each see the traffic, write two sets of
        flows and raise two findings for one event — and the alert count an
        officer is reading becomes a number with no meaning.
        """
        started = {}

        def never_ending(**kwargs):
            kwargs['on_session'](_FakeSession())
            started['go'] = True
            while not kwargs['should_stop']():
                import time
                time.sleep(0.02)

        with patch('capture.privileges.can_capture', return_value=(True, '')), \
             patch('capture.service.run_live_capture', side_effect=never_ending):
            monitor.start(interface='eth0')
            for _ in range(100):
                if started.get('go'):
                    break
                import time
                time.sleep(0.02)

            with self.assertRaises(monitor.MonitorBusy) as caught:
                monitor.start(interface='eth0')
            self.assertIn('already running', str(caught.exception))
            monitor.stop(timeout=5)

    def test_the_window_is_clamped_to_a_range_that_can_work(self):
        """
        Below five seconds the loop spends longer re-deriving the session than
        watching the wire, and the findings that matter are claims about a time
        series a five-second slice cannot support.
        """
        with patch('capture.privileges.can_capture', return_value=(True, '')), \
             patch('capture.service.run_live_capture'):
            state = monitor.start(interface='eth0', window_seconds=1)
            self.assertEqual(state['window_seconds'], monitor.MIN_WINDOW)
            monitor._state = None

            state = monitor.start(interface='eth0', window_seconds=99999)
            self.assertEqual(state['window_seconds'], monitor.MAX_WINDOW)

    def test_the_status_says_how_fresh_its_numbers_are(self):
        """
        A stalled capture leaves a plausible packet count frozen in place.
        Without the freshness of the read, nothing distinguishes it from a
        quiet network.
        """
        with patch('capture.privileges.can_capture', return_value=(True, '')), \
             patch('capture.service.run_live_capture'):
            monitor.start(interface='eth0')

        monitor._record_window({
            'window': 1, 'packets': 120, 'flows': 8,
            'findings_total': 2, 'findings_new': 2,
            'new': ['Periodic callback'], 'alerts': [],
        })
        state = monitor.status()
        self.assertEqual(state['packets'], 120)
        self.assertIsNotNone(state['last_window_at'])
        self.assertIsNotNone(state['seconds_since_window'])

    def test_delivery_outcomes_are_counted_separately_from_attempts(self):
        """
        An alert nobody received that the system believes it sent is worse than
        no alerting at all, so the two numbers are never collapsed into one.
        """
        with patch('capture.privileges.can_capture', return_value=(True, '')), \
             patch('capture.service.run_live_capture'):
            monitor.start(interface='eth0')

        monitor._record_window({
            'window': 1, 'packets': 10, 'flows': 1,
            'findings_total': 3, 'findings_new': 3, 'new': [],
            'alerts': [
                {'ok': True, 'sink': 'syslog', 'detail': 'sent'},
                {'ok': False, 'sink': 'webhook', 'detail': 'connection refused'},
            ],
        })
        state = monitor.status()
        self.assertEqual(state['alerts_attempted'], 2)
        self.assertEqual(state['alerts_delivered'], 1)
        self.assertEqual(len(state['deliveries']), 2)

    @override_settings(ALERT_SYSLOG_HOST='', ALERT_WEBHOOK_URL='')
    def test_no_sink_configured_is_stated_as_correct_not_as_a_fault(self):
        sinks = monitor._describe_sinks()
        self.assertEqual(sinks['configured'], 0)
        self.assertIn('correct setting, not a fault', sinks['note'])

    @override_settings(ALERT_SYSLOG_HOST='10.0.0.9', ALERT_SYSLOG_PORT=514,
                       ALERT_WEBHOOK_URL='')
    def test_a_configured_sink_is_named_before_an_alert_is_raised(self):
        sinks = monitor._describe_sinks()
        self.assertEqual(sinks['configured'], 1)
        self.assertEqual(sinks['sinks'][0]['kind'], 'syslog')
        self.assertIn('10.0.0.9', sinks['sinks'][0]['target'])


class _FakeSession:
    id = 1
    name = 'live'


class MonitorEndpointTests(TestCase):
    def setUp(self):
        monitor._state = None
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='GJ-M1', department='Cyber',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.viewer = User.objects.create_user(
            username='rec', password='x', badge_id='GJ-M2', department='Records',
            role=User.Role.VIEWER, is_approved=True,
        )

    def tearDown(self):
        monitor._state = None

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def test_anyone_approved_may_read_whether_the_box_is_watching(self):
        response = self._client(self.viewer).get('/api/sessions/monitor/')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['running'])

    def test_a_viewer_cannot_start_a_capture(self):
        """A capture writes evidence, so it takes the clearance every other
        evidence-writing act takes."""
        response = self._client(self.viewer).post(
            '/api/sessions/monitor/',
            {'action': 'start', 'interface': 'eth0'}, format='json')
        self.assertEqual(response.status_code, 403)

    def test_starting_without_an_interface_is_refused(self):
        response = self._client(self.officer).post(
            '/api/sessions/monitor/', {'action': 'start'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_a_box_without_capture_privileges_answers_412_not_500(self):
        """
        Not a server error — the box simply cannot capture, and the officer
        needs the reason rather than a stack trace.
        """
        with patch('capture.privileges.can_capture',
                   return_value=(False, 'CAP_NET_RAW is not held.')):
            response = self._client(self.officer).post(
                '/api/sessions/monitor/',
                {'action': 'start', 'interface': 'eth0'}, format='json')
        self.assertEqual(response.status_code, 412)
        self.assertIn('CAP_NET_RAW', response.json()['detail'])

    def test_an_unknown_action_is_refused(self):
        response = self._client(self.officer).post(
            '/api/sessions/monitor/', {'action': 'pause'}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_the_interface_list_says_whether_capture_is_possible_at_all(self):
        response = self._client(self.officer).get('/api/sessions/interfaces/')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertIn('interfaces', body)
        self.assertIn('can_capture', body)
