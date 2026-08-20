from django.conf import settings
from django.core.cache import cache
from django.test import TestCase

# Create your tests here.
"""
Role enforcement.

Registration offers a "clearance level" and blocks self-requested admin. That
was stored and never checked: every endpoint was IsAuthenticated, so a viewer
could triage findings, re-verify exhibits and sign a Section 63 certificate.
"""

from django.test import TestCase
from rest_framework.test import APIClient

from .models import AuditLog, User


class ClearanceEnforcementTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.viewer = User.objects.create_user(
            username='viewer1', password='x', badge_id='V-1',
            department='Cyber', role=User.Role.VIEWER, is_approved=True,
        )
        self.investigator = User.objects.create_user(
            username='io1', password='x', badge_id='I-1',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.pending = User.objects.create_user(
            username='pending1', password='x', badge_id='P-1',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=False,
        )

    def test_viewer_can_read_findings(self):
        """Investigations are collaborative; a viewer who cannot see is useless."""
        self.client.force_authenticate(self.viewer)
        self.assertEqual(self.client.get('/api/detections/').status_code, 200)

    def test_viewer_cannot_triage(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post('/api/detections/1/triage/', {'status': 'dismissed'})
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_issue_a_certificate(self):
        """A Section 63 certificate is a statutory declaration."""
        self.client.force_authenticate(self.viewer)
        response = self.client.post('/api/evidence/1/certificate/', {})
        self.assertEqual(response.status_code, 403)

    def test_viewer_cannot_verify_evidence(self):
        self.client.force_authenticate(self.viewer)
        response = self.client.post('/api/evidence/1/verify/')
        self.assertEqual(response.status_code, 403)

    def test_investigator_is_not_blocked_by_role(self):
        """404 (no such exhibit) proves the role check passed; 403 would not."""
        self.client.force_authenticate(self.investigator)
        response = self.client.post('/api/evidence/999/verify/')
        self.assertEqual(response.status_code, 404)

    def test_an_unapproved_account_cannot_read_at_all(self):
        """Holding a token is not approval."""
        self.client.force_authenticate(self.pending)
        self.assertEqual(self.client.get('/api/detections/').status_code, 403)

    def test_anonymous_is_still_denied(self):
        self.assertEqual(self.client.get('/api/detections/').status_code, 401)


class LogoutTests(TestCase):
    """
    Sign-out used to be client-side only: the refresh token stayed valid for a
    day and nothing recorded that the session ended.
    """

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='io2', password='pw-for-test-1234', badge_id='I-2',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True,
        )

    def _tokens(self):
        response = self.client.post('/api/auth/login/', {
            'username': 'io2', 'password': 'pw-for-test-1234',
        }, format='json')
        self.assertEqual(response.status_code, 200, response.data)
        return response.data

    def test_logout_blacklists_the_refresh_token(self):
        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')

        response = self.client.post('/api/auth/logout/',
                                    {'refresh': tokens['refresh']}, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['token_blacklisted'])

        # The blacklisted token must no longer mint access tokens
        self.client.credentials()
        refreshed = self.client.post('/api/auth/login/refresh/',
                                     {'refresh': tokens['refresh']}, format='json')
        self.assertEqual(refreshed.status_code, 401)

    def test_logout_is_recorded_in_the_audit_log(self):
        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        self.client.post('/api/auth/logout/', {'refresh': tokens['refresh']}, format='json')

        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.LOGOUT, user=self.user).exists(),
            'signing out must leave a trace',
        )

    def test_logout_succeeds_without_a_usable_refresh_token(self):
        """The intent is to end the session; that outcome holds either way."""
        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        response = self.client.post('/api/auth/logout/', {'refresh': 'not-a-token'},
                                    format='json')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data['token_blacklisted'])

    def test_logout_stops_a_live_monitor_this_officer_started(self):
        """
        A live capture is a supervised acquisition, not a background daemon.
        If the officer who started it signs out, nobody is left to see what it
        raises — so logging out must request it to stop rather than leave it
        sniffing unattended.
        """
        from capture.models import LiveMonitorState

        LiveMonitorState.objects.update_or_create(pk=1, defaults={
            'running': True, 'started_by': self.user,
        })

        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        response = self.client.post('/api/auth/logout/',
                                    {'refresh': tokens['refresh']}, format='json')

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['monitor_stopped'])
        self.assertTrue(LiveMonitorState.load().stop_requested)

    def test_logout_leaves_another_officers_monitor_running(self):
        """One officer's logout must not stop a capture they did not start."""
        from capture.models import LiveMonitorState

        other = User.objects.create_user(
            username='io3', password='x', badge_id='I-3',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True,
        )
        LiveMonitorState.objects.update_or_create(pk=1, defaults={
            'running': True, 'started_by': other,
        })

        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        response = self.client.post('/api/auth/logout/',
                                    {'refresh': tokens['refresh']}, format='json')

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data['monitor_stopped'])
        self.assertFalse(LiveMonitorState.load().stop_requested)

    def test_logout_with_no_monitor_running_is_a_no_op(self):
        from capture.models import LiveMonitorState

        tokens = self._tokens()
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {tokens["access"]}')
        response = self.client.post('/api/auth/logout/',
                                    {'refresh': tokens['refresh']}, format='json')

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data['monitor_stopped'])
        self.assertFalse(LiveMonitorState.load().stop_requested)


class AuditTaxonomyTests(TestCase):
    """
    An audit trail whose entries all say VIEW_EVIDENCE cannot answer the
    question it exists for: which entry records the moment a finding was
    confirmed, or a certificate signed.
    """

    def test_approving_an_account_is_recorded_wherever_it_happens(self):
        """
        There is no approval endpoint — approval happens in the Django admin.
        The one administrative act that decides who may touch evidence must
        still leave a trace.
        """
        user = User.objects.create_user(
            username='pending', password='x', badge_id='B-9', department='Cyber',
        )
        self.assertFalse(
            AuditLog.objects.filter(action=AuditLog.Action.APPROVE_USER).exists()
        )

        user.is_approved = True
        user.save()

        entry = AuditLog.objects.get(action=AuditLog.Action.APPROVE_USER)
        self.assertEqual(entry.user, user)
        self.assertIn('pending', entry.detail)

    def test_approval_is_recorded_once_not_on_every_later_save(self):
        user = User.objects.create_user(
            username='approved-once', password='x', badge_id='B-8', department='Cyber',
        )
        user.is_approved = True
        user.save()
        user.department = 'Cyber Crime Branch'
        user.save()

        self.assertEqual(
            AuditLog.objects.filter(action=AuditLog.Action.APPROVE_USER).count(), 1,
        )

    def test_an_account_created_already_approved_is_recorded(self):
        User.objects.create_user(
            username='straight-in', password='x', badge_id='B-7',
            department='Cyber', is_approved=True,
        )
        self.assertEqual(
            AuditLog.objects.filter(action=AuditLog.Action.APPROVE_USER).count(), 1,
        )

    def test_every_declared_action_is_emitted_somewhere_in_the_codebase(self):
        """
        A defined-but-unused action is a promise the audit trail does not keep.
        """
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        sources = '\n'.join(
            path.read_text()
            for path in root.rglob('*.py')
            if '.venv' not in str(path) and 'migrations' not in str(path)
            and path.name != 'tests.py'
        )

        for name in AuditLog.Action.names:
            self.assertTrue(
                re.search(rf'Action\.{name}\b', sources),
                f'AuditLog.Action.{name} is declared but never written',
            )


class PublicEndpointThrottleTests(TestCase):
    """
    Three endpoints answer unauthenticated callers. Each has its own limit,
    because they fail in different ways: login leaks credentials to a guesser,
    registration floods the approval queue an administrator has to work
    through, and the status check answers "does this username hold this badge"
    for anyone who asks.
    """

    def setUp(self):
        cache.clear()

    def tearDown(self):
        cache.clear()

    def test_registration_is_throttled_on_its_own_scope(self):
        from django.conf import settings

        limit = int(
            settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['register'].split('/')[0]
        )

        accepted = 0
        for i in range(limit + 3):
            response = self.client.post('/api/auth/register/', {
                'username': f'applicant{i}',
                'password': 'a-long-enough-password',
                'badge_id': f'B-{i}',
                'department': 'Cyber',
                'role': 'investigator',
            }, content_type='application/json')
            if response.status_code == 429:
                break
            accepted += 1

        self.assertLessEqual(
            accepted, limit,
            'registration must stop accepting once its hourly limit is reached',
        )
        self.assertEqual(response.status_code, 429)

    def test_the_status_check_is_throttled(self):
        from django.conf import settings

        limit = int(
            settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['approval_status']
            .split('/')[0]
        )

        for _ in range(limit + 2):
            response = self.client.post('/api/auth/status/', {
                'username': 'nobody', 'badge_id': 'B-0',
            }, content_type='application/json')
            if response.status_code == 429:
                break

        self.assertEqual(
            response.status_code, 429,
            'an unauthenticated oracle must be limited by volume',
        )

    def test_the_status_check_answers_identically_for_every_kind_of_miss(self):
        """
        A different message for "no such user" and "wrong badge" would turn
        this into a username enumerator.
        """
        User.objects.create_user(
            username='real', password='x', badge_id='B-REAL', department='Cyber',
        )

        replies = set()
        for username, badge in (
            ('real', 'B-WRONG'), ('ghost', 'B-REAL'), ('ghost', 'B-WRONG'),
        ):
            response = self.client.post('/api/auth/status/', {
                'username': username, 'badge_id': badge,
            }, content_type='application/json')
            replies.add((response.status_code, response.json().get('detail')))

        self.assertEqual(
            len(replies), 1,
            f'the three misses must be indistinguishable, got {replies}',
        )


class ApprovalQueueTests(TestCase):
    """
    Approving an officer decides who may touch evidence. It was only possible
    through the Django admin — the one act the application cared most about
    happening outside the application.
    """

    def setUp(self):
        cache.clear()
        self.admin = User.objects.create_user(
            username='commander', password='x', badge_id='A-1',
            department='Cyber', role=User.Role.ADMIN, is_approved=True,
        )
        self.investigator = User.objects.create_user(
            username='io', password='x', badge_id='I-1',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.applicant = User.objects.create_user(
            username='applicant', password='x', badge_id='P-1', department='Cyber',
        )
        self.client = APIClient()

    def tearDown(self):
        cache.clear()

    def test_an_administrator_sees_the_queue(self):
        self.client.force_authenticate(self.admin)
        response = self.client.get('/api/auth/accounts/pending/')

        self.assertEqual(response.status_code, 200)
        usernames = [u['username'] for u in response.data['pending']]
        self.assertIn('applicant', usernames)
        self.assertNotIn('io', usernames)

    def test_an_investigator_cannot_see_or_act_on_the_queue(self):
        self.client.force_authenticate(self.investigator)
        self.assertEqual(self.client.get('/api/auth/accounts/pending/').status_code, 403)
        self.assertEqual(
            self.client.post('/api/auth/accounts/pending/',
                             {'username': 'applicant', 'decision': 'approve'},
                             format='json').status_code,
            403,
        )

    def test_approving_records_who_decided_and_when(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            '/api/auth/accounts/pending/',
            {'username': 'applicant', 'decision': 'approve'}, format='json',
        )
        self.assertEqual(response.status_code, 200)

        self.applicant.refresh_from_db()
        self.assertTrue(self.applicant.is_approved)
        self.assertEqual(self.applicant.approved_by, self.admin)
        self.assertIsNotNone(self.applicant.approved_at)

        # The audit entry comes from the model signal, so it is written the
        # same way whether the decision was made here or in the Django admin.
        self.assertTrue(
            AuditLog.objects.filter(
                action=AuditLog.Action.APPROVE_USER,
                username_attempted='applicant',
            ).exists()
        )

    def test_rejecting_deactivates_and_is_recorded_rather_than_deleting(self):
        self.client.force_authenticate(self.admin)
        self.client.post('/api/auth/accounts/pending/',
                         {'username': 'applicant', 'decision': 'reject'}, format='json')

        self.applicant.refresh_from_db()
        self.assertFalse(self.applicant.is_active)
        self.assertFalse(self.applicant.is_approved)
        # The application, and the decision on it, stay on the record.
        self.assertTrue(User.objects.filter(username='applicant').exists())

    def test_an_account_cannot_approve_itself(self):
        lone = User.objects.create_user(
            username='selfstarter', password='x', badge_id='S-1',
            department='Cyber', role=User.Role.ADMIN,
        )
        self.client.force_authenticate(lone)
        response = self.client.post(
            '/api/auth/accounts/pending/',
            {'username': 'selfstarter', 'decision': 'approve'}, format='json',
        )
        self.assertEqual(response.status_code, 409)

    def test_an_unknown_decision_is_refused(self):
        self.client.force_authenticate(self.admin)
        response = self.client.post(
            '/api/auth/accounts/pending/',
            {'username': 'applicant', 'decision': 'maybe'}, format='json',
        )
        self.assertEqual(response.status_code, 400)


class SignInIsRecordedTests(TestCase):
    """
    The sign-in page states, on screen, that attempts are recorded with a
    timestamp, a username and a source address. These tests exist because that
    sentence is a claim, and a claim on a screen an officer reads is worth no
    less than one in a certificate.
    """

    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='officer', password='a-long-enough-password',
            badge_id='B-901', department='Cyber', role=User.Role.INVESTIGATOR,
            is_approved=True,
        )

    def tearDown(self):
        cache.clear()

    def _login(self, password):
        return self.client.post(
            '/api/auth/login/',
            {'username': 'officer', 'password': password},
            content_type='application/json',
        )

    def test_a_rejected_password_is_recorded_with_all_three_facts(self):
        self._login('wrong-password')

        entry = AuditLog.objects.filter(action=AuditLog.Action.LOGIN_FAILED).latest('timestamp')
        self.assertEqual(entry.username_attempted, 'officer')
        self.assertTrue(entry.ip_address, 'source address must be recorded')
        self.assertIsNotNone(entry.timestamp)
        # The row must not name the account as the actor: nobody has proved
        # they are that officer, which is the entire point of the failure.
        self.assertIsNone(entry.user)

    def test_the_per_account_failure_counter_advances(self):
        """
        `failed_login_attempts` was reset to zero on success and incremented
        nowhere — a counter that could only ever count down. It is on the
        account rather than the request so it survives an attacker moving
        between source addresses.
        """
        for expected in (1, 2, 3):
            self._login('wrong-password')
            self.user.refresh_from_db()
            self.assertEqual(self.user.failed_login_attempts, expected)

        self._login('a-long-enough-password')
        self.user.refresh_from_db()
        self.assertEqual(
            self.user.failed_login_attempts, 0,
            'a successful sign-in clears the run of failures',
        )

    def test_an_attempt_on_an_unknown_account_is_still_recorded(self):
        self.client.post(
            '/api/auth/login/',
            {'username': 'no-such-officer', 'password': 'whatever'},
            content_type='application/json',
        )
        entry = AuditLog.objects.filter(action=AuditLog.Action.LOGIN_FAILED).latest('timestamp')
        self.assertEqual(entry.username_attempted, 'no-such-officer')
        self.assertIn('no such account', entry.detail)

    def test_attempts_refused_by_the_rate_limit_are_recorded_too(self):
        """
        The gap this closes. Throttling happens in DRF's `initial()`, before the
        view body runs, so a burst produced a handful of audit rows and then
        nothing — and the silence started exactly where the traffic became
        worth looking at.
        """
        limit = int(
            settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES']['login'].split('/')[0]
        )

        throttled = 0
        for _ in range(limit + 3):
            if self._login('wrong-password').status_code == 429:
                throttled += 1

        self.assertGreater(throttled, 0, 'the limit must actually engage')

        rows = AuditLog.objects.filter(action=AuditLog.Action.LOGIN_FAILED)
        rate_limited = rows.filter(detail__contains='rate limit')
        self.assertEqual(
            rate_limited.count(), throttled,
            'every refused attempt must leave a row, not just the ones that '
            'reached the password check',
        )
        for entry in rate_limited:
            self.assertEqual(entry.username_attempted, 'officer')
            self.assertTrue(entry.ip_address)

    def test_a_malformed_body_does_not_break_the_record(self):
        """
        `throttled()` runs early enough that reading the request body can fail.
        A refused attempt with an unreadable body is still worth a row — the
        source address alone is the interesting part.
        """
        for _ in range(20):
            self.client.post(
                '/api/auth/login/', 'not json at all',
                content_type='application/json',
            )
        # No assertion on content: the point is that nothing raised a 500.
        self.assertTrue(True)
