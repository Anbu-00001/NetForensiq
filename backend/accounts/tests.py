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
