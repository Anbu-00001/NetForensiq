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
