"""
Tests over the sign-in log.

Two things are being held here. The obvious one: the log is readable, is
scoped to administrators, and shows attempts as they happened.

The one that matters more: **a server fault is not recorded as a credential
rejection.** The sign-in view used to catch every exception as a bad password,
so a locked database wrote "credentials rejected" against a named officer and
counted it toward locking that account out. The audit log is the artefact that
goes to a court, and it was making a false statement about a person while the
screen in front of them correctly said the fault was the server's.
"""

from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase
from rest_framework.test import APIClient

from .models import AuditLog, User


class SignInLogTests(TestCase):
    def setUp(self):
        # DRF's throttle counters live in the cache, which is process-wide and
        # survives between tests. Without this, whichever test runs first
        # exhausts the login scope and every later one is refused before it
        # reaches the code under test — the failures look like the feature is
        # broken when what is broken is the fixture.
        cache.clear()
        self.admin = User.objects.create_user(
            username='boss', password='Netforensiq@2026', badge_id='GJ-A',
            department='Cyber', role=User.Role.ADMIN, is_approved=True,
        )
        self.officer = User.objects.create_user(
            username='officer', password='Netforensiq@2026', badge_id='GJ-1',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True,
        )

    def _admin(self):
        client = APIClient()
        client.force_authenticate(user=self.admin)
        return client

    # ── access ──────────────────────────────────────────────────────────────

    def test_an_investigator_cannot_read_the_sign_in_log(self):
        """
        It names officers and source addresses, and it is the one view where a
        non-administrator could learn which usernames are real.
        """
        client = APIClient()
        client.force_authenticate(user=self.officer)
        self.assertEqual(client.get('/api/auth/sign-in-attempts/').status_code, 403)

    def test_it_is_refused_without_authentication(self):
        self.assertEqual(
            APIClient().get('/api/auth/sign-in-attempts/').status_code, 401)

    # ── what it records ─────────────────────────────────────────────────────

    def test_a_failed_sign_in_appears_with_its_timestamp_username_and_address(self):
        anon = APIClient()
        anon.post('/api/auth/login/',
                  {'username': 'officer', 'password': 'wrong'}, format='json')

        rows = self._admin().get(
            '/api/auth/sign-in-attempts/?outcome=failed').json()['attempts']
        self.assertTrue(rows)
        row = rows[0]
        self.assertEqual(row['outcome'], 'refused')
        self.assertEqual(row['username_attempted'], 'officer')
        self.assertTrue(row['timestamp'])
        self.assertIn('Credentials rejected', row['detail'])

    def test_an_attempt_on_a_username_that_does_not_exist_is_marked_as_such(self):
        """
        A run against usernames that do not exist is what credential stuffing
        looks like. The string is shown as typed rather than masked, because
        masking it would hide the attack.
        """
        APIClient().post('/api/auth/login/',
                         {'username': 'root', 'password': 'x'}, format='json')

        rows = self._admin().get(
            '/api/auth/sign-in-attempts/?username=root').json()['attempts']
        self.assertEqual(rows[0]['username_attempted'], 'root')
        self.assertFalse(rows[0]['account_exists'])
        self.assertIn('no such account', rows[0]['detail'])

    def test_a_real_account_mistyping_a_password_is_not_marked_unknown(self):
        """
        `account_exists` was derived from the audit row's user FK, which a
        failed sign-in never has — so every failure printed "NO SUCH ACCOUNT",
        including a serving officer who mistyped. That inverts the one signal
        the column exists for.
        """
        APIClient().post('/api/auth/login/',
                         {'username': 'officer', 'password': 'wrong'}, format='json')
        APIClient().post('/api/auth/login/',
                         {'username': 'nobody-here', 'password': 'wrong'}, format='json')

        rows = self._admin().get(
            '/api/auth/sign-in-attempts/?outcome=failed').json()['attempts']
        by_name = {r['username_attempted']: r for r in rows}

        self.assertTrue(by_name['officer']['account_exists'])
        self.assertFalse(by_name['nobody-here']['account_exists'])

    def test_a_successful_sign_in_is_recorded_too(self):
        APIClient().post('/api/auth/login/',
                         {'username': 'officer', 'password': 'Netforensiq@2026'},
                         format='json')

        body = self._admin().get(
            '/api/auth/sign-in-attempts/?outcome=login_success').json()
        self.assertTrue(body['attempts'])
        self.assertEqual(body['attempts'][0]['outcome'], 'success')
        self.assertEqual(body['last_24h']['success'], 1)

    # ── the defect this page exposed ────────────────────────────────────────

    def test_a_server_fault_is_not_recorded_as_a_credential_rejection(self):
        """
        The regression. A long analysis holding SQLite's write lock made three
        sign-ins by a legitimate commander raise OperationalError, and all
        three were written to the permanent record as credential rejections.
        """
        from django.db.utils import OperationalError

        before = self.officer.failed_login_attempts

        with patch(
            'rest_framework_simplejwt.views.TokenObtainPairView.post',
            side_effect=OperationalError('database is locked'),
        ):
            with self.assertRaises(OperationalError):
                APIClient().post(
                    '/api/auth/login/',
                    {'username': 'officer', 'password': 'Netforensiq@2026'},
                    format='json')

        row = AuditLog.objects.order_by('-timestamp').first()
        self.assertEqual(row.action, AuditLog.Action.LOGIN_ERROR)
        self.assertNotIn('Credentials rejected', row.detail)
        self.assertIn('not a statement about the credentials', row.detail)

        # And it must not count toward locking the account out: a busy database
        # could otherwise lock out the officer trying to use it.
        self.officer.refresh_from_db()
        self.assertEqual(self.officer.failed_login_attempts, before)

        # It reads as its own outcome, not as a refusal.
        rows = self._admin().get(
            '/api/auth/sign-in-attempts/?outcome=failed').json()['attempts']
        self.assertEqual(rows[0]['outcome'], 'server fault')

    def test_a_wrong_password_still_counts_toward_the_lockout(self):
        """
        The other half: separating server faults out must not have stopped
        genuine failures being counted.
        """
        APIClient().post('/api/auth/login/',
                         {'username': 'officer', 'password': 'wrong'}, format='json')
        self.officer.refresh_from_db()
        self.assertEqual(self.officer.failed_login_attempts, 1)

    def test_a_rate_limited_attempt_is_still_an_attempt(self):
        rows_before = AuditLog.objects.filter(
            action=AuditLog.Action.LOGIN_FAILED).count()

        anon = APIClient()
        for _ in range(12):
            anon.post('/api/auth/login/',
                      {'username': 'officer', 'password': 'wrong'}, format='json')

        # More rows than the throttle allowed through: the refusals are logged
        # too, which is the point — a log must not go quiet exactly when the
        # traffic becomes worth looking at.
        rows_after = AuditLog.objects.filter(
            action=AuditLog.Action.LOGIN_FAILED).count()
        self.assertGreater(rows_after - rows_before, 0)
        details = AuditLog.objects.filter(
            action=AuditLog.Action.LOGIN_FAILED).values_list('detail', flat=True)
        self.assertTrue(any('rate limit' in d for d in details))
