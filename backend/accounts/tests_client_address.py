# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Where a request came from is decided by the server, not by the request.

A blind audit (31 Oct 2026) found that the client address was the first entry of
X-Forwarded-For, taken as given. Rotating that header got fifteen wrong
passwords past an eight-an-hour limit, and a signed-in user stored the text
'6.6.6.6|forged' as a custody entry's IP address. These tests are those attacks.
"""
from django.core.cache import cache
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings

from evidence.models import CustodyEvent, EvidenceRecord
from evidence.service import record_custody, verify_custody_chain
from evidence.tests_cases import CaseFixtureMixin

from .models import User
from .utils import get_client_ip

LOGIN = '/api/auth/login/'


def _rf(settings_proxies=None):
    from django.conf import settings
    rest = dict(settings.REST_FRAMEWORK)
    rest['NUM_PROXIES'] = settings_proxies
    return override_settings(REST_FRAMEWORK=rest)


class ClientAddress(SimpleTestCase):
    def _request(self, remote='10.0.0.9', forwarded=None):
        request = RequestFactory().get('/')
        request.META['REMOTE_ADDR'] = remote
        if forwarded is not None:
            request.META['HTTP_X_FORWARDED_FOR'] = forwarded
        return request

    def test_the_header_is_ignored_when_no_proxy_is_declared(self):
        self.assertEqual(get_client_ip(self._request(forwarded='6.6.6.6')), '10.0.0.9')

    def test_a_declared_proxy_is_believed_for_its_own_hop_only(self):
        # The client forged the first entry; the proxy appended the real one.
        with _rf(1):
            self.assertEqual(get_client_ip(self._request(forwarded='6.6.6.6, 203.0.113.7')),
                             '203.0.113.7')

    def test_whatever_arrives_must_be_an_ip_address(self):
        with _rf(1):
            self.assertIsNone(get_client_ip(self._request(forwarded='6.6.6.6|forged')))
        self.assertIsNone(get_client_ip(self._request(remote='not-an-address')))


class SignInLimits(TestCase):
    def setUp(self):
        cache.clear()
        self.addCleanup(cache.clear)
        User.objects.create_user(username='officer', password='Right-passw0rd-long',
                                 badge_id='GJ-77', department='Cyber', is_approved=True)

    def _attempt(self, n, **meta):
        return self.client.post(LOGIN, {'username': 'officer', 'password': f'wrong-{n}'},
                                content_type='application/json', **meta)

    def test_a_rotating_forwarded_header_does_not_buy_more_attempts(self):
        codes = [self._attempt(i, HTTP_X_FORWARDED_FOR=f'198.51.100.{i}').status_code
                 for i in range(12)]
        self.assertIn(429, codes, codes)
        self.assertEqual(codes.index(429), 8, codes)

    def test_attempts_at_one_account_are_limited_whatever_the_address(self):
        codes = [self._attempt(i, REMOTE_ADDR=f'198.51.100.{i}').status_code for i in range(13)]
        self.assertIn(429, codes, codes)
        self.assertEqual(codes.index(429), 10, codes)

    def test_another_account_is_not_affected(self):
        for i in range(10):
            self._attempt(i, REMOTE_ADDR=f'198.51.100.{i}')
        other = self.client.post(LOGIN, {'username': 'someone-else', 'password': 'x'},
                                 content_type='application/json', REMOTE_ADDR='192.0.2.50')
        self.assertEqual(other.status_code, 401)


class CustodyAddress(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.record = self._ingest(
            exhibit_number='EX-IP-1', collected_by=self.io, fir_number='0113/2026',
            police_station='Cyber Crime PS, Ahmedabad City',
            provenance=EvidenceRecord.Provenance.SEIZED)

    def test_text_that_is_not_an_address_is_not_stored_as_one(self):
        event = record_custody(self.record, CustodyEvent.Action.VIEWED, actor_ip='6.6.6.6|forged')
        self.assertIsNone(event.actor_ip)
        self.assertEqual(record_custody(self.record, CustodyEvent.Action.VIEWED,
                                        actor_ip=' 192.0.2.4 ').actor_ip, '192.0.2.4')

    def test_the_server_check_rejects_a_pipe_written_around_it(self):
        """An entry written before this fix, or by direct database access."""
        event = record_custody(self.record, CustodyEvent.Action.VIEWED, actor_ip='192.0.2.4')
        CustodyEvent.objects.filter(pk=event.pk).update(actor_ip='6.6.6.6|forged')
        event.refresh_from_db()
        CustodyEvent.objects.filter(pk=event.pk).update(entry_hash=event.compute_hash())
        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)
        self.assertTrue(any("actor_ip contains '|'" in p for p in problems), problems)
