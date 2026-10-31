# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
A seal check has three answers, and the cheap callers do not re-read exhibits.

From a blind audit (31 Oct 2026, M2): any error reading a stored exhibit set
the sticky TAMPERED status, so a passing permission problem or a key not yet
restored branded an exhibit altered for good; and the anonymous /api/verify/
page and the status strip polled every minute re-hashed the whole exhibit on
every request.
"""
import base64
import os
from datetime import timedelta
from pathlib import Path
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User

from .models import EvidenceRecord
from .service import issue_certificate
from .tests_cases import CaseFixtureMixin

KEY = base64.b64encode(b'k' * 32).decode()
HASHER = 'evidence.models.hash_file'


class ThreeAnswers(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.record = self._ingest(exhibit_number='EX-SEAL-1', collected_by=self.io,
                                   provenance=EvidenceRecord.Provenance.SEIZED)
        self.checked = self.record.last_verified_at

    def _assert_untouched(self):
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, EvidenceRecord.Status.SEALED)
        self.assertEqual(self.record.last_verified_at, self.checked)

    def test_a_missing_copy_is_not_checked_rather_than_tampered(self):
        Path(self.record.stored_path).unlink()
        self.assertEqual(self.record.verify(), (None, None))
        self._assert_untouched()

    def test_a_copy_that_cannot_be_opened_is_not_checked(self):
        if os.geteuid() == 0:
            self.skipTest('root reads files whatever their mode')
        path = Path(self.record.stored_path)
        path.chmod(0)
        self.addCleanup(path.chmod, 0o600)
        self.assertEqual(self.record.verify(), (None, None))
        self._assert_untouched()
        # Once readable again it verifies: nothing sticky was recorded.
        path.chmod(0o600)
        self.assertTrue(self.record.verify()[0])

    def test_an_altered_copy_is_still_tampered(self):
        with open(self.record.stored_path, 'ab') as fh:
            fh.write(b'\x00')
        ok, computed = self.record.verify()
        self.assertIs(ok, False)
        self.assertNotEqual(computed, self.record.sha256_hash)
        self.assertEqual(self.record.status, EvidenceRecord.Status.TAMPERED)

    def test_an_unreadable_copy_cannot_be_certified(self):
        Path(self.record.stored_path).unlink()
        with self.assertRaisesRegex(ValueError, 'could not be read'):
            issue_certificate(self.record, part_a_user=self.io, part_a_name='R. Patel',
                              part_a_designation='IO', part_a_organisation='Cyber Crime PS',
                              part_a_address='Ahmedabad')


@override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY=KEY)
class EncryptedAnswers(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.record = self._ingest(exhibit_number='EX-SEAL-ENC', collected_by=self.io,
                                   provenance=EvidenceRecord.Provenance.SEIZED)

    def test_a_missing_key_is_not_checked_rather_than_tampered(self):
        with override_settings(EVIDENCE_ENCRYPTION_KEY='',
                               EVIDENCE_KEY_FILE=Path(self.tmp) / 'absent.key'):
            self.assertEqual(self.record.verify(), (None, None))
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, EvidenceRecord.Status.SEALED)
        self.assertTrue(self.record.verify()[0])

    def test_a_failed_authentication_tag_is_still_tampered(self):
        path = Path(self.record.stored_path)
        data = bytearray(path.read_bytes())
        data[-1] ^= 0xFF
        path.write_bytes(bytes(data))
        self.assertEqual(self.record.verify(), (False, None))
        self.record.refresh_from_db()
        self.assertEqual(self.record.status, EvidenceRecord.Status.TAMPERED)


class CheapCallersReuseARecentCheck(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.record = self._ingest(exhibit_number='EX-SEAL-2', collected_by=self.io,
                                   provenance=EvidenceRecord.Provenance.SEIZED)
        self.officer = User.objects.create_user(
            username='inv', password='a-long-enough-password', badge_id='GP-3002',
            role=User.Role.INVESTIGATOR, is_approved=True)
        self.client = APIClient()

    def _age(self, seconds):
        EvidenceRecord.objects.filter(pk=self.record.pk).update(
            last_verified_at=timezone.now() - timedelta(seconds=seconds))
        self.record.refresh_from_db()

    def _public(self):
        return self.client.get('/api/verify/EX-SEAL-2/').json()

    def _posture(self):
        self.client.force_authenticate(self.officer)
        return self.client.get('/api/evidence/posture/').json()['latest_exhibit']

    def test_the_public_page_does_not_read_a_recently_checked_exhibit(self):
        with mock.patch(HASHER) as hasher:
            body = self._public()
        hasher.assert_not_called()
        self.assertIs(body['content_intact'], True)
        self.assertIs(body['content_checked_now'], False)
        self.assertIsNone(body['computed_sha256'])
        self.assertIsNotNone(body['content_checked_at'])

    def test_the_status_strip_does_not_read_a_recently_checked_exhibit(self):
        with mock.patch(HASHER) as hasher:
            exhibit = self._posture()
        hasher.assert_not_called()
        self.assertIs(exhibit['seal_intact'], True)

    def test_an_old_check_is_repeated_and_finds_tampering(self):
        Path(self.record.stored_path).write_bytes(b'altered after sealing')
        self._age(901)
        body = self._public()
        self.assertIs(body['content_intact'], False)
        self.assertIs(body['content_checked_now'], True)
        self.assertNotEqual(body['computed_sha256'], body['recorded_sha256'])

    def test_a_tampered_exhibit_is_reported_without_reading_it(self):
        EvidenceRecord.objects.filter(pk=self.record.pk).update(
            status=EvidenceRecord.Status.TAMPERED)
        with mock.patch(HASHER) as hasher:
            body = self._public()
        hasher.assert_not_called()
        self.assertIs(body['content_intact'], False)

    def test_an_unreadable_exhibit_is_reported_as_not_checked(self):
        Path(self.record.stored_path).unlink()
        self._age(901)
        body = self._public()
        self.assertIsNone(body['content_intact'])
        self.assertIsNone(body['content_checked_at'])
        self.assertEqual(body['status'], EvidenceRecord.Status.SEALED)
        self.assertIsNone(self._posture()['seal_intact'])

    def test_the_officers_verify_button_always_reads_the_file(self):
        Path(self.record.stored_path).write_bytes(b'altered after sealing')
        self.client.force_authenticate(self.officer)
        body = self.client.post(f'/api/evidence/{self.record.pk}/verify/').json()
        self.assertIs(body['verified'], False)

    def test_the_window_is_a_setting(self):
        with override_settings(SEAL_CHECK_REUSE_SECONDS=0), mock.patch(
                HASHER, return_value=({'sha256': self.record.sha256_hash}, 0)) as hasher:
            body = self._public()
        hasher.assert_called_once()
        self.assertIs(body['content_checked_now'], True)
