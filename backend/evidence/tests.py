"""
Tests for the evidence integrity layer.

These are the assertions the whole court-admissibility claim rests on: if
tampering is not detected here, nothing else in the product matters.
"""

import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from accounts.models import User

from .models import CustodyEvent, EvidenceRecord, hash_file
from .service import (
    ingest_evidence, issue_certificate, record_custody, verify_custody_chain,
)


def make_capture_file(content=b'\xd4\xc3\xb2\xa1 fake pcap payload'):
    path = Path(tempfile.mkdtemp()) / 'sample.pcap'
    path.write_bytes(content)
    return path


class HashTests(TestCase):
    def test_hash_file_matches_known_digest(self):
        import hashlib
        path = make_capture_file(b'netforensiq')
        digests, size = hash_file(path)
        self.assertEqual(digests['sha256'], hashlib.sha256(b'netforensiq').hexdigest())
        self.assertEqual(digests['md5'], hashlib.md5(b'netforensiq').hexdigest())
        self.assertEqual(size, len(b'netforensiq'))

    def test_hash_is_streamed_in_chunks(self):
        """Large files must not be read into memory whole."""
        path = make_capture_file(b'x' * (3 * 1024 * 1024))
        digests, size = hash_file(path, chunk_size=1024)
        self.assertEqual(size, 3 * 1024 * 1024)
        self.assertEqual(len(digests['sha256']), 64)


class IngestTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _ingest(self, **kwargs):
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            return ingest_evidence(make_capture_file(), **kwargs)

    def test_ingest_seals_and_logs(self):
        record = self._ingest(case_reference='CR/2026/1')
        self.assertEqual(record.status, EvidenceRecord.Status.SEALED)
        self.assertEqual(len(record.sha256_hash), 64)
        self.assertEqual(len(record.md5_hash), 32)
        # Acquisition and hashing are both recorded before anything reads it
        actions = list(record.custody_events.values_list('action', flat=True))
        self.assertEqual(actions, ['acquired', 'hashed'])

    def test_original_is_copied_not_moved(self):
        source = make_capture_file()
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            record = ingest_evidence(source)
        self.assertTrue(source.exists(), 'the source artefact must be left in place')
        self.assertTrue(Path(record.stored_path).exists())

    def test_verify_passes_on_untouched_artefact(self):
        record = self._ingest()
        ok, computed = record.verify()
        self.assertTrue(ok)
        self.assertEqual(computed, record.sha256_hash)

    def test_verify_detects_a_single_altered_byte(self):
        record = self._ingest()
        with open(record.stored_path, 'ab') as fh:
            fh.write(b'\x00')
        ok, computed = record.verify()
        self.assertFalse(ok)
        self.assertNotEqual(computed, record.sha256_hash)
        self.assertEqual(record.status, EvidenceRecord.Status.TAMPERED)

    def test_verify_handles_a_missing_artefact(self):
        record = self._ingest()
        Path(record.stored_path).unlink()
        ok, computed = record.verify()
        self.assertFalse(ok)
        self.assertIsNone(computed)
        self.assertEqual(record.status, EvidenceRecord.Status.TAMPERED)


class CustodyChainTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            self.record = ingest_evidence(make_capture_file())

    def test_chain_is_intact_after_ingest(self):
        ok, problems = verify_custody_chain(self.record)
        self.assertTrue(ok, problems)

    def test_entries_are_linked_to_predecessors(self):
        events = list(self.record.custody_events.order_by('sequence'))
        self.assertEqual(events[0].previous_hash, '')
        self.assertEqual(events[1].previous_hash, events[0].entry_hash)

    def test_editing_an_entry_breaks_the_chain(self):
        event = self.record.custody_events.get(sequence=1)
        event.detail = 'falsified'
        event.save(update_fields=['detail'])

        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)
        self.assertTrue(any('#1' in p for p in problems))

    def test_deleting_an_entry_breaks_the_chain(self):
        record_custody(self.record, CustodyEvent.Action.VIEWED, detail='third entry')
        self.record.custody_events.filter(sequence=2).delete()

        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)

    def test_appending_a_valid_entry_keeps_the_chain_intact(self):
        record_custody(self.record, CustodyEvent.Action.VIEWED, detail='inspected')
        ok, problems = verify_custody_chain(self.record)
        self.assertTrue(ok, problems)


class CertificateTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            self.record = ingest_evidence(make_capture_file())
        self.officer = User.objects.create_user(
            username='officer', password='x', badge_id='GJ-1', department='Cyber',
        )
        self.expert = User.objects.create_user(
            username='expert', password='x', badge_id='GJ-2', department='FSL',
        )

    def test_certificate_freezes_the_verified_hash(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        self.assertEqual(cert.certified_sha256, self.record.sha256_hash)
        self.assertEqual(cert.certified_md5, self.record.md5_hash)

    def test_certificate_requires_both_parts_to_be_complete(self):
        """s.63(4) requires the person in charge AND an expert, conjunctively."""
        cert = issue_certificate(self.record, part_a_user=self.officer)
        self.assertFalse(cert.is_complete)

        cert.part_b_user = self.expert
        from django.utils import timezone
        cert.part_b_signed_at = timezone.now()
        cert.save()
        self.assertTrue(cert.is_complete)

    def test_certificate_is_refused_when_integrity_fails(self):
        """Certifying a hash we have not just re-verified would defeat the point."""
        with open(self.record.stored_path, 'ab') as fh:
            fh.write(b'tampered')
        with self.assertRaises(ValueError):
            issue_certificate(self.record, part_a_user=self.officer)

    def test_issuing_a_certificate_is_recorded_in_custody(self):
        issue_certificate(self.record, part_a_user=self.officer)
        actions = list(self.record.custody_events.values_list('action', flat=True))
        self.assertIn('certificate', actions)
        ok, problems = verify_custody_chain(self.record)
        self.assertTrue(ok, problems)
