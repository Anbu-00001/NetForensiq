"""
Tests for encryption of the evidence store at rest.

The property that matters is narrow: encryption must not change what the
certificate says. The SHA-256 printed on a Section 63 certificate is of the
capture as seized, and it has to stay reproducible by anyone holding the same
file — so these tests check the digest survives a round trip, and that a
tampered or truncated ciphertext is refused rather than silently accepted.
"""

import base64
import hashlib
import os
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from accounts.models import User

from . import crypto
from .models import CustodyEvent, EvidenceRecord
from .service import ingest_evidence
from .tests import make_capture_file

KEY = base64.b64encode(b'k' * 32).decode()


@override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY=KEY)
class RoundTripTests(TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.key = crypto.load_key()

    def _round_trip(self, payload):
        plain = self.tmp / 'in.bin'
        plain.write_bytes(payload)
        sealed = self.tmp / 'out.enc'
        crypto.encrypt_file(plain, sealed, self.key)
        back = self.tmp / 'back.bin'
        crypto.decrypt_file(sealed, back, self.key)
        return sealed, back

    def test_a_file_survives_a_round_trip_byte_for_byte(self):
        payload = os.urandom(1000)
        _, back = self._round_trip(payload)
        self.assertEqual(back.read_bytes(), payload)

    def test_a_file_larger_than_one_chunk_survives(self):
        """The chunked construction is where an off-by-one would live."""
        payload = os.urandom(crypto.CHUNK_BYTES * 2 + 517)
        _, back = self._round_trip(payload)
        self.assertEqual(hashlib.sha256(back.read_bytes()).hexdigest(),
                         hashlib.sha256(payload).hexdigest())

    def test_a_file_exactly_one_chunk_long_survives(self):
        payload = os.urandom(crypto.CHUNK_BYTES)
        _, back = self._round_trip(payload)
        self.assertEqual(back.read_bytes(), payload)

    def test_an_empty_file_survives(self):
        _, back = self._round_trip(b'')
        self.assertEqual(back.read_bytes(), b'')

    def test_the_ciphertext_does_not_contain_the_plaintext(self):
        payload = b'SUSPECT CONFESSION' * 200
        sealed, _ = self._round_trip(payload)
        self.assertNotIn(b'SUSPECT CONFESSION', sealed.read_bytes())

    def test_a_flipped_bit_is_refused(self):
        sealed, _ = self._round_trip(os.urandom(4096))
        data = bytearray(sealed.read_bytes())
        data[-1] ^= 0x01
        sealed.write_bytes(bytes(data))

        with self.assertRaises(crypto.EvidenceDecryptionError):
            crypto.decrypt_file(sealed, self.tmp / 'x', self.key)

    def test_a_truncated_file_is_refused(self):
        """
        Chopping the tail off a chunked file leaves a shorter but internally
        consistent stream unless the last chunk is distinguishable. It is —
        the final chunk's counter carries a flag no other chunk carries.
        """
        payload = os.urandom(crypto.CHUNK_BYTES * 2 + 64)
        sealed, _ = self._round_trip(payload)
        data = sealed.read_bytes()
        sealed.write_bytes(data[:crypto.CHUNK_BYTES + crypto.TAG_BYTES
                                + len(crypto.MAGIC) + crypto.NONCE_PREFIX_BYTES])

        with self.assertRaises(crypto.EvidenceDecryptionError):
            crypto.decrypt_file(sealed, self.tmp / 'x', self.key)

    def test_the_wrong_key_is_refused(self):
        sealed, _ = self._round_trip(os.urandom(2048))
        with self.assertRaises(crypto.EvidenceDecryptionError):
            crypto.decrypt_file(sealed, self.tmp / 'x', b'w' * 32)


@override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY=KEY)
class SealedStoreTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.officer = User.objects.create_user(username='io', password='x')

    def _ingest(self, **kwargs):
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            return ingest_evidence(make_capture_file(), collected_by=self.officer,
                                   **kwargs)

    def test_the_stored_artefact_is_ciphertext(self):
        record = self._ingest(exhibit_number='ENC-1')
        self.assertTrue(record.encrypted_at_rest)
        self.assertTrue(crypto.is_encrypted(record.stored_path))
        self.assertNotIn(b'fake pcap payload', Path(record.stored_path).read_bytes())

    def test_the_recorded_hash_is_of_the_plaintext(self):
        """
        This is the whole point. A digest of ciphertext cannot be reproduced by
        anyone handed the same capture, so it would be useless on a
        certificate.
        """
        record = self._ingest(exhibit_number='ENC-2')
        expected = hashlib.sha256(b'\xd4\xc3\xb2\xa1 fake pcap payload').hexdigest()
        self.assertEqual(record.sha256_hash, expected)

    def test_verification_passes_on_an_encrypted_artefact(self):
        record = self._ingest(exhibit_number='ENC-3')
        ok, computed = record.verify()
        self.assertTrue(ok)
        self.assertEqual(computed, record.sha256_hash)

    def test_tampering_with_the_ciphertext_fails_verification(self):
        record = self._ingest(exhibit_number='ENC-4')
        path = Path(record.stored_path)
        data = bytearray(path.read_bytes())
        data[-1] ^= 0xFF
        path.write_bytes(bytes(data))

        ok, _ = record.verify()

        self.assertFalse(ok)
        record.refresh_from_db()
        self.assertEqual(record.status, EvidenceRecord.Status.TAMPERED)

    def test_reading_without_the_key_is_an_error_not_a_fallback(self):
        record = self._ingest(exhibit_number='ENC-5')
        with override_settings(EVIDENCE_ENCRYPTION_KEY='',
                               EVIDENCE_KEY_FILE=Path(self.tmp) / 'absent.key'):
            with self.assertRaises(crypto.EvidenceDecryptionError):
                with crypto.readable(record.stored_path):
                    pass

    def test_the_temporary_plaintext_is_removed_afterwards(self):
        record = self._ingest(exhibit_number='ENC-6')
        with crypto.readable(record.stored_path) as opened:
            self.assertNotEqual(str(opened), record.stored_path)
            temp = Path(opened)
            self.assertTrue(temp.exists())
        self.assertFalse(temp.exists())

    def test_the_temporary_plaintext_is_removed_when_the_caller_raises(self):
        record = self._ingest(exhibit_number='ENC-7')
        seen = {}
        with self.assertRaises(RuntimeError):
            with crypto.readable(record.stored_path) as opened:
                seen['path'] = Path(opened)
                raise RuntimeError('analysis blew up')
        self.assertFalse(seen['path'].exists())


class DisclosureTests(TestCase):
    """The system has to be honest about whether encryption is actually on."""

    @override_settings(EVIDENCE_ENCRYPTION='off')
    def test_switched_off_is_reported_as_switched_off(self):
        state = crypto.describe()
        self.assertFalse(state['enabled'])
        self.assertIn('Disabled by configuration', state['reason'])

    @override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY='',
                       EVIDENCE_KEY_FILE=Path(tempfile.mkdtemp()) / 'nope.key')
    def test_no_key_yet_says_the_store_is_in_the_clear(self):
        state = crypto.describe()
        self.assertFalse(state['enabled'])
        self.assertIn('in the clear', state['reason'])
        self.assertIn('full-disk encryption', state['reason'])

    @override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY=KEY)
    def test_switched_on_names_the_algorithm(self):
        state = crypto.describe()
        self.assertTrue(state['enabled'])
        self.assertIn('AES-256-GCM', state['algorithm'])

    @override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY='c2hvcnQ=')
    def test_a_malformed_key_is_reported_rather_than_crashing_the_page(self):
        state = crypto.describe()
        self.assertFalse(state['enabled'])
        self.assertIn('could not be read', state['reason'])


@override_settings(EVIDENCE_ENCRYPTION='on', EVIDENCE_ENCRYPTION_KEY=KEY)
class MigrationCommandTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.officer = User.objects.create_user(username='io2', password='x')

    def _ingest_in_the_clear(self, exhibit_number):
        with override_settings(EVIDENCE_ENCRYPTION='off',
                               EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            return ingest_evidence(make_capture_file(),
                                   exhibit_number=exhibit_number,
                                   collected_by=self.officer)

    def test_an_existing_plaintext_store_is_encrypted_in_place(self):
        from django.core.management import call_command
        from io import StringIO

        record = self._ingest_in_the_clear('OLD-1')
        self.assertFalse(crypto.is_encrypted(record.stored_path))
        digest_before = record.sha256_hash

        call_command('encrypt_evidence_store', stdout=StringIO(), stderr=StringIO())

        record.refresh_from_db()
        self.assertTrue(crypto.is_encrypted(record.stored_path))
        self.assertTrue(record.encrypted_at_rest)
        # The assertion the certificate depends on.
        self.assertEqual(record.sha256_hash, digest_before)
        ok, _ = record.verify()
        self.assertTrue(ok)

    def test_encrypting_is_recorded_in_the_chain_of_custody(self):
        from django.core.management import call_command
        from io import StringIO

        record = self._ingest_in_the_clear('OLD-2')
        call_command('encrypt_evidence_store', stdout=StringIO(), stderr=StringIO())

        actions = list(record.custody_events.values_list('action', flat=True))
        self.assertIn(CustodyEvent.Action.ENCRYPTED, actions)

    def test_a_corrupted_artefact_is_skipped_not_encrypted(self):
        from django.core.management import call_command
        from io import StringIO

        record = self._ingest_in_the_clear('OLD-3')
        Path(record.stored_path).write_bytes(b'this is not the file we sealed')

        err = StringIO()
        call_command('encrypt_evidence_store', stdout=StringIO(), stderr=err)

        self.assertIn('SKIPPED', err.getvalue())
        self.assertFalse(crypto.is_encrypted(record.stored_path))
