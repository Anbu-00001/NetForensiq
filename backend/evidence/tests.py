"""
Tests for the evidence integrity layer.

These are the assertions the whole court-admissibility claim rests on: if
tampering is not detected here, nothing else in the product matters.
"""

import tempfile
from pathlib import Path

from django.conf import settings
from django.test import TestCase, override_settings

from accounts.models import User

from .models import CustodyEvent, EvidenceRecord, hash_file
from .service import (
    ingest_evidence, issue_certificate, record_custody, sign_part_b,
    verify_custody_chain,
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
        # Both roots are redirected: issuing a certificate now renders a PDF,
        # and tests must not write into the project's real evidence store.
        self.roots = override_settings(
            EVIDENCE_ROOT=Path(self.tmp) / 'pcaps',
            CERTIFICATE_ROOT=Path(self.tmp) / 'certificates',
        )
        self.roots.enable()
        self.addCleanup(self.roots.disable)

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

        cert = sign_part_b(cert, user=self.expert, qualification='M.Tech, CHFI')
        self.assertTrue(cert.is_complete)

    def test_certificate_is_refused_when_integrity_fails(self):
        """Certifying a hash we have not just re-verified would defeat the point."""
        with open(self.record.stored_path, 'ab') as fh:
            fh.write(b'tampered')
        with self.assertRaises(ValueError):
            issue_certificate(self.record, part_a_user=self.officer)

    def test_one_account_cannot_sign_both_parts(self):
        """
        s.63(4) contemplates two people: the person in charge of the device and
        an expert. A certificate one account signed twice attests to nothing,
        and this safeguard was previously only described in a comment.
        """
        cert = issue_certificate(self.record, part_a_user=self.officer)
        with self.assertRaises(ValueError) as ctx:
            sign_part_b(cert, user=self.officer)
        self.assertIn('different people', str(ctx.exception))

        cert.refresh_from_db()
        self.assertFalse(cert.is_complete)

    def test_a_different_expert_can_countersign(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        cert = sign_part_b(cert, user=self.expert, qualification='M.Tech')
        self.assertTrue(cert.is_complete)

    def test_countersigning_is_refused_when_integrity_fails(self):
        """An expert must not attest to a hash that no longer matches the file."""
        cert = issue_certificate(self.record, part_a_user=self.officer)
        with open(self.record.stored_path, 'ab') as fh:
            fh.write(b'tampered after issue')
        with self.assertRaises(ValueError):
            sign_part_b(cert, user=self.expert)

    def test_issuing_a_certificate_is_recorded_in_custody(self):
        issue_certificate(self.record, part_a_user=self.officer)
        actions = list(self.record.custody_events.values_list('action', flat=True))
        self.assertIn('certificate', actions)
        ok, problems = verify_custody_chain(self.record)
        self.assertTrue(ok, problems)


class CertificatePdfTests(TestCase):
    """
    The PDF is the artefact that actually reaches a court, so these check what
    is on the page — not merely that a file was produced.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.roots = override_settings(
            EVIDENCE_ROOT=Path(self.tmp) / 'pcaps',
            CERTIFICATE_ROOT=Path(self.tmp) / 'certificates',
        )
        self.roots.enable()
        self.addCleanup(self.roots.disable)

        self.record = ingest_evidence(
            make_capture_file(), case_reference='I-CR-2026-0042',
        )
        self.officer = User.objects.create_user(
            username='officer', password='x', badge_id='GJ-1', department='Cyber',
        )
        self.expert = User.objects.create_user(
            username='expert', password='x', badge_id='GJ-2', department='FSL',
        )

    @staticmethod
    def _text(path):
        """
        Extract page text without a third-party dependency.

        reportlab wraps content streams as ASCII85 *over* Flate by default, so
        both layers have to come off; decoding only the Flate layer yields an
        empty string and silently passes every assertion. Both decodes are
        attempted per stream, in that order, with the raw bytes as a fallback.
        """
        import base64
        import re
        import zlib

        raw = Path(path).read_bytes()
        chunks = []
        for match in re.finditer(rb'stream\r?\n(.*?)endstream', raw, re.S):
            data = match.group(1).strip()
            try:
                data = base64.a85decode(data, adobe=True)
            except ValueError:
                pass
            try:
                data = zlib.decompress(data)
            except zlib.error:
                pass
            chunks.append(data)

        blob = b'\n'.join(chunks).decode('latin-1')
        # Text is emitted as (literal) Tj / TJ arrays; recover the literals.
        literals = re.findall(r'\((?:[^()\\]|\\.)*\)', blob)
        return ''.join(literals).replace('\\', '')

    def test_pdf_is_written_and_recorded_on_the_certificate(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        self.assertTrue(cert.pdf_path, 'pdf_path must be recorded on the model')
        path = Path(cert.pdf_path)
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes()[:4], b'%PDF')

    def test_pdf_reproduces_the_schedule_not_a_paraphrase(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        text = self._text(cert.pdf_path)

        self.assertIn('THE SCHEDULE', text)
        self.assertIn('See section 63(4)(c)', text)
        self.assertIn('PART A', text)
        self.assertIn('PART B', text)
        self.assertIn('To be filled by the Party', text)
        self.assertIn('To be filled by the Expert', text)
        # Wording lifted verbatim from the bare Act
        self.assertIn('solemnly affirm and sincerely state', text)
        self.assertIn('Hash report to be enclosed with the certificate', text)

    def test_pdf_carries_the_real_digest(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        text = self._text(cert.pdf_path)
        self.assertIn(self.record.sha256_hash, text)
        self.assertIn(self.record.exhibit_number, text)

    def test_schedule_names_all_three_algorithms(self):
        """
        The Schedule prints SHA1, SHA256 and MD5. Omitting the line for one we
        do not compute would misrepresent the prescribed form.
        """
        cert = issue_certificate(self.record, part_a_user=self.officer)
        text = self._text(cert.pdf_path)
        for algorithm in ('SHA1', 'SHA256', 'MD5'):
            self.assertIn(algorithm, text)

    def test_unsigned_certificate_is_marked_draft(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        text = self._text(cert.pdf_path)
        self.assertIn('NOT A VALID CERTIFICATE', text)
        self.assertIn('INCOMPLETE', text)

    def test_fully_signed_certificate_drops_the_draft_marking(self):
        cert = issue_certificate(self.record, part_a_user=self.officer)
        cert = sign_part_b(
            cert, user=self.expert, name='Dr A Expert',
            designation='Assistant Director', organisation='FSL Gandhinagar',
            qualification='Ph.D. Computer Science',
        )
        text = self._text(cert.pdf_path)
        self.assertNotIn('NOT A VALID CERTIFICATE', text)
        self.assertIn('Dr A Expert', text)
        self.assertIn('Ph.D. Computer Science', text)

    def test_unknown_statutory_fields_are_left_blank_not_invented(self):
        """
        The Schedule asks for a parent's name and the device colour. We hold
        neither. They must appear as blank rules for completion in ink — a
        plausible-looking value would be a forged statutory declaration.
        """
        cert = issue_certificate(self.record, part_a_user=self.officer)
        text = self._text(cert.pdf_path)
        self.assertIn('Son/daughter/spouse of', text)
        self.assertIn('Color:', text)
        self.assertIn('_____', text)

    def test_timestamps_labelled_IST_are_actually_IST(self):
        """
        Datetimes are stored UTC-aware, and strftime formats in the object's own
        tzinfo — so a bare format string under a label reading "Time (IST)"
        printed UTC while claiming IST. Five and a half hours wrong on a
        statutory declaration, with the date rolling back a day for anything
        before 05:30 IST.
        """
        from datetime import datetime, timezone as dt_timezone
        from zoneinfo import ZoneInfo

        # 22:00 UTC on 1 Jan is 03:30 IST on 2 Jan — wrong hour AND wrong date
        moment = datetime(2026, 1, 1, 22, 0, 0, tzinfo=dt_timezone.utc)
        cert = issue_certificate(self.record, part_a_user=self.officer)
        cert.part_a_signed_at = moment
        cert.save(update_fields=['part_a_signed_at'])

        from .certificate_pdf import render_certificate_pdf
        render_certificate_pdf(cert)
        text = self._text(cert.pdf_path)

        local = moment.astimezone(ZoneInfo('Asia/Kolkata'))
        self.assertEqual((local.hour, local.minute, local.day), (3, 30, 2))

        self.assertIn(f'{local:%d/%m/%Y}', text)
        self.assertIn(f'{local:%H:%M}', text)
        self.assertNotIn('22:00', text)

    def test_custody_annexure_reports_a_broken_chain(self):
        """A tampered custody log must be visible on the document itself."""
        cert = issue_certificate(self.record, part_a_user=self.officer)

        event = self.record.custody_events.get(sequence=1)
        event.detail = 'falsified'
        event.save(update_fields=['detail'])

        from .certificate_pdf import render_certificate_pdf
        render_certificate_pdf(cert)
        text = self._text(cert.pdf_path)
        self.assertIn('CHAIN BROKEN', text)


class ProvenanceTests(TestCase):
    """
    A generated capture and a seized one are byte-identical artefacts. The
    only thing that can tell them apart downstream is a recorded statement
    about where each came from — and that statement has to reach the register
    and the certificate, or it protects nothing.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.source = Path(self.tmp) / 'capture.pcap'
        self.source.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x00' * 200)

    def test_a_file_with_no_manifest_is_unattested_not_seized(self):
        record = ingest_evidence(self.source)
        self.assertEqual(record.provenance, EvidenceRecord.Provenance.UNATTESTED)
        self.assertFalse(record.is_demonstration_only)

    def test_a_generated_file_is_sealed_as_synthetic(self):
        from capture.provenance import write_manifest, KIND_SYNTHETIC

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed', seed=7)
        record = ingest_evidence(self.source)

        self.assertEqual(record.provenance, EvidenceRecord.Provenance.SYNTHETIC)
        self.assertTrue(record.is_demonstration_only)
        self.assertIn('seed 7', record.provenance_detail)

    def test_a_manifest_describing_a_different_file_is_ignored(self):
        """
        Detaching a manifest and reattaching it elsewhere must not transfer a
        claim about origin. The digest in the manifest is what prevents it.
        """
        from capture.provenance import write_manifest, read_manifest, KIND_SYNTHETIC

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed')
        self.source.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\xff' * 400)

        self.assertIsNone(read_manifest(self.source))
        record = ingest_evidence(self.source)
        self.assertEqual(record.provenance, EvidenceRecord.Provenance.UNATTESTED)

    def test_an_intake_declaration_that_contradicts_the_manifest_records_both(self):
        from capture.provenance import write_manifest, KIND_SYNTHETIC

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed')
        record = ingest_evidence(
            self.source, provenance=EvidenceRecord.Provenance.SEIZED,
        )

        self.assertEqual(record.provenance, EvidenceRecord.Provenance.SEIZED)
        self.assertIn('manifest', record.provenance_detail.lower())
        self.assertIn('synthetic', record.provenance_detail.lower())

    def test_the_certificate_pdf_says_synthetic_in_terms_no_one_could_miss(self):
        from capture.provenance import write_manifest, KIND_SYNTHETIC

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed')
        record = ingest_evidence(self.source)

        officer = User.objects.create_user(
            username='po', password='x', badge_id='B-1', department='Cyber',
        )
        certificate = issue_certificate(record, part_a_user=officer)

        text = CertificatePdfTests._text(certificate.pdf_path)
        self.assertIn('SYNTHETIC DATA', text)
        self.assertIn('NOT EVIDENCE', text)


class ExhibitNumberSafetyTests(TestCase):
    """
    The exhibit number becomes a filename inside the evidence store. A record
    can claim a file is in custody while the bytes were written somewhere else
    entirely, which is the worst possible failure for an evidence layer.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.source = Path(self.tmp) / 'capture.pcap'
        self.source.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x00' * 64)

    def test_a_traversing_exhibit_number_is_refused(self):
        for attempt in ('../escaped', '..', 'a/b', '/absolute', 'x\x00y'):
            with self.assertRaises(ValueError, msg=attempt):
                ingest_evidence(self.source, exhibit_number=attempt)

    def test_an_overlong_exhibit_number_is_refused(self):
        with self.assertRaises(ValueError):
            ingest_evidence(self.source, exhibit_number='A' * 101)

    def test_an_ordinary_exhibit_number_is_accepted(self):
        record = ingest_evidence(self.source, exhibit_number='GJ-CYB-2026-0001')
        self.assertEqual(record.exhibit_number, 'GJ-CYB-2026-0001')
        self.assertTrue(Path(record.stored_path).exists())
        self.assertEqual(
            Path(record.stored_path).parent.resolve(),
            Path(settings.EVIDENCE_ROOT).resolve(),
        )


class ProvenanceSurvivesResealingTests(TestCase):
    """
    Reprocessing an exhibit means importing the sealed copy, not the original.
    If the statement of origin stays behind with the original file, a synthetic
    capture re-imported from the store comes back as "origin unknown" — quieter
    than the truth, which is the direction a provenance system must never fail.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.source = Path(self.tmp) / 'generated.pcap'
        self.source.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x00' * 128)

    def test_re_sealing_the_stored_copy_keeps_the_synthetic_marker(self):
        from capture.provenance import write_manifest, KIND_SYNTHETIC

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed', seed=7)
        first = ingest_evidence(self.source)
        self.assertTrue(first.is_demonstration_only)

        # Someone reprocesses the exhibit from the evidence store.
        second = ingest_evidence(first.stored_path)

        self.assertTrue(
            second.is_demonstration_only,
            're-sealing the stored copy lost the SYNTHETIC marker',
        )
        self.assertEqual(second.provenance, EvidenceRecord.Provenance.SYNTHETIC)

    def test_the_copied_manifest_still_only_describes_its_own_file(self):
        """
        The manifest carries the digest, so copying it beside a different file
        must not transfer the claim.
        """
        from capture.provenance import (
            write_manifest, read_manifest, manifest_path, KIND_SYNTHETIC,
        )
        import shutil as _shutil

        write_manifest(self.source, kind=KIND_SYNTHETIC, scenario='mixed')

        other = Path(self.tmp) / 'unrelated.pcap'
        other.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\xee' * 128)
        _shutil.copy2(manifest_path(self.source), manifest_path(other))

        self.assertIsNone(read_manifest(other))
        record = ingest_evidence(other)
        self.assertEqual(record.provenance, EvidenceRecord.Provenance.UNATTESTED)
