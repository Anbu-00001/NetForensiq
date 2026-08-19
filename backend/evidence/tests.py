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


class ScheduleAlgorithmTests(TestCase):
    """
    THE SCHEDULE prints a checkbox for SHA1, SHA256 and MD5. A certificate that
    fills one and leaves two blank is a statutory form with something missing —
    and Gujarat courts have been reading these forms literally.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.source = Path(self.tmp) / 'capture.pcap'
        self.source.write_bytes(b'\xd4\xc3\xb2\xa1' + b'\x2a' * 512)
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='B-1', department='Cyber',
        )

    def test_all_three_named_digests_are_computed_in_one_pass(self):
        record = ingest_evidence(self.source)

        self.assertEqual(len(record.sha256_hash), 64)
        self.assertEqual(len(record.sha1_hash), 40)
        self.assertEqual(len(record.md5_hash), 32)

        # And they must actually be digests of this file, not of anything else.
        import hashlib
        raw = self.source.read_bytes()
        self.assertEqual(record.sha256_hash, hashlib.sha256(raw).hexdigest())
        self.assertEqual(record.sha1_hash, hashlib.sha1(raw).hexdigest())
        self.assertEqual(record.md5_hash, hashlib.md5(raw).hexdigest())

    def test_the_certificate_prints_every_digest_and_names_the_one_relied_upon(self):
        record = ingest_evidence(self.source)
        certificate = issue_certificate(record, part_a_user=self.officer)

        text = CertificatePdfTests._text(certificate.pdf_path)

        self.assertIn(record.sha256_hash, text)
        self.assertIn(record.sha1_hash, text)
        self.assertIn(record.md5_hash, text)

        # Printing three digests without saying which one carries the weight
        # would be worse than printing one.
        # The bold run splits the sentence across two text objects in the
        # PDF stream, so the assertion matches the half that carries the claim.
        self.assertIn('primary digest and the only one relied upon', text)
        self.assertIn('collision resistance', text)


class PublicVerifyTests(TestCase):
    """
    Open verification.

    A §63 certificate asserts a SHA-256. If testing that assertion requires
    credentials to the investigating agency's own system, the other side is
    being asked to take the investigator's word for the investigator's own
    exhibit. These tests hold the endpoint to answering the question while
    disclosing nothing about the case.
    """

    def setUp(self):
        from django.core.cache import cache
        cache.clear()
        self.tmp = tempfile.mkdtemp()
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            self.record = ingest_evidence(
                make_capture_file(),
                exhibit_number='EX-PUB-1',
                case_reference='CR/2026/SECRET',
                seized_from='A name that must not leak',
                fir_number='0123/2026',
                provenance=EvidenceRecord.Provenance.SEIZED,
            )

    def tearDown(self):
        from django.core.cache import cache
        cache.clear()

    def _get(self, exhibit='EX-PUB-1', query=''):
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            return self.client.get(f'/api/verify/{exhibit}/{query}')

    def test_anyone_can_verify_without_signing_in(self):
        response = self._get()
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['found'])
        self.assertTrue(body['content_intact'])
        self.assertTrue(body['custody_chain_intact'])
        self.assertEqual(body['recorded_sha256'], self.record.sha256_hash)

    def test_it_discloses_nothing_about_the_case(self):
        """
        An exhibit number is printed on a document handed to the other side.
        The case around it is not.
        """
        raw = self._get().content.decode()
        for secret in ('CR/2026/SECRET', 'A name that must not leak',
                       '0123/2026', 'sample.pcap'):
            self.assertNotIn(secret, raw, f'{secret!r} must not be disclosed')

    def test_a_supplied_digest_is_checked_against_the_register(self):
        """Lets the holder of a certificate check their own copy of the file."""
        ok = self._get(query=f'?h={self.record.sha256_hash}')
        self.assertTrue(ok.json()['supplied_digest_matches'])

        wrong = self._get(query='?h=' + '0' * 64)
        self.assertFalse(wrong.json()['supplied_digest_matches'])

        # Absent means "not asked", not "did not match".
        self.assertIsNone(self._get().json()['supplied_digest_matches'])

    def test_tampering_is_reported_to_the_public_caller(self):
        Path(self.record.stored_path).write_bytes(b'altered after sealing')
        body = self._get().json()
        self.assertFalse(body['content_intact'])
        self.assertNotEqual(body['computed_sha256'], body['recorded_sha256'])

    def test_provenance_is_published_so_a_demo_cannot_pass_as_evidence(self):
        """
        The point of exposing provenance here. A synthetic capture verified in
        front of a court must announce itself as synthetic.
        """
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            ingest_evidence(
                make_capture_file(b'\xd4\xc3\xb2\xa1 generated'),
                exhibit_number='EX-DEMO-1',
                provenance=EvidenceRecord.Provenance.SYNTHETIC,
            )
        body = self._get('EX-DEMO-1').json()
        self.assertEqual(body['provenance'], EvidenceRecord.Provenance.SYNTHETIC)
        self.assertTrue(body['is_demonstration_only'])

    def test_an_unknown_exhibit_is_refused_without_saying_why(self):
        response = self._get('EX-NOPE-9')
        self.assertEqual(response.status_code, 404)
        self.assertFalse(response.json()['found'])

    def test_every_public_check_is_recorded(self):
        from accounts.models import AuditLog
        before = AuditLog.objects.filter(action=AuditLog.Action.VERIFY_EVIDENCE).count()
        self._get()
        after = AuditLog.objects.filter(action=AuditLog.Action.VERIFY_EVIDENCE).count()
        self.assertEqual(after, before + 1,
                         'who checked an exhibit, and when, is part of the record')


class InvestigationReportTests(TestCase):
    """
    The forensic report — the document that goes in the case file.

    Its value is entirely in what it refuses to leave out: the reasoning behind
    each finding, the fact that most thresholds are our own, and what the
    examination does not establish. A report that lists only hits reads as a
    conclusion, and these tests exist to stop it drifting into one.
    """

    def setUp(self):
        from capture.models import CaptureSession, Detection, Flow
        from django.utils import timezone

        self.tmp = tempfile.mkdtemp()
        self.session = CaptureSession.objects.create(
            name='report-test', source_type=CaptureSession.Source.PCAP,
            packet_count=1000, byte_count=500000,
            capture_start=timezone.now(), capture_end=timezone.now(),
        )
        self.flow = Flow.objects.create(
            session=self.session, src_ip='10.0.0.9', dst_ip='198.51.100.4',
            initiator_ip='10.0.0.9', src_port=44000, dst_port=443,
            protocol='TCP', first_seen=timezone.now(), last_seen=timezone.now(),
            app_protocol='HTTPS', app_protocol_source='observed',
        )
        Detection.objects.create(
            session=self.session, flow=self.flow,
            rule_id='C2_BEACON_PERIODIC',
            title='10.0.0.9 contacted 198.51.100.4 every ~60s',
            category='c2', severity=Detection.Severity.HIGH, severity_rank=70,
            method=Detection.Method.RULE, subject_ip='10.0.0.9',
            rationale='41 connections at 60s intervals; RITA threshold is 23.',
        )
        Detection.objects.create(
            session=self.session, flow=self.flow,
            rule_id='ANOMALY_STATISTICAL',
            title='10.0.0.9 → 198.51.100.4: volume sent unusually high',
            category='anomaly', severity=Detection.Severity.MEDIUM,
            severity_rank=40, method=Detection.Method.MODEL,
            subject_ip='10.0.0.9',
            rationale='Isolated as unusual against the other flows.',
        )

    def _render(self):
        from evidence.investigation_report import render_investigation_report
        with override_settings(CERTIFICATE_ROOT=Path(self.tmp)):
            return render_investigation_report(self.session)

    def _text(self):
        import subprocess
        path = self._render()
        result = subprocess.run(
            ['pdftotext', '-layout', str(path), '-'],
            capture_output=True, text=True, check=False,
        )
        if result.returncode != 0:
            self.skipTest('pdftotext unavailable')
        return result.stdout

    def test_it_renders(self):
        path = self._render()
        self.assertTrue(Path(path).exists())
        self.assertGreater(Path(path).stat().st_size, 2000)

    def test_every_finding_carries_its_reasoning(self):
        text = self._text()
        self.assertIn('C2_BEACON_PERIODIC', text)
        self.assertIn('RITA threshold is 23', text)

    def test_technical_terms_are_glossed_in_plain_language(self):
        """An officer reading this may never have heard the word 'beacon'."""
        text = self._text()
        self.assertIn('regular rhythm', text)

    def test_the_limits_section_is_never_omitted(self):
        """
        The part a competent defence reaches for first. A report that lists
        only what was found reads as a conclusion.
        """
        text = self._text()
        self.assertIn('LIMITS OF THIS EXAMINATION', text)
        self.assertIn('behaviour', text)
        self.assertIn('not identity', text)
        self.assertIn('tamper-evident', text)
        self.assertIn('heuristics', text)

    def test_a_statistical_finding_is_marked_as_proving_nothing(self):
        text = self._text()
        self.assertIn('ANOMALY_STATISTICAL', text)
        self.assertIn('nothing is proven by them', text)

    def test_a_demonstration_capture_says_so_on_the_first_page(self):
        """
        A demonstration report that reads like a real one is the most damaging
        artefact this system could produce.
        """
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            record = ingest_evidence(
                make_capture_file(), exhibit_number='EX-REP-DEMO',
                provenance=EvidenceRecord.Provenance.SYNTHETIC,
            )
        self.session.evidence = record
        self.session.save(update_fields=['evidence'])

        text = self._text()
        self.assertIn('DEMONSTRATION DATA', text)
        self.assertIn('NOT EVIDENCE', text)


class FslForwardingTests(TestCase):
    """
    The forwarding letter sent with an exhibit to a Forensic Science Laboratory.

    Its value is that nothing on it is retyped. Transcribing a SHA-256 by hand
    produces exactly one kind of error and produces it silently, so these tests
    hold the letter to being generated from the record.
    """

    def setUp(self):
        from accounts.models import User
        from capture.models import CaptureSession, Detection

        self.tmp = tempfile.mkdtemp()
        self.officer = User.objects.create_user(
            username='fsl-officer', password='a-long-enough-password',
            badge_id='B-311', department='Cyber Crime Branch',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            self.record = ingest_evidence(
                make_capture_file(),
                exhibit_number='EX-FSL-1',
                fir_number='0123/2026',
                police_station='Cyber Crime Branch, Ahmedabad',
                seized_from='Complainant device',
                collected_by=self.officer,
                provenance=EvidenceRecord.Provenance.SEIZED,
            )
        self.session = CaptureSession.objects.create(
            name='fsl-session', source_type=CaptureSession.Source.PCAP,
            evidence=self.record,
        )
        Detection.objects.create(
            session=self.session, rule_id='C2_BEACON_PERIODIC',
            title='beaconing', category='c2',
            severity=Detection.Severity.HIGH, severity_rank=70,
            method=Detection.Method.RULE, subject_ip='10.0.0.5',
        )

    def _package(self, **kwargs):
        from evidence.fsl_forwarding import build_package
        return build_package(self.record, officer=self.officer, **kwargs)

    def _text(self, **kwargs):
        import subprocess
        from evidence.fsl_forwarding import render_forwarding_letter
        with override_settings(CERTIFICATE_ROOT=Path(self.tmp)):
            path = render_forwarding_letter(
                self.record, officer=self.officer, **kwargs)
        result = subprocess.run(
            ['pdftotext', str(path), '-'], capture_output=True, text=True,
            check=False,
        )
        if result.returncode != 0:
            self.skipTest('pdftotext unavailable')
        return result.stdout

    def test_the_case_and_seal_come_from_the_record(self):
        """Nothing on the letter is retyped — that is the entire point."""
        package = self._package()
        self.assertEqual(package['case']['fir_number'], '0123/2026')
        self.assertEqual(package['exhibit']['sha256'], self.record.sha256_hash)
        self.assertEqual(package['exhibit']['md5'], self.record.md5_hash)
        self.assertEqual(
            package['exhibit']['exhibit_number'], self.record.exhibit_number)

    def test_preliminary_findings_are_counted_from_the_session(self):
        """
        The reverse accessor from an exhibit to its captures is `sessions`, and
        asking for `session` returned None without complaining — so the letter
        reported zero findings for an exhibit that had thirty-five.
        """
        package = self._package()
        self.assertEqual(package['preliminary_findings']['total'], 1)
        self.assertEqual(
            package['preliminary_findings']['by_severity'], {'high': 1})

    def test_the_hash_appears_on_the_letter_exactly(self):
        text = self._text()
        self.assertIn(self.record.sha256_hash, text.replace('\n', ''))

    def test_the_receiving_officer_is_asked_to_verify_before_unsealing(self):
        text = self._text()
        self.assertIn('verify them before unsealing', text)

    def test_examinations_can_be_narrowed(self):
        package = self._package(requested=['integrity'])
        self.assertEqual(len(package['examinations_requested']), 1)
        self.assertEqual(package['examinations_requested'][0][0], 'integrity')

    def test_no_examination_is_offered_that_a_capture_cannot_support(self):
        """
        A letter requesting analysis the exhibit cannot support wastes a
        laboratory's time and returns a report saying so, weeks later.
        """
        from evidence.fsl_forwarding import EXAMINATIONS
        offered = ' '.join(text for _key, text in EXAMINATIONS).lower()
        for impossible in ('device', 'handset', 'imei', 'fingerprint', 'dna'):
            self.assertNotIn(impossible, offered)

    def test_preliminary_findings_are_not_offered_as_a_substitute(self):
        text = self._text()
        self.assertIn('not a substitute for examination', text)

    def test_a_demonstration_exhibit_is_marked_do_not_forward(self):
        """An FSL must never be asked to examine demonstration data."""
        self.record.provenance = EvidenceRecord.Provenance.SYNTHETIC
        self.record.save(update_fields=['provenance'])
        text = self._text()
        self.assertIn('DEMONSTRATION DATA', text)
        self.assertIn('DO NOT FORWARD', text)

    def test_the_forwarding_officer_is_named_with_their_badge(self):
        text = self._text()
        self.assertIn('fsl-officer', text)
        self.assertIn('B-311', text)
