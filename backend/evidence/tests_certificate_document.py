# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The certificate document: what goes into it, and that it stays what was issued.

From a blind audit (31 Oct 2026): a '<' in a file name stopped certificate issue
part-way, leaving a certificate row and a custody entry with no document; markup
in a field was rendered rather than printed; and the PDF was re-rendered on every
download, so no two copies, and no copy and a later case package, ever matched.
"""
import hashlib
import json
import subprocess
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import User

from . import case_package
from .models import CustodyEvent, EvidenceRecord, Section63Certificate
from .service import issue_certificate
from .tests_cases import CaseFixtureMixin


class CertificateDocument(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(override_settings(CERTIFICATE_ROOT=Path(self.tmp) / 'certs'))
        self.record = self._ingest(
            exhibit_number='EX-DOC-1', collected_by=self.io, fir_number='0113/2026',
            police_station='Cyber Crime PS, Ahmedabad City',
            provenance=EvidenceRecord.Provenance.SEIZED)
        self.officer = User.objects.create_user(
            username='inv', password='a-long-enough-password', badge_id='GP-3001',
            role=User.Role.INVESTIGATOR, is_approved=True)
        self.client = APIClient()
        self.client.force_authenticate(self.officer)

    def _issue(self, **extra):
        return issue_certificate(self.record, part_a_user=self.io, part_a_name='R. Patel',
                                 part_a_designation='IO', part_a_organisation='Cyber Crime PS',
                                 part_a_address='Ahmedabad', **extra)

    def _text(self, path):
        done = subprocess.run(['pdftotext', '-layout', str(path), '-'],
                              capture_output=True, text=True, check=False)
        if done.returncode != 0:
            self.skipTest('pdftotext unavailable')
        return done.stdout

    def _download(self, certificate):
        response = self.client.get(f'/api/certificates/{certificate.id}/pdf/')
        return response, b''.join(getattr(response, 'streaming_content', [])) or response.content

    # ── what goes in ──────────────────────────────────────────────────────

    def test_text_is_printed_as_written_not_read_as_markup(self):
        EvidenceRecord.objects.filter(pk=self.record.pk).update(original_filename='evil<b.pcap')
        self.record.refresh_from_db()
        cert = self._issue(findings_summary='Seen: <font color="white">hidden</font> & more')
        text = self._text(cert.pdf_path)
        self.assertIn('evil<b.pcap', text)
        self.assertIn('<font color="white">hidden</font> & more', text)

    def test_a_failed_render_leaves_nothing_behind(self):
        before = self.record.custody_events.count()
        with mock.patch('evidence.certificate_pdf.render_certificate_pdf',
                        side_effect=RuntimeError('render failed')):
            with self.assertRaises(RuntimeError):
                self._issue()
        self.assertFalse(Section63Certificate.objects.filter(evidence=self.record).exists())
        self.assertEqual(self.record.custody_events.count(), before)
        self.assertFalse(self.record.custody_events.filter(
            action=CustodyEvent.Action.CERTIFICATE_ISSUED).exists())

    # ── staying what was issued ───────────────────────────────────────────

    def test_every_download_is_the_issued_document(self):
        cert = self._issue()
        issued = Path(cert.pdf_path).read_bytes()
        self.assertEqual(cert.pdf_sha256, hashlib.sha256(issued).hexdigest())
        first = self._download(cert)
        second = self._download(cert)
        self.assertEqual(first[0].status_code, 200)
        self.assertEqual(first[1], issued)
        self.assertEqual(second[1], issued)

    def test_a_downloaded_copy_matches_a_package_exported_afterwards(self):
        cert = self._issue()
        _, copy = self._download(cert)
        text, _ = case_package.build_case_package([self.record])
        manifest = json.loads(json.loads(text)['manifest_json'])
        recorded = manifest['exhibits'][0]['certificates'][0]['pdf_sha256']
        self.assertEqual(recorded, hashlib.sha256(copy).hexdigest())

    def test_the_same_state_renders_to_the_same_bytes(self):
        from .certificate_pdf import render_certificate_pdf
        cert = self._issue()
        again = render_certificate_pdf(cert, output_path=Path(self.tmp) / 'again.pdf')
        self.assertEqual(Path(again).read_bytes(), Path(cert.pdf_path).read_bytes())

    def test_a_document_changed_on_disk_is_refused_not_served(self):
        cert = self._issue()
        with open(cert.pdf_path, 'ab') as f:
            f.write(b'%appended')
        response, _ = self._download(cert)
        self.assertEqual(response.status_code, 409)
        self.assertIn('no longer matches', response.json()['detail'])


    # ── who may add to the record ─────────────────────────────────────────

    def test_a_viewers_download_is_audited_but_not_added_to_custody(self):
        from accounts.models import AuditLog
        cert = self._issue()
        viewer = User.objects.create_user(
            username='reader', password='a-long-enough-password', badge_id='GP-3009',
            role=User.Role.VIEWER, is_approved=True)
        before = self.record.custody_events.count()
        self.client.force_authenticate(viewer)
        response, body = self._download(cert)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(body, Path(cert.pdf_path).read_bytes())
        self.assertEqual(self.record.custody_events.count(), before)
        self.assertTrue(AuditLog.objects.filter(
            user=viewer, action=AuditLog.Action.EXPORT_EVIDENCE).exists())

    def test_an_officers_download_is_added_to_custody(self):
        cert = self._issue()
        before = self.record.custody_events.count()
        self._download(cert)
        self.assertEqual(self.record.custody_events.count(), before + 1)

    def test_the_api_does_not_send_the_servers_file_path(self):
        cert = self._issue()
        body = self.client.get(f'/api/certificates/{cert.id}/').json()
        self.assertEqual(body['reference'], cert.reference)
        self.assertNotIn('pdf_path', body)
