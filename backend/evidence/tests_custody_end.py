# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The end of a custody log is recorded, so entries removed from it are noticed.

From a blind audit (31 Oct 2026, M3): deleting the last entries of a log left a
chain that still re-derived link by link, and verification said intact. And
(M4) the certificate's Officer column printed the account name, which no hash
covers, instead of the badge, which the entry hash does.
"""
import importlib
import subprocess
from pathlib import Path

from django.apps import apps
from django.test import TestCase, override_settings

from .models import CustodyEvent, CustodyHead, EvidenceRecord
from .service import issue_certificate, record_custody, verify_custody_chain
from .tests_cases import CaseFixtureMixin


class EndOfLog(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.record = self._ingest(exhibit_number='EX-END-1', collected_by=self.io,
                                   provenance=EvidenceRecord.Provenance.SEIZED)
        for _ in range(3):
            record_custody(self.record, CustodyEvent.Action.VIEWED, actor=self.io)

    def _events(self):
        return list(self.record.custody_events.order_by('sequence'))

    def test_the_recorded_end_follows_every_entry(self):
        head = CustodyHead.objects.get(evidence=self.record)
        events = self._events()
        self.assertEqual(head.entry_count, len(events))
        self.assertEqual(head.head_hash, events[-1].entry_hash)
        self.assertEqual(verify_custody_chain(self.record), (True, []))

    def test_removing_the_last_entries_is_detected(self):
        events = self._events()
        CustodyEvent.objects.filter(pk__in=[e.pk for e in events[-2:]]).delete()
        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)
        self.assertTrue(any(f'entries after #{len(events) - 2} are missing' in p
                            for p in problems), problems)

    def test_replacing_the_last_entry_with_a_valid_link_is_detected(self):
        """The chain re-derives; only the recorded head hash tells them apart."""
        last = self._events()[-1]
        last.detail = 'a different account of the last step'
        last.entry_hash = last.compute_hash()
        last.save(update_fields=['detail', 'entry_hash'])
        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)
        self.assertIn('the last entry is not the one recorded as the end of the log', problems)

    def test_a_log_with_no_recorded_end_says_so(self):
        CustodyHead.objects.filter(evidence=self.record).delete()
        ok, problems = verify_custody_chain(self.record)
        self.assertFalse(ok)
        self.assertTrue(any('no recorded end' in p for p in problems), problems)

    def test_the_migration_records_the_end_of_existing_logs(self):
        CustodyHead.objects.filter(evidence=self.record).delete()
        migration = importlib.import_module('evidence.migrations.0012_custody_head')
        migration.record_existing_ends(apps, None)
        self.assertEqual(verify_custody_chain(self.record), (True, []))


class CertificateCustodyAnnex(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.enterContext(override_settings(CERTIFICATE_ROOT=Path(self.tmp) / 'certs'))
        self.record = self._ingest(exhibit_number='EX-END-2', collected_by=self.io,
                                   provenance=EvidenceRecord.Provenance.SEIZED)
        record_custody(self.record, CustodyEvent.Action.VIEWED, actor=self.io)

    def test_the_badge_leads_and_the_end_of_the_log_is_printed(self):
        cert = issue_certificate(self.record, part_a_user=self.io, part_a_name='R. Patel',
                                 part_a_designation='IO', part_a_organisation='Cyber Crime PS',
                                 part_a_address='Ahmedabad')
        done = subprocess.run(['pdftotext', '-raw', str(cert.pdf_path), '-'],
                              capture_output=True, text=True, check=False)
        if done.returncode != 0:
            self.skipTest('pdftotext unavailable')
        text = ''.join(done.stdout.split())
        self.assertIn('GP-1001·io', text)
        # Rendered after the entry that records the issue, so that entry is
        # the end printed.
        head = CustodyHead.objects.get(evidence=self.record)
        last = self.record.custody_events.order_by('-sequence').first()
        self.assertEqual(last.action, CustodyEvent.Action.CERTIFICATE_ISSUED)
        self.assertIn(head.head_hash, text)
        self.assertIn(f'{head.entry_count}entries', text)
