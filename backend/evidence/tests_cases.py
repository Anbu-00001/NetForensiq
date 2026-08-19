"""
Tests for case management and the s.193(3)(i) custody register.

The claim under test is narrow and worth stating plainly: linking an exhibit to
an investigation must never quietly rewrite what the exhibit says about itself,
and the register produced for a charge sheet must not attest to anything a
database can't actually attest to.
"""

import datetime
import tempfile
from pathlib import Path

from django.test import TestCase, override_settings

from accounts.models import User

from .custody_register import SIGNATURE_COLUMN, build_register
from .models import Case, CaseAssignment, CustodyEvent
from .service import ingest_evidence, link_evidence_to_case
from .tests import make_capture_file


class CaseFixtureMixin:
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.io = User.objects.create_user(
            username='io', password='x', badge_id='GP-1001',
            first_name='Rakesh', last_name='Patel',
        )
        self.expert = User.objects.create_user(
            username='fsl', password='x', badge_id='FSL-22',
            first_name='Meera', last_name='Shah',
        )
        self.case = Case.objects.create(
            case_number='CYB/2026/0041',
            title='Unauthorised access to a co-operative bank server',
            fir_number='0113/2026',
            police_station='Cyber Crime PS, Ahmedabad City',
            district='Ahmedabad',
            offence_sections='BNS s.319, IT Act s.66',
            opened_on=datetime.date(2026, 3, 4),
            investigating_officer=self.io,
        )

    def _ingest(self, **kwargs):
        with override_settings(EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'):
            return ingest_evidence(make_capture_file(), **kwargs)


class CaseModelTests(CaseFixtureMixin, TestCase):
    def test_reference_line_carries_the_identifiers_a_court_uses(self):
        self.assertEqual(
            self.case.reference_line,
            'CYB/2026/0041 · FIR 0113/2026 · Cyber Crime PS, Ahmedabad City',
        )

    def test_reference_line_omits_what_is_not_recorded(self):
        """A case with no FIR yet must not print 'FIR ' followed by nothing."""
        bare = Case.objects.create(
            case_number='CYB/2026/0042', title='Preliminary enquiry',
            police_station='Cyber Crime PS', opened_on=datetime.date(2026, 3, 5),
        )
        self.assertEqual(bare.reference_line, 'CYB/2026/0042 · Cyber Crime PS')

    def test_one_officer_holds_one_capacity_on_a_case(self):
        """
        The same person as both investigating officer and countersigning
        expert defeats the separation BSA s.63(4) exists to create.
        """
        CaseAssignment.objects.create(
            case=self.case, officer=self.io, role=CaseAssignment.Role.IO,
        )
        with self.assertRaises(Exception):
            CaseAssignment.objects.create(
                case=self.case, officer=self.io, role=CaseAssignment.Role.EXPERT,
            )


class LinkingTests(CaseFixtureMixin, TestCase):
    def test_linking_records_a_custody_movement(self):
        record = self._ingest(exhibit_number='EX-1', collected_by=self.io)
        before = record.custody_events.count()

        link_evidence_to_case(record, self.case, actor=self.io)

        record.refresh_from_db()
        self.assertEqual(record.case, self.case)
        self.assertEqual(record.custody_events.count(), before + 1)
        last = record.custody_events.order_by('-sequence').first()
        self.assertEqual(last.action, CustodyEvent.Action.CASE_LINKED)
        self.assertIn('CYB/2026/0041', last.detail)

    def test_relinking_the_same_case_is_not_a_second_movement(self):
        record = self._ingest(exhibit_number='EX-2', collected_by=self.io)
        link_evidence_to_case(record, self.case, actor=self.io)
        count = record.custody_events.count()

        link_evidence_to_case(record, self.case, actor=self.io)

        self.assertEqual(record.custody_events.count(), count)

    def test_moving_an_exhibit_between_cases_is_refused(self):
        other = Case.objects.create(
            case_number='CYB/2026/0099', title='Unrelated',
            police_station='Cyber Crime PS', opened_on=datetime.date(2026, 4, 1),
        )
        record = self._ingest(exhibit_number='EX-3', collected_by=self.io)
        link_evidence_to_case(record, self.case, actor=self.io)

        with self.assertRaises(ValueError):
            link_evidence_to_case(record, other, actor=self.io)

    def test_a_reference_that_disagrees_is_surfaced_not_corrected(self):
        """
        The seizure memo said one thing. If the case record says another, the
        officer has to see the discrepancy — it is a fact about the
        investigation, not a data-entry defect for software to tidy away.
        """
        record = self._ingest(
            exhibit_number='EX-4', collected_by=self.io,
            case_reference='CYB/2025/0007',
        )

        link_evidence_to_case(record, self.case, actor=self.io)

        record.refresh_from_db()
        # The original reference is untouched...
        self.assertEqual(record.case_reference, 'CYB/2025/0007')
        # ...and the mismatch is on the record.
        last = record.custody_events.order_by('-sequence').first()
        self.assertIn('does not match this case', last.detail)
        self.assertIn('CYB/2025/0007', last.detail)


class CustodyRegisterTests(CaseFixtureMixin, TestCase):
    def setUp(self):
        super().setUp()
        self.record = self._ingest(
            exhibit_number='EX-REG-1', collected_by=self.io,
            seized_from='Server room, 2nd floor',
        )
        link_evidence_to_case(self.record, self.case, actor=self.io)

    def test_register_cites_its_statutory_basis(self):
        register = build_register(self.record)
        self.assertIn('193(3)(i)', register['statutory_basis'])
        self.assertIn('2025 INSC 845', register['statutory_basis'])

    def test_every_movement_carries_a_reason(self):
        """
        Kattavellai asks for the reason for each movement, not only the fact of
        it. A blank reason must read as 'not recorded' rather than as nothing.
        """
        register = build_register(self.record)
        self.assertTrue(register['entries'])
        for entry in register['entries']:
            self.assertTrue(entry['reason'])

    def test_the_signature_column_is_printed_empty(self):
        """
        The direction wants a counter-signature from the person who made the
        movement. A row saying who was logged in is not that, so the column is
        left for a pen.
        """
        register = build_register(self.record)
        self.assertEqual(register['signature_column'], SIGNATURE_COLUMN)
        self.assertTrue(all(e['signature'] == '' for e in register['entries']))

    def test_the_officer_is_named_with_their_badge(self):
        register = build_register(self.record)
        acquired = register['entries'][0]
        self.assertIn('Rakesh Patel', acquired['officer'])
        self.assertIn('GP-1001', acquired['officer'])

    def test_case_identifiers_come_from_the_case_record(self):
        register = build_register(self.record)
        self.assertEqual(register['case']['fir_number'], '0113/2026')
        self.assertEqual(register['case']['district'], 'Ahmedabad')

    def test_an_unlinked_exhibit_still_produces_a_register(self):
        """
        An exhibit seized before the case was opened must not crash the
        document that has to accompany it.
        """
        loose = self._ingest(exhibit_number='EX-REG-2', collected_by=self.io)
        register = build_register(loose)
        self.assertEqual(register['case']['case_number'], '')
        self.assertTrue(register['entries'])

    def test_a_broken_chain_is_reported_not_hidden(self):
        event = self.record.custody_events.order_by('sequence').first()
        event.detail = 'edited after the fact'
        event.save(update_fields=['detail'])

        register = build_register(self.record)

        self.assertFalse(register['integrity']['chain_intact'])
        self.assertTrue(register['integrity']['problems'])

    def test_the_register_states_how_integrity_was_checked(self):
        register = build_register(self.record)
        self.assertIn('SHA-256', register['integrity']['method'])
