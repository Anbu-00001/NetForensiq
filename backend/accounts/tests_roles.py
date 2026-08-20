"""
Tests over the separation of duties between the four roles.

The point of these is one sentence: **an investigator must not be able to
complete a certificate on their own, even with a second investigator's login.**

Before the examiner role existed, `sign_part_b` checked only that the
countersigning account differed from the one that signed Part A. Two
investigators satisfy that, and two investigators are interchangeable — so the
BSA 2023 s.63(4) guarantee that the person in charge of the device and the
expert are different people reduced to "somebody remembered to use a second
login". The tests below hold the stronger rule.
"""

from django.test import TestCase
from rest_framework.test import APIClient

from capture.models import CaptureSession, Detection
from evidence.models import Case, CaseAssignment
from evidence.service import ingest_evidence, issue_certificate, sign_part_b
from evidence.tests import make_capture_file

from .models import User


class RoleSeparationTests(TestCase):
    def setUp(self):
        self.record = ingest_evidence(make_capture_file())
        self.io = User.objects.create_user(
            username='io', password='x', badge_id='GJ-IO', department='Cyber',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.second_io = User.objects.create_user(
            username='io2', password='x', badge_id='GJ-IO2', department='Cyber',
            role=User.Role.INVESTIGATOR, is_approved=True,
        )
        self.examiner = User.objects.create_user(
            username='fsl', password='x', badge_id='GJ-FSL', department='FSL',
            role=User.Role.EXPERT, is_approved=True,
        )
        self.viewer = User.objects.create_user(
            username='records', password='x', badge_id='GJ-V', department='Records',
            role=User.Role.VIEWER, is_approved=True,
        )

    # ── the rule that was missing ───────────────────────────────────────────

    def test_a_second_investigator_cannot_countersign(self):
        """
        The regression this whole change exists for. This test passed before
        the examiner role, because the only check was that the two accounts
        differed — which any two investigators satisfy.
        """
        cert = issue_certificate(self.record, part_a_user=self.io)
        with self.assertRaises(ValueError) as caught:
            sign_part_b(cert, user=self.second_io, qualification='B.Tech')

        message = str(caught.exception)
        self.assertIn('does not hold examiner standing', message)
        cert.refresh_from_db()
        self.assertFalse(cert.is_complete)

    def test_the_examiner_can_countersign(self):
        cert = issue_certificate(self.record, part_a_user=self.io)
        cert = sign_part_b(cert, user=self.examiner, qualification='M.Tech, CHFI')
        self.assertTrue(cert.is_complete)
        self.assertEqual(cert.part_b_user, self.examiner)

    def test_one_account_still_cannot_sign_both_halves(self):
        """
        An administrator holds examiner standing, so the different-person rule
        has to stand on its own rather than falling out of the role check.
        """
        admin = User.objects.create_user(
            username='boss', password='x', badge_id='GJ-A', department='Cyber',
            role=User.Role.ADMIN, is_approved=True,
        )
        cert = issue_certificate(self.record, part_a_user=admin)
        with self.assertRaises(ValueError) as caught:
            sign_part_b(cert, user=admin)
        self.assertIn('different people', str(caught.exception))

    def test_an_investigator_assigned_as_the_cases_examiner_may_countersign(self):
        """
        The seconded-officer case. Standing can come from the case file as well
        as from the account, which is what makes a `CaseAssignment` capacity
        mean something instead of being a label in a sidebar.
        """
        case = Case.objects.create(
            case_number='C-1', title='t', opened_on='2026-01-01',
            created_by=self.io,
        )
        self.record.case = case
        self.record.save(update_fields=['case'])
        CaseAssignment.objects.create(
            case=case, officer=self.second_io,
            role=CaseAssignment.Role.EXPERT, assigned_by=self.io,
        )

        cert = issue_certificate(self.record, part_a_user=self.io)
        cert = sign_part_b(cert, user=self.second_io, qualification='M.Sc')
        self.assertTrue(cert.is_complete)

    # ── each role's actual reach ────────────────────────────────────────────

    def _client(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        return client

    def test_the_examiner_cannot_triage_a_finding(self):
        """
        The other half of the separation. If the examiner could also make the
        investigative decision, the two roles would differ only in name.
        """
        session = CaptureSession.objects.create(
            name='s', source_type='pcap', state='completed')
        finding = Detection.objects.create(
            session=session, rule_id='C2_BEACON_PERIODIC', title='t',
            category='c2', severity='high', rationale='r', subject_ip='10.0.0.1',
        )
        response = self._client(self.examiner).post(
            f'/api/detections/{finding.id}/triage/',
            {'status': 'confirmed'}, format='json')
        self.assertEqual(response.status_code, 403)

        # And the investigator can, so the refusal is about the role and not
        # about the endpoint being broken.
        allowed = self._client(self.io).post(
            f'/api/detections/{finding.id}/triage/',
            {'status': 'confirmed'}, format='json')
        self.assertEqual(allowed.status_code, 200)

    def test_the_investigator_is_refused_at_the_sign_endpoint(self):
        cert = issue_certificate(self.record, part_a_user=self.io)
        response = self._client(self.second_io).post(
            f'/api/certificates/{cert.id}/sign/',
            {'qualification': 'B.Tech'}, format='json')
        self.assertEqual(response.status_code, 403)
        self.assertIn('Examiner', response.json()['detail'])

    def test_the_examiner_may_read_the_contents_of_a_communication(self):
        """
        Reading a reconstructed session is gated above viewer. The examiner is
        the person whose job is to read it and speak to it, so withholding it
        would be an odd reading of the word "expert".
        """
        from accounts.permissions import CanReadCommunicationContent

        permission = CanReadCommunicationContent()

        class Req:
            method = 'GET'

        for user, allowed in ((self.examiner, True), (self.io, True),
                              (self.viewer, False)):
            request = Req()
            request.user = user
            self.assertIs(
                permission.has_permission(request, None), allowed,
                f'{user.username} ({user.role})',
            )

    def test_the_four_roles_are_four_distinct_permission_sets(self):
        """
        The demonstration presents four logins. Before this change they were
        three roles and a duplicate — `expert` held exactly the investigator's
        permissions — so a judge asking "what can the examiner do that the
        investigator cannot" had no answer.
        """
        from accounts.permissions import (
            CanReadCommunicationContent, IsAdministrator, IsExaminer,
            IsInvestigatorOrReadOnly,
        )

        admin = User.objects.create_user(
            username='adm', password='x', badge_id='GJ-AD', department='Cyber',
            role=User.Role.ADMIN, is_approved=True,
        )

        class Write:
            method = 'POST'

        def profile(user):
            write, examine, administer, content = (
                Write(), Write(), Write(), Write())
            for request in (write, examine, administer, content):
                request.user = user
            return (
                IsInvestigatorOrReadOnly().has_permission(write, None),
                IsExaminer().has_permission(examine, None),
                IsAdministrator().has_permission(administer, None),
                CanReadCommunicationContent().has_permission(content, None),
            )

        profiles = {
            'admin': profile(admin),
            'investigator': profile(self.io),
            'expert': profile(self.examiner),
            'viewer': profile(self.viewer),
        }

        # Every role differs from every other in at least one capability.
        self.assertEqual(len(set(profiles.values())), 4, profiles)

        # And specifically the pair that used to be identical.
        self.assertNotEqual(profiles['investigator'], profiles['expert'])
        self.assertEqual(profiles['investigator'], (True, False, False, True))
        self.assertEqual(profiles['expert'], (False, True, False, True))
        self.assertEqual(profiles['viewer'], (False, False, False, False))
