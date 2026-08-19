"""
Tests for the operator strip.

The strip is a permanent claim about the state of the holding, so what is
under test here is mostly the *shape* of what it refuses to say: that the
90-day clock stops when a case does, that a deadline is labelled as the duty
it actually is, that a half-signed certificate is counted as incomplete rather
than as a certificate, and that "nowhere to write" is reported instead of
crashing the panel that would have warned about it.
"""

import datetime
import tempfile
from pathlib import Path
from unittest import mock

from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from accounts.models import User
from capture.models import CaptureSession, Detection

from . import posture
from .models import Case, CaseAssignment, EvidenceRecord, Section63Certificate
from .service import ingest_evidence, link_evidence_to_case
from .tests import make_capture_file


class TriageBacklogTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(
            name='s', source_type=CaptureSession.Source.PCAP,
        )

    def _finding(self, severity, status=Detection.Triage.NEW):
        return Detection.objects.create(
            session=self.session, rule_id='R', title='t', category='c',
            severity=severity, rationale='r', triage_status=status,
        )

    def test_counts_only_what_nobody_has_reviewed(self):
        self._finding('critical')
        self._finding('high')
        self._finding('high', Detection.Triage.CONFIRMED)
        self._finding('low', Detection.Triage.DISMISSED)

        state = posture.triage_backlog()
        self.assertEqual(state['awaiting_review'], 2)
        self.assertEqual(state['by_severity']['high'], 1)
        self.assertEqual(state['by_severity']['low'], 0)

    def test_names_the_worst_thing_waiting(self):
        """
        A backlog of 400 mediums and one critical is the same number as 401
        mediums, and a completely different morning. The strip has room for one
        word about it, so that word has to be the worst severity present.
        """
        for _ in range(5):
            self._finding('medium')
        self.assertEqual(posture.triage_backlog()['worst_waiting'], 'medium')
        self._finding('critical')
        self.assertEqual(posture.triage_backlog()['worst_waiting'], 'critical')

    def test_an_empty_queue_names_nothing(self):
        state = posture.triage_backlog()
        self.assertEqual(state['awaiting_review'], 0)
        self.assertEqual(state['worst_waiting'], '')


class DocketClockTests(TestCase):
    """
    BNSS 2023 s.193(3)(ii). The statute is a duty to *inform the informant or
    victim of progress* within ninety days of the FIR. Every test here exists
    because getting one of these wrong would print a confident, wrong deadline
    on a criminal matter.
    """

    def setUp(self):
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='GP-1',
        )
        self.today = timezone.localdate()

    def _case(self, days_ago, status=Case.Status.INVESTIGATION, number='C/1'):
        case = Case.objects.create(
            case_number=number, title='t', police_station='PS',
            status=status,
            opened_on=self.today - datetime.timedelta(days=days_ago),
        )
        CaseAssignment.objects.create(
            case=case, officer=self.officer, role=CaseAssignment.Role.IO,
        )
        return case

    def test_the_day_the_fir_was_recorded_is_day_one(self):
        """A police diary counts the day of registration as day one. An
        off-by-one here is a day of somebody's deadline."""
        self._case(days_ago=0)
        clock = posture.case_docket(self.officer)['cases'][0]['informant_update']
        self.assertEqual(clock['day'], 1)
        self.assertEqual(clock['days_left'], 89)
        self.assertFalse(clock['overdue'])

    def test_ninety_days_is_not_yet_overdue_and_ninety_one_is(self):
        self._case(days_ago=89, number='C/A')          # day 90
        self._case(days_ago=90, number='C/B')          # day 91
        by_number = {c['case_number']: c
                     for c in posture.case_docket(self.officer)['cases']}
        self.assertFalse(by_number['C/A']['informant_update']['overdue'])
        self.assertTrue(by_number['C/B']['informant_update']['overdue'])

    def test_the_clock_stops_when_the_case_does(self):
        """
        A charge-sheeted case has had its report filed under s.193. Continuing
        to nag about a progress update on it would be noise, and noise in a
        permanent strip is how a real warning gets ignored.
        """
        self._case(days_ago=400, status=Case.Status.CHARGESHEETED, number='C/X')
        self._case(days_ago=400, status=Case.Status.CLOSED, number='C/Y')
        docket = posture.case_docket(self.officer)
        self.assertEqual(docket['updates_due'], 0)
        for row in docket['cases']:
            self.assertIsNone(row['informant_update'])

    def test_the_duty_travels_with_the_number(self):
        """
        This is the whole risk of the feature. It is a notification deadline,
        not a deadline to finish the investigation and not the s.187(3)
        default-bail clock, and a number rendered without that label is a
        number an officer can act on wrongly.
        """
        self._case(days_ago=10)
        clock = posture.case_docket(self.officer)['cases'][0]['informant_update']
        self.assertEqual(clock['authority'], 'BNSS 2023 s.193(3)(ii)')
        self.assertIn('informant', clock['duty'].lower())
        self.assertNotIn('bail', clock['duty'].lower())
        self.assertNotIn('charge', clock['duty'].lower())

    def test_overdue_cases_come_first(self):
        self._case(days_ago=5, number='C/NEW')
        self._case(days_ago=200, number='C/OLD')
        rows = posture.case_docket(self.officer)['cases']
        self.assertEqual(rows[0]['case_number'], 'C/OLD')

    def test_an_officer_sees_only_their_own_cases(self):
        self._case(days_ago=5)
        other = User.objects.create_user(username='other', password='x', badge_id='GP-2')
        self.assertEqual(posture.case_docket(other)['total'], 0)

    def test_capacity_is_reported_because_s63_needs_two_people(self):
        self._case(days_ago=5)
        row = posture.case_docket(self.officer)['cases'][0]
        self.assertEqual(row['capacity'], 'io')
        self.assertEqual(row['capacity_label'], 'Investigating Officer')

    def test_an_anonymous_reader_gets_an_empty_docket(self):
        from django.contrib.auth.models import AnonymousUser
        self.assertEqual(posture.case_docket(AnonymousUser())['total'], 0)


class CertificateStateTests(TestCase):
    """
    BSA 2023 s.63(4) requires both signatures conjunctively. A certificate
    carrying only Part A is not a weaker certificate; it is not one.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='GP-1',
        )
        with override_settings(EVIDENCE_ROOT=self.tmp):
            self.record = ingest_evidence(
                make_capture_file(), collected_by=self.officer,
                case_reference='C/1',
            )

    def _certificate(self, part_a=False, part_b=False, reference='CERT/1'):
        now = timezone.now()
        return Section63Certificate.objects.create(
            evidence=self.record, reference=reference,
            certified_sha256='0' * 64,
            part_a_signed_at=now if part_a else None,
            part_b_signed_at=now if part_b else None,
        )

    def test_part_a_alone_counts_as_incomplete(self):
        self._certificate(part_a=True)
        state = posture.certificate_state()
        self.assertEqual(state['complete'], 0)
        self.assertEqual(state['awaiting_part_b'], 1)
        self.assertEqual(state['incomplete'], 1)

    def test_part_b_alone_is_counted_separately_from_part_a_alone(self):
        """Different failures with different fixes: one needs an expert, the
        other needs the person who held the device."""
        self._certificate(part_b=True)
        state = posture.certificate_state()
        self.assertEqual(state['awaiting_part_a'], 1)
        self.assertEqual(state['awaiting_part_b'], 0)

    def test_both_signed_is_the_only_complete_state(self):
        self._certificate(part_a=True, part_b=True)
        state = posture.certificate_state()
        self.assertEqual(state['complete'], 1)
        self.assertEqual(state['incomplete'], 0)

    def test_an_unsigned_draft_is_neither_complete_nor_silently_ignored(self):
        self._certificate()
        state = posture.certificate_state()
        self.assertEqual(state['unsigned'], 1)
        self.assertEqual(state['incomplete'], 1)


class StoreHeadroomTests(TestCase):
    def test_reports_free_space_on_the_volume_holding_evidence(self):
        with override_settings(EVIDENCE_ROOT=tempfile.mkdtemp()):
            state = posture.store_headroom()
        self.assertTrue(state['available'])
        self.assertGreater(state['total_bytes'], 0)
        self.assertEqual(
            state['used_bytes'] + state['free_bytes'] <= state['total_bytes'], True,
        )

    def test_a_store_that_does_not_exist_yet_measures_its_future_volume(self):
        """
        The directory is created on first seizure. Before then, "cannot stat"
        would be a misleading answer to "is there room" — the question is about
        the volume, and the volume is there.
        """
        missing = Path(tempfile.mkdtemp()) / 'not' / 'created' / 'yet'
        with override_settings(EVIDENCE_ROOT=missing):
            state = posture.store_headroom()
        self.assertTrue(state['available'])
        self.assertEqual(state['path'], str(missing))
        self.assertNotEqual(state['measured_on'], str(missing))

    def test_an_unreadable_path_is_reported_and_does_not_raise(self):
        """
        The panel that would warn about a full disk must not be the panel that
        takes the sidebar down.
        """
        with override_settings(EVIDENCE_ROOT='/tmp/x'), \
                mock.patch('shutil.disk_usage', side_effect=OSError('boom')):
            state = posture.store_headroom()
        self.assertFalse(state['available'])
        self.assertIn('boom', state['error'])

    def test_thresholds_are_named_in_the_payload(self):
        """A colour without its threshold is an opinion. The reader gets the
        number that produced it."""
        with override_settings(EVIDENCE_ROOT=tempfile.mkdtemp()):
            state = posture.store_headroom()
        self.assertEqual(state['warn_below_pct'], posture.DISK_WARN_PCT)
        self.assertEqual(state['critical_below_pct'], posture.DISK_CRITICAL_PCT)

    def test_no_time_remaining_estimate_is_offered(self):
        """
        Deliberate absence. How long a capture can run depends on traffic
        nobody has seen yet, and a wrong reassurance is worse than a number.
        """
        with override_settings(EVIDENCE_ROOT=tempfile.mkdtemp()):
            state = posture.store_headroom()
        self.assertFalse(any('remaining' in k or 'eta' in k for k in state))


class CaptureHeartbeatTests(TestCase):
    def test_a_finished_capture_is_not_reported_as_running(self):
        """
        The failure this exists to prevent: a capture that died ten minutes ago
        looking identical to one that is recording.
        """
        CaptureSession.objects.create(
            name='done', source_type=CaptureSession.Source.LIVE,
            state=CaptureSession.State.COMPLETED, ended_at=timezone.now(),
        )
        state = posture.capture_heartbeat()
        self.assertFalse(state['running'])
        self.assertEqual(state['last_session']['name'], 'done')

    def test_a_running_capture_reports_its_counts_with_an_observation_time(self):
        CaptureSession.objects.create(
            name='live', source_type=CaptureSession.Source.LIVE,
            state=CaptureSession.State.RUNNING, packet_count=42, flow_count=7,
        )
        state = posture.capture_heartbeat()
        self.assertTrue(state['running'])
        self.assertEqual(state['session']['packet_count'], 42)
        # Without this the reader cannot tell a live figure from a stale one.
        self.assertTrue(state['observed_at'])

    def test_no_captures_at_all_is_not_an_error(self):
        state = posture.capture_heartbeat()
        self.assertFalse(state['running'])
        self.assertIsNone(state['last_session'])


class CustodyReconciliationTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='GP-1',
        )

    def _exhibit(self, name, reference):
        with override_settings(EVIDENCE_ROOT=self.tmp):
            return ingest_evidence(
                make_capture_file(f'pcap-{name}'.encode()),
                original_filename=name, collected_by=self.officer,
                case_reference=reference,
            )

    def test_an_exhibit_sealed_under_a_different_reference_is_counted(self):
        """
        The system refuses to rewrite what an exhibit was sealed bearing, and
        logs the disagreement instead. Logged is not the same as seen — this
        is what stops the first sighting being under cross-examination.
        """
        case = Case.objects.create(
            case_number='CYB/2026/1', title='t', police_station='PS',
            opened_on=timezone.localdate(),
        )
        record = self._exhibit('a.pcap', 'TYPO/2026/1')
        link_evidence_to_case(record, case, actor=self.officer)
        self.assertEqual(posture.custody_reconciliation()['mismatched_exhibits'], 1)

    def test_a_reference_matching_either_the_case_or_the_fir_is_not_flagged(self):
        case = Case.objects.create(
            case_number='CYB/2026/2', title='t', police_station='PS',
            fir_number='0113/2026', opened_on=timezone.localdate(),
        )
        by_case = self._exhibit('b.pcap', 'CYB/2026/2')
        by_fir = self._exhibit('c.pcap', '0113/2026')
        link_evidence_to_case(by_case, case, actor=self.officer)
        link_evidence_to_case(by_fir, case, actor=self.officer)
        self.assertEqual(posture.custody_reconciliation()['mismatched_exhibits'], 0)

    def test_an_unfiled_exhibit_cannot_disagree_with_anything(self):
        self._exhibit('d.pcap', 'WHATEVER')
        self.assertEqual(posture.custody_reconciliation()['mismatched_exhibits'], 0)


class PostureEndpointTests(TestCase):
    """The strip is one request by design; this holds it to that."""

    def setUp(self):
        self.officer = User.objects.create_user(
            username='io', password='x', badge_id='GP-1', is_approved=True,
        )
        # The API is token-authenticated, so a session login would be answered
        # with a 401 that says nothing about the view under test.
        self.client = APIClient()
        self.client.force_authenticate(user=self.officer)

    def test_every_block_the_sidebar_draws_arrives_in_one_response(self):
        response = self.client.get('/api/evidence/posture/')
        self.assertEqual(response.status_code, 200)
        for block in ('clock', 'encryption', 'exhibits', 'latest_exhibit',
                      'triage', 'certificates', 'docket', 'store',
                      'capture', 'custody'):
            self.assertIn(block, response.data)

    def test_the_clock_discloses_whether_the_hardware_clock_is_local_time(self):
        """
        Already computed by timesource and previously not rendered anywhere. A
        workstation with an RTC in local time reports exhibit timestamps that
        shift across a daylight-saving boundary.
        """
        response = self.client.get('/api/evidence/posture/')
        self.assertIn('rtc_in_local_time', response.data['clock'])

    def test_it_needs_a_signed_in_officer(self):
        self.client.force_authenticate(user=None)
        self.assertEqual(
            self.client.get('/api/evidence/posture/').status_code, 401,
        )
