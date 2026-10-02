# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Filing a MobSF report beside a sample (capture/second_opinion.py).

The fixtures in tests_data/ are real MobSF 4.5.4 reports from the comparison in
research/159, trimmed to the fields the importer reads: one is the hackathon
malware, whose manifest MobSF could not read (package "Failed", score 73), the
other a legitimate app. Where a test needs a report that describes a particular
sample, the real report's `sha256` is replaced with that sample's — the one
synthetic edit, made so the hash can be matched.

What is held:

* a report is tied to an exhibit by hash and by nothing else;
* a sample that arrived inside a ZIP is matched by the inner package's hash;
* the examination is recorded with the exhibit, so the two can be shown together;
* the report is stored as received and re-hashes to what was recorded;
* attaching it is a custody event and the chain still verifies;
* nothing a report contains is executed or trusted, and malformed input stores nothing.
"""
import hashlib
import io
import json
from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient

from apk_engine.tests import factories
from evidence import crypto
from evidence.models import CustodyEvent, EvidenceRecord
from evidence.service import verify_custody_chain

from . import second_opinion
from .models import ApkExamination, ThirdPartyReport

User = get_user_model()
DATA = Path(__file__).resolve().parent / 'tests_data'


def fixture(name):
    return (DATA / name).read_bytes()


def with_subject(name, sha256, **changes):
    """A real report, re-addressed to describe the package with `sha256`."""
    report = json.loads(fixture(name))
    report['sha256'] = sha256
    report.update(changes)
    return json.dumps(report).encode()


class ParseRealReportsTests(SimpleTestCase):
    def test_the_report_whose_manifest_mobsf_could_not_read_is_flagged_as_such(self):
        summary, _ = second_opinion.parse_mobsf(fixture('mobsf_4.5.4_unreadable_manifest.json'))
        self.assertEqual(summary['score'], 73)
        self.assertEqual(summary['package'], 'Failed')
        self.assertTrue(summary['manifest_unreadable'])
        self.assertEqual(summary['permission_count'], 0)
        self.assertTrue(any('can score well' in n for n in summary['notes']))
        self.assertIn('664e43ef02578bb6c44956471e1275f276e33e5af39ed50694f926241278f49a',
                      summary['subject']['sha256'])

    def test_what_mobsf_did_find_is_kept(self):
        summary, _ = second_opinion.parse_mobsf(fixture('mobsf_4.5.4_unreadable_manifest.json'))
        self.assertTrue(any('Resources Confusion' in line for line in summary['apkid']))
        self.assertTrue(any(d.endswith('trycloudflare.com') for d in summary['domains']))
        self.assertGreater(summary['behaviour_rules'], 0)

    def test_a_legitimate_apps_report_is_read_normally(self):
        summary, _ = second_opinion.parse_mobsf(fixture('mobsf_4.5.4_legitimate_app.json'))
        self.assertEqual((summary['score'], summary['package']), (52, 'de.blinkt.openvpn'))
        self.assertFalse(summary['manifest_unreadable'])
        self.assertGreater(len(summary['dangerous_permissions']), 0)
        self.assertGreater(sum(summary['components'].values()), 0)
        self.assertFalse(summary['virus_total_consulted'])

    def test_the_report_hash_is_of_the_bytes_filed(self):
        data = fixture('mobsf_4.5.4_legitimate_app.json')
        self.assertEqual(second_opinion.parse_mobsf(data)[1], hashlib.sha256(data).hexdigest())

    def test_the_score_is_never_presented_as_a_verdict(self):
        summary, _ = second_opinion.parse_mobsf(fixture('mobsf_4.5.4_legitimate_app.json'))
        self.assertIn('not whether an app is malicious', summary['score_note'])
        self.assertIn('research/159', summary['score_note'])


class RefusalTests(SimpleTestCase):
    def refused(self, data, fragment):
        with self.assertRaises(second_opinion.NotAMobsfReport) as caught:
            second_opinion.parse_mobsf(data)
        self.assertIn(fragment, str(caught.exception))

    def test_not_json(self):
        self.refused(b'not json at all', 'not valid JSON')

    def test_json_that_is_not_an_object(self):
        self.refused(b'[1, 2, 3]', 'not an object')

    def test_no_hash_means_it_cannot_be_tied_to_anything(self):
        self.refused(json.dumps({'appsec': {}}).encode(), 'no SHA-256')

    def test_a_hash_that_is_not_a_hash_is_the_same_as_none(self):
        self.refused(json.dumps({'sha256': 'z' * 64, 'appsec': {}}).encode(), 'no SHA-256')
        self.refused(json.dumps({'sha256': 'ab' * 20, 'appsec': {}}).encode(), 'no SHA-256')

    def test_a_hash_alone_is_not_a_mobsf_report(self):
        self.refused(json.dumps({'sha256': 'a' * 64}).encode(), 'none of the sections')

    def test_an_oversized_file_is_refused_before_it_is_parsed(self):
        self.refused(b'0' * (second_opinion.MAX_REPORT_BYTES + 1), 'larger than')

    def test_pathologically_nested_json_is_a_refusal_not_a_crash(self):
        self.refused(b'[' * 200000 + b']' * 200000, 'not valid JSON')


class HostileContentTests(SimpleTestCase):
    def report(self, **changes):
        base = {'sha256': 'a' * 64, 'version': 'v4.5.4', 'package_name': 'p',
                'appsec': {'security_score': 50, 'high': [], 'warning': [], 'info': []},
                'permissions': {'android.permission.INTERNET': {'status': 'normal'}}}
        base.update(changes)
        return json.dumps(base).encode()

    def test_markup_in_a_finding_stays_text(self):
        payload = '<img src=x onerror=alert(1)><script>alert(2)</script>'
        summary, _ = second_opinion.parse_mobsf(self.report(
            appsec={'security_score': 50, 'high': [{'title': payload}], 'warning': [], 'info': []}))
        self.assertEqual(summary['appsec_high'], [payload])  # kept as the literal string

    def test_lists_and_strings_are_bounded(self):
        many = [{'title': 'x' * 5000}] * 500
        summary, _ = second_opinion.parse_mobsf(self.report(
            appsec={'security_score': 50, 'high': many, 'warning': many, 'info': []},
            domains={f'h{i}.example': {} for i in range(5000)}))
        self.assertEqual(len(summary['appsec_high']), 25)
        self.assertTrue(all(len(t) <= 200 for t in summary['appsec_high']))
        self.assertLessEqual(len(summary['domains']), 40)
        self.assertEqual(summary['appsec_counts']['high'], 500)  # the true count is still reported

    def test_wrong_types_are_ignored_not_trusted(self):
        summary, _ = second_opinion.parse_mobsf(self.report(
            appsec={'security_score': '99; drop table', 'high': 'not a list'},
            permissions='nope', domains=['x'], apkid=7, trackers=3))
        self.assertIsNone(summary['score'])
        self.assertEqual(summary['appsec_counts']['high'], 0)
        self.assertEqual(summary['domains'], [])

    def test_a_score_outside_zero_to_a_hundred_is_dropped(self):
        for bad in (-1, 101, 1e9, True):
            summary, _ = second_opinion.parse_mobsf(self.report(
                appsec={'security_score': bad}))
            self.assertIsNone(summary['score'] if bad is not True else None)

    def test_a_report_that_consulted_virustotal_says_so(self):
        summary, _ = second_opinion.parse_mobsf(self.report(virus_total={'positives': 3}))
        self.assertTrue(summary['virus_total_consulted'])
        self.assertTrue(any('VirusTotal' in n for n in summary['notes']))

    def test_another_major_version_is_accepted_and_flagged(self):
        summary, _ = second_opinion.parse_mobsf(self.report(version='v3.9.0'))
        self.assertTrue(any('Only MobSF 4.x was tested' in n for n in summary['notes']))
        summary, _ = second_opinion.parse_mobsf(self.report(version=''))
        self.assertTrue(any('unknown version' in n for n in summary['notes']))

    def test_the_hash_is_lower_cased(self):
        summary, _ = second_opinion.parse_mobsf(self.report(sha256='AB' * 32))
        self.assertEqual(summary['subject']['sha256'], 'ab' * 32)


class FilingFixture:
    def setUp(self):
        super().setUp()
        cache.clear()
        self.client = APIClient()
        self.examiner = User.objects.create_user(
            username='so-examiner', password='a-long-enough-password', badge_id='B-7001',
            department='FSL', role=User.Role.EXPERT, is_approved=True)
        self.investigator = User.objects.create_user(
            username='so-investigator', password='a-long-enough-password', badge_id='B-7002',
            department='Cyber', role=User.Role.INVESTIGATOR, is_approved=True)
        self.viewer = User.objects.create_user(
            username='so-viewer', password='a-long-enough-password', badge_id='B-7003',
            department='Records', role=User.Role.VIEWER, is_approved=True)

    def examine(self, payload, name='sample.apk'):
        """Seal and examine through the real view and the real engine process."""
        self.client.force_authenticate(user=self.examiner)
        upload = io.BytesIO(payload)
        upload.name = name
        response = self.client.post(
            '/api/samples/examine/', {'file': upload, 'provenance': 'seized'}, format='multipart')
        self.assertEqual(response.status_code, 201, response.content[:300])
        return response.json()

    def file_report(self, data, user=None, **extra):
        self.client.force_authenticate(user=user or self.examiner)
        upload = io.BytesIO(data)
        upload.name = 'report.json'
        return self.client.post('/api/samples/second-opinion/', {'file': upload, **extra},
                                format='multipart')


class ExaminationIsRecordedTests(FilingFixture, TestCase):
    def test_a_bare_apk_records_its_own_hash_as_the_examined_one(self):
        apk = factories.apk()
        body = self.examine(apk)
        exam = ApkExamination.objects.get()
        self.assertEqual(exam.analysed_sha256, hashlib.sha256(apk).hexdigest())
        self.assertEqual(exam.evidence.exhibit_number, body['exhibit_number'])
        self.assertEqual(exam.tier, body['assessment']['tier'])
        self.assertEqual(exam.package, body['identity']['package'])
        self.assertEqual(exam.examined_by, self.examiner)
        self.assertEqual(len(exam.baselines_sha256), 64)

    def test_a_wrapped_sample_records_the_inner_packages_hash_not_the_zips(self):
        """
        The exhibit's hash is the ZIP's; every other tool that examines the package
        reports the inner file's. This is the column that lets the two be matched.
        """
        apk = factories.apk()
        wrapped = factories.zip_with({'inner.apk': apk})
        self.examine(wrapped, name='received.zip')
        exam = ApkExamination.objects.get()
        self.assertEqual(exam.analysed_sha256, hashlib.sha256(apk).hexdigest())
        self.assertNotEqual(exam.analysed_sha256, exam.evidence.sha256_hash)
        self.assertEqual(exam.evidence.sha256_hash, hashlib.sha256(wrapped).hexdigest())

    def test_the_basis_is_recorded_as_ids_not_prose(self):
        self.examine(factories.forge_compression_method(factories.apk()))
        exam = ApkExamination.objects.get()
        self.assertIsInstance(exam.basis_ids, list)
        self.assertTrue(all(isinstance(i, str) and len(i) <= 120 for i in exam.basis_ids))


class FilingTests(FilingFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.apk = factories.apk()
        self.exhibit_body = self.examine(self.apk)
        self.exhibit = EvidenceRecord.objects.get(exhibit_number=self.exhibit_body['exhibit_number'])
        self.sha = hashlib.sha256(self.apk).hexdigest()

    def test_a_report_for_an_examined_package_is_linked_and_compared(self):
        response = self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', self.sha))
        self.assertEqual(response.status_code, 201, response.content[:300])
        body = response.json()
        self.assertEqual(body['exhibit_number'], self.exhibit.exhibit_number)
        self.assertEqual(body['matched_by'], 'examined')
        self.assertEqual(body['netforensiq_examination']['tier'], self.exhibit_body['assessment']['tier'])
        aspects = {row['aspect'] for row in body['comparison']}
        self.assertIn('Conclusion', aspects)
        conclusion = next(r for r in body['comparison'] if r['aspect'] == 'Conclusion')
        self.assertIn('No conclusion about malice', conclusion['mobsf'])
        self.assertNotIn('agree', json.dumps(body['comparison']).lower())  # no agreement score

    def test_attaching_is_a_custody_event_that_names_the_hashes(self):
        data = with_subject('mobsf_4.5.4_legitimate_app.json', self.sha)
        self.file_report(data)
        event = self.exhibit.custody_events.filter(action=CustodyEvent.Action.REPORT_ATTACHED).get()
        self.assertIn(hashlib.sha256(data).hexdigest(), event.detail)
        self.assertIn(self.sha, event.detail)
        self.assertIn('not evidence', event.detail)
        self.assertEqual(event.actor, self.examiner)

    def test_the_custody_chain_still_verifies_after_attaching(self):
        self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', self.sha))
        ok, problems = verify_custody_chain(self.exhibit)
        self.assertTrue(ok, problems)

    def test_the_stored_report_re_hashes_to_what_was_recorded(self):
        data = with_subject('mobsf_4.5.4_legitimate_app.json', self.sha)
        body = self.file_report(data).json()
        report = ThirdPartyReport.objects.get()
        with crypto.readable(report.stored_path) as plain:
            self.assertEqual(hashlib.sha256(Path(plain).read_bytes()).hexdigest(),
                             body['report_sha256'])
        self.assertEqual(report.report_sha256, hashlib.sha256(data).hexdigest())

    def test_the_stored_report_is_encrypted_when_the_evidence_store_is(self):
        """It describes a hostile sample and quotes its strings: it is held like the exhibit."""
        report_bytes = with_subject('mobsf_4.5.4_legitimate_app.json', self.sha)
        self.file_report(report_bytes)
        stored = ThirdPartyReport.objects.get()
        self.assertTrue(stored.encrypted_at_rest)
        self.assertTrue(crypto.is_encrypted(stored.stored_path))
        self.assertNotIn(b'de.blinkt.openvpn', Path(stored.stored_path).read_bytes())

    def test_a_report_for_a_different_package_is_stored_but_never_linked(self):
        """The importer's word is not enough: two different hashes are two different files."""
        other = hashlib.sha256(b'a different package').hexdigest()
        before = self.exhibit.custody_events.count()
        response = self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', other))
        body = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertIsNone(body['exhibit_number'])
        self.assertEqual(body['matched_by'], 'none')
        self.assertIn('Two different hashes are two different files', body['unlinked_reason'])
        self.assertEqual(self.exhibit.custody_events.count(), before)

    def test_the_same_report_filed_twice_is_one_opinion_not_two(self):
        data = with_subject('mobsf_4.5.4_legitimate_app.json', self.sha)
        self.file_report(data)
        second = self.file_report(data)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()['already_filed'])
        self.assertEqual(ThirdPartyReport.objects.count(), 1)
        self.assertEqual(self.exhibit.custody_events.filter(
            action=CustodyEvent.Action.REPORT_ATTACHED).count(), 1)

    def test_a_package_sealed_before_examinations_were_recorded_is_matched_by_its_sealed_hash(self):
        ApkExamination.objects.all().delete()
        body = self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', self.sha)).json()
        self.assertEqual(body['matched_by'], 'sealed')
        self.assertEqual(body['exhibit_number'], self.exhibit.exhibit_number)
        self.assertIsNone(body['netforensiq_examination'])  # no conclusion is invented

    def test_a_sample_that_arrived_in_a_zip_is_found_by_the_inner_hash(self):
        inner = factories.apk(package='com.example.wrapped')
        wrapped_body = self.examine(factories.zip_with({'inner.apk': inner}), name='received.zip')
        sha = hashlib.sha256(inner).hexdigest()
        body = self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', sha)).json()
        self.assertEqual(body['exhibit_number'], wrapped_body['exhibit_number'])
        self.assertEqual(body['matched_by'], 'examined')

    def test_the_report_that_could_not_read_the_manifest_carries_its_warning_into_the_comparison(self):
        body = self.file_report(with_subject('mobsf_4.5.4_unreadable_manifest.json', self.sha)).json()
        self.assertTrue(body['summary']['manifest_unreadable'])
        self.assertTrue(any('manifest was not read' in n for n in body['summary']['notes']))

    def test_get_lists_what_was_filed_for_an_exhibit(self):
        self.file_report(with_subject('mobsf_4.5.4_legitimate_app.json', self.sha))
        self.client.force_authenticate(user=self.viewer)
        listing = self.client.get(f'/api/samples/second-opinion/?exhibit={self.exhibit.id}').json()
        self.assertEqual(len(listing), 1)
        self.assertEqual(listing[0]['tool'], 'mobsf')
        self.assertEqual(self.client.get('/api/samples/second-opinion/?exhibit=999999').json(), [])


class PermissionAndRefusalTests(FilingFixture, TestCase):
    def test_an_investigator_cannot_file_a_report(self):
        """Filing appends to the custody log; examining samples is the examiner's act."""
        response = self.file_report(fixture('mobsf_4.5.4_legitimate_app.json'), user=self.investigator)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(ThirdPartyReport.objects.count(), 0)

    def test_a_viewer_can_read_but_not_file(self):
        self.assertEqual(self.file_report(fixture('mobsf_4.5.4_legitimate_app.json'),
                                          user=self.viewer).status_code, 403)
        self.client.force_authenticate(user=self.viewer)
        self.assertEqual(self.client.get('/api/samples/second-opinion/').status_code, 200)

    def test_an_anonymous_caller_gets_nothing(self):
        client = APIClient()
        self.assertIn(client.get('/api/samples/second-opinion/').status_code, (401, 403))
        self.assertIn(client.post('/api/samples/second-opinion/').status_code, (401, 403))

    def test_a_file_that_is_not_a_mobsf_report_stores_nothing(self):
        before = set(Path(self._store()).glob('*')) if Path(self._store()).exists() else set()
        response = self.file_report(b'{"some": "other json"}')
        self.assertEqual(response.status_code, 400)
        self.assertIn('detail', response.json())
        self.assertEqual(ThirdPartyReport.objects.count(), 0)
        after = set(Path(self._store()).glob('*')) if Path(self._store()).exists() else set()
        self.assertEqual(before, after)

    def test_no_file_is_a_clear_refusal(self):
        self.client.force_authenticate(user=self.examiner)
        response = self.client.post('/api/samples/second-opinion/', {}, format='multipart')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Choose a MobSF JSON report', response.json()['detail'])

    @staticmethod
    def _store():
        from django.conf import settings
        return Path(settings.MEDIA_ROOT) / 'third_party'


class CompareTests(SimpleTestCase):
    def summary(self):
        return second_opinion.parse_mobsf(fixture('mobsf_4.5.4_legitimate_app.json'))[0]

    def test_without_an_examination_here_the_row_says_so_instead_of_inventing_one(self):
        rows = second_opinion.compare(None, self.summary())
        self.assertNotIn('Conclusion', {r['aspect'] for r in rows})
        package = next(r for r in rows if r['aspect'] == 'Package read')
        self.assertEqual(package['netforensiq'], 'not examined here')
