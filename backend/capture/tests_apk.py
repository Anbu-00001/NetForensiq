"""
The web side of sample examination: the process boundary, the view, correlation.

What these tests are defending
==============================
* The engine runs as a separate process and is never handed this process's
  environment — no database password, no SECRET_KEY, to a program whose input is
  hostile by hypothesis.
* Every failure of that process becomes a tier-0 report. The failure mode that
  matters is the one the old module had: an examination that goes wrong must
  never produce an empty findings list an officer could read as "clean".
* The exhibit is the file as received. A ZIP is sealed as the ZIP, even when
  what gets examined is the APK inside it.
"""

import io
import json
import os
import subprocess
import tempfile
import zipfile
from unittest import mock

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from apk_engine.tests import factories

from . import apk_runner
from .apk_correlation import correlate_with_captures
from .models import CaptureSession, DNSRecord, Flow

User = get_user_model()


def completed(stdout=b'', returncode=0, stderr=b''):
    return subprocess.CompletedProcess(args=[], returncode=returncode,
                                       stdout=stdout, stderr=stderr)


class RunnerTests(TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.apk = os.path.join(self._dir.name, 'sample.apk')
        with open(self.apk, 'wb') as handle:
            handle.write(factories.apk())

    def test_examines_a_real_package_through_the_command_line(self):
        report = apk_runner.run_examination(self.apk, original_name='sample.apk')
        self.assertEqual(report['assessment']['tier'], 1)
        self.assertEqual(report['identity']['package'], 'com.example.app')

    def test_the_engine_is_not_given_this_process_s_environment(self):
        with mock.patch.dict(os.environ, {'SECRET_KEY': 'top-secret', 'DB_PASSWORD': 'hunter2'}), \
                mock.patch.object(apk_runner.subprocess, 'run',
                                  return_value=completed(b'{"assessment": {"tier": 1}}')) as run:
            apk_runner.run_examination(self.apk)
        environment = run.call_args.kwargs['env']
        self.assertNotIn('SECRET_KEY', environment)
        self.assertNotIn('DB_PASSWORD', environment)
        self.assertEqual(set(environment) - {'APK_ENGINE_BASELINES'},
                         {'PATH', 'PYTHONPATH', 'LANG', 'PYTHONDONTWRITEBYTECODE'})

    def test_memory_and_cpu_limits_are_passed_to_the_engine(self):
        with mock.patch.object(apk_runner.subprocess, 'run',
                               return_value=completed(b'{"assessment": {"tier": 1}}')) as run:
            apk_runner.run_examination(self.apk)
        command = run.call_args.args[0]
        self.assertIn('--max-memory-mb', command)
        self.assertIn('--max-cpu-seconds', command)

    def test_a_timeout_becomes_tier_0_with_the_reason(self):
        with mock.patch.object(apk_runner.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired('x', 1)):
            report = apk_runner.run_examination(self.apk)
        self.assertEqual(report['assessment']['tier'], 0)
        self.assertIn('did not finish', report['assessment']['summary'])
        self.assertEqual(report['behaviours'], [])

    def test_output_that_is_not_a_report_becomes_tier_0(self):
        with mock.patch.object(apk_runner.subprocess, 'run',
                               return_value=completed(b'Killed', returncode=-9, stderr=b'oom')):
            report = apk_runner.run_examination(self.apk)
        self.assertEqual(report['assessment']['tier'], 0)
        self.assertIn('without producing a report', report['assessment']['summary'])
        self.assertIn('signal 9', report['assessment']['summary'])

    def test_a_crash_never_looks_like_a_clean_result(self):
        with mock.patch.object(apk_runner.subprocess, 'run',
                               return_value=completed(b'', returncode=1)):
            report = apk_runner.run_examination(self.apk)
        self.assertNotEqual(report['assessment']['tier'], 1)
        self.assertNotIn('No harmful behaviour', report['assessment']['label'])

    def test_a_second_examination_waits_rather_than_running_alongside(self):
        import fcntl
        with open(apk_runner.LOCK_PATH, 'a+') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            try:
                with mock.patch.object(apk_runner, 'LOCK_WAIT_SECONDS', 0):
                    report = apk_runner.run_examination(self.apk)
            finally:
                fcntl.flock(held, fcntl.LOCK_UN)
        self.assertEqual(report['assessment']['tier'], 0)
        self.assertIn('Another examination', report['assessment']['summary'])


@override_settings(DEFAULT_THROTTLE_RATES={})
class ExaminationViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        from django.core.cache import cache
        cache.clear()
        self.examiner = User.objects.create_user(
            username='apk-examiner', password='a-long-enough-password',
            badge_id='B-9001', department='FSL', role=User.Role.EXPERT, is_approved=True)
        self.investigator = User.objects.create_user(
            username='apk-investigator', password='a-long-enough-password',
            badge_id='B-9002', department='Cyber', role=User.Role.INVESTIGATOR,
            is_approved=True)
        self.report = {
            'schema': 'netforensiq.apk-examination/2', 'errors': [],
            'file': {'sha256': 'a' * 64}, 'identity': {'package': 'com.example.app'},
            'assessment': {'tier': 1, 'label': 'No harmful behaviour established',
                           'summary': '', 'basis': [], 'families': [], 'attack': [],
                           'not_established': []},
            'integrity': {'findings': []}, 'behaviours': [], 'capabilities': [],
            'endpoints': {'app': []},
        }

    def post(self, payload, name='sample.apk', **extra):
        upload = io.BytesIO(payload)
        upload.name = name
        data = {'file': upload, 'provenance': 'seized'}
        data.update(extra)
        return self.client.post('/api/samples/examine/', data, format='multipart')

    def test_investigators_may_not_submit_samples(self):
        self.client.force_authenticate(user=self.investigator)
        response = self.post(factories.apk())
        self.assertEqual(response.status_code, 403)

    def test_provenance_must_be_declared(self):
        self.client.force_authenticate(user=self.examiner)
        upload = io.BytesIO(factories.apk())
        upload.name = 'sample.apk'
        response = self.client.post('/api/samples/examine/', {'file': upload}, format='multipart')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Declare where this sample came from', response.json()['detail'])

    def test_a_file_that_is_not_an_archive_is_refused(self):
        self.client.force_authenticate(user=self.examiner)
        response = self.post(b'plain text, not a zip')
        self.assertEqual(response.status_code, 400)

    def test_a_package_is_sealed_and_examined(self):
        import hashlib
        self.client.force_authenticate(user=self.examiner)
        payload = factories.apk()
        with mock.patch('capture.apk_views.run_examination', return_value=dict(self.report)) as run:
            response = self.post(payload)
        self.assertEqual(response.json()['sealed_sha256'], hashlib.sha256(payload).hexdigest())
        self.assertEqual(response.status_code, 201)
        body = response.json()
        self.assertTrue(body['exhibit_number'])
        # A bare .apk is its own container: nothing was unwrapped.
        self.assertIsNone(run.call_args.kwargs['container_path'])
        self.assertEqual(body['unwrapped_from'], '')

    def test_an_apk_inside_a_zip_is_unwrapped_but_the_zip_is_the_exhibit(self):
        self.client.force_authenticate(user=self.examiner)
        wrapped = factories.zip_with({'inner.apk': factories.apk()})
        with mock.patch('capture.apk_views.run_examination', return_value=dict(self.report)) as run:
            response = self.post(wrapped, name='received.zip')
        body = response.json()
        self.assertEqual(response.status_code, 201)
        self.assertEqual(body['analysed_filename'], 'inner.apk')
        self.assertEqual(body['unwrapped_from'], 'received.zip')
        self.assertIsNotNone(run.call_args.kwargs['container_path'])
        # The digest describes what was handed in, not what was lifted out.
        import hashlib
        self.assertEqual(body['sealed_sha256'], hashlib.sha256(wrapped).hexdigest())

    def test_an_encrypted_archive_opens_with_the_conventional_password(self):
        pyzipper = __import__('pyzipper')
        buffer = io.BytesIO()
        with pyzipper.AESZipFile(buffer, 'w', compression=pyzipper.ZIP_DEFLATED,
                                 encryption=pyzipper.WZ_AES) as archive:
            archive.setpassword(b'infected')
            archive.writestr('inner.apk', factories.apk())
        self.client.force_authenticate(user=self.examiner)
        with mock.patch('capture.apk_views.run_examination', return_value=dict(self.report)):
            response = self.post(buffer.getvalue(), name='sample.zip')
        self.assertEqual(response.status_code, 201, response.content[:400])
        self.assertEqual(response.json()['analysed_filename'], 'inner.apk')

    def test_an_overlapping_archive_is_sealed_but_never_extracted(self):
        self.client.force_authenticate(user=self.examiner)
        payload = factories.overlap_entries(
            factories.zip_with({'a.apk': b'A' * 2048, 'b.apk': b'B' * 2048}), 'a.apk', 'b.apk')
        with mock.patch('capture.apk_views.run_examination') as run:
            response = self.post(payload, name='bomb.zip')
        self.assertEqual(response.status_code, 201)
        run.assert_not_called()
        body = response.json()
        self.assertEqual(body['assessment']['tier'], 0)
        self.assertTrue(body['exhibit_number'])
        self.assertIn('share compressed data', body['assessment']['summary'])

    def test_an_archive_with_no_package_inside_is_refused(self):
        self.client.force_authenticate(user=self.examiner)
        response = self.post(factories.zip_with({'notes.txt': b'hello'}), name='notes.zip')
        self.assertEqual(response.status_code, 400)
        self.assertIn('no Android package', response.json()['detail'])


class CorrelationTests(TestCase):
    def setUp(self):
        self.session = CaptureSession.objects.create(name='exhibit capture')
        now = timezone.now()
        DNSRecord.objects.create(session=self.session, query_name='c2.example.net',
                                 src_ip='10.0.0.5', timestamp=now)
        Flow.objects.create(session=self.session, src_ip='10.0.0.5', dst_ip='203.0.113.9',
                            dst_port=443, protocol='TCP', first_seen=now, last_seen=now)

    def report_with(self, app_endpoints):
        return {'endpoints': {'app': app_endpoints, 'sdk': []}}

    def test_a_name_in_the_package_that_a_capture_resolved_is_matched(self):
        result = correlate_with_captures(self.report_with(
            [{'host': 'c2.example.net', 'kind': 'host', 'examples': ['http://c2.example.net/a']}]))
        self.assertEqual([m['indicator'] for m in result['matches']], ['c2.example.net'])
        self.assertEqual(result['matches'][0]['kind'], 'dns')

    def test_an_address_in_the_package_that_a_capture_contacted_is_matched(self):
        result = correlate_with_captures(self.report_with(
            [{'host': '203.0.113.9', 'kind': 'ip', 'examples': ['203.0.113.9']}]))
        self.assertEqual([m['kind'] for m in result['matches']], ['flow'])

    def test_sdk_traffic_is_never_correlated(self):
        report = {'endpoints': {'app': [], 'sdk': [
            {'host': 'c2.example.net', 'kind': 'host', 'examples': [], 'sdk': 'Some tracker'}]}}
        result = correlate_with_captures(report)
        self.assertEqual(result['matches'], [])
        self.assertEqual(result['checked_hosts'], 0)

    def test_correlation_states_that_it_does_not_change_the_tier(self):
        result = correlate_with_captures(self.report_with([]))
        self.assertIn('corroboration', result['tier_effect'])
