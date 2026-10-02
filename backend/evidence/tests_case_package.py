# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The signed case package and its signing key.

What these hold the code to, in order of how much a recipient depends on it:

* a package built here verifies, and every way of altering it is caught;
* the one thing a signature cannot do — vouch that a key is the laboratory's —
  is demonstrated by a forged package that *does* verify, and is caught only by
  the fingerprint comparison;
* the custody timestamp survives as the exact string that was hashed, including
  the case where `isoformat()` drops the fractional part;
* the package carries no stored path and no account name.

The browser verifier is held to the same cases by verifier/test/ against
packages built by this module (see tests_case_package_js.py).
"""
import base64
import datetime
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase, TestCase, override_settings
from rest_framework.test import APIClient

from accounts.models import AuditLog, User

from . import case_package, signing
from .models import CustodyEvent, EvidenceRecord
from .service import issue_certificate, record_custody, verify_custody_chain
from .tests_cases import CaseFixtureMixin


class SigningKeyTests(SimpleTestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.enterContext(override_settings(
            SIGNING_KEY_FILE=self.dir / 'k', PACKAGE_SIGNING_KEY=''))

    def test_no_key_is_created_unless_asked(self):
        self.assertIsNone(signing.load_private_key())
        self.assertFalse((self.dir / 'k').exists())

    def test_the_key_file_is_private_from_the_moment_it_exists(self):
        signing.load_private_key(create=True)
        mode = stat.S_IMODE(os.stat(self.dir / 'k').st_mode)
        self.assertEqual(mode, 0o600)

    def test_the_same_key_is_returned_on_every_load(self):
        first = signing.public_key_bytes(signing.load_private_key(create=True))
        second = signing.public_key_bytes(signing.load_private_key())
        self.assertEqual(first, second)

    # RFC 8032 section 7.1, test 1. The secret key and the public key it must
    # yield; independent of this code, so a wrong key derivation cannot hide.
    RFC8032_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'
    RFC8032_PUBLIC = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'

    def test_a_configured_key_takes_precedence_and_writes_nothing(self):
        seed = base64.b64encode(bytes.fromhex(self.RFC8032_SEED)).decode()
        with override_settings(PACKAGE_SIGNING_KEY=seed):
            key = signing.load_private_key(create=True)
        self.assertEqual(signing.public_key_bytes(key).hex(), self.RFC8032_PUBLIC)
        self.assertFalse((self.dir / 'k').exists())

    def test_a_malformed_key_is_an_error_not_a_missing_key(self):
        for bad in (base64.b64encode(b'short').decode(), '!!!not base64!!!'):
            with override_settings(PACKAGE_SIGNING_KEY=bad):
                with self.assertRaises(signing.SigningKeyError):
                    signing.load_private_key(create=True)

    def test_a_signature_is_bound_to_its_document_type(self):
        key = signing.load_private_key(create=True)
        public = signing.public_key_bytes(key)
        sig = signing.sign(b'netforensiq.case-package/1\n', b'data', key)
        self.assertTrue(signing.verify(b'netforensiq.case-package/1\n', b'data', sig, public))
        self.assertFalse(signing.verify(b'netforensiq.update-bundle/1\n', b'data', sig, public))
        self.assertFalse(signing.verify(b'netforensiq.case-package/1\n', b'datb', sig, public))

    def test_malformed_input_is_false_not_an_exception(self):
        self.assertFalse(signing.verify(b'c', b'd', b'short', b'short'))
        self.assertFalse(signing.verify(b'c', b'd', bytes(64), bytes(32)))

    def test_fingerprint_is_the_sha256_of_the_raw_public_key(self):
        import hashlib
        public = signing.public_key_bytes(signing.load_private_key(create=True))
        self.assertEqual(signing.fingerprint(public), hashlib.sha256(public).hexdigest())
        shown = signing.display_fingerprint(signing.fingerprint(public))
        self.assertEqual(len(shown.split()), 8)


class PackageFixture(CaseFixtureMixin):
    def setUp(self):
        super().setUp()
        self.key_dir = Path(tempfile.mkdtemp())
        self.enterContext(override_settings(
            SIGNING_KEY_FILE=self.key_dir / 'k', PACKAGE_SIGNING_KEY='',
            EVIDENCE_ROOT=Path(self.tmp) / 'pcaps'))
        self.record = self._ingest(
            exhibit_number='EX-PKG-1', collected_by=self.io,
            fir_number='0113/2026', police_station='Cyber Crime PS, Ahmedabad City',
            provenance=EvidenceRecord.Provenance.SEIZED)
        record_custody(self.record, CustodyEvent.Action.VIEWED, actor=self.io,
                       detail='Reviewed the capture | with a pipe, and unicode: ₹ é')
        self.text, self.summary = case_package.build_case_package(
            [self.record], case=None)

    def forge(self, mutate):
        """
        What an attacker with their own key can do: change the manifest and
        re-sign it. The signature will verify; nothing else should.
        """
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        envelope = json.loads(self.text)
        manifest = json.loads(envelope['manifest_json'])
        mutate(manifest)
        manifest_json = json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                                   separators=(',', ':'))
        attacker = Ed25519PrivateKey.from_private_bytes(bytes([7]) * 32)
        public = signing.public_key_bytes(attacker)
        envelope['manifest_json'] = manifest_json
        envelope['signature'] = {
            'algorithm': 'ed25519',
            'public_key': base64.b64encode(public).decode(),
            'key_fingerprint': signing.fingerprint(public),
            'value': base64.b64encode(signing.sign(
                case_package.CONTEXT, manifest_json.encode('utf-8'), attacker)).decode(),
        }
        return json.dumps(envelope)

    def failing(self, report):
        return [c for c in report['checks'] if c['level'] == 'fail']


class PackageTests(PackageFixture, TestCase):
    def test_a_package_built_here_verifies(self):
        report = case_package.verify_package(self.text)
        self.assertTrue(report['ok'], self.failing(report))
        ids = [c['id'] for c in report['checks'] if c['level'] == 'pass']
        self.assertIn('signature', ids)
        self.assertIn('chain:EX-PKG-1', ids)

    def test_the_summary_names_the_key(self):
        self.assertEqual(report := case_package.verify_package(self.text)['fingerprint'],
                         self.summary['key_fingerprint'], report)

    def test_a_fingerprint_supplied_by_the_recipient_is_checked(self):
        real = self.summary['key_fingerprint']
        good = case_package.verify_package(self.text, signing.display_fingerprint(real))
        self.assertTrue(good['ok'])
        self.assertIn('fingerprint', [c['id'] for c in good['checks'] if c['level'] == 'pass'])
        bad = case_package.verify_package(self.text, 'ab' * 32)
        self.assertFalse(bad['ok'])

    def test_editing_the_signed_text_breaks_the_signature_and_reveals_nothing(self):
        envelope = json.loads(self.text)
        envelope['manifest_json'] = envelope['manifest_json'].replace('EX-PKG-1', 'EX-PKG-2', 1)
        report = case_package.verify_package(json.dumps(envelope))
        self.assertFalse(report['ok'])
        self.assertIsNone(report['manifest'],
                          'an unverified manifest must not be handed back as if trustworthy')

    def test_a_swapped_signature_is_rejected(self):
        envelope = json.loads(self.text)
        raw = bytearray(base64.b64decode(envelope['signature']['value']))
        raw[0] ^= 1
        envelope['signature']['value'] = base64.b64encode(bytes(raw)).decode()
        self.assertFalse(case_package.verify_package(json.dumps(envelope))['ok'])

    def test_a_forged_package_verifies_and_only_the_fingerprint_exposes_it(self):
        """
        The honest limit of a signature. Anyone can sign a package with their own
        key. It verifies. What distinguishes it is the key, which the recipient
        must know from somewhere other than the package.
        """
        forged = self.forge(lambda m: None)
        report = case_package.verify_package(forged)
        self.assertTrue(report['ok'], self.failing(report))
        self.assertNotEqual(report['fingerprint'], self.summary['key_fingerprint'])
        against = case_package.verify_package(forged, self.summary['key_fingerprint'])
        self.assertFalse(against['ok'])

    def test_altering_an_entry_is_caught_by_the_chain_even_if_re_signed(self):
        def mutate(m):
            m['exhibits'][0]['custody']['events'][1]['detail'] = 'something else'
        report = case_package.verify_package(self.forge(mutate))
        self.assertFalse(report['ok'])
        self.assertTrue(any('altered' in c['text'] for c in self.failing(report)))

    def test_removing_a_middle_entry_is_caught(self):
        record_custody(self.record, CustodyEvent.Action.VERIFIED, actor=self.io, detail='again')
        text, _ = case_package.build_case_package([self.record])
        self.text = text

        def mutate(m):
            del m['exhibits'][0]['custody']['events'][1]
        report = case_package.verify_package(self.forge(mutate))
        self.assertFalse(report['ok'])

    def test_truncating_the_end_is_caught_by_the_count_and_head(self):
        def mutate(m):
            m['exhibits'][0]['custody']['events'].pop()
        report = case_package.verify_package(self.forge(mutate))
        messages = ' '.join(c['text'] for c in self.failing(report))
        self.assertIn('entries', messages)
        self.assertIn('head_hash', messages)

    def test_reordering_is_caught(self):
        def mutate(m):
            events = m['exhibits'][0]['custody']['events']
            events[0], events[1] = events[1], events[0]
        self.assertFalse(case_package.verify_package(self.forge(mutate))['ok'])

    def test_a_certificate_that_certifies_another_hash_is_caught(self):
        issue_certificate(self.record, part_a_user=self.io, part_a_name='R. Patel',
                          part_a_designation='IO', part_a_organisation='Cyber Crime PS',
                          part_a_address='Ahmedabad')
        text, _ = case_package.build_case_package([self.record])
        self.text = text
        self.assertTrue(case_package.verify_package(text)['ok'])

        def mutate(m):
            m['exhibits'][0]['certificates'][0]['certified_sha256'] = 'f' * 64
        report = case_package.verify_package(self.forge(mutate))
        self.assertTrue(any('different hash' in c['text'] for c in self.failing(report)))

    def test_the_certificate_pdf_hash_is_recorded(self):
        """Lets a recipient confirm the PDF they were handed is the one issued."""
        from .certificate_pdf import render_certificate_pdf

        certificate = issue_certificate(
            self.record, part_a_user=self.io, part_a_name='R. Patel',
            part_a_designation='IO', part_a_organisation='Cyber Crime PS',
            part_a_address='Ahmedabad')
        with override_settings(CERTIFICATE_ROOT=Path(self.tmp) / 'certs'):
            path = render_certificate_pdf(certificate)
        certificate.pdf_path = str(path)
        certificate.save(update_fields=['pdf_path'])

        import hashlib
        text, _ = case_package.build_case_package([self.record])
        manifest = json.loads(json.loads(text)['manifest_json'])
        recorded = manifest['exhibits'][0]['certificates'][0]['pdf_sha256']
        self.assertEqual(recorded, hashlib.sha256(Path(path).read_bytes()).hexdigest())

    def test_a_zero_microsecond_timestamp_survives_as_the_hashed_string(self):
        """
        `datetime.isoformat()` omits the fractional part when the microsecond is
        zero. A verifier formatting dates itself would produce a different string
        for exactly these entries and report tampering that did not happen.
        """
        moment = datetime.datetime(2026, 10, 2, 9, 30, 0, 0, tzinfo=datetime.timezone.utc)
        with mock.patch('django.utils.timezone.now', return_value=moment):
            record_custody(self.record, CustodyEvent.Action.VERIFIED, actor=self.io,
                           detail='on the second')
        text, _ = case_package.build_case_package([self.record])
        manifest = json.loads(json.loads(text)['manifest_json'])
        stamps = [e['timestamp'] for e in manifest['exhibits'][0]['custody']['events']]
        self.assertIn('2026-10-02T09:30:00+00:00', stamps)
        self.assertTrue(case_package.verify_package(text)['ok'])

    def test_a_pipe_and_unicode_in_a_detail_do_not_confuse_the_chain(self):
        """The chain joins fields with '|'; a detail containing one must still verify."""
        self.assertTrue(case_package.verify_package(self.text)['ok'])
        manifest = json.loads(json.loads(self.text)['manifest_json'])
        details = [e['detail'] for e in manifest['exhibits'][0]['custody']['events']]
        self.assertTrue(any('|' in d and '₹' in d for d in details))

    def test_the_package_carries_no_stored_path_and_no_account_name(self):
        manifest_text = json.loads(self.text)['manifest_json']
        self.assertNotIn(self.tmp, manifest_text)
        self.assertNotIn('stored_path', manifest_text)
        self.assertNotIn('"username"', manifest_text)
        self.assertNotIn('collected_by', manifest_text)
        # the badge is a hash input and is carried; the account name is not
        self.assertIn('GP-1001', manifest_text)

    def test_the_tool_block_names_the_tables_the_findings_rest_on(self):
        manifest = json.loads(json.loads(self.text)['manifest_json'])
        tool = manifest['tool']
        self.assertEqual(tool['name'], 'NetForensiq')
        self.assertEqual(len(tool['rule_base_rates_sha256']), 64)
        self.assertEqual(len(tool['apk_baselines_sha256']), 64)

    def test_a_file_changed_since_sealing_is_reported_not_hidden(self):
        """
        Re-hashed at export. A package that said 'intact' because the file was
        intact when sealed could never report that it had since changed.
        """
        from .crypto import encrypt_file, load_key

        path = Path(self.record.stored_path)
        key = load_key()
        payload = b'altered after sealing'
        if key:
            tmp = path.with_suffix('.tmp')
            tmp.write_bytes(payload)
            encrypt_file(tmp, path, key)
            tmp.unlink()
        else:
            path.chmod(0o600)
            path.write_bytes(payload)
        text, summary = case_package.build_case_package([self.record])
        self.assertFalse(summary['all_content_intact'])
        report = case_package.verify_package(text)
        self.assertFalse(report['ok'])
        self.assertTrue(any('did NOT match' in c['text'] for c in self.failing(report)))

    def test_an_empty_package_is_refused(self):
        with self.assertRaises(case_package.PackageError):
            case_package.build_case_package([])

    def test_not_json_and_wrong_format_are_clean_failures(self):
        self.assertFalse(case_package.verify_package('not json')['ok'])
        self.assertFalse(case_package.verify_package('{"format": "other"}')['ok'])
        self.assertFalse(case_package.verify_package('[]')['ok'])


class PackageApiTests(PackageFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.investigator = User.objects.create_user(
            username='inv', password='a-long-enough-password', badge_id='GP-2001',
            role=User.Role.INVESTIGATOR, is_approved=True)
        self.viewer = User.objects.create_user(
            username='view', password='a-long-enough-password', badge_id='GP-2002',
            role=User.Role.VIEWER, is_approved=True)
        self.client = APIClient()

    def _post(self, user, url):
        self.client.force_authenticate(user)
        return self.client.post(url)

    def test_an_investigator_receives_a_package_that_verifies(self):
        response = self._post(self.investigator, f'/api/evidence/{self.record.id}/package/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('EX-PKG-1.nfcase.json', response['Content-Disposition'])
        report = case_package.verify_package(response.content.decode('utf-8'))
        self.assertTrue(report['ok'], self.failing(report))
        self.assertEqual(report['fingerprint'], response['X-NetForensiq-Key-Fingerprint'])

    def test_the_export_is_in_the_package_and_in_the_log(self):
        response = self._post(self.investigator, f'/api/evidence/{self.record.id}/package/')
        manifest = json.loads(json.loads(response.content)['manifest_json'])
        events = manifest['exhibits'][0]['custody']['events']
        self.assertEqual(events[-1]['action'], 'exported')
        self.assertIn('GP-2001', events[-1]['actor_badge'])
        ok, problems = verify_custody_chain(self.record)
        self.assertTrue(ok, problems)

    def test_the_export_is_audited(self):
        self._post(self.investigator, f'/api/evidence/{self.record.id}/package/')
        self.assertTrue(AuditLog.objects.filter(
            action=AuditLog.Action.EXPORT_EVIDENCE,
            detail__contains='signed case package').exists())

    def test_a_viewer_cannot_export(self):
        """Exporting appends to the custody log, so it needs the clearance to do that."""
        before = self.record.custody_events.count()
        response = self._post(self.viewer, f'/api/evidence/{self.record.id}/package/')
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.record.custody_events.count(), before)

    def test_an_anonymous_caller_cannot_export(self):
        response = APIClient().post(f'/api/evidence/{self.record.id}/package/')
        self.assertIn(response.status_code, (401, 403))

    def test_two_exports_use_the_same_key(self):
        first = self._post(self.investigator, f'/api/evidence/{self.record.id}/package/')
        second = self._post(self.investigator, f'/api/evidence/{self.record.id}/package/')
        self.assertEqual(first['X-NetForensiq-Key-Fingerprint'],
                         second['X-NetForensiq-Key-Fingerprint'])
        manifest = json.loads(json.loads(second.content)['manifest_json'])
        self.assertEqual(manifest['exhibits'][0]['custody']['event_count'],
                         self.record.custody_events.count())

    def test_a_case_package_carries_every_exhibit_and_the_case(self):
        from .service import link_evidence_to_case
        second = self._ingest(exhibit_number='EX-PKG-2', collected_by=self.io)
        for record in (self.record, second):
            link_evidence_to_case(record, self.case, actor=self.io)
        response = self._post(self.investigator, f'/api/cases/{self.case.id}/package/')
        self.assertEqual(response.status_code, 200)
        manifest = json.loads(json.loads(response.content)['manifest_json'])
        self.assertEqual({e['exhibit_number'] for e in manifest['exhibits']},
                         {'EX-PKG-1', 'EX-PKG-2'})
        self.assertEqual(manifest['case']['case_number'], 'CYB/2026/0041')
        self.assertTrue(case_package.verify_package(response.content.decode())['ok'])

    def test_a_case_with_no_exhibits_is_a_conflict_not_an_empty_file(self):
        response = self._post(self.investigator, f'/api/cases/{self.case.id}/package/')
        self.assertEqual(response.status_code, 409)


class SigningKeyEndpointTests(PackageFixture, TestCase):
    def setUp(self):
        super().setUp()
        self.viewer = User.objects.create_user(
            username='view2', password='a-long-enough-password', badge_id='GP-2003',
            role=User.Role.VIEWER, is_approved=True)
        self.client = APIClient()
        self.client.force_authenticate(self.viewer)

    def test_reading_the_key_creates_nothing(self):
        # PackageFixture already built a package, which created the key; remove
        # it to show the read-only path.
        (self.key_dir / 'k').unlink()
        response = self.client.get('/api/evidence/signing-key/')
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()['configured'])
        self.assertFalse((self.key_dir / 'k').exists())

    def test_it_reports_the_fingerprint_a_recipient_should_compare(self):
        response = self.client.get('/api/evidence/signing-key/').json()
        self.assertTrue(response['configured'])
        self.assertEqual(response['fingerprint'], self.summary['key_fingerprint'])
        self.assertEqual(len(response['fingerprint_display'].split()), 8)
        self.assertNotIn('seed', json.dumps(response).lower())
        self.assertNotIn('private', json.dumps(response).lower())

    def test_it_requires_a_signed_in_officer(self):
        self.assertIn(APIClient().get('/api/evidence/signing-key/').status_code, (401, 403))
