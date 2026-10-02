# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The browser verifier against the Python one.

Two implementations of the same checks are only worth having if they are made to
agree. Here Python builds a set of packages — one good, and every way of
altering or forging one that the Python tests cover — records what *its*
verifier says about each, and runs the JavaScript verifier (the same code the
page ships) over the same files. The two must give identical results: same
verdict, same checks in the same order, same wording. Then JavaScript signs a
package and Python verifies it.

Skipped, loudly, when Node or the committed noble bundle is missing: a test
that silently passes without running is worse than one that fails.
"""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from django.test import TestCase, override_settings

from . import case_package, signing
from .models import CustodyEvent
from .service import issue_certificate, record_custody
from .tests_case_package import PackageFixture

REPO = Path(__file__).resolve().parents[2]
VERIFIER = REPO / 'verifier'
NODE = shutil.which('node') or ''
READY = bool(NODE) and (VERIFIER / 'vendor' / 'noble.iife.js').exists()

# The RFC 8032 test key. Public, and used only for fixtures and the JS->Python
# direction; never for a real package.
TEST_SEED = '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60'


def _expected(text, fingerprint=''):
    result = case_package.verify_package(text, fingerprint or None)
    return {'ok': result['ok'], 'fingerprint': result['fingerprint'],
            'checks': result['checks']}


@unittest.skipUnless(READY, 'Node, or verifier/vendor/noble.iife.js, is not available')
class CrossLanguageTests(PackageFixture, TestCase):
    def _write(self, directory, name, text, fingerprint=''):
        (directory / f'{name}.json').write_text(text, encoding='utf-8')
        if fingerprint:
            (directory / f'{name}.fp').write_text(fingerprint)
        (directory / f'{name}.expected.json').write_text(
            json.dumps(_expected(text, fingerprint)), encoding='utf-8')

    def _cases(self):
        real = self.summary['key_fingerprint']
        cases = {
            'good': (self.text, ''),
            'good-right-fingerprint': (self.text, signing.display_fingerprint(real)),
            'good-wrong-fingerprint': (self.text, 'ab' * 32),
            'not-json': ('not json at all', ''),
            'wrong-format': ('{"format": "other"}', ''),
            'empty-array': ('[]', ''),
        }

        envelope = json.loads(self.text)
        edited = dict(envelope)
        edited['manifest_json'] = envelope['manifest_json'].replace('EX-PKG-1', 'EX-PKG-2', 1)
        cases['edited-signed-text'] = (json.dumps(edited), '')

        swapped = json.loads(self.text)
        raw = bytearray(base64.b64decode(swapped['signature']['value']))
        raw[0] ^= 1
        swapped['signature']['value'] = base64.b64encode(bytes(raw)).decode()
        cases['swapped-signature'] = (json.dumps(swapped), '')

        cases['forged-unchanged'] = (self.forge(lambda m: None), '')
        cases['forged-vs-real-fingerprint'] = (self.forge(lambda m: None), real)

        def alter(m):
            m['exhibits'][0]['custody']['events'][1]['detail'] = 'something else'
        cases['forged-altered-entry'] = (self.forge(alter), '')

        def truncate(m):
            m['exhibits'][0]['custody']['events'].pop()
        cases['forged-truncated'] = (self.forge(truncate), '')

        def reorder(m):
            e = m['exhibits'][0]['custody']['events']
            e[0], e[1] = e[1], e[0]
        cases['forged-reordered'] = (self.forge(reorder), '')

        def break_head(m):
            m['exhibits'][0]['custody']['head_hash'] = 'f' * 64
        cases['forged-bad-head'] = (self.forge(break_head), '')

        def bad_hash(m):
            m['exhibits'][0]['sha256'] = 'not-a-digest'
        cases['forged-bad-sha256'] = (self.forge(bad_hash), '')

        # A longer log, with a zero-microsecond entry, then a removed middle entry.
        import datetime
        from unittest import mock
        moment = datetime.datetime(2026, 10, 2, 9, 30, 0, 0, tzinfo=datetime.timezone.utc)
        with mock.patch('django.utils.timezone.now', return_value=moment):
            record_custody(self.record, CustodyEvent.Action.VERIFIED, actor=self.io,
                           detail='on the second')
        record_custody(self.record, CustodyEvent.Action.VERIFIED, actor=self.io, detail='again')
        issue_certificate(self.record, part_a_user=self.io, part_a_name='R. Patel',
                          part_a_designation='IO', part_a_organisation='Cyber Crime PS',
                          part_a_address='Ahmedabad')
        longer, _ = case_package.build_case_package([self.record])
        cases['longer-with-certificate'] = (longer, '')
        self.text = longer

        def remove_middle(m):
            del m['exhibits'][0]['custody']['events'][2]
        cases['forged-removed-middle'] = (self.forge(remove_middle), '')

        def wrong_cert(m):
            m['exhibits'][0]['certificates'][0]['certified_sha256'] = 'f' * 64
        cases['forged-certificate-mismatch'] = (self.forge(wrong_cert), '')

        def not_intact(m):
            m['exhibits'][0]['content_check']['intact'] = False
        cases['forged-content-not-intact'] = (self.forge(not_intact), '')
        return cases

    def test_javascript_and_python_give_identical_results_on_every_case(self):
        directory = Path(tempfile.mkdtemp())
        cases = self._cases()
        for name, (text, fingerprint) in cases.items():
            self._write(directory, name, text, fingerprint)

        done = subprocess.run(
            [NODE, str(VERIFIER / 'test' / 'cross_check.mjs'), str(directory)],
            capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(f'OK {len(cases)} cases identical', done.stdout)

        # The other direction: signed by noble in JavaScript, verified here.
        signed = (directory / 'js-signed.out').read_text()
        fingerprint = (directory / 'js-signed.fingerprint').read_text().strip()
        report = case_package.verify_package(signed, fingerprint)
        self.assertTrue(report['ok'], [c for c in report['checks'] if c['level'] == 'fail'])
        self.assertEqual(report['fingerprint'], fingerprint)

    def test_the_cases_really_do_differ_in_outcome(self):
        """Guard against a vacuous agreement: both sides failing everything."""
        outcomes = {name: _expected(text, fp)['ok']
                    for name, (text, fp) in self._cases().items()}
        self.assertTrue(outcomes['good'])
        self.assertTrue(outcomes['good-right-fingerprint'])
        self.assertTrue(outcomes['forged-unchanged'])      # a forgery verifies...
        self.assertFalse(outcomes['forged-vs-real-fingerprint'])  # ...until the fingerprint is known
        self.assertFalse(outcomes['forged-altered-entry'])
        self.assertFalse(outcomes['edited-signed-text'])
        self.assertGreaterEqual(sum(1 for ok in outcomes.values() if ok), 4)
        self.assertGreaterEqual(sum(1 for ok in outcomes.values() if not ok), 10)

    def test_the_command_line_tool_agrees(self):
        directory = Path(tempfile.mkdtemp())
        path = directory / 'p.json'
        path.write_text(self.text)
        ok = subprocess.run([NODE, str(VERIFIER / 'nfverify.mjs'), str(path),
                             '--fingerprint', self.summary['key_fingerprint']],
                            capture_output=True, text=True, timeout=60)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn('Result: verified', ok.stdout)
        bad = subprocess.run([NODE, str(VERIFIER / 'nfverify.mjs'), str(path),
                              '--fingerprint', 'ab' * 32],
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(bad.returncode, 1)

    def test_the_command_line_tool_matches_an_exhibit_file(self):
        """The recipient's real task: does the file in my hand match the package?"""
        from .crypto import readable
        directory = Path(tempfile.mkdtemp())
        package = directory / 'p.json'
        package.write_text(self.text)
        exhibit = directory / 'exhibit.bin'
        with readable(self.record.stored_path) as plaintext:
            exhibit.write_bytes(Path(plaintext).read_bytes())
        other = directory / 'other.bin'
        other.write_bytes(b'not the exhibit')

        match = subprocess.run([NODE, str(VERIFIER / 'nfverify.mjs'), str(package), str(exhibit)],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(match.returncode, 0, match.stdout + match.stderr)
        self.assertIn('is exhibit EX-PKG-1', match.stdout)

        miss = subprocess.run([NODE, str(VERIFIER / 'nfverify.mjs'), str(package), str(other)],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(miss.returncode, 1)
        self.assertIn('does NOT match', miss.stdout)


@unittest.skipUnless(os.environ.get('NF_VERIFIER_FIXTURES'),
                     'set NF_VERIFIER_FIXTURES=<dir> to regenerate the committed fixtures')
class FixtureWriter(PackageFixture, TestCase):
    """
    Regenerates verifier/test/fixtures/, used by the browser test and the README
    screenshots. Signed with the public RFC 8032 test key and on synthetic data,
    so nothing in them is a real key or real evidence.

        NF_VERIFIER_FIXTURES=verifier/test/fixtures python manage.py test \\
            evidence.tests_case_package_js.FixtureWriter
    """

    EXHIBIT_CONTENT = b'Synthetic exhibit for the verifier fixtures. Not a capture, not evidence.\n'

    def test_write(self):
        from .crypto import readable
        out = Path(os.environ['NF_VERIFIER_FIXTURES']).resolve()
        out.mkdir(parents=True, exist_ok=True)
        key_b64 = base64.b64encode(bytes.fromhex(TEST_SEED)).decode()
        issue_certificate(self.record, part_a_user=self.io, part_a_name='Rakesh Patel',
                          part_a_designation='Investigating Officer',
                          part_a_organisation='Cyber Crime PS, Ahmedabad City',
                          part_a_address='Ahmedabad')
        record_custody(self.record, CustodyEvent.Action.VIEWED, actor=self.io,
                       detail='Reviewed in the examination room')
        with override_settings(PACKAGE_SIGNING_KEY=key_b64):
            text, summary = case_package.build_case_package([self.record], case=self.case)
        (out / 'good.nfcase.json').write_text(text, encoding='utf-8')
        (out / 'fingerprint.txt').write_text(
            signing.display_fingerprint(summary['key_fingerprint']) + '\n')
        with readable(self.record.stored_path) as plaintext:
            (out / 'exhibit.bin').write_bytes(Path(plaintext).read_bytes())

        envelope = json.loads(text)
        edited = dict(envelope)
        edited['manifest_json'] = envelope['manifest_json'].replace('Reviewed', 'Revised', 1)
        (out / 'tampered.nfcase.json').write_text(json.dumps(edited, indent=1), encoding='utf-8')

        def drop_event(m):
            del m['exhibits'][0]['custody']['events'][1]
        (out / 'forged-removed-entry.nfcase.json').write_text(
            self.forge(drop_event), encoding='utf-8')
        (out / 'README.txt').write_text(
            'Synthetic data signed with the public RFC 8032 test key. Not evidence, not a real key.\n'
            'Regenerate: see evidence/tests_case_package_js.py (FixtureWriter).\n')


class PublishedVerifierTests(TestCase):
    """The page the product serves is the page that was built and tested."""

    def test_the_served_copy_is_the_built_copy(self):
        built = (VERIFIER / 'dist' / 'nfverify.html').read_bytes()
        served = (REPO / 'frontend' / 'public' / 'nfverify.html').read_bytes()
        self.assertEqual(built, served,
                         'frontend/public/nfverify.html differs from verifier/dist: run `npm run build` in verifier/')

    def test_the_published_digest_matches(self):
        import hashlib
        published = (VERIFIER / 'dist' / 'nfverify.html.sha256').read_text().split()[0]
        built = hashlib.sha256((VERIFIER / 'dist' / 'nfverify.html').read_bytes()).hexdigest()
        self.assertEqual(built, published)
