"""Structural tampering: found when present, silent when not."""

import unittest

from apk_engine import integrity

from . import factories


class IntegrityTests(unittest.TestCase):
    def ids(self, payload):
        result = integrity.check(payload)
        self.assertTrue(result['checked'], result['error'])
        return {finding['id'] for finding in result['findings']}

    def test_well_formed_package_produces_no_findings(self):
        self.assertEqual(self.ids(factories.apk()), set())

    def test_forged_compression_method_is_found_with_its_values(self):
        payload = factories.forge_compression_method(factories.apk())
        result = integrity.check(payload)
        findings = {f['id']: f for f in result['findings']}
        self.assertIn('zip.unknown_compression_method', findings)
        evidence = findings['zip.unknown_compression_method']['evidence']['examples'][0]
        self.assertEqual(evidence['central_compression_method'], 65350)
        self.assertEqual(evidence['local_compression_method'], 25686)
        # The two headers disagreeing is a separate, separately measured fact.
        self.assertIn('zip.header_mismatch', findings)

    def test_every_finding_carries_sources_and_a_technique(self):
        result = integrity.check(factories.forge_compression_method(factories.apk()))
        for finding in result['findings']:
            self.assertTrue(finding['sources'], finding['id'])
            self.assertTrue(all('url' in s for s in finding['sources']))
            self.assertEqual([t['id'] for t in finding['attack']], ['T1406'])

    def test_encryption_flag_without_encryption_is_found(self):
        payload = factories.set_encryption_flag(factories.apk())
        self.assertIn('zip.encryption_flag_on_package', self.ids(payload))

    def test_unparsable_input_reports_a_reason_and_no_findings(self):
        result = integrity.check(b'this is not a zip')
        self.assertFalse(result['checked'])
        self.assertTrue(result['error'])
        self.assertEqual(result['findings'], [])
