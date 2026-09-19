# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
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


class MeasurementTests(unittest.TestCase):
    """
    A signal that never fires must still be measured.

    Signals were recorded only when they fired, so an indicator absent from
    every legitimate app never reached baselines.json at all, and
    ``baselines.status`` then called it *unmeasured* — barring it from raising
    a tier. That disqualified precisely the indicators that discriminate best.
    Measured on 200 MalwareBazaar packages, ``zip.encryption_flag_on_package``
    fired on 71 of 195 and on no legitimate app, and could do nothing.
    """

    def signals_for(self, report):
        from apk_engine.engine import signals
        return signals(dict({'capabilities': [], 'behaviours': [], 'identity': None}, **report))

    def test_every_indicator_is_recorded_even_when_it_did_not_fire(self):
        fired = self.signals_for(
            {'integrity': {'checked': True, 'findings': [{'id': 'zip.header_mismatch'}]}})
        for indicator_id in integrity.INDICATORS:
            self.assertIn(indicator_id, fired, f'{indicator_id} was not measured')
        self.assertTrue(fired['zip.header_mismatch'])
        self.assertFalse(fired['zip.encryption_flag_on_package'])

    def test_a_file_that_could_not_be_checked_claims_nothing_either_way(self):
        # "Did not fire" would be a statement about a file nothing could read.
        fired = self.signals_for({'integrity': {'checked': False, 'findings': []}})
        self.assertEqual([k for k in fired if k in integrity.INDICATORS], [])

    def test_a_real_package_measures_every_indicator(self):
        from apk_engine import integrity as module
        fired = self.signals_for({'integrity': module.check(factories.apk())})
        self.assertEqual(set(module.INDICATORS) - set(fired), set())
        self.assertFalse(any(fired[i] for i in module.INDICATORS))
