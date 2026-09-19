# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The tier decision, including the rules about what may not move it.

These are the tests that keep the promise the old module broke: an unmeasured
or experimental signal is reported but cannot make the system call something
harmful, and a failed examination never reads as a clean one.
"""

import unittest

from apk_engine import baselines as baseline_store
from apk_engine.report import unexaminable
from apk_engine.verdict import decide


def measured(signal_id, benign_fired=0, benign_n=31, malicious_fired=1):
    return {'measured_at': '2026-09-17T00:00:00+00:00',
            'corpus': {'benign': benign_n, 'malicious': 1},
            'signals': {signal_id: {'benign_fired': benign_fired,
                                    'malicious_fired': malicious_fired}}}


def behaviour(signal_id='beh.install_under_network_blackout', tier=3, pha='hostile-downloader',
              status=None):
    return {'id': signal_id, 'title': 'Installs under a network blackout', 'tier': tier,
            'pha': pha, 'attack': [{'id': 'T1407', 'name': 'Download New Code at Runtime'}],
            'baseline': status or baseline_store.status(measured(signal_id), signal_id)}


def integrity_finding(signal_id='zip.unknown_compression_method', status=None):
    return {'findings': [{'id': signal_id, 'title': 'Compression method field forged',
                          'attack': [{'id': 'T1406', 'name': 'Obfuscated Files or Information'}],
                          'baseline': status or baseline_store.status(measured(signal_id), signal_id)}]}


class TierTests(unittest.TestCase):
    def test_validated_behaviour_reaches_tier_3_with_a_family(self):
        assessment = decide(None, [behaviour()], None, True, True)
        self.assertEqual(assessment['tier'], 3)
        self.assertEqual(assessment['families'][0]['category'], 'Hostile downloader')
        self.assertIn('definition', assessment['families'][0])
        self.assertEqual([t['id'] for t in assessment['attack']], ['T1407'])

    def test_experimental_behaviour_is_reported_but_changes_nothing(self):
        status = baseline_store.status(measured('beh.x', benign_fired=2), 'beh.x')
        self.assertEqual(status['status'], 'experimental')
        assessment = decide(None, [behaviour('beh.x', status=status)], None, True, True)
        self.assertEqual(assessment['tier'], 1)
        self.assertEqual(assessment['not_established'][0]['id'], 'beh.x')
        self.assertEqual(assessment['families'], [])

    def test_unmeasured_behaviour_cannot_raise_the_tier(self):
        status = baseline_store.status({}, 'beh.y')
        self.assertEqual(status['status'], 'unmeasured')
        assessment = decide(None, [behaviour('beh.y', status=status)], None, True, True)
        self.assertEqual(assessment['tier'], 1)

    def test_a_small_corpus_cannot_validate_anything(self):
        status = baseline_store.status(measured('beh.z', benign_n=5), 'beh.z')
        self.assertEqual(status['status'], 'experimental')

    def test_validated_integrity_finding_reaches_tier_2(self):
        assessment = decide(integrity_finding(), [], None, True, True)
        self.assertEqual(assessment['tier'], 2)
        self.assertEqual(assessment['label'], 'Built to evade inspection')
        self.assertEqual(assessment['families'], [])

    def test_identity_intel_match_reaches_tier_4(self):
        intel = {'identity_match': True, 'matches': [
            {'kind': 'signing_certificate', 'value': 'AA', 'product': 'TheTruthSpy',
             'strength': 'identity', 'source': 'stalkerware-indicators (Echap)',
             'snapshot': 'commit abc'}]}
        assessment = decide(None, [], intel, True, True)
        self.assertEqual(assessment['tier'], 4)
        self.assertEqual(assessment['families'][0]['product'], 'TheTruthSpy')

    def test_supporting_intel_alone_does_not_reach_tier_4(self):
        intel = {'identity_match': False, 'matches': [
            {'kind': 'package_name', 'value': 'com.x', 'product': 'Some product',
             'strength': 'supporting', 'source': 's', 'snapshot': 'c'}]}
        assessment = decide(None, [], intel, True, True)
        self.assertEqual(assessment['tier'], 1)

    def test_incomplete_examination_is_tier_0_not_tier_1(self):
        assessment = decide(None, [], None, False, True)
        self.assertEqual(assessment['tier'], 0)
        self.assertEqual(assessment['label'], 'Could not be examined')

    def test_tier_1_never_says_safe(self):
        assessment = decide(None, [], None, True, True)
        self.assertEqual(assessment['tier'], 1)
        self.assertIn('not a finding that the app is safe', assessment['meaning'])

    def test_evidence_survives_a_failure_to_parse_the_code(self):
        # Tampering was found, the code was not readable: still tier 2.
        assessment = decide(integrity_finding(), [], None, False, False)
        self.assertEqual(assessment['tier'], 2)

    def test_unexaminable_report_is_tier_0_and_carries_the_reason(self):
        report = unexaminable('It timed out.')
        self.assertEqual(report['assessment']['tier'], 0)
        self.assertIn('It timed out.', report['assessment']['summary'])
        self.assertEqual(report['behaviours'], [])
