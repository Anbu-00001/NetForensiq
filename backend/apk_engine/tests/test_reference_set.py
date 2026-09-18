"""
Identity claims: is this the package it says it is?

The cases that matter are the ones where the honest answer is "not necessarily
malicious". A package signed by a key other than the one on record IS a
different build; whether that is impersonation or an alternative store depends
on what the reference entry actually claims to know, which is why authority is
recorded per entry and drives the tier.
"""

import unittest

from apk_engine.reference_set import PLAY_MINIMUM_NOT_AFTER, build, check
from apk_engine.verdict import decide

AUTHORISED = 'a' * 64
OTHER = 'b' * 64
FAR_FUTURE = '2045-01-01T00:00:00'


def identity(package='com.example.pension', label='Pension Seva',
             sha256=AUTHORISED, not_after=FAR_FUTURE):
    return {'package': package, 'label': label,
            'signing': {'certificates': [{'sha256': sha256, 'not_after': not_after}]}}


def reference(authority='publisher', label='Pension Seva'):
    return {'built': '2026-09-18T00:00:00+00:00', 'note': 'Google Play, 18 Sep 2026',
            'entries': {'com.example.pension': {
                'label': label, 'certificates_sha256': [AUTHORISED], 'authority': authority,
                'source': {'note': 'Google Play listing', 'file': 'pension.apk'}}}}


def ids(result):
    return [f['id'] for f in result['findings']]


class SignerTests(unittest.TestCase):
    def test_the_authorised_key_produces_no_finding(self):
        self.assertEqual(ids(check(identity(), reference())), [])

    def test_a_different_key_under_a_known_name_is_reported(self):
        result = check(identity(sha256=OTHER), reference())
        self.assertIn('identity.signer_not_authorised', ids(result))
        finding = result['findings'][0]
        self.assertEqual(finding['establishes'], 'identity')
        self.assertEqual(finding['expected_sha256'], [AUTHORISED])
        self.assertEqual(finding['observed_sha256'], [OTHER])
        self.assertTrue(finding['lookalikes'])

    def test_authority_decides_how_strongly_it_is_put(self):
        publisher = check(identity(sha256=OTHER), reference('publisher'))['findings'][0]
        distributor = check(identity(sha256=OTHER), reference('distributor'))['findings'][0]
        self.assertEqual(publisher['tier'], 3)
        self.assertEqual(distributor['tier'], 2)
        self.assertIn('not produced by the holder', publisher['statement'])
        self.assertIn('not that build', distributor['statement'])

    def test_an_unknown_package_is_not_accused_of_anything(self):
        self.assertEqual(ids(check(identity(package='com.unknown.app', label='Nothing'),
                                   reference())), [])

    def test_an_empty_reference_set_reports_that_nothing_was_checked(self):
        result = check(identity(sha256=OTHER), {'entries': {}, 'built': '', 'note': ''})
        self.assertEqual(result['findings'], [])
        self.assertEqual(result['checked_against']['entries'], 0)

    def test_a_package_with_no_certificate_is_not_a_mismatch(self):
        blank = {'package': 'com.example.pension', 'label': 'x', 'signing': {'certificates': []}}
        self.assertEqual(ids(check(blank, reference())), [])


class ClaimTests(unittest.TestCase):
    def test_a_known_label_under_a_different_package_is_reported_but_not_as_a_fact(self):
        result = check(identity(package='com.evil.clone', label='Pension  Seva!'), reference())
        finding = result['findings'][0]
        self.assertEqual(finding['id'], 'identity.label_claims_another_package')
        self.assertEqual(finding['establishes'], 'claim')
        self.assertEqual(finding['impersonates'], 'com.example.pension')

    def test_a_certificate_too_short_lived_for_play_is_reported(self):
        result = check(identity(package='com.unknown.app', label='x', not_after='2027-01-01'),
                       reference())
        finding = result['findings'][0]
        self.assertEqual(finding['id'], 'cert.expires_before_play_minimum')
        self.assertIn(PLAY_MINIMUM_NOT_AFTER.isoformat(), finding['statement'])

    def test_a_long_lived_certificate_is_not_reported(self):
        self.assertNotIn('cert.expires_before_play_minimum',
                         ids(check(identity(package='com.unknown.app'), reference())))


class VerdictTests(unittest.TestCase):
    """A claim must never set the tier; only an identity fact may."""

    def decide_with(self, result):
        return decide({'findings': []}, [], None, True, True, reference=result)

    def test_a_signer_mismatch_sets_the_tier_and_is_named_plainly(self):
        assessment = self.decide_with(check(identity(sha256=OTHER), reference('publisher')))
        self.assertEqual(assessment['tier'], 3)
        self.assertEqual(assessment['label'], 'Not the application it claims to be')
        self.assertIn('com.example.pension', assessment['summary'])
        self.assertEqual([b['kind'] for b in assessment['basis']], ['identity'])

    def test_a_label_claim_alone_leaves_the_tier_where_it_was(self):
        assessment = self.decide_with(
            check(identity(package='com.evil.clone', label='Pension Seva'), reference()))
        self.assertEqual(assessment['tier'], 1)
        self.assertEqual(assessment['basis'], [])

    def test_a_demonstrated_behaviour_keeps_its_own_wording_at_the_same_tier(self):
        behaviour = [{'id': 'beh.x', 'title': 'Installs a package under a network blackout',
                      'tier': 3, 'attack': [], 'pha': None,
                      'baseline': {'status': 'validated', 'benign_fired': 0, 'benign_n': 31}}]
        assessment = decide({'findings': []}, behaviour, None, True, True,
                            reference=check(identity(sha256=OTHER), reference('publisher')))
        self.assertEqual(assessment['tier'], 3)
        self.assertEqual(assessment['label'], 'Harmful behaviour demonstrated')


class BuildTests(unittest.TestCase):
    def test_building_from_nothing_gives_an_empty_but_valid_set(self):
        data = build([], authority='publisher', note='none')
        self.assertEqual(data['entry_count'], 0)
        self.assertEqual(data['authority'], 'publisher')
        self.assertEqual(data['entries'], {})

    def test_an_unreadable_file_is_recorded_as_a_failure_not_an_entry(self):
        data = build(['/nonexistent/missing.apk'])
        self.assertEqual(data['entry_count'], 0)
        self.assertEqual(len(data['failures']), 1)
