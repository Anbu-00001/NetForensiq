# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The limits the tool states about itself (capture/limits.py), and that they are the
measured ones.

What these hold the code to: no figure on the page, in the API or in a report is
typed; the sentence for "nothing found" carries the miss rate; where nothing was
measured the module says so instead of inventing a number; and what is quoted from
a standard is marked as read or as secondary.
"""
import json
import re
from pathlib import Path
from unittest import mock

from django.test import SimpleTestCase
from rest_framework.test import APIClient

from . import limits

REPO = Path(__file__).resolve().parents[2]


def _results():
    return json.loads((REPO / 'validation' / 'results.json').read_text())


class MeasuredFiguresTests(SimpleTestCase):
    def test_the_summary_is_what_the_validation_data_says(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            'build_validation_report', REPO / 'scripts' / 'build_validation_report.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(
            (REPO / 'backend' / 'capture' / 'data' / 'validation_summary.json').read_text(),
            module.build_summary(_results()),
            'backend/capture/data/validation_summary.json is out of date: '
            'run scripts/build_validation_report.py')

    def test_the_apk_sentence_carries_the_measured_numbers(self):
        v = limits.summary()
        u = v['apk']['unseen']
        sentence = limits.apk_nothing_found()
        # The exact phrases, not bare digits: "8" is inside "58%" and "38%", and an
        # assertion that a digit appears somewhere would pass with the figure removed.
        for phrase in (f"On {u['n']} malware samples", f"reached a tier on {u['detected']} (",
                       f"reached none on {u['missed']} (",
                       f"could not examine {u['could_not_be_examined']}."):
            self.assertIn(phrase, sentence)
        self.assertIn('not a finding that the app is safe', sentence)
        self.assertIn('may be among those it misses', sentence)

    def test_the_sentence_does_not_round_the_miss_rate_down(self):
        u = limits.summary()['apk']['unseen']
        self.assertIn(f"{u['missed'] / u['n'] * 100:.0f}%", limits.apk_nothing_found())

    def test_where_nothing_was_measured_no_number_is_invented(self):
        with mock.patch.object(limits, 'summary', return_value=None):
            sentence = limits.apk_nothing_found()
        self.assertIn('has not been measured', sentence)
        self.assertNotRegex(sentence, r'\d+ malware samples')

    def test_the_network_sentence_names_how_few_attacks_there_were(self):
        n = limits.network_figures()
        self.assertIn(str(n['attack_captures']), limits.network_nothing_found())
        self.assertIn('not evidence the network was quiet', limits.network_nothing_found())

    def test_the_counts_are_read_from_the_code(self):
        from .detection import RULE_IDS, THRESHOLDS
        c = limits.counts()
        self.assertEqual((c['thresholds'], c['rules']), (len(THRESHOLDS), len(RULE_IDS)))
        self.assertEqual(c['heuristic_thresholds'],
                         sum(1 for _, s in THRESHOLDS.values() if 'OUR HEURISTIC' in s))

    def test_the_rate_table_figures_match_the_table(self):
        from . import base_rates
        n = limits.network_figures()
        rules = base_rates.table()['rules']
        self.assertEqual(set(n['rules_untested']),
                         {r for r, v in rules.items() if v['benign_fired'] == 0 and v['malicious_fired'] == 0})
        self.assertNotIn('ANOMALY_STATISTICAL', n['rules_firing_on_ordinary_traffic'])


class StandardsTests(SimpleTestCase):
    def test_each_standard_says_whether_its_text_was_read(self):
        by_id = {s['id']: s for s in limits.standards()}
        self.assertTrue(by_id['NIST SP 800-86']['verified'])
        self.assertFalse(by_id['ISO/IEC 27037:2012']['verified'])
        self.assertIn('Secondary', by_id['ISO/IEC 27037:2012']['note'])

    def test_the_nist_quotations_are_the_documents_words(self):
        """Spot-checked against the PDF's text; these are the sentences that were read."""
        self.assertIn('identified, labeled, recorded, and collected, and its integrity is preserved',
                      limits.NIST_PHASES)
        self.assertEqual(limits.NIST_FALSE_NEGATIVE,
                         'False Negative: Incorrectly classifying malicious activity as benign.')

    def test_the_mapping_never_claims_the_tool_acquires_evidence(self):
        text = json.dumps(limits.standards())
        self.assertIn('no imaging', text)
        self.assertIn('no write-blocking', text)

    def test_the_tool_does_not_claim_the_standard_endorses_it(self):
        text = json.dumps(limits.standards()).lower()
        for claim in ('compliant', 'complies', 'certified', 'accredited by'):
            self.assertNotIn(claim, text)


class LimitsListTests(SimpleTestCase):
    def test_the_engines_own_limits_are_included_verbatim(self):
        from apk_engine.report import LIMITS
        for line in LIMITS:
            self.assertIn(line, limits.cannot())

    def test_the_review_status_is_stated_plainly(self):
        text = ' '.join(limits.cannot())
        self.assertIn('reviewed by anyone other than its author', text)
        self.assertIn('not accredited', text)

    def test_every_reference_is_printed_as_text_with_its_verification_state(self):
        refs = limits.references()
        self.assertGreater(len(refs), 20)
        for ref in refs:
            self.assertTrue(ref['url'].startswith('https://'), ref)
            self.assertIsInstance(ref['verified'], bool)


class NoTypedNumbersTests(SimpleTestCase):
    """The failure this module exists to prevent."""

    STALE = ('thirty-five', 'twenty-three', 'ten rules', 'of the ten', 'twenty-four thresholds')

    def test_the_report_source_does_not_spell_out_counts_that_have_changed(self):
        source = (REPO / 'backend' / 'evidence' / 'investigation_report.py').read_text()
        code = '\n'.join(l for l in source.splitlines() if not l.strip().startswith('#'))
        for phrase in self.STALE:
            self.assertNotIn(phrase, code)

    def test_the_limits_module_has_no_digits_in_its_prose_that_belong_to_the_data(self):
        """Percentages and counts in sentences are formatted from variables, not typed."""
        source = (REPO / 'backend' / 'capture' / 'limits.py').read_text()
        prose = re.findall(r"f?'([^'\n]{40,})'", source)
        for line in prose:
            if '{' in line:
                continue
            self.assertNotRegex(line, r'\b\d{2,3}%|\b\d{2,3} (malware|captures|thresholds|rules)\b', line)


class EndpointTests(SimpleTestCase):
    def test_it_is_public_and_returns_the_document(self):
        response = APIClient().get('/api/engine/limits/')
        self.assertEqual(response.status_code, 200)
        body = response.json()
        for key in ('validation', 'counts', 'network', 'nothing_found', 'cannot', 'standards',
                    'references', 'status'):
            self.assertIn(key, body)
        self.assertEqual(body['nothing_found']['apk'], limits.apk_nothing_found())

    def test_it_exposes_no_case_data(self):
        text = json.dumps(APIClient().get('/api/engine/limits/').json())
        for forbidden in ('exhibit_number', 'sha256_hash', 'fir_number', 'username'):
            self.assertNotIn(forbidden, text)


class MeasuredSentenceTests(SimpleTestCase):
    def test_the_measured_half_is_what_the_sample_page_adds(self):
        measured = limits.apk_measured()
        self.assertIn('may be among those it misses', measured)
        self.assertNotIn('not a finding that the app is safe', measured)  # the banner already says it
        self.assertTrue(limits.apk_nothing_found().endswith(measured))

    def test_unmeasured_gives_none_not_an_invented_figure(self):
        with mock.patch.object(limits, 'summary', return_value=None):
            self.assertIsNone(limits.apk_measured())

    def test_the_api_carries_both(self):
        body = APIClient().get('/api/engine/limits/').json()
        self.assertEqual(body['nothing_found']['apk_measured'], limits.apk_measured())
