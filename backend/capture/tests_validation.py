# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The validation report (validation/VALIDATION_REPORT.md) held to its own rules.

A validation report is only worth reading if every figure can be traced and if it
cannot quietly describe a different tool from the one shipped. These tests make
four things true:

* the committed report is exactly what the generator produces from results.json,
  so no figure was edited by hand;
* the per-sample file agrees with the summary derived from it;
* the README's headline numbers are the report's numbers;
* the report names the hash of the baseline table and the rate table that are
  actually in the repository, so changing either without re-measuring fails here
  instead of leaving a report that describes the previous tool (change control).
"""
import csv
import hashlib
import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

from django.test import SimpleTestCase

REPO = Path(__file__).resolve().parents[2]
VALIDATION = REPO / 'validation'
HEX64 = re.compile(r'^[0-9a-f]{64}$')


def _generator():
    spec = importlib.util.spec_from_file_location(
        'build_validation_report', REPO / 'scripts' / 'build_validation_report.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _results():
    return json.loads((VALIDATION / 'results.json').read_text())


def _samples():
    with open(VALIDATION / 'apk_samples.csv', newline='') as handle:
        return list(csv.DictReader(handle))


class ReportIsDerivedTests(SimpleTestCase):
    def test_the_committed_report_is_what_the_generator_produces(self):
        expected = _generator().build(_results())
        self.assertEqual(
            (VALIDATION / 'VALIDATION_REPORT.md').read_text(), expected,
            'validation/VALIDATION_REPORT.md was edited by hand or is out of date: '
            'run scripts/build_validation_report.py')

    def test_the_report_states_its_own_status_and_limits(self):
        text = (VALIDATION / 'VALIDATION_REPORT.md').read_text()
        for phrase in ('developer-supplied testing information',
                       'not been reviewed by anyone other than its author',
                       'Tier 1 never means "safe"', 'Tier 0 is not a clean result',
                       'not representative of seized devices'):
            self.assertIn(phrase, text)


class SampleFileAgreesTests(SimpleTestCase):
    def test_each_runs_tier_counts_match_its_rows(self):
        rows = _samples()
        for run in _results()['apk_runs']:
            counts = Counter(int(r['tier']) for r in rows if r['run'] == run['id'])
            for tier in range(5):
                self.assertEqual(counts.get(tier, 0), run['tiers'][str(tier)],
                                 f"{run['id']} tier {tier}")
            self.assertEqual(sum(counts.values()), run['n'], run['id'])

    def test_every_sample_is_identified_by_a_digest_and_listed_once_per_run(self):
        seen = set()
        for row in _samples():
            self.assertRegex(row['sha256'], HEX64, row)
            key = (row['run'], row['sha256'])
            self.assertNotIn(key, seen, f'{key} listed twice')
            seen.add(key)

    def test_malicious_runs_cover_their_whole_manifest(self):
        for run in _results()['apk_runs']:
            if run['label'] == 'malicious':
                self.assertTrue(run['all_manifest_samples_present'], run['id'])

    def test_nothing_that_identifies_a_contributor_is_published(self):
        header = (VALIDATION / 'apk_samples.csv').read_text().splitlines()[0]
        for forbidden in ('reporter', 'tags', 'family', 'uploader', 'user'):
            self.assertNotIn(forbidden, header)
        self.assertNotIn('reporter', json.dumps(_results()))


class HeadlineFiguresTests(SimpleTestCase):
    def test_the_readmes_unseen_malware_figures_are_the_reports(self):
        runs = {r['id']: r for r in _results()['apk_runs']}
        heldout = runs.get('heldout-v6') or runs['heldout-v5']
        blind = runs['blind-v6']
        combined = f"{heldout['detected_of_n'] + blind['detected_of_n']} / {heldout['n'] + blind['n']}"
        readme = (REPO / 'README.md').read_text()
        self.assertIn(combined, readme, f'README does not state the combined unseen figure {combined}')
        self.assertIn(f"{blind['detected_of_n']} / {blind['n']}", readme)
        fresh = runs['fresh-benign-v6']
        fp, examined = fresh['false_positives_of_examined']
        self.assertIn(f'{fp} / {examined} examined', readme)

    def test_the_readmes_in_sample_figure_is_the_reports(self):
        design = {r['id']: r for r in _results()['apk_runs']}['design-v5']
        self.assertIn(f"{design['detected_of_n']} / {design['n']}", (REPO / 'README.md').read_text())


class ChangeControlTests(SimpleTestCase):
    """The report must describe the tool that is actually in the repository."""

    def _sha(self, relative):
        return hashlib.sha256((REPO / relative).read_bytes()).hexdigest()

    def test_the_baseline_table_is_the_one_the_report_names(self):
        self.assertEqual(
            _results()['shipped_baselines_sha256'],
            self._sha('backend/apk_engine/data/baselines.json'),
            'the shipped APK baseline table changed since the validation data were derived: '
            're-measure, then rerun scripts/extract_validation_data.py')

    def test_the_rate_table_is_the_one_the_report_names(self):
        self.assertEqual(
            _results()['network']['rule_table_sha256'],
            self._sha('backend/capture/data/rule_base_rates.json'),
            'backend/capture/data/rule_base_rates.json changed since the validation data were '
            'derived: re-measure, then rerun scripts/extract_validation_data.py')

    def test_every_run_records_what_it_ran_on(self):
        for run in _results()['apk_runs']:
            self.assertTrue(run['engine_image'], run['id'])
            self.assertRegex(run['baselines_sha256'] or '', HEX64, run['id'])


class NetworkCorpusTests(SimpleTestCase):
    def test_every_capture_has_a_digest_and_a_result(self):
        net = _results()['network']
        names = [c['name'] for c in net['corpus']]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(net['per_capture']))
        for capture in net['corpus']:
            self.assertRegex(capture['sha256'], HEX64, capture['name'])

    def test_the_rule_table_in_the_report_data_is_the_shipped_one(self):
        shipped = json.loads((REPO / 'backend/capture/data/rule_base_rates.json').read_text())
        self.assertEqual(_results()['network']['rule_table'], shipped)
