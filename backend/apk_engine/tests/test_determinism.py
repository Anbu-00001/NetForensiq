"""
The same file, examined twice, must give the same report.

Why this is a test and not a remark
===================================
An expert opinion a second examiner cannot obtain again is worth less than one
they can, and s.63(4) of the Bharatiya Sakshya Adhiniyam contemplates exactly
that second examiner. Determinism is easy to lose by accident — a set iterated
without sorting, a dict keyed on object identity, a timestamp written into a
finding — and impossible to notice by eye, because two reports differing in one
ordering still both look right.

``engine.seconds`` is the single field allowed to differ; it measures elapsed
time and is named as volatile in the report's own reproduction block.
"""

import json
import os
import tempfile
import unittest

from apk_engine.engine import examine

from . import factories

VOLATILE = ('seconds',)


def stable(report):
    report = json.loads(json.dumps(report, default=str, sort_keys=True))
    for field in VOLATILE:
        report['engine'].pop(field, None)
    return json.dumps(report, sort_keys=True)


class DeterminismTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.addCleanup(self._dir.cleanup)
        self.apk = os.path.join(self._dir.name, 'sample.apk')
        with open(self.apk, 'wb') as handle:
            handle.write(factories.apk())

    def test_two_examinations_of_one_file_agree_in_every_field_but_timing(self):
        first, second = examine(self.apk), examine(self.apk)
        self.assertEqual(stable(first), stable(second))

    def test_the_report_states_how_to_obtain_it_again(self):
        report = examine(self.apk)
        reproduction = report['reproduction']
        self.assertIn(report['file']['sha256'], reproduction['command'])
        self.assertIn('engine.seconds', reproduction['determinism'])
        # Every reference file the engine read is pinned by digest, so a report
        # produced against a different snapshot is visibly a different report.
        self.assertIn('baselines.json', reproduction['reference_data_sha256'])
        for digest in reproduction['reference_data_sha256'].values():
            self.assertEqual(len(digest), 64)

    def test_a_copy_of_the_file_under_another_name_reports_the_same_findings(self):
        other = os.path.join(self._dir.name, 'renamed.apk')
        with open(self.apk, 'rb') as source, open(other, 'wb') as target:
            target.write(source.read())
        first = examine(self.apk, original_name='sample.apk')
        second = examine(other, original_name='renamed.apk')
        self.assertEqual(first['assessment'], second['assessment'])
        self.assertEqual(first['file']['sha256'], second['file']['sha256'])
