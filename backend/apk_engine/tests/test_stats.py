"""The confidence bound printed next to every measured count."""

import unittest

from apk_engine.stats import binomial_cdf, upper_bound


class UpperBoundTests(unittest.TestCase):
    def test_zero_in_n_matches_the_closed_form(self):
        # The "rule of three": with no firings the 95% bound is ≈ 3/n.
        self.assertAlmostEqual(upper_bound(0, 31), 1 - 0.05 ** (1 / 31), places=12)
        self.assertAlmostEqual(upper_bound(0, 31), 0.0921, places=4)
        self.assertAlmostEqual(upper_bound(0, 300), 0.00995, places=4)

    def test_a_larger_corpus_bounds_more_tightly(self):
        self.assertLess(upper_bound(0, 300), upper_bound(0, 31))

    def test_bound_with_firings_satisfies_its_definition(self):
        bound = upper_bound(2, 50)
        self.assertAlmostEqual(binomial_cdf(2, 50, bound), 0.05, places=3)
        self.assertGreater(bound, 2 / 50)

    def test_no_measurement_bounds_nothing(self):
        self.assertIsNone(upper_bound(0, 0))

    def test_all_firings_bound_is_one(self):
        self.assertEqual(upper_bound(5, 5), 1.0)
