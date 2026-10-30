# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The shipped rate limits are real limits, and the documents say what they are.

For ten weeks every default was 10000/hour while the docs said eight sign-ins an
hour. Nothing failed, because the throttle tests ran on separate hard-coded test
values and nothing compared the docs with the code. These tests do both.
"""
import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from .throttles import RATES, throttle_rates

REPO = Path(__file__).resolve().parents[2]


def per_hour(rate):
    count, period = rate.split('/')
    return int(count) * {'second': 3600, 'sec': 3600, 's': 3600, 'minute': 60, 'min': 60,
                         'm': 60, 'hour': 1, 'h': 1, 'day': 1 / 24, 'd': 1 / 24}[period]


class ShippedDefaults(SimpleTestCase):
    def test_with_nothing_configured_sign_in_is_limited_to_eight_an_hour(self):
        self.assertEqual(throttle_rates({})['login'], '8/hour')

    def test_no_default_is_a_limit_in_name_only(self):
        """The regression this file exists for: a default so high it limits nothing."""
        for scope, rate in throttle_rates({}).items():
            with self.subTest(scope=scope):
                self.assertLessEqual(per_hour(rate), 1000, f'{scope} defaults to {rate}')

    def test_an_operator_can_raise_a_limit_deliberately(self):
        self.assertEqual(throttle_rates({'LOGIN_THROTTLE_RATE': '200/hour'})['login'], '200/hour')

    def test_an_empty_variable_is_unset_not_unlimited(self):
        """`.env.example` ships `LOGIN_THROTTLE_RATE=` with nothing after it."""
        self.assertEqual(throttle_rates({'LOGIN_THROTTLE_RATE': ''})['login'], '8/hour')

    def test_under_test_the_environment_cannot_weaken_the_limits(self):
        rates = throttle_rates({'LOGIN_THROTTLE_RATE': '10000/hour'}, testing=True)
        self.assertEqual(rates['login'], '8/hour')

    def test_the_running_configuration_uses_these_rates(self):
        self.assertEqual(settings.REST_FRAMEWORK['DEFAULT_THROTTLE_RATES'],
                         throttle_rates({}, testing=True))


class DocumentsAgree(SimpleTestCase):
    def test_the_compose_file_defaults_are_the_shipped_defaults(self):
        compose = (REPO / 'docker-compose.yml').read_text()
        for variable, default in RATES.values():
            found = re.search(r'\$\{' + variable + r':-([^}]*)\}', compose)
            if found is None:
                continue  # not every scope is exposed in the compose file
            with self.subTest(variable=variable):
                self.assertEqual(found.group(1), default)

    def test_the_example_environment_states_the_real_sign_in_default(self):
        example = (REPO / 'backend' / '.env.example').read_text()
        stated = re.search(r'Sign-in attempts allowed per hour per source address\. Default (\d+)\.',
                           example)
        self.assertIsNotNone(stated, '.env.example no longer states the sign-in default')
        self.assertEqual(f'{stated.group(1)}/hour', RATES['login'][1])
