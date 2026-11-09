# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The HTTPS-only switch, the admin switch, and the documents that describe them.

From a blind review (1 Nov 2026): `manage.py check --deploy` gave four warnings
about HTTPS, nothing said what to do about them, `.env.example` set DEBUG=True
although the code defaults to False, and Django's /admin/ could not be removed.
"""
import re
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase

from .transport import DEFAULT_HSTS_SECONDS, admin_enabled, flag, transport_settings

REPO = Path(__file__).resolve().parents[2]


class Switch(SimpleTestCase):
    def test_nothing_changes_by_default(self):
        """The default deployment is plain HTTP on loopback; these would lock it out."""
        self.assertEqual(transport_settings({}), {})
        self.assertEqual(transport_settings({'HTTPS_ONLY': ''}), {})
        self.assertEqual(transport_settings({'HTTPS_ONLY': 'false'}), {})

    def test_https_only_turns_on_the_four_settings_check_deploy_asks_for(self):
        got = transport_settings({'HTTPS_ONLY': 'true'})
        self.assertIs(got['SECURE_SSL_REDIRECT'], True)
        self.assertIs(got['SESSION_COOKIE_SECURE'], True)
        self.assertIs(got['CSRF_COOKIE_SECURE'], True)
        self.assertEqual(got['SECURE_HSTS_SECONDS'], DEFAULT_HSTS_SECONDS)

    def test_the_hsts_period_is_short_by_default_and_settable(self):
        self.assertLessEqual(DEFAULT_HSTS_SECONDS, 86400)
        got = transport_settings({'HTTPS_ONLY': '1', 'SECURE_HSTS_SECONDS': '31536000'})
        self.assertEqual(got['SECURE_HSTS_SECONDS'], 31536000)

    def test_a_forwarded_protocol_header_is_believed_only_behind_a_declared_proxy(self):
        env = {'HTTPS_ONLY': 'true'}
        self.assertNotIn('SECURE_PROXY_SSL_HEADER', transport_settings(env, trusted_proxies=0))
        self.assertEqual(transport_settings(env, trusted_proxies=1)['SECURE_PROXY_SSL_HEADER'],
                         ('HTTP_X_FORWARDED_PROTO', 'https'))

    def test_flag_reads_the_usual_spellings(self):
        for yes in ('1', 'true', 'TRUE', ' yes ', 'on'):
            self.assertTrue(flag(yes), yes)
        for no in ('0', 'false', 'off', 'no', 'maybe'):
            self.assertFalse(flag(no), no)
        self.assertTrue(flag('', default=True))
        self.assertFalse(flag(None))

    def test_admin_is_on_unless_switched_off(self):
        self.assertTrue(admin_enabled({}))
        self.assertTrue(admin_enabled({'ADMIN_ENABLED': ''}))
        self.assertFalse(admin_enabled({'ADMIN_ENABLED': 'false'}))

    def test_the_running_configuration_is_the_default(self):
        """Under test nothing is set, so none of the secure-only settings are on."""
        self.assertFalse(getattr(settings, 'SECURE_SSL_REDIRECT', False))
        self.assertTrue(settings.ADMIN_ENABLED)


class DocumentsAgree(SimpleTestCase):
    def test_the_example_environment_does_not_turn_debug_on(self):
        example = (REPO / 'backend' / '.env.example').read_text()
        self.assertEqual(re.findall(r'^DEBUG=(.*)$', example, re.M), ['False'])

    def test_compose_defaults_match_the_code(self):
        compose = (REPO / 'docker-compose.yml').read_text()
        self.assertIn('HTTPS_ONLY: ${HTTPS_ONLY:-false}', compose)
        self.assertIn(f'SECURE_HSTS_SECONDS: ${{SECURE_HSTS_SECONDS:-{DEFAULT_HSTS_SECONDS}}}',
                      compose)
        self.assertIn('ADMIN_ENABLED: ${ADMIN_ENABLED:-true}', compose)

    def test_the_keys_have_a_volume_in_the_main_compose_file(self):
        """Without one they were deleted with the container (audit F-02/F-03)."""
        compose = (REPO / 'docker-compose.yml').read_text()
        self.assertIn('- data:/app/data', compose)
        self.assertRegex(compose, r'(?m)^volumes:\n(?:  \w+:\n)*  data:\n')
