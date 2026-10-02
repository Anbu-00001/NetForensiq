# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
A test run must not write into the evidence store of the database a person is
actually using.

Until research/161 s.5 it did. `backend/evidence_store/` collected 780 MB of
sealed test files beside real demo exhibits, and a root-owned leftover from one
run made `ExhibitNumberSafetyTests` fail with PermissionError on the next.
"""
from pathlib import Path

from django.conf import settings
from django.test import SimpleTestCase


class TestStoreIsolationTests(SimpleTestCase):
    def test_the_store_is_not_the_projects_real_evidence_directory(self):
        real = (Path(settings.BASE_DIR) / 'evidence_store').resolve()
        for name in ('MEDIA_ROOT', 'EVIDENCE_ROOT', 'CERTIFICATE_ROOT'):
            path = Path(getattr(settings, name)).resolve()
            self.assertFalse(
                path == real or real in path.parents,
                f'{name} points into {real}: a test run would write test files '
                f'beside real exhibits')

    def test_the_encryption_key_is_not_the_projects_real_key(self):
        real = (Path(settings.BASE_DIR) / '.evidence.key').resolve()
        self.assertNotEqual(Path(settings.EVIDENCE_KEY_FILE).resolve(), real)
