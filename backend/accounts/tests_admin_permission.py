# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
An administrator account that has not been approved holds no clearance.

From a blind audit (31 Oct 2026, L6): IsAdministrator checked the role field
and not approval, unlike every other permission class here.
"""
from django.test import TestCase
from rest_framework.test import APIClient

from .models import User

PENDING = '/api/auth/accounts/pending/'


class AdministratorNeedsApproval(TestCase):
    def _get(self, **fields):
        user = User.objects.create_user(password='a-long-enough-password', **fields)
        client = APIClient()
        client.force_authenticate(user)
        return client.get(PENDING).status_code

    def test_an_unapproved_admin_is_refused(self):
        self.assertEqual(self._get(username='a1', badge_id='GP-9001',
                                   role=User.Role.ADMIN, is_approved=False), 403)

    def test_an_approved_admin_is_allowed(self):
        self.assertEqual(self._get(username='a2', badge_id='GP-9002',
                                   role=User.Role.ADMIN, is_approved=True), 200)

    def test_the_bootstrap_superuser_is_allowed(self):
        self.assertEqual(self._get(username='a3', badge_id='GP-9003', is_superuser=True,
                                   is_staff=True, is_approved=False), 200)
