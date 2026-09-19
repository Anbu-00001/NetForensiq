# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Attribution is stated in one place and checked everywhere it is repeated.

The author's name appears in LICENSE, NOTICE.md, CITATION.cff, the Docker image
labels, the header of every source file and the public engine-info endpoint.
Each copy that can drift is a copy that eventually will, and a stale name in the
licence is worse than none — it is the one line the MIT licence obliges every
copy to keep. These tests make changing the author a single edit to
netforensiq_backend/provenance.py plus whatever these tests then say is stale.
"""

import os
import re
import subprocess
import sys

from django.test import SimpleTestCase
from rest_framework.test import APIClient

from netforensiq_backend import provenance

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _read(name):
    with open(os.path.join(REPO, name), encoding='utf-8') as handle:
        return handle.read()


class AttributionConsistencyTests(SimpleTestCase):

    def test_licence_names_the_author(self):
        licence = _read('LICENSE')
        self.assertTrue(licence.startswith('MIT License'),
                        'LICENSE must stay the standard MIT text')
        self.assertIn(provenance.COPYRIGHT, licence)
        self.assertNotIn('The NetForensiq authors', licence)

    def test_notice_names_the_author_and_repository(self):
        notice = _read('NOTICE.md')
        self.assertIn(provenance.COPYRIGHT, notice)
        self.assertIn(provenance.REPOSITORY.replace('https://', ''), notice)

    def test_citation_file_names_the_author_and_repository(self):
        citation = _read('CITATION.cff')
        given, family = provenance.AUTHOR.rsplit(' ', 1)
        self.assertIn(f'family-names: "{family}"', citation)
        self.assertIn(f'given-names: "{given}"', citation)
        self.assertIn(f'repository-code: "{provenance.REPOSITORY}"', citation)
        self.assertIn(f'license: {provenance.LICENSE}', citation)

    def test_docker_image_labels_match(self):
        dockerfile = _read('Dockerfile')
        labels = dict(re.findall(r'org\.opencontainers\.image\.(\w+)="([^"]*)"', dockerfile))
        self.assertEqual(labels.get('authors'), provenance.AUTHOR)
        self.assertEqual(labels.get('source'), provenance.REPOSITORY)
        self.assertEqual(labels.get('licenses'), provenance.LICENSE)

    def test_every_source_file_carries_the_current_header(self):
        result = subprocess.run(
            [sys.executable, os.path.join(REPO, 'scripts', 'add_spdx_headers.py'), '--check'],
            capture_output=True, text=True, cwd=REPO)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class EngineInfoProvenanceTests(SimpleTestCase):
    """What a deployment shows the world, before anyone signs in."""

    def test_public_endpoint_reports_the_author(self):
        response = APIClient().get('/api/engine/')
        self.assertEqual(response.status_code, 200, response.content[:200])
        self.assertEqual(response.json()['provenance'], provenance.as_dict())
