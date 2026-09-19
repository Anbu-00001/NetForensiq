# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""Archive facts and the safety decisions that gate extraction."""

import os
import tempfile
import unittest
import zipfile

from apk_engine.container import inspect_archive

from . import factories


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self._dir = tempfile.TemporaryDirectory()
        self.dir = self._dir.name
        self.addCleanup(self._dir.cleanup)

    def write(self, name, payload):
        path = os.path.join(self.dir, name)
        with open(path, 'wb') as handle:
            handle.write(payload)
        return path

    def test_unreadable_file_is_reported_not_raised(self):
        result = inspect_archive(self.write('junk.zip', b'not a zip at all'))
        self.assertFalse(result['readable'])
        self.assertIn('Not a readable ZIP archive', result['error'])
        self.assertFalse(result['safe_to_extract'])

    def test_apk_is_recognised_by_its_manifest(self):
        result = inspect_archive(self.write('app.apk', factories.apk()))
        self.assertTrue(result['readable'])
        self.assertTrue(result['has_manifest'])
        self.assertEqual(result['encryption'], [])
        self.assertTrue(result['safe_to_extract'])

    def test_zip_carrying_an_apk_lists_the_member(self):
        payload = factories.zip_with({'PENSION.apk': factories.apk()})
        result = inspect_archive(self.write('wrapped.zip', payload))
        self.assertFalse(result['has_manifest'])
        self.assertEqual(result['apk_members'], ['PENSION.apk'])

    def test_encryption_is_recorded_as_a_fact_and_does_not_block(self):
        payload = factories.set_encryption_flag(
            factories.zip_with({'AndroidManifest.xml': b'x' * 32}), 'AndroidManifest.xml')
        result = inspect_archive(self.write('enc.zip', payload))
        self.assertEqual(result['encryption'], ['zipcrypto'])
        self.assertTrue(result['safe_to_extract'])
        self.assertEqual(result['safety'], [])

    def test_overlapping_entries_block_extraction(self):
        payload = factories.overlap_entries(
            factories.zip_with({'a.apk': b'A' * 4096, 'b.txt': b'B' * 4096}), 'a.apk', 'b.txt')
        result = inspect_archive(self.write('bomb.zip', payload))
        self.assertFalse(result['safe_to_extract'])
        self.assertEqual([f['id'] for f in result['safety']], ['archive.overlapping_entries'])

    def test_declared_size_above_the_limit_blocks_extraction(self):
        payload = factories.zip_with({'big.apk': b'\x00' * 100_000})
        result = inspect_archive(self.write('big.zip', payload), max_extract_bytes=1024)
        self.assertFalse(result['safe_to_extract'])
        self.assertIn('archive.declared_size_exceeds_limit',
                      [f['id'] for f in result['safety']])

    def test_path_traversal_names_are_recorded(self):
        payload = factories.zip_with({'../../evil.apk': b'x', 'ok.txt': b'y'})
        result = inspect_archive(self.write('traversal.zip', payload))
        self.assertIn('archive.path_traversal_names', [f['id'] for f in result['safety']])
        # Recorded, but not a reason to refuse: extraction writes to a fixed name.
        self.assertTrue(result['safe_to_extract'])

    def test_counts_and_sizes_are_reported(self):
        payload = factories.zip_with({'one.txt': b'a' * 100, 'two.txt': b'b' * 200},
                                     compression=zipfile.ZIP_STORED)
        result = inspect_archive(self.write('two.zip', payload))
        self.assertEqual(result['entries'], 2)
        self.assertEqual(result['declared_bytes'], 300)
