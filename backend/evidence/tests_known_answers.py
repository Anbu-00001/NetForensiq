# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Known-answer tests: the platform's hashing and sealing held to published values
that do not come from this code or from the library it calls.

The digests below are the published results for the empty input, for "abc", and
for one million repetitions of "a" (FIPS 180 for SHA-1 and SHA-256, RFC 1321 for
MD5; they are the standard vectors reproduced in every implementation's test
suite). A hash function that returns the right answer for an input its author
chose proves little. These are fixed by the standards, and the "million a" input
is longer than the 1 MiB streaming chunk, so the chunk boundary is exercised too.

The test for what a hash is *used for* — a flipped bit is detected, a sealed file
that changes is reported — lives in tests.py; this file is only about whether the
numbers are the right numbers.
"""
import tempfile
from pathlib import Path

from django.test import SimpleTestCase

from .models import hash_file

VECTORS = {
    b'': {
        'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
        'md5': 'd41d8cd98f00b204e9800998ecf8427e',
    },
    b'abc': {
        'sha256': 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        'sha1': 'a9993e364706816aba3e25717850c26c9cd0d89d',
        'md5': '900150983cd24fb0d6963f7d28e17f72',
    },
    b'a' * 1_000_000: {
        'sha256': 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0',
        'sha1': '34aa973cd4c4daa4f61eeb2bdbad27316534016f',
        'md5': '7707d6ae4e027c70eea2a935c2296f21',
    },
}


class KnownAnswerTests(SimpleTestCase):
    def _file(self, data):
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(data)
        handle.close()
        self.addCleanup(Path(handle.name).unlink)
        return handle.name

    def test_hash_file_returns_the_published_digests(self):
        for data, expected in VECTORS.items():
            digests, size = hash_file(self._file(data))
            self.assertEqual(size, len(data))
            for algorithm, digest in expected.items():
                self.assertEqual(digests[algorithm], digest,
                                 f'{algorithm} of {len(data)} bytes')

    def test_the_chunk_size_cannot_change_the_answer(self):
        data = b'a' * 1_000_000
        path = self._file(data)
        for chunk in (1, 7, 4096, 1024 * 1024, 2_000_000):
            digests, _ = hash_file(path, chunk_size=chunk)
            self.assertEqual(digests['sha256'], VECTORS[data]['sha256'], f'chunk {chunk}')

    def test_a_single_flipped_bit_changes_every_digest(self):
        data = bytearray(b'a' * 1_000_000)
        data[500_000] ^= 0x01
        digests, _ = hash_file(self._file(bytes(data)))
        for algorithm, digest in VECTORS[b'a' * 1_000_000].items():
            self.assertNotEqual(digests[algorithm], digest, algorithm)
