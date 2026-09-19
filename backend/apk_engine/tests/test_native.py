# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
The ELF reader, held against the system's own — and against hostile input.

Why an oracle is used here too
==============================
`native.py` parses a binary format by hand, from bytes, out of files supplied
by the sample under examination. Two things can go wrong, and only one of them
is loud:

* it can fail to read a real library, which shows up as every native signal
  reading zero and a capability that quietly never fires;
* it can report a *fault in the file* that is really a limit in the reader.

The second is the dangerous one, because "the ELF header is deliberately
broken" is a finding — Ruggia et al. saw it in malware and in none of their
goodware — and a reader that manufactures it would put an innocent app in that
category. It happened while this was being written: a 4 MB read limit made
OpenSSL's libcrypto look deliberately damaged, because a section header table
lives at the end of the file. `test_a_large_library_is_not_called_broken`
covers exactly that.

`readelf` is the oracle, as scapy is for the packet readers. Where it is not
installed the comparison is skipped and the hand-built cases still run.
"""

import os
import shutil
import struct
import subprocess
import tempfile
import unittest
import zipfile

from apk_engine import native


def _readelf(path, *args):
    return subprocess.run(['readelf', *args, '-W', path],
                          capture_output=True, text=True).stdout


def _needed(path):
    return sorted({line.split('[')[1].split(']')[0]
                   for line in _readelf(path, '-d').splitlines()
                   if 'NEEDED' in line and '[' in line})


def _symbols(path, undefined):
    names = set()
    for line in _readelf(path, '--dyn-syms').splitlines()[3:]:
        parts = line.split()
        if len(parts) >= 8 and ((parts[6] == 'UND') == undefined):
            name = parts[7].split('@')[0]
            if name:
                names.add(name)
    return names


def _system_libraries(limit=8):
    """Real ELF files on this machine, whatever machine it is."""
    found = []
    for directory in ('/usr/lib/x86_64-linux-gnu', '/usr/lib', '/lib',
                      '/usr/lib/aarch64-linux-gnu', '/usr/bin'):
        if not os.path.isdir(directory):
            continue
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            path = os.path.join(directory, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            try:
                with open(path, 'rb') as handle:
                    if handle.read(4) != native.ELF_MAGIC:
                        continue
            except OSError:
                continue
            found.append(path)
            if len(found) >= limit:
                return found
    return found


def _tiny_elf():
    """A 64-bit little-endian ELF header with no section table."""
    header = bytearray(64)
    header[0:4] = native.ELF_MAGIC
    header[4] = 2                      # 64-bit
    header[5] = 1                      # little-endian
    header[6] = 1                      # version
    struct.pack_into('<H', header, 16, 3)     # e_type = ET_DYN
    struct.pack_into('<H', header, 18, 0xB7)  # e_machine = arm64
    return bytes(header)


class ElfAgainstReadelfTests(unittest.TestCase):
    """Every symbol we report must be a symbol readelf reports, and vice versa."""

    @unittest.skipUnless(shutil.which('readelf'), 'readelf is not installed')
    def test_imports_exports_and_needed_match_readelf(self):
        libraries = _system_libraries()
        self.assertGreaterEqual(len(libraries), 3,
                                'no ELF files found to compare against')
        for path in libraries:
            with self.subTest(library=os.path.basename(path)):
                with open(path, 'rb') as handle:
                    whole = handle.read()
                data = whole[:native.MAX_ELF_BYTES]
                elf = native.Elf(data, partial=len(data) < len(whole))

                self.assertFalse(elf.broken, f'{path}: {elf.reason}')
                self.assertEqual(sorted(elf.needed), _needed(path))
                self.assertEqual(elf.imports, _symbols(path, undefined=True))
                self.assertEqual(elf.exports, _symbols(path, undefined=False))


class HostileInputTests(unittest.TestCase):
    """Nothing a file can contain may raise, and nothing may be invented."""

    def test_a_large_library_is_not_called_broken(self):
        """
        A reader that holds only part of a file knows less about it — it does
        not know something bad about it. This is the defect that motivated
        `partial`: the section header table sits at the end, so a library
        bigger than the read limit looked deliberately damaged.
        """
        body = _tiny_elf() + b'\0' * 4096
        # Claim a section table far beyond what was read.
        header = bytearray(body)
        struct.pack_into('<Q', header, 40, 10_000_000)   # e_shoff
        struct.pack_into('<H', header, 58, 64)           # e_shentsize
        struct.pack_into('<H', header, 60, 8)            # e_shnum

        truncated = native.Elf(bytes(header), partial=True)
        self.assertFalse(truncated.broken,
                         'a partial read must never be reported as a broken file')
        self.assertIn('not examined', truncated.reason)

        whole = native.Elf(bytes(header), partial=False)
        self.assertTrue(whole.broken,
                        'a complete file whose section table is out of bounds IS broken')

    def test_a_truncated_header_is_reported_not_raised(self):
        for data in (b'', native.ELF_MAGIC, native.ELF_MAGIC + b'\x02\x01' + b'\0' * 20):
            with self.subTest(length=len(data)):
                elf = native.Elf(data)
                self.assertTrue(elf.broken)
                self.assertTrue(elf.reason)

    def test_an_impossible_class_or_byte_order_is_refused(self):
        data = bytearray(_tiny_elf())
        data[4] = 9
        elf = native.Elf(bytes(data))
        self.assertTrue(elf.broken)
        self.assertIn('impossible', elf.reason)

    def test_a_stripped_library_is_not_broken(self):
        """No section table is ordinary in a release build, not a defect."""
        elf = native.Elf(_tiny_elf())
        self.assertFalse(elf.broken)
        self.assertEqual(elf.reason, 'no section header table')
        self.assertEqual(elf.machine, 'arm64')

    def test_absurd_section_counts_do_not_run_away(self):
        data = bytearray(_tiny_elf() + b'\0' * 8192)
        struct.pack_into('<Q', data, 40, 64)             # e_shoff
        struct.pack_into('<H', data, 58, 64)             # e_shentsize
        struct.pack_into('<H', data, 60, 0xFFFF)         # e_shnum — absurd
        elf = native.Elf(bytes(data))
        # Either it is refused as out of bounds or it is read within the cap;
        # what it must not do is take unbounded time or raise.
        self.assertIsInstance(elf.imports, set)


class SurveyTests(unittest.TestCase):
    """What the engine is handed, from a package rather than a file."""

    def _apk(self, entries):
        directory = tempfile.mkdtemp(prefix='netforensiq-native-')
        path = os.path.join(directory, 'sample.apk')
        with zipfile.ZipFile(path, 'w') as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
        return path

    def test_an_elf_outside_lib_is_recorded(self):
        path = self._apk({
            'lib/arm64-v8a/libnormal.so': _tiny_elf(),
            'assets/payload.dat': _tiny_elf(),
            'classes.dex': b'dex\n035\0' + b'\0' * 200,
        })
        found = native.survey(path)
        self.assertEqual(found['elf_count'], 2)
        self.assertEqual(found['elf_in_lib'], 1)
        self.assertEqual(found['elf_outside_lib'], ['assets/payload.dat'])
        self.assertEqual(found['elf_wrong_extension'], ['assets/payload.dat'])

    def test_a_packer_library_names_the_packer(self):
        path = self._apk({'lib/armeabi-v7a/libjiagu.so': _tiny_elf()})
        self.assertEqual(native.survey(path)['packers'],
                         {'Qihoo 360 Jiagu': 'libjiagu.so'})

    def test_a_file_that_is_not_an_elf_is_not_read(self):
        path = self._apk({'res/drawable/icon.png': b'\x89PNG\r\n\x1a\n' + b'\0' * 500})
        found = native.survey(path)
        self.assertEqual(found['elf_count'], 0)
        self.assertEqual(found['broken_headers'], [])

    def test_strings_are_found_in_the_body_of_a_library(self):
        body = _tiny_elf() + b'\0' * 64 + b'/proc/self/maps\0frida-server\0'
        path = self._apk({'lib/arm64-v8a/libcheck.so': body})
        found = native.survey(path)
        self.assertEqual(found['strings']['proc_self_maps'], ['/proc/self/maps'])
        self.assertEqual(found['strings']['instrumentation_tooling'], ['frida'])

    def test_a_package_that_is_not_a_zip_returns_nothing_rather_than_raising(self):
        directory = tempfile.mkdtemp(prefix='netforensiq-native-')
        path = os.path.join(directory, 'broken.apk')
        with open(path, 'wb') as handle:
            handle.write(b'not a zip at all')
        self.assertEqual(native.survey(path)['elf_count'], 0)

    def test_the_read_is_bounded_however_many_libraries_there_are(self):
        entries = {f'lib/arm64-v8a/lib{index}.so': _tiny_elf()
                   for index in range(native.MAX_ELF_ENTRIES + 20)}
        found = native.survey(self._apk(entries))
        self.assertEqual(found['elf_count'], native.MAX_ELF_ENTRIES)
        self.assertTrue(found['truncated'],
                        'stopping early must be disclosed, not silent')
