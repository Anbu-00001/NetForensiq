# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
What the app's *native* code does — the half the engine could not read.

The gap this closes
===================
Every capability detector in this engine reads DEX bytecode. `codemap` indexes
it, `behaviours` asks questions of that index, and `frameworks` reports which
runtimes hold code that was never examined. So an app whose behaviour lives in
``lib/<abi>/*.so`` was described by an honest sentence — "behaviour implemented
there has not been examined" — and nothing else.

That is where modern Android malware puts the parts it does not want read.
Ruggia et al., *The Dark Side of Native Code on Android* (ACM TOPS 2025),
measured the difference across ten years of malware against current Play Store
apps, and the discrepancies are large enough to be worth reading directly:

* **Where the ELF files are.** "Most of the goodware (78%) contain ELF files
  only in the standard lib folder... On the other hand, about 85% of the
  malware contains ELF files in a non-standard location" (§, p.20-21).
* **Disguised ELF files.** "More than 5% of ELF files in the malware samples
  were extracted from an archive or have an extension that did not match the
  file type. The most common wrong extension names we found are: png, jar,
  sdk, and lib."
* **Deliberately broken headers.** Some malware had a "broken header section,
  while none of the goodware had this peculiarity" — part of the ELF header is
  removed and restored at runtime, purely to defeat static analysis.
* **Imported functions.** ``libz`` is "used by 90% of malware and 6% of
  goodware"; ``chmod`` by 59% and ``mprotect`` by 87% of recent malware.
* **Files opened.** "in 2021, 54% of malware and 2% of goodware opened the
  /proc/version".

None of those numbers is used as a threshold here. They are the reason to
*look*; what a signal is worth on this engine's own corpora is measured by
`evaluate`, on 201 benign F-Droid apps, exactly as every other signal is. A
published rate measured on someone else's corpus is a reason to test something,
not a licence to assert it.

How this reads an ELF file
==========================
With `struct`, from bytes, in this process, and never by executing anything.
The file being parsed is hostile by assumption: it comes out of a sample under
examination. So every read is bounded (MAX_ELF_ENTRIES files, MAX_ELF_BYTES
each), every offset is checked against the data actually read, and every
failure is caught and *recorded* rather than raised — a header that cannot be
parsed is itself one of the findings above, not an error.

No new dependency. pyelftools would do this well, but the engine process
deliberately carries the smallest set of libraries that can do the job (see
`apk_engine/__init__.py`), and what is needed here is three tables: the section
headers, the dynamic symbol table, and the dynamic section.
"""

import struct
import zipfile

ELF_MAGIC = b'\x7fELF'

# Bounds. A package cannot make this read more than MAX_TOTAL_ELF_BYTES,
# whatever it contains, and no single file more than MAX_ELF_BYTES.
#
# The per-file limit has to be generous, and the reason is a defect this very
# check found: a section header table lives at the *end* of an ELF file, so a
# library larger than the limit came back with its section headers "beyond the
# end of the file" — reported as a deliberately broken header, which is the one
# indicator Ruggia et al. found in malware and in none of their goodware. A
# 4 MB limit did that to OpenSSL's libcrypto. Reading less of a file is a fact
# about this engine; it must never be reported as a fact about the file, so
# `partial` and `broken` are now separate things.
MAX_ELF_ENTRIES = 64
MAX_ELF_BYTES = 16 * 1024 * 1024
MAX_TOTAL_ELF_BYTES = 64 * 1024 * 1024
MAX_SECTIONS = 512
MAX_SYMBOLS = 20000
MAX_DYNAMIC_ENTRIES = 512

# Section types, from the ELF specification (Tool Interface Standard, ELF 1.2,
# figure 1-10) — the same values Android's linker reads.
SHT_DYNSYM = 11
SHT_DYNAMIC = 6
SHT_STRTAB = 3
DT_NEEDED = 1
DT_NULL = 0
SHN_UNDEF = 0

# Machine values (e_machine), for reporting which ABI a library was built for.
MACHINES = {
    0x03: 'x86', 0x28: 'arm', 0x3E: 'x86_64', 0xB7: 'arm64',
    0x08: 'mips', 0xF3: 'riscv',
}

# Imported functions worth counting. Each is a question, not a verdict: the
# benign rate of every one of them is measured before any of them is allowed to
# raise a tier.
#
# Grouped by what an examiner would ask. The groups are deliberately coarse —
# `execve` and `system` answer the same question, and separating them would
# only produce two signals that fire together and look like corroboration.
WATCHED_IMPORTS = {
    'process_execution': ('system', 'execv', 'execve', 'execl', 'execlp',
                          'execvp', 'popen', 'fork', 'vfork', 'posix_spawn'),
    'dynamic_loading': ('dlopen', 'dlsym', 'android_dlopen_ext'),
    'anti_debugging': ('ptrace',),
    'memory_permissions': ('mprotect',),
    'file_permissions': ('chmod', 'fchmod', 'chown'),
    'process_inspection': ('kill', 'getppid', 'prctl'),
}

# Strings worth counting, for the same reason. Matched as bytes against the
# file, case-sensitively: these are paths and process names, and Android's
# filesystem is case-sensitive.
WATCHED_STRINGS = {
    'proc_self_maps': (b'/proc/self/maps',),
    'proc_version': (b'/proc/version',),
    'su_binary': (b'/system/bin/su', b'/system/xbin/su'),
    'root_manager': (b'magisk', b'Magisk', b'supersu', b'SuperSU'),
    'instrumentation_tooling': (b'frida', b'xposed', b'Xposed', b'substrate'),
    'emulator_check': (b'ro.kernel.qemu', b'goldfish', b'ranchu'),
    'jni_dynamic_binding': (b'RegisterNatives',),
}

# Native libraries shipped by commercial Android packers.
#
# A packer is not malware — it is a product sold to developers, and legitimate
# apps use them, which is why this only ever *names the packer* and lets the
# measured benign rate decide what it is worth. The names are the ones the
# packing literature uses as signatures; DroidUnpack (Duan et al., NDSS 2018)
# studies this set of commercial packers directly.
PACKER_LIBRARIES = {
    'libjiagu': 'Qihoo 360 Jiagu',
    'libjiagu_art': 'Qihoo 360 Jiagu',
    'libjiagu_a64': 'Qihoo 360 Jiagu',
    'libsecexe': 'Bangcle',
    'libsecmain': 'Bangcle',
    'libsecshell': 'Bangcle',
    'libdexhelper': 'DexProtector',
    'libexec': 'Ijiami',
    'libexecmain': 'Ijiami',
    'libapktoolplus_jiagu': 'APKProtect',
    'libapkprotect': 'APKProtect',
    'libshell': 'Tencent Legu',
    'libshella': 'Tencent Legu',
    'libtup': 'Tencent Legu',
    'libtosprotection': 'Tencent',
    'libbaiduprotect': 'Baidu',
    'libnesec': 'NetEase',
    'libmobisec': 'Alibaba',
    'libddog': 'Naga',
    'libfakejni': 'Naga',
    'libnqshield': 'NetQin',
}

def _u(data, fmt, offset):
    """Unpack, or None if the file is too short for what it claims."""
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        return None
    return struct.unpack_from(fmt, data, offset)


class Elf:
    """
    One ELF file, parsed as far as it can be.

    `broken` says the header or section table could not be read. That is a
    result, not a failure: removing part of the header to defeat static
    analysis is a technique Ruggia et al. observed in malware and in none of
    their goodware.
    """

    def __init__(self, data, partial=False):
        self.data = data
        # `partial` says we hold only the first MAX_ELF_BYTES of a larger file.
        # Everything that then lies beyond what we hold is unread, not broken.
        self.partial = partial
        self.broken = False
        self.reason = ''
        self.machine = ''
        self.bits = 0
        self.imports = set()
        self.exports = set()
        self.needed = set()
        self._parse()

    def _parse(self):
        data = self.data
        if len(data) < 64 or not data.startswith(ELF_MAGIC):
            self._break('not an ELF file, or truncated before the header ends')
            return

        ei_class, ei_data = data[4], data[5]
        if ei_class not in (1, 2) or ei_data not in (1, 2):
            self._break('ELF identification claims an impossible class or byte order')
            return
        self.bits = 32 if ei_class == 1 else 64
        endian = '<' if ei_data == 1 else '>'

        machine = _u(data, endian + 'H', 18)
        self.machine = MACHINES.get(machine[0], f'machine {machine[0]}') if machine else ''

        if self.bits == 64:
            header = _u(data, endian + 'QQQIHHHHHH', 24)   # entry, phoff, shoff, flags, ...
            if header is None:
                self._break('64-bit header is truncated')
                return
            _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx = header
        else:
            header = _u(data, endian + 'IIIIHHHHHH', 24)
            if header is None:
                self._break('32-bit header is truncated')
                return
            _entry, _phoff, shoff, _flags, _ehsize, _phentsize, _phnum, shentsize, shnum, shstrndx = header

        if shoff == 0 or shnum == 0:
            # Stripped of its section table. Common in release builds, so this
            # is not by itself suspicious — it only means the symbol tables
            # cannot be read from what we hold.
            self.reason = 'no section header table'
            return
        if shnum > MAX_SECTIONS:
            shnum = MAX_SECTIONS

        sections = []
        for index in range(shnum):
            base = shoff + index * shentsize
            if self.bits == 64:
                entry = _u(data, endian + 'IIQQQQIIQQ', base)
            else:
                entry = _u(data, endian + 'IIIIIIIIII', base)
            if entry is None:
                self._break(f'section header {index} lies beyond the end of the file')
                return
            name, kind, _flags, _addr, offset, size, link, _info, _align, entsize = entry
            sections.append({'name': name, 'type': kind, 'offset': offset,
                             'size': size, 'link': link, 'entsize': entsize})

        self._read_symbols(sections, endian)
        self._read_dynamic(sections, endian, shstrndx)

    def _break(self, reason):
        if self.partial:
            # We did not read the whole file, so we cannot say the file is
            # wrong — only that we cannot see this part of it.
            self.reason = f'not examined: {reason}, and only the first ' \
                          f'{len(self.data):,} bytes were read'
            return
        self.broken = True
        self.reason = reason

    def _string_at(self, table, offset):
        start = table['offset'] + offset
        if start < 0 or start >= len(self.data):
            return ''
        end = self.data.find(b'\0', start, min(start + 256, len(self.data)))
        if end < 0:
            return ''
        return self.data[start:end].decode('utf-8', 'replace')

    def _read_symbols(self, sections, endian):
        for section in sections:
            if section['type'] != SHT_DYNSYM:
                continue
            if section['link'] >= len(sections):
                continue
            strtab = sections[section['link']]
            entry_size = 24 if self.bits == 64 else 16
            if section['entsize']:
                entry_size = section['entsize']
            count = min(section['size'] // max(entry_size, 1), MAX_SYMBOLS)
            for index in range(count):
                base = section['offset'] + index * entry_size
                if self.bits == 64:
                    # st_name, st_info, st_other, st_shndx, st_value, st_size
                    fields = _u(self.data, endian + 'IBBHQQ', base)
                    if fields is None:
                        break
                    name_offset, _info, _other, shndx = fields[0], fields[1], fields[2], fields[3]
                else:
                    fields = _u(self.data, endian + 'IIIBBH', base)
                    if fields is None:
                        break
                    name_offset, shndx = fields[0], fields[5]
                name = self._string_at(strtab, name_offset)
                if not name:
                    continue
                if shndx == SHN_UNDEF:
                    self.imports.add(name)
                else:
                    self.exports.add(name)

    def _read_dynamic(self, sections, endian, shstrndx):
        """DT_NEEDED — the libraries this one asks the linker for."""
        strtab = None
        for section in sections:
            if section['type'] == SHT_STRTAB and section['link'] == 0:
                # .dynstr is referenced by the dynamic section's sh_link, but a
                # stripped file may not have it; fall back to the first string
                # table that is not the section-name table.
                if shstrndx < len(sections) and sections[shstrndx] is section:
                    continue
                strtab = strtab or section

        for section in sections:
            if section['type'] != SHT_DYNAMIC:
                continue
            if section['link'] < len(sections):
                strtab = sections[section['link']]
            if strtab is None:
                return
            entry_size = 16 if self.bits == 64 else 8
            count = min(section['size'] // entry_size, MAX_DYNAMIC_ENTRIES)
            for index in range(count):
                base = section['offset'] + index * entry_size
                fields = _u(self.data, endian + ('QQ' if self.bits == 64 else 'II'), base)
                if fields is None:
                    return
                tag, value = fields
                if tag == DT_NULL:
                    break
                if tag == DT_NEEDED:
                    name = self._string_at(strtab, value)
                    if name:
                        self.needed.add(name)


def _watched_imports(symbols):
    found = {}
    for group, names in WATCHED_IMPORTS.items():
        hit = sorted(symbol for symbol in symbols if symbol in names)
        if hit:
            found[group] = hit
    return found


def _watched_strings(data):
    found = {}
    for group, needles in WATCHED_STRINGS.items():
        hit = sorted({needle.decode() for needle in needles if needle in data})
        if hit:
            found[group] = hit
    return found


def survey(apk_path):
    """
    Everything this module can say about a package's native code.

    Returns plain data — no verdicts, no tiers. `behaviours` decides what any
    of it means, and only for signals whose benign rate has been measured.
    """
    result = {
        'elf_count': 0,
        'elf_in_lib': 0,
        'elf_outside_lib': [],
        'elf_wrong_extension': [],
        'broken_headers': [],
        'machines': set(),
        'packers': {},
        'imports': {},
        'strings': {},
        'needed': set(),
        'exports_jni_onload': False,
        'truncated': False,
        # Files we hold only the first MAX_ELF_BYTES of. Recorded separately
        # from `broken_headers`, and never counted as one: see `_break`.
        'partial_reads': [],
    }

    try:
        archive = zipfile.ZipFile(apk_path)
        entries = archive.infolist()
    except Exception:                                         # noqa: BLE001
        return _finalise(result)

    examined = 0
    budget = MAX_TOTAL_ELF_BYTES
    for info in entries:
        if examined >= MAX_ELF_ENTRIES or budget <= 0:
            result['truncated'] = True
            break
        if info.is_dir() or info.file_size < 64:
            continue
        name = info.filename
        allowance = min(MAX_ELF_BYTES, budget)
        try:
            with archive.open(info) as handle:
                head = handle.read(4)
                if head != ELF_MAGIC:
                    continue
                # Only now is the rest read: the magic is four bytes, and a
                # package of ten thousand PNGs must not cost ten thousand
                # megabyte reads.
                data = head + handle.read(allowance - 4)
        except Exception:                                     # noqa: BLE001
            continue

        budget -= len(data)
        partial = len(data) < info.file_size

        examined += 1
        result['elf_count'] += 1
        in_lib = name.startswith('lib/')
        if in_lib:
            result['elf_in_lib'] += 1
        else:
            result['elf_outside_lib'].append(name)
        if not name.endswith('.so'):
            result['elf_wrong_extension'].append(name)

        basename = name.rsplit('/', 1)[-1].lower()
        stem = basename[:-3] if basename.endswith('.so') else basename
        if stem in PACKER_LIBRARIES:
            result['packers'][PACKER_LIBRARIES[stem]] = basename

        elf = Elf(data, partial=partial)
        if partial:
            result['partial_reads'].append(name)
        if elf.broken:
            result['broken_headers'].append(f'{name}: {elf.reason}')
            continue
        if elf.machine:
            result['machines'].add(elf.machine)
        result['needed'].update(elf.needed)
        if 'JNI_OnLoad' in elf.exports:
            result['exports_jni_onload'] = True

        for group, names in _watched_imports(elf.imports).items():
            result['imports'].setdefault(group, set()).update(names)
        for group, names in _watched_strings(data).items():
            result['strings'].setdefault(group, set()).update(names)

    return _finalise(result)


def _finalise(result):
    result['machines'] = sorted(result['machines'])
    result['needed'] = sorted(result['needed'])
    result['imports'] = {k: sorted(v) for k, v in sorted(result['imports'].items())}
    result['strings'] = {k: sorted(v) for k, v in sorted(result['strings'].items())}
    result['elf_outside_lib'] = sorted(result['elf_outside_lib'])[:20]
    result['elf_wrong_extension'] = sorted(result['elf_wrong_extension'])[:20]
    result['broken_headers'] = sorted(result['broken_headers'])[:20]
    result['partial_reads'] = sorted(result['partial_reads'])[:20]
    return result
