"""
Synthetic APKs and archives for the engine's tests.

Fixtures are generated rather than committed: no third-party app ends up in the
repository, and the tampered variants are produced by patching the bytes of a
well-formed archive, which is how the samples in the wild are made too.
"""

import io
import struct
import zipfile

from . import axml

LOCAL_MAGIC = b'PK\x03\x04'
CENTRAL_MAGIC = b'PK\x01\x02'


def apk(manifest_tree=None, files=None, package='com.example.app'):
    """A minimal, well-formed APK: a ZIP with a binary AndroidManifest.xml."""
    manifest = axml.build(manifest_tree or axml.manifest(package), package)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('AndroidManifest.xml', manifest)
        archive.writestr('resources.arsc', b'\x00' * 64)
        for name, payload in (files or {}).items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def zip_with(entries, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression) as archive:
        for name, payload in entries.items():
            archive.writestr(name, payload)
    return buffer.getvalue()


def _entry_offsets(data, name):
    """(local header offset, central directory offset) for ``name``."""
    encoded = name.encode()
    local = central = None
    position = 0
    while True:
        position = data.find(LOCAL_MAGIC, position)
        if position < 0:
            break
        if data[position + 30:position + 30 + len(encoded)] == encoded:
            local = position
            break
        position += 4
    position = 0
    while True:
        position = data.find(CENTRAL_MAGIC, position)
        if position < 0:
            break
        if data[position + 46:position + 46 + len(encoded)] == encoded:
            central = position
            break
        position += 4
    return local, central


def forge_compression_method(data, name='AndroidManifest.xml', local=25686, central=65350):
    """
    Write compression-method values no ZIP library implements.

    The technique Zimperium documented in 2023: Android treats an unknown
    method as deflate and installs the package, while analysis tools refuse the
    entry. The two headers are given different bogus values, as the judge's
    sample had (central 65350, local 25686).
    """
    patched = bytearray(data)
    local_offset, central_offset = _entry_offsets(data, name)
    struct.pack_into('<H', patched, local_offset + 8, local)
    struct.pack_into('<H', patched, central_offset + 10, central)
    return bytes(patched)


def set_encryption_flag(data, name='AndroidManifest.xml'):
    """Set general-purpose bit 0 without encrypting anything (Konfety)."""
    patched = bytearray(data)
    local_offset, central_offset = _entry_offsets(data, name)
    struct.pack_into('<H', patched, local_offset + 6,
                     struct.unpack_from('<H', patched, local_offset + 6)[0] | 0x1)
    struct.pack_into('<H', patched, central_offset + 8,
                     struct.unpack_from('<H', patched, central_offset + 8)[0] | 0x1)
    return bytes(patched)


def overlap_entries(data, first, second):
    """Point ``second``'s central entry at ``first``'s local header (zip bomb shape)."""
    patched = bytearray(data)
    first_local, _ = _entry_offsets(data, first)
    _, second_central = _entry_offsets(data, second)
    struct.pack_into('<I', patched, second_central + 42, first_local)
    return bytes(patched)


def write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_bytes(payload)
    return str(path)
