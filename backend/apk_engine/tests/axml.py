"""
Build a binary AndroidManifest.xml, for tests only.

The engine's tests need real APKs — a ZIP whose AndroidManifest.xml androguard
parses — without committing anyone's app into the repository or downloading one.
So the fixtures are generated: this module writes Android's binary XML (the
format AOSP's ResourceTypes.h defines) from a small tree of tags.

It writes only what a manifest needs: a UTF-8 string pool, one namespace, and
start/end tags with string-typed attributes. Tampered variants for the integrity
tests are made by editing the bytes afterwards (see factories.py).
"""

import struct

ANDROID_URI = 'http://schemas.android.com/apk/res/android'

RES_XML_TYPE = 0x0003
RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103

UTF8_FLAG = 0x0100
TYPE_STRING = 0x03


class Tag:
    def __init__(self, name, attributes=None, children=()):
        self.name = name
        self.attributes = attributes or {}      # {(uri|None, name): value}
        self.children = list(children)


class _Pool:
    def __init__(self):
        self.strings = []
        self.index = {}

    def add(self, value):
        if value not in self.index:
            self.index[value] = len(self.strings)
            self.strings.append(value)
        return self.index[value]

    def chunk(self):
        offsets, data = [], bytearray()
        for value in self.strings:
            offsets.append(len(data))
            encoded = value.encode('utf-8')
            # UTF-8 pools carry the character count then the byte count, each a
            # single byte below 0x80 (test strings stay short).
            data += bytes([len(value) & 0x7F, len(encoded) & 0x7F]) + encoded + b'\x00'
        while len(data) % 4:
            data += b'\x00'
        header_size = 28
        strings_start = header_size + 4 * len(offsets)
        size = strings_start + len(data)
        header = struct.pack('<HHIIIIII', RES_STRING_POOL_TYPE, header_size, size,
                             len(self.strings), 0, UTF8_FLAG, strings_start, 0)
        return header + b''.join(struct.pack('<I', o) for o in offsets) + bytes(data)


def build(root, package='com.example.app'):
    """Return the bytes of a binary AndroidManifest.xml for ``root`` (a Tag)."""
    pool = _Pool()
    uri_index = pool.add(ANDROID_URI)
    prefix_index = pool.add('android')

    def intern(tag):
        pool.add(tag.name)
        for (uri, name), value in tag.attributes.items():
            if uri:
                pool.add(uri)
            pool.add(name)
            pool.add(str(value))
        for child in tag.children:
            intern(child)

    intern(root)

    body = bytearray()
    body += struct.pack('<HHIiiii', RES_XML_START_NAMESPACE_TYPE, 16, 24, 1, -1,
                        prefix_index, uri_index)

    def emit(tag):
        attributes = bytearray()
        for (uri, name), value in tag.attributes.items():
            value_index = pool.index[str(value)]
            attributes += struct.pack(
                '<iiiHBBI',
                pool.index[uri] if uri else -1,
                pool.index[name],
                value_index,
                8,                      # typed value size
                0,                      # res0
                TYPE_STRING,
                value_index)
        size = 36 + len(attributes)
        body_start = struct.pack('<HHIiiiiHHHHHH', RES_XML_START_ELEMENT_TYPE, 16, size,
                                 1, -1, -1, pool.index[tag.name],
                                 20, 20, len(tag.attributes), 0, 0, 0)
        chunk = body_start + bytes(attributes)
        for child in tag.children:
            chunk += emit(child)
        chunk += struct.pack('<HHIiiii', RES_XML_END_ELEMENT_TYPE, 16, 24, 1, -1,
                             -1, pool.index[tag.name])
        return chunk

    body += emit(root)
    body += struct.pack('<HHIiiii', RES_XML_END_NAMESPACE_TYPE, 16, 24, 1, -1,
                        prefix_index, uri_index)

    pool_chunk = pool.chunk()
    total = 8 + len(pool_chunk) + len(body)
    return struct.pack('<HHI', RES_XML_TYPE, 8, total) + pool_chunk + bytes(body)


def manifest(package='com.example.app', permissions=(), application=None):
    """A minimal but well-formed manifest tree."""
    children = [Tag('uses-permission', {(ANDROID_URI, 'name'): p}) for p in permissions]
    children.append(application or Tag('application', {(ANDROID_URI, 'label'): 'Example'}))
    return Tag('manifest', {(None, 'package'): package,
                            (ANDROID_URI, 'versionName'): '1.0',
                            (ANDROID_URI, 'versionCode'): '1'}, children)
