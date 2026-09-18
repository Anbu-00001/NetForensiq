"""
Facts about the archive a sample arrived in, and whether it is safe to open.

Standard library only: the web process imports this module to decide whether to
extract anything at all, before the examination process is started.

Two different kinds of output, kept apart on purpose
====================================================
* **Safety** findings protect the examiner's workstation — an archive whose
  entries overlap, or which declares more data than we will write to disk.
  They stop extraction. They say nothing about whether the *sample* is
  malicious: a hostile archive and a malicious app are different claims.
* **Facts** are recorded and never scored. Encryption is the obvious one:
  ``infected`` is the sample-sharing convention MalwareBazaar documents, and
  encryption hides contents from every scanner whoever applied it. Treating it
  as evidence of anything would be the base-rate fallacy again.

Overlapping entries
===================
A non-recursive zip bomb works by pointing many central-directory entries at
overlapping stretches of one compressed stream, so a small file expands
quadratically (Fifield, "A better zip bomb", WOOT 2019). A well-formed archive
never needs two entries to share bytes, so any overlap is refused. Declared
sizes are checked too, but they are attacker-supplied, which is why extraction
also counts bytes as it writes (see capture/apk_views.py).
"""

import struct
import zipfile

LOCAL_HEADER = struct.Struct('<4sHHHHHIIIHH')
LOCAL_MAGIC = b'PK\x03\x04'
AES_EXTRA_ID = 0x9901

# The most any single examination will write to disk when unwrapping an archive.
# Sized well above the largest real APKs in the evaluation corpus (Termux,
# ~114 MB) and far below anything that threatens a workstation.
DEFAULT_MAX_EXTRACT_BYTES = 1024 * 1024 * 1024


def _encryption(info):
    if not info.flag_bits & 0x1:
        return 'none'
    extra, index = info.extra or b'', 0
    while index + 4 <= len(extra):
        header_id, size = struct.unpack_from('<HH', extra, index)
        if header_id == AES_EXTRA_ID:
            return 'aes'
        index += 4 + size
    return 'zipcrypto'


def _data_span(handle, info):
    """Byte range [start, end) an entry occupies, local header included."""
    handle.seek(info.header_offset)
    raw = handle.read(LOCAL_HEADER.size)
    if len(raw) < LOCAL_HEADER.size:
        return None
    fields = LOCAL_HEADER.unpack(raw)
    if fields[0] != LOCAL_MAGIC:
        return None
    name_len, extra_len = fields[9], fields[10]
    start = info.header_offset
    end = start + LOCAL_HEADER.size + name_len + extra_len + info.compress_size
    return start, end


def _unsafe_name(name):
    parts = name.replace('\\', '/').split('/')
    return (name.startswith(('/', '\\'))
            or (len(name) > 1 and name[1] == ':')
            or '..' in parts)


def inspect_archive(path, max_extract_bytes=DEFAULT_MAX_EXTRACT_BYTES):
    """
    Describe an archive without decompressing anything.

    Never raises for a malformed file; an archive that cannot be read is itself
    the answer, returned as ``readable: False`` with the reason.
    """
    result = {
        'readable': False, 'error': '',
        'entries': 0, 'compressed_bytes': 0, 'declared_bytes': 0,
        'encryption': [], 'apk_members': [], 'has_manifest': False,
        'safety': [], 'safe_to_extract': False,
    }
    try:
        archive = zipfile.ZipFile(path)
    except Exception as exc:
        result['error'] = f'Not a readable ZIP archive: {exc}'
        return result

    with archive, open(path, 'rb') as handle:
        infos = archive.infolist()
        result['readable'] = True
        result['entries'] = len(infos)
        result['compressed_bytes'] = sum(i.compress_size for i in infos)
        result['declared_bytes'] = sum(i.file_size for i in infos)
        result['has_manifest'] = any(i.filename == 'AndroidManifest.xml' for i in infos)
        result['apk_members'] = [i.filename for i in infos
                                 if i.filename.lower().endswith('.apk')][:50]
        result['encryption'] = sorted({_encryption(i) for i in infos} - {'none'})

        spans = []
        for info in infos:
            span = _data_span(handle, info)
            if span:
                spans.append((span[0], span[1], info.filename))
        spans.sort()
        overlaps = []
        # Compare against the furthest end seen so far, not just the previous
        # span: one long entry can overlap several that follow it.
        reach_end, reach_name = -1, ''
        for start, end, name in spans:
            if start < reach_end:
                overlaps.append([reach_name, name])
            if end > reach_end:
                reach_end, reach_name = end, name
        if overlaps:
            result['safety'].append({
                'id': 'archive.overlapping_entries',
                'title': 'Entries share compressed data',
                'detail': (f'{len(overlaps)} pair(s) of entries occupy overlapping bytes, '
                           f'e.g. {overlaps[0][0]!r} and {overlaps[0][1]!r}. This is the '
                           'construction of a non-recursive zip bomb; no well-formed '
                           'archive needs it.'),
            })

        biggest_apk = max((i.file_size for i in infos
                           if i.filename.lower().endswith('.apk')), default=0)
        if biggest_apk > max_extract_bytes:
            result['safety'].append({
                'id': 'archive.declared_size_exceeds_limit',
                'title': 'Declares more data than this workstation will extract',
                'detail': (f'An .apk member declares {biggest_apk:,} bytes; the limit '
                           f'is {max_extract_bytes:,}.'),
            })

        traversal = [i.filename for i in infos if _unsafe_name(i.filename)]
        if traversal:
            # Extraction here always writes to a fixed name, so these cannot
            # escape — but an archive built to do so is worth recording.
            result['safety'].append({
                'id': 'archive.path_traversal_names',
                'title': 'Entry names that climb out of the extraction directory',
                'detail': f'{len(traversal)} entr(ies), e.g. {traversal[0]!r}.',
            })

    blocking = {'archive.overlapping_entries', 'archive.declared_size_exceeds_limit'}
    result['safe_to_extract'] = not any(f['id'] in blocking for f in result['safety'])
    return result
