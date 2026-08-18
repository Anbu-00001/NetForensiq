"""
JA4 TLS client fingerprinting.

Why JA4 and not JA3
-------------------
The model carried a `ja3_hash` column that nothing ever wrote. Filling it in
would have been worse than leaving it empty: JA3 has been retired. Salesforce
stopped maintaining it and its own README now points at FoxIO
(https://github.com/salesforce/ja3), and since Chrome 110 shipped ClientHello
extension-order randomisation in 2023 a real browser produces a *different*
JA3 on every connection — the hash stops identifying the client at all.

JA4 sorts the cipher and extension lists before hashing, which is precisely the
property that survives randomisation, so it is the fingerprint that still means
something on 2026 traffic.

Specification
-------------
FoxIO-LLC/ja4, `technical_details/JA4.md`, implemented field by field:

    (q|d|t)(2-char version)(d|i)(2-char cipher count)(2-char ext count)
    (first+last char of first ALPN)_(sha256 of sorted ciphers)[:12]
    _(sha256 of sorted extensions _ signature algorithms)[:12]

GREASE values (RFC 8701) are ignored wherever they appear.

Scope, stated honestly
----------------------
Only TLS over TCP is fingerprinted, so the first character is always ``t``.
QUIC and DTLS ClientHellos are not parsed — we do not reassemble QUIC initial
packets, and claiming a ``q`` fingerprint we cannot compute would be a lie.
A ClientHello split across TCP segments is skipped rather than guessed at;
`parse_client_hello` returns None and the flow simply carries no fingerprint.
"""

import hashlib

# RFC 8701 reserves 16 values in each of several registries as GREASE:
# 0x0a0a, 0x1a1a, 0x2a2a … 0xfafa. Both bytes are equal and of the form 0xNa.
GREASE = frozenset(
    (nibble << 12) | (0x0A << 8) | (nibble << 4) | 0x0A
    for nibble in range(0x0, 0x10)
)

# JA4's two-character rendering of the negotiated version.
VERSION_LABEL = {
    0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10',
    0x0300: 's3', 0x0002: 's2',
    0xFEFF: 'd1', 0xFEFD: 'd2', 0xFEFC: 'd3',
}

EXT_SERVER_NAME = 0x0000
EXT_ALPN = 0x0010
EXT_SIG_ALGS = 0x000D
EXT_SUPPORTED_VERSIONS = 0x002B

_TLS_HANDSHAKE_RECORD = 0x16
_CLIENT_HELLO = 0x01


def _is_grease(value):
    return value in GREASE


def _u16(data, pos):
    return int.from_bytes(data[pos:pos + 2], 'big')


def parse_client_hello(data):
    """
    Decode a TLS ClientHello into the fields JA4 needs.

    Returns a dict, or None if `data` is not a ClientHello we can read in
    full. Every length is checked against the buffer before it is used: a
    truncated or malformed handshake yields None rather than a fingerprint
    computed over whatever happened to follow in memory.
    """
    try:
        if len(data) < 45 or data[0] != _TLS_HANDSHAKE_RECORD:
            return None

        record_len = _u16(data, 3)
        # The record header claims a length; if the segment is shorter, the
        # handshake continues in a packet we are not looking at.
        if len(data) < 5 + record_len:
            return None
        body = data[5:5 + record_len]

        if not body or body[0] != _CLIENT_HELLO:
            return None

        legacy_version = _u16(body, 4)

        pos = 6 + 32                      # msg header (4) + version (2) + random (32)
        if pos >= len(body):
            return None

        session_id_len = body[pos]
        pos += 1 + session_id_len

        cipher_bytes_len = _u16(body, pos)
        pos += 2
        if pos + cipher_bytes_len > len(body):
            return None
        ciphers = [
            _u16(body, pos + i) for i in range(0, cipher_bytes_len, 2)
        ]
        pos += cipher_bytes_len

        compression_len = body[pos]
        pos += 1 + compression_len

        extensions = []
        sig_algs = []
        alpn_values = []
        supported_versions = []
        has_sni = False

        # Extensions are optional in the wire format even though every real
        # client sends some.
        if pos + 2 <= len(body):
            ext_total = _u16(body, pos)
            pos += 2
            end = min(pos + ext_total, len(body))

            while pos + 4 <= end:
                ext_type = _u16(body, pos)
                ext_len = _u16(body, pos + 2)
                pos += 4
                payload = body[pos:pos + ext_len]
                if len(payload) < ext_len:
                    return None
                pos += ext_len

                extensions.append(ext_type)

                if ext_type == EXT_SERVER_NAME:
                    has_sni = True
                elif ext_type == EXT_SIG_ALGS and len(payload) >= 2:
                    list_len = _u16(payload, 0)
                    sig_algs = [
                        _u16(payload, 2 + i)
                        for i in range(0, min(list_len, len(payload) - 2), 2)
                    ]
                elif ext_type == EXT_ALPN and len(payload) >= 2:
                    alpn_values = _parse_alpn(payload)
                elif ext_type == EXT_SUPPORTED_VERSIONS and len(payload) >= 1:
                    list_len = payload[0]
                    supported_versions = [
                        _u16(payload, 1 + i)
                        for i in range(0, min(list_len, len(payload) - 1), 2)
                    ]
    except (IndexError, ValueError):
        return None

    return {
        'legacy_version': legacy_version,
        'ciphers': [c for c in ciphers if not _is_grease(c)],
        'extensions': [e for e in extensions if not _is_grease(e)],
        'sig_algs': [s for s in sig_algs if not _is_grease(s)],
        'supported_versions': [v for v in supported_versions if not _is_grease(v)],
        'alpn': alpn_values,
        'has_sni': has_sni,
        'server_name': _first_server_name(body, extensions) if has_sni else '',
    }


def _parse_alpn(payload):
    """ALPN protocol names, in the order the client listed them."""
    values = []
    list_len = _u16(payload, 0)
    pos = 2
    end = min(2 + list_len, len(payload))
    while pos < end:
        name_len = payload[pos]
        pos += 1
        values.append(payload[pos:pos + name_len])
        pos += name_len
    return values


def _first_server_name(body, extensions):
    """
    Re-walk the extensions for the SNI host.

    Kept separate from the JA4 fields because the fingerprint only cares
    whether SNI is present, not what it says — but the flow record wants the
    hostname, and parsing the ClientHello twice is wasteful.
    """
    pos = 6 + 32
    try:
        pos += 1 + body[pos]
        pos += 2 + _u16(body, pos)
        pos += 1 + body[pos]
        if pos + 2 > len(body):
            return ''
        ext_total = _u16(body, pos)
        pos += 2
        end = min(pos + ext_total, len(body))
        while pos + 4 <= end:
            ext_type = _u16(body, pos)
            ext_len = _u16(body, pos + 2)
            pos += 4
            if ext_type == EXT_SERVER_NAME:
                payload = body[pos:pos + ext_len]
                # server_name_list length (2) + name_type (1) + length (2)
                if len(payload) < 5:
                    return ''
                name_len = _u16(payload, 3)
                return payload[5:5 + name_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except (IndexError, ValueError):
        return ''
    return ''


def _alpn_marker(alpn_values):
    """
    The two-character ALPN field.

    Normally the first and last characters of the first protocol name — "h2"
    for h2, "h1" for http/1.1. When either of those bytes is not ASCII
    alphanumeric the spec switches to the first and last characters of the
    value's hex representation, which is how a binary ALPN still yields two
    printable characters.
    """
    if not alpn_values or not alpn_values[0]:
        return '00'

    first = alpn_values[0]
    alnum = set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0x61, 0x7B))
    if first[0] in alnum and first[-1] in alnum:
        return chr(first[0]) + chr(first[-1])

    hexed = first.hex()
    return hexed[0] + hexed[-1]


def _sha12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4_fingerprint(hello):
    """
    Build the JA4 string from a parsed ClientHello.

    Returns (fingerprint, raw) — the raw form keeps the sorted lists in the
    clear, which is what makes a fingerprint arguable in court: an analyst can
    see exactly which ciphers and extensions produced the hash instead of being
    asked to trust twelve hex characters.
    """
    if hello is None:
        return '', ''

    version = max(hello['supported_versions']) if hello['supported_versions'] \
        else hello['legacy_version']
    version_label = VERSION_LABEL.get(version, '00')

    sni_flag = 'd' if hello['has_sni'] else 'i'
    cipher_count = min(len(hello['ciphers']), 99)
    ext_count = min(len(hello['extensions']), 99)
    alpn = _alpn_marker(hello['alpn'])

    prefix = f"t{version_label}{sni_flag}{cipher_count:02d}{ext_count:02d}{alpn}"

    cipher_list = ','.join(f'{c:04x}' for c in sorted(hello['ciphers']))
    cipher_hash = _sha12(cipher_list) if cipher_list else '000000000000'

    # SNI and ALPN are excluded here because they are already represented in
    # the prefix; leaving them in would make the same client hash differently
    # depending on which host it was visiting.
    ext_sorted = sorted(
        e for e in hello['extensions'] if e not in (EXT_SERVER_NAME, EXT_ALPN)
    )
    ext_list = ','.join(f'{e:04x}' for e in ext_sorted)
    sig_list = ','.join(f'{s:04x}' for s in hello['sig_algs'])

    if not ext_list:
        ext_hash = '000000000000'
        ext_raw = ''
    else:
        ext_raw = f'{ext_list}_{sig_list}' if sig_list else ext_list
        ext_hash = _sha12(ext_raw)

    return (
        f'{prefix}_{cipher_hash}_{ext_hash}',
        f'{prefix}_{cipher_list}_{ext_raw}',
    )


def fingerprint_payload(data):
    """
    (ja4, ja4_raw, server_name) for a TCP payload, or ('', '', '') if it is
    not a readable ClientHello.
    """
    hello = parse_client_hello(data)
    if hello is None:
        return '', '', ''
    ja4, raw = ja4_fingerprint(hello)
    return ja4, raw, hello['server_name']
