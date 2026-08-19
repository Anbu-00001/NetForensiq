"""
Reading what was actually said, for the protocols that said it in the clear.

Scope, stated up front
----------------------
FTP, SMTP and HTTP without TLS. That is the whole list, and the limit is not an
oversight: without the session keys, a TLS-wrapped conversation cannot be
decoded, and this module will say so rather than produce a partial guess. An
examiner who is told "encrypted, contents not recoverable" can act on that. One
who is shown an empty transcript may conclude nothing was said.

Credentials
-----------
A cleartext FTP or SMTP login puts a password on the wire, and that password is
evidence — of the offence, and often of the suspect's other accounts. It is
decoded, and it is tagged `sensitive` so that every surface downstream can
decide to mask it. It is not silently dropped: destroying evidence to protect
someone's password is not this tool's decision to make. It is also not printed
by default into a document that will be photocopied.

Everything here works on the output of capture/reassembly.py, so every caveat
that module reports — gaps, ambiguity, a capture that began mid-stream — comes
with the transcript and must be shown beside it.
"""

import re

# Cleartext control channels. These are the ports where a transcript is
# possible at all; anything else is reported as not decoded rather than
# guessed at.
CLEARTEXT_PORTS = {
    21: 'ftp',
    25: 'smtp',
    587: 'smtp',
    80: 'http',
    8080: 'http',
    8000: 'http',
}

# Ports whose traffic is TLS by definition. Named so the answer can be
# "encrypted" rather than "unrecognised" — a materially different statement.
TLS_PORTS = {443, 465, 993, 995, 990, 989, 8443}

# A transcript pane, not an archive. Bodies beyond this are described rather
# than reproduced.
MAX_BODY_PREVIEW = 4096

FTP_CREDENTIAL_COMMANDS = {'PASS'}
FTP_COMMAND = re.compile(rb'^([A-Za-z]{3,4})\s*(.*)$')
FTP_RESPONSE = re.compile(rb'^(\d{3})([ -])(.*)$')

SMTP_COMMAND = re.compile(rb'^([A-Za-z]{4})\s*(.*)$', re.I)
SMTP_CREDENTIAL_COMMANDS = {'AUTH'}

HTTP_REQUEST = re.compile(
    rb'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT) (\S+) HTTP/(\d\.\d)$')
HTTP_RESPONSE = re.compile(rb'^HTTP/(\d\.\d) (\d{3})(?: (.*))?$')


def _text(raw):
    """Bytes as text without ever raising. Undecodable bytes are marked, not dropped."""
    return raw.decode('utf-8', errors='replace')


def _lines(stream):
    """
    CRLF-delimited lines from every recovered run.

    Each run is split on its own and the results are concatenated. Lines are
    never joined *across* a gap: splicing the tail of one run onto the head of
    the next would manufacture a command that nobody sent. A fragment left at
    a run boundary simply fails to match any command pattern and is dropped,
    and the gap itself is already in the stream's caveats.

    Reading only the first run — which this did originally — silently discarded
    every command after the first missing segment.
    """
    lines = []
    for _, data in stream.runs:
        lines.extend(data.split(b'\r\n'))
    return lines


def protocol_for(port_a, port_b):
    """
    What was probably spoken, from the port numbers alone.

    Returns (name, decodable). Port-based identification is a guess and is
    labelled as one everywhere it surfaces — a service on a non-standard port
    is common, and so is something else entirely on port 80.
    """
    for port in (port_a, port_b):
        if port in TLS_PORTS:
            return 'tls', False
        if port in CLEARTEXT_PORTS:
            return CLEARTEXT_PORTS[port], True
    return 'unknown', False


# ── FTP ────────────────────────────────────────────────────────────────────

def decode_ftp(c2s, s2c):
    """The control channel as an ordered exchange of commands and replies."""
    events = []
    for raw in _lines(c2s):
        match = FTP_COMMAND.match(raw.strip())
        if not match:
            continue
        verb = match.group(1).upper().decode('ascii', 'replace')
        argument = match.group(2)
        events.append({
            'direction': 'client',
            'command': verb,
            'argument': _text(argument),
            # PASS carries a password in the clear. Kept, flagged, and left to
            # the caller to mask.
            'sensitive': verb in FTP_CREDENTIAL_COMMANDS,
        })
    for raw in _lines(s2c):
        match = FTP_RESPONSE.match(raw.strip())
        if not match:
            continue
        events.append({
            'direction': 'server',
            'code': match.group(1).decode('ascii'),
            'text': _text(match.group(3)),
            'sensitive': False,
        })

    transferred = [e['argument'] for e in events
                   if e.get('command') in ('RETR', 'STOR', 'STOU', 'APPE')]
    users = [e['argument'] for e in events if e.get('command') == 'USER']
    return {
        'protocol': 'ftp',
        'events': events,
        # The summary an officer reads first: who logged in, and what moved.
        'accounts_used': users,
        'files_transferred': transferred,
        'credentials_in_the_clear': any(e.get('sensitive') for e in events),
        # The data connection is a separate TCP conversation on another port.
        # Saying so prevents the reasonable but wrong conclusion that a
        # transcript showing RETR contains the file.
        'note': (
            'This is the FTP control channel. File contents travel on a '
            'separate data connection and are not part of this transcript.'
        ),
    }


# ── SMTP ───────────────────────────────────────────────────────────────────

def decode_smtp(c2s, s2c):
    """Envelope, headers, and the fact of a body — not the body itself."""
    events, senders, recipients = [], [], []
    in_data = False
    headers, body_bytes = [], 0

    for raw in _lines(c2s):
        stripped = raw.strip()
        if in_data:
            if stripped == b'.':
                in_data = False
                continue
            if headers is not None and stripped == b'':
                headers = headers or []
                # Blank line ends the header block; everything after is body.
                headers.append(None)
                continue
            if headers is not None and None not in headers:
                headers.append(_text(stripped))
            else:
                body_bytes += len(raw) + 2
            continue

        match = SMTP_COMMAND.match(stripped)
        if not match:
            continue
        verb = match.group(1).upper().decode('ascii', 'replace')
        argument = _text(match.group(2))
        if verb == 'DATA':
            in_data = True
        elif verb == 'MAIL':
            senders.append(argument)
        elif verb == 'RCPT':
            recipients.append(argument)
        events.append({
            'direction': 'client',
            'command': verb,
            'argument': argument,
            # AUTH LOGIN / AUTH PLAIN carry base64 credentials on the wire.
            'sensitive': verb in SMTP_CREDENTIAL_COMMANDS,
        })

    return {
        'protocol': 'smtp',
        'events': events,
        'senders': senders,
        'recipients': recipients,
        'headers': [h for h in (headers or []) if h],
        'body_bytes': body_bytes,
        'credentials_in_the_clear': any(e['sensitive'] for e in events),
        'note': (
            'Message bodies are counted, not reproduced. The exhibit holds '
            'them; a transcript is not the place to make a second copy.'
        ),
    }


# ── HTTP ───────────────────────────────────────────────────────────────────

def _split_head(stream):
    # The first run only, deliberately: an HTTP header block starts at offset
    # zero, so if it is not in the first run it was not captured. Stitching
    # later runs on would look for headers in the middle of a body.
    if not stream.runs:
        return b'', b''
    data = stream.runs[0][1]
    head, sep, body = data.partition(b'\r\n\r\n')
    return head, body if sep else b''


def decode_http(c2s, s2c):
    """One request and one response. Pipelined or keep-alive reuse shows as such."""
    request_head, request_body = _split_head(c2s)
    response_head, response_body = _split_head(s2c)

    def parse(head):
        lines = head.split(b'\r\n')
        first = lines[0] if lines else b''
        fields = {}
        for line in lines[1:]:
            name, sep, value = line.partition(b':')
            if sep:
                fields[_text(name).strip()] = _text(value).strip()
        return first, fields

    request_line, request_headers = parse(request_head)
    status_line, response_headers = parse(response_head)

    request = {}
    match = HTTP_REQUEST.match(request_line.strip())
    if match:
        request = {
            'method': match.group(1).decode(),
            'target': _text(match.group(2)),
            'version': match.group(3).decode(),
        }

    response = {}
    match = HTTP_RESPONSE.match(status_line.strip())
    if match:
        response = {
            'version': match.group(1).decode(),
            'status': int(match.group(2)),
            'reason': _text(match.group(3) or b''),
        }

    return {
        'protocol': 'http',
        'request': request,
        'request_headers': request_headers,
        'response': response,
        'response_headers': response_headers,
        'request_body_bytes': len(request_body),
        'response_body_bytes': len(response_body),
        'response_body_preview': _text(response_body[:MAX_BODY_PREVIEW]),
        'response_body_truncated': len(response_body) > MAX_BODY_PREVIEW,
        # Basic auth is base64, not encryption, and it is worth calling out by
        # name because it looks like ciphertext to a reader skimming headers.
        'credentials_in_the_clear': any(
            name.lower() == 'authorization' for name in request_headers
        ),
    }


DECODERS = {'ftp': decode_ftp, 'smtp': decode_smtp, 'http': decode_http}


def decode(c2s, s2c, src_port, dst_port):
    """
    Decode a reassembled conversation, or say why it cannot be.

    The caveats from reassembly travel with the result. A transcript that looks
    complete but was rebuilt across a gap, or from segments that contradicted
    each other, is the thing this whole module exists not to hand anybody.
    """
    name, decodable = protocol_for(src_port, dst_port)
    caveats = c2s.caveats() + s2c.caveats()

    if not decodable:
        return {
            'protocol': name,
            'decoded': False,
            'reason': (
                'Encrypted (TLS). Without the session keys the contents cannot '
                'be recovered, and no partial reconstruction is offered.'
                if name == 'tls' else
                f'No cleartext decoder for ports {src_port}/{dst_port}. '
                f'Protocol identification here is by port number, which is a '
                f'guess.'
            ),
            'caveats': caveats,
            'bytes_client_to_server': c2s.bytes_recovered,
            'bytes_server_to_client': s2c.bytes_recovered,
        }

    decoded = DECODERS[name](c2s, s2c)
    decoded.update({
        'decoded': True,
        'identified_by': 'port number',
        'caveats': caveats,
        'reconstruction_ambiguous': c2s.is_ambiguous or s2c.is_ambiguous,
        'reconstruction_complete': c2s.is_complete and s2c.is_complete,
        'bytes_client_to_server': c2s.bytes_recovered,
        'bytes_server_to_client': s2c.bytes_recovered,
    })
    return decoded
