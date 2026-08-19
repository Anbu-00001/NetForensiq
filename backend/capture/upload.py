"""
Import a capture file through the browser.

Why this exists
---------------
Until now the only way to get a capture into the system was
`manage.py import_pcap` at a terminal. That is fine for the person who built
it and wrong for the person meant to use it: an investigating officer handed a
USB stick by a complainant should not need a shell prompt, and asking them to
type a path is how the wrong file gets sealed.

What it does NOT relax
----------------------
Everything the command line enforces, this enforces. The file is copied into
the evidence store and hashed before anything reads it, custody is attributed
to the signed-in officer, and provenance must be declared rather than assumed.
An upload is a slower, more careful path than a download — it takes custody of
something — so it is deliberately not a drag-and-drop that succeeds silently.
"""

import os
import tempfile

from django.db import transaction
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from accounts.models import AuditLog
from accounts.permissions import IsInvestigatorOrReadOnly
from accounts.utils import get_client_ip, log_action
from evidence.models import EvidenceRecord

from .service import run_pcap_import

# libpcap and pcapng file signatures.
#
# Checked rather than trusting the extension, because the extension is the one
# part of an uploaded file entirely under the sender's control. This is a
# sanity check on the format, not a security boundary: it stops an officer
# sealing a Word document they believed was a capture, and it stops the parser
# being handed something it will only fail on much later.
#
#   d4 c3 b2 a1  classic libpcap, little-endian    (tcpdump)
#   a1 b2 c3 d4  classic libpcap, big-endian
#   4d 3c b2 a1  libpcap with nanosecond timestamps, little-endian
#   a1 b2 3c 4d  libpcap with nanosecond timestamps, big-endian
#   0a 0d 0d 0a  pcapng Section Header Block        (Wireshark default)
PCAP_MAGIC = (
    b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4',
    b'\x4d\x3c\xb2\xa1', b'\xa1\xb2\x3c\x4d',
    b'\x0a\x0d\x0d\x0a',
)

# A capture larger than this is a job for the command line, where nothing times
# out and the officer can watch it. The figure is our own: it is roughly ten
# times the largest reference capture the project analyses, and comfortably
# above what a phone or a home router produces in a session.
MAX_UPLOAD_BYTES = 512 * 1024 * 1024

# Read in chunks rather than into memory: a 512 MB capture read whole would
# consume that much RAM on a workstation that may not have it to spare.
CHUNK_BYTES = 1024 * 1024


class CaptureUploadView(APIView):
    """
    POST a capture file. It is sealed, then analysed.

    Multipart fields:
        file           the .pcap or .pcapng                          (required)
        provenance     seized | reference | synthetic                (required)
        case_reference, fir_number, police_station, seized_from      (optional)
        exhibit_number, name, home_net                               (optional)
    """

    permission_classes = [IsInvestigatorOrReadOnly]
    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'upload'

    def post(self, request):
        upload = request.FILES.get('file')
        if not upload:
            return self._refuse('No file was supplied.')

        if upload.size > MAX_UPLOAD_BYTES:
            return self._refuse(
                f'That capture is {upload.size / 1e6:.0f} MB. The browser path '
                f'accepts up to {MAX_UPLOAD_BYTES / 1e6:.0f} MB — import a '
                f'larger file with "manage.py import_pcap", which has no limit.'
            )

        if upload.size == 0:
            return self._refuse('That file is empty.')

        # Provenance is required, not defaulted.
        #
        # A default here would mean the system deciding, on an officer's behalf,
        # what a file is — and the only safe default is the one that makes the
        # feature useless. Making it a required choice is the whole point: the
        # officer states what they are handing over, and that statement is what
        # gets recorded.
        provenance = (request.data.get('provenance') or '').strip()
        valid = {c for c, _ in EvidenceRecord.Provenance.choices}
        valid.discard(EvidenceRecord.Provenance.UNATTESTED)
        if provenance not in valid:
            return self._refuse(
                'Declare where this capture came from: '
                + ', '.join(sorted(valid)) + '.'
            )

        head = upload.read(4)
        upload.seek(0)
        if head not in PCAP_MAGIC:
            return self._refuse(
                'That does not look like a packet capture. The file must be '
                '.pcap or .pcapng — check that it was exported from Wireshark, '
                'tcpdump or a capture appliance rather than converted.'
            )

        # Written to a temporary file rather than kept in memory, because
        # ingest_evidence hashes and copies from a path, and because the sealed
        # copy must be made from bytes that are already at rest.
        tmp_dir = tempfile.mkdtemp(prefix='netforensiq-upload-')
        tmp_path = os.path.join(tmp_dir, os.path.basename(upload.name) or 'upload.pcap')
        try:
            with open(tmp_path, 'wb') as handle:
                for chunk in upload.chunks(CHUNK_BYTES):
                    handle.write(chunk)

            return self._ingest(request, tmp_path, upload.name, provenance)
        finally:
            # The temporary copy is removed whatever happened. The evidence
            # store holds the copy that matters; leaving a second one in /tmp
            # is an unsealed duplicate of an exhibit.
            try:
                os.remove(tmp_path)
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def _ingest(self, request, tmp_path, original_name, provenance):
        from evidence.service import ingest_evidence

        data = request.data
        try:
            with transaction.atomic():
                record = ingest_evidence(
                    tmp_path,
                    original_filename=original_name,
                    exhibit_number=(data.get('exhibit_number') or '').strip() or None,
                    collected_by=request.user,
                    case_reference=(data.get('case_reference') or '').strip(),
                    fir_number=(data.get('fir_number') or '').strip(),
                    police_station=(data.get('police_station') or '').strip(),
                    seized_from=(data.get('seized_from') or '').strip(),
                    acquisition_notes=(data.get('acquisition_notes') or '').strip(),
                    provenance=provenance,
                    actor_ip=get_client_ip(request),
                )

                # Analyse the sealed copy, never the upload: it is the artefact
                # the recorded hash describes and the one a court is shown.
                session, (flows, dns) = run_pcap_import(
                    pcap_path=record.stored_path,
                    name=(data.get('name') or '').strip() or None,
                    home_net=(data.get('home_net') or '').strip(),
                    user=request.user,
                    evidence=record,
                )
        except ValueError as exc:
            return self._refuse(str(exc))
        except Exception as exc:
            # A capture that the parser cannot read is a bad file, not a bug,
            # and the officer needs to know which of the two it is.
            return self._refuse(
                f'The file was accepted but could not be parsed: {exc}. '
                f'It may be truncated or use an unsupported link type.',
                status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(
                f'Uploaded {original_name} → exhibit {record.exhibit_number}, '
                f'session #{session.id} ({provenance})'
            ),
        )

        return Response({
            'session_id': session.id,
            'session_name': session.name,
            'packets': session.packet_count,
            'bytes': session.byte_count,
            'flows': flows,
            'dns_records': dns,
            'exhibit_number': record.exhibit_number,
            'sha256': record.sha256_hash,
            'md5': record.md5_hash,
            'provenance': record.provenance,
            'provenance_label': record.get_provenance_display(),
            'is_demonstration_only': record.is_demonstration_only,
            'custody_events': record.custody_events.count(),
        }, status=status.HTTP_201_CREATED)

    @staticmethod
    def _refuse(detail, code=status.HTTP_400_BAD_REQUEST):
        return Response({'detail': detail}, status=code)
