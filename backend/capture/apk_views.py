"""
Take an Android package into evidence and examine it.

The endpoint is deliberately the same shape as the PCAP upload: the file is
sealed and hashed before anything reads it, custody is attributed to the
signed-in officer, and the analysis runs against the sealed copy. An exhibit
that was examined before it was sealed is an exhibit whose examined bytes and
recorded digest describe two different files.
"""

import os
import struct
import tempfile
import zipfile

try:
    import pyzipper
except ImportError:            # AES archives will be refused with a clear reason
    pyzipper = None

from django.db import transaction
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView

from accounts.models import AuditLog, User
from accounts.utils import get_client_ip, log_action
from evidence.models import EvidenceRecord

from .apk import analyse_apk, classify, correlate_with_captures

# A submitted sample is untrusted input that is about to be unzipped, so the
# ceiling is on the compressed file. Decompression itself is bounded inside
# the analyser, which reads a fixed byte budget of DEX and nothing else.
MAX_UPLOAD_BYTES = 256 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024

# ZIP and APK share a magic number; an APK is a ZIP. Checked rather than
# trusting the extension, for the same reason the PCAP path checks it.
ZIP_MAGIC = (b'PK\x03\x04', b'PK\x05\x06', b'PK\x07\x08')



# Passwords conventionally used when a malicious sample is passed around.
# "infected" is the near-universal convention (MalwareBazaar, VirusShare,
# most CERT advisories); the others turn up often enough to be worth a try.
# They are attempted only after any password the officer supplied, and each
# attempt is on an archive already sealed as an exhibit, so nothing here
# changes what was taken into evidence.
CONVENTIONAL_PASSWORDS = ('infected', 'malware', 'virus', 'sample', 'password')


class _NeedsPassword(Exception):
    """The archive is encrypted and no working password was found."""


def _encryption_of(archive, member):
    """
    Which encryption an entry uses: 'none', 'zipcrypto' or 'aes'.

    Worth distinguishing because the two failures look identical from the
    outside and have opposite fixes. `zipfile` cannot open WinZip-AES at all,
    and the way it fails is by reporting a bad password — so an officer with
    the *correct* password is told their password is wrong, and retypes it
    forever. The general-purpose bit flag and the AES extra field say which
    it is, before anything is attempted.
    """
    try:
        info = archive.getinfo(member)
    except KeyError:
        return 'none'
    if not (info.flag_bits & 0x1):
        return 'none'
    # Extra field 0x9901 is the WinZip AES marker.
    extra = info.extra or b''
    index = 0
    while index + 4 <= len(extra):
        header_id, size = struct.unpack_from('<HH', extra, index)
        if header_id == 0x9901:
            return 'aes'
        index += 4 + size
    return 'zipcrypto'


def _extract_member(archive, member, target, supplied='', zip_path=None):
    """
    Write one member of a ZIP to `target`, handling encrypted archives.

    Samples are distributed password-protected precisely so that scanners and
    mail gateways cannot open them, which means an examination tool that
    cannot take a password cannot examine the files it exists for.

    Two encryption schemes are in use in the wild and both are supported:
    legacy ZipCrypto through the standard library, and WinZip-AES through
    `pyzipper`. AES is what a modern 7-Zip or WinRAR produces by default, so
    refusing it would refuse most of the samples that actually arrive.
    """
    scheme = _encryption_of(archive, member)
    candidates = ([supplied] if supplied else []) + list(CONVENTIONAL_PASSWORDS)

    if scheme == 'none':
        with archive.open(member) as src, open(target, 'wb') as dst:
            while True:
                block = src.read(CHUNK_BYTES)
                if not block:
                    break
                dst.write(block)
        return ''

    openers = []
    if scheme == 'zipcrypto':
        openers.append(('zipcrypto', lambda: zipfile.ZipFile(zip_path)))
    if pyzipper is not None:
        openers.append(('aes', lambda: pyzipper.AESZipFile(zip_path)))
    elif scheme == 'aes':
        raise _NeedsPassword(
            f'{member} uses WinZip-AES encryption, which this build cannot '
            f'open (pyzipper is not installed). Re-zip with standard ZIP '
            f'encryption, or upload the .apk directly.'
        )

    for _name, factory in openers:
        for password in candidates:
            try:
                with factory() as handle:
                    handle.setpassword(password.encode())
                    with handle.open(member) as src, open(target, 'wb') as dst:
                        while True:
                            block = src.read(CHUNK_BYTES)
                            if not block:
                                break
                            dst.write(block)
                return password
            except Exception:
                continue

    scheme_note = ('WinZip-AES' if scheme == 'aes' else 'ZipCrypto')
    if supplied:
        raise _NeedsPassword(
            f'The password supplied did not open {member} '
            f'({scheme_note} encrypted). Check for stray spaces or a different '
            f'case — the password is passed through exactly as typed.'
        )
    raise _NeedsPassword(
        f'{member} is password-protected ({scheme_note}). Enter the archive '
        f'password above — {", ".join(CONVENTIONAL_PASSWORDS)} were tried '
        f'automatically and none worked.'
    )


class CanExamineSamples(BasePermission):
    """
    Commander/Administrator, plus the FSL examiner.

    Submitting a suspected malicious sample is a supervisory act: it takes
    custody of a file that is, by hypothesis, hostile, and it produces a
    classification that will be quoted. Investigators read the result; they do
    not decide what enters the sample store.

    The commander account holds the ADMIN role — there is no separate
    COMMANDER role in this deployment — so the two are the same check here.
    """

    message = ('Examining a submitted sample requires Commander/Administrator '
               'or FSL Examiner clearance.')

    def has_permission(self, request, view):
        user = request.user
        if not (user and user.is_authenticated):
            return False
        if not (user.is_superuser or getattr(user, 'is_approved', False)):
            return False
        return (
            user.is_superuser
            or getattr(user, 'role', None) in (User.Role.ADMIN, User.Role.EXPERT)
        )


class APKExaminationView(APIView):
    """
    POST an .apk (or a .zip containing one). It is sealed, then examined.

    Multipart fields:
        file          the .apk or .zip                                (required)
        provenance    seized | reference | synthetic                  (required)
        case_reference, fir_number, police_station, seized_from       (optional)
        acquisition_notes                                             (optional)
        archive_password  password for an encrypted ZIP                  (optional)
    """

    permission_classes = [CanExamineSamples]
    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'upload'

    def post(self, request):
        upload = request.FILES.get('file')
        if not upload:
            return self._refuse('No file was supplied.')
        if upload.size == 0:
            return self._refuse('That file is empty.')
        if upload.size > MAX_UPLOAD_BYTES:
            return self._refuse(
                f'That sample is {upload.size / 1e6:.0f} MB. This path accepts '
                f'up to {MAX_UPLOAD_BYTES / 1e6:.0f} MB.')

        provenance = (request.data.get('provenance') or '').strip()
        valid = {c for c, _ in EvidenceRecord.Provenance.choices}
        valid.discard(EvidenceRecord.Provenance.UNATTESTED)
        if provenance not in valid:
            return self._refuse(
                'Declare where this sample came from: ' + ', '.join(sorted(valid)) + '.')

        head = upload.read(4)
        upload.seek(0)
        if head not in ZIP_MAGIC:
            return self._refuse(
                'That is not a ZIP or APK. An Android package is a ZIP archive; '
                'this file does not begin like one.')

        tmp_dir = tempfile.mkdtemp(prefix='netforensiq-apk-')
        tmp_path = os.path.join(tmp_dir, os.path.basename(upload.name) or 'sample.apk')
        try:
            with open(tmp_path, 'wb') as handle:
                for chunk in upload.chunks(CHUNK_BYTES):
                    handle.write(chunk)
            return self._examine(request, tmp_path, upload.name, provenance)
        finally:
            for path in (tmp_path, os.path.join(tmp_dir, '_inner.apk')):
                try:
                    os.remove(path)
                except OSError:
                    pass
            try:
                os.rmdir(tmp_dir)
            except OSError:
                pass

    def _examine(self, request, tmp_path, original_name, provenance):
        from evidence.service import ingest_evidence

        data = request.data
        analysed_path, analysed_name, unwrapped_from = tmp_path, original_name, ''

        # A sample arriving in a ZIP is the norm, not the exception: mail
        # gateways strip .apk attachments, so samples are passed around zipped
        # (often the judge's own copy). Unwrapping one layer here means the
        # officer does not have to extract a hostile file by hand first, which
        # is precisely the step you do not want performed on a workstation.
        if not zipfile.is_zipfile(tmp_path):
            return self._refuse('That file is not a readable ZIP archive.')
        try:
            with zipfile.ZipFile(tmp_path) as archive:
                if 'AndroidManifest.xml' not in archive.namelist():
                    inner = [n for n in archive.namelist() if n.lower().endswith('.apk')]
                    if inner:
                        supplied = (data.get('archive_password') or '').strip()
                        target = os.path.join(os.path.dirname(tmp_path), '_inner.apk')
                        try:
                            _extract_member(archive, inner[0], target, supplied, tmp_path)
                        except _NeedsPassword as exc:
                            return self._refuse(str(exc))
                        analysed_path = target
                        analysed_name = os.path.basename(inner[0])
                        unwrapped_from = original_name
        except _NeedsPassword as exc:
            return self._refuse(str(exc))
        except Exception as exc:
            return self._refuse(f'The archive could not be opened: {exc}')

        try:
            with transaction.atomic():
                # The exhibit is the file as received — the ZIP the officer was
                # handed, not the .apk lifted out of it. The digest has to
                # describe what was submitted, or it describes nothing.
                record = ingest_evidence(
                    tmp_path,
                    original_filename=original_name,
                    collected_by=request.user,
                    case_reference=(data.get('case_reference') or '').strip(),
                    fir_number=(data.get('fir_number') or '').strip(),
                    police_station=(data.get('police_station') or '').strip(),
                    seized_from=(data.get('seized_from') or '').strip(),
                    acquisition_notes=(data.get('acquisition_notes') or '').strip(),
                    provenance=provenance,
                    actor_ip=get_client_ip(request),
                )
        except ValueError as exc:
            return self._refuse(str(exc))
        except Exception as exc:
            return self._refuse(f'The sample could not be sealed: {exc}',
                                status.HTTP_422_UNPROCESSABLE_ENTITY)

        try:
            report = analyse_apk(analysed_path)
            report['families'] = classify(report)
            report['correlation'] = correlate_with_captures(report)
        except Exception as exc:
            return self._refuse(
                f'The sample was sealed as {record.exhibit_number} but could not '
                f'be examined: {exc}',
                status.HTTP_422_UNPROCESSABLE_ENTITY)

        report['exhibit_number'] = record.exhibit_number
        report['original_filename'] = original_name
        report['analysed_filename'] = analysed_name
        report['unwrapped_from'] = unwrapped_from
        report['provenance'] = record.provenance
        report['provenance_label'] = record.get_provenance_display()
        report['sealed_sha256'] = record.sha256_hash

        top = report['families'][0]['family'] if report['families'] else 'no family matched'
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(f'Examined sample {original_name} -> exhibit '
                    f'{record.exhibit_number}: score {report["score"]}, '
                    f'{report["verdict"]}, {top}'),
        )
        return Response(report, status=status.HTTP_201_CREATED)

    @staticmethod
    def _refuse(detail, code=status.HTTP_400_BAD_REQUEST):
        return Response({'detail': detail}, status=code)
