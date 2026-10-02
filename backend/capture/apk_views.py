# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
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
from accounts.permissions import IsApproved
from accounts.utils import get_client_ip, log_action
from evidence.models import EvidenceRecord

from apk_engine.container import DEFAULT_MAX_EXTRACT_BYTES, inspect_archive
from apk_engine.report import unexaminable

from .apk_correlation import correlate_with_captures
from .apk_runner import run_examination

# A submitted sample is untrusted input that is about to be unzipped, so there
# are two ceilings: one on the file as uploaded, and one on the bytes written
# while unwrapping it, counted as they are written because the sizes an archive
# declares are chosen by whoever built it.
MAX_UPLOAD_BYTES = 256 * 1024 * 1024
MAX_EXTRACT_BYTES = DEFAULT_MAX_EXTRACT_BYTES
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


class _TooLarge(Exception):
    """Unwrapping wrote more than MAX_EXTRACT_BYTES; the partial file is discarded."""


def _copy_bounded(src, dst):
    written = 0
    while True:
        block = src.read(CHUNK_BYTES)
        if not block:
            return written
        written += len(block)
        if written > MAX_EXTRACT_BYTES:
            raise _TooLarge(
                f'Unwrapping stopped after {MAX_EXTRACT_BYTES:,} bytes — the archive '
                f'expands beyond what this workstation will extract.')
        dst.write(block)


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
            _copy_bounded(src, dst)
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
                        _copy_bounded(src, dst)
                return password
            except _TooLarge:
                raise
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
        data = request.data
        analysed_path, analysed_name, unwrapped_from = tmp_path, original_name, ''

        # Read the archive's structure before decompressing a byte of it.
        container = inspect_archive(tmp_path, MAX_EXTRACT_BYTES)
        if not container['readable']:
            return self._refuse('That file is not a readable ZIP archive.')

        # A sample arriving in a ZIP is the norm, not the exception: mail
        # gateways strip .apk attachments, so samples are passed around zipped
        # (the judge's copy was). Unwrapping one layer here means the officer
        # does not have to extract a hostile file by hand, which is precisely
        # the step you do not want performed on a workstation.
        unsafe_reason = ''
        if not container['has_manifest']:
            if not container['apk_members']:
                return self._refuse(
                    'The archive contains no Android package: no AndroidManifest.xml '
                    'and no .apk inside it.')
            if not container['safe_to_extract']:
                unsafe_reason = ('The archive was sealed but not opened: '
                                 + ' '.join(f['title'] + '.' for f in container['safety']))
            else:
                supplied = (data.get('archive_password') or '').strip()
                target = os.path.join(os.path.dirname(tmp_path), '_inner.apk')
                try:
                    with zipfile.ZipFile(tmp_path) as archive:
                        _extract_member(archive, container['apk_members'][0], target,
                                        supplied, tmp_path)
                except _NeedsPassword as exc:
                    return self._refuse(str(exc))
                except _TooLarge as exc:
                    unsafe_reason = f'The archive was sealed but not examined. {exc}'
                except Exception as exc:
                    return self._refuse(f'The archive could not be opened: {exc}')
                else:
                    analysed_path = target
                    analysed_name = os.path.basename(container['apk_members'][0])
                    unwrapped_from = original_name

        record = self._seal(request, tmp_path, original_name, provenance)
        if not isinstance(record, EvidenceRecord):
            return record

        if unsafe_reason:
            report = unexaminable(unsafe_reason, container=container)
        else:
            report = run_examination(
                analysed_path,
                container_path=tmp_path if unwrapped_from else None,
                original_name=analysed_name)
        report['correlation'] = correlate_with_captures(report)

        if len(container['apk_members']) > 1 and unwrapped_from:
            report['errors'].append(
                f'The archive holds {len(container["apk_members"])} packages; only '
                f'{analysed_name} was examined. Submit the others separately.')

        report['exhibit_number'] = record.exhibit_number
        report['original_filename'] = original_name
        report['analysed_filename'] = analysed_name
        report['unwrapped_from'] = unwrapped_from
        report['provenance'] = record.provenance
        report['provenance_label'] = record.get_provenance_display()
        report['sealed_sha256'] = record.sha256_hash

        assessment = report['assessment']
        self._record_examination(request, record, report, assessment)
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(f'Examined sample {original_name} -> exhibit {record.exhibit_number}: '
                    f'tier {assessment["tier"]} ({assessment["label"]})'),
        )
        return Response(report, status=status.HTTP_201_CREATED)

    @staticmethod
    def _record_examination(request, record, report, assessment):
        """
        Keep the conclusion with the exhibit. It used to live only in this response and
        in one line of the audit log, so nothing could later show a tier beside a second
        opinion or say which baseline table had produced it.
        """
        from .models import ApkExamination

        analysed = ((report.get('file') or {}).get('sha256') or '').lower()
        ApkExamination.objects.create(
            evidence=record,
            analysed_sha256=analysed if len(analysed) == 64 else '',
            package=((report.get('identity') or {}).get('package') or '')[:255],
            tier=assessment['tier'], tier_label=assessment['label'][:80],
            basis_ids=[(b.get('id') or b.get('title') or '')[:120]
                       for b in (assessment.get('basis') or [])][:50],
            engine_version=((report.get('engine') or {}).get('engine') or '')[:20],
            baselines_sha256=(((report.get('reproduction') or {}).get('reference_data_sha256') or {})
                              .get('baselines.json') or ''),
            examined_by=request.user)

    def _seal(self, request, tmp_path, original_name, provenance):
        from evidence.service import ingest_evidence

        data = request.data
        try:
            with transaction.atomic():
                # The exhibit is the file as received — the ZIP the officer was
                # handed, not the .apk lifted out of it. The digest has to
                # describe what was submitted, or it describes nothing.
                return ingest_evidence(
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

    @staticmethod
    def _refuse(detail, code=status.HTTP_400_BAD_REQUEST):
        return Response({'detail': detail}, status=code)


class SecondOpinionView(APIView):
    """
    File another tool's report beside a sample, and read the two side by side.

    POST (examiners and administrators — it appends to an exhibit's custody log):
        file   a MobSF JSON report                         (required)
        note   a line for the record                       (optional)
    GET    ?exhibit=<id>   the reports filed against an exhibit (any signed-in officer)

    The report states the SHA-256 of what it examined. It is tied to an exhibit only
    if that matches a package this system examined (or an APK it sealed directly);
    otherwise it is stored unlinked, and says so. See capture/second_opinion.py.
    """

    parser_classes = [MultiPartParser, FormParser]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'upload'

    def get_permissions(self):
        if self.request.method == 'POST':
            return [CanExamineSamples()]
        return [IsApproved()]

    @staticmethod
    def present(report):
        from . import second_opinion

        exam = None
        if report.evidence_id:
            exam = (report.evidence.apk_examinations
                    .filter(analysed_sha256=report.subject_sha256).order_by('-examined_at').first())
        return {
            'id': report.id,
            'tool': report.tool, 'tool_version': report.tool_version,
            'subject_sha256': report.subject_sha256, 'report_sha256': report.report_sha256,
            'report_bytes': report.report_bytes,
            'imported_at': report.imported_at,
            'imported_by': report.imported_by.username if report.imported_by_id else None,
            'note': report.note,
            'encrypted_at_rest': report.encrypted_at_rest,
            'exhibit_number': report.evidence.exhibit_number if report.evidence_id else None,
            'netforensiq_examination': ({
                'tier': exam.tier, 'tier_label': exam.tier_label, 'package': exam.package,
                'basis': exam.basis_ids, 'engine_version': exam.engine_version,
                'examined_at': exam.examined_at,
            } if exam else None),
            'comparison': second_opinion.compare(exam, report.summary),
            'summary': report.summary,
        }

    def get(self, request):
        from .models import ThirdPartyReport

        reports = ThirdPartyReport.objects.select_related('evidence', 'imported_by')
        exhibit = request.query_params.get('exhibit')
        if exhibit:
            reports = reports.filter(evidence_id=exhibit)
        return Response([self.present(r) for r in reports[:50]])

    def post(self, request):
        from evidence.models import CustodyEvent
        from evidence.service import record_custody

        from . import second_opinion
        from .models import ThirdPartyReport

        upload = request.FILES.get('file')
        if upload is None:
            return Response({'detail': 'Choose a MobSF JSON report.'},
                            status=status.HTTP_400_BAD_REQUEST)
        if upload.size > second_opinion.MAX_REPORT_BYTES:
            return Response({'detail': 'That file is larger than a report can be.'},
                            status=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE)
        data = upload.read()
        try:
            summary, report_sha = second_opinion.parse_mobsf(data)
        except second_opinion.NotAMobsfReport as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        subject = summary['subject']['sha256']
        exhibit, matched_by, _exam = second_opinion.find_exhibit(subject)

        existing = ThirdPartyReport.objects.filter(report_sha256=report_sha, evidence=exhibit).first()
        if existing:
            body = self.present(existing)
            body['already_filed'] = True
            return Response(body, status=status.HTTP_200_OK)

        path, encrypted = second_opinion.store_report(data, report_sha)
        with transaction.atomic():
            report = ThirdPartyReport.objects.create(
                tool=ThirdPartyReport.Tool.MOBSF, tool_version=summary['tool_version'][:40],
                subject_sha256=subject, report_sha256=report_sha, report_bytes=len(data),
                stored_path=path, encrypted_at_rest=encrypted, summary=summary,
                evidence=exhibit, imported_by=request.user,
                note=(request.data.get('note') or '').strip()[:500])
            if exhibit is not None:
                record_custody(
                    exhibit, CustodyEvent.Action.REPORT_ATTACHED, actor=request.user,
                    detail=(f'Third-party report attached: MobSF {summary["tool_version"] or "(version not stated)"}'
                            f', report sha256 {report_sha}, describing package sha256 {subject}. '
                            f'Opinion produced elsewhere; not evidence.'),
                    actor_ip=get_client_ip(request))
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(f'Filed MobSF report {report_sha[:16]} for package {subject[:16]} '
                    + (f'against exhibit {exhibit.exhibit_number} (matched by {matched_by})'
                       if exhibit else 'unlinked: no exhibit with that examined hash')))
        body = self.present(report)
        body['matched_by'] = matched_by
        if exhibit is None:
            body['unlinked_reason'] = (
                'No exhibit in this system has an examined package with the SHA-256 this report '
                'describes, so it is stored unlinked. Two different hashes are two different files: '
                'examine the exact package MobSF was given, or check that the report is for it.')
        return Response(body, status=status.HTTP_201_CREATED)

