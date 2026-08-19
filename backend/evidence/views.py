from django.http import FileResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.serializers import BooleanField, CharField, ModelSerializer

from accounts.models import AuditLog
from accounts.permissions import IsInvestigatorOrReadOnly
from accounts.utils import get_client_ip, log_action

from .certificate_pdf import render_certificate_pdf
from .models import CustodyEvent, EvidenceRecord, Section63Certificate
from .service import (
    issue_certificate, record_custody, sign_part_b, verify_custody_chain,
)


class CustodyEventSerializer(ModelSerializer):
    actor_username = CharField(source='actor.username', read_only=True, default=None)

    class Meta:
        model = CustodyEvent
        fields = [
            'id', 'sequence', 'action', 'actor', 'actor_username', 'actor_badge',
            'actor_ip', 'detail', 'timestamp', 'previous_hash', 'entry_hash',
        ]


class EvidenceRecordSerializer(ModelSerializer):
    # Where the bytes came from, in words. Exposed because a register that
    # cannot tell generated traffic from a seized capture is worse than no
    # register: both rows look identical and only one of them is evidence.
    provenance_label = CharField(source='get_provenance_display', read_only=True)
    is_demonstration_only = BooleanField(read_only=True)

    class Meta:
        model = EvidenceRecord
        fields = [
            'id', 'exhibit_number', 'original_filename', 'file_size_bytes',
            'sha256_hash', 'md5_hash', 'hash_algorithm_declared', 'status',
            'last_verified_at', 'acquisition_timestamp', 'device_type',
            'device_make_model', 'device_serial', 'device_identifier',
            'custodian_relationship', 'case_reference', 'fir_number',
            'police_station', 'seized_from',
            'acquisition_notes', 'collected_by', 'created_at',
            'provenance', 'provenance_label', 'provenance_detail',
            'is_demonstration_only',
        ]


class Section63CertificateSerializer(ModelSerializer):
    is_complete = BooleanField(read_only=True)
    exhibit_number = CharField(source='evidence.exhibit_number', read_only=True)

    class Meta:
        model = Section63Certificate
        fields = '__all__'


class EvidenceViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsInvestigatorOrReadOnly]
    queryset = EvidenceRecord.objects.all()
    serializer_class = EvidenceRecordSerializer

    @action(detail=True, methods=['get'])
    def custody(self, request, pk=None):
        """
        The full chain of custody, with an integrity verdict over it.

        Opening an exhibit's custody log is itself recorded. "Who has looked at
        this exhibit, and when" is a question defence counsel asks, and a
        system that cannot answer it is asking to be taken at its word.
        """
        record = self.get_object()
        ok, problems = verify_custody_chain(record)
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(
                f'Opened custody chain for {record.exhibit_number} '
                f'({record.custody_events.count()} entries, '
                f'{"intact" if ok else "BROKEN"})'
            ),
        )
        return Response({
            'chain_intact': ok,
            'problems': problems,
            'events': CustodyEventSerializer(
                record.custody_events.order_by('sequence'), many=True,
            ).data,
        })

    @action(detail=True, methods=['post'])
    def verify(self, request, pk=None):
        """
        Re-hash the sealed artefact and compare against the recorded digest.

        Recorded as a custody event either way — a failed verification is
        exactly the thing that must not be quietly discarded.
        """
        record = self.get_object()
        ok, computed = record.verify()

        record_custody(
            record, CustodyEvent.Action.VERIFIED, actor=request.user,
            detail=('Integrity verified' if ok
                    else f'INTEGRITY FAILED — computed {computed}'),
            actor_ip=get_client_ip(request),
        )
        log_action(
            request, AuditLog.Action.VERIFY_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Verified {record.exhibit_number}: {"pass" if ok else "FAIL"}',
        )
        return Response({
            'exhibit_number': record.exhibit_number,
            'verified': ok,
            'expected_sha256': record.sha256_hash,
            'computed_sha256': computed,
            'status': record.status,
        })

    @action(detail=True, methods=['get'])
    def fsl_forwarding(self, request, pk=None):
        """
        The forwarding letter and memo of evidence for sending this exhibit to
        an FSL.

        Generated from the record rather than retyped from it. Every fact on
        the letter — the FIR, the seal, the hash, the custody count — was
        entered once, at seizure, and re-keying it into a letter produces
        exactly one kind of error: a transposed hash, silently.

        Query parameters: `examinations` (comma-separated keys), `sections`,
        `addressed_to`, `remarks`.
        """
        from .fsl_forwarding import render_forwarding_letter

        record = self.get_object()
        requested = [
            part.strip() for part in
            (request.query_params.get('examinations') or '').split(',')
            if part.strip()
        ]

        path = render_forwarding_letter(
            record,
            requested=requested,
            officer=request.user,
            addressed_to=request.query_params.get('addressed_to', ''),
            sections=request.query_params.get('sections', ''),
            remarks=request.query_params.get('remarks', ''),
        )

        record_custody(
            record, CustodyEvent.Action.EXPORTED, actor=request.user,
            detail='FSL forwarding letter generated',
            actor_ip=get_client_ip(request),
        )
        log_action(
            request, AuditLog.Action.EXPORT_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Generated FSL forwarding letter for {record.exhibit_number}',
        )

        return FileResponse(
            open(path, 'rb'), content_type='application/pdf', as_attachment=True,
            filename=f'fsl-forwarding-{record.exhibit_number}.pdf',
        )

    @action(detail=True, methods=['post'])
    def certificate(self, request, pk=None):
        """Issue a BSA s.63 certificate over this exhibit."""
        record = self.get_object()
        try:
            certificate = issue_certificate(
                record,
                session=None,
                part_a_user=request.user,
                part_a_name=request.data.get('part_a_name', ''),
                part_a_designation=request.data.get('part_a_designation', ''),
                part_a_organisation=request.data.get('part_a_organisation', ''),
                part_a_address=request.data.get('part_a_address', ''),
                part_b_name=request.data.get('part_b_name', ''),
                part_b_designation=request.data.get('part_b_designation', ''),
                part_b_organisation=request.data.get('part_b_organisation', ''),
                part_b_qualification=request.data.get('part_b_qualification', ''),
                findings_summary=request.data.get('findings_summary', ''),
                actor_ip=get_client_ip(request),
            )
        except ValueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_409_CONFLICT)

        log_action(
            request, AuditLog.Action.ISSUE_CERTIFICATE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Issued certificate {certificate.reference} for {record.exhibit_number}',
        )
        return Response(
            Section63CertificateSerializer(certificate).data,
            status=status.HTTP_201_CREATED,
        )


class CertificateViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [IsInvestigatorOrReadOnly]
    queryset = Section63Certificate.objects.select_related('evidence')
    serializer_class = Section63CertificateSerializer

    @action(detail=True, methods=['post'])
    def sign(self, request, pk=None):
        """
        Countersign Part B as the expert.

        Separate from issue because s.63(4) contemplates two different people:
        the person in charge of the device, and an expert. Collapsing them into
        one call would let a single account produce a complete certificate,
        which is precisely the thing the two-part form exists to prevent.
        """
        certificate = self.get_object()
        try:
            certificate = sign_part_b(
                certificate,
                user=request.user,
                name=request.data.get('part_b_name', ''),
                designation=request.data.get('part_b_designation', ''),
                organisation=request.data.get('part_b_organisation', ''),
                qualification=request.data.get('part_b_qualification', ''),
                actor_ip=get_client_ip(request),
            )
        except ValueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_409_CONFLICT)

        log_action(
            request, AuditLog.Action.SIGN_CERTIFICATE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Signed Part B of {certificate.reference}',
        )
        return Response(Section63CertificateSerializer(certificate).data)

    @action(detail=True, methods=['get'])
    def pdf(self, request, pk=None):
        """
        Download the rendered certificate.

        Re-rendered on request rather than served from disk: the custody
        annexure and its verdict must reflect the chain as it stands now, not
        as it stood at issue. Every download is itself a custody event — an
        exported copy leaving the system is exactly what a court will ask about.
        """
        certificate = self.get_object()
        path = render_certificate_pdf(certificate)

        record_custody(
            certificate.evidence, CustodyEvent.Action.EXPORTED, actor=request.user,
            detail=f'Certificate {certificate.reference} exported as PDF',
            actor_ip=get_client_ip(request),
        )
        log_action(
            request, AuditLog.Action.EXPORT_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Downloaded certificate {certificate.reference}',
        )

        response = FileResponse(
            open(path, 'rb'), content_type='application/pdf',
            as_attachment=True, filename=f'{certificate.reference}.pdf',
        )
        return response


class PublicVerifyView(APIView):
    """
    Confirm an exhibit's integrity without holding an account.

    Why this is open
    ----------------
    A §63 certificate asserts that a file has a particular SHA-256. Defence
    counsel, a magistrate, or an FSL officer receiving that certificate has no
    way to test the assertion if checking it requires credentials to the
    investigating agency's own system — they would be taking the investigator's
    word for the investigator's own exhibit. That is precisely the thing a
    court is entitled to be sceptical about.

    So this endpoint answers one question, to anyone, about an exhibit number
    printed on a certificate: does the sealed file still hash to what the
    certificate says, and is its custody chain unbroken?

    What it deliberately does not disclose
    --------------------------------------
    No filename, no case reference, no FIR number, no seizure details, no
    findings, no officer names, and never any content. An exhibit number is not
    a secret — it is printed on a document handed to the other side — but the
    case around it is. The reply is the same shape whether or not the caller
    supplies a digest, so it cannot be used to enumerate.

    The provenance field is included on purpose: it is what stops a
    demonstration capture being verified in front of a court and mistaken for
    seized evidence. A "synthetic" answer here is as important as an "intact"
    one.
    """

    permission_classes = [AllowAny]
    throttle_classes = [ScopedRateThrottle]
    throttle_scope = 'public_verify'

    def get(self, request, exhibit_number):
        record = EvidenceRecord.objects.filter(
            exhibit_number__iexact=exhibit_number.strip(),
        ).first()

        if not record:
            # Same wording whichever way it fails: an exhibit that does not
            # exist and one the caller mistyped are not distinguished.
            return Response(
                {'found': False,
                 'detail': 'No sealed exhibit matches that number.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        intact, computed = record.verify()
        chain_ok, chain_problems = verify_custody_chain(record)

        # An optional digest lets the holder of a certificate check their own
        # copy of the file against the register, rather than trusting that the
        # number printed on the page was transcribed correctly.
        supplied = (request.query_params.get('h') or '').strip().lower()
        supplied_matches = (supplied == record.sha256_hash) if supplied else None

        certificate = record.certificates.order_by('-generated_at').first()

        log_action(
            request, AuditLog.Action.VERIFY_EVIDENCE,
            username_attempted='(public)',
            detail=(
                f'Public verification of {record.exhibit_number}: '
                f'content {"intact" if intact else "FAILED"}, '
                f'chain {"intact" if chain_ok else "BROKEN"}'
            ),
        )

        return Response({
            'found': True,
            'exhibit_number': record.exhibit_number,
            'sealed_at': record.created_at,
            'status': record.status,

            # The two questions a court actually has.
            'content_intact': intact,
            'custody_chain_intact': chain_ok,
            'custody_chain_problems': chain_problems,
            'custody_event_count': record.custody_events.count(),

            # What the register says the file hashes to, so a holder of the
            # file can check it themselves offline.
            'recorded_sha256': record.sha256_hash,
            'computed_sha256': computed,
            'supplied_digest_matches': supplied_matches,

            # The claim this exhibit is entitled to make about itself.
            'provenance': record.provenance,
            'provenance_label': record.get_provenance_display(),
            'is_demonstration_only': record.is_demonstration_only,

            'certificate_reference': certificate.reference if certificate else None,
            'certificate_complete': certificate.is_complete if certificate else None,
        })
