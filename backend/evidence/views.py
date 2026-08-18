from django.http import FileResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
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
