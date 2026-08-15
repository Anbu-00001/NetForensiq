from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.serializers import BooleanField, CharField, ModelSerializer

from accounts.models import AuditLog
from accounts.utils import get_client_ip, log_action

from .models import CustodyEvent, EvidenceRecord, Section63Certificate
from .service import issue_certificate, record_custody, verify_custody_chain


class CustodyEventSerializer(ModelSerializer):
    actor_username = CharField(source='actor.username', read_only=True, default=None)

    class Meta:
        model = CustodyEvent
        fields = [
            'id', 'sequence', 'action', 'actor', 'actor_username', 'actor_badge',
            'actor_ip', 'detail', 'timestamp', 'previous_hash', 'entry_hash',
        ]


class EvidenceRecordSerializer(ModelSerializer):
    class Meta:
        model = EvidenceRecord
        fields = [
            'id', 'exhibit_number', 'original_filename', 'file_size_bytes',
            'sha256_hash', 'md5_hash', 'hash_algorithm_declared', 'status',
            'last_verified_at', 'acquisition_timestamp', 'device_type',
            'device_make_model', 'device_serial', 'device_identifier',
            'custodian_relationship', 'case_reference', 'seized_from',
            'acquisition_notes', 'collected_by', 'created_at',
        ]


class Section63CertificateSerializer(ModelSerializer):
    is_complete = BooleanField(read_only=True)
    exhibit_number = CharField(source='evidence.exhibit_number', read_only=True)

    class Meta:
        model = Section63Certificate
        fields = '__all__'


class EvidenceViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = EvidenceRecord.objects.all()
    serializer_class = EvidenceRecordSerializer

    @action(detail=True, methods=['get'])
    def custody(self, request, pk=None):
        """The full chain of custody, with an integrity verdict over it."""
        record = self.get_object()
        ok, problems = verify_custody_chain(record)
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
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
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
            request, AuditLog.Action.EXPORT_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=f'Issued certificate {certificate.reference} for {record.exhibit_number}',
        )
        return Response(
            Section63CertificateSerializer(certificate).data,
            status=status.HTTP_201_CREATED,
        )


class CertificateViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Section63Certificate.objects.select_related('evidence')
    serializer_class = Section63CertificateSerializer
