from django.http import FileResponse
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.views import APIView
from rest_framework.serializers import (
    BooleanField, CharField, IntegerField, ModelSerializer, SerializerMethodField,
)

from accounts.models import AuditLog
from accounts.permissions import IsExaminer, IsInvestigatorOrReadOnly
from accounts.utils import get_client_ip, log_action

from .certificate_pdf import render_certificate_pdf
from .custody_register import build_register
from .models import Case, CaseAssignment, CustodyEvent, EvidenceRecord, Section63Certificate
from .service import (
    issue_certificate, link_evidence_to_case, record_custody, sign_part_b,
    verify_custody_chain,
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
    case_number = CharField(source='case.case_number', read_only=True, default='')

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
            'case', 'case_number', 'encrypted_at_rest', 'encryption_algorithm',
        ]


class Section63CertificateSerializer(ModelSerializer):
    is_complete = BooleanField(read_only=True)
    exhibit_number = CharField(source='evidence.exhibit_number', read_only=True)

    class Meta:
        model = Section63Certificate
        fields = '__all__'


class CaseAssignmentSerializer(ModelSerializer):
    officer_name = CharField(source='officer.get_full_name', read_only=True)
    officer_username = CharField(source='officer.username', read_only=True)
    officer_badge = CharField(source='officer.badge_id', read_only=True, default='')
    role_display = CharField(source='get_role_display', read_only=True)

    class Meta:
        model = CaseAssignment
        fields = [
            'id', 'officer', 'officer_name', 'officer_username', 'officer_badge',
            'role', 'role_display', 'assigned_at',
        ]
        read_only_fields = ['assigned_at']


class CaseSerializer(ModelSerializer):
    status_display = CharField(source='get_status_display', read_only=True)
    reference_line = CharField(read_only=True)
    assignments = CaseAssignmentSerializer(many=True, read_only=True)
    exhibit_count = IntegerField(source='exhibits.count', read_only=True)
    io_name = CharField(source='investigating_officer.get_full_name',
                        read_only=True, default='')
    # The whole point of the model: whether the separation s.63(4) requires is
    # actually available on this case, answered from the record.
    has_independent_expert = SerializerMethodField()

    class Meta:
        model = Case
        fields = [
            'id', 'case_number', 'title', 'fir_number', 'police_station',
            'district', 'offence_sections', 'status', 'status_display',
            'opened_on', 'summary', 'investigating_officer', 'io_name',
            'reference_line', 'assignments', 'exhibit_count',
            'has_independent_expert', 'created_at', 'updated_at',
        ]
        read_only_fields = ['created_at', 'updated_at']

    def get_has_independent_expert(self, case):
        """
        True when someone other than the investigating officer is on the case
        as an examiner.

        BSA 2023 s.63(4) wants Part A and Part B signed by two different
        people. Answering this before a certificate is drafted is cheaper than
        discovering it at signing, which is where it was discovered before.
        """
        experts = [a.officer_id for a in case.assignments.all()
                   if a.role == CaseAssignment.Role.EXPERT]
        return any(officer_id != case.investigating_officer_id
                   for officer_id in experts)


class CaseViewSet(viewsets.ModelViewSet):
    """
    Investigations.

    Read is open to any signed-in officer; creating and editing needs
    investigator rights, which is what IsInvestigatorOrReadOnly enforces. A
    read-only records viewer can therefore look up a case and see which
    exhibits belong to it, and can change nothing about it.
    """

    permission_classes = [IsInvestigatorOrReadOnly]
    serializer_class = CaseSerializer
    queryset = Case.objects.prefetch_related('assignments__officer', 'exhibits')

    def perform_create(self, serializer):
        case = serializer.save(created_by=self.request.user)
        log_action(
            self.request, AuditLog.Action.VIEW_EVIDENCE, user=self.request.user,
            username_attempted=self.request.user.username,
            detail=f'Created case {case.case_number} ({case.title})',
        )

    @action(detail=True, methods=['post'])
    def assign(self, request, pk=None):
        """Put an officer on this case in a stated capacity."""
        case = self.get_object()
        officer_id = request.data.get('officer')
        role = request.data.get('role')
        if not officer_id or role not in CaseAssignment.Role.values:
            return Response(
                {'detail': 'officer and a valid role are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        assignment, created = CaseAssignment.objects.update_or_create(
            case=case, officer_id=officer_id,
            defaults={'role': role, 'assigned_by': request.user},
        )
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(f'{"Assigned" if created else "Changed"} officer '
                    f'{officer_id} as {role} on case {case.case_number}'),
        )
        return Response(CaseAssignmentSerializer(assignment).data,
                        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

    @action(detail=True, methods=['post'], url_path='link-exhibit')
    def link_exhibit(self, request, pk=None):
        """Attach a sealed exhibit to this case, recording it in the chain."""
        case = self.get_object()
        try:
            record = EvidenceRecord.objects.get(pk=request.data.get('evidence'))
        except EvidenceRecord.DoesNotExist:
            return Response({'detail': 'No such exhibit.'},
                            status=status.HTTP_404_NOT_FOUND)
        try:
            link_evidence_to_case(
                record, case, actor=request.user, actor_ip=get_client_ip(request),
            )
        except ValueError as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_409_CONFLICT)
        return Response(EvidenceRecordSerializer(record).data)


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

    @action(detail=False, methods=['get'])
    def posture(self, request):
        """
        The state of the evidence holding, for the operator strip.

        One call, because these facts are read together or not at all, and a
        request per row is a chance per row for a partial answer.

        Every field here is measured, not configured. The clock is read from
        the system; the seal is re-derived; the encryption count walks the store
        rather than trusting a flag on a row; the disk figure comes from the
        filesystem. An operator strip that reported a setting instead of a
        state would be exactly the wrong thing to put in an officer's eyeline
        all day.

        What each block is for, and the statute behind it where there is one,
        is documented in `evidence/posture.py`; the research that selected
        them is `research/140_SIDEBAR_FEATURE_RESEARCH.md`.
        """
        from . import posture as operator_posture, timesource
        from .crypto import describe as describe_encryption, is_encrypted

        records = list(EvidenceRecord.objects.select_related('case')
                       .order_by('-id'))
        latest = records[0] if records else None

        clock = timesource.describe()
        clock['summary'] = timesource.summary_line(clock)

        encryption = describe_encryption()
        encrypted_on_disk = sum(1 for r in records if is_encrypted(r.stored_path))

        exhibit = None
        if latest is not None:
            ok, _ = latest.verify()
            case = latest.case
            exhibit = {
                'exhibit_number': latest.exhibit_number,
                'status': latest.status,
                'status_label': latest.get_status_display(),
                'seal_intact': ok,
                'provenance': latest.provenance,
                'provenance_label': latest.get_provenance_display(),
                'is_demonstration_only': latest.is_demonstration_only,
                'custody_entries': latest.custody_events.count(),
                'case_number': case.case_number if case else '',
                'fir_number': (case.fir_number if case else '') or latest.fir_number,
                'police_station': ((case.police_station if case else '')
                                   or latest.police_station),
                # What the exhibit was sealed bearing, when no Case record
                # exists. Printed so the strip is never blank where a real
                # deployment would show an FIR.
                'reference_on_exhibit': latest.case_reference,
            }

        return Response({
            'clock': clock,
            'encryption': {
                **encryption,
                'exhibits_encrypted': encrypted_on_disk,
                'exhibits_total': len(records),
            },
            'exhibits': {
                'total': len(records),
                'sealed': sum(1 for r in records
                              if r.status == EvidenceRecord.Status.SEALED),
                'tampered': sum(1 for r in records
                                if r.status == EvidenceRecord.Status.TAMPERED),
            },
            'latest_exhibit': exhibit,

            # The obligations and the silent-failure states. Each is assembled
            # in evidence/posture.py, where the reason it earns permanent
            # screen space is written down next to it.
            'triage': operator_posture.triage_backlog(),
            'certificates': operator_posture.certificate_state(),
            'docket': operator_posture.case_docket(request.user),
            'store': operator_posture.store_headroom(),
            'capture': operator_posture.capture_heartbeat(),
            'custody': operator_posture.custody_reconciliation(),
            'feeds': operator_posture.intel_feeds(),
        })

    @action(detail=False, methods=['get'], url_path='store-status')
    def store_status(self, request):
        """
        Whether the evidence store is encrypted at rest, and by what.

        Authenticated rather than public: whether a store is encrypted is
        exactly what someone deciding whether to steal the disk would like to
        know. Officers who hold evidence need the answer; the internet does
        not.

        This reports the configuration, and separately how many exhibits are
        actually ciphertext on disk. Those two disagree whenever encryption was
        switched on after evidence had already been taken into custody, and the
        gap is the thing worth seeing — 'encryption: on' beside forty exhibits
        in the clear is the failure this endpoint exists to make visible.
        """
        from .crypto import describe, is_encrypted

        records = list(EvidenceRecord.objects.all())
        on_disk = sum(1 for r in records if is_encrypted(r.stored_path))
        state = describe()
        return Response({
            **state,
            'exhibits_total': len(records),
            'exhibits_encrypted': on_disk,
            'exhibits_in_the_clear': len(records) - on_disk,
            'remedy': (
                None if on_disk == len(records)
                else 'Run: manage.py encrypt_evidence_store'
            ),
        })

    @action(detail=True, methods=['get'], url_path='custody-register')
    def custody_register(self, request, pk=None):
        """
        The custody log as the register a charge sheet has to carry.

        Same rows as /custody/, different audience. That endpoint answers the
        interface; this one produces the document required by BNSS 2023
        s.193(3)(i) — "the sequence of custody in case of electronic device" —
        in the register form directed in Kattavellai @ Devakar v. State of
        Tamil Nadu, 2025 INSC 845.
        """
        record = self.get_object()
        register = build_register(record)
        log_action(
            request, AuditLog.Action.VIEW_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(f'Produced s.193(3)(i) custody register for '
                    f'{record.exhibit_number} '
                    f'({len(register["entries"])} movements)'),
        )
        return Response(register)

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

    @action(detail=True, methods=['post'],
            permission_classes=[IsExaminer])
    def sign(self, request, pk=None):
        """
        Countersign Part B as the expert.

        Separate from issue because s.63(4) contemplates two different people:
        the person in charge of the device, and an expert. Collapsing them into
        one call would let a single account produce a complete certificate,
        which is precisely the thing the two-part form exists to prevent.

        Gated on `IsExaminer` rather than the viewset's default so an
        investigator is refused at the door with a sentence explaining why,
        instead of reaching the service layer and being refused there. The
        service check stays regardless — it is the one that runs for the CLI
        and for anything else that calls `sign_part_b` directly, and a rule
        enforced only at the HTTP edge is a rule with a way around it.
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
