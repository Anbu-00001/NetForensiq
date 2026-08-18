from django.db.models import Count, Q, Sum
from django.utils import timezone

from rest_framework import status, viewsets
from rest_framework.decorators import action, api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.models import AuditLog
from accounts.permissions import IsInvestigatorOrReadOnly
from accounts.utils import log_action

from .detection import INFORMATIONAL_THRESHOLDS, THRESHOLDS, analyse_session
from .models import CaptureSession, DNSRecord, Detection, Flow
from .serializers import (
    CaptureSessionSerializer, DNSRecordSerializer, DetectionSerializer,
    FlowSerializer, FlowSummarySerializer,
)


class CaptureSessionViewSet(viewsets.ReadOnlyModelViewSet):
    """Capture sessions, plus the analysis and summary actions over them."""

    # Running detection rewrites the whole finding set for a session, so it
    # is a write however it is spelled. Without this a Viewer could trigger
    # it from a one-click button.
    permission_classes = [IsInvestigatorOrReadOnly]

    serializer_class = CaptureSessionSerializer

    def get_queryset(self):
        return (
            CaptureSession.objects
            .annotate(detection_count=Count('detections', distinct=True))
            .select_related('started_by')
        )

    @action(detail=True, methods=['post'])
    def analyse(self, request, pk=None):
        """Run the detection rules over this session."""
        session = self.get_object()
        summary = analyse_session(session)
        log_action(
            request, AuditLog.Action.ANALYSE_SESSION, user=request.user,
            username_attempted=request.user.username,
            detail=f'Analysed session #{session.id}: {summary["total"]} detections',
        )
        return Response(summary)

    @action(detail=True, methods=['get'])
    def summary(self, request, pk=None):
        """
        Everything the dashboard needs for one session, computed from stored
        rows. No figure on the dashboard is authored anywhere but here.
        """
        session = self.get_object()
        flows = session.flows.all()

        protocols = list(
            flows.values('protocol')
            .annotate(count=Count('id'),
                      bytes=Sum('bytes_sent') + Sum('bytes_received'))
            .order_by('-count')
        )
        # Split by how the protocol was determined. "HTTPS" because a
        # ClientHello was parsed and "HTTPS" because the port was 443 are
        # different claims, and a tunnel hiding on a permitted port is exactly
        # the case where the second one is wrong. The chart says which.
        applications = [
            {
                'app_protocol': row['app_protocol'],
                'count': row['count'],
                'observed': row['observed'],
                'inferred_from_port': row['count'] - row['observed'],
            }
            for row in flows.exclude(app_protocol='')
            .values('app_protocol')
            .annotate(
                count=Count('id'),
                observed=Count('id', filter=Q(app_protocol_source='observed')),
            )
            .order_by('-count')[:8]
        ]
        talkers = list(
            flows.values('initiator_ip')
            .annotate(count=Count('id'), bytes=Sum('bytes_sent'))
            .order_by('-bytes')[:10]
        )
        severities = list(
            session.detections.values('severity')
            .annotate(count=Count('id')).order_by()
        )

        return Response({
            'session': CaptureSessionSerializer(session).data,
            'totals': {
                'flows': flows.count(),
                'packets': session.packet_count,
                'bytes': session.byte_count,
                'dns_queries': session.dns_records.count(),
                'detections': session.detections.count(),
                # Reported separately because the dashboard used to label
                # the total as "awaiting triage" — a figure that never
                # dropped however many findings an analyst reviewed.
                'detections_pending': session.detections.filter(
                    triage_status=Detection.Triage.NEW).count(),
                'flagged_flows': flows.filter(risk_score__gt=0).count(),
            },
            'protocols': protocols,
            'applications': applications,
            'top_talkers': talkers,
            'detections_by_severity': severities,
        })

    # Resolution of the activity chart. Presentation only — no rule reads it —
    # but it decides what an officer can see: a week-long capture in 30 buckets
    # is one point per 5.6 hours, which can hide a burst entirely. Overridable
    # per request, and the width it produced is returned so the chart can say
    # what each point covers instead of leaving the reader to assume.
    DEFAULT_TIMELINE_BUCKETS = 30
    MAX_TIMELINE_BUCKETS = 500

    @action(detail=True, methods=['get'])
    def timeline(self, request, pk=None):
        """Packet activity bucketed over the capture window, for the chart."""
        session = self.get_object()
        if not (session.capture_start and session.capture_end):
            return Response([])

        try:
            buckets = int(request.query_params.get(
                'buckets', self.DEFAULT_TIMELINE_BUCKETS,
            ))
        except (TypeError, ValueError):
            buckets = self.DEFAULT_TIMELINE_BUCKETS
        buckets = max(1, min(buckets, self.MAX_TIMELINE_BUCKETS))

        span = (session.capture_end - session.capture_start).total_seconds()
        width = max(span / buckets, 1)

        series = [
            {'t': i, 'flows': 0, 'bytes': 0, 'flagged': 0}
            for i in range(buckets)
        ]
        for flow in session.flows.all():
            offset = (flow.first_seen - session.capture_start).total_seconds()
            idx = min(int(offset / width), buckets - 1)
            series[idx]['flows'] += 1
            series[idx]['bytes'] += flow.bytes_sent + flow.bytes_received
            if (flow.risk_score or 0) > 0:
                series[idx]['flagged'] += 1

        return Response({
            'start': session.capture_start,
            'end': session.capture_end,
            'bucket_seconds': round(width, 3),
            'series': series,
        })


class FlowViewSet(viewsets.ReadOnlyModelViewSet):
    """Flows, filterable by session, risk and endpoint."""

    def get_queryset(self):
        qs = Flow.objects.annotate(detection_count=Count('detections'))
        params = self.request.query_params

        if params.get('session'):
            qs = qs.filter(session_id=params['session'])
        if params.get('protocol'):
            qs = qs.filter(protocol=params['protocol'].upper())
        if params.get('ip'):
            ip = params['ip']
            qs = qs.filter(Q(src_ip=ip) | Q(dst_ip=ip))
        if params.get('flagged') == 'true':
            qs = qs.filter(risk_score__gt=0)

        ordering = params.get('ordering', '-risk_score')
        return qs.order_by(ordering, '-last_seen')

    def get_serializer_class(self):
        if self.action == 'list':
            return FlowSummarySerializer
        return FlowSerializer


class DNSRecordViewSet(viewsets.ReadOnlyModelViewSet):
    serializer_class = DNSRecordSerializer

    def get_queryset(self):
        qs = DNSRecord.objects.all()
        params = self.request.query_params
        if params.get('session'):
            qs = qs.filter(session_id=params['session'])
        if params.get('min_length'):
            qs = qs.filter(subdomain_length__gte=params['min_length'])
        return qs


class DetectionViewSet(viewsets.ReadOnlyModelViewSet):
    """Findings, plus the analyst triage action."""

    permission_classes = [IsInvestigatorOrReadOnly]
    serializer_class = DetectionSerializer

    def get_queryset(self):
        # session__evidence is joined, not lazily loaded: every finding now
        # reports the exhibit it rests on, and without this each row costs two
        # extra queries. Over 343 findings in seven pages that is 1,372 round
        # trips, which took the findings page from responsive to timing out.
        qs = Detection.objects.select_related(
            'flow', 'session', 'session__evidence', 'reviewed_by',
        )
        params = self.request.query_params
        if params.get('session'):
            qs = qs.filter(session_id=params['session'])
        if params.get('severity'):
            qs = qs.filter(severity=params['severity'])
        if params.get('triage'):
            qs = qs.filter(triage_status=params['triage'])
        return qs

    @action(detail=True, methods=['post'])
    def triage(self, request, pk=None):
        """
        Record an analyst's decision on a finding.

        The machine proposes; a named officer disposes. Both the decision and
        who made it are stored, because a chargesheet needs a person behind
        the conclusion, not a rule id.
        """
        detection = self.get_object()
        decision = request.data.get('status')
        valid = dict(Detection.Triage.choices)

        if decision not in valid:
            return Response(
                {'detail': f'status must be one of: {", ".join(valid)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        detection.triage_status = decision
        detection.reviewed_by = request.user
        detection.reviewed_at = timezone.now()
        detection.review_note = request.data.get('note', '')
        detection.save(update_fields=[
            'triage_status', 'reviewed_by', 'reviewed_at', 'review_note',
        ])

        log_action(
            request, AuditLog.Action.TRIAGE_DETECTION, user=request.user,
            username_attempted=request.user.username,
            detail=f'Triaged detection #{detection.id} ({detection.rule_id}) as {decision}',
        )
        return Response(DetectionSerializer(detection).data)

    @action(detail=False, methods=['get'])
    def thresholds(self, request):
        """
        Publish every detection threshold and its provenance.

        Exposing this is the point: a reviewer can audit what we compare
        against and where each number came from, including the ones we made up.
        """
        return Response([
            {
                'key': key,
                'value': value,
                'source': source,
                # Prefix match, not exact: sources carry qualified variants such
                # as "[OUR HEURISTIC, informed by practitioner sources]", and an
                # exact-match check would silently report those as sourced.
                'is_heuristic': '[OUR HEURISTIC' in source,
                # Aggregation parameters shape what the rules see but are
                # not themselves a test any rule performs. Presenting them
                # identically to detection thresholds overstates what the
                # engine checks.
                'is_informational': key in INFORMATIONAL_THRESHOLDS,
            }
            for key, (value, source) in sorted(THRESHOLDS.items())
        ])


@api_view(['GET'])
@permission_classes([AllowAny])
def engine_info(request):
    """
    What the engine is, for pages shown before anyone signs in.

    The landing and login pages state how many detection rules exist and which
    version this is. Those were three separate hardcoded strings that no test
    could keep honest — add a rule and the marketing copy silently becomes
    wrong. They are read from here instead.

    Public because the pages that need it are public. It exposes counts and a
    version, not rule logic, thresholds or any data.
    """
    from .detection import INFORMATIONAL_THRESHOLDS, RULE_IDS, THRESHOLDS
    from netforensiq_backend.version import get_version

    return Response({
        'version': get_version(),
        'rule_count': len(RULE_IDS),
        'threshold_count': len(THRESHOLDS),
        'heuristic_threshold_count': sum(
            1 for _, source in THRESHOLDS.values() if 'OUR HEURISTIC' in source
        ),
        'informational_threshold_count': len(INFORMATIONAL_THRESHOLDS),
    })
