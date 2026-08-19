from collections import defaultdict

from django.db.models import Count, Max, Q, Sum
from django.http import FileResponse
from django.utils import timezone

from rest_framework import status, viewsets
from rest_framework.decorators import (
    action, api_view, permission_classes, throttle_classes,
)
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.throttling import ScopedRateThrottle
from rest_framework.response import Response

from accounts.models import AuditLog
from accounts.permissions import (
    CanReadCommunicationContent, IsInvestigatorOrReadOnly,
)
from accounts.utils import get_client_ip, log_action
from evidence.crypto import EvidenceDecryptionError
from evidence.models import CustodyEvent as EvidenceCustodyEvent
from evidence.service import record_custody

from .detection import (
    INFORMATIONAL_THRESHOLDS, THRESHOLDS, analyse_session, describe_home_net,
    is_internal, session_home_networks,
)
from .hosts import profile_hosts
from .protocols import decode
from .reassembly import (
    POLICY as REASSEMBLY_POLICY, UnsupportedCapture,
    conversation_endpoints, reassemble_flow,
)
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
    def siem(self, request, pk=None):
        """
        Stream this session's findings in a format a SIEM ingests.

            ?fmt=ecs      Elastic Common Schema, newline-delimited JSON
            ?fmt=cef      Common Event Format (ArcSight lineage)
            ?fmt=syslog   RFC 5424

        The parameter is `fmt`, not `format`. `format` is reserved by DRF for
        content negotiation: passing `?format=ecs` makes it look for a renderer
        by that name and return 404 before this method is ever called.

        Streamed rather than assembled: a session with thousands of findings
        should not be held whole in memory on a workstation, and every log
        shipper reads a line at a time anyway.

        See capture/siem.py for what is deliberately withheld — a SIEM has a
        broad readership and the case around a finding is not operational data.
        """
        from django.http import StreamingHttpResponse

        from .siem import FORMATS, export

        session = self.get_object()
        fmt = (request.query_params.get('fmt') or 'ecs').lower()
        if fmt not in FORMATS:
            return Response(
                {'detail': f'fmt must be one of: {", ".join(sorted(FORMATS))}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        findings = session.detections.select_related('flow', 'session__evidence')
        content_type, _render = FORMATS[fmt]

        log_action(
            request, AuditLog.Action.EXPORT_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(
                f'Exported {findings.count()} findings from session '
                f'#{session.id} as {fmt.upper()}'
            ),
        )

        from .attack_mapping import beaconing_hosts_in

        response = StreamingHttpResponse(
            export(findings, fmt, beaconing_hosts=beaconing_hosts_in(session)),
            content_type=content_type,
        )
        response['Content-Disposition'] = (
            f'attachment; filename="netforensiq-session-{session.id}.{fmt}"'
        )
        return response

    @action(detail=True, methods=['get'])
    def report(self, request, pk=None):
        """
        Download the forensic examination report for this capture.

        Distinct from the §63 certificate, which is a statutory declaration
        about a file's hash and says nothing about what was found. This is the
        document that goes in the case file: what was captured, what was
        found, why, and what it does not establish.

        Re-rendered on request rather than served from disk, for the same
        reason the certificate is — the findings and their triage state must
        reflect the case as it stands now, not as it stood when someone last
        pressed a button. Every download is recorded.
        """
        from evidence.investigation_report import render_investigation_report

        session = self.get_object()
        path = render_investigation_report(session)

        log_action(
            request, AuditLog.Action.EXPORT_EVIDENCE, user=request.user,
            username_attempted=request.user.username,
            detail=(
                f'Downloaded forensic report for session #{session.id} '
                f'({session.detections.count()} findings)'
            ),
        )

        return FileResponse(
            open(path, 'rb'), content_type='application/pdf',
            as_attachment=True,
            filename=f'netforensiq-report-session-{session.id}.pdf',
        )

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

    # How many machines the host view returns by default. A capture of a
    # university network can contain thousands of hosts, and rendering all of
    # them serves nobody; the total is always reported alongside so the page
    # says what it left out rather than quietly truncating.
    DEFAULT_HOST_LIMIT = 50
    MAX_HOST_LIMIT = 1000

    @action(detail=True, methods=['get'])
    def hosts(self, request, pk=None):
        """
        The capture grouped by machine, worst first.

        "Which computer?" is the question an investigation actually turns on.
        A flow count does not answer it; this does.
        """
        session = self.get_object()
        try:
            limit = int(request.query_params.get('limit', self.DEFAULT_HOST_LIMIT))
        except (TypeError, ValueError):
            limit = self.DEFAULT_HOST_LIMIT
        limit = max(1, min(limit, self.MAX_HOST_LIMIT))

        return Response(profile_hosts(session, limit=limit))

    # Resolution of the activity chart. Presentation only — no rule reads it —
    # but it decides what an officer can see: a week-long capture in 30 buckets
    # is one point per 5.6 hours, which can hide a burst entirely. Overridable
    # per request, and the width it produced is returned so the chart can say
    # what each point covers instead of leaving the reader to assume.
    DEFAULT_TIMELINE_BUCKETS = 30
    MAX_TIMELINE_BUCKETS = 500

    # How many hosts the graph will draw before it starts summarising.
    #
    # A week-long server capture touches thousands of addresses. Drawing them
    # all produces a hairball that is technically complete and tells an officer
    # nothing — the visualisation equivalent of handing someone the raw pcap.
    # The busiest are drawn and the remainder are counted, so the picture says
    # what it left out instead of pretending to be the whole network.
    MAX_GRAPH_NODES = 60
    MAX_GRAPH_EDGES = 150

    @action(detail=True, methods=['get'])
    def graph(self, request, pk=None):
        """
        The capture as a picture: who talked to whom, and which of it matters.

        The dashboard's numbers answer "how much traffic was there". An officer
        asks a different question — "which machine is in trouble, and who was
        it talking to" — and that is a shape, not a figure. This returns the
        nodes and edges to draw it.

        Every node carries the plain-language reason it is drawn the way it is,
        so the picture can be read without a legend and without knowing what a
        flow is.
        """
        session = self.get_object()
        networks = session_home_networks(session)

        try:
            limit = int(request.query_params.get('nodes', self.MAX_GRAPH_NODES))
        except (TypeError, ValueError):
            limit = self.MAX_GRAPH_NODES
        limit = max(5, min(limit, 300))

        # Rank hosts by the worst finding against them, then by how much they
        # moved. Risk first, because a quiet host running a C2 beacon matters
        # more than a noisy one downloading updates — and volume alone would
        # bury it.
        # `__isnull=False`, not `exclude(subject_ip='')`.
        #
        # subject_ip is a nullable GenericIPAddressField, so an absent value is
        # stored as NULL and never as the empty string. `NOT (subject_ip = '')`
        # is NULL-unsafe in SQL: every row compares as unknown and is excluded,
        # so the exclusion quietly matched everything and no host ever showed a
        # finding. The graph looked correct and was empty of the one thing it
        # exists to show.
        subjects = session.detections.filter(subject_ip__isnull=False)
        worst = dict(
            subjects.values('subject_ip')
            .annotate(rank=Max('severity_rank'))
            .values_list('subject_ip', 'rank')
        )
        finding_counts = dict(
            subjects.values('subject_ip').annotate(n=Count('id'))
            .values_list('subject_ip', 'n')
        )

        traffic = defaultdict(lambda: {'bytes': 0, 'flows': 0, 'peers': set()})
        edges = defaultdict(lambda: {'bytes': 0, 'flows': 0, 'risk': 0, 'protocols': set()})

        for flow in session.flows.all().only(
            'src_ip', 'dst_ip', 'initiator_ip', 'bytes_sent', 'bytes_received',
            'risk_score', 'protocol', 'app_protocol',
        ):
            moved = (flow.bytes_sent or 0) + (flow.bytes_received or 0)
            a = flow.initiator_ip or flow.src_ip
            b = flow.dst_ip if a == flow.src_ip else flow.src_ip
            if not a or not b or a == b:
                continue

            for host, peer in ((a, b), (b, a)):
                traffic[host]['bytes'] += moved
                traffic[host]['flows'] += 1
                traffic[host]['peers'].add(peer)

            key = (a, b)
            edges[key]['bytes'] += moved
            edges[key]['flows'] += 1
            edges[key]['risk'] = max(edges[key]['risk'], flow.risk_score or 0)
            edges[key]['protocols'].add(flow.app_protocol or flow.protocol)

        ranked = sorted(
            traffic.items(),
            key=lambda item: (worst.get(item[0], 0), item[1]['bytes']),
            reverse=True,
        )
        kept = dict(ranked[:limit])

        nodes = []
        for ip, stats in kept.items():
            rank = worst.get(ip, 0)
            internal = is_internal(ip, networks)
            nodes.append({
                'id': ip,
                'internal': internal,
                'bytes': stats['bytes'],
                'flows': stats['flows'],
                'peers': len(stats['peers']),
                'severity_rank': rank,
                'finding_count': finding_counts.get(ip, 0),
                # Why this circle looks the way it does, in words. A legend
                # explains a colour; this explains the machine.
                'caption': self._describe_node(
                    ip, internal, stats, rank, finding_counts.get(ip, 0),
                ),
            })

        drawn = set(kept)
        visible_edges = sorted(
            (
                {
                    'source': a, 'target': b,
                    'bytes': e['bytes'], 'flows': e['flows'], 'risk': e['risk'],
                    'protocols': sorted(p for p in e['protocols'] if p)[:3],
                }
                for (a, b), e in edges.items() if a in drawn and b in drawn
            ),
            key=lambda e: (e['risk'], e['bytes']), reverse=True,
        )[:self.MAX_GRAPH_EDGES]

        return Response({
            'nodes': nodes,
            'edges': visible_edges,
            'hosts_total': len(traffic),
            'hosts_drawn': len(nodes),
            'home_networks': describe_home_net(networks),
            # Said plainly, because a picture that hides most of the network
            # while looking complete is a misleading picture.
            'caption': (
                f'{len(nodes)} of {len(traffic)} hosts shown — the ones with '
                f'findings against them first, then the busiest.'
                if len(nodes) < len(traffic)
                else f'All {len(nodes)} hosts in this capture.'
            ),
        })

    @staticmethod
    def _describe_node(ip, internal, stats, severity_rank, findings):
        """One sentence an officer can read without knowing what a flow is."""
        side = 'Inside the monitored network' if internal else 'Outside address'
        volume = stats['bytes']
        if volume >= 1_000_000_000:
            size = f'{volume / 1_000_000_000:.1f} GB'
        elif volume >= 1_000_000:
            size = f'{volume / 1_000_000:.1f} MB'
        elif volume >= 1000:
            size = f'{volume / 1000:.0f} KB'
        else:
            size = f'{volume} bytes'

        sentence = (
            f'{side}. Exchanged {size} across {stats["flows"]} '
            f'{"conversation" if stats["flows"] == 1 else "conversations"} '
            f'with {len(stats["peers"])} '
            f'{"machine" if len(stats["peers"]) == 1 else "machines"}.'
        )
        if findings:
            sentence += (
                f' {findings} finding{"s" if findings != 1 else ""} '
                f'recorded against it.'
            )
        else:
            sentence += ' Nothing flagged against it.'
        return sentence

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

    @action(detail=True, methods=['get'],
            permission_classes=[CanReadCommunicationContent])
    def transcript(self, request, pk=None):
        """
        Rebuild one conversation from the sealed exhibit and read it back.

        Reconstruction happens on demand and nothing is kept: the decoded
        content of a communication is never written into the analysis database,
        because a working table full of message bodies is a second copy of the
        intercepted material in a place with weaker handling than the exhibit
        it came from.

        Recorded as a custody event. "Who read the contents of this
        conversation, and when" is a question that gets asked, and a system
        that cannot answer it is asking to be taken at its word.
        """
        flow = self.get_object()
        if flow.protocol != 'TCP':
            return Response(
                {'detail': f'Reassembly applies to TCP. This flow is '
                           f'{flow.protocol}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        record = getattr(flow.session, 'evidence', None)
        if record is None or not record.stored_path:
            return Response(
                {'detail': 'This session has no sealed exhibit behind it, so '
                           'there is nothing to reconstruct from.'},
                status=status.HTTP_409_CONFLICT,
            )

        # Oriented on who opened the connection, not on which address the
        # capture saw first — see reassembly.conversation_endpoints.
        client_ip, client_port, server_ip, server_port = conversation_endpoints(flow)
        try:
            client, server = reassemble_flow(record.stored_path, flow)
        except UnsupportedCapture as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_409_CONFLICT)
        except (OSError, EvidenceDecryptionError) as exc:
            return Response({'detail': f'Could not read the exhibit: {exc}'},
                            status=status.HTTP_409_CONFLICT)

        decoded = decode(client, server, client_port, server_port)

        record_custody(
            record, EvidenceCustodyEvent.Action.VIEWED, actor=request.user,
            detail=(f'Reconstructed the conversation '
                    f'{client_ip}:{client_port} → {server_ip}:{server_port} '
                    f'({decoded.get("protocol", "unknown")})'),
            actor_ip=get_client_ip(request),
        )
        return Response({
            'flow': flow.id,
            'endpoints': {
                'client': f'{client_ip}:{client_port}',
                'server': f'{server_ip}:{server_port}',
            },
            'exhibit_number': record.exhibit_number,
            'reassembly_policy': REASSEMBLY_POLICY,
            **decoded,
        })


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


class LargePageAllowed(PageNumberPagination):
    """
    Default page of 50, up to 500 on request.

    The findings list is read whole — an officer triaging a capture needs all
    of it, and the page counts "awaiting review" across the set. At 50 per page
    that was seven sequential requests for one capture, which is slow and
    spends the hourly request budget for no benefit. The cap stays, because an
    unbounded page_size is a denial-of-service parameter.
    """

    page_size_query_param = 'page_size'
    max_page_size = 500


class DetectionViewSet(viewsets.ReadOnlyModelViewSet):
    """Findings, plus the analyst triage action."""

    permission_classes = [IsInvestigatorOrReadOnly]
    serializer_class = DetectionSerializer
    pagination_class = LargePageAllowed

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


class EngineInfoThrottle(ScopedRateThrottle):
    """Its own bucket, so a public page cannot exhaust the general one."""

    scope = 'engine'


@api_view(['GET'])
@permission_classes([AllowAny])
@throttle_classes([EngineInfoThrottle])
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
