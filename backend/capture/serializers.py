from rest_framework import serializers

from .models import CaptureSession, Flow, DNSRecord, Detection


class DetectionSerializer(serializers.ModelSerializer):
    severity_label = serializers.CharField(source='get_severity_display', read_only=True)
    # A finding is an assertion about traffic in a specific sealed artefact.
    # Carrying the exhibit number and its provenance means an officer reading
    # the findings list can see, without navigating anywhere, both which
    # exhibit the claim rests on and whether that exhibit is evidence at all.
    exhibit_number = serializers.CharField(
        source='session.evidence.exhibit_number', read_only=True, default=None,
    )
    exhibit_provenance = serializers.CharField(
        source='session.evidence.provenance', read_only=True, default=None,
    )
    is_demonstration_only = serializers.BooleanField(
        source='session.evidence.is_demonstration_only', read_only=True, default=False,
    )
    method_label = serializers.CharField(source='get_method_display', read_only=True)
    # The MITRE ATT&CK classification, or a sentence saying why there is none.
    #
    # A shared vocabulary matters more than it looks: a technique id can be
    # looked up, compared against another tool's output, and discussed with
    # someone who has never used this platform. Two of the ten rules carry no
    # identifier, and the field says so rather than going blank — a blank reads
    # as an oversight, and someone would eventually "fix" it by guessing.
    mitre_attack = serializers.SerializerMethodField()

    def get_mitre_attack(self, detection):
        from .attack_mapping import classify, describe
        return {
            'techniques': classify(detection),
            'summary': describe(detection),
        }
    reviewed_by_username = serializers.CharField(
        source='reviewed_by.username', read_only=True, default=None,
    )

    class Meta:
        model = Detection
        fields = [
            'id', 'session', 'flow', 'rule_id', 'title', 'category',
            'severity', 'severity_label', 'method', 'method_label',
            'confidence', 'rationale', 'evidence', 'subject_ip', 'created_at',
            # Analyst review state. Without these the client cannot tell a
            # reviewed finding from an unreviewed one, and the triage controls
            # never render.
            'triage_status', 'reviewed_by', 'reviewed_by_username',
            'reviewed_at', 'review_note',
            'exhibit_number', 'exhibit_provenance', 'is_demonstration_only',
        
            'mitre_attack',
        ]


class FlowSerializer(serializers.ModelSerializer):
    total_bytes = serializers.SerializerMethodField()
    total_packets = serializers.SerializerMethodField()
    detection_count = serializers.IntegerField(read_only=True, default=0)
    peer_ip = serializers.SerializerMethodField()

    class Meta:
        model = Flow
        fields = [
            'id', 'session',
            'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
            'initiator_ip', 'initiator_port', 'initiator_confirmed', 'peer_ip',
            'packets_sent', 'packets_received', 'bytes_sent', 'bytes_received',
            'total_bytes', 'total_packets',
            'first_seen', 'last_seen', 'duration_seconds',
            'avg_packet_size', 'packets_per_second', 'bytes_ratio',
            'unique_dst_ports', 'payload_entropy', 'tcp_flags_seen',
            'interval_count', 'interval_mean', 'interval_median',
            'interval_stddev', 'interval_mad', 'interval_dispersion',
            'app_protocol', 'dns_query_count', 'longest_dns_label',
            'max_dns_entropy', 'app_protocol_source', 'http_host', 'tls_sni', 'ja4_fingerprint', 'ja4_raw',
            'is_analyzed', 'risk_score', 'detection_count',
        ]

    def get_total_bytes(self, obj):
        return obj.bytes_sent + obj.bytes_received

    def get_total_packets(self, obj):
        return obj.packets_sent + obj.packets_received

    def get_peer_ip(self, obj):
        """The endpoint that is not the initiator — i.e. who was contacted."""
        if obj.initiator_ip == obj.src_ip:
            return obj.dst_ip
        return obj.src_ip


class FlowSummarySerializer(serializers.ModelSerializer):
    """Lightweight shape for long flow tables."""

    total_bytes = serializers.SerializerMethodField()

    class Meta:
        model = Flow
        fields = [
            'id', 'initiator_ip', 'dst_ip', 'dst_port', 'protocol',
            'app_protocol', 'total_bytes', 'duration_seconds',
            'payload_entropy', 'risk_score', 'tls_sni', 'http_host',
        ]

    def get_total_bytes(self, obj):
        return obj.bytes_sent + obj.bytes_received


class DNSRecordSerializer(serializers.ModelSerializer):
    class Meta:
        model = DNSRecord
        fields = [
            'id', 'session', 'flow', 'src_ip', 'query_name', 'query_type',
            'response_ip', 'subdomain_length', 'label_count',
            'query_entropy', 'timestamp',
        ]


class CaptureSessionSerializer(serializers.ModelSerializer):
    started_by_username = serializers.CharField(
        source='started_by.username', read_only=True, default=None,
    )
    detection_count = serializers.IntegerField(read_only=True, default=0)
    capture_duration_seconds = serializers.SerializerMethodField()
    exhibit_number = serializers.CharField(
        source='evidence.exhibit_number', read_only=True, default=None,
    )
    exhibit_provenance_label = serializers.CharField(
        source='evidence.get_provenance_display', read_only=True, default=None,
    )
    is_demonstration_only = serializers.BooleanField(
        source='evidence.is_demonstration_only', read_only=True, default=False,
    )

    class Meta:
        model = CaptureSession
        fields = [
            'id', 'name', 'source_type', 'interface', 'pcap_filename',
            'bpf_filter', 'state', 'started_at', 'ended_at',
            'capture_start', 'capture_end', 'capture_duration_seconds',
            'packet_count', 'byte_count', 'flow_count',
            'started_by', 'started_by_username', 'error_message',
            'detection_count',
            # The monitored network is a property of this capture, not of the
            # install, and every egress finding depends on it. Published so an
            # analyst can see what the rules were applied against.
            'home_net',
            'evidence', 'exhibit_number', 'exhibit_provenance_label',
            'is_demonstration_only',
        ]
        read_only_fields = [
            'state', 'started_at', 'ended_at', 'capture_start', 'capture_end',
            'packet_count', 'byte_count', 'flow_count', 'started_by',
            'error_message',
        ]

    def get_capture_duration_seconds(self, obj):
        """Wall-clock span of the traffic itself, not of our processing run."""
        if obj.capture_start and obj.capture_end:
            return round((obj.capture_end - obj.capture_start).total_seconds(), 3)
        return None


class PcapUploadSerializer(serializers.Serializer):
    """Validates an operator-supplied capture file before it becomes evidence."""

    file = serializers.FileField()
    name = serializers.CharField(max_length=150, required=False, allow_blank=True)

    def validate_file(self, value):
        allowed = ('.pcap', '.pcapng', '.cap')
        if not value.name.lower().endswith(allowed):
            raise serializers.ValidationError(
                f"Unsupported file type. Expected one of: {', '.join(allowed)}"
            )
        return value
