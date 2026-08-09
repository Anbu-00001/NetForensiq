from django.db import models
from django.conf import settings


class CaptureSession(models.Model):
    """One capture run — either live sniffing or an imported PCAP file."""

    class Source(models.TextChoices):
        LIVE = 'live', 'Live Interface'
        PCAP = 'pcap', 'Imported PCAP'

    class State(models.TextChoices):
        RUNNING = 'running', 'Running'
        STOPPED = 'stopped', 'Stopped'
        COMPLETED = 'completed', 'Completed'
        FAILED = 'failed', 'Failed'

    name = models.CharField(max_length=150)
    source_type = models.CharField(max_length=10, choices=Source.choices)
    interface = models.CharField(max_length=200, blank=True)
    pcap_filename = models.CharField(max_length=255, blank=True)
    bpf_filter = models.CharField(max_length=255, blank=True)

    state = models.CharField(max_length=12, choices=State.choices, default=State.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    packet_count = models.BigIntegerField(default=0)
    byte_count = models.BigIntegerField(default=0)
    flow_count = models.IntegerField(default=0)

    started_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='capture_sessions',
    )
    error_message = models.TextField(blank=True)

    class Meta:
        ordering = ['-started_at']

    def __str__(self):
        return f"{self.name} [{self.source_type}] {self.packet_count} pkts"


class Flow(models.Model):
    """
    An aggregated bidirectional conversation between two endpoints.
    This is the unit the ML model scores in Phase 3.
    """

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name='flows',
    )

    # 5-tuple identity
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(default=0)
    dst_port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=12)

    # Volume features
    packets_sent = models.IntegerField(default=0)
    packets_received = models.IntegerField(default=0)
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)

    # Timing features
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    duration_seconds = models.FloatField(default=0.0)

    # Behavioural features
    avg_packet_size = models.FloatField(default=0.0)
    packets_per_second = models.FloatField(default=0.0)
    bytes_ratio = models.FloatField(default=0.0)      # sent / (sent+received)
    unique_dst_ports = models.IntegerField(default=1)
    payload_entropy = models.FloatField(default=0.0)
    tcp_flags_seen = models.CharField(max_length=40, blank=True)

    # Application-layer metadata
    app_protocol = models.CharField(max_length=20, blank=True)
    dns_query_count = models.IntegerField(default=0)
    longest_dns_label = models.IntegerField(default=0)
    http_host = models.CharField(max_length=255, blank=True)
    tls_sni = models.CharField(max_length=255, blank=True)
    ja3_hash = models.CharField(max_length=64, blank=True)

    # Filled in by Phase 3
    is_analyzed = models.BooleanField(default=False)
    anomaly_score = models.FloatField(null=True, blank=True)
    risk_score = models.IntegerField(null=True, blank=True)

    class Meta:
        ordering = ['-last_seen']
        indexes = [
            models.Index(fields=['src_ip']),
            models.Index(fields=['dst_ip']),
            models.Index(fields=['session', 'last_seen']),
            models.Index(fields=['risk_score']),
        ]

    def __str__(self):
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port} [{self.protocol}]"


class DNSRecord(models.Model):
    """DNS queries — the primary signal for tunneling detection."""

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name='dns_records',
    )
    flow = models.ForeignKey(
        Flow, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='dns_records',
    )

    src_ip = models.GenericIPAddressField()
    query_name = models.CharField(max_length=512)
    query_type = models.CharField(max_length=12, blank=True)
    response_ip = models.CharField(max_length=64, blank=True)

    subdomain_length = models.IntegerField(default=0)
    label_count = models.IntegerField(default=0)
    query_entropy = models.FloatField(default=0.0)

    timestamp = models.DateTimeField()

    class Meta:
        ordering = ['-timestamp']
        indexes = [models.Index(fields=['session', 'timestamp'])]

    def __str__(self):
        return f"{self.src_ip} → {self.query_name}"