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

    # The address space being monitored in THIS capture, in the sense Snort
    # and Suricata use $HOME_NET. Comma-separated CIDRs; blank means fall back
    # to the deployment-wide default in settings.
    #
    # It belongs on the capture and not in settings because the answer is a
    # property of the traffic, not of the install: an office capture is
    # RFC 1918 and a capture of a public-facing server is not. With one global
    # value, loading the second case silently inverts every egress rule
    # applied to the first.
    home_net = models.CharField(max_length=400, blank=True)

    # The sealed exhibit this analysis was run against.
    #
    # Without it, a finding could only be tied back to evidence by matching
    # filenames — which is not a relationship, it is a coincidence that usually
    # holds. The project's whole claim is that an assertion about a network
    # traces to a hashed artefact in custody; that trace has to be a foreign
    # key.
    #
    # PROTECT, not CASCADE: deleting an exhibit must not silently take the
    # analysis of it with it. String reference because evidence links back to
    # capture in the other direction.
    evidence = models.ForeignKey(
        'evidence.EvidenceRecord', null=True, blank=True,
        on_delete=models.PROTECT, related_name='sessions',
    )

    state = models.CharField(max_length=12, choices=State.choices, default=State.RUNNING)

    # When we processed the capture. For an imported PCAP this is the import
    # time and says nothing about when the traffic occurred.
    started_at = models.DateTimeField(auto_now_add=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    # When the traffic actually happened, taken from the packets themselves.
    # Keeping these separate from started_at/ended_at is what lets an analyst
    # testify about the events rather than about our processing run.
    capture_start = models.DateTimeField(null=True, blank=True)
    capture_end = models.DateTimeField(null=True, blank=True)

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

    # 5-tuple identity. src/dst here are the canonical (sorted) endpoints and
    # carry no directional meaning — use initiator_ip for that.
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(default=0)
    dst_port = models.IntegerField(default=0)
    protocol = models.CharField(max_length=12)

    # Who opened the conversation. Confirmed by a TCP SYN where available,
    # otherwise inferred from the first packet observed. Everything
    # directional (bytes_sent, bytes_ratio) is measured relative to this.
    initiator_ip = models.GenericIPAddressField(null=True, blank=True)
    initiator_port = models.IntegerField(default=0)
    initiator_confirmed = models.BooleanField(default=False)

    # Volume features
    packets_sent = models.IntegerField(default=0)
    packets_received = models.IntegerField(default=0)
    bytes_sent = models.BigIntegerField(default=0)
    bytes_received = models.BigIntegerField(default=0)

    # Timing features, derived from packet timestamps
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    duration_seconds = models.FloatField(default=0.0)

    # Inter-packet gap statistics — the basis of beaconing detection.
    interval_count = models.IntegerField(default=0)
    interval_mean = models.FloatField(default=0.0)
    interval_median = models.FloatField(default=0.0)
    interval_stddev = models.FloatField(default=0.0)
    interval_mad = models.FloatField(default=0.0)
    interval_dispersion = models.FloatField(default=0.0)

    # Behavioural features
    avg_packet_size = models.FloatField(default=0.0)
    packets_per_second = models.FloatField(default=0.0)
    bytes_ratio = models.FloatField(default=0.0)      # sent / (sent+received)
    unique_dst_ports = models.IntegerField(default=1)
    payload_entropy = models.FloatField(default=0.0)
    # Number of samples behind payload_entropy — see MAX_ENTROPY_SAMPLES.
    entropy_sample_count = models.IntegerField(default=0)
    tcp_flags_seen = models.CharField(max_length=40, blank=True)

    # Application-layer metadata
    app_protocol = models.CharField(max_length=20, blank=True)
    # Whether app_protocol was read off the wire or guessed from the port.
    # "SSH because the port was 22" and "TLS because we parsed a ClientHello"
    # are different claims, and only one of them survives a tunnel hiding on
    # a permitted port.
    app_protocol_source = models.CharField(
        max_length=10, blank=True,
        choices=[('observed', 'Observed in the payload'),
                 ('port', 'Inferred from the port number')],
    )
    dns_query_count = models.IntegerField(default=0)
    longest_dns_label = models.IntegerField(default=0)
    max_dns_entropy = models.FloatField(default=0.0)
    http_host = models.CharField(max_length=255, blank=True)
    tls_sni = models.CharField(max_length=255, blank=True)
    # JA4, not JA3. Salesforce retired JA3 and its own README points at
    # FoxIO's successor; since Chrome 110 randomised ClientHello extension
    # order in 2023, a real browser produces a different JA3 every connection,
    # so the hash stops identifying anything. JA4 sorts the lists before
    # hashing, which is exactly what survives that. See capture/tls_fingerprint.py.
    #
    # ja4_raw keeps the sorted cipher and extension lists in the clear: an
    # analyst asked in court why two flows share a fingerprint can point at
    # the values, not at twelve hex characters.
    ja4_fingerprint = models.CharField(max_length=64, blank=True, db_index=True)
    ja4_raw = models.TextField(blank=True)

    # Populated by the detection engine (capture/detection.py).
    # risk_score is the 0-100 rollup of matched rules.
    #
    # There was an `anomaly_score` here too, documented as "the separate
    # unsupervised score". No unsupervised model exists in this codebase, so
    # the column was always null and the API published a field that would
    # never carry a value. It is gone rather than filled with something
    # invented; if a model is ever trained, the field comes back with it.
    is_analyzed = models.BooleanField(default=False)
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
    # Addresses the reply carried, comma-separated. A/AAAA only: CNAME and
    # NS records answer a different question than 'where did this resolve'.
    response_ip = models.CharField(max_length=255, blank=True)

    subdomain_length = models.IntegerField(default=0)
    label_count = models.IntegerField(default=0)
    query_entropy = models.FloatField(default=0.0)

    timestamp = models.DateTimeField()

    class Meta:
        ordering = ['-timestamp']
        indexes = [models.Index(fields=['session', 'timestamp'])]

    def __str__(self):
        return f"{self.src_ip} → {self.query_name}"


class Detection(models.Model):
    """
    A single finding against a flow or host, produced by a named rule.

    Each row carries the rule that fired, the observed values that triggered
    it, and the threshold it was compared against. An investigator asked
    "why is this flagged?" in court can read the answer off the record
    instead of appealing to a model's judgement — which is the reason
    detection is rules-first here.
    """

    class Severity(models.TextChoices):
        LOW = 'low', 'Low'
        MEDIUM = 'medium', 'Medium'
        HIGH = 'high', 'High'
        CRITICAL = 'critical', 'Critical'


    class Method(models.TextChoices):
        RULE = 'rule', 'Deterministic rule'
        MODEL = 'model', 'Unsupervised model'

    session = models.ForeignKey(
        CaptureSession, on_delete=models.CASCADE, related_name='detections',
    )
    flow = models.ForeignKey(
        Flow, null=True, blank=True,
        on_delete=models.CASCADE, related_name='detections',
    )

    rule_id = models.CharField(max_length=64)
    title = models.CharField(max_length=200)
    category = models.CharField(max_length=40)
    severity = models.CharField(max_length=10, choices=Severity.choices)
    method = models.CharField(max_length=10, choices=Method.choices, default=Method.RULE)

    # 0.0-1.0. For rules this reflects how far past the threshold the
    # observation sits, not a probability of maliciousness.
    confidence = models.FloatField(default=0.0)

    # Plain-language explanation shown to the investigator and printed into
    # the evidence report.
    rationale = models.TextField()

    # The numbers behind the finding: {"observed": ..., "threshold": ...,
    # "source": "<citation for the threshold>"}.
    evidence = models.JSONField(default=dict, blank=True)

    subject_ip = models.GenericIPAddressField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # ── Analyst review (human-in-the-loop) ──
    # Nothing here is auto-actioned. A detection is a prompt for a human to
    # look, and the machine's opinion is never the final word on the record —
    # which is both good SOC practice and the only defensible posture when the
    # output may end up in a chargesheet.
    class Triage(models.TextChoices):
        NEW = 'new', 'Awaiting review'
        CONFIRMED = 'confirmed', 'Confirmed by analyst'
        DISMISSED = 'dismissed', 'Dismissed — false positive'
        ESCALATED = 'escalated', 'Escalated'

    severity_rank = models.PositiveSmallIntegerField(
        default=0, db_index=True,
        help_text='Numeric rank of severity, so ordering is by urgency rather '
                  'than by the alphabet.',
    )

    triage_status = models.CharField(
        max_length=12, choices=Triage.choices, default=Triage.NEW, db_index=True,
    )
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='reviewed_detections',
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    review_note = models.TextField(blank=True)

    class Meta:
        # Ordering by the severity CharField sorts alphabetically, and
        # descending that gives medium > low > high > critical — the Findings
        # list would put medium- and low-severity rows *above* critical ones
        # under severity-coloured chips implying rank. severity_rank is the
        # explicit ordering key; see severity_rank_for().
        ordering = ['-severity_rank', '-confidence']

        # These were written inside save() rather than here, so none of them
        # existed. Every one backs a query the API actually issues: the
        # dashboard's severity breakdown, the per-rule counts, and the search
        # by subject address.
        indexes = [
            models.Index(fields=['session', 'severity']),
            models.Index(fields=['rule_id']),
            models.Index(fields=['subject_ip']),
        ]

    @staticmethod
    def severity_rank_for(severity):
        """
        The 0-100 weight for a severity, from the published thresholds.

        The table used to be duplicated here as bare literals while
        detection.py derived its copy from THRESHOLDS and called itself the
        "single source of truth". Both were live on different write paths —
        bulk_create through detection.py, individual saves through here — and
        they agreed only by coincidence. Retuning a published threshold would
        have left the two disagreeing with no test to notice.

        Imported inside the call because detection.py imports this module.
        """
        from .detection import SEVERITY_WEIGHT

        return SEVERITY_WEIGHT.get(severity, 0)

    def save(self, *args, **kwargs):
        # Denormalised so the database can order on it; bulk_create bypasses
        # save(), so analyse_session sets it explicitly too.
        self.severity_rank = self.severity_rank_for(self.severity)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"[{self.severity}] {self.rule_id} · {self.subject_ip or '-'}"

class IOCFeed(models.Model):
    """
    A threat-intelligence feed, as imported from a file.

    Why a file and never a fetch
    ---------------------------
    The obvious design is for the analysis node to download the feed. It is
    also wrong twice over. The examination workstation is air-gapped, so it
    cannot; and if it could, it should not — an evidence machine that opens
    outbound connections while a capture is loaded has just introduced traffic
    of its own into an environment whose whole purpose is establishing what
    traffic existed. The feed is downloaded elsewhere, carried in, and imported
    with its provenance recorded.

    What provenance means here
    --------------------------
    A blocklist match is an assertion by a third party, and its worth depends
    entirely on facts about the file: which list, obtained from where, when,
    and hashing to what. `retrieved_on` is **stated by the importing officer**
    rather than inferred from a file timestamp, because a copied file's mtime
    says when it was copied.

    The reason this matters is staleness. Addresses are reassigned. A blocklist
    downloaded a year after a capture may name an address that belonged to
    somebody else entirely at the time the packets were recorded, and a finding
    that does not disclose the gap between the two dates is an accusation with
    a hole in it. `capture/ioc.py` computes and reports that gap on every
    match.
    """

    class Format(models.TextChoices):
        FEODO_IP = 'feodo_ip', 'abuse.ch Feodo Tracker — IP blocklist CSV'
        URLHAUS = 'urlhaus', 'abuse.ch URLhaus — URL CSV'
        PLAIN_IP = 'plain_ip', 'Plain list — one address per line'
        PLAIN_DOMAIN = 'plain_domain', 'Plain list — one domain per line'

    name = models.CharField(max_length=160)
    # Where the officer says it came from. Recorded verbatim; never fetched.
    source = models.CharField(max_length=500, blank=True)
    fmt = models.CharField(max_length=20, choices=Format.choices)

    file_name = models.CharField(max_length=255, blank=True)
    file_sha256 = models.CharField(max_length=64)
    file_bytes = models.BigIntegerField(default=0)

    # Stated at import, not read off the filesystem.
    retrieved_on = models.DateField()
    # Some feeds carry their own generation timestamp in a header comment. Null
    # when the file does not say, rather than filled in with the import date.
    published_on = models.DateTimeField(null=True, blank=True)

    licence = models.CharField(max_length=200, blank=True)
    notes = models.TextField(blank=True)

    entry_count = models.IntegerField(default=0)
    imported_at = models.DateTimeField(auto_now_add=True)
    imported_by = models.ForeignKey(
        'accounts.User', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='ioc_feeds',
    )

    class Meta:
        ordering = ['-retrieved_on', '-imported_at']

    def __str__(self):
        return f'{self.name} ({self.retrieved_on})'


class IOCIndicator(models.Model):
    """
    One entry from a feed.

    `source_line` keeps the row exactly as the file had it. A finding quotes it
    rather than paraphrasing, so an officer asked "where does this claim come
    from" can answer with the line and the file's digest instead of with the
    name of a website.
    """

    class Kind(models.TextChoices):
        IPV4 = 'ipv4', 'IPv4 address'
        IPV6 = 'ipv6', 'IPv6 address'
        DOMAIN = 'domain', 'Domain name'
        URL = 'url', 'URL'

        # There is deliberately no JA3 kind. abuse.ch's SSL blocklist publishes
        # JA3 MD5s; this tool computes JA4, and the two are different
        # constructions over different inputs — a JA3 hash cannot be compared
        # against a JA4 string, and no arrangement of them makes it possible.
        # Importing JA3 indicators would produce a feed that loads cleanly,
        # reports a healthy entry count and can never match anything, which is
        # worse than not supporting the format at all.

    feed = models.ForeignKey(
        IOCFeed, on_delete=models.CASCADE, related_name='indicators',
    )
    kind = models.CharField(max_length=10, choices=Kind.choices)
    value = models.CharField(max_length=512)
    # Whatever the feed said about it — malware family, port, confidence.
    context = models.CharField(max_length=300, blank=True)
    # The date the feed itself attributes to the entry, where it carries one.
    listed_on = models.DateTimeField(null=True, blank=True)
    source_line = models.TextField(blank=True)

    class Meta:
        unique_together = [('feed', 'kind', 'value')]
        indexes = [
            models.Index(fields=['kind', 'value']),
        ]

    def __str__(self):
        return f'{self.kind}:{self.value}'
