from django.contrib import admin
from .models import CaptureSession, Flow, DNSRecord


@admin.register(CaptureSession)
class CaptureSessionAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'source_type', 'state', 'packet_count', 'flow_count', 'started_at')
    list_filter = ('source_type', 'state')
    search_fields = ('name', 'interface', 'pcap_filename')


@admin.register(Flow)
class FlowAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol',
        'app_protocol', 'bytes_sent', 'bytes_received', 'payload_entropy', 'risk_score',
    )
    list_filter = ('protocol', 'app_protocol', 'is_analyzed')
    search_fields = ('src_ip', 'dst_ip', 'tls_sni', 'http_host')


@admin.register(DNSRecord)
class DNSRecordAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'src_ip', 'query_name', 'subdomain_length', 'query_entropy')
    search_fields = ('query_name', 'src_ip')