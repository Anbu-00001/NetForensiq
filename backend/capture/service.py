import time
from django.utils import timezone
from django.db import transaction

from scapy.all import sniff, rdpcap, conf

from .models import CaptureSession, Flow, DNSRecord
from .processor import FlowAggregator


def resolve_interface(index_or_name):
    """Accept either a Scapy interface index or a raw device name."""
    try:
        return conf.ifaces.dev_from_index(int(index_or_name))
    except (ValueError, KeyError):
        return index_or_name


@transaction.atomic
def persist_results(session, flows, dns_records, aggregator):
    """Write aggregated flows and DNS records into PostgreSQL in bulk."""

    flow_objects = []
    key_to_index = {}

    for idx, f in enumerate(flows):
        key = f.pop('_key')
        key_to_index[key] = idx
        flow_objects.append(Flow(session=session, **f))

    created_flows = Flow.objects.bulk_create(flow_objects, batch_size=500)

    dns_objects = []
    for rec in dns_records:
        fkey = rec.pop('flow_key', None)
        linked_flow = None
        if fkey is not None and fkey in key_to_index:
            linked_flow = created_flows[key_to_index[fkey]]
        dns_objects.append(DNSRecord(session=session, flow=linked_flow, **rec))

    DNSRecord.objects.bulk_create(dns_objects, batch_size=500)

    session.packet_count = aggregator.total_packets
    session.byte_count = aggregator.total_bytes
    session.flow_count = len(created_flows)
    session.ended_at = timezone.now()
    session.state = CaptureSession.State.COMPLETED
    session.save()

    return len(created_flows), len(dns_objects)


def run_live_capture(interface, packet_count=0, duration=0, bpf_filter='', name=None, user=None):
    """Sniff live traffic and persist the resulting flows."""

    iface = resolve_interface(interface)

    session = CaptureSession.objects.create(
        name=name or f"Live capture {timezone.now():%Y-%m-%d %H:%M:%S}",
        source_type=CaptureSession.Source.LIVE,
        interface=str(iface),
        bpf_filter=bpf_filter,
        state=CaptureSession.State.RUNNING,
        started_by=user,
    )

    aggregator = FlowAggregator()

    try:
        sniff_kwargs = {
            'iface': iface,
            'prn': aggregator.process,
            'store': False,
        }
        if packet_count:
            sniff_kwargs['count'] = packet_count
        if duration:
            sniff_kwargs['timeout'] = duration
        if bpf_filter:
            sniff_kwargs['filter'] = bpf_filter

        sniff(**sniff_kwargs)

    except KeyboardInterrupt:
        pass
    except Exception as exc:
        session.state = CaptureSession.State.FAILED
        session.error_message = str(exc)
        session.ended_at = timezone.now()
        session.save()
        raise

    flows, dns_records = aggregator.finalize()
    return session, persist_results(session, flows, dns_records, aggregator)


def run_pcap_import(pcap_path, name=None, user=None):
    """Read a stored PCAP file and persist the resulting flows."""

    session = CaptureSession.objects.create(
        name=name or f"PCAP import {timezone.now():%Y-%m-%d %H:%M:%S}",
        source_type=CaptureSession.Source.PCAP,
        pcap_filename=str(pcap_path),
        state=CaptureSession.State.RUNNING,
        started_by=user,
    )

    aggregator = FlowAggregator()

    try:
        packets = rdpcap(str(pcap_path))
        for pkt in packets:
            aggregator.process(pkt)
    except Exception as exc:
        session.state = CaptureSession.State.FAILED
        session.error_message = str(exc)
        session.ended_at = timezone.now()
        session.save()
        raise

    flows, dns_records = aggregator.finalize()
    return session, persist_results(session, flows, dns_records, aggregator)