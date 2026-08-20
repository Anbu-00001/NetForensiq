import time
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone
from django.db import transaction

from scapy.all import sniff, conf
from scapy.utils import PcapReader

from .models import CaptureSession, Flow, DNSRecord
from .processor import FlowAggregator


def resolve_interface(index_or_name):
    """Accept either a Scapy interface index or a raw device name."""
    try:
        return conf.ifaces.dev_from_index(int(index_or_name))
    except (ValueError, KeyError):
        return index_or_name


def _utc(ts):
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc) if ts else None


@transaction.atomic
def persist_results(session, flows, dns_records, aggregator):
    """Write aggregated flows and DNS records into the database in bulk."""

    flow_objects = []
    key_to_index = {}

    for idx, f in enumerate(flows):
        record = dict(f)
        # Flows are identified by a unique id, not by 5-tuple: with idle
        # timeouts one tuple can produce many flows, and keying by tuple would
        # attach every DNS record to whichever of them happened to be last.
        uid = record.pop('_uid')
        record.pop('_timestamps', None)          # timing already reduced to features
        key_to_index[uid] = idx
        flow_objects.append(Flow(session=session, **record))

    created_flows = Flow.objects.bulk_create(flow_objects, batch_size=500)

    dns_objects = []
    for rec in dns_records:
        record = dict(rec)
        fkey = record.pop('flow_uid', None)
        linked_flow = None
        if fkey is not None and fkey in key_to_index:
            linked_flow = created_flows[key_to_index[fkey]]
        dns_objects.append(DNSRecord(session=session, flow=linked_flow, **record))

    DNSRecord.objects.bulk_create(dns_objects, batch_size=500)

    session.packet_count = aggregator.total_packets
    session.byte_count = aggregator.total_bytes
    session.flow_count = len(created_flows)
    session.capture_start = _utc(aggregator.first_packet_time)
    session.capture_end = _utc(aggregator.last_packet_time)
    session.ended_at = timezone.now()
    session.state = CaptureSession.State.COMPLETED
    session.save()

    return len(created_flows), len(dns_objects)


def _fail(session, exc):
    session.state = CaptureSession.State.FAILED
    session.error_message = str(exc)
    session.ended_at = timezone.now()
    session.save()


def run_live_capture(interface, packet_count=0, duration=0, bpf_filter='',
                     name=None, user=None, window_seconds=0, home_net='',
                     on_window=None, should_stop=None, on_session=None):
    """
    Sniff live traffic and persist the resulting flows.

    With `window_seconds` set, this becomes a monitoring loop rather than a
    recording: every window the accumulated traffic is re-derived, every rule
    is run over it, and findings that were not present last time are pushed to
    the configured alert sinks. Latency to an alert is one window, not the
    length of the capture.

    Why detection runs over the whole session and not over the window
    ----------------------------------------------------------------
    Because the interesting findings are not visible in a window. A beacon
    calling home every 45 seconds is a claim about a time series; a 30-second
    slice of it is two packets and no periodicity. Re-deriving the full session
    each pass is more work than analysing a slice and it is the only thing that
    can find what these rules look for. It also means a finding never appears,
    disappears and reappears as the window moves under it.

    "Offline" does not mean "not live"
    ----------------------------------
    An air-gapped machine has no route to the internet. It still has a network
    interface, and a NIC in promiscuous mode on a mirror port sees traffic in
    real time. Isolated networks are where local detection matters most,
    precisely because nothing on them can phone a cloud for an opinion.
    `should_stop` is polled once per window so a caller outside this thread —
    the browser, via `capture.monitor` — can ask for the loop to finish. It is
    checked between windows rather than inside one: the window persists flows
    and runs detection, and stopping halfway leaves a session holding traffic
    nothing has been analysed against, which looks exactly like a capture in
    which nothing was found.

    `on_session` fires once, as soon as the row exists, so a caller can report
    which session it is watching without waiting a whole window for the first
    result.
    """
    iface = resolve_interface(interface)

    session = CaptureSession.objects.create(
        name=name or f"Live capture {timezone.now():%Y-%m-%d %H:%M:%S}",
        source_type=CaptureSession.Source.LIVE,
        interface=str(iface),
        bpf_filter=bpf_filter,
        state=CaptureSession.State.RUNNING,
        started_by=user,
        home_net=home_net or '',
    )

    if on_session:
        on_session(session)

    if window_seconds > 0:
        return _run_live_monitor(session, iface, packet_count, duration,
                                 bpf_filter, window_seconds, on_window,
                                 should_stop)

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
        _fail(session, exc)
        raise

    flows, dns_records = aggregator.finalize()
    return session, persist_results(session, flows, dns_records, aggregator)


def _fingerprint(finding):
    """
    What makes two findings across two windows 'the same finding'.

    The rule that fired, who it is about, and what it said. Matching on the
    database id would alert again every window, because each pass rewrites the
    rows; matching on the claim does not.
    """
    return (finding.rule_id, finding.subject_ip, finding.title)


def _run_live_monitor(session, iface, packet_count, duration, bpf_filter,
                      window_seconds, on_window, should_stop=None):
    """The monitoring loop. See run_live_capture for why it is shaped this way."""
    from scapy.sendrecv import AsyncSniffer

    from .alerting import dispatch
    from .detection import analyse_session

    aggregator = FlowAggregator(thread_safe=True)

    sniff_kwargs = {'iface': iface, 'prn': aggregator.process, 'store': False}
    if bpf_filter:
        sniff_kwargs['filter'] = bpf_filter

    sniffer = AsyncSniffer(**sniff_kwargs)
    sniffer.start()

    already_alerted = set()
    started = time.monotonic()
    windows = 0

    try:
        while True:
            # Slept in short steps rather than one long sleep, so a stop
            # request is honoured in about a second instead of being sat on
            # for the rest of a five-minute window. The window itself is
            # unchanged — only the responsiveness of the stop.
            waited = 0.0
            while waited < window_seconds:
                if should_stop and should_stop():
                    break
                step = min(1.0, window_seconds - waited)
                time.sleep(step)
                waited += step

            stopping = bool(should_stop and should_stop())
            windows += 1

            flows, dns_records = aggregator.finalize()
            # Replace rather than append. The aggregator holds the whole
            # session, so appending would duplicate every flow seen so far on
            # every pass.
            session.flows.all().delete()
            persist_results(session, flows, dns_records, aggregator)

            summary = analyse_session(session, dispatch_alerts=False)

            fresh = [f for f in session.detections.all()
                     if _fingerprint(f) not in already_alerted]
            deliveries = dispatch(fresh, session=session) if fresh else []
            already_alerted.update(_fingerprint(f) for f in fresh)

            if on_window:
                on_window({
                    'window': windows,
                    'elapsed_seconds': round(time.monotonic() - started, 1),
                    'packets': aggregator.total_packets,
                    'flows': len(flows),
                    'findings_total': summary['total'],
                    'findings_new': len(fresh),
                    'new': [f.title for f in fresh],
                    'alerts': [d.as_dict() for d in deliveries],
                })

            if stopping:
                break
            if duration and (time.monotonic() - started) >= duration:
                break
            if packet_count and aggregator.total_packets >= packet_count:
                break

    except KeyboardInterrupt:
        pass
    finally:
        # Always stop the sniffer thread. Without this an interrupted capture
        # leaves it running against a session that is already finished.
        try:
            sniffer.stop()
        except Exception:
            pass

    flows, dns_records = aggregator.finalize()
    session.flows.all().delete()
    counts = persist_results(session, flows, dns_records, aggregator)
    analyse_session(session, dispatch_alerts=False)
    return session, counts


def run_pcap_import(pcap_path, name=None, user=None, session=None, home_net='',
                    evidence=None):
    """
    Read a stored PCAP and persist the resulting flows.

    Packets are streamed with PcapReader rather than loaded via rdpcap, so
    memory scales with the number of distinct conversations rather than with
    file size — police captures are routinely multi-gigabyte.

    When the evidence store is encrypted the sealed copy is decrypted to a
    private temporary file for the duration of the read and removed afterwards.
    That happens here, at the one point every caller goes through, rather than
    at each of the three call sites — a decryption wrapper that three callers
    have to remember to apply is a decryption wrapper one of them will forget.
    """
    from evidence.crypto import readable

    with readable(pcap_path) as plaintext:
        return _import_from(plaintext, pcap_path, name, user, session, home_net,
                            evidence)


def _import_from(plaintext_path, recorded_path, name, user, session, home_net,
                 evidence):
    # `recorded_path` is what goes in the session record: the exhibit's place
    # in the evidence store, not the temporary file it was decrypted into,
    # which will not exist by the time anyone reads the session back.
    session = session or CaptureSession.objects.create(
        name=name or f"PCAP import {timezone.now():%Y-%m-%d %H:%M:%S}",
        source_type=CaptureSession.Source.PCAP,
        pcap_filename=str(recorded_path),
        state=CaptureSession.State.RUNNING,
        started_by=user,
        home_net=home_net or '',
        evidence=evidence,
    )

    aggregator = FlowAggregator()

    try:
        with PcapReader(str(plaintext_path)) as reader:
            for pkt in reader:
                aggregator.process(pkt)
    except Exception as exc:
        _fail(session, exc)
        raise

    flows, dns_records = aggregator.finalize()
    return session, persist_results(session, flows, dns_records, aggregator)
