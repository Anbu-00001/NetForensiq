# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
import os
import time
from datetime import datetime, timezone as dt_timezone

from django.utils import timezone
from django.db import transaction

from scapy.all import sniff, conf
from scapy.utils import PcapReader

from . import fastparse
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


# How many flow rows go into one database transaction.
#
# The figure is not about insert throughput, which barely moves across two
# orders of magnitude here. It is about how long the write lock is held:
# SQLite allows "only one writer at a time" (sqlite.org/wal.html s.2.2), and
# Django is configured to BEGIN IMMEDIATE, so a transaction takes that lock
# when it opens and holds it until it commits. Everything else that writes —
# an officer signing in, a triage decision, the audit log — waits behind it,
# and gives up after SQLITE_TIMEOUT seconds.
#
# Importing a 500,000-packet capture in one transaction held the lock for
# about 100 seconds and a sign-in during it failed with HTTP 500 after 42.4 s
# (research/155 s.4.1). 2,000 rows is roughly 0.1 s of lock, so a waiting
# writer gets in within the 30 s timeout many times over.
PERSIST_BATCH_FLOWS = 2000

# How often the reader stops to write out what can no longer change.
#
# Counted in packets rather than seconds so that the same file always produces
# the same batches: a capture re-imported on a busier machine must yield the
# same rows, and a wall-clock cadence would not.
TICK_PACKETS = 50_000

# A capture file's bytes that are not frame bytes: per-packet record headers
# and the file header. Used only to estimate how far through a file an import
# has read — see `_progress_bytes`.
PCAP_RECORD_HEADER_BYTES = 16
PCAP_FILE_HEADER_BYTES = 24


def _flow_model(session, record):
    """One in-memory flow record as an unsaved Flow row, and its uid."""
    record = dict(record)
    # Flows are identified by a unique id, not by 5-tuple: with idle
    # timeouts one tuple can produce many flows, and keying by tuple would
    # attach every DNS record to whichever of them happened to be last.
    uid = record.pop('_uid')
    record.pop('_timestamps', None)          # timing already reduced to features
    return uid, Flow(session=session, **record)


@transaction.atomic
def write_flow_batch(session, records, dns_uids, flow_ids):
    """
    Write one batch of flows, in one short transaction.

    `flow_ids` is filled in for the flows that carried a DNS query, and only
    those: their primary keys are needed at the end to link DNS records, and
    remembering every key would put the table back in memory that writing in
    batches exists to get out of it.
    """
    uids, objects = [], []
    for record in records:
        uid, flow = _flow_model(session, record)
        uids.append(uid)
        objects.append(flow)

    created = Flow.objects.bulk_create(objects, batch_size=500)
    for uid, flow in zip(uids, created):
        if uid in dns_uids:
            flow_ids[uid] = flow.pk
    return len(created)


def write_dns_records(session, dns_records, flow_ids, batch=PERSIST_BATCH_FLOWS):
    """Write the DNS records, linked to the flows that carried them."""
    written = 0
    for start in range(0, len(dns_records), batch):
        objects = []
        for rec in dns_records[start:start + batch]:
            record = dict(rec)
            uid = record.pop('flow_uid', None)
            objects.append(DNSRecord(
                session=session, flow_id=flow_ids.get(uid), **record))
        with transaction.atomic():
            DNSRecord.objects.bulk_create(objects, batch_size=500)
        written += len(objects)
    return written


@transaction.atomic
def persist_results(session, flows, dns_records, aggregator):
    """
    Write aggregated flows and DNS records into the database in bulk.

    The whole-session path, used by live capture: a window's worth of flows is
    small, it is replaced wholesale every window, and one transaction is the
    right shape for that. The import path writes in batches as it reads —
    see `_import_from`.
    """
    flow_ids = {}
    dns_uids = aggregator.dns_flow_uids
    flow_count = 0
    for start in range(0, len(flows), PERSIST_BATCH_FLOWS):
        flow_count += write_flow_batch(
            session, flows[start:start + PERSIST_BATCH_FLOWS], dns_uids, flow_ids)

    dns_count = write_dns_records(session, dns_records, flow_ids)
    record_totals(session, aggregator, flow_count)
    return flow_count, dns_count


def record_totals(session, aggregator, flow_count, finished=True):
    """
    Record what was read. With `finished`, also mark the session complete.

    The import passes `finished=False` and marks it complete only once the
    rules have run. Found while measuring the background import: the session
    was marked COMPLETED the moment the flows were written, so for the 43
    seconds detection then took, a 500,000-packet capture was on screen as a
    *finished* analysis with zero findings — indistinguishable from a capture
    in which nothing was found. That is the exact false reassurance
    `_analyse_after_ingest` exists to prevent, produced one step earlier.
    """
    session.packet_count = aggregator.total_packets
    session.byte_count = aggregator.total_bytes
    session.flow_count = flow_count
    session.capture_start = _utc(aggregator.first_packet_time)
    session.capture_end = _utc(aggregator.last_packet_time)
    # Named fields, not the whole row. The import reports its progress with
    # UPDATE statements while this object is held in memory, so a full save()
    # here writes back the progress figures as they were before the import
    # started and erases every report it made.
    fields = ['packet_count', 'byte_count', 'flow_count', 'capture_start',
              'capture_end']
    if finished:
        session.ended_at = timezone.now()
        session.state = CaptureSession.State.COMPLETED
        fields += ['ended_at', 'state']
    session.save(update_fields=fields)


def mark_completed(session):
    """The session is analysed, and only now says so."""
    session.ended_at = timezone.now()
    session.state = CaptureSession.State.COMPLETED
    session.save(update_fields=['ended_at', 'state'])


def _read_into(aggregator, path, on_tick=None):
    """
    Feed every packet in a capture file to the aggregator.

    Two routes, and the choice is made on one question: can `fastparse` read
    this file's link layer?

    * **It can** — the overwhelmingly common case, Ethernet and the raw-IP and
      Linux-cooked variants — and the frames go straight from disk to the flow
      model without a scapy object being built. On a 2.27 M-packet capture
      that is the difference between reading the file in seconds and reading
      it in minutes.

    * **It cannot** — an unusual link type — and the whole file goes through
      scapy's general dissector instead, exactly as it always did. Slower, and
      correct, which is the right way round for that trade: a capture format
      we have not taught the fast reader must not be parsed by guessing.

    The fallback is per file rather than per packet on purpose. A file half
    parsed by each reader would be a file whose findings depend on which
    packets happened to be readable, and that is not a property anyone can
    testify to.

    `on_tick`, if given, is called every TICK_PACKETS packets. The import path
    uses it to write out the flows that can no longer change and to report how
    far it has got; nothing in the reading itself depends on it.
    """
    linktype = fastparse.linktype_of(path)
    tick_at = TICK_PACKETS if on_tick else 0

    if linktype is not None and fastparse.supports(linktype):
        process_frame = aggregator.process_frame
        for data, timestamp, frame_linktype in fastparse.iter_frames(path):
            process_frame(data, timestamp, frame_linktype)
            if tick_at and aggregator.total_packets >= tick_at:
                on_tick()
                tick_at = aggregator.total_packets + TICK_PACKETS
        return

    with PcapReader(str(path)) as reader:
        for pkt in reader:
            aggregator.process(pkt)
            if tick_at and aggregator.total_packets >= tick_at:
                on_tick()
                tick_at = aggregator.total_packets + TICK_PACKETS


def _analyse_after_ingest(session):
    """
    Run the detection rules over a session that has just been ingested.

    Why this is called from every ingest path
    ========================================
    It was called from only one — the windowed monitor loop — and the gap was
    invisible in the demo, because `seed_demo` analyses each reference capture
    itself after importing it. Every other route in (the browser upload,
    `manage.py import_pcap`, and a one-shot live capture) produced a session
    holding flows and DNS records and **zero findings**, with nothing on
    screen to separate "this capture is clean" from "this capture has never
    been examined".

    For a tool whose output is meant to be evidence those are opposite
    claims, and the reassuring one was the default. An officer would have
    uploaded a capture, seen no findings, and drawn a conclusion the system
    had done no work to support.

    Why alerts are not dispatched
    =============================
    An import describes traffic that already happened, sometimes years ago.
    Paging a duty officer the moment a 2015 capture is loaded would be an
    alert about the act of importing, not about the network — so findings are
    recorded and shown, and the alert sinks are left for the live monitor,
    which is the only path watching something that is still happening.
    """
    from .detection import analyse_session
    return analyse_session(session, dispatch_alerts=False)


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
    counts = persist_results(session, flows, dns_records, aggregator)
    _analyse_after_ingest(session)
    return session, counts


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


def create_import_session(recorded_path, name=None, user=None, home_net='',
                          evidence=None):
    """
    The session row for an import that has not been read yet.

    Split out so that the browser upload can create it, commit, and hand the
    id to a separate process (`capture.importer`) — the row has to exist and
    be visible to another connection before that process can report against
    it.

    `recorded_path` is what goes in the session record: the exhibit's place in
    the evidence store, not the temporary file it may be decrypted into, which
    will not exist by the time anyone reads the session back.
    """
    return CaptureSession.objects.create(
        name=name or f"PCAP import {timezone.now():%Y-%m-%d %H:%M:%S}",
        source_type=CaptureSession.Source.PCAP,
        pcap_filename=str(recorded_path),
        state=CaptureSession.State.RUNNING,
        started_by=user,
        home_net=home_net or '',
        evidence=evidence,
    )


def _import_from(plaintext_path, recorded_path, name, user, session, home_net,
                 evidence):
    session = session or create_import_session(
        recorded_path, name=name, user=user, home_net=home_net, evidence=evidence)

    aggregator = FlowAggregator()
    progress = _Progress(session, aggregator, plaintext_path)
    written = {'flows': 0}
    flow_ids = {}

    def tick():
        """Write out what can no longer change, and say how far we have got."""
        written['flows'] += _write_drained(session, aggregator, flow_ids)
        progress.report(CaptureSession.Stage.READING, written['flows'])

    try:
        _read_into(aggregator, plaintext_path, on_tick=tick)
        written['flows'] += _write_drained(session, aggregator, flow_ids, force=True)
        dns_count = write_dns_records(session, aggregator.dns_output(), flow_ids)
    except Exception as exc:
        _fail(session, exc)
        raise

    # The totals are recorded now — they are true now — but the session is
    # not called finished until the rules have run. See `record_totals`.
    record_totals(session, aggregator, written['flows'], finished=False)
    progress.report(CaptureSession.Stage.ANALYSING, written['flows'])
    _analyse_after_ingest(session)
    mark_completed(session)
    progress.finished()
    return session, (written['flows'], dns_count)


def _write_drained(session, aggregator, flow_ids, force=False):
    """Persist every flow the aggregator can let go of, a batch per transaction."""
    records = aggregator.drain(force=force)
    written = 0
    for start in range(0, len(records), PERSIST_BATCH_FLOWS):
        written += write_flow_batch(
            session, records[start:start + PERSIST_BATCH_FLOWS],
            aggregator.dns_flow_uids, flow_ids)
    return written


class _Progress:
    """
    What the Import page reads while an import is running.

    Why this is on the session row
    ==============================
    The import runs in a process of its own (`importer.py`), so the figures
    have to cross a process boundary to reach the browser. There is already a
    database; `capture.monitor` crossed the same boundary the same way, for
    the same reason — no broker, nothing extra to install on a machine with no
    network.

    Written with `.update()` rather than `save()`: it is one small UPDATE that
    must not overwrite anything else on the row, and it happens between flow
    batches, in its own transaction, so it never extends the lock the batch
    holds.
    """

    def __init__(self, session, aggregator, path):
        self.session = session
        self.aggregator = aggregator
        try:
            self.total_bytes = os.path.getsize(path)
        except OSError:
            self.total_bytes = 0

    def _read_estimate(self):
        """
        Roughly how many bytes of the file have been read.

        Frame bytes plus a per-packet record header, which is exact for
        classic pcap and an underestimate for pcapng, whose block headers and
        padding are larger. So the figure can lag reality and never runs
        ahead of it: an import reaches 100% early rather than appearing to
        stall at 99%. It is a progress bar, and it is labelled as an estimate
        wherever it is shown.
        """
        return (PCAP_FILE_HEADER_BYTES + self.aggregator.total_bytes
                + PCAP_RECORD_HEADER_BYTES * self.aggregator.total_packets)

    def report(self, stage, flows_written):
        CaptureSession.objects.filter(pk=self.session.pk).update(
            progress_stage=stage,
            progress_packets=self.aggregator.total_packets,
            progress_flows=flows_written,
            progress_bytes_read=min(self._read_estimate(), self.total_bytes)
            if self.total_bytes else self._read_estimate(),
            progress_total_bytes=self.total_bytes,
            progress_updated_at=timezone.now(),
        )

    def finished(self):
        CaptureSession.objects.filter(pk=self.session.pk).update(
            progress_stage=CaptureSession.Stage.DONE,
            progress_packets=self.aggregator.total_packets,
            progress_bytes_read=self.total_bytes or self._read_estimate(),
            progress_updated_at=timezone.now(),
        )
