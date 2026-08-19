"""
TCP stream reassembly, and honest reporting of where it is uncertain.

The problem this has to face
----------------------------
Reassembling a TCP stream is not concatenation. Segments arrive out of order,
get retransmitted, and can overlap while carrying *different bytes* for the
same sequence range. Ptacek and Newsham showed in 1998 that operating systems
resolve those overlaps differently — some keep the first arrival, some the
last — which means the reconstructed conversation depends on an assumption
about the machine that received it.

Intrusion detection solves this by guessing: Snort's target-based reassembly is
configured with the destination OS so the sensor reassembles the way the victim
would. That is the right answer for a sensor, whose job is to predict what the
target saw.

It is the wrong answer here. A forensic examiner is not predicting; they are
testifying. So this module does not guess an OS and does not silently pick a
winner. It keeps the first arrival, states that it does, and — when a later
segment contradicts an earlier one — records the conflict and reports the
reconstruction as ambiguous. An examiner shown a conversation is shown, in the
same breath, whether anyone could have made it say something else.

What it also refuses to do
--------------------------
It never invents bytes. A gap in the capture — a segment that was never
recorded — ends the current run and starts a new one at the correct offset,
rather than being padded with zeros or closed up. A capture that missed the
middle of a file transfer must not produce a file that looks complete.

Nothing is stored
-----------------
Reconstruction reads the sealed exhibit and returns bytes to the caller. The
decoded content of a communication is not written into the analysis database:
a working table full of message bodies is a second copy of the intercepted
material, in a place with weaker handling than the exhibit it came from.
"""

import socket
import struct
from dataclasses import dataclass, field

SEQ_SPACE = 1 << 32
SEQ_HALF = 1 << 31

# Per direction. A conversation larger than this is reported truncated rather
# than read into memory whole; the number is a working limit for a review pane,
# not a claim about what TCP can carry.
MAX_STREAM_BYTES = 32 * 1024 * 1024

POLICY = 'first-arrival'


@dataclass
class Conflict:
    """Two segments claimed the same sequence range and disagreed."""
    offset: int
    length: int
    kept_from_packet: int
    contradicted_by_packet: int

    def describe(self):
        return (
            f'{self.length} byte(s) at offset {self.offset}: packet '
            f'#{self.contradicted_by_packet} re-sent this range with different '
            f'content from packet #{self.kept_from_packet}. The first arrival '
            f'was kept; a receiving host might have kept the other.'
        )


@dataclass
class Gap:
    """A sequence range that no captured packet carried."""
    offset: int
    length: int

    def describe(self):
        return (f'{self.length} byte(s) missing at offset {self.offset} — '
                f'never captured.')


@dataclass
class Stream:
    """One direction of a conversation, plus what is wrong with it."""
    src: str = ''
    dst: str = ''
    src_port: int = 0
    dst_port: int = 0
    # Contiguous runs of recovered bytes as (offset, data). More than one run
    # means the capture has holes in it.
    runs: list = field(default_factory=list)
    gaps: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    retransmissions: int = 0
    started_mid_stream: bool = False
    truncated: bool = False
    bytes_recovered: int = 0

    @property
    def is_ambiguous(self):
        """
        True when the reconstruction is not the only defensible one.

        This is the field that belongs in a report. Everything else describes
        how the bytes were obtained; this says whether to rely on them.
        """
        return bool(self.conflicts)

    @property
    def is_complete(self):
        return not self.gaps and not self.started_mid_stream and not self.truncated

    def data(self):
        """The recovered bytes, runs joined. Only meaningful when complete."""
        return b''.join(run[1] for run in self.runs)

    def caveats(self):
        """Everything a reader must be told before believing the content."""
        notes = []
        if self.started_mid_stream:
            notes.append(
                'The capture began after this connection was established, so '
                'the start of the conversation is not present. Offsets are '
                'relative to the first byte captured, not to the first byte '
                'sent.'
            )
        for gap in self.gaps:
            notes.append(gap.describe())
        for conflict in self.conflicts:
            notes.append(conflict.describe())
        if self.retransmissions:
            notes.append(
                f'{self.retransmissions} retransmitted segment(s) carried '
                f'identical bytes and were discarded as duplicates.'
            )
        if self.truncated:
            notes.append(
                f'Reconstruction stopped at {MAX_STREAM_BYTES:,} bytes. The '
                f'conversation continues beyond what is shown.'
            )
        return notes


def _relative(seq, base):
    """Sequence number as an offset from `base`, across the 32-bit wrap."""
    return (seq - base) % SEQ_SPACE


class _DirectionBuilder:
    """Accumulates one direction's segments and resolves them at the end."""

    def __init__(self):
        self.segments = []      # (relative_seq, data, packet_index)
        self.base = None
        self.saw_syn = False

    def note_syn(self, seq):
        # The SYN consumes one sequence number, so the first data byte is at
        # ISN + 1. Getting this wrong shifts the entire stream by one byte,
        # which is invisible in text and fatal in a binary.
        self.base = (seq + 1) % SEQ_SPACE
        self.saw_syn = True

    def add(self, seq, data, packet_index):
        if not data:
            return
        if self.base is None:
            # No SYN seen: the capture started mid-connection. Anchor on the
            # first data byte we did see and say so, rather than pretending
            # offset 0 is the start of the conversation.
            self.base = seq
        self.segments.append((_relative(seq, self.base), data, packet_index))

    def build(self, stream):
        stream.started_mid_stream = not self.saw_syn and bool(self.segments)
        if not self.segments:
            return stream

        # Stable sort: equal offsets keep capture order, which is what makes
        # "first arrival" mean the first one on the wire.
        self.segments.sort(key=lambda s: s[0])

        # written[offset] -> (byte, packet_index), built as runs.
        recovered = bytearray()
        provenance = []          # packet index per recovered byte
        origin = None            # offset of recovered[0]
        runs = []

        for offset, data, packet_index in self.segments:
            if origin is None:
                origin = offset

            end_of_recovered = origin + len(recovered)

            if offset > end_of_recovered:
                # A hole. Close the current run and start a new one rather
                # than joining across bytes nobody captured.
                if recovered:
                    runs.append((origin, bytes(recovered)))
                stream.gaps.append(Gap(end_of_recovered, offset - end_of_recovered))
                recovered = bytearray()
                provenance = []
                origin = offset

            overlap_start = offset
            overlap_end = min(offset + len(data), origin + len(recovered))
            if overlap_end > overlap_start:
                # This range is already recovered. Compare rather than trust.
                existing = recovered[overlap_start - origin:overlap_end - origin]
                incoming = data[:overlap_end - overlap_start]
                if existing == incoming:
                    stream.retransmissions += 1
                else:
                    # The disagreement is the finding. Report the whole
                    # overlapping range, not the individual differing bytes:
                    # an examiner needs to know which span is contested.
                    kept = provenance[overlap_start - origin]
                    stream.conflicts.append(Conflict(
                        offset=overlap_start,
                        length=overlap_end - overlap_start,
                        kept_from_packet=kept,
                        contradicted_by_packet=packet_index,
                    ))

            fresh = data[max(0, (origin + len(recovered)) - offset):]
            if fresh:
                recovered.extend(fresh)
                provenance.extend([packet_index] * len(fresh))

            if len(recovered) >= MAX_STREAM_BYTES:
                stream.truncated = True
                del recovered[MAX_STREAM_BYTES:]
                break

        if recovered:
            runs.append((origin, bytes(recovered)))

        stream.runs = runs
        stream.bytes_recovered = sum(len(run[1]) for run in runs)
        return stream


@dataclass
class Record:
    """One TCP segment, reduced to the fields reassembly needs."""
    index: int
    src: str
    src_port: int
    dst: str
    dst_port: int
    seq: int
    syn: bool
    payload: bytes


def reassemble_records(records, four_tuple):
    """
    Rebuild both directions of one TCP conversation from normalised records.

    `four_tuple` is (client_ip, client_port, server_ip, server_port) and names
    the direction treated as client-to-server. Getting that the wrong way round
    does not fail loudly — it produces a transcript in which the server appears
    to issue the commands — so callers derive it from the flow's recorded
    initiator rather than from whichever address happens to be in `src_ip`.

    Returns (client_to_server, server_to_client). Either may be empty: a
    connection that was refused carries no payload, which is a fact about the
    capture rather than a failure.
    """
    src_ip, src_port, dst_ip, dst_port = four_tuple
    forward, reverse = _DirectionBuilder(), _DirectionBuilder()

    for record in records:
        key = (record.src, record.src_port, record.dst, record.dst_port)
        if key == (src_ip, src_port, dst_ip, dst_port):
            builder = forward
        elif key == (dst_ip, dst_port, src_ip, src_port):
            builder = reverse
        else:
            continue

        # A SYN — with or without ACK — opens its own direction and consumes
        # one sequence number.
        if record.syn:
            builder.note_syn(record.seq)
        if record.payload:
            builder.add(record.seq, record.payload, record.index)

    c2s = forward.build(Stream(src=src_ip, dst=dst_ip,
                               src_port=src_port, dst_port=dst_port))
    s2c = reverse.build(Stream(src=dst_ip, dst=src_ip,
                               src_port=dst_port, dst_port=src_port))
    return c2s, s2c


def reassemble(packets, four_tuple):
    """Same, from (index, scapy packet) pairs. Used by the tests."""
    from scapy.layers.inet import TCP

    records = []
    for index, packet in packets:
        if TCP not in packet:
            continue
        ip_layer = packet.getlayer('IP') or packet.getlayer('IPv6')
        if ip_layer is None:
            continue
        tcp = packet[TCP]
        records.append(Record(
            index=index, src=ip_layer.src, src_port=tcp.sport,
            dst=ip_layer.dst, dst_port=tcp.dport, seq=tcp.seq,
            syn=bool(tcp.flags.S), payload=bytes(tcp.payload),
        ))
    return reassemble_records(records, four_tuple)


# One conversation is rebuilt by walking the exhibit, so this bounds the walk.
# A capture large enough to hit it will still have produced its flow records;
# only the transcript is affected, and the caller is told the scan stopped.
MAX_PACKETS_SCANNED = 2_000_000

# Link types we know how to strip. Anything else is refused by name rather
# than parsed hopefully — misreading the link layer shifts every offset after
# it and produces a transcript made of the wrong bytes.
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IPV4 = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_RAW = 12
LINKTYPE_LOOPBACK = 0
# DLT_IPV4 / DLT_IPV6. What scapy writes when handed bare IP packets, so any
# capture produced without a link layer arrives with one of these.
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8

IPPROTO_TCP = 6
TCP_SYN = 0x02


class UnsupportedCapture(Exception):
    """The capture's link layer is one this reader will not guess at."""


def _strip_link_layer(raw, linktype):
    """Return (ethertype, offset) for the IP header, or (None, 0)."""
    if linktype == LINKTYPE_IPV4:
        return ETHERTYPE_IPV4, 0
    if linktype == LINKTYPE_IPV6:
        return ETHERTYPE_IPV6, 0
    if linktype in (LINKTYPE_RAW_IPV4, LINKTYPE_RAW):
        # DLT_RAW carries either, distinguished only by the version nibble.
        version = (raw[0] >> 4) if raw else 0
        return ({4: ETHERTYPE_IPV4, 6: ETHERTYPE_IPV6}.get(version), 0)

    if linktype == LINKTYPE_LOOPBACK:
        # 4-byte host-order address family. 2 is AF_INET everywhere; AF_INET6
        # differs per platform, so only v4 is claimed.
        if len(raw) < 4:
            return None, 0
        family = struct.unpack('<I', raw[:4])[0]
        return (ETHERTYPE_IPV4 if family == 2 else None), 4

    if linktype == LINKTYPE_LINUX_SLL:
        if len(raw) < 16:
            return None, 0
        return struct.unpack('!H', raw[14:16])[0], 16

    if linktype != LINKTYPE_ETHERNET:
        raise UnsupportedCapture(
            f'Link type {linktype} is not one this reader understands. The '
            f'flow records for this capture are unaffected; only transcript '
            f'reconstruction needs the link layer stripped.'
        )

    if len(raw) < 14:
        return None, 0
    ethertype = struct.unpack('!H', raw[12:14])[0]
    offset = 14
    # VLAN tags stack. Each adds four bytes and republishes the ethertype.
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        if len(raw) < offset + 4:
            return None, 0
        ethertype = struct.unpack('!H', raw[offset + 2:offset + 4])[0]
        offset += 4
    return ethertype, offset


def _parse_tcp(raw, linktype, index):
    """
    One packet as a Record, or None if it is not TCP over IP.

    The subtlety worth naming: payload length comes from the IP header's total
    length, never from the captured frame. Ethernet pads frames to 60 bytes, so
    a short TCP segment arrives with trailing zeros that are not payload.
    Appending them corrupts the stream in a way that looks like real data.
    """
    ethertype, offset = _strip_link_layer(raw, linktype)

    if ethertype == ETHERTYPE_IPV4:
        if len(raw) < offset + 20:
            return None
        version_ihl = raw[offset]
        header_len = (version_ihl & 0x0F) * 4
        if header_len < 20:
            return None
        total_length, = struct.unpack('!H', raw[offset + 2:offset + 4])
        protocol = raw[offset + 9]
        if protocol != IPPROTO_TCP:
            return None
        src = socket.inet_ntoa(raw[offset + 12:offset + 16])
        dst = socket.inet_ntoa(raw[offset + 16:offset + 20])
        ip_payload_len = total_length - header_len
        tcp_offset = offset + header_len

    elif ethertype == ETHERTYPE_IPV6:
        if len(raw) < offset + 40:
            return None
        payload_length, = struct.unpack('!H', raw[offset + 4:offset + 6])
        next_header = raw[offset + 6]
        # Extension headers are not walked. Returning None loses the segment,
        # which shows up as a gap the reader is told about — better than
        # guessing an offset and inventing bytes.
        if next_header != IPPROTO_TCP:
            return None
        src = socket.inet_ntop(socket.AF_INET6, raw[offset + 8:offset + 24])
        dst = socket.inet_ntop(socket.AF_INET6, raw[offset + 24:offset + 40])
        ip_payload_len = payload_length
        tcp_offset = offset + 40
    else:
        return None

    if len(raw) < tcp_offset + 20:
        return None
    src_port, dst_port, seq = struct.unpack('!HHI', raw[tcp_offset:tcp_offset + 8])
    data_offset = (raw[tcp_offset + 12] >> 4) * 4
    if data_offset < 20:
        return None
    flags = raw[tcp_offset + 13]

    payload_len = ip_payload_len - data_offset
    payload_start = tcp_offset + data_offset
    if payload_len <= 0:
        payload = b''
    else:
        # Never read past what was captured: a snaplen-truncated packet claims
        # more payload in its header than the file holds.
        payload = raw[payload_start:payload_start + payload_len]

    return Record(index=index, src=src, src_port=src_port, dst=dst,
                  dst_port=dst_port, seq=seq, syn=bool(flags & TCP_SYN),
                  payload=payload)


def conversation_endpoints(flow):
    """
    (client_ip, client_port, server_ip, server_port) for a recorded flow.

    `src_ip` is whichever address appeared first in the capture, which for a
    flow observed from the server side is the server. Orienting a transcript on
    it produces one in which the server issues the commands — wrong, and wrong
    quietly. The aggregator already worked out who opened the connection, so
    that is used whenever it was confirmed.
    """
    if flow.initiator_confirmed and flow.initiator_ip:
        if (flow.initiator_ip, flow.initiator_port) == (flow.dst_ip, flow.dst_port):
            return flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port
    return flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port


def reassemble_flow(pcap_path, flow):
    """
    Rebuild one recorded Flow from the exhibit it came from.

    Headers are parsed directly rather than through a full packet dissector.
    That is not premature optimisation: finding one conversation means walking
    the whole capture, and dissecting every layer of every packet to read four
    fields took forty seconds on a 28 MB exhibit — long enough that nobody
    would use the feature. Only the fields reassembly needs are read.

    Decryption is transparent; `readable` hands back a plaintext path and
    removes it afterwards.
    """
    from scapy.utils import RawPcapReader

    from evidence.crypto import readable

    client_ip, client_port, server_ip, server_port = conversation_endpoints(flow)
    endpoints = {
        (client_ip, client_port, server_ip, server_port),
        (server_ip, server_port, client_ip, client_port),
    }

    records = []
    with readable(pcap_path) as plaintext:
        with RawPcapReader(str(plaintext)) as reader:
            linktype = reader.linktype
            for index, (raw, _meta) in enumerate(reader, start=1):
                if index > MAX_PACKETS_SCANNED:
                    break
                record = _parse_tcp(raw, linktype, index)
                if record is None:
                    continue
                if (record.src, record.src_port,
                        record.dst, record.dst_port) in endpoints:
                    records.append(record)

    return reassemble_records(
        records, (client_ip, client_port, server_ip, server_port))
