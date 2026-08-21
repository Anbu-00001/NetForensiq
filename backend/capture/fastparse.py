"""
Header extraction straight from the captured bytes, without building a scapy
object for every packet.

Why this exists
===============
Importing a 200 MB / 2.27 M-packet capture took just under nine minutes, and
almost all of it went to one line: `PcapReader` constructing a fully dissected
scapy `Ether` object for every single packet. Measured on that file:

    reading the frames, no dissection at all         3.7 s
    the same frames, dissected by scapy            ~465   s

A factor of a hundred and twenty-five, to produce objects from which this
application reads nine scalars and a byte-slice. Scapy builds a tree of
Python field objects per layer per packet — it is a protocol *workbench*, and
it is excellent at that, but a flow aggregator does not need a workbench.

So the ingest path reads the nine values it actually uses directly out of the
frame with `struct`, and scapy is kept for the two jobs that genuinely need a
dissector: DNS message parsing and the TLS ClientHello fingerprint, both of
which run on a small minority of packets (2.6% and 2.7% of that capture).

What this deliberately does NOT do
==================================
It does not reimplement scapy. It reads Ethernet/VLAN, IPv4/IPv6, TCP/UDP/ICMP
headers — the layers the flow model is defined over — and it returns `None`
for anything it does not recognise, so the caller can fall back. It never
guesses. A frame it cannot read is a frame it says it cannot read.

Truncation is handled by refusing to parse: every accessor is bounds-checked
against the captured length, because a snaplen-truncated capture is normal
evidence, not a corrupt file, and reading past the end of one would invent
port numbers that were never on the wire.

Equivalence with the scapy path is not asserted here, it is tested: see
`tests_fastparse.py`, which runs both parsers over real captures and requires
identical flows, identical DNS records and identical findings.
"""

import socket
from struct import unpack_from

from scapy.utils import RawPcapNgReader, RawPcapReader

# Resolved once. These are hot-loop calls and the attribute lookup is not free.
_inet_ntoa = socket.inet_ntoa
_inet_ntop = socket.inet_ntop
_AF_INET6 = socket.AF_INET6

# EtherTypes we look through or into.
_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_VLAN_TPIDS = (0x8100, 0x88A8, 0x9100)

# IP protocol numbers.
_PROTO_ICMP = 1
_PROTO_TCP = 6
_PROTO_UDP = 17
_PROTO_ICMPV6 = 58

# IPv6 extension headers that are skipped to reach the transport header. Each
# uses the same (next-header, length-in-8-octet-units-minus-one) shape, which
# is why they can be walked generically. Fragment (44) is fixed at 8 bytes and
# is handled as a special case below.
_IPV6_EXT_SKIP = frozenset((0, 43, 51, 60))
_IPV6_FRAGMENT = 44

# Link types this module can read, by libpcap DLT number. Anything absent
# falls back to scapy rather than being guessed at.
#
#   1   Ethernet
#   12  raw IP (BSD / some tunnels)      101  raw IP (Linux convention)
#   228 raw IPv4                         229  raw IPv6
#   113 Linux "cooked" SLL               276  Linux cooked SLL v2
#   0   BSD loopback (null)              108  OpenBSD loopback
DLT_ETHERNET = 1
DLT_RAW_12 = 12
DLT_RAW_101 = 101
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276
DLT_NULL = 0
DLT_LOOP = 108

SUPPORTED_LINKTYPES = frozenset((
    DLT_ETHERNET, DLT_RAW_12, DLT_RAW_101, DLT_IPV4, DLT_IPV6,
    DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_NULL, DLT_LOOP,
))


def supports(linktype):
    """Whether `parse` can read frames of this link type."""
    return linktype in SUPPORTED_LINKTYPES


def _network_offset(data, linktype, n):
    """
    Return (ethertype, offset_of_IP_header), or (None, 0) if unreadable.

    The link layer only has to answer one question — where does the network
    header start, and is it v4 or v6 — so each case resolves to exactly that
    rather than modelling the link header in full.
    """
    if linktype == DLT_ETHERNET:
        if n < 14:
            return None, 0
        et = unpack_from('!H', data, 12)[0]
        off = 14
        # 802.1Q and QinQ. Bounded rather than `while True`: a crafted frame
        # claiming endless VLAN tags must not spin here.
        depth = 0
        while et in _VLAN_TPIDS and depth < 4 and off + 4 <= n:
            et = unpack_from('!H', data, off + 2)[0]
            off += 4
            depth += 1
        return et, off

    if linktype in (DLT_RAW_12, DLT_RAW_101):
        # No link header; the IP version nibble is the only discriminator.
        if n < 1:
            return None, 0
        version = data[0] >> 4
        if version == 4:
            return _ETH_IPV4, 0
        if version == 6:
            return _ETH_IPV6, 0
        return None, 0

    if linktype == DLT_IPV4:
        return _ETH_IPV4, 0
    if linktype == DLT_IPV6:
        return _ETH_IPV6, 0

    if linktype == DLT_LINUX_SLL:
        if n < 16:
            return None, 0
        return unpack_from('!H', data, 14)[0], 16

    if linktype == DLT_LINUX_SLL2:
        if n < 20:
            return None, 0
        return unpack_from('!H', data, 0)[0], 20

    if linktype in (DLT_NULL, DLT_LOOP):
        # A 4-byte host-order (NULL) or network-order (LOOP) address family.
        if n < 4:
            return None, 0
        fmt = '<I' if linktype == DLT_NULL else '!I'
        family = unpack_from(fmt, data, 0)[0]
        if family == 2:
            return _ETH_IPV4, 4
        # 24/28/30 are AF_INET6 across BSDs; 10 is Linux.
        if family in (10, 24, 28, 30):
            return _ETH_IPV6, 4
        return None, 0

    return None, 0


def parse(data, linktype=DLT_ETHERNET):
    """
    Extract the flow-relevant fields from one captured frame.

    Returns `(src_ip, dst_ip, protocol, sport, dport, tcp_flags, payload)`
    or `None` when the frame carries no IP conversation this model describes
    (ARP, STP, LLDP, a truncated header, an unsupported link type).

    `tcp_flags` is the raw flag byte; the caller decodes it. `payload` is a
    slice of the caller's buffer, not a copy of a rebuilt packet — the bytes
    that were on the wire.
    """
    n = len(data)
    et, off = _network_offset(data, linktype, n)
    if et is None:
        return None

    if et == _ETH_IPV4:
        # Need the full 20-byte fixed header before reading any field from it.
        if off + 20 > n:
            return None
        ihl = (data[off] & 0x0F) * 4
        # A header shorter than 20 bytes is malformed; longer means options.
        if ihl < 20 or off + ihl > n:
            return None
        proto = data[off + 9]
        src = _inet_ntoa(data[off + 12:off + 16])
        dst = _inet_ntoa(data[off + 16:off + 20])
        toff = off + ihl

        # Only the first fragment carries the transport header. Later
        # fragments have a non-zero offset and must not have their payload
        # read as ports — that is how a fragmented capture grows impossible
        # conversations on port 0.
        frag_off = unpack_from('!H', data, off + 6)[0] & 0x1FFF
        if frag_off:
            return src, dst, 'OTHER', 0, 0, 0, b''

    elif et == _ETH_IPV6:
        if off + 40 > n:
            return None
        proto = data[off + 6]
        src = _inet_ntop(_AF_INET6, data[off + 8:off + 24])
        dst = _inet_ntop(_AF_INET6, data[off + 24:off + 40])
        toff = off + 40

        depth = 0
        while depth < 8:
            if proto in _IPV6_EXT_SKIP:
                if toff + 8 > n:
                    return None
                nxt = data[toff]
                length = (data[toff + 1] + 1) * 8
                proto = nxt
                toff += length
            elif proto == _IPV6_FRAGMENT:
                if toff + 8 > n:
                    return None
                # Same reasoning as IPv4: only offset zero holds the transport
                # header.
                if unpack_from('!H', data, toff + 2)[0] & 0xFFF8:
                    return src, dst, 'OTHER', 0, 0, 0, b''
                proto = data[toff]
                toff += 8
            else:
                break
            depth += 1
    else:
        return None

    if proto == _PROTO_TCP:
        if toff + 20 > n:
            return None
        sport, dport = unpack_from('!HH', data, toff)

        # A data offset below 5 words is malformed — RFC 9293 s.3.1 fixes the
        # minimum TCP header at 20 octets — but malformed packets are exactly
        # what a forensic capture is full of, and dropping one silently would
        # make the packet count depend on which reader ran.
        #
        # Real example, found by the equivalence check rather than by reading
        # the spec: one frame in a 2,274,747-packet ICS capture declares
        # dataofs=0. The dissector reads it as a plain 20-octet header and
        # keeps the packet; refusing it here lost one packet, one flow and 62
        # bytes against the old numbers. Clamping reproduces the dissector's
        # reading exactly, payload included.
        doff = (data[toff + 12] >> 4) * 4
        if doff < 20:
            doff = 20
        flags = data[toff + 13]
        start = toff + doff
        return src, dst, 'TCP', sport, dport, flags, (
            data[start:] if start < n else b'')

    if proto == _PROTO_UDP:
        if toff + 8 > n:
            return None
        sport, dport = unpack_from('!HH', data, toff)
        start = toff + 8
        # Everything after the header, NOT clamped to the UDP length field.
        #
        # Clamping looks more correct and is not what the dissector does. In
        # scapy the trailing bytes become a `Padding` layer rather than being
        # discarded, and `bytes(udp.payload)` rebuilds the whole remaining
        # chain — payload and padding together. Measured over 40,000 real UDP
        # packets, the dissector's payload was the bytes to the end of the
        # frame every single time.
        #
        # Trimming here instead changed `payload_entropy` on four flows of
        # 946,238, which is exactly the kind of quiet divergence this reader
        # must not introduce. Matching the dissector matters more than
        # matching the RFC, because the recorded findings were derived with
        # the dissector's reading.
        return src, dst, 'UDP', sport, dport, 0, (
            data[start:] if start < n else b'')

    if proto == _PROTO_ICMP:
        if toff + 4 > n:
            return None
        # Type and code packed into the destination port, matching the Cisco
        # NetFlow convention the aggregator already uses, so ICMP flows keep
        # their message kind through aggregation.
        #
        # Note the payload here is the WHOLE ICMP message, header included,
        # unlike TCP and UDP where it is the bytes after the header. That is
        # not an inconsistency for its own sake: where the ICMP header ends
        # depends on the message type (8 bytes usually, 20 for a timestamp
        # message) and, for error messages, on dissecting the original packet
        # quoted inside them. The aggregator hands this to scapy to find that
        # boundary — affordable, because ICMP is well under 1% of a typical
        # capture, and necessary, because the entropy of an ICMP payload is
        # what the tunnelling rule reads.
        return src, dst, 'ICMP', 0, (data[toff] * 256) + data[toff + 1], 0, data[toff:]

    # ICMPv6 is deliberately NOT classified as ICMP.
    #
    # Not because that would be wrong in principle — it would arguably be an
    # improvement — but because the dissector path does not do it either:
    # `_classify` looks for scapy's `ICMP`, which models IPv4 ICMP only, so an
    # ICMPv6 packet has always been recorded as OTHER with no ports. Making
    # the fast reader smarter here would mean the same capture yielding
    # different flows depending on which reader ran, and would quietly change
    # findings on IPv6 captures as a side effect of a performance change.
    # Those are two separate decisions and this is only the first one.
    return src, dst, 'OTHER', 0, 0, 0, b''


def iter_frames(path):
    """
    Yield `(frame_bytes, timestamp, linktype)` for every packet in a capture.

    Handles both classic pcap and pcapng — `RawPcapReader` dispatches on the
    file magic — and returns the raw bytes without dissecting anything.

    On timestamps
    =============
    The value must match what the scapy path produces exactly, because a
    capture re-imported after this change must yield the same intervals,
    durations and beacon periods as before, and "almost the same time" is not
    a property evidence can have.

    Scapy computes the time in `Decimal` and the caller converts to `float`,
    i.e. the nearest double to the exact decimal value. Doing the arithmetic
    as `int / int` reaches the same double: Python's true division of two
    integers is correctly rounded, so both routes land on the nearest
    representable value rather than accumulating two separate roundings the
    way `sec + usec * 1e-6` would.
    """
    reader = RawPcapReader(str(path))
    is_ng = isinstance(reader, RawPcapNgReader)

    try:
        if is_ng:
            # pcapng carries the link type and timestamp resolution per
            # interface, so both arrive with each packet rather than once in
            # a file header.
            for data, meta in reader:
                resolution = meta.tsresol or 1000000
                ticks = (meta.tshigh << 32) + meta.tslow
                yield data, ticks / resolution, meta.linktype
        else:
            # Classic pcap: one link type for the file, and a magic number
            # that says whether the sub-second field counts microseconds or
            # nanoseconds.
            linktype = reader.linktype
            denominator = 1000000000 if reader.nano else 1000000
            for data, meta in reader:
                yield data, (meta.sec * denominator + meta.usec) / denominator, linktype
    finally:
        reader.close()


def linktype_of(path):
    """
    The link type of a capture, read from its header alone.

    Used to decide before ingest whether the fast path can read this file at
    all. pcapng declares the link type per interface, so a file with any
    interface this module cannot read is reported by its first such interface
    and the caller falls back for the whole file — a mixed-link-type capture
    is rare, and splitting one across two parsers is not worth the risk of the
    two disagreeing.
    """
    reader = RawPcapReader(str(path))
    try:
        if isinstance(reader, RawPcapNgReader):
            types = {i[0] for i in reader.interfaces} if reader.interfaces else set()
            if not types:
                # No IDB seen yet: read one packet, which forces the header
                # blocks to be parsed, and ask again.
                for _data, meta in reader:
                    return meta.linktype
                return None
            unsupported = types - SUPPORTED_LINKTYPES
            return next(iter(unsupported)) if unsupported else next(iter(types))
        return reader.linktype
    finally:
        reader.close()
