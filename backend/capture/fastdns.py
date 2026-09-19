"""
DNS message reading without building a scapy object per packet.

Why this exists
===============
`fastparse` removed scapy from the packet-header path in 2025 and the import
got a hundred times faster. What it left behind was scapy in two *dissection*
roles, and profiling in Sept 2026 found those had become the bottleneck: a full
scapy `DNS` object was being constructed for every packet on port 53, to read
six fields. Measured over real captures:

    4SICS   40,000 DNS messages   scapy 9.157s   this module 0.166s    55x
    wrccdc   4,780 DNS messages   scapy 2.769s   this module 0.029s    96x

Aggregation is ~90% of a PCAP import and scapy DNS was 33–72% of that, so this
is the single largest cost in the ingest path. See
research/153_PCAP_ENGINE_PERFORMANCE.md for the full measurement.

What "correct" means here
=========================
Not "what RFC 1035 says". **What scapy does** — including where scapy is
strange — because every finding recorded to date was derived through scapy, and
a capture re-imported after this change must yield the same flows, the same DNS
records and the same findings. A parser that is more correct than scapy would
silently reclassify old evidence, which is a worse outcome than a shared quirk.

Three places where that distinction bites, all verified against
`scapy.layers.dns.dns_get_str` (scapy 2.7.0) rather than against the RFC:

* **Any label with either high bit set is a pointer.** scapy tests
  `cur & 0xc0`, not `cur & 0xc0 == 0xc0`, so the reserved label types 0x40 and
  0x80 are followed as pointers with the top two bits masked off. RFC 1035
  s.4.1.4 reserves them; scapy jumps.
* **Pointers may point forward.** RFC 1035 requires a pointer to a prior
  occurrence, and RFC 9267 s.3 names unbounded forward jumps as an
  anti-pattern, but scapy follows them. Loops are caught by remembering every
  target already visited, and by a hard stop after 20 jumps — not by requiring
  the target to be backwards.
* **A truncated name is returned, not rejected.** scapy breaks out of its loop
  and keeps the labels it has. A snaplen-truncated capture is ordinary
  evidence, so this module keeps the partial name too.

The 20-jump cap and the visited-set are what bound the work here, and they are
scapy's own limits rather than stricter ones invented for this module: a
stricter limit would reject packets scapy accepted, which is the same
divergence in the other direction.

Equivalence is not asserted, it is tested — `tests_equivalence.py` runs this
module and scapy over every DNS message in the reference captures and over
generated malformed input, and requires identical results.
"""

from collections import namedtuple
from struct import unpack_from


# A DNS message reduced to what capture.processor actually reads. Everything
# scapy exposes beyond this is unused by the flow model, and building it is the
# cost this module exists to avoid.
#
# `answers` is already filtered to the addresses A and AAAA records carried,
# because that is the only use `_record_dns_answers` makes of the answer
# section.
DnsMessage = namedtuple('DnsMessage', 'id qr qname qtype answers')


# scapy's `dnsqtypes`, copied rather than imported so this module does not pull
# scapy in. `tests_equivalence.py` asserts the two tables are still identical,
# so a scapy upgrade that adds a type fails the test instead of silently
# changing how a query is labelled in evidence.
QTYPES = {
    0: 'RESERVED', 1: 'A', 2: 'NS', 3: 'MD', 4: 'MF', 5: 'CNAME', 6: 'SOA', 7: 'MB',
    8: 'MG', 9: 'MR', 10: 'NULL', 11: 'WKS', 12: 'PTR', 13: 'HINFO', 14: 'MINFO', 15: 'MX',
    16: 'TXT', 17: 'RP', 18: 'AFSDB', 19: 'X25', 20: 'ISDN', 21: 'RT', 22: 'NSAP',
    23: 'NSAP-PTR', 24: 'SIG', 25: 'KEY', 26: 'PX', 27: 'GPOS', 28: 'AAAA', 29: 'LOC',
    30: 'NXT', 31: 'EID', 32: 'NIMLOC', 33: 'SRV', 34: 'ATMA', 35: 'NAPTR', 36: 'KX',
    37: 'CERT', 38: 'A6', 39: 'DNAME', 40: 'SINK', 41: 'OPT', 42: 'APL', 43: 'DS',
    44: 'SSHFP', 45: 'IPSECKEY', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 49: 'DHCID',
    50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 53: 'SMIMEA', 55: 'HIP', 56: 'NINFO',
    57: 'RKEY', 58: 'TALINK', 59: 'CDS', 60: 'CDNSKEY', 61: 'OPENPGPKEY', 62: 'CSYNC',
    63: 'ZONEMD', 64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 100: 'UINFO', 101: 'UID', 102: 'GID',
    103: 'UNSPEC', 104: 'NID', 105: 'L32', 106: 'L64', 107: 'LP', 108: 'EUI48',
    109: 'EUI64', 249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR', 253: 'MAILB',
    254: 'MAILA', 255: 'ALL', 256: 'URI', 257: 'CAA', 258: 'AVC', 259: 'DOA',
    260: 'AMTRELAY', 32768: 'TA', 32769: 'DLV', 65535: 'RESERVED',
}

# scapy stops after this many jumps and drops the packet as evil. Matching the
# number matters: a lower one would reject names scapy resolved.
MAX_JUMPS = 20

# Answer records walked per message. The flow model reads addresses out of the
# answer section; it does not need an unbounded walk of a hostile one, and a
# message declaring 65,535 answers must not turn one packet into 65,535 slices.
# Above this the remaining answers are ignored, exactly as a short `an` list in
# scapy would cause `_record_dns_answers` to break out early.
MAX_ANSWERS = 64

_A, _AAAA = 1, 28


def _name(data, pos, n):
    """
    Read a domain name at `pos`, following compression pointers.

    Returns `(name_bytes, offset_after_the_name)`. The offset is the position
    after the name *in the buffer where it started* — following a pointer must
    not move the caller's cursor, or every field after a compressed name would
    be read from the wrong place.

    Mirrors `scapy.layers.dns.dns_get_str`; see the module docstring for the
    three behaviours that are scapy's rather than the RFC's.
    """
    labels = []
    after_pointer = None
    visited = set()
    jumps = 0

    while True:
        if pos >= n:
            # Premature end. scapy logs and keeps what it has; so do we.
            break
        cur = data[pos]
        pos += 1

        if cur & 0xC0:
            # Deliberately `& 0xC0` and not `== 0xC0`: see module docstring.
            if after_pointer is None:
                after_pointer = pos + 1
            if pos >= n:
                break                      # incomplete jump token
            target = ((cur & ~0xC0) << 8) + data[pos]
            if target in visited:
                break                      # decompression loop
            if jumps >= MAX_JUMPS:
                break                      # scapy calls this an evil packet
            visited.add(target)
            jumps += 1
            pos = target
            continue

        if cur:
            labels.append(data[pos:pos + cur])
            pos += cur
        else:
            break

    if after_pointer is not None:
        pos = after_pointer

    # scapy returns b"." for a name that produced no labels (the root), which
    # is not the same as the empty string and is what ends up in evidence.
    name = b''.join(label + b'.' for label in labels) or b'.'
    return name, pos


def parse(payload, over_tcp=False):
    """
    Read one DNS message. Returns a `DnsMessage`, or None if there is none.

    `over_tcp` strips the two-octet length prefix DNS-over-TCP carries
    (RFC 1035 s.4.2.2). scapy models that with a field conditional on the
    underlayer being TCP, which a standalone `DNS(...)` cannot see, so the
    caller has always had to remove it explicitly.

    None means "no DNS message here", which is not an error: traffic on port 53
    that is a tunnel carrying something else, or a capture truncated before the
    header, simply has no message to record.
    """
    if over_tcp:
        if len(payload) <= 2:
            return None
        payload = payload[2:]

    n = len(payload)
    if n < 12:
        return None

    ident, flags, qdcount, ancount = unpack_from('!HHHH', payload, 0)
    if qdcount == 0:
        # `_process_dns` returns early on a message with no question section,
        # so there is nothing to build.
        return None

    qname, pos = _name(payload, 12, n)
    if pos + 4 > n:
        return None
    qtype = unpack_from('!H', payload, pos)[0]
    pos += 4                                # qtype (2) + qclass (2)

    answers = []
    if flags & 0x8000:                      # QR set: a response
        for _ in range(min(ancount, MAX_ANSWERS)):
            _rrname, pos = _name(payload, pos, n)
            if pos + 10 > n:
                break
            atype, _cls, _ttl, rdlength = unpack_from('!HHIH', payload, pos)
            pos += 10
            if pos + rdlength > n:
                break
            # Only A and AAAA carry addresses. CNAME and friends carry names,
            # which answer a different question than "where did this go".
            if atype == _A and rdlength == 4:
                answers.append('%d.%d.%d.%d' % tuple(payload[pos:pos + 4]))
            elif atype == _AAAA and rdlength == 16:
                answers.append(_ipv6(payload[pos:pos + 16]))
            pos += rdlength

    return DnsMessage(
        id=ident,
        qr=(flags >> 15) & 1,
        qname=qname.decode('utf-8', errors='ignore'),
        qtype=QTYPES.get(qtype, str(qtype)),
        answers=answers,
    )


def _ipv6(raw):
    """
    An IPv6 address in the form scapy's `rdata` carries it.

    `socket.inet_ntop` is not used because it renders through the platform's
    resolver, and scapy formats AAAA rdata itself; the two differ on how a
    run of zero groups is compressed in some cases. Reproducing scapy's text
    keeps query names and answer addresses comparable across a re-import.
    """
    groups = ['%x' % g for g in unpack_from('!8H', raw, 0)]

    # Longest run of consecutive zero groups is replaced by '::' (RFC 5952
    # s.4.2); a run of one is not abbreviated.
    best_start = best_len = -1
    run_start = -1
    for i, g in enumerate(groups + ['x']):
        if g == '0':
            if run_start < 0:
                run_start = i
        else:
            if run_start >= 0 and i - run_start > best_len:
                best_start, best_len = run_start, i - run_start
            run_start = -1

    if best_len > 1:
        head = ':'.join(groups[:best_start])
        tail = ':'.join(groups[best_start + best_len:])
        return head + '::' + tail
    return ':'.join(groups)


def from_scapy(dns):
    """
    The same `DnsMessage` from an already-dissected scapy layer.

    The live-capture path gets packets scapy has already built, so there is
    nothing to be saved by parsing the bytes again — but the aggregator must
    see one shape regardless of which path fed it, or the flow model would have
    two readings to keep in step.
    """
    if dns is None or not dns.qd:
        return None
    try:
        qname = dns.qd.qname.decode('utf-8', errors='ignore')
    except Exception:
        return None

    try:
        qtype = dns.qd.get_field('qtype').i2repr(dns.qd, dns.qd.qtype)
    except Exception:
        qtype = ''

    answers = []
    for index in range(int(getattr(dns, 'ancount', 0) or 0)):
        try:
            answer = dns.an[index]
        except (IndexError, TypeError):
            break
        if getattr(answer, 'type', None) in (_A, _AAAA):
            value = getattr(answer, 'rdata', None)
            if value is None:
                continue
            answers.append(value.decode() if isinstance(value, bytes) else str(value))

    return DnsMessage(id=int(dns.id), qr=int(dns.qr), qname=qname,
                      qtype=qtype, answers=answers)
