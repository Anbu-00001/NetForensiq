"""
Prototype: read the six DNS fields the aggregator uses, with struct only.

Needed by processor.py: id, qr, ancount, qd.qname, qd.qtype, and for each
answer its type + rdata (A/AAAA only). Nothing else. This is the same bet
fastparse.py already made for IP/TCP/UDP headers.
"""
from struct import unpack_from
import socket

_ntoa, _ntop, _AF6 = socket.inet_ntoa, socket.inet_ntop, socket.AF_INET6

QTYPES = {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX', 16:'TXT',
          28:'AAAA', 33:'SRV', 35:'NAPTR', 41:'OPT', 43:'DS', 46:'RRSIG',
          48:'DNSKEY', 52:'TLSA', 65:'HTTPS', 64:'SVCB', 255:'ALL', 251:'IXFR',
          252:'AXFR', 257:'CAA'}


def _name(data, pos, n):
    """Read a possibly-compressed DNS name. Returns (name, next_pos) or None."""
    labels = []
    jumped = False
    end = pos
    hops = 0
    while True:
        if pos >= n:
            return None
        length = data[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:          # compression pointer
            if pos + 2 > n:
                return None
            target = unpack_from('!H', data, pos)[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            # A pointer must point backwards; bounded hops stop a crafted loop.
            hops += 1
            if hops > 16 or target >= pos:
                return None
            pos = target
            jumped = True
            continue
        if length & 0xC0:                  # reserved label type
            return None
        pos += 1
        if pos + length > n:
            return None
        labels.append(data[pos:pos + length])
        pos += length
    return b'.'.join(labels) + b'.', end


def parse(data):
    """Return a dict of the fields the aggregator reads, or None."""
    n = len(data)
    if n < 12:
        return None
    ident, flags, qdcount, ancount = unpack_from('!HHHH', data, 0)
    if qdcount == 0:
        return None
    got = _name(data, 12, n)
    if got is None:
        return None
    qname, pos = got
    if pos + 4 > n:
        return None
    qtype = unpack_from('!H', data, pos)[0]
    pos += 4

    answers = []
    if flags & 0x8000:                     # response: walk the answer section
        for _ in range(min(ancount, 64)):
            got = _name(data, pos, n)
            if got is None:
                break
            _an, pos = got
            if pos + 10 > n:
                break
            atype, _cls, _ttl, rdlen = unpack_from('!HHIH', data, pos)
            pos += 10
            if pos + rdlen > n:
                break
            if atype == 1 and rdlen == 4:
                answers.append(_ntoa(data[pos:pos + 4]))
            elif atype == 28 and rdlen == 16:
                answers.append(_ntop(_AF6, data[pos:pos + 16]))
            pos += rdlen

    return {'id': ident, 'qr': (flags >> 15) & 1, 'ancount': ancount,
            'qname': qname, 'qtype': QTYPES.get(qtype, str(qtype)),
            'answers': answers}
