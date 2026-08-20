import threading
import time
from datetime import datetime, timezone as dt_timezone

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

from . import fastparse
from .features import shannon_entropy, dns_query_features, compute_flow_metrics
from .tls_fingerprint import fingerprint_payload


TCP_FLAG_MAP = {
    0x01: 'F', 0x02: 'S', 0x04: 'R',
    0x08: 'P', 0x10: 'A', 0x20: 'U',
}

WELL_KNOWN_PORTS = {
    20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET',
    25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
    143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'SMTP',
    993: 'IMAPS', 995: 'POP3S', 3389: 'RDP', 8080: 'HTTP-ALT',
}

# Cap on per-flow entropy samples, and on bytes measured per sample.
#
# payload_entropy is therefore the mean of at most 40 samples of at most 512
# bytes each, taken in arrival order — at most 20 KB of a flow that may be
# hundreds of megabytes. That matters because the value is compared against
# exfil_entropy_high, which carries a real citation: the threshold is sourced
# and the measurement it judges is an estimate.
#
# The earlier comment here claimed the bound was "without materially changing
# the entropy estimate". Nothing established that, so it is not claimed. What
# is done instead: the policy is published through THRESHOLDS as informational,
# and every finding that rests on entropy states how many samples backed it, so
# an officer can see the estimate is an estimate.
#
# First-N rather than reservoir sampling is deliberate — a capture replayed
# twice must produce identical findings, and random sampling would not.
MAX_ENTROPY_SAMPLES = 40
ENTROPY_SAMPLE_BYTES = 512

# A 5-tuple is not a connection. Clients reuse ephemeral ports, so over a long
# capture the same tuple recurs for conversations hours apart; without a
# timeout they merge into one "flow" whose duration and intervals are
# meaningless. A real week-long server capture produced flows reporting 22,736
# seconds while carrying 148 bytes.
#
# Values are Zeek's, verified against its source rather than its docs:
# scripts/base/init-bare.zeek declares
#   const tcp_inactivity_timeout  = 5 min   (line 1791)
#   const udp_inactivity_timeout  = 1 min   (line 1797)
#   const icmp_inactivity_timeout = 1 min   (line 1803)
# Zeek also defines a timeout for unknown IP protocols; 1 min is used here for
# anything not listed, matching its UDP/ICMP choice.
IDLE_TIMEOUT_SECONDS = {'TCP': 300.0, 'UDP': 60.0, 'ICMP': 60.0}
DEFAULT_IDLE_TIMEOUT = 60.0
# The citation for these values is published once — as SRC_ZEEK_IDLE in
# detection.py, which reads IDLE_TIMEOUT_SECONDS from here and surfaces both
# through /api/detections/thresholds/. A second copy of the same source string
# lived here, referenced by nothing; two strings for one source is how they
# drift apart. It is not re-imported because detection.py imports this module.


def packet_timestamp(pkt):
    """
    The capture time recorded *in the packet*, not the time we happened to
    parse it.

    This distinction is the whole ballgame for forensics: an imported PCAP
    describes events that already happened, so every interval, duration and
    beacon period must come from pkt.time. Falling back to wall-clock is only
    correct for live capture, where the two are the same thing.

    Scapy exposes .time as EDecimal; float() keeps it JSON- and DB-friendly.
    """
    ts = getattr(pkt, 'time', None)
    if ts is None:
        return time.time()
    try:
        return float(ts)
    except (TypeError, ValueError):
        return time.time()


def flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
    """
    Canonical bidirectional key: sorting the endpoints means packets in both
    directions map to the same flow, so we measure conversations rather than
    one-way streams.

    Note this says nothing about who *started* the conversation — that is
    tracked separately as the initiator, because sort order is an artefact of
    IP string comparison and carries no forensic meaning.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return (a[0], a[1], b[0], b[1], protocol)
    return (b[0], b[1], a[0], a[1], protocol)



class _NoLock:
    """A lock-shaped object that does nothing, for the single-threaded path."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FlowAggregator:
    """
    Accumulates packets into flow records in memory, then hands them to the
    persistence layer via finalize().

    Memory is bounded by the number of distinct flows, not by packet count,
    so a long capture of few conversations stays cheap. Callers ingesting
    very large PCAPs should stream packets in (see service.iter_pcap).
    """

    def __init__(self, thread_safe=False):
        # Live capture reads this aggregator from one thread while scapy's
        # sniffer writes to it from another, and iterating a dict that another
        # thread is inserting into raises RuntimeError partway through — which
        # would surface as an intermittently failing live capture rather than
        # as anything obviously threading-related.
        #
        # Off by default: reading a PCAP is single-threaded, and paying for a
        # lock on every packet of a multi-gigabyte file to protect against a
        # thread that does not exist is not free.
        self._lock = threading.Lock() if thread_safe else _NoLock()

        # Active flows, keyed by 5-tuple. A flow leaves here and joins
        # `completed` when the connection ends or goes idle, so a reused
        # ephemeral port starts a fresh record rather than extending an old one.
        self.flows = {}
        self.completed = []
        # A 5-tuple can now yield several flows, so DNS records cannot be
        # linked back by tuple. Each flow gets a unique id instead.
        self._next_uid = 0
        self.dns_records = []
        # (client_ip, transaction_id, qname) -> addresses seen in the reply
        self._dns_answers = {}
        self.total_packets = 0
        self.total_bytes = 0
        self.first_packet_time = None
        self.last_packet_time = None

    # ── ingestion ────────────────────────────────────────────────────────

    def process(self, pkt):
        """
        Ingest one dissected scapy packet.

        This is the live-capture path: scapy's sniffer hands over packets it
        has already built, so there is nothing to be saved by parsing them
        again. Reading a PCAP goes through `process_frame` instead.
        """
        with self._lock:
            self._process(pkt)

    def process_frame(self, data, timestamp, linktype=fastparse.DLT_ETHERNET):
        """
        Ingest one captured frame straight from its bytes.

        The PCAP import path. `fastparse` reads the handful of header fields
        the flow model is defined over without constructing a scapy object,
        which is where nearly all of the import time used to go — see the
        module docstring in `fastparse.py` for the measurements.

        Frames it cannot read return None and are skipped, exactly as the
        scapy path skips a packet with no IP layer. Callers that need the
        general dissector for an unusual link type check `fastparse.supports`
        first and fall back.
        """
        parsed = fastparse.parse(data, linktype)
        if parsed is None:
            return

        src_ip, dst_ip, protocol, sport, dport, raw_flags, payload = parsed

        if protocol == 'TCP':
            flags = self._decode_tcp_flags(raw_flags)
        else:
            flags = ''
            if protocol == 'ICMP':
                # `fastparse` hands over the whole ICMP message because where
                # its header ends is a question about the message type, and
                # for error messages about the packet quoted inside it. Scapy
                # answers that; the cost is confined to ICMP, which is a
                # fraction of a percent of a capture.
                payload = self._icmp_payload(payload)

        with self._lock:
            self._ingest(src_ip, dst_ip, protocol, sport, dport, flags,
                         payload, len(data), timestamp, None)

    def _process(self, pkt):
        # Each `X in pkt` / `pkt[X]` pair walks the layer chain, and this
        # method used to do six such walks per packet (IP, IPv6, TCP, UDP,
        # ICMP, DNS) plus more inside the helpers. getlayer() returns the layer
        # or None in one traversal, so every lookup below happens exactly once
        # and the resolved layer is passed down rather than re-fetched.
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            return

        protocol, sport, dport, flags, transport = self._classify(pkt)
        self._ingest(
            ip_layer.src, ip_layer.dst, protocol, sport, dport, flags,
            self._payload_of(transport), len(pkt), packet_timestamp(pkt), pkt,
        )

    def _ingest(self, src_ip, dst_ip, protocol, sport, dport, flags, payload,
                pkt_len, now, scapy_pkt):
        """
        Fold one packet into the flow table.

        Everything above this point differs between the two entry paths — one
        has a dissected object, the other has bytes. Everything from here down
        is the analysis, and it is deliberately shared: two copies of the flow
        model would be two things to keep in step, and the moment they drifted
        the same capture would yield different findings depending on how it
        arrived. `tests_fastparse.py` holds both paths to the same output.
        """

        self.total_packets += 1
        self.total_bytes += pkt_len

        if self.first_packet_time is None or now < self.first_packet_time:
            self.first_packet_time = now
        if self.last_packet_time is None or now > self.last_packet_time:
            self.last_packet_time = now

        key = flow_key(src_ip, dst_ip, sport, dport, protocol)

        is_syn = (protocol == 'TCP' and 'S' in flags and 'A' not in flags)

        f = self.flows.get(key)
        if f is not None and self._starts_new_flow(f, protocol, now, is_syn):
            self.completed.append(f)
            del self.flows[key]
            f = None

        if f is None:
            f = self._new_flow(key, protocol, src_ip, sport, now)
            self.flows[key] = f

        # Establish direction. A TCP SYN without ACK is definitive proof of
        # who opened the conversation, and overrides the first-seen guess —
        # captures frequently start mid-stream.
        if is_syn:
            f['initiator_ip'] = src_ip
            f['initiator_port'] = sport
            f['initiator_confirmed'] = True

        f['last_seen'] = max(f['last_seen'], now)
        f['first_seen'] = min(f['first_seen'], now)
        f['dst_ports'].add(dport)

        outbound = (src_ip == f['initiator_ip'] and sport == f['initiator_port'])
        if outbound:
            f['packets_sent'] += 1
            f['bytes_sent'] += pkt_len
            # Callback periodicity is a property of the *outbound* leg only.
            # Mixing in server replies alternates a ~0.2s response gap with
            # the real ~30s period and hides the beacon entirely.
            f['timestamps_out'].append(now)
        else:
            f['packets_received'] += 1
            f['bytes_received'] += pkt_len

        f['timestamps'].append(now)

        if flags:
            f['tcp_flags'].update(flags)

        if not f['app_protocol']:
            # A guess from the port number, not a dissection. Recorded as such:
            # the dashboard's protocol ranking would otherwise report "SSH"
            # about anything on 22, which is exactly what a tunnel hiding on a
            # permitted port relies on. Overwritten below by a real
            # observation — an HTTP Host header, a TLS ClientHello, a DNS
            # message — whenever one is available.
            guessed = WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport) or ''
            if guessed:
                f['app_protocol'] = guessed
                f['app_protocol_source'] = 'port'

        if payload and len(f['entropy_samples']) < MAX_ENTROPY_SAMPLES:
            f['entropy_samples'].append(
                shannon_entropy(payload[:ENTROPY_SAMPLE_BYTES])
            )

        # `DNS in pkt` walks the layer chain on every packet. DNS rides port
        # 53, and a tunnel must use 53 too — that is the whole point of the
        # technique, it is the port allowed out. Gating on the port first
        # skips the traversal for the overwhelming majority of packets.
        if 53 in (sport, dport):
            dns = self._dns_layer(scapy_pkt, protocol, payload)
            if dns is not None:
                self._process_dns(dns, f, src_ip, dst_ip, now)

        if protocol == 'TCP' and payload:
            self._process_app_layer(payload, f, dport)

    def _classify(self, pkt):
        """
        Return (protocol, sport, dport, tcp_flags, transport_layer).

        The transport layer is returned so callers can read its payload
        without walking the chain again.
        """
        tcp = pkt.getlayer(TCP)
        if tcp is not None:
            return 'TCP', tcp.sport, tcp.dport, self._decode_tcp_flags(tcp.flags), tcp
        udp = pkt.getlayer(UDP)
        if udp is not None:
            return 'UDP', udp.sport, udp.dport, '', udp
        icmp = pkt.getlayer(ICMP)
        if icmp is not None:
            # ICMP has no ports. Following the Cisco NetFlow convention, the
            # type and code are packed into the destination port field as
            # type*256 + code, so the message kind survives flow aggregation.
            # Without it every ICMP flow looks alike, and the tunnel rule
            # cannot tell an echo request carrying data from a destination-
            # unreachable error — which quotes the original packet headers and
            # is therefore also large.
            return 'ICMP', 0, (int(icmp.type) * 256) + int(icmp.code), '', icmp
        return 'OTHER', 0, 0, '', None

    def _starts_new_flow(self, f, protocol, now, is_syn):
        """
        Whether this packet begins a new conversation on an existing 5-tuple.

        Two independent signals:

        * **A fresh SYN.** A TCP SYN without ACK on a tuple that already
          carries traffic is a new connection by definition — the client
          reused the ephemeral port. This is exact, not heuristic.
        * **Idle gap.** For everything else (UDP, ICMP, captures that begin
          mid-stream and never show a SYN), a silence longer than the
          protocol's inactivity timeout ends the flow, as Zeek does.

        Only forward gaps count: packets can arrive slightly out of order and
        a negative gap must never split a flow.
        """
        if is_syn and (f['packets_sent'] + f['packets_received']) > 0:
            return True

        timeout = IDLE_TIMEOUT_SECONDS.get(protocol, DEFAULT_IDLE_TIMEOUT)
        return (now - f['last_seen']) > timeout

    def _new_flow(self, key, protocol, src_ip, sport, now):
        self._next_uid += 1
        return {
            '_uid': self._next_uid,
            'src_ip': key[0], 'src_port': key[1],
            'dst_ip': key[2], 'dst_port': key[3],
            'protocol': protocol,
            # Provisional: the first packet we saw. Upgraded on a TCP SYN.
            'initiator_ip': src_ip,
            'initiator_port': sport,
            'initiator_confirmed': False,
            'packets_sent': 0, 'packets_received': 0,
            'bytes_sent': 0, 'bytes_received': 0,
            'first_seen': now, 'last_seen': now,
            'timestamps': [],
            'timestamps_out': [],
            'entropy_samples': [],
            'tcp_flags': set(),
            'dst_ports': set(),
            'dns_query_count': 0,
            'longest_dns_label': 0,
            'max_dns_entropy': 0.0,
            'app_protocol': '',
            'app_protocol_source': '',
            'http_host': '',
            'tls_sni': '',
            'ja4_fingerprint': '',
            'ja4_raw': '',
        }

    def _icmp_payload(self, message):
        """
        The payload of an ICMP message, as the dissector path defines it.

        Verified against 9,415 real ICMP messages spanning echo, destination
        unreachable, time exceeded and timestamp types: identical to
        `pkt.getlayer(ICMP).payload` in every case, including the error
        messages whose payload sits inside a quoted packet.
        """
        if not message:
            return b''
        try:
            return bytes(ICMP(message).payload)
        except Exception:
            return b''

    def _payload_of(self, transport):
        if transport is None:
            return b''
        try:
            return bytes(transport.payload)
        except Exception:
            return b''

    def _decode_tcp_flags(self, flag_value):
        return ''.join(
            char for bit, char in TCP_FLAG_MAP.items() if int(flag_value) & bit
        )

    def _dns_layer(self, scapy_pkt, protocol, payload):
        """
        The DNS message for a packet already known to be on port 53.

        Two sources, one result. The live path has a dissected packet and just
        asks for the layer. The import path has bytes, so the message is
        dissected here — and only here, for the ~2.6% of packets on port 53,
        rather than for every packet in the capture.

        DNS over TCP is length-prefixed (RFC 1035 s.4.2.2). Scapy models that
        with a field conditional on the underlayer being TCP, which a
        standalone `DNS(...)` cannot see, so the two octets are removed
        explicitly instead of being read as part of the header.
        """
        if scapy_pkt is not None:
            return scapy_pkt.getlayer(DNS)

        if not payload:
            return None
        try:
            if protocol == 'TCP':
                return DNS(payload[2:]) if len(payload) > 2 else None
            return DNS(payload)
        except Exception:
            # Traffic on 53 that is not a DNS message — a tunnel carrying
            # something else, or a truncated capture. Not an error; there is
            # simply no message to record.
            return None

    def _process_dns(self, dns, f, src_ip, dst_ip, now):
        # Callers gate on port 53, which is necessary but not sufficient:
        # traffic on 53 that was not dissected as DNS (truncated, or something
        # else entirely on that port) yields no usable question section.
        if dns is None or not dns.qd:
            return

        if dns.qr == 1:
            self._record_dns_answers(dns, dst_ip)
            return

        try:
            qname = dns.qd.qname.decode('utf-8', errors='ignore')
        except Exception:
            return

        feats = dns_query_features(qname)
        f['dns_query_count'] += 1
        f['longest_dns_label'] = max(f['longest_dns_label'], feats['subdomain_length'])
        f['max_dns_entropy'] = max(f['max_dns_entropy'], feats['query_entropy'])
        f['app_protocol'] = 'DNS'
        f['app_protocol_source'] = 'observed'

        qtype = ''
        try:
            qtype = dns.qd.get_field('qtype').i2repr(dns.qd, dns.qd.qtype)
        except Exception:
            pass

        self.dns_records.append({
            '_answer_key': (src_ip, int(dns.id), qname.rstrip('.').lower()),
            'src_ip': src_ip,
            'query_name': qname.rstrip('.')[:512],
            'query_type': qtype[:12],
            'subdomain_length': feats['subdomain_length'],
            'label_count': feats['label_count'],
            'query_entropy': feats['query_entropy'],
            'timestamp': datetime.fromtimestamp(now, tz=dt_timezone.utc),
            'flow_uid': f['_uid'],
        })

    def _record_dns_answers(self, dns, client_ip):
        """
        Remember the addresses a response carried, keyed to its query.

        `response_ip` was a column on the model, exposed on the API, that
        nothing ever wrote — a field promising data it never delivered. It
        matters for forensics: a tunnelling domain that resolves to the same
        host as the C2 channel ties two findings to one operator, and an
        analyst cannot make that link from query names alone.

        Correlation uses the transaction ID together with the client address
        and the queried name, which is the association the protocol itself
        provides. Matching on name alone would merge unrelated lookups of the
        same host made minutes apart.
        """
        try:
            qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.').lower()
        except Exception:
            return

        key = (client_ip, int(dns.id), qname)
        addresses = self._dns_answers.setdefault(key, [])

        for index in range(int(getattr(dns, 'ancount', 0) or 0)):
            try:
                answer = dns.an[index]
            except (IndexError, TypeError):
                break
            # A and AAAA carry addresses; CNAME/NS and friends carry names,
            # which belong to a different question than "where did this go".
            if getattr(answer, 'type', None) in (1, 28):
                value = getattr(answer, 'rdata', None)
                if value is None:
                    continue
                text = value.decode() if isinstance(value, bytes) else str(value)
                if text not in addresses:
                    addresses.append(text)

    def _process_app_layer(self, payload, f, dport):
        # HTTP Host header
        if dport in (80, 8080) and not f['http_host']:
            try:
                text = payload[:400].decode('utf-8', errors='ignore')
                for line in text.split('\r\n'):
                    if line.lower().startswith('host:'):
                        f['http_host'] = line.split(':', 1)[1].strip()[:255]
                        f['app_protocol'] = 'HTTP'
                        f['app_protocol_source'] = 'observed'
                        break
            except Exception:
                pass

        # TLS ClientHello — the destination domain and the client's JA4
        # fingerprint, both readable although the session is encrypted. This
        # is the "encrypted traffic analysis without decryption" capability.
        #
        # Gated on 443 for cost, not correctness: parsing every TCP payload in
        # a multi-gigabyte capture to look for a handshake is not affordable,
        # and TLS on a non-standard port is what rule_unknown_long_channel is
        # for. A capture where that matters can be re-run with the port list
        # widened; pretending otherwise would be the wrong trade to hide.
        elif dport == 443 and not f['ja4_fingerprint']:
            ja4, ja4_raw, sni = fingerprint_payload(payload)
            if ja4:
                f['ja4_fingerprint'] = ja4
                f['ja4_raw'] = ja4_raw
                f['app_protocol'] = 'TLS'
                f['app_protocol_source'] = 'observed'
            if sni and not f['tls_sni']:
                f['tls_sni'] = sni[:255]
                f['app_protocol'] = 'TLS'
                f['app_protocol_source'] = 'observed'

    # ── output ───────────────────────────────────────────────────────────

    def finalize(self):
        """
        Convert in-memory state into database-ready dicts.

        Read-only with respect to the aggregator, which is what lets live
        capture call it repeatedly on a session that is still growing.
        """
        with self._lock:
            return self._finalize()

    def _finalize(self):
        results = []
        # Flows retired mid-capture plus those still open at the end.
        for f in [*self.completed, *self.flows.values()]:
            metrics = compute_flow_metrics(f)
            results.append({
                'src_ip': f['src_ip'],
                'dst_ip': f['dst_ip'],
                'src_port': f['src_port'],
                'dst_port': f['dst_port'],
                'protocol': f['protocol'],
                'initiator_ip': f['initiator_ip'],
                'initiator_port': f['initiator_port'],
                'initiator_confirmed': f['initiator_confirmed'],
                'packets_sent': f['packets_sent'],
                'packets_received': f['packets_received'],
                'bytes_sent': f['bytes_sent'],
                'bytes_received': f['bytes_received'],
                'first_seen': datetime.fromtimestamp(f['first_seen'], tz=dt_timezone.utc),
                'last_seen': datetime.fromtimestamp(f['last_seen'], tz=dt_timezone.utc),
                'unique_dst_ports': len(f['dst_ports']),
                'tcp_flags_seen': ''.join(sorted(f['tcp_flags'])),
                'app_protocol': f['app_protocol'],
                'app_protocol_source': f['app_protocol_source'],
                'dns_query_count': f['dns_query_count'],
                'longest_dns_label': f['longest_dns_label'],
                'max_dns_entropy': round(f['max_dns_entropy'], 4),
                'http_host': f['http_host'],
                'tls_sni': f['tls_sni'],
                'ja4_fingerprint': f['ja4_fingerprint'],
                'ja4_raw': f['ja4_raw'],
                '_uid': f['_uid'],
                '_timestamps': f['timestamps'],
                **metrics,
            })
        # Attach the answers to the queries they belong to. Done here rather
        # than during the stream because a reply is only seen after its query
        # record already exists.
        for record in self.dns_records:
            addresses = self._dns_answers.get(record.pop('_answer_key'), [])
            record['response_ip'] = ', '.join(addresses)[:255]

        return results, self.dns_records
