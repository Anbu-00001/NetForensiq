import time
from datetime import datetime, timezone as dt_timezone

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS

from .features import shannon_entropy, dns_query_features, compute_flow_metrics


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

# Cap on per-flow entropy samples, and on bytes hashed per sample. Bounds
# memory on large captures without materially changing the entropy estimate.
MAX_ENTROPY_SAMPLES = 40
ENTROPY_SAMPLE_BYTES = 512


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


class FlowAggregator:
    """
    Accumulates packets into flow records in memory, then hands them to the
    persistence layer via finalize().

    Memory is bounded by the number of distinct flows, not by packet count,
    so a long capture of few conversations stays cheap. Callers ingesting
    very large PCAPs should stream packets in (see service.iter_pcap).
    """

    def __init__(self):
        self.flows = {}
        self.dns_records = []
        self.total_packets = 0
        self.total_bytes = 0
        self.first_packet_time = None
        self.last_packet_time = None

    # ── ingestion ────────────────────────────────────────────────────────

    def process(self, pkt):
        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
        else:
            return

        src_ip, dst_ip = ip_layer.src, ip_layer.dst

        self.total_packets += 1
        pkt_len = len(pkt)
        self.total_bytes += pkt_len

        now = packet_timestamp(pkt)
        if self.first_packet_time is None or now < self.first_packet_time:
            self.first_packet_time = now
        if self.last_packet_time is None or now > self.last_packet_time:
            self.last_packet_time = now

        protocol, sport, dport, flags = self._classify(pkt)
        key = flow_key(src_ip, dst_ip, sport, dport, protocol)

        f = self.flows.get(key)
        if f is None:
            f = self._new_flow(key, protocol, src_ip, sport, now)
            self.flows[key] = f

        # Establish direction. A TCP SYN without ACK is definitive proof of
        # who opened the conversation, and overrides the first-seen guess —
        # captures frequently start mid-stream.
        if protocol == 'TCP' and 'S' in flags and 'A' not in flags:
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
            f['app_protocol'] = (
                WELL_KNOWN_PORTS.get(dport) or WELL_KNOWN_PORTS.get(sport) or ''
            )

        payload = self._payload_of(pkt, protocol)
        if payload and len(f['entropy_samples']) < MAX_ENTROPY_SAMPLES:
            f['entropy_samples'].append(
                shannon_entropy(payload[:ENTROPY_SAMPLE_BYTES])
            )

        if DNS in pkt:
            self._process_dns(pkt, f, src_ip, now)

        if protocol == 'TCP' and payload:
            self._process_app_layer(payload, f, dport)

    def _classify(self, pkt):
        """Return (protocol, sport, dport, tcp_flags)."""
        if TCP in pkt:
            return 'TCP', pkt[TCP].sport, pkt[TCP].dport, self._decode_tcp_flags(pkt[TCP].flags)
        if UDP in pkt:
            return 'UDP', pkt[UDP].sport, pkt[UDP].dport, ''
        if ICMP in pkt:
            # ICMP has no ports. Following the Cisco NetFlow convention, the
            # type and code are packed into the destination port field as
            # type*256 + code, so the message kind survives flow aggregation.
            # Without it every ICMP flow looks alike, and the tunnel rule
            # cannot tell an echo request carrying data from a destination-
            # unreachable error — which quotes the original packet headers and
            # is therefore also large.
            icmp = pkt[ICMP]
            return 'ICMP', 0, (int(icmp.type) * 256) + int(icmp.code), ''
        return 'OTHER', 0, 0, ''

    def _new_flow(self, key, protocol, src_ip, sport, now):
        return {
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
            'http_host': '',
            'tls_sni': '',
        }

    def _payload_of(self, pkt, protocol):
        try:
            if protocol == 'TCP':
                return bytes(pkt[TCP].payload)
            if protocol == 'UDP':
                return bytes(pkt[UDP].payload)
            if protocol == 'ICMP':
                return bytes(pkt[ICMP].payload)
        except Exception:
            return b''
        return b''

    def _decode_tcp_flags(self, flag_value):
        return ''.join(
            char for bit, char in TCP_FLAG_MAP.items() if int(flag_value) & bit
        )

    def _process_dns(self, pkt, f, src_ip, now):
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:
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

        qtype = ''
        try:
            qtype = dns.qd.get_field('qtype').i2repr(dns.qd, dns.qd.qtype)
        except Exception:
            pass

        self.dns_records.append({
            'src_ip': src_ip,
            'query_name': qname.rstrip('.')[:512],
            'query_type': qtype[:12],
            'subdomain_length': feats['subdomain_length'],
            'label_count': feats['label_count'],
            'query_entropy': feats['query_entropy'],
            'timestamp': datetime.fromtimestamp(now, tz=dt_timezone.utc),
            'flow_key': (f['src_ip'], f['src_port'], f['dst_ip'], f['dst_port'], f['protocol']),
        })

    def _process_app_layer(self, payload, f, dport):
        # HTTP Host header
        if dport in (80, 8080) and not f['http_host']:
            try:
                text = payload[:400].decode('utf-8', errors='ignore')
                for line in text.split('\r\n'):
                    if line.lower().startswith('host:'):
                        f['http_host'] = line.split(':', 1)[1].strip()[:255]
                        f['app_protocol'] = 'HTTP'
                        break
            except Exception:
                pass

        # TLS SNI from ClientHello — gives us the destination domain
        # even though the session is encrypted. This is the
        # "encrypted traffic analysis without decryption" capability.
        elif dport == 443 and not f['tls_sni']:
            sni = self._extract_sni(payload)
            if sni:
                f['tls_sni'] = sni[:255]
                f['app_protocol'] = 'TLS'

    def _extract_sni(self, data):
        """
        Pull the server_name from a TLS ClientHello.

        Offset 43 = 5-byte record header + 4-byte handshake header
        + 2-byte client version + 32-byte random, which lands on session_id.
        Only handles a ClientHello contained in a single segment; fragmented
        handshakes are skipped rather than guessed at.
        """
        try:
            if len(data) < 45 or data[0] != 0x16:
                return None
            pos = 43
            sid_len = data[pos]
            pos += 1 + sid_len
            cs_len = int.from_bytes(data[pos:pos + 2], 'big')
            pos += 2 + cs_len
            comp_len = data[pos]
            pos += 1 + comp_len
            ext_total = int.from_bytes(data[pos:pos + 2], 'big')
            pos += 2
            end = pos + ext_total

            while pos + 4 <= end and pos + 4 <= len(data):
                ext_type = int.from_bytes(data[pos:pos + 2], 'big')
                ext_len = int.from_bytes(data[pos + 2:pos + 4], 'big')
                pos += 4
                if ext_type == 0x0000:
                    name_len = int.from_bytes(data[pos + 3:pos + 5], 'big')
                    return data[pos + 5:pos + 5 + name_len].decode('utf-8', errors='ignore')
                pos += ext_len
        except Exception:
            return None
        return None

    # ── output ───────────────────────────────────────────────────────────

    def finalize(self):
        """Convert in-memory state into database-ready dicts."""
        results = []
        for key, f in self.flows.items():
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
                'dns_query_count': f['dns_query_count'],
                'longest_dns_label': f['longest_dns_label'],
                'max_dns_entropy': round(f['max_dns_entropy'], 4),
                'http_host': f['http_host'],
                'tls_sni': f['tls_sni'],
                '_key': key,
                '_timestamps': f['timestamps'],
                **metrics,
            })
        return results, self.dns_records
