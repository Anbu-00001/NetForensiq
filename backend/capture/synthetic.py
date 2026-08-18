import random
import string
import time
from pathlib import Path

from scapy.all import wrpcap, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS, DNSQR


INTERNAL_HOSTS = [f'10.45.57.{i}' for i in range(20, 60)]
DNS_SERVER = '10.45.57.249'
GATEWAY = '10.45.57.1'

BENIGN_DESTINATIONS = [
    ('142.250.183.14', 'www.google.com'),
    ('13.107.42.14', 'www.bing.com'),
    ('151.101.1.140', 'www.reddit.com'),
    ('104.244.42.1', 'api.twitter.com'),
    ('52.84.150.39', 'cdn.amazonaws.com'),
    ('20.42.73.25', 'login.microsoftonline.com'),
    ('185.199.108.153', 'raw.githubusercontent.com'),
]

BENIGN_DOMAINS = [
    'www.google.com', 'mail.google.com', 'docs.google.com',
    'www.wikipedia.org', 'cdn.jsdelivr.net', 'fonts.gstatic.com',
    'api.github.com', 'update.microsoft.com', 'ntp.ubuntu.com',
]


def _rand_bytes(n):
    return bytes(random.getrandbits(8) for _ in range(n))


def _text_payload(n):
    """Low-entropy, human-readable payload — mimics plaintext protocols."""
    words = ['GET', 'POST', 'HTTP/1.1', 'Host:', 'User-Agent:', 'Accept:',
             'Content-Type:', 'text/html', 'charset=utf-8', 'Connection:', 'keep-alive']
    out = ' '.join(random.choice(words) for _ in range(n // 8))
    return out.encode()[:n]


# ─────────────────────── BENIGN BASELINE ───────────────────────

def generate_benign(packet_count=1200, base_time=None):
    packets = []
    t = base_time or time.time()
    sessions = []
    planned = 0

    while planned < packet_count:
        host = random.choice(INTERNAL_HOSTS)
        sport = random.randint(49152, 65535)
        roll = random.random()

        if roll < 0.25:
            s = {'kind': 'dns', 'src': host, 'sport': sport,
                 'domain': random.choice(BENIGN_DOMAINS),
                 'remaining': random.randint(1, 3)}
        elif roll < 0.80:
            dst_ip, _ = random.choice(BENIGN_DESTINATIONS)
            s = {'kind': 'https', 'src': host, 'sport': sport,
                 'dst': dst_ip, 'remaining': random.randint(10, 45)}
        elif roll < 0.95:
            dst_ip, hostname = random.choice(BENIGN_DESTINATIONS)
            s = {'kind': 'http', 'src': host, 'sport': sport,
                 'dst': dst_ip, 'host': hostname,
                 'remaining': random.randint(6, 20)}
        else:
            s = {'kind': 'icmp', 'src': host, 'sport': sport,
                 'remaining': random.randint(2, 6)}

        sessions.append(s)
        planned += s['remaining']

    active = list(sessions)

    while active and len(packets) < packet_count:
        s = random.choice(active)
        kind = s['kind']

        if kind == 'dns':
            pkt = (
                IP(src=s['src'], dst=DNS_SERVER)
                / UDP(sport=s['sport'], dport=53)
                / DNS(rd=1, qd=DNSQR(qname=s['domain'], qtype='A'))
            )
            pkt.time = t
            packets.append(pkt)

            resp = (
                IP(src=DNS_SERVER, dst=s['src'])
                / UDP(sport=53, dport=s['sport'])
                / DNS(qr=1, rd=1, qd=DNSQR(qname=s['domain'], qtype='A'))
            )
            resp.time = t + random.uniform(0.002, 0.02)
            packets.append(resp)

        elif kind == 'https':
            size = max(64, min(int(random.gauss(700, 350)), 1400))
            pkt = (
                IP(src=s['src'], dst=s['dst'])
                / TCP(sport=s['sport'], dport=443, flags='PA')
                / Raw(load=_rand_bytes(size))
            )
            pkt.time = t
            packets.append(pkt)

            # Downstream is usually larger than upstream when browsing
            if random.random() < 0.75:
                dsize = max(64, min(int(random.gauss(1100, 400)), 1440))
                resp = (
                    IP(src=s['dst'], dst=s['src'])
                    / TCP(sport=443, dport=s['sport'], flags='PA')
                    / Raw(load=_rand_bytes(dsize))
                )
                resp.time = t + random.uniform(0.004, 0.05)
                packets.append(resp)

        elif kind == 'http':
            pkt = (
                IP(src=s['src'], dst=s['dst'])
                / TCP(sport=s['sport'], dport=80, flags='PA')
                / Raw(load=_text_payload(random.randint(120, 600)))
            )
            pkt.time = t
            packets.append(pkt)

            if random.random() < 0.8:
                resp = (
                    IP(src=s['dst'], dst=s['src'])
                    / TCP(sport=80, dport=s['sport'], flags='PA')
                    / Raw(load=_text_payload(random.randint(400, 1200)))
                )
                resp.time = t + random.uniform(0.005, 0.06)
                packets.append(resp)

        else:  # icmp
            pkt = IP(src=s['src'], dst=GATEWAY) / ICMP() / Raw(load=_rand_bytes(48))
            pkt.time = t
            packets.append(pkt)

            reply = IP(src=GATEWAY, dst=s['src']) / ICMP(type=0) / Raw(load=_rand_bytes(48))
            reply.time = t + random.uniform(0.001, 0.01)
            packets.append(reply)

        t += random.uniform(0.005, 0.09)
        s['remaining'] -= 1
        if s['remaining'] <= 0:
            active.remove(s)

    return packets


# ─────────────────────── ATTACK SCENARIOS ───────────────────────

def generate_dns_tunneling(query_count=140, base_time=None, attacker='10.45.57.33'):
    """
    DNS tunneling: data is encoded into long, random subdomain labels
    and queried repeatedly against an attacker-controlled domain.

    Signals produced: very long subdomain labels, high query entropy,
    abnormal query frequency from a single host.
    """
    packets = []
    t = base_time or time.time()
    tunnel_domain = 'exfil-c2.net'

    for _ in range(query_count):
        chunk = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(40, 58)))
        qname = f'{chunk}.{tunnel_domain}'
        pkt = (
            IP(src=attacker, dst=DNS_SERVER)
            / UDP(sport=random.randint(49152, 65535), dport=53)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype='TXT'))
        )
        pkt.time = t
        t += random.uniform(0.02, 0.12)   # rapid, machine-driven cadence
        packets.append(pkt)

    return packets


def generate_data_exfiltration(packet_count=260, base_time=None, insider='10.45.57.41'):
    """
    Bulk outbound transfer to an unfamiliar external host.

    Signals produced: extreme bytes_ratio (almost all outbound),
    large sustained volume, high payload entropy, long session duration.
    """
    packets = []
    t = base_time or time.time()
    exfil_server = '203.0.113.77'
    sport = random.randint(49152, 65535)

    for i in range(packet_count):
        # Large, near-MTU packets carrying encrypted/compressed data
        pkt = (
            IP(src=insider, dst=exfil_server)
            / TCP(sport=sport, dport=8443, flags='PA')
            / Raw(load=_rand_bytes(random.randint(1200, 1440)))
        )
        pkt.time = t
        t += random.uniform(0.01, 0.05)
        packets.append(pkt)

        # Sparse ACKs back — the ratio stays heavily one-directional
        if i % 12 == 0:
            ack = (
                IP(src=exfil_server, dst=insider)
                / TCP(sport=8443, dport=sport, flags='A')
            )
            ack.time = t
            packets.append(ack)

    return packets


def generate_port_scan(base_time=None, scanner='10.45.57.52', target='10.45.57.10'):
    """
    Reconnaissance: SYN sweep across many ports on one target.

    Signals produced: very high unique_dst_ports, tiny packets,
    SYN-only flags, near-zero payload.
    """
    packets = []
    t = base_time or time.time()

    for port in random.sample(range(1, 1024), 400):
        pkt = (
            IP(src=scanner, dst=target)
            / TCP(sport=random.randint(49152, 65535), dport=port, flags='S')
        )
        pkt.time = t
        t += random.uniform(0.001, 0.006)
        packets.append(pkt)

    return packets


def generate_c2_beaconing(beacon_count=90, base_time=None, infected='10.45.57.28'):
    packets = []
    t = base_time or time.time()
    c2_server = '198.51.100.23'
    sport = random.randint(49152, 65535)
    interval = 30.0

    for _ in range(beacon_count):
        pkt = (
            IP(src=infected, dst=c2_server)
            / TCP(sport=sport, dport=443, flags='PA')
            / Raw(load=_rand_bytes(random.randint(180, 220)))
        )
        pkt.time = t
        packets.append(pkt)

        # Small uniform response from the C2 server
        resp = (
            IP(src=c2_server, dst=infected)
            / TCP(sport=443, dport=sport, flags='PA')
            / Raw(load=_rand_bytes(random.randint(40, 80)))
        )
        resp.time = t + random.uniform(0.05, 0.3)
        packets.append(resp)

        t += interval + random.uniform(-1.5, 1.5)

    return packets


def generate_c2_beaconing_connections(
    beacon_count=40, base_time=None, infected='10.45.57.29',
    c2_server='198.51.100.24', interval=45.0,
):
    """
    Beaconing that opens a NEW connection per callback.

    This is the shape RITA's algorithm is built for: periodicity lives in the
    gaps *between* connections, not between packets inside one. The other
    generator models the opposite case — a single session held open with
    periodic keepalives — and the two are detected by different rules.

    Having only the keepalive shape in the corpus is what let a beacon rule
    that counted packets-per-flow pass for RITA's connection counting; real
    malware traffic exposed it. Both shapes are now represented.
    """
    packets = []
    t = base_time or time.time()

    for _ in range(beacon_count):
        sport = random.randint(49152, 65535)
        seq = random.randint(1000, 900000)

        syn = IP(src=infected, dst=c2_server) / TCP(
            sport=sport, dport=8443, flags='S', seq=seq)
        syn.time = t
        packets.append(syn)

        synack = IP(src=c2_server, dst=infected) / TCP(
            sport=8443, dport=sport, flags='SA', seq=random.randint(1000, 900000),
            ack=seq + 1)
        synack.time = t + 0.04
        packets.append(synack)

        # Uniform-ish payload: RITA's data-size subscore rewards consistency
        req = (IP(src=infected, dst=c2_server)
               / TCP(sport=sport, dport=8443, flags='PA', seq=seq + 1)
               / Raw(load=_rand_bytes(random.randint(190, 210))))
        req.time = t + 0.08
        packets.append(req)

        resp = (IP(src=c2_server, dst=infected)
                / TCP(sport=8443, dport=sport, flags='PA')
                / Raw(load=_rand_bytes(random.randint(50, 70))))
        resp.time = t + 0.19
        packets.append(resp)

        fin = IP(src=infected, dst=c2_server) / TCP(
            sport=sport, dport=8443, flags='FA')
        fin.time = t + 0.24
        packets.append(fin)

        t += interval + random.uniform(-2.0, 2.0)

    return packets


def generate_icmp_tunnel(packet_count=120, base_time=None, host='10.45.57.37'):
    """
    ICMP tunneling: data hidden inside oversized ping payloads.

    Signals produced: ICMP packets far larger than the normal 32-64 bytes,
    high entropy inside what should be filler data.
    """
    packets = []
    t = base_time or time.time()
    remote = '198.51.100.99'

    for _ in range(packet_count):
        pkt = (
            IP(src=host, dst=remote)
            / ICMP(type=8)
            / Raw(load=_rand_bytes(random.randint(900, 1300)))
        )
        pkt.time = t
        t += random.uniform(0.05, 0.2)
        packets.append(pkt)

    return packets


# ─────────────────────── ORCHESTRATION ───────────────────────

def generate_covert_channel(
    base_time=None, infected='10.45.57.41', c2_server='198.51.100.77',
    port=3232, duration=200.0, exchanges=60,
):
    """
    A sustained conversation on a non-standard port that declares nothing.

    Modelled directly on real AsyncRAT traffic (malware-traffic-analysis.net,
    2024-03-14): a long-lived TCP session to port 3232 carrying encrypted
    payload, with no recognisable application protocol and — unlike every
    benign TLS flow beside it — no SNI announcing where it is going.

    That combination, not timing, is what identified the real sample. Its
    beacon period was not statistically detectable in 3.5 minutes of capture;
    the shape of the channel was. See research/96_REAL_TRAFFIC_VALIDATION.md.
    """
    packets = []
    t = base_time or time.time()
    sport = random.randint(49152, 65535)
    seq = random.randint(1000, 900000)

    syn = IP(src=infected, dst=c2_server) / TCP(sport=sport, dport=port, flags='S', seq=seq)
    syn.time = t
    packets.append(syn)

    synack = IP(src=c2_server, dst=infected) / TCP(
        sport=port, dport=sport, flags='SA', ack=seq + 1)
    synack.time = t + 0.03
    packets.append(synack)

    ack = IP(src=infected, dst=c2_server) / TCP(sport=sport, dport=port, flags='A')
    ack.time = t + 0.05
    packets.append(ack)

    # Encrypted-looking payload both ways, spread across the session
    step = duration / max(exchanges, 1)
    for i in range(exchanges):
        when = t + 0.1 + (i * step)
        out = (IP(src=infected, dst=c2_server)
               / TCP(sport=sport, dport=port, flags='PA')
               / Raw(load=_rand_bytes(random.randint(60, 240))))
        out.time = when
        packets.append(out)

        back = (IP(src=c2_server, dst=infected)
                / TCP(sport=port, dport=sport, flags='PA')
                / Raw(load=_rand_bytes(random.randint(40, 180))))
        back.time = when + random.uniform(0.05, 0.4)
        packets.append(back)

    return packets


def generate_compromised_host(base_time=None, victim='10.45.57.44',
                             c2_server='198.51.100.77'):
    """
    One host doing several things at once — what a real compromise looks like.

    Every other scenario in this file gives its behaviour to a different
    address: the DNS tunnel is .33, the scanner is .52, the beacon is .28. That
    made each rule easy to test in isolation and made the corpus quietly
    unrealistic, because an actual compromised workstation beacons to its C2,
    holds a covert channel open and pushes data out — all from one machine.

    It also meant nothing in the corpus could exercise the corroboration pass,
    which exists precisely to notice a host that several independent rules keep
    pointing at.

    The real AsyncRAT capture behaves this way: one victim, several behaviours,
    one operator.
    """
    t = base_time or time.time()
    packets = []
    packets += generate_c2_beaconing_connections(base_time=t, infected=victim,
                                                 c2_server=c2_server)
    packets += generate_covert_channel(base_time=t + 300, infected=victim,
                                       c2_server=c2_server)
    packets += generate_dns_tunneling(base_time=t + 600, attacker=victim)
    packets += generate_data_exfiltration(base_time=t + 900, insider=victim)
    return packets


SCENARIOS = {
    'benign': generate_benign,
    'dns_tunnel': generate_dns_tunneling,
    'exfiltration': generate_data_exfiltration,
    'port_scan': generate_port_scan,
    'c2_beacon': generate_c2_beaconing,
    'icmp_tunnel': generate_icmp_tunnel,
    'c2_beacon_connections': generate_c2_beaconing_connections,
    'covert_channel': generate_covert_channel,
    'compromised_host': generate_compromised_host,
}


def build_mixed_capture(output_path, benign_packets=1500, include_attacks=True, seed=None):
    """
    Produces one PCAP containing a benign baseline with attacks
    interleaved at realistic points — this is the demo storyline file.
    """
    if seed is not None:
        random.seed(seed)

    start = time.time() - 3600   # backdate so timestamps look historical
    all_packets = []

    all_packets += generate_benign(benign_packets, base_time=start)

    if include_attacks:
        all_packets += generate_dns_tunneling(base_time=start + 420)
        all_packets += generate_port_scan(base_time=start + 900)
        # Both beacon shapes are present deliberately: one session held
        # open with keepalives, and repeated short connections. They are
        # detected by different rules, and having only the first in the corpus
        # is what let a broken beacon rule look correct for weeks.
        all_packets += generate_c2_beaconing(base_time=start + 1200)
        all_packets += generate_c2_beaconing_connections(base_time=start + 1500)
        all_packets += generate_icmp_tunnel(base_time=start + 1800)
        all_packets += generate_covert_channel(base_time=start + 2100)
        all_packets += generate_data_exfiltration(base_time=start + 2400)
        # One host exhibiting several behaviours, so the corpus contains
        # the case the corroboration pass exists for.
        all_packets += generate_compromised_host(base_time=start + 2700)

    all_packets.sort(key=lambda p: p.time)

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), all_packets)

    return len(all_packets), str(output_path)