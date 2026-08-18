"""
Suggesting the monitored network for a capture.

Why a suggestion and not a setting
----------------------------------
Every egress rule in the engine depends on knowing which addresses are inside
the network under investigation. Get it wrong and the rules invert: on a
capture of a public-facing server, an RFC 1918 default made every scanner on
the internet reaching *in* look like an internal host calling *out* — 7,052
alerts, all wrong (research/96).

The answer is a property of the traffic, so the traffic is where it should be
read from. But it is read as a **proposal**: this module never sets HOME_NET.
It prints what it found and how it decided, and an officer passes
`--home-net` if they agree. An inferred value applied silently would be a
guess wearing the clothes of a measurement.

The heuristic
-------------
[OUR HEURISTIC] — no published algorithm to cite; the reasoning is stated so
it can be argued with:

  * A monitored host appears in a large share of the capture, because the
    capture was taken at or near it.
  * Hosts on the far side appear once or twice each.

So: tally packets per address, group the addresses by /24, and rank the
groups. If a group holds several busy hosts, the network is the /24. If it
holds exactly one, the network is that host alone — proposing its whole /24
would claim monitoring of neighbours that never appeared.
"""

import ipaddress
from collections import Counter

from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

# How many packets to read before deciding. A monitored host shows up in the
# first few seconds; reading a multi-gigabyte capture twice to answer a
# question this coarse is not a good trade.
SAMPLE_PACKETS = 200_000

# A host is "busy" if it carries at least this share of the sampled packets.
# Low enough to keep a quiet workstation on a monitored LAN, high enough to
# exclude a remote peer that happened to be chatty.
BUSY_SHARE = 0.01


def _addresses(packet):
    layer = packet.getlayer(IP) or packet.getlayer(IPv6)
    if layer is None:
        return None
    return layer.src, layer.dst


def observe(pcap_path, sample=SAMPLE_PACKETS):
    """Packets per address over the first `sample` packets."""
    counts = Counter()
    seen = 0
    with PcapReader(str(pcap_path)) as reader:
        for packet in reader:
            pair = _addresses(packet)
            if pair is None:
                continue
            counts[pair[0]] += 1
            counts[pair[1]] += 1
            seen += 1
            if seen >= sample:
                break
    return counts, seen


def _group_key(address):
    """The /24 an IPv4 address sits in, or the /64 for IPv6."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return None
    prefix = 24 if parsed.version == 4 else 64
    return ipaddress.ip_network(f'{address}/{prefix}', strict=False)


def suggest(pcap_path, sample=SAMPLE_PACKETS, busy_share=BUSY_SHARE):
    """
    (proposal, explanation) for a capture.

    `proposal` is a comma-separated CIDR string suitable for --home-net, or ''
    when the traffic gives no clear answer — in which case the caller must ask
    rather than invent one.
    """
    counts, sampled = observe(pcap_path, sample)
    if not sampled:
        return '', {'sampled_packets': 0, 'reason': 'no IP packets in the sample'}

    busy_floor = max(1, int(sampled * busy_share))

    groups = {}
    for address, hits in counts.items():
        key = _group_key(address)
        if key is None:
            continue
        entry = groups.setdefault(key, {'packets': 0, 'busy_hosts': []})
        entry['packets'] += hits
        if hits >= busy_floor:
            entry['busy_hosts'].append((address, hits))

    if not groups:
        return '', {'sampled_packets': sampled, 'reason': 'no parseable addresses'}

    ranked = sorted(groups.items(), key=lambda kv: kv[1]['packets'], reverse=True)
    network, detail = ranked[0]
    busy = sorted(detail['busy_hosts'], key=lambda h: h[1], reverse=True)

    if not busy:
        return '', {
            'sampled_packets': sampled,
            'reason': 'no address carried enough of the capture to look monitored',
        }

    if len(busy) >= 2:
        proposal = str(network)
        basis = (
            f'{len(busy)} hosts in {network} each carried at least '
            f'{busy_share:.0%} of the sampled packets, so the monitored network '
            f'is the range rather than any one host.'
        )
    else:
        address = busy[0][0]
        parsed = ipaddress.ip_address(address)
        proposal = f'{address}/{32 if parsed.version == 4 else 128}'
        basis = (
            f'only {address} carried a meaningful share of the capture. The '
            f'proposal is that host alone: claiming all of {network} would '
            f'assert monitoring of neighbours that never appeared in the traffic.'
        )

    return proposal, {
        'sampled_packets': sampled,
        'busy_threshold_packets': busy_floor,
        'top_networks': [
            {
                'network': str(net),
                'packets': info['packets'],
                'busy_hosts': [
                    {'address': a, 'packets': n}
                    for a, n in sorted(info['busy_hosts'], key=lambda h: h[1], reverse=True)[:5]
                ],
            }
            for net, info in ranked[:5]
        ],
        'basis': basis,
        'heuristic': (
            '[OUR HEURISTIC] Derived from observed packet volume, not from any '
            'published algorithm. It is a proposal for an officer to confirm.'
        ),
    }
