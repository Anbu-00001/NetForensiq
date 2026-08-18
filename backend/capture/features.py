import math
import statistics
from collections import Counter


def shannon_entropy(data):
    """
    Measures randomness in bytes (0 = uniform, 8 = maximum randomness).
    Encrypted or compressed payloads score high; plain text scores low.
    This is a primary exfiltration signal — data being smuggled out is
    usually encrypted or compressed first.
    """
    if not data:
        return 0.0

    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')

    counts = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def dns_query_features(qname):
    """
    DNS tunneling hides data inside subdomain labels, producing
    abnormally long, high-entropy labels. Normal domains don't look
    like 'a8f3d9e2b1c4f7a0.tunnel.example.com'.
    """
    if not qname:
        return {'subdomain_length': 0, 'label_count': 0, 'query_entropy': 0.0}

    qname = qname.rstrip('.')
    labels = qname.split('.')

    # Ignore the registrable domain; tunneled data lives in the leftmost labels
    subdomain_labels = labels[:-2] if len(labels) > 2 else []
    longest = max((len(l) for l in subdomain_labels), default=0)

    return {
        'subdomain_length': longest,
        'label_count': len(labels),
        'query_entropy': shannon_entropy(''.join(subdomain_labels)),
    }


def interval_features(timestamps):
    """
    Timing statistics over the gaps between packets in a flow.

    Automated callbacks produce gaps clustered tightly around a target
    period; human-driven traffic does not. Median absolute deviation is the
    discriminator of choice here because it is robust to the occasional huge
    gap (a laptop sleeping, a network blip) that would wreck a plain stddev.

    Requires real packet timestamps to mean anything — see
    processor.packet_timestamp.
    """
    empty = {
        'interval_count': 0,
        'interval_mean': 0.0,
        'interval_median': 0.0,
        'interval_stddev': 0.0,
        'interval_mad': 0.0,
        'interval_dispersion': 0.0,
    }

    if not timestamps or len(timestamps) < 3:
        return empty

    ordered = sorted(timestamps)
    gaps = [b - a for a, b in zip(ordered, ordered[1:]) if (b - a) > 0]

    if len(gaps) < 2:
        return empty

    mean = statistics.fmean(gaps)
    median = statistics.median(gaps)
    stddev = statistics.pstdev(gaps)
    mad = statistics.median([abs(g - median) for g in gaps])

    # Normalised jitter: 0 = perfectly periodic, higher = more irregular.
    # Dividing by the median makes it comparable across different periods,
    # so a 30s beacon and a 300s beacon score alike.
    dispersion = (mad / median) if median > 0 else 0.0

    return {
        'interval_count': len(gaps),
        'interval_mean': round(mean, 4),
        'interval_median': round(median, 4),
        'interval_stddev': round(stddev, 4),
        'interval_mad': round(mad, 4),
        'interval_dispersion': round(dispersion, 4),
    }


def compute_flow_metrics(flow_state):
    """Derive the numeric feature vector from accumulated flow counters."""
    duration = max(flow_state['last_seen'] - flow_state['first_seen'], 0.0)
    total_packets = flow_state['packets_sent'] + flow_state['packets_received']
    total_bytes = flow_state['bytes_sent'] + flow_state['bytes_received']

    avg_packet_size = (total_bytes / total_packets) if total_packets else 0.0

    # Below ~0.1s of observed duration the rate is not measurable; reporting
    # the raw packet count would invent a per-second figure from a single
    # instant, so report 0 and let consumers treat it as "unknown".
    packets_per_second = (total_packets / duration) if duration > 0.1 else 0.0

    # Share of bytes originating from the side that opened the conversation.
    # >0.5 means the initiator is pushing data outward — the exfiltration
    # shape. This is only meaningful because direction is anchored to the
    # initiator rather than to IP sort order.
    bytes_ratio = (flow_state['bytes_sent'] / total_bytes) if total_bytes else 0.0

    entropy_samples = flow_state.get('entropy_samples', [])
    payload_entropy = (sum(entropy_samples) / len(entropy_samples)) if entropy_samples else 0.0

    metrics = {
        'duration_seconds': round(duration, 3),
        'avg_packet_size': round(avg_packet_size, 2),
        'packets_per_second': round(packets_per_second, 3),
        'bytes_ratio': round(bytes_ratio, 4),
        'payload_entropy': round(payload_entropy, 4),
        # How much of the flow the entropy estimate actually saw. Reported
        # in every finding that compares it against a threshold.
        'entropy_sample_count': len(entropy_samples),
    }
    # Beacon periodicity is measured on outbound packets only.
    metrics.update(interval_features(flow_state.get('timestamps_out', [])))
    return metrics
