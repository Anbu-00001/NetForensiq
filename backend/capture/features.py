import math
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


def compute_flow_metrics(flow_state):
    """Derive the numeric feature vector from accumulated flow counters."""
    duration = max(flow_state['last_seen'] - flow_state['first_seen'], 0.0)
    total_packets = flow_state['packets_sent'] + flow_state['packets_received']
    total_bytes = flow_state['bytes_sent'] + flow_state['bytes_received']

    avg_packet_size = (total_bytes / total_packets) if total_packets else 0.0
    packets_per_second = (total_packets / duration) if duration > 0.1 else float(total_packets)
    bytes_ratio = (flow_state['bytes_sent'] / total_bytes) if total_bytes else 0.0

    entropy_samples = flow_state.get('entropy_samples', [])
    payload_entropy = (sum(entropy_samples) / len(entropy_samples)) if entropy_samples else 0.0

    return {
        'duration_seconds': round(duration, 3),
        'avg_packet_size': round(avg_packet_size, 2),
        'packets_per_second': round(packets_per_second, 3),
        'bytes_ratio': round(bytes_ratio, 4),
        'payload_entropy': round(payload_entropy, 4),
    }