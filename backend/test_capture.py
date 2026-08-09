from scapy.all import sniff, conf
from capture.processor import FlowAggregator

IFACE = conf.ifaces.dev_from_index(9)

print(f"Capturing on: {IFACE}")
print("Generating traffic helps — browse a website while this runs.\n")

agg = FlowAggregator()

sniff(iface=IFACE, prn=agg.process, count=200, store=False)

flows, dns = agg.finalize()

print(f"\nPackets processed : {agg.total_packets}")
print(f"Bytes processed   : {agg.total_bytes:,}")
print(f"Flows built       : {len(flows)}")
print(f"DNS queries       : {len(dns)}\n")

print("Top flows by volume:")
for f in sorted(flows, key=lambda x: x['bytes_sent'] + x['bytes_received'], reverse=True)[:8]:
    total = f['bytes_sent'] + f['bytes_received']
    label = f['tls_sni'] or f['http_host'] or f['app_protocol'] or '-'
    print(
        f"  {f['src_ip']}:{f['src_port']} → {f['dst_ip']}:{f['dst_port']} "
        f"[{f['protocol']}] {total:,}B  entropy={f['payload_entropy']:.2f}  {label}"
    )