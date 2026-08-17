from django.core.management.base import BaseCommand
from capture.synthetic import build_mixed_capture, SCENARIOS, generate_benign
from scapy.all import wrpcap
from pathlib import Path
import time


class Command(BaseCommand):
    help = 'Generate synthetic PCAP files for training data and demo scenarios.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--scenario', default='mixed',
            help=f"One of: mixed, {', '.join(SCENARIOS.keys())}",
        )
        parser.add_argument('--output', default='', help='Output .pcap path')
        parser.add_argument('--benign', type=int, default=1500, help='Benign packet count for mixed')
        parser.add_argument('--seed', type=int, default=None, help='Random seed for reproducibility')

    def handle(self, *args, **opts):
        scenario = opts['scenario']
        out_dir = Path('synthetic_captures')
        out_dir.mkdir(exist_ok=True)

        if scenario == 'mixed':
            path = opts['output'] or out_dir / 'demo_storyline.pcap'
            count, written = build_mixed_capture(
                path, benign_packets=opts['benign'], seed=opts['seed'],
            )
            self.stdout.write(self.style.SUCCESS(
                f'\nGenerated {count:,} packets → {written}\n'
                f'  Contains: benign baseline + DNS tunnel + port scan\n'
                f'            + C2 beaconing, both shapes (one persistent session\n'
                f'              with keepalives, and repeated short connections)\n'
                f'            + covert channel on a non-standard port\n'
                f'            + ICMP tunnel + exfiltration'
            ))

        elif scenario == 'benign':
            path = opts['output'] or out_dir / 'benign_baseline.pcap'
            packets = generate_benign(opts['benign'], base_time=time.time() - 3600)
            wrpcap(str(path), packets)
            self.stdout.write(self.style.SUCCESS(
                f'\nGenerated {len(packets):,} benign packets → {path}'
            ))

        elif scenario in SCENARIOS:
            path = opts['output'] or out_dir / f'{scenario}.pcap'
            packets = SCENARIOS[scenario](base_time=time.time() - 3600)
            wrpcap(str(path), packets)
            self.stdout.write(self.style.SUCCESS(
                f'\nGenerated {len(packets):,} packets [{scenario}] → {path}'
            ))

        else:
            self.stdout.write(self.style.ERROR(
                f"Unknown scenario '{scenario}'. Options: mixed, {', '.join(SCENARIOS.keys())}"
            ))