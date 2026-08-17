from django.core.management.base import BaseCommand, CommandError
from capture.service import run_live_capture


class Command(BaseCommand):
    help = 'Capture live network traffic and store aggregated flows.'

    def add_arguments(self, parser):
        # No default. It used to be '9' — a scapy interface index that meant
        # something on one developer's machine and something arbitrary on
        # everyone else's, so running the documented command without --iface
        # captured on whatever happened to be ninth. Capturing the wrong
        # interface is not a recoverable mistake in an investigation.
        parser.add_argument(
            '--iface', required=True,
            help='Interface to capture on: a device name (eth0, wlan0) or a '
                 'scapy interface index. List them with: python -c '
                 '"from scapy.all import conf; print(conf.ifaces)"',
        )
        parser.add_argument('--count', type=int, default=0, help='Stop after N packets (0 = unlimited)')
        parser.add_argument('--duration', type=int, default=0, help='Stop after N seconds (0 = unlimited)')
        parser.add_argument('--filter', default='', help='BPF filter, e.g. "tcp port 443"')
        parser.add_argument('--name', default='', help='Session label')

    def handle(self, *args, **opts):
        if not opts['count'] and not opts['duration']:
            raise CommandError('Specify --count or --duration so the capture terminates.')

        self.stdout.write(self.style.WARNING(
            f"Capturing on interface {opts['iface']}… press Ctrl+C to stop early."
        ))

        session, (flow_count, dns_count) = run_live_capture(
            interface=opts['iface'],
            packet_count=opts['count'],
            duration=opts['duration'],
            bpf_filter=opts['filter'],
            name=opts['name'] or None,
        )

        self.stdout.write(self.style.SUCCESS(
            f"\nSession #{session.id} '{session.name}' complete\n"
            f"  Packets : {session.packet_count:,}\n"
            f"  Bytes   : {session.byte_count:,}\n"
            f"  Flows   : {flow_count}\n"
            f"  DNS     : {dns_count}"
        ))