from django.core.management.base import BaseCommand, CommandError
from capture.privileges import can_capture
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
        parser.add_argument(
            '--window', type=int, default=0,
            help='Monitor mode: re-run every rule and alert on new findings '
                 'every N seconds, instead of analysing once at the end. '
                 'Latency to an alert becomes one window. Try 30.',
        )
        parser.add_argument(
            '--home-net', default='',
            help='The address space being monitored, e.g. 10.0.0.0/8. Egress '
                 'rules only fire for initiators inside it.',
        )

    def handle(self, *args, **opts):
        if not opts['count'] and not opts['duration']:
            raise CommandError('Specify --count or --duration so the capture terminates.')

        # Asked before the capture rather than inferred from an empty result.
        ok, reason = can_capture()
        if not ok:
            raise CommandError(reason)

        mode = (f"monitoring, {opts['window']}s windows" if opts['window']
                else 'recording, analysed at the end')
        self.stdout.write(self.style.WARNING(
            f"Capturing on interface {opts['iface']} ({mode})… "
            f"press Ctrl+C to stop early."
        ))

        def report(window):
            # Printed as each window closes so an operator watching a terminal
            # sees the same thing the alert sink is being sent.
            line = (f"  [{window['elapsed_seconds']:>6.1f}s] "
                    f"{window['packets']:>8,} pkts  "
                    f"{window['flows']:>5} flows  "
                    f"{window['findings_total']:>4} findings")
            if window['findings_new']:
                self.stdout.write(self.style.ERROR(
                    f"{line}  ← {window['findings_new']} NEW"))
                for title in window['new'][:5]:
                    self.stdout.write(self.style.ERROR(f"        {title}"))
                for delivery in window['alerts']:
                    state = 'sent' if delivery['ok'] else f"FAILED: {delivery['error']}"
                    self.stdout.write(
                        f"        → {delivery['transport']} "
                        f"{delivery['destination']}: {state}")
            else:
                self.stdout.write(line)

        session, (flow_count, dns_count) = run_live_capture(
            interface=opts['iface'],
            packet_count=opts['count'],
            duration=opts['duration'],
            bpf_filter=opts['filter'],
            name=opts['name'] or None,
            window_seconds=opts['window'],
            home_net=opts['home_net'],
            on_window=report if opts['window'] else None,
        )

        self.stdout.write(self.style.SUCCESS(
            f"\nSession #{session.id} '{session.name}' complete\n"
            f"  Packets : {session.packet_count:,}\n"
            f"  Bytes   : {session.byte_count:,}\n"
            f"  Flows   : {flow_count}\n"
            f"  DNS     : {dns_count}"
        ))