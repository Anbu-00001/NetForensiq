import json

from django.core.management.base import BaseCommand, CommandError

from capture.home_net import suggest


class Command(BaseCommand):
    """
    Propose the monitored network for a capture, showing the working.

    Deliberately does not set anything. The value decides whether every egress
    rule fires or inverts, so it is stated with its basis and left for an
    officer to pass to `import_pcap --home-net`.
    """

    help = 'Propose a $HOME_NET for a capture, with the evidence for the proposal.'

    def add_arguments(self, parser):
        parser.add_argument('pcap_path')
        parser.add_argument('--sample', type=int, default=None,
                            help='Packets to read before deciding')
        parser.add_argument('--json', action='store_true', help='Machine-readable output')

    def handle(self, *args, **opts):
        import os

        if not os.path.exists(opts['pcap_path']):
            raise CommandError(f"File not found: {opts['pcap_path']}")

        kwargs = {'sample': opts['sample']} if opts['sample'] else {}
        proposal, detail = suggest(opts['pcap_path'], **kwargs)

        if opts['json']:
            self.stdout.write(json.dumps({'proposal': proposal, **detail}, indent=2))
            return

        if not proposal:
            self.stdout.write(self.style.ERROR(
                f"No proposal: {detail.get('reason', 'inconclusive')}.\n"
                f"Set --home-net explicitly from what you know about the capture."
            ))
            return

        self.stdout.write(self.style.SUCCESS(f'\n  --home-net {proposal}\n'))
        self.stdout.write(f"  Sampled {detail['sampled_packets']:,} packets.")
        self.stdout.write(f"  {detail['basis']}\n")
        self.stdout.write(
            '  Busiest networks in the sample (an appearance is one endpoint of\n'
            '  one packet, so the totals sum to about twice the packet count):'
        )
        for entry in detail['top_networks']:
            hosts = ', '.join(
                f"{h['address']} ({h['appearances']:,})" for h in entry['busy_hosts']
            ) or '—'
            self.stdout.write(
                f"    {entry['network']:<22} "
                f"{entry['endpoint_appearances']:>10,} appearances   {hosts}"
            )
        self.stdout.write(self.style.WARNING(f"\n  {detail['heuristic']}"))
