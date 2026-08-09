import os
from django.core.management.base import BaseCommand, CommandError
from capture.service import run_pcap_import


class Command(BaseCommand):
    help = 'Import a stored PCAP file and store aggregated flows.'

    def add_arguments(self, parser):
        parser.add_argument('pcap_path', help='Path to the .pcap or .pcapng file')
        parser.add_argument('--name', default='', help='Session label')

    def handle(self, *args, **opts):
        path = opts['pcap_path']
        if not os.path.exists(path):
            raise CommandError(f'File not found: {path}')

        self.stdout.write(self.style.WARNING(f'Reading {path}…'))

        session, (flow_count, dns_count) = run_pcap_import(
            pcap_path=path,
            name=opts['name'] or None,
        )

        self.stdout.write(self.style.SUCCESS(
            f"\nSession #{session.id} '{session.name}' imported\n"
            f"  Packets : {session.packet_count:,}\n"
            f"  Bytes   : {session.byte_count:,}\n"
            f"  Flows   : {flow_count}\n"
            f"  DNS     : {dns_count}"
        ))