import os

from django.core.management.base import BaseCommand, CommandError

from capture.service import run_pcap_import


class Command(BaseCommand):
    """
    Import a stored PCAP.

    By default the file is **sealed first**: hashed, copied into the evidence
    store, and given a custody record, before anything reads it for analysis.
    That ordering is the whole point of the evidence layer — a digest taken
    after parsing describes a file we have already opened, not the artefact as
    received.

    This used to be documented and not done. `run_pcap_import` read packets and
    persisted flows; `ingest_evidence` existed but was called from nothing
    except the test suite, so an exhibit could only be created by hand in
    `manage.py shell` and the sealing pipeline in the README described a code
    path that did not exist.

    `--no-seal` skips it, for the case where a capture is being explored rather
    than taken into evidence.
    """

    help = 'Seal a stored PCAP into evidence and import its flows.'

    def add_arguments(self, parser):
        parser.add_argument('pcap_path', help='Path to the .pcap or .pcapng file')
        parser.add_argument('--name', default='', help='Session label')
        parser.add_argument('--case', default='', help='Case reference (FIR/CR number)')
        parser.add_argument('--seized-from', default='', help='Where the capture was taken')
        parser.add_argument('--exhibit', default='', help='Exhibit number (generated if omitted)')
        parser.add_argument(
            '--no-seal', action='store_true',
            help='Import for analysis only, without taking the file into evidence.',
        )

    def handle(self, *args, **opts):
        path = opts['pcap_path']
        if not os.path.exists(path):
            raise CommandError(f'File not found: {path}')

        record = None
        if not opts['no_seal']:
            # Imported here so `--no-seal` works even if the evidence app is
            # unavailable for some reason.
            from evidence.service import ingest_evidence

            self.stdout.write(self.style.WARNING(f'Sealing {path} before reading it…'))
            record = ingest_evidence(
                path,
                exhibit_number=opts['exhibit'] or None,
                case_reference=opts['case'],
                seized_from=opts['seized_from'],
            )
            self.stdout.write(self.style.SUCCESS(
                f"  Exhibit : {record.exhibit_number}\n"
                f"  SHA-256 : {record.sha256_hash}"
            ))
            # Analyse the sealed copy, not the original: it is the artefact the
            # hash describes and the one a court will be shown.
            path = record.stored_path

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
        if record:
            self.stdout.write(
                f"  Sealed as exhibit {record.exhibit_number} "
                f"({record.custody_events.count()} custody entries)"
            )
        else:
            self.stdout.write(self.style.WARNING(
                '  NOT sealed (--no-seal): this capture is not in evidence.'
            ))
