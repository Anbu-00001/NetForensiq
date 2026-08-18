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
            '--officer', default='',
            help=(
                'Username of the officer taking custody. Every custody entry '
                'this import writes is attributed to them. Omitted, the entries '
                'carry no officer and print as blank on the certificate rather '
                'than naming a placeholder.'
            ),
        )
        parser.add_argument(
            '--home-net', default='',
            help=(
                'Comma-separated CIDRs describing the network this capture was '
                'taken inside, e.g. 10.3.14.0/24. Egress rules only fire for '
                'initiators inside it. Omit for the deployment default '
                '(RFC 1918); set it explicitly for a capture of a '
                'public-facing server, whose own addresses are public.'
            ),
        )
        parser.add_argument(
            '--provenance', choices=['seized', 'reference', 'synthetic'], default=None,
            help=(
                'Declare where this capture came from. Omit to take the sidecar '
                'manifest beside the file, or to record it as unattested when '
                'there is none. Use "seized" only for a capture actually taken '
                'from a network under investigation.'
            ),
        )
        parser.add_argument(
            '--no-seal', action='store_true',
            help='Import for analysis only, without taking the file into evidence.',
        )

    def handle(self, *args, **opts):
        path = opts['pcap_path']
        if not os.path.exists(path):
            raise CommandError(f'File not found: {path}')

        officer = None
        if opts['officer']:
            from django.contrib.auth import get_user_model

            try:
                officer = get_user_model().objects.get(username=opts['officer'])
            except get_user_model().DoesNotExist:
                raise CommandError(
                    f"No such user: {opts['officer']}. Custody must be attributed to "
                    f"an account that exists, not to a name typed at the console."
                )

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
                provenance=opts['provenance'],
                collected_by=officer,
            )
            self.stdout.write(self.style.SUCCESS(
                f"  Exhibit : {record.exhibit_number}\n"
                f"  SHA-256 : {record.sha256_hash}"
            ))
            style = (
                self.style.ERROR if record.is_demonstration_only else self.style.WARNING
            )
            self.stdout.write(style(
                f"  Origin  : {record.get_provenance_display()}"
            ))
            # Analyse the sealed copy, not the original: it is the artefact the
            # hash describes and the one a court will be shown.
            path = record.stored_path

        self.stdout.write(self.style.WARNING(f'Reading {path}…'))

        session, (flow_count, dns_count) = run_pcap_import(
            pcap_path=path,
            name=opts['name'] or None,
            home_net=opts['home_net'],
            user=officer,
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
