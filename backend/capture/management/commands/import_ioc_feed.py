"""
Import a threat-intelligence feed from a file.

Deliberately a file, and deliberately a command an officer runs rather than a
scheduled fetch. The reasoning is in `capture/ioc.py`: this workstation is
air-gapped, and even where it is not, an evidence machine must not be opening
outbound connections while a capture is loaded.

`--retrieved-on` is required and has no default. It is the officer's statement
of when the file was obtained, and it is the date every staleness figure in
every finding is computed against. Defaulting it to today would silently
declare that a feed someone carried in on a USB stick last March was downloaded
this morning.
"""

from datetime import date

from django.core.management.base import BaseCommand, CommandError

from capture.ioc import import_feed
from capture.models import IOCFeed


class Command(BaseCommand):
    help = 'Import a threat-intelligence feed file, recording its provenance.'

    def add_arguments(self, parser):
        parser.add_argument('path', help='Path to the feed file on this machine')
        parser.add_argument('--name', required=True,
                            help='What the feed is called, e.g. "Feodo Tracker IP Blocklist"')
        parser.add_argument(
            '--format', required=True,
            choices=[choice for choice, _ in IOCFeed.Format.choices],
            help='How to parse the file',
        )
        parser.add_argument(
            '--retrieved-on', required=True,
            help='YYYY-MM-DD — when this file was downloaded. Stated, not guessed.',
        )
        parser.add_argument('--source', default='',
                            help='Where it was downloaded from')
        parser.add_argument('--licence', default='',
                            help='Licence or terms the feed is published under')
        parser.add_argument('--notes', default='')

    def handle(self, *args, **options):
        try:
            retrieved = date.fromisoformat(options['retrieved_on'])
        except ValueError as exc:
            raise CommandError(
                f'--retrieved-on must be YYYY-MM-DD: {exc}') from exc

        if retrieved > date.today():
            raise CommandError(
                'A feed cannot have been retrieved in the future. Every '
                'staleness figure printed on a finding is measured from this '
                'date, so it has to be right.'
            )

        try:
            feed = import_feed(
                options['path'],
                name=options['name'],
                fmt=options['format'],
                retrieved_on=retrieved,
                source=options['source'],
                licence=options['licence'],
                notes=options['notes'],
            )
        except (OSError, ValueError) as exc:
            raise CommandError(str(exc)) from exc

        self.stdout.write(self.style.SUCCESS(
            f'Imported {feed.entry_count} indicator(s) as "{feed.name}".'))
        self.stdout.write(f'  sha256       {feed.file_sha256}')
        self.stdout.write(f'  retrieved on {feed.retrieved_on} (as stated)')
        self.stdout.write(
            f'  published    {feed.published_on or "not stated in the file"}')
        self.stdout.write(
            '\nRe-run analysis on any session for the feed to be applied: '
            'manage.py analyze_session <id>'
        )
