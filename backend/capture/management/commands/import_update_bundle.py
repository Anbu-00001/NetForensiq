# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Apply a signed update bundle carried across an air gap.

    manage.py import_update_bundle bundle.nfupd.json --dry-run
    manage.py import_update_bundle bundle.nfupd.json

Always run `--dry-run` first: it prints who signed the bundle, whether this machine
trusts that key, its sequence number and expiry, and what it would change, and lists
*every* problem rather than stopping at the first. Applying is all or nothing.

It is a command and not a web page on purpose (see capture/updates.py).
"""
import getpass

from django.core.management.base import BaseCommand, CommandError

from capture import updates
from evidence import signing
from evidence.update_bundle import BundleError


class Command(BaseCommand):
    help = 'Check, and apply, a signed update bundle.'

    def add_arguments(self, parser):
        parser.add_argument('path')
        parser.add_argument('--dry-run', action='store_true',
                            help='Report what would happen and change nothing.')
        parser.add_argument('--allow-expired', action='store_true',
                            help='Apply a bundle past its expiry date. Recorded as such.')

    def handle(self, *args, **options):
        try:
            with open(options['path'], 'rb') as handle:
                text = handle.read()
        except OSError as exc:
            raise CommandError(str(exc)) from exc

        result = updates.assess(text, allow_expired=options['allow_expired'])

        self.stdout.write('Bundle')
        if result.fingerprint:
            self.stdout.write(f'  signed by   {signing.display_fingerprint(result.fingerprint)}')
            self.stdout.write(f'  claims to be {result.publisher_name or "(no name)"}')
            self.stdout.write(f'  trusted     {"yes" if result.trusted else "NO"}')
            self.stdout.write(f'  sequence    {result.sequence} '
                              f'(last applied from this key: {result.last_applied})')
            self.stdout.write(f'  created     {result.created.isoformat() if result.created else "?"}')
            self.stdout.write(f'  expires     {result.expires.isoformat() if result.expires else "?"}')
            for item in result.items:
                self.stdout.write(f'  item        {item["type"]:11s} {item["name"]}  '
                                  f'{item["size"]:,} bytes  sha256 {item["sha256"][:16]}…')
        if result.issues:
            self.stdout.write('')
            for code, message in result.issues:
                self.stdout.write(self.style.ERROR(f'  [{code}] {message}'))
        if not result.acceptable:
            raise CommandError('This bundle would not be applied.')
        if options['dry_run']:
            self.stdout.write(self.style.SUCCESS('\nAll checks pass. (dry run: nothing changed)'))
            return

        try:
            row = updates.apply_bundle(text, actor=getpass.getuser(),
                                       allow_expired=options['allow_expired'])
        except BundleError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(
            f'\nApplied update #{row.sequence}: {len(row.contents)} item(s). '
            f'Re-run analysis on a session for new indicator feeds to take effect.'))
