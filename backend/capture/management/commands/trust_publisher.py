# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Decide whose signed update bundles this machine will accept.

    manage.py trust_publisher --list
    manage.py trust_publisher --name "Cyber Crime PS lab" \\
        --public-key <base64> --fingerprint "a1b2c3d4 e5f6a7b8 ..."
    manage.py trust_publisher --remove "a1b2c3d4 ..."

Trusting a key is an act, and the act requires the fingerprint — typed, from a
source other than the bundle being examined (a phone call, a printed notice, the
publisher's own announcement). If the fingerprint does not match the key given,
nothing is added. A bundle that carries a key proves nothing about whether the key
should be trusted; anyone can make one.
"""
from django.core.management.base import BaseCommand, CommandError

from capture import updates
from evidence import signing
from evidence.update_bundle import BundleError


class Command(BaseCommand):
    help = 'List, add or remove the publishers whose update bundles are accepted.'

    def add_arguments(self, parser):
        parser.add_argument('--list', action='store_true')
        parser.add_argument('--name', help='A label for your own records')
        parser.add_argument('--public-key', help='The publisher\'s public key, base64')
        parser.add_argument('--fingerprint',
                            help='The key\'s fingerprint, as the publisher gave it to you')
        parser.add_argument('--remove', metavar='FINGERPRINT')

    def handle(self, *args, **options):
        try:
            if options['remove']:
                removed = updates.untrust_publisher(options['remove'])
                self.stdout.write(self.style.SUCCESS(
                    f'No longer trusting {removed["name"]} '
                    f'({signing.display_fingerprint(removed["fingerprint"])}). Bundles already '
                    f'applied stay applied; no further bundle from that key will be.'))
                return
            if options['list'] or not options['public_key']:
                entries = updates.trusted_publishers()
                if not entries:
                    self.stdout.write('No publishers are trusted. No update bundle will be applied.')
                for entry in entries.values():
                    self.stdout.write(
                        f'{entry["name"]}\n  {signing.display_fingerprint(entry["fingerprint"])}'
                        f'\n  added {entry["added"]}')
                return
            if not (options['name'] and options['fingerprint']):
                raise CommandError('--name and --fingerprint are required with --public-key')
            entry = updates.trust_publisher(
                options['name'], options['public_key'], options['fingerprint'])
        except BundleError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(self.style.SUCCESS(
            f'Trusting {entry["name"]}: {signing.display_fingerprint(entry["fingerprint"])}'))
