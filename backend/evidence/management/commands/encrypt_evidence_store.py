"""Encrypt sealed artefacts that were taken into custody before encryption was on."""

import os
from pathlib import Path

from django.core.management.base import BaseCommand

from evidence import crypto
from evidence.models import CustodyEvent, EvidenceRecord
from evidence.service import record_custody


class Command(BaseCommand):
    help = 'Encrypt any evidence still stored in the clear, in place.'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run', action='store_true',
            help='List what would be encrypted and change nothing.',
        )

    def handle(self, *args, **opts):
        state = crypto.describe()
        if not state['enabled'] and not opts['dry_run']:
            # Generating a key as a side effect of a maintenance command is how
            # a key ends up somewhere nobody wrote down.
            key = crypto.load_key(create=True)
            if key is None:
                self.stderr.write(self.style.ERROR(
                    'Encryption is switched off (EVIDENCE_ENCRYPTION=off). '
                    'Nothing to do.'
                ))
                return
            self.stdout.write(self.style.WARNING(
                f'Generated a new key at {crypto._key_file()}. Escrow it now — '
                f'without it every exhibit below becomes unreadable.'
            ))

        pending = [r for r in EvidenceRecord.objects.all()
                   if not crypto.is_encrypted(r.stored_path)]
        if not pending:
            self.stdout.write(self.style.SUCCESS(
                'Every artefact in the store is already encrypted.'))
            return

        self.stdout.write(f'{len(pending)} artefact(s) stored in the clear.')
        if opts['dry_run']:
            for record in pending:
                self.stdout.write(f'  would encrypt {record.exhibit_number}')
            return

        key = crypto.load_key(create=True)
        done = skipped = 0
        for record in pending:
            # Verify before encrypting. Encrypting an artefact that already
            # fails its hash would preserve the corruption and make it harder
            # to look at, which is the opposite of the point.
            ok, computed = record.verify()
            if not ok:
                self.stderr.write(self.style.ERROR(
                    f'  SKIPPED {record.exhibit_number}: integrity check failed '
                    f'(computed {computed}). Encrypting a suspect artefact '
                    f'would preserve the problem and hide it.'
                ))
                skipped += 1
                continue

            source = Path(record.stored_path)
            sealed = source.with_suffix(source.suffix + '.enc')
            crypto.encrypt_file(source, sealed, key)
            os.replace(sealed, source)

            record.encrypted_at_rest = True
            record.encryption_algorithm = crypto.ALGORITHM
            record.save(update_fields=['encrypted_at_rest', 'encryption_algorithm'])
            record_custody(
                record, CustodyEvent.Action.ENCRYPTED,
                detail=(f'Store encrypted with {crypto.ALGORITHM}. The recorded '
                        f'SHA-256 is unchanged: it describes the capture as '
                        f'seized, not the file on disk.'),
            )
            self.stdout.write(self.style.SUCCESS(f'  encrypted {record.exhibit_number}'))
            done += 1

        self.stdout.write(self.style.SUCCESS(f'\n{done} encrypted, {skipped} skipped.'))
