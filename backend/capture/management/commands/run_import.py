# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Anbuchelvan Ganesan — NetForensiq (https://github.com/Anbu-00001/NetForensiq)
"""
Import the capture a session already points at.

This is the child half of `capture.importer` — the program the web process
starts and then forgets about. It is also runnable by hand, which is how an
import that failed for a reason the officer has since fixed (a full disk, a
machine with more memory) is retried without re-sealing the exhibit.
"""

import os
import sys

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from capture.models import CaptureSession


def _limit_memory(megabytes):
    """Cap this process's address space, so exhausting it kills only this."""
    if not megabytes:
        return
    try:
        import resource
        value = megabytes * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (value, value))
    except (ImportError, ValueError, OSError):
        # Not every platform exposes the limit. The import still runs; it just
        # runs without a ceiling, which is what it did before this existed.
        pass


class Command(BaseCommand):
    help = 'Read and analyse the capture file an existing session points at.'

    def add_arguments(self, parser):
        parser.add_argument('--session', type=int, required=True,
                            help='CaptureSession id to import into.')
        parser.add_argument('--memory-mb', type=int, default=0,
                            help='Address-space ceiling for this process.')

    def handle(self, *args, **opts):
        from capture.service import run_pcap_import

        _limit_memory(opts['memory_mb'])

        try:
            session = CaptureSession.objects.get(pk=opts['session'])
        except CaptureSession.DoesNotExist:
            raise CommandError(f"No capture session with id {opts['session']}.")

        path = session.pcap_filename
        if not path or not os.path.exists(path):
            self._fail(session,
                       'The sealed capture file is not where the session says it is '
                       f'({path or "no path recorded"}).')
            raise CommandError('capture file missing')

        try:
            session, (flows, dns) = run_pcap_import(
                pcap_path=path,
                session=session,
                home_net=session.home_net,
                user=session.started_by,
                evidence=session.evidence,
            )
        except MemoryError:
            # The ceiling above, or the machine. Either way the file is fine
            # and the officer needs to know which of the two it is.
            self._fail(session, (
                f'This import ran out of memory (ceiling {opts["memory_mb"]} MB). '
                'Memory grows with the number of distinct conversations, and a '
                'capture containing a scan can hold hundreds of thousands of '
                'them. Split it into smaller files (for example '
                '`editcap -c 500000 in.pcap part.pcap`) and import the parts, '
                'or import it on a machine with more memory.'))
            raise CommandError('out of memory')
        except Exception as exc:
            # run_pcap_import marks the session failed itself; this is the
            # message, and a non-zero exit for anything watching.
            self._fail(session, f'{type(exc).__name__}: {exc}')
            raise

        self.stdout.write(
            f'Session #{session.pk}: {session.packet_count:,} packets, '
            f'{flows:,} flows, {dns:,} DNS records.')

    def _fail(self, session, message):
        session.refresh_from_db(fields=['state'])
        session.state = CaptureSession.State.FAILED
        session.error_message = message
        session.ended_at = timezone.now()
        session.save(update_fields=['state', 'error_message', 'ended_at'])
        print(message, file=sys.stderr)
