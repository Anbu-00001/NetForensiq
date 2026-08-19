"""
Capture a phone's traffic and take it into evidence, in one step.

    python manage.py capture_phone --duration 60 --provenance seized

Answers the question "where does a police station get a .pcap?" for the device
an officer actually has in front of them. See capture/phone_bridge.py for why
tethering rather than an on-device app is the right route for an exhibit.
"""

import os
import tempfile

from django.core.management.base import BaseCommand, CommandError

from capture.phone_bridge import (
    adb_devices, find_tethered_interface, list_interfaces,
    pull_pcapdroid_capture,
)


class Command(BaseCommand):
    help = "Capture a tethered phone's traffic, seal it, and analyse it."

    def add_arguments(self, parser):
        parser.add_argument(
            '--iface', default='',
            help='Interface to capture on. Detected automatically when exactly '
                 'one tethered phone is present.',
        )
        parser.add_argument('--duration', type=int, default=60,
                            help='Seconds to capture (default 60).')
        parser.add_argument('--count', type=int, default=0,
                            help='Stop after N packets (0 = no packet limit).')
        parser.add_argument('--filter', default='',
                            help='BPF filter, e.g. "not port 22".')
        parser.add_argument('--name', default='', help='Session label.')
        parser.add_argument(
            '--provenance', default='',
            help='Where this came from: seized | reference | synthetic. '
                 'Required — the system will not decide this for you.',
        )
        parser.add_argument('--case', default='', help='Case reference.')
        parser.add_argument('--fir', default='', help='FIR number.')
        parser.add_argument('--police-station', default='')
        parser.add_argument('--seized-from', default='',
                            help='Whose device this is, as recorded.')
        parser.add_argument('--officer', default='',
                            help='Username taking custody.')
        parser.add_argument(
            '--from-pcapdroid', action='store_true',
            help='Instead of capturing, copy the newest PCAPdroid capture off '
                 'the phone over adb. For a consenting complainant or a '
                 'department handset — not for a seized exhibit.',
        )
        parser.add_argument('--list', action='store_true',
                            help='Show interfaces and connected phones, then exit.')

    def handle(self, *args, **opts):
        if opts['list']:
            return self._list()

        if opts['from_pcapdroid']:
            return self._from_phone(opts)

        return self._capture(opts)

    # ── informational ──────────────────────────────────────────────────────

    def _list(self):
        self.stdout.write(self.style.MIGRATE_HEADING('Interfaces'))
        for i in list_interfaces():
            mark = self.style.SUCCESS('  ← tethered phone') if i['is_tether'] else ''
            self.stdout.write(f"  {i['name']:22} {i['state']:8}{mark}")

        self.stdout.write(self.style.MIGRATE_HEADING('\nPhones visible to adb'))
        devices = adb_devices()
        if not devices:
            self.stdout.write('  none')
        for serial, state in devices:
            self.stdout.write(f'  {serial:24} {state}')

        name, explanation = find_tethered_interface()
        self.stdout.write('')
        self.stdout.write(self.style.SUCCESS(explanation) if name
                          else self.style.WARNING(explanation))

    # ── the two routes ─────────────────────────────────────────────────────

    def _capture(self, opts):
        from capture.service import run_live_capture

        iface = opts['iface']
        if not iface:
            iface, explanation = find_tethered_interface()
            if not iface:
                raise CommandError(
                    explanation + '\n\nRun with --list to see what is connected, '
                    'or name an interface with --iface.'
                )
            self.stdout.write(self.style.SUCCESS(explanation))

        if not opts['duration'] and not opts['count']:
            raise CommandError('Give --duration or --count so the capture ends.')

        self._check_privileges()
        record = self._seal_target(opts)

        self.stdout.write(self.style.WARNING(
            f"Capturing on {iface} for {opts['duration']}s — everything the "
            f"phone sends and receives passes through this interface."
        ))
        session, (flows, dns) = run_live_capture(
            interface=iface,
            packet_count=opts['count'],
            duration=opts['duration'],
            bpf_filter=opts['filter'],
            name=opts['name'] or f'phone-{iface}',
            user=record[1] if record else None,
        )
        self._report(session, flows, dns)

    def _from_phone(self, opts):
        provenance = self._require_provenance(opts)
        officer = self._officer(opts)

        tmp_dir = tempfile.mkdtemp(prefix='netforensiq-phone-')
        target = os.path.join(tmp_dir, 'phone-capture.pcap')
        path, explanation = pull_pcapdroid_capture(target)
        if not path:
            raise CommandError(explanation)
        self.stdout.write(self.style.SUCCESS(explanation))

        from capture.service import run_pcap_import
        from evidence.service import ingest_evidence

        try:
            record = ingest_evidence(
                path,
                collected_by=officer,
                case_reference=opts['case'],
                fir_number=opts['fir'],
                police_station=opts['police_station'],
                seized_from=opts['seized_from'],
                provenance=provenance,
                acquisition_notes='Copied from phone over adb (PCAPdroid).',
            )
            self.stdout.write(self.style.SUCCESS(
                f'  Exhibit : {record.exhibit_number}\n'
                f'  SHA-256 : {record.sha256_hash}'
            ))
            session, (flows, dns) = run_pcap_import(
                pcap_path=record.stored_path,
                name=opts['name'] or 'phone-capture',
                user=officer,
                evidence=record,
            )
        finally:
            for cleanup in (lambda: os.remove(target), lambda: os.rmdir(tmp_dir)):
                try:
                    cleanup()
                except OSError:
                    pass

        self._report(session, flows, dns)

    # ── helpers ────────────────────────────────────────────────────────────

    def _check_privileges(self):
        from capture.privileges import can_capture

        ok, reason = can_capture()
        if not ok:
            raise CommandError(reason)

    def _require_provenance(self, opts):
        valid = {'seized', 'reference', 'synthetic'}
        if opts['provenance'] not in valid:
            raise CommandError(
                'Declare where this capture came from with --provenance '
                f"({' | '.join(sorted(valid))}). There is no default: the "
                'system will not decide on your behalf whether something is '
                'evidence.'
            )
        return opts['provenance']

    def _officer(self, opts):
        if not opts['officer']:
            return None
        from django.contrib.auth import get_user_model

        try:
            return get_user_model().objects.get(username=opts['officer'])
        except get_user_model().DoesNotExist:
            raise CommandError(
                f"No such user: {opts['officer']}. Custody is attributed to an "
                f'account that exists, not to a name typed at a console.'
            )

    def _seal_target(self, opts):
        """Validate the evidence arguments before spending a minute capturing."""
        return self._require_provenance(opts), self._officer(opts)

    def _report(self, session, flows, dns):
        self.stdout.write(self.style.SUCCESS(
            f"\nSession #{session.id} '{session.name}'\n"
            f'  Packets : {session.packet_count:,}\n'
            f'  Flows   : {flows}\n'
            f'  DNS     : {dns}'
        ))
        self.stdout.write(
            '\nMost phone traffic is TLS, so what was recorded is who was '
            'contacted, when, how often and how much — not message content.'
        )
